//! Streaming verification of a selected offer's public evaluation proof.
use super::transcript::{Reader, hash, hash_after, prefix, requested, sample, wide};
use super::{Element, Refusal, ZERO, add, encode, multiply, root, scale, subtract};
use parallel_work::CHUNK_LIMIT;
use statement_stream::proof_field::{MODULUS, inverse_extension, multiply as multiply_base, power};
use std::collections::BTreeMap;
use supported_profile::{
    Profile,
    relation::{
        EVALUATION_DOMAIN_SIZE, EVALUATION_FOLDS, EVALUATION_HEADER_BYTES, EVALUATION_QUERY_COUNT,
        SYSTEMATIC, evaluation_message_bytes,
    },
};

struct Transcript {
    role: Vec<u8>,
    context: [u8; 64],
    state: Vec<u8>,
    message: Vec<u8>,
    round: u32,
}
impl Transcript {
    fn next(&mut self) {
        self.round += 1;
        self.message = wide(
            b"bounded-proof/verifier-message",
            &[
                &self.role,
                &self.context,
                &self.state,
                &self.round.to_le_bytes(),
            ],
            self.state.len(),
        );
    }
    fn respond(&mut self, parts: &[&[u8]]) {
        let round = self.round.to_le_bytes();
        let salt = [0; 128];
        let mut inputs = vec![
            self.role.as_slice(),
            self.context.as_slice(),
            round.as_slice(),
            salt.as_slice(),
        ];
        inputs.extend(parts);
        let root = hash(b"bounded-proof/message-root", &inputs);
        let chained = wide(
            b"bounded-proof/chain-state",
            &[&self.role, &self.context, &self.message, &root],
            self.state.len(),
        );
        self.state[..64].copy_from_slice(&root);
        let length = self.state.len() - 64;
        self.state[64..].copy_from_slice(&chained[..length]);
    }
}

fn transcript(
    profile: Profile,
    role: &[u8],
    aggregate: &[u8; 64],
    roots: &[[u8; 64]],
) -> Result<Transcript, Refusal> {
    if role.is_empty() || role.len() > 1000 || roots.len() != profile.setup_contributors() {
        return Err(Refusal::Context);
    }
    let parameters: Vec<u8> = [
        profile.participants(),
        profile.options(),
        SYSTEMATIC,
        EVALUATION_DOMAIN_SIZE,
        EVALUATION_QUERY_COUNT,
        profile.committed_columns(),
        evaluation_message_bytes(profile),
    ]
    .into_iter()
    .flat_map(|value| (value as u32).to_le_bytes())
    .collect();
    let roots: Vec<u8> = roots.iter().flatten().copied().collect();
    let context = hash(
        b"committed-key/evaluation-statement",
        &[role, &profile.setup_statement_header(), &parameters, &roots],
    );
    let mut transcript = Transcript {
        role: role.to_vec(),
        context,
        state: vec![0; evaluation_message_bytes(profile)],
        message: Vec::new(),
        round: 0,
    };
    transcript.next();
    transcript.respond(&[aggregate]);
    transcript.next();
    Ok(transcript)
}

pub fn aggregate_challenges(
    profile: Profile,
    role: &[u8],
    aggregate: &[u8; 64],
    roots: &[[u8; 64]],
) -> Result<(Element, Vec<Element>), Refusal> {
    let transcript = transcript(profile, role, aggregate, roots)?;
    Ok((
        sample(&transcript.message, 0, true),
        (0..profile.committed_columns())
            .map(|index| sample(&transcript.message, index + 1, false))
            .collect(),
    ))
}

pub struct EvaluationVerifier {
    role: Vec<u8>,
    contribution_role: Vec<u8>,
    ordinal: usize,
    public_root: [u8; 64],
    point: Element,
    weights: Vec<Element>,
    claim: Element,
    terminal: Element,
    fold_roots: Vec<[u8; 64]>,
    folds: Vec<Element>,
    queries: Vec<usize>,
    indices: Vec<usize>,
    values: Vec<Element>,
    expected: Vec<(usize, Element)>,
    known: BTreeMap<usize, [u8; 64]>,
    buffer: Vec<u8>,
    reading_count: bool,
    position: usize,
    stage: usize,
    failed: bool,
    complete: bool,
}

impl EvaluationVerifier {
    pub fn open(
        profile: Profile,
        role: &[u8],
        aggregate: &[u8; 64],
        roots: &[[u8; 64]],
        ordinal: usize,
        contribution_role: &[u8],
        header: &[u8],
    ) -> Result<Self, Refusal> {
        if header.len() != EVALUATION_HEADER_BYTES
            || contribution_role.is_empty()
            || contribution_role.len() > 1024
        {
            return Err(Refusal::Length);
        }
        let public_root = *roots.get(ordinal).ok_or(Refusal::Context)?;
        let mut transcript = transcript(profile, role, aggregate, roots)?;
        let point = sample(&transcript.message, 0, true);
        let weights = (0..profile.committed_columns())
            .map(|index| sample(&transcript.message, index + 1, false))
            .collect();
        let mut reader = Reader::new(header);
        let claim = reader.element()?;
        let fold_roots: Vec<[u8; 64]> = (0..EVALUATION_FOLDS - 1)
            .map(|_| Ok(reader.take(64)?.try_into().unwrap()))
            .collect::<Result<_, Refusal>>()?;
        let terminal = reader.element()?;
        transcript.respond(&[&(ordinal as u32).to_le_bytes(), &encode(claim)]);
        let mut folds = Vec::new();
        for root in &fold_roots {
            transcript.next();
            folds.push(sample(&transcript.message, 0, false));
            transcript.respond(&[root]);
        }
        transcript.next();
        folds.push(sample(&transcript.message, 0, false));
        transcript.respond(&[&encode(terminal)]);
        transcript.next();
        let queries: Vec<usize> = (0..EVALUATION_QUERY_COUNT)
            .map(|index| {
                u32::from_le_bytes(
                    transcript.message[4 * index..4 * (index + 1)]
                        .try_into()
                        .unwrap(),
                ) as usize
                    % (EVALUATION_DOMAIN_SIZE / 2)
            })
            .collect();
        Ok(Self {
            role: role.to_vec(),
            contribution_role: contribution_role.to_vec(),
            ordinal,
            public_root,
            point,
            weights,
            claim,
            terminal,
            fold_roots,
            folds,
            indices: requested(&queries, EVALUATION_DOMAIN_SIZE),
            queries,
            values: Vec::new(),
            expected: Vec::new(),
            known: BTreeMap::new(),
            buffer: Vec::new(),
            reading_count: true,
            position: 0,
            stage: 0,
            failed: false,
            complete: false,
        })
    }

    fn shape(&self) -> (usize, usize, [u8; 64], Vec<u8>) {
        if self.stage == 0 {
            (
                EVALUATION_DOMAIN_SIZE,
                16 * self.weights.len(),
                self.public_root,
                self.contribution_role.clone(),
            )
        } else {
            let mut role = self.role.clone();
            role.extend((self.ordinal as u32).to_le_bytes());
            role.extend(((self.stage - 1) as u32).to_le_bytes());
            (
                EVALUATION_DOMAIN_SIZE >> self.stage,
                48,
                self.fold_roots[self.stage - 1],
                role,
            )
        }
    }

    fn missing(&self, mut node: usize) -> usize {
        let mut count = 0;
        while node > 1 && !self.known.contains_key(&node) {
            count += usize::from(!self.known.contains_key(&(node ^ 1)));
            node /= 2;
        }
        count
    }

    fn opening(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let (length, width, root, role) = self.shape();
        let mut reader = Reader::new(bytes);
        let index = reader.word()?;
        if self.indices.get(self.position) != Some(&index) {
            return Err(Refusal::Encoding);
        }
        let row = reader.take(width)?;
        let mut fields = Reader::new(row);
        for _ in 0..width / 16 {
            fields.base()?;
        }
        let mut digest = hash(
            b"committed-key/leaf",
            &[&role, &(index as u32).to_le_bytes(), row],
        );
        let node_prefix = prefix(b"committed-key/node", &[&role]);
        let mut node = length + index;
        let mut level = 1u32;
        let mut pending = Vec::new();
        while node > 1 && !self.known.contains_key(&node) {
            pending.push((node, digest));
            let sibling = if let Some(value) = self.known.get(&(node ^ 1)) {
                *value
            } else {
                let value: [u8; 64] = reader.take(64)?.try_into().unwrap();
                pending.push((node ^ 1, value));
                value
            };
            digest = if node.is_multiple_of(2) {
                hash_after(&node_prefix, &[&level.to_le_bytes(), &digest, &sibling])
            } else {
                hash_after(&node_prefix, &[&level.to_le_bytes(), &sibling, &digest])
            };
            node /= 2;
            level += 1;
        }
        if digest != *self.known.get(&node).unwrap_or(&root) || reader.position != bytes.len() {
            return Err(Refusal::Authentication);
        }
        self.known.extend(pending);
        let mut reader = Reader::new(row);
        let value = if self.stage == 0 {
            let mut combined = ZERO;
            for weight in &self.weights {
                combined = add(combined, scale(*weight, reader.base()?));
            }
            let position = multiply_base(7, power(super::root(length), index as u128));
            let denominator = inverse_extension(subtract([position, 0, 0], self.point))
                .ok_or(Refusal::Relation)?;
            multiply(subtract(combined, self.claim), denominator)
        } else {
            reader.element()?
        };
        if let Ok(expected) = self
            .expected
            .binary_search_by_key(&index, |(index, _)| *index)
            && value != self.expected[expected].1
        {
            return Err(Refusal::Relation);
        }
        self.values.push(value);
        Ok(())
    }

    fn advance(&mut self) -> Result<(), Refusal> {
        let length = EVALUATION_DOMAIN_SIZE >> self.stage;
        let half = power(2, MODULUS - 2);
        let shift = power(7, 1 << self.stage);
        let mut expected = Vec::new();
        for index in self
            .indices
            .iter()
            .copied()
            .filter(|index| *index < length / 2)
        {
            let left = self.values[self
                .indices
                .binary_search(&index)
                .map_err(|_| Refusal::Encoding)?];
            let right = self.values[self
                .indices
                .binary_search(&(index + length / 2))
                .map_err(|_| Refusal::Encoding)?];
            let position = multiply_base(shift, power(root(length), index as u128));
            let folded = add(
                scale(add(left, right), half),
                multiply(
                    self.folds[self.stage],
                    scale(
                        subtract(left, right),
                        multiply_base(half, power(position, MODULUS - 2)),
                    ),
                ),
            );
            if self.stage + 1 == EVALUATION_FOLDS {
                if folded != self.terminal {
                    return Err(Refusal::Relation);
                }
            } else {
                expected.push((index, folded));
            }
        }
        self.stage += 1;
        self.values.clear();
        self.known.clear();
        if self.stage == EVALUATION_FOLDS {
            self.complete = true;
            return Ok(());
        }
        self.expected = expected;
        self.indices = requested(&self.queries, EVALUATION_DOMAIN_SIZE >> self.stage);
        self.position = 0;
        self.reading_count = true;
        Ok(())
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed || bytes.len() > CHUNK_LIMIT {
            self.failed = true;
            return Err(Refusal::Length);
        }
        let result = (|| {
            while !bytes.is_empty() {
                if self.complete {
                    return Err(Refusal::Length);
                }
                let (length, width, _, _) = self.shape();
                let required = if self.reading_count {
                    4
                } else {
                    4 + width + 64 * self.missing(length + self.indices[self.position])
                };
                let count = bytes.len().min(required - self.buffer.len());
                self.buffer.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.buffer.len() == required {
                    let buffer = std::mem::take(&mut self.buffer);
                    if self.reading_count {
                        if Reader::new(&buffer).word()? != self.indices.len() {
                            return Err(Refusal::Encoding);
                        }
                        self.reading_count = false;
                    } else {
                        self.opening(&buffer)?;
                        self.position += 1;
                        if self.position == self.indices.len() {
                            self.advance()?;
                        }
                    }
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn finish(self) -> Option<Element> {
        (!self.failed && self.complete && self.buffer.is_empty()).then_some(self.claim)
    }
}
