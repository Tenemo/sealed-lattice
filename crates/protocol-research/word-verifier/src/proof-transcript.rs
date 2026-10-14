use super::{Element, FOLDS, HEADER_LENGTH, Refusal, ZERO, encode, root};
use parallel_work::ProtocolHash;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use statement_stream::proof_field::MODULUS;
use supported_profile::relation::{
    EVALUATION_DOMAIN_SIZE, MASKS, MAXIMUM_DEGREE, QUERY_COUNT, Relation, SYSTEMATIC,
    WITNESS_DEGREE,
};

/// The verifier's own reading of a relation's witness, lookup and oracle
/// counts and leaf widths.
pub(super) struct Shape {
    pub(super) words: usize,
    pub(super) booleans: usize,
    pub(super) columns: usize,
    pub(super) lookups: Vec<(usize, u128)>,
    pub(super) zero_products: Vec<(usize, usize)>,
    pub(super) original: usize,
    pub(super) oracles: usize,
    pub(super) first_width: usize,
    pub(super) second_width: usize,
    pub(super) message_bytes: usize,
}
impl Shape {
    pub(super) fn new(relation: &Relation) -> Self {
        let columns = relation.words + relation.booleans;
        let lookups: Vec<_> = (0..relation.words)
            .map(|column| (column, 1))
            .chain(relation.narrow.iter().copied())
            .collect();
        let original = columns + lookups.len() + 4;
        Self {
            words: relation.words,
            booleans: relation.booleans,
            columns,
            oracles: original
                + relation.booleans
                + relation.zero_product_pairs.len()
                + lookups.len()
                + 2,
            original,
            first_width: (columns + 1) * 16 + 48,
            second_width: (lookups.len() + 2) * 48,
            lookups,
            zero_products: relation.zero_product_pairs.clone(),
            message_bytes: relation.message_bytes,
        }
    }
}

fn degree(shape: &Shape, index: usize) -> usize {
    if index < shape.original - 1 {
        WITNESS_DEGREE
    } else if index == shape.original - 1 || index == shape.oracles - 2 {
        WITNESS_DEGREE - 1
    } else if index == shape.oracles - 1 {
        SYSTEMATIC - 2
    } else {
        2 * WITNESS_DEGREE - SYSTEMATIC
    }
}
/// The relation parameters, oracle degrees and lookups that a proof's
/// context binds.
fn context_parameters(relation: &Relation) -> Vec<u8> {
    let shape = &Shape::new(relation);
    let mut bytes: Vec<u8> = [
        SYSTEMATIC,
        QUERY_COUNT,
        MASKS,
        EVALUATION_DOMAIN_SIZE,
        MAXIMUM_DEGREE,
        2,
        shape.message_bytes,
    ]
    .into_iter()
    .chain(relation.parameters.iter().copied())
    .chain((0..shape.oracles).map(|index| degree(shape, index)))
    .flat_map(|value| (value as u32).to_le_bytes())
    .collect();
    for (column, scale) in &shape.lookups {
        bytes.extend((*column as u32).to_le_bytes());
        bytes.extend((*scale as u32).to_le_bytes());
    }
    bytes
}
/// The statement context: the role, the proof system's constants, the
/// relation parameters and the statement digest.
pub(crate) fn context(relation: &Relation, role: &[u8], statement: &[u8; 64]) -> [u8; 64] {
    hash(
        b"bounded-proof/statement",
        &[
            role,
            relation.tag,
            &2u128.to_le_bytes(),
            &root(1 << 20).to_le_bytes(),
            &7u128.to_le_bytes(),
            &context_parameters(relation),
            &(MODULUS - 1).to_le_bytes(),
            statement,
        ],
    )
}
pub(super) fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = ProtocolHash::new();
    part(&mut hash, domain);
    for value in parts {
        part(&mut hash, value);
    }
    hash.finalize()
}
fn part(hash: &mut ProtocolHash, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_le_bytes());
    hash.update(bytes);
}
/// The sponge of a hash that has absorbed its domain and first parts, which
/// every hash with that prefix continues.
pub(super) fn prefix(domain: &[u8], parts: &[&[u8]]) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    part(&mut hash, domain);
    for value in parts {
        part(&mut hash, value);
    }
    hash
}
/// The hash of the prefix's domain and parts followed by these parts.
pub(super) fn hash_after(prefix: &ProtocolHash, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = prefix.clone();
    for value in parts {
        part(&mut hash, value);
    }
    hash.finalize()
}
fn wide(domain: &[u8], parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut hash = Shake256::default();
    Update::update(&mut hash, &(domain.len() as u32).to_le_bytes());
    Update::update(&mut hash, domain);
    for value in parts {
        Update::update(&mut hash, &(value.len() as u32).to_le_bytes());
        Update::update(&mut hash, value);
    }
    let mut output = vec![0; length];
    XofReader::read(&mut hash.finalize_xof(), &mut output);
    output
}
fn residue(bytes: &[u8], modulus: u128) -> u128 {
    let mut remainder = 0;
    for byte in bytes.iter().rev() {
        for bit in (0..8).rev() {
            let complement = modulus - remainder;
            remainder = if remainder >= complement {
                remainder - complement
            } else {
                remainder + remainder
            };
            if byte >> bit & 1 != 0 {
                remainder = if remainder == modulus - 1 {
                    0
                } else {
                    remainder + 1
                };
            }
        }
    }
    remainder
}
fn sample(message: &[u8], index: usize, nonbase: bool) -> Element {
    std::array::from_fn(|coordinate| {
        let nonzero = nonbase && coordinate == 2;
        let value = residue(
            &message[96 * index + 32 * coordinate..96 * index + 32 * (coordinate + 1)],
            if nonzero { MODULUS - 1 } else { MODULUS },
        );
        value + u128::from(nonzero)
    })
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pub(super) position: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], Refusal> {
        let end = self.position.checked_add(length).ok_or(Refusal::Length)?;
        let result = self.bytes.get(self.position..end).ok_or(Refusal::Length)?;
        self.position = end;
        Ok(result)
    }
    pub(super) fn word(&mut self) -> Result<usize, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    pub(super) fn base(&mut self) -> Result<u128, Refusal> {
        let value = u128::from_le_bytes(self.take(16)?.try_into().unwrap());
        if value >= MODULUS {
            return Err(Refusal::Encoding);
        }
        Ok(value)
    }
    pub(super) fn element(&mut self) -> Result<Element, Refusal> {
        Ok([self.base()?, self.base()?, self.base()?])
    }
}

pub(super) struct Header {
    pub(super) statement: [u8; 64],
    pub(super) roots: [[u8; 64]; 3],
    pub(super) mask_sum: Element,
    pub(super) salts: Vec<[u8; 128]>,
    pub(super) fold_roots: Vec<[u8; 64]>,
    pub(super) terminal: Element,
}
impl Header {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != HEADER_LENGTH {
            return Err(Refusal::Length);
        }
        let mut reader = Reader::new(bytes);
        let statement = reader.take(64)?.try_into().unwrap();
        let mut roots = [[0; 64]; 3];
        for root in &mut roots {
            *root = reader.take(64)?.try_into().unwrap();
        }
        let mask_sum = reader.element()?;
        let mut salts = Vec::new();
        for _ in 0..FOLDS + 3 {
            salts.push(reader.take(128)?.try_into().unwrap());
        }
        let mut fold_roots = Vec::new();
        for _ in 0..FOLDS - 1 {
            fold_roots.push(reader.take(64)?.try_into().unwrap());
        }
        let terminal = reader.element()?;
        Ok(Self {
            statement,
            roots,
            mask_sum,
            salts,
            fold_roots,
            terminal,
        })
    }
}

pub(super) struct Challenges {
    pub(super) beta: Element,
    pub(super) alpha: Element,
    pub(super) mask: Element,
    pub(super) combination: Vec<Element>,
    pub(super) folds: Vec<Element>,
    pub(super) queries: Vec<usize>,
}
pub(super) fn challenges(
    shape: &Shape,
    role: &[u8],
    context: &[u8; 64],
    header: &Header,
) -> Challenges {
    let length = shape.message_bytes;
    let mut state = vec![0; length];
    let mut beta = ZERO;
    let mut alpha = ZERO;
    let mut mask = ZERO;
    let mut combination = Vec::new();
    let mut folds = Vec::new();
    for round in 1..=FOLDS + 3 {
        let message = wide(
            b"bounded-proof/verifier-message",
            &[role, context, &state, &(round as u32).to_le_bytes()],
            length,
        );
        if round == 2 {
            beta = sample(&message, 0, true);
        }
        if round == 3 {
            alpha = sample(&message, 0, false);
            mask = sample(&message, 1, false);
        }
        if round == 4 {
            combination = (0..2 * shape.oracles)
                .map(|index| sample(&message, index, false))
                .collect();
        }
        if round >= 4 {
            folds.push(sample(
                &message,
                if round == 4 { 2 * shape.oracles } else { 0 },
                false,
            ));
        }
        let sum = encode(header.mask_sum);
        let terminal = encode(header.terminal);
        let parts: Vec<&[u8]> = match round {
            1 => vec![&header.roots[0]],
            2 => vec![&header.roots[1], &sum],
            3 => vec![&header.roots[2]],
            _ => {
                if round == FOLDS + 3 {
                    vec![&terminal]
                } else {
                    vec![&header.fold_roots[round - 4]]
                }
            }
        };
        let round_bytes = (round as u32).to_le_bytes();
        let mut input = vec![
            role,
            context.as_slice(),
            round_bytes.as_slice(),
            header.salts[round - 1].as_slice(),
        ];
        input.extend(parts);
        let root = hash(b"bounded-proof/message-root", &input);
        let digest = wide(
            b"bounded-proof/chain-state",
            &[role, context, &message, &root],
            length,
        );
        state[..64].copy_from_slice(&root);
        state[64..].copy_from_slice(&digest[..length - 64]);
    }
    let message = wide(
        b"bounded-proof/verifier-message",
        &[role, context, &state, &((FOLDS + 4) as u32).to_le_bytes()],
        length,
    );
    let queries = (0..QUERY_COUNT)
        .map(|index| {
            u32::from_le_bytes(message[4 * index..4 * (index + 1)].try_into().unwrap()) as usize
                % (EVALUATION_DOMAIN_SIZE / 2)
        })
        .collect();
    Challenges {
        beta,
        alpha,
        mask,
        combination,
        folds,
        queries,
    }
}
pub(super) fn requested(queries: &[usize], length: usize) -> Vec<usize> {
    let mut values: Vec<usize> = queries
        .iter()
        .flat_map(|query| {
            let lower = query % (length / 2);
            [lower, lower + length / 2]
        })
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}
