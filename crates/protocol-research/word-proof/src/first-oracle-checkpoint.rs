use super::{Phase, Refusal, SetupProver};
use crate::{
    field::{self, Element, MODULUS},
    oracles::{FirstOracle, Witness},
    rows::RowShards,
    transcript::{self, Transcript},
    tree::{SALT_SEED_BYTES, Tree},
};
use parallel_work::{
    ProtocolHash,
    sealing::{self, Sealed, TAG_BYTES},
};
use supported_profile::{Profile, relation::*};
use zeroize::Zeroizing;

/// The most plaintext bytes one record seals, the chunk bound of the
/// participant's other retained records.
pub const RECORD_BYTES: usize = 1 << 20;
const MAXIMUM_ROLE_BYTES: usize = 1024;

// The checkpoint names its profile, whose statement header it carries, and
// one recipient key hash for each participant.
#[derive(Clone)]
struct Header {
    profile: Profile,
    column: usize,
    role: Vec<u8>,
    expected: [u8; 64],
    statement: Vec<u8>,
    input_hashes: Vec<[u8; 64]>,
}
impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![
            self.profile.participants() as u8,
            self.profile.options() as u8,
        ];
        bytes.extend((self.column as u32).to_le_bytes());
        bytes.extend((self.role.len() as u16).to_le_bytes());
        bytes.extend(&self.role);
        bytes.extend(self.expected);
        bytes.extend(&self.statement);
        bytes.extend((self.input_hashes.len() as u16).to_le_bytes());
        for hash in &self.input_hashes {
            bytes.extend(hash);
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() < 8 {
            return Err(Refusal::Operation);
        }
        let profile = Profile::new(usize::from(bytes[0]), usize::from(bytes[1]))
            .map_err(|_| Refusal::Operation)?;
        let statement = profile.setup_statement_header();
        let column = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) as usize;
        let role_length = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
        let start = 8 + role_length;
        let input_start = start + 64 + statement.len();
        if role_length == 0
            || role_length > MAXIMUM_ROLE_BYTES
            || column > setup_relation(profile).columns() + 1
            || bytes.len() < input_start + 2
        {
            return Err(Refusal::Operation);
        }
        let count =
            u16::from_le_bytes(bytes[input_start..input_start + 2].try_into().unwrap()) as usize;
        if count != profile.participants()
            || bytes.len() != input_start + 2 + count * 64
            || bytes[start + 64..input_start] != statement
        {
            return Err(Refusal::Operation);
        }
        Ok(Self {
            profile,
            column,
            role: bytes[8..start].to_vec(),
            expected: bytes[start..start + 64].try_into().unwrap(),
            statement,
            input_hashes: bytes[input_start + 2..]
                .chunks_exact(64)
                .map(|hash| hash.try_into().unwrap())
                .collect(),
        })
    }
    fn associated(&self, record: usize) -> Vec<u8> {
        let mut bytes = Vec::from(b"first-oracle-checkpoint/1".as_slice());
        bytes.extend(ProtocolHash::digest(self.encode()));
        bytes.extend((record as u32).to_le_bytes());
        bytes
    }
}

fn fields(relation: &Relation) -> [(usize, usize); 5] {
    [
        (relation.columns() * SYSTEMATIC, 2),
        ((relation.columns() + 1) * MASKS, 16),
        (MAXIMUM_DEGREE + 1, 48),
        (1, SALT_SEED_BYTES),
        (EVALUATION_DOMAIN_SIZE, 201),
    ]
}
/// Records of a checkpoint of the relation's first oracle.
pub fn record_count(relation: &Relation) -> usize {
    fields(relation)
        .iter()
        .map(|(units, width)| units.div_ceil(RECORD_BYTES / width))
        .sum()
}
/// The longest header of a profile's checkpoint: its profile, column and
/// role length, the longest role, the statement digest, the statement header,
/// and a recipient key hash for each participant.
pub fn maximum_header_bytes(profile: Profile) -> usize {
    8 + MAXIMUM_ROLE_BYTES
        + 64
        + profile.setup_statement_header().len()
        + 2
        + profile.participants() * 64
}
/// Each sealed record's length, in record order.
pub fn record_lengths(relation: &Relation) -> Vec<usize> {
    (0..record_count(relation))
        .map(|record| {
            let (_, _, count, width) = record_layout(relation, record).unwrap();
            count * width + TAG_BYTES
        })
        .collect()
}
fn record_layout(relation: &Relation, mut record: usize) -> Option<(usize, usize, usize, usize)> {
    for (field, (units, width)) in fields(relation).into_iter().enumerate() {
        let per_record = RECORD_BYTES / width;
        let records = units.div_ceil(per_record);
        if record < records {
            let start = record * per_record;
            return Some((field, start, per_record.min(units - start), width));
        }
        record -= records;
    }
    None
}

// The row states' records are sealed from the rows as each is sealed,
// and each opened record's states are restored into the rows at once.
pub struct Export {
    relation: Relation,
    header: Header,
    next: usize,
}
impl Export {
    pub fn begin_with_inputs(
        prover: &mut SetupProver,
        input_hashes: &[[u8; 64]],
    ) -> Result<Self, Refusal> {
        let profile = prover.profile;
        // A header the import would refuse is never exported.
        if input_hashes.len() != profile.participants()
            || !(1..=MAXIMUM_ROLE_BYTES).contains(&prover.role.len())
        {
            return Err(Refusal::Operation);
        }
        let Phase::FirstColumn(column) = prover.phase else {
            return Err(Refusal::Operation);
        };
        let first = prover.first.as_mut().ok_or(())?;
        let transcript = prover.transcript.as_ref().ok_or(())?;
        if first.degree_mask.len() != MAXIMUM_DEGREE + 1
            || transcript.round != 1
            || !transcript.salts.is_empty()
        {
            return Err(Refusal::Operation);
        }
        first.rows.as_ref().ok_or(())?;
        Ok(Self {
            relation: prover.relation.clone(),
            header: Header {
                profile,
                column,
                role: prover.role.clone(),
                expected: prover.expected,
                statement: prover.statement_header.clone(),
                input_hashes: input_hashes.to_vec(),
            },
            next: 0,
        })
    }
    pub fn header(&self) -> Vec<u8> {
        self.header.encode()
    }
    pub fn complete(&self) -> bool {
        self.next == record_count(&self.relation)
    }
    /// Seals the next record under a fresh key.
    pub fn seal(&mut self, prover: &mut SetupProver) -> Result<Sealed, Refusal> {
        let (field, start, count, width) = record_layout(&self.relation, self.next).ok_or(())?;
        if prover.profile != self.header.profile
            || prover.phase != Phase::FirstColumn(self.header.column)
            || prover.role != self.header.role
            || prover.expected != self.header.expected
            || prover.statement_header != self.header.statement
        {
            return Err(Refusal::Operation);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(count * width));
        if field == 4 {
            let rows = prover.first.as_mut().ok_or(())?.rows.as_mut().ok_or(())?;
            bytes.extend_from_slice(&rows.export(start, count));
        } else {
            let witness = prover.witness.as_ref().ok_or(())?;
            let first = prover.first.as_ref().ok_or(())?;
            for index in start..start + count {
                match field {
                    0 => bytes.extend(
                        witness.columns[index / SYSTEMATIC][index % SYSTEMATIC].to_le_bytes(),
                    ),
                    1 => bytes.extend(first.masks[index / MASKS][index % MASKS].to_le_bytes()),
                    2 => bytes.extend(field::encode(first.degree_mask[index])),
                    3 => bytes.extend(first.tree.seed()),
                    _ => unreachable!(),
                }
            }
        }
        let sealed = sealing::seal(&bytes, &self.header.associated(self.next));
        self.next += 1;
        Ok(sealed)
    }
}

pub struct Import {
    relation: Relation,
    header: Header,
    next: usize,
    failed: bool,
    columns: Zeroizing<Vec<Vec<u16>>>,
    masks: Zeroizing<Vec<Vec<u128>>>,
    degree_mask: Zeroizing<Vec<Element>>,
    seed: Zeroizing<[u8; SALT_SEED_BYTES]>,
    rows: Option<RowShards>,
}
impl Import {
    pub fn profile(&self) -> Profile {
        self.header.profile
    }
    pub fn input_hashes(&self) -> &[[u8; 64]] {
        &self.header.input_hashes
    }
    pub fn role(&self) -> &[u8] {
        &self.header.role
    }
    pub fn relation(&self) -> &Relation {
        &self.relation
    }
    pub fn begin(bytes: &[u8]) -> Result<Self, Refusal> {
        let header = Header::decode(bytes)?;
        Ok(Self {
            relation: setup_relation(header.profile),
            header,
            next: 0,
            failed: false,
            columns: Zeroizing::new(Vec::new()),
            masks: Zeroizing::new(Vec::new()),
            degree_mask: Zeroizing::new(Vec::new()),
            seed: Zeroizing::new([0; SALT_SEED_BYTES]),
            rows: None,
        })
    }
    pub fn complete(&self) -> bool {
        !self.failed && self.next == record_count(&self.relation)
    }
    pub fn open(&mut self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Operation);
        }
        let result = self.open_record(key, bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn open_record(&mut self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
        let (field, start, count, width) = record_layout(&self.relation, self.next).ok_or(())?;
        if bytes.len() != count * width + TAG_BYTES {
            return Err(Refusal::Operation);
        }
        let plaintext = sealing::open(key, &self.header.associated(self.next), bytes).ok_or(())?;
        for bytes in plaintext.chunks_exact(width) {
            match field {
                0 => {
                    if self
                        .columns
                        .last()
                        .is_none_or(|values| values.len() == SYSTEMATIC)
                    {
                        self.columns.push(Vec::with_capacity(SYSTEMATIC));
                    }
                    self.columns
                        .last_mut()
                        .unwrap()
                        .push(u16::from_le_bytes(bytes.try_into().unwrap()));
                }
                1 => {
                    let value = u128::from_le_bytes(bytes.try_into().unwrap());
                    if value >= MODULUS {
                        return Err(Refusal::Operation);
                    }
                    if self.masks.last().is_none_or(|values| values.len() == MASKS) {
                        self.masks.push(Vec::with_capacity(MASKS));
                    }
                    self.masks.last_mut().unwrap().push(value);
                }
                2 => {
                    let value = std::array::from_fn(|index| {
                        u128::from_le_bytes(bytes[16 * index..16 * (index + 1)].try_into().unwrap())
                    });
                    if value.iter().any(|value| *value >= MODULUS) {
                        return Err(Refusal::Operation);
                    }
                    self.degree_mask.push(value);
                }
                3 => self.seed.copy_from_slice(bytes),
                4 => {
                    let expected_cursor = ProtocolHash::absorption_cursor_after(
                        crate::tree::leaf_message_prefix_bytes(self.header.role.len())
                            + 16 * self.header.column,
                    );
                    if usize::from(bytes[200]) != expected_cursor {
                        return Err(Refusal::Operation);
                    }
                    let encoded: &[u8; ProtocolHash::STATE_BYTES] =
                        bytes.try_into().map_err(|_| ())?;
                    ProtocolHash::deserialize(encoded).ok_or(())?;
                }
                _ => unreachable!(),
            }
        }
        if field == 4 {
            self.rows
                .get_or_insert_with(RowShards::importing)
                .import(start, &plaintext);
        }
        self.next += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Result<SetupProver, Refusal> {
        if !self.complete() {
            return Err(Refusal::Operation);
        }
        let witness = Witness::from_columns(
            &self.relation,
            self.header.expected,
            std::mem::take(&mut *self.columns),
        )
        .map_err(|_| ())?;
        let mut prover =
            SetupProver::new(self.header.profile, &self.header.role, self.header.expected);
        let mut transcript = Transcript::new(
            &self.header.role,
            transcript::context(&self.relation, &self.header.role, &self.header.expected),
            self.relation.message_bytes(),
        );
        transcript.next();
        prover.witness = Some(witness);
        prover.statement_header = self.header.statement;
        prover.transcript = Some(transcript);
        prover.first = Some(FirstOracle {
            masks: std::mem::take(&mut *self.masks),
            degree_mask: std::mem::take(&mut *self.degree_mask),
            tree: Tree::with_seed(
                &self.header.role,
                0,
                EVALUATION_DOMAIN_SIZE,
                self.relation.first_width(),
                self.seed,
            ),
            rows: Some(self.rows.take().ok_or(())?),
            prefetched: Default::default(),
        });
        prover.phase = Phase::FirstColumn(self.header.column);
        Ok(prover)
    }
}

#[cfg(test)]
#[path = "first-oracle-checkpoint-tests.rs"]
mod tests;
