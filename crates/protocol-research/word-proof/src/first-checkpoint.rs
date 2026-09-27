use super::{Error, Phase, Prover};
use crate::{
    field::{self, Element, MODULUS},
    oracles::{FirstOracle, Witness},
    parameters::*,
    rows::RowShards,
    transcript::Transcript,
    tree::{SALT_SEED_BYTES, Tree},
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use stateful_sha3::{
    Digest, Sha3_512,
    digest::common::hazmat::{SerializableState, SerializedState},
};
use supported_profile::Profile;
use zeroize::Zeroizing;

/// The most plaintext bytes one record seals, the chunk bound of the
/// participant's other retained records.
pub const RECORD_BYTES: usize = 1 << 20;
const MAGIC: &[u8; 4] = b"FPC4";
const MAXIMUM_ROLE_BYTES: usize = 1024;
/// Each record is sealed with an AES-GCM tag of this many bytes.
const TAG_BYTES: usize = 16;

// The checkpoint names its profile, whose statement header it carries, and
// either no recipient key hashes or one for each participant.
#[derive(Clone)]
struct Header {
    profile: Profile,
    column: usize,
    role: Vec<u8>,
    expected: [u8; 64],
    context: [u8; 64],
    statement: Vec<u8>,
    input_hashes: Vec<[u8; 64]>,
}
impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend([
            self.profile.participants() as u8,
            self.profile.options() as u8,
        ]);
        bytes.extend((self.column as u32).to_le_bytes());
        bytes.extend((self.role.len() as u16).to_le_bytes());
        bytes.extend(&self.role);
        bytes.extend(self.expected);
        bytes.extend(self.context);
        bytes.extend(&self.statement);
        bytes.extend((self.input_hashes.len() as u16).to_le_bytes());
        for hash in &self.input_hashes {
            bytes.extend(hash);
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 12 || &bytes[..4] != MAGIC {
            return Err(Error::Operation);
        }
        let profile = Profile::new(usize::from(bytes[4]), usize::from(bytes[5]))
            .map_err(|_| Error::Operation)?;
        let statement = profile.setup_statement_header();
        let column = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        let role_length = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
        let start = 12 + role_length;
        let input_start = start + 128 + statement.len();
        if role_length == 0
            || role_length > MAXIMUM_ROLE_BYTES
            || column > setup_relation(profile).columns() + 1
            || bytes.len() < input_start + 2
        {
            return Err(Error::Operation);
        }
        let count =
            u16::from_le_bytes(bytes[input_start..input_start + 2].try_into().unwrap()) as usize;
        if ![0, profile.participants()].contains(&count)
            || bytes.len() != input_start + 2 + count * 64
            || bytes[start + 128..input_start] != statement
        {
            return Err(Error::Operation);
        }
        Ok(Self {
            profile,
            column,
            role: bytes[12..start].to_vec(),
            expected: bytes[start..start + 64].try_into().unwrap(),
            context: bytes[start + 64..start + 128].try_into().unwrap(),
            statement,
            input_hashes: bytes[input_start + 2..]
                .chunks_exact(64)
                .map(|hash| hash.try_into().unwrap())
                .collect(),
        })
    }
    fn associated(&self, record: usize) -> Vec<u8> {
        let mut bytes = Vec::from(b"first-oracle-checkpoint/1".as_slice());
        bytes.extend(Sha3_512::digest(self.encode()));
        bytes.extend((record as u32).to_le_bytes());
        bytes
    }
}

fn fields(relation: &Relation) -> [(usize, usize); 5] {
    [
        (relation.columns() * SYSTEMATIC, 2),
        ((relation.columns() + 1) * MASKS, 16),
        (MAX_DEGREE + 1, 48),
        (1, SALT_SEED_BYTES),
        (DOMAIN, 201),
    ]
}
/// Records of a checkpoint of the relation's first oracle.
pub fn record_count(relation: &Relation) -> usize {
    fields(relation)
        .iter()
        .map(|(units, width)| units.div_ceil(RECORD_BYTES / width))
        .sum()
}
/// The longest header of a profile's checkpoint: its magic, profile, column
/// and role length, the longest role, the expected and context digests, the
/// statement header, and a recipient key hash for each participant.
pub fn maximum_header_bytes(profile: Profile) -> usize {
    12 + MAXIMUM_ROLE_BYTES
        + 2 * 64
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

pub struct Export {
    relation: Relation,
    header: Header,
    next: usize,
    // Every row's hash state, in row order.
    states: Zeroizing<Vec<[u8; 201]>>,
}
impl Export {
    pub fn begin_with_inputs(
        prover: &mut Prover,
        input_hashes: &[[u8; 64]],
    ) -> Result<Self, Error> {
        let profile = prover.profile;
        // A header the import would refuse is never exported.
        if ![0, profile.participants()].contains(&input_hashes.len())
            || !(1..=MAXIMUM_ROLE_BYTES).contains(&prover.role.len())
        {
            return Err(Error::Operation);
        }
        let Phase::FirstColumn(column) = prover.phase else {
            return Err(Error::Operation);
        };
        let first = prover.first.as_mut().ok_or(())?;
        let transcript = prover.transcript.as_ref().ok_or(())?;
        if first.degree_mask.len() != MAX_DEGREE + 1
            || transcript.round != 1
            || !transcript.salts.is_empty()
        {
            return Err(Error::Operation);
        }
        let states = first.rows.as_mut().ok_or(())?.export();
        Ok(Self {
            relation: prover.relation.clone(),
            header: Header {
                profile,
                column,
                role: prover.role.clone(),
                expected: prover.expected,
                context: transcript.context,
                statement: prover.statement_header.clone(),
                input_hashes: input_hashes.to_vec(),
            },
            next: 0,
            states,
        })
    }
    pub fn header(&self) -> Vec<u8> {
        self.header.encode()
    }
    pub fn complete(&self) -> bool {
        self.next == record_count(&self.relation)
    }
    pub fn seal(&mut self, prover: &Prover, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let (field, start, count, width) = record_layout(&self.relation, self.next).ok_or(())?;
        if prover.profile != self.header.profile
            || prover.phase != Phase::FirstColumn(self.header.column)
            || prover.role != self.header.role
            || prover.expected != self.header.expected
            || prover.statement_header != self.header.statement
            || prover
                .transcript
                .as_ref()
                .is_none_or(|value| value.context != self.header.context)
        {
            return Err(Error::Operation);
        }
        let witness = prover.witness.as_ref().ok_or(())?;
        let first = prover.first.as_ref().ok_or(())?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(count * width + TAG_BYTES));
        for index in start..start + count {
            match field {
                0 => bytes
                    .extend(witness.columns[index / SYSTEMATIC][index % SYSTEMATIC].to_le_bytes()),
                1 => bytes.extend(first.masks[index / MASKS][index % MASKS].to_le_bytes()),
                2 => bytes.extend(field::encode(first.degree_mask[index])),
                3 => bytes.extend(first.tree.seed()),
                4 => bytes.extend(self.states[index]),
                _ => unreachable!(),
            }
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
        cipher
            .encrypt_in_place(
                Nonce::from_slice(&[0; 12]),
                &self.header.associated(self.next),
                &mut *bytes,
            )
            .map_err(|_| ())?;
        self.next += 1;
        Ok(std::mem::take(&mut *bytes))
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
    hashers: Vec<Sha3_512>,
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
    pub fn begin(bytes: &[u8]) -> Result<Self, Error> {
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
            hashers: Vec::new(),
        })
    }
    pub fn complete(&self) -> bool {
        !self.failed && self.next == record_count(&self.relation)
    }
    pub fn open(&mut self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Operation);
        }
        let result = self.open_record(key, bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn open_record(&mut self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        let (field, _, count, width) = record_layout(&self.relation, self.next).ok_or(())?;
        if bytes.len() != count * width + TAG_BYTES {
            return Err(Error::Operation);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
        let mut plaintext = Zeroizing::new(bytes.to_vec());
        cipher
            .decrypt_in_place(
                Nonce::from_slice(&[0; 12]),
                &self.header.associated(self.next),
                &mut *plaintext,
            )
            .map_err(|_| ())?;
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
                        return Err(Error::Operation);
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
                        return Err(Error::Operation);
                    }
                    self.degree_mask.push(value);
                }
                3 => self.seed.copy_from_slice(bytes),
                4 => {
                    let expected_cursor = (crate::tree::leaf_prefix_bytes(self.header.role.len())
                        + 16 * self.header.column)
                        % 72;
                    if usize::from(bytes[200]) != expected_cursor {
                        return Err(Error::Operation);
                    }
                    let encoded: &SerializedState<Sha3_512> = bytes.try_into().map_err(|_| ())?;
                    self.hashers
                        .push(Sha3_512::deserialize(encoded).map_err(|_| ())?);
                }
                _ => unreachable!(),
            }
        }
        self.next += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Result<Prover, Error> {
        if !self.complete() {
            return Err(Error::Operation);
        }
        let witness = Witness::from_columns(
            &self.relation,
            self.header.expected,
            std::mem::take(&mut *self.columns),
        )
        .map_err(|_| ())?;
        let mut prover = Prover::new(self.header.profile, &self.header.role, self.header.expected);
        let mut transcript = Transcript::new(
            &self.header.role,
            self.header.context,
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
                DOMAIN,
                self.relation.first_width(),
                self.seed,
            ),
            rows: Some(RowShards::import(&self.hashers)),
            prefetched: Default::default(),
        });
        prover.phase = Phase::FirstColumn(self.header.column);
        Ok(prover)
    }
}
