use super::{Error, Phase, Prover};
use crate::{
    field::{self, Element, MODULUS},
    oracles::{FirstOracle, Witness},
    parameters::*,
    transcript::Transcript,
    tree::Tree,
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use stateful_sha3::{
    Digest, Sha3_512,
    digest::common::hazmat::{SerializableState, SerializedState},
};
use zeroize::Zeroizing;

pub const RECORD_BYTES: usize = 16_384;
const HEADER_FIXED: usize = 4 + 4 + 2 + 64 + 64 + 145;

#[derive(Clone)]
struct Header {
    column: usize,
    role: Vec<u8>,
    expected: [u8; 64],
    context: [u8; 64],
    statement: Vec<u8>,
    input_hashes: Vec<[u8; 64]>,
}
impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::from(b"FPC2".as_slice());
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
        if bytes.len() < HEADER_FIXED + 1 + 2
            || bytes.len() > HEADER_FIXED + 1024 + 2 + 10 * 64
            || &bytes[..4] != b"FPC2"
        {
            return Err(Error::Operation);
        }
        let column = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let role_length = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
        if role_length == 0
            || role_length > 1024
            || column > COLUMNS + 1
            || bytes.len() < HEADER_FIXED + role_length + 2
        {
            return Err(Error::Operation);
        }
        let start = 10 + role_length;
        let input_start = HEADER_FIXED + role_length;
        let count =
            u16::from_le_bytes(bytes[input_start..input_start + 2].try_into().unwrap()) as usize;
        if ![0, 10].contains(&count) || bytes.len() != input_start + 2 + count * 64 {
            return Err(Error::Operation);
        }
        Ok(Self {
            column,
            role: bytes[10..start].to_vec(),
            expected: bytes[start..start + 64].try_into().unwrap(),
            context: bytes[start + 64..start + 128].try_into().unwrap(),
            statement: bytes[start + 128..input_start].to_vec(),
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

fn fields() -> [(usize, usize); 5] {
    [
        (COLUMNS * SYSTEMATIC, 2),
        ((COLUMNS + 1) * MASKS, 16),
        (MAX_DEGREE + 1, 48),
        (DOMAIN, 128),
        (DOMAIN, 201),
    ]
}
pub fn record_count() -> usize {
    fields()
        .iter()
        .map(|(units, width)| units.div_ceil(RECORD_BYTES / width))
        .sum()
}
fn record_layout(mut record: usize) -> Option<(usize, usize, usize, usize)> {
    for (field, (units, width)) in fields().into_iter().enumerate() {
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
    header: Header,
    next: usize,
}
impl Export {
    pub fn begin(prover: &Prover) -> Result<Self, Error> {
        Self::begin_with_inputs(prover, &[])
    }
    pub fn begin_with_inputs(prover: &Prover, input_hashes: &[[u8; 64]]) -> Result<Self, Error> {
        if ![0, 10].contains(&input_hashes.len()) {
            return Err(Error::Operation);
        }
        let Phase::FirstColumn(column) = prover.phase else {
            return Err(Error::Operation);
        };
        let first = prover.first.as_ref().ok_or(())?;
        let transcript = prover.transcript.as_ref().ok_or(())?;
        if first.hashers.len() != DOMAIN
            || first.degree_mask.len() != MAX_DEGREE + 1
            || transcript.round != 1
            || !transcript.salts.is_empty()
        {
            return Err(Error::Operation);
        }
        Ok(Self {
            header: Header {
                column,
                role: prover.role.clone(),
                expected: prover.expected,
                context: transcript.context,
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
        self.next == record_count()
    }
    pub fn seal(&mut self, prover: &Prover, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let (field, start, count, width) = record_layout(self.next).ok_or(())?;
        if prover.phase != Phase::FirstColumn(self.header.column)
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
        let mut bytes = Zeroizing::new(Vec::with_capacity(count * width + 16));
        for index in start..start + count {
            match field {
                0 => bytes
                    .extend(witness.columns[index / SYSTEMATIC][index % SYSTEMATIC].to_le_bytes()),
                1 => bytes.extend(first.masks[index / MASKS][index % MASKS].to_le_bytes()),
                2 => bytes.extend(field::encode(first.degree_mask[index])),
                3 => bytes.extend(first.tree.salts[index]),
                4 => {
                    let encoded =
                        Zeroizing::new(<[u8; 201]>::from(first.hashers[index].serialize()));
                    bytes.extend(encoded.as_slice());
                }
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
    header: Header,
    next: usize,
    failed: bool,
    columns: Zeroizing<Vec<Vec<u16>>>,
    masks: Zeroizing<Vec<Vec<u128>>>,
    degree_mask: Zeroizing<Vec<Element>>,
    salts: Zeroizing<Vec<[u8; 128]>>,
    hashers: Vec<Sha3_512>,
}
impl Import {
    pub fn input_hashes(&self) -> &[[u8; 64]] {
        &self.header.input_hashes
    }
    pub fn role(&self) -> &[u8] {
        &self.header.role
    }
    pub fn begin(bytes: &[u8]) -> Result<Self, Error> {
        let header = Header::decode(bytes)?;
        Ok(Self {
            header,
            next: 0,
            failed: false,
            columns: Zeroizing::new(Vec::new()),
            masks: Zeroizing::new(Vec::new()),
            degree_mask: Zeroizing::new(Vec::new()),
            salts: Zeroizing::new(Vec::new()),
            hashers: Vec::new(),
        })
    }
    pub fn complete(&self) -> bool {
        !self.failed && self.next == record_count()
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
        let (field, _, count, width) = record_layout(self.next).ok_or(())?;
        if bytes.len() != count * width + 16 {
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
                3 => self.salts.push(bytes.try_into().unwrap()),
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
        let witness =
            Witness::from_columns(self.header.expected, std::mem::take(&mut *self.columns))
                .map_err(|_| ())?;
        let mut control = Vec::from((self.header.role.len() as u32).to_le_bytes());
        control.extend(&self.header.role);
        control.extend(self.header.expected);
        let mut prover = Prover::new(&control)?;
        let mut transcript = Transcript::new(&self.header.role, self.header.context);
        transcript.next();
        prover.witness = Some(witness);
        prover.statement_header = self.header.statement;
        prover.transcript = Some(transcript);
        prover.first = Some(FirstOracle {
            masks: std::mem::take(&mut *self.masks),
            degree_mask: std::mem::take(&mut *self.degree_mask),
            tree: Tree {
                length: DOMAIN,
                width: FIRST_WIDTH,
                stage: 0,
                role: self.header.role,
                salts: std::mem::take(&mut *self.salts),
                nodes: vec![[0; 64]; 2 * DOMAIN],
            },
            hashers: self.hashers,
        });
        prover.phase = Phase::FirstColumn(self.header.column);
        Ok(prover)
    }
}
