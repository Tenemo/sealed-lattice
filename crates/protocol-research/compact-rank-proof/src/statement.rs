use crate::{Error, Result, reader::Reader, require};
use supported_profile::{AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, Profile, auxiliary_modulus};

pub const DEGREE: usize = AUXILIARY_DEGREE;
pub const SUPPORT: usize = AUXILIARY_SECRET_SUPPORT;
pub const PLAINTEXT: usize = 3329;
pub const CANDIDATES: usize = 14;

pub fn modulus() -> i64 {
    let mut bytes = [0; 8];
    let encoded = auxiliary_modulus();
    bytes[..encoded.len()].copy_from_slice(encoded);
    i64::from_le_bytes(bytes)
}
pub fn message_scale() -> i64 {
    (modulus() + (PLAINTEXT / 2) as i64) / PLAINTEXT as i64
}
pub fn centered(value: i64) -> i64 {
    let modulus = modulus();
    let reduced = value.rem_euclid(modulus);
    if reduced > modulus / 2 {
        reduced - modulus
    } else {
        reduced
    }
}
pub fn field(value: i64) -> usize {
    value.rem_euclid(PLAINTEXT as i64) as usize
}
pub fn power(mut value: usize, mut exponent: usize) -> usize {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * value % PLAINTEXT;
        }
        value = value * value % PLAINTEXT;
        exponent >>= 1;
    }
    result
}

pub struct Packet {
    pub constant: Vec<i64>,
    pub linear: Vec<i64>,
}
pub struct Statement {
    pub profile: Profile,
    pub top: usize,
    pub mask_coordinates: usize,
    pub queries: usize,
    pub common: Vec<i64>,
    pub public_key: Vec<i64>,
    pub aggregate: Vec<Packet>,
    pub masked: Vec<usize>,
    pub selections: Vec<usize>,
    pub multiplication: Vec<usize>,
    pub output: Vec<usize>,
}
impl Statement {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        require(reader.take(4)? == b"RRS1", Error::Statement)?;
        let participants = reader.word()?;
        let options = reader.word()?;
        let profile = Profile::new(participants, options).map_err(|_| Error::Statement)?;
        let top = reader.word()?;
        require(
            options >= 3 && top >= 1 && top < options - 1,
            Error::Statement,
        )?;
        require(reader.word()? < participants, Error::Statement)?;
        let queries = options * top;
        let repeated = queries * CANDIDATES;
        let mask_coordinates = (options * (options - 1)).div_ceil(256) * 128;
        let packets = (mask_coordinates + 5 * repeated).div_ceil(DEGREE);
        let polynomial_bytes = DEGREE * 6;
        let expected_bytes = 116
            + 2 * polynomial_bytes
            + 8
            + profile.setup_contributors() * (4 + packets * 2 * polynomial_bytes)
            + 16
            + 2 * (mask_coordinates + 2 * repeated + queries);
        require(bytes.len() == expected_bytes, Error::Statement)?;
        reader.take(64)?;
        require(
            reader.word()? == DEGREE
                && reader.wide()? == modulus() as u64
                && reader.wide()? == message_scale() as u64
                && reader.word()? == SUPPORT
                && reader.word()? == PLAINTEXT
                && reader.word()? == CANDIDATES,
            Error::Statement,
        )?;
        let common = read_polynomial(&mut reader)?;
        let public_key = read_polynomial(&mut reader)?;
        require(
            reader.word()? == profile.setup_contributors() && reader.word()? == packets,
            Error::Statement,
        )?;
        let mut aggregate: Vec<Packet> = (0..packets)
            .map(|_| Packet {
                constant: vec![0; DEGREE],
                linear: vec![0; DEGREE],
            })
            .collect();
        let mut previous = None;
        for _ in 0..profile.setup_contributors() {
            let contributor = reader.word()?;
            require(
                contributor < profile.setup_eligible_contributors()
                    && previous.is_none_or(|prior| prior < contributor),
                Error::Statement,
            )?;
            previous = Some(contributor);
            for packet in &mut aggregate {
                for destination in [&mut packet.constant, &mut packet.linear] {
                    for (destination, value) in
                        destination.iter_mut().zip(read_polynomial(&mut reader)?)
                    {
                        *destination = centered(*destination + value);
                    }
                }
            }
        }
        let masked = read_fields(&mut reader, mask_coordinates)?;
        let products = read_fields(&mut reader, repeated)?;
        let multiplication = read_fields(&mut reader, repeated)?;
        let output = read_fields(&mut reader, queries)?;
        reader.finish()?;
        let selections = products
            .chunks_exact(CANDIDATES)
            .map(|row| {
                row.iter()
                    .position(|&value| value != 0)
                    .unwrap_or(CANDIDATES)
            })
            .collect();
        Ok(Self {
            profile,
            top,
            mask_coordinates,
            queries,
            common,
            public_key,
            aggregate,
            masked,
            selections,
            multiplication,
            output,
        })
    }

    pub fn source_position(&self, kind: usize, query: usize, candidate: usize) -> usize {
        self.mask_coordinates + kind * self.queries * CANDIDATES + query * CANDIDATES + candidate
    }

    pub fn rank_forms(&self) -> (Vec<Vec<usize>>, Vec<usize>) {
        let options = self.profile.options();
        let root = (2..PLAINTEXT)
            .map(|candidate| power(candidate, (PLAINTEXT - 1) / 256))
            .find(|&value| power(value, 128) != 1)
            .unwrap();
        let slots: Vec<_> = (0..128)
            .map(|slot| {
                let mut exponent = 1;
                for _ in 0..slot % 64 {
                    exponent = exponent * 5 % 256;
                }
                power(root, if slot < 64 { exponent } else { 256 - exponent })
            })
            .collect();
        let mut rows = vec![vec![0; self.mask_coordinates]; options];
        let mut ranks = vec![0; options];
        let mut pair = 0;
        for first in 0..options {
            for second in first + 1..options {
                let slot = slots[pair % 128];
                let inverse_slot = power(slot, PLAINTEXT - 2);
                let multiplier = power(field(1 - inverse_slot as i64), PLAINTEXT - 2);
                let offset = 128 * (pair / 128);
                let mut coefficient = multiplier;
                for exponent in 0..128 {
                    rows[first][offset + exponent] =
                        field((rows[first][offset + exponent] + coefficient) as i64);
                    rows[second][offset + exponent] =
                        field(rows[second][offset + exponent] as i64 - coefficient as i64);
                    coefficient = coefficient * slot % PLAINTEXT;
                }
                let value = self.masked[offset..offset + 128]
                    .iter()
                    .rev()
                    .fold(0, |sum, &coefficient| {
                        (sum * slot + coefficient) % PLAINTEXT
                    });
                let comparison = field((value as i64 - inverse_slot as i64) * multiplier as i64);
                ranks[first] = field(ranks[first] as i64 + 1 - comparison as i64);
                ranks[second] = field((ranks[second] + comparison) as i64);
                pair += 1;
            }
        }
        let public_parts = (0..self.queries)
            .map(|query| field(ranks[query / self.top] as i64 - (query % self.top) as i64))
            .collect();
        (rows, public_parts)
    }
}
fn read_polynomial(reader: &mut Reader<'_>) -> Result<Vec<i64>> {
    (0..DEGREE)
        .map(|_| {
            let bytes = reader.take(6)?;
            let sign = bytes[0];
            let mut magnitude = [0; 8];
            magnitude[..5].copy_from_slice(&bytes[1..]);
            let magnitude = i64::from_le_bytes(magnitude);
            require(
                sign <= 1 && magnitude <= modulus() / 2 && (magnitude != 0 || sign == 0),
                Error::Statement,
            )?;
            Ok(if sign == 0 { magnitude } else { -magnitude })
        })
        .collect()
}
fn read_fields(reader: &mut Reader<'_>, count: usize) -> Result<Vec<usize>> {
    require(reader.word()? == count, Error::Statement)?;
    (0..count)
        .map(|_| {
            let value = u16::from_le_bytes(reader.take(2)?.try_into().unwrap()) as usize;
            require(value < PLAINTEXT, Error::Statement)?;
            Ok(value)
        })
        .collect()
}
