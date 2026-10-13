use super::super::word_arithmetic::{MAXIMUM_WORDS, larger};
use super::{Ciphertext, DEGREE, Engine, Polynomial, Refusal};
use protocol_foundations::{foundation::CanonicalItem, identity::IdentityHasher};
use std::collections::BTreeSet;
use supported_profile::Profile;

const EVALUATION_VALUE_DOMAIN: &str = "sealed-lattice/public-evaluation-work/v2";
/// Bytes of one stored working value of the profile: every coefficient word
/// of both components.
pub fn stored_value_bytes(profile: Profile) -> usize {
    2 * DEGREE * profile.ciphertext_modulus().bits().div_ceil(64) * 8
}

/// The stored bytes of a working value: every coefficient word in
/// little-endian order.
pub fn stored_bytes(value: &Ciphertext) -> Vec<u8> {
    value
        .iter()
        .flatten()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

/// The resident values to evict so that `needed` more fit the capacity,
/// farthest next use first and never an input of the current instruction.
/// A value whose verified copy is still stored, because it was reloaded, is
/// dropped rather than written again; every other one is spilled. Returns the
/// spills and the drops.
pub(super) fn evictions(
    mut resident: Vec<usize>,
    required: &BTreeSet<usize>,
    needed: usize,
    capacity: usize,
    next_use: impl Fn(usize) -> usize,
    stored: impl Fn(usize) -> bool,
) -> Result<(Vec<usize>, Vec<usize>), Refusal> {
    let (mut spills, mut drops) = (Vec::new(), Vec::new());
    while resident.len() + needed > capacity {
        let evicted = resident
            .iter()
            .filter(|index| !required.contains(index))
            .max_by_key(|index| (next_use(**index), **index))
            .copied()
            .ok_or(Refusal::Allocation)?;
        resident.retain(|index| *index != evicted);
        if stored(evicted) {
            drops.push(evicted);
        } else {
            spills.push(evicted);
        }
    }
    Ok((spills, drops))
}

/// The words of a value that a piece of its stored bytes covers, from the
/// piece's first word: the first component's, then the second's.
fn covered_words(value: &Ciphertext, first: usize, count: usize) -> impl Iterator<Item = &u64> {
    let (words, end) = (value[0].len(), first + count);
    value[0][first.min(words)..end.min(words)]
        .iter()
        .chain(&value[1][first.saturating_sub(words)..end.saturating_sub(words)])
}

fn covered_words_mut(
    value: &mut Ciphertext,
    first: usize,
    count: usize,
) -> impl Iterator<Item = &mut u64> {
    let (words, end) = (value[0].len(), first + count);
    let [low, high] = value;
    low[first.min(words)..end.min(words)]
        .iter_mut()
        .chain(&mut high[first.saturating_sub(words)..end.saturating_sub(words)])
}

/// A polynomial decoded from its canonical coefficient bytes as they
/// arrive: each coefficient a sign byte and its magnitude's little-endian
/// bytes.
pub struct PolynomialDecoder {
    output: Polynomial,
    decoded: usize,
    /// The first bytes of a coefficient that the last piece split.
    partial: Vec<u8>,
}

/// A stored working value that arrives in pieces of whole words: a spilled
/// value's readback, whose words must repeat those of the value the engine
/// holds, or a reload, whose words become the value again once they have
/// the identity recorded when it was spilled.
pub struct StoredValueRead {
    index: usize,
    hash: IdentityHasher,
    length: usize,
    received: usize,
    kind: StoredKind,
}

enum StoredKind {
    /// Whether every word so far repeats the resident value's.
    Readback(bool),
    Reload(Ciphertext),
}
impl Engine {
    pub fn decode_polynomial(&self, bytes: &[u8]) -> Result<Polynomial, Refusal> {
        let mut decoder = self.polynomial_decoder();
        self.decode_into(&mut decoder, bytes)?;
        self.finish_polynomial(decoder)
    }

    pub fn polynomial_decoder(&self) -> PolynomialDecoder {
        PolynomialDecoder {
            output: self.arithmetic.zero(),
            decoded: 0,
            partial: Vec::with_capacity(self.coefficient_bytes()),
        }
    }

    /// Decodes the coefficients the next piece of bytes completes and keeps
    /// the bytes of one it splits.
    pub fn decode_into(
        &self,
        decoder: &mut PolynomialDecoder,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        let width = self.coefficient_bytes();
        let mut rest = bytes;
        if !decoder.partial.is_empty() {
            let taken = (width - decoder.partial.len()).min(rest.len());
            decoder.partial.extend_from_slice(&rest[..taken]);
            rest = &rest[taken..];
            if decoder.partial.len() < width {
                return Ok(());
            }
            let partial = std::mem::take(&mut decoder.partial);
            self.decode_coefficient(decoder, &partial)?;
            decoder.partial = partial;
            decoder.partial.clear();
        }
        let whole = rest.len() - rest.len() % width;
        for coefficient in rest[..whole].chunks_exact(width) {
            self.decode_coefficient(decoder, coefficient)?;
        }
        decoder.partial.extend_from_slice(&rest[whole..]);
        Ok(())
    }

    fn decode_coefficient(
        &self,
        decoder: &mut PolynomialDecoder,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        if decoder.decoded == DEGREE {
            return Err(Refusal::Shape);
        }
        let words = self.arithmetic.words;
        let mut magnitude = [0u64; MAXIMUM_WORDS];
        let magnitude = &mut magnitude[..words];
        for (index, byte) in bytes[1..].iter().enumerate() {
            magnitude[index / 8] |= u64::from(*byte) << (8 * (index % 8));
        }
        let zero = magnitude.iter().all(|word| *word == 0);
        if bytes[0] > 1 || larger(magnitude, &self.arithmetic.wide.half) || (bytes[0] == 1 && zero)
        {
            return Err(Refusal::Coefficient);
        }
        let coefficient =
            &mut decoder.output[decoder.decoded * words..(decoder.decoded + 1) * words];
        if bytes[0] == 1 {
            self.arithmetic.wide.negate(magnitude, coefficient);
        } else {
            coefficient.copy_from_slice(magnitude);
        }
        decoder.decoded += 1;
        Ok(())
    }

    /// The decoded polynomial, once every coefficient arrived whole.
    pub fn finish_polynomial(&self, decoder: PolynomialDecoder) -> Result<Polynomial, Refusal> {
        if decoder.decoded != DEGREE || !decoder.partial.is_empty() {
            return Err(Refusal::Shape);
        }
        Ok(decoder.output)
    }

    pub(super) fn validate_polynomial(&self, polynomial: &[u64]) -> Result<(), Refusal> {
        if polynomial.len() != self.arithmetic.polynomial_words()
            || !self
                .arithmetic
                .coefficients(polynomial)
                .all(|coefficient| self.arithmetic.wide.is_canonical(coefficient))
        {
            return Err(Refusal::Coefficient);
        }
        Ok(())
    }

    /// Checks that both components are canonical polynomials of the
    /// profile's ciphertext modulus.
    pub fn validate_value(&self, value: &Ciphertext) -> Result<(), Refusal> {
        value
            .iter()
            .try_for_each(|polynomial| self.validate_polynomial(polynomial))
    }

    /// Absorbs a stored value's bytes in order; see [`stored_bytes`].
    pub(super) fn value_hasher(&self, index: usize) -> Result<IdentityHasher, Refusal> {
        IdentityHasher::new(
            EVALUATION_VALUE_DOMAIN,
            &[
                CanonicalItem::hash512(self.program_hash),
                CanonicalItem::unsigned64(index as u64),
            ],
            stored_value_bytes(self.profile),
        )
        .map_err(|_| Refusal::Identity)
    }

    /// Starts reading back a value that this step spills, whose words the
    /// read's bytes must repeat.
    pub fn begin_readback(&self, index: usize) -> Result<StoredValueRead, Refusal> {
        self.value(index)?;
        Ok(StoredValueRead {
            index,
            hash: self.value_hasher(index)?,
            length: stored_value_bytes(self.profile),
            received: 0,
            kind: StoredKind::Readback(true),
        })
    }

    /// Starts reloading a stored value, whose words it decodes as they
    /// arrive.
    pub fn begin_reload(&self, index: usize) -> Result<StoredValueRead, Refusal> {
        Ok(StoredValueRead {
            index,
            hash: self.value_hasher(index)?,
            length: stored_value_bytes(self.profile),
            received: 0,
            kind: StoredKind::Reload([self.arithmetic.zero(), self.arithmetic.zero()]),
        })
    }

    /// Absorbs the next piece of a stored value's bytes, a whole number of
    /// words: a readback's words are compared with the resident value's and
    /// a reload's decoded. Only the stored bytes are hashed, so a spill
    /// hashes its value once, for the identity its reload must have.
    pub fn push_read(&self, read: &mut StoredValueRead, bytes: &[u8]) -> Result<(), Refusal> {
        if !bytes.len().is_multiple_of(8) || bytes.len() > read.length - read.received {
            return Err(Refusal::Shape);
        }
        read.hash.absorb(bytes).map_err(|_| Refusal::Identity)?;
        let (first, count) = (read.received / 8, bytes.len() / 8);
        let words = bytes
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()));
        match &mut read.kind {
            StoredKind::Readback(repeats) => {
                let value = self.value(read.index)?;
                *repeats &= covered_words(value, first, count)
                    .zip(words)
                    .all(|(held, word)| *held == word);
            }
            StoredKind::Reload(value) => {
                for (held, word) in covered_words_mut(value, first, count).zip(words) {
                    *held = word;
                }
            }
        }
        read.received += bytes.len();
        Ok(())
    }

    /// Retires a read-back value to storage under its bytes' identity once
    /// they repeat the value this step spills, or makes a reloaded one
    /// resident again once its bytes have the identity recorded when it was
    /// spilled.
    pub fn finish_read(&mut self, read: StoredValueRead) -> Result<(), Refusal> {
        let StoredValueRead {
            index,
            hash,
            length,
            received,
            kind,
        } = read;
        if received != length {
            return Err(Refusal::Shape);
        }
        let identity = hash.finish().map_err(|_| Refusal::Identity)?;
        let required = self.requirements()?;
        match kind {
            StoredKind::Readback(repeats) => {
                if !required.spills.contains(&index) || !repeats {
                    return Err(Refusal::Identity);
                }
                self.stored[index] = Some(identity);
                self.values[index] = None;
            }
            StoredKind::Reload(value) => {
                if !required.reloads.contains(&index) || self.stored[index] != Some(identity) {
                    return Err(Refusal::Identity);
                }
                self.validate_value(&value)?;
                self.values[index] = Some(value);
            }
        }
        Ok(())
    }
}
