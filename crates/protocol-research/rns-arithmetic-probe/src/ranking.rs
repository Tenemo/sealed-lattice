use super::{Arithmetic, Polynomial, Transformed, unpack};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use registration_credentials::{
    foundation::CanonicalItem,
    identity::{IdentityHasher, identity},
};
use std::collections::BTreeSet;
pub use supported_profile::DEGREE;
use supported_profile::{PLAINTEXT_MODULUS, Profile};

#[path = "ranking-plaintext.rs"]
mod plaintext;
#[cfg(feature = "numerical-probes")]
#[path = "requested-output-probe.rs"]
mod requested_output;
#[cfg(feature = "numerical-probes")]
pub use requested_output::probe as requested_output_probe;

/// The browser's memory bound, the reserve for the runtime and the
/// module's own state, and the reserve for the host's transfer buffers.
const MEMORY_BYTES: usize = 671_088_640;
const RUNTIME_RESERVE_BYTES: usize = 67_108_864;
const TRANSFER_RESERVE_BYTES: usize = 2_097_152;
/// Each transform owns four tables of a word per coefficient.
const TRANSFORM_TABLES: usize = 4;
/// Every supported profile's ranking program is shorter.
pub const MAXIMUM_INSTRUCTIONS: usize = 1024;
/// The identity of a ranking program's complete bytecode.
const RANKING_PROGRAM_DOMAIN: &str = "sealed-lattice/ranking-program/v1";
/// The identity of one stored working value under its program and index.
const EVALUATION_VALUE_DOMAIN: &str = "sealed-lattice/public-evaluation-work/v2";

pub fn program_identity(program: &[u8]) -> Result<[u8; 64], Refusal> {
    identity(RANKING_PROGRAM_DOMAIN, program).map_err(|_| Refusal::Program)
}

pub type Ciphertext = [Polynomial; 2];

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Program,
    Phase,
    Shape,
    Coefficient,
    Identity,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    Multiplication,
    Rotation,
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub operation: u32,
    pub inputs: Vec<usize>,
    pub parameter: u32,
}

pub struct Requirements {
    pub step: usize,
    pub cache: Option<Cache>,
    pub key_count: usize,
    pub spills: Vec<usize>,
    pub reloads: Vec<usize>,
    pub input_position: Option<usize>,
}

pub struct Engine {
    profile: Profile,
    arithmetic: Arithmetic,
    program_hash: [u8; 64],
    instructions: Vec<Instruction>,
    remaining_uses: Vec<usize>,
    values: Vec<Option<Ciphertext>>,
    stored: Vec<Option<[u8; 64]>>,
    step: usize,
    cache: Option<Cache>,
    keys: Vec<Transformed>,
    input: Option<Ciphertext>,
    comparison_coefficients: Vec<i32>,
    ranking_coefficients: Vec<Vec<i32>>,
    input_offset: Vec<i32>,
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

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
fn evictions(
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
/// Splits stored bytes into the two components' words. The engine checks a
/// readback's shape and retained identity before it uses the value.
pub fn stored_value(bytes: &[u8]) -> Result<Ciphertext, Refusal> {
    if !bytes.len().is_multiple_of(16) {
        return Err(Refusal::Shape);
    }
    let (first, second) = bytes.split_at(bytes.len() / 2);
    let words = |bytes: &[u8]| {
        bytes
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
            .collect()
    };
    Ok([words(first), words(second)])
}

impl Engine {
    /// Checks a ranking program for the profile: an input for every roster
    /// position, comparison weights of the profile's odd comparison degree,
    /// rank weights of one requested result length and every intermediate
    /// value used.
    pub fn new(profile: Profile, program: &[u8], expected_hash: [u8; 64]) -> Result<Self, Refusal> {
        if program.len() < 16 || &program[..4] != b"BRK1" || word(&program[4..8]) != DEGREE as u32 {
            return Err(Refusal::Program);
        }
        let count = word(&program[8..12]) as usize;
        if !(1..=MAXIMUM_INSTRUCTIONS).contains(&count)
            || program.len() != 16 + 16 * count
            || word(&program[12..16]) as usize != count - 1
            || program_identity(program) != Ok(expected_hash)
        {
            return Err(Refusal::Program);
        }
        let options = profile.options();
        let comparison_degree = profile.comparison_degree();
        let mut instructions = Vec::with_capacity(count);
        let mut input_positions = BTreeSet::new();
        let mut remaining_uses = vec![0; count];
        let mut top_count = None;
        for (index, bytes) in program[16..].chunks_exact(16).enumerate() {
            let operation = word(&bytes[..4]);
            let arity = match operation {
                0 => 0,
                1 | 2 => 2,
                3..=6 => 1,
                _ => return Err(Refusal::Program),
            };
            let candidates = [word(&bytes[4..8]), word(&bytes[8..12])];
            let mut inputs = Vec::with_capacity(arity);
            for (position, value) in candidates.into_iter().enumerate() {
                if position < arity {
                    if value as usize >= index {
                        return Err(Refusal::Program);
                    }
                    inputs.push(value as usize);
                    remaining_uses[value as usize] += 1;
                } else if value != u32::MAX {
                    return Err(Refusal::Program);
                }
            }
            let parameter = word(&bytes[12..]);
            let valid = match operation {
                0 => {
                    (parameter as usize) < profile.participants()
                        && input_positions.insert(parameter)
                }
                1 | 2 | 6 => parameter == 0,
                3 => (1..=comparison_degree).contains(&(parameter as usize)) && parameter % 2 == 1,
                4 => {
                    (parameter as usize) < options * options
                        && !(parameter as usize).is_multiple_of(options)
                }
                5 => (parameter as usize) < options + 2,
                _ => false,
            };
            if !valid {
                return Err(Refusal::Program);
            }
            // Rank weights of family zero give the complete ordering; family
            // k gives the first k ranks.
            let declared_top_count = match operation {
                4 => Some(match parameter as usize / options {
                    0 => options,
                    value => value,
                }),
                5 if parameter >= 2 => Some(match parameter {
                    2 => options,
                    value => value as usize - 2,
                }),
                _ => None,
            };
            if let Some(declared) = declared_top_count {
                if top_count.is_some_and(|existing| existing != declared) {
                    return Err(Refusal::Program);
                }
                top_count = Some(declared);
            }
            instructions.push(Instruction {
                operation,
                inputs,
                parameter,
            });
        }
        if input_positions.len() != profile.participants()
            || remaining_uses[..count - 1].contains(&0)
        {
            return Err(Refusal::Program);
        }
        remaining_uses[count - 1] = 1;
        let (comparison_coefficients, ranking_coefficients, input_offset) =
            plaintext::parameters(profile, top_count.unwrap_or(options));
        Ok(Self {
            profile,
            arithmetic: Arithmetic::new(profile, DEGREE),
            program_hash: expected_hash,
            instructions,
            remaining_uses,
            values: (0..count).map(|_| None).collect(),
            stored: vec![None; count],
            step: 0,
            cache: None,
            keys: Vec::new(),
            input: None,
            comparison_coefficients,
            ranking_coefficients,
            input_offset,
        })
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn instruction(&self) -> Option<&Instruction> {
        self.instructions.get(self.step)
    }

    pub fn step(&self) -> usize {
        self.step
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Bytes of one canonical public coefficient: a sign byte and the
    /// magnitude.
    pub fn coefficient_bytes(&self) -> usize {
        1 + self.profile.ciphertext_modulus().byte_length()
    }

    /// The zero ciphertext, which an absent ballot contributes.
    pub fn zero_value(&self) -> Ciphertext {
        std::array::from_fn(|_| self.arithmetic.zero())
    }

    pub fn requirements(&mut self) -> Result<Requirements, Refusal> {
        let instruction = self.instructions.get(self.step).ok_or(Refusal::Phase)?;
        let wanted = match instruction.operation {
            2 => Some(Cache::Multiplication),
            6 => Some(Cache::Rotation),
            _ => self.cache,
        };
        if wanted != self.cache {
            self.keys.clear();
            self.cache = wanted;
        }
        let gadget_length = self.arithmetic.gadget_length;
        let key_count = match self.cache {
            Some(Cache::Multiplication) => 4 * gadget_length,
            Some(Cache::Rotation) => 2 * gadget_length,
            None => 0,
        };
        let residue_bytes = DEGREE * 8;
        let polynomial_bytes = self.arithmetic.polynomial_words() * 8;
        let tensor_primes = self.arithmetic.tensor_primes();
        let external_primes = self.arithmetic.external_primes;
        let table_bytes = tensor_primes * TRANSFORM_TABLES * residue_bytes;
        let key_bytes = key_count * external_primes * residue_bytes;
        // A multiplication holds its four transformed tensor sources and one
        // product; a rotation holds its transformed digits and one product.
        let scratch = match instruction.operation {
            2 => 5 * tensor_primes * residue_bytes + 2 * polynomial_bytes,
            6 => (gadget_length + 1) * external_primes * residue_bytes,
            _ => 0,
        };
        let available = MEMORY_BYTES
            .checked_sub(
                RUNTIME_RESERVE_BYTES + TRANSFER_RESERVE_BYTES + table_bytes + key_bytes + scratch,
            )
            .ok_or(Refusal::Allocation)?;
        let capacity = available / (2 * polynomial_bytes);
        let required: BTreeSet<_> = instruction.inputs.iter().copied().collect();
        let reloads: Vec<_> = required
            .iter()
            .filter(|index| self.values[**index].is_none())
            .copied()
            .collect();
        if reloads.iter().any(|index| self.stored[*index].is_none()) {
            return Err(Refusal::Phase);
        }
        let resident: Vec<_> = self
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| value.as_ref().map(|_| index))
            .collect();
        let (spills, drops) = evictions(
            resident,
            &required,
            reloads.len() + 1,
            capacity,
            |value| {
                self.instructions[self.step + 1..]
                    .iter()
                    .position(|next| next.inputs.contains(&value))
                    .map_or(self.instructions.len(), |offset| self.step + 1 + offset)
            },
            |value| self.stored[value].is_some(),
        )?;
        for index in drops {
            self.values[index] = None;
        }
        Ok(Requirements {
            step: self.step,
            cache: self.cache,
            key_count,
            spills,
            reloads,
            input_position: (instruction.operation == 0).then_some(instruction.parameter as usize),
        })
    }

    /// Whether a cached key is a public common polynomial, and its setup
    /// polynomial index. A multiplication uses each gadget coordinate's
    /// encryption key, first relinearization key, second relinearization
    /// key and second relinearization common polynomial; a rotation uses
    /// each coordinate's automorphism key and common polynomial.
    pub fn key_identity(
        profile: Profile,
        cache: Cache,
        ordinal: usize,
    ) -> Result<(bool, usize), Refusal> {
        let gadget_length = profile.gadget_length();
        let (group, digit) = (ordinal / gadget_length, ordinal % gadget_length);
        let (common, component) = match (cache, group) {
            (Cache::Multiplication, 0) => (false, 1),
            (Cache::Multiplication, 1) => (false, 2),
            (Cache::Multiplication, 2) => (false, 4),
            (Cache::Multiplication, 3) => (true, 3),
            (Cache::Rotation, 0) => (false, 6),
            (Cache::Rotation, 1) => (true, 5),
            _ => return Err(Refusal::Shape),
        };
        Ok((common, profile.fhe_polynomial(digit, component)))
    }

    pub fn decode_polynomial(&self, bytes: &[u8]) -> Result<Polynomial, Refusal> {
        let width = self.coefficient_bytes();
        if bytes.len() != DEGREE * width {
            return Err(Refusal::Shape);
        }
        let half = &self.arithmetic.modulus >> 1usize;
        let mut output = Vec::with_capacity(self.arithmetic.polynomial_words());
        for bytes in bytes.chunks_exact(width) {
            let magnitude = BigUint::from_bytes_le(&bytes[1..]);
            if bytes[0] > 1 || magnitude > half || (bytes[0] == 1 && magnitude.is_zero()) {
                return Err(Refusal::Coefficient);
            }
            if bytes[0] == 1 {
                self.arithmetic
                    .push(&mut output, &(&self.arithmetic.modulus - magnitude));
            } else {
                self.arithmetic.push(&mut output, &magnitude);
            }
        }
        Ok(output)
    }

    pub fn load_key(&mut self, ordinal: usize, polynomial: Polynomial) -> Result<(), Refusal> {
        let cache = self.cache.ok_or(Refusal::Phase)?;
        Self::key_identity(self.profile, cache, ordinal)?;
        if ordinal != self.keys.len() {
            return Err(Refusal::Phase);
        }
        self.validate_polynomial(&polynomial)?;
        self.keys.push(
            self.arithmetic
                .transformed(&polynomial, self.arithmetic.external_primes),
        );
        Ok(())
    }

    fn validate_polynomial(&self, polynomial: &[u64]) -> Result<(), Refusal> {
        if polynomial.len() != self.arithmetic.polynomial_words()
            || self
                .arithmetic
                .coefficients(polynomial)
                .any(|coefficient| unpack(coefficient) >= self.arithmetic.modulus)
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

    pub fn load_input(&mut self, position: usize, value: Ciphertext) -> Result<(), Refusal> {
        let instruction = self.instruction().ok_or(Refusal::Phase)?;
        if instruction.operation != 0
            || instruction.parameter as usize != position
            || self.input.is_some()
        {
            return Err(Refusal::Phase);
        }
        self.validate_value(&value)?;
        self.input = Some(value);
        Ok(())
    }

    pub fn value(&self, index: usize) -> Result<&Ciphertext, Refusal> {
        self.values
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Refusal::Phase)
    }

    /// Absorbs a stored value's bytes in order; see [`stored_bytes`].
    pub fn value_hasher(&self, index: usize) -> Result<IdentityHasher, Refusal> {
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

    pub fn value_identity(&self, index: usize, value: &Ciphertext) -> Result<[u8; 64], Refusal> {
        let mut hash = self.value_hasher(index)?;
        let mut buffer = [0_u8; 8192];
        for polynomial in value {
            for words in polynomial.chunks(buffer.len() / 8) {
                for (bytes, word) in buffer.chunks_exact_mut(8).zip(words) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
                hash.absorb(&buffer[..8 * words.len()])
                    .map_err(|_| Refusal::Identity)?;
            }
        }
        hash.finish().map_err(|_| Refusal::Identity)
    }

    pub fn retire_to_storage(&mut self, index: usize, identity: [u8; 64]) -> Result<(), Refusal> {
        if !self.requirements()?.spills.contains(&index)
            || self.value_identity(index, self.value(index)?)? != identity
        {
            return Err(Refusal::Identity);
        }
        self.stored[index] = Some(identity);
        self.values[index] = None;
        Ok(())
    }

    pub fn reload(&mut self, index: usize, value: Ciphertext) -> Result<(), Refusal> {
        self.validate_value(&value)?;
        if !self.requirements()?.reloads.contains(&index)
            || self.stored[index] != Some(self.value_identity(index, &value)?)
        {
            return Err(Refusal::Identity);
        }
        self.values[index] = Some(value);
        Ok(())
    }

    fn add_plaintext(&self, input: &Ciphertext, coefficients: &[i32]) -> Ciphertext {
        // The plaintext scale is the rounded quotient of the ciphertext and
        // plaintext moduli.
        let delta =
            BigInt::from((&self.arithmetic.modulus + PLAINTEXT_MODULUS / 2) / PLAINTEXT_MODULUS);
        let mut constant = Vec::with_capacity(self.arithmetic.polynomial_words());
        for (value, plaintext) in self.arithmetic.coefficients(&input[0]).zip(coefficients) {
            self.arithmetic.push_normalized(
                &mut constant,
                BigInt::from(unpack(value)) + &delta * *plaintext,
            );
        }
        [constant, input[1].clone()]
    }

    fn multiply_scalar(&self, input: &Ciphertext, scalar: i32) -> Ciphertext {
        std::array::from_fn(|part| {
            let mut output = Vec::with_capacity(self.arithmetic.polynomial_words());
            for value in self.arithmetic.coefficients(&input[part]) {
                self.arithmetic
                    .push_normalized(&mut output, BigInt::from(unpack(value)) * scalar);
            }
            output
        })
    }

    pub fn execute(&mut self) -> Result<Vec<usize>, Refusal> {
        let requirements = self.requirements()?;
        if !requirements.spills.is_empty()
            || !requirements.reloads.is_empty()
            || self.keys.len() != requirements.key_count
        {
            return Err(Refusal::Phase);
        }
        let options = self.profile.options();
        let instruction = self.instructions[self.step].clone();
        let output = if instruction.operation == 0 {
            self.input.take().ok_or(Refusal::Phase)?
        } else {
            let left = self.value(instruction.inputs[0])?;
            match instruction.operation {
                1 => {
                    let right = self.value(instruction.inputs[1])?;
                    let mut output = left.clone();
                    for (value, other) in output.iter_mut().zip(right) {
                        self.arithmetic.add(value, other);
                    }
                    output
                }
                2 => self.arithmetic.relinearized_product(
                    left,
                    self.value(instruction.inputs[1])?,
                    &self.keys,
                ),
                3 => self.multiply_scalar(
                    left,
                    self.comparison_coefficients[instruction.parameter as usize],
                ),
                4 => {
                    let mut plaintext = Vec::with_capacity(self.arithmetic.polynomial_words());
                    for value in
                        &self.ranking_coefficients[instruction.parameter as usize % options]
                    {
                        self.arithmetic
                            .push_normalized(&mut plaintext, BigInt::from(*value));
                    }
                    std::array::from_fn(|part| {
                        self.arithmetic.multiply(&plaintext, &left[part], false)
                    })
                }
                5 => match instruction.parameter {
                    0 => self.add_plaintext(left, &self.input_offset),
                    1 => {
                        let mut constant = vec![0; DEGREE];
                        constant[0] = self.comparison_coefficients[0];
                        self.add_plaintext(left, &constant)
                    }
                    parameter if (parameter as usize) < options + 2 => {
                        self.add_plaintext(left, &self.ranking_coefficients[0])
                    }
                    _ => return Err(Refusal::Program),
                },
                6 => self.arithmetic.rotated(left, &self.keys),
                _ => return Err(Refusal::Program),
            }
        };
        self.values[self.step] = Some(output);
        let mut retired = Vec::new();
        for input in instruction.inputs {
            self.remaining_uses[input] -= 1;
            if self.remaining_uses[input] == 0 {
                self.values[input] = None;
                self.stored[input] = None;
                retired.push(input);
            }
        }
        self.step += 1;
        Ok(retired)
    }

    pub fn finished(&self) -> bool {
        self.step == self.instructions.len()
    }

    /// Switches the result to the profile's release modulus and encodes
    /// each coefficient as a sign byte and a magnitude.
    pub fn final_switch(&self) -> Result<Vec<u8>, Refusal> {
        if !self.finished() {
            return Err(Refusal::Phase);
        }
        let release = self.profile.release_modulus();
        let width = release.byte_length();
        let release_modulus = (BigUint::from(release.odd_factor()) << release.exponent()) + 1u32;
        let release_half = &release_modulus >> 1usize;
        let half = &self.arithmetic.modulus >> 1usize;
        let mut output = Vec::with_capacity(2 * DEGREE * (1 + width));
        for polynomial in self.value(self.step - 1)? {
            for coefficient in self.arithmetic.coefficients(polynomial) {
                let value = unpack(coefficient);
                let negative = value > half;
                let magnitude = if negative {
                    &self.arithmetic.modulus - value
                } else {
                    value
                };
                let rounded = (magnitude * &release_modulus + &half) / &self.arithmetic.modulus;
                let residue = if negative && !rounded.is_zero() {
                    &release_modulus - rounded
                } else {
                    rounded
                };
                let negative = residue > release_half;
                let magnitude = if negative {
                    &release_modulus - residue
                } else {
                    residue
                };
                let bytes = magnitude.to_bytes_le();
                if bytes.len() > width {
                    return Err(Refusal::Coefficient);
                }
                output.push(u8::from(negative));
                output.extend(&bytes);
                output.resize(output.len() + width - bytes.len(), 0);
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::{Refusal, evictions};
    use std::collections::BTreeSet;

    #[test]
    fn a_reloaded_value_evicted_again_is_dropped_rather_than_written() {
        // Four resident values, room for three and one more needed: the two
        // with the farthest next uses leave. Value 1 still has its stored
        // copy, so only value 2 is written.
        let next_use = |index: usize| [5, 9, 7, 6][index];
        assert_eq!(
            evictions(
                vec![0, 1, 2, 3],
                &BTreeSet::from([0]),
                1,
                3,
                next_use,
                |index| index == 1
            ),
            Ok((vec![2], vec![1]))
        );
        assert_eq!(
            evictions(
                vec![0, 1, 2, 3],
                &BTreeSet::from([0]),
                1,
                3,
                next_use,
                |_| false
            ),
            Ok((vec![1, 2], vec![]))
        );
    }

    #[test]
    fn a_fitting_step_evicts_nothing_and_inputs_are_never_evicted() {
        assert_eq!(
            evictions(vec![0, 1], &BTreeSet::new(), 1, 3, |_| 0, |_| false),
            Ok((vec![], vec![]))
        );
        // Equal next uses evict the larger index first.
        assert_eq!(
            evictions(vec![0, 1, 2], &BTreeSet::new(), 1, 3, |_| 4, |_| false),
            Ok((vec![2], vec![]))
        );
        assert_eq!(
            evictions(
                vec![0, 1, 2],
                &BTreeSet::from([0, 1, 2]),
                1,
                3,
                |_| 0,
                |_| true
            ),
            Err(Refusal::Allocation)
        );
    }
}
