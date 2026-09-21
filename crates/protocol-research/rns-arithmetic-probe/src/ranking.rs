use super::{Arithmetic, Polynomial, Transformed, pack, unpack};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;

#[path = "ranking-plaintext.rs"]
mod plaintext;
#[path = "requested-output-probe.rs"]
mod requested_output;
pub use requested_output::probe as requested_output_probe;

#[cfg(target_arch = "wasm32")]
#[path = "ranking-browser.rs"]
mod browser;

pub const DEGREE: usize = 65_536;
const OPTION_COUNT: usize = 10;
pub const COEFFICIENT_BYTES: usize = 109;
pub const STORED_COEFFICIENT_BYTES: usize = 112;
pub type Ciphertext = [Vec<[u64; 14]>; 2];

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

impl Engine {
    pub fn new(program: &[u8], expected_hash: [u8; 64]) -> Result<Self, Refusal> {
        if program.len() < 16 || &program[..4] != b"BRK1" || word(&program[4..8]) != DEGREE as u32 {
            return Err(Refusal::Program);
        }
        let count = word(&program[8..12]) as usize;
        if !(1..=1024).contains(&count)
            || program.len() != 16 + 16 * count
            || word(&program[12..16]) as usize != count - 1
            || <[u8; 64]>::from(Sha512::digest(program)) != expected_hash
        {
            return Err(Refusal::Program);
        }
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
                0 => parameter < 10 && input_positions.insert(parameter),
                1 | 2 | 6 => parameter == 0,
                3 => (1..=181).contains(&parameter) && parameter % 2 == 1,
                4 => {
                    parameter < (OPTION_COUNT * OPTION_COUNT) as u32
                        && !parameter.is_multiple_of(OPTION_COUNT as u32)
                }
                5 => parameter < (OPTION_COUNT + 2) as u32,
                _ => false,
            };
            if !valid {
                return Err(Refusal::Program);
            }
            let declared_top_count = match operation {
                4 => Some(match parameter as usize / OPTION_COUNT {
                    0 => OPTION_COUNT,
                    value => value,
                }),
                5 if parameter >= 2 => Some(match parameter {
                    2 => OPTION_COUNT,
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
        if input_positions.len() != 10 || remaining_uses[..count - 1].contains(&0) {
            return Err(Refusal::Program);
        }
        remaining_uses[count - 1] = 1;
        let (comparison_coefficients, ranking_coefficients, input_offset) =
            plaintext::parameters(top_count.unwrap_or(OPTION_COUNT));
        Ok(Self {
            arithmetic: Arithmetic::new(DEGREE),
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

    pub fn instruction(&self) -> Option<&Instruction> {
        self.instructions.get(self.step)
    }

    pub fn step(&self) -> usize {
        self.step
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
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
        let key_count = match self.cache {
            Some(Cache::Multiplication) => 24,
            Some(Cache::Rotation) => 12,
            None => 0,
        };
        let polynomial_bytes = DEGREE * 14 * 8;
        let table_bytes = 31 * 4 * DEGREE * 8;
        let key_bytes = key_count * 18 * DEGREE * 8;
        let scratch = match instruction.operation {
            2 => 5 * 31 * DEGREE * 8 + 2 * polynomial_bytes,
            6 => 7 * 18 * DEGREE * 8,
            _ => 0,
        };
        let available = 671_088_640usize
            .checked_sub(67_108_864 + 2_097_152 + table_bytes + key_bytes + scratch)
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
        let mut resident: Vec<_> = self
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| value.as_ref().map(|_| index))
            .collect();
        let mut spills = Vec::new();
        while resident.len() + reloads.len() + 1 > capacity {
            let next_use = |value: usize| {
                self.instructions[self.step + 1..]
                    .iter()
                    .position(|next| next.inputs.contains(&value))
                    .map_or(self.instructions.len(), |offset| self.step + 1 + offset)
            };
            let evicted = resident
                .iter()
                .filter(|index| !required.contains(index))
                .max_by_key(|index| (next_use(**index), **index))
                .copied()
                .ok_or(Refusal::Allocation)?;
            resident.retain(|index| *index != evicted);
            spills.push(evicted);
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

    pub fn key_identity(cache: Cache, ordinal: usize) -> Result<(bool, usize), Refusal> {
        let (group, digit) = (ordinal / 6, ordinal % 6);
        let (common, offset) = match (cache, group) {
            (Cache::Multiplication, 0) => (false, 1),
            (Cache::Multiplication, 1) => (false, 2),
            (Cache::Multiplication, 2) => (false, 4),
            (Cache::Multiplication, 3) => (true, 3),
            (Cache::Rotation, 0) => (false, 6),
            (Cache::Rotation, 1) => (true, 5),
            _ => return Err(Refusal::Shape),
        };
        Ok((common, 7 * digit + offset))
    }

    pub fn decode_polynomial(&self, bytes: &[u8]) -> Result<Polynomial, Refusal> {
        if bytes.len() != DEGREE * COEFFICIENT_BYTES {
            return Err(Refusal::Shape);
        }
        bytes
            .chunks_exact(COEFFICIENT_BYTES)
            .map(|bytes| {
                let magnitude = BigUint::from_bytes_le(&bytes[1..]);
                if bytes[0] > 1
                    || magnitude > (&self.arithmetic.modulus >> 1usize)
                    || (bytes[0] == 1 && magnitude.is_zero())
                {
                    return Err(Refusal::Coefficient);
                }
                Ok(if bytes[0] == 1 {
                    pack(&(&self.arithmetic.modulus - magnitude))
                } else {
                    pack(&magnitude)
                })
            })
            .collect()
    }

    pub fn load_key(&mut self, ordinal: usize, polynomial: Polynomial) -> Result<(), Refusal> {
        let cache = self.cache.ok_or(Refusal::Phase)?;
        Self::key_identity(cache, ordinal)?;
        if ordinal != self.keys.len() || polynomial.len() != DEGREE {
            return Err(Refusal::Phase);
        }
        self.validate_polynomial(&polynomial)?;
        self.keys.push(self.arithmetic.transformed(&polynomial, 18));
        Ok(())
    }

    fn validate_polynomial(&self, polynomial: &Polynomial) -> Result<(), Refusal> {
        if polynomial.len() != DEGREE
            || polynomial
                .iter()
                .any(|coefficient| unpack(coefficient) >= self.arithmetic.modulus)
        {
            return Err(Refusal::Coefficient);
        }
        Ok(())
    }

    pub fn load_input(&mut self, position: usize, value: Ciphertext) -> Result<(), Refusal> {
        let instruction = self.instruction().ok_or(Refusal::Phase)?;
        if instruction.operation != 0
            || instruction.parameter as usize != position
            || self.input.is_some()
        {
            return Err(Refusal::Phase);
        }
        for polynomial in &value {
            self.validate_polynomial(polynomial)?;
        }
        self.input = Some(value);
        Ok(())
    }

    pub fn value(&self, index: usize) -> Result<&Ciphertext, Refusal> {
        self.values
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Refusal::Phase)
    }

    pub fn value_hasher(&self, index: usize) -> Sha512 {
        let mut hash = Sha512::new();
        hash.update(b"sealed-lattice/public-evaluation-work/1");
        hash.update(self.program_hash);
        hash.update((index as u32).to_le_bytes());
        hash
    }

    pub fn value_identity(&self, index: usize, value: &Ciphertext) -> [u8; 64] {
        let mut hash = self.value_hasher(index);
        for polynomial in value {
            for coefficient in polynomial {
                for word in coefficient {
                    hash.update(word.to_le_bytes());
                }
            }
        }
        hash.finalize().into()
    }

    pub fn retire_to_storage(&mut self, index: usize, identity: [u8; 64]) -> Result<(), Refusal> {
        if !self.requirements()?.spills.contains(&index)
            || self.value_identity(index, self.value(index)?) != identity
        {
            return Err(Refusal::Identity);
        }
        self.stored[index] = Some(identity);
        self.values[index] = None;
        Ok(())
    }

    pub fn reload(&mut self, index: usize, value: Ciphertext) -> Result<(), Refusal> {
        for polynomial in &value {
            self.validate_polynomial(polynomial)?;
        }
        if !self.requirements()?.reloads.contains(&index)
            || self.stored[index] != Some(self.value_identity(index, &value))
        {
            return Err(Refusal::Identity);
        }
        self.values[index] = Some(value);
        Ok(())
    }

    fn multiply(&self, left: &Ciphertext, right: &Ciphertext) -> Ciphertext {
        let [mut constant, mut linear, other_linear, quadratic] =
            self.arithmetic.tensors(left, right);
        self.arithmetic.add(&mut linear, &other_linear);
        drop(other_linear);
        let digits = self.arithmetic.digit_transforms(&quadratic);
        let intermediate = self.arithmetic.external(&digits, &self.keys[..6]);
        self.arithmetic.add(
            &mut linear,
            &self.arithmetic.external(&digits, &self.keys[6..12]),
        );
        drop(digits);
        drop(quadratic);
        let digits = self.arithmetic.digit_transforms(&intermediate);
        self.arithmetic.add(
            &mut constant,
            &self.arithmetic.external(&digits, &self.keys[12..18]),
        );
        self.arithmetic.add(
            &mut linear,
            &self.arithmetic.external(&digits, &self.keys[18..24]),
        );
        [constant, linear]
    }

    fn automorphism(&self, polynomial: &Polynomial) -> Polynomial {
        let mut output = vec![[0; 14]; DEGREE];
        for (index, value) in polynomial.iter().enumerate() {
            let exponent = index * 5;
            output[exponent % DEGREE] =
                if (exponent / DEGREE).is_multiple_of(2) || value.iter().all(|word| *word == 0) {
                    *value
                } else {
                    pack(&(&self.arithmetic.modulus - unpack(value)))
                };
        }
        output
    }

    fn add_plaintext(&self, input: &Ciphertext, coefficients: &[i32]) -> Ciphertext {
        let delta = BigInt::from((&self.arithmetic.modulus - 1u32) / 65537u32);
        let mut output = input.clone();
        for (value, plaintext) in output[0].iter_mut().zip(coefficients) {
            *value = self
                .arithmetic
                .normalize(BigInt::from(unpack(value)) + &delta * *plaintext);
        }
        output
    }

    pub fn execute(&mut self) -> Result<Vec<usize>, Refusal> {
        let requirements = self.requirements()?;
        if !requirements.spills.is_empty()
            || !requirements.reloads.is_empty()
            || self.keys.len() != requirements.key_count
        {
            return Err(Refusal::Phase);
        }
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
                2 => self.multiply(left, self.value(instruction.inputs[1])?),
                3 => {
                    let scalar = self.comparison_coefficients[instruction.parameter as usize];
                    std::array::from_fn(|part| {
                        left[part]
                            .iter()
                            .map(|value| {
                                self.arithmetic
                                    .normalize(BigInt::from(unpack(value)) * scalar)
                            })
                            .collect()
                    })
                }
                4 => {
                    let plaintext: Polynomial = self.ranking_coefficients
                        [instruction.parameter as usize % OPTION_COUNT]
                        .iter()
                        .map(|value| self.arithmetic.normalize(BigInt::from(*value)))
                        .collect();
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
                    parameter if parameter < (OPTION_COUNT + 2) as u32 => {
                        self.add_plaintext(left, &self.ranking_coefficients[0])
                    }
                    _ => return Err(Refusal::Program),
                },
                6 => {
                    let mut constant = self.automorphism(&left[0]);
                    let shifted = self.automorphism(&left[1]);
                    let digits = self.arithmetic.digit_transforms(&shifted);
                    self.arithmetic.add(
                        &mut constant,
                        &self.arithmetic.external(&digits, &self.keys[..6]),
                    );
                    [
                        constant,
                        self.arithmetic.external(&digits, &self.keys[6..12]),
                    ]
                }
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

    pub fn final_switch(&self) -> Result<Vec<u8>, Refusal> {
        if !self.finished() {
            return Err(Refusal::Phase);
        }
        let release_modulus = ((BigUint::from(65537u32) * 65445u32) << 160usize) + 1u32;
        let release_half = &release_modulus >> 1usize;
        let half = &self.arithmetic.modulus >> 1usize;
        let mut output = Vec::with_capacity(2 * DEGREE * 25);
        for polynomial in self.value(self.step - 1)? {
            for coefficient in polynomial {
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
                if bytes.len() > 24 {
                    return Err(Refusal::Coefficient);
                }
                output.push(u8::from(negative));
                output.extend(&bytes);
                output.resize(output.len() + 24 - bytes.len(), 0);
            }
        }
        Ok(output)
    }
}
