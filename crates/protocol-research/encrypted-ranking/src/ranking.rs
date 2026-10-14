#[path = "ranking-memory.rs"]
mod memory;
#[path = "ranking-program.rs"]
mod program;
#[path = "ranking-storage.rs"]
mod storage;
use memory::{
    MEMORY_BYTES, RUNTIME_RESERVE_BYTES, TRANSFER_RESERVE_BYTES, capacity, helper_reserved_bytes,
    scratch_bytes, value_bytes,
};
pub use memory::{fewest_resident_values, helper_memory_bytes};
pub use program::{Instruction, program_identity};
use program::{Program, decode_program, peak_values};
use storage::evictions;
pub use storage::{PolynomialDecoder, StoredValueRead, stored_bytes, stored_value_bytes};

pub use super::RecordRequest;
use super::jobs::KEYED_GROUPS;
use super::word_arithmetic::{MAXIMUM_WORDS, words_of};
use super::{
    Arithmetic, KeyedWork, Polynomial, RecordContext, Step, prime_count_bounds, shared, unpack,
};
use num_bigint::BigUint;
use num_traits::Zero;
use std::{
    collections::{BTreeSet, VecDeque},
    rc::Rc,
};
pub use supported_profile::DEGREE;
use supported_profile::{PLAINTEXT_MODULUS, Profile};

#[path = "ranking-plaintext.rs"]
mod plaintext;
#[cfg(feature = "numerical-probes")]
#[path = "requested-output-probe.rs"]
mod requested_output;
#[cfg(feature = "numerical-probes")]
pub use requested_output::probe as requested_output_probe;

/// Every supported profile's ranking program is shorter.
pub const MAXIMUM_INSTRUCTIONS: usize = 1024;

pub type Ciphertext = [Polynomial; 2];
/// Bytes of one key record: a key polynomial's transformed residues modulo
/// one prime.
pub const KEY_RECORD_BYTES: usize = 8 * DEGREE;
/// The most key-record requests after the pending one that the engine names
/// for the host to read ahead.
pub(crate) const READ_AHEAD: usize = 3;

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
impl Cache {
    /// The cache's number in its key records' identities.
    fn number(self) -> u32 {
        match self {
            Self::Multiplication => 0,
            Self::Rotation => 1,
        }
    }
}

/// What an instruction's execution reached: its completion, with the
/// values whose last use it was, the key records it needs before it
/// continues, or a helper's job, by the host's number, whose end the host
/// awaits before it executes again.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    Executed(Vec<usize>),
    Records(RecordRequest),
    Waiting(u32),
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
    arithmetic: Rc<Arithmetic>,
    program_hash: [u8; 64],
    instructions: Vec<Instruction>,
    remaining_uses: Vec<usize>,
    peak_values: usize,
    /// The linear-memory bound of the instance that runs the evaluation,
    /// which caps what its capacity lets that instance hold.
    instance_bound: usize,
    values: Vec<Option<Ciphertext>>,
    stored: Vec<Option<[u8; 64]>>,
    step: usize,
    cache: Option<Cache>,
    /// The identity of each loaded key's record modulo each external-product
    /// prime, by ordinal, which the host's working storage holds.
    records: Vec<Vec<[u8; 64]>>,
    /// The last loaded key's records that the host has yet to store, in
    /// prime order.
    pending: VecDeque<Vec<u8>>,
    /// The current instruction's keyed work.
    work: Option<KeyedWork>,
    input: Option<Ciphertext>,
    comparison_coefficients: Vec<i32>,
    ranking_coefficients: Vec<Vec<i32>>,
    input_offset: Vec<i32>,
}

impl Engine {
    /// Checks a ranking program for the profile: an input for every roster
    /// position, comparison weights of the profile's odd comparison degree,
    /// rank weights of one requested result length and every intermediate
    /// value used.
    pub fn new(profile: Profile, program: &[u8]) -> Result<Self, Refusal> {
        let Program {
            program_hash,
            instructions,
            remaining_uses,
            top_count,
        } = decode_program(profile, program)?;
        let count = instructions.len();
        let (comparison_coefficients, ranking_coefficients, input_offset) =
            plaintext::parameters(profile, top_count);
        let arithmetic = shared(profile, DEGREE);
        Ok(Self {
            profile,
            arithmetic,
            program_hash,
            peak_values: peak_values(&instructions, remaining_uses.clone()),
            instance_bound: usize::MAX,
            instructions,
            remaining_uses,
            values: (0..count).map(|_| None).collect(),
            stored: vec![None; count],
            step: 0,
            cache: None,
            records: Vec::new(),
            pending: VecDeque::new(),
            work: None,
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

    /// The keys of the current cache whose records exist.
    pub fn key_count(&self) -> usize {
        self.records.len()
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

    /// The next instruction's requirements, before it starts: its cache's
    /// keys, the values to spill and reload, and its ballot input. A new
    /// cache forgets the earlier cache's records.
    pub fn requirements(&mut self) -> Result<Requirements, Refusal> {
        if self.work.is_some() || !self.pending.is_empty() {
            return Err(Refusal::Phase);
        }
        let instruction = self.instructions.get(self.step).ok_or(Refusal::Phase)?;
        let wanted = match instruction.operation {
            2 => Some(Cache::Multiplication),
            6 => Some(Cache::Rotation),
            _ => self.cache,
        };
        if wanted != self.cache {
            self.records.clear();
            self.cache = wanted;
        }
        let key_count = self.key_total(self.cache);
        let capacity = self.capacity(instruction.operation)?;
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

    /// The keys a cache uses.
    fn key_total(&self, cache: Option<Cache>) -> usize {
        let gadget_length = self.arithmetic.gadget_length;
        match cache {
            Some(Cache::Multiplication) => 2 * KEYED_GROUPS * gadget_length,
            Some(Cache::Rotation) => KEYED_GROUPS * gadget_length,
            None => 0,
        }
    }
    /// Bytes of one resident working value.
    fn value_bytes(&self) -> usize {
        value_bytes(&self.arithmetic)
    }
    fn capacity(&self, operation: u32) -> Result<usize, Refusal> {
        capacity(
            &self.arithmetic,
            operation,
            parallel_work::helpers(),
            self.instance_bound,
        )
    }
    /// Caps what the evaluation lets its instance hold at the instance's
    /// linear-memory bound, which the operation's memory plan set.
    pub fn bound_instance(&mut self, bytes: usize) {
        self.instance_bound = bytes;
    }
    /// The linear memory the evaluation's instance plans to add for it.
    /// Without helpers it runs every job itself and plans the whole target,
    /// or its instance's bound when that is lower, but the reserves. With
    /// them it plans, at the kind of instruction that needs the most, that
    /// instruction's scratch and the resident values its capacity allows,
    /// never more than the program holds at once.
    pub fn planned_memory_bytes(&self) -> usize {
        let helpers = parallel_work::helpers();
        if helpers == 0 {
            return MEMORY_BYTES
                .min(self.instance_bound)
                .saturating_sub(RUNTIME_RESERVE_BYTES + TRANSFER_RESERVE_BYTES);
        }
        let held = |operation: u32| {
            self.capacity(operation).map_or(0, |capacity| {
                scratch_bytes(&self.arithmetic, operation, helpers)
                    + capacity.min(self.peak_values) * self.value_bytes()
            })
        };
        [1, 2, 4, 6].into_iter().map(held).max().unwrap()
    }

    /// The memory one of the helpers plans for the evaluation.
    pub fn helper_planned_bytes(&self, helper: usize, helpers: usize) -> usize {
        helper_reserved_bytes(&self.arithmetic, helper, helpers)
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

    /// The records of the key of a cache and ordinal, for this program.
    fn record_context(&self, cache: Cache, ordinal: usize) -> RecordContext {
        RecordContext {
            program: self.program_hash,
            cache: cache.number(),
            ordinal,
        }
    }
    /// Loads the next key of the current cache: its record modulo each
    /// external-product prime, which the host stores, and each record's
    /// identity, which the engine keeps.
    pub fn load_key(&mut self, ordinal: usize, polynomial: Polynomial) -> Result<(), Refusal> {
        let cache = self.cache.ok_or(Refusal::Phase)?;
        Self::key_identity(self.profile, cache, ordinal)?;
        if ordinal != self.records.len() || !self.pending.is_empty() || self.work.is_some() {
            return Err(Refusal::Phase);
        }
        self.validate_polynomial(&polynomial)?;
        let (identities, records) = self
            .arithmetic
            .key_records(&polynomial, self.record_context(cache, ordinal));
        self.records.push(identities);
        self.pending = records.into();
        Ok(())
    }
    /// The next record of the last loaded key for the host to store, with
    /// its prime, in prime order.
    pub fn take_record(&mut self) -> Option<(usize, Vec<u8>)> {
        let prime = self.arithmetic.external_primes - self.pending.len();
        self.pending.pop_front().map(|record| (prime, record))
    }
    /// Up to [`READ_AHEAD`] key-record requests that the running instruction
    /// makes after its pending request, in order.
    pub fn following_requests(&self) -> Vec<RecordRequest> {
        self.work
            .as_ref()
            .map_or_else(Vec::new, |work| self.arithmetic.following(work, READ_AHEAD))
    }
    /// Takes the next key record the running instruction's request names.
    pub fn key_record(
        &mut self,
        ordinal: usize,
        prime: usize,
        record: &[u8],
    ) -> Result<(), Refusal> {
        let work = self.work.as_mut().ok_or(Refusal::Phase)?;
        if !self.arithmetic.deliver(work, ordinal, prime, record) {
            return Err(Refusal::Phase);
        }
        Ok(())
    }

    /// Takes the key records of the running instruction's pending request,
    /// which the host shared itself.
    pub fn shared_key_records(
        &mut self,
        request: RecordRequest,
        records: parallel_work::Shared,
    ) -> Result<(), Refusal> {
        let work = self.work.as_mut().ok_or(Refusal::Phase)?;
        if !self.arithmetic.deliver_shared(work, request, records) {
            return Err(Refusal::Phase);
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

    fn add_plaintext(&self, input: &Ciphertext, coefficients: &[i32]) -> Ciphertext {
        assert_eq!(coefficients.len(), DEGREE);
        let words = self.arithmetic.words;
        let wide = &self.arithmetic.wide;
        // The plaintext scale is the rounded quotient of the ciphertext and
        // plaintext moduli.
        let delta = words_of(
            &((&self.arithmetic.modulus + PLAINTEXT_MODULUS / 2) / PLAINTEXT_MODULUS),
            words,
        );
        let mut constant = input[0].clone();
        let (mut term, mut sum) = ([0u64; MAXIMUM_WORDS], [0u64; MAXIMUM_WORDS]);
        let (term, sum) = (&mut term[..words], &mut sum[..words]);
        for (value, plaintext) in constant.chunks_exact_mut(words).zip(coefficients) {
            wide.multiply_signed(&delta, i64::from(*plaintext), term);
            wide.add(value, term, sum);
            value.copy_from_slice(sum);
        }
        [constant, input[1].clone()]
    }

    fn multiply_scalar(&self, input: &Ciphertext, scalar: i32) -> Ciphertext {
        let words = self.arithmetic.words;
        std::array::from_fn(|part| {
            let mut output = self.arithmetic.zero();
            for (product, value) in output
                .chunks_exact_mut(words)
                .zip(self.arithmetic.coefficients(&input[part]))
            {
                self.arithmetic
                    .wide
                    .multiply_signed(value, i64::from(scalar), product);
            }
            output
        })
    }

    /// Executes the next instruction, or continues its keyed work: its
    /// completion, the key records it needs next, or a job to await.
    /// Refuses records whose identities differ from the loaded keys'; a
    /// refusal ends the evaluation.
    pub fn execute(&mut self) -> Result<Progress, Refusal> {
        let output = match self.work.as_mut() {
            Some(work) => match self
                .arithmetic
                .advance(work, &self.records)
                .map_err(|()| Refusal::Identity)?
            {
                Step::Records(request) => return Ok(Progress::Records(request)),
                Step::Waiting(number) => return Ok(Progress::Waiting(number)),
                Step::Done(output) => {
                    self.work = None;
                    output
                }
            },
            None => {
                let requirements = self.requirements()?;
                if !requirements.spills.is_empty()
                    || !requirements.reloads.is_empty()
                    || self.records.len() != requirements.key_count
                {
                    return Err(Refusal::Phase);
                }
                match self.start()? {
                    Some(output) => output,
                    None => return self.execute(),
                }
            }
        };
        self.values[self.step] = Some(output);
        let mut retired = Vec::new();
        for input in self.instructions[self.step].inputs.clone() {
            self.remaining_uses[input] -= 1;
            if self.remaining_uses[input] == 0 {
                self.values[input] = None;
                self.stored[input] = None;
                retired.push(input);
            }
        }
        self.step += 1;
        Ok(Progress::Executed(retired))
    }
    // Computes the instruction's output, or starts its keyed work.
    fn start(&mut self) -> Result<Option<Ciphertext>, Refusal> {
        let options = self.profile.options();
        let instruction = self.instructions[self.step].clone();
        if instruction.operation == 0 {
            return Ok(Some(self.input.take().ok_or(Refusal::Phase)?));
        }
        let left = self.value(instruction.inputs[0])?;
        let output = match instruction.operation {
            1 => {
                let right = self.value(instruction.inputs[1])?;
                let mut output = left.clone();
                for (value, other) in output.iter_mut().zip(right) {
                    self.arithmetic.add(value, other);
                }
                output
            }
            2 | 6 => {
                let cache = self.cache.ok_or(Refusal::Phase)?;
                let context = self.record_context(cache, 0);
                let work = if instruction.operation == 2 {
                    let right = self.value(instruction.inputs[1])?;
                    self.arithmetic.start_product(left, right, context)
                } else {
                    self.arithmetic.start_rotation(left, context)
                };
                self.work = Some(work);
                return Ok(None);
            }
            3 => self.multiply_scalar(
                left,
                self.comparison_coefficients[instruction.parameter as usize],
            ),
            4 => {
                let coefficients =
                    &self.ranking_coefficients[instruction.parameter as usize % options];
                assert_eq!(coefficients.len(), DEGREE);
                let plaintext = self.arithmetic.signed(coefficients);
                std::array::from_fn(|part| self.arithmetic.multiply(&plaintext, &left[part], false))
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
            _ => return Err(Refusal::Program),
        };
        Ok(Some(output))
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
#[path = "ranking-tests.rs"]
mod tests;
