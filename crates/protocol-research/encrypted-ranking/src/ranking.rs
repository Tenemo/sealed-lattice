pub use super::RecordRequest;
use super::jobs::KEYED_GROUPS;
use super::word_arithmetic::{MAXIMUM_WORDS, larger, words_of};
use super::{
    Arithmetic, KeyedWork, Polynomial, RecordContext, Step, prime_count_bounds, shared, unpack,
};
use num_bigint::BigUint;
use num_traits::Zero;
use protocol_foundations::{
    foundation::CanonicalItem,
    identity::{IdentityHasher, identity},
};
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

/// The planning target for the peak linear memory of the evaluation's
/// instances together, the reserve for the runtime and the module's own
/// state, the reserve for the host's transfer buffers, and the reserve for
/// a helper instance's own state.
const MEMORY_BYTES: usize = 402_653_184;
const RUNTIME_RESERVE_BYTES: usize = 67_108_864;
const TRANSFER_RESERVE_BYTES: usize = 2_097_152;
const HELPER_RESERVE_BYTES: usize = 2_097_152;
/// Each transform owns two tables of a word per coefficient: the forward
/// twiddles and their Shoup companions, from which the backward transform
/// reads its own.
const TRANSFORM_TABLES: usize = 2;
/// The tensor sources a multiplication keeps at once.
const KEPT_SOURCES: usize = 3;
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
/// Bytes of one key record: a key polynomial's transformed residues modulo
/// one prime.
pub const KEY_RECORD_BYTES: usize = 8 * DEGREE;
/// The most key-record requests after the pending one that the engine names
/// for the host to read ahead.
pub const READ_AHEAD: usize = 3;

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

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

/// The memory a helper keeps for evaluation beside its jobs' own when it
/// holds the given counts of tensor and external-product primes: their
/// transform tables and the transformed polynomials a multiplication keeps
/// there, its tensor sources or one prime's digits, since a helper runs the
/// last keyed job of a prime before the next prime's digits.
fn helper_kept_bytes(tensor_primes: usize, external_primes: usize, gadget_length: usize) -> usize {
    let residue_bytes = DEGREE * 8;
    tensor_primes * TRANSFORM_TABLES * residue_bytes
        + (KEPT_SOURCES * tensor_primes).max(gadget_length * external_primes.min(1)) * residue_bytes
}
/// The memory a helper instance keeps for evaluation beside its running
/// job's, one of `helpers` helpers that hold the primes in turn, for the
/// profile that needs the most. An instance computes it before its first
/// allocation, so it allocates nothing.
pub fn helper_memory_bytes(helpers: usize) -> usize {
    let held = |count: usize| count.div_ceil(helpers.max(1));
    Profile::all()
        .map(|profile| {
            let (tensor_primes, external_primes) = prime_count_bounds(profile, DEGREE);
            helper_kept_bytes(
                held(tensor_primes),
                held(external_primes),
                profile.gadget_length(),
            )
        })
        .max()
        .unwrap()
}
/// The memory one of the helpers reserves for the evaluation: what it
/// keeps for the primes it holds and one job.
fn helper_reserved_bytes(arithmetic: &Arithmetic, helper: usize, helpers: usize) -> usize {
    let held = |count: usize| (helper..count).step_by(helpers).count();
    helper_kept_bytes(
        held(arithmetic.tensor_primes()),
        held(arithmetic.external_primes),
        arithmetic.gadget_length,
    ) + arithmetic.job_bytes(helpers)
}
/// What the helpers' instances hold for the evaluation: each one's
/// reservation beside the reserve for its own state.
fn helpers_reserved_bytes(arithmetic: &Arithmetic, helpers: usize) -> usize {
    (0..helpers)
        .map(|helper| HELPER_RESERVE_BYTES + helper_reserved_bytes(arithmetic, helper, helpers))
        .sum()
}
/// The fewest resident values that any kind of instruction of the profile's
/// evaluation allows an instance of the bound beside the helpers.
pub fn fewest_resident_values(
    profile: Profile,
    helpers: usize,
    bound: usize,
) -> Result<usize, Refusal> {
    let arithmetic = shared(profile, DEGREE);
    [1, 2, 4, 6]
        .into_iter()
        .try_fold(usize::MAX, |fewest, operation| {
            Ok(fewest.min(capacity(&arithmetic, operation, helpers, bound)?))
        })
}

/// Bytes of one resident working value.
fn value_bytes(arithmetic: &Arithmetic) -> usize {
    2 * arithmetic.polynomial_words() * 8
}
/// The memory an instruction of the operation adds in the instance that
/// runs it beside its inputs and output: a multiplication holds three
/// lifted tensors beside one tensor's products, and later two of them
/// beside a keyed product's sums and a delivered group's records; a
/// plaintext product holds the plaintext beside one component's products; a
/// rotation holds its automorphic components, and later one of them beside
/// the same. Each key a keyed instruction loads before it starts holds its
/// polynomial beside its records. With helpers the instance also holds the
/// data it moves for one job beside those. Without them it keeps what they
/// would, since it runs each job as it starts: at most three transformed
/// tensor sources, a plaintext product's copied component and its
/// products' bytes, a keyed product's polynomial and one prime's digits, or
/// a loaded key's copied polynomial.
fn scratch_bytes(arithmetic: &Arithmetic, operation: u32, helpers: usize) -> usize {
    let residue_bytes = DEGREE * 8;
    let polynomial_bytes = arithmetic.polynomial_words() * 8;
    let kept = usize::from(helpers == 0);
    let moved = |bytes: usize| usize::from(helpers > 0) * bytes;
    let tensor = 3 * polynomial_bytes
        + (1 + kept * KEPT_SOURCES) * arithmetic.tensor_primes() * residue_bytes
        + moved(arithmetic.transfer_bytes(arithmetic.tensor_primes(), false, helpers));
    let keyed = kept * polynomial_bytes
        + (2 * arithmetic.external_primes + (1 + kept) * arithmetic.gadget_length) * residue_bytes
        + moved(arithmetic.transfer_bytes(arithmetic.external_primes, true, helpers));
    let load = (1 + kept) * polynomial_bytes
        + arithmetic.external_primes * residue_bytes
        + moved(arithmetic.records_transfer_bytes(helpers));
    match operation {
        2 => tensor.max(2 * polynomial_bytes + keyed).max(load),
        4 => {
            (1 + kept) * (polynomial_bytes + arithmetic.key_primes * residue_bytes)
                + moved(arithmetic.transfer_bytes(arithmetic.key_primes, false, helpers))
        }
        6 => (2 * polynomial_bytes)
            .max(polynomial_bytes + keyed)
            .max(load),
        _ => 0,
    }
}
/// The resident values an instruction of the operation allows within the
/// planning target and the bound of the instance that runs it. Without
/// helpers the instance also holds the transform tables and one job; with
/// them each helper holds its reservation at every instruction, since an
/// instance's memory never shrinks, and the instance keeps what they leave
/// of the target.
fn capacity(
    arithmetic: &Arithmetic,
    operation: u32,
    helpers: usize,
    bound: usize,
) -> Result<usize, Refusal> {
    let (helpers_hold, instance_holds) = if helpers == 0 {
        (
            0,
            arithmetic.tensor_primes() * TRANSFORM_TABLES * DEGREE * 8 + arithmetic.job_bytes(0),
        )
    } else {
        (helpers_reserved_bytes(arithmetic, helpers), 0)
    };
    let available = MEMORY_BYTES
        .checked_sub(helpers_hold)
        .ok_or(Refusal::Allocation)?
        .min(bound)
        .checked_sub(
            RUNTIME_RESERVE_BYTES
                + TRANSFER_RESERVE_BYTES
                + instance_holds
                + scratch_bytes(arithmetic, operation, helpers),
        )
        .ok_or(Refusal::Allocation)?;
    Ok(available / value_bytes(arithmetic))
}

/// The most values a program holds at once when each stays from its
/// instruction until its last use, given each value's count of uses.
fn peak_values(instructions: &[Instruction], mut remaining_uses: Vec<usize>) -> usize {
    let (mut held, mut peak) = (0usize, 0usize);
    for instruction in instructions {
        held += 1;
        peak = peak.max(held);
        for input in &instruction.inputs {
            remaining_uses[*input] -= 1;
            if remaining_uses[*input] == 0 {
                held -= 1;
            }
        }
    }
    peak
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

impl Engine {
    /// Checks a ranking program for the profile: an input for every roster
    /// position, comparison weights of the profile's odd comparison degree,
    /// rank weights of one requested result length and every intermediate
    /// value used.
    pub fn new(profile: Profile, program: &[u8]) -> Result<Self, Refusal> {
        if program.len() < 16 || &program[..4] != b"BRK1" || word(&program[4..8]) != DEGREE as u32 {
            return Err(Refusal::Program);
        }
        let count = word(&program[8..12]) as usize;
        if !(1..=MAXIMUM_INSTRUCTIONS).contains(&count)
            || program.len() != 16 + 16 * count
            || word(&program[12..16]) as usize != count - 1
        {
            return Err(Refusal::Program);
        }
        let program_hash = program_identity(program)?;
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

    fn validate_polynomial(&self, polynomial: &[u64]) -> Result<(), Refusal> {
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
    fn value_hasher(&self, index: usize) -> Result<IdentityHasher, Refusal> {
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
