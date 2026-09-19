use super::{Cache, Ciphertext, DEGREE, Engine, Refusal};
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha512};
use std::cell::RefCell;

const CHUNK_BYTES: usize = 1 << 20;

enum Destination {
    Key(usize),
    Input(usize, usize),
    Reload(usize),
    Readback(usize),
}
struct Incoming {
    destination: Destination,
    expected: [u8; 64],
    hash: Sha512,
    values: Ciphertext,
    coefficients: usize,
}
struct State {
    input: Vec<u8>,
    output: Vec<u8>,
    engine: Option<Engine>,
    incoming: Option<Incoming>,
    first_input: Option<(usize, Vec<[u64; 14]>)>,
    final_ciphertext: Option<Vec<u8>>,
}
thread_local! {
    static STATE:RefCell<State>=RefCell::new(State{input:vec![0;CHUNK_BYTES],output:Vec::with_capacity(CHUNK_BYTES),engine:None,incoming:None,first_input:None,final_ciphertext:None});
}
#[unsafe(no_mangle)]
pub extern "C" fn ranking_input_pointer() -> *mut u8 {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn ranking_output_pointer() -> *const u8 {
    STATE.with(|state| state.borrow().output.as_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn ranking_output_length() -> usize {
    STATE.with(|state| state.borrow().output.len())
}

impl State {
    fn append_word(&mut self, value: usize) {
        self.output.extend((value as u32).to_le_bytes());
    }
    fn begin(&mut self, destination: Destination, expected: [u8; 64]) -> Result<(), Refusal> {
        if self.incoming.is_some() {
            return Err(Refusal::Phase);
        }
        let engine = self.engine.as_ref().ok_or(Refusal::Phase)?;
        let (expected, hash, count) = match destination {
            Destination::Key(ordinal) => {
                Engine::key_identity(engine.cache.ok_or(Refusal::Phase)?, ordinal)?;
                if ordinal != engine.key_count() {
                    return Err(Refusal::Phase);
                }
                (expected, Sha512::new(), 1)
            }
            Destination::Input(position, part) => {
                let instruction = engine.instruction().ok_or(Refusal::Phase)?;
                if instruction.operation != 0
                    || instruction.parameter as usize != position
                    || part > 1
                    || (part == 0 && self.first_input.is_some())
                    || (part == 1
                        && self.first_input.as_ref().map(|value| value.0) != Some(position))
                {
                    return Err(Refusal::Phase);
                }
                (expected, Sha512::new(), 1)
            }
            Destination::Reload(index) => {
                let expected = engine
                    .stored
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or(Refusal::Phase)?;
                if engine.values[index].is_some() {
                    return Err(Refusal::Phase);
                }
                (expected, engine.value_hasher(index), 2)
            }
            Destination::Readback(index) => (
                engine.value_identity(index, engine.value(index)?),
                engine.value_hasher(index),
                0,
            ),
        };
        self.incoming = Some(Incoming {
            destination,
            expected,
            hash,
            values: std::array::from_fn(|part| {
                if part < count {
                    Vec::with_capacity(DEGREE)
                } else {
                    Vec::new()
                }
            }),
            coefficients: 0,
        });
        Ok(())
    }
    fn push(&mut self, offset: usize, length: usize, stored: bool) -> Result<(), Refusal> {
        let incoming = self.incoming.as_mut().ok_or(Refusal::Phase)?;
        let stored_destination = matches!(
            incoming.destination,
            Destination::Reload(_) | Destination::Readback(_)
        );
        let width = if stored { 112 } else { 109 };
        let maximum = if stored { 2 * DEGREE } else { DEGREE };
        if stored != stored_destination
            || length == 0
            || !length.is_multiple_of(width)
            || offset != incoming.coefficients
            || length / width > maximum - offset
        {
            return Err(Refusal::Shape);
        }
        let engine = self.engine.as_ref().ok_or(Refusal::Phase)?;
        let modulus = &engine.arithmetic.modulus;
        let half = modulus >> 1usize;
        incoming.hash.update(&self.input[..length]);
        for bytes in self.input[..length].chunks_exact(width) {
            if !matches!(incoming.destination, Destination::Readback(_)) {
                let coefficient = if stored {
                    let value = std::array::from_fn(|index| {
                        u64::from_le_bytes(bytes[8 * index..8 * index + 8].try_into().unwrap())
                    });
                    if super::unpack(&value) >= *modulus {
                        return Err(Refusal::Coefficient);
                    }
                    value
                } else {
                    let magnitude = BigUint::from_bytes_le(&bytes[1..]);
                    if bytes[0] > 1 || magnitude > half || (bytes[0] == 1 && magnitude.is_zero()) {
                        return Err(Refusal::Coefficient);
                    }
                    if bytes[0] == 1 {
                        super::pack(&(modulus - magnitude))
                    } else {
                        super::pack(&magnitude)
                    }
                };
                incoming.values[incoming.coefficients / DEGREE].push(coefficient);
            }
            incoming.coefficients += 1;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Refusal> {
        let incoming = self.incoming.take().ok_or(Refusal::Phase)?;
        let expected_count = if matches!(
            incoming.destination,
            Destination::Reload(_) | Destination::Readback(_)
        ) {
            2 * DEGREE
        } else {
            DEGREE
        };
        if incoming.coefficients != expected_count
            || <[u8; 64]>::from(incoming.hash.finalize()) != incoming.expected
        {
            return Err(Refusal::Identity);
        }
        let engine = self.engine.as_mut().ok_or(Refusal::Phase)?;
        match incoming.destination {
            Destination::Key(ordinal) => {
                let [value, _] = incoming.values;
                engine.load_key(ordinal, value)
            }
            Destination::Input(position, 0) => {
                let [value, _] = incoming.values;
                self.first_input = Some((position, value));
                Ok(())
            }
            Destination::Input(position, 1) => {
                let (saved, first) = self.first_input.take().ok_or(Refusal::Phase)?;
                if saved != position {
                    return Err(Refusal::Phase);
                }
                let [second, _] = incoming.values;
                engine.load_input(position, [first, second])
            }
            Destination::Input(_, _) => Err(Refusal::Phase),
            Destination::Reload(index) => engine.reload(index, incoming.values),
            Destination::Readback(index) => engine.retire_to_storage(index, incoming.expected),
        }
    }
    fn command(&mut self, operation: u32, argument: usize, length: usize) -> Result<(), Refusal> {
        if length > CHUNK_BYTES {
            return Err(Refusal::Shape);
        }
        match operation {
            0 => {
                if argument != 0
                    || !(80..=64 + 16 + 16 * 1024).contains(&length)
                    || self.engine.is_some()
                    || self.final_ciphertext.is_some()
                {
                    return Err(Refusal::Phase);
                }
                let expected = self.input[..64].try_into().unwrap();
                self.engine = Some(Engine::new(&self.input[64..length], expected)?);
                Ok(())
            }
            1 => {
                if argument != 0 || length != 0 || self.incoming.is_some() {
                    return Err(Refusal::Phase);
                }
                let engine = self.engine.as_mut().ok_or(Refusal::Phase)?;
                let requirements = engine.requirements()?;
                let loaded = engine.key_count();
                for value in [
                    requirements.step,
                    match requirements.cache {
                        None => 0,
                        Some(Cache::Multiplication) => 1,
                        Some(Cache::Rotation) => 2,
                    },
                    requirements.key_count,
                    loaded,
                    requirements.input_position.unwrap_or(u32::MAX as usize),
                    requirements.spills.len(),
                    requirements.reloads.len(),
                ] {
                    self.append_word(value);
                }
                for value in requirements.spills.into_iter().chain(requirements.reloads) {
                    self.append_word(value);
                }
                Ok(())
            }
            2 | 5 => {
                if length != 64 {
                    return Err(Refusal::Shape);
                }
                let expected = self.input[..64].try_into().unwrap();
                self.begin(
                    if operation == 2 {
                        Destination::Key(argument)
                    } else {
                        Destination::Input(argument / 2, argument % 2)
                    },
                    expected,
                )
            }
            3 => self.push(argument, length, false),
            4 => {
                if argument != 0 || length != 0 {
                    return Err(Refusal::Shape);
                }
                self.finish()
            }
            6 => {
                if length != 0 || self.incoming.is_some() || self.first_input.is_some() {
                    return Err(Refusal::Phase);
                }
                self.engine
                    .as_mut()
                    .ok_or(Refusal::Phase)?
                    .load_input(argument, std::array::from_fn(|_| vec![[0; 14]; DEGREE]))
            }
            7 => {
                if length != 8 || self.incoming.is_some() {
                    return Err(Refusal::Phase);
                }
                let offset = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let count = u32::from_le_bytes(self.input[4..8].try_into().unwrap()) as usize;
                if count == 0
                    || count > CHUNK_BYTES / 112
                    || offset > 2 * DEGREE
                    || count > 2 * DEGREE - offset
                {
                    return Err(Refusal::Shape);
                }
                let value = self
                    .engine
                    .as_ref()
                    .ok_or(Refusal::Phase)?
                    .value(argument)?;
                for position in offset..offset + count {
                    for word in value[position / DEGREE][position % DEGREE] {
                        self.output.extend(word.to_le_bytes());
                    }
                }
                Ok(())
            }
            9 | 16 => {
                if length != 0 {
                    return Err(Refusal::Shape);
                }
                self.begin(
                    if operation == 9 {
                        Destination::Reload(argument)
                    } else {
                        Destination::Readback(argument)
                    },
                    [0; 64],
                )
            }
            10 => self.push(argument, length, true),
            11 => {
                if length != 0
                    || argument != 0
                    || self.incoming.is_some()
                    || self.first_input.is_some()
                {
                    return Err(Refusal::Phase);
                }
                let retired = self.engine.as_mut().ok_or(Refusal::Phase)?.execute()?;
                self.append_word(retired.len());
                for value in retired {
                    self.append_word(value);
                }
                Ok(())
            }
            12 => {
                if length != 0 || argument != 0 || self.incoming.is_some() {
                    return Err(Refusal::Phase);
                }
                let value = self.engine.as_ref().ok_or(Refusal::Phase)?.final_switch()?;
                self.append_word(value.len());
                self.final_ciphertext = Some(value);
                self.engine = None;
                Ok(())
            }
            13 => {
                if length != 4 {
                    return Err(Refusal::Shape);
                }
                let count = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let value = self.final_ciphertext.as_ref().ok_or(Refusal::Phase)?;
                if count == 0
                    || count > CHUNK_BYTES
                    || argument > value.len()
                    || count > value.len() - argument
                {
                    return Err(Refusal::Shape);
                }
                self.output
                    .extend_from_slice(&value[argument..argument + count]);
                Ok(())
            }
            _ => Err(Refusal::Phase),
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ranking_command(operation: u32, argument: usize, length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.output.clear();
        match state.command(operation, argument, length) {
            Ok(()) => 0,
            Err(_) => {
                state.engine = None;
                state.incoming = None;
                state.first_input = None;
                state.final_ciphertext = None;
                state.output.clear();
                1
            }
        }
    })
}
