use crate::target::{
    ClassifiedClosedInventory, Error, EvaluationSession, VerifiedEvaluationTarget,
};
use ballot_proof::body::BallotBodyClassification;
use num_bigint::Sign;
use registration_credentials::{
    ballot_body::{BallotBodyHasher, HEADER_BYTES},
    poll::VerifiedPoll,
};
use rns_arithmetic_probe::ranking::{COEFFICIENT_BYTES, Ciphertext, DEGREE, Engine};
use setup_aggregate::verified::VerifiedSetupAggregate;
use sha2::{Digest, Sha512};
use std::{cell::RefCell, sync::Arc};

const CHUNK_BYTES: usize = 1 << 20;
enum Destination {
    Key(usize),
    Ballot(usize),
    Readback(usize),
    Reload(usize),
}
struct Incoming {
    destination: Destination,
    length: usize,
    received: usize,
    bytes: Vec<u8>,
    hash: Sha512,
    expected: Option<[u8; 64]>,
    ballot_hash: Option<BallotBodyHasher>,
}
struct State {
    input: Vec<u8>,
    output: Vec<u8>,
    context: Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>,
    classifications: Vec<Option<BallotBodyClassification>>,
    session: Option<EvaluationSession>,
    incoming: Option<Incoming>,
    target: Option<Arc<VerifiedEvaluationTarget>>,
}
impl State {
    fn new() -> Self {
        Self {
            input: vec![0; CHUNK_BYTES],
            output: Vec::with_capacity(CHUNK_BYTES),
            context: None,
            classifications: Vec::new(),
            session: None,
            incoming: None,
            target: None,
        }
    }
    fn session(&mut self) -> Result<&mut EvaluationSession, Error> {
        self.session.as_mut().ok_or(Error::Context)
    }
    fn engine(&mut self) -> Result<&mut Engine, Error> {
        self.session()?.engine.as_mut().ok_or(Error::Arithmetic)
    }
    fn word(&mut self, value: usize) {
        self.output.extend((value as u32).to_le_bytes());
    }
    fn begin(
        &mut self,
        destination: Destination,
        length: usize,
        expected: Option<[u8; 64]>,
        hash: Sha512,
        ballot_hash: Option<BallotBodyHasher>,
    ) -> Result<(), Error> {
        if self.incoming.is_some() {
            return Err(Error::Incomplete);
        }
        self.incoming = Some(Incoming {
            destination,
            length,
            received: 0,
            bytes: Vec::new(),
            expected,
            hash,
            ballot_hash,
        });
        Ok(())
    }
    fn push(&mut self, length: usize) -> Result<(), Error> {
        let value = self.incoming.as_mut().ok_or(Error::Incomplete)?;
        if length == 0 || length > value.length - value.received {
            return Err(Error::PublicInput);
        }
        let bytes = &self.input[..length];
        if let Some(hash) = value.ballot_hash.as_mut() {
            hash.push(bytes).map_err(|_| Error::PublicInput)?;
            let first = value.received.max(HEADER_BYTES);
            let last = (value.received + length).min(HEADER_BYTES + 2 * DEGREE * COEFFICIENT_BYTES);
            if first < last {
                value
                    .bytes
                    .extend(&bytes[first - value.received..last - value.received]);
            }
        } else {
            value.hash.update(bytes);
            value.bytes.extend(bytes);
        }
        value.received += length;
        Ok(())
    }
    fn finish_incoming(&mut self) -> Result<(), Error> {
        let incoming = self.incoming.take().ok_or(Error::Incomplete)?;
        if incoming.received != incoming.length {
            return Err(Error::Incomplete);
        }
        let digest = if let Some(hash) = incoming.ballot_hash {
            hash.finish().map_err(|_| Error::PublicInput)?
        } else {
            incoming.hash.finalize().into()
        };
        if incoming.expected.is_some_and(|expected| expected != digest) {
            return Err(Error::PublicInput);
        }
        let engine = self.engine()?;
        match incoming.destination {
            Destination::Key(ordinal) => {
                let value = engine
                    .decode_polynomial(&incoming.bytes)
                    .map_err(|_| Error::PublicInput)?;
                engine
                    .load_key(ordinal, value)
                    .map_err(|_| Error::Arithmetic)
            }
            Destination::Ballot(author) => {
                let length = DEGREE * COEFFICIENT_BYTES;
                if incoming.bytes.len() != 2 * length {
                    return Err(Error::PublicInput);
                }
                let value = [
                    engine
                        .decode_polynomial(&incoming.bytes[..length])
                        .map_err(|_| Error::PublicInput)?,
                    engine
                        .decode_polynomial(&incoming.bytes[length..])
                        .map_err(|_| Error::PublicInput)?,
                ];
                engine
                    .load_input(author, value)
                    .map_err(|_| Error::Arithmetic)
            }
            Destination::Readback(index) => engine
                .retire_to_storage(index, digest)
                .map_err(|_| Error::Storage),
            Destination::Reload(index) => {
                if incoming.bytes.len() != 2 * DEGREE * 112 {
                    return Err(Error::Storage);
                }
                let value: Ciphertext = std::array::from_fn(|part| {
                    incoming.bytes[part * DEGREE * 112..(part + 1) * DEGREE * 112]
                        .chunks_exact(112)
                        .map(|coefficient| {
                            std::array::from_fn(|word| {
                                u64::from_le_bytes(
                                    coefficient[word * 8..word * 8 + 8].try_into().unwrap(),
                                )
                            })
                        })
                        .collect()
                });
                engine.reload(index, value).map_err(|_| Error::Storage)
            }
        }
    }
    fn command(&mut self, operation: u32, argument: usize, length: usize) -> Result<(), Error> {
        if length > CHUNK_BYTES {
            return Err(Error::Encoding);
        }
        self.output.clear();
        if self.target.is_some() && operation != 20 {
            return Err(Error::Context);
        }
        if ![12, 13].contains(&operation) && self.incoming.is_some() {
            return Err(Error::Incomplete);
        }
        match operation {
            0 => {
                if argument != 0 || length != 0 || self.context.is_some() || self.session.is_some()
                {
                    return Err(Error::Context);
                }
                self.context =
                    Some(setup_aggregate::setup_browser::context().ok_or(Error::Context)?);
                Ok(())
            }
            1 => {
                if argument != 0 || length != 0 || self.session.is_some() {
                    return Err(Error::Context);
                }
                let (_, setup) = self.context.as_ref().ok_or(Error::Context)?;
                if self.classifications.len() >= setup.inventory().confirmations().len() {
                    return Err(Error::Incomplete);
                }
                self.classifications
                    .push(ballot_proof::take_browser_classification());
                Ok(())
            }
            2 => {
                if argument != 0 || length != 0 || self.session.is_some() {
                    return Err(Error::Context);
                }
                let (poll, setup) = self.context.take().ok_or(Error::Context)?;
                let barrier =
                    ballot_proof::take_browser_close_barrier().ok_or(Error::Incomplete)?;
                // The barrier must come from this instance's own setup verifier.
                if barrier.poll().identity() != poll.identity()
                    || barrier.setup().inventory().identity() != setup.inventory().identity()
                {
                    return Err(Error::Context);
                }
                let session = ClassifiedClosedInventory::new(
                    barrier,
                    std::mem::take(&mut self.classifications),
                )?
                .start()?;
                if session.engine.is_none() {
                    self.target = Some(Arc::new(session.finish()?));
                } else {
                    self.session = Some(session);
                }
                Ok(())
            }
            10 => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                let session = self.session()?;
                let engine = session.engine.as_mut().ok_or(Error::Arithmetic)?;
                let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
                let loaded = engine.key_count();
                let input_kind = required.input_position.map_or(0, |author| {
                    usize::from(session.inventory.accepted[author].is_some())
                });
                for value in [
                    required.step,
                    loaded,
                    required.key_count,
                    required.spills.len(),
                    required.reloads.len(),
                    required.input_position.unwrap_or(u32::MAX as usize),
                    input_kind,
                ] {
                    self.word(value);
                }
                for value in required.spills.into_iter().chain(required.reloads) {
                    self.word(value);
                }
                Ok(())
            }
            11 => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                let session = self.session()?;
                let engine = session.engine.as_mut().ok_or(Error::Arithmetic)?;
                let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
                let ordinal = engine.key_count();
                if ordinal >= required.key_count {
                    return Err(Error::Incomplete);
                }
                let (common, index) =
                    Engine::key_identity(required.cache.ok_or(Error::Arithmetic)?, ordinal)
                        .map_err(|_| Error::Arithmetic)?;
                if common {
                    let values = setup_witness::contribution::common_polynomial(index)
                        .map_err(|_| Error::PublicInput)?;
                    let mut bytes = Vec::with_capacity(DEGREE * COEFFICIENT_BYTES);
                    for value in values {
                        let (sign, magnitude) = value.to_bytes_le();
                        if magnitude.len() >= COEFFICIENT_BYTES {
                            return Err(Error::PublicInput);
                        }
                        bytes.push(u8::from(sign == Sign::Minus));
                        bytes.extend(&magnitude);
                        bytes.resize(bytes.len() + COEFFICIENT_BYTES - 1 - magnitude.len(), 0);
                    }
                    let value = engine
                        .decode_polynomial(&bytes)
                        .map_err(|_| Error::PublicInput)?;
                    engine
                        .load_key(ordinal, value)
                        .map_err(|_| Error::Arithmetic)?;
                    self.word(u32::MAX as usize);
                } else {
                    let metadata = session
                        .inventory
                        .setup
                        .polynomials()
                        .iter()
                        .find(|value| value.index() == index)
                        .ok_or(Error::Context)?;
                    let expected = *metadata.digest();
                    let bytes = metadata.bytes();
                    self.begin(
                        Destination::Key(ordinal),
                        bytes,
                        Some(expected),
                        Sha512::new(),
                        None,
                    )?;
                    self.word(index);
                }
                Ok(())
            }
            12 => {
                if argument != 0 {
                    return Err(Error::Encoding);
                }
                let result = self.push(length);
                if result.is_err() {
                    self.incoming = None;
                }
                result
            }
            13 => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                self.finish_incoming()
            }
            14 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let session = self.session()?;
                let engine = session.engine.as_mut().ok_or(Error::Arithmetic)?;
                let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
                if required.input_position != Some(argument) {
                    return Err(Error::Context);
                }
                if let Some(envelope) = session
                    .inventory
                    .accepted
                    .get(argument)
                    .ok_or(Error::Context)?
                    .as_ref()
                {
                    let bytes = envelope.body_length();
                    let expected = *envelope.body_identity();
                    let hash =
                        BallotBodyHasher::for_body_length(bytes).map_err(|_| Error::PublicInput)?;
                    self.begin(
                        Destination::Ballot(argument),
                        bytes,
                        Some(expected),
                        Sha512::new(),
                        Some(hash),
                    )?;
                    self.word(bytes);
                } else {
                    engine
                        .load_input(argument, std::array::from_fn(|_| vec![[0; 14]; DEGREE]))
                        .map_err(|_| Error::Arithmetic)?;
                    self.word(0);
                }
                Ok(())
            }
            15 => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                let retired = self.engine()?.execute().map_err(|_| Error::Arithmetic)?;
                self.word(retired.len());
                for index in retired {
                    self.word(index);
                }
                Ok(())
            }
            16 => {
                if length != 8 {
                    return Err(Error::Encoding);
                }
                let offset = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let count = u32::from_le_bytes(self.input[4..8].try_into().unwrap()) as usize;
                if count == 0 || count > CHUNK_BYTES / 112 || offset > 2 * DEGREE - count {
                    return Err(Error::Encoding);
                }
                let value = self.engine()?.value(argument).map_err(|_| Error::Storage)?;
                let mut output = Vec::with_capacity(count * 112);
                for position in offset..offset + count {
                    for word in value[position / DEGREE][position % DEGREE] {
                        output.extend(word.to_le_bytes());
                    }
                }
                self.output = output;
                Ok(())
            }
            17 | 18 => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let engine = self.engine()?;
                let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
                let (destination, expected) = if operation == 17 {
                    if !required.spills.contains(&argument) {
                        return Err(Error::Storage);
                    }
                    (
                        Destination::Readback(argument),
                        Some(engine.value_identity(
                            argument,
                            engine.value(argument).map_err(|_| Error::Storage)?,
                        )),
                    )
                } else {
                    if !required.reloads.contains(&argument) {
                        return Err(Error::Storage);
                    }
                    (Destination::Reload(argument), None)
                };
                let hash = engine.value_hasher(argument);
                self.begin(destination, 2 * DEGREE * 112, expected, hash, None)
            }
            19 => {
                if argument != 0 || length != 0 || !self.engine()?.finished() {
                    return Err(Error::Incomplete);
                }
                self.target = Some(Arc::new(
                    self.session.take().ok_or(Error::Context)?.finish()?,
                ));
                Ok(())
            }
            20 => {
                if argument != 0 || length != 8 {
                    return Err(Error::Encoding);
                }
                let offset = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let count = u32::from_le_bytes(self.input[4..8].try_into().unwrap()) as usize;
                let ciphertext = self
                    .target
                    .as_ref()
                    .and_then(|target| target.ciphertext())
                    .ok_or(Error::Incomplete)?;
                if count == 0
                    || count > CHUNK_BYTES
                    || offset > ciphertext.len().saturating_sub(count)
                {
                    return Err(Error::Encoding);
                }
                self.output.extend_from_slice(
                    ciphertext
                        .get(offset..offset + count)
                        .ok_or(Error::Encoding)?,
                );
                Ok(())
            }
            _ => Err(Error::Encoding),
        }
    }
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::new());}
pub(crate) fn verified_target() -> Option<Arc<VerifiedEvaluationTarget>> {
    STATE.with(|state| state.borrow().target.clone())
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_input_pointer() -> usize {
    STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_output_pointer() -> usize {
    STATE.with(|state| state.borrow().output.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_output_length() -> usize {
    STATE.with(|state| state.borrow().output.len())
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_command(operation: u32, argument: usize, length: usize) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        u32::from(state.command(operation, argument, length).is_err())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_body_pointer() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .target
            .as_ref()
            .map_or(0, |target| target.body().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_body_length() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .target
            .as_ref()
            .map_or(0, |target| target.body().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_ciphertext_length() -> usize {
    STATE.with(|state| {
        state
            .borrow()
            .target
            .as_ref()
            .and_then(|target| target.ciphertext())
            .map_or(0, <[u8]>::len)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn evaluation_target_finished() -> u32 {
    STATE.with(|state| {
        u32::from(
            state
                .borrow()
                .session
                .as_ref()
                .and_then(|session| session.engine.as_ref())
                .is_some_and(Engine::finished),
        )
    })
}
