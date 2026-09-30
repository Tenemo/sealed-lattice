use crate::target::{
    ClassifiedClosedInventory, Error, EvaluationSession, VerifiedEvaluationTarget,
};
use ballot_proof::body::BallotBodyClassification;
use registration_credentials::{
    ballot_body::{BallotBodyHasher, HEADER_BYTES},
    identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
};
use rns_arithmetic_probe::ranking::{
    DEGREE, Engine, KEY_RECORD_BYTES, PolynomialDecoder, Progress, RecordRequest, Refusal,
    StoredValueRead, stored_value_bytes,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{cell::RefCell, sync::Arc};

const CHUNK_BYTES: usize = 1 << 20;
/// What an incoming stream becomes as its pieces arrive: a key polynomial
/// of the ordinal, a ballot body of the author, whose FHE ciphertext's two
/// components follow its header, or a stored value; each with the identity
/// its bytes must have.
enum Payload {
    Key {
        ordinal: usize,
        hash: IdentityHasher,
        expected: [u8; 64],
        decoder: PolynomialDecoder,
    },
    Ballot {
        author: usize,
        hash: BallotBodyHasher,
        expected: [u8; 64],
        components: [PolynomialDecoder; 2],
    },
    Stored(StoredValueRead),
}
struct Incoming {
    length: usize,
    received: usize,
    payload: Payload,
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
    fn begin(&mut self, length: usize, payload: Payload) -> Result<(), Error> {
        if self.incoming.is_some() {
            return Err(Error::Incomplete);
        }
        self.incoming = Some(Incoming {
            length,
            received: 0,
            payload,
        });
        Ok(())
    }
    fn push(&mut self, length: usize) -> Result<(), Error> {
        let Self {
            input,
            session,
            incoming,
            ..
        } = self;
        let value = incoming.as_mut().ok_or(Error::Incomplete)?;
        if length == 0 || length > value.length - value.received {
            return Err(Error::PublicInput);
        }
        let engine = session
            .as_ref()
            .and_then(|session| session.engine.as_ref())
            .ok_or(Error::Arithmetic)?;
        let bytes = &input[..length];
        let received = value.received;
        match &mut value.payload {
            Payload::Key { hash, decoder, .. } => {
                hash.absorb(bytes).map_err(|_| Error::PublicInput)?;
                engine
                    .decode_into(decoder, bytes)
                    .map_err(|_| Error::PublicInput)?;
            }
            Payload::Ballot {
                hash, components, ..
            } => {
                hash.push(bytes).map_err(|_| Error::PublicInput)?;
                let split = DEGREE * engine.coefficient_bytes();
                for (index, component) in components.iter_mut().enumerate() {
                    let start = HEADER_BYTES + index * split;
                    let first = received.max(start);
                    let last = (received + length).min(start + split);
                    if first < last {
                        engine
                            .decode_into(component, &bytes[first - received..last - received])
                            .map_err(|_| Error::PublicInput)?;
                    }
                }
            }
            Payload::Stored(read) => engine
                .push_read(read, bytes)
                .map_err(|_| Error::PublicInput)?,
        }
        value.received += length;
        Ok(())
    }
    fn finish_incoming(&mut self) -> Result<(), Error> {
        let incoming = self.incoming.take().ok_or(Error::Incomplete)?;
        if incoming.received != incoming.length {
            return Err(Error::Incomplete);
        }
        let engine = self.engine()?;
        match incoming.payload {
            Payload::Key {
                ordinal,
                hash,
                expected,
                decoder,
            } => {
                if hash.finish().map_err(|_| Error::PublicInput)? != expected {
                    return Err(Error::PublicInput);
                }
                let polynomial = engine
                    .finish_polynomial(decoder)
                    .map_err(|_| Error::PublicInput)?;
                engine
                    .load_key(ordinal, polynomial)
                    .map_err(|_| Error::Arithmetic)
            }
            Payload::Ballot {
                author,
                hash,
                expected,
                components: [first, second],
            } => {
                if hash.finish().map_err(|_| Error::PublicInput)? != expected {
                    return Err(Error::PublicInput);
                }
                let value = [
                    engine
                        .finish_polynomial(first)
                        .map_err(|_| Error::PublicInput)?,
                    engine
                        .finish_polynomial(second)
                        .map_err(|_| Error::PublicInput)?,
                ];
                engine
                    .load_input(author, value)
                    .map_err(|_| Error::Arithmetic)
            }
            Payload::Stored(read) => engine.finish_read(read).map_err(|_| Error::Storage),
        }
    }
    fn command(&mut self, operation: u32, argument: usize, length: usize) -> Result<(), Error> {
        if length > CHUNK_BYTES {
            return Err(Error::Encoding);
        }
        self.output.clear();
        if self.target.is_some() && ![20, 24].contains(&operation) {
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
                // Inputs an earlier, unfinished classification kept.
                ballot_proof::release_browser_ballot_inputs();
                Ok(())
            }
            1 => {
                if argument != 0 || length != 0 || self.session.is_some() {
                    return Err(Error::Context);
                }
                let (_, setup) = self.context.as_ref().ok_or(Error::Context)?;
                if self.classifications.len() >= setup.profile().participants() {
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
                // Every classification is taken, so the ballots' shared
                // inputs are not held through the evaluation.
                ballot_proof::release_browser_ballot_inputs();
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
                let profile = engine.profile();
                let width = engine.coefficient_bytes();
                let (common, index) = Engine::key_identity(
                    profile,
                    required.cache.ok_or(Error::Arithmetic)?,
                    ordinal,
                )
                .map_err(|_| Error::Arithmetic)?;
                if common {
                    let bytes = setup_witness::contribution::common_records(profile, index)
                        .map_err(|_| Error::PublicInput)?;
                    if bytes.len() != DEGREE * width {
                        return Err(Error::PublicInput);
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
                    let bytes = metadata.bytes();
                    let payload = Payload::Key {
                        ordinal,
                        hash: IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], bytes)
                            .map_err(|_| Error::Context)?,
                        expected: *metadata.digest(),
                        decoder: engine.polynomial_decoder(),
                    };
                    self.begin(bytes, payload)?;
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
                    // The body carries the FHE ciphertext's two components
                    // first.
                    let payload = Payload::Ballot {
                        author: argument,
                        hash: BallotBodyHasher::for_body_length(engine.profile(), bytes)
                            .map_err(|_| Error::PublicInput)?,
                        expected: *envelope.body_identity(),
                        components: [engine.polynomial_decoder(), engine.polynomial_decoder()],
                    };
                    self.begin(bytes, payload)?;
                    self.word(bytes);
                } else {
                    let zero = engine.zero_value();
                    engine
                        .load_input(argument, zero)
                        .map_err(|_| Error::Arithmetic)?;
                    self.word(0);
                }
                Ok(())
            }
            15 => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                // Executed: the values whose last use it was. Records: the
                // request the host delivers next and those that follow it,
                // whose records the host may read ahead. Waiting: the job
                // whose end the host awaits before it asks again. A
                // delivered key record that is not the stored one ends the
                // evaluation.
                match self.engine()?.execute() {
                    Ok(Progress::Executed(retired)) => {
                        self.word(0);
                        for index in retired {
                            self.word(index);
                        }
                    }
                    Ok(Progress::Records(request)) => {
                        self.word(1);
                        for request in
                            std::iter::once(request).chain(self.engine()?.following_requests())
                        {
                            for value in [request.first, request.count, request.prime] {
                                self.word(value);
                            }
                        }
                    }
                    Ok(Progress::Waiting(number)) => {
                        self.word(3);
                        self.word(number as usize);
                    }
                    Err(Refusal::Identity) => {
                        self.session = None;
                        self.word(2);
                    }
                    Err(_) => return Err(Error::Arithmetic),
                }
                Ok(())
            }
            16 => {
                if length != 8 {
                    return Err(Error::Encoding);
                }
                let offset = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let count = u32::from_le_bytes(self.input[4..8].try_into().unwrap()) as usize;
                let value = self.engine()?.value(argument).map_err(|_| Error::Storage)?;
                // The stored value's coefficients in order: both components'
                // words.
                let words = value[0].len() / DEGREE;
                if count == 0 || count > CHUNK_BYTES / (8 * words) || offset > 2 * DEGREE - count {
                    return Err(Error::Encoding);
                }
                let mut output = Vec::with_capacity(count * 8 * words);
                for position in offset..offset + count {
                    let (part, index) = (position / DEGREE, position % DEGREE);
                    for word in &value[part][index * words..(index + 1) * words] {
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
                let read = if operation == 17 {
                    if !required.spills.contains(&argument) {
                        return Err(Error::Storage);
                    }
                    engine.begin_readback(argument)
                } else {
                    if !required.reloads.contains(&argument) {
                        return Err(Error::Storage);
                    }
                    engine.begin_reload(argument)
                }
                .map_err(|_| Error::Storage)?;
                let bytes = stored_value_bytes(engine.profile());
                self.begin(bytes, Payload::Stored(read))
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
            21 => {
                // The request's next key record of the ordinal, after its
                // prime.
                if length != 4 + KEY_RECORD_BYTES {
                    return Err(Error::Encoding);
                }
                let prime = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let record = &self.input[4..length];
                self.session
                    .as_mut()
                    .and_then(|session| session.engine.as_mut())
                    .ok_or(Error::Arithmetic)?
                    .key_record(argument, prime, record)
                    .map_err(|_| Error::Storage)
            }
            23 => {
                // The request's key records, which the host shared itself
                // one after another: their handle, and the request's first
                // ordinal, count and prime and the records' length.
                if length != 16 {
                    return Err(Error::Encoding);
                }
                let [first, count, prime, bytes] = std::array::from_fn(|index| {
                    u32::from_le_bytes(self.input[4 * index..4 * (index + 1)].try_into().unwrap())
                        as usize
                });
                let records = parallel_work::adopt(argument as u32, bytes).ok_or(Error::Storage)?;
                self.session
                    .as_mut()
                    .and_then(|session| session.engine.as_mut())
                    .ok_or(Error::Arithmetic)?
                    .shared_key_records(
                        RecordRequest {
                            first,
                            count,
                            prime,
                        },
                        records,
                    )
                    .map_err(|_| Error::Storage)
            }
            22 => {
                // The last loaded key's next record for the host to store,
                // after its prime, or nothing once every record is stored.
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                if let Some((prime, record)) = self.engine()?.take_record() {
                    self.word(prime);
                    self.output.extend_from_slice(&record);
                }
                Ok(())
            }
            24 => {
                // The close barrier this instance verified again beside a
                // restored target, which must be the barrier the target was
                // evaluated from, so that a visit recording its reads
                // records that close.
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                let target = self.target.as_ref().ok_or(Error::Incomplete)?;
                let barrier =
                    ballot_proof::take_browser_close_barrier().ok_or(Error::Incomplete)?;
                if !target.names_barrier(&barrier) {
                    return Err(Error::PublicInput);
                }
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
pub(crate) fn restore_target(target: VerifiedEvaluationTarget) -> bool {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.target.is_some()
            || state.context.is_some()
            || state.session.is_some()
            || state.incoming.is_some()
            || !state.classifications.is_empty()
        {
            return false;
        }
        state.target = Some(Arc::new(target));
        true
    })
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
