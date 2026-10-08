use crate::close::VerifiedCloseBarrier;
use crate::target::{
    ClassifiedClosedInventory, Error, EvaluationSession, VerifiedEvaluationTarget,
};
use ballot_proof::body::BallotBodyClassification;
use encrypted_ranking::ranking::{
    DEGREE, Engine, KEY_RECORD_BYTES, PolynomialDecoder, Progress, RecordRequest, Refusal,
    StoredValueRead, stored_value_bytes,
};
use protocol_foundations::{
    ballot_body::{self, HEADER_BYTES},
    identity::{BodyHasher, IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

protocol_foundations::operation_codes! {
    /// The evaluation target's commands.
    enum EvaluationOperation {
        Begin = 0,
        TakeClassification = 1,
        Start = 2,
        Requirements = 10,
        NextKey = 11,
        PushInput = 12,
        FinishInput = 13,
        BeginBallotInput = 14,
        Execute = 15,
        ReadValue = 16,
        ReadBack = 17,
        Reload = 18,
        Finish = 19,
        KeyRecord = 21,
        TakeKeyRecord = 22,
        SharedKeyRecords = 23,
    }
}
/// The input buffer's length; the host never writes more.
pub const EVALUATION_INPUT_BYTES: usize = 1 << 20;
// A key record after its prime fits the input buffer.
const _: () = assert!(4 + KEY_RECORD_BYTES <= EVALUATION_INPUT_BYTES);
/// What an evaluation target takes from the instance's other verifiers: its
/// verified setup, each ballot's classification, the release of the
/// statement inputs the classified ballots shared, and the verified close
/// barrier.
pub trait EvaluationInputs {
    fn setup(&mut self) -> Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>;
    fn take_classification(&mut self) -> Option<BallotBodyClassification>;
    fn release_ballot_inputs(&mut self);
    fn take_barrier(&mut self) -> Option<VerifiedCloseBarrier>;
}
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
        hash: BodyHasher,
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
/// The evaluation target of one instance: its classified inputs, the
/// running evaluation and the target it certifies.
pub struct TargetSession {
    input: Vec<u8>,
    output: Vec<u8>,
    context: Option<(Arc<VerifiedPoll>, Arc<VerifiedSetupAggregate>)>,
    classifications: Vec<Option<BallotBodyClassification>>,
    session: Option<EvaluationSession>,
    incoming: Option<Incoming>,
    target: Option<Arc<VerifiedEvaluationTarget>>,
}
impl TargetSession {
    pub fn new() -> Self {
        Self {
            input: vec![0; EVALUATION_INPUT_BYTES],
            output: Vec::with_capacity(EVALUATION_INPUT_BYTES),
            context: None,
            classifications: Vec::new(),
            session: None,
            incoming: None,
            target: None,
        }
    }
    pub fn input(&mut self) -> &mut [u8] {
        &mut self.input
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn target(&self) -> Option<Arc<VerifiedEvaluationTarget>> {
        self.target.clone()
    }
    /// Takes a target restored from the participant's retained copy while
    /// this instance holds no target and runs no evaluation.
    pub fn restore_target(&mut self, target: VerifiedEvaluationTarget) -> bool {
        if self.target.is_some()
            || self.context.is_some()
            || self.session.is_some()
            || self.incoming.is_some()
            || !self.classifications.is_empty()
        {
            return false;
        }
        self.target = Some(Arc::new(target));
        true
    }
    /// Whether the running evaluation executed its last instruction.
    pub fn finished(&self) -> bool {
        self.session
            .as_ref()
            .and_then(|session| session.engine.as_ref())
            .is_some_and(Engine::finished)
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
    pub fn command(
        &mut self,
        inputs: &mut impl EvaluationInputs,
        operation: u32,
        argument: usize,
        length: usize,
    ) -> Result<(), Error> {
        if length > EVALUATION_INPUT_BYTES {
            return Err(Error::Encoding);
        }
        let operation = EvaluationOperation::from_code(operation);
        self.output.clear();
        if self.target.is_some() {
            return Err(Error::Context);
        }
        if !matches!(
            operation,
            Some(EvaluationOperation::PushInput | EvaluationOperation::FinishInput)
        ) && self.incoming.is_some()
        {
            return Err(Error::Incomplete);
        }
        match operation {
            Some(EvaluationOperation::Begin) => {
                if argument != 0 || length != 0 || self.context.is_some() || self.session.is_some()
                {
                    return Err(Error::Context);
                }
                self.context = Some(inputs.setup().ok_or(Error::Context)?);
                // Inputs an earlier, unfinished classification kept.
                inputs.release_ballot_inputs();
                Ok(())
            }
            Some(EvaluationOperation::TakeClassification) => {
                if argument != 0 || length != 0 || self.session.is_some() {
                    return Err(Error::Context);
                }
                let (_, setup) = self.context.as_ref().ok_or(Error::Context)?;
                if self.classifications.len() >= setup.profile().participants() {
                    return Err(Error::Incomplete);
                }
                self.classifications.push(inputs.take_classification());
                Ok(())
            }
            Some(EvaluationOperation::Start) => {
                if argument != 0 || length != 0 || self.session.is_some() {
                    return Err(Error::Context);
                }
                let (poll, setup) = self.context.take().ok_or(Error::Context)?;
                // Every classification is taken, so the ballots' shared
                // inputs are not held through the evaluation.
                inputs.release_ballot_inputs();
                let barrier = inputs.take_barrier().ok_or(Error::Incomplete)?;
                // The barrier must come from this instance's own setup verifier.
                if barrier.poll().identity() != poll.identity()
                    || barrier.setup().identity() != setup.identity()
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
            Some(EvaluationOperation::Requirements) => {
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
            Some(EvaluationOperation::NextKey) => {
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
            Some(EvaluationOperation::PushInput) => {
                if argument != 0 {
                    return Err(Error::Encoding);
                }
                let result = self.push(length);
                if result.is_err() {
                    self.incoming = None;
                }
                result
            }
            Some(EvaluationOperation::FinishInput) => {
                if argument != 0 || length != 0 {
                    return Err(Error::Encoding);
                }
                self.finish_incoming()
            }
            Some(EvaluationOperation::BeginBallotInput) => {
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
                        hash: ballot_body::body_hasher(engine.profile(), bytes)
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
            Some(EvaluationOperation::Execute) => {
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
            Some(EvaluationOperation::ReadValue) => {
                if length != 8 {
                    return Err(Error::Encoding);
                }
                let offset = u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
                let count = u32::from_le_bytes(self.input[4..8].try_into().unwrap()) as usize;
                let value = self.engine()?.value(argument).map_err(|_| Error::Storage)?;
                // The stored value's coefficients in order: both components'
                // words.
                let words = value[0].len() / DEGREE;
                if count == 0
                    || count > EVALUATION_INPUT_BYTES / (8 * words)
                    || offset.checked_add(count).is_none_or(|end| end > 2 * DEGREE)
                {
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
            Some(EvaluationOperation::ReadBack | EvaluationOperation::Reload) => {
                if length != 0 {
                    return Err(Error::Encoding);
                }
                let engine = self.engine()?;
                let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
                let read = if operation == Some(EvaluationOperation::ReadBack) {
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
            Some(EvaluationOperation::Finish) => {
                if argument != 0 || length != 0 || !self.engine()?.finished() {
                    return Err(Error::Incomplete);
                }
                self.target = Some(Arc::new(
                    self.session.take().ok_or(Error::Context)?.finish()?,
                ));
                Ok(())
            }
            Some(EvaluationOperation::KeyRecord) => {
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
            Some(EvaluationOperation::SharedKeyRecords) => {
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
            Some(EvaluationOperation::TakeKeyRecord) => {
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
            None => Err(Error::Encoding),
        }
    }
}
impl Default for TargetSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "target-session-tests.rs"]
mod tests;
