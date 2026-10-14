use crate::close::{ClosedSlot, VerifiedCloseBarrier};
use crate::program::RankingProgram;
use ballot_proof::body::BallotBodyClassification;
use encrypted_ranking::ranking::{
    Ciphertext, DEGREE, Engine, PolynomialDecoder, Progress, Refusal,
};
use protocol_foundations::{
    Credential, RETAINED_TAG_BYTES,
    ballot_authentication::BallotEnvelope,
    ballot_body::{self, HEADER_BYTES},
    foundation::{CanonicalItem, CanonicalTuple, hash_foundation_tuple_512},
    identity::{BodyHasher, IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN},
    poll::VerifiedPoll,
    target_signing::{MAXIMUM_TARGET_BODY_BYTES, TARGET_PURPOSE, TargetMessage},
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{io::Read, sync::Arc};
use supported_profile::minimum_turnout;

#[derive(Debug)]
pub enum Error {
    Context,
    Incomplete,
    UnsupportedProfile,
    PublicInput,
    Arithmetic,
    Storage,
    Encoding,
}

/// The provider supplies bytes, never acceptance flags or operand identities.
pub trait PublicInputs {
    fn aggregate(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error>;
    fn ballot(&mut self, author: usize) -> Result<Box<dyn Read + '_>, Error>;
}

/// Public working ciphertexts and key records. Every readback is checked
/// against the identity retained in the live evaluator before a value is
/// retired or used again, and every key record before its product is used.
pub trait WorkingStore {
    fn put(&mut self, index: usize, value: &Ciphertext) -> Result<(), Error>;
    /// The stored bytes of the value of the index.
    fn get(&mut self, index: usize) -> Result<Vec<u8>, Error>;
    fn remove(&mut self, index: usize) -> Result<(), Error>;
    /// Stores the record of the current cache's key of the ordinal modulo
    /// the prime.
    fn put_record(&mut self, ordinal: usize, prime: usize, record: &[u8]) -> Result<(), Error>;
    fn get_record(&mut self, ordinal: usize, prime: usize) -> Result<Vec<u8>, Error>;
    /// Removes every key record.
    fn clear_records(&mut self) -> Result<(), Error>;
}

/// Classification codes in the target: 0 absent, 1 invalid, 2 accepted and
/// 3 conflicting.
pub struct ClassifiedClosedInventory {
    pub(crate) poll: Arc<VerifiedPoll>,
    pub(crate) setup: Arc<VerifiedSetupAggregate>,
    barrier: VerifiedCloseBarrier,
    classifications: Vec<u8>,
    pub(crate) accepted: Vec<Option<BallotEnvelope>>,
}
impl ClassifiedClosedInventory {
    /// Consumes the close barrier and exactly one owning classification for
    /// each usable slot; absent and conflicting slots take none.
    pub fn new(
        barrier: VerifiedCloseBarrier,
        classifications: Vec<Option<BallotBodyClassification>>,
    ) -> Result<Self, Error> {
        let count = barrier.slots().len();
        if classifications.len() != count {
            return Err(Error::Incomplete);
        }
        let mut encoded = Vec::with_capacity(count);
        let mut accepted = Vec::with_capacity(count);
        for (slot, classification) in barrier.slots().iter().zip(classifications) {
            match (slot, classification) {
                (ClosedSlot::Absent, None) => {
                    encoded.push(0);
                    accepted.push(None);
                }
                (ClosedSlot::Conflicting(_), None) => {
                    encoded.push(3);
                    accepted.push(None);
                }
                (ClosedSlot::Usable(source), Some(BallotBodyClassification::Invalid(value))) => {
                    if source.authentication().envelope().bytes() != value.envelope().bytes() {
                        return Err(Error::Context);
                    }
                    encoded.push(1);
                    accepted.push(None);
                }
                (ClosedSlot::Usable(source), Some(BallotBodyClassification::Valid(value))) => {
                    // The owning submission verifier matched this envelope to
                    // its verified body, so equal body hashes cannot transfer
                    // validity across authors or ballot times.
                    if value.envelope().bytes() != source.authentication().envelope().bytes() {
                        return Err(Error::Context);
                    }
                    encoded.push(2);
                    accepted.push(Some(value.envelope().clone()));
                }
                _ => return Err(Error::Incomplete),
            }
        }
        Ok(Self {
            poll: barrier.poll().clone(),
            setup: barrier.setup().clone(),
            barrier,
            classifications: encoded,
            accepted,
        })
    }
    pub fn accepted_authors(&self) -> impl Iterator<Item = usize> + '_ {
        self.accepted
            .iter()
            .enumerate()
            .filter_map(|(position, value)| value.as_ref().map(|_| position))
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn setup(&self) -> &Arc<VerifiedSetupAggregate> {
        &self.setup
    }
    pub fn barrier(&self) -> &VerifiedCloseBarrier {
        &self.barrier
    }
    fn target_fields(&self) -> Result<Vec<CanonicalItem>, Error> {
        Ok(vec![
            CanonicalItem::nonempty_ascii(TARGET_PURPOSE).map_err(|_| Error::Encoding)?,
            CanonicalItem::hash512(self.poll.identity()),
            CanonicalItem::hash512(self.setup.identity()),
            CanonicalItem::hash512(*self.barrier.proposal().identity()),
            CanonicalItem::variable_bytes(&self.classifications).map_err(|_| Error::Encoding)?,
        ])
    }
    /// Loads the next key polynomial the evaluation's cache requires when it
    /// is a common polynomial, recomputed here. A setup aggregate polynomial
    /// instead returns its index and the reader its bytes must pass.
    pub(crate) fn next_key(
        &self,
        engine: &mut Engine,
    ) -> Result<Option<(usize, KeyReader)>, Error> {
        let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
        let ordinal = engine.key_count();
        if ordinal >= required.key_count {
            return Err(Error::Incomplete);
        }
        let profile = engine.profile();
        let length = DEGREE * engine.coefficient_bytes();
        let (common, index) =
            Engine::key_identity(profile, required.cache.ok_or(Error::Arithmetic)?, ordinal)
                .map_err(|_| Error::Arithmetic)?;
        if common {
            let bytes = setup_witness::contribution::common_records(profile, index)
                .map_err(|_| Error::PublicInput)?;
            if bytes.len() != length {
                return Err(Error::PublicInput);
            }
            let polynomial = engine
                .decode_polynomial(&bytes)
                .map_err(|_| Error::PublicInput)?;
            engine
                .load_key(ordinal, polynomial)
                .map_err(|_| Error::Arithmetic)?;
            return Ok(None);
        }
        let metadata = self
            .setup
            .polynomials()
            .iter()
            .find(|value| value.index() == index)
            .ok_or(Error::Context)?;
        let reader = KeyReader {
            ordinal,
            length,
            hash: IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], length)
                .map_err(|_| Error::Context)?,
            expected: *metadata.digest(),
            decoder: engine.polynomial_decoder(),
        };
        Ok(Some((index, reader)))
    }
    /// Loads the zero value of the input author the evaluation requires when
    /// no ballot of theirs was accepted. An accepted ballot instead returns
    /// the reader its body must pass.
    pub(crate) fn ballot_input(
        &self,
        engine: &mut Engine,
        author: usize,
    ) -> Result<Option<BallotReader>, Error> {
        let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
        if required.input_position != Some(author) {
            return Err(Error::Context);
        }
        let Some(envelope) = self.accepted.get(author).ok_or(Error::Context)?.as_ref() else {
            let zero = engine.zero_value();
            engine
                .load_input(author, zero)
                .map_err(|_| Error::Arithmetic)?;
            return Ok(None);
        };
        Ok(Some(BallotReader {
            author,
            length: envelope.body_length(),
            received: 0,
            hash: ballot_body::body_hasher(engine.profile(), envelope.body_length())
                .map_err(|_| Error::PublicInput)?,
            expected: *envelope.body_identity(),
            components: [engine.polynomial_decoder(), engine.polynomial_decoder()],
        }))
    }
    pub fn start(self) -> Result<RunningEvaluation, Error> {
        let program = if self.accepted_authors().count() < minimum_turnout(self.accepted.len()) {
            None
        } else {
            Some(
                RankingProgram::for_profile(
                    self.setup.profile(),
                    usize::from(self.poll.top_count()),
                )
                .ok_or(Error::UnsupportedProfile)?,
            )
        };
        let mut engine = program
            .as_ref()
            .map(|program| {
                Engine::new(self.setup.profile(), program.bytes()).map_err(|_| Error::Arithmetic)
            })
            .transpose()?;
        // The instance and each helper grow once to what the evaluation plans
        // them to hold beside their live allocations, within the instance's
        // bound.
        if let Some(engine) = &mut engine {
            #[cfg(target_arch = "wasm32")]
            {
                engine.bound_instance(parallel_work::scalar_allocator::linear_memory_bound());
                parallel_work::scalar_allocator::plan_linear_memory(engine.planned_memory_bytes());
            }
            let helpers = parallel_work::helpers();
            let tickets: Vec<_> = (0..helpers)
                .map(|helper| {
                    let bytes = engine.helper_planned_bytes(helper, helpers) as u64;
                    parallel_work::submit(
                        &crate::PLAN,
                        Some(helper),
                        &[parallel_work::Part::Bytes(&bytes.to_le_bytes())],
                        0,
                    )
                })
                .collect();
            for ticket in tickets {
                assert!(ticket.wait().is_empty());
            }
        }
        Ok(RunningEvaluation {
            inventory: self,
            engine,
        })
    }
    pub fn evaluate(
        self,
        inputs: &mut impl PublicInputs,
        store: &mut impl WorkingStore,
    ) -> Result<VerifiedEvaluationTarget, Error> {
        let mut session = self.start()?;
        let Some(engine) = session.engine.as_mut() else {
            return session.finish();
        };
        while !engine.finished() {
            let required = engine.requirements().map_err(|_| Error::Arithmetic)?;
            for index in required.spills {
                let mut read = engine
                    .begin_readback(index)
                    .map_err(|_| Error::Arithmetic)?;
                store.put(index, engine.value(index).map_err(|_| Error::Arithmetic)?)?;
                engine
                    .push_read(&mut read, &store.get(index)?)
                    .map_err(|_| Error::Storage)?;
                engine.finish_read(read).map_err(|_| Error::Storage)?;
            }
            for index in required.reloads {
                let mut read = engine.begin_reload(index).map_err(|_| Error::Storage)?;
                engine
                    .push_read(&mut read, &store.get(index)?)
                    .map_err(|_| Error::Storage)?;
                engine.finish_read(read).map_err(|_| Error::Storage)?;
            }
            if required.cache.is_some() {
                // A new cache replaces the earlier cache's records.
                if engine.key_count() == 0 {
                    store.clear_records()?;
                }
                while engine.key_count() < required.key_count {
                    let ordinal = engine.key_count();
                    if let Some((index, mut reader)) = session.inventory.next_key(engine)? {
                        read_exactly(inputs.aggregate(index)?, reader.length(), |bytes| {
                            reader.push(engine, bytes)
                        })?;
                        reader.finish(engine)?;
                    }
                    while let Some((prime, record)) = engine.take_record() {
                        store.put_record(ordinal, prime, &record)?;
                    }
                }
            }
            if let Some(author) = required.input_position
                && let Some(mut reader) = session.inventory.ballot_input(engine, author)?
            {
                read_exactly(inputs.ballot(author)?, reader.length(), |bytes| {
                    reader.push(engine, bytes)
                })?;
                reader.finish(engine)?;
            }
            loop {
                match engine.execute() {
                    Ok(Progress::Executed(retired)) => {
                        for index in retired {
                            store.remove(index)?;
                        }
                        break;
                    }
                    // The job has not ended; executing again looks anew.
                    Ok(Progress::Waiting(_)) => {}
                    Ok(Progress::Records(request)) => {
                        for ordinal in request.first..request.first + request.count {
                            let record = store.get_record(ordinal, request.prime)?;
                            engine
                                .key_record(ordinal, request.prime, &record)
                                .map_err(|_| Error::Storage)?;
                        }
                    }
                    Err(Refusal::Identity) => return Err(Error::Storage),
                    Err(_) => return Err(Error::Arithmetic),
                }
            }
        }
        store.clear_records()?;
        session.finish()
    }
}

pub struct RunningEvaluation {
    pub(crate) inventory: ClassifiedClosedInventory,
    pub(crate) engine: Option<Engine>,
}
impl RunningEvaluation {
    /// Completes the target body: the no-result branch, or the result branch
    /// and the identity of its final ciphertext, whose framing also fixes its
    /// length. The program is not a field, since the profile and the poll's
    /// result length determine it.
    pub(crate) fn finish(self) -> Result<VerifiedEvaluationTarget, Error> {
        let Self { inventory, engine } = self;
        let mut fields = inventory.target_fields()?;
        let ciphertext = match engine {
            None => {
                fields.push(CanonicalItem::unsigned16(0));
                None
            }
            Some(engine) => {
                let ciphertext = engine.final_switch().map_err(|_| Error::Arithmetic)?;
                fields.extend([
                    CanonicalItem::unsigned16(1),
                    CanonicalItem::hash512(ciphertext_identity(&ciphertext)?),
                ]);
                Some(ciphertext)
            }
        };
        VerifiedEvaluationTarget::finish(inventory, fields, ciphertext)
    }
}

const CIPHERTEXT_IDENTITY_DOMAIN: &str = "sealed-lattice/evaluation-ciphertext/v1";

fn ciphertext_identity(ciphertext: &[u8]) -> Result<[u8; 64], Error> {
    Ok(hash_foundation_tuple_512(
        CIPHERTEXT_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(ciphertext).map_err(|_| Error::Encoding)?],
    )
    .map_err(|_| Error::Encoding)?
    .into_bytes())
}

/// A setup aggregate key polynomial's stream, whose bytes must have the
/// identity the verified setup binds.
pub(crate) struct KeyReader {
    ordinal: usize,
    length: usize,
    hash: IdentityHasher,
    expected: [u8; 64],
    decoder: PolynomialDecoder,
}
impl KeyReader {
    pub(crate) fn length(&self) -> usize {
        self.length
    }
    pub(crate) fn push(&mut self, engine: &Engine, bytes: &[u8]) -> Result<(), Error> {
        self.hash.absorb(bytes).map_err(|_| Error::PublicInput)?;
        engine
            .decode_into(&mut self.decoder, bytes)
            .map_err(|_| Error::PublicInput)
    }
    pub(crate) fn finish(self, engine: &mut Engine) -> Result<(), Error> {
        if self.hash.finish().map_err(|_| Error::PublicInput)? != self.expected {
            return Err(Error::PublicInput);
        }
        let polynomial = engine
            .finish_polynomial(self.decoder)
            .map_err(|_| Error::PublicInput)?;
        engine
            .load_key(self.ordinal, polynomial)
            .map_err(|_| Error::Arithmetic)
    }
}

/// An accepted ballot body's stream, whose bytes must have the identity its
/// envelope names. The FHE ciphertext's two components follow the header.
pub(crate) struct BallotReader {
    author: usize,
    length: usize,
    received: usize,
    hash: BodyHasher,
    expected: [u8; 64],
    components: [PolynomialDecoder; 2],
}
impl BallotReader {
    pub(crate) fn length(&self) -> usize {
        self.length
    }
    pub(crate) fn push(&mut self, engine: &Engine, bytes: &[u8]) -> Result<(), Error> {
        self.hash.push(bytes).map_err(|_| Error::PublicInput)?;
        let split = DEGREE * engine.coefficient_bytes();
        let received = self.received;
        for (index, component) in self.components.iter_mut().enumerate() {
            let start = HEADER_BYTES + index * split;
            let first = received.max(start);
            let last = (received + bytes.len()).min(start + split);
            if first < last {
                engine
                    .decode_into(component, &bytes[first - received..last - received])
                    .map_err(|_| Error::PublicInput)?;
            }
        }
        self.received += bytes.len();
        Ok(())
    }
    pub(crate) fn finish(self, engine: &mut Engine) -> Result<(), Error> {
        if self.hash.finish().map_err(|_| Error::PublicInput)? != self.expected {
            return Err(Error::PublicInput);
        }
        let [first, second] = self.components;
        let value = [
            engine
                .finish_polynomial(first)
                .map_err(|_| Error::PublicInput)?,
            engine
                .finish_polynomial(second)
                .map_err(|_| Error::PublicInput)?,
        ];
        engine
            .load_input(self.author, value)
            .map_err(|_| Error::Arithmetic)
    }
}

/// Passes exactly the length's bytes of the reader to the receiver in parts
/// of at most one mebibyte, and refuses a reader that holds more.
fn read_exactly(
    mut reader: Box<dyn Read + '_>,
    length: usize,
    mut receive: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut buffer = vec![0; length.min(1 << 20)];
    let mut offset = 0;
    while offset < length {
        let part = buffer.len().min(length - offset);
        reader
            .read_exact(&mut buffer[..part])
            .map_err(|_| Error::PublicInput)?;
        receive(&buffer[..part])?;
        offset += part;
    }
    if reader.read(&mut [0]).map_err(|_| Error::PublicInput)? != 0 {
        return Err(Error::PublicInput);
    }
    Ok(())
}

const RETAINED_TARGET_LABEL: &[u8] = b"sealed-lattice/retained-evaluation-target/v2";
const RETAINED_TARGET_MAGIC: &[u8; 4] = b"RET1";

/// Only completed deterministic evaluation (or an accepted set below the
/// minimum turnout) creates this value, or its restoration from the copy the
/// same participant's credential keyed when it evaluated. Target signatures
/// and durable handoff are separate.
pub struct VerifiedEvaluationTarget {
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    // The classified closed inventory this instance evaluated; a restored
    // target has none.
    classified: Option<ClassifiedClosedInventory>,
    body: Vec<u8>,
    identity: [u8; 64],
    ciphertext: Option<Vec<u8>>,
}
impl VerifiedEvaluationTarget {
    fn finish(
        inventory: ClassifiedClosedInventory,
        fields: Vec<CanonicalItem>,
        ciphertext: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let body = CanonicalTuple::new(1, 1, fields)
            .encode()
            .map_err(|_| Error::Encoding)?;
        let identity = target_identity(&body, inventory.setup.profile().participants())?;
        Ok(Self {
            poll: inventory.poll.clone(),
            setup: inventory.setup.clone(),
            classified: Some(inventory),
            body,
            identity,
            ciphertext,
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn ciphertext(&self) -> Option<&[u8]> {
        self.ciphertext.as_deref()
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn setup(&self) -> &Arc<VerifiedSetupAggregate> {
        &self.setup
    }
    /// The classified closed inventory of an evaluation in this instance.
    pub fn classified(&self) -> Option<&ClassifiedClosedInventory> {
        self.classified.as_ref()
    }
    /// Keys this target, which this instance evaluated, to the participant's
    /// credential: its body and ciphertext, so that a later visit of the same
    /// participant restores it instead of evaluating again.
    pub fn retain(&self, credential: &Credential) -> Result<Vec<u8>, Error> {
        if self.classified.is_none() {
            return Err(Error::Context);
        }
        let ciphertext = self.ciphertext.as_deref().unwrap_or_default();
        let mut bytes = Vec::with_capacity(8 + self.body.len() + ciphertext.len() + 64);
        bytes.extend(RETAINED_TARGET_MAGIC);
        bytes.extend((self.body.len() as u32).to_le_bytes());
        bytes.extend(&self.body);
        bytes.extend(ciphertext);
        let tag = credential.retained_tag(RETAINED_TARGET_LABEL, &self.poll, &bytes);
        bytes.extend(tag);
        Ok(bytes)
    }
    /// Restores the target this participant evaluated from the copy its
    /// credential keyed, for the verified poll and setup of this instance:
    /// the body must name both, and the ciphertext must be the one it names,
    /// or none when it names no evaluation.
    pub fn restore(
        credential: &Credential,
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
        retained: &[u8],
    ) -> Result<Self, Error> {
        let split = retained
            .len()
            .checked_sub(RETAINED_TAG_BYTES)
            .ok_or(Error::Encoding)?;
        let (bytes, tag) = retained.split_at(split);
        credential
            .check_retained_tag(RETAINED_TARGET_LABEL, &poll, bytes, tag)
            .map_err(|_| Error::Context)?;
        if bytes.len() < 8 || &bytes[..4] != RETAINED_TARGET_MAGIC {
            return Err(Error::Encoding);
        }
        let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if length > MAXIMUM_TARGET_BODY_BYTES || bytes.len() < 8 + length {
            return Err(Error::Encoding);
        }
        let (body, ciphertext) = bytes[8..].split_at(length);
        let message = TargetMessage::parse(body, setup.profile().participants())
            .map_err(|_| Error::Encoding)?;
        if message.poll() != &poll.identity() || message.setup_identity() != &setup.identity() {
            return Err(Error::Context);
        }
        let ciphertext = match message.ciphertext_identity() {
            Some(identity) => {
                if identity != &ciphertext_identity(ciphertext)? {
                    return Err(Error::Context);
                }
                Some(ciphertext.to_vec())
            }
            None if ciphertext.is_empty() => None,
            None => return Err(Error::Encoding),
        };
        Ok(Self {
            poll,
            setup,
            classified: None,
            body: body.to_vec(),
            identity: *message.identity(),
            ciphertext,
        })
    }
}

// A target body's identity, which the finality message it parses as names.
fn target_identity(body: &[u8], participants: usize) -> Result<[u8; 64], Error> {
    if body.len() > MAXIMUM_TARGET_BODY_BYTES {
        return Err(Error::Encoding);
    }
    let message = TargetMessage::parse(body, participants).map_err(|_| Error::Encoding)?;
    Ok(*message.identity())
}
