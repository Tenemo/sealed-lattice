use crate::close::{ClosedSlot, VerifiedCloseBarrier};
use crate::program::RankingProgram;
use ballot_proof::body::BallotBodyClassification;
use encrypted_ranking::ranking::{Ciphertext, DEGREE, Engine, Progress, Refusal};
use protocol_foundations::{
    Credential, RETAINED_TAG_BYTES,
    ballot_authentication::BallotEnvelope,
    ballot_body::{self, HEADER_BYTES},
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    identity::{PUBLIC_POLYNOMIAL_DOMAIN, identity},
    poll::VerifiedPoll,
    target_signing::{MAXIMUM_TARGET_BODY_BYTES, TargetMessage, minimum_turnout},
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{io::Read, sync::Arc};

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
            CanonicalItem::nonempty_ascii("sealed-lattice/evaluation-target/v1")
                .map_err(|_| Error::Encoding)?,
            CanonicalItem::hash512(self.poll.identity()),
            CanonicalItem::hash512(self.setup.identity()),
            CanonicalItem::hash512(*self.barrier.proposal().identity()),
            CanonicalItem::variable_bytes(&self.classifications).map_err(|_| Error::Encoding)?,
        ])
    }
    pub fn start(self) -> Result<EvaluationSession, Error> {
        let program = if self.accepted_authors().count() < minimum_turnout(self.accepted.len()) {
            None
        } else {
            Some(
                RankingProgram::for_profile(
                    self.setup.profile(),
                    usize::from(self.poll.top_count()),
                )
                .map_err(|_| Error::UnsupportedProfile)?,
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
        Ok(EvaluationSession {
            inventory: self,
            program,
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
            if let Some(cache) = required.cache {
                let profile = engine.profile();
                let width = engine.coefficient_bytes();
                // A new cache replaces the earlier cache's records.
                if engine.key_count() == 0 {
                    store.clear_records()?;
                }
                while engine.key_count() < required.key_count {
                    let ordinal = engine.key_count();
                    let (common, index) = Engine::key_identity(profile, cache, ordinal)
                        .map_err(|_| Error::Arithmetic)?;
                    let bytes = if common {
                        let bytes = setup_witness::contribution::common_records(profile, index)
                            .map_err(|_| Error::PublicInput)?;
                        if bytes.len() != DEGREE * width {
                            return Err(Error::PublicInput);
                        }
                        bytes
                    } else {
                        let metadata = session
                            .inventory
                            .setup
                            .polynomials()
                            .iter()
                            .find(|value| value.index() == index)
                            .ok_or(Error::Context)?;
                        let bytes = exact_bytes(inputs.aggregate(index)?, DEGREE * width)?;
                        if identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes).ok()
                            != Some(*metadata.digest())
                        {
                            return Err(Error::PublicInput);
                        }
                        bytes
                    };
                    let polynomial = engine
                        .decode_polynomial(&bytes)
                        .map_err(|_| Error::PublicInput)?;
                    engine
                        .load_key(ordinal, polynomial)
                        .map_err(|_| Error::Arithmetic)?;
                    while let Some((prime, record)) = engine.take_record() {
                        store.put_record(ordinal, prime, &record)?;
                    }
                }
            }
            if let Some(author) = required.input_position {
                let value = if let Some(envelope) = session
                    .inventory
                    .accepted
                    .get(author)
                    .ok_or(Error::Context)?
                    .as_ref()
                {
                    read_ballot(inputs.ballot(author)?, envelope, engine)?
                } else {
                    engine.zero_value()
                };
                engine
                    .load_input(author, value)
                    .map_err(|_| Error::Arithmetic)?;
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

pub struct EvaluationSession {
    pub(crate) inventory: ClassifiedClosedInventory,
    pub(crate) program: Option<RankingProgram>,
    pub(crate) engine: Option<Engine>,
}
impl EvaluationSession {
    pub(crate) fn finish(self) -> Result<VerifiedEvaluationTarget, Error> {
        let Self {
            inventory,
            program,
            engine,
        } = self;
        let mut fields = inventory.target_fields()?;
        let ciphertext = match (program, engine) {
            (None, None) => {
                fields.push(CanonicalItem::unsigned16(0));
                None
            }
            (Some(program), Some(engine)) => {
                let ciphertext = engine.final_switch().map_err(|_| Error::Arithmetic)?;
                let identity = hash_foundation_tuple_512(
                    "sealed-lattice/evaluation-ciphertext/v1",
                    &[CanonicalItem::variable_bytes(&ciphertext).map_err(|_| Error::Encoding)?],
                )
                .map_err(|_| Error::Encoding)?;
                fields.extend([
                    CanonicalItem::unsigned16(1),
                    CanonicalItem::hash512(*program.identity()),
                    CanonicalItem::hash512(identity.into_bytes()),
                    CanonicalItem::unsigned64(ciphertext.len() as u64),
                ]);
                Some(ciphertext)
            }
            _ => return Err(Error::Context),
        };
        VerifiedEvaluationTarget::finish(inventory, fields, ciphertext)
    }
}

fn exact_bytes(mut reader: Box<dyn Read + '_>, length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| Error::PublicInput)?;
    if reader.read(&mut [0]).map_err(|_| Error::PublicInput)? != 0 {
        return Err(Error::PublicInput);
    }
    Ok(bytes)
}
fn read_ballot(
    mut reader: Box<dyn Read + '_>,
    envelope: &BallotEnvelope,
    engine: &Engine,
) -> Result<Ciphertext, Error> {
    let mut hash = ballot_body::body_hasher(engine.profile(), envelope.body_length())
        .map_err(|_| Error::PublicInput)?;
    // The body carries the FHE ciphertext's two components first.
    let split = DEGREE * engine.coefficient_bytes();
    let end = HEADER_BYTES + 2 * split;
    let mut ciphertext = Vec::with_capacity(end - HEADER_BYTES);
    let mut buffer = vec![0; 1 << 20];
    let mut offset = 0;
    while offset < envelope.body_length() {
        let length = buffer.len().min(envelope.body_length() - offset);
        reader
            .read_exact(&mut buffer[..length])
            .map_err(|_| Error::PublicInput)?;
        hash.push(&buffer[..length])
            .map_err(|_| Error::PublicInput)?;
        let first = offset.max(HEADER_BYTES);
        let last = (offset + length).min(end);
        if first < last {
            ciphertext.extend(&buffer[first - offset..last - offset]);
        }
        offset += length;
    }
    if reader.read(&mut [0]).map_err(|_| Error::PublicInput)? != 0
        || &hash.finish().map_err(|_| Error::PublicInput)? != envelope.body_identity()
    {
        return Err(Error::PublicInput);
    }
    if ciphertext.len() != end - HEADER_BYTES {
        return Err(Error::PublicInput);
    }
    Ok([
        engine
            .decode_polynomial(&ciphertext[..split])
            .map_err(|_| Error::PublicInput)?,
        engine
            .decode_polynomial(&ciphertext[split..])
            .map_err(|_| Error::PublicInput)?,
    ])
}

const RETAINED_TARGET_LABEL: &[u8] = b"sealed-lattice/retained-evaluation-target/v1";
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
        // The finality message's parser accepts only a canonical target body
        // of this profile, so its fields are read at their positions.
        let identity = target_identity(body, setup.profile().participants())?;
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_TARGET_BODY_BYTES,
            maximum_item_count: 9,
            maximum_item_byte_length: MAXIMUM_TARGET_BODY_BYTES,
            maximum_nesting_depth: 0,
            ..CanonicalDecodeLimits::default()
        };
        let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Encoding)?;
        let items = &tuple.items;
        let hash = |index: usize| {
            items
                .get(index)
                .filter(|item| item.item_type() == CanonicalItemType::Hash512)
                .map(|item| item.canonical_bytes())
        };
        if hash(1) != Some(poll.identity().as_slice())
            || hash(2) != Some(setup.identity().as_slice())
        {
            return Err(Error::Context);
        }
        let evaluated = match items.len() {
            6 => false,
            9 => true,
            _ => return Err(Error::Encoding),
        };
        let ciphertext = if evaluated {
            let expected = hash_foundation_tuple_512(
                "sealed-lattice/evaluation-ciphertext/v1",
                &[CanonicalItem::variable_bytes(ciphertext).map_err(|_| Error::Encoding)?],
            )
            .map_err(|_| Error::Encoding)?
            .into_bytes();
            if hash(7) != Some(expected.as_slice())
                || items[8].canonical_bytes() != (ciphertext.len() as u64).to_le_bytes()
            {
                return Err(Error::Context);
            }
            Some(ciphertext.to_vec())
        } else if ciphertext.is_empty() {
            None
        } else {
            return Err(Error::Encoding);
        };
        Ok(Self {
            poll,
            setup,
            classified: None,
            body: body.to_vec(),
            identity,
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
