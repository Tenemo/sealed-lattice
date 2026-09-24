use crate::program::RankingProgram;
use ballot_proof::{
    body::BallotBodyClassification,
    close::{ClosedSlot, VerifiedCloseBarrier},
};
use num_bigint::Sign;
use registration_credentials::{
    ballot_authentication::BallotEnvelope,
    ballot_body::{BallotBodyHasher, HEADER_BYTES},
    foundation::{CanonicalItem, CanonicalTuple, hash_foundation_tuple_512},
    poll::VerifiedPoll,
    target_signing::{TargetMessage, minimum_turnout},
};
use rns_arithmetic_probe::ranking::{COEFFICIENT_BYTES, Ciphertext, DEGREE, Engine};
use setup_aggregate::verified::VerifiedSetupAggregate;
use sha2::{Digest, Sha512};
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

/// Public working ciphertexts. Every readback is checked against the identity
/// retained in the live evaluator before a value is retired or used again.
pub trait WorkingStore {
    fn put(&mut self, index: usize, value: &Ciphertext) -> Result<(), Error>;
    fn get(&mut self, index: usize) -> Result<Ciphertext, Error>;
    fn remove(&mut self, index: usize) -> Result<(), Error>;
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
    pub fn proposal_identity(&self) -> &[u8; 64] {
        self.barrier.proposal().identity()
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
            CanonicalItem::hash512(self.setup.inventory().identity()),
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
                    self.accepted.len(),
                    self.poll.manifest().option_count(),
                    usize::from(self.poll.top_count()),
                )
                .map_err(|_| Error::UnsupportedProfile)?,
            )
        };
        let engine = program
            .as_ref()
            .map(|program| {
                Engine::new(program.bytes(), *program.identity()).map_err(|_| Error::Arithmetic)
            })
            .transpose()?;
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
                let value = engine.value(index).map_err(|_| Error::Arithmetic)?;
                let expected = engine.value_identity(index, value);
                store.put(index, value)?;
                let restored = store.get(index)?;
                if restored.iter().any(|polynomial| polynomial.len() != DEGREE)
                    || engine.value_identity(index, &restored) != expected
                {
                    return Err(Error::Storage);
                }
                engine
                    .retire_to_storage(index, expected)
                    .map_err(|_| Error::Storage)?;
            }
            for index in required.reloads {
                let value = store.get(index)?;
                engine.reload(index, value).map_err(|_| Error::Storage)?;
            }
            if let Some(cache) = required.cache {
                while engine.key_count() < required.key_count {
                    let ordinal = engine.key_count();
                    let (common, index) =
                        Engine::key_identity(cache, ordinal).map_err(|_| Error::Arithmetic)?;
                    let bytes = if common {
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
                        bytes
                    } else {
                        let metadata = session
                            .inventory
                            .setup
                            .polynomials()
                            .iter()
                            .find(|value| value.index() == index)
                            .ok_or(Error::Context)?;
                        let bytes =
                            exact_bytes(inputs.aggregate(index)?, DEGREE * COEFFICIENT_BYTES)?;
                        if <[u8; 64]>::from(Sha512::digest(&bytes)) != *metadata.digest() {
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
                    std::array::from_fn(|_| vec![[0; 14]; DEGREE])
                };
                engine
                    .load_input(author, value)
                    .map_err(|_| Error::Arithmetic)?;
            }
            let retired = engine.execute().map_err(|_| Error::Arithmetic)?;
            for index in retired {
                store.remove(index)?;
            }
        }
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
    let mut hash = BallotBodyHasher::for_body_length(envelope.body_length())
        .map_err(|_| Error::PublicInput)?;
    let end = HEADER_BYTES + 2 * DEGREE * COEFFICIENT_BYTES;
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
    let split = DEGREE * COEFFICIENT_BYTES;
    Ok([
        engine
            .decode_polynomial(&ciphertext[..split])
            .map_err(|_| Error::PublicInput)?,
        engine
            .decode_polynomial(&ciphertext[split..])
            .map_err(|_| Error::PublicInput)?,
    ])
}

/// Only completed deterministic evaluation (or an accepted set below the
/// minimum turnout) creates this value. Target signatures and durable handoff
/// are separate.
pub struct VerifiedEvaluationTarget {
    inventory: ClassifiedClosedInventory,
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
        if body.len() > 2048 {
            return Err(Error::Encoding);
        }
        let identity = hash_foundation_tuple_512(
            "sealed-lattice/evaluation-target-id/v1",
            &[CanonicalItem::variable_bytes(&body).map_err(|_| Error::Encoding)?],
        )
        .map_err(|_| Error::Encoding)?
        .into_bytes();
        let message =
            TargetMessage::parse(&body, inventory.setup.inventory().confirmations().len())
                .map_err(|_| Error::Encoding)?;
        if message.identity() != &identity {
            return Err(Error::Encoding);
        }
        Ok(Self {
            inventory,
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
    pub fn inventory(&self) -> &ClassifiedClosedInventory {
        &self.inventory
    }
}
