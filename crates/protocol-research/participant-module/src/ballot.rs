use ballot_encryption::{context::BallotComputationContext, encryption::check_ballot_scores};
use ballot_proof::statement::setup_input;
use protocol_foundations::{
    Credential, Error, RETAINED_TAG_BYTES, SIGNATURE_BYTES,
    ballot_authentication::{BallotEnvelope, ENVELOPE_BYTES, RetainedBallotOwner},
    poll::{VerifiedPoll, verify_poll},
    roster::RetainedContributionContext,
};
use setup_aggregate::{
    RetainedAggregatePolynomial, RetainedPolynomialReader, RetainedSetupInputs,
    verified::VerifiedSetupAggregate,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// The only producer of a retained setup reference: it encodes the owning
/// setup verifier's result and keys it to the participant's credential.
pub fn retained_setup_reference(
    credential: &Credential,
    poll: &VerifiedPoll,
    setup: &VerifiedSetupAggregate,
) -> Result<Vec<u8>, Error> {
    let mut reference = RetainedSetupInputs::reference(setup).map_err(|_| Error::Context)?;
    let tag = credential.retained_setup_tag(poll, &reference);
    reference.extend(tag);
    Ok(reference)
}

protocol_foundations::operation_codes! {
    /// The ballot commands; the participant session begins the ballot
    /// work, and the work runs every other command.
    pub enum BallotOperation {
        Begin = 0,
        BeginKey = 1,
        PushKey = 2,
        FinishKey = 3,
        Create = 4,
        BeginImport = 5,
        PushImport = 6,
        FinishImport = 7,
        Sign = 8,
        Envelope = 10,
        BodySlice = 11,
        Signature = 12,
    }
}
/// Volatile private operations beneath the authenticated parent's ballot phases.
/// No operation loads a public setup capability from saved records.
pub struct BallotWork {
    owner: RetainedBallotOwner,
    inputs: RetainedSetupInputs,
    context: Option<BallotComputationContext>,
    key: Option<RetainedAggregatePolynomial>,
    reader: Option<RetainedPolynomialReader>,
    key_offset: usize,
    consumed: bool,
    body: Vec<u8>,
    pending: Option<BallotEnvelope>,
    envelope: Option<BallotEnvelope>,
    signature: Option<[u8; SIGNATURE_BYTES]>,
    failed: bool,
}
impl BallotWork {
    pub fn into_owner(self) -> RetainedBallotOwner {
        self.owner
    }
    pub fn new(
        credential: &Credential,
        proposal: &RetainedContributionContext,
        input: &[u8],
    ) -> Result<Self, Error> {
        if input.len() < 132 {
            return Err(Error::Shape);
        }
        let definition_length = u32::from_le_bytes(input[128..132].try_into().unwrap()) as usize;
        if definition_length > protocol_foundations::poll::MAXIMUM_POLL_BYTES
            || input.len() < 132 + definition_length + SIGNATURE_BYTES + 64 + RETAINED_TAG_BYTES
        {
            return Err(Error::Shape);
        }
        let mut offset = 132 + definition_length;
        let poll = Arc::new(verify_poll(
            input[..64].try_into().unwrap(),
            input[64..128].try_into().unwrap(),
            &input[132..offset],
            &input[offset..offset + SIGNATURE_BYTES],
        )?);
        offset += SIGNATURE_BYTES;
        let setup_identity = input[offset..offset + 64].try_into().unwrap();
        offset += 64;
        let retained = &input[offset..];
        let (reference, tag) = retained.split_at(
            retained
                .len()
                .checked_sub(RETAINED_TAG_BYTES)
                .ok_or(Error::Shape)?,
        );
        let owner = credential.retain_setup_ballot_owner(
            &poll,
            proposal,
            setup_identity,
            reference,
            tag,
        )?;
        let inputs = RetainedSetupInputs::parse(proposal.profile(), reference, setup_identity)
            .map_err(|_| Error::Context)?;
        let context = BallotComputationContext::from_retained(poll, &owner, &inputs)
            .map_err(|_| Error::Context)?;
        Ok(Self {
            owner,
            inputs,
            context: Some(context),
            key: None,
            reader: None,
            key_offset: 0,
            consumed: false,
            body: Vec::new(),
            pending: None,
            envelope: None,
            signature: None,
            failed: false,
        })
    }
    pub fn command(
        &mut self,
        credential: &mut Credential,
        operation: BallotOperation,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err(Error::Consumed);
        }
        let result = self.command_inner(credential, operation, argument, input);
        // Public key delivery failures preserve no parsed operand; the current
        // worker must refetch in a fresh private session under the same root.
        // Ballot creation refuses its scores before consuming the attempt, so
        // that refusal leaves the delivered keys usable.
        if result.is_err()
            && matches!(
                operation,
                BallotOperation::BeginKey
                    | BallotOperation::PushKey
                    | BallotOperation::FinishKey
                    | BallotOperation::Create
                    | BallotOperation::BeginImport
                    | BallotOperation::PushImport
                    | BallotOperation::FinishImport
            )
            && (operation != BallotOperation::Create || self.consumed)
        {
            self.failed = true;
        }
        result
    }
    fn command_inner(
        &mut self,
        credential: &mut Credential,
        operation: BallotOperation,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.len() > 1 << 20 {
            return Err(Error::Shape);
        }
        match operation {
            BallotOperation::BeginKey => {
                if !input.is_empty()
                    || self.consumed
                    || self.reader.is_some()
                    || self.key.is_some()
                    || argument != setup_input(self.inputs.profile()).2
                {
                    return Err(Error::Consumed);
                }
                self.reader = Some(
                    self.inputs
                        .read_polynomial(argument)
                        .map_err(|_| Error::Context)?,
                );
                self.key_offset = 0;
            }
            BallotOperation::PushKey => {
                if argument != self.key_offset {
                    return Err(Error::Shape);
                }
                self.reader
                    .as_mut()
                    .ok_or(Error::Consumed)?
                    .push(argument, input)
                    .map_err(|_| Error::Crypto)?;
                self.key_offset += input.len();
            }
            BallotOperation::FinishKey => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                let reader = self.reader.take().ok_or(Error::Consumed)?;
                self.key = Some(reader.finish().map_err(|_| Error::Crypto)?);
            }
            // Input is the ballot time fixed by the attempt lock, then the scores.
            BallotOperation::Create => {
                if argument != 0 || self.consumed || self.key.is_none() || self.reader.is_some() {
                    return Err(Error::Consumed);
                }
                let context = self.context.as_ref().ok_or(Error::Consumed)?;
                let (time, scores) = input.split_at_checked(8).ok_or(Error::Shape)?;
                check_ballot_scores(context.poll(), scores).map_err(|_| Error::Shape)?;
                credential.reserve_ballot_attempt(&self.owner)?;
                self.consumed = true;
                let ballot_time = u64::from_le_bytes(time.try_into().unwrap());
                let scores = Zeroizing::new(scores.to_vec());
                let fhe = self.key.take().unwrap();
                let (body, envelope) = ballot_proof::private_ballot::create(
                    self.context.take().ok_or(Error::Consumed)?,
                    fhe,
                    &scores,
                    ballot_time,
                )
                .map_err(|_| Error::Crypto)?;
                self.body = body;
                self.envelope = Some(envelope);
            }
            BallotOperation::BeginImport => {
                if argument != 0 || self.consumed || self.key.is_none() || self.reader.is_some() {
                    return Err(Error::Consumed);
                }
                let envelope = BallotEnvelope::decode(self.inputs.profile(), input)?;
                if envelope.poll() != self.owner.poll()
                    || envelope.setup_identity() != self.owner.setup_identity()
                    || envelope.position() != self.owner.position()
                {
                    return Err(Error::Context);
                }
                self.consumed = true;
                self.body = Vec::with_capacity(envelope.body_length());
                self.pending = Some(envelope);
            }
            BallotOperation::PushImport => {
                let expected = self.pending.as_ref().ok_or(Error::Consumed)?;
                if input.is_empty()
                    || argument != self.body.len()
                    || input.len() > expected.body_length() - self.body.len()
                {
                    return Err(Error::Shape);
                }
                self.body.extend(input);
            }
            BallotOperation::FinishImport => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                let pending = self.pending.take().ok_or(Error::Consumed)?;
                let key = self.key.take().ok_or(Error::Context)?;
                let checked = ballot_proof::private_ballot::verify(
                    self.context.as_ref().ok_or(Error::Context)?,
                    &key,
                    &self.body,
                    pending.ballot_time(),
                )
                .map_err(|_| Error::Crypto)?;
                if checked.bytes() != pending.bytes() {
                    return Err(Error::Context);
                }
                self.envelope = Some(checked);
            }
            BallotOperation::Sign => {
                if argument != 0 || input.len() != ENVELOPE_BYTES || self.signature.is_some() {
                    return Err(Error::Consumed);
                }
                let envelope = self.envelope.as_ref().ok_or(Error::Consumed)?;
                if input[..ENVELOPE_BYTES] != *envelope.bytes() {
                    return Err(Error::Context);
                }
                self.signature =
                    Some(credential.sign_retained_ballot_envelope(&self.owner, envelope)?);
            }
            BallotOperation::Envelope => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                return Ok(self
                    .envelope
                    .as_ref()
                    .ok_or(Error::Consumed)?
                    .bytes()
                    .to_vec());
            }
            BallotOperation::BodySlice => {
                if input.len() != 4 || self.envelope.is_none() {
                    return Err(Error::Consumed);
                }
                let length = u32::from_le_bytes(input.try_into().unwrap()) as usize;
                if length == 0
                    || length > 1 << 20
                    || argument > self.body.len()
                    || length > self.body.len() - argument
                {
                    return Err(Error::Shape);
                }
                return Ok(self.body[argument..argument + length].to_vec());
            }
            BallotOperation::Signature => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                return Ok(self.signature.as_ref().ok_or(Error::Consumed)?.to_vec());
            }
            BallotOperation::Begin => return Err(Error::Shape),
        }
        Ok(Vec::new())
    }
}
