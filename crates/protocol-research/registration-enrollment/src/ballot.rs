use ballot_encryption::{context::BallotComputationContext, encryption::check_ballot_scores};
use registration_credentials::{
    Credential, Error,
    ballot_authentication::{
        BallotEnvelope, ENVELOPE_BYTES, RETAINED_SETUP_TAG_BYTES, RetainedBallotOwner,
    },
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

/// Volatile private operations beneath the authenticated parent's ballot phases.
/// No operation loads a public setup capability from saved records.
pub struct BallotWork {
    owner: RetainedBallotOwner,
    inputs: RetainedSetupInputs,
    context: Option<BallotComputationContext>,
    keys: Vec<RetainedAggregatePolynomial>,
    reader: Option<RetainedPolynomialReader>,
    key_offset: usize,
    consumed: bool,
    body: Vec<u8>,
    pending: Option<BallotEnvelope>,
    envelope: Option<BallotEnvelope>,
    signature: Option<[u8; 3309]>,
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
        if definition_length > registration_credentials::poll::MAXIMUM_POLL_BYTES
            || input.len() < 132 + definition_length + 3309 + 64 + 4
        {
            return Err(Error::Shape);
        }
        let mut offset = 132 + definition_length;
        let poll = Arc::new(verify_poll(
            input[..64].try_into().unwrap(),
            input[64..128].try_into().unwrap(),
            &input[132..offset],
            &input[offset..offset + 3309],
        )?);
        offset += 3309;
        let inventory = input[offset..offset + 64].try_into().unwrap();
        offset += 64;
        let packet_length =
            u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if !(4 + 3309..=4 + 1024 + 3309).contains(&packet_length)
            || input.len() < offset + packet_length
        {
            return Err(Error::Shape);
        }
        let opening_length =
            u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        if packet_length != 4 + opening_length + 3309 {
            return Err(Error::Shape);
        }
        let owner = credential.retain_ballot_owner(
            &poll,
            proposal,
            inventory,
            &input[offset + 4..offset + 4 + opening_length],
            &input[offset + 4 + opening_length..offset + packet_length],
        )?;
        offset += packet_length;
        let retained = &input[offset..];
        let (reference, tag) = retained.split_at(
            retained
                .len()
                .checked_sub(RETAINED_SETUP_TAG_BYTES)
                .ok_or(Error::Shape)?,
        );
        credential.check_retained_setup_tag(&poll, reference, tag)?;
        let inputs =
            RetainedSetupInputs::parse(reference, inventory).map_err(|_| Error::Context)?;
        let context = BallotComputationContext::from_retained(poll, &owner, &inputs)
            .map_err(|_| Error::Context)?;
        Ok(Self {
            owner,
            inputs,
            context: Some(context),
            keys: Vec::new(),
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
        operation: u32,
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
        if result.is_err() && matches!(operation, 1..=7) && (operation != 4 || self.consumed) {
            self.failed = true;
        }
        result
    }
    fn command_inner(
        &mut self,
        credential: &mut Credential,
        operation: u32,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.len() > 1 << 20 {
            return Err(Error::Shape);
        }
        match operation {
            1 => {
                if !input.is_empty()
                    || self.consumed
                    || self.reader.is_some()
                    || self.keys.len() >= 2
                    || argument != [1, 74][self.keys.len()]
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
            2 => {
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
            3 => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                let reader = self.reader.take().ok_or(Error::Consumed)?;
                self.keys.push(reader.finish().map_err(|_| Error::Crypto)?);
            }
            4 => {
                if argument != 0 || self.consumed || self.keys.len() != 2 || self.reader.is_some() {
                    return Err(Error::Consumed);
                }
                let context = self.context.as_ref().ok_or(Error::Consumed)?;
                check_ballot_scores(context.poll(), input).map_err(|_| Error::Shape)?;
                credential.reserve_ballot_attempt(&self.owner)?;
                self.consumed = true;
                let scores = Zeroizing::new(input.to_vec());
                let auxiliary = self.keys.pop().unwrap();
                let fhe = self.keys.pop().unwrap();
                let (body, envelope) = ballot_proof::private_ballot::create(
                    self.context.take().ok_or(Error::Consumed)?,
                    fhe,
                    auxiliary,
                    &scores,
                )
                .map_err(|_| Error::Crypto)?;
                self.body = body;
                self.envelope = Some(envelope);
            }
            5 => {
                if argument != 0 || self.consumed || self.keys.len() != 2 || self.reader.is_some() {
                    return Err(Error::Consumed);
                }
                let envelope = BallotEnvelope::decode(input)?;
                if envelope.poll() != self.owner.poll()
                    || envelope.inventory() != self.owner.inventory()
                    || envelope.position() != self.owner.position()
                {
                    return Err(Error::Context);
                }
                self.consumed = true;
                self.body = Vec::with_capacity(envelope.body_length());
                self.pending = Some(envelope);
            }
            6 => {
                let expected = self.pending.as_ref().ok_or(Error::Consumed)?;
                if input.is_empty()
                    || argument != self.body.len()
                    || input.len() > expected.body_length() - self.body.len()
                {
                    return Err(Error::Shape);
                }
                self.body.extend(input);
            }
            7 => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                let pending = self.pending.take().ok_or(Error::Consumed)?;
                let keys: [RetainedAggregatePolynomial; 2] = std::mem::take(&mut self.keys)
                    .try_into()
                    .map_err(|_| Error::Context)?;
                let checked = ballot_proof::private_ballot::verify(
                    self.context.as_ref().ok_or(Error::Context)?,
                    &keys,
                    &self.body,
                )
                .map_err(|_| Error::Crypto)?;
                if checked.bytes() != pending.bytes() {
                    return Err(Error::Context);
                }
                self.envelope = Some(checked);
            }
            8 => {
                if argument != 0 || input.len() != ENVELOPE_BYTES + 32 || self.signature.is_some() {
                    return Err(Error::Consumed);
                }
                let envelope = self.envelope.as_ref().ok_or(Error::Consumed)?;
                if input[..ENVELOPE_BYTES] != *envelope.bytes() {
                    return Err(Error::Context);
                }
                self.signature = Some(credential.sign_retained_ballot_envelope(
                    &self.owner,
                    envelope,
                    input[ENVELOPE_BYTES..].try_into().unwrap(),
                )?);
            }
            9 => {
                if argument != 0 || input.len() != ENVELOPE_BYTES + 3309 || self.signature.is_some()
                {
                    return Err(Error::Consumed);
                }
                let envelope = self.envelope.as_ref().ok_or(Error::Consumed)?;
                if input[..ENVELOPE_BYTES] != *envelope.bytes() {
                    return Err(Error::Context);
                }
                credential.restore_retained_ballot_signing(
                    &self.owner,
                    envelope,
                    &input[ENVELOPE_BYTES..],
                )?;
                self.signature = Some(input[ENVELOPE_BYTES..].try_into().unwrap());
            }
            10 => {
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
            11 => {
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
            12 => {
                if argument != 0 || !input.is_empty() {
                    return Err(Error::Shape);
                }
                return Ok(self.signature.as_ref().ok_or(Error::Consumed)?.to_vec());
            }
            _ => return Err(Error::Shape),
        }
        Ok(Vec::new())
    }
}
