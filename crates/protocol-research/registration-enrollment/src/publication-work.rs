use ballot_proof::{
    publication::{AuthenticatedClose, AuthenticatedSource, PublicationContext},
    submission::{BallotBodyAuthentication, authenticate_envelope},
};
use registration_credentials::{
    Credential, Error,
    ballot_authentication::{BallotEnvelope, RetainedBallotOwner},
    poll::VerifiedPoll,
    publication_signing::PublicationPurpose,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::sync::Arc;

/// Original-key signing beneath the authenticated browser root. Public source
/// inputs pass the owning setup, envelope, and complete-body verifiers first.
pub struct PublicationWork {
    owner: RetainedBallotOwner,
    setup: Arc<VerifiedSetupAggregate>,
    context: PublicationContext,
    close: Option<AuthenticatedClose>,
    sources: Vec<AuthenticatedSource>,
    pending: Option<BallotBodyAuthentication>,
    prepared: Option<(PublicationPurpose, Vec<u8>)>,
}

fn packet(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let length =
        u32::from_le_bytes(bytes.get(..4).ok_or(Error::Shape)?.try_into().unwrap()) as usize;
    if length > 2048 || bytes.len() != 4 + length + 3309 {
        return Err(Error::Shape);
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}
fn purpose(value: usize) -> Result<PublicationPurpose, Error> {
    match value {
        0 => Ok(PublicationPurpose::Close),
        1 => Ok(PublicationPurpose::Empty),
        2 => Ok(PublicationPurpose::Witness),
        _ => Err(Error::Shape),
    }
}
impl PublicationWork {
    pub fn new(
        owner: RetainedBallotOwner,
        poll: Arc<VerifiedPoll>,
        setup: Arc<VerifiedSetupAggregate>,
    ) -> Result<Self, Error> {
        let proposal = setup.inventory().proposal().proposal();
        if owner.poll() != &poll.identity()
            || owner.runtime() != &poll.runtime()
            || owner.inventory() != &setup.inventory().identity()
            || owner.position() >= proposal.records().len()
        {
            return Err(Error::Context);
        }
        let context = PublicationContext::new(poll, setup.clone()).map_err(|_| Error::Context)?;
        Ok(Self {
            owner,
            setup,
            context,
            close: None,
            sources: Vec::new(),
            pending: None,
            prepared: None,
        })
    }
    fn next_author(&self) -> Result<usize, Error> {
        self.context
            .assigned_sources(self.owner.position())
            .map_err(|_| Error::Context)?
            .get(self.sources.len())
            .copied()
            .ok_or(Error::Consumed)
    }
    pub fn command(
        &mut self,
        credential: &mut Credential,
        operation: u32,
        argument: usize,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if input.len() > 1 << 20 || (operation != 1 && operation != 9 && argument != 0) {
            return Err(Error::Shape);
        }
        match operation {
            // Build the exact message from checked dependencies. Input never
            // supplies a witness digest or a caller-selected signing target.
            1 => {
                if !input.is_empty() || self.prepared.is_some() || self.pending.is_some() {
                    return Err(Error::Consumed);
                }
                let selected = purpose(argument)?;
                let body = match selected {
                    PublicationPurpose::Close => self.context.close_body(),
                    PublicationPurpose::Empty => self.context.empty_body(
                        self.close.as_ref().ok_or(Error::Context)?,
                        self.owner.position(),
                    ),
                    PublicationPurpose::Witness => self.context.witness_body(
                        self.owner.position(),
                        &self.sources.iter().collect::<Vec<_>>(),
                    ),
                }
                .map_err(|_| Error::Context)?;
                self.prepared = Some((selected, body.clone()));
                Ok(body)
            }
            2 => {
                if self.close.is_some() || self.prepared.is_some() {
                    return Err(Error::Consumed);
                }
                let (body, signature) = packet(input)?;
                self.close = Some(
                    self.context
                        .authenticate_close(body, signature)
                        .map_err(|_| Error::Crypto)?,
                );
                Ok(Vec::new())
            }
            3 => {
                if self.pending.is_some() || self.prepared.is_some() || input.len() != 206 + 3309 {
                    return Err(Error::Shape);
                }
                let authentication =
                    authenticate_envelope(&self.setup, &input[..206], &input[206..])
                        .map_err(|_| Error::Crypto)?;
                if authentication.envelope().position() != self.next_author()? {
                    return Err(Error::Context);
                }
                self.pending =
                    Some(BallotBodyAuthentication::new(authentication).map_err(|_| Error::Shape)?);
                Ok(Vec::new())
            }
            4 => {
                if self
                    .pending
                    .as_mut()
                    .ok_or(Error::Context)?
                    .push(input)
                    .is_err()
                {
                    self.pending = None;
                    return Err(Error::Crypto);
                }
                Ok(Vec::new())
            }
            5 => {
                if !input.is_empty() {
                    return Err(Error::Shape);
                }
                let body = self
                    .pending
                    .take()
                    .ok_or(Error::Context)?
                    .finish()
                    .map_err(|_| Error::Crypto)?;
                self.sources.push(
                    self.context
                        .ballot_source(body)
                        .map_err(|_| Error::Context)?,
                );
                Ok(Vec::new())
            }
            6 => {
                if self.pending.is_some() || self.prepared.is_some() {
                    return Err(Error::Consumed);
                }
                let (body, signature) = packet(input)?;
                let source = self
                    .context
                    .authenticate_empty(self.close.as_ref().ok_or(Error::Context)?, body, signature)
                    .map_err(|_| Error::Crypto)?;
                if source.author() != self.next_author()? {
                    return Err(Error::Context);
                }
                self.sources.push(source);
                Ok(Vec::new())
            }
            // Signing is reachable only after the root commits this body and
            // its exact coins. This volatile operation consumes before signing.
            8 => {
                if input.len() < 32 {
                    return Err(Error::Shape);
                }
                let (selected, body) = self.prepared.as_ref().ok_or(Error::Context)?;
                if input[..input.len() - 32] != *body {
                    return Err(Error::Context);
                }
                let signature = credential.sign_publication_message(
                    &self.owner,
                    self.setup.inventory().proposal(),
                    *selected,
                    body,
                    self.close
                        .as_ref()
                        .map(|close| close.signature().as_slice()),
                    input[input.len() - 32..].try_into().unwrap(),
                )?;
                self.prepared = None;
                Ok(signature.to_vec())
            }
            9 => {
                if self.prepared.is_some() || self.pending.is_some() {
                    return Err(Error::Consumed);
                }
                let (body, signature) = packet(input)?;
                credential.restore_publication_message(
                    &self.owner,
                    self.setup.inventory().proposal(),
                    purpose(argument)?,
                    body,
                    signature,
                )?;
                Ok(Vec::new())
            }
            // Restore the spent ballot purpose before publication work. This
            // requires the original completed local envelope and signature.
            10 => {
                if input.len() != 206 + 3309 {
                    return Err(Error::Shape);
                }
                let envelope = BallotEnvelope::decode(&input[..206])?;
                credential.restore_retained_ballot_signing(
                    &self.owner,
                    &envelope,
                    &input[206..],
                )?;
                Ok(Vec::new())
            }
            _ => Err(Error::Shape),
        }
    }
}
