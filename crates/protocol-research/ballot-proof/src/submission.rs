use crate::body::VerifiedBallotBody;
use registration_credentials::{
    Credential,
    ballot_authentication::{BallotEnvelope, verify_ballot_signature},
};
use setup_aggregate::verified::VerifiedSetupAggregate;

#[derive(Debug)]
pub enum Error {
    Context,
    Signature,
}

pub struct VerifiedBallotSubmission {
    body: VerifiedBallotBody,
    authentication: AuthenticatedBallotEnvelope,
}
impl VerifiedBallotSubmission {
    pub fn body(&self) -> &VerifiedBallotBody {
        &self.body
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.authentication.signature
    }
}

/// Authenticates the envelope only. Its body and proof still require verification.
#[derive(Clone)]
pub struct AuthenticatedBallotEnvelope {
    envelope: BallotEnvelope,
    signature: [u8; 3309],
}

/// Exact bytes of an authenticated envelope's body. This is not proof validity.
#[derive(Clone)]
pub struct AuthenticatedBallotBody {
    authentication: AuthenticatedBallotEnvelope,
}
impl AuthenticatedBallotBody {
    pub fn authentication(&self) -> &AuthenticatedBallotEnvelope {
        &self.authentication
    }
}

pub struct BallotBodyAuthentication {
    authentication: AuthenticatedBallotEnvelope,
    hash: registration_credentials::ballot_body::BallotBodyHasher,
}
impl BallotBodyAuthentication {
    pub fn new(authentication: AuthenticatedBallotEnvelope) -> Result<Self, Error> {
        let hash = registration_credentials::ballot_body::BallotBodyHasher::for_body_length(
            authentication.envelope().body_length(),
        )
        .map_err(|_| Error::Context)?;
        Ok(Self {
            authentication,
            hash,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.hash.push(bytes).map_err(|_| Error::Context)
    }
    pub fn finish(self) -> Result<AuthenticatedBallotBody, Error> {
        if &self.hash.finish().map_err(|_| Error::Context)?
            != self.authentication.envelope().body_identity()
        {
            return Err(Error::Context);
        }
        Ok(AuthenticatedBallotBody {
            authentication: self.authentication,
        })
    }
}
impl AuthenticatedBallotEnvelope {
    pub fn envelope(&self) -> &BallotEnvelope {
        &self.envelope
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}

pub fn authenticate_envelope(
    setup: &VerifiedSetupAggregate,
    bytes: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedBallotEnvelope, Error> {
    let envelope = BallotEnvelope::decode(bytes).map_err(|_| Error::Context)?;
    let signature: [u8; 3309] = signature.try_into().map_err(|_| Error::Signature)?;
    if !verify_ballot_signature(
        setup.inventory().proposal(),
        &setup.inventory().identity(),
        &envelope,
        &signature,
    ) {
        return Err(Error::Signature);
    }
    Ok(AuthenticatedBallotEnvelope {
        envelope,
        signature,
    })
}

fn check_setup(body: &VerifiedBallotBody, setup: &VerifiedSetupAggregate) -> Result<usize, Error> {
    let relation = body.relation();
    let inventory = setup.inventory();
    if relation.inventory() != &inventory.identity()
        || relation.poll() != &inventory.proposal().proposal().records()[0].header().poll
        || relation.position() >= inventory.confirmations().len()
    {
        return Err(Error::Context);
    }
    Ok(relation.position())
}
pub fn sign_body(
    credential: &mut Credential,
    body: &VerifiedBallotBody,
    setup: &VerifiedSetupAggregate,
    coins: [u8; 32],
) -> Result<(BallotEnvelope, [u8; 3309]), Error> {
    let position = check_setup(body, setup)?;
    let envelope = BallotEnvelope::new(
        *body.relation().poll(),
        setup.inventory().identity(),
        position,
        body.length(),
        *body.identity(),
    )
    .map_err(|_| Error::Context)?;
    let signature = credential
        .sign_ballot_envelope(setup.inventory().proposal(), &envelope, coins)
        .map_err(|_| Error::Signature)?;
    Ok((envelope, signature))
}
pub fn verify_submission(
    body: VerifiedBallotBody,
    setup: &VerifiedSetupAggregate,
    authentication: AuthenticatedBallotEnvelope,
) -> Result<VerifiedBallotSubmission, Error> {
    let position = check_setup(&body, setup)?;
    let envelope = &authentication.envelope;
    if envelope.inventory() != &setup.inventory().identity()
        || envelope.poll() != body.relation().poll()
        || envelope.position() != position
        || envelope.body_length() != body.length()
        || envelope.body_identity() != body.identity()
    {
        return Err(Error::Context);
    }
    Ok(VerifiedBallotSubmission {
        body,
        authentication,
    })
}
