use crate::body::VerifiedBallotBody;
use registration_credentials::ballot_authentication::{BallotEnvelope, verify_ballot_signature};
use setup_aggregate::verified::VerifiedSetupAggregate;
use supported_profile::Profile;

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
    pub fn envelope(&self) -> &BallotEnvelope {
        &self.authentication.envelope
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.authentication.signature
    }
}

/// Authenticates the envelope only. Its body and proof still require verification.
#[derive(Clone)]
pub struct AuthenticatedBallotEnvelope {
    profile: Profile,
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
    hash: registration_credentials::identity::BodyHasher,
}
impl BallotBodyAuthentication {
    pub fn new(authentication: AuthenticatedBallotEnvelope) -> Result<Self, Error> {
        let hash = registration_credentials::ballot_body::body_hasher(
            authentication.profile,
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
    let profile = setup.profile();
    let envelope = BallotEnvelope::decode(profile, bytes).map_err(|_| Error::Context)?;
    let signature: [u8; 3309] = signature.try_into().map_err(|_| Error::Signature)?;
    if !verify_ballot_signature(setup.roster(), &setup.identity(), &envelope, &signature) {
        return Err(Error::Signature);
    }
    Ok(AuthenticatedBallotEnvelope {
        profile,
        envelope,
        signature,
    })
}

fn check_setup(body: &VerifiedBallotBody, setup: &VerifiedSetupAggregate) -> Result<usize, Error> {
    let relation = body.relation();
    if relation.inventory() != &setup.identity()
        || relation.poll() != &setup.roster().proposal().records()[0].header().poll
        || relation.position() >= setup.profile().participants()
    {
        return Err(Error::Context);
    }
    Ok(relation.position())
}
pub fn verify_submission(
    body: VerifiedBallotBody,
    setup: &VerifiedSetupAggregate,
    authentication: AuthenticatedBallotEnvelope,
) -> Result<VerifiedBallotSubmission, Error> {
    let position = check_setup(&body, setup)?;
    let envelope = &authentication.envelope;
    if envelope.inventory() != &setup.identity()
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
