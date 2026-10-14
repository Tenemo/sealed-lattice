use crate::body::VerifiedBallotBody;
use protocol_foundations::SIGNATURE_BYTES;
use protocol_foundations::ballot_authentication::{BallotEnvelope, verify_ballot_signature};
use setup_aggregate::verified::VerifiedSetupAggregate;
use supported_profile::Profile;

#[derive(Debug)]
pub enum Refusal {
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
}

/// Authenticates the envelope only. Its body and proof still require verification.
#[derive(Clone)]
pub struct AuthenticatedBallotEnvelope {
    profile: Profile,
    envelope: BallotEnvelope,
    signature: [u8; SIGNATURE_BYTES],
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
    hash: protocol_foundations::identity::BodyHasher,
}
impl BallotBodyAuthentication {
    pub fn new(authentication: AuthenticatedBallotEnvelope) -> Result<Self, Refusal> {
        let hash = protocol_foundations::ballot_body::body_hasher(
            authentication.profile,
            authentication.envelope().body_length(),
        )
        .map_err(|_| Refusal::Context)?;
        Ok(Self {
            authentication,
            hash,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.hash.push(bytes).map_err(|_| Refusal::Context)
    }
    pub fn finish(self) -> Result<AuthenticatedBallotBody, Refusal> {
        if &self.hash.finish().map_err(|_| Refusal::Context)?
            != self.authentication.envelope().body_identity()
        {
            return Err(Refusal::Context);
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
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}

pub fn authenticate_envelope(
    setup: &VerifiedSetupAggregate,
    bytes: &[u8],
    signature: &[u8],
) -> Result<AuthenticatedBallotEnvelope, Refusal> {
    let profile = setup.profile();
    let envelope = BallotEnvelope::decode(profile, bytes).map_err(|_| Refusal::Context)?;
    let signature: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| Refusal::Signature)?;
    if !verify_ballot_signature(setup.roster(), &setup.identity(), &envelope, &signature) {
        return Err(Refusal::Signature);
    }
    Ok(AuthenticatedBallotEnvelope {
        profile,
        envelope,
        signature,
    })
}

fn check_setup(
    body: &VerifiedBallotBody,
    setup: &VerifiedSetupAggregate,
) -> Result<usize, Refusal> {
    let relation = body.relation();
    if relation.setup_identity() != &setup.identity()
        || relation.poll() != &setup.roster().proposal().records()[0].header().poll
        || relation.position() >= setup.profile().participants()
    {
        return Err(Refusal::Context);
    }
    Ok(relation.position())
}
pub fn verify_submission(
    body: VerifiedBallotBody,
    setup: &VerifiedSetupAggregate,
    authentication: AuthenticatedBallotEnvelope,
) -> Result<VerifiedBallotSubmission, Refusal> {
    let position = check_setup(&body, setup)?;
    let envelope = &authentication.envelope;
    if envelope.setup_identity() != &setup.identity()
        || envelope.poll() != body.relation().poll()
        || envelope.position() != position
        || envelope.body_length() != body.length()
        || envelope.body_identity() != body.identity()
    {
        return Err(Refusal::Context);
    }
    Ok(VerifiedBallotSubmission {
        body,
        authentication,
    })
}
