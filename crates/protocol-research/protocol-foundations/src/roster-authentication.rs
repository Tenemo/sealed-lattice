use crate::{Credential, Error, SIGNATURE_BYTES, SigningPurpose, roster::RosterProposal};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

pub const ROSTER_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/roster-proposal/v1";

pub struct AuthenticatedRosterProposal {
    proposal: RosterProposal,
    signature: [u8; SIGNATURE_BYTES],
}
impl AuthenticatedRosterProposal {
    pub fn proposal(&self) -> &RosterProposal {
        &self.proposal
    }
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
}

impl Credential {
    pub fn validate_roster_proposal_target(&self, proposal: &RosterProposal) -> Result<(), Error> {
        self.check_unlocked(SigningPurpose::RosterProposal)?;
        if self.proposal_signed {
            return Err(Error::Consumed);
        }
        let creator = &proposal.records()[proposal.organizer_position()];
        if self.signing_public != creator.header().signing_public
            || self.completed_body != Some(creator.body_digest())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn sign_roster_proposal(
        &mut self,
        proposal: &RosterProposal,
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        self.validate_roster_proposal_target(proposal)?;
        self.proposal_signed = true;
        self.sign_deterministically(&proposal.identity(), ROSTER_SIGNATURE_CONTEXT)
    }
}

pub fn authenticate_roster_proposal(
    proposal: RosterProposal,
    signature: &[u8],
) -> Result<AuthenticatedRosterProposal, Error> {
    let signature: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| Error::Shape)?;
    let key = proposal.records()[proposal.organizer_position()]
        .header()
        .signing_public;
    let public = ml_dsa_65::PublicKey::try_from_bytes(key).map_err(|_| Error::Shape)?;
    if !public.verify(&proposal.identity(), &signature, ROSTER_SIGNATURE_CONTEXT) {
        return Err(Error::Crypto);
    }
    Ok(AuthenticatedRosterProposal {
        proposal,
        signature,
    })
}
