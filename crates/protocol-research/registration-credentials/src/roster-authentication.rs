use crate::{Credential, Error, roster::RosterProposal};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

pub const ROSTER_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/roster-proposal/v1";

pub struct OrganizerSignedRoster {
    proposal: RosterProposal,
    signature: [u8; 3309],
}
impl OrganizerSignedRoster {
    pub fn proposal(&self) -> &RosterProposal {
        &self.proposal
    }
    pub fn signature(&self) -> &[u8; 3309] {
        &self.signature
    }
}

impl Credential {
    pub fn consume_proposal_signing(&mut self) {
        self.proposal_signed = true;
    }
    pub fn validate_roster_proposal_target(&self, proposal: &RosterProposal) -> Result<(), Error> {
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
        randomness: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        self.validate_roster_proposal_target(proposal)?;
        self.proposal_signed = true;
        let coins = Zeroizing::new(randomness);
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        private
            .try_sign_with_seed(&coins, &proposal.identity(), ROSTER_SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)
    }
}

pub fn verify_roster_proposal(
    proposal: RosterProposal,
    signature: &[u8],
) -> Result<OrganizerSignedRoster, Error> {
    let signature: [u8; 3309] = signature.try_into().map_err(|_| Error::Shape)?;
    let key = proposal.records()[proposal.organizer_position()]
        .header()
        .signing_public;
    let public = ml_dsa_65::PublicKey::try_from_bytes(key).map_err(|_| Error::Shape)?;
    if !public.verify(&proposal.identity(), &signature, ROSTER_SIGNATURE_CONTEXT) {
        return Err(Error::Crypto);
    }
    Ok(OrganizerSignedRoster {
        proposal,
        signature,
    })
}
