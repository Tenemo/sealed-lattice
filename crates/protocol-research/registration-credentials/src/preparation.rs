//! Original enrollment's single confirmed roster, shared by every
//! preparation purpose. Durable scope comes from the authenticated parent.
use crate::{
    Credential, Error, SigningPurpose,
    roster::{RetainedContributionContext, RosterProposal},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, Signer},
};
use zeroize::Zeroizing;

pub(crate) struct ConfirmedRoster {
    proposal: [u8; 64],
    position: usize,
}

impl Credential {
    /// Mirrors the one roster already committed by the authenticated parent.
    /// An identical replay preserves the lock; another roster never replaces it.
    pub fn confirm_roster(&mut self, context: &RetainedContributionContext) -> Result<(), Error> {
        if self.completed_body != Some(context.owner_body) {
            return Err(Error::Context);
        }
        match &self.confirmed_roster {
            Some(held)
                if held.proposal != context.proposal || held.position != context.position =>
            {
                Err(Error::Context)
            }
            Some(_) => Ok(()),
            None => {
                self.confirmed_roster = Some(ConfirmedRoster {
                    proposal: context.proposal,
                    position: context.position,
                });
                Ok(())
            }
        }
    }
    pub(crate) fn check_confirmed_context(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Error> {
        if self.completed_body != Some(context.owner_body)
            || !self.confirmed_roster.as_ref().is_some_and(|held| {
                held.proposal == context.proposal && held.position == context.position
            })
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub(crate) fn check_confirmed_position(
        &self,
        proposal: &RosterProposal,
        position: usize,
    ) -> Result<(), Error> {
        let original = proposal.records().get(position).ok_or(Error::Context)?;
        if self.signing_public != original.header().signing_public
            || self.completed_body != Some(original.body_digest())
            || !self.confirmed_roster.as_ref().is_some_and(|held| {
                held.proposal == proposal.identity() && held.position == position
            })
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn validate_offer_context(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Error> {
        self.validate_offer_owner(context)?;
        self.check_unlocked(SigningPurpose::Offer)?;
        if self.preparation_retired || self.offer_signed.is_some() {
            return Err(Error::Consumed);
        }
        Ok(())
    }
    pub fn validate_offer_owner(&self, context: &RetainedContributionContext) -> Result<(), Error> {
        self.check_confirmed_context(context)?;
        if self.preparation_retired
            || context.position >= context.profile().setup_eligible_contributors()
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Called only after the parent commits the verified winning setup and
    /// retires every reconstructing source and unused private offer record.
    pub fn retire_preparation(&mut self) {
        self.preparation_retired = true;
        self.locked_purposes |= SigningPurpose::Offer.mask()
            | SigningPurpose::SelectionProposal.mask()
            | SigningPurpose::SelectionEndorsement.mask();
    }
    pub(crate) fn sign_preparation_digest(
        &self,
        identity: &[u8; 64],
        context: &[u8],
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        let coins = Zeroizing::new(coins);
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        private
            .try_sign_with_seed(&coins, identity, context)
            .map_err(|_| Error::Crypto)
    }
}
