//! Original enrollment's single confirmed roster, shared by every
//! preparation purpose. Durable scope comes from the authenticated parent.
use crate::{
    Credential, Refusal, SigningPurpose,
    roster::{RetainedContributionContext, RosterProposal},
};

pub(crate) struct ConfirmedRoster {
    proposal: [u8; 64],
    position: usize,
}

impl Credential {
    /// Opens the original encrypted source only under the already committed
    /// confirmation and the authenticated proposal. The parent still owns
    /// the generation intent and the required retained seed record.
    pub fn source_contribution(
        &self,
        roster: &crate::roster_authentication::AuthenticatedRosterProposal,
        position: usize,
        source: setup_witness::encrypted_source::EncryptedSource,
    ) -> Result<setup_witness::encrypted_source::LinkedContribution, Refusal> {
        let proposal = roster.proposal();
        self.check_confirmed_position(proposal, position)?;
        self.check_unlocked(SigningPurpose::Offer)?;
        if self.offer_signed.is_some() || self.preparation_retired {
            return Err(Refusal::Consumed);
        }
        let original = proposal.records().get(position).ok_or(Refusal::Context)?;
        let owner =
            crate::foundation::derive_participant_identity(&original.header().signing_public)
                .map_err(|_| Refusal::Shape)?;
        let binding = source
            .public()
            .binding(
                proposal.profile(),
                &original.header().poll,
                owner.as_bytes(),
            )
            .map_err(|_| Refusal::Shape)?;
        if &binding != proposal.source_binding(position)? {
            return Err(Refusal::Context);
        }
        source
            .into_contribution(proposal.profile())
            .map_err(|_| Refusal::Context)
    }

    /// Mirrors the one roster already committed by the authenticated parent.
    /// An identical replay preserves the lock; another roster never replaces it.
    pub fn confirm_roster(&mut self, context: &RetainedContributionContext) -> Result<(), Refusal> {
        if self.completed_body != Some(context.owner_body) {
            return Err(Refusal::Context);
        }
        match &self.confirmed_roster {
            Some(held)
                if held.proposal != context.proposal || held.position != context.position =>
            {
                Err(Refusal::Context)
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
    ) -> Result<(), Refusal> {
        if self.completed_body != Some(context.owner_body)
            || !self.confirmed_roster.as_ref().is_some_and(|held| {
                held.proposal == context.proposal && held.position == context.position
            })
        {
            return Err(Refusal::Context);
        }
        Ok(())
    }
    pub(crate) fn check_confirmed_position(
        &self,
        proposal: &RosterProposal,
        position: usize,
    ) -> Result<(), Refusal> {
        let original = proposal.records().get(position).ok_or(Refusal::Context)?;
        if self.signing_public != original.header().signing_public
            || self.completed_body != Some(original.body_digest())
            || !self.confirmed_roster.as_ref().is_some_and(|held| {
                held.proposal == proposal.identity() && held.position == position
            })
        {
            return Err(Refusal::Context);
        }
        Ok(())
    }
    pub fn validate_offer_context(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Refusal> {
        self.validate_offer_owner(context)?;
        self.check_unlocked(SigningPurpose::Offer)?;
        if self.preparation_retired || self.offer_signed.is_some() {
            return Err(Refusal::Consumed);
        }
        Ok(())
    }
    pub fn validate_offer_owner(
        &self,
        context: &RetainedContributionContext,
    ) -> Result<(), Refusal> {
        self.check_confirmed_context(context)?;
        if self.preparation_retired
            || context.position >= context.profile().setup_eligible_contributors()
        {
            return Err(Refusal::Context);
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
}
