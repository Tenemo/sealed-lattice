use registration_credentials::{
    Credential, Error,
    contribution_authentication::{
        CommitmentInventory, SignedConfirmation, SignedOpening, VerifiedConfirmation,
        verify_confirmation,
    },
    contribution_commitment::{ComputedContributionCommitment, ContributionCommitmentHasher},
    roster::RetainedContributionContext,
    roster_authentication::OrganizerSignedRoster,
};
use std::sync::Arc;

enum BodyContext {
    Public(Arc<OrganizerSignedRoster>),
    Retained(Box<RetainedContributionContext>),
}

/// Volatile operations beneath the worker's authenticated persist-before-sign boundary.
/// No method restores durable authority from a public transcript.
#[derive(Default)]
pub struct ContributionSigning {
    context: Option<BodyContext>,
    hasher: Option<ContributionCommitmentHasher>,
    computed: Option<ComputedContributionCommitment>,
    confirmation: Option<SignedConfirmation>,
    confirmations: Vec<VerifiedConfirmation>,
    inventory: Option<CommitmentInventory>,
    opening: Option<SignedOpening>,
}

impl ContributionSigning {
    pub fn body_started(&self) -> bool {
        self.context.is_some()
    }

    pub fn begin_body(
        &mut self,
        credential: &Credential,
        proposal: Arc<OrganizerSignedRoster>,
        position: usize,
        salt: &[u8; 64],
        header: &[u8],
    ) -> Result<(), Error> {
        if self.context.is_some() {
            return Err(Error::Consumed);
        }
        credential.validate_confirmation_position(&proposal, position)?;
        let hasher =
            ContributionCommitmentHasher::new(proposal.proposal(), position, salt, header)?;
        self.context = Some(BodyContext::Public(proposal));
        self.hasher = Some(hasher);
        Ok(())
    }

    pub fn begin_retained_body(
        &mut self,
        credential: &Credential,
        context: RetainedContributionContext,
        salt: &[u8; 64],
        header: &[u8],
    ) -> Result<(), Error> {
        if self.context.is_some() {
            return Err(Error::Consumed);
        }
        let hasher =
            ContributionCommitmentHasher::from_retained(credential, &context, salt, header)?;
        self.context = Some(BodyContext::Retained(Box::new(context)));
        self.hasher = Some(hasher);
        Ok(())
    }

    fn public_proposal(&self) -> Result<&Arc<OrganizerSignedRoster>, Error> {
        match self.context.as_ref() {
            Some(BodyContext::Public(proposal)) => Ok(proposal),
            _ => Err(Error::Context),
        }
    }

    pub fn polynomial(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.hasher
            .as_mut()
            .ok_or(Error::Consumed)?
            .push_polynomial(index, offset, bytes)
    }

    pub fn proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.hasher
            .as_mut()
            .ok_or(Error::Consumed)?
            .push_proof(offset, bytes)
    }

    pub fn finish_body(&mut self) -> Result<(), Error> {
        let value = self.hasher.as_mut().ok_or(Error::Consumed)?.finish()?;
        self.computed = Some(value);
        self.hasher = None;
        Ok(())
    }

    pub fn commitment(&self) -> Option<&[u8; 64]> {
        self.computed
            .as_ref()
            .map(ComputedContributionCommitment::digest)
    }

    pub fn confirmation_body(&self, credential: &Credential) -> Result<Vec<u8>, Error> {
        let computed = self.computed.as_ref().ok_or(Error::Consumed)?;
        match self.context.as_ref().ok_or(Error::Context)? {
            BodyContext::Public(proposal) => credential.confirmation_body(proposal, computed),
            BodyContext::Retained(context) => {
                credential.retained_confirmation_body(context, computed)
            }
        }
    }

    pub fn opening_body(&self, credential: &Credential) -> Result<Vec<u8>, Error> {
        credential.opening_body(self.inventory.as_ref().ok_or(Error::Context)?)
    }

    pub fn sign_confirmation(
        &mut self,
        credential: &mut Credential,
        expected_commitment: &[u8; 64],
        coins: [u8; 32],
    ) -> Result<(), Error> {
        let context = self.context.as_ref().ok_or(Error::Context)?;
        let computed = self.computed.as_ref().ok_or(Error::Consumed)?;
        if computed.digest() != expected_commitment {
            return Err(Error::Context);
        }
        let computed = self.computed.take().unwrap();
        self.confirmation = Some(match context {
            BodyContext::Public(proposal) => {
                credential.sign_confirmation(proposal, computed, coins)?
            }
            BodyContext::Retained(context) => {
                credential.sign_retained_confirmation(context, computed, coins)?
            }
        });
        Ok(())
    }

    /// The worker must authenticate the current retained root before calling this.
    /// The computed value is rebuilt from the same retained complete body and salt.
    pub fn restore_confirmation(
        &mut self,
        credential: &mut Credential,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let proposal = self.public_proposal()?.clone();
        let confirmation = verify_confirmation(&proposal, body, signature)?;
        let computed = self.computed.as_ref().ok_or(Error::Consumed)?;
        if confirmation.commitment() != computed.digest()
            || proposal.proposal().records()[confirmation.position()]
                .header()
                .signing_public
                != *credential.signing_public()
        {
            return Err(Error::Context);
        }
        let computed = self.computed.take().ok_or(Error::Consumed)?;
        credential.restore_confirmation(&proposal, computed, &confirmation)
    }

    pub fn confirmation(&self) -> Option<&SignedConfirmation> {
        self.confirmation.as_ref()
    }

    pub fn accept_confirmation(&mut self, body: &[u8], signature: &[u8]) -> Result<(), Error> {
        if self.inventory.is_some() {
            return Err(Error::Consumed);
        }
        let proposal = self.public_proposal()?;
        let confirmation = verify_confirmation(proposal, body, signature)?;
        if self
            .confirmations
            .iter()
            .any(|old| old.position() == confirmation.position())
        {
            return Err(Error::Consumed);
        }
        self.confirmations.push(confirmation);
        Ok(())
    }

    pub fn finish_inventory(&mut self) -> Result<(), Error> {
        if self.inventory.is_some() {
            return Err(Error::Consumed);
        }
        let proposal = self.public_proposal()?.clone();
        if self.confirmations.len() != proposal.proposal().records().len() {
            return Err(Error::Shape);
        }
        self.inventory = Some(CommitmentInventory::new(
            proposal.clone(),
            std::mem::take(&mut self.confirmations),
        )?);
        Ok(())
    }

    pub fn inventory(&self) -> Option<&CommitmentInventory> {
        self.inventory.as_ref()
    }

    pub fn sign_opening(
        &mut self,
        credential: &mut Credential,
        expected_inventory: &[u8; 64],
        coins: [u8; 32],
    ) -> Result<(), Error> {
        let inventory = self.inventory.as_ref().ok_or(Error::Context)?;
        if inventory.identity_bytes() != expected_inventory {
            return Err(Error::Context);
        }
        self.opening = Some(credential.sign_opening(inventory, coins)?);
        Ok(())
    }

    pub fn consume_opening(
        &self,
        credential: &mut Credential,
        body: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let inventory = self.inventory.as_ref().ok_or(Error::Context)?;
        credential.restore_opening(inventory, body, signature)
    }

    pub fn opening(&self) -> Option<&SignedOpening> {
        self.opening.as_ref()
    }
}
