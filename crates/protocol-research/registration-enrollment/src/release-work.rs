use evaluation_target::release::{RELEASE_PROOF_ROLE, ReleaseContext};
use linked_release_proof::{proof::ReleaseRelationProof, statement::PublicStatement};
use registration_credentials::{
    Credential, Error, ballot_authentication::RetainedBallotOwner, target_signing::TargetMessage,
};
use setup_witness::registration::RegistrationKey;
use std::sync::Arc;

/// Private generation is reachable only from an actual verified target
/// certificate and the corresponding original participant/root context.
pub struct ReleaseWork {
    context: Arc<ReleaseContext>,
    owner: Arc<RetainedBallotOwner>,
}
impl ReleaseWork {
    pub fn new(
        owner: Arc<RetainedBallotOwner>,
        context: Arc<ReleaseContext>,
    ) -> Result<Self, Error> {
        let inventory = context.certificate().target().inventory();
        if owner.position() != context.position()
            || owner.poll() != &inventory.poll().identity()
            || owner.runtime() != &inventory.poll().runtime()
            || owner.inventory() != &inventory.setup().inventory().identity()
        {
            return Err(Error::Context);
        }
        Ok(Self { context, owner })
    }
    /// Consumes this volatile operation. The worker must retain the exact
    /// target and entropy journal first; restart replays that same operation.
    pub fn prove(
        self,
        key: &RegistrationKey,
        credential: &mut Credential,
    ) -> Result<(Arc<ReleaseContext>, PublicStatement, ReleaseRelationProof), Error> {
        if self.owner.position() != self.context.position()
            || key.public_key() != self.context.public_key()
        {
            return Err(Error::Context);
        }
        key.validate_retained().map_err(|_| Error::Crypto)?;
        let target = self.context.certificate().target();
        let setup = target.inventory().setup();
        let message = TargetMessage::parse(target.body(), setup.inventory().confirmations().len())?;
        credential.begin_release(&self.owner, setup.inventory().proposal(), &message)?;
        let prepared = key
            .prepare_release(
                *self.context.header(),
                self.context.encrypted_constant().to_vec(),
                self.context.encrypted_linear().to_vec(),
                self.context.target_linear().to_vec(),
            )
            .map_err(|_| Error::Crypto)?;
        let (statement, proof) = ReleaseRelationProof::from_prepared(RELEASE_PROOF_ROLE, prepared);
        let expected = self
            .context
            .statement(&statement.polynomials[5])
            .map_err(|_| Error::Crypto)?;
        if statement.header != expected.header || statement.polynomials != expected.polynomials {
            return Err(Error::Context);
        }
        Ok((self.context, statement, proof))
    }
}
