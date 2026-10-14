use evaluation_target::release::ReleaseContext;
use linked_release_proof::{
    ReleaseInputs, prepare_release, proof::prove, statement::PublicStatement,
};
use protocol_foundations::{
    Credential, Refusal, ballot_authentication::RetainedSetupOwner, target_signing::TargetMessage,
};
use setup_witness::{contribution::common_share_polynomial, registration::RecipientKey};
use std::sync::Arc;
use word_proof::in_memory::InMemoryProof;

/// Private generation is reachable only from an actual verified target
/// certificate and the corresponding original participant/root context.
pub struct ReleaseWork {
    context: Arc<ReleaseContext>,
    owner: Arc<RetainedSetupOwner>,
}
impl ReleaseWork {
    pub fn new(
        owner: Arc<RetainedSetupOwner>,
        context: Arc<ReleaseContext>,
    ) -> Result<Self, Refusal> {
        let target = context.certificate().target();
        if owner.position() != context.position()
            || owner.poll() != &target.poll().identity()
            || owner.setup_identity() != &target.setup().identity()
        {
            return Err(Refusal::Context);
        }
        Ok(Self { context, owner })
    }
    /// Consumes this volatile operation. The worker must retain the exact
    /// target and the release seed first; restart replays that same
    /// operation from the seed.
    pub fn prove(
        self,
        key: &RecipientKey,
        credential: &mut Credential,
    ) -> Result<(Arc<ReleaseContext>, PublicStatement, InMemoryProof), Refusal> {
        if self.owner.position() != self.context.position()
            || key.public_key() != self.context.public_key()
        {
            return Err(Refusal::Context);
        }
        let target = self.context.certificate().target();
        let setup = target.setup();
        let message = TargetMessage::parse(target.body(), setup.profile().participants())?;
        credential.begin_release(&self.owner, setup.roster(), &message)?;
        // The key lends its secret only to the release's preparation and
        // proof, which leave it with the public statement and proof alone.
        let (statement, proof) = key
            .lend_secret(|secret| {
                let inputs = ReleaseInputs::new(
                    self.context.profile(),
                    common_share_polynomial(),
                    key.public_key().to_vec(),
                    self.context.encrypted_constant().to_vec(),
                    self.context.encrypted_linear().to_vec(),
                    self.context.target_linear().to_vec(),
                    secret,
                )
                .map_err(|_| Refusal::Crypto)?;
                let prepared =
                    prepare_release(inputs, *self.context.header()).map_err(|_| Refusal::Crypto)?;
                let role = self.context.proof_role().map_err(|_| Refusal::Context)?;
                Ok(prove(&role, prepared))
            })
            .map_err(|_| Refusal::Crypto)??;
        let expected = self
            .context
            .statement(&statement.polynomials[5])
            .map_err(|_| Refusal::Crypto)?;
        if statement.header != expected.header || statement.polynomials != expected.polynomials {
            return Err(Refusal::Context);
        }
        Ok((self.context, statement, proof))
    }
}
