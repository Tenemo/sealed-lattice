use ballot_proof::publication::SourceValue;
use evaluation_target::target::VerifiedEvaluationTarget;
use registration_credentials::{
    Credential, Error,
    ballot_authentication::RetainedBallotOwner,
    target_signing::{TargetMessage, TargetVote},
};
use std::sync::Arc;

fn packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(signature);
    bytes
}

/// Signing continuation from a genuinely evaluated target and the original
/// participant's retained public messages. Persistence stays in the root worker.
pub struct FinalityWork {
    owner: Arc<RetainedBallotOwner>,
    target: Arc<VerifiedEvaluationTarget>,
    message: TargetMessage,
}
impl FinalityWork {
    pub fn new(
        owner: Arc<RetainedBallotOwner>,
        target: Arc<VerifiedEvaluationTarget>,
        retained_source: &[u8],
        retained_witness: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let inventory = target.inventory();
        let count = inventory.setup().inventory().confirmations().len();
        if owner.poll() != &inventory.poll().identity()
            || owner.runtime() != &inventory.poll().runtime()
            || owner.inventory() != &inventory.setup().inventory().identity()
            || owner.position() >= count
        {
            return Err(Error::Context);
        }
        let source = inventory.closed().slots()[owner.position()].source();
        let expected = match source.value() {
            SourceValue::Ballot(body) => {
                let mut bytes = vec![1];
                bytes.extend(body.authentication().envelope().bytes());
                bytes.extend(body.authentication().signature());
                bytes
            }
            SourceValue::Empty { body, signature } => {
                let mut bytes = vec![0];
                bytes.extend(packet(body, signature));
                bytes
            }
        };
        if expected != retained_source {
            return Err(Error::Context);
        }
        let mut occurrences = 0;
        for slot in inventory.closed().slots() {
            for batch in slot.batches() {
                if batch.signer() == owner.position() {
                    if retained_witness != Some(packet(batch.body(), batch.signature()).as_slice())
                    {
                        return Err(Error::Context);
                    }
                    occurrences += 1;
                }
            }
        }
        let fault_bound = (count - 1) / 3;
        if occurrences != fault_bound || (fault_bound == 0 && retained_witness.is_some()) {
            return Err(Error::Context);
        }
        let message = TargetMessage::parse(target.body(), count)?;
        if message.identity() != target.identity() {
            return Err(Error::Context);
        }
        Ok(Self {
            owner,
            target,
            message,
        })
    }
    pub fn body(&self) -> &[u8] {
        self.message.body()
    }
    pub fn identity(&self) -> &[u8; 64] {
        self.message.identity()
    }
    pub fn sign(
        &self,
        credential: &mut Credential,
        retained_body: &[u8],
        coins: [u8; 32],
    ) -> Result<TargetVote, Error> {
        if retained_body != self.body() {
            return Err(Error::Context);
        }
        credential.sign_target(
            &self.owner,
            self.target.inventory().setup().inventory().proposal(),
            &self.message,
            coins,
        )
    }
}
