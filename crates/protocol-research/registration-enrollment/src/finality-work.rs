use ballot_proof::close::ClosedSlot;
use evaluation_target::target::VerifiedEvaluationTarget;
use registration_credentials::{
    Credential, Error,
    ballot_authentication::RetainedBallotOwner,
    target_signing::{TargetMessage, TargetVote},
};
use std::sync::Arc;

/// Whether this participant's own ballot entered the certified inventory. An
/// omitted voter still signs the valid target; the application shows the
/// omission instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnBallotStatus {
    NotCast,
    Late,
    Included,
    Omitted,
}

/// Signing continuation from a genuinely evaluated target. Persistence stays in
/// the root worker.
pub struct FinalityWork {
    owner: Arc<RetainedBallotOwner>,
    target: Arc<VerifiedEvaluationTarget>,
    message: TargetMessage,
}
impl FinalityWork {
    pub fn new(
        owner: Arc<RetainedBallotOwner>,
        target: Arc<VerifiedEvaluationTarget>,
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
    pub fn ballot_status(&self, credential: &Credential) -> OwnBallotStatus {
        let barrier = self.target.inventory().barrier();
        let Some((identity, time)) = credential.signed_ballot() else {
            return OwnBallotStatus::NotCast;
        };
        if *time > barrier.intent().message().close_time() {
            return OwnBallotStatus::Late;
        }
        match &barrier.slots()[self.owner.position()] {
            ClosedSlot::Usable(body)
                if body.authentication().envelope().identity() == *identity =>
            {
                OwnBallotStatus::Included
            }
            _ => OwnBallotStatus::Omitted,
        }
    }
    /// A used response in this participant's name must be the one it signed.
    pub fn sign(
        &self,
        credential: &mut Credential,
        retained_body: &[u8],
        coins: [u8; 32],
    ) -> Result<TargetVote, Error> {
        if retained_body != self.body() {
            return Err(Error::Context);
        }
        let barrier = self.target.inventory().barrier();
        if barrier.responses().iter().any(|response| {
            response.message().responder() == self.owner.position()
                && Some(response.message().identity()) != credential.close_response_identity()
        }) {
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
