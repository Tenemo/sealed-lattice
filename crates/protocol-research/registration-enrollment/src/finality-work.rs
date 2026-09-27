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

/// Signing continuation from a target this instance evaluated, whose
/// classified closed inventory it keeps. Persistence stays in the root
/// worker.
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
        let count = target.setup().profile().participants();
        if target.classified().is_none()
            || owner.poll() != &target.poll().identity()
            || owner.runtime() != &target.poll().runtime()
            || owner.inventory() != &target.setup().inventory().identity()
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
    // The close barrier the target was evaluated from, which the constructor
    // requires.
    fn barrier(&self) -> &ballot_proof::close::VerifiedCloseBarrier {
        self.target
            .classified()
            .expect("A finality target keeps its classified inventory.")
            .barrier()
    }
    pub fn ballot_status(&self, credential: &Credential) -> OwnBallotStatus {
        let barrier = self.barrier();
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
        let barrier = self.barrier();
        if barrier.responses().iter().any(|response| {
            response.message().responder() == self.owner.position()
                && Some(response.message().identity()) != credential.close_response_identity()
        }) {
            return Err(Error::Context);
        }
        credential.sign_target(
            &self.owner,
            self.target.setup().inventory().proposal(),
            &self.message,
            coins,
        )
    }
}
