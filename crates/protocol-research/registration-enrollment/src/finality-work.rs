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
impl OwnBallotStatus {
    /// The status's code in the browser interface.
    pub fn code(self) -> u8 {
        match self {
            Self::NotCast => 0,
            Self::Late => 1,
            Self::Included => 2,
            Self::Omitted => 3,
        }
    }
}

/// The own ballot's status read from a target's classification of this
/// participant's slot instead of from the close barrier: late when signed
/// after the locked close time, included when the slot is usable, which the
/// target classifies as invalid or accepted, and otherwise omitted. Only this
/// participant signs envelopes for its slot, and it signs one, so a usable
/// slot holds that ballot, as the barrier's status requires.
pub fn classified_ballot_status(
    signed_time: Option<u64>,
    close_time: u64,
    classification: Option<u8>,
) -> OwnBallotStatus {
    let Some(time) = signed_time else {
        return OwnBallotStatus::NotCast;
    };
    if time > close_time {
        return OwnBallotStatus::Late;
    }
    match classification {
        Some(1 | 2) => OwnBallotStatus::Included,
        _ => OwnBallotStatus::Omitted,
    }
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
            || owner.inventory() != &target.setup().identity()
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
        credential.sign_target(&self.owner, self.target.setup().roster(), &self.message)
    }
}

#[cfg(test)]
#[path = "finality-work-tests.rs"]
mod tests;
