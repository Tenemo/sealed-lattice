use registration_credentials::{ballot_authentication::RetainedBallotOwner, poll::VerifiedPoll};
use setup_aggregate::{RetainedSetupInputs, verified::VerifiedSetupAggregate};
use std::sync::Arc;

#[derive(Debug)]
pub struct Error;
/// Fixed private-computation inputs. It is not a public setup capability.
pub struct BallotComputationContext {
    poll: Arc<VerifiedPoll>,
    inventory: [u8; 64],
    position: usize,
}
impl BallotComputationContext {
    pub fn from_verified(
        poll: Arc<VerifiedPoll>,
        setup: &VerifiedSetupAggregate,
        position: usize,
    ) -> Result<Self, Error> {
        if position >= setup.inventory().confirmations().len()
            || setup.inventory().proposal().proposal().records()[0]
                .header()
                .poll
                != poll.identity()
        {
            return Err(Error);
        }
        Ok(Self {
            poll,
            inventory: setup.inventory().identity(),
            position,
        })
    }
    pub fn from_retained(
        poll: Arc<VerifiedPoll>,
        owner: &RetainedBallotOwner,
        inputs: &RetainedSetupInputs,
    ) -> Result<Self, Error> {
        if owner.poll() != &poll.identity()
            || owner.runtime() != &poll.runtime()
            || owner.inventory() != inputs.inventory()
            || owner.position() >= 10
        {
            return Err(Error);
        }
        Ok(Self {
            poll,
            inventory: *owner.inventory(),
            position: owner.position(),
        })
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
}
