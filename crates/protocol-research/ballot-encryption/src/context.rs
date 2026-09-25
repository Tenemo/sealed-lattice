use registration_credentials::{ballot_authentication::RetainedBallotOwner, poll::VerifiedPoll};
use setup_aggregate::RetainedSetupInputs;
use std::sync::Arc;
use supported_profile::Profile;

#[derive(Debug)]
pub struct Error;
/// Fixed private-computation inputs. It is not a public setup capability.
pub struct BallotComputationContext {
    poll: Arc<VerifiedPoll>,
    profile: Profile,
    inventory: [u8; 64],
    position: usize,
}
impl BallotComputationContext {
    pub fn from_retained(
        poll: Arc<VerifiedPoll>,
        owner: &RetainedBallotOwner,
        inputs: &RetainedSetupInputs,
    ) -> Result<Self, Error> {
        let profile = inputs.profile();
        if owner.poll() != &poll.identity()
            || owner.runtime() != &poll.runtime()
            || owner.inventory() != inputs.inventory()
            || owner.position() >= profile.participants()
            || profile.options() != poll.manifest().option_count()
        {
            return Err(Error);
        }
        Ok(Self {
            poll,
            profile,
            inventory: *owner.inventory(),
            position: owner.position(),
        })
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn position(&self) -> usize {
        self.position
    }
}
