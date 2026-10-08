use registration_credentials::foundation::participant_identity::ParticipantIdentity;
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
    setup_identity: [u8; 64],
    position: usize,
    participant_identity: ParticipantIdentity,
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
            || owner.setup_identity() != inputs.setup_identity()
            || owner.position() >= profile.participants()
            || profile.options() != poll.manifest().option_count()
        {
            return Err(Error);
        }
        Ok(Self {
            poll,
            profile,
            setup_identity: *owner.setup_identity(),
            position: owner.position(),
            participant_identity: owner.participant_identity(),
        })
    }
    pub fn poll(&self) -> &Arc<VerifiedPoll> {
        &self.poll
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn participant_identity(&self) -> ParticipantIdentity {
        self.participant_identity
    }
}
