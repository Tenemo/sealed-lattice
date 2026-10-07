use registration_credentials::{
    foundation::participant_identity::{ParticipantIdentity, derive_participant_identity},
    foundation::{CanonicalItem, CanonicalTuple},
    poll::VerifiedPoll,
};
use setup_aggregate::verified::VerifiedSetupAggregate;

#[derive(Debug)]
pub struct Error;

pub fn proof_role(
    poll: &VerifiedPoll,
    setup: &VerifiedSetupAggregate,
    position: usize,
) -> Result<Vec<u8>, Error> {
    let original = setup
        .roster()
        .proposal()
        .records()
        .get(position)
        .ok_or(Error)?;
    if position >= setup.profile().participants()
        || original.header().poll != poll.identity()
        || original.header().runtime != poll.runtime()
    {
        return Err(Error);
    }
    encode_role(
        derive_participant_identity(&original.header().signing_public).map_err(|_| Error)?,
        poll.identity(),
        poll.runtime(),
        setup.identity(),
        position,
    )
}
pub fn private_proof_role(
    context: &ballot_encryption::context::BallotComputationContext,
) -> Result<Vec<u8>, Error> {
    encode_role(
        context.participant_identity(),
        context.poll().identity(),
        context.poll().runtime(),
        *context.inventory(),
        context.position(),
    )
}
fn encode_role(
    participant_identity: ParticipantIdentity,
    poll: [u8; 64],
    runtime: [u8; 64],
    inventory: [u8; 64],
    position: usize,
) -> Result<Vec<u8>, Error> {
    let position = u16::try_from(position).map_err(|_| Error)?;
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/ballot-proof/v2").map_err(|_| Error)?,
            CanonicalItem::nonempty_ascii(&participant_identity.to_lowercase_hex())
                .map_err(|_| Error)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(runtime),
            CanonicalItem::hash512(inventory),
            CanonicalItem::unsigned16(position),
        ],
    )
    .encode()
    .map_err(|_| Error)
}

#[cfg(test)]
#[path = "context-tests.rs"]
mod tests;
