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
mod tests {
    use super::*;
    #[test]
    fn proof_roles_separate_every_variable_context_input() {
        let owner = derive_participant_identity(&[7; 1952]).unwrap();
        let other_owner = derive_participant_identity(&[8; 1952]).unwrap();
        let original = encode_role(owner, [1; 64], [2; 64], [3; 64], 0).unwrap();
        for changed in [
            encode_role(other_owner, [1; 64], [2; 64], [3; 64], 0),
            encode_role(owner, [4; 64], [2; 64], [3; 64], 0),
            encode_role(owner, [1; 64], [4; 64], [3; 64], 0),
            encode_role(owner, [1; 64], [2; 64], [4; 64], 0),
            encode_role(owner, [1; 64], [2; 64], [3; 64], 1),
        ] {
            assert_ne!(changed.unwrap(), original);
        }
        assert!(original.len() <= 1024);
        assert_eq!(original.len(), 404);
        let tuple = CanonicalTuple::decode(&original, &Default::default()).unwrap();
        assert_eq!(tuple.items.len(), 6);
        assert_eq!(
            tuple.items[0].variable_value_bytes().unwrap(),
            b"sealed-lattice/ballot-proof/v2"
        );
        assert_eq!(
            tuple.items[1].item_type(),
            registration_credentials::foundation::CanonicalItemType::Ascii
        );
        assert_eq!(
            tuple.items[1].variable_value_bytes().unwrap(),
            owner.to_lowercase_hex().as_bytes()
        );
        assert!(encode_role(owner, [1; 64], [2; 64], [3; 64], usize::MAX).is_err());
    }
}
