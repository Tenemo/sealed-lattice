use registration_credentials::{
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
    let inventory = setup.inventory();
    if position >= inventory.confirmations().len()
        || inventory.proposal().proposal().records()[0].header().poll != poll.identity()
    {
        return Err(Error);
    }
    encode_role(
        poll.identity(),
        poll.runtime(),
        inventory.identity(),
        position,
    )
}
pub fn private_proof_role(
    context: &ballot_encryption::context::BallotComputationContext,
) -> Result<Vec<u8>, Error> {
    encode_role(
        context.poll().identity(),
        context.poll().runtime(),
        *context.inventory(),
        context.position(),
    )
}
fn encode_role(
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
            CanonicalItem::nonempty_ascii("sealed-lattice/ballot-proof/v1").map_err(|_| Error)?,
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
        let original = encode_role([1; 64], [2; 64], [3; 64], 0).unwrap();
        for changed in [
            encode_role([4; 64], [2; 64], [3; 64], 0),
            encode_role([1; 64], [4; 64], [3; 64], 0),
            encode_role([1; 64], [2; 64], [4; 64], 0),
            encode_role([1; 64], [2; 64], [3; 64], 1),
        ] {
            assert_ne!(changed.unwrap(), original);
        }
        assert!(original.len() <= 1024);
        assert!(encode_role([1; 64], [2; 64], [3; 64], usize::MAX).is_err());
    }
}
