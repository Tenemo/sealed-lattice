use zeroize::Zeroize;

use crate::foundation::RefusalReason;

use super::{
    ProtocolRefusal, ProtocolResult,
    field::{
        BitCodeword, CORRUPTION_BOUND, DIRECT_CHECK_REPETITION_COUNT, FieldElement,
        PARTICIPANT_COUNT,
    },
    random_tape::RandomBitTape,
};

const RANDOM_BITS_PER_CHALLENGE_CODEWORD: usize = 1 + 4 * CORRUPTION_BOUND;
pub(crate) const CHALLENGE_DEALER_RANDOM_BYTE_LENGTH: usize =
    (DIRECT_CHECK_REPETITION_COUNT * RANDOM_BITS_PER_CHALLENGE_CODEWORD).div_ceil(8);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChallengeDealerCoordinates {
    recipient_blocks: [Vec<FieldElement>; PARTICIPANT_COUNT],
}

impl Zeroize for ChallengeDealerCoordinates {
    fn zeroize(&mut self) {
        for block in &mut self.recipient_blocks {
            block.zeroize();
        }
    }
}

impl Drop for ChallengeDealerCoordinates {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ChallengeDealerCoordinates {
    pub(crate) fn from_recipient_blocks(
        recipient_blocks: [Vec<FieldElement>; PARTICIPANT_COUNT],
    ) -> ProtocolResult<Self> {
        if recipient_blocks
            .iter()
            .any(|block| block.len() != DIRECT_CHECK_REPETITION_COUNT)
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "challenge dealer block has the wrong repetition count",
            ));
        }
        Ok(Self { recipient_blocks })
    }

    pub(crate) fn recipient_block(&self, recipient_position: usize) -> &[FieldElement] {
        &self.recipient_blocks[recipient_position]
    }
}

pub(crate) fn create_challenge_dealer_coordinates(
    random_bytes: &[u8],
) -> ProtocolResult<ChallengeDealerCoordinates> {
    let required_bit_length = DIRECT_CHECK_REPETITION_COUNT
        .checked_mul(RANDOM_BITS_PER_CHALLENGE_CODEWORD)
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "challenge random tape length overflows",
            )
        })?;
    let mut tape = RandomBitTape::new(random_bytes, required_bit_length)?;
    let mut recipient_blocks: [Vec<FieldElement>; PARTICIPANT_COUNT] =
        core::array::from_fn(|_| Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT));
    for _ in 0..DIRECT_CHECK_REPETITION_COUNT {
        let coefficients = [
            if tape.read_bit()? {
                FieldElement::ONE
            } else {
                FieldElement::ZERO
            },
            read_field_element(&mut tape)?,
            read_field_element(&mut tape)?,
            read_field_element(&mut tape)?,
        ];
        let codeword = BitCodeword::from_coefficients(coefficients)?;
        for (recipient_block, coordinate) in recipient_blocks.iter_mut().zip(codeword.coordinates())
        {
            recipient_block.push(*coordinate);
        }
    }
    tape.finish()?;
    ChallengeDealerCoordinates::from_recipient_blocks(recipient_blocks)
}

pub(crate) fn verify_and_aggregate_challenge(
    dealers: &[ChallengeDealerCoordinates],
) -> ProtocolResult<Vec<bool>> {
    if dealers.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "challenge opening is missing a roster dealer",
        ));
    }
    let mut aggregate = Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT);
    for repetition in 0..DIRECT_CHECK_REPETITION_COUNT {
        let mut aggregate_bit = false;
        for dealer in dealers {
            let coordinates =
                core::array::from_fn(|recipient| dealer.recipient_block(recipient)[repetition]);
            let codeword = BitCodeword::verify(coordinates)?;
            aggregate_bit ^= codeword.constant() == FieldElement::ONE;
        }
        aggregate.push(aggregate_bit);
    }
    Ok(aggregate)
}

fn read_field_element(tape: &mut RandomBitTape<'_>) -> ProtocolResult<FieldElement> {
    FieldElement::new(tape.read_low_bits(4)?).ok_or_else(|| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "random tape produced a noncanonical field element",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_valid_dealers_produce_one_public_challenge_vector() {
        let dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                let random_bytes = (0..CHALLENGE_DEALER_RANDOM_BYTE_LENGTH)
                    .map(|offset| dealer.wrapping_mul(29).wrapping_add(offset as u8))
                    .collect::<Vec<_>>();
                create_challenge_dealer_coordinates(&random_bytes)
                    .expect("test dealer randomness has the exact length")
            })
            .collect::<Vec<_>>();
        let aggregate = verify_and_aggregate_challenge(&dealers)
            .expect("ten complete valid dealer openings verify");
        assert_eq!(aggregate.len(), DIRECT_CHECK_REPETITION_COUNT);
        assert!(aggregate.iter().any(|coefficient| *coefficient));
        assert!(aggregate.iter().any(|coefficient| !*coefficient));
    }

    #[test]
    fn missing_dealer_and_invalid_coordinate_refuse() {
        let mut dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_challenge_dealer_coordinates(&vec![
                    dealer;
                    CHALLENGE_DEALER_RANDOM_BYTE_LENGTH
                ])
                .expect("test dealer randomness has the exact length")
            })
            .collect::<Vec<_>>();
        assert!(verify_and_aggregate_challenge(&dealers[..PARTICIPANT_COUNT - 1]).is_err());

        dealers[4].recipient_blocks[9][173] =
            dealers[4].recipient_blocks[9][173].add(FieldElement::ONE);
        assert!(verify_and_aggregate_challenge(&dealers).is_err());
    }

    #[test]
    fn random_tape_length_is_exact_and_used_bits_affect_the_opening() {
        assert!(
            create_challenge_dealer_coordinates(&vec![0; CHALLENGE_DEALER_RANDOM_BYTE_LENGTH - 1])
                .is_err()
        );
        let zero =
            create_challenge_dealer_coordinates(&vec![0; CHALLENGE_DEALER_RANDOM_BYTE_LENGTH])
                .expect("zero tape has the exact length");
        let mut changed_bytes = vec![0; CHALLENGE_DEALER_RANDOM_BYTE_LENGTH];
        changed_bytes[0] = 1;
        let changed = create_challenge_dealer_coordinates(&changed_bytes)
            .expect("changed tape has the exact length");
        assert_ne!(zero, changed);
    }
}
