use zeroize::Zeroize;

use crate::foundation::RefusalReason;

use super::{
    ProtocolRefusal, ProtocolResult,
    field::{
        BitCodeword, CORRUPTION_BOUND, DIRECT_CHECK_REPETITION_COUNT, FieldElement,
        PARTICIPANT_COUNT, PreparationCandidate, PreparationCandidateCoordinates, ProductCodeword,
        ZeroCodeword,
    },
    random_tape::RandomBitTape,
};

const PREPARATION_RANDOM_BIT_LENGTH: usize = 1 + 4 * (CORRUPTION_BOUND + 6 + CORRUPTION_BOUND);
const SOURCE_RANDOM_BIT_LENGTH: usize = 4 * CORRUPTION_BOUND;
const SOURCE_PAD_RANDOM_BIT_LENGTH: usize = 1 + SOURCE_RANDOM_BIT_LENGTH;

pub(crate) const PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH: usize =
    PREPARATION_RANDOM_BIT_LENGTH.div_ceil(8);
pub(crate) const PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH: usize =
    (DIRECT_CHECK_REPETITION_COUNT * PREPARATION_RANDOM_BIT_LENGTH).div_ceil(8);
pub(crate) const SOURCE_CODEWORD_RANDOM_BYTE_LENGTH: usize = SOURCE_RANDOM_BIT_LENGTH.div_ceil(8);
pub(crate) const SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH: usize =
    (DIRECT_CHECK_REPETITION_COUNT * SOURCE_PAD_RANDOM_BIT_LENGTH).div_ceil(8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceCodewordCoordinates {
    coordinates: [FieldElement; PARTICIPANT_COUNT],
}

impl SourceCodewordCoordinates {
    pub(crate) fn from_coordinates(
        coordinates: [FieldElement; PARTICIPANT_COUNT],
    ) -> ProtocolResult<Self> {
        BitCodeword::verify(coordinates)?;
        Ok(Self { coordinates })
    }

    pub(crate) const fn coordinates(&self) -> &[FieldElement; PARTICIPANT_COUNT] {
        &self.coordinates
    }

    pub(crate) fn bit(&self) -> bool {
        BitCodeword::verify(self.coordinates)
            .expect("source coordinates were verified at construction")
            .constant()
            == FieldElement::ONE
    }
}

impl Zeroize for SourceCodewordCoordinates {
    fn zeroize(&mut self) {
        self.coordinates.zeroize();
    }
}

impl Drop for SourceCodewordCoordinates {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub(crate) fn create_preparation_candidate(
    random_bytes: &[u8],
) -> ProtocolResult<PreparationCandidateCoordinates> {
    let mut tape = RandomBitTape::new(random_bytes, PREPARATION_RANDOM_BIT_LENGTH)?;
    let candidate = create_preparation_from_tape(&mut tape)?;
    tape.finish()?;
    Ok(PreparationCandidateCoordinates::from(candidate))
}

pub(crate) fn create_preparation_response_pads(
    random_bytes: &[u8],
) -> ProtocolResult<Vec<PreparationCandidateCoordinates>> {
    let required_bit_length = DIRECT_CHECK_REPETITION_COUNT
        .checked_mul(PREPARATION_RANDOM_BIT_LENGTH)
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "preparation response-pad tape length overflows",
            )
        })?;
    let mut tape = RandomBitTape::new(random_bytes, required_bit_length)?;
    let mut pads = Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT);
    for _ in 0..DIRECT_CHECK_REPETITION_COUNT {
        pads.push(PreparationCandidateCoordinates::from(
            create_preparation_from_tape(&mut tape)?,
        ));
    }
    tape.finish()?;
    Ok(pads)
}

pub(crate) fn create_source_codeword(
    bit: bool,
    random_bytes: &[u8],
) -> ProtocolResult<SourceCodewordCoordinates> {
    let mut tape = RandomBitTape::new(random_bytes, SOURCE_RANDOM_BIT_LENGTH)?;
    let word = create_bit_codeword_from_tape(bit, &mut tape)?;
    tape.finish()?;
    SourceCodewordCoordinates::from_coordinates(*word.coordinates())
}

pub(crate) fn create_source_response_pads(
    random_bytes: &[u8],
) -> ProtocolResult<Vec<SourceCodewordCoordinates>> {
    let required_bit_length = DIRECT_CHECK_REPETITION_COUNT
        .checked_mul(SOURCE_PAD_RANDOM_BIT_LENGTH)
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "source response-pad tape length overflows",
            )
        })?;
    let mut tape = RandomBitTape::new(random_bytes, required_bit_length)?;
    let mut pads = Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT);
    for _ in 0..DIRECT_CHECK_REPETITION_COUNT {
        let bit = tape.read_bit()?;
        let word = create_bit_codeword_from_tape(bit, &mut tape)?;
        pads.push(SourceCodewordCoordinates::from_coordinates(
            *word.coordinates(),
        )?);
    }
    tape.finish()?;
    Ok(pads)
}

pub(crate) fn aggregate_preparation_coordinates(
    dealers: &[&PreparationCandidateCoordinates],
) -> ProtocolResult<PreparationCandidateCoordinates> {
    require_complete_dealer_batch(dealers.len())?;
    let mut aggregate = PreparationCandidateCoordinates {
        low: [FieldElement::ZERO; PARTICIPANT_COUNT],
        high: [FieldElement::ZERO; PARTICIPANT_COUNT],
        output_zero: [FieldElement::ZERO; PARTICIPANT_COUNT],
    };
    for dealer in dealers {
        add_coordinates(&mut aggregate.low, &dealer.low);
        add_coordinates(&mut aggregate.high, &dealer.high);
        add_coordinates(&mut aggregate.output_zero, &dealer.output_zero);
    }
    Ok(aggregate)
}

pub(crate) fn aggregate_source_pad_coordinates(
    dealers: &[&SourceCodewordCoordinates],
) -> ProtocolResult<[FieldElement; PARTICIPANT_COUNT]> {
    require_complete_dealer_batch(dealers.len())?;
    let mut aggregate = [FieldElement::ZERO; PARTICIPANT_COUNT];
    for dealer in dealers {
        add_coordinates(&mut aggregate, dealer.coordinates());
    }
    Ok(aggregate)
}

fn create_preparation_from_tape(
    tape: &mut RandomBitTape<'_>,
) -> ProtocolResult<PreparationCandidate> {
    let common_bit = if tape.read_bit()? {
        FieldElement::ONE
    } else {
        FieldElement::ZERO
    };
    let low = BitCodeword::from_coefficients([
        common_bit,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
    ])?;
    let high = ProductCodeword::from_coefficients([
        common_bit,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
    ])?;
    let output_zero_mask = ZeroCodeword::from_coefficients([
        FieldElement::ZERO,
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
    ])?;
    Ok(PreparationCandidate {
        mask_pair: super::field::MaskPairCodeword { low, high },
        output_zero_mask,
    })
}

fn create_bit_codeword_from_tape(
    bit: bool,
    tape: &mut RandomBitTape<'_>,
) -> ProtocolResult<BitCodeword> {
    BitCodeword::from_coefficients([
        if bit {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
        read_field_element(tape)?,
        read_field_element(tape)?,
        read_field_element(tape)?,
    ])
}

fn read_field_element(tape: &mut RandomBitTape<'_>) -> ProtocolResult<FieldElement> {
    FieldElement::new(tape.read_low_bits(4)?).ok_or_else(|| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "random tape produced a noncanonical field element",
        )
    })
}

fn require_complete_dealer_batch(dealer_count: usize) -> ProtocolResult<()> {
    if dealer_count != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "sharing batch is missing a roster dealer",
        ));
    }
    Ok(())
}

fn add_coordinates(
    target: &mut [FieldElement; PARTICIPANT_COUNT],
    source: &[FieldElement; PARTICIPANT_COUNT],
) {
    for (target_coordinate, source_coordinate) in target.iter_mut().zip(source) {
        *target_coordinate = target_coordinate.add(*source_coordinate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::field::{MaskPairCodeword, ZeroCodeword};

    #[test]
    fn preparation_randomness_builds_one_matched_pair_and_zero_mask() {
        let candidate =
            create_preparation_candidate(&[0xa5; PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH])
                .expect("candidate randomness has the exact length");
        MaskPairCodeword::verify(candidate.low, candidate.high)
            .expect("generated mask pair has one common bit");
        ZeroCodeword::verify(candidate.output_zero)
            .expect("generated output mask has zero constant");
        assert!(
            create_preparation_candidate(&[0; PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH - 1])
                .is_err()
        );
    }

    #[test]
    fn source_randomness_preserves_the_selected_bit() {
        let zero = create_source_codeword(false, &[0x6d; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH])
            .expect("source randomness has the exact length");
        let one = create_source_codeword(true, &[0x6d; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH])
            .expect("source randomness has the exact length");
        assert!(!zero.bit());
        assert!(one.bit());
        assert_ne!(zero.coordinates(), one.coordinates());
    }

    #[test]
    fn response_pad_batches_have_exact_independent_row_counts() {
        let preparation = create_preparation_response_pads(&vec![
            0x37;
            PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH
        ])
        .expect("preparation pad tape has the exact length");
        let source =
            create_source_response_pads(&vec![0x91; SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH])
                .expect("source pad tape has the exact length");
        assert_eq!(preparation.len(), DIRECT_CHECK_REPETITION_COUNT);
        assert_eq!(source.len(), DIRECT_CHECK_REPETITION_COUNT);
        assert_ne!(preparation[0], preparation[1]);
        assert_ne!(source[0], source[1]);
    }

    #[test]
    fn all_ten_dealer_coordinates_aggregate_without_prevalidating_corrupt_input() {
        let dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_preparation_candidate(
                    &[dealer.wrapping_mul(17); PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH],
                )
                .expect("dealer randomness has the exact length")
            })
            .collect::<Vec<_>>();
        let dealer_references = dealers.iter().collect::<Vec<_>>();
        let aggregate = aggregate_preparation_coordinates(&dealer_references)
            .expect("complete dealer batch aggregates");
        MaskPairCodeword::verify(aggregate.low, aggregate.high)
            .expect("sum of matched pairs remains matched");
        ZeroCodeword::verify(aggregate.output_zero).expect("sum of zero masks remains zero");
        assert!(aggregate_preparation_coordinates(&dealer_references[..9]).is_err());
    }
}
