use crate::foundation::RefusalReason;

use super::{
    ProtocolRefusal, ProtocolResult,
    field::{
        DIRECT_CHECK_REPETITION_COUNT, FieldElement, PARTICIPANT_COUNT,
        PreparationCandidateCoordinates, PreparationResponse, create_preparation_response,
        create_source_response, verify_preparation_response_batch, verify_source_response_batch,
    },
    sharing::{
        SourceCodewordCoordinates, aggregate_preparation_coordinates,
        aggregate_source_pad_coordinates,
    },
};

pub(crate) fn create_vertical_preparation_response_batch(
    candidate: &PreparationCandidateCoordinates,
    challenge_coefficients: &[bool],
    dealer_pad_batches: &[Vec<PreparationCandidateCoordinates>],
) -> ProtocolResult<Vec<PreparationResponse>> {
    require_vertical_check_shape(challenge_coefficients, dealer_pad_batches)?;
    let mut responses = Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT);
    for repetition in 0..DIRECT_CHECK_REPETITION_COUNT {
        let pad_references = dealer_pad_batches
            .iter()
            .map(|dealer| &dealer[repetition])
            .collect::<Vec<_>>();
        let aggregate_pad = aggregate_preparation_coordinates(&pad_references)?;
        responses.push(create_preparation_response(
            core::slice::from_ref(candidate),
            core::slice::from_ref(&challenge_coefficients[repetition]),
            &aggregate_pad,
        )?);
    }
    Ok(responses)
}

pub(crate) fn verify_vertical_preparation_response_batch(
    responses: &[PreparationResponse],
) -> ProtocolResult<()> {
    verify_preparation_response_batch(responses)
}

pub(crate) fn create_vertical_source_response_batch(
    candidate: Option<&SourceCodewordCoordinates>,
    challenge_coefficients: &[bool],
    dealer_pad_batches: &[Vec<SourceCodewordCoordinates>],
) -> ProtocolResult<Vec<[FieldElement; PARTICIPANT_COUNT]>> {
    require_vertical_check_shape(challenge_coefficients, dealer_pad_batches)?;
    let mut responses = Vec::with_capacity(DIRECT_CHECK_REPETITION_COUNT);
    for repetition in 0..DIRECT_CHECK_REPETITION_COUNT {
        let pad_references = dealer_pad_batches
            .iter()
            .map(|dealer| &dealer[repetition])
            .collect::<Vec<_>>();
        let aggregate_pad = aggregate_source_pad_coordinates(&pad_references)?;
        responses.push(match candidate {
            Some(candidate) => create_source_response(
                candidate.coordinates(),
                challenge_coefficients[repetition],
                &aggregate_pad,
            ),
            None => aggregate_pad,
        });
    }
    Ok(responses)
}

pub(crate) fn verify_vertical_source_response_batch(
    responses: &[[FieldElement; PARTICIPANT_COUNT]],
) -> ProtocolResult<()> {
    verify_source_response_batch(responses)
}

fn require_vertical_check_shape<Pad>(
    challenge_coefficients: &[bool],
    dealer_pad_batches: &[Vec<Pad>],
) -> ProtocolResult<()> {
    if challenge_coefficients.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "vertical challenge has the wrong repetition count",
        ));
    }
    if dealer_pad_batches.len() != PARTICIPANT_COUNT
        || dealer_pad_batches
            .iter()
            .any(|batch| batch.len() != DIRECT_CHECK_REPETITION_COUNT)
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "vertical response-pad inventory is incomplete",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::{
        challenge::{
            CHALLENGE_DEALER_RANDOM_BYTE_LENGTH, create_challenge_dealer_coordinates,
            verify_and_aggregate_challenge,
        },
        sharing::{
            PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH, PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            SOURCE_CODEWORD_RANDOM_BYTE_LENGTH, SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH,
            create_preparation_candidate, create_preparation_response_pads, create_source_codeword,
            create_source_response_pads,
        },
    };

    fn challenge(seed_offset: u8) -> Vec<bool> {
        let dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_challenge_dealer_coordinates(&vec![
                    seed_offset.wrapping_add(dealer);
                    CHALLENGE_DEALER_RANDOM_BYTE_LENGTH
                ])
                .expect("challenge tape has the exact length")
            })
            .collect::<Vec<_>>();
        verify_and_aggregate_challenge(&dealers).expect("challenge dealers verify")
    }

    #[test]
    fn complete_preparation_check_accepts_and_one_invalid_candidate_coordinate_refuses() {
        let dealers = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_preparation_candidate(
                    &[dealer.wrapping_mul(13); PREPARATION_CANDIDATE_RANDOM_BYTE_LENGTH],
                )
                .expect("candidate tape has the exact length")
            })
            .collect::<Vec<_>>();
        let dealer_references = dealers.iter().collect::<Vec<_>>();
        let candidate = aggregate_preparation_coordinates(&dealer_references)
            .expect("candidate dealer inventory is complete");
        let challenge = challenge(0x41);
        assert!(challenge.iter().any(|coefficient| *coefficient));
        let pads = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_preparation_response_pads(&vec![
                    0x80_u8.wrapping_add(dealer);
                    PREPARATION_RESPONSE_PAD_RANDOM_BYTE_LENGTH
                ])
                .expect("pad tape has the exact length")
            })
            .collect::<Vec<_>>();
        let responses = create_vertical_preparation_response_batch(&candidate, &challenge, &pads)
            .expect("complete response inputs create a batch");
        verify_vertical_preparation_response_batch(&responses).expect("valid batch verifies");

        let mut invalid_candidate = candidate;
        invalid_candidate.high[9] = invalid_candidate.high[9].add(FieldElement::ONE);
        let invalid_responses =
            create_vertical_preparation_response_batch(&invalid_candidate, &challenge, &pads)
                .expect("raw invalid candidate still enters the response relation");
        assert!(verify_vertical_preparation_response_batch(&invalid_responses).is_err());
    }

    #[test]
    fn complete_source_check_accepts_and_mutated_response_refuses() {
        let candidate = create_source_codeword(true, &[0x59; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH])
            .expect("source tape has the exact length");
        let challenge = challenge(0x19);
        let pads = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_source_response_pads(&vec![
                    0x21_u8.wrapping_add(dealer);
                    SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH
                ])
                .expect("source pad tape has the exact length")
            })
            .collect::<Vec<_>>();
        let mut responses =
            create_vertical_source_response_batch(Some(&candidate), &challenge, &pads)
                .expect("complete response inputs create a batch");
        verify_vertical_source_response_batch(&responses).expect("valid source batch verifies");
        responses[207][8] = responses[207][8].add(FieldElement::ONE);
        assert!(verify_vertical_source_response_batch(&responses).is_err());
    }

    #[test]
    fn incomplete_challenge_or_pad_inventory_refuses_before_response() {
        let candidate = create_source_codeword(false, &[0x18; SOURCE_CODEWORD_RANDOM_BYTE_LENGTH])
            .expect("source tape has the exact length");
        let challenge = challenge(0x73);
        let pads = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|dealer| {
                create_source_response_pads(&vec![dealer; SOURCE_RESPONSE_PAD_RANDOM_BYTE_LENGTH])
                    .expect("source pad tape has the exact length")
            })
            .collect::<Vec<_>>();
        assert!(
            create_vertical_source_response_batch(Some(&candidate), &challenge[..383], &pads)
                .is_err()
        );
        assert!(
            create_vertical_source_response_batch(Some(&candidate), &challenge, &pads[..9])
                .is_err()
        );
        let absent = create_vertical_source_response_batch(None, &challenge, &pads)
            .expect("an absent source checks only the complete pad family");
        verify_vertical_source_response_batch(&absent)
            .expect("valid source pads remain valid for canonical absence");
    }
}
