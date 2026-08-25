use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    degree_three_opening_decoder::{DegreeThreeOpeningDecoder, DegreeThreeOpeningDecoding},
    output_sharing::{DegreeThreeMaskPolynomial, DegreeThreeMaskShare, canonical_evaluation_point},
};

#[test]
fn completion_decoder_corrects_every_static_error_set_through_the_fault_bound() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let polynomial = hostile_polynomial();
    let original_shares = polynomial.shares(participant_count).unwrap();
    let expected_constant_term = polynomial.evaluate(BinaryFieldElement256::ZERO);
    let decoder = DegreeThreeOpeningDecoder::new(participant_count).unwrap();

    for inconsistent_share_mask in 0_u16..(1_u16 << participant_count) {
        if inconsistent_share_mask.count_ones() > u32::from(FOUNDATION_PROFILE.active_fault_bound) {
            continue;
        }
        let mut supplied_shares = original_shares.clone();
        let expected_corrected_positions = (0..participant_count)
            .filter(|roster_position| inconsistent_share_mask & (1_u16 << roster_position) != 0)
            .collect::<Vec<_>>();
        for roster_position in &expected_corrected_positions {
            supplied_shares[usize::from(*roster_position)] = changed_share(
                supplied_shares[usize::from(*roster_position)],
                BinaryFieldElement256::from_low_polynomial_u16(0xa500 | (*roster_position + 1)),
            );
        }
        if inconsistent_share_mask & 1 == 1 {
            supplied_shares.reverse();
        } else if supplied_shares.len() > 1 {
            let rotation = usize::from(inconsistent_share_mask) % supplied_shares.len();
            supplied_shares.rotate_left(rotation);
        }

        let DegreeThreeOpeningDecoding::Decoded(decoded) =
            decoder.decode(&supplied_shares).unwrap()
        else {
            panic!("a complete opening within the active-fault bound must decode");
        };
        assert_eq!(decoded.constant_term(), expected_constant_term);
        assert_eq!(
            decoded.corrected_roster_positions(),
            expected_corrected_positions
        );
    }
}

#[test]
fn one_missing_share_remains_pending_at_every_roster_position() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let shares = hostile_polynomial().shares(participant_count).unwrap();
    let decoder = DegreeThreeOpeningDecoder::new(participant_count).unwrap();

    for missing_roster_position in 0..participant_count {
        let supplied_shares = shares
            .iter()
            .copied()
            .filter(|share| share.roster_position() != missing_roster_position)
            .collect::<Vec<_>>();
        assert_eq!(
            decoder.decode(&supplied_shares).unwrap(),
            DegreeThreeOpeningDecoding::Pending {
                required_share_count: usize::from(participant_count),
                received_share_count: usize::from(participant_count - 1),
            }
        );
    }

    assert_eq!(
        decoder.decode(&[]).unwrap(),
        DegreeThreeOpeningDecoding::Pending {
            required_share_count: usize::from(participant_count),
            received_share_count: 0,
        }
    );
}

#[test]
fn duplicate_and_mixed_roster_shares_are_refused_before_pending() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let shares = hostile_polynomial().shares(participant_count).unwrap();
    let decoder = DegreeThreeOpeningDecoder::new(participant_count).unwrap();
    assert_eq!(
        decoder.decode(&[shares[3], shares[3]]),
        Err(TallyPreparationError::DuplicateSharePosition { roster_position: 3 })
    );

    let other_participant_count = participant_count + 1;
    let other_share = hostile_polynomial()
        .share(other_participant_count, 0)
        .unwrap();
    assert_eq!(
        decoder.decode(&[other_share]),
        Err(TallyPreparationError::ParticipantCountMismatch)
    );
}

#[test]
fn four_consistent_value_changes_exceed_the_unique_decoding_radius() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let mut shares = hostile_polynomial().shares(participant_count).unwrap();
    let common_difference = BinaryFieldElement256::from_low_polynomial_u16(0x5a71);
    for share in shares.iter_mut().take(4) {
        *share = changed_share(*share, common_difference);
    }

    assert_eq!(
        DegreeThreeOpeningDecoder::new(participant_count)
            .unwrap()
            .decode(&shares),
        Err(TallyPreparationError::DegreeThreeOpeningDecodingFailure {
            maximum_inconsistent_share_count: usize::from(FOUNDATION_PROFILE.active_fault_bound),
        })
    );
}

#[test]
fn only_rosters_with_the_degree_three_threshold_and_required_distance_are_admitted() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let result = DegreeThreeOpeningDecoder::new(participant_count);
        if (9..=11).contains(&participant_count) {
            assert!(result.is_ok(), "participant count {participant_count}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(TallyPreparationError::DegreeThreeOpeningProfileMismatch { .. })
                ),
                "participant count {participant_count}"
            );
        }
    }
}

#[test]
fn every_admitted_roster_decodes_its_maximum_error_positions() {
    for participant_count in 9..=11 {
        let decoder = DegreeThreeOpeningDecoder::new(participant_count).unwrap();
        let mut shares = hostile_polynomial().shares(participant_count).unwrap();
        let maximum_error_count = usize::from((participant_count - 1) / 3);
        let first_corrected_position = participant_count
            - u16::try_from(maximum_error_count).expect("the roster fault bound fits in u16");
        for roster_position in first_corrected_position..participant_count {
            shares[usize::from(roster_position)] = changed_share(
                shares[usize::from(roster_position)],
                BinaryFieldElement256::from_low_polynomial_u16(0x7100 | (roster_position + 1)),
            );
        }
        let DegreeThreeOpeningDecoding::Decoded(decoded) = decoder.decode(&shares).unwrap() else {
            panic!("the admitted roster must decode through its derived fault bound");
        };
        assert_eq!(
            decoded.corrected_roster_positions(),
            &(first_corrected_position..participant_count).collect::<Vec<_>>()
        );
    }
}

fn hostile_polynomial() -> DegreeThreeMaskPolynomial {
    DegreeThreeMaskPolynomial::new(
        BinaryFieldElement256::from_canonical_bytes(&[0xff; 32]).unwrap(),
        [
            BinaryFieldElement256::from_canonical_bytes(&[0x81; 32]).unwrap(),
            BinaryFieldElement256::from_canonical_bytes(&[0x42; 32]).unwrap(),
            BinaryFieldElement256::from_canonical_bytes(&[0xbd; 32]).unwrap(),
        ],
    )
}

fn changed_share(
    share: DegreeThreeMaskShare,
    difference: BinaryFieldElement256,
) -> DegreeThreeMaskShare {
    DegreeThreeMaskShare::new(
        share.participant_count(),
        share.roster_position(),
        canonical_evaluation_point(share.participant_count(), share.roster_position()).unwrap(),
        share.value().add(difference),
    )
    .unwrap()
}
