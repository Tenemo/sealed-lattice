use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, MaskedBallotBundleError320},
    masked_ballot_release_320::{
        MaskedBallotReleaseCoordinate320, MaskedBallotReleaseDecoder320,
        MaskedBallotReleaseDecoding320, MaskedBallotReleaseError320,
    },
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
};

#[test]
fn completion_release_round_trips_the_minimal_bundle_and_corrects_each_fault_position() {
    let circuit = completion_circuit();
    let decoder = MaskedBallotReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();
    assert_eq!(decoder.required_share_count(), 10);
    assert_eq!(decoder.reconstruction_threshold(), 4);
    assert_eq!(decoder.maximum_inconsistent_share_count(), 3);
    assert_eq!(decoder.codeword_byte_length(), 400);
    assert_eq!(decoder.maximum_interpolation_candidate_count(), 210);

    let bundle = patterned_bundle(&circuit);
    let polynomial = [
        bundle.field_element(),
        field(0x1021),
        field(0x2203),
        field(0x3405),
    ];
    let shares = shares_for_polynomial(FOUNDATION_PROFILE.participant_count, &polynomial);
    let decoded = expect_decoded(decoder.decode(&circuit, &shares).unwrap());
    assert_eq!(decoded.bundle(), &bundle);
    assert!(decoded.inconsistent_roster_positions().is_empty());

    for corrupted_position in 0..FOUNDATION_PROFILE.participant_count {
        let mut corrupted_shares = shares.clone();
        replace_share_value(
            &mut corrupted_shares,
            corrupted_position,
            field(0x4100 + corrupted_position),
        );
        let decoded = expect_decoded(decoder.decode(&circuit, &corrupted_shares).unwrap());
        assert_eq!(decoded.bundle(), &bundle);
        assert_eq!(
            decoded.inconsistent_roster_positions(),
            &[corrupted_position]
        );
    }
}

#[test]
fn completion_release_corrects_three_spread_faults_but_refuses_four() {
    let circuit = completion_circuit();
    let decoder = MaskedBallotReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();
    let bundle = patterned_bundle(&circuit);
    let polynomial = [
        bundle.field_element(),
        field(0x5111),
        field(0x6222),
        field(0x7333),
    ];
    let shares = shares_for_polynomial(FOUNDATION_PROFILE.participant_count, &polynomial);

    for corrupted_positions in [vec![0, 1, 2], vec![0, 4, 9], vec![7, 8, 9]] {
        let mut corrupted_shares = shares.clone();
        for corrupted_position in &corrupted_positions {
            replace_share_value(
                &mut corrupted_shares,
                *corrupted_position,
                field(0x8000 + *corrupted_position),
            );
        }
        let decoded = expect_decoded(decoder.decode(&circuit, &corrupted_shares).unwrap());
        assert_eq!(decoded.bundle(), &bundle);
        assert_eq!(decoded.inconsistent_roster_positions(), corrupted_positions);
    }

    let alternate_polynomial = [
        polynomial[0].add(field(1)),
        polynomial[1],
        polynomial[2],
        polynomial[3],
    ];
    let alternate_shares =
        shares_for_polynomial(FOUNDATION_PROFILE.participant_count, &alternate_polynomial);
    let mut four_faults = shares;
    for corrupted_position in 0..4_u16 {
        four_faults[usize::from(corrupted_position)] =
            alternate_shares[usize::from(corrupted_position)];
    }
    assert_eq!(
        decoder.decode(&circuit, &four_faults),
        Err(MaskedBallotReleaseError320::Undecodable {
            maximum_inconsistent_share_count: 3,
        })
    );
}

#[test]
fn missing_is_pending_and_malformed_coordinate_sets_refuse() {
    let circuit = completion_circuit();
    let decoder = MaskedBallotReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();
    let shares = shares_for_polynomial(
        FOUNDATION_PROFILE.participant_count,
        &[field(1), field(2), field(3), field(4)],
    );

    for received_share_count in 0..decoder.required_share_count() {
        assert_eq!(
            decoder
                .decode(&circuit, &shares[..received_share_count])
                .unwrap(),
            MaskedBallotReleaseDecoding320::Pending {
                required_share_count: 10,
                received_share_count,
            }
        );
    }

    let mut duplicate = shares[..9].to_vec();
    duplicate.push(shares[0]);
    assert_eq!(
        decoder.decode(&circuit, &duplicate),
        Err(MaskedBallotReleaseError320::DuplicateRosterPosition { roster_position: 0 })
    );

    let mut excess = shares.clone();
    excess.push(shares[0]);
    assert_eq!(
        decoder.decode(&circuit, &excess),
        Err(MaskedBallotReleaseError320::ExcessShareCount {
            participant_count: 10,
            actual: 11,
        })
    );

    let wrong_count_share = MaskedBallotReleaseCoordinate320::new(9, 0, field(5)).unwrap();
    assert_eq!(
        decoder.decode(&circuit, &[wrong_count_share]),
        Err(MaskedBallotReleaseError320::ShareParticipantCountMismatch {
            expected: 10,
            actual: 9,
        })
    );

    assert_eq!(
        MaskedBallotReleaseCoordinate320::from_parts(
            FOUNDATION_PROFILE.participant_count,
            3,
            canonical_evaluation_point_320(FOUNDATION_PROFILE.participant_count, 4).unwrap(),
            field(6),
        ),
        Err(MaskedBallotReleaseError320::ShareEvaluationPointMismatch { roster_position: 3 })
    );

    let nine_participant_circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(9, FOUNDATION_PROFILE.option_count, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoder.decode(&nine_participant_circuit, &[]),
        Err(
            MaskedBallotReleaseError320::CircuitParticipantCountMismatch {
                circuit_participant_count: 9,
                release_participant_count: 10,
            }
        )
    );
}

#[test]
fn reconstructed_field_value_must_be_one_canonical_compiler_bundle() {
    let circuit = completion_circuit();
    let decoder = MaskedBallotReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();
    let mut noncanonical_constant_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    noncanonical_constant_bytes[20] = 1;
    let noncanonical_constant =
        BinaryFieldElement320::from_canonical_bytes(&noncanonical_constant_bytes).unwrap();
    let shares = shares_for_polynomial(
        FOUNDATION_PROFILE.participant_count,
        &[noncanonical_constant, field(11), field(12), field(13)],
    );
    assert_eq!(
        decoder.decode(&circuit, &shares),
        Err(MaskedBallotReleaseError320::Bundle(
            MaskedBallotBundleError320::NonzeroCanonicalPadding,
        ))
    );
}

#[test]
fn every_three_share_completion_view_is_compatible_with_another_secret() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let original_polynomial = [field(0x101), field(0x202), field(0x303), field(0x404)];
    let original_secret = original_polynomial[0];

    for first_position in 0..participant_count - 2 {
        for second_position in first_position + 1..participant_count - 1 {
            for third_position in second_position + 1..participant_count {
                let corrupt_positions = [first_position, second_position, third_position];
                let mut vanishing_polynomial = vec![BinaryFieldElement320::ONE];
                for corrupt_position in corrupt_positions {
                    vanishing_polynomial = multiply_by_x_plus_constant(
                        &vanishing_polynomial,
                        canonical_evaluation_point_320(participant_count, corrupt_position)
                            .unwrap(),
                    );
                }
                assert_eq!(vanishing_polynomial.len(), 4);
                assert_ne!(vanishing_polynomial[0], BinaryFieldElement320::ZERO);
                let alternate_polynomial: [BinaryFieldElement320; 4] =
                    core::array::from_fn(|coefficient_position| {
                        original_polynomial[coefficient_position]
                            .add(vanishing_polynomial[coefficient_position])
                    });
                assert_ne!(alternate_polynomial[0], original_secret);
                for corrupt_position in corrupt_positions {
                    let point = canonical_evaluation_point_320(participant_count, corrupt_position)
                        .unwrap();
                    assert_eq!(
                        evaluate_polynomial(&original_polynomial, point),
                        evaluate_polynomial(&alternate_polynomial, point),
                    );
                }
            }
        }
    }
}

#[test]
fn every_admitted_roster_derives_a_unique_decoding_radius() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let decoder = MaskedBallotReleaseDecoder320::new(participant_count).unwrap();
        let minimum_code_distance = usize::from(participant_count)
            - usize::from(roster_parameters.reconstruction_threshold)
            + 1;
        assert!(
            minimum_code_distance > 2 * usize::from(roster_parameters.active_fault_bound),
            "participant count {participant_count}"
        );
        assert_eq!(
            decoder.reconstruction_threshold(),
            usize::from(roster_parameters.reconstruction_threshold)
        );
        assert_eq!(
            decoder.maximum_inconsistent_share_count(),
            usize::from(roster_parameters.active_fault_bound)
        );
        assert_eq!(
            decoder.required_share_count(),
            usize::from(participant_count)
        );
    }
}

fn completion_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}

fn patterned_bundle(circuit: &CompiledTallyCircuit) -> MaskedBallotBundle320 {
    let mut bytes = [0_u8; 16];
    for (position, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(position * 13 + 7).unwrap();
    }
    bytes[15] &= 0b0000_0111;
    MaskedBallotBundle320::from_canonical_bytes(circuit, &bytes).unwrap()
}

fn shares_for_polynomial(
    participant_count: u16,
    coefficients: &[BinaryFieldElement320],
) -> Vec<MaskedBallotReleaseCoordinate320> {
    (0..participant_count)
        .map(|roster_position| {
            let point = canonical_evaluation_point_320(participant_count, roster_position).unwrap();
            MaskedBallotReleaseCoordinate320::new(
                participant_count,
                roster_position,
                evaluate_polynomial(coefficients, point),
            )
            .unwrap()
        })
        .collect()
}

fn replace_share_value(
    shares: &mut [MaskedBallotReleaseCoordinate320],
    roster_position: u16,
    difference: BinaryFieldElement320,
) {
    let share = shares[usize::from(roster_position)];
    shares[usize::from(roster_position)] = MaskedBallotReleaseCoordinate320::new(
        share.participant_count(),
        share.roster_position(),
        share.value().add(difference),
    )
    .unwrap();
}

fn expect_decoded(
    decoding: MaskedBallotReleaseDecoding320,
) -> super::masked_ballot_release_320::DecodedMaskedBallotRelease320 {
    match decoding {
        MaskedBallotReleaseDecoding320::Decoded(decoded) => decoded,
        MaskedBallotReleaseDecoding320::Pending { .. } => {
            panic!("a complete release must not remain pending")
        }
    }
}

fn evaluate_polynomial(
    coefficients: &[BinaryFieldElement320],
    point: BinaryFieldElement320,
) -> BinaryFieldElement320 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(BinaryFieldElement320::ZERO, |value, coefficient| {
            value.multiply(point).add(coefficient)
        })
}

fn multiply_by_x_plus_constant(
    coefficients: &[BinaryFieldElement320],
    constant: BinaryFieldElement320,
) -> Vec<BinaryFieldElement320> {
    let mut product = vec![BinaryFieldElement320::ZERO; coefficients.len() + 1];
    for (position, coefficient) in coefficients.iter().copied().enumerate() {
        product[position] = product[position].add(coefficient.multiply(constant));
        product[position + 1] = product[position + 1].add(coefficient);
    }
    product
}

fn field(value: u16) -> BinaryFieldElement320 {
    BinaryFieldElement320::from_low_polynomial_u16(value)
}
