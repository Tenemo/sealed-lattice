use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bivariate_sharing_320::{
        MaskedBallotBivariateCrosspoint320, MaskedBallotBivariateReleaseDecoder320,
        MaskedBallotBivariateReleaseDecoding320, MaskedBallotBivariateRow320,
        MaskedBallotBivariateSharingError320, MaskedBallotSymmetricBivariatePolynomial320,
    },
    masked_ballot_bundle_320::{MaskedBallotBundle320, MaskedBallotBundleError320},
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
};

#[test]
fn every_seven_row_completion_subset_reconstructs_the_same_bundle() {
    let circuit = completion_circuit();
    let bundle = patterned_bundle(&circuit, 7);
    let polynomial = completion_polynomial(&bundle, 0x1100);
    let rows = rows_for_polynomial(&polynomial);
    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();

    assert_eq!(decoder.participant_count(), 10);
    assert_eq!(decoder.reconstruction_threshold(), 4);
    assert_eq!(decoder.minimum_consistent_row_count(), 7);
    assert_eq!(decoder.maximum_row_subset_count(), 120);
    assert_eq!(decoder.committed_field_value_count(), 55);
    assert_eq!(decoder.field_values_per_holder(), 10);
    assert_eq!(polynomial.coefficient_count_per_axis(), 4);
    assert_eq!(polynomial.random_coefficient_count(), 9);

    let mut selected_positions = (0..decoder.minimum_consistent_row_count()).collect::<Vec<_>>();
    let mut tested_subset_count = 0_u64;
    loop {
        let selected_rows = selected_positions
            .iter()
            .map(|position| rows[*position].clone())
            .collect::<Vec<_>>();
        let decoded = expect_decoded(decoder.decode(&circuit, &selected_rows).unwrap());
        assert_eq!(decoded.bundle(), &bundle);
        assert_eq!(
            decoded.supporting_roster_positions(),
            selected_positions
                .iter()
                .map(|position| u16::try_from(*position).unwrap())
                .collect::<Vec<_>>()
        );
        tested_subset_count += 1;
        if !advance_combination(&mut selected_positions, rows.len()) {
            break;
        }
    }
    assert_eq!(tested_subset_count, decoder.maximum_row_subset_count());
}

#[test]
fn three_root_bound_malicious_rows_cannot_change_the_reconstructed_bundle() {
    let circuit = completion_circuit();
    let original_bundle = patterned_bundle(&circuit, 13);
    let alternate_bundle = patterned_bundle(&circuit, 71);
    let original_rows = rows_for_polynomial(&completion_polynomial(&original_bundle, 0x2200));
    let alternate_rows = rows_for_polynomial(&completion_polynomial(&alternate_bundle, 0x5500));
    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();

    for malicious_positions in [[0_u16, 1, 2], [0, 4, 9], [7, 8, 9]] {
        let mut mixed_rows = original_rows.clone();
        for malicious_position in malicious_positions {
            mixed_rows[usize::from(malicious_position)] =
                alternate_rows[usize::from(malicious_position)].clone();
        }
        let decoded = expect_decoded(decoder.decode(&circuit, &mixed_rows).unwrap());
        assert_eq!(decoded.bundle(), &original_bundle);
        assert_eq!(decoded.supporting_roster_positions().len(), 7);
        assert!(
            decoded
                .supporting_roster_positions()
                .iter()
                .all(|position| !malicious_positions.contains(position))
        );
    }
}

#[test]
fn incomplete_inconsistent_rows_remain_pending_and_a_complete_split_burns() {
    let circuit = completion_circuit();
    let first_bundle = patterned_bundle(&circuit, 19);
    let second_bundle = patterned_bundle(&circuit, 91);
    let first_rows = rows_for_polynomial(&completion_polynomial(&first_bundle, 0x3300));
    let second_rows = rows_for_polynomial(&completion_polynomial(&second_bundle, 0x6600));
    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();

    for received_row_count in 0..decoder.minimum_consistent_row_count() {
        assert_eq!(
            decoder
                .decode(&circuit, &first_rows[..received_row_count])
                .unwrap(),
            MaskedBallotBivariateReleaseDecoding320::Pending {
                minimum_consistent_row_count: 7,
                received_row_count,
            }
        );
    }

    let mut split_rows = first_rows[..5].to_vec();
    split_rows.extend_from_slice(&second_rows[5..9]);
    assert_eq!(
        decoder.decode(&circuit, &split_rows).unwrap(),
        MaskedBallotBivariateReleaseDecoding320::Pending {
            minimum_consistent_row_count: 7,
            received_row_count: 9,
        }
    );
    split_rows.push(second_rows[9].clone());
    assert_eq!(
        decoder.decode(&circuit, &split_rows),
        Err(MaskedBallotBivariateSharingError320::NoConsistentRowSet {
            minimum_consistent_row_count: 7,
        })
    );

    let mut locally_invalid_rows = first_rows;
    for roster_position in 0..4_u16 {
        locally_invalid_rows[usize::from(roster_position)] = shift_one_crosspoint(
            &locally_invalid_rows[usize::from(roster_position)],
            field(0x7000 + roster_position),
        );
    }
    assert_eq!(
        decoder.decode(&circuit, &locally_invalid_rows),
        Err(MaskedBallotBivariateSharingError320::NoConsistentRowSet {
            minimum_consistent_row_count: 7,
        })
    );
}

#[test]
fn malformed_row_inventories_refuse_before_algebraic_acceptance() {
    let circuit = completion_circuit();
    let bundle = patterned_bundle(&circuit, 23);
    let rows = rows_for_polynomial(&completion_polynomial(&bundle, 0x4400));
    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();

    let row = &rows[3];
    assert_eq!(
        MaskedBallotBivariateRow320::from_parts(
            row.participant_count(),
            row.roster_position(),
            canonical_evaluation_point_320(row.participant_count(), 4).unwrap(),
            row.secret_axis_value(),
            row.crosspoints().to_vec(),
        ),
        Err(
            MaskedBallotBivariateSharingError320::RowEvaluationPointMismatch { roster_position: 3 }
        )
    );

    let mut missing_crosspoint = row.crosspoints().to_vec();
    missing_crosspoint.pop();
    assert_eq!(
        MaskedBallotBivariateRow320::from_parts(
            row.participant_count(),
            row.roster_position(),
            row.evaluation_point(),
            row.secret_axis_value(),
            missing_crosspoint,
        ),
        Err(
            MaskedBallotBivariateSharingError320::RowCrosspointCountMismatch {
                roster_position: 3,
                expected: 9,
                actual: 8,
            }
        )
    );

    let mut wrong_peer_order = row.crosspoints().to_vec();
    wrong_peer_order.swap(0, 1);
    assert_eq!(
        MaskedBallotBivariateRow320::from_parts(
            row.participant_count(),
            row.roster_position(),
            row.evaluation_point(),
            row.secret_axis_value(),
            wrong_peer_order,
        ),
        Err(
            MaskedBallotBivariateSharingError320::RowCrosspointRosterPositionMismatch {
                roster_position: 3,
                crosspoint_position: 0,
                expected_peer_roster_position: 0,
                actual_peer_roster_position: 1,
            }
        )
    );

    let mut wrong_peer_point = row.crosspoints().to_vec();
    let first_crosspoint = wrong_peer_point[0];
    wrong_peer_point[0] = MaskedBallotBivariateCrosspoint320::from_parts(
        first_crosspoint.peer_roster_position(),
        canonical_evaluation_point_320(row.participant_count(), 1).unwrap(),
        first_crosspoint.value(),
    );
    assert_eq!(
        MaskedBallotBivariateRow320::from_parts(
            row.participant_count(),
            row.roster_position(),
            row.evaluation_point(),
            row.secret_axis_value(),
            wrong_peer_point,
        ),
        Err(
            MaskedBallotBivariateSharingError320::RowCrosspointEvaluationPointMismatch {
                roster_position: 3,
                peer_roster_position: 0,
            }
        )
    );

    let mut duplicate = rows[..9].to_vec();
    duplicate.push(rows[0].clone());
    assert_eq!(
        decoder.decode(&circuit, &duplicate),
        Err(
            MaskedBallotBivariateSharingError320::DuplicateRowRosterPosition { roster_position: 0 }
        )
    );

    let mut excess = rows.clone();
    excess.push(rows[0].clone());
    assert_eq!(
        decoder.decode(&circuit, &excess),
        Err(MaskedBallotBivariateSharingError320::ExcessRowCount {
            participant_count: 10,
            actual: 11,
        })
    );

    let nine_participant_circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(9, FOUNDATION_PROFILE.option_count, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decoder.decode(&nine_participant_circuit, &[]),
        Err(
            MaskedBallotBivariateSharingError320::CircuitParticipantCountMismatch {
                circuit_participant_count: 9,
                sharing_participant_count: 10,
            }
        )
    );

    let nine_participant_bundle = patterned_bundle(&nine_participant_circuit, 29);
    let nine_participant_polynomial = polynomial_for_bundle(
        9,
        &nine_participant_bundle,
        random_coefficients(
            derive_foundation_roster_parameters(9)
                .unwrap()
                .reconstruction_threshold,
            0x8800,
        ),
    );
    assert_eq!(
        decoder.decode(&circuit, &[nine_participant_polynomial.row(0).unwrap()]),
        Err(
            MaskedBallotBivariateSharingError320::RowParticipantCountMismatch {
                expected: 10,
                actual: 9,
            }
        )
    );
}

#[test]
fn reconstructed_secret_must_remain_in_the_compiler_bundle_language() {
    let circuit = completion_circuit();
    let bundle = patterned_bundle(&circuit, 31);
    let rows = rows_for_polynomial(&completion_polynomial(&bundle, 0x7700));
    let mut noncanonical_difference_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    noncanonical_difference_bytes[20] = 1;
    let noncanonical_difference =
        BinaryFieldElement320::from_canonical_bytes(&noncanonical_difference_bytes).unwrap();
    let shifted_rows = rows
        .iter()
        .map(|row| shift_complete_row(row, noncanonical_difference))
        .collect::<Vec<_>>();
    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();

    assert_eq!(
        decoder.decode(&circuit, &shifted_rows),
        Err(MaskedBallotBivariateSharingError320::Bundle(
            MaskedBallotBundleError320::NonzeroCanonicalPadding,
        ))
    );
}

#[test]
fn every_completion_view_of_at_most_three_rows_is_compatible_with_another_bundle() {
    let circuit = completion_circuit();
    let original_bundle = patterned_bundle(&circuit, 37);
    let alternate_bundle = patterned_bundle(&circuit, 101);
    assert_ne!(original_bundle, alternate_bundle);
    let original_polynomial = completion_polynomial(&original_bundle, 0x9900);
    let desired_secret_difference = original_bundle
        .field_element()
        .add(alternate_bundle.field_element());
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let maximum_corrupt_row_count = derive_foundation_roster_parameters(participant_count)
        .unwrap()
        .active_fault_bound;

    for corrupt_row_count in 1..=maximum_corrupt_row_count {
        let mut corrupt_positions = (0..usize::from(corrupt_row_count)).collect::<Vec<_>>();
        loop {
            let corrupt_roster_positions = corrupt_positions
                .iter()
                .map(|position| u16::try_from(*position).unwrap())
                .collect::<Vec<_>>();
            let alternate_polynomial = perturb_outside_rows(
                &original_polynomial,
                &corrupt_roster_positions,
                desired_secret_difference,
            );
            assert_eq!(
                alternate_polynomial
                    .evaluate(BinaryFieldElement320::ZERO, BinaryFieldElement320::ZERO,),
                alternate_bundle.field_element()
            );
            for corrupt_roster_position in &corrupt_roster_positions {
                assert_eq!(
                    original_polynomial.row(*corrupt_roster_position).unwrap(),
                    alternate_polynomial.row(*corrupt_roster_position).unwrap(),
                );
            }
            if !advance_combination(&mut corrupt_positions, usize::from(participant_count)) {
                break;
            }
        }
    }
}

#[test]
fn every_admitted_roster_derives_consistent_bivariate_geometry() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(participant_count, 2, 1).unwrap(),
        )
        .unwrap();
        let bundle = patterned_bundle(&circuit, u8::try_from(participant_count).unwrap());
        let coefficients = random_coefficients(
            roster_parameters.reconstruction_threshold,
            0xa000 + participant_count,
        );
        let polynomial = polynomial_for_bundle(participant_count, &bundle, coefficients);
        let rows = rows_for_polynomial(&polynomial);
        let decoder = MaskedBallotBivariateReleaseDecoder320::new(participant_count).unwrap();
        let minimum_consistent_row_count =
            usize::from(participant_count) - usize::from(roster_parameters.active_fault_bound);
        let minimum_intersection_count =
            2 * minimum_consistent_row_count - usize::from(participant_count);

        assert!(
            minimum_intersection_count >= usize::from(roster_parameters.reconstruction_threshold),
            "participant count {participant_count}"
        );
        assert_eq!(
            decoder.reconstruction_threshold(),
            usize::from(roster_parameters.reconstruction_threshold)
        );
        assert_eq!(
            decoder.minimum_consistent_row_count(),
            minimum_consistent_row_count
        );
        assert_eq!(
            decoder.committed_field_value_count(),
            usize::from(participant_count)
                + (usize::from(participant_count) * (usize::from(participant_count) - 1)) / 2
        );
        assert_eq!(
            decoder.field_values_per_holder(),
            usize::from(participant_count)
        );
        let decoded = expect_decoded(
            decoder
                .decode(&circuit, &rows[..minimum_consistent_row_count])
                .unwrap(),
        );
        assert_eq!(decoded.bundle(), &bundle);
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

fn completion_polynomial(
    bundle: &MaskedBallotBundle320,
    first_coefficient: u16,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    polynomial_for_bundle(
        FOUNDATION_PROFILE.participant_count,
        bundle,
        random_coefficients(
            FOUNDATION_PROFILE.reconstruction_threshold,
            first_coefficient,
        ),
    )
}

fn polynomial_for_bundle(
    participant_count: u16,
    bundle: &MaskedBallotBundle320,
    random_coefficients: Vec<BinaryFieldElement320>,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    MaskedBallotSymmetricBivariatePolynomial320::from_bundle_and_random_coefficients(
        participant_count,
        bundle,
        &random_coefficients,
    )
    .unwrap()
}

fn random_coefficients(
    reconstruction_threshold: u16,
    first_coefficient: u16,
) -> Vec<BinaryFieldElement320> {
    let coefficient_count = usize::from(reconstruction_threshold);
    let random_coefficient_count = coefficient_count * (coefficient_count + 1) / 2 - 1;
    (0..random_coefficient_count)
        .map(|position| {
            field(
                first_coefficient
                    .checked_add(u16::try_from(position).unwrap())
                    .unwrap(),
            )
        })
        .collect()
}

fn rows_for_polynomial(
    polynomial: &MaskedBallotSymmetricBivariatePolynomial320,
) -> Vec<MaskedBallotBivariateRow320> {
    (0..polynomial.participant_count())
        .map(|roster_position| polynomial.row(roster_position).unwrap())
        .collect()
}

fn patterned_bundle(circuit: &CompiledTallyCircuit, pattern_offset: u8) -> MaskedBallotBundle320 {
    let input_bit_count = 3 * (1 + 4 * usize::from(circuit.profile().option_count()));
    let mut bytes = vec![0_u8; input_bit_count.div_ceil(8)];
    for (position, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(position).unwrap().wrapping_mul(17) ^ pattern_offset;
    }
    let used_bits_in_last_byte = input_bit_count % 8;
    if used_bits_in_last_byte != 0 {
        let used_bit_mask = (1_u8 << used_bits_in_last_byte) - 1;
        *bytes.last_mut().unwrap() &= used_bit_mask;
    }
    MaskedBallotBundle320::from_canonical_bytes(circuit, &bytes).unwrap()
}

fn shift_one_crosspoint(
    row: &MaskedBallotBivariateRow320,
    difference: BinaryFieldElement320,
) -> MaskedBallotBivariateRow320 {
    let mut crosspoints = row.crosspoints().to_vec();
    let first_crosspoint = crosspoints[0];
    crosspoints[0] = MaskedBallotBivariateCrosspoint320::from_parts(
        first_crosspoint.peer_roster_position(),
        first_crosspoint.peer_evaluation_point(),
        first_crosspoint.value().add(difference),
    );
    MaskedBallotBivariateRow320::from_parts(
        row.participant_count(),
        row.roster_position(),
        row.evaluation_point(),
        row.secret_axis_value(),
        crosspoints,
    )
    .unwrap()
}

fn shift_complete_row(
    row: &MaskedBallotBivariateRow320,
    difference: BinaryFieldElement320,
) -> MaskedBallotBivariateRow320 {
    let crosspoints = row
        .crosspoints()
        .iter()
        .map(|crosspoint| {
            MaskedBallotBivariateCrosspoint320::from_parts(
                crosspoint.peer_roster_position(),
                crosspoint.peer_evaluation_point(),
                crosspoint.value().add(difference),
            )
        })
        .collect();
    MaskedBallotBivariateRow320::from_parts(
        row.participant_count(),
        row.roster_position(),
        row.evaluation_point(),
        row.secret_axis_value().add(difference),
        crosspoints,
    )
    .unwrap()
}

fn perturb_outside_rows(
    polynomial: &MaskedBallotSymmetricBivariatePolynomial320,
    unchanged_roster_positions: &[u16],
    desired_secret_difference: BinaryFieldElement320,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    let mut vanishing_polynomial = vec![BinaryFieldElement320::ONE];
    for roster_position in unchanged_roster_positions {
        vanishing_polynomial = multiply_by_x_plus_constant(
            &vanishing_polynomial,
            canonical_evaluation_point_320(polynomial.participant_count(), *roster_position)
                .unwrap(),
        );
    }
    let value_at_zero = vanishing_polynomial[0];
    let scale = desired_secret_difference
        .divide(value_at_zero.square())
        .unwrap();
    let mut perturbed_coefficients = polynomial.coefficient_matrix().to_vec();
    for first_exponent in 0..vanishing_polynomial.len() {
        for second_exponent in 0..vanishing_polynomial.len() {
            let perturbation = vanishing_polynomial[first_exponent]
                .multiply(vanishing_polynomial[second_exponent])
                .multiply(scale);
            perturbed_coefficients[first_exponent][second_exponent] =
                perturbed_coefficients[first_exponent][second_exponent].add(perturbation);
        }
    }
    MaskedBallotSymmetricBivariatePolynomial320::from_symmetric_coefficient_matrix(
        polynomial.participant_count(),
        perturbed_coefficients,
    )
    .unwrap()
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

fn expect_decoded(
    decoding: MaskedBallotBivariateReleaseDecoding320,
) -> super::masked_ballot_bivariate_sharing_320::DecodedMaskedBallotBivariateRelease320 {
    match decoding {
        MaskedBallotBivariateReleaseDecoding320::Decoded(decoded) => decoded,
        MaskedBallotBivariateReleaseDecoding320::Pending { .. } => {
            panic!("a consistent release must not remain pending")
        }
    }
}

fn advance_combination(positions: &mut [usize], item_count: usize) -> bool {
    let selection_count = positions.len();
    for pivot in (0..selection_count).rev() {
        let maximum_position = item_count - selection_count + pivot;
        if positions[pivot] == maximum_position {
            continue;
        }
        positions[pivot] += 1;
        for position in pivot + 1..selection_count {
            positions[position] = positions[position - 1] + 1;
        }
        return true;
    }
    false
}

fn field(value: u16) -> BinaryFieldElement320 {
    BinaryFieldElement320::from_low_polynomial_u16(value)
}
