use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
};

use super::{
    binary_field_320::BinaryFieldElement320,
    collective_coin_source_bivariate_sharing_320::{
        CollectiveCoinSourceBivariateCrosspoint320, CollectiveCoinSourceBivariateReleaseDecoder320,
        CollectiveCoinSourceBivariateReleaseDecoding320, CollectiveCoinSourceBivariateRow320,
        CollectiveCoinSourceBivariateSharingError320, CollectiveCoinSourceComponent320,
        CollectiveCoinSourceSymmetricBivariatePolynomial320,
        DecodedCollectiveCoinSourceBivariateRelease320,
    },
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
    pseudorandom_zero_sharing_seed_master_join_320_tests::completion_joined_seed_masters_for_test,
};

#[test]
fn positively_joined_source_and_salt_feed_the_production_polynomial_constructor() {
    let joined_seed_masters = completion_joined_seed_masters_for_test();
    let participant_count = joined_seed_masters
        .preparation_context()
        .participant_count();
    let contributor_position = joined_seed_masters.participant_position();
    let source = *joined_seed_masters.collective_coin_source().source();
    let commitment_salt = *joined_seed_masters
        .collective_coin_source()
        .commitment_salt();
    let polynomial = CollectiveCoinSourceSymmetricBivariatePolynomial320::
        from_joined_seed_masters_and_random_coefficients(
            &joined_seed_masters,
            random_coefficients(FOUNDATION_PROFILE.reconstruction_threshold, 0x1050),
        )
        .unwrap();
    let rows = rows_for_polynomial(&polynomial);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();
    let decoded = expect_decoded(
        decoder
            .decode(&rows[..decoder.minimum_consistent_row_count()])
            .unwrap(),
    );

    assert_eq!(polynomial.participant_count(), participant_count);
    assert_eq!(polynomial.contributor_position(), contributor_position);
    assert_eq!(decoded.source(), &source);
    assert_eq!(decoded.commitment_salt(), &commitment_salt);
}

#[test]
fn every_completion_consistent_release_set_reconstructs_the_exact_source_and_salt() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 6;
    let source = patterned_source(0x31);
    let commitment_salt = patterned_commitment_salt(0x83);
    let polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &source,
        &commitment_salt,
        0x1100,
    );
    let rows = rows_for_polynomial(&polynomial);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();

    assert_eq!(polynomial.coefficient_count_per_axis(), 4);
    assert_eq!(polynomial.random_coefficient_count(), 27);
    assert_eq!(decoder.reconstruction_threshold(), 4);
    assert_eq!(decoder.minimum_consistent_row_count(), 7);
    assert_eq!(decoder.committed_field_value_count(), 165);
    assert_eq!(decoder.field_values_per_holder(), 30);

    let mut selected_positions = (0..decoder.minimum_consistent_row_count()).collect::<Vec<_>>();
    let mut tested_subset_count = 0_u16;
    loop {
        let selected_rows = selected_positions
            .iter()
            .map(|position| rows[*position].clone())
            .collect::<Vec<_>>();
        let decoded = expect_decoded(decoder.decode(&selected_rows).unwrap());
        assert_eq!(decoded.source(), &source);
        assert_eq!(decoded.commitment_salt(), &commitment_salt);
        assert_eq!(
            decoded.supporting_holder_positions(),
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
    assert_eq!(tested_subset_count, 120);
}

#[test]
fn four_arbitrary_completion_rows_do_not_create_an_early_coin_opening() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 2;
    let source = patterned_source(0x42);
    let commitment_salt = patterned_commitment_salt(0x95);
    let polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &source,
        &commitment_salt,
        0x2200,
    );
    let rows = rows_for_polynomial(&polynomial);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();

    for received_row_count in 0..decoder.minimum_consistent_row_count() {
        assert!(matches!(
            decoder.decode(&rows[..received_row_count]).unwrap(),
            CollectiveCoinSourceBivariateReleaseDecoding320::Pending {
                minimum_consistent_row_count: 7,
                received_row_count: actual_received_row_count,
            } if actual_received_row_count == received_row_count
        ));
    }
}

#[test]
fn every_supplied_row_is_checked_without_correction_or_subset_fallback() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 4;
    let source = patterned_source(0x53);
    let alternate_source = patterned_source(0xb7);
    let commitment_salt = patterned_commitment_salt(0xa6);
    let original_polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &source,
        &commitment_salt,
        0x3300,
    );
    let alternate_polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &alternate_source,
        &commitment_salt,
        0x6600,
    );
    let mut rows = rows_for_polynomial(&original_polynomial);
    rows[0] = alternate_polynomial.row(0).unwrap();
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();

    assert_eq!(
        decoder.decode(&rows[..decoder.minimum_consistent_row_count()]),
        Err(
            CollectiveCoinSourceBivariateSharingError320::CrosspointMismatch {
                first_holder_position: 0,
                second_holder_position: 1,
                component: CollectiveCoinSourceComponent320::Source,
            }
        )
    );

    for component in [
        CollectiveCoinSourceComponent320::Source,
        CollectiveCoinSourceComponent320::CommitmentSaltPrefix,
        CollectiveCoinSourceComponent320::CommitmentSaltSuffix,
    ] {
        let mut locally_malformed_rows = rows_for_polynomial(&original_polynomial);
        locally_malformed_rows[3] =
            shift_secret_axis_value(&locally_malformed_rows[3], component, field(0x9d));
        assert_eq!(
            decoder.decode(&locally_malformed_rows[..decoder.minimum_consistent_row_count()]),
            Err(
                CollectiveCoinSourceBivariateSharingError320::RowDegreeExceeded {
                    holder_position: 3,
                    component,
                }
            )
        );
    }
}

#[test]
fn malformed_row_inventories_refuse_before_reconstruction() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 5;
    let source = patterned_source(0x64);
    let commitment_salt = patterned_commitment_salt(0xb9);
    let polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &source,
        &commitment_salt,
        0x4400,
    );
    let rows = rows_for_polynomial(&polynomial);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();
    let row = &rows[3];

    assert_eq!(
        CollectiveCoinSourceBivariateRow320::from_parts(
            row.participant_count(),
            row.contributor_position(),
            row.holder_position(),
            canonical_evaluation_point_320(row.participant_count(), 4).unwrap(),
            row.secret_axis_values(),
            row.crosspoints().to_vec(),
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowEvaluationPointMismatch {
                holder_position: 3,
            }
        )
    );

    let mut missing_crosspoint = row.crosspoints().to_vec();
    missing_crosspoint.pop();
    assert_eq!(
        CollectiveCoinSourceBivariateRow320::from_parts(
            row.participant_count(),
            row.contributor_position(),
            row.holder_position(),
            row.evaluation_point(),
            row.secret_axis_values(),
            missing_crosspoint,
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowCrosspointCountMismatch {
                holder_position: 3,
                expected: 9,
                actual: 8,
            }
        )
    );

    let mut wrong_peer_order = row.crosspoints().to_vec();
    wrong_peer_order.swap(0, 1);
    assert_eq!(
        CollectiveCoinSourceBivariateRow320::from_parts(
            row.participant_count(),
            row.contributor_position(),
            row.holder_position(),
            row.evaluation_point(),
            row.secret_axis_values(),
            wrong_peer_order,
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowCrosspointHolderPositionMismatch {
                holder_position: 3,
                crosspoint_position: 0,
                expected_peer_holder_position: 0,
                actual_peer_holder_position: 1,
            }
        )
    );

    let first_crosspoint = row.crosspoints()[0];
    let mut wrong_peer_point = row.crosspoints().to_vec();
    wrong_peer_point[0] = CollectiveCoinSourceBivariateCrosspoint320::from_parts(
        first_crosspoint.peer_holder_position(),
        canonical_evaluation_point_320(row.participant_count(), 1).unwrap(),
        first_crosspoint.component_values(),
    );
    assert_eq!(
        CollectiveCoinSourceBivariateRow320::from_parts(
            row.participant_count(),
            row.contributor_position(),
            row.holder_position(),
            row.evaluation_point(),
            row.secret_axis_values(),
            wrong_peer_point,
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowCrosspointEvaluationPointMismatch {
                holder_position: 3,
                peer_holder_position: 0,
            }
        )
    );

    let mut duplicate = rows[..decoder.minimum_consistent_row_count() - 1].to_vec();
    duplicate.push(rows[0].clone());
    assert_eq!(
        decoder.decode(&duplicate),
        Err(
            CollectiveCoinSourceBivariateSharingError320::DuplicateHolderPosition {
                holder_position: 0,
            }
        )
    );

    let mut excess = rows.clone();
    excess.push(rows[0].clone());
    assert_eq!(
        decoder.decode(&excess),
        Err(
            CollectiveCoinSourceBivariateSharingError320::ExcessRowCount {
                participant_count,
                actual: 11,
            }
        )
    );

    let wrong_contributor_decoder =
        CollectiveCoinSourceBivariateReleaseDecoder320::new(participant_count, 1).unwrap();
    assert_eq!(
        wrong_contributor_decoder.decode(&rows[..1]),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowContributorPositionMismatch {
                expected: 1,
                actual: contributor_position,
            }
        )
    );

    let nine_participant_polynomial =
        polynomial_for_source_and_salt(9, contributor_position, &source, &commitment_salt, 0x5500);
    assert_eq!(
        decoder.decode(&[nine_participant_polynomial.row(0).unwrap()]),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RowParticipantCountMismatch {
                expected: participant_count,
                actual: 9,
            }
        )
    );
}

#[test]
fn coefficient_and_contributor_boundaries_refuse() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let source = patterned_source(0x75);
    let commitment_salt = patterned_commitment_salt(0xca);
    let coefficients = random_coefficients(FOUNDATION_PROFILE.reconstruction_threshold, 0x7700);

    assert!(matches!(
        CollectiveCoinSourceSymmetricBivariatePolynomial320::from_source_and_salt_for_test(
            participant_count,
            0,
            &source,
            &commitment_salt,
            &coefficients[..coefficients.len() - 1],
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RandomCoefficientCountMismatch {
                expected: 27,
                actual: 26,
            }
        )
    ));
    let mut excess_coefficients = coefficients.clone();
    excess_coefficients.push(field(0xffff));
    assert!(matches!(
        CollectiveCoinSourceSymmetricBivariatePolynomial320::from_source_and_salt_for_test(
            participant_count,
            0,
            &source,
            &commitment_salt,
            &excess_coefficients,
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::RandomCoefficientCountMismatch {
                expected: 27,
                actual: 28,
            }
        )
    ));

    assert!(matches!(
        CollectiveCoinSourceSymmetricBivariatePolynomial320::from_source_and_salt_for_test(
            participant_count,
            participant_count,
            &source,
            &commitment_salt,
            &coefficients,
        ),
        Err(
            CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                contributor_position: actual_contributor_position,
                participant_count: actual_participant_count,
            }
        ) if actual_contributor_position == participant_count
            && actual_participant_count == participant_count
    ));
    assert!(matches!(
        CollectiveCoinSourceBivariateReleaseDecoder320::new(participant_count, participant_count),
        Err(
            CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                contributor_position: actual_contributor_position,
                participant_count: actual_participant_count,
            }
        ) if actual_contributor_position == participant_count
            && actual_participant_count == participant_count
    ));
}

#[test]
fn nonzero_suffix_padding_cannot_decode_as_a_commitment_salt() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 7;
    let source = BinaryFieldElement320::from_canonical_bytes(&patterned_source(0x86)).unwrap();
    let salt_prefix = BinaryFieldElement320::from_canonical_bytes(
        &patterned_commitment_salt(0xdb)[..BinaryFieldElement320::CANONICAL_BYTE_LENGTH],
    )
    .unwrap();
    let mut invalid_suffix_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    invalid_suffix_bytes[..24].copy_from_slice(&patterned_commitment_salt(0xec)[40..]);
    invalid_suffix_bytes[24] = 1;
    let invalid_suffix =
        BinaryFieldElement320::from_canonical_bytes(&invalid_suffix_bytes).unwrap();
    let polynomial =
        CollectiveCoinSourceSymmetricBivariatePolynomial320::from_component_secrets_for_test(
            participant_count,
            contributor_position,
            [source, salt_prefix, invalid_suffix],
            &random_coefficients(FOUNDATION_PROFILE.reconstruction_threshold, 0x8800),
        )
        .unwrap();
    let rows = rows_for_polynomial(&polynomial);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        participant_count,
        contributor_position,
    )
    .unwrap();

    assert!(matches!(
        decoder.decode(&rows[..decoder.minimum_consistent_row_count()]),
        Err(CollectiveCoinSourceBivariateSharingError320::NonzeroCommitmentSaltPadding)
    ));
}

#[test]
fn every_completion_view_with_at_most_three_rows_hides_alternate_source_and_salt_values() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let contributor_position = 8;
    let source = patterned_source(0x97);
    let alternate_source = patterned_source(0xf1);
    let commitment_salt = patterned_commitment_salt(0xfd);
    let alternate_commitment_salt = patterned_commitment_salt(0x5b);
    let original_polynomial = polynomial_for_source_and_salt(
        participant_count,
        contributor_position,
        &source,
        &commitment_salt,
        0x9900,
    );
    let original_component_secrets = component_secrets(&source, &commitment_salt);
    let alternate_component_secrets =
        component_secrets(&alternate_source, &alternate_commitment_salt);
    let maximum_corrupt_row_count = derive_foundation_roster_parameters(participant_count)
        .unwrap()
        .active_fault_bound;

    for corrupt_row_count in 1..=maximum_corrupt_row_count {
        let mut corrupt_positions = (0..usize::from(corrupt_row_count)).collect::<Vec<_>>();
        loop {
            let corrupt_holder_positions = corrupt_positions
                .iter()
                .map(|position| u16::try_from(*position).unwrap())
                .collect::<Vec<_>>();
            for component in [
                CollectiveCoinSourceComponent320::Source,
                CollectiveCoinSourceComponent320::CommitmentSaltPrefix,
                CollectiveCoinSourceComponent320::CommitmentSaltSuffix,
            ] {
                let component_position = component_position(component);
                let alternate_polynomial = perturb_component_outside_rows(
                    &original_polynomial,
                    &corrupt_holder_positions,
                    component,
                    original_component_secrets[component_position]
                        .add(alternate_component_secrets[component_position]),
                );
                assert_eq!(
                    alternate_polynomial.evaluate(
                        component,
                        BinaryFieldElement320::ZERO,
                        BinaryFieldElement320::ZERO,
                    ),
                    alternate_component_secrets[component_position]
                );
                for corrupt_holder_position in &corrupt_holder_positions {
                    assert_eq!(
                        original_polynomial.row(*corrupt_holder_position).unwrap(),
                        alternate_polynomial.row(*corrupt_holder_position).unwrap(),
                    );
                }
            }
            if !advance_combination(&mut corrupt_positions, usize::from(participant_count)) {
                break;
            }
        }
    }
}

#[test]
fn every_admitted_roster_derives_consistent_source_and_salt_geometry() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let contributor_position = participant_count - 1;
        let source = patterned_source(u8::try_from(participant_count).unwrap());
        let commitment_salt =
            patterned_commitment_salt(u8::try_from(participant_count).unwrap().wrapping_mul(7));
        let polynomial = polynomial_for_source_and_salt(
            participant_count,
            contributor_position,
            &source,
            &commitment_salt,
            0xa000 + participant_count,
        );
        let rows = rows_for_polynomial(&polynomial);
        let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
            participant_count,
            contributor_position,
        )
        .unwrap();
        let minimum_consistent_row_count =
            usize::from(participant_count) - usize::from(roster_parameters.active_fault_bound);
        let minimum_intersection_count =
            2 * minimum_consistent_row_count - usize::from(participant_count);

        assert!(
            minimum_intersection_count >= usize::from(roster_parameters.reconstruction_threshold),
            "participant count {participant_count}"
        );
        assert_eq!(decoder.participant_count(), participant_count);
        assert_eq!(decoder.contributor_position(), contributor_position);
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
            3 * (usize::from(participant_count)
                + (usize::from(participant_count) * (usize::from(participant_count) - 1)) / 2)
        );
        assert_eq!(
            decoder.field_values_per_holder(),
            3 * usize::from(participant_count)
        );
        let decoded = expect_decoded(
            decoder
                .decode(&rows[..minimum_consistent_row_count])
                .unwrap(),
        );
        assert_eq!(decoded.source(), &source);
        assert_eq!(decoded.commitment_salt(), &commitment_salt);
    }
}

fn polynomial_for_source_and_salt(
    participant_count: u16,
    contributor_position: u16,
    source: &[u8; 40],
    commitment_salt: &[u8; 64],
    first_coefficient: u16,
) -> CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    let reconstruction_threshold = derive_foundation_roster_parameters(participant_count)
        .unwrap()
        .reconstruction_threshold;
    CollectiveCoinSourceSymmetricBivariatePolynomial320::from_source_and_salt_for_test(
        participant_count,
        contributor_position,
        source,
        commitment_salt,
        &random_coefficients(reconstruction_threshold, first_coefficient),
    )
    .unwrap()
}

fn random_coefficients(
    reconstruction_threshold: u16,
    first_coefficient: u16,
) -> Vec<BinaryFieldElement320> {
    let coefficient_count = usize::from(reconstruction_threshold);
    let random_coefficient_count_per_component =
        coefficient_count * (coefficient_count + 1) / 2 - 1;
    (0..3 * random_coefficient_count_per_component)
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
    polynomial: &CollectiveCoinSourceSymmetricBivariatePolynomial320,
) -> Vec<CollectiveCoinSourceBivariateRow320> {
    (0..polynomial.participant_count())
        .map(|holder_position| polynomial.row(holder_position).unwrap())
        .collect()
}

fn patterned_source(pattern_offset: u8) -> [u8; 40] {
    core::array::from_fn(|position| {
        u8::try_from(position)
            .unwrap()
            .wrapping_mul(29)
            .wrapping_add(pattern_offset)
    })
}

fn patterned_commitment_salt(pattern_offset: u8) -> [u8; 64] {
    core::array::from_fn(|position| {
        u8::try_from(position)
            .unwrap()
            .wrapping_mul(43)
            .wrapping_add(pattern_offset)
    })
}

fn shift_secret_axis_value(
    row: &CollectiveCoinSourceBivariateRow320,
    component: CollectiveCoinSourceComponent320,
    difference: BinaryFieldElement320,
) -> CollectiveCoinSourceBivariateRow320 {
    let mut secret_axis_values = row.secret_axis_values();
    let component_position = component_position(component);
    secret_axis_values[component_position] = secret_axis_values[component_position].add(difference);
    CollectiveCoinSourceBivariateRow320::from_parts(
        row.participant_count(),
        row.contributor_position(),
        row.holder_position(),
        row.evaluation_point(),
        secret_axis_values,
        row.crosspoints().to_vec(),
    )
    .unwrap()
}

fn perturb_component_outside_rows(
    polynomial: &CollectiveCoinSourceSymmetricBivariatePolynomial320,
    unchanged_holder_positions: &[u16],
    component: CollectiveCoinSourceComponent320,
    desired_secret_difference: BinaryFieldElement320,
) -> CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    let mut vanishing_polynomial = vec![BinaryFieldElement320::ONE];
    for holder_position in unchanged_holder_positions {
        vanishing_polynomial = multiply_by_x_plus_constant(
            &vanishing_polynomial,
            canonical_evaluation_point_320(polynomial.participant_count(), *holder_position)
                .unwrap(),
        );
    }
    let value_at_zero = vanishing_polynomial[0];
    let scale = desired_secret_difference
        .divide(value_at_zero.square())
        .unwrap();
    let mut perturbed_coefficient_matrices = polynomial.coefficient_matrices().clone();
    let component_position = component_position(component);
    for first_exponent in 0..vanishing_polynomial.len() {
        for second_exponent in 0..vanishing_polynomial.len() {
            let perturbation = vanishing_polynomial[first_exponent]
                .multiply(vanishing_polynomial[second_exponent])
                .multiply(scale);
            perturbed_coefficient_matrices[component_position][first_exponent][second_exponent] =
                perturbed_coefficient_matrices[component_position][first_exponent][second_exponent]
                    .add(perturbation);
        }
    }
    CollectiveCoinSourceSymmetricBivariatePolynomial320::from_coefficient_matrices_for_test(
        polynomial.participant_count(),
        polynomial.contributor_position(),
        perturbed_coefficient_matrices,
    )
    .unwrap()
}

fn component_secrets(source: &[u8; 40], commitment_salt: &[u8; 64]) -> [BinaryFieldElement320; 3] {
    let mut salt_suffix = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
    salt_suffix[..24].copy_from_slice(&commitment_salt[40..]);
    [
        BinaryFieldElement320::from_canonical_bytes(source).unwrap(),
        BinaryFieldElement320::from_canonical_bytes(&commitment_salt[..40]).unwrap(),
        BinaryFieldElement320::from_canonical_bytes(&salt_suffix).unwrap(),
    ]
}

const fn component_position(component: CollectiveCoinSourceComponent320) -> usize {
    match component {
        CollectiveCoinSourceComponent320::Source => 0,
        CollectiveCoinSourceComponent320::CommitmentSaltPrefix => 1,
        CollectiveCoinSourceComponent320::CommitmentSaltSuffix => 2,
    }
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
    decoding: CollectiveCoinSourceBivariateReleaseDecoding320,
) -> DecodedCollectiveCoinSourceBivariateRelease320 {
    match decoding {
        CollectiveCoinSourceBivariateReleaseDecoding320::Decoded(decoded) => decoded,
        CollectiveCoinSourceBivariateReleaseDecoding320::Pending { .. } => {
            panic!("a complete consistent source release must not remain pending")
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
