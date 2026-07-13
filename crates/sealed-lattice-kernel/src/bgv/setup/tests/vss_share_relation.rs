use super::*;

#[test]
fn carry_aware_vss_share_relation_accepts_no_wrap_and_wrap_cases_for_every_q_share_prime() {
    for modulus in DATA_PRIMES {
        let no_wrap_coefficients = [7, 3, 0, 0];
        let no_wrap_verification =
            verify_carry_aware_vss_share_opening(&no_wrap_coefficients, 0, 10, 0, modulus)
                .expect("no-wrap VSS share verification");
        assert_eq!(no_wrap_verification.trustee_point, 1);
        assert_eq!(no_wrap_verification.unreduced_evaluation, 10);
        assert_eq!(no_wrap_verification.reduced_evaluation, 10);
        assert_eq!(no_wrap_verification.expected_carry, 0);
        assert_eq!(no_wrap_verification.lifted_share, 10);

        let wrap_coefficients = [modulus - 1, modulus - 2, modulus - 3, modulus - 4];
        let trustee_point = canonical_trustee_point(1, modulus).expect("trustee point");
        let unreduced_evaluation =
            evaluate_unreduced_shamir_polynomial(&wrap_coefficients, trustee_point, modulus)
                .expect("unreduced evaluation");
        let share_value = (unreduced_evaluation % u128::from(modulus)) as u64;
        let carry_witness = unreduced_evaluation / u128::from(modulus);

        let wrap_verification = verify_carry_aware_vss_share_opening(
            &wrap_coefficients,
            1,
            share_value,
            carry_witness,
            modulus,
        )
        .expect("wrap VSS share verification");
        assert_eq!(wrap_verification.trustee_point, 2);
        assert_eq!(wrap_verification.unreduced_evaluation, unreduced_evaluation);
        assert_eq!(wrap_verification.reduced_evaluation, share_value);
        assert_eq!(wrap_verification.expected_carry, carry_witness);
        assert!(wrap_verification.carry_bound >= carry_witness);
        assert_eq!(wrap_verification.lifted_share, unreduced_evaluation);
    }
}

#[test]
fn carry_aware_vss_share_relation_matches_reduced_shamir_evaluation() {
    for modulus in DATA_PRIMES {
        let coefficients = [modulus - 17, 12_345 % modulus, modulus / 3, modulus / 5];
        for recipient_roster_position in 0..10 {
            let trustee_point =
                canonical_trustee_point(recipient_roster_position, modulus).expect("trustee point");
            let share_value = evaluate_shamir_polynomial(&coefficients, trustee_point, modulus)
                .expect("reduced evaluation");
            let unreduced_evaluation =
                evaluate_unreduced_shamir_polynomial(&coefficients, trustee_point, modulus)
                    .expect("unreduced evaluation");
            let carry_witness = unreduced_evaluation / u128::from(modulus);

            let verification = verify_carry_aware_vss_share_opening(
                &coefficients,
                recipient_roster_position,
                share_value,
                carry_witness,
                modulus,
            )
            .expect("VSS share verification");

            assert_eq!(verification.trustee_point, trustee_point);
            assert_eq!(verification.reduced_evaluation, share_value);
            assert_eq!(verification.unreduced_evaluation, unreduced_evaluation);
            assert_eq!(verification.expected_carry, carry_witness);
            assert_eq!(
                verification.lifted_share,
                u128::from(share_value) + u128::from(modulus) * carry_witness
            );
        }
    }
}

#[test]
fn carry_aware_vss_share_relation_rejects_malformed_openings() {
    let modulus = DATA_PRIMES[0];
    let coefficients = [modulus - 1, modulus - 2, 19, 23];
    let recipient_roster_position = 3;
    let trustee_point =
        canonical_trustee_point(recipient_roster_position, modulus).expect("trustee point");
    let unreduced_evaluation =
        evaluate_unreduced_shamir_polynomial(&coefficients, trustee_point, modulus)
            .expect("unreduced evaluation");
    let share_value = (unreduced_evaluation % u128::from(modulus)) as u64;
    let carry_witness = unreduced_evaluation / u128::from(modulus);

    assert!(
        verify_carry_aware_vss_share_opening(
            &coefficients,
            recipient_roster_position,
            (share_value + 1) % modulus,
            carry_witness,
            modulus,
        )
        .is_err()
    );
    assert!(
        verify_carry_aware_vss_share_opening(
            &coefficients,
            recipient_roster_position,
            share_value,
            carry_witness + 1,
            modulus,
        )
        .is_err()
    );
    assert!(
        verify_carry_aware_vss_share_opening(
            &coefficients,
            recipient_roster_position + 1,
            share_value,
            carry_witness,
            modulus,
        )
        .is_err()
    );
    assert!(
        verify_carry_aware_vss_share_opening(
            &coefficients,
            recipient_roster_position,
            modulus,
            carry_witness,
            modulus,
        )
        .is_err()
    );

    let mut out_of_range_coefficients = coefficients;
    out_of_range_coefficients[1] = modulus;
    assert!(
        verify_carry_aware_vss_share_opening(
            &out_of_range_coefficients,
            recipient_roster_position,
            share_value,
            carry_witness,
            modulus,
        )
        .is_err()
    );
    assert!(
        verify_carry_aware_vss_share_opening(
            &[],
            recipient_roster_position,
            share_value,
            carry_witness,
            modulus,
        )
        .is_err()
    );

    let invalid_roster_position =
        usize::try_from(modulus - 1).expect("modulus fits roster position");
    assert!(
        verify_carry_aware_vss_share_opening(
            &coefficients,
            invalid_roster_position,
            share_value,
            carry_witness,
            modulus,
        )
        .is_err()
    );
}

#[test]
fn carry_aware_vss_commitment_opening_matches_lifted_share_relation() {
    let modulus = DATA_PRIMES[0];
    let public_matrix_seed_hash = valid_hash('c');
    let ring_degree = 8_usize;
    let recipient_roster_position = 2_usize;
    let trustee_point =
        canonical_trustee_point(recipient_roster_position, modulus).expect("trustee point");
    let coefficient_messages_by_shamir_index = vec![
        vec![modulus - 5, 17, 19, 23, modulus - 11, 31, 37, 41],
        vec![7, modulus - 13, 43, 47, 53, modulus - 17, 59, 61],
        vec![67, 71, modulus - 19, 73, 79, 83, modulus - 23, 89],
        vec![97, 101, 103, modulus - 29, 107, 109, 113, modulus - 31],
    ];
    let coefficient_randomness_by_shamir_index = (0..4)
        .map(|coefficient_index| commitment_randomness_for_vss_test(coefficient_index, ring_degree))
        .collect::<Vec<_>>();
    let coefficient_commitments = coefficient_messages_by_shamir_index
        .iter()
        .zip(coefficient_randomness_by_shamir_index.iter())
        .enumerate()
        .map(|(coefficient_index, (message, randomness))| {
            let message_coefficients = message
                .iter()
                .map(|value| u128::from(*value))
                .collect::<Vec<_>>();
            compute_setup_commitment_for_tests(
                &public_matrix_seed_hash,
                0,
                modulus,
                coefficient_index as u64,
                &message_coefficients,
                randomness,
                ring_degree,
            )
            .expect("coefficient commitment")
        })
        .collect::<Vec<_>>();
    let mut share_values = Vec::with_capacity(ring_degree);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    let mut lifted_values = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let coefficient_values = coefficient_messages_by_shamir_index
            .iter()
            .map(|coefficient_vector| coefficient_vector[coefficient_position])
            .collect::<Vec<_>>();
        let unreduced_evaluation =
            evaluate_unreduced_shamir_polynomial(&coefficient_values, trustee_point, modulus)
                .expect("unreduced evaluation");
        share_values.push((unreduced_evaluation % u128::from(modulus)) as u64);
        carry_witnesses.push(unreduced_evaluation / u128::from(modulus));
        lifted_values.push(unreduced_evaluation);
    }

    let verification =
        verify_carry_aware_vss_commitment_opening(CarryAwareVssCommitmentOpeningInput {
            public_matrix_seed_hash: &public_matrix_seed_hash,
            coefficient_commitments: &coefficient_commitments,
            coefficient_messages_by_shamir_index: &coefficient_messages_by_shamir_index,
            coefficient_randomness_by_shamir_index: &coefficient_randomness_by_shamir_index,
            recipient_roster_position,
            share_values: &share_values,
            carry_witnesses: &carry_witnesses,
            modulus,
            fresh_randomness_bound: TEST_SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        })
        .expect("VSS commitment opening verification");

    assert_eq!(verification.trustee_point, trustee_point);
    assert_eq!(verification.lifted_share_openings.len(), ring_degree);
    assert_eq!(
        verification.commitment_opening.message_coefficient_bound,
        *lifted_values.iter().max().expect("lifted max")
    );
    assert_eq!(verification.homomorphic_randomness_bound, 40);

    let mut wrong_carry_witnesses = carry_witnesses.clone();
    wrong_carry_witnesses[0] += 1;
    assert!(
        verify_carry_aware_vss_commitment_opening(CarryAwareVssCommitmentOpeningInput {
            public_matrix_seed_hash: &public_matrix_seed_hash,
            coefficient_commitments: &coefficient_commitments,
            coefficient_messages_by_shamir_index: &coefficient_messages_by_shamir_index,
            coefficient_randomness_by_shamir_index: &coefficient_randomness_by_shamir_index,
            recipient_roster_position,
            share_values: &share_values,
            carry_witnesses: &wrong_carry_witnesses,
            modulus,
            fresh_randomness_bound: TEST_SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        },)
        .is_err()
    );

    let mut wrong_randomness = coefficient_randomness_by_shamir_index.clone();
    wrong_randomness[0][0][0] += 1;
    assert!(
        verify_carry_aware_vss_commitment_opening(CarryAwareVssCommitmentOpeningInput {
            public_matrix_seed_hash: &public_matrix_seed_hash,
            coefficient_commitments: &coefficient_commitments,
            coefficient_messages_by_shamir_index: &coefficient_messages_by_shamir_index,
            coefficient_randomness_by_shamir_index: &wrong_randomness,
            recipient_roster_position,
            share_values: &share_values,
            carry_witnesses: &carry_witnesses,
            modulus,
            fresh_randomness_bound: TEST_SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        },)
        .is_err()
    );
}

fn commitment_randomness_for_vss_test(
    coefficient_index: usize,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (coefficient_index + column_index + coefficient_position) % 3 {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    }
                })
                .collect()
        })
        .collect()
}
