use super::*;
use crate::bgv::modular_arithmetic::pow_mod;
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_MESSAGE_DIGIT_COUNT, CompactVssCommitmentOpeningInput,
    compact_vss_message_digit_trits_for_count, compact_vss_message_digits,
    compact_vss_message_encoding_layout, compute_compact_vss_commitment_from_opening,
};
use crate::bgv::setup::trustee_evaluation_key_proof::signed_value_residue;
use serde_json::json;

#[test]
fn galois_transpose_matches_forward_automorphism_inner_product() {
    // The lincheck relies on <u, phi_g(s)> = <M_phi^T u, s>; check it for
    // random vectors against the forward automorphism over a profile prime.
    let modulus = DATA_PRIMES[0];
    let degree = 64_usize;
    let mut seed_value = 0x9e3779b97f4a7c15_u64;
    let mut next = || {
        seed_value ^= seed_value << 13;
        seed_value ^= seed_value >> 7;
        seed_value ^= seed_value << 17;
        seed_value % modulus
    };
    for galois_element in [3_usize, 5, 31, 127] {
        let values = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let vector = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let rotated = galois_automorphism_apply(&values, galois_element, modulus)
            .expect("forward automorphism");
        let transposed = galois_automorphism_transpose_apply(&vector, galois_element, modulus)
            .expect("transpose automorphism");
        let dot = |left: &[u64], right: &[u64]| -> u128 {
            left.iter().zip(right.iter()).fold(0_u128, |total, (a, b)| {
                (total + u128::from(*a) * u128::from(*b)) % u128::from(modulus)
            })
        };
        assert_eq!(
            dot(&vector, &rotated),
            dot(&transposed, &values),
            "transpose identity must hold for element {galois_element}"
        );
    }
}

#[test]
fn degree_t_sumcheck_residual_shifts_subgroup_constant() {
    // A sumcheck residual of degree exactly T can hide a false constant by
    // adding a term that vanishes on the trace subgroup: the forged slack is
    // zero at X = 0 but has degree exactly T. This is why the residual column
    // carries its own degree-below-T low-degree proof, which rejects it.
    let modulus = DATA_PRIMES[0];
    let trace_size = 64_usize;
    let trace_root = pow_mod(
        crate::bgv::profile::root_parameters_for_modulus(modulus)
            .expect("root parameters")
            .negacyclic_root,
        (2 * crate::bgv::profile::POLYNOMIAL_DEGREE / trace_size) as u64,
        modulus,
    )
    .expect("trace root");
    let false_constant_delta = 17_u64;
    let true_expected_constant = 123_u64;
    let false_expected_constant = (true_expected_constant + false_constant_delta) % modulus;
    let forged_top_coefficient = (modulus - false_constant_delta) % modulus;

    assert_ne!(forged_top_coefficient, 0);
    assert_eq!(
        (false_expected_constant + forged_top_coefficient) % modulus,
        true_expected_constant
    );

    let mut subgroup_point = 1_u64;
    for _position in 0..trace_size {
        assert_eq!(
            pow_mod(subgroup_point, trace_size as u64, modulus).expect("power"),
            1
        );
        let forged_residual_at_trace_point = forged_top_coefficient;
        assert_eq!(
            (false_expected_constant + forged_residual_at_trace_point) % modulus,
            true_expected_constant,
            "the degree-T slack preserves the false sumcheck on the trace subgroup"
        );
        subgroup_point =
            (u128::from(subgroup_point) * u128::from(trace_root) % u128::from(modulus)) as u64;
    }

    let mut forged_residual_coefficients = vec![0_u64; trace_size + 1];
    forged_residual_coefficients[trace_size] = forged_top_coefficient;
    assert_eq!(forged_residual_coefficients[0], 0);
    assert!(
        forged_residual_coefficients.len() > trace_size,
        "the forged residual has degree T and violates the new degree-below-T bound"
    );
}

#[test]
fn compact_vss_share_linkage_vectors_match_carried_share_openings() {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("bc");
    let source_rns_limb_index = 0_usize;
    let source_message_modulus = DATA_PRIMES[source_rns_limb_index];
    let recipient_roster_position = 2_u64;
    let recipient_trustee_point = recipient_roster_position + 1;
    let commitment_modulus_index = 1_usize;
    let commitment_modulus = DATA_PRIMES[commitment_modulus_index];
    let coefficient_count = 3_usize;

    let coefficient_messages = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    if coefficient_index % 11 == shamir_coefficient_index {
                        source_message_modulus - 4 - shamir_coefficient_index as u64
                    } else {
                        (17 + 19 * shamir_coefficient_index as u64 + 23 * coefficient_index as u64)
                            % source_message_modulus
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut recipient_share_values = Vec::with_capacity(ring_degree);
    let mut recipient_share_carry_values = Vec::with_capacity(ring_degree);
    let mut trustee_point_powers = Vec::with_capacity(coefficient_count);
    let mut trustee_point_power = 1_u128;
    for _ in 0..coefficient_count {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power *= u128::from(recipient_trustee_point);
    }
    for coefficient_index in 0..ring_degree {
        let lifted_share = coefficient_messages
            .iter()
            .zip(trustee_point_powers.iter())
            .fold(0_u128, |sum, (messages, point_power)| {
                sum + u128::from(messages[coefficient_index]) * *point_power
            });
        recipient_share_values.push((lifted_share % u128::from(source_message_modulus)) as u64);
        recipient_share_carry_values
            .push((lifted_share / u128::from(source_message_modulus)) as u64);
    }
    assert!(
        recipient_share_carry_values
            .iter()
            .any(|carry_value| *carry_value > 0),
        "the compact share-linkage fixture must exercise a carried share relation"
    );

    let coefficient_randomness = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            compact_randomness_columns_for_test(ring_degree, 10 + shamir_coefficient_index as i64)
        })
        .collect::<Vec<_>>();
    let recipient_share_randomness = compact_randomness_columns_for_test(ring_degree, 41);

    let coefficient_coordinates = coefficient_messages
        .iter()
        .zip(coefficient_randomness.iter())
        .enumerate()
        .map(
            |(shamir_coefficient_index, (messages, randomness_by_column))| {
                compact_commitment_coordinates_for_test(
                    "coefficient",
                    json!({
                        "testPurpose": "compact-share-linkage-relation",
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                    &public_matrix_seed_hash,
                    source_rns_limb_index,
                    source_message_modulus,
                    ring_degree,
                    messages,
                    randomness_by_column,
                    commitment_modulus_index,
                )
            },
        )
        .collect::<Vec<_>>();
    let recipient_share_coordinates = compact_commitment_coordinates_for_test(
        "recipient-share",
        json!({
            "testPurpose": "compact-share-linkage-relation",
            "recipientRosterPosition": recipient_roster_position,
        }),
        &public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        ring_degree,
        &recipient_share_values,
        &recipient_share_randomness,
        commitment_modulus_index,
    );

    let tower =
        super::super::extension_field::ChallengeExtensionTower::for_modulus(commitment_modulus)
            .expect("challenge tower");
    let relation_count = (coefficient_count + 1)
        * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
        + LINCHECK_REPETITIONS
        + (coefficient_count + 1) * COMPACT_VSS_MESSAGE_DIGIT_COUNT * LINCHECK_REPETITIONS;
    let relation_alpha = (0..relation_count)
        .map(|relation_index| {
            tower.embed_base(((relation_index as u64 + 1) * 37) % commitment_modulus)
        })
        .collect::<Vec<_>>();
    let u_power_vectors = (0..LINCHECK_REPETITIONS)
        .map(|repetition| {
            let challenge = tower.embed_base(5 + 7 * repetition as u64);
            let mut powers = Vec::with_capacity(ring_degree);
            let mut power = super::super::extension_field::ChallengeExtensionTower::one();
            for _ in 0..ring_degree {
                powers.push(power);
                power = tower.mul(&power, &challenge);
            }
            powers
        })
        .collect::<Vec<_>>();
    let coefficient_commitments = coefficient_coordinates
        .iter()
        .enumerate()
        .map(
            |(coefficient_index, coordinates)| CompactVssShareLinkageCommitment {
                coordinates_by_commitment_modulus: (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
                    .map(|selected_commitment_modulus_index| {
                        if selected_commitment_modulus_index == commitment_modulus_index {
                            coordinates.clone()
                        } else {
                            compact_commitment_coordinates_for_test(
                                "coefficient",
                                json!({
                                    "testPurpose": "compact-share-linkage-relation",
                                    "shamirCoefficientIndex": coefficient_index,
                                }),
                                &public_matrix_seed_hash,
                                source_rns_limb_index,
                                source_message_modulus,
                                ring_degree,
                                &coefficient_messages[coefficient_index],
                                &coefficient_randomness[coefficient_index],
                                selected_commitment_modulus_index,
                            )
                        }
                    })
                    .collect(),
            },
        )
        .collect::<Vec<_>>();
    let recipient_share_commitment = CompactVssShareLinkageCommitment {
        coordinates_by_commitment_modulus: (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .map(|selected_commitment_modulus_index| {
                if selected_commitment_modulus_index == commitment_modulus_index {
                    recipient_share_coordinates.clone()
                } else {
                    compact_commitment_coordinates_for_test(
                        "recipient-share",
                        json!({
                            "testPurpose": "compact-share-linkage-relation",
                            "recipientRosterPosition": recipient_roster_position,
                        }),
                        &public_matrix_seed_hash,
                        source_rns_limb_index,
                        source_message_modulus,
                        ring_degree,
                        &recipient_share_values,
                        &recipient_share_randomness,
                        selected_commitment_modulus_index,
                    )
                }
            })
            .collect(),
    };
    let (relation_claim, public_vectors) = build_compact_vss_share_linkage_public_vectors(
        CompactVssShareLinkagePublicVectorInput {
            public_matrix_seed_hash: &public_matrix_seed_hash,
            rns_limb_index: source_rns_limb_index,
            commitment_modulus_index,
            modulus: commitment_modulus,
            source_message_modulus,
            recipient_roster_position,
            ring_degree,
            coefficient_commitments: &coefficient_commitments,
            recipient_share_commitment: &recipient_share_commitment,
            relation_alpha: &relation_alpha,
            u_power_vectors: &u_power_vectors,
            coefficient_message_range_evidence: crate::bgv::setup::compact_vss_commitment::CompactVssMessageRangeEvidence::DigitAndTritColumns,
            recipient_message_range_evidence: crate::bgv::setup::compact_vss_commitment::CompactVssMessageRangeEvidence::DigitAndTritColumns,
        },
        &tower,
    )
    .expect("compact share-linkage vectors");

    let mut witness_columns = Vec::new();
    for messages in &coefficient_messages {
        witness_columns.extend(compact_message_encoding_columns_for_test(
            messages,
            source_message_modulus,
            commitment_modulus,
        ));
    }
    witness_columns.extend(compact_message_encoding_columns_for_test(
        &recipient_share_values,
        source_message_modulus,
        commitment_modulus,
    ));
    witness_columns.push(residue_column(
        &recipient_share_carry_values,
        commitment_modulus,
    ));
    for randomness_by_column in &coefficient_randomness {
        for randomness_column in randomness_by_column {
            witness_columns.push(signed_residue_column(randomness_column, commitment_modulus));
        }
    }
    for randomness_column in &recipient_share_randomness {
        witness_columns.push(signed_residue_column(randomness_column, commitment_modulus));
    }
    assert_eq!(public_vectors.len(), witness_columns.len());

    let evaluated_relation =
        evaluate_extension_vector_dot_products(&public_vectors, &witness_columns, &tower);
    assert_eq!(
        evaluated_relation, relation_claim,
        "compact share-linkage vectors must reproduce the compact commitments and carried Shamir share relation"
    );

    let carry_column_index = (coefficient_count + 1)
        * compact_vss_message_encoding_layout(source_message_modulus)
            .expect("compact message layout")
            .encoding_column_count();
    let mut single_tamper_witness_columns = witness_columns.clone();
    single_tamper_witness_columns[carry_column_index][0] =
        (single_tamper_witness_columns[carry_column_index][0] + 1) % commitment_modulus;
    let tampered_relation = evaluate_extension_vector_dot_products(
        &public_vectors,
        &single_tamper_witness_columns,
        &tower,
    );
    assert_ne!(
        tampered_relation, relation_claim,
        "changing a carried share witness must break the compact share-linkage relation"
    );

    let mut offsetting_witness_columns = witness_columns;
    offsetting_witness_columns[carry_column_index][0] =
        (offsetting_witness_columns[carry_column_index][0] + 1) % commitment_modulus;
    offsetting_witness_columns[carry_column_index][1] =
        (offsetting_witness_columns[carry_column_index][1] + commitment_modulus - 1)
            % commitment_modulus;
    let offsetting_relation = evaluate_extension_vector_dot_products(
        &public_vectors,
        &offsetting_witness_columns,
        &tower,
    );
    assert_ne!(
        offsetting_relation, relation_claim,
        "offsetting carried-share tampering must break the randomized compact share-linkage relation"
    );
}

fn compact_randomness_columns_for_test(ring_degree: usize, seed_offset: i64) -> Vec<Vec<i64>> {
    (0..2)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    (seed_offset + randomness_column_index as i64 + coefficient_index as i64)
                        .rem_euclid(3)
                        - 1
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn compact_commitment_coordinates_for_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
    commitment_modulus_index: usize,
) -> Vec<u64> {
    let computation =
        compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
            commitment_role,
            commitment_context: &commitment_context,
            public_matrix_seed_hash,
            rns_limb_index,
            rns_prime,
            ring_degree,
            message_coefficients,
            message_coefficient_bound: rns_prime,
            randomness_by_column,
        })
        .expect("compact VSS commitment");
    computation.commitment["commitmentLimbs"]
        .as_array()
        .expect("compact commitment limbs")
        .iter()
        .find(|limb| {
            limb["commitmentModulusIndex"]
                .as_u64()
                .expect("commitment modulus index")
                == commitment_modulus_index as u64
        })
        .expect("selected compact commitment limb")["coordinates"]
        .as_array()
        .expect("compact commitment coordinates")
        .iter()
        .map(|coordinate| coordinate.as_u64().expect("compact coordinate"))
        .collect()
}

fn residue_column(values: &[u64], modulus: u64) -> Vec<u64> {
    values.iter().map(|value| *value % modulus).collect()
}

fn compact_message_encoding_columns_for_test(
    values: &[u64],
    message_bound: u64,
    modulus: u64,
) -> Vec<Vec<u64>> {
    let layout = compact_vss_message_encoding_layout(message_bound).expect("compact layout");
    let mut columns = vec![vec![0_u64; values.len()]; layout.encoding_column_count()];
    for (value_index, value) in values.iter().enumerate() {
        let digits = compact_vss_message_digits(*value).expect("compact message digits");
        for (digit_index, digit) in digits.iter().enumerate() {
            let digit_column = layout
                .digit_encoding_column(digit_index)
                .expect("compact message digit column");
            columns[digit_column][value_index] = *digit % modulus;
            let trit_count = layout
                .digit_trit_count(digit_index)
                .expect("compact message trit count");
            let trits = compact_vss_message_digit_trits_for_count(*digit, trit_count)
                .expect("compact message trits");
            for (trit_index, trit) in trits.iter().enumerate() {
                let trit_column = layout
                    .trit_encoding_column(digit_index, trit_index)
                    .expect("compact message trit column");
                columns[trit_column][value_index] = *trit % modulus;
            }
        }
    }

    columns
}

fn signed_residue_column(values: &[i64], modulus: u64) -> Vec<u64> {
    values
        .iter()
        .map(|value| signed_value_residue(*value, modulus))
        .collect()
}

fn evaluate_extension_vector_dot_products(
    public_vectors: &[Vec<super::super::extension_field::ChallengeExtensionElement>],
    witness_columns: &[Vec<u64>],
    tower: &super::super::extension_field::ChallengeExtensionTower,
) -> super::super::extension_field::ChallengeExtensionElement {
    public_vectors.iter().zip(witness_columns.iter()).fold(
        super::super::extension_field::ChallengeExtensionTower::zero(),
        |mut accumulated, (public_vector, witness_column)| {
            for (public_value, witness_value) in public_vector.iter().zip(witness_column.iter()) {
                accumulated = tower.add(
                    &accumulated,
                    &tower.scale_base(public_value, *witness_value),
                );
            }
            accumulated
        },
    )
}
