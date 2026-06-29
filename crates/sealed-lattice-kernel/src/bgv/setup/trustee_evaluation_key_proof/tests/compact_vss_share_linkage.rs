use super::*;
use crate::bgv::setup::compact_vss_commitment::{
    CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
};
use serde_json::json;

#[test]
fn compact_vss_share_linkage_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = compact_vss_share_linkage_instance();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify compact share-linkage proof");

    let (invalid_share_statement, mut invalid_share_witness) = compact_vss_share_linkage_instance();
    invalid_share_witness.compact_vss_recipient_share_messages_by_item[0][0] =
        (invalid_share_witness.compact_vss_recipient_share_messages_by_item[0][0] + 1)
            % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(
            &invalid_share_statement,
            &invalid_share_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a witness whose lifted share relation does not match"
    );

    let (non_ternary_statement, mut non_ternary_witness) = compact_vss_share_linkage_instance();
    non_ternary_witness.compact_vss_recipient_share_opening_randomness_by_item[1][0][0] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_ternary_statement,
            &non_ternary_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject non-ternary compact opening randomness"
    );

    let (mut tampered_statement, _unused_witness) = compact_vss_share_linkage_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_statement
        .compact_vss_share_linkage
        .as_mut()
        .expect("compact statement")
        .recipient_share_commitment
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the public compact recipient-share commitment must reject"
    );

    let (mut tampered_opening_statement, _unused_witness) = compact_vss_share_linkage_instance();
    tampered_opening_statement
        .compact_vss_share_linkage
        .as_mut()
        .expect("compact statement")
        .coefficient_opening_roots[0] = repeated_hash("fa");

    assert!(
        verify_evaluation_key_share(&tampered_opening_statement, &proof).is_err(),
        "tampering with a compact coefficient opening root must reject"
    );

    let (mut tampered_additional_statement, _unused_witness) = compact_vss_share_linkage_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_additional_statement
        .compact_vss_share_linkage
        .as_mut()
        .expect("compact statement")
        .additional_linkage_items[0]
        .recipient_share_commitment
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_additional_statement, &proof).is_err(),
        "tampering with an additional compact recipient-share commitment must reject"
    );
}

fn compact_vss_share_linkage_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("bc");
    let primary_item = compact_share_linkage_item_for_test(
        "primary",
        &public_matrix_seed_hash,
        ring_degree,
        0,
        2,
        3,
        10,
    );
    let mut same_source_additional_item = compact_share_linkage_item_for_test(
        "same-source-additional",
        &public_matrix_seed_hash,
        ring_degree,
        0,
        4,
        3,
        10,
    );
    same_source_additional_item.coefficient_commitment_computations =
        primary_item.coefficient_commitment_computations.clone();
    let additional_item = compact_share_linkage_item_for_test(
        "additional",
        &public_matrix_seed_hash,
        ring_degree,
        1,
        3,
        2,
        70,
    );

    let source_coefficient_commitment_root = repeated_hash("91");
    let source_recipient_share_commitment_root = repeated_hash("92");
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: super::super::COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY.to_string(),
            ceremony_id: "compact-vss-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![
                (
                    "sourceCoefficientCommitmentRoot".to_string(),
                    source_coefficient_commitment_root.clone(),
                ),
                (
                    "sourceRecipientShareCommitmentRoot".to_string(),
                    source_recipient_share_commitment_root.clone(),
                ),
            ],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: Some(CompactVssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            recipient_identity: primary_item.recipient_identity.clone(),
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root,
            source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            source_message_modulus: primary_item.source_message_modulus,
            coefficient_commitment_roots: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.commitment_root.clone())
                .collect(),
            coefficient_opening_roots: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.opening_root.clone())
                .collect(),
            coefficient_commitments: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.commitment.clone())
                .collect(),
            recipient_share_commitment_root: primary_item
                .recipient_share_commitment_computation
                .commitment_root
                .clone(),
            recipient_share_opening_root: primary_item
                .recipient_share_commitment_computation
                .opening_root
                .clone(),
            recipient_share_commitment: primary_item
                .recipient_share_commitment_computation
                .commitment
                .clone(),
            additional_linkage_items: vec![
                compact_share_linkage_item_statement(&same_source_additional_item),
                compact_share_linkage_item_statement(&additional_item),
            ],
        }),
        compact_same_secret_bridge: None,
        target_decryption_share: None,
    };
    statement
        .validate_shape()
        .expect("compact share-linkage statement");
    let layout = LimbColumnLayout::new(&statement, 0).expect("compact share-linkage layout");
    assert_eq!(
        layout.compact_vss_coefficient_relation_columns, 8,
        "three compact share-linkage items bind eight public coefficient commitments"
    );
    assert_eq!(
        layout.compact_vss_coefficient_columns, 5,
        "the two same-source items share three coefficient witness columns"
    );
    assert_eq!(
        layout.compact_vss_item_columns, 3,
        "the compact share-linkage statement should batch three carried share relations"
    );
    assert!(
        layout.compact_vss_randomness_columns > 0,
        "opening randomness must remain in the compact opening lincheck"
    );
    assert_eq!(
        layout.consistency_vector_count(),
        layout.compact_vss_item_columns
            + layout.compact_vss_message_vector_count()
                * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT,
        "compact share-linkage consistency claims must bind carries and message digits"
    );
    assert_eq!(
        layout.claim_count(),
        layout.consistency_vector_count() * layout.consistency_repetitions
    );
    let later_commitment_limb_layout =
        LimbColumnLayout::new(&statement, 1).expect("compact share-linkage second limb layout");
    assert_eq!(
        layout.compact_vss_coefficient_decoder_digit_count(),
        0,
        "compact share-linkage coefficient digits are bounded by masked digit claims"
    );
    assert_eq!(
        layout.compact_vss_recipient_decoder_digit_count(),
        0,
        "compact share-linkage recipient digits are bounded by masked digit claims"
    );
    assert_eq!(
        layout.compact_vss_message_encoding_column_count(0),
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT,
        "compact share-linkage coefficient messages should carry only digit columns"
    );
    assert_eq!(
        layout.compact_vss_message_encoding_column_count(layout.compact_vss_coefficient_columns),
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT,
        "compact share-linkage recipient messages should carry only digit columns"
    );
    assert_eq!(
        layout.compact_vss_message_trit_count(layout.compact_vss_coefficient_columns, 0),
        0,
        "compact share-linkage recipient digits should not carry trit decoder columns"
    );
    assert!(
        later_commitment_limb_layout.compact_vss_coefficient_decoder_digit_count() == 0
            && later_commitment_limb_layout.compact_vss_recipient_decoder_digit_count() == 0,
        "later compact share-linkage limbs also carry digit-only encodings"
    );
    assert_eq!(
        later_commitment_limb_layout.consistency_vector_count(),
        layout.consistency_vector_count(),
        "digit-only limbs must keep the same cross-field claim set"
    );
    assert_eq!(
        later_commitment_limb_layout.compact_vss_message_encoding_columns(),
        layout.compact_vss_message_encoding_columns(),
        "all compact share-linkage limbs should use the same digit-only message width"
    );

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: primary_item
            .coefficient_messages
            .iter()
            .chain(additional_item.coefficient_messages.iter())
            .map(|messages| {
                messages
                    .iter()
                    .map(|value| i64::try_from(*value).expect("message fits i64"))
                    .collect()
            })
            .collect(),
        compact_vss_recipient_share_messages: primary_item
            .recipient_share_values
            .iter()
            .map(|value| i64::try_from(*value).expect("share fits i64"))
            .collect(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: primary_item
            .coefficient_randomness
            .iter()
            .chain(additional_item.coefficient_randomness.iter())
            .cloned()
            .collect(),
        compact_vss_recipient_share_opening_randomness: primary_item
            .recipient_share_randomness
            .clone(),
        compact_vss_carry_witnesses: primary_item.recipient_share_carry_values.clone(),
        compact_vss_recipient_share_messages_by_item: vec![
            primary_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
            same_source_additional_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
            additional_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
        ],
        compact_vss_recipient_share_opening_randomness_by_item: vec![
            primary_item.recipient_share_randomness,
            same_source_additional_item.recipient_share_randomness,
            additional_item.recipient_share_randomness,
        ],
        compact_vss_carry_witnesses_by_item: vec![
            primary_item.recipient_share_carry_values,
            same_source_additional_item.recipient_share_carry_values,
            additional_item.recipient_share_carry_values,
        ],
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    };

    (statement, witness)
}

fn compact_share_linkage_item_statement(
    item: &CompactShareLinkageItemForTest,
) -> CompactVssShareLinkageItem {
    CompactVssShareLinkageItem {
        recipient_identity: item.recipient_identity.clone(),
        recipient_roster_position: item.recipient_roster_position,
        source_rns_limb_index: item.source_rns_limb_index,
        source_message_modulus: item.source_message_modulus,
        coefficient_commitment_roots: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.commitment_root.clone())
            .collect(),
        coefficient_opening_roots: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.opening_root.clone())
            .collect(),
        coefficient_commitments: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.commitment.clone())
            .collect(),
        recipient_share_commitment_root: item
            .recipient_share_commitment_computation
            .commitment_root
            .clone(),
        recipient_share_opening_root: item
            .recipient_share_commitment_computation
            .opening_root
            .clone(),
        recipient_share_commitment: item
            .recipient_share_commitment_computation
            .commitment
            .clone(),
    }
}

struct CompactShareLinkageItemForTest {
    recipient_identity: String,
    recipient_roster_position: u64,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    coefficient_messages: Vec<Vec<u64>>,
    coefficient_randomness: Vec<Vec<Vec<i64>>>,
    recipient_share_values: Vec<u64>,
    recipient_share_randomness: Vec<Vec<i64>>,
    recipient_share_carry_values: Vec<i64>,
    coefficient_commitment_computations: Vec<CompactCommitmentComputationForTest>,
    recipient_share_commitment_computation: CompactCommitmentComputationForTest,
}

fn compact_share_linkage_item_for_test(
    item_label: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    source_rns_limb_index: usize,
    recipient_roster_position: u64,
    coefficient_count: usize,
    seed_offset: i64,
) -> CompactShareLinkageItemForTest {
    let source_message_modulus = DATA_PRIMES[source_rns_limb_index];
    let recipient_trustee_point = recipient_roster_position + 1;
    let coefficient_messages = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    if coefficient_index % 11 == shamir_coefficient_index {
                        source_message_modulus - 4 - shamir_coefficient_index as u64
                    } else {
                        (17 + seed_offset as u64
                            + 19 * shamir_coefficient_index as u64
                            + 23 * coefficient_index as u64)
                            % source_message_modulus
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let coefficient_randomness = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            compact_ternary_randomness_columns(
                ring_degree,
                seed_offset + shamir_coefficient_index as i64,
            )
        })
        .collect::<Vec<_>>();
    let recipient_share_randomness =
        compact_ternary_randomness_columns(ring_degree, seed_offset + 31);

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
            .push((lifted_share / u128::from(source_message_modulus)) as i64);
    }
    assert!(
        recipient_share_carry_values
            .iter()
            .any(|carry_value| *carry_value > 0),
        "compact share-linkage fixture must exercise carried share values"
    );

    let coefficient_commitment_computations = coefficient_messages
        .iter()
        .zip(coefficient_randomness.iter())
        .enumerate()
        .map(
            |(shamir_coefficient_index, (messages, randomness_by_column))| {
                compact_commitment_computation_for_test(
                    "coefficient",
                    json!({
                        "testPurpose": "compact-share-linkage-proof",
                        "itemLabel": item_label,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                    public_matrix_seed_hash,
                    source_rns_limb_index,
                    source_message_modulus,
                    ring_degree,
                    messages,
                    randomness_by_column,
                )
            },
        )
        .collect::<Vec<_>>();
    let recipient_share_commitment_computation = compact_commitment_computation_for_test(
        "recipient-share",
        json!({
            "testPurpose": "compact-share-linkage-proof",
            "itemLabel": item_label,
            "recipientRosterPosition": recipient_roster_position,
        }),
        public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        ring_degree,
        &recipient_share_values,
        &recipient_share_randomness,
    );

    CompactShareLinkageItemForTest {
        recipient_identity: format!("trustee-{recipient_roster_position}"),
        recipient_roster_position,
        source_rns_limb_index,
        source_message_modulus,
        coefficient_messages,
        coefficient_randomness,
        recipient_share_values,
        recipient_share_randomness,
        recipient_share_carry_values,
        coefficient_commitment_computations,
        recipient_share_commitment_computation,
    }
}

#[derive(Clone)]
struct CompactCommitmentComputationForTest {
    commitment: CompactVssShareLinkageCommitment,
    commitment_root: String,
    opening_root: String,
}

fn compact_ternary_randomness_columns(ring_degree: usize, seed_offset: i64) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    ((seed_offset + column_index as i64 * 5 + coefficient_index as i64 * 7)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn compact_commitment_computation_for_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
) -> CompactCommitmentComputationForTest {
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

    let coordinates_by_commitment_modulus = computation
        .commitment
        .get("commitmentLimbs")
        .and_then(serde_json::Value::as_array)
        .expect("compact commitment limbs")
        .iter()
        .map(|limb| {
            limb.get("coordinates")
                .and_then(serde_json::Value::as_array)
                .expect("compact commitment coordinates")
                .iter()
                .map(|coordinate| coordinate.as_u64().expect("compact coordinate"))
                .collect()
        })
        .collect();

    CompactCommitmentComputationForTest {
        commitment: CompactVssShareLinkageCommitment {
            coordinates_by_commitment_modulus,
        },
        commitment_root: computation.commitment_root,
        opening_root: computation.opening_root,
    }
}
