use super::*;
use crate::bgv::evaluator::top_k::canonical_target_basis_hash;
use crate::bgv::setup::compact_vss_commitment::{
    CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
};
use serde_json::json;

#[test]
fn compact_same_secret_bridge_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = compact_same_secret_bridge_instance();
    assert_eq!(
        statement
            .compact_same_secret_bridge
            .as_ref()
            .expect("compact bridge statement")
            .target_rns_primes
            .len(),
        7,
        "compact bridge fixture should exercise the current target-basis limb count"
    );
    let layout = LimbColumnLayout::new(&statement, 0).expect("compact bridge layout");
    let bridge_digit_count = layout.compact_same_secret_bridge_target_count()
        * crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT;
    assert_eq!(
        layout.compact_same_secret_bridge_decoder_digit_count(),
        0,
        "compact bridge target-message digits are bounded by masked digit claims"
    );
    assert_eq!(
        layout.compact_same_secret_bridge_message_encoding_columns(),
        bridge_digit_count,
        "compact bridge target messages should carry only digit columns"
    );
    assert_eq!(
        layout.consistency_vector_count(),
        2 + bridge_digit_count + layout.linkage_randomness_columns,
        "compact bridge consistency claims must bind the secret, indicator, target digits, and randomness"
    );
    assert_eq!(
        layout.compact_same_secret_bridge_relation_count(),
        layout.compact_same_secret_bridge_target_count()
            * (crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT
                + LINCHECK_REPETITIONS),
        "compact bridge relation challenges should not include decoder rows"
    );
    assert_eq!(
        layout.compact_same_secret_bridge_message_trit_count(0, 0),
        0,
        "compact bridge target messages should not carry trit decoder columns"
    );
    let later_commitment_limb_layout =
        LimbColumnLayout::new(&statement, 1).expect("compact bridge second limb layout");
    assert_eq!(
        later_commitment_limb_layout.compact_same_secret_bridge_relation_count(),
        layout.compact_same_secret_bridge_relation_count(),
        "compact bridge commitment limbs should use the same digit-only relation"
    );
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify compact same-secret bridge");

    let (invalid_secret_statement, mut invalid_secret_witness) =
        compact_same_secret_bridge_instance();
    invalid_secret_witness.secret_coefficients[0] = 1;
    invalid_secret_witness.negative_indicator_coefficients[0] = 0;
    assert!(
        prove_evaluation_key_share(
            &invalid_secret_statement,
            &invalid_secret_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a secret that no longer opens the compact target constants"
    );

    let (non_binary_statement, mut non_binary_witness) = compact_same_secret_bridge_instance();
    non_binary_witness.negative_indicator_coefficients[1] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_binary_statement,
            &non_binary_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a non-binary negative indicator"
    );

    let (mut tampered_statement, _unused_witness) = compact_same_secret_bridge_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_statement
        .compact_same_secret_bridge
        .as_mut()
        .expect("compact bridge statement")
        .target_constant_commitments[0]
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the public compact target constant must reject"
    );

    let (mut wrong_target_basis_statement, _unused_witness) = compact_same_secret_bridge_instance();
    wrong_target_basis_statement
        .compact_same_secret_bridge
        .as_mut()
        .expect("compact bridge statement")
        .target_basis_hash = repeated_hash("c1");
    assert!(
        wrong_target_basis_statement.validate_shape().is_err(),
        "compact same-secret bridge statements must bind the canonical target basis hash"
    );
}

fn compact_same_secret_bridge_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("cd");
    let target_basis_hash = canonical_target_basis_hash().expect("canonical target basis hash");
    let target_rns_limb_count = 7_usize;
    let target_rns_primes = DATA_PRIMES[..target_rns_limb_count].to_vec();
    let secret_coefficients = (0..ring_degree)
        .map(|coefficient_index| match coefficient_index % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect::<Vec<_>>();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let opening_randomness_by_limb = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, _target_rns_prime)| {
            compact_bridge_randomness_columns(ring_degree, 17 + target_rns_limb_index as i64)
        })
        .collect::<Vec<_>>();

    let target_constant_commitments = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &secret_coefficients,
                &negative_indicator_coefficients,
                *target_rns_prime,
            );
            CompactVssShareLinkageCommitment {
                coordinates_by_commitment_modulus: compact_bridge_coordinates_by_modulus_for_test(
                    &public_matrix_seed_hash,
                    target_rns_limb_index,
                    *target_rns_prime,
                    ring_degree,
                    &message_coefficients,
                    &opening_randomness_by_limb[target_rns_limb_index],
                ),
            }
        })
        .collect::<Vec<_>>();

    let compact_same_secret_bridge_statement_root = repeated_hash("a1");
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY.to_string(),
            ceremony_id: "compact-bridge-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![
                (
                    "compactSameSecretBridgeStatementRoot".to_string(),
                    compact_same_secret_bridge_statement_root,
                ),
                ("sameSecretStatementRoot".to_string(), repeated_hash("b1")),
                ("sameSecretProofRoot".to_string(), repeated_hash("b2")),
                (
                    "sameSecretProofFamilyBindingRoot".to_string(),
                    repeated_hash("b3"),
                ),
            ],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: None,
        compact_same_secret_bridge: Some(CompactSameSecretBridgeStatement {
            public_matrix_seed_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            target_basis_hash,
            target_rns_primes,
            target_constant_commitment_roots: (0..target_rns_limb_count)
                .map(|target_rns_limb_index| {
                    repeated_hash(&format!("{:02x}", 0xd0 + target_rns_limb_index))
                })
                .collect(),
            target_constant_commitments,
        }),
        target_decryption_share: None,
    };
    statement
        .validate_shape()
        .expect("compact same-secret bridge statement");

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients,
        opening_randomness_by_limb,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_messages: Vec::new(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_opening_randomness: Vec::new(),
        compact_vss_carry_witnesses: Vec::new(),
        compact_vss_recipient_share_messages_by_item: Vec::new(),
        compact_vss_recipient_share_opening_randomness_by_item: Vec::new(),
        compact_vss_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    };

    (statement, witness)
}

fn bridge_message_coefficients(
    secret_coefficients: &[i64],
    negative_indicator_coefficients: &[i64],
    target_rns_prime: u64,
) -> Vec<u64> {
    secret_coefficients
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(secret_coefficient, negative_indicator)| {
            let lifted = i128::from(*secret_coefficient)
                + i128::from(*negative_indicator) * i128::from(target_rns_prime);
            u64::try_from(lifted).expect("bridge message is canonical")
        })
        .collect()
}

fn compact_bridge_randomness_columns(ring_degree: usize, seed_offset: i64) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    ((seed_offset + column_index as i64 * 11 + coefficient_index as i64 * 13)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}

fn compact_bridge_coordinates_by_modulus_for_test(
    public_matrix_seed_hash: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
) -> Vec<Vec<u64>> {
    (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
        .map(|commitment_modulus_index| {
            let computation =
                compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
                    commitment_role: "coefficient",
                    commitment_context: &json!({
                        "testPurpose": "compact-same-secret-bridge-proof",
                        "targetRnsLimbIndex": target_rns_limb_index,
                    }),
                    public_matrix_seed_hash,
                    rns_limb_index: target_rns_limb_index,
                    rns_prime: target_rns_prime,
                    ring_degree,
                    message_coefficients,
                    message_coefficient_bound: target_rns_prime,
                    randomness_by_column,
                })
                .expect("compact same-secret bridge commitment");

            computation
                .commitment
                .get("commitmentLimbs")
                .and_then(serde_json::Value::as_array)
                .expect("compact commitment limbs")
                .get(commitment_modulus_index)
                .and_then(|limb| limb.get("coordinates"))
                .and_then(serde_json::Value::as_array)
                .expect("compact commitment coordinates")
                .iter()
                .map(|coordinate| coordinate.as_u64().expect("compact coordinate"))
                .collect()
        })
        .collect()
}
