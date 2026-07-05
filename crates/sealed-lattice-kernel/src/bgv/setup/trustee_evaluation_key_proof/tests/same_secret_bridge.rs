use super::super::LINCHECK_REPETITIONS;
use super::super::SAME_SECRET_BRIDGE_PROOF_FAMILY;
use super::super::relation::{
    SameSecretBridgeStatement, SuccinctSetupProofFamilyShape, TrusteeEvaluationKeyWitness,
    VssShareLinkageCommitment,
};
use super::*;
use crate::bgv::evaluator::top_k::canonical_target_basis_hash;
use crate::bgv::setup::vss_commitment::{
    VSS_PUBLIC_MESSAGE_DIGIT_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
    VssPublicCommitmentOpeningInput, compute_vss_public_commitment_from_opening,
    vss_public_canonical_message_digit_columns,
};
use serde_json::json;

#[test]
fn same_secret_bridge_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = same_secret_bridge_instance();
    assert_eq!(
        statement
            .same_secret_bridge
            .as_ref()
            .expect("bridge statement")
            .target_rns_primes
            .len(),
        7,
        "bridge fixture should exercise the current target-basis limb count"
    );
    let layout = LimbColumnLayout::new(&statement, 0).expect("bridge layout");
    let bridge_digit_count = layout.same_secret_bridge_target_count()
        * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
    assert_eq!(
        layout.same_secret_bridge_decoder_digit_count(),
        bridge_digit_count,
        "bridge target-message digits must carry verifier-side decoder rows"
    );
    assert!(
        layout.same_secret_bridge_message_encoding_columns() > bridge_digit_count,
        "bridge target messages must carry digit and trit columns"
    );
    assert_eq!(
        layout.consistency_vector_count(),
        2 + bridge_digit_count + layout.linkage_randomness_columns,
        "bridge consistency claims must bind the secret, indicator, target digits, and randomness"
    );
    assert_eq!(
        layout.same_secret_bridge_relation_count(),
        layout.same_secret_bridge_target_count()
            * (crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT
                + LINCHECK_REPETITIONS)
            + layout.same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS,
        "bridge relation challenges must include decoder rows"
    );
    assert!(
        layout.same_secret_bridge_message_trit_count(0, 0) > 0,
        "bridge target messages must carry trit decoder columns"
    );
    let later_commitment_limb_layout =
        LimbColumnLayout::new(&statement, 1).expect("bridge second limb layout");
    assert_eq!(
        later_commitment_limb_layout.same_secret_bridge_relation_count(),
        layout.same_secret_bridge_relation_count(),
        "bridge commitment limbs should use the same decoder-backed relation"
    );
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify same-secret bridge");

    let (invalid_secret_statement, mut invalid_secret_witness) = same_secret_bridge_instance();
    invalid_secret_witness.secret_coefficients[0] = 1;
    invalid_secret_witness.negative_indicator_coefficients[0] = 0;
    assert!(
        prove_evaluation_key_share(
            &invalid_secret_statement,
            &invalid_secret_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a secret that no longer opens the target constants"
    );

    let (non_binary_statement, mut non_binary_witness) = same_secret_bridge_instance();
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

    let (mut tampered_statement, _unused_witness) = same_secret_bridge_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the public target constant must reject"
    );

    let (mut wrong_target_basis_statement, _unused_witness) = same_secret_bridge_instance();
    wrong_target_basis_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_basis_hash = repeated_hash("c1");
    assert!(
        wrong_target_basis_statement.validate_shape().is_err(),
        "same-secret bridge statements must bind the canonical target basis hash"
    );
}

#[test]
fn public_key_share_proof_round_trips_with_same_secret_bridge() {
    let (statement, witness) =
        generate_development_public_key_share_instance("c0ffee01", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let (statement, witness) =
        attach_same_secret_bridge_to_key_statement(statement, witness, DATA_PRIMES.len());

    assert_eq!(
        statement.family_shape().expect("statement shape"),
        SuccinctSetupProofFamilyShape::PublicKeyShare
    );
    assert!(
        statement.same_secret_linkage.is_none(),
        "public-key share must use the same-secret bridge"
    );
    assert!(
        statement.same_secret_bridge.is_some(),
        "public-key share must carry bridge material"
    );
    assert_eq!(statement.limb_count(), DATA_PRIMES.len());

    let setup_field_layout =
        LimbColumnLayout::new(&statement, 0).expect("public-key setup-field layout");
    assert!(setup_field_layout.same_secret_bridge_material_active());
    let bridge_digit_count = DATA_PRIMES.len() * VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
    assert_eq!(
        setup_field_layout.consistency_vector_count(),
        1 + statement.keys[0].digit_count()
            + 1
            + bridge_digit_count
            + setup_field_layout.linkage_randomness_columns,
        "setup commitment fields must claim key errors and bridge witnesses together"
    );
    assert_eq!(
        setup_field_layout.same_secret_bridge_relation_count(),
        DATA_PRIMES.len()
            * (crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT
                + LINCHECK_REPETITIONS)
            + setup_field_layout.same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS,
    );

    let key_only_limb_index = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
    assert!(
        key_only_limb_index < DATA_PRIMES.len(),
        "the public-key share fixture should exercise key-only limbs after setup commitment fields"
    );
    let key_only_layout =
        LimbColumnLayout::new(&statement, key_only_limb_index).expect("public-key key-only layout");
    assert!(!key_only_layout.same_secret_bridge_material_active());
    assert_eq!(key_only_layout.linkage_randomness_columns, 0);
    assert_eq!(
        key_only_layout.consistency_vector_count(),
        1 + statement.keys[0].digit_count(),
        "later public-key limbs should carry only the key relation claims"
    );

    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify public-key share");

    let mut tampered_statement = statement;
    let coordinate = &mut tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % DATA_PRIMES[0];
    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with bridge material must reject the public-key share proof"
    );
}

#[test]
fn trustee_evaluation_key_proof_round_trips_with_same_secret_bridge() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "facefeed",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("trustee evaluation-key instance");
    let (statement, witness) =
        attach_same_secret_bridge_to_key_statement(statement, witness, DATA_PRIMES.len());

    assert_eq!(
        statement.family_shape().expect("statement shape"),
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey
    );
    assert!(
        statement.same_secret_linkage.is_none(),
        "evaluation-key proof must use the same-secret bridge"
    );
    assert_eq!(
        statement.proof_limb_count(),
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len(),
        "the focused evaluation-key fixture keeps proof limbs on the setup commitment fields"
    );
    let layout =
        LimbColumnLayout::new(&statement, 0).expect("trustee evaluation-key setup-field layout");
    assert!(layout.same_secret_bridge_material_active());
    assert_eq!(layout.active_keys.len(), 1);
    assert_eq!(layout.total_error_columns, statement.keys[0].digit_count());
    assert_eq!(
        layout.consistency_vector_count(),
        1 + statement.keys[0].digit_count()
            + 1
            + DATA_PRIMES.len() * VSS_PUBLIC_MESSAGE_DIGIT_COUNT
            + DATA_PRIMES.len() * VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        "evaluation-key bridge fields must claim the key, bridge digits, and opening randomness"
    );

    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify trustee evaluation-key proof");
}

fn same_secret_bridge_instance() -> (
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
            bridge_randomness_columns(ring_degree, 17 + target_rns_limb_index as i64)
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
            VssShareLinkageCommitment {
                coordinates_by_commitment_modulus: bridge_coordinates_by_modulus_for_test(
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

    let same_secret_bridge_statement_root = repeated_hash("a1");
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY.to_string(),
            ceremony_id: "bridge-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![
                (
                    "sameSecretBridgeStatementRoot".to_string(),
                    same_secret_bridge_statement_root,
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
        vss_share_linkage: None,
        same_secret_bridge: Some(SameSecretBridgeStatement {
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
        .expect("same-secret bridge statement");

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients,
        opening_randomness_by_limb,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages: Vec::new(),
        vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        vss_public_recipient_share_opening_randomness: Vec::new(),
        vss_public_carry_witnesses: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    };

    (statement, witness)
}

fn attach_same_secret_bridge_to_key_statement(
    mut statement: TrusteeEvaluationKeyStatement,
    mut witness: TrusteeEvaluationKeyWitness,
    target_rns_limb_count: usize,
) -> (TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness) {
    assert!((1..=DATA_PRIMES.len()).contains(&target_rns_limb_count));
    let public_matrix_seed_hash = statement
        .same_secret_linkage
        .as_ref()
        .map(|linkage| linkage.public_matrix_seed_hash.clone())
        .unwrap_or_else(|| repeated_hash("cd"));
    let target_basis_hash = canonical_target_basis_hash().expect("canonical target basis hash");
    let target_rns_primes = DATA_PRIMES[..target_rns_limb_count].to_vec();
    let opening_randomness_by_limb = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, _target_rns_prime)| {
            bridge_randomness_columns(statement.ring_degree, 101 + target_rns_limb_index as i64)
        })
        .collect::<Vec<_>>();
    let target_constant_commitments = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &witness.secret_coefficients,
                &witness.negative_indicator_coefficients,
                *target_rns_prime,
            );
            VssShareLinkageCommitment {
                coordinates_by_commitment_modulus: bridge_coordinates_by_modulus_for_test(
                    &public_matrix_seed_hash,
                    target_rns_limb_index,
                    *target_rns_prime,
                    statement.ring_degree,
                    &message_coefficients,
                    &opening_randomness_by_limb[target_rns_limb_index],
                ),
            }
        })
        .collect::<Vec<_>>();

    statement.same_secret_linkage = None;
    statement.same_secret_bridge = Some(SameSecretBridgeStatement {
        public_matrix_seed_hash,
        source_trustee_identity: statement.context.trustee_identity.clone(),
        source_trustee_roster_position: statement.context.trustee_roster_position,
        target_basis_hash,
        target_rns_primes,
        target_constant_commitment_roots: (0..target_rns_limb_count)
            .map(|target_rns_limb_index| {
                repeated_hash(&format!("{:02x}", 0xe0 + target_rns_limb_index))
            })
            .collect(),
        target_constant_commitments,
    });
    witness.opening_randomness_by_limb = opening_randomness_by_limb;
    statement.validate_shape().expect("key statement shape");

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

fn bridge_randomness_columns(ring_degree: usize, seed_offset: i64) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
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

fn bridge_coordinates_by_modulus_for_test(
    public_matrix_seed_hash: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
) -> Vec<Vec<u64>> {
    (0..SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
        .map(|commitment_modulus_index| {
            let message_digit_columns =
                vss_public_canonical_message_digit_columns(message_coefficients, ring_degree)
                    .expect("same-secret bridge message digit columns");
            let computation =
                compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
                    commitment_role: "coefficient",
                    commitment_context: &json!({
                        "testPurpose": "same-secret-bridge-proof",
                        "targetRnsLimbIndex": target_rns_limb_index,
                    }),
                    public_matrix_seed_hash,
                    rns_limb_index: target_rns_limb_index,
                    rns_prime: target_rns_prime,
                    ring_degree,
                    message_coefficients,
                    message_digit_columns: &message_digit_columns,
                    message_coefficient_bound: target_rns_prime,
                    randomness_by_column,
                })
                .expect("same-secret bridge commitment");

            computation
                .commitment
                .get("commitmentLimbs")
                .and_then(serde_json::Value::as_array)
                .expect("commitment limbs")
                .get(commitment_modulus_index)
                .and_then(|limb| limb.get("coordinates"))
                .and_then(serde_json::Value::as_array)
                .expect("commitment coordinates")
                .iter()
                .map(|coordinate| coordinate.as_u64().expect("coordinate"))
                .collect()
        })
        .collect()
}
