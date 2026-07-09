use super::super::LINCHECK_REPETITIONS;
use super::super::SAME_SECRET_BRIDGE_PROOF_FAMILY;
use super::super::relation::{
    SameSecretBridgeStatement, SuccinctSetupProofFamilyShape, TrusteeEvaluationKeyWitness,
};
use super::*;
use crate::bgv::evaluator::top_k::canonical_target_basis_hash;
use crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
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
        layout.same_secret_bridge_target_count() * LINCHECK_REPETITIONS
            + layout.same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS,
        "bridge relation challenges must include the bridge lincheck and decoder rows"
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
    tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .material_roots_by_commitment_field[0][0] ^= 0x01;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the published target constant material root must reject"
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
        DATA_PRIMES.len() * LINCHECK_REPETITIONS
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
    tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .material_roots_by_commitment_field[0][0] ^= 0x01;
    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with bridge material must reject the public-key share proof"
    );
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

    let target_constant_material = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &secret_coefficients,
                &negative_indicator_coefficients,
                *target_rns_prime,
            );
            test_committed_material_commitment(
                "coefficient",
                json!({
                    "testPurpose": "same-secret-bridge-proof",
                    "targetRnsLimbIndex": target_rns_limb_index,
                }),
                target_rns_limb_index,
                *target_rns_prime,
                ring_degree,
                &message_coefficients,
                *target_rns_prime,
            )
        })
        .collect::<Vec<_>>();
    let target_constant_commitments = target_constant_material
        .iter()
        .map(|material| material.commitment.clone())
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
        opening_randomness_by_limb: Vec::new(),
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
        vss_committed_material_seeds_by_bound_message: target_constant_material
            .iter()
            .map(|material| material.material_seed_hex.clone())
            .collect(),
        vss_committed_material_context_hashes_by_bound_message: target_constant_material
            .iter()
            .map(|material| material.context_hash.clone())
            .collect(),
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
    let target_constant_material = target_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &witness.secret_coefficients,
                &witness.negative_indicator_coefficients,
                *target_rns_prime,
            );
            test_committed_material_commitment(
                "coefficient",
                json!({
                    "testPurpose": "same-secret-bridge-key-attach",
                    "targetRnsLimbIndex": target_rns_limb_index,
                }),
                target_rns_limb_index,
                *target_rns_prime,
                statement.ring_degree,
                &message_coefficients,
                *target_rns_prime,
            )
        })
        .collect::<Vec<_>>();
    let target_constant_commitments = target_constant_material
        .iter()
        .map(|material| material.commitment.clone())
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
    witness.opening_randomness_by_limb = Vec::new();
    witness.vss_committed_material_seeds_by_bound_message = target_constant_material
        .iter()
        .map(|material| material.material_seed_hex.clone())
        .collect();
    witness.vss_committed_material_context_hashes_by_bound_message = target_constant_material
        .iter()
        .map(|material| material.context_hash.clone())
        .collect();
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
