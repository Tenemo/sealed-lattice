use super::super::relation::{
    TargetDecryptionShareLimbStatement, TargetDecryptionShareRoleStatement,
    TargetDecryptionShareStatement, VssShareLinkageCommitment,
    masked_claim_bounds_for_global_claim,
};
use super::super::{
    CLAIM_MASK_RADIX, CONSISTENCY_COEFFICIENT_BITS, LINCHECK_REPETITIONS,
    TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
    TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
    TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
};
use super::*;
use crate::bgv::evaluator::engine::negacyclic_mul;
use crate::bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast};
use crate::bgv::parameters::PLAINTEXT_MODULUS;
use crate::bgv::setup::vss_commitment::{
    VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, vss_public_message_encoding_layout,
};
use serde_json::{Value, json};

#[test]
fn target_decryption_share_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = target_decryption_share_instance();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify target-decryption share proof");

    let (mut tampered_partial_statement, _unused_witness) = target_decryption_share_instance();
    let target_decryption_share = tampered_partial_statement
        .target_decryption_share
        .as_mut()
        .expect("target statement");
    target_decryption_share.limb_statements[0].role_statements[0].released_partial_decryption[0] =
        (target_decryption_share.limb_statements[0].role_statements[0].released_partial_decryption
            [0]
            + 1)
            % target_decryption_share.limb_statements[0].target_rns_prime;
    assert!(
        verify_evaluation_key_share(&tampered_partial_statement, &proof).is_err(),
        "tampering with the released partial must reject"
    );

    let (mut tampered_commitment_statement, _unused_witness) = target_decryption_share_instance();
    tampered_commitment_statement
        .target_decryption_share
        .as_mut()
        .expect("target statement")
        .limb_statements[0]
        .aggregate_commitment
        .material_roots_by_commitment_field[0][0] ^= 0x01;
    assert!(
        verify_evaluation_key_share(&tampered_commitment_statement, &proof).is_err(),
        "tampering with a published aggregate commitment material root must reject"
    );

    let (invalid_aggregate_statement, mut invalid_aggregate_witness) =
        target_decryption_share_instance();
    let target_prime = invalid_aggregate_statement
        .target_decryption_share
        .as_ref()
        .expect("target statement")
        .limb_statements[0]
        .target_rns_prime;
    invalid_aggregate_witness.target_decryption_message_vectors[0][5] =
        (invalid_aggregate_witness.target_decryption_message_vectors[0][5] + 1)
            % i64::try_from(target_prime).expect("target prime fits i64");
    assert!(
        prove_evaluation_key_share(
            &invalid_aggregate_statement,
            &invalid_aggregate_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject an aggregate-share witness that no longer reconstructs the partial"
    );

    let (invalid_bound_statement, mut invalid_bound_witness) = target_decryption_share_instance();
    let aggregate_message_coefficient_bound = invalid_bound_statement
        .target_decryption_share
        .as_ref()
        .expect("target statement")
        .aggregate_message_coefficient_bound;
    invalid_bound_witness.target_decryption_message_vectors[0][0] =
        i64::try_from(aggregate_message_coefficient_bound).expect("aggregate bound fits i64");
    assert!(
        prove_evaluation_key_share(
            &invalid_bound_statement,
            &invalid_bound_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject aggregate-share messages at the excluded coefficient bound"
    );

    let (invalid_smudging_statement, mut invalid_smudging_witness) =
        target_decryption_share_instance();
    invalid_smudging_witness.target_decryption_message_vectors[2][7] += 1;
    assert!(
        prove_evaluation_key_share(
            &invalid_smudging_statement,
            &invalid_smudging_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a smudging witness that no longer reconstructs the partial"
    );

    // A tampered smudging message that no longer opens its committed material
    // makes the regenerated material root differ from the published one, so the
    // prover refuses fail-closed.
    let (mismatched_material_statement, mut mismatched_material_witness) =
        target_decryption_share_instance();
    mismatched_material_witness.target_decryption_message_vectors[1][3] += 1;
    assert!(
        prove_evaluation_key_share(
            &mismatched_material_statement,
            &mismatched_material_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a target-decryption message that does not open its committed material"
    );

    let (mut wrong_target_basis_statement, _unused_witness) = target_decryption_share_instance();
    wrong_target_basis_statement
        .target_decryption_share
        .as_mut()
        .expect("target statement")
        .target_basis_hash = repeated_hash("df");
    assert!(
        wrong_target_basis_statement.validate_shape().is_err(),
        "target-decryption share statements must bind the canonical target basis hash"
    );
}

#[test]
fn target_decryption_share_proof_bytes_round_trips_and_rejects_tampering() {
    let generate_request = target_decryption_share_command_request();
    let proof_bytes =
        super::generate_target_decryption_share_proof_bytes_from_request(&generate_request)
            .expect("generate target-decryption share proof bytes");
    assert!(!proof_bytes.is_empty());

    let verify_request = target_decryption_share_verification_request(&generate_request);
    super::verify_target_decryption_share_proof_bytes_from_request(&verify_request, &proof_bytes)
        .expect("verify target-decryption share proof bytes");
    let mut tampered_proof_bytes = proof_bytes.clone();
    let flip_position = tampered_proof_bytes.len() / 2;
    tampered_proof_bytes[flip_position] ^= 1;
    assert!(
        super::verify_target_decryption_share_proof_bytes_from_request(
            &verify_request,
            &tampered_proof_bytes
        )
        .is_err(),
        "tampered target-decryption proof bytes must reject"
    );

    let mut tampered_partial_request = verify_request;
    let target_prime = tampered_partial_request["targetDecryptionShare"]["targetRnsLimbStatements"]
        [0]["targetRnsPrime"]
        .as_u64()
        .expect("target prime");
    let first_partial = tampered_partial_request["targetDecryptionShare"]
        ["targetRnsLimbStatements"][0]["targetRoleStatements"][0]["releasedPartialDecryption"][0]
        .as_u64()
        .expect("released partial");
    tampered_partial_request["targetDecryptionShare"]["targetRnsLimbStatements"][0]["targetRoleStatements"]
        [0]["releasedPartialDecryption"][0] = json!((first_partial + 1) % target_prime);
    assert!(
        super::verify_target_decryption_share_proof_bytes_from_request(
            &tampered_partial_request,
            &proof_bytes
        )
        .is_err(),
        "tampering with the released partial must reject proof verification"
    );
}

#[test]
fn target_decryption_share_proof_requires_enough_lift_fields() {
    let instance = target_decryption_share_instance_parts();
    assert_eq!(instance.statement.proof_limb_indices(), vec![0, 1, 2, 3, 4]);
    let commitment_field_layout =
        LimbColumnLayout::new(&instance.statement, 0).expect("commitment-field layout");
    assert_eq!(
        commitment_field_layout.target_decryption_message_columns,
        35
    );
    assert_eq!(
        commitment_field_layout.vss_committed_material_bound_message_count(),
        35,
        "commitment fields open a committed-material tree for every bound message"
    );
    let target_field_layout =
        LimbColumnLayout::new(&instance.statement, 4).expect("target-field layout");
    assert_eq!(target_field_layout.target_decryption_message_columns, 11);
    assert_eq!(
        target_field_layout.vss_committed_material_bound_message_count(),
        0,
        "target-only fields open no committed-material trees; the material trees live in the setup commitment fields"
    );
    assert_eq!(
        target_field_layout.target_decryption_logical_columns(),
        target_decryption_message_encoding_columns_for_limb(&instance.statement, 4)
    );
    assert_eq!(
        target_field_layout.target_decryption_message_trit_count(0, 0),
        0,
        "lifted aggregate messages use digit-only columns on non-decoder limbs"
    );
    assert!(
        target_field_layout.target_decryption_message_trit_count(4, 0) > 0,
        "a target message's own limb must carry the decoder columns"
    );
    let target_statement = instance
        .statement
        .target_decryption_share
        .as_ref()
        .expect("target statement");
    let aggregate_layout =
        vss_public_message_encoding_layout(target_statement.aggregate_message_coefficient_bound)
            .expect("aggregate message layout");
    assert_eq!(
        aggregate_layout
            .digit_trit_count(0)
            .expect("aggregate low digit trit count"),
        VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT,
        "large aggregate-message digits still need the full base-digit trit decoder"
    );
    let smudging_layout =
        vss_public_message_encoding_layout(target_statement.smudging_message_coefficient_bound)
            .expect("smudging message layout");
    assert_eq!(
        smudging_layout
            .digit_trit_count(0)
            .expect("smudging low digit trit count"),
        4,
        "bound-33 smudging messages need only four low-digit trits"
    );
    assert_eq!(
        smudging_layout
            .digit_trit_count(1)
            .expect("smudging high digit trit count"),
        0,
        "bound-33 smudging messages do not need high-digit trits"
    );
    assert_eq!(
        smudging_layout.encoding_column_count(),
        6,
        "two digit columns plus four decoder columns should be carried"
    );
    let target_only_relation_count = instance
        .statement
        .target_decryption_share
        .as_ref()
        .and_then(|target_statement| {
            target_statement
                .limb_statements
                .iter()
                .find(|limb_statement| limb_statement.target_rns_limb_index == 4)
        })
        .map(|limb_statement| limb_statement.role_statements.len() * LINCHECK_REPETITIONS)
        .expect("target limb statement");
    assert!(
        target_field_layout.target_decryption_relation_count > target_only_relation_count,
        "target-decryption relation challenges must include decoder rows"
    );

    let mut sparse_request = instance.command_request;
    let sparse_limb_statement =
        sparse_request["targetDecryptionShare"]["targetRnsLimbStatements"][4].clone();
    sparse_request["targetDecryptionShare"]["targetRnsLimbStatements"] =
        json!([sparse_limb_statement]);
    let error = super::generate_target_decryption_share_proof_bytes_from_request(&sparse_request)
        .expect_err("sparse target-decryption proof must reject before proving");
    assert!(
        error.message.contains(
            "target-decryption proof must cover every active target limb in canonical order"
        ),
        "unexpected sparse target proof error: {}",
        error.message
    );
}

fn target_decryption_message_encoding_columns_for_limb(
    statement: &TrusteeEvaluationKeyStatement,
    limb_index: usize,
) -> usize {
    statement
        .target_decryption_message_encoding_layouts(limb_index)
        .expect("target-decryption message layout")
        .into_iter()
        .map(|layout| layout.encoding_column_count())
        .sum()
}

#[test]
fn target_decryption_share_mask_bound_uses_lifted_aggregate_bound() {
    let instance = target_decryption_share_instance_parts();
    let target_statement = instance
        .statement
        .target_decryption_share
        .as_ref()
        .expect("target statement");
    let aggregate_message_coefficient_bound =
        i128::from(target_statement.aggregate_message_coefficient_bound);
    let largest_target_prime = target_statement
        .limb_statements
        .iter()
        .map(|limb_statement| i128::from(limb_statement.target_rns_prime))
        .max()
        .expect("target limb");
    assert!(
        aggregate_message_coefficient_bound > largest_target_prime,
        "fixture must exercise the lifted aggregate-message range"
    );

    let (claim_lower_bound, claim_upper_bound) =
        masked_claim_bounds_for_global_claim(&instance.statement, 0).expect("target mask bounds");
    let coefficient_bound = (1_i128 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    let aggregate_message_digit_bound =
        crate::bgv::setup::vss_commitment::vss_public_message_digit_bound(
            u64::try_from(aggregate_message_coefficient_bound)
                .expect("aggregate message bound fits u64"),
            0,
        )
        .expect("aggregate message digit bound")
        .saturating_sub(1);
    let expected_clear_claim_bound =
        i128::from(aggregate_message_digit_bound) * SMALL_RING_DEGREE as i128 * coefficient_bound;
    assert_eq!(
        claim_lower_bound,
        num_bigint::BigInt::from(-expected_clear_claim_bound)
    );
    assert_eq!(
        claim_upper_bound,
        num_bigint::BigInt::from(CLAIM_MASK_RADIX)
            .pow(TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT as u32)
            + num_bigint::BigInt::from(expected_clear_claim_bound)
    );

    let first_smudging_global_claim_id = (instance
        .statement
        .target_decryption_smudging_message_global_index()
        .expect("first smudging message")
        * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT
        * CONSISTENCY_REPETITIONS) as u64;
    let (smudging_lower_bound, smudging_upper_bound) =
        masked_claim_bounds_for_global_claim(&instance.statement, first_smudging_global_claim_id)
            .expect("target smudging message mask bounds");
    let expected_smudging_clear_claim_bound = i128::from(
        crate::bgv::setup::vss_commitment::vss_public_message_digit_bound(
            target_statement.smudging_message_coefficient_bound,
            0,
        )
        .expect("smudging message digit bound")
        .saturating_sub(1),
    ) * SMALL_RING_DEGREE as i128
        * coefficient_bound;
    assert_eq!(
        smudging_lower_bound,
        num_bigint::BigInt::from(-expected_smudging_clear_claim_bound)
    );
    assert_eq!(
        smudging_upper_bound,
        num_bigint::BigInt::from(CLAIM_MASK_RADIX)
            .pow(TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT as u32)
            + num_bigint::BigInt::from(expected_smudging_clear_claim_bound)
    );
}

fn target_decryption_share_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let instance = target_decryption_share_instance_parts();

    (instance.statement, instance.witness)
}

struct TargetDecryptionShareInstanceParts {
    statement: TrusteeEvaluationKeyStatement,
    witness: super::super::relation::TrusteeEvaluationKeyWitness,
    command_request: Value,
}

fn target_decryption_share_command_request() -> Value {
    target_decryption_share_instance_parts().command_request
}

fn target_decryption_share_verification_request(generate_request: &Value) -> Value {
    let mut verify_request = generate_request.clone();
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("targetDecryptionMessageVectors");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("vssCommittedMaterialSeedsByBoundMessage");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("vssCommittedMaterialContextHashesByBoundMessage");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("proofRandomnessSeedHex");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("proofRandomnessNonceHex");

    verify_request
}

fn target_decryption_share_instance_parts() -> TargetDecryptionShareInstanceParts {
    target_decryption_share_instance_parts_for_active_limb_count(5)
}

fn target_decryption_share_instance_parts_for_active_limb_count(
    active_limb_count: usize,
) -> TargetDecryptionShareInstanceParts {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("de");
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let largest_target_prime = DATA_PRIMES[..active_limb_count]
        .iter()
        .copied()
        .max()
        .expect("active target prime");
    let interpolation_point = 5_u64;
    let smudging_polynomial_degree = 3_usize;
    let smudging_coefficient_bound = 16_i64;
    let smudging_signed_coefficient_offset = smudging_coefficient_bound;
    let smudging_message_coefficient_bound =
        u64::try_from(smudging_coefficient_bound * 2 + 1).expect("message bound fits u64");
    let aggregate_message_coefficient_bound = largest_target_prime
        .checked_mul(2)
        .expect("aggregate message bound");
    let active_credential_binding_root = repeated_hash("70");
    let target_decryption_roles = ["targetId", "targetOrder"];
    let mut limb_statements = Vec::with_capacity(active_limb_count);
    let mut command_limb_statements = Vec::with_capacity(active_limb_count);
    let target_message_count_per_limb =
        1 + target_decryption_roles.len() * smudging_polynomial_degree;
    let mut target_decryption_message_vectors =
        Vec::with_capacity(active_limb_count * target_message_count_per_limb);
    // Committed-material regeneration inputs, one per bound commitment in the
    // same order as target_decryption_message_vectors (aggregate then smudging
    // per limb and role).
    let mut material_seeds_by_bound_message =
        Vec::with_capacity(active_limb_count * target_message_count_per_limb);
    let mut material_context_hashes_by_bound_message =
        Vec::with_capacity(active_limb_count * target_message_count_per_limb);
    let mut smudging_commitment_records = Vec::with_capacity(
        active_limb_count * target_decryption_roles.len() * smudging_polynomial_degree,
    );

    for (target_rns_limb_index, target_rns_prime) in DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .take(active_limb_count)
    {
        let aggregate_share_residues = (0..ring_degree)
            .map(|coefficient_index| {
                if coefficient_index % 17 == 0 {
                    target_rns_prime - 3
                } else {
                    (23 + 31 * coefficient_index as u64 + target_rns_limb_index as u64)
                        % target_rns_prime
                }
            })
            .collect::<Vec<_>>();
        let mut aggregate_commitment_messages = aggregate_share_residues.clone();
        aggregate_commitment_messages[0] = aggregate_commitment_messages[0]
            .checked_add(target_rns_prime)
            .expect("lifted aggregate commitment message");
        assert!(
            aggregate_commitment_messages[0] < aggregate_message_coefficient_bound,
            "target proof fixture must exercise a lifted aggregate commitment message"
        );
        let aggregate_commitment = commitment_for_target_decryption_test(
            "aggregate-threshold-share",
            json!({
                "testPurpose": "target-decryption-share-proof",
                "targetRnsLimbIndex": target_rns_limb_index,
                "shareRole": "aggregate",
            }),
            target_rns_limb_index,
            target_rns_prime,
            ring_degree,
            &aggregate_commitment_messages,
            aggregate_message_coefficient_bound,
        );

        let aggregate_opening_root = repeated_hash("78");
        let mut command_role_statements = Vec::with_capacity(target_decryption_roles.len());
        let mut role_statements = Vec::with_capacity(target_decryption_roles.len());

        material_seeds_by_bound_message.push(aggregate_commitment.material_seed_hex.clone());
        material_context_hashes_by_bound_message.push(aggregate_commitment.context_hash.clone());
        target_decryption_message_vectors.push(
            aggregate_commitment_messages
                .iter()
                .map(|coefficient| i64::try_from(*coefficient).expect("aggregate message fits i64"))
                .collect(),
        );

        for (target_role_index, target_role) in target_decryption_roles.iter().copied().enumerate()
        {
            let target_ciphertext_component_one = (0..ring_degree)
                .map(|coefficient_index| {
                    let role_offset = 13_u64 * target_role_index as u64;
                    if (coefficient_index + target_role_index) % 19 == 0 {
                        target_rns_prime - 5 - target_role_index as u64
                    } else {
                        (101 + role_offset
                            + 47 * coefficient_index as u64
                            + target_rns_limb_index as u64)
                            % target_rns_prime
                    }
                })
                .collect::<Vec<_>>();
            let smudging_signed_coefficients = (1..=smudging_polynomial_degree)
                .map(|polynomial_degree| {
                    smudging_signed_coefficients_for_degree(
                        ring_degree,
                        smudging_coefficient_bound,
                        polynomial_degree
                            + target_rns_limb_index
                            + target_role_index * smudging_polynomial_degree,
                    )
                })
                .collect::<Vec<_>>();
            let smudging_encoded_coefficients = smudging_signed_coefficients
                .iter()
                .map(|coefficients| {
                    coefficients
                        .iter()
                        .map(|coefficient| {
                            u64::try_from(*coefficient + smudging_signed_coefficient_offset)
                                .expect("encoded smudging coefficient")
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let released_partial_decryption = target_decryption_released_partial(
                &target_ciphertext_component_one,
                &aggregate_share_residues,
                &smudging_signed_coefficients,
                interpolation_point,
                PLAINTEXT_MODULUS,
                target_rns_prime,
            );
            let smudging_commitments = smudging_encoded_coefficients
                .iter()
                .enumerate()
                .map(|(polynomial_index, message_coefficients)| {
                    commitment_for_target_decryption_test(
                        "target-decryption-smudging-polynomial-coefficient",
                        json!({
                            "testPurpose": "target-decryption-share-proof",
                            "targetRnsLimbIndex": target_rns_limb_index,
                            "targetRole": target_role,
                            "polynomialDegree": polynomial_index + 1,
                        }),
                        target_rns_limb_index,
                        target_rns_prime,
                        ring_degree,
                        message_coefficients,
                        smudging_message_coefficient_bound,
                    )
                })
                .collect::<Vec<_>>();
            let smudging_commitment_roots = smudging_commitments
                .iter()
                .map(|commitment| commitment.commitment_root.clone())
                .collect::<Vec<_>>();
            smudging_commitment_records.extend(smudging_commitments.iter().enumerate().map(
                |(polynomial_index, commitment)| {
                    json!({
                        "objectType": "TargetDecryptionSmudgingCommitment",
                        "role": target_role,
                        "rnsLimbIndex": target_rns_limb_index,
                        "rnsPrime": target_rns_prime,
                        "polynomialDegree": polynomial_index + 1,
                        "commitmentRoot": commitment.commitment_root.clone(),
                        "commitment": commitment.commitment_value.clone(),
                    })
                },
            ));
            command_role_statements.push(json!({
                "targetRole": target_role,
                "targetCiphertextComponentOne": target_ciphertext_component_one.clone(),
                "releasedPartialDecryption": released_partial_decryption.clone(),
            }));
            role_statements.push(TargetDecryptionShareRoleStatement {
                target_role: target_role.to_string(),
                target_ciphertext_component_one: target_ciphertext_component_one.clone(),
                released_partial_decryption: released_partial_decryption.clone(),
                smudging_commitment_roots,
                smudging_commitments: smudging_commitments
                    .iter()
                    .map(|commitment| commitment.commitment.clone())
                    .collect(),
            });
            material_seeds_by_bound_message.extend(
                smudging_commitments
                    .iter()
                    .map(|commitment| commitment.material_seed_hex.clone()),
            );
            material_context_hashes_by_bound_message.extend(
                smudging_commitments
                    .iter()
                    .map(|commitment| commitment.context_hash.clone()),
            );
            target_decryption_message_vectors.extend(smudging_encoded_coefficients.iter().map(
                |coefficients| {
                    coefficients
                        .iter()
                        .map(|coefficient| {
                            i64::try_from(*coefficient)
                                .expect("encoded smudging coefficient fits i64")
                        })
                        .collect()
                },
            ));
        }
        command_limb_statements.push(json!({
            "targetRnsLimbIndex": target_rns_limb_index,
            "targetRnsPrime": target_rns_prime,
            "targetRoleStatements": command_role_statements,
            "aggregateCommitmentRoot": aggregate_commitment.commitment_root.clone(),
            "aggregateOpeningRoot": aggregate_opening_root.clone(),
            "aggregateCommitment": aggregate_commitment.commitment_value.clone(),
        }));
        limb_statements.push(TargetDecryptionShareLimbStatement {
            target_rns_limb_index,
            target_rns_prime,
            aggregate_commitment_root: aggregate_commitment.commitment_root.clone(),
            aggregate_opening_root,
            aggregate_commitment: aggregate_commitment.commitment.clone(),
            role_statements,
        });
    }

    let mut smudging_commitment_set = json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "targetBasisHash": target_basis_hash.clone(),
        "publicMatrixSeedHash": public_matrix_seed_hash.clone(),
        "activeRnsLimbCount": active_limb_count,
        "ringDegree": ring_degree,
        "smudgingCoefficientBound": smudging_coefficient_bound,
        "signedCoefficientOffset": smudging_signed_coefficient_offset,
        "messageCoefficientBound": smudging_message_coefficient_bound,
        "smudgingPolynomialDegree": smudging_polynomial_degree,
        "commitmentRole": "target-decryption-smudging-polynomial-coefficient",
        "commitmentRecords": smudging_commitment_records,
    });
    let smudging_commitment_set_root = derive_canonical_object_hash(&smudging_commitment_set)
        .expect("smudging commitment set root");
    smudging_commitment_set["smudgingCommitmentSetRoot"] =
        json!(smudging_commitment_set_root.clone());
    let target_share_proof_statement_root = repeated_hash("71");

    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: TARGET_DECRYPTION_SHARE_PROOF_FAMILY.to_string(),
            ceremony_id: "target-decryption-share-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![
                (
                    "targetShareProofStatementRoot".to_string(),
                    target_share_proof_statement_root.clone(),
                ),
                (
                    "activeCredentialBindingRoot".to_string(),
                    active_credential_binding_root.clone(),
                ),
                (
                    "smudgingCommitmentSetRoot".to_string(),
                    smudging_commitment_set_root.clone(),
                ),
            ],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        vss_share_linkage: None,
        same_secret_bridge: None,
        target_decryption_share: Some(TargetDecryptionShareStatement {
            public_matrix_seed_hash: public_matrix_seed_hash.clone(),
            target_basis_hash: target_basis_hash.clone(),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            active_credential_binding_root: active_credential_binding_root.clone(),
            interpolation_point,
            aggregate_message_coefficient_bound,
            smudging_commitment_set_root,
            limb_statements,
            smudging_polynomial_degree,
            smudging_coefficient_bound,
            smudging_signed_coefficient_offset,
            smudging_message_coefficient_bound,
            plaintext_multiple: PLAINTEXT_MODULUS,
        }),
    };
    statement
        .validate_shape()
        .expect("target-decryption share statement");

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors,
        target_decryption_opening_randomness_by_commitment: Vec::new(),
        vss_committed_material_seeds_by_bound_message: material_seeds_by_bound_message,
        vss_committed_material_context_hashes_by_bound_message:
            material_context_hashes_by_bound_message,
    };

    let command_request = json!({
        "context": {
            "ceremonyId": "target-decryption-share-proof-test",
            "manifestHash": repeated_hash("11"),
            "rosterHash": repeated_hash("22"),
            "trusteeIdentity": "trustee-0",
            "trusteeRosterPosition": 0,
            "setupEpoch": "setup-epoch-1",
            "targetShareProofStatementRoot": target_share_proof_statement_root.clone(),
            "activeCredentialBindingRoot": active_credential_binding_root.clone(),
            "smudgingCommitmentSetRoot": smudging_commitment_set["smudgingCommitmentSetRoot"].clone(),
        },
        "ringDegree": ring_degree,
        "targetDecryptionShare": {
            "targetShareProofStatementRoot": target_share_proof_statement_root,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": target_basis_hash,
            "trusteeIdentity": "trustee-0",
            "trusteeRosterPosition": 0,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "interpolationPoint": interpolation_point,
            "aggregateMessageCoefficientBound": aggregate_message_coefficient_bound,
            "targetRnsLimbStatements": command_limb_statements,
            "smudgingCommitmentSet": smudging_commitment_set,
            "plaintextMultiple": PLAINTEXT_MODULUS,
        },
        "targetDecryptionMessageVectors": witness.target_decryption_message_vectors.clone(),
        "vssCommittedMaterialSeedsByBoundMessage": witness.vss_committed_material_seeds_by_bound_message.clone(),
        "vssCommittedMaterialContextHashesByBoundMessage": witness.vss_committed_material_context_hashes_by_bound_message.clone(),
        "proofRandomnessSeedHex": PROOF_RANDOMNESS_SEED,
        "proofRandomnessNonceHex": PROOF_RANDOMNESS_NONCE,
    });

    TargetDecryptionShareInstanceParts {
        statement,
        witness,
        command_request,
    }
}

fn smudging_signed_coefficients_for_degree(
    ring_degree: usize,
    coefficient_bound: i64,
    polynomial_degree: usize,
) -> Vec<i64> {
    let span = coefficient_bound * 2 + 1;
    (0..ring_degree)
        .map(|coefficient_index| {
            ((coefficient_index as i64 * 7 + polynomial_degree as i64 * 11).rem_euclid(span))
                - coefficient_bound
        })
        .collect()
}

fn target_decryption_released_partial(
    target_ciphertext_component_one: &[u64],
    aggregate_share: &[u64],
    smudging_signed_coefficients: &[Vec<i64>],
    interpolation_point: u64,
    plaintext_multiple: u64,
    target_rns_prime: u64,
) -> Vec<u64> {
    let mut released_partial = negacyclic_mul(
        target_ciphertext_component_one,
        aggregate_share,
        target_rns_prime,
    )
    .expect("target aggregate multiplication");
    let mut interpolation_power = interpolation_point % target_rns_prime;
    for smudging_coefficients in smudging_signed_coefficients {
        let smudging_scale = mul_mod_fast(
            plaintext_multiple % target_rns_prime,
            interpolation_power,
            target_rns_prime,
        );
        for (partial_coefficient, smudging_coefficient) in released_partial
            .iter_mut()
            .zip(smudging_coefficients.iter())
        {
            let smudging_residue = signed_residue_for_test(*smudging_coefficient, target_rns_prime);
            let smudging_term = mul_mod_fast(smudging_scale, smudging_residue, target_rns_prime);
            *partial_coefficient =
                add_mod_fast(*partial_coefficient, smudging_term, target_rns_prime);
        }
        interpolation_power = mul_mod_fast(
            interpolation_power,
            interpolation_point % target_rns_prime,
            target_rns_prime,
        );
    }

    released_partial
}

fn signed_residue_for_test(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative value fits u64") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

struct CommitmentForTargetDecryptionTest {
    commitment_root: String,
    commitment_value: Value,
    commitment: VssShareLinkageCommitment,
    material_seed_hex: String,
    context_hash: String,
}

fn commitment_for_target_decryption_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    message_coefficient_bound: u64,
) -> CommitmentForTargetDecryptionTest {
    let material = test_committed_material_commitment(
        commitment_role,
        commitment_context.clone(),
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients,
        message_coefficient_bound,
    );
    // Rebuild the canonical commitment object (the transport/command records
    // carry it) by re-running the request path and taking its commitment body.
    let material_seed_hex = material.material_seed_hex.clone();
    let commitment_value =
        crate::bgv::setup::compute_vss_committed_material_commitment_request(&json!({
            "commitmentRole": commitment_role,
            "commitmentContext": commitment_context,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "ringDegree": ring_degree,
            "messageCoefficients": message_coefficients,
            "messageCoefficientBound": message_coefficient_bound,
            "materialSeedHex": material_seed_hex,
        }))
        .expect("committed-material commitment body")["commitment"]
            .clone();

    CommitmentForTargetDecryptionTest {
        commitment_root: material.commitment_root,
        commitment_value,
        commitment: material.commitment,
        material_seed_hex: material.material_seed_hex,
        context_hash: material.context_hash,
    }
}
