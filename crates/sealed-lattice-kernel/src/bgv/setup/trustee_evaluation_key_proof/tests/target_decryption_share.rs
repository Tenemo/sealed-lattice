use super::*;
use crate::bgv::evaluator::engine::negacyclic_mul;
use crate::bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast};
use crate::bgv::profile::PLAINTEXT_MODULUS;
use crate::bgv::setup::compact_vss_commitment::{
    CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
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
    target_decryption_share.released_partial_decryption[0] =
        (target_decryption_share.released_partial_decryption[0] + 1)
            % target_decryption_share.target_rns_prime;
    assert!(
        verify_evaluation_key_share(&tampered_partial_statement, &proof).is_err(),
        "tampering with the released partial must reject"
    );

    let (mut tampered_commitment_statement, _unused_witness) = target_decryption_share_instance();
    let target_decryption_share = tampered_commitment_statement
        .target_decryption_share
        .as_mut()
        .expect("target statement");
    let first_commitment_modulus = DATA_PRIMES[0];
    target_decryption_share
        .aggregate_commitment
        .coordinates_by_commitment_modulus[0][0] = (target_decryption_share
        .aggregate_commitment
        .coordinates_by_commitment_modulus[0][0]
        + 1)
        % first_commitment_modulus;
    assert!(
        verify_evaluation_key_share(&tampered_commitment_statement, &proof).is_err(),
        "tampering with a public aggregate commitment coordinate must reject"
    );

    let (invalid_aggregate_statement, mut invalid_aggregate_witness) =
        target_decryption_share_instance();
    let target_prime = invalid_aggregate_statement
        .target_decryption_share
        .as_ref()
        .expect("target statement")
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

    let (non_ternary_statement, mut non_ternary_witness) = target_decryption_share_instance();
    non_ternary_witness.target_decryption_opening_randomness_by_commitment[1][0][3] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_ternary_statement,
            &non_ternary_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject non-ternary target-decryption opening randomness"
    );
}

#[test]
fn target_decryption_share_proof_command_round_trips_and_rejects_tampering() {
    let generate_request = target_decryption_share_command_request();
    let generated = super::generate_target_decryption_share_proof_from_request(&generate_request)
        .expect("generate target-decryption share proof command");
    assert_eq!(generated["ok"], true);
    assert_eq!(
        generated["operation"],
        json!("generateTargetDecryptionShareProof")
    );
    assert_eq!(generated["proofFamily"], json!("target-decryption-share"));
    assert_eq!(generated["targetRole"], json!("targetId"));
    assert_eq!(generated["targetRnsLimbIndex"], json!(3));

    let verify_request = target_decryption_share_verify_request(
        &generate_request,
        generated["proofBytesHex"].as_str().expect("proof bytes"),
    );
    let verified = super::verify_target_decryption_share_proof_from_request(&verify_request)
        .expect("verify target-decryption share proof command");
    assert_eq!(verified["ok"], true);
    assert_eq!(
        verified["operation"],
        json!("verifyTargetDecryptionShareProof")
    );
    assert_eq!(verified["statementHash"], generated["statementHash"]);

    let mut tampered_proof_request = verify_request.clone();
    let mut tampered_proof_hex = tampered_proof_request["proofBytesHex"]
        .as_str()
        .expect("proof hex")
        .to_string();
    let flip_position = tampered_proof_hex.len() / 2;
    let original = tampered_proof_hex.as_bytes()[flip_position];
    let replacement = if original == b'0' { '1' } else { '0' };
    tampered_proof_hex.replace_range(flip_position..flip_position + 1, &replacement.to_string());
    tampered_proof_request["proofBytesHex"] = json!(tampered_proof_hex);
    assert!(
        super::verify_target_decryption_share_proof_from_request(&tampered_proof_request).is_err(),
        "tampered target-decryption proof bytes must reject"
    );

    let mut tampered_aggregate_commitment_request = verify_request.clone();
    tampered_aggregate_commitment_request["targetDecryptionShare"]["aggregateCommitment"]["commitmentLimbs"]
        [0]["coordinates"][0] = json!(0);
    assert!(
        super::verify_target_decryption_share_proof_from_request(
            &tampered_aggregate_commitment_request
        )
        .is_err(),
        "tampering with the aggregate commitment object must reject before proof verification"
    );

    let mut tampered_partial_request = verify_request.clone();
    let target_prime = tampered_partial_request["targetDecryptionShare"]["targetRnsPrime"]
        .as_u64()
        .expect("target prime");
    let first_partial =
        tampered_partial_request["targetDecryptionShare"]["releasedPartialDecryption"][0]
            .as_u64()
            .expect("released partial");
    tampered_partial_request["targetDecryptionShare"]["releasedPartialDecryption"][0] =
        json!((first_partial + 1) % target_prime);
    assert!(
        super::verify_target_decryption_share_proof_from_request(&tampered_partial_request)
            .is_err(),
        "tampering with the released partial must reject proof verification"
    );

    let mut tampered_smudging_set_request = verify_request;
    tampered_smudging_set_request["targetDecryptionShare"]["smudgingCommitmentSet"]["smudgingCoefficientBound"] =
        json!(15);
    assert!(
        super::verify_target_decryption_share_proof_from_request(&tampered_smudging_set_request)
            .is_err(),
        "tampering with the smudging commitment set payload must reject its root"
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

fn target_decryption_share_verify_request(
    generate_request: &Value,
    proof_bytes_hex: &str,
) -> Value {
    let mut verify_request = generate_request.clone();
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("targetDecryptionMessageVectors");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("targetDecryptionOpeningRandomnessByCommitment");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("proofRandomnessSource");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("proofRandomnessSeedHex");
    verify_request
        .as_object_mut()
        .expect("target proof command request")
        .remove("proofRandomnessNonceHex");
    verify_request["proofBytesHex"] = json!(proof_bytes_hex);

    verify_request
}

fn target_decryption_share_instance_parts() -> TargetDecryptionShareInstanceParts {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("de");
    let target_basis_hash = repeated_hash("df");
    let target_rns_limb_index = 3_usize;
    let target_rns_prime = DATA_PRIMES[target_rns_limb_index];
    let interpolation_point = 5_u64;
    let smudging_polynomial_degree = 3_usize;
    let smudging_coefficient_bound = 16_i64;
    let smudging_signed_coefficient_offset = smudging_coefficient_bound;
    let smudging_message_coefficient_bound =
        u64::try_from(smudging_coefficient_bound * 2 + 1).expect("message bound fits u64");

    let aggregate_share_residues = (0..ring_degree)
        .map(|coefficient_index| {
            if coefficient_index % 17 == 0 {
                target_rns_prime - 3
            } else {
                (23 + 31 * coefficient_index as u64) % target_rns_prime
            }
        })
        .collect::<Vec<_>>();
    let aggregate_message_coefficient_bound = target_rns_prime
        .checked_mul(2)
        .expect("aggregate message bound");
    let mut aggregate_commitment_messages = aggregate_share_residues.clone();
    aggregate_commitment_messages[0] = aggregate_commitment_messages[0]
        .checked_add(target_rns_prime)
        .expect("lifted aggregate commitment message");
    assert!(
        aggregate_commitment_messages[0] < aggregate_message_coefficient_bound,
        "target proof fixture must exercise a lifted aggregate commitment message"
    );
    let target_ciphertext_component_one = (0..ring_degree)
        .map(|coefficient_index| {
            if coefficient_index % 19 == 0 {
                target_rns_prime - 5
            } else {
                (101 + 47 * coefficient_index as u64) % target_rns_prime
            }
        })
        .collect::<Vec<_>>();

    let smudging_signed_coefficients = (1..=smudging_polynomial_degree)
        .map(|polynomial_degree| {
            smudging_signed_coefficients_for_degree(
                ring_degree,
                smudging_coefficient_bound,
                polynomial_degree,
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

    let aggregate_randomness = target_decryption_ternary_randomness_columns(ring_degree, 23);
    let aggregate_commitment = compact_commitment_for_target_decryption_test(
        "aggregate-threshold-share",
        json!({
            "testPurpose": "target-decryption-share-proof",
            "targetRnsLimbIndex": target_rns_limb_index,
            "shareRole": "aggregate",
        }),
        &public_matrix_seed_hash,
        target_rns_limb_index,
        target_rns_prime,
        ring_degree,
        &aggregate_commitment_messages,
        aggregate_message_coefficient_bound,
        &aggregate_randomness,
    );

    let smudging_randomness_by_degree = (1..=smudging_polynomial_degree)
        .map(|polynomial_degree| {
            target_decryption_ternary_randomness_columns(
                ring_degree,
                41 + polynomial_degree as i64 * 17,
            )
        })
        .collect::<Vec<_>>();
    let smudging_commitments = smudging_encoded_coefficients
        .iter()
        .zip(smudging_randomness_by_degree.iter())
        .enumerate()
        .map(
            |(polynomial_index, (message_coefficients, randomness_by_column))| {
                compact_commitment_for_target_decryption_test(
                    "target-decryption-smudging-polynomial-coefficient",
                    json!({
                        "testPurpose": "target-decryption-share-proof",
                        "targetRnsLimbIndex": target_rns_limb_index,
                        "targetRole": "targetId",
                        "polynomialDegree": polynomial_index + 1,
                    }),
                    &public_matrix_seed_hash,
                    target_rns_limb_index,
                    target_rns_prime,
                    ring_degree,
                    message_coefficients,
                    smudging_message_coefficient_bound,
                    randomness_by_column,
                )
            },
        )
        .collect::<Vec<_>>();
    let smudging_commitment_roots = smudging_commitments
        .iter()
        .map(|commitment| commitment.commitment_root.clone())
        .collect::<Vec<_>>();
    let smudging_commitment_records = smudging_commitments
        .iter()
        .enumerate()
        .map(|(polynomial_index, commitment)| {
            json!({
                "objectType": "TargetDecryptionSmudgingCommitment",
                "objectVersion": 1,
                "role": "targetId",
                "rnsLimbIndex": target_rns_limb_index,
                "rnsPrime": target_rns_prime,
                "polynomialDegree": polynomial_index + 1,
                "commitmentRoot": commitment.commitment_root.clone(),
                "commitment": commitment.commitment_value.clone(),
            })
        })
        .collect::<Vec<_>>();
    let mut smudging_commitment_set = json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "objectVersion": 1,
        "targetBasisHash": target_basis_hash.clone(),
        "publicMatrixSeedHash": public_matrix_seed_hash.clone(),
        "activeRnsLimbCount": target_rns_limb_index + 1,
        "ringDegree": ring_degree,
        "smudgingCoefficientBound": smudging_coefficient_bound,
        "signedCoefficientOffset": smudging_signed_coefficient_offset,
        "messageCoefficientBound": smudging_message_coefficient_bound,
        "smudgingPolynomialDegree": smudging_polynomial_degree,
        "commitmentRole": "target-decryption-smudging-polynomial-coefficient",
        "commitmentRecords": smudging_commitment_records,
    });
    let smudging_commitment_set_root = derive_protocol_hash(
        "TargetDecryptionSmudgingCommitmentSetRoot",
        &smudging_commitment_set,
    )
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
                    "aggregateCommitmentRoot".to_string(),
                    aggregate_commitment.commitment_root.clone(),
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
        compact_vss_share_linkage: None,
        compact_same_secret_bridge: None,
        target_decryption_share: Some(TargetDecryptionShareStatement {
            public_matrix_seed_hash: public_matrix_seed_hash.clone(),
            target_basis_hash: target_basis_hash.clone(),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            target_role: "targetId".to_string(),
            target_rns_limb_index,
            target_rns_prime,
            interpolation_point,
            target_ciphertext_component_one: target_ciphertext_component_one.clone(),
            released_partial_decryption: released_partial_decryption.clone(),
            aggregate_commitment_root: aggregate_commitment.commitment_root.clone(),
            aggregate_commitment: aggregate_commitment.commitment.clone(),
            aggregate_message_coefficient_bound,
            smudging_commitment_set_root,
            smudging_commitment_roots,
            smudging_commitments: smudging_commitments
                .iter()
                .map(|commitment| commitment.commitment.clone())
                .collect(),
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

    let mut target_decryption_opening_randomness_by_commitment = Vec::new();
    target_decryption_opening_randomness_by_commitment.push(aggregate_randomness);
    target_decryption_opening_randomness_by_commitment.extend(smudging_randomness_by_degree);
    let mut target_decryption_message_vectors = Vec::new();
    target_decryption_message_vectors.push(
        aggregate_commitment_messages
            .iter()
            .map(|coefficient| i64::try_from(*coefficient).expect("aggregate message fits i64"))
            .collect(),
    );
    target_decryption_message_vectors.extend(smudging_encoded_coefficients.iter().map(
        |coefficients| {
            coefficients
                .iter()
                .map(|coefficient| {
                    i64::try_from(*coefficient).expect("encoded smudging coefficient fits i64")
                })
                .collect()
        },
    ));

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_messages: Vec::new(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_opening_randomness: Vec::new(),
        compact_vss_carry_witnesses: Vec::new(),
        target_decryption_message_vectors,
        target_decryption_opening_randomness_by_commitment,
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
            "aggregateCommitmentRoot": aggregate_commitment.commitment_root.clone(),
            "smudgingCommitmentSetRoot": smudging_commitment_set["smudgingCommitmentSetRoot"].clone(),
        },
        "ringDegree": ring_degree,
        "targetDecryptionShare": {
            "targetShareProofStatementRoot": target_share_proof_statement_root,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": target_basis_hash,
            "trusteeIdentity": "trustee-0",
            "trusteeRosterPosition": 0,
            "targetRole": "targetId",
            "targetRnsLimbIndex": target_rns_limb_index,
            "targetRnsPrime": target_rns_prime,
            "interpolationPoint": interpolation_point,
            "targetCiphertextComponentOne": target_ciphertext_component_one,
            "releasedPartialDecryption": released_partial_decryption,
            "aggregateCommitmentRoot": aggregate_commitment.commitment_root.clone(),
            "aggregateCommitment": aggregate_commitment.commitment_value,
            "aggregateMessageCoefficientBound": aggregate_message_coefficient_bound,
            "smudgingCommitmentSet": smudging_commitment_set,
            "plaintextMultiple": PLAINTEXT_MODULUS,
        },
        "targetDecryptionMessageVectors": witness.target_decryption_message_vectors.clone(),
        "targetDecryptionOpeningRandomnessByCommitment": witness
            .target_decryption_opening_randomness_by_commitment
            .clone(),
        "proofRandomnessSource": "development-deterministic-fixture",
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

fn target_decryption_ternary_randomness_columns(
    ring_degree: usize,
    seed_offset: i64,
) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    ((seed_offset + column_index as i64 * 13 + coefficient_index as i64 * 17)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}

struct CompactCommitmentForTargetDecryptionTest {
    commitment_root: String,
    commitment_value: Value,
    commitment: CompactVssShareLinkageCommitment,
}

#[allow(clippy::too_many_arguments)]
fn compact_commitment_for_target_decryption_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    message_coefficient_bound: u64,
    randomness_by_column: &[Vec<i64>],
) -> CompactCommitmentForTargetDecryptionTest {
    let computation =
        compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
            commitment_role,
            commitment_context: &commitment_context,
            public_matrix_seed_hash,
            rns_limb_index,
            rns_prime,
            ring_degree,
            message_coefficients,
            message_coefficient_bound,
            randomness_by_column,
        })
        .expect("compact target-decryption commitment");

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

    CompactCommitmentForTargetDecryptionTest {
        commitment_root: computation.commitment_root,
        commitment_value: computation.commitment,
        commitment: CompactVssShareLinkageCommitment {
            coordinates_by_commitment_modulus,
        },
    }
}
