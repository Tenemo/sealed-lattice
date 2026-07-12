mod evaluation_keys;

use self::evaluation_keys::{evaluation_key_streaming_commitment, public_rlwe_samples_by_basis};
use super::*;
use crate::bgv::evaluator::records::target_layout_hash;
use crate::hashing::derive_canonical_object_hash;

pub(super) fn setup_certificates(
    participant_count: usize,
    key_switch_decomposition: &Value,
    key_switch_decomposition_hash: &str,
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    let rotation_key_roots = evaluation_keys["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots use array");
    let rotation_key_count = rotation_key_roots.len();
    let public_samples = public_rlwe_samples_by_basis(participant_count, rotation_key_count);
    let evaluation_key_streaming_commitment = evaluation_key_streaming_commitment(evaluation_keys)?;

    Ok(json!({
        "keySwitchDecomposition": key_switch_decomposition,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicRlweSamplesByBasis": public_samples,
        "evaluationKeyStreamingCommitment": evaluation_key_streaming_commitment,
    }))
}

pub(super) fn key_switch_decomposition_parameters() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvKeySwitchDecompositionParameters",
        "digitBaseBits": 23,
        "digitCountPerPrime": 3,
    }))
}

// Identity of the target-decryption parameters: the bound BGV parameters hash
// and secret-share domain. Implementation maturity and the availability of the
// target secret relation remain public scope constraints; they are not asserted
// as self-attested bound fields.
pub(super) fn target_decryption_parameters(bgv_parameters_hash: &str) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "TargetDecryptionParameters",
        "bgvParametersHash": bgv_parameters_hash,
        "secretShareDomain": SECRET_SHARE_DOMAIN,
    }))
}

pub(super) fn passive_setup_evaluator_context_bindings(
    setup_inputs: &Value,
) -> CanonicalResult<Value> {
    let evaluator_binding_context = json!({
        "objectType": "PassiveSetupEvaluatorBindingContext",
        "ceremonyId": string_at_path(setup_inputs, &["ceremonyId"])?,
        "manifestHash": string_at_path(setup_inputs, &["manifestHash"])?,
        "rosterHash": string_at_path(setup_inputs, &["rosterHash"])?,
        "thresholdParametersHash": string_at_path(setup_inputs, &["thresholdParametersHash"])?,
        "participantCount": unsigned_at_path(setup_inputs, &["participantCount"])?,
        "setupSeedHash": string_at_path(setup_inputs, &["setupSeedHash"])?,
    });
    let evaluator_binding_context_hash = derive_canonical_object_hash(&evaluator_binding_context)?;
    let bgv_parameters_hash = bgv_parameters_hash()?;
    let comparison_input_derivation_record = json!({
        "objectType": "ComparisonInputDerivationCircuitBinding",
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison",
        "bgvParametersHash": &bgv_parameters_hash,
    });
    let encrypted_comparison_input_record = json!({
        "objectType": "EncryptedComparisonInputBinding",
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "selectedEvaluatorPath": "direct-encrypted-score-comparison",
        "comparisonInputDerivationCircuitHash": derive_canonical_object_hash(
            &comparison_input_derivation_record,
        )?,
        "bgvParametersHash": &bgv_parameters_hash,
    });
    let sparse_target_projection_record = json!({
        "objectType": "EncryptedSparseTargetProjectionBinding",
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "targetLayoutHash": target_layout_hash(MAXIMUM_OPTION_COUNT)?,
        "bgvParametersHash": &bgv_parameters_hash,
    });

    let comparison_input_derivation_circuit_hash =
        derive_canonical_object_hash(&comparison_input_derivation_record)?;
    let encrypted_comparison_input_hash =
        derive_canonical_object_hash(&encrypted_comparison_input_record)?;
    let encrypted_sparse_target_projection_hash =
        derive_canonical_object_hash(&sparse_target_projection_record)?;
    let binding_record = json!({
        "objectType": "PassiveSetupEvaluatorContextBinding",
        "evaluatorBindingContextHash": &evaluator_binding_context_hash,
        "bgvParametersHash": &bgv_parameters_hash,
        "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash,
        "encryptedComparisonInputHash": encrypted_comparison_input_hash,
        "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash,
        "targetLayoutHash": sparse_target_projection_record["targetLayoutHash"],
        "selectedEvaluatorPath": "direct-encrypted-score-comparison",
    });

    Ok(json!({
        "evaluatorBindingContextHash": binding_record["evaluatorBindingContextHash"],
        "bgvParametersHash": binding_record["bgvParametersHash"],
        "comparisonInputDerivationCircuitHash": binding_record["comparisonInputDerivationCircuitHash"],
        "encryptedComparisonInputHash": binding_record["encryptedComparisonInputHash"],
        "encryptedSparseTargetProjectionHash": binding_record["encryptedSparseTargetProjectionHash"],
        "targetLayoutHash": binding_record["targetLayoutHash"],
        "passiveSetupEvaluatorContextBindingHash": derive_canonical_object_hash(
            &binding_record,
        )?,
    }))
}

pub(super) fn public_common_random_polynomial_root(
    input: &PassiveSetupInput,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "setupSeedHash": input.setup_seed_hash,
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "sampledResidues": sample_public_residues(
            &input.setup_seed_hash,
            "public-common-random-polynomial",
            DATA_PRIMES[0],
        ),
    }))
}
