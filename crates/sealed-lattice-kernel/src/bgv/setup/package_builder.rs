use super::*;
use super::{
    certificates::{
        key_switch_decomposition_parameters, passive_setup_evaluator_context_bindings,
        public_common_random_polynomial_root, setup_certificates, target_decryption_parameters,
    },
    key_material::{collective_public_key, evaluation_keys, threshold_verification_material},
    participant_material::participant_setup_material,
};
use crate::hashing::derive_canonical_object_hash;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

pub(super) fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
    let bgv_parameters_hash = bgv_parameters_hash()?;
    let key_switch_decomposition = key_switch_decomposition_parameters()?;
    let key_switch_decomposition_hash = derive_canonical_object_hash(&key_switch_decomposition)?;
    let target_decryption_parameters = target_decryption_parameters(&bgv_parameters_hash)?;
    let target_decryption_parameters_hash =
        derive_canonical_object_hash(&target_decryption_parameters)?;
    let target_decryption_parameters_binding_hash = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionParametersBinding",
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
    }))?;
    let public_common_random_polynomial_root = public_common_random_polynomial_root(input)?;
    #[cfg(not(target_arch = "wasm32"))]
    let participant_material = input
        .participants
        .par_iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &bgv_parameters_hash,
                &public_common_random_polynomial_root,
                &target_decryption_parameters_hash,
                &target_decryption_parameters_binding_hash,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let participant_material = input
        .participants
        .iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &bgv_parameters_hash,
                &public_common_random_polynomial_root,
                &target_decryption_parameters_hash,
                &target_decryption_parameters_binding_hash,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let participant_records = participant_material
        .iter()
        .map(|material| material.participant_record.clone())
        .collect::<Vec<_>>();
    let public_key_share_roots = participant_material
        .iter()
        .map(|material| material.public_key_share_root.clone())
        .collect::<Vec<_>>();
    let participant_setup_record_hashes = participant_material
        .iter()
        .map(|material| material.participant_setup_record_hash.clone())
        .collect::<Vec<_>>();
    let trustee_threshold_verification_key_hashes = participant_material
        .iter()
        .map(|material| material.trustee_threshold_verification_key_hash.clone())
        .collect::<Vec<_>>();
    let collective_public_key = collective_public_key(
        input,
        &bgv_parameters_hash,
        &public_common_random_polynomial_root,
        &public_key_share_roots,
    )?;
    let threshold_verification_material = threshold_verification_material(
        input,
        &target_decryption_parameters_hash,
        &target_decryption_parameters_binding_hash,
        &participant_setup_record_hashes,
        &trustee_threshold_verification_key_hashes,
    )?;
    let evaluation_keys = evaluation_keys(
        input,
        &collective_public_key,
        &key_switch_decomposition_hash,
    )?;
    let setup_inputs = json!({
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "thresholdParametersHash": input.threshold_parameters_hash,
        "participantCount": input.participants.len(),
        "participantIdentities": input.participants.iter().map(|participant| participant.trustee_identity.clone()).collect::<Vec<_>>(),
        "defaultSetupSeedUsed": !input.setup_seed_provided,
        "setupSeedHash": input.setup_seed_hash,
    });
    let certificates = setup_certificates(
        input.participants.len(),
        &key_switch_decomposition,
        &key_switch_decomposition_hash,
        &evaluation_keys,
    )?;
    let evaluator_context_bindings = passive_setup_evaluator_context_bindings(&setup_inputs)?;

    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "setupMode": "passive-full-roster-development",
        "setupInputs": setup_inputs,
        "parameterBindings": {
            "bgvParametersHash": bgv_parameters_hash,
            "evaluatorBindingContextHash": evaluator_context_bindings["evaluatorBindingContextHash"],
            "comparisonInputDerivationCircuitHash": evaluator_context_bindings["comparisonInputDerivationCircuitHash"],
            "encryptedComparisonInputHash": evaluator_context_bindings["encryptedComparisonInputHash"],
            "encryptedSparseTargetProjectionHash": evaluator_context_bindings["encryptedSparseTargetProjectionHash"],
            "targetLayoutHash": evaluator_context_bindings["targetLayoutHash"],
            "passiveSetupEvaluatorContextBindingHash": evaluator_context_bindings["passiveSetupEvaluatorContextBindingHash"],
        },
        "participants": participant_records,
        "collectivePublicKey": collective_public_key,
        "thresholdVerificationMaterial": threshold_verification_material,
        "evaluationKeys": evaluation_keys,
        "certificates": certificates,
        "targetDecryptionStatus": {
            "targetDecryptionParametersHash": target_decryption_parameters_hash,
            "targetDecryptionParametersBindingHash": target_decryption_parameters_binding_hash,
        },
    });
    let setup_package_hash = derive_canonical_object_hash(&package)?;
    package["setupPackageHash"] = Value::String(setup_package_hash);

    Ok(package)
}
