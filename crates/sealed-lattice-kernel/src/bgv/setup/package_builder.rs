use super::*;
use super::{
    key_material::{collective_public_key, evaluation_keys, threshold_verification_material},
    parameters::target_decryption_parameters,
    participant_material::participant_setup_material,
};
use crate::hashing::derive_canonical_object_hash;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

pub(super) fn build_passive_setup_package(input: &PassiveSetupInput) -> CanonicalResult<Value> {
    let bgv_parameters_hash = bgv_parameters_hash()?;
    let target_decryption_parameters = target_decryption_parameters(&bgv_parameters_hash)?;
    let target_decryption_parameters_hash =
        derive_canonical_object_hash(&target_decryption_parameters)?;
    #[cfg(not(target_arch = "wasm32"))]
    let participant_material = input
        .participants
        .par_iter()
        .map(|participant| {
            participant_setup_material(
                input,
                participant,
                &bgv_parameters_hash,
                &target_decryption_parameters_hash,
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
                &target_decryption_parameters_hash,
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
    let collective_public_key =
        collective_public_key(input, &bgv_parameters_hash, &public_key_share_roots)?;
    let threshold_verification_material = threshold_verification_material(
        input,
        &target_decryption_parameters_hash,
        &participant_setup_record_hashes,
        &trustee_threshold_verification_key_hashes,
    )?;
    let evaluation_keys = evaluation_keys(input, &collective_public_key)?;
    let setup_inputs = json!({
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "thresholdParametersHash": input.threshold_parameters_hash,
        "setupSeedHash": input.setup_seed_hash,
    });
    let mut package = json!({
        "objectType": "BgvPassiveSetupPackage",
        "setupInputs": setup_inputs,
        "bgvParametersHash": bgv_parameters_hash,
        "participants": participant_records,
        "collectivePublicKey": collective_public_key,
        "thresholdVerificationMaterial": threshold_verification_material,
        "evaluationKeys": evaluation_keys,
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
    });
    let setup_package_hash = derive_canonical_object_hash(&package)?;
    package["setupPackageHash"] = Value::String(setup_package_hash);

    Ok(package)
}
