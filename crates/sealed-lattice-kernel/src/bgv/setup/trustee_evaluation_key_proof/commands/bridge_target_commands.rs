use super::decoding::*;
use super::request_parsing::*;
use super::target_decryption_parsing::*;
use super::*;

pub(crate) fn generate_same_secret_bridge_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = same_secret_bridge_statement_from_request(request)?;
    let witness = same_secret_bridge_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let bridge_statement = statement
        .same_secret_bridge
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("same-secret bridge statement missing"))?;

    let proof_bytes_hash = hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )?;
    crate::bgv::setup::retain_generated_canonical_proof_material(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_material_root.clone(),
        proof_bytes,
    )?;
    Ok(json!({
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "bridgeRnsLimbCount": bridge_statement.bridge_rns_primes.len(),
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

pub(crate) fn verify_same_secret_bridge_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<Value> {
    let statement = same_secret_bridge_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    Ok(json!({
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
    }))
}

#[derive(Debug)]
pub(crate) struct GeneratedTargetDecryptionShareProofBytes {
    pub(crate) target_roles: Vec<String>,
    pub(crate) target_rns_limb_indices: Vec<usize>,
    pub(crate) proof_bytes: Vec<u8>,
}

pub(crate) fn generate_target_decryption_share_proof_bytes_from_request(
    request: &Value,
) -> CanonicalResult<GeneratedTargetDecryptionShareProofBytes> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let witness = target_decryption_share_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let target_statement = statement
        .target_decryption_share
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("target-decryption share statement missing"))?;

    Ok(GeneratedTargetDecryptionShareProofBytes {
        target_roles: target_statement
            .limb_statements
            .first()
            .into_iter()
            .flat_map(|limb_statement| limb_statement.role_statements.iter())
            .map(|role_statement| role_statement.target_role.clone())
            .collect(),
        target_rns_limb_indices: target_statement
            .limb_statements
            .iter()
            .map(|limb_statement| limb_statement.target_rns_limb_index)
            .collect(),
        proof_bytes,
    })
}

#[cfg(test)]
pub(crate) fn verify_target_decryption_share_proof_bytes_from_request(
    request: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<Value> {
    verify_target_decryption_share_proof_source_from_request(request, proof_bytes)
}

pub(crate) fn verify_target_decryption_share_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<Value> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let target_statement = statement
        .target_decryption_share
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("target-decryption share statement missing"))?;

    let target_roles = target_statement
        .limb_statements
        .first()
        .into_iter()
        .flat_map(|limb_statement| limb_statement.role_statements.iter())
        .map(|role_statement| role_statement.target_role.clone())
        .collect::<Vec<_>>();
    let single_target_role = target_roles
        .first()
        .filter(|_| target_roles.len() == 1)
        .cloned();
    let target_rns_limb_indices = target_statement
        .limb_statements
        .iter()
        .map(|limb_statement| limb_statement.target_rns_limb_index)
        .collect::<Vec<_>>();
    let single_target_limb_index = target_rns_limb_indices
        .first()
        .filter(|_| target_rns_limb_indices.len() == 1)
        .copied();
    let mut response = json!({
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRoles": target_roles,
        "targetRnsLimbIndices": target_rns_limb_indices,
        "proofByteLength": proof_bytes.byte_length(),
    });
    if let Some(target_role) = single_target_role {
        response["targetRole"] = json!(target_role);
    }
    if let Some(target_rns_limb_index) = single_target_limb_index {
        response["targetRnsLimbIndex"] = json!(target_rns_limb_index);
    }

    Ok(response)
}
