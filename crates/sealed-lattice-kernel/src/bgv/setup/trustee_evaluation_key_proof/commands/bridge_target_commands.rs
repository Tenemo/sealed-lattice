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

    Ok(json!({
        "ok": true,
        "operation": "generateSameSecretBridgeProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRnsLimbCount": bridge_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

pub(crate) fn verify_same_secret_bridge_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = same_secret_bridge_statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let bridge_statement = statement
        .same_secret_bridge
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("same-secret bridge statement missing"))?;

    Ok(json!({
        "ok": true,
        "operation": "verifySameSecretBridgeProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRnsLimbCount": bridge_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
    }))
}

#[cfg(any(test, feature = "target-decryption-development-commands"))]
#[derive(Debug)]
pub(crate) struct GeneratedTargetDecryptionShareProofBytes {
    pub(crate) target_roles: Vec<String>,
    pub(crate) target_rns_limb_indices: Vec<usize>,
    pub(crate) proof_bytes: Vec<u8>,
}

#[cfg(any(test, feature = "target-decryption-development-commands"))]
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

pub(crate) fn verify_target_decryption_share_proof_bytes_from_request(
    request: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<Value> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof(&statement, proof_bytes)?;
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
        "ok": true,
        "operation": "verifyTargetDecryptionProofBytes",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRoles": target_roles,
        "targetRnsLimbIndices": target_rns_limb_indices,
        "proofByteLength": proof_bytes.len(),
    });
    if let Some(target_role) = single_target_role {
        response["targetRole"] = json!(target_role);
    }
    if let Some(target_rns_limb_index) = single_target_limb_index {
        response["targetRnsLimbIndex"] = json!(target_rns_limb_index);
    }

    Ok(response)
}
