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
        "statementHash": to_hex(&statement.statement_hash()),
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

pub(crate) fn verify_same_secret_bridge_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    let statement = same_secret_bridge_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)
}

pub(crate) fn generate_target_decryption_share_proof_bytes_from_request(
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
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
    Ok(encode_trustee_evaluation_key_proof(&proof))
}

#[cfg(test)]
pub(crate) fn verify_target_decryption_share_proof_bytes_from_request(
    request: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    verify_target_decryption_share_proof_source_from_request(request, proof_bytes)
}

pub(crate) fn verify_target_decryption_share_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)
}
