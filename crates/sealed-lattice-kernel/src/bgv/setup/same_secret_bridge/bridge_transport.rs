use super::*;

use crate::bgv::setup::setup_proof::take_verified_setup_proof_material_bytes;

#[derive(Debug)]
pub(super) struct ValidatedSameSecretBridgeProofReference {
    pub(super) proof_bytes_hash: String,
}

pub(super) fn validate_same_secret_bridge_proof_reference(
    proof_bytes_hash: &str,
) -> CanonicalResult<ValidatedSameSecretBridgeProofReference> {
    validate_hash_string(proof_bytes_hash, "same-secret bridge proofBytesHashes")?;
    Ok(ValidatedSameSecretBridgeProofReference {
        proof_bytes_hash: proof_bytes_hash.to_string(),
    })
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    reference: ValidatedSameSecretBridgeProofReference,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_bytes = take_verified_setup_proof_material_bytes(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &reference.proof_bytes_hash,
        "same-secret bridge proofBytesHash",
        proof_binding_session,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        &reference.proof_bytes_hash,
        &proof_bytes_hash,
        "same-secret bridge proof record proofBytesHash",
    )?;
    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_proof_reference_reads_the_proof_bytes_hash() {
        let proof_bytes_hash = "3".repeat(128);
        let validated = validate_same_secret_bridge_proof_reference(&proof_bytes_hash)
            .expect("same-secret bridge proof reference is accepted");
        assert_eq!(validated.proof_bytes_hash, proof_bytes_hash);
    }
}
