use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn public_rlwe_samples_by_basis(
    participant_count: usize,
    rotation_key_count: usize,
) -> Value {
    let q_data_bits = data_basis_modulus_bits();
    let q_extended_utility_bits = extended_basis_modulus_bits();

    json!({
        "QData": {
            "modulusBits": q_data_bits,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "relinearizationKeys": DATA_PRIMES.len() - 1,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QPPublic": {
            "modulusBits": q_extended_utility_bits,
            "relinearizationKeys": 0,
            "rotationKeys": 0,
            "keySwitchKeys": 0,
        },
        "QTarget": {
            "modulusBits": null,
        },
    })
}

pub(super) fn evaluation_key_streaming_commitment(
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitmentStream",
        "objectVersion": 1,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetHash": evaluation_keys["rotSetHash"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "evaluationKeyMaterialCommitmentHash": evaluation_keys["evaluationKeyMaterialCommitmentHash"],
        "evaluationKeyMaterialCommitment": evaluation_keys["evaluationKeyMaterialCommitment"],
        "serializationPolicy": "sealed-lattice-canonical-json-evaluation-key-material-commitment-stream",
    });
    let stream_bytes = canonical_json(&stream_record)?.into_bytes();
    let chunk_root_value = chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?;
    let commitment_record = json!({
        "objectType": "BgvEvaluationKeyStreamingCommitment",
        "objectVersion": 1,
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkSizeBytes": EVALUATION_KEY_CHUNK_SIZE_BYTES,
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
    });
    let commitment_hash = derive_canonical_object_hash(&commitment_record)?;

    Ok(json!({
        "commitment": commitment_record,
        "commitmentHash": commitment_hash,
    }))
}
