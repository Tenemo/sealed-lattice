use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn evaluation_key_streaming_commitment(
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitmentStream",
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
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
    });
    let commitment_hash = derive_canonical_object_hash(&commitment_record)?;

    Ok(json!({
        "commitment": commitment_record,
        "commitmentHash": commitment_hash,
    }))
}
