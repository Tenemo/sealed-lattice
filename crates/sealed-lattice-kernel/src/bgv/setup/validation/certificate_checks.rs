use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn validate_setup_certificates(setup_package: &Value) -> CanonicalResult<()> {
    let certificates = value_at_path(setup_package, &["certificates"])?;
    compare_derived_hash(
        value_at_path(certificates, &["keySwitchDecomposition"])?,
        hash_at_path(certificates, &["keySwitchDecompositionHash"])?,
        "key-switch decomposition hash",
    )?;
    validate_evaluation_key_streaming_commitment(certificates)?;
    Ok(())
}

fn validate_evaluation_key_streaming_commitment(certificates: &Value) -> CanonicalResult<String> {
    let wrapped_commitment = value_at_path(certificates, &["evaluationKeyStreamingCommitment"])?;
    let commitment_record = value_at_path(wrapped_commitment, &["commitment"])?;
    compare_string_at_path(
        commitment_record,
        &["objectType"],
        "BgvEvaluationKeyStreamingCommitment",
        "evaluation key streaming commitment object type",
    )?;
    if usize_at_path(commitment_record, &["chunkSizeBytes"])? != EVALUATION_KEY_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "evaluation key streaming commitment chunk size changed",
        ));
    }
    let stream_record = value_at_path(commitment_record, &["streamRecord"])?;
    let stream_bytes = canonical_json(stream_record)?.into_bytes();
    if usize_at_path(commitment_record, &["canonicalStreamByteLength"])? != stream_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation key streaming commitment byte length does not match its stream record",
        ));
    }
    compare_hash_at_path(
        commitment_record,
        &["chunkRoot"],
        &chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?,
        "evaluation key streaming commitment chunk root",
    )?;
    let commitment_hash = derive_canonical_object_hash(commitment_record)?;
    compare_hash_at_path(
        wrapped_commitment,
        &["commitmentHash"],
        &commitment_hash,
        "evaluation key streaming commitment hash",
    )?;

    Ok(commitment_hash)
}
