use super::*;

pub(crate) fn verify_target_decryption_result_from_request(
    _request: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "ok": false,
        "operation": "verifyTargetDecryptionResult",
        "refusalReason": "CompactVssPublicMaterialNotBinding",
    }))
}
