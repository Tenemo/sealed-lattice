use super::*;

use super::super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;

// A setup package proves its trustees committed one short secret through the
// same-secret bridge over the target key-switch basis, which the verifier checks
// upstream. The bridge subsumes the per-trustee same-secret linkage anchors, so
// this phase only requires that the bridge material verified before the
// same-secret anchors are considered satisfied.
pub(in super::super) fn verify_optional_same_secret_proofs(
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
) -> CanonicalResult<Option<Value>> {
    if verified_same_secret_bridge.is_some() {
        return Ok(None);
    }
    Ok(Some(same_secret_proof_refusal(
        "sameSecretAnchorRebindingRequired",
        "setup packages require verified same-secret bridge proof material before the same-secret anchors are satisfied",
        "setupPackage.sameSecretBridgeProofMaterialSet",
    )?))
}
