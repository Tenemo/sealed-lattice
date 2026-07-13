use super::*;

mod expected_roots;
mod manifest;
mod material_transport;
mod public_key_reconstruction;
mod set_verification;

pub(super) use material_transport::transported_evaluation_key_share_component_material_from_request;
pub(super) use set_verification::{
    verify_public_evaluation_key_set, verify_required_public_evaluation_key_set,
};

#[derive(Debug, Clone)]
struct PublicEvaluationKeyMaterialTransportHashes {
    full_object_hash: String,
    total_byte_length: u64,
}

pub(super) fn evaluation_key_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("relinearizationRoundOne"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
