use super::*;

mod material_transport;
mod public_key_reconstruction;

pub(super) use material_transport::verify_evaluation_key_share_component_material_transport;

pub(super) fn evaluation_key_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
