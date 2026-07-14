use super::*;

pub(super) fn evaluation_key_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    ))
}
