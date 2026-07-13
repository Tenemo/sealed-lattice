use super::public_key_reconstruction::*;
use super::*;

pub(in super::super) fn verify_evaluation_key_share_component_material_transport(
    setup_package: &Value,
    request: &Value,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Option<Refusals>> {
    let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") else {
        return Ok(Some(setup_refusals(
            vec!["transportedEvaluationKeyShareComponentMaterial".to_string()],
            Vec::new(),
        )));
    };
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyComponentMaterialTransportHeaderMismatch",
            "transportedEvaluationKeyShareComponentMaterial must be an evaluation-key component material transport set",
            "transportedEvaluationKeyShareComponentMaterial",
        )?));
    }
    if let Err(error) = accepted_setup_public_relinearization_keys_from_transport(
        setup_package,
        request,
        accepted_setup_session,
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(error)?));
    }
    if let Err(error) = accepted_setup_public_galois_keys_from_transport(
        setup_package,
        request,
        accepted_setup_session,
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(error)?));
    }

    Ok(None)
}

fn evaluation_key_material_verification_failure(
    error: CanonicalError,
) -> CanonicalResult<Refusals> {
    evaluation_key_material_refusal(
        "evaluationKeyMaterialVerificationFailed",
        error.message,
        "transportedEvaluationKeyShareComponentMaterial.componentMaterials",
    )
}
