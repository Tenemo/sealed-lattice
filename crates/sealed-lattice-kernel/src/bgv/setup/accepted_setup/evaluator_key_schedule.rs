use super::*;

use super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;

pub(super) fn verify_pending_evaluation_key_material_boundary(
    setup_package: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let complete_share_record_containers = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(Value::as_object)
        .is_some_and(|rounds| !rounds.is_empty())
        && setup_package
            .get("galoisKeyShareBatches")
            .and_then(Value::as_array)
            .is_some_and(|batches| !batches.is_empty());
    if !complete_share_record_containers
        && let Some(response) = verify_trustee_evaluation_key_proofs(
            setup_package,
            verified_same_secret_bridge,
            proof_binding_session,
        )?
    {
        return Ok(Some(response));
    }
    if let Some(response) =
        verify_relinearization_key_share_rounds(setup_package, trustee_registrations)?
    {
        return Ok(Some(response));
    }
    if let Some(response) = verify_galois_key_share_batches(setup_package, trustee_registrations)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_trustee_evaluation_key_proofs(
        setup_package,
        verified_same_secret_bridge,
        proof_binding_session,
    )? {
        return Ok(Some(response));
    }

    Ok(None)
}
