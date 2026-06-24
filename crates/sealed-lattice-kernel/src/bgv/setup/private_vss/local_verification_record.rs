use super::*;

pub(super) fn local_verification_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    envelope_binding: &PrivateEnvelopeBinding,
    ring_degree: usize,
    ring_degree_status: &str,
    limb_verifications: &[LimbVerification],
) -> CanonicalResult<Value> {
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    Ok(json!({
        "objectType": "PrivateVssLocalVerification",
        "objectVersion": 1,
        "ceremonyId": string_field(
            setup_context,
            "ceremonyId",
            "setupContext.ceremonyId",
            "setupContextCeremonyMissing",
            "setupContext.ceremonyId is required",
        ).map_err(refusal_to_error)?,
        "manifestHash": string_field(
            setup_context,
            "manifestHash",
            "setupContext.manifestHash",
            "setupContextHashMissing",
            "setupContext.manifestHash is required",
        ).map_err(refusal_to_error)?,
        "rosterHash": string_field(
            setup_context,
            "rosterHash",
            "setupContext.rosterHash",
            "setupContextHashMissing",
            "setupContext.rosterHash is required",
        ).map_err(refusal_to_error)?,
        "setupParametersHash": string_field(
            setup_context,
            "setupParametersHash",
            "setupContext.setupParametersHash",
            "setupContextHashMissing",
            "setupContext.setupParametersHash is required",
        ).map_err(refusal_to_error)?,
        "setupEpoch": string_field(
            setup_context,
            "setupEpoch",
            "setupContext.setupEpoch",
            "setupContextEpochMissing",
            "setupContext.setupEpoch is required",
        ).map_err(refusal_to_error)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeHash": envelope_binding.private_envelope_hash,
        "privateEnvelopeAadHash": envelope_binding.private_envelope_aad_hash,
        "sourceTrusteeIdentity": source_trustee_binding.source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_binding.source_trustee_roster_position,
        "recipientIdentity": envelope_binding.recipient_identity,
        "recipientRosterPosition": envelope_binding.recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_binding.source_trustee_commitment_root,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "verifiedRnsLimbCount": limb_verifications.len(),
        "verifiedShamirCoefficientCommitmentCount": limb_verifications.len() * roster.decryption_threshold as usize,
        "verifiedPrivateVssShareProofCount": limb_verifications.len(),
        "limbVerificationRoots": limb_verifications
            .iter()
            .map(|verification| verification.limb_verification_root.clone())
            .collect::<Vec<_>>(),
    }))
}

pub(super) fn limb_verification_value(verification: LimbVerification) -> Value {
    json!({
        "rnsLimbIndex": verification.rns_limb_index,
        "rnsPrime": verification.rns_prime,
        "ringDegree": verification.ring_degree,
        "coefficientCommitmentRoots": verification.coefficient_commitment_roots,
        "shareValuesHash": verification.share_values_hash,
        "privateVssShareProofHash": verification.private_vss_share_proof_hash,
        "proofStatementRoot": verification.proof_statement_root,
        "limbVerificationRoot": verification.limb_verification_root,
    })
}

pub(super) fn verification_response(
    ok: bool,
    verifier_status: &str,
    private_envelope_hash: Option<String>,
    local_verification_root: Option<String>,
    limb_verifications: Vec<Value>,
    refused_objects: Vec<PrivateVssRefusal>,
) -> Value {
    json!({
        "ok": ok,
        "operation": "verifyPrivateVssShareEnvelope",
        "verifierStatus": verifier_status,
        "privateEnvelopeHash": private_envelope_hash,
        "localVerificationRoot": local_verification_root,
        "limbVerifications": limb_verifications,
        "refusedObjects": refused_objects
            .into_iter()
            .map(|refusal| refusal.to_value())
            .collect::<Vec<_>>(),
    })
}
