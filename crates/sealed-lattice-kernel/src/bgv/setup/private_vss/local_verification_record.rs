use super::*;

pub(super) fn local_verification_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_binding: &SourceTrusteeCommitmentBinding,
    envelope_binding: &PrivateEnvelopeBinding,
    ring_degree: usize,
    limb_verifications: &[LimbVerification],
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "PrivateVssLocalVerification",
        "setupContextHash": accepted_setup::setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeHash": envelope_binding.private_envelope_hash,
        "privateEnvelopeAadHash": envelope_binding.private_envelope_aad_hash,
        "sourceTrusteeIdentity": source_trustee_binding.source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_binding.source_trustee_roster_position,
        "recipientIdentity": envelope_binding.recipient_identity,
        "recipientRosterPosition": envelope_binding.recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_binding.source_trustee_commitment_root,
        "ringDegree": ring_degree,
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
        "limbVerificationRoot": verification.limb_verification_root,
    })
}

pub(super) fn verification_response(
    is_valid: bool,
    private_envelope_hash: Option<String>,
    local_verification_root: Option<String>,
    limb_verifications: Vec<Value>,
    refused_objects: Vec<PrivateVssRefusal>,
) -> Value {
    if is_valid {
        return match (private_envelope_hash, local_verification_root) {
            (Some(private_envelope_hash), Some(local_verification_root)) => json!({
                "isValid": true,
                "value": {
                    "privateEnvelopeHash": private_envelope_hash,
                    "localVerificationRoot": local_verification_root,
                    "limbVerifications": limb_verifications,
                },
            }),
            _ => json!({
                "isValid": false,
                "refusalReason": crate::foundation::RefusalReason::MalformedEncoding.name(),
            }),
        };
    }

    json!({
        "isValid": false,
        "refusalReason": refused_objects
            .first()
            .map(PrivateVssRefusal::refusal_reason)
            .unwrap_or(crate::foundation::RefusalReason::MalformedEncoding)
            .name(),
    })
}
