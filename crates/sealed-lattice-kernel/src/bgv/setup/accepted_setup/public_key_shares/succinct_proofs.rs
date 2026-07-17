use super::common::*;

use super::super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
use super::shares::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY;

pub(in super::super) fn verify_public_key_share_succinct_proofs(
    setup_package: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    ring_degree: usize,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<PublicKeyShareSuccinctProofVerification> {
    let material_set = setup_package.get("publicKeyShareMaterial");
    let proof_set = setup_package.get("publicKeyShareSuccinctProofs");
    if material_set.is_none() && proof_set.is_none() {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            setup_refusals(
                vec![
                    "publicKeyShareMaterial".to_string(),
                    "publicKeyShareSuccinctProofs".to_string(),
                ],
                Vec::new(),
            ),
        ));
    }
    let Some(material_set) = material_set else {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            setup_refusals(vec!["publicKeyShareMaterial".to_string()], Vec::new()),
        ));
    };
    let Some(proof_set) = proof_set else {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            single_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "publicKeyShareSuccinctProofsMissing",
                "publicKeyShareSuccinctProofs must accompany accepted public-key share material",
            ),
        ));
    };
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupContext was required before public-key share succinct proof verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "commonRandomness.publicMatrixSeedHash was required before public-key share succinct proof verification",
            )
    })?;
    let common_binding = public_key_common_binding(setup_package)?;
    let public_key_share_set_root = derive_public_key_share_set_root(setup_package)?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        ring_degree,
        &public_key_share_set_root,
        &share_records,
        proof_binding_session,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(PublicKeyShareSuccinctProofVerification::Refused(
                single_refusal(
                    crate::foundation::RefusalReason::MalformedEncoding,
                    "publicKeyShareMaterialVerificationFailed",
                    error.message,
                ),
            ));
        }
    };
    if !proof_set.is_object() {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            single_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "publicKeyShareSuccinctProofSetNotObject",
                "publicKeyShareSuccinctProofs must be a root-bound object",
            ),
        ));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            single_refusal(
                crate::foundation::RefusalReason::WrongTypeOrLength,
                "publicKeyShareSuccinctProofSetTypeMismatch",
                "publicKeyShareSuccinctProofs.objectType must be PublicKeyShareSuccinctProofSet",
            ),
        ));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    let Some(proof_bytes_hashes) = proof_set.get("proofBytesHashes").and_then(Value::as_array)
    else {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            single_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "publicKeyShareSuccinctProofHashesMissing",
                "publicKeyShareSuccinctProofs.proofBytesHashes must be present on the accepted proof set",
            ),
        ));
    };
    if proof_bytes_hashes.len() != roster.participant_count as usize {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            single_refusal(
                crate::foundation::RefusalReason::WrongTypeOrLength,
                "publicKeyShareSuccinctProofCountMismatch",
                "publicKeyShareSuccinctProofs.proofBytesHashes must contain one proof per trustee",
            ),
        ));
    }
    let verification_context = PublicKeyShareSuccinctProofVerificationContext {
        setup_context,
        public_matrix_seed_hash,
        share_records: &share_records,
        material_bindings: &material_bindings,
        verified_same_secret_bridge,
        proof_binding_session,
    };
    // Resolve or consume one proof before advancing to the next record. This is
    // the same bounded lifecycle on native and browser targets and prevents a
    // native verifier from retaining one multi-megabyte proof per worker.
    for (record_position, proof_bytes_hash) in proof_bytes_hashes.iter().enumerate() {
        match verify_public_key_share_succinct_proof_record(
            &verification_context,
            proof_bytes_hash.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "public-key share succinct proof hash must be a string",
                )
            })?,
            record_position as u64,
        ) {
            Ok(()) => {}
            Err(error) => {
                return Ok(PublicKeyShareSuccinctProofVerification::Refused(
                    single_refusal(
                        crate::foundation::RefusalReason::InvalidProof,
                        "publicKeyShareSuccinctProofVerificationFailed",
                        error.message,
                    ),
                ));
            }
        }
    }
    Ok(PublicKeyShareSuccinctProofVerification::Verified(
        material_bindings,
    ))
}

pub(in super::super) enum PublicKeyShareSuccinctProofVerification {
    Verified(BTreeMap<u64, PublicKeyShareMaterialBinding>),
    Refused(Refusals),
}

struct PublicKeyShareSuccinctProofVerificationContext<'a> {
    setup_context: &'a Value,
    public_matrix_seed_hash: &'a str,
    share_records: &'a BTreeMap<u64, Value>,
    material_bindings: &'a BTreeMap<u64, PublicKeyShareMaterialBinding>,
    verified_same_secret_bridge: Option<&'a VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &'a crate::bgv::setup::AcceptedSetupProofBindingSession,
}

fn verify_public_key_share_succinct_proof_record(
    context: &PublicKeyShareSuccinctProofVerificationContext<'_>,
    proof_bytes_hash: &str,
    trustee_roster_position: u64,
) -> CanonicalResult<()> {
    validate_hash_string(
        proof_bytes_hash,
        "publicKeyShareSuccinctProofs.proofBytesHashes",
    )?;
    let share_record = context
        .share_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "public-key share succinct proof must reference an accepted share record",
            )
        })?;
    if !context
        .material_bindings
        .contains_key(&trustee_roster_position)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "public-key share succinct proof must reference accepted public-key share material",
        ));
    }
    // The public-key relation opens the constant commitment bound by the
    // verified same-secret bridge statement.
    let verified_same_secret_bridge = context
        .verified_same_secret_bridge
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "same-secret bridge material was required for public-key share succinct proof verification",
            )
        })?;
    let bridge_binding =
        verified_same_secret_bridge.statement_for_roster_position(trustee_roster_position)?;
    let trustee_identity = bridge_binding.trustee_identity.as_str();
    let public_key_share_root = derive_public_key_share_root(
        context.setup_context,
        context.public_matrix_seed_hash,
        trustee_roster_position,
        share_record,
    )?;
    let verification_binding_hash = public_key_share_succinct_proof_verification_binding_hash(
        proof_bytes_hash,
        &setup_context_hash(context.setup_context)?,
        trustee_identity,
        trustee_roster_position,
        &bridge_binding.statement.target_constant_commitment_roots,
        &public_key_share_root,
    )?;
    if !crate::bgv::setup::consume_accepted_setup_proof_binding(
        context.proof_binding_session.session_handle,
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
        &verification_binding_hash,
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "public-key share proof was not verified by the common proof verifier for the reconstructed statement",
        ));
    }

    Ok(())
}

/// Binds a session-owned common-proof verification result to the exact public
/// material reconstructed by accepted setup. This is verifier state, not a
/// serialized receipt or a producer-supplied verdict.
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_verification_binding_hash(
    proof_bytes_hash: &str,
    setup_context_hash: &str,
    trustee_identity: &str,
    trustee_roster_position: u64,
    anchor_commitment_roots: &[String],
    public_key_share_root: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "AcceptedSetupPublicKeyShareCommonProofBinding",
        "proofBytesHash": proof_bytes_hash,
        "setupContextHash": setup_context_hash,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": trustee_roster_position,
        "anchorCommitmentRoots": anchor_commitment_roots,
        "publicKeyShareRoot": public_key_share_root,
    }))
}
