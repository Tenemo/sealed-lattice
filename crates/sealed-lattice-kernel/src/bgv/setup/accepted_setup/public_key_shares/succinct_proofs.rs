use super::common::*;

use super::super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
use super::shares::*;
use super::succinct_proof_transport::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    PUBLIC_KEY_SHARE_PROOF_FAMILY, SetupProofStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, decode_trustee_evaluation_key_proof_from_source,
    public_key_share_succinct_proof_material_bytes_hash, verify_evaluation_key_share,
};

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
            public_key_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "publicKeyShareSuccinctProofsMissing",
                "publicKeyShareSuccinctProofs must accompany accepted public-key share material",
                "setupPackage.publicKeyShareSuccinctProofs",
            )?,
        ));
    };
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share succinct proof verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
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
                public_key_refusal(
                    crate::foundation::RefusalReason::MalformedEncoding,
                    "publicKeyShareMaterialVerificationFailed",
                    error.message,
                    "setupPackage.publicKeyShareMaterial",
                )?,
            ));
        }
    };
    if !proof_set.is_object() {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            public_key_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "publicKeyShareSuccinctProofSetNotObject",
                "publicKeyShareSuccinctProofs must be a root-bound object",
                "setupPackage.publicKeyShareSuccinctProofs",
            )?,
        ));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            public_key_refusal(
                crate::foundation::RefusalReason::WrongTypeOrLength,
                "publicKeyShareSuccinctProofSetTypeMismatch",
                "publicKeyShareSuccinctProofs.objectType must be PublicKeyShareSuccinctProofSet",
                "setupPackage.publicKeyShareSuccinctProofs.objectType",
            )?,
        ));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    let Some(proof_records_array) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            public_key_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "publicKeyShareSuccinctProofRecordsMissing",
                "publicKeyShareSuccinctProofs.proofRecords must be present on the accepted proof set",
                "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
            )?,
        ));
    };
    if proof_records_array.len() != roster.participant_count as usize {
        return Ok(PublicKeyShareSuccinctProofVerification::Refused(
            public_key_refusal(
                crate::foundation::RefusalReason::WrongTypeOrLength,
                "publicKeyShareSuccinctProofCountMismatch",
                "publicKeyShareSuccinctProofs.proofRecords must contain one proof per trustee",
                "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
            )?,
        ));
    }
    let verification_context = PublicKeyShareSuccinctProofVerificationContext {
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        share_records: &share_records,
        material_bindings: &material_bindings,
        verified_same_secret_bridge,
        proof_binding_session,
    };
    // Resolve or consume one proof before advancing to the next record. This is
    // the same bounded lifecycle on native and browser targets and prevents a
    // native verifier from retaining one multi-megabyte proof per worker.
    for (record_position, succinct_proof_record) in proof_records_array.iter().enumerate() {
        match verify_public_key_share_succinct_proof_record(
            &verification_context,
            succinct_proof_record,
            record_position as u64,
        ) {
            Ok(()) => {}
            Err(error) => {
                return Ok(PublicKeyShareSuccinctProofVerification::Refused(
                    public_key_refusal(
                        crate::foundation::RefusalReason::InvalidProof,
                        "publicKeyShareSuccinctProofVerificationFailed",
                        error.message,
                        "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
                    )?,
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
    ring_degree: usize,
    share_records: &'a BTreeMap<u64, Value>,
    material_bindings: &'a BTreeMap<u64, PublicKeyShareMaterialBinding>,
    verified_same_secret_bridge: Option<&'a VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &'a crate::bgv::setup::AcceptedSetupProofBindingSession,
}

fn verify_public_key_share_succinct_proof_record(
    context: &PublicKeyShareSuccinctProofVerificationContext<'_>,
    proof_record: &Value,
    trustee_roster_position: u64,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof records must be objects",
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_SUCCINCT_PROOF_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof objectType must be PublicKeyShareSuccinctProof",
        ));
    }
    let share_record = context
        .share_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proof must reference an accepted share record",
            )
        })?;
    let material_binding = context
        .material_bindings
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proof must reference accepted public-key share material",
            )
        })?;
    // The public-key relation opens the constant commitment bound by the
    // verified same-secret bridge statement.
    let verified_same_secret_bridge = context
        .verified_same_secret_bridge
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret bridge material was required for public-key share succinct proof verification",
            )
        })?;
    let bridge_binding =
        verified_same_secret_bridge.statement_for_roster_position(trustee_roster_position)?;
    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    if trustee_identity != bridge_binding.trustee_identity.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "verified same-secret bridge material must bind the accepted public-key trustee",
        ));
    }
    if bridge_binding.statement.bridge_rns_primes.is_empty()
        || bridge_binding
            .statement
            .target_constant_commitment_roots
            .is_empty()
        || bridge_binding
            .statement
            .target_constant_commitments
            .is_empty()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge statement must carry the limb-zero target commitment",
        ));
    }
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            setup_context_hash: setup_context_hash(context.setup_context)?,
            trustee_identity: trustee_identity.to_string(),
            trustee_roster_position,
            binding_roots: Vec::new(),
        },
        ring_degree: context.ring_degree,
        proof: SetupProofStatement::PublicKeyShare {
            // A public-key share is one digit spanning all Q_share limbs with no diagonal source; key_switch_seed_hex carries the public matrix seed because the relation's public sample is the shared reference polynomial a.
            key: EvaluationKeyShareDescriptor {
                kind: EvaluationKeyShareKind::PublicKeyShare,
                level: DATA_PRIMES.len() - 1,
                key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
                key_switch_seed_hex: context.public_matrix_seed_hash.to_string(),
                component_b_by_digit: vec![material_binding.coefficients_by_limb.clone()],
                round_one_aggregate_diagonal: Vec::new(),
            },
            same_secret_bridge: bridge_binding.statement.clone(),
        },
    };
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    let verification_binding_hash =
        public_key_share_succinct_proof_verification_binding_hash(proof_record, &statement)?;
    if !crate::bgv::setup::consume_accepted_setup_proof_binding(
        context.proof_binding_session.session_handle,
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
        &verification_binding_hash,
    )? {
        // Production verification receives authenticated raw stream bytes. Test
        // fixtures instead restore the exact verifier-derived binding above, so
        // no proof corpus survives between fixture construction and this pass.
        let proof_bytes = public_key_share_succinct_proof_bytes_from_hash(
            proof_bytes_hash,
            context.proof_binding_session,
        )?;
        if proof_bytes_hash
            != public_key_share_succinct_proof_material_bytes_hash(proof_bytes.as_ref())?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proofBytesHash must match supplied proof bytes",
            ));
        }
        let proof =
            decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes.as_ref())?;
        verify_evaluation_key_share(&statement, &proof)?;
    }

    Ok(())
}

pub(in crate::bgv::setup) fn public_key_share_succinct_proof_verification_binding_hash(
    proof_record: &Value,
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "AcceptedSetupPublicKeyShareSuccinctProofVerificationBinding",
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
        "statementHash": crate::hashing::to_hex(&statement.statement_hash()),
    }))
}
