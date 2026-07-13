use super::common::*;

use super::super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
use super::shares::*;
use super::succinct_proof_transport::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    PUBLIC_KEY_SHARE_PROOF_FAMILY, SameSecretLinkageStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, decode_trustee_evaluation_key_proof_from_source,
    public_key_share_succinct_proof_material_bytes_hash, verify_evaluation_key_share,
};

pub(in super::super) fn verify_public_key_share_succinct_proofs(
    setup_package: &Value,
    request: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Option<Value>> {
    let material_set = setup_package.get("publicKeyShareMaterial");
    let proof_set = setup_package.get("publicKeyShareSuccinctProofs");
    if material_set.is_none() && proof_set.is_none() {
        return Ok(Some(verification_response(
            vec![
                "publicKeyShareMaterial".to_string(),
                "publicKeyShareSuccinctProofs".to_string(),
            ],
            Vec::new(),
        )?));
    }
    let Some(material_set) = material_set else {
        return Ok(Some(verification_response(
            vec!["publicKeyShareMaterial".to_string()],
            Vec::new(),
        )?));
    };
    let Some(proof_set) = proof_set else {
        return Ok(Some(verification_response(
            vec!["publicKeyShareSuccinctProofs".to_string()],
            Vec::new(),
        )?));
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
    let public_key_share_set_root = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSetRoot was required before public-key share succinct proof verification",
            )
        })?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    if request.get("transportedPublicKeyShareMaterial").is_none() {
        return Ok(Some(verification_response(
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
        )?));
    }
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        public_key_share_set_root,
        &share_records,
        request,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(Some(public_key_refusal(
                "publicKeyShareMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    let ring_degree = usize::try_from(value_u64(material_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.ringDegree does not fit usize",
        )
    })?;
    if !proof_set.is_object() {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofSetNotObject",
            "publicKeyShareSuccinctProofs must be a root-bound object",
            "setupPackage.publicKeyShareSuccinctProofs",
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofSetTypeMismatch",
            "publicKeyShareSuccinctProofs.objectType must be PublicKeyShareSuccinctProofSet",
            "setupPackage.publicKeyShareSuccinctProofs.objectType",
        )?));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    let Some(proof_records_array) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofRecordsMissing",
            "publicKeyShareSuccinctProofs.proofRecords must be present on the accepted proof set",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        )?));
    };
    if proof_records_array.len() != roster.participant_count as usize {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofCountMismatch",
            "publicKeyShareSuccinctProofs.proofRecords must contain one proof per trustee",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        )?));
    }
    let verification_context = PublicKeyShareSuccinctProofVerificationContext {
        request,
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        share_records: &share_records,
        material_bindings: &material_bindings,
        verified_same_secret_bridge,
        proof_binding_session,
    };
    let mut roster_position_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for succinct_proof_record in proof_records_array {
        *roster_position_counts
            .entry(value_u64(succinct_proof_record, "trusteeRosterPosition")?)
            .or_insert(0) += 1;
    }
    // Resolve or consume one proof before advancing to the next record. This is
    // the same bounded lifecycle on native and browser targets and prevents a
    // native verifier from retaining one multi-megabyte proof per worker.
    for succinct_proof_record in proof_records_array {
        if let Err(error) = verify_public_key_share_succinct_proof_record(
            &verification_context,
            succinct_proof_record,
            &roster_position_counts,
        ) {
            return Ok(Some(public_key_refusal(
                "publicKeyShareSuccinctProofVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
            )?));
        }
    }
    let Some(succinct_proof_set_root) = proof_set
        .get("publicKeyShareSuccinctProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofSetRootMissing",
            "publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot must be present on the accepted proof set",
            "setupPackage.publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot",
        )?));
    };
    validate_hash_string(
        succinct_proof_set_root,
        "publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot",
    )?;
    let expected_root = derive_canonical_object_hash(&json!({
        "objectType": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE,
        "proofRecords": proof_records_array,
    }))?;
    if succinct_proof_set_root != expected_root {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSuccinctProofSetRootMismatch",
            "publicKeyShareSuccinctProofSetRoot does not match the canonical public-key share succinct proof set",
            "setupPackage.publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot",
        )?));
    }

    Ok(None)
}

struct PublicKeyShareSuccinctProofVerificationContext<'a> {
    request: &'a Value,
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
    roster_position_counts: &BTreeMap<u64, usize>,
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
    verify_context_fields_match(
        proof_record,
        context.setup_context,
        "publicKeyShareSuccinctProofs.proofRecords",
    )?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if roster_position_counts
        .get(&trustee_roster_position)
        .copied()
        .unwrap_or(0)
        > 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof records must have distinct trustee roster positions",
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
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(material_binding.public_key_share_root.as_str())
        || proof_record
            .get("publicKeyShareMaterialRoot")
            .and_then(Value::as_str)
            != Some(material_binding.public_key_share_material_root.as_str())
        || proof_record.get("trusteeIdentity") != share_record.get("trusteeIdentity")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share succinct proof must bind the accepted share and material",
        ));
    }
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
    if proof_record.get("trusteeIdentity").and_then(Value::as_str)
        != Some(bridge_binding.trustee_identity.as_str())
        || proof_record
            .get("sameSecretBridgeStatementRoot")
            .and_then(Value::as_str)
            != Some(bridge_binding.same_secret_bridge_statement_root.as_str())
        || proof_record
            .get("sameSecretBridgeProofRecordRoot")
            .and_then(Value::as_str)
            != Some(bridge_binding.same_secret_bridge_proof_record_root.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "public-key share succinct proof must bind the verified same-secret bridge statement and proof record",
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
    let same_secret_linkage: Option<SameSecretLinkageStatement> = None;
    let same_secret_bridge = Some(bridge_binding.statement.clone());
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: PUBLIC_KEY_SHARE_PROOF_FAMILY.to_string(),
            ceremony_id: value_string(context.setup_context, "ceremonyId")?.to_string(),
            manifest_hash: value_string(context.setup_context, "manifestHash")?.to_string(),
            roster_hash: value_string(context.setup_context, "rosterHash")?.to_string(),
            trustee_identity: value_string(proof_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position,
            setup_epoch: value_string(context.setup_context, "setupEpoch")?.to_string(),
            binding_roots: vec![
                (
                    "sameSecretBridgeStatementRoot".to_string(),
                    bridge_binding.same_secret_bridge_statement_root.clone(),
                ),
                (
                    "sameSecretBridgeProofRecordRoot".to_string(),
                    bridge_binding.same_secret_bridge_proof_record_root.clone(),
                ),
            ],
        },
        ring_degree: context.ring_degree,
        // A public-key share is one digit spanning all Q_share limbs with no diagonal source; key_switch_seed_hex carries the public matrix seed because the relation's public sample is the shared reference polynomial a.
        keys: vec![EvaluationKeyShareDescriptor {
            kind: EvaluationKeyShareKind::PublicKeyShare,
            level: DATA_PRIMES.len() - 1,
            key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
            key_switch_seed_hex: context.public_matrix_seed_hash.to_string(),
            component_b_by_digit: vec![material_binding.coefficients_by_limb.clone()],
            round_one_aggregate_diagonal: Vec::new(),
        }],
        vss_share_linkage: None,
        same_secret_bridge,
        same_secret_linkage,
        private_vss_share: None,
        target_decryption_share: None,
    };
    let statement_hash_hex = statement
        .statement_hash()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(statement_hash_hex.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof statementHash must match the rebuilt statement",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    let verification_binding_hash =
        public_key_share_succinct_proof_verification_binding_hash(proof_record, &statement)?;
    if !crate::bgv::setup::consume_accepted_setup_proof_binding(
        context.proof_binding_session.session_handle,
        &context.proof_binding_session.capability,
        PUBLIC_KEY_SHARE_PROOF_FAMILY,
        proof_material_root,
        &verification_binding_hash,
    )? {
        // Production verification receives authenticated raw stream bytes. Test
        // fixtures instead restore the exact verifier-derived binding above, so
        // no proof corpus survives between fixture construction and this pass.
        let proof_bytes =
            public_key_share_succinct_proof_bytes_from_record(proof_record, context.request)?;
        let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
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
        "proofMaterialRoot": public_key_share_succinct_proof_material_root(proof_record)?,
        "statementHash": crate::hashing::to_hex(&statement.statement_hash()),
        "proofRecordRoot": derive_canonical_object_hash(proof_record)?,
    }))
}
