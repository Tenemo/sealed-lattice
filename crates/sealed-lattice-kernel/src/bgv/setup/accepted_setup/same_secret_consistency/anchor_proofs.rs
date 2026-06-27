use super::accessors::*;

use super::family_binding::*;
use super::proof_transport::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY, SameSecretLinkageStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, decode_trustee_evaluation_key_proof,
    same_secret_anchor_proof_bytes_hash, verify_evaluation_key_share,
};

pub(in super::super) fn verify_optional_same_secret_proofs(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("sameSecretProofs") else {
        return Ok(None);
    };
    if !proof_set.is_object() {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofsNotObject",
            "sameSecretProofs must be a root-bound object",
            "setupPackage.sameSecretProofs",
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str) != Some("SameSecretProofSet") {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetTypeMismatch",
            "sameSecretProofs.objectType must be SameSecretProofSet",
            "setupPackage.sameSecretProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetVersionMismatch",
            "sameSecretProofs.objectVersion must be 1",
            "setupPackage.sameSecretProofs.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before same-secret proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetContextMismatch",
            error.message,
            "setupPackage.sameSecretProofs",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY)] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetParametersMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    let roster = super::accepted_roster_from_package(setup_package);
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetCountMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    let expected_same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
        || proof_set
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(expected_same_secret_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofConsistencyRootMismatch",
            "sameSecretProofs must match accepted same-secret statements and proof-family binding",
            "setupPackage.sameSecretProofs",
        )?));
    }
    let material_root = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material| material.get("vssCoefficientCommitmentMaterialRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterialRoot was required before same-secret proof verification",
            )
        })?;
    if proof_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        != Some(material_root)
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofMaterialRootMismatch",
            "sameSecretProofs.vssCoefficientCommitmentMaterialRoot must match accepted public VSS material",
            "setupPackage.sameSecretProofs.vssCoefficientCommitmentMaterialRoot",
        )?));
    }

    let statement_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofRecordsMissing",
            "sameSecretProofs.proofRecords must be present on the accepted proof set",
            "setupPackage.sameSecretProofs.proofRecords",
        )?));
    };
    if proof_records.len() != roster.participant_count as usize {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofCountMismatch",
            "sameSecretProofs.proofRecords must contain one proof per trustee",
            "setupPackage.sameSecretProofs.proofRecords",
        )?));
    }
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before same-secret proof verification",
            )
        })?;
    let verification_context = SameSecretAnchorProofVerificationContext {
        setup_package,
        request,
        setup_context,
        public_matrix_seed_hash,
        vss_coefficient_commitment_material_root: material_root,
        statement_records: &statement_records,
        transported_constant_commitments: &transported_constant_commitments,
    };
    let mut roster_position_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for proof_record in proof_records {
        *roster_position_counts
            .entry(value_u64(proof_record, "trusteeRosterPosition")?)
            .or_insert(0) += 1;
    }
    // Each anchor proof verifies a multi-megabyte succinct argument and is
    // independent given the read-only context, so the ten verify concurrently on
    // native targets; outcomes are collected in record order so the first refusal
    // matches sequential verification. wasm32 stays sequential.
    let verify_record = |proof_record: &Value| -> CanonicalResult<()> {
        verify_same_secret_anchor_proof_record(
            &verification_context,
            proof_record,
            &roster_position_counts,
        )
    };
    #[cfg(not(target_arch = "wasm32"))]
    let record_verifications: Vec<CanonicalResult<()>> =
        proof_records.par_iter().map(verify_record).collect();
    #[cfg(target_arch = "wasm32")]
    let record_verifications: Vec<CanonicalResult<()>> =
        proof_records.iter().map(verify_record).collect();
    if let Some(error) = record_verifications
        .into_iter()
        .filter_map(Result::err)
        .next()
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofVerificationFailed",
            error.message,
            "setupPackage.sameSecretProofs.proofRecords",
        )?));
    }
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        proof_roots.push(json!({
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "sameSecretProofRoot": value_string(proof_record, "sameSecretProofRoot")?,
        }));
    }
    if proof_set.get("sameSecretProofRoots") != Some(&Value::Array(proof_roots)) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofRootListMismatch",
            "sameSecretProofs.sameSecretProofRoots must match the ordered proof records",
            "setupPackage.sameSecretProofs.sameSecretProofRoots",
        )?));
    }

    let Some(proof_set_root) = proof_set
        .get("sameSecretProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetRootMissing",
            "sameSecretProofs.sameSecretProofSetRoot must be present on the accepted proof set",
            "setupPackage.sameSecretProofs.sameSecretProofSetRoot",
        )?));
    };
    validate_hash_string(proof_set_root, "sameSecretProofs.sameSecretProofSetRoot")?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof set object was checked")
        .remove("sameSecretProofSetRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if proof_set_root != expected_root {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetRootMismatch",
            "sameSecretProofSetRoot does not match the canonical same-secret proof set",
            "setupPackage.sameSecretProofs.sameSecretProofSetRoot",
        )?));
    }

    Ok(None)
}

struct SameSecretAnchorProofVerificationContext<'a> {
    setup_package: &'a Value,
    request: &'a Value,
    setup_context: &'a Value,
    public_matrix_seed_hash: &'a str,
    vss_coefficient_commitment_material_root: &'a str,
    statement_records: &'a BTreeMap<u64, Value>,
    transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
}

fn verify_same_secret_anchor_proof_record(
    context: &SameSecretAnchorProofVerificationContext<'_>,
    proof_record: &Value,
    roster_position_counts: &BTreeMap<u64, usize>,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must be objects",
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str) != Some("SameSecretProof") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectType must be SameSecretProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectVersion must be 1",
        ));
    }
    verify_same_secret_context(proof_record, context.setup_context)?;
    for (field_name, expected_value) in [("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY)] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if roster_position_counts
        .get(&trustee_roster_position)
        .copied()
        .unwrap_or(0)
        > 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must have distinct trustee roster positions",
        ));
    }
    let statement_record = context
        .statement_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof trusteeRosterPosition must reference an accepted statement",
            )
        })?;
    for field_name in [
        "trusteeIdentity",
        "trusteeSecretCommitmentRoot",
        "sameSecretStatementRoot",
        "sameSecretProofFamilyBindingRoot",
    ] {
        if proof_record.get(field_name) != statement_record.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must match the accepted statement"),
            ));
        }
    }

    let proof_bytes = same_secret_proof_bytes_from_record(proof_record, context.request)?;
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofSizeBytes must match proofBytesHex",
        ));
    }
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    if proof_bytes_hash != same_secret_anchor_proof_bytes_hash(&proof_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesHash must match proofBytesHex",
        ));
    }
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        context.setup_package,
        trustee_roster_position,
        context.transported_constant_commitments,
    )?;
    let ring_degree = constant_commitments
        .first()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof verification requires constant commitments",
            )
        })?
        .ring_degree;
    if value_u64(proof_record, "ringDegree")? != ring_degree as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof ringDegree must match the rebuilt anchor statement",
        ));
    }
    // Rebuild the keyless anchor statement (no keys, one commitment per limb) exactly as the prover did; the matching statement_hash is what binds the proof to this ceremony, trustee, and VSS material root.
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY.to_string(),
            ceremony_id: value_string(context.setup_context, "ceremonyId")?.to_string(),
            manifest_hash: value_string(context.setup_context, "manifestHash")?.to_string(),
            roster_hash: value_string(context.setup_context, "rosterHash")?.to_string(),
            trustee_identity: value_string(proof_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position,
            setup_epoch: value_string(context.setup_context, "setupEpoch")?.to_string(),
            binding_roots: vec![(
                "vssCoefficientCommitmentMaterialRoot".to_string(),
                context.vss_coefficient_commitment_material_root.to_string(),
            )],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: Some(SameSecretLinkageStatement {
            public_matrix_seed_hash: context.public_matrix_seed_hash.to_string(),
            commitments: constant_commitments,
        }),
        private_vss_share: None,
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
            "same-secret proof statementHash must match the rebuilt anchor statement",
        ));
    }
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let proof_root = value_string(proof_record, "sameSecretProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof record object was checked")
        .remove("sameSecretProofRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if proof_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sameSecretProofRoot does not match the canonical same-secret proof record",
        ));
    }

    Ok(())
}
