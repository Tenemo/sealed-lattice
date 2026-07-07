use super::anchor_transport::*;
use super::reconstructed::*;
use super::statement_record::*;
use super::*;

pub(super) fn verify_same_secret_evidence_sets(
    input: EvidenceSetVerificationInput<'_>,
) -> CanonicalResult<()> {
    let (Some(same_secret_consistency), Some(same_secret_proofs)) = (
        input.request.get("sameSecretConsistency"),
        input.request.get("sameSecretProofs"),
    ) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge evidence verification requires both sameSecretConsistency and sameSecretProofs",
        ));
    };
    let same_secret_statement_records =
        verify_same_secret_consistency_evidence(same_secret_consistency, &input)?;
    verify_same_secret_proof_evidence(same_secret_proofs, &input, &same_secret_statement_records)
}

pub(super) fn verify_same_secret_consistency_evidence(
    same_secret_consistency: &Value,
    input: &EvidenceSetVerificationInput<'_>,
) -> CanonicalResult<Vec<Value>> {
    compare_required_string(
        string_at_path(same_secret_consistency, &["objectType"])?,
        "SameSecretConsistencyStatementSet",
        "same-secret consistency objectType",
    )?;
    compare_required_string(
        string_at_path(same_secret_consistency, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "same-secret consistency proofFamily",
    )?;
    compare_evidence_context(
        same_secret_consistency,
        input.statement_set,
        "same-secret consistency",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_consistency, &["participantCount"])?,
        input.participant_count as u64,
        "same-secret consistency participantCount",
    )?;
    compare_required_string(
        hash_at_path(same_secret_consistency, &["sameSecretConsistencyRoot"])?,
        input.same_secret_consistency_root,
        "same-secret consistency root",
    )?;
    compare_required_string(
        hash_at_path(
            same_secret_consistency,
            &["sameSecretProofFamilyBindingRoot"],
        )?,
        input.same_secret_proof_family_binding_root,
        "same-secret consistency proof-family binding root",
    )?;
    let expected_consistency_root = derive_canonical_object_hash(&value_without_root_field(
        same_secret_consistency,
        "sameSecretConsistencyRoot",
        "same-secret consistency statement set",
    )?)?;
    if expected_consistency_root != input.same_secret_consistency_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret consistency root does not match its bound statement set",
        ));
    }

    let statement_records = array_at_path(same_secret_consistency, &["statementRecords"])?;
    if statement_records.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret consistency statement records must cover every participant",
        ));
    }
    let mut verified_statement_records = Vec::with_capacity(statement_records.len());
    for (expected_position, (statement_record, bridge_statement)) in statement_records
        .iter()
        .zip(input.bridge_statement_records.iter())
        .enumerate()
        .take(input.participant_count)
    {
        compare_required_string(
            string_at_path(statement_record, &["objectType"])?,
            "SameSecretConsistencyStatement",
            "same-secret consistency statement objectType",
        )?;
        compare_evidence_context(
            statement_record,
            input.statement_set,
            "same-secret consistency statement",
        )?;
        let trustee_identity = read_non_empty_string(statement_record, "trusteeIdentity")?;
        compare_required_u64(
            unsigned_at_path(statement_record, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret consistency statement trusteeRosterPosition",
        )?;
        compare_required_string(
            string_at_path(bridge_statement, &["trusteeIdentity"])?,
            trustee_identity,
            "same-secret bridge evidence trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_statement, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret bridge evidence trusteeRosterPosition",
        )?;
        let same_secret_statement_root =
            hash_at_path(statement_record, &["sameSecretStatementRoot"])?;
        let trustee_secret_commitment_root =
            hash_at_path(statement_record, &["trusteeSecretCommitmentRoot"])?;
        let same_secret_proof_family_binding_root =
            hash_at_path(statement_record, &["sameSecretProofFamilyBindingRoot"])?;
        compare_required_string(
            same_secret_proof_family_binding_root,
            input.same_secret_proof_family_binding_root,
            "same-secret consistency statement proof-family binding root",
        )?;
        compare_required_string(
            string_at_path(statement_record, &["sameSecretRelation"])?,
            SAME_SECRET_RELATION,
            "same-secret consistency statement relation",
        )?;
        let expected_statement_root = derive_canonical_object_hash(&value_without_root_field(
            statement_record,
            "sameSecretStatementRoot",
            "same-secret consistency statement",
        )?)?;
        if expected_statement_root != same_secret_statement_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret consistency statement root does not match its bound statement",
            ));
        }
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretStatementRoot"])?,
            same_secret_statement_root,
            "same-secret bridge evidence sameSecretStatementRoot",
        )?;
        compare_required_string(
            hash_at_path(bridge_statement, &["trusteeSecretCommitmentRoot"])?,
            trustee_secret_commitment_root,
            "same-secret bridge evidence trusteeSecretCommitmentRoot",
        )?;
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretProofFamilyBindingRoot"])?,
            same_secret_proof_family_binding_root,
            "same-secret bridge evidence sameSecretProofFamilyBindingRoot",
        )?;
        verified_statement_records.push(statement_record.clone());
    }

    Ok(verified_statement_records)
}

pub(super) fn verify_same_secret_proof_evidence(
    same_secret_proofs: &Value,
    input: &EvidenceSetVerificationInput<'_>,
    same_secret_statement_records: &[Value],
) -> CanonicalResult<()> {
    compare_required_string(
        string_at_path(same_secret_proofs, &["objectType"])?,
        "SameSecretProofSet",
        "same-secret proof set objectType",
    )?;
    compare_required_string(
        string_at_path(same_secret_proofs, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "same-secret proof set proofFamily",
    )?;
    compare_evidence_context(
        same_secret_proofs,
        input.statement_set,
        "same-secret proof set",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_proofs, &["participantCount"])?,
        input.participant_count as u64,
        "same-secret proof set participantCount",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretConsistencyRoot"])?,
        input.same_secret_consistency_root,
        "same-secret proof set consistency root",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretProofSetRoot"])?,
        input.same_secret_proof_set_root,
        "same-secret proof set root",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretProofFamilyBindingRoot"])?,
        input.same_secret_proof_family_binding_root,
        "same-secret proof set proof-family binding root",
    )?;
    let expected_proof_set_root = derive_canonical_object_hash(&value_without_root_field(
        same_secret_proofs,
        "sameSecretProofSetRoot",
        "same-secret proof set",
    )?)?;
    if expected_proof_set_root != input.same_secret_proof_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret proof set root does not match its bound proof records",
        ));
    }

    let proof_records = array_at_path(same_secret_proofs, &["proofRecords"])?;
    if proof_records.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof records must cover every participant",
        ));
    }

    for (expected_position, ((proof_record, statement_record), bridge_statement)) in proof_records
        .iter()
        .zip(same_secret_statement_records.iter())
        .zip(input.bridge_statement_records.iter())
        .enumerate()
        .take(input.participant_count)
    {
        compare_required_string(
            string_at_path(proof_record, &["objectType"])?,
            "SameSecretProof",
            "same-secret proof record objectType",
        )?;
        compare_evidence_context(
            proof_record,
            input.statement_set,
            "same-secret proof record",
        )?;
        let trustee_identity = string_at_path(statement_record, &["trusteeIdentity"])?;
        compare_required_string(
            string_at_path(proof_record, &["trusteeIdentity"])?,
            trustee_identity,
            "same-secret proof record trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_record, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret proof record trusteeRosterPosition",
        )?;
        let same_secret_statement_root =
            hash_at_path(statement_record, &["sameSecretStatementRoot"])?;
        let trustee_secret_commitment_root =
            hash_at_path(statement_record, &["trusteeSecretCommitmentRoot"])?;
        let same_secret_proof_family_binding_root =
            hash_at_path(statement_record, &["sameSecretProofFamilyBindingRoot"])?;
        let same_secret_proof_root = hash_at_path(proof_record, &["sameSecretProofRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretStatementRoot"])?,
            same_secret_statement_root,
            "same-secret proof record statement root",
        )?;
        compare_required_string(
            hash_at_path(proof_record, &["trusteeSecretCommitmentRoot"])?,
            trustee_secret_commitment_root,
            "same-secret proof record trustee secret root",
        )?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretProofFamilyBindingRoot"])?,
            same_secret_proof_family_binding_root,
            "same-secret proof record proof-family binding root",
        )?;
        verify_same_secret_proof_byte_binding(proof_record, input.request)?;
        let expected_proof_root = derive_canonical_object_hash(&value_without_root_field(
            proof_record,
            "sameSecretProofRoot",
            "same-secret proof",
        )?)?;
        if expected_proof_root != same_secret_proof_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret proof root does not match its bound proof record",
            ));
        }
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretProofRoot"])?,
            same_secret_proof_root,
            "same-secret bridge evidence sameSecretProofRoot",
        )?;
    }

    Ok(())
}

pub(super) fn verify_same_secret_proof_byte_binding(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<()> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    if proof_record.get("proofBytesHex").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret proof record must not mix embedded proofBytesHex with transported proof material",
            ));
        }
        let proof_bytes_hex = string_at_path(proof_record, &["proofBytesHex"])?;
        let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
        let expected_proof_bytes_hash =
            hash512_hex(SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "same-secret proof record proofBytesHash",
        )?;
    } else {
        compare_required_string(
            string_at_path(proof_record, &["proofBytesEncoding"])?,
            SETUP_PROOF_MATERIAL_ENCODING,
            "same-secret proof record proofBytesEncoding",
        )?;
        let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
        let transported_binding =
            transported_same_secret_proof_material_binding(request, proof_material_root)?;
        verify_same_secret_proof_transport_reference(
            proof_record,
            &transported_binding.transport_hashes,
        )?;
        compare_required_string(
            proof_bytes_hash,
            &transported_binding.proof_bytes_hash,
            "same-secret proof record proofBytesHash",
        )?;
        let expected_proof_material_root = same_secret_anchor_proof_material_root(
            proof_record,
            &transported_binding.transport_hashes,
        )?;
        compare_required_string(
            proof_material_root,
            &expected_proof_material_root,
            "same-secret proof record proofMaterialRoot",
        )?;
    }

    Ok(())
}
