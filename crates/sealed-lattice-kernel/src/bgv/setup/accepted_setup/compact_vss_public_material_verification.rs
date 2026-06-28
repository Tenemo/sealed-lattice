use super::*;

const COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD: &str = "compactVssCoefficientCommitmentSet";
const COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD: &str =
    "compactVssRecipientShareCommitmentSet";
const COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "compactVssAggregateThresholdCommitmentSet";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "compactVssShareLinkageStatement";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD: &str =
    "compactVssShareLinkageProofMaterialSet";
const COMPACT_VSS_SHARE_LINKAGE_BINARY_TRANSPORT_OBJECT_TYPE: &str =
    "CompactVssShareLinkageBinaryProofMaterialTransport";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "compact-vss-share-linkage";
const COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT: &str =
    "compact-vss-share-linkage-proof-material-binary-v1";

pub(super) fn verify_optional_compact_vss_public_material(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let compact_public_material_fields = [
        COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD,
        COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD,
        COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD,
        COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD,
    ];
    let present_field_count = compact_public_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    let proof_material_set = setup_package.get(COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD);
    if present_field_count == 0 && proof_material_set.is_none() {
        return Ok(None);
    }

    if present_field_count != compact_public_material_fields.len() {
        let missing_fields = compact_public_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssPublicMaterialIncomplete",
            format!(
                "compact VSS public material requires all compact commitment sets and the share-linkage statement; missing {missing_fields}"
            ),
            "setupPackage",
        )?));
    }

    if let Some(response) =
        verify_compact_share_linkage_proof_material_transport_reference(setup_package, request)?
    {
        return Ok(Some(response));
    }

    Ok(Some(compact_vss_public_material_refusal(
        "compactVssPublicMaterialNotBinding",
        "compact VSS public material is not accepted by this verifier because the current sparse linear commitment is not binding for full-width coefficient vectors",
        "setupPackage.compactVssCoefficientCommitmentSet",
    )?))
}

fn verify_compact_share_linkage_proof_material_transport_reference(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(transported_material) = request.get("transportedCompactVssShareLinkageProofMaterial")
    else {
        return Ok(None);
    };
    if transported_material.get("chunks").is_some() {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialChunksNotAccepted",
            "transportedCompactVssShareLinkageProofMaterial must be a chunkless reference for accepted setup verification",
            "transportedCompactVssShareLinkageProofMaterial.chunks",
        )?));
    }
    let Some(proof_material_set_root) = setup_package
        .get(COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD)
        .and_then(|proof_material_set| proof_material_set.get("proofMaterialSetRoot"))
        .and_then(Value::as_str)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialRootMissing",
            "compactVssShareLinkageProofMaterialSet.proofMaterialSetRoot is required when transported compact share-linkage proof material is supplied",
            "setupPackage.compactVssShareLinkageProofMaterialSet.proofMaterialSetRoot",
        )?));
    };
    validate_hash_string(
        proof_material_set_root,
        "setupPackage.compactVssShareLinkageProofMaterialSet.proofMaterialSetRoot",
    )?;
    if transported_material
        .get("proofMaterialSetRoot")
        .and_then(Value::as_str)
        != Some(proof_material_set_root)
    {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialRootMismatch",
            "transportedCompactVssShareLinkageProofMaterial.proofMaterialSetRoot must match the setup package compact proof-material set root",
            "transportedCompactVssShareLinkageProofMaterial.proofMaterialSetRoot",
        )?));
    }
    if let Some(response) =
        verify_compact_share_linkage_proof_material_transport_header(transported_material)?
    {
        return Ok(Some(response));
    }

    Ok(None)
}

fn verify_compact_share_linkage_proof_material_transport_header(
    transported_material: &Value,
) -> CanonicalResult<Option<Value>> {
    for (field_name, expected_value) in [
        (
            "objectType",
            COMPACT_VSS_SHARE_LINKAGE_BINARY_TRANSPORT_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("proofFamily", COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY),
        ("binaryFormat", COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT),
    ] {
        if transported_material.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(compact_vss_public_material_refusal(
                "compactVssShareLinkageProofMaterialReferenceMismatch",
                format!(
                    "transportedCompactVssShareLinkageProofMaterial.{field_name} must match the compact share-linkage binary transport profile"
                ),
                format!("transportedCompactVssShareLinkageProofMaterial.{field_name}"),
            )?));
        }
    }
    if transported_material
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialReferenceMismatch",
            "transportedCompactVssShareLinkageProofMaterial.objectVersion must be 1",
            "transportedCompactVssShareLinkageProofMaterial.objectVersion",
        )?));
    }
    let Some(full_object_hash) = transported_material
        .get("fullObjectHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportHashMissing",
            "transportedCompactVssShareLinkageProofMaterial.fullObjectHash is required",
            "transportedCompactVssShareLinkageProofMaterial.fullObjectHash",
        )?));
    };
    validate_hash_string(
        full_object_hash,
        "transportedCompactVssShareLinkageProofMaterial.fullObjectHash",
    )?;
    let Some(chunk_root) = transported_material
        .get("chunkRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportHashMissing",
            "transportedCompactVssShareLinkageProofMaterial.chunkRoot is required",
            "transportedCompactVssShareLinkageProofMaterial.chunkRoot",
        )?));
    };
    validate_hash_string(
        chunk_root,
        "transportedCompactVssShareLinkageProofMaterial.chunkRoot",
    )?;
    let Some(chunk_size_bytes) = transported_material
        .get("chunkSizeBytes")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMissing",
            "transportedCompactVssShareLinkageProofMaterial.chunkSizeBytes is required",
            "transportedCompactVssShareLinkageProofMaterial.chunkSizeBytes",
        )?));
    };
    if chunk_size_bytes != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMismatch",
            "transportedCompactVssShareLinkageProofMaterial.chunkSizeBytes must match the compact proof transport chunk size",
            "transportedCompactVssShareLinkageProofMaterial.chunkSizeBytes",
        )?));
    }
    let Some(chunk_count) = transported_material
        .get("chunkCount")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMissing",
            "transportedCompactVssShareLinkageProofMaterial.chunkCount is required",
            "transportedCompactVssShareLinkageProofMaterial.chunkCount",
        )?));
    };
    let Some(total_byte_length) = transported_material
        .get("totalByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMissing",
            "transportedCompactVssShareLinkageProofMaterial.totalByteLength is required",
            "transportedCompactVssShareLinkageProofMaterial.totalByteLength",
        )?));
    };
    if chunk_count == 0 || total_byte_length == 0 {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMismatch",
            "transportedCompactVssShareLinkageProofMaterial chunk count and byte length must be positive",
            "transportedCompactVssShareLinkageProofMaterial",
        )?));
    }
    let Some(chunk_hash_values) = transported_material
        .get("chunkHashes")
        .and_then(Value::as_array)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportHashMissing",
            "transportedCompactVssShareLinkageProofMaterial.chunkHashes must list every proof-material chunk hash",
            "transportedCompactVssShareLinkageProofMaterial.chunkHashes",
        )?));
    };
    if chunk_hash_values.len()
        != usize::try_from(chunk_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact share-linkage proof material chunk count does not fit usize",
            )
        })?
    {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportMetadataMismatch",
            "transportedCompactVssShareLinkageProofMaterial.chunkHashes length must match chunkCount",
            "transportedCompactVssShareLinkageProofMaterial.chunkHashes",
        )?));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Ok(Some(compact_vss_public_material_refusal(
                "compactVssShareLinkageProofMaterialTransportHashInvalid",
                "transportedCompactVssShareLinkageProofMaterial.chunkHashes entries must be protocol hashes",
                format!(
                    "transportedCompactVssShareLinkageProofMaterial.chunkHashes[{chunk_index}]"
                ),
            )?));
        };
        validate_hash_string(
            chunk_hash,
            &format!("transportedCompactVssShareLinkageProofMaterial.chunkHashes[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }
    let expected_chunk_root = setup_proof_material_chunk_manifest_root(
        COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        chunk_size_bytes,
        chunk_count,
        total_byte_length,
        &chunk_hashes,
        full_object_hash,
    )?;
    if chunk_root != expected_chunk_root {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialTransportHashMismatch",
            "transportedCompactVssShareLinkageProofMaterial.chunkRoot must match the canonical compact proof-material chunk manifest",
            "transportedCompactVssShareLinkageProofMaterial.chunkRoot",
        )?));
    }

    Ok(None)
}

fn compact_vss_public_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_compact_vss_public_material_is_absent_by_default() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(&json!({}), &json!({}))?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_requires_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(
            &json!({
                "compactVssCoefficientCommitmentSet": {},
            }),
            &json!({}),
        )?
        .expect("partial compact VSS public material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(
            &json!({
                "compactVssCoefficientCommitmentSet": {},
                "compactVssRecipientShareCommitmentSet": {},
                "compactVssAggregateThresholdCommitmentSet": {},
                "compactVssShareLinkageStatement": {},
                "compactVssShareLinkageProofMaterialSet": {},
            }),
            &json!({}),
        )?
        .expect("complete compact VSS public material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialNotBinding")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactVssCoefficientCommitmentSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_rejects_embedded_transport_chunks()
    -> CanonicalResult<()> {
        let proof_material_set_root = valid_test_hash('1');
        let response = verify_optional_compact_vss_public_material(
            &complete_compact_vss_public_material_with_proof_root(&proof_material_set_root),
            &json!({
                "transportedCompactVssShareLinkageProofMaterial": {
                    "proofMaterialSetRoot": proof_material_set_root,
                    "chunks": [],
                },
            }),
        )?
        .expect("compact VSS public material with raw chunks must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofMaterialChunksNotAccepted")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_rejects_drifted_transport_root() -> CanonicalResult<()>
    {
        let proof_material_set_root = valid_test_hash('1');
        let response = verify_optional_compact_vss_public_material(
            &complete_compact_vss_public_material_with_proof_root(&proof_material_set_root),
            &json!({
                "transportedCompactVssShareLinkageProofMaterial":
                    compact_share_linkage_transport_reference(&valid_test_hash('2')),
            }),
        )?
        .expect("compact VSS public material with drifted proof-material root must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofMaterialRootMismatch")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_rejects_drifted_transport_chunk_root()
    -> CanonicalResult<()> {
        let proof_material_set_root = valid_test_hash('1');
        let mut transported_material =
            compact_share_linkage_transport_reference(&proof_material_set_root);
        transported_material["chunkRoot"] = json!(valid_test_hash('9'));
        let response = verify_optional_compact_vss_public_material(
            &complete_compact_vss_public_material_with_proof_root(&proof_material_set_root),
            &json!({
                "transportedCompactVssShareLinkageProofMaterial": transported_material,
            }),
        )?
        .expect("compact VSS public material with drifted chunk root must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofMaterialTransportHashMismatch")
        );
        Ok(())
    }

    fn complete_compact_vss_public_material_with_proof_root(
        proof_material_set_root: &str,
    ) -> Value {
        json!({
            "compactVssCoefficientCommitmentSet": {},
            "compactVssRecipientShareCommitmentSet": {},
            "compactVssAggregateThresholdCommitmentSet": {},
            "compactVssShareLinkageStatement": {},
            "compactVssShareLinkageProofMaterialSet": {
                "proofMaterialSetRoot": proof_material_set_root,
            },
        })
    }

    fn compact_share_linkage_transport_reference(proof_material_set_root: &str) -> Value {
        let full_object_hash = valid_test_hash('3');
        let chunk_hash = valid_test_hash('4');
        let chunk_root = setup_proof_material_chunk_manifest_root(
            COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            1,
            64,
            std::slice::from_ref(&chunk_hash),
            &full_object_hash,
        )
        .expect("compact share-linkage chunk root");

        json!({
            "objectType": COMPACT_VSS_SHARE_LINKAGE_BINARY_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
            "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "binaryFormat": COMPACT_VSS_SHARE_LINKAGE_BINARY_FORMAT,
            "proofMaterialSetRoot": proof_material_set_root,
            "shareLinkageStatementRoot": valid_test_hash('2'),
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": 1,
            "totalByteLength": 64,
            "fullObjectHash": full_object_hash,
            "chunkRoot": chunk_root,
            "chunkHashes": [chunk_hash],
        })
    }

    fn valid_test_hash(character: char) -> String {
        (0..128).map(|_| character).collect()
    }
}
