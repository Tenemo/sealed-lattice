use super::*;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    PUBLIC_KEY_SHARE_PROOF_FAMILY, PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
    PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS, SameSecretLinkageStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement, decode_trustee_evaluation_key_proof,
    public_key_share_succinct_proof_bytes_hash, succinct_public_key_share_accounting_hash,
    verify_evaluation_key_share,
};

pub(super) struct PublicKeyCommonBinding {
    pub(super) public_matrix_seed_hash: String,
    pub(super) public_key_crp_root: String,
    pub(super) public_a_polynomial_root: String,
}

struct PublicKeyShareBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    public_key_share_root: String,
    trustee_secret_commitment_root: String,
    same_secret_statement_root: String,
}

fn public_key_share_succinct_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "publicKeyShareSuccinctProof.proofMaterialRoot",
    )?;
    let chunks = transported_public_key_share_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        "public-key-share",
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_public_key_share_succinct_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        public_key_share_succinct_proof_material_root(proof_record, &transport_hashes)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

// Canonical transported proof material reference for one public-key share
// succinct proof. The succinct proof has no LNP relation commitment or tbox
// prefix, so the reference binds only the statement hash and proof byte
// identity, mirroring the same-secret anchor proof material reference.
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_material_root(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicKeyShareProofMaterialRoot",
        &json!({
            "objectType": "PublicKeyShareSuccinctProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "public-key-share",
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "statementHash": value_string(proof_record, "statementHash")?,
            "proofSizeBytes": value_u64(proof_record, "proofSizeBytes")?,
            "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

fn verify_public_key_share_succinct_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofChunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofTotalByteLength must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofSizeBytes must match transported proof byte length",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "public-key share succinct proofChunkHashes[{chunk_index}] must be a hash string"
                ),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("publicKeyShareSuccinctProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_public_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedPublicKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial was required by transported public-key share succinct proof records",
            )
        })?;
    verify_transported_public_key_share_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_public_key_share_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            transported_public_key_share_proof_chunks(proof_material)?
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                PUBLIC_KEY_SHARE_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedPublicKeyShareProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            PUBLIC_KEY_SHARE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_public_key_share_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_public_key_share_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_public_key_share_proof_material_set_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transportedPublicKeyShareProofMaterial contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        (
            "objectType",
            PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transportedPublicKeyShareProofMaterial.{field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_public_key_share_proof_material_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_public_key_share_proof_material_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transported public-key share succinct proof material contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported public-key share succinct proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedPublicKeyShareProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_public_key_share_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share succinct proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if let Some(unexpected_field) =
            unexpected_transported_public_key_share_proof_chunk_field(chunk_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported public-key share succinct proof chunk contains unexpected field {unexpected_field}"
                ),
            ));
        }
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share succinct proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_public_key_share_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share succinct proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}

fn unexpected_transported_public_key_share_proof_material_set_field(
    value: &Value,
) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterials",
        ],
    )
}

fn unexpected_transported_public_key_share_proof_material_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterialRoot",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ],
    )
}

fn unexpected_transported_public_key_share_proof_chunk_field(value: &Value) -> Option<String> {
    unexpected_field(value, &["chunkIndex", "bytesHex"])
}

pub(super) fn verify_public_key_shares(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(share_set) = setup_package.get("publicKeyShares") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !share_set.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeySharesNotObject",
            "publicKeyShares must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShares",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_set_field(share_set) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetUnexpectedField",
            format!("publicKeyShares contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShares.{unexpected_field}"),
        )?));
    }
    if share_set.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetTypeMismatch",
            "publicKeyShares.objectType must be PublicKeyShareSet",
            "setupPackage.publicKeyShares.objectType",
        )?));
    }
    if share_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetVersionMismatch",
            "publicKeyShares.objectVersion must be 1",
            "setupPackage.publicKeyShares.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(share_set, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShares",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofBindingStatus", "public-key-share-proof-required"),
    ] {
        if share_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetProfileMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if share_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetCountMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        share_set,
        &common_binding,
        "publicKeyShares",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if share_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretRootMismatch",
            "publicKeyShares.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShares.sameSecretConsistencyRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(share_records) = share_set.get("shareRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if share_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCountMismatch",
            "publicKeyShares.shareRecords must contain one share per trustee",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut public_key_share_roots = Vec::new();
    for share_record in share_records {
        if let Some(response) = verify_public_key_share_record(
            share_record,
            setup_context,
            &expected_trustees,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
        public_key_share_roots.push(json!({
            "trusteeIdentity": value_string(share_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(share_record, "trusteeRosterPosition")?,
            "publicKeyShareRoot": value_string(share_record, "publicKeyShareRoot")?,
        }));
    }
    if share_set.get("publicKeyShareRoots") != Some(&Value::Array(public_key_share_roots)) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootListMismatch",
            "publicKeyShares.publicKeyShareRoots must match the ordered share records",
            "setupPackage.publicKeyShares.publicKeyShareRoots",
        )?));
    }

    let Some(public_key_share_set_root) = share_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.publicKeyShareSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_set_root,
        "publicKeyShares.publicKeyShareSetRoot",
    )?;
    let mut root_input = share_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share set object was checked")
        .remove("publicKeyShareSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_set_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetRootMismatch",
            "publicKeyShareSetRoot does not match the canonical public-key share set",
            "setupPackage.publicKeyShares.publicKeyShareSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_record(
    share_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !share_record.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareNotObject",
            "public-key share records must be objects",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_field(share_record) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareUnexpectedField",
            format!("public-key share contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShares.shareRecords.{unexpected_field}"),
        )?));
    }
    if share_record.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTypeMismatch",
            "public-key share objectType must be PublicKeyShare",
            "setupPackage.publicKeyShares.shareRecords.objectType",
        )?));
    }
    if share_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareVersionMismatch",
            "public-key share objectVersion must be 1",
            "setupPackage.publicKeyShares.shareRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(share_record, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareContextMismatch",
            error.message,
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("shareComponent", "component-zero-b_i"),
        ("proofBindingStatus", "public-key-share-proof-required"),
    ] {
        if share_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareProfileMismatch",
                format!("public-key share {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.shareRecords.{field_name}"),
            )?));
        }
    }
    if share_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRnsLimbCountMismatch",
            "public-key share rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShares.shareRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        share_record,
        common_binding,
        "publicKeyShares.shareRecords",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareDuplicate",
            "public-key share records must have distinct trustee roster positions",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if expected_trustees
        .get(&trustee_roster_position)
        .map(String::as_str)
        != Some(trustee_identity)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTrusteeMismatch",
            "public-key share trustee identity must match the accepted setup roster",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretMissing",
            "public-key share must reference an accepted same-secret statement",
            "setupPackage.publicKeyShares.shareRecords.trusteeRosterPosition",
        )?));
    };
    if same_secret_binding.trustee_identity != trustee_identity {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretTrusteeMismatch",
            "public-key share trustee must match the same-secret statement trustee",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    if share_record
        .get("trusteeSecretCommitmentRoot")
        .and_then(Value::as_str)
        != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || share_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretBindingMismatch",
            "public-key share must bind the accepted trustee secret and same-secret statement roots",
            "setupPackage.publicKeyShares.shareRecords.sameSecretStatementRoot",
        )?));
    }
    if let Some(response) = verify_public_key_share_limb_hashes(
        share_record
            .get("shareCoefficientVectorHash512ByLimb")
            .and_then(Value::as_array),
    )? {
        return Ok(Some(response));
    }

    let Some(public_key_share_root) = share_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.publicKeyShareRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_root,
        "publicKeyShares.shareRecords.publicKeyShareRoot",
    )?;
    let mut root_input = share_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share object was checked")
        .remove("publicKeyShareRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootMismatch",
            "publicKeyShareRoot does not match the canonical public-key share",
            "setupPackage.publicKeyShares.shareRecords.publicKeyShareRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_public_key_share_proofs(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("publicKeyShareProofs") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !proof_set.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofsNotObject",
            "publicKeyShareProofs must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_proof_set_field(proof_set) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetUnexpectedField",
            format!("publicKeyShareProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetTypeMismatch",
            "publicKeyShareProofs.objectType must be PublicKeyShareProofSet",
            "setupPackage.publicKeyShareProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetVersionMismatch",
            "publicKeyShareProofs.objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            "succinct-proof-verification-pending",
        ),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetProfileMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetCountMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        proof_set,
        &common_binding,
        "publicKeyShareProofs",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretRootMismatch",
            "publicKeyShareProofs.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShareProofs.sameSecretConsistencyRoot",
        )?));
    }
    let public_key_share_set_root = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSetRoot was required before public-key share proof verification",
            )
        })?;
    if proof_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
        != Some(public_key_share_set_root)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareSetRootMismatch",
            "publicKeyShareProofs.publicKeyShareSetRoot must match publicKeyShares",
            "setupPackage.publicKeyShareProofs.publicKeyShareSetRoot",
        )?));
    }

    let share_bindings = public_key_share_bindings_from_package(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofCountMismatch",
            "publicKeyShareProofs.proofRecords must contain one proof statement per trustee",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut public_key_share_proof_roots = Vec::new();
    for proof_record in proof_records {
        if let Some(response) = verify_public_key_share_proof_record(
            proof_record,
            setup_context,
            &share_bindings,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
        public_key_share_proof_roots.push(json!({
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "publicKeyShareProofRoot": value_string(proof_record, "publicKeyShareProofRoot")?,
        }));
    }
    if proof_set.get("publicKeyShareProofRoots")
        != Some(&Value::Array(public_key_share_proof_roots))
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRootListMismatch",
            "publicKeyShareProofs.publicKeyShareProofRoots must match the ordered proof records",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofRoots",
        )?));
    }

    let Some(public_key_share_proof_set_root) = proof_set
        .get("publicKeyShareProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.publicKeyShareProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_proof_set_root,
        "publicKeyShareProofs.publicKeyShareProofSetRoot",
    )?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof set object was checked")
        .remove("publicKeyShareProofSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if public_key_share_proof_set_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetRootMismatch",
            "publicKeyShareProofSetRoot does not match the canonical public-key share proof set",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofSetRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_optional_public_key_share_succinct_proofs(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let material_set = setup_package.get("publicKeyShareMaterial");
    let proof_set = setup_package.get("publicKeyShareSuccinctProofs");
    if material_set.is_none() && proof_set.is_none() {
        return Ok(None);
    }
    let Some(material_set) = material_set else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(proof_set) = proof_set else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareSuccinctProofs".to_string()],
            Vec::new(),
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
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if setup_package.get("sameSecretProofs").is_none() {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    let same_secret_proof_set_root = same_secret_proof_set_root_from_package(setup_package)?;
    let same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
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
    let public_key_share_proof_set_root = setup_package
        .get("publicKeyShareProofs")
        .and_then(|root_set| root_set.get("publicKeyShareProofSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareProofSetRoot was required before public-key share succinct proof verification",
            )
        })?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let proof_records = public_key_share_proof_records_by_roster_position(setup_package)?;
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    if public_key_share_material_uses_transport(material_set)
        && request.get("transportedPublicKeyShareMaterial").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
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
            return Ok(Some(public_key_share_succinct_proof_refusal(
                "publicKeyShareMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    if !proof_set.is_object() {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetNotObject",
            "publicKeyShareSuccinctProofs must be a root-bound object",
            "setupPackage.publicKeyShareSuccinctProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_succinct_proof_set_field(proof_set)
    {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetUnexpectedField",
            format!("publicKeyShareSuccinctProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareSuccinctProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetTypeMismatch",
            "publicKeyShareSuccinctProofs.objectType must be PublicKeyShareSuccinctProofSet",
            "setupPackage.publicKeyShareSuccinctProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetVersionMismatch",
            "publicKeyShareSuccinctProofs.objectVersion must be 1",
            "setupPackage.publicKeyShareSuccinctProofs.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShareSuccinctProofs",
        )?));
    }
    let expected_accounting_hash = succinct_public_key_share_accounting_hash()?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", PUBLIC_KEY_SHARE_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        ),
        (
            "proofModelStatus",
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        ),
        ("proofAccountingHash", expected_accounting_hash.as_str()),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_succinct_proof_refusal(
                "publicKeyShareSuccinctProofSetProfileMismatch",
                format!("publicKeyShareSuccinctProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareSuccinctProofs.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_succinct_proof_refusal(
                "publicKeyShareSuccinctProofSetCountMismatch",
                format!("publicKeyShareSuccinctProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareSuccinctProofs.{field_name}"),
            )?));
        }
    }
    if proof_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || proof_set.get("publicKeyCrpRoot").and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || proof_set
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
        || proof_set
            .get("sameSecretConsistencyRoot")
            .and_then(Value::as_str)
            != Some(same_secret_consistency_root.as_str())
        || proof_set
            .get("sameSecretProofSetRoot")
            .and_then(Value::as_str)
            != Some(same_secret_proof_set_root.as_str())
        || proof_set
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(same_secret_proof_family_binding_root.as_str())
        || proof_set
            .get("publicKeyShareSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_set_root)
        || proof_set
            .get("publicKeyShareProofSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_proof_set_root)
        || proof_set
            .get("publicKeyShareMaterialSetRoot")
            .and_then(Value::as_str)
            != material_set
                .get("publicKeyShareMaterialSetRoot")
                .and_then(Value::as_str)
    {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetBindingMismatch",
            "publicKeyShareSuccinctProofs must bind accepted public randomness, same-secret, share, proof, and material roots",
            "setupPackage.publicKeyShareSuccinctProofs",
        )?));
    }
    let Some(proof_records_array) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareSuccinctProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records_array.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofCountMismatch",
            "publicKeyShareSuccinctProofs.proofRecords must contain one proof per trustee",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        )?));
    }
    let verification_context = PublicKeyShareSuccinctProofVerificationContext {
        setup_package,
        request,
        setup_context,
        public_matrix_seed_hash,
        share_records: &share_records,
        public_key_share_proof_records: &proof_records,
        same_secret_records: &same_secret_records,
        same_secret_proof_bindings: &same_secret_proof_bindings,
        material_bindings: &material_bindings,
        transported_constant_commitments: &transported_constant_commitments,
    };
    let mut seen_roster_positions = BTreeSet::new();
    let mut proof_roots = Vec::new();
    for succinct_proof_record in proof_records_array {
        if let Err(error) = verify_public_key_share_succinct_proof_record(
            &verification_context,
            succinct_proof_record,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(public_key_share_succinct_proof_refusal(
                "publicKeyShareSuccinctProofVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
            )?));
        }
        proof_roots.push(json!({
            "trusteeIdentity": value_string(succinct_proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(succinct_proof_record, "trusteeRosterPosition")?,
            "publicKeyShareSuccinctProofRoot": value_string(
                succinct_proof_record,
                "publicKeyShareSuccinctProofRoot",
            )?,
        }));
    }
    if proof_set.get("publicKeyShareSuccinctProofRoots") != Some(&Value::Array(proof_roots)) {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofRootListMismatch",
            "publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofRoots must match the ordered proof records",
            "setupPackage.publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofRoots",
        )?));
    }
    let Some(succinct_proof_set_root) = proof_set
        .get("publicKeyShareSuccinctProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        succinct_proof_set_root,
        "publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot",
    )?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share succinct proof set object was checked")
        .remove("publicKeyShareSuccinctProofSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if succinct_proof_set_root != expected_root {
        return Ok(Some(public_key_share_succinct_proof_refusal(
            "publicKeyShareSuccinctProofSetRootMismatch",
            "publicKeyShareSuccinctProofSetRoot does not match the canonical public-key share succinct proof set",
            "setupPackage.publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_public_key_material_acceptance_boundary(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in ["bgvPublicKey", "bgvPublicKeyRoot"] {
        if setup_package.get(field_name).is_some() {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyMaterialBeforeProofVerification",
                "raw BGV public-key material is not accepted until accepted public-key proof-byte verifiers pass",
                format!("setupPackage.{field_name}"),
            )?));
        }
    }

    Ok(None)
}

struct PublicKeyShareSuccinctProofVerificationContext<'a> {
    setup_package: &'a Value,
    request: &'a Value,
    setup_context: &'a Value,
    public_matrix_seed_hash: &'a str,
    share_records: &'a BTreeMap<u64, Value>,
    public_key_share_proof_records: &'a BTreeMap<u64, Value>,
    same_secret_records: &'a BTreeMap<u64, Value>,
    same_secret_proof_bindings: &'a BTreeMap<u64, SameSecretProofBinding>,
    material_bindings: &'a BTreeMap<u64, PublicKeyShareMaterialBinding>,
    transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
}

fn verify_public_key_share_succinct_proof_record(
    context: &PublicKeyShareSuccinctProofVerificationContext<'_>,
    proof_record: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof records must be objects",
        ));
    }
    if let Some(unexpected_field) =
        unexpected_public_key_share_succinct_proof_record_field(proof_record)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("public-key share succinct proof contains unexpected field {unexpected_field}"),
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
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof objectVersion must be 1",
        ));
    }
    verify_same_secret_context(proof_record, context.setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", PUBLIC_KEY_SHARE_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        ),
        (
            "proofModelStatus",
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
        ),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public-key share succinct proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
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
    let public_key_share_proof_record = context
        .public_key_share_proof_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proof must reference an accepted public-key proof statement",
            )
        })?;
    let same_secret_record = context
        .same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proof must reference an accepted same-secret statement",
            )
        })?;
    let same_secret_proof_binding = context
        .same_secret_proof_bindings
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proof must reference a verified same-secret proof",
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
    for field_name in [
        "trusteeIdentity",
        "publicKeyShareRoot",
        "sameSecretStatementRoot",
        "trusteeSecretCommitmentRoot",
    ] {
        if proof_record.get(field_name) != public_key_share_proof_record.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "public-key share succinct proof {field_name} must match the proof statement"
                ),
            ));
        }
    }
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(material_binding.public_key_share_root.as_str())
        || proof_record
            .get("publicKeyShareMaterialRoot")
            .and_then(Value::as_str)
            != Some(material_binding.public_key_share_material_root.as_str())
        || proof_record.get("publicKeyShareProofRoot")
            != public_key_share_proof_record.get("publicKeyShareProofRoot")
        || proof_record.get("sameSecretStatementRoot")
            != same_secret_record.get("sameSecretStatementRoot")
        || proof_record.get("trusteeSecretCommitmentRoot")
            != same_secret_record.get("trusteeSecretCommitmentRoot")
        || proof_record.get("trusteeIdentity") != same_secret_record.get("trusteeIdentity")
        || proof_record.get("trusteeIdentity") != share_record.get("trusteeIdentity")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share succinct proof must bind the accepted share, proof statement, material, and same-secret roots",
        ));
    }
    if proof_record
        .get("sameSecretProofRoot")
        .and_then(Value::as_str)
        != Some(same_secret_proof_binding.same_secret_proof_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .same_secret_statement_root
                    .as_str(),
            )
        || proof_record
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .same_secret_proof_family_binding_root
                    .as_str(),
            )
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .trustee_secret_commitment_root
                    .as_str(),
            )
        || proof_record.get("trusteeIdentity").and_then(Value::as_str)
            != Some(same_secret_proof_binding.trustee_identity.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share succinct proof must bind the verified same-secret proof root",
        ));
    }
    let proof_bytes =
        public_key_share_succinct_proof_bytes_from_record(proof_record, context.request)?;
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share succinct proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofSizeBytes must match supplied proof bytes",
        ));
    }
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    if proof_bytes_hash != public_key_share_succinct_proof_bytes_hash(&proof_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofBytesHash must match supplied proof bytes",
        ));
    }
    // The pk relation opens exactly the limb-zero accepted BDLOP constant
    // commitment, the same commitment the same-secret linkage anchor verified,
    // so the proven share secret is provably the committed trustee secret.
    let mut constant_commitments = same_secret_constant_commitment_values_from_material(
        context.setup_package,
        trustee_roster_position,
        context.transported_constant_commitments,
    )?;
    if constant_commitments.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proof requires the limb-zero constant commitment opening",
        ));
    }
    let limb_zero_commitment = constant_commitments.remove(0);
    let ring_degree = limb_zero_commitment.ring_degree;
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
                    "sameSecretStatementRoot".to_string(),
                    same_secret_proof_binding.same_secret_statement_root.clone(),
                ),
                (
                    "sameSecretProofRoot".to_string(),
                    same_secret_proof_binding.same_secret_proof_root.clone(),
                ),
            ],
        },
        ring_degree,
        keys: vec![EvaluationKeyShareDescriptor {
            kind: EvaluationKeyShareKind::PublicKeyShare,
            level: DATA_PRIMES.len() - 1,
            key_switch_domain: PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL.to_string(),
            key_switch_seed_hex: context.public_matrix_seed_hash.to_string(),
            component_b_by_digit: vec![material_binding.coefficients_by_limb.clone()],
            round_one_aggregate_diagonal: Vec::new(),
        }],
        same_secret_linkage: Some(SameSecretLinkageStatement {
            public_matrix_seed_hash: context.public_matrix_seed_hash.to_string(),
            commitments: vec![limb_zero_commitment],
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
            "public-key share succinct proof statementHash must match the rebuilt statement",
        ));
    }
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let proof_root = value_string(proof_record, "publicKeyShareSuccinctProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share succinct proof record object was checked")
        .remove("publicKeyShareSuccinctProofRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if proof_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareSuccinctProofRoot does not match the canonical public-key share succinct proof record",
        ));
    }

    Ok(())
}

pub(super) fn public_key_share_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShares.shareRecords were required before public-key share succinct proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, share_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn public_key_share_proof_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let proof_records = setup_package
        .get("publicKeyShareProofs")
        .and_then(|proof_set| proof_set.get("proofRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareProofs.proofRecords were required before public-key share succinct proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for proof_record in proof_records {
        let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, proof_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share proof records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn verify_public_key_share_proof_record(
    proof_record: &Value,
    setup_context: &Value,
    share_bindings: &BTreeMap<u64, PublicKeyShareBinding>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !proof_record.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofNotObject",
            "public-key share proof records must be objects",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_proof_field(proof_record) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofUnexpectedField",
            format!("public-key share proof contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareProofs.proofRecords.{unexpected_field}"),
        )?));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTypeMismatch",
            "public-key share proof objectType must be PublicKeyShareProof",
            "setupPackage.publicKeyShareProofs.proofRecords.objectType",
        )?));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofVersionMismatch",
            "public-key share proof objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.proofRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(proof_record, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            "succinct-proof-verification-pending",
        ),
        (
            "errorSupport",
            "checked-by-public-key-share-succinct-proof-set",
        ),
        (
            "proofBytesStatus",
            "supplied-by-public-key-share-succinct-proof-set",
        ),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofProfileMismatch",
                format!("public-key share proof {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.proofRecords.{field_name}"),
            )?));
        }
    }
    if proof_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRnsLimbCountMismatch",
            "public-key share proof rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShareProofs.proofRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        proof_record,
        common_binding,
        "publicKeyShareProofs.proofRecords",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(proof_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofDuplicate",
            "public-key share proof records must have distinct trustee roster positions",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let Some(share_binding) = share_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareMissing",
            "public-key share proof must reference an accepted public-key share",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretMissing",
            "public-key share proof must reference an accepted same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    if share_binding.trustee_roster_position != trustee_roster_position
        || share_binding.trustee_identity != trustee_identity
        || same_secret_binding.trustee_identity != trustee_identity
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTrusteeMismatch",
            "public-key share proof trustee must match the accepted share and same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeIdentity",
        )?));
    }
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(share_binding.public_key_share_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(share_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(share_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofBindingMismatch",
            "public-key share proof must bind the accepted share, trustee secret, and same-secret roots",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareRoot",
        )?));
    }

    let Some(public_key_share_proof_root) = proof_record
        .get("publicKeyShareProofRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.proofRecords.publicKeyShareProofRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_proof_root,
        "publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
    )?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof object was checked")
        .remove("publicKeyShareProofRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if public_key_share_proof_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRootMismatch",
            "publicKeyShareProofRoot does not match the canonical public-key share proof statement",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_limb_hashes(
    limb_values: Option<&Vec<Value>>,
) -> CanonicalResult<Option<Value>> {
    let Some(limb_values) = limb_values else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if limb_values.len() != DATA_PRIMES.len() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCoefficientLimbCountMismatch",
            "public-key share must bind one coefficient hash for every Q_share limb",
            "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
        )?));
    }
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let limb_value = &limb_values[rns_limb_index];
        if limb_value.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || limb_value.get("rnsPrime").and_then(Value::as_u64) != Some(rns_prime)
            || limb_value.get("component").and_then(Value::as_str) != Some("b_i")
        {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareCoefficientLimbMismatch",
                "public-key share coefficient hash entries must follow Q_share order",
                "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
            )?));
        }
        let Some(hash) = limb_value
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("publicKeyShareProofs"),
                vec![
                    "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512"
                        .to_string(),
                ],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512",
        )?;
    }

    Ok(None)
}

pub(super) fn public_key_common_binding(
    setup_package: &Value,
) -> CanonicalResult<PublicKeyCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before public-key share verification",
        )
    })?;
    let public_derivations = common_randomness.get("publicDerivations").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations was required before public-key share verification",
        )
    })?;
    Ok(PublicKeyCommonBinding {
        public_matrix_seed_hash: value_string(common_randomness, "publicMatrixSeedHash")?
            .to_string(),
        public_key_crp_root: public_derivations
            .get("crpRoots")
            .and_then(|crp_roots| crp_roots.get("publicKeyCrpRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public-key CRP root was required before public-key share verification",
                )
            })?
            .to_string(),
        public_a_polynomial_root: public_derivations
            .get("bgvPublicA")
            .and_then(|public_a| public_a.get("publicPolynomialRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "BGV public a root was required before public-key share verification",
                )
            })?
            .to_string(),
    })
}

#[derive(Clone, Copy)]
enum PublicKeyRefusalKind {
    Share,
    Proof,
}

fn verify_public_key_common_fields(
    value: &Value,
    common_binding: &PublicKeyCommonBinding,
    object_path: &str,
    refusal_kind: PublicKeyRefusalKind,
) -> CanonicalResult<Option<Value>> {
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            common_binding.public_matrix_seed_hash.as_str(),
        ),
        (
            "publicKeyCrpRoot",
            common_binding.public_key_crp_root.as_str(),
        ),
        (
            "publicAPolynomialRoot",
            common_binding.public_a_polynomial_root.as_str(),
        ),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            let message =
                format!("{object_path}.{field_name} must match accepted common randomness");
            let path = format!("setupPackage.{object_path}.{field_name}");
            return Ok(Some(match refusal_kind {
                PublicKeyRefusalKind::Share => {
                    public_key_share_refusal("publicKeyShareCommonBindingMismatch", message, path)?
                }
                PublicKeyRefusalKind::Proof => public_key_share_proof_refusal(
                    "publicKeyShareCommonBindingMismatch",
                    message,
                    path,
                )?,
            }));
        }
    }

    Ok(None)
}

fn public_key_share_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareBinding>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records were required before public-key share proof verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if bindings
            .insert(
                trustee_roster_position,
                PublicKeyShareBinding {
                    trustee_identity: value_string(share_record, "trusteeIdentity")?.to_string(),
                    trustee_roster_position,
                    public_key_share_root: value_string(share_record, "publicKeyShareRoot")?
                        .to_string(),
                    trustee_secret_commitment_root: value_string(
                        share_record,
                        "trusteeSecretCommitmentRoot",
                    )?
                    .to_string(),
                    same_secret_statement_root: value_string(
                        share_record,
                        "sameSecretStatementRoot",
                    )?
                    .to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn unexpected_public_key_share_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofBindingStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "publicKeyShareRoots",
            "shareRecords",
            "publicKeyShareSetRoot",
        ],
    )
}

fn unexpected_public_key_share_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "shareComponent",
            "rnsLimbCount",
            "shareCoefficientVectorHash512ByLimb",
            "proofBindingStatus",
            "publicKeyShareRoot",
        ],
    )
}

fn unexpected_public_key_share_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofRoots",
            "proofRecords",
            "publicKeyShareProofSetRoot",
        ],
    )
}

fn unexpected_public_key_share_proof_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "rnsLimbCount",
            "errorSupport",
            "proofBytesStatus",
            "publicKeyShareProofRoot",
        ],
    )
}

fn unexpected_public_key_share_succinct_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "proofAccountingHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofSetRoot",
            "publicKeyShareMaterialSetRoot",
            "publicKeyShareSuccinctProofRoots",
            "proofRecords",
            "publicKeyShareSuccinctProofSetRoot",
        ],
    )
}

fn unexpected_public_key_share_succinct_proof_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicKeyShareRoot",
            "publicKeyShareProofRoot",
            "publicKeyShareMaterialRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "sameSecretProofRoot",
            "statementHash",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "proofBytesHex",
            "publicKeyShareSuccinctProofRoot",
        ],
    )
}

fn public_key_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn public_key_share_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn public_key_share_succinct_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
