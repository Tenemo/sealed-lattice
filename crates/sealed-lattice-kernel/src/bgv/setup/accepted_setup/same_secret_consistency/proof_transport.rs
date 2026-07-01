use super::*;

use crate::bgv::setup::setup_proof::{
    setup_proof_record_has_transport_reference, transported_setup_proof_material_chunks,
    verify_setup_proof_record_transport_reference, verify_transported_setup_proof_material_hashes,
};
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY;

pub(super) fn same_secret_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = setup_proof_record_has_transport_reference(proof_record);

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(proof_material_root, "sameSecretProof.proofMaterialRoot")?;
    let chunks = transported_same_secret_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_same_secret_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        same_secret_anchor_proof_material_root(proof_record, &transport_hashes)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

// No relation prefix is needed because statementHash already transcript-binds the family and ceremony; the material root only binds proof-byte identity.
pub(in crate::bgv::setup) fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretLinkageAnchorProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "statementHash": value_string(proof_record, "statementHash")?,
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_setup_proof_record_transport_reference(
        proof_record,
        transport_hashes,
        "same-secret",
        "same-secret",
        "sameSecretProof",
    )
}

fn transported_same_secret_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedSameSecretProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial was required by transported same-secret proof records",
            )
        })?;
    verify_transported_same_secret_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_same_secret_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            transported_same_secret_proof_chunks(proof_material)?
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedSameSecretProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_proof_material_hashes(proof_material, &transport_hashes)?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("transportedSameSecretProofMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_same_secret_proof_material_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported same-secret proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedSameSecretProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_same_secret_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    transported_setup_proof_material_chunks(
        value,
        "transported same-secret proof material",
        "transported same-secret proof",
    )
}

fn verify_transported_same_secret_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_transported_setup_proof_material_hashes(
        value,
        transport_hashes,
        "transported same-secret proof",
    )
}
