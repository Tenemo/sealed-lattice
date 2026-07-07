use super::*;

use crate::bgv::setup::setup_proof::{
    setup_proof_record_has_transport_reference, transported_setup_proof_material_chunks,
    verify_setup_proof_record_transport_reference, verify_transported_setup_proof_material_hashes,
};
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY;

pub(super) fn public_key_share_succinct_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = setup_proof_record_has_transport_reference(proof_record);

    // Embedded and transported proof bytes are mutually exclusive so a record cannot present one byte string for verification and bind a different one through the transport manifest.
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
        chunks.as_ref(),
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
    for chunk in chunks.iter() {
        proof_bytes.extend_from_slice(chunk);
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
    derive_canonical_object_hash(&json!({
        "objectType": "PublicKeyShareSuccinctProofMaterialReference",
        "proofFamily": "public-key-share",
        "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "statementHash": value_string(proof_record, "statementHash")?,
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

fn verify_public_key_share_succinct_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_setup_proof_record_transport_reference(
        proof_record,
        transport_hashes,
        "public-key share",
        "public-key share succinct",
        "publicKeyShareSuccinctProof",
    )
}

fn transported_public_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SetupProofMaterialChunks> {
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
            Arc::new(transported_public_key_share_proof_chunks(proof_material)?)
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
            chunks.as_ref(),
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
    for (field_name, expected_value) in [
        (
            "objectType",
            PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
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

    Ok(())
}

fn verify_transported_public_key_share_proof_material_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
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
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedPublicKeyShareProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_public_key_share_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    transported_setup_proof_material_chunks(
        value,
        "transported public-key share succinct proof material",
    )
}

fn verify_transported_public_key_share_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_transported_setup_proof_material_hashes(
        value,
        transport_hashes,
        "transported public-key share succinct proof",
    )
}
