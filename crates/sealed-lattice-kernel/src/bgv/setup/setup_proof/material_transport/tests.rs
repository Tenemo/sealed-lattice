use super::*;

#[test]
fn setup_proof_material_stream_handle_recovers_chunkless_material() {
    let proof_family = "same-secret-linkage-anchor";
    let proof_chunks = vec![b"bounded setup proof material".to_vec()];
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        &proof_chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("setup proof material transport hashes");
    let proof_material_root = valid_hash_for_test('7');
    let transported_proof_material = json!({
        "objectType": "SetupTransportedSameSecretProofMaterial",
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    });
    let verification_id = "same-secret-handle-test";

    begin_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
        "transportedSetupProofMaterial": transported_proof_material.clone(),
    }))
    .expect("begin setup proof material stream");
    absorb_setup_proof_material_transport_stream_chunk_request(&json!({
        "verificationId": verification_id,
        "chunkIndex": 0,
        "bytesHex": to_hex(&proof_chunks[0]),
    }))
    .expect("absorb setup proof material chunk");
    let finished = finish_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
    }))
    .expect("finish setup proof material stream");
    let verified_setup_proof_material = finished["verifiedSetupProofMaterial"].clone();
    let request = json!({
        "verifiedSetupProofMaterials": {
            "objectType": VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE,
            "proofMaterials": [
                verified_setup_proof_material
            ],
        },
    });

    let recovered_chunks = verified_setup_proof_material_chunks_from_request(
        &request,
        proof_family,
        &proof_material_root,
        &transported_proof_material,
        "transportedSameSecretProofMaterial.proofMaterials[0]",
    )
    .expect("verified setup proof material chunks");

    assert_eq!(recovered_chunks.as_ref(), &proof_chunks);
}

#[test]
fn setup_proof_material_stream_handle_rejects_metadata_rebinding() {
    let proof_family = "public-key-share";
    let proof_chunks = vec![b"public-key proof bytes".to_vec()];
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        &proof_chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("setup proof material transport hashes");
    let proof_material_root = valid_hash_for_test('8');
    let mut transported_proof_material = json!({
        "objectType": "SetupTransportedPublicKeyShareProofMaterial",
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    });
    let verification_id = "public-key-handle-rebinding-test";

    begin_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
        "transportedSetupProofMaterial": transported_proof_material.clone(),
    }))
    .expect("begin setup proof material stream");
    absorb_setup_proof_material_transport_stream_chunk_request(&json!({
        "verificationId": verification_id,
        "chunkIndex": 0,
        "bytesHex": to_hex(&proof_chunks[0]),
    }))
    .expect("absorb setup proof material chunk");
    let finished = finish_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
    }))
    .expect("finish setup proof material stream");
    let request = json!({
        "verifiedSetupProofMaterials": {
            "objectType": VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE,
            "proofMaterials": [
                finished["verifiedSetupProofMaterial"].clone()
            ],
        },
    });
    transported_proof_material["fullObjectHash"] = json!(valid_hash_for_test('9'));

    let error = verified_setup_proof_material_chunks_from_request(
        &request,
        proof_family,
        &proof_material_root,
        &transported_proof_material,
        "transportedPublicKeyShareProofMaterial.proofMaterials[0]",
    )
    .expect_err("rebinding must fail");

    assert!(
        error
            .message
            .contains("does not match the canonical proof chunk manifest")
            || error
                .message
                .contains("metadata does not match the stream-verified setup proof material"),
        "unexpected error: {}",
        error.message
    );
}

#[test]
fn trustee_evaluation_key_transport_reference_uses_setup_proof_hashes() {
    let proof_family = "trustee-evaluation-key";
    let proof_chunks = vec![b"trustee evaluation key proof bytes".to_vec()];
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        &proof_chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("setup proof material transport hashes");
    let proof_material_root = valid_hash_for_test('a');
    let proof_record = json!({
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_material_root,
        "proofChunkCount": transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transport_hashes.total_byte_length,
        "proofFullObjectHash": transport_hashes.full_object_hash.clone(),
        "proofChunkRoot": transport_hashes.chunk_root.clone(),
        "proofChunkHashes": transport_hashes.chunk_hashes.clone(),
    });

    verify_setup_proof_record_transport_reference(
        &proof_record,
        &transport_hashes,
        "trustee evaluation-key proof",
        "trustee evaluation-key proof",
        "trusteeEvaluationKeyProof",
    )
    .expect("trustee evaluation-key proof transport reference");

    let mut tampered_record = proof_record;
    tampered_record["proofChunkHashes"] = json!([valid_hash_for_test('b')]);
    let error = verify_setup_proof_record_transport_reference(
        &tampered_record,
        &transport_hashes,
        "trustee evaluation-key proof",
        "trustee evaluation-key proof",
        "trusteeEvaluationKeyProof",
    )
    .expect_err("tampered trustee evaluation-key proof chunk hash must fail");

    assert!(
        error
            .message
            .contains("proofChunkHashes must match transported proof chunks"),
        "unexpected error: {}",
        error.message
    );
}

fn valid_hash_for_test(character: char) -> String {
    character.to_string().repeat(128)
}
