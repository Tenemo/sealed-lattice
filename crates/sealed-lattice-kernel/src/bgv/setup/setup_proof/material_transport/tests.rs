use super::*;

// Stream one proof-material buffer through begin/absorb/finish under
// `verification_id`, returning the chunkless transported reference (for the
// metadata comparison the recovery path performs) and the verified handle the
// store keys by verificationId.
fn stream_and_verify_setup_proof_material(
    proof_family: &str,
    proof_bytes: &[u8],
    proof_material_root: &str,
    verification_id: &str,
) -> (Value, Value) {
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        proof_bytes,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("setup proof material transport hashes");
    let transported_proof_material = json!({
        "objectType": "SetupTransportedProofMaterial",
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    });
    begin_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
        "transportedSetupProofMaterial": transported_proof_material.clone(),
    }))
    .expect("begin setup proof material stream");
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size");
    for (chunk_index, chunk) in proof_bytes.chunks(chunk_size).enumerate() {
        absorb_setup_proof_material_transport_stream_chunk_request(&json!({
            "verificationId": verification_id,
            "chunkIndex": chunk_index,
            "bytesHex": to_hex(chunk),
        }))
        .expect("absorb setup proof material chunk");
    }
    let finished = finish_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
    }))
    .expect("finish setup proof material stream");

    (
        transported_proof_material,
        finished["verifiedSetupProofMaterial"].clone(),
    )
}

fn request_with_verified_materials(handles: &[Value]) -> Value {
    json!({
        "verifiedSetupProofMaterials": {
            "objectType": VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE,
            "proofMaterials": handles,
        },
    })
}

#[test]
fn setup_proof_material_stream_handle_recovers_chunkless_material() {
    let proof_family = "same-secret-bridge";
    let proof_bytes = b"bounded setup proof material".to_vec();
    let proof_material_root = valid_hash_for_test('7');
    let (transported_proof_material, verified_setup_proof_material) =
        stream_and_verify_setup_proof_material(
            proof_family,
            &proof_bytes,
            &proof_material_root,
            "same-secret-handle-test",
        );
    let request = request_with_verified_materials(&[verified_setup_proof_material]);

    let recovered_bytes = verified_setup_proof_material_bytes_from_request(
        &request,
        proof_family,
        &proof_material_root,
        &transported_proof_material,
        "transportedSameSecretBridgeProofMaterial.proofMaterials[0]",
    )
    .expect("verified setup proof material bytes");

    assert_eq!(recovered_bytes.as_ref(), &proof_bytes);
}

#[test]
fn setup_proof_material_stream_handle_rejects_metadata_rebinding() {
    let proof_family = "public-key-share";
    let proof_bytes = b"public-key proof bytes".to_vec();
    let proof_material_root = valid_hash_for_test('8');
    let (mut transported_proof_material, verified_setup_proof_material) =
        stream_and_verify_setup_proof_material(
            proof_family,
            &proof_bytes,
            &proof_material_root,
            "public-key-handle-rebinding-test",
        );
    let request = request_with_verified_materials(&[verified_setup_proof_material]);
    transported_proof_material["fullObjectHash"] = json!(valid_hash_for_test('9'));

    let error = verified_setup_proof_material_bytes_from_request(
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
    let proof_bytes = b"trustee evaluation key proof bytes".to_vec();
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family,
        &proof_bytes,
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

#[test]
fn setup_proof_material_eviction_guard_scopes_to_requested_materials() {
    let proof_family = "same-secret-bridge";
    let referenced_root = valid_hash_for_test('c');
    let unreferenced_root = valid_hash_for_test('d');
    let referenced_bytes = b"referenced setup proof material".to_vec();
    let unreferenced_bytes = b"unreferenced setup proof material".to_vec();
    let (referenced_material, referenced_handle) = stream_and_verify_setup_proof_material(
        proof_family,
        &referenced_bytes,
        &referenced_root,
        "eviction-scope-referenced",
    );
    let (unreferenced_material, unreferenced_handle) = stream_and_verify_setup_proof_material(
        proof_family,
        &unreferenced_bytes,
        &unreferenced_root,
        "eviction-scope-unreferenced",
    );

    // Arm the guard for a request that references only the first material, then
    // let it drop the way verify returns.
    let request = request_with_verified_materials(std::slice::from_ref(&referenced_handle));
    drop(VerifiedSetupProofMaterialEvictionGuard::for_request(
        &request,
    ));

    // The referenced material was evicted, so its handle no longer resolves.
    let referenced_request = request_with_verified_materials(&[referenced_handle]);
    let error = verified_setup_proof_material_bytes_from_request(
        &referenced_request,
        proof_family,
        &referenced_root,
        &referenced_material,
        "verifiedSetupProofMaterials.proofMaterials[0]",
    )
    .expect_err("evicted material must not resolve");
    assert!(
        error
            .message
            .contains("does not match a live stream-verified material"),
        "unexpected error: {}",
        error.message
    );

    // The second material was outside the request's scope, so eviction left it in
    // place and it still resolves to its bytes.
    let unreferenced_request = request_with_verified_materials(&[unreferenced_handle]);
    let recovered = verified_setup_proof_material_bytes_from_request(
        &unreferenced_request,
        proof_family,
        &unreferenced_root,
        &unreferenced_material,
        "verifiedSetupProofMaterials.proofMaterials[0]",
    )
    .expect("unreferenced material still resolves");
    assert_eq!(recovered.as_ref(), &unreferenced_bytes);
}

#[test]
fn setup_proof_material_verification_id_reusable_after_eviction() {
    let proof_family = "public-key-share";
    let proof_material_root = valid_hash_for_test('e');
    let verification_id = "restream-after-eviction";
    let first_bytes = b"first stream proof bytes".to_vec();
    let (first_material, first_handle) = stream_and_verify_setup_proof_material(
        proof_family,
        &first_bytes,
        &proof_material_root,
        verification_id,
    );

    // A second begin under the same id is rejected while the store still holds the
    // verified material.
    let re_begin_before_eviction = begin_setup_proof_material_transport_stream_request(&json!({
        "verificationId": verification_id,
        "transportedSetupProofMaterial": first_material,
    }))
    .expect_err("re-begin before eviction must be rejected");
    assert!(
        re_begin_before_eviction
            .message
            .contains("already has verified material"),
        "unexpected error: {}",
        re_begin_before_eviction.message
    );

    // Evicting the request's material frees the id.
    let request = request_with_verified_materials(&[first_handle]);
    drop(VerifiedSetupProofMaterialEvictionGuard::for_request(
        &request,
    ));

    // The same id now streams fresh material and resolves to the new bytes, the
    // way the SDK re-streams a sequence-numbered id on every verify.
    let second_bytes = b"second stream proof bytes".to_vec();
    let (second_material, second_handle) = stream_and_verify_setup_proof_material(
        proof_family,
        &second_bytes,
        &proof_material_root,
        verification_id,
    );
    let request = request_with_verified_materials(&[second_handle]);
    let recovered = verified_setup_proof_material_bytes_from_request(
        &request,
        proof_family,
        &proof_material_root,
        &second_material,
        "verifiedSetupProofMaterials.proofMaterials[0]",
    )
    .expect("re-streamed material resolves");
    assert_eq!(recovered.as_ref(), &second_bytes);
}

fn valid_hash_for_test(character: char) -> String {
    character.to_string().repeat(128)
}
