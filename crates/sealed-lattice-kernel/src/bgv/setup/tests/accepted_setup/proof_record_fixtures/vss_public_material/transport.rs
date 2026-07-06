use super::commitment_sets::*;
use super::same_secret_bridge::*;
use super::share_linkage::*;
use super::*;

// Move every share-linkage proof record's proof bytes out of the
// embedded base64 field and onto the shared setup proof-material transport,
// returning the rewritten proof material set alongside the transported material
// object that carries the streamed chunks. Each record binds its proof record
// root to the transport reference fields instead of the base64 bytes, exactly
// as the kernel verifier rebuilds it, so a transported set verifies identically
// to the embedded set it replaces.
pub(in super::super::super) fn move_vss_share_linkage_proof_bytes_to_transport(
    proof_material_set: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("share-linkage proof records");
    let mut transported_proof_materials = Vec::new();
    for proof_record in proof_records.iter_mut() {
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_record["proofBytesBase64"]
                .as_str()
                .expect("embedded share-linkage proof bytes"),
            "share-linkage proofBytesBase64",
        )
        .expect("decode share-linkage proof bytes");
        let chunks = transport_chunks(&proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("share-linkage transport hashes");
        let proof_material_root = transport_proof_material_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            proof_record["proofBytesHash"]
                .as_str()
                .expect("proofBytesHash"),
            &transport_hashes,
        );

        let record_object = proof_record
            .as_object_mut()
            .expect("share-linkage proof record object");
        record_object.remove("proofBytesBase64");
        record_object.remove("proofRecordRoot");
        record_object.insert(
            "proofBytesEncoding".to_string(),
            serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING),
        );
        insert_transport_reference(record_object, &proof_material_root, &transport_hashes);
        proof_record["proofRecordRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record)
                .expect("share-linkage transported proof record root")
        );

        transported_proof_materials.push(transport_material_object(
            VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE,
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_material_root,
            &chunks,
            &transport_hashes,
        ));
    }

    rebind_proof_material_set_root(proof_material_set);

    serde_json::json!({
        "objectType": VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "proofMaterials": transported_proof_materials,
    })
}

// Move every same-secret bridge proof record's proof bytes onto the
// shared setup proof-material transport, mirroring the share-linkage helper.
pub(in super::super::super) fn move_same_secret_bridge_proof_bytes_to_transport(
    proof_material_set: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("same-secret bridge proof records");
    let mut transported_proof_materials = Vec::new();
    for proof_record in proof_records.iter_mut() {
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_record["proofBytesBase64"]
                .as_str()
                .expect("embedded same-secret bridge proof bytes"),
            "same-secret bridge proofBytesBase64",
        )
        .expect("decode same-secret bridge proof bytes");
        let chunks = transport_chunks(&proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("same-secret bridge transport hashes");
        let proof_material_root = transport_proof_material_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            proof_record["proofBytesHash"]
                .as_str()
                .expect("proofBytesHash"),
            &transport_hashes,
        );

        let record_object = proof_record
            .as_object_mut()
            .expect("same-secret bridge proof record object");
        record_object.remove("proofBytesBase64");
        record_object.remove("proofRecordRoot");
        record_object.insert(
            "proofBytesEncoding".to_string(),
            serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING),
        );
        insert_transport_reference(record_object, &proof_material_root, &transport_hashes);
        proof_record["proofRecordRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record)
                .expect("same-secret bridge transported proof record root")
        );

        transported_proof_materials.push(transport_material_object(
            SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_material_root,
            &chunks,
            &transport_hashes,
        ));
    }

    rebind_proof_material_set_root(proof_material_set);

    serde_json::json!({
        "objectType": SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "proofMaterials": transported_proof_materials,
    })
}

const VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterialSet";
const VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterial";
const SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterialSet";
const SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterial";

// Recompute a proof material set root over the canonical body. The
// verifier hashes the set with its proofMaterialSetRoot field absent, so the
// stale root must be removed before rehashing rather than left in place.
pub(super) fn rebind_proof_material_set_root(proof_material_set: &mut serde_json::Value) {
    proof_material_set
        .as_object_mut()
        .expect("proof material set object")
        .remove("proofMaterialSetRoot");
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(proof_material_set)
            .expect("transported proof material set root")
    );
}

// Split proof bytes into the uniform transport chunk size the kernel enforces.
// The development proofs are far smaller than one chunk, so this yields
// a single chunk, but the split is written for the general case.
pub(super) fn transport_chunks(proof_bytes: &[u8]) -> Vec<Vec<u8>> {
    let chunk_size =
        usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size fits usize");
    if proof_bytes.is_empty() {
        return vec![Vec::new()];
    }
    proof_bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

pub(super) fn transport_proof_material_root(
    proof_family: &str,
    proof_bytes_hash: &str,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": proof_family,
        "proofBytesHash": proof_bytes_hash,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
    .expect("transport proof material root")
}

pub(super) fn insert_transport_reference(
    record_object: &mut serde_json::Map<String, serde_json::Value>,
    proof_material_root: &str,
    transport_hashes: &SetupProofMaterialTransportHashes,
) {
    record_object.insert(
        "proofMaterialRoot".to_string(),
        serde_json::json!(proof_material_root),
    );
    record_object.insert(
        "proofChunkSizeBytes".to_string(),
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES),
    );
    record_object.insert(
        "proofChunkCount".to_string(),
        serde_json::json!(transport_hashes.chunk_hashes.len()),
    );
    record_object.insert(
        "proofTotalByteLength".to_string(),
        serde_json::json!(transport_hashes.total_byte_length),
    );
    record_object.insert(
        "proofFullObjectHash".to_string(),
        serde_json::json!(transport_hashes.full_object_hash),
    );
    record_object.insert(
        "proofChunkRoot".to_string(),
        serde_json::json!(transport_hashes.chunk_root),
    );
    record_object.insert(
        "proofChunkHashes".to_string(),
        serde_json::json!(transport_hashes.chunk_hashes),
    );
}

pub(super) fn transport_material_object(
    object_type: &str,
    proof_family: &str,
    proof_material_root: &str,
    chunks: &[Vec<u8>],
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> serde_json::Value {
    let chunk_entries = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesBase64": crate::transcript_core::encode_standard_base64(chunk),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "objectType": object_type,
        "objectVersion": 1,
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunks": chunk_entries,
    })
}

// Assert two proof-material-set verification responses accept and agree
// on every verified field except the proof material set root, which binds the
// per-record proof-bytes encoding and so legitimately differs between the
// embedded and transported forms.
pub(super) fn assert_semantically_identical_verification(
    embedded: &serde_json::Value,
    transported: &serde_json::Value,
) {
    assert_eq!(
        embedded["ok"],
        serde_json::json!(true),
        "embedded verification must accept"
    );
    assert_eq!(
        transported["ok"],
        serde_json::json!(true),
        "transported verification must accept"
    );
    let mut embedded_without_root = embedded.clone();
    let mut transported_without_root = transported.clone();
    for response in [&mut embedded_without_root, &mut transported_without_root] {
        response
            .as_object_mut()
            .expect("verification response object")
            .remove("proofMaterialSetRoot");
    }
    assert_eq!(
        embedded_without_root, transported_without_root,
        "embedded and transported verifications must agree on every field except the proof material set root"
    );
}

#[test]
fn vss_share_linkage_transported_proof_material_matches_embedded() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    let embedded_proof_material_set = vss_share_linkage_proof_material_set_object(&package);

    let embedded_verification =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": embedded_proof_material_set,
            }),
        )
        .expect("embedded share-linkage proof material set verifies");

    let mut transported_proof_material_set = embedded_proof_material_set.clone();
    let transported_material =
        move_vss_share_linkage_proof_bytes_to_transport(&mut transported_proof_material_set);

    let transported_verification =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedVssShareLinkageProofMaterial": transported_material,
            }),
        )
        .expect("transported share-linkage proof material set verifies");

    // The transported and embedded forms both accept and agree on every verified
    // semantic field. The proof material set root legitimately differs because it
    // canonically binds the record encoding: an embedded record carries base64
    // proof bytes while a transported record carries the transport reference, and
    // the verifier recomputes the root from the encoding it was given. So the
    // transported verification's root binds the transported set it was given, not
    // the embedded set's root.
    assert_semantically_identical_verification(&embedded_verification, &transported_verification);
    assert_eq!(
        transported_verification["proofMaterialSetRoot"],
        transported_proof_material_set["proofMaterialSetRoot"],
        "transported verification must recompute the transported proof material set root"
    );
    assert_ne!(
        transported_verification["proofMaterialSetRoot"],
        embedded_verification["proofMaterialSetRoot"],
        "the transported record encoding must give a distinct proof material set root"
    );

    // A transported record with no supplied transport material must be refused.
    assert!(
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
            }),
        )
        .is_err(),
        "transported share-linkage records must require transported proof material"
    );

    // Tampering with a transported chunk hash must be rejected.
    let mut tampered_material =
        move_vss_share_linkage_proof_bytes_to_transport(&mut embedded_proof_material_set.clone());
    tampered_material["proofMaterials"][0]["chunkHashes"][0] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedVssShareLinkageProofMaterial": tampered_material,
            }),
        )
        .is_err(),
        "tampered transported share-linkage chunk hash must be rejected"
    );
}

#[test]
fn same_secret_bridge_transported_proof_material_matches_embedded() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    let embedded_proof_material_set = same_secret_bridge_proof_material_set_object(&package, None);

    let embedded_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "sameSecretConsistency": package["sameSecretConsistency"],
        "sameSecretProofs": package["sameSecretProofs"],
        "proofMaterialSet": embedded_proof_material_set,
    });
    let embedded_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &embedded_request,
        )
        .expect("embedded same-secret bridge proof material set verifies");

    let mut transported_proof_material_set = embedded_proof_material_set.clone();
    let transported_material =
        move_same_secret_bridge_proof_bytes_to_transport(&mut transported_proof_material_set);

    let transported_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedSameSecretBridgeProofMaterial": transported_material,
            }),
        )
        .expect("transported same-secret bridge proof material set verifies");

    // As with share-linkage, both forms accept and agree on every verified
    // semantic field; only the proof material set root legitimately differs
    // because it canonically binds the per-record proof-bytes encoding.
    assert_semantically_identical_verification(&embedded_verification, &transported_verification);
    assert_eq!(
        transported_verification["proofMaterialSetRoot"],
        transported_proof_material_set["proofMaterialSetRoot"],
        "transported verification must recompute the transported proof material set root"
    );
    assert_ne!(
        transported_verification["proofMaterialSetRoot"],
        embedded_verification["proofMaterialSetRoot"],
        "the transported record encoding must give a distinct proof material set root"
    );

    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
            }),
        )
        .is_err(),
        "transported same-secret bridge records must require transported proof material"
    );

    let mut tampered_material =
        move_same_secret_bridge_proof_bytes_to_transport(&mut embedded_proof_material_set.clone());
    tampered_material["proofMaterials"][0]["chunkHashes"][0] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedSameSecretBridgeProofMaterial": tampered_material,
            }),
        )
        .is_err(),
        "tampered transported same-secret bridge chunk hash must be rejected"
    );
}

// Rebind a base setup package to the embedded coefficient commitment sets, the
// same-secret bridge, and a ThresholdShareCommitmentBinding so the package is
// accepted by the collective setup verifier. The participant count is read from
// the package, so this drives any supported roster size.
