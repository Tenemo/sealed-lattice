use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn setup_transport_chunk_manifest_root_fixture(
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupTransportChunkManifest",
        "objectVersion": 1,
        "chunkSizeBytes": 1_048_576_u64,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))
    .expect("setup transport chunk manifest root")
}

pub(in super::super) fn setup_transport_certificate_fixture(
    _parameters: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
) -> serde_json::Value {
    let chunk_size_bytes = 1_048_576_u64;
    // The transported VSS object byte length is a function of the material's
    // roster and ring degree, matching the verifier's roster-and-ring-derived
    // expectation (transport_policy::setup_transport_vss_material_byte_length_for_roster).
    // It is read from the material set so a reduced-ring or non-first-closure
    // material declares a consistent transport object. The streamed path then
    // overrides byteLength from the actually transported material.
    let material_participant_count = vss_coefficient_commitment_material["participantCount"]
        .as_u64()
        .expect("VSS material participant count");
    let material_decryption_threshold = vss_coefficient_commitment_material["thresholdDegree"]
        .as_u64()
        .expect("VSS material threshold degree");
    let material_ring_degree = vss_coefficient_commitment_material["ringDegree"]
        .as_u64()
        .expect("VSS material ring degree") as usize;
    let total_byte_length = vss_material_binary_total_byte_length(
        material_ring_degree,
        material_participant_count,
        material_decryption_threshold,
    );
    let chunk_count = total_byte_length.div_ceil(chunk_size_bytes);
    let vss_full_object_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupTransportChunkManifestRoot",
        "fixture": "setup-transport-full-object-hash",
        "totalByteLength": total_byte_length,
    }))
    .expect("transport full object hash");
    let chunk_hashes = (0..chunk_count)
        .map(|chunk_index| {
            derive_canonical_object_hash(&serde_json::json!({
                "objectType": "SetupTransportChunkManifestRoot",
                "fixture": "setup-transport-chunk-hash",
                "chunkIndex": chunk_index,
            }))
            .expect("transport chunk hash")
        })
        .collect::<Vec<_>>();
    let vss_chunk_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupTransportChunkManifest",
        "objectVersion": 1,
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": vss_full_object_hash,
    }))
    .expect("setup transport chunk root");
    let transported_objects = serde_json::json!([
        {
            "objectType": "SetupTransportedObject",
            "objectVersion": 1,
            "objectName": "vssCoefficientCommitmentMaterial",
            "objectRole": "public-vss-coefficient-commitment-material",
            "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
            "byteLength": total_byte_length,
            "chunkStartIndex": 0_u64,
            "chunkCount": chunk_count,
            "chunkRoot": vss_chunk_root,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": vss_full_object_hash,
            "encoding": "binary",
            "loadingPolicy": "stream-verified-before-object-use",
        }
    ]);
    let aggregate_full_object_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "transportedObjects": [{
                "objectName": "vssCoefficientCommitmentMaterial",
                "objectRole": "public-vss-coefficient-commitment-material",
                "objectRoot": vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"],
                "byteLength": total_byte_length,
                "chunkStartIndex": 0_u64,
                "chunkCount": chunk_count,
                "chunkRoot": vss_chunk_root,
                "fullObjectHash": vss_full_object_hash,
            }],
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
    .expect("setup transport full object set hash");
    let chunk_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupTransportChunkManifest",
        "objectVersion": 1,
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": aggregate_full_object_hash,
    }))
    .expect("setup transport aggregate chunk root");
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(
                material_participant_count,
            ),
        )
        .expect("roster-derived setup parameters hash");
    let mut certificate = serde_json::json!({
        "objectType": "SetupTransportCertificate",
        "objectVersion": 1,
        "setupParametersHash": setup_parameters_hash,
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "storageQuotaBytes": 2_147_483_648_u64,
        "largestSingleBufferBytes": 1_572_864_u64,
        "copyCountLimit": 2_u64,
        "streamVerificationOrder": "ascending-chunk-index",
        "resumePolicy": "chunk-index-checkpointed-by-hash",
        "lazyLoadingPolicy": "root-addressed-large-object-loading",
        "transportedObjects": transported_objects,
        "chunkHashes": chunk_hashes,
        "chunkRoot": chunk_root,
        "fullObjectHash": aggregate_full_object_hash,
    });
    let certificate_hash =
        derive_canonical_object_hash(&certificate).expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    certificate
}

pub(in super::super) fn setup_transport_certificate_for_transported_vss_material(
    parameters: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
    transported_vss_material: &serde_json::Value,
) -> serde_json::Value {
    let mut certificate =
        setup_transport_certificate_fixture(parameters, vss_coefficient_commitment_material);
    let vss_transport_object = certificate["transportedObjects"][0]
        .as_object_mut()
        .expect("VSS transport certificate object");
    vss_transport_object.insert(
        "objectRoot".to_string(),
        vss_coefficient_commitment_material["vssCoefficientCommitmentMaterialRoot"].clone(),
    );
    vss_transport_object.insert(
        "byteLength".to_string(),
        transported_vss_material["totalByteLength"].clone(),
    );
    vss_transport_object.insert(
        "chunkCount".to_string(),
        transported_vss_material["chunkCount"].clone(),
    );
    vss_transport_object.insert(
        "chunkRoot".to_string(),
        transported_vss_material["chunkRoot"].clone(),
    );
    vss_transport_object.insert(
        "chunkHashes".to_string(),
        transported_vss_material["chunkHashes"].clone(),
    );
    vss_transport_object.insert(
        "fullObjectHash".to_string(),
        transported_vss_material["fullObjectHash"].clone(),
    );
    rebind_setup_transport_certificate(&mut certificate);

    certificate
}
