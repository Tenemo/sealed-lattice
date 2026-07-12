use super::*;

use crate::hashing::derive_canonical_object_hash;

#[derive(Clone, Copy)]
pub(in super::super) struct SetupProofMaterialTransportCertificateFields {
    pub(in super::super) object_name: &'static str,
    pub(in super::super) object_role: &'static str,
    pub(in super::super) byte_length: &'static str,
    pub(in super::super) chunk_count: &'static str,
    pub(in super::super) full_object_hash: &'static str,
    pub(in super::super) chunk_root: &'static str,
    pub(in super::super) chunk_hashes: &'static str,
}

pub(in super::super) const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_CERTIFICATE_FIELDS:
    SetupProofMaterialTransportCertificateFields = SetupProofMaterialTransportCertificateFields {
    object_name: "publicKeyShareProofMaterial",
    object_role: "public-key-share-proof-material",
    byte_length: "totalByteLength",
    chunk_count: "chunkCount",
    full_object_hash: "fullObjectHash",
    chunk_root: "chunkRoot",
    chunk_hashes: "chunkHashes",
};

pub(in super::super) const TRUSTEE_EVALUATION_KEY_PROOF_TRANSPORT_CERTIFICATE_FIELDS:
    SetupProofMaterialTransportCertificateFields = SetupProofMaterialTransportCertificateFields {
    object_name: "evaluationKeyShareProofMaterial",
    object_role: "evaluation-key-share-proof-material",
    byte_length: "proofTotalByteLength",
    chunk_count: "proofChunkCount",
    full_object_hash: "proofFullObjectHash",
    chunk_root: "proofChunkRoot",
    chunk_hashes: "proofChunkHashes",
};

pub(in super::super) fn setup_transport_certificate_fixture(
    _parameters: &serde_json::Value,
    vss_coefficient_commitment_material: &serde_json::Value,
) -> serde_json::Value {
    let chunk_size_bytes = 1_048_576_u64;
    // The transported VSS object byte length is a function of the material's
    // roster and ring degree, matching the verifier's roster-and-ring-derived
    // expectation (transport_policy::setup_transport_vss_material_byte_length_for_roster).
    // It is read from the material set so a reduced-ring or non-foundation
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
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": vss_full_object_hash,
    }))
    .expect("setup transport chunk root");
    let transported_objects = serde_json::json!([
        {
            "objectType": "SetupTransportedObject",
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
        }
    ]);
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(
                material_participant_count,
            ),
        )
        .expect("roster-derived setup parameters hash");
    let mut certificate = serde_json::json!({
        "objectType": "SetupTransportCertificate",
        "setupParametersHash": setup_parameters_hash,
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "storageQuotaBytes": 2_147_483_648_u64,
        "largestSingleBufferBytes": 1_572_864_u64,
        "copyCountLimit": 2_u64,
        "streamVerificationOrder": "ascending-chunk-index",
        "resumePolicy": "chunk-index-checkpointed-by-hash",
        "lazyLoadingPolicy": "root-addressed-large-object-loading",
        "transportedObjects": transported_objects,
    });
    let certificate_hash =
        derive_canonical_object_hash(&certificate).expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    certificate
}

// Replaces one proof family's transport-certificate entries from its current
// descriptor set, then rebuilds the global gap-free chunk schedule and both
// certificate hashes. The helper is intentionally idempotent so a tamper test
// can change authenticated proof bytes and rebuild the exact transport binding
// without leaving stale entries from the original fixture.
pub(in super::super) fn replace_setup_proof_material_transport_certificate_objects(
    package: &mut serde_json::Value,
    transported_proof_material: &serde_json::Value,
    fields: SetupProofMaterialTransportCertificateFields,
) {
    let replacement_objects = transported_proof_material["proofMaterials"]
        .as_array()
        .expect("transported setup proof materials")
        .iter()
        .map(|proof_material| {
            let proof_material_root = proof_material["proofMaterialRoot"]
                .as_str()
                .expect("transported setup proof material root");
            let byte_length = proof_material[fields.byte_length]
                .as_u64()
                .expect("transported setup proof material byte length");
            let chunk_count = proof_material[fields.chunk_count]
                .as_u64()
                .expect("transported setup proof material chunk count");
            let full_object_hash = proof_material[fields.full_object_hash]
                .as_str()
                .expect("transported setup proof material full-object hash");
            let chunk_root = proof_material[fields.chunk_root]
                .as_str()
                .expect("transported setup proof material chunk root");
            let chunk_hashes = proof_material[fields.chunk_hashes]
                .as_array()
                .expect("transported setup proof material chunk hashes");

            serde_json::json!({
                "objectType": "SetupTransportedObject",
                "objectName": fields.object_name,
                "objectRole": fields.object_role,
                "objectRoot": proof_material_root,
                "byteLength": byte_length,
                "chunkStartIndex": 0,
                "chunkCount": chunk_count,
                "chunkRoot": chunk_root,
                "chunkHashes": chunk_hashes,
                "fullObjectHash": full_object_hash,
                "encoding": "binary",
            })
        })
        .collect::<Vec<_>>();

    let certificate = package["setupTransportCertificate"]
        .as_object_mut()
        .expect("setup transport certificate");
    let transported_objects = certificate["transportedObjects"]
        .as_array_mut()
        .expect("setup transport certificate objects");
    transported_objects.retain(|transported_object| {
        transported_object["objectName"].as_str() != Some(fields.object_name)
            || transported_object["objectRole"].as_str() != Some(fields.object_role)
    });
    transported_objects.extend(replacement_objects);

    let mut next_chunk_start_index = 0_u64;
    let mut aggregate_byte_length = 0_u64;
    for transported_object in transported_objects {
        transported_object["chunkStartIndex"] = serde_json::json!(next_chunk_start_index);
        let chunk_count = transported_object["chunkCount"]
            .as_u64()
            .expect("setup transported object chunk count");
        let byte_length = transported_object["byteLength"]
            .as_u64()
            .expect("setup transported object byte length");
        next_chunk_start_index = next_chunk_start_index
            .checked_add(chunk_count)
            .expect("setup transport aggregate chunk count");
        aggregate_byte_length = aggregate_byte_length
            .checked_add(byte_length)
            .expect("setup transport aggregate byte length");
    }
    certificate["chunkCount"] = serde_json::json!(next_chunk_start_index);
    certificate["totalByteLength"] = serde_json::json!(aggregate_byte_length);
    certificate.remove("setupTransportCertificateHash");
    let certificate_hash =
        derive_canonical_object_hash(&serde_json::Value::Object(certificate.clone()))
            .expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(&certificate_hash);
    package["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);
}
