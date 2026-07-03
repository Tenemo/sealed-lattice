use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) struct SetupTransportCertificateObjectFixture {
    pub(super) object_name: &'static str,
    pub(super) object_role: &'static str,
    pub(super) object_root: String,
    pub(super) byte_length: u64,
    pub(super) full_object_hash: String,
    pub(super) chunk_root: String,
    pub(super) chunk_hashes: Vec<String>,
}

pub(super) fn append_setup_transport_certificate_object(
    package: &mut serde_json::Value,
    object_fixture: SetupTransportCertificateObjectFixture,
) {
    let certificate_hash = {
        let certificate = package
            .get_mut("setupTransportCertificate")
            .expect("setup transport certificate");
        let chunk_start_index = certificate["chunkCount"]
            .as_u64()
            .expect("setup transport chunk count");
        let chunk_count =
            u64::try_from(object_fixture.chunk_hashes.len()).expect("chunk hash count");
        certificate["transportedObjects"]
            .as_array_mut()
            .expect("transported objects")
            .push(serde_json::json!({
                "objectType": "SetupTransportedObject",
                "objectVersion": 1,
                "objectName": object_fixture.object_name,
                "objectRole": object_fixture.object_role,
                "objectRoot": object_fixture.object_root,
                "byteLength": object_fixture.byte_length,
                "chunkStartIndex": chunk_start_index,
                "chunkCount": chunk_count,
                "chunkRoot": object_fixture.chunk_root,
                "chunkHashes": object_fixture.chunk_hashes,
                "fullObjectHash": object_fixture.full_object_hash,
                "encoding": "binary",
                "loadingPolicy": "stream-verified-before-object-use",
            }));
        rebind_setup_transport_certificate(certificate)
    };
    package["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);
}

pub(super) fn rebind_setup_transport_certificate(certificate: &mut serde_json::Value) -> String {
    let transported_objects = certificate["transportedObjects"]
        .as_array()
        .expect("transported objects");
    let mut total_byte_length = 0_u64;
    let mut chunk_count = 0_u64;

    for transported_object in transported_objects {
        let byte_length = transported_object["byteLength"]
            .as_u64()
            .expect("transported object byte length");
        let object_chunk_count = transported_object["chunkCount"]
            .as_u64()
            .expect("transported object chunk count");
        total_byte_length = total_byte_length
            .checked_add(byte_length)
            .expect("transport byte length sum");
        chunk_count = chunk_count
            .checked_add(object_chunk_count)
            .expect("transport chunk count sum");
    }

    certificate["chunkCount"] = serde_json::json!(chunk_count);
    certificate["totalByteLength"] = serde_json::json!(total_byte_length);
    let mut certificate_hash_input = certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("setup transport certificate object")
        .remove("setupTransportCertificateHash");
    let certificate_hash = derive_canonical_object_hash(&certificate_hash_input)
        .expect("setup transport certificate hash");
    certificate["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    certificate_hash
}

pub(super) fn append_vss_material_binary_header(
    output: &mut Vec<u8>,
    ring_degree: usize,
    participant_count: u64,
    decryption_threshold: u64,
) {
    output.extend(b"SLVSSMAT");
    append_varuint(output, 1);
    append_varuint(output, participant_count);
    append_varuint(output, decryption_threshold);
    append_varuint(output, DATA_PRIMES.len() as u64);
    append_varuint(output, ring_degree as u64);
    append_varuint(output, SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64);
    append_varuint(output, SETUP_COMMITMENT_ROW_COUNT as u64);
}

pub(super) fn vss_material_binary_total_byte_length(
    ring_degree: usize,
    participant_count: u64,
    decryption_threshold: u64,
) -> u64 {
    let mut header = Vec::new();
    append_vss_material_binary_header(
        &mut header,
        ring_degree,
        participant_count,
        decryption_threshold,
    );
    let coordinate_byte_length = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            (0..DATA_PRIMES.len()).flat_map(move |rns_limb_index| {
                (0..decryption_threshold).map(move |shamir_coefficient_index| {
                    let mut coordinate_bytes = Vec::new();
                    append_varuint(&mut coordinate_bytes, source_trustee_roster_position);
                    append_varuint(&mut coordinate_bytes, rns_limb_index as u64);
                    append_varuint(&mut coordinate_bytes, shamir_coefficient_index);
                    coordinate_bytes.len() as u64
                })
            })
        })
        .sum::<u64>();
    let commitment_limb_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let mut index_bytes = Vec::new();
            append_varuint(&mut index_bytes, *commitment_modulus_index as u64);
            index_bytes.len() as u64
                + 8
                + (SETUP_COMMITMENT_ROW_COUNT as u64 * ring_degree as u64 * 8)
        })
        .sum::<u64>();
    let material_record_count = participant_count * DATA_PRIMES.len() as u64 * decryption_threshold;

    header.len() as u64
        + coordinate_byte_length
        + material_record_count * commitment_limb_byte_length
}

pub(super) fn move_same_secret_proof_bytes_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = package["sameSecretProofs"]["proofRecords"]
        .as_array_mut()
        .expect("same-secret proof records");
    let mut proof_materials = Vec::new();
    for proof_record in proof_records {
        let proof_bytes_hex = proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded proof bytes")
            .to_string();
        let proof_bytes = decode_hex(&proof_bytes_hex).expect("proof bytes");
        let chunks = proof_bytes_transport_chunks(proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            "same-secret-linkage-anchor",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("same-secret proof transport hashes");
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("same-secret proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove("sameSecretProofRoot");
        proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
        proof_record["proofChunkSizeBytes"] =
            serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
        proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
        proof_record["proofTotalByteLength"] =
            serde_json::json!(transport_hashes.total_byte_length);
        proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
        proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
        proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
        let proof_material_root =
            same_secret_anchor_proof_material_root(proof_record, &transport_hashes)
                .expect("same-secret anchor proof material root");
        proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
        proof_record["sameSecretProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record).expect("same-secret proof root")
        );
        proof_materials.push(serde_json::json!({
            "objectType": "SetupTransportedSameSecretProofMaterial",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "proofMaterialRoot": proof_record["proofMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": proof_record["proofFullObjectHash"],
            "chunkHashes": proof_record["proofChunkHashes"],
            "chunkRoot": proof_record["proofChunkRoot"],
            "chunks": chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                }))
                .collect::<Vec<_>>(),
        }));
    }
    rebind_collective_same_secret_proof_set_root(package);

    serde_json::json!({
        "objectType": "SetupTransportedSameSecretProofMaterialSet",
        "objectVersion": 1,
        "proofFamily": "same-secret-linkage-anchor",
        "proofMaterials": proof_materials,
    })
}

pub(super) fn proof_bytes_transport_chunks(proof_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    proof_bytes_transport_chunks_from_slice(&proof_bytes)
}

pub(super) fn proof_bytes_transport_chunks_from_slice(proof_bytes: &[u8]) -> Vec<Vec<u8>> {
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES)
        .expect("proof transport chunk size");
    proof_bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

pub(super) struct TransportedMaterialCertificateFields {
    byte_length: &'static str,
    full_object_hash: &'static str,
    chunk_root: &'static str,
    chunk_hashes: &'static str,
}

pub(super) const DIRECT_TRANSPORT_CERTIFICATE_FIELDS: TransportedMaterialCertificateFields =
    TransportedMaterialCertificateFields {
        byte_length: "totalByteLength",
        full_object_hash: "fullObjectHash",
        chunk_root: "chunkRoot",
        chunk_hashes: "chunkHashes",
    };

pub(super) fn append_transport_certificate_entries_from_material_set(
    package: &mut serde_json::Value,
    material_set: &serde_json::Value,
    materials_field_name: &'static str,
    object_root_field_name: &'static str,
    object_name: &'static str,
    object_role: &'static str,
    fields: TransportedMaterialCertificateFields,
) {
    for transported_material in material_set[materials_field_name]
        .as_array()
        .expect("transported material entries")
    {
        append_setup_transport_certificate_object(
            package,
            SetupTransportCertificateObjectFixture {
                object_name,
                object_role,
                object_root: transported_material[object_root_field_name]
                    .as_str()
                    .expect("transported material root")
                    .to_string(),
                byte_length: transported_material[fields.byte_length]
                    .as_u64()
                    .expect("transported material byte length"),
                full_object_hash: transported_material[fields.full_object_hash]
                    .as_str()
                    .expect("transported material full object hash")
                    .to_string(),
                chunk_root: transported_material[fields.chunk_root]
                    .as_str()
                    .expect("transported material chunk root")
                    .to_string(),
                chunk_hashes: transport_certificate_chunk_hashes(
                    transported_material,
                    fields.chunk_hashes,
                ),
            },
        );
    }
}

fn transport_certificate_chunk_hashes(
    transported_material: &serde_json::Value,
    field_name: &str,
) -> Vec<String> {
    transported_material[field_name]
        .as_array()
        .expect("transported material chunk hashes")
        .iter()
        .map(|chunk_hash| {
            chunk_hash
                .as_str()
                .expect("transported material chunk hash")
                .to_string()
        })
        .collect()
}

pub(super) fn encode_transport_material_from_package(package: &serde_json::Value) -> Vec<u8> {
    let material_records = package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"]
        .as_array()
        .expect("coefficient material records");
    let ring_degree = package["vssCoefficientCommitmentMaterial"]["ringDegree"]
        .as_u64()
        .expect("ring degree");
    // Roster counts come straight from the package so the re-encoding matches
    // the package the transport binds, for any supported roster size.
    let participant_count = package["setupContext"]["participantCount"]
        .as_u64()
        .expect("participant count");
    let decryption_threshold = package["vssCoefficientCommitmentMaterial"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree");
    let mut output = Vec::new();
    output.extend(b"SLVSSMAT");
    crate::encoding::append_varuint(&mut output, 1);
    crate::encoding::append_varuint(&mut output, participant_count);
    crate::encoding::append_varuint(&mut output, decryption_threshold);
    crate::encoding::append_varuint(&mut output, DATA_PRIMES.len() as u64);
    crate::encoding::append_varuint(&mut output, ring_degree);
    crate::encoding::append_varuint(
        &mut output,
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64,
    );
    crate::encoding::append_varuint(&mut output, SETUP_COMMITMENT_ROW_COUNT as u64);

    for source_trustee_roster_position in 0..participant_count {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..decryption_threshold {
                let record_index = (((source_trustee_roster_position as usize)
                    * DATA_PRIMES.len()
                    + rns_limb_index)
                    * decryption_threshold as usize)
                    + shamir_coefficient_index as usize;
                let commitment = &material_records[record_index]["commitment"];
                crate::encoding::append_varuint(&mut output, source_trustee_roster_position);
                crate::encoding::append_varuint(&mut output, rns_limb_index as u64);
                crate::encoding::append_varuint(&mut output, shamir_coefficient_index);
                for limb in commitment["commitmentLimbs"]
                    .as_array()
                    .expect("commitment limbs")
                {
                    crate::encoding::append_varuint(
                        &mut output,
                        limb["commitmentModulusIndex"]
                            .as_u64()
                            .expect("commitment modulus index"),
                    );
                    output.extend(
                        limb["modulus"]
                            .as_u64()
                            .expect("commitment modulus")
                            .to_le_bytes(),
                    );
                    for row in limb["rows"].as_array().expect("commitment rows") {
                        for coefficient in row.as_array().expect("commitment row coefficients") {
                            output.extend(
                                coefficient
                                    .as_u64()
                                    .expect("commitment coefficient")
                                    .to_le_bytes(),
                            );
                        }
                    }
                }
            }
        }
    }

    output
}

pub(super) fn transported_material_value(material_bytes: &[u8]) -> serde_json::Value {
    let chunks = material_bytes
        .chunks(1_048_576)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let transport_hashes =
        crate::bgv::setup::threshold_share_commitments::setup_vss_material_transport_hashes(
            &chunks, 1_048_576,
        )
        .expect("transport hashes");

    serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": 1_048_576,
        "chunkCount": chunks.len(),
        "totalByteLength": material_bytes.len(),
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunkRoot": transport_hashes.chunk_root,
        "chunks": chunks.iter().enumerate().map(|(chunk_index, chunk)| {
            serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesHex": crate::hashing::to_hex(chunk),
            })
        }).collect::<Vec<_>>(),
    })
}
