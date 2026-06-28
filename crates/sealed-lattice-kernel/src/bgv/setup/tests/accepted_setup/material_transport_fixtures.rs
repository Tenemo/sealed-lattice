use super::*;

// One synthetic single-chunk transport object's hash triple, derived from a
// fixture label so each unrequested or unreferenced transport sidecar reuses the
// same derivation shape. The root field name varies per sidecar (object,
// proof-material, or component-material root), so it is a parameter; the full
// object and chunk hashes use fixed `full-object-hash` and `chunk-hash` field
// labels exactly as the per-sidecar derivations did before.
struct SyntheticTransportObjectHashes {
    object_root: String,
    full_object_hash: String,
    chunk_hash: String,
    chunk_root: String,
}

fn synthetic_transport_object_hashes(
    fixture_label: &str,
    root_field_name: &str,
) -> SyntheticTransportObjectHashes {
    let object_root = derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &serde_json::json!({
            "fixture": fixture_label,
            "field": root_field_name,
        }),
    )
    .expect("synthetic setup transport object root");
    let full_object_hash = derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &serde_json::json!({
            "fixture": fixture_label,
            "field": "full-object-hash",
        }),
    )
    .expect("synthetic setup transport full object hash");
    let chunk_hash = derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &serde_json::json!({
            "fixture": fixture_label,
            "field": "chunk-hash",
        }),
    )
    .expect("synthetic setup transport chunk hash");
    let chunk_root = setup_transport_chunk_manifest_root_fixture(
        1,
        1,
        std::slice::from_ref(&chunk_hash),
        &full_object_hash,
    );

    SyntheticTransportObjectHashes {
        object_root,
        full_object_hash,
        chunk_hash,
        chunk_root,
    }
}

pub(super) fn append_unrequested_setup_transport_object(package: &mut serde_json::Value) {
    let hashes =
        synthetic_transport_object_hashes("unrequested-setup-transport-object", "object-root");
    append_setup_transport_certificate_object(
        package,
        SetupTransportCertificateObjectFixture {
            object_name: "unrequestedSetupMaterial",
            object_role: "unrequested-setup-material",
            object_root: hashes.object_root,
            byte_length: 1,
            full_object_hash: hashes.full_object_hash,
            chunk_root: hashes.chunk_root,
            chunk_hashes: vec![hashes.chunk_hash],
        },
    );
}

pub(super) fn append_unreferenced_same_secret_transport_sidecar(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let hashes = synthetic_transport_object_hashes(
        "unreferenced-same-secret-proof-material",
        "proof-material-root",
    );

    append_setup_transport_certificate_object(
        package,
        SetupTransportCertificateObjectFixture {
            object_name: "sameSecretProofMaterial",
            object_role: "same-secret-proof-material",
            object_root: hashes.object_root.clone(),
            byte_length: 1,
            full_object_hash: hashes.full_object_hash.clone(),
            chunk_root: hashes.chunk_root.clone(),
            chunk_hashes: vec![hashes.chunk_hash.clone()],
        },
    );

    serde_json::json!({
        "proofMaterials": [{
            "proofMaterialRoot": hashes.object_root,
            "totalByteLength": 1_u64,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
            "chunkHashes": [hashes.chunk_hash],
        }],
    })
}

pub(super) fn append_unreferenced_evaluation_key_component_transport_sidecar(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let hashes = synthetic_transport_object_hashes(
        "unreferenced-evaluation-key-component-material",
        "component-material-root",
    );

    append_setup_transport_certificate_object(
        package,
        SetupTransportCertificateObjectFixture {
            object_name: "evaluationKeyShareComponentMaterial",
            object_role: "evaluation-key-share-component-material",
            object_root: hashes.object_root.clone(),
            byte_length: 1,
            full_object_hash: hashes.full_object_hash.clone(),
            chunk_root: hashes.chunk_root.clone(),
            chunk_hashes: vec![hashes.chunk_hash.clone()],
        },
    );

    serde_json::json!({
        "componentMaterials": [{
            "keySwitchComponentMaterialRoot": hashes.object_root,
            "totalByteLength": 1_u64,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
            "chunkHashes": [hashes.chunk_hash],
        }],
    })
}

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
    let mut chunk_hashes = Vec::new();
    let mut transported_object_summaries = Vec::new();

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
        chunk_hashes.extend(
            transported_object["chunkHashes"]
                .as_array()
                .expect("transported object chunk hashes")
                .iter()
                .map(|chunk_hash| {
                    chunk_hash
                        .as_str()
                        .expect("transported object chunk hash")
                        .to_string()
                }),
        );
        transported_object_summaries.push(serde_json::json!({
            "objectName": transported_object["objectName"].clone(),
            "objectRole": transported_object["objectRole"].clone(),
            "objectRoot": transported_object["objectRoot"].clone(),
            "byteLength": byte_length,
            "chunkStartIndex": transported_object["chunkStartIndex"].clone(),
            "chunkCount": object_chunk_count,
            "chunkRoot": transported_object["chunkRoot"].clone(),
            "fullObjectHash": transported_object["fullObjectHash"].clone(),
        }));
    }

    let aggregate_full_object_hash = derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &serde_json::json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
            "transportedObjects": transported_object_summaries,
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes.clone(),
        }),
    )
    .expect("setup transport aggregate full object hash");
    let aggregate_chunk_root = setup_transport_chunk_manifest_root_fixture(
        chunk_count,
        total_byte_length,
        &chunk_hashes,
        &aggregate_full_object_hash,
    );

    certificate["chunkCount"] = serde_json::json!(chunk_count);
    certificate["totalByteLength"] = serde_json::json!(total_byte_length);
    certificate["chunkHashes"] = serde_json::json!(chunk_hashes);
    certificate["fullObjectHash"] = serde_json::json!(aggregate_full_object_hash);
    certificate["chunkRoot"] = serde_json::json!(aggregate_chunk_root);
    let mut certificate_hash_input = certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("setup transport certificate object")
        .remove("setupTransportCertificateHash");
    let certificate_hash =
        derive_protocol_hash("SetupTransportCertificateHash", &certificate_hash_input)
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

pub(super) struct StreamingVssMaterialFixtureWriter {
    derivation_id: String,
    expected_total_byte_length: u64,
    observed_total_byte_length: u64,
    chunk_index: usize,
    chunk_buffer: Vec<u8>,
}

impl StreamingVssMaterialFixtureWriter {
    pub(super) fn new(derivation_id: String, expected_total_byte_length: u64) -> Self {
        Self {
            derivation_id,
            expected_total_byte_length,
            observed_total_byte_length: 0,
            chunk_index: 0,
            chunk_buffer: Vec::with_capacity(SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS as usize),
        }
    }

    pub(super) fn write_bytes(&mut self, mut bytes: &[u8]) -> CanonicalResult<()> {
        let chunk_size = SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS as usize;
        while !bytes.is_empty() {
            let available = chunk_size - self.chunk_buffer.len();
            let byte_count = available.min(bytes.len());
            self.chunk_buffer.extend_from_slice(&bytes[..byte_count]);
            bytes = &bytes[byte_count..];
            if self.chunk_buffer.len() == chunk_size {
                self.flush_chunk()?;
            }
        }

        Ok(())
    }

    fn flush_chunk(&mut self) -> CanonicalResult<()> {
        if self.chunk_buffer.is_empty() {
            return Ok(());
        }
        self.observed_total_byte_length = self
            .observed_total_byte_length
            .checked_add(self.chunk_buffer.len() as u64)
            .expect("streamed VSS byte length");
        absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
            &serde_json::json!({
                "derivationId": self.derivation_id.as_str(),
                "chunkIndex": self.chunk_index,
                "bytesHex": to_hex(&self.chunk_buffer),
            }),
        )?;
        self.chunk_index += 1;
        self.chunk_buffer.clear();

        Ok(())
    }

    pub(super) fn finish(
        mut self,
        vss_coefficient_commitment_root: &serde_json::Value,
        source_trustee_records: &serde_json::Value,
    ) -> CanonicalResult<serde_json::Value> {
        self.flush_chunk()?;
        if self.observed_total_byte_length != self.expected_total_byte_length {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "streamed VSS material byte length did not match the declared transport length",
            ));
        }

        finish_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
            "derivationId": self.derivation_id.as_str(),
            "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
            "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
        }))
    }
}

pub(super) fn move_same_secret_proof_bytes_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = package["sameSecretProofs"]["proofRecords"]
        .as_array_mut()
        .expect("same-secret proof records");
    let mut proof_materials = Vec::new();
    let mut proof_roots = Vec::new();
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
        let trustee_identity = proof_record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity")
            .to_string();
        let trustee_roster_position = proof_record["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position");
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
            derive_protocol_hash("SameSecretProofRoot", proof_record)
                .expect("same-secret proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
        }));
        proof_materials.push(serde_json::json!({
            "objectType": "SetupTransportedSameSecretProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
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
                    "bytesBase64": crate::transcript_core::encode_standard_base64(&chunk),
                }))
                .collect::<Vec<_>>(),
        }));
    }
    package["sameSecretProofs"]["sameSecretProofRoots"] = serde_json::json!(proof_roots);
    rebind_collective_same_secret_proof_set_root(package);

    serde_json::json!({
        "objectType": "SetupTransportedSameSecretProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": "same-secret-linkage-anchor",
        "proofMaterials": proof_materials,
    })
}

pub(super) fn move_public_key_share_succinct_proof_bytes_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = package["publicKeyShareSuccinctProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key share succinct proof records");
    let mut proof_materials = Vec::new();
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        let proof_bytes_hex = proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded public-key proof bytes")
            .to_string();
        let proof_bytes = decode_hex(&proof_bytes_hex).expect("public-key proof bytes");
        let chunks = proof_bytes_transport_chunks(proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            "public-key-share",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("public-key proof transport hashes");
        let trustee_identity = proof_record["trusteeIdentity"]
            .as_str()
            .expect("trustee identity")
            .to_string();
        let trustee_roster_position = proof_record["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position");
        let proof_material_root =
            public_key_share_succinct_proof_material_root(proof_record, &transport_hashes)
                .expect("public-key share succinct proof material root");
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("public-key share succinct proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove("publicKeyShareSuccinctProofRoot");
        proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
        proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
        proof_record["proofChunkSizeBytes"] =
            serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
        proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
        proof_record["proofTotalByteLength"] =
            serde_json::json!(transport_hashes.total_byte_length);
        proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
        proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
        proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
        proof_record["publicKeyShareSuccinctProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", proof_record)
                .expect("public-key succinct proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareSuccinctProofRoot": proof_record["publicKeyShareSuccinctProofRoot"],
        }));
        proof_materials.push(serde_json::json!({
            "objectType": "SetupTransportedPublicKeyShareProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "public-key-share",
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
    package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofRoots"] =
        serde_json::json!(proof_roots);
    rebind_collective_public_key_succinct_proof_roots(package);

    serde_json::json!({
        "objectType": "SetupTransportedPublicKeyShareProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofMaterials": proof_materials,
    })
}

pub(super) fn proof_bytes_transport_chunks(proof_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES)
        .expect("proof transport chunk size");
    proof_bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

static TRANSPORTED_PUBLIC_SETUP_COMPANIONS_CACHE: OnceLock<(
    serde_json::Value,
    TransportedPublicSetupCompanions,
)> = OnceLock::new();

#[derive(Clone)]
pub(super) struct TransportedPublicSetupCompanions {
    pub(super) vss_coefficient_commitment_material: serde_json::Value,
    pub(super) verified_vss_coefficient_commitment_material: serde_json::Value,
    pub(super) same_secret_proof_material: serde_json::Value,
    pub(super) public_key_share_material: serde_json::Value,
    pub(super) public_key_share_proof_material: serde_json::Value,
    pub(super) evaluation_key_share_component_material: serde_json::Value,
    pub(super) evaluation_key_share_proof_material: serde_json::Value,
    pub(super) public_evaluation_key_material: serde_json::Value,
}

#[derive(Default)]
pub(super) struct TerminalEvaluationKeyTransportSinks {
    pub(super) component_materials: Vec<serde_json::Value>,
    pub(super) proof_materials: Vec<serde_json::Value>,
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

const PROOF_TRANSPORT_CERTIFICATE_FIELDS: TransportedMaterialCertificateFields =
    TransportedMaterialCertificateFields {
        byte_length: "proofTotalByteLength",
        full_object_hash: "proofFullObjectHash",
        chunk_root: "proofChunkRoot",
        chunk_hashes: "proofChunkHashes",
    };

pub(super) fn setup_package_with_transported_public_setup_companions()
-> (serde_json::Value, TransportedPublicSetupCompanions) {
    TRANSPORTED_PUBLIC_SETUP_COMPANIONS_CACHE
        .get_or_init(build_setup_package_with_transported_public_setup_companions)
        .clone()
}

fn build_setup_package_with_transported_public_setup_companions()
-> (serde_json::Value, TransportedPublicSetupCompanions) {
    terminal_phase("start profile-ring package fixture");
    let terminal_profile_ring_fixture =
        terminal_profile_ring_minimal_collective_setup_package_fixture();
    terminal_phase("built profile-ring package fixture");
    assemble_transported_public_setup_companions(terminal_profile_ring_fixture)
}

/// Reduced development-ring (128) terminal fixture for roster size n. Builds the
/// streamed reduced-ring base package, then layers on the same proof families,
/// evaluation-key records, and transported public companions as the profile-ring
/// terminal path, so the full accepted-setup verifier exercises every
/// roster-dependent binding for any supported n without the heavy profile ring.
/// The terminal profile-ring claim gate then refuses the reduced ring, so this
/// reaches that gate rather than `accepted`.
pub(super) fn reduced_ring_setup_package_with_transported_public_setup_companions(
    participant_count: u64,
    stream_derivation_purpose: &str,
) -> (serde_json::Value, TransportedPublicSetupCompanions) {
    terminal_phase("start reduced-ring package fixture");
    let reduced_ring_fixture = reduced_ring_streamed_collective_setup_package_fixture(
        participant_count,
        stream_derivation_purpose,
    );
    terminal_phase("built reduced-ring package fixture");
    assemble_transported_public_setup_companions(reduced_ring_fixture)
}

fn assemble_transported_public_setup_companions(
    base_fixture: TerminalProfileRingSetupPackageFixture,
) -> (serde_json::Value, TransportedPublicSetupCompanions) {
    let terminal_profile_ring_fixture = base_fixture;
    let mut package = terminal_profile_ring_fixture.package.clone();
    let transported_vss_material = terminal_profile_ring_fixture
        .transported_vss_coefficient_commitment_material
        .clone();
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate = setup_transport_certificate_for_transported_vss_material(
        &profile,
        &package["vssCoefficientCommitmentMaterial"],
        &transported_vss_material,
    );
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    terminal_phase("generated same-secret proofs");
    let same_secret_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &same_secret_proof_material,
        "proofMaterials",
        "proofMaterialRoot",
        "sameSecretProofMaterial",
        "same-secret-proof-material",
        DIRECT_TRANSPORT_CERTIFICATE_FIELDS,
    );

    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareSuccinctProofs"] = public_key_share_succinct_proofs_object(&package);
    terminal_phase("generated public-key material and proofs");
    let public_key_share_proof_material =
        move_public_key_share_succinct_proof_bytes_to_transport(&mut package);
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &public_key_share_proof_material,
        "proofMaterials",
        "proofMaterialRoot",
        "publicKeyShareProofMaterial",
        "public-key-share-proof-material",
        DIRECT_TRANSPORT_CERTIFICATE_FIELDS,
    );

    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    let public_key_share_material = move_public_key_share_material_to_transport(&mut package);
    terminal_phase("transported public-key material");
    let public_key_share_material_root =
        package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"]
            .as_str()
            .expect("public-key share material root")
            .to_string();
    append_direct_transport_certificate_entry(
        &mut package,
        &public_key_share_material,
        public_key_share_material_root,
        "publicKeyShareMaterial",
        "public-key-share-material",
    );

    let mut evaluation_key_transport_sinks = TerminalEvaluationKeyTransportSinks::default();
    let RelinearizationKeyShareRoundsFixture {
        rounds: relinearization_key_share_rounds,
        round_one_aggregate_diagonals_by_level,
    } = relinearization_key_share_rounds_fixture_with_terminal_transport(
        &package,
        &mut evaluation_key_transport_sinks,
    );
    package["relinearizationKeyShareRounds"] = relinearization_key_share_rounds;
    package["galoisKeyShareBatches"] = galois_key_share_batches_object_with_terminal_transport(
        &package,
        &mut evaluation_key_transport_sinks,
    );
    terminal_phase("generated evaluation-key records");
    let evaluation_key_share_component_material = serde_json::json!({
        "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "componentMaterials": evaluation_key_transport_sinks.component_materials.clone(),
    });
    package["trusteeEvaluationKeyProofs"] =
        trustee_evaluation_key_proofs_object_with_terminal_transport(
            &package,
            &evaluation_key_share_component_material,
            &round_one_aggregate_diagonals_by_level,
            &mut evaluation_key_transport_sinks,
        );
    terminal_phase("generated trustee evaluation-key proofs");
    package["evaluationKeys"] = public_evaluation_key_set_object(&package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &evaluation_key_share_component_material,
        "componentMaterials",
        "keySwitchComponentMaterialRoot",
        "evaluationKeyShareComponentMaterial",
        "evaluation-key-share-component-material",
        DIRECT_TRANSPORT_CERTIFICATE_FIELDS,
    );

    let evaluation_key_share_proof_material = serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyShareProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": "trustee-evaluation-key",
        "proofMaterials": evaluation_key_transport_sinks.proof_materials,
    });
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &evaluation_key_share_proof_material,
        "proofMaterials",
        "proofMaterialRoot",
        "evaluationKeyShareProofMaterial",
        "evaluation-key-share-proof-material",
        PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );

    let public_evaluation_key_material = add_public_evaluation_key_material_transport(&mut package);
    terminal_phase("generated public evaluation-key material");

    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);
    terminal_phase("rebound terminal certificates and package hash");

    (
        package,
        TransportedPublicSetupCompanions {
            vss_coefficient_commitment_material: transported_material_reference_value(
                &transported_vss_material,
            ),
            verified_vss_coefficient_commitment_material: terminal_profile_ring_fixture
                .verified_vss_coefficient_commitment_material,
            same_secret_proof_material,
            public_key_share_material,
            public_key_share_proof_material,
            evaluation_key_share_component_material,
            evaluation_key_share_proof_material,
            public_evaluation_key_material,
        },
    )
}

fn append_direct_transport_certificate_entry(
    package: &mut serde_json::Value,
    transported_material: &serde_json::Value,
    object_root: String,
    object_name: &'static str,
    object_role: &'static str,
) {
    append_setup_transport_certificate_object(
        package,
        SetupTransportCertificateObjectFixture {
            object_name,
            object_role,
            object_root,
            byte_length: transported_material["totalByteLength"]
                .as_u64()
                .expect("transported material byte length"),
            full_object_hash: transported_material["fullObjectHash"]
                .as_str()
                .expect("transported material full object hash")
                .to_string(),
            chunk_root: transported_material["chunkRoot"]
                .as_str()
                .expect("transported material chunk root")
                .to_string(),
            chunk_hashes: transport_certificate_chunk_hashes(transported_material, "chunkHashes"),
        },
    );
}

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

pub(super) fn rebind_public_evaluation_key_material_transport(
    package: &mut serde_json::Value,
    transported_public_evaluation_key_material: &mut serde_json::Value,
    material_bytes: Vec<u8>,
) {
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = public_evaluation_key_material_transport_hashes(&chunks)
        .expect("public evaluation-key material transport hashes");
    let expected_manifest =
        public_evaluation_key_material_manifest(package, &package["evaluationKeys"])
            .expect("public evaluation-key material manifest");
    let material_root = public_evaluation_key_material_reference_root(
        &package["evaluationKeys"],
        &expected_manifest,
        &transport_hashes,
    )
    .expect("public evaluation-key material root");

    package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"] = serde_json::json!(material_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"] =
        serde_json::json!(transport_hashes.chunk_root);
    package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes);
    package["evaluationKeys"]
        .as_object_mut()
        .expect("evaluation key set")
        .remove("evaluationKeySetHash");
    package["evaluationKeys"]["evaluationKeySetHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetHash", &package["evaluationKeys"])
            .expect("evaluation key set hash")
    );
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);

    let material_entry =
        &mut transported_public_evaluation_key_material["publicEvaluationKeyMaterials"][0];
    material_entry["evaluationKeySetHash"] =
        package["evaluationKeys"]["evaluationKeySetHash"].clone();
    material_entry["publicEvaluationKeyMaterialRoot"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"].clone();
    material_entry["chunkCount"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkCount"].clone();
    material_entry["totalByteLength"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialTotalByteLength"].clone();
    material_entry["fullObjectHash"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialFullObjectHash"].clone();
    material_entry["chunkRoot"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkRoot"].clone();
    material_entry["chunkHashes"] =
        package["evaluationKeys"]["publicEvaluationKeyMaterialChunkHashes"].clone();
    material_entry["chunks"] = serde_json::Value::Array(
        chunks
            .into_iter()
            .enumerate()
            .map(|(chunk_index, chunk)| {
                serde_json::json!({
                    "chunkIndex": chunk_index,
                    "bytesHex": to_hex(&chunk),
                })
            })
            .collect::<Vec<_>>(),
    );
}

pub(super) fn move_evaluation_key_share_component_vectors_to_compact_transport(
    proof_record: &mut serde_json::Value,
    proof_family: EvaluationKeyShareProofFamily,
    fixture_material: &EvaluationKeyShareFixtureMaterial,
) -> serde_json::Value {
    move_evaluation_key_share_component_vectors_to_transport_with_chunk_policy(
        proof_record,
        proof_family,
        fixture_material,
        false,
    )
}

fn move_evaluation_key_share_component_vectors_to_transport_with_chunk_policy(
    proof_record: &mut serde_json::Value,
    proof_family: EvaluationKeyShareProofFamily,
    fixture_material: &EvaluationKeyShareFixtureMaterial,
    include_chunks: bool,
) -> serde_json::Value {
    let level = proof_record["level"].as_u64().expect("level") as usize;
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    assert_eq!(
        proof_record["keySwitchComponentVectorRoot"].as_str(),
        Some(fixture_material.component_vector_root.as_str()),
        "record component vector root must match the proof witness material"
    );
    let material_bytes = encode_evaluation_key_share_component_vectors(
        level,
        ring_degree,
        &fixture_material.component_b_by_digit,
    )
    .expect("evaluation-key component material bytes");
    let chunks = proof_bytes_transport_chunks(material_bytes);
    let transport_hashes = evaluation_key_share_component_material_transport_hashes(
        proof_family,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("evaluation-key component material transport hashes");
    {
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("evaluation-key proof record object");
        proof_record_object.remove("keySwitchComponentVectors");
        proof_record_object.remove("statementHash");
        proof_record_object.remove("relationCommitmentHash");
        proof_record_object.remove("tboxCommitmentPrefixHash");
        proof_record_object.remove("challenge");
        proof_record_object.remove("proofSizeBytes");
        proof_record_object.remove("proofBytesHash");
        proof_record_object.remove("proofBytesHex");
    }
    proof_record["keySwitchMaterialEncoding"] =
        serde_json::json!(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING);
    let material_root = evaluation_key_share_component_material_reference_root(
        proof_family,
        proof_record,
        &transport_hashes,
    )
    .expect("evaluation-key component material root");
    proof_record["keySwitchComponentMaterialRoot"] = serde_json::json!(material_root.clone());
    proof_record["keySwitchComponentChunkSizeBytes"] =
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    proof_record["keySwitchComponentChunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    proof_record["keySwitchComponentTotalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    proof_record["keySwitchComponentFullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    proof_record["keySwitchComponentChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    proof_record["keySwitchComponentChunkHashes"] =
        serde_json::json!(transport_hashes.chunk_hashes.clone());

    let mut component_material = serde_json::json!({
            "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": proof_family.proof_family(),
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "keySwitchDomain": proof_record["keySwitchDomain"],
            "keySwitchSeedHex": proof_record["keySwitchSeedHex"],
            "level": proof_record["level"],
            "ringDegree": proof_record["ringDegree"],
            "digitCount": level + 1,
            "rnsLimbCount": level + 1,
            "keySwitchComponentVectorRoot": proof_record["keySwitchComponentVectorRoot"],
            "keySwitchComponentMaterialRoot": proof_record["keySwitchComponentMaterialRoot"],
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": proof_record["keySwitchComponentFullObjectHash"],
            "chunkRoot": proof_record["keySwitchComponentChunkRoot"],
            "chunkHashes": proof_record["keySwitchComponentChunkHashes"],
    });
    if include_chunks {
        component_material["chunks"] = serde_json::Value::Array(
            chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| {
                    serde_json::json!({
                        "chunkIndex": chunk_index,
                        "bytesHex": to_hex(&chunk),
                    })
                })
                .collect::<Vec<_>>(),
        );
    } else {
        register_verified_evaluation_key_share_component_material_chunks(
            &material_root,
            chunks,
            &transport_hashes,
        )
        .expect("verified evaluation-key component material chunks");
    }

    serde_json::json!({
        "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "componentMaterials": [component_material],
    })
}

pub(super) fn move_trustee_evaluation_key_proof_record_bytes_to_compact_transport(
    proof_record: &mut serde_json::Value,
) -> serde_json::Value {
    move_trustee_evaluation_key_proof_record_bytes_with_chunk_policy(proof_record, false)
}

fn move_trustee_evaluation_key_proof_record_bytes_with_chunk_policy(
    proof_record: &mut serde_json::Value,
    include_chunks: bool,
) -> serde_json::Value {
    let proof_bytes_hex = proof_record["proofBytesHex"]
        .as_str()
        .expect("embedded trustee evaluation-key proof bytes")
        .to_string();
    let proof_bytes = decode_hex(&proof_bytes_hex).expect("trustee evaluation-key proof bytes");
    let chunks = proof_bytes_transport_chunks(proof_bytes);
    let transport_hashes = setup_proof_material_transport_hashes(
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("trustee evaluation-key proof transport hashes");
    {
        let proof_record_object = proof_record
            .as_object_mut()
            .expect("trustee evaluation-key proof record object");
        proof_record_object.remove("proofBytesHex");
        proof_record_object.remove("trusteeEvaluationKeyProofRoot");
    }
    proof_record["proofBytesEncoding"] = serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING);
    proof_record["proofChunkSizeBytes"] = serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
    proof_record["proofChunkCount"] = serde_json::json!(transport_hashes.chunk_hashes.len());
    proof_record["proofTotalByteLength"] = serde_json::json!(transport_hashes.total_byte_length);
    proof_record["proofFullObjectHash"] = serde_json::json!(transport_hashes.full_object_hash);
    proof_record["proofChunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    proof_record["proofChunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes.clone());
    let proof_material_root =
        trustee_evaluation_key_proof_material_root(proof_record, &transport_hashes)
            .expect("trustee evaluation-key proof material root");
    proof_record["proofMaterialRoot"] = serde_json::json!(proof_material_root.clone());
    proof_record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
        derive_protocol_hash("TrusteeEvaluationKeyProofRoot", proof_record)
            .expect("transported trustee evaluation-key proof root")
    );

    let mut proof_material = serde_json::json!({
        "objectType": "SetupTransportedEvaluationKeyShareProofMaterial",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_record["proofMaterialRoot"],
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transport_hashes.total_byte_length,
        "proofFullObjectHash": proof_record["proofFullObjectHash"],
        "proofChunkRoot": proof_record["proofChunkRoot"],
        "proofChunkHashes": proof_record["proofChunkHashes"],
    });
    if include_chunks {
        proof_material["chunks"] = serde_json::Value::Array(
            chunks
                .into_iter()
                .enumerate()
                .map(|(chunk_index, chunk)| {
                    serde_json::json!({
                        "chunkIndex": chunk_index,
                        "bytesHex": to_hex(&chunk),
                    })
                })
                .collect::<Vec<_>>(),
        );
    } else {
        register_verified_trustee_evaluation_key_proof_material_chunks(
            &proof_material_root,
            chunks,
        )
        .expect("verified trustee evaluation-key proof material chunks");
    }

    proof_material
}

pub(super) fn move_public_key_share_material_to_transport(
    package: &mut serde_json::Value,
) -> serde_json::Value {
    let embedded_material_set = package["publicKeyShareMaterial"].clone();
    let chunks = encode_public_key_share_material_transport_chunks(&embedded_material_set);
    let transport_hashes = public_key_share_material_transport_hashes(&chunks)
        .expect("public-key material transport hashes");
    let mut transported_material_set = embedded_material_set;
    {
        let material_set_object = transported_material_set
            .as_object_mut()
            .expect("public-key material set object");
        material_set_object.insert(
            "materialEncoding".to_string(),
            serde_json::json!(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING),
        );
        material_set_object.insert(
            "binaryFormat".to_string(),
            serde_json::json!(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT),
        );
        material_set_object.remove("shareMaterialRecords");
        material_set_object.remove("publicKeyShareMaterialSetRoot");
        material_set_object.insert(
            "transport".to_string(),
            serde_json::json!({
                "transportProfileId": "sealed-lattice-setup-binary-chunked-transport-v1",
                "chunkSizeBytes": 1_048_576,
                "chunkCount": transport_hashes.chunk_hashes.len(),
                "totalByteLength": transport_hashes.total_byte_length,
                "fullObjectHash": transport_hashes.full_object_hash,
                "chunkRoot": transport_hashes.chunk_root,
            }),
        );
    }
    transported_material_set["publicKeyShareMaterialSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &transported_material_set)
            .expect("transported public-key material set root")
    );
    package["publicKeyShareMaterial"] = transported_material_set;
    package["publicKeyShareSuccinctProofs"]["publicKeyShareMaterialSetRoot"] =
        package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"].clone();
    rebind_collective_public_key_succinct_proof_roots(package);
    if package["collectivePublicKey"].is_object() {
        package["collectivePublicKey"]["publicKeyShareMaterialSetRoot"] =
            package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"].clone();
        package["collectivePublicKey"]["publicKeyShareSuccinctProofSetRoot"] =
            package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"].clone();
        rebind_collective_public_key_root(package);
    }

    serde_json::json!({
        "objectType": PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE,
        "objectVersion": 1,
        "binaryFormat": PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT,
        "chunkSizeBytes": 1_048_576,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunkRoot": transport_hashes.chunk_root,
        "chunks": chunks
            .into_iter()
            .enumerate()
            .map(|(chunk_index, chunk)| serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesHex": to_hex(&chunk),
            }))
            .collect::<Vec<_>>(),
    })
}

fn encode_public_key_share_material_transport_chunks(
    material_set: &serde_json::Value,
) -> Vec<Vec<u8>> {
    let participant_count = material_set["participantCount"]
        .as_u64()
        .expect("participant count");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLPKSMV1");
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, participant_count);
    append_varuint(
        &mut bytes,
        material_set["rnsLimbCount"]
            .as_u64()
            .expect("RNS limb count"),
    );
    append_varuint(
        &mut bytes,
        material_set["ringDegree"].as_u64().expect("ring degree"),
    );
    let material_records = material_set["shareMaterialRecords"]
        .as_array()
        .expect("public-key share material records");
    for expected_roster_position in 0..participant_count {
        let material_record = material_records
            .iter()
            .find(|record| {
                record["trusteeRosterPosition"].as_u64() == Some(expected_roster_position)
            })
            .expect("public-key material record");
        append_varuint(&mut bytes, expected_roster_position);
        let limbs = material_record["shareCoefficientVectorsByLimb"]
            .as_array()
            .expect("public-key material limbs");
        for (expected_rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
            let limb = limbs
                .iter()
                .find(|candidate| {
                    candidate["rnsLimbIndex"].as_u64() == Some(expected_rns_limb_index as u64)
                })
                .expect("public-key material limb");
            append_varuint(&mut bytes, expected_rns_limb_index as u64);
            bytes.extend_from_slice(&modulus.to_le_bytes());
            let coefficients = coefficient_vector_from_le_hex(
                limb["coefficientsLeHex"]
                    .as_str()
                    .expect("public-key coefficient hex"),
                material_set["ringDegree"]
                    .as_u64()
                    .expect("ring degree")
                    .try_into()
                    .expect("ring degree usize"),
                "public-key material fixture coefficient width",
            )
            .expect("public-key coefficients");
            for coefficient in coefficients {
                bytes.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
    }

    let chunk_size = 1_048_576_usize;
    bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
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

pub(super) fn transported_material_reference_value(
    transported_material: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "objectType": transported_material["objectType"],
        "objectVersion": transported_material["objectVersion"],
        "binaryFormat": transported_material["binaryFormat"],
        "chunkSizeBytes": transported_material["chunkSizeBytes"],
        "chunkCount": transported_material["chunkCount"],
        "totalByteLength": transported_material["totalByteLength"],
        "fullObjectHash": transported_material["fullObjectHash"],
        "chunkHashes": transported_material["chunkHashes"],
        "chunkRoot": transported_material["chunkRoot"],
    })
}

pub(super) fn stream_verified_vss_material_from_package(
    package: &serde_json::Value,
    transported_material: &serde_json::Value,
    derivation_id: &str,
) -> serde_json::Value {
    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": package["setupContext"],
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "transportedVssCoefficientCommitmentMaterial": transported_material_reference_value(transported_material),
    }))
    .expect("begin VSS material stream verification");

    for chunk in transported_material["chunks"]
        .as_array()
        .expect("transport chunks")
    {
        absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
            &serde_json::json!({
                "derivationId": derivation_id,
                "chunkIndex": chunk["chunkIndex"],
                "bytesHex": chunk["bytesHex"],
            }),
        )
        .expect("absorb VSS material stream chunk");
    }

    finish_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
        "sourceTrusteeCoefficientCommitmentRecords": package["vssCoefficientCommitments"]["sourceTrusteeRecords"],
    }))
    .expect("finish VSS material stream verification")
}

pub(super) fn append_vss_material_binary_record(
    output: &mut Vec<u8>,
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    commitment: &crate::bgv::setup::commitment::SetupCommitmentValue,
) {
    append_varuint(output, source_trustee_roster_position);
    append_varuint(output, rns_limb_index as u64);
    append_varuint(output, shamir_coefficient_index);
    for limb in &commitment.limbs {
        append_varuint(output, limb.commitment_modulus_index as u64);
        output.extend(limb.modulus.to_le_bytes());
        for row in &limb.rows {
            for coefficient in row {
                output.extend(coefficient.to_le_bytes());
            }
        }
    }
}
