use super::*;

#[derive(Clone)]
pub(in super::super::super) struct DescriptorBackedVssProofMaterialFixture {
    pub(in super::super::super) verification_request: serde_json::Value,
    retained_proof_materials: Vec<RetainedVssProofMaterial>,
}

#[derive(Clone)]
struct RetainedVssProofMaterial {
    proof_family: &'static str,
    proof_bytes_hash_domain: &'static str,
    proof_material_root: String,
    proof_bytes_hash: String,
    proof_bytes: Vec<u8>,
}

impl DescriptorBackedVssProofMaterialFixture {
    pub(in super::super::super) fn retain_proof_materials(&self) {
        for material in &self.retained_proof_materials {
            if let Some(existing_material) =
                crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
                    material.proof_family,
                    &material.proof_material_root,
                )
                .expect("VSS proof material lookup")
            {
                assert_eq!(
                    existing_material
                        .hash512_hex(material.proof_bytes_hash_domain)
                        .expect("retained VSS proof bytes hash"),
                    material.proof_bytes_hash,
                    "retained VSS proof material must match its descriptor",
                );
                continue;
            }

            authenticate_setup_proof_material_stream_for_test(
                material.proof_family,
                &material.proof_material_root,
                &material.proof_bytes,
            )
            .expect("authenticate VSS proof material stream");
        }
    }
}

struct RewrittenProofMaterialSet {
    transported_proof_material: serde_json::Value,
    retained_proof_materials: Vec<RetainedVssProofMaterial>,
}

struct ProofMaterialFamilyFields {
    proof_family: &'static str,
    proof_bytes_hash_domain: &'static str,
    proof_record_root_field: &'static str,
    transport_set_object_type: &'static str,
    transport_object_type: &'static str,
    proof_bytes_path: &'static str,
}

const VSS_SHARE_LINKAGE_PROOF_MATERIAL_FIELDS: ProofMaterialFamilyFields =
    ProofMaterialFamilyFields {
        proof_family: VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_bytes_hash_domain: VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
        proof_record_root_field: "proofRecordRoot",
        transport_set_object_type: VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE,
        transport_object_type: VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE,
        proof_bytes_path: "share-linkage proofBytesBase64",
    };

const SAME_SECRET_BRIDGE_PROOF_MATERIAL_FIELDS: ProofMaterialFamilyFields =
    ProofMaterialFamilyFields {
        proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_bytes_hash_domain: SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
        proof_record_root_field: "sameSecretBridgeProofRecordRoot",
        transport_set_object_type: SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
        transport_object_type: SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
        proof_bytes_path: "same-secret bridge proofBytesBase64",
    };

// The raw proof builders keep bytes only long enough to checkpoint prover work.
// This transform publishes the production descriptor record, retains the bytes
// in the authenticated-material store, and returns only reference sidecars for
// verification. No verifier consumes inline bytes or transport descriptors.
fn rewrite_proof_material_set_for_authenticated_transport(
    proof_material_set: &mut serde_json::Value,
    fields: &ProofMaterialFamilyFields,
) -> RewrittenProofMaterialSet {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("proof material set proof records");
    let mut transported_proof_materials = Vec::with_capacity(proof_records.len());
    let mut retained_proof_materials = Vec::with_capacity(proof_records.len());
    for proof_record in proof_records.iter_mut() {
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_record["proofBytesBase64"]
                .as_str()
                .expect("embedded proof bytes fixture intermediate"),
            fields.proof_bytes_path,
        )
        .expect("decode proof bytes fixture intermediate");
        let proof_bytes_hash = proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
            .to_string();
        assert_eq!(
            hash512_hex(fields.proof_bytes_hash_domain, &[&proof_bytes]),
            proof_bytes_hash,
            "fixture proof bytes must match their published hash",
        );
        let proof_material_root =
            crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                fields.proof_family,
                &proof_bytes_hash,
            )
            .expect("setup proof material reference root");
        let transport_accounting =
            canonical_setup_proof_material_transport_accounting(fields.proof_family, &proof_bytes)
                .expect("canonical setup proof material transport accounting");

        let record_object = proof_record
            .as_object_mut()
            .expect("proof material record object");
        record_object.remove("proofBytesBase64");
        record_object.remove(fields.proof_record_root_field);
        record_object.insert(
            "proofBytesEncoding".to_string(),
            serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING),
        );
        record_object.insert(
            "proofMaterialRoot".to_string(),
            serde_json::json!(&proof_material_root),
        );
        proof_record[fields.proof_record_root_field] = serde_json::json!(
            derive_canonical_object_hash(proof_record)
                .expect("descriptor-backed proof material record root")
        );

        transported_proof_materials.push(serde_json::json!({
            "objectType": fields.transport_object_type,
            "proofFamily": fields.proof_family,
            "proofMaterialRoot": proof_material_root,
            "chunkCount": transport_accounting.chunk_hashes.len(),
            "totalByteLength": transport_accounting.total_byte_length,
            "fullObjectHash": transport_accounting.full_object_hash,
            "chunkRoot": transport_accounting.chunk_root,
            "chunkHashes": transport_accounting.chunk_hashes,
        }));
        retained_proof_materials.push(RetainedVssProofMaterial {
            proof_family: fields.proof_family,
            proof_bytes_hash_domain: fields.proof_bytes_hash_domain,
            proof_material_root,
            proof_bytes_hash,
            proof_bytes,
        });
    }

    rebind_proof_material_set_root(proof_material_set);

    RewrittenProofMaterialSet {
        transported_proof_material: serde_json::json!({
            "objectType": fields.transport_set_object_type,
            "proofFamily": fields.proof_family,
            "proofMaterials": transported_proof_materials,
        }),
        retained_proof_materials,
    }
}

fn retained_aggregate_threshold_proof_materials(
    package: &serde_json::Value,
) -> Vec<RetainedVssProofMaterial> {
    package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdProofs"]
        .as_array()
        .expect("VSS aggregate threshold proof records")
        .iter()
        .map(|proof_record| {
            let proof_material_root = proof_record["proofMaterialRoot"]
                .as_str()
                .expect("VSS aggregate threshold proof material root")
                .to_string();
            let proof_bytes_hash = proof_record["proofBytesHash"]
                .as_str()
                .expect("VSS aggregate threshold proof bytes hash")
                .to_string();
            let proof_material = crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_material_root,
            )
            .expect("VSS aggregate threshold proof material lookup")
            .expect("VSS aggregate threshold proof material remains retained");
            assert_eq!(
                proof_material
                    .hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)
                    .expect("VSS aggregate threshold proof bytes hash"),
                proof_bytes_hash,
                "retained VSS aggregate threshold proof material must match its descriptor",
            );
            let proof_bytes = proof_material
                .chunks()
                .flat_map(|chunk| chunk.iter().copied())
                .collect();

            RetainedVssProofMaterial {
                proof_family: VSS_SHARE_LINKAGE_PROOF_FAMILY,
                proof_bytes_hash_domain: VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
                proof_material_root,
                proof_bytes_hash,
                proof_bytes,
            }
        })
        .collect()
}

pub(in super::super::super) fn descriptor_backed_vss_proof_material_fixture(
    package: &mut serde_json::Value,
) -> DescriptorBackedVssProofMaterialFixture {
    let aggregate_retained_proof_materials = retained_aggregate_threshold_proof_materials(package);
    let mut aggregate_transport = package
        .as_object_mut()
        .expect("collective setup package object")
        .remove("transportedVssShareLinkageProofMaterial")
        .expect("VSS aggregate threshold transported proof material");
    for transported_material in aggregate_transport["proofMaterials"]
        .as_array_mut()
        .expect("transported VSS aggregate threshold proof materials")
    {
        let proof_material_root = transported_material["proofMaterialRoot"]
            .as_str()
            .expect("VSS aggregate threshold transported proof material root");
        let retained_material = aggregate_retained_proof_materials
            .iter()
            .find(|material| material.proof_material_root == proof_material_root)
            .expect("retained VSS aggregate threshold proof material");
        let transport_accounting = canonical_setup_proof_material_transport_accounting(
            retained_material.proof_family,
            &retained_material.proof_bytes,
        )
        .expect("canonical aggregate threshold proof material transport accounting");
        transported_material["chunkCount"] =
            serde_json::json!(transport_accounting.chunk_hashes.len());
        transported_material["totalByteLength"] =
            serde_json::json!(transport_accounting.total_byte_length);
        transported_material["fullObjectHash"] =
            serde_json::json!(transport_accounting.full_object_hash);
        transported_material["chunkRoot"] = serde_json::json!(transport_accounting.chunk_root);
        transported_material["chunkHashes"] = serde_json::json!(transport_accounting.chunk_hashes);
    }

    let rewritten_share_linkage = rewrite_proof_material_set_for_authenticated_transport(
        &mut package["vssShareLinkageProofMaterialSet"],
        &VSS_SHARE_LINKAGE_PROOF_MATERIAL_FIELDS,
    );
    let mut transported_vss_share_linkage_proof_material =
        rewritten_share_linkage.transported_proof_material;
    transported_vss_share_linkage_proof_material["proofMaterials"]
        .as_array_mut()
        .expect("transported VSS share-linkage proof materials")
        .extend(
            aggregate_transport["proofMaterials"]
                .as_array()
                .expect("transported VSS aggregate threshold proof materials")
                .iter()
                .cloned(),
        );

    let rewritten_same_secret_bridge = rewrite_proof_material_set_for_authenticated_transport(
        &mut package["sameSecretBridgeProofMaterialSet"],
        &SAME_SECRET_BRIDGE_PROOF_MATERIAL_FIELDS,
    );

    package["thresholdShareCommitments"]["shareLinkageProofMaterialSetRoot"] =
        package["vssShareLinkageProofMaterialSet"]["proofMaterialSetRoot"].clone();
    package["thresholdShareCommitments"]
        .as_object_mut()
        .expect("threshold share commitment binding")
        .remove("thresholdShareCommitmentRoot");
    package["thresholdShareCommitments"]["thresholdShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["thresholdShareCommitments"])
            .expect("threshold share commitment root")
    );

    let mut retained_proof_materials = rewritten_share_linkage.retained_proof_materials;
    retained_proof_materials.extend(aggregate_retained_proof_materials);
    retained_proof_materials.extend(rewritten_same_secret_bridge.retained_proof_materials);
    let fixture = DescriptorBackedVssProofMaterialFixture {
        verification_request: serde_json::json!({
            "transportedVssShareLinkageProofMaterial":
                transported_vss_share_linkage_proof_material,
            "transportedSameSecretBridgeProofMaterial":
                rewritten_same_secret_bridge.transported_proof_material,
        }),
        retained_proof_materials,
    };
    fixture.retain_proof_materials();
    fixture
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

#[test]
fn vss_share_linkage_uses_authenticated_descriptor_material() {
    let mut package = minimal_collective_setup_package();
    let fixture = descriptor_backed_vss_proof_material_fixture(&mut package);
    let _proof_material_eviction_guard =
        crate::bgv::setup::setup_proof::VerifiedSetupProofMaterialEvictionGuard::for_request(
            &fixture.verification_request,
        );
    let transported_vss_share_linkage_proof_material =
        &fixture.verification_request["transportedVssShareLinkageProofMaterial"];
    let request = serde_json::json!({
        "statement": package["vssShareLinkageStatement"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
        "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
        "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
        "transportedVssShareLinkageProofMaterial":
            transported_vss_share_linkage_proof_material,
    });
    let verification =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(&request)
            .expect("descriptor-backed share-linkage proof material set verifies");
    assert_eq!(
        verification["proofMaterialSetRoot"],
        package["vssShareLinkageProofMaterialSet"]["proofMaterialSetRoot"],
        "verification must recompute the descriptor-backed proof material set root",
    );

    let first_proof_material_root = transported_vss_share_linkage_proof_material["proofMaterials"]
        [0]["proofMaterialRoot"]
        .as_str()
        .expect("first VSS share-linkage proof material root");
    assert!(
        crate::bgv::setup::take_verified_canonical_proof_material_bytes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            first_proof_material_root,
        )
        .expect("take retained VSS share-linkage proof material")
        .is_some(),
        "the missing-material case must remove an authenticated source",
    );
    let missing_material_error =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(&request)
            .expect_err(
                "descriptor-backed share-linkage records must require authenticated material",
            );
    assert_eq!(
        missing_material_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
    );
    assert!(
        missing_material_error
            .message
            .contains("missing canonical stream-authenticated proof material"),
        "unexpected missing-material diagnostic: {}",
        missing_material_error.message,
    );
    fixture.retain_proof_materials();

    let mut wrong_root_request = request.clone();
    wrong_root_request["transportedVssShareLinkageProofMaterial"]["proofMaterials"][0]["proofMaterialRoot"] =
        serde_json::json!("0".repeat(128));
    let wrong_root_error =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &wrong_root_request,
        )
        .expect_err("a wrong share-linkage proof material root must be rejected");
    assert_eq!(
        wrong_root_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
    );
    assert!(
        wrong_root_error
            .message
            .contains("missing the requested proofMaterialRoot"),
        "unexpected wrong-root diagnostic: {}",
        wrong_root_error.message,
    );

    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::DealerVssShareLinkageProof,
        &fixture.retained_proof_materials[0].proof_bytes,
    );
}

#[test]
fn same_secret_bridge_uses_authenticated_descriptor_material() {
    let mut package = minimal_collective_setup_package();
    let fixture = descriptor_backed_vss_proof_material_fixture(&mut package);
    let _proof_material_eviction_guard =
        crate::bgv::setup::setup_proof::VerifiedSetupProofMaterialEvictionGuard::for_request(
            &fixture.verification_request,
        );
    let transported_same_secret_bridge_proof_material =
        &fixture.verification_request["transportedSameSecretBridgeProofMaterial"];
    let request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "vssCoefficientCommitments": package["vssCoefficientCommitments"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
        "transportedSameSecretBridgeProofMaterial":
            transported_same_secret_bridge_proof_material,
    });
    let verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(&request)
            .expect("descriptor-backed same-secret bridge proof material set verifies");
    assert_eq!(
        verification["proofMaterialSetRoot"],
        package["sameSecretBridgeProofMaterialSet"]["proofMaterialSetRoot"],
        "verification must recompute the descriptor-backed proof material set root",
    );

    let first_proof_material_root = transported_same_secret_bridge_proof_material["proofMaterials"]
        [0]["proofMaterialRoot"]
        .as_str()
        .expect("first same-secret bridge proof material root");
    assert!(
        crate::bgv::setup::take_verified_canonical_proof_material_bytes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            first_proof_material_root,
        )
        .expect("take retained same-secret bridge proof material")
        .is_some(),
        "the missing-material case must remove an authenticated source",
    );
    let missing_material_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(&request)
            .expect_err(
                "descriptor-backed same-secret bridge records must require authenticated material",
            );
    assert_eq!(
        missing_material_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
    );
    assert!(
        missing_material_error
            .message
            .contains("missing canonical stream-authenticated proof material"),
        "unexpected missing-material diagnostic: {}",
        missing_material_error.message,
    );
    fixture.retain_proof_materials();

    let mut wrong_root_request = request;
    wrong_root_request["transportedSameSecretBridgeProofMaterial"]["proofMaterials"][0]["proofMaterialRoot"] =
        serde_json::json!("0".repeat(128));
    let wrong_root_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &wrong_root_request,
        )
        .expect_err("a wrong same-secret bridge proof material root must be rejected");
    assert_eq!(
        wrong_root_error.code,
        crate::encoding::CanonicalErrorCode::ComponentMismatch,
    );
    assert!(
        wrong_root_error
            .message
            .contains("missing the requested proofMaterialRoot"),
        "unexpected wrong-root diagnostic: {}",
        wrong_root_error.message,
    );

    let same_secret_material = fixture
        .retained_proof_materials
        .iter()
        .find(|material| material.proof_family == SAME_SECRET_BRIDGE_PROOF_FAMILY)
        .expect("same-secret bridge retained proof material");
    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::SameSecretProof,
        &same_secret_material.proof_bytes,
    );
}

fn assert_tampered_canonical_stream_chunk_is_refused(
    stream_domain: crate::foundation::CanonicalStreamDomain,
    proof_bytes: &[u8],
) {
    use crate::foundation::{
        CanonicalStreamVerifier, FOUNDATION_PROFILE, RefusalReason, VerificationResult,
        derive_canonical_stream_descriptor,
    };

    let descriptor = derive_canonical_stream_descriptor(stream_domain, proof_bytes)
        .expect("canonical proof stream descriptor");
    let mut verifier =
        CanonicalStreamVerifier::new(stream_domain, descriptor).expect("canonical stream verifier");
    let first_chunk_length = proof_bytes
        .len()
        .min(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut tampered_chunk = proof_bytes[..first_chunk_length].to_vec();
    tampered_chunk[0] ^= 1;
    assert_eq!(
        verifier.absorb_chunk(0, &tampered_chunk),
        VerificationResult::refused(RefusalReason::WrongHashOrRoot),
        "canonical stream authentication must reject tampered proof bytes",
    );
}
