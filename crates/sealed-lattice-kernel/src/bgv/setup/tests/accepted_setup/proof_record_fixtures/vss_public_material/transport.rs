use super::*;

#[derive(Clone)]
pub(in super::super::super) struct DescriptorBackedVssProofMaterialFixture {
    retained_proof_materials: Vec<RetainedVssProofMaterial>,
}

#[derive(Clone)]
struct RetainedVssProofMaterial {
    proof_family: &'static str,
    proof_bytes_hash_domain: &'static str,
    proof_material_root: String,
    proof_bytes_hash: String,
    proof_bytes: Option<Vec<u8>>,
    proof_binding_lease: Option<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

impl DescriptorBackedVssProofMaterialFixture {
    pub(super) fn begin_proof_binding_session(
        &self,
    ) -> crate::bgv::setup::AcceptedSetupProofBindingSession {
        let proof_binding_session =
            crate::bgv::setup::AcceptedSetupProofBindingSession::begin_fresh()
                .expect("begin descriptor-backed VSS proof binding session");
        self.retain_proof_materials(&proof_binding_session);
        proof_binding_session
    }

    pub(in super::super::super) fn retain_proof_materials(
        &self,
        proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    ) {
        for material in &self.retained_proof_materials {
            if let Some(proof_binding_lease) = &material.proof_binding_lease {
                crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
                    proof_binding_session.session_handle,
                    proof_binding_lease,
                )
                .expect("restore verifier-owned VSS proof binding");
                continue;
            }
            let proof_bytes = material
                .proof_bytes
                .as_deref()
                .expect("retained VSS proof material has bytes or a verifier-owned binding");
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
                proof_bytes,
            )
            .expect("authenticate VSS proof material stream");
        }
    }

    pub(in super::super::super) fn proof_binding_leases(
        &self,
    ) -> Vec<crate::bgv::setup::CanonicalSetupProofBindingLease> {
        self.retained_proof_materials
            .iter()
            .filter_map(|material| material.proof_binding_lease.clone())
            .collect()
    }
}

struct ProofMaterialFamilyFields {
    proof_family: &'static str,
    proof_bytes_hash_domain: &'static str,
    proof_record_root_field: Option<&'static str>,
}

const VSS_SHARE_LINKAGE_PROOF_MATERIAL_FIELDS: ProofMaterialFamilyFields =
    ProofMaterialFamilyFields {
        proof_family: VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_bytes_hash_domain: VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
        proof_record_root_field: None,
    };

const SAME_SECRET_BRIDGE_PROOF_MATERIAL_FIELDS: ProofMaterialFamilyFields =
    ProofMaterialFamilyFields {
        proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY,
        proof_bytes_hash_domain: SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
        proof_record_root_field: Some("sameSecretBridgeProofRecordRoot"),
    };

// The raw proof builders keep bytes only long enough to checkpoint prover work.
// This transform publishes the production descriptor record, retains the bytes
// in the authenticated-material store. No verifier consumes inline proof bytes.
fn rewrite_proof_material_set_for_authenticated_store(
    proof_material_set: &mut serde_json::Value,
    fields: &ProofMaterialFamilyFields,
    proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
) -> Vec<RetainedVssProofMaterial> {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("proof material set proof records");
    let mut retained_proof_materials = Vec::with_capacity(proof_records.len());
    for proof_record in proof_records.iter_mut() {
        let proof_bytes_hash = proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
            .to_string();
        let proof_material_root =
            crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                fields.proof_family,
                &proof_bytes_hash,
            )
            .expect("setup proof material reference root");
        assert_eq!(
            proof_record["proofMaterialRoot"]
                .as_str()
                .expect("descriptor-backed proof material root"),
            proof_material_root,
            "descriptor-backed proof material root",
        );
        let proof_binding_lease = proof_binding_leases
            .iter()
            .find(|lease| lease.proof_material_root() == proof_material_root)
            .cloned()
            .expect("descriptor-backed proof binding");
        let retained_material = RetainedVssProofMaterial {
            proof_family: fields.proof_family,
            proof_bytes_hash_domain: fields.proof_bytes_hash_domain,
            proof_material_root: proof_material_root.clone(),
            proof_bytes_hash: proof_bytes_hash.clone(),
            proof_bytes: None,
            proof_binding_lease: Some(proof_binding_lease),
        };

        let record_object = proof_record
            .as_object_mut()
            .expect("proof material record object");
        if let Some(proof_record_root_field) = fields.proof_record_root_field {
            record_object.remove(proof_record_root_field);
        }
        record_object.insert(
            "proofMaterialRoot".to_string(),
            serde_json::json!(&proof_material_root),
        );
        if let Some(proof_record_root_field) = fields.proof_record_root_field {
            proof_record[proof_record_root_field] = serde_json::json!(
                derive_canonical_object_hash(proof_record)
                    .expect("descriptor-backed proof material record root")
            );
        }

        retained_proof_materials.push(retained_material);
    }

    retained_proof_materials
}

fn retained_aggregate_threshold_proof_materials(
    package: &serde_json::Value,
    proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
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
            let proof_binding_lease = proof_binding_leases
                .iter()
                .find(|lease| lease.proof_material_root() == proof_material_root)
                .cloned()
                .expect("VSS aggregate threshold proof binding");

            RetainedVssProofMaterial {
                proof_family: VSS_SHARE_LINKAGE_PROOF_FAMILY,
                proof_bytes_hash_domain: VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
                proof_material_root,
                proof_bytes_hash,
                proof_bytes: None,
                proof_binding_lease: Some(proof_binding_lease),
            }
        })
        .collect()
}

pub(in super::super::super) fn descriptor_backed_vss_proof_material_fixture(
    package: &mut serde_json::Value,
    proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
) -> DescriptorBackedVssProofMaterialFixture {
    let aggregate_retained_proof_materials =
        retained_aggregate_threshold_proof_materials(package, proof_binding_leases);

    let share_linkage_proof_materials = rewrite_proof_material_set_for_authenticated_store(
        &mut package["vssShareLinkageProofMaterialSet"],
        &VSS_SHARE_LINKAGE_PROOF_MATERIAL_FIELDS,
        proof_binding_leases,
    );
    let same_secret_bridge_proof_materials = rewrite_proof_material_set_for_authenticated_store(
        &mut package["sameSecretBridgeProofMaterialSet"],
        &SAME_SECRET_BRIDGE_PROOF_MATERIAL_FIELDS,
        proof_binding_leases,
    );

    let mut retained_proof_materials = share_linkage_proof_materials;
    retained_proof_materials.extend(aggregate_retained_proof_materials);
    retained_proof_materials.extend(same_secret_bridge_proof_materials);
    DescriptorBackedVssProofMaterialFixture {
        retained_proof_materials,
    }
}

#[test]
fn vss_share_linkage_uses_authenticated_descriptor_material() {
    let mut finalized_fixture = minimal_collective_setup_package_fixture();
    let fixture = descriptor_backed_vss_proof_material_fixture(
        &mut finalized_fixture.package,
        &finalized_fixture.proof_binding_leases,
    );
    let package = finalized_fixture.package;
    let request = serde_json::json!({
        "statement": package["vssShareLinkageStatement"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
        "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
        "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
    });
    let proof_binding_session = fixture.begin_proof_binding_session();
    crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
        &request,
        Some(&proof_binding_session),
    )
    .expect("descriptor-backed share-linkage proof material set verifies");
    crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
        proof_binding_session.session_handle,
    )
    .expect("cancel direct share-linkage fixture binding session");
    let first_proof_material_root =
        package["vssShareLinkageProofMaterialSet"]["proofRecords"][0]["proofMaterialRoot"]
            .as_str()
            .expect("first VSS share-linkage proof material root");
    assert!(
        crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            first_proof_material_root,
        )
        .expect("lookup consumed VSS share-linkage proof material")
        .is_none(),
        "verification must release each authenticated VSS proof source as it advances",
    );
    crate::bgv::setup::evict_verified_canonical_setup_proof_materials(&[
        first_proof_material_root.to_string()
    ]);
    let missing_material_error =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(&request, None)
            .expect_err(
                "descriptor-backed share-linkage records must require authenticated material",
            );
    assert_eq!(
        missing_material_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
        "unexpected missing-material diagnostic: {}",
        missing_material_error.message,
    );
    assert!(
        missing_material_error
            .message
            .contains("has no canonical stream-authenticated proof material"),
        "unexpected missing-material diagnostic: {}",
        missing_material_error.message,
    );
    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::DealerVssShareLinkageProof,
        &vec![0x5a; crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length + 1],
    );
}

#[test]
fn same_secret_bridge_uses_authenticated_descriptor_material() {
    let mut finalized_fixture = minimal_collective_setup_package_fixture();
    let fixture = descriptor_backed_vss_proof_material_fixture(
        &mut finalized_fixture.package,
        &finalized_fixture.proof_binding_leases,
    );
    let package = finalized_fixture.package;
    let request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "vssCoefficientCommitments": package["vssCoefficientCommitments"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
    });
    let proof_binding_session = fixture.begin_proof_binding_session();
    crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
        &request,
        Some(&proof_binding_session),
    )
    .expect("descriptor-backed same-secret bridge proof material set verifies");
    crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
        proof_binding_session.session_handle,
    )
    .expect("cancel direct same-secret fixture binding session");
    let first_proof_material_root = package["sameSecretBridgeProofMaterialSet"]["proofRecords"][0]
        ["proofMaterialRoot"]
        .as_str()
        .expect("first same-secret bridge proof material root");
    assert!(
        crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            first_proof_material_root,
        )
        .expect("lookup consumed same-secret bridge proof material")
        .is_none(),
        "verification must release each authenticated bridge proof source as it advances",
    );
    crate::bgv::setup::evict_verified_canonical_setup_proof_materials(&[
        first_proof_material_root.to_string()
    ]);
    let missing_material_error =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(&request, None)
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
            .contains("has no canonical stream-authenticated proof material"),
        "unexpected missing-material diagnostic: {}",
        missing_material_error.message,
    );
    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::SameSecretProof,
        &vec![0xa5; crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length + 1],
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
