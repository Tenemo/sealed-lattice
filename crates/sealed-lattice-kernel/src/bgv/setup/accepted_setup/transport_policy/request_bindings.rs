use super::*;

struct SetupTransportExpectedObject {
    object_root: String,
    object_path: String,
}

#[derive(Clone, Copy)]
struct SetupTransportMaterialDescriptor {
    object_root: &'static str,
}

pub(in super::super) fn verify_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Option<Value>> {
    match verify_setup_transport_request_bindings_in_session(
        setup_package,
        request,
        proof_binding_session,
    )? {
        Ok(()) => Ok(None),
        Err(refusal) => Ok(Some(verification_response(
            None,
            Vec::new(),
            vec![refusal],
            Vec::new(),
        )?)),
    }
}

#[cfg(test)]
pub(super) fn verify_setup_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Result<(), Refusal>> {
    verify_setup_transport_request_bindings_in_session(setup_package, request, None)
}

fn verify_setup_transport_request_bindings_in_session(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let referenced_public_key_material_roots =
        setup_transport_referenced_public_key_share_material_roots(setup_package)?;
    transport_canonical_try!(require_setup_transport_single_material_entry(
        request.get("transportedPublicKeyShareMaterial"),
        "transportedPublicKeyShareMaterial",
        SetupTransportMaterialDescriptor {
            object_root: "publicKeyShareMaterialSetRoot",
        },
        &referenced_public_key_material_roots,
        AuthenticatedSetupTransportMaterialSource::PublicKeyShareMaterial,
        proof_binding_session,
    ));

    let referenced_public_key_proof_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "publicKeyShareSuccinctProofs",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        request.get("transportedPublicKeyShareProofMaterial"),
        "transportedPublicKeyShareProofMaterial",
        SetupTransportMaterialDescriptor {
            object_root: "proofMaterialRoot",
        },
        &referenced_public_key_proof_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(PUBLIC_KEY_SHARE_PROOF_FAMILY),
        proof_binding_session,
    ));

    let mut referenced_vss_share_linkage_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "vssShareLinkageProofMaterialSet",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    referenced_vss_share_linkage_roots.extend(setup_transport_referenced_proof_material_roots(
        setup_package,
        "vssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdProofs",
        "proofMaterialRoot",
    )?);
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        request.get("transportedVssShareLinkageProofMaterial"),
        "transportedVssShareLinkageProofMaterial",
        SetupTransportMaterialDescriptor {
            object_root: "proofMaterialRoot",
        },
        &referenced_vss_share_linkage_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(VSS_SHARE_LINKAGE_PROOF_FAMILY),
        proof_binding_session,
    ));

    let referenced_same_secret_bridge_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "sameSecretBridgeProofMaterialSet",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        request.get("transportedSameSecretBridgeProofMaterial"),
        "transportedSameSecretBridgeProofMaterial",
        SetupTransportMaterialDescriptor {
            object_root: "proofMaterialRoot",
        },
        &referenced_same_secret_bridge_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(SAME_SECRET_BRIDGE_PROOF_FAMILY),
        proof_binding_session,
    ));

    let referenced_evaluation_key_proof_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "trusteeEvaluationKeyProofs",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        request.get("transportedEvaluationKeyShareProofMaterial"),
        "transportedEvaluationKeyShareProofMaterial",
        SetupTransportMaterialDescriptor {
            object_root: "proofMaterialRoot",
        },
        &referenced_evaluation_key_proof_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,),
        proof_binding_session,
    ));

    let referenced_evaluation_key_component_roots =
        setup_transport_referenced_evaluation_key_material_roots(
            setup_package,
            "keySwitchComponentMaterialRoot",
        )?;
    transport_canonical_try!(require_setup_transport_material_entries(
        request.get("transportedEvaluationKeyShareComponentMaterial"),
        SetupTransportMaterialSetLocation {
            material_set_path: "transportedEvaluationKeyShareComponentMaterial",
            material_array_field_name: "componentMaterials",
        },
        SetupTransportMaterialDescriptor {
            object_root: "keySwitchComponentMaterialRoot",
        },
        &referenced_evaluation_key_component_roots,
        AuthenticatedSetupTransportMaterialSource::EvaluationKeyComponent,
        proof_binding_session,
    ));

    let referenced_public_evaluation_key_material_roots =
        setup_transport_referenced_public_evaluation_key_material_roots(setup_package)?;
    transport_canonical_try!(require_setup_transport_material_entries(
        request.get("transportedPublicEvaluationKeyMaterial"),
        SetupTransportMaterialSetLocation {
            material_set_path: "transportedPublicEvaluationKeyMaterial",
            material_array_field_name: "publicEvaluationKeyMaterials",
        },
        SetupTransportMaterialDescriptor {
            object_root: "publicEvaluationKeyMaterialRoot",
        },
        &referenced_public_evaluation_key_material_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(
            PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
        ),
        proof_binding_session,
    ));

    Ok(Ok(()))
}

fn setup_transport_referenced_proof_material_roots(
    setup_package: &Value,
    record_set_name: &str,
    records_field_name: &str,
    root_field_name: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let Some(record_set) = setup_package.get(record_set_name) else {
        return Ok(BTreeSet::new());
    };
    let Some(records) = record_set.get(records_field_name).and_then(Value::as_array) else {
        return Ok(BTreeSet::new());
    };

    let mut referenced_roots = BTreeSet::new();
    for record in records {
        if let Some(root) = record.get(root_field_name).and_then(Value::as_str) {
            validate_hash_string(
                root,
                &format!("setupPackage.{record_set_name}.{records_field_name}.{root_field_name}"),
            )?;
            referenced_roots.insert(root.to_string());
        }
    }

    Ok(referenced_roots)
}

fn setup_transport_referenced_public_key_share_material_roots(
    setup_package: &Value,
) -> CanonicalResult<BTreeSet<String>> {
    let mut referenced_roots = BTreeSet::new();
    let Some(material) = setup_package.get("publicKeyShareMaterial") else {
        return Ok(referenced_roots);
    };
    if material.get("materialEncoding").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING)
    {
        return Ok(referenced_roots);
    }
    if let Some(root) = material
        .get("publicKeyShareMaterialSetRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            root,
            "setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
        )?;
        referenced_roots.insert(root.to_string());
    }

    Ok(referenced_roots)
}

fn setup_transport_referenced_evaluation_key_material_roots(
    setup_package: &Value,
    root_field_name: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let mut referenced_roots = BTreeSet::new();
    if let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") {
        for records_field_name in ["roundOneRecords", "roundTwoRecords"] {
            setup_transport_collect_optional_record_roots(
                rounds,
                records_field_name,
                root_field_name,
                &format!(
                    "setupPackage.relinearizationKeyShareRounds.{records_field_name}.{root_field_name}"
                ),
                &mut referenced_roots,
            )?;
        }
    }
    if let Some(batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in batches {
            setup_transport_collect_optional_record_roots(
                batch,
                "galoisKeyShareMaterialRecords",
                root_field_name,
                &format!(
                    "setupPackage.galoisKeyShareBatches.galoisKeyShareMaterialRecords.{root_field_name}"
                ),
                &mut referenced_roots,
            )?;
        }
    }

    Ok(referenced_roots)
}

fn setup_transport_referenced_public_evaluation_key_material_roots(
    setup_package: &Value,
) -> CanonicalResult<BTreeSet<String>> {
    let mut referenced_roots = BTreeSet::new();
    if let Some(root) = setup_package
        .get("evaluationKeys")
        .and_then(|evaluation_keys| evaluation_keys.get("publicEvaluationKeyMaterialRoot"))
        .and_then(Value::as_str)
    {
        validate_hash_string(
            root,
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialRoot",
        )?;
        referenced_roots.insert(root.to_string());
    }

    Ok(referenced_roots)
}

fn setup_transport_collect_optional_record_roots(
    value: &Value,
    records_field_name: &str,
    root_field_name: &str,
    object_path: &str,
    referenced_roots: &mut BTreeSet<String>,
) -> CanonicalResult<()> {
    let Some(records) = value.get(records_field_name).and_then(Value::as_array) else {
        return Ok(());
    };
    for record in records {
        if let Some(root) = record.get(root_field_name).and_then(Value::as_str) {
            validate_hash_string(root, object_path)?;
            referenced_roots.insert(root.to_string());
        }
    }

    Ok(())
}

fn require_setup_transport_proof_material_entries(
    material_set: Option<&Value>,
    material_set_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Result<(), Refusal>> {
    let Some(material_set) = material_set else {
        return Ok(if referenced_material_roots.is_empty() {
            Ok(())
        } else {
            Err(missing_referenced_transport_material_refusal(
                material_set_path,
                referenced_material_roots,
            ))
        });
    };
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Ok(Err(Refusal::new(
            "transportedProofMaterialListMissing",
            format!(
                "{material_set_path}.proofMaterials must list transported proof material objects"
            ),
            format!("{material_set_path}.proofMaterials"),
        )));
    };
    let mut matched_material_roots = BTreeSet::new();
    for (material_index, proof_material) in proof_materials.iter().enumerate() {
        let object_path = format!("{material_set_path}.proofMaterials[{material_index}]");
        let Some(object_root) = referenced_material_root(
            proof_material,
            descriptor.object_root,
            &object_path,
            referenced_material_roots,
        )?
        else {
            continue;
        };
        if !matched_material_roots.insert(object_root.clone()) {
            return Ok(Err(Refusal::new(
                "transportedMaterialRootDuplicate",
                format!("{material_set_path}.proofMaterials must not repeat a referenced root"),
                object_path,
            )));
        }
        let expected_material =
            setup_transport_expected_material_with_root(object_root, object_path);
        if let Err(refusal) = require_authenticated_setup_transport_entry(
            proof_material,
            &expected_material,
            authenticated_source,
            proof_binding_session,
        )? {
            return Ok(Err(refusal));
        }
    }
    if matched_material_roots != *referenced_material_roots {
        return Ok(Err(missing_referenced_transport_material_refusal(
            material_set_path,
            referenced_material_roots,
        )));
    }

    Ok(Ok(()))
}

struct SetupTransportMaterialSetLocation {
    material_set_path: &'static str,
    material_array_field_name: &'static str,
}

fn require_setup_transport_material_entries(
    material_set: Option<&Value>,
    material_set_location: SetupTransportMaterialSetLocation,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Result<(), Refusal>> {
    let SetupTransportMaterialSetLocation {
        material_set_path,
        material_array_field_name,
    } = material_set_location;
    let Some(material_set) = material_set else {
        return Ok(if referenced_material_roots.is_empty() {
            Ok(())
        } else {
            Err(missing_referenced_transport_material_refusal(
                material_set_path,
                referenced_material_roots,
            ))
        });
    };
    let Some(materials) = material_set
        .get(material_array_field_name)
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            "transportedMaterialListMissing",
            format!(
                "{material_set_path}.{material_array_field_name} must list transported material objects"
            ),
            format!("{material_set_path}.{material_array_field_name}"),
        )));
    };
    let mut matched_material_roots = BTreeSet::new();
    for (material_index, material) in materials.iter().enumerate() {
        let object_path =
            format!("{material_set_path}.{material_array_field_name}[{material_index}]");
        let Some(object_root) = referenced_material_root(
            material,
            descriptor.object_root,
            &object_path,
            referenced_material_roots,
        )?
        else {
            continue;
        };
        if !matched_material_roots.insert(object_root.clone()) {
            return Ok(Err(Refusal::new(
                "transportedMaterialRootDuplicate",
                format!(
                    "{material_set_path}.{material_array_field_name} must not repeat a referenced root"
                ),
                object_path,
            )));
        }
        let expected_material =
            setup_transport_expected_material_with_root(object_root, object_path);
        if let Err(refusal) = require_authenticated_setup_transport_entry(
            material,
            &expected_material,
            authenticated_source,
            proof_binding_session,
        )? {
            return Ok(Err(refusal));
        }
    }
    if matched_material_roots != *referenced_material_roots {
        return Ok(Err(missing_referenced_transport_material_refusal(
            material_set_path,
            referenced_material_roots,
        )));
    }

    Ok(Ok(()))
}

fn require_setup_transport_single_material_entry(
    material: Option<&Value>,
    material_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Result<(), Refusal>> {
    if referenced_material_roots.is_empty() {
        return Ok(Ok(()));
    }
    let Some(material) = material else {
        return Ok(Err(missing_referenced_transport_material_refusal(
            material_path,
            referenced_material_roots,
        )));
    };
    let object_root = match referenced_material_root(
        material,
        descriptor.object_root,
        material_path,
        referenced_material_roots,
    )? {
        Some(root) => root,
        None => {
            return Ok(Err(missing_referenced_transport_material_refusal(
                material_path,
                referenced_material_roots,
            )));
        }
    };
    let expected_material =
        setup_transport_expected_material_with_root(object_root, material_path.to_string());
    require_authenticated_setup_transport_entry(
        material,
        &expected_material,
        authenticated_source,
        proof_binding_session,
    )
}

fn missing_referenced_transport_material_refusal(
    material_path: &str,
    referenced_material_roots: &BTreeSet<String>,
) -> Refusal {
    Refusal::new(
        "transportedMaterialReferenceMissing",
        format!(
            "{material_path} must account for every setup-package material root: {}",
            referenced_material_roots
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        material_path,
    )
}

#[derive(Clone, Copy)]
enum AuthenticatedSetupTransportMaterialSource {
    SetupProof(&'static str),
    EvaluationKeyComponent,
    PublicKeyShareMaterial,
}

fn require_authenticated_setup_transport_entry(
    material: &Value,
    expected: &SetupTransportExpectedObject,
    source: AuthenticatedSetupTransportMaterialSource,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<Result<(), Refusal>> {
    let stream_summary = match source {
        AuthenticatedSetupTransportMaterialSource::SetupProof(proof_family) => {
            authenticated_setup_proof_material_stream_summary_in_session(
                proof_binding_session,
                proof_family,
                &expected.object_root,
            )
        }
        AuthenticatedSetupTransportMaterialSource::EvaluationKeyComponent => {
            let Some(proof_family) = material.get("proofFamily").and_then(Value::as_str) else {
                return Ok(Err(Refusal::new(
                    "transportedMaterialProofFamilyMissing",
                    format!("{}.proofFamily is required", expected.object_path),
                    format!("{}.proofFamily", expected.object_path),
                )));
            };
            authenticated_evaluation_key_component_stream_summary_in_session(
                proof_binding_session,
                proof_family,
                &expected.object_root,
            )
        }
        AuthenticatedSetupTransportMaterialSource::PublicKeyShareMaterial => {
            authenticated_public_key_share_material_stream_summary_in_session(
                proof_binding_session,
                &expected.object_root,
            )
        }
    };
    match stream_summary {
        Ok(Some(_summary)) => {}
        Ok(None) => {
            return Ok(Err(Refusal::new(
                "transportedObjectAuthenticatedMaterialMissing",
                format!(
                    "{} must refer to canonical stream material authenticated during this verification",
                    expected.object_path
                ),
                &expected.object_path,
            )));
        }
        Err(error) if error.code == CanonicalErrorCode::ComponentMismatch => {
            return Ok(Err(Refusal::new(
                "transportedObjectAuthenticatedMaterialMismatch",
                format!(
                    "{} does not own its authenticated canonical stream material: {}",
                    expected.object_path, error.message
                ),
                &expected.object_path,
            )));
        }
        Err(error) => return Err(error),
    }

    Ok(Ok(()))
}

fn referenced_material_root(
    material: &Value,
    root_field_name: &str,
    object_path: &str,
    referenced_material_roots: &BTreeSet<String>,
) -> CanonicalResult<Option<String>> {
    let Some(object_root) = material.get(root_field_name).and_then(Value::as_str) else {
        return Ok(None);
    };
    if !referenced_material_roots.contains(object_root) {
        return Ok(None);
    }
    validate_hash_string(object_root, &format!("{object_path}.{root_field_name}"))?;

    Ok(Some(object_root.to_string()))
}

fn setup_transport_expected_material_with_root(
    object_root: String,
    object_path: String,
) -> SetupTransportExpectedObject {
    SetupTransportExpectedObject {
        object_root,
        object_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encoding::append_varuint,
        foundation::{
            CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CanonicalStreamDomain, FOUNDATION_PROFILE,
            derive_canonical_stream_descriptor,
        },
    };

    fn protocol_hash(character: char) -> String {
        character.to_string().repeat(128)
    }

    fn authenticate_bgv_material_stream(
        family_code: u32,
        stream_domain: CanonicalStreamDomain,
        material_root: &str,
        material_bytes: &[u8],
        capability_byte: u8,
    ) {
        let descriptor = derive_canonical_stream_descriptor(stream_domain, material_bytes)
            .expect("canonical material descriptor");
        let descriptor_bytes = descriptor.encode().expect("encode material descriptor");
        let material_root_bytes = crate::transcript_core::decode_hex(material_root)
            .expect("canonical material root bytes");
        let capability = [capability_byte; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let stream = crate::bgv::setup::begin_bgv_canonical_stream(
            family_code,
            &material_root_bytes,
            &descriptor_bytes,
            capability,
        )
        .expect("begin BGV canonical material stream");
        for (chunk_index, chunk) in material_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            crate::bgv::setup::absorb_bgv_canonical_stream_chunk(
                stream.handle,
                &capability,
                u32::try_from(chunk_index).expect("canonical chunk index fits u32"),
                chunk,
            )
            .expect("absorb BGV canonical material chunk");
        }
        crate::bgv::setup::finish_bgv_canonical_stream(stream.handle, &capability)
            .expect("finish BGV canonical material stream");
    }

    fn public_key_share_material_bytes() -> Vec<u8> {
        let participant_count = MINIMUM_SUPPORTED_PARTICIPANT_COUNT;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SLPKSMV1");
        for value in [1, participant_count, DATA_PRIMES.len() as u64, 1] {
            append_varuint(&mut bytes, value);
        }
        for trustee_roster_position in 0..participant_count {
            append_varuint(&mut bytes, trustee_roster_position);
            for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
                append_varuint(&mut bytes, rns_limb_index as u64);
                bytes.extend_from_slice(&rns_prime.to_le_bytes());
                bytes.extend_from_slice(
                    &((trustee_roster_position + rns_limb_index as u64) % rns_prime).to_le_bytes(),
                );
            }
        }
        bytes
    }

    #[test]
    fn every_public_setup_binary_material_reference_requires_its_transport_sidecar() {
        let material_root = protocol_hash('a');
        let packages = [
            json!({
                "publicKeyShareMaterial": {
                    "materialEncoding": PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
                    "publicKeyShareMaterialSetRoot": material_root,
                },
            }),
            json!({
                "publicKeyShareSuccinctProofs": {
                    "proofRecords": [{ "proofMaterialRoot": material_root }],
                },
            }),
            json!({
                "vssShareLinkageProofMaterialSet": {
                    "proofRecords": [{ "proofMaterialRoot": material_root }],
                },
            }),
            json!({
                "vssPublicAggregateThresholdCommitmentSet": {
                    "aggregateThresholdProofs": [{ "proofMaterialRoot": material_root }],
                },
            }),
            json!({
                "sameSecretBridgeProofMaterialSet": {
                    "proofRecords": [{ "proofMaterialRoot": material_root }],
                },
            }),
            json!({
                "trusteeEvaluationKeyProofs": {
                    "proofRecords": [{ "proofMaterialRoot": material_root }],
                },
            }),
            json!({
                "relinearizationKeyShareRounds": {
                    "roundOneRecords": [{ "keySwitchComponentMaterialRoot": material_root }],
                },
            }),
            json!({
                "galoisKeyShareBatches": [{
                    "galoisKeyShareMaterialRecords": [{
                        "keySwitchComponentMaterialRoot": material_root,
                    }],
                }],
            }),
            json!({
                "evaluationKeys": {
                    "publicEvaluationKeyMaterialRoot": material_root,
                },
            }),
        ];

        for package in packages {
            let refusal = verify_setup_transport_request_bindings(&package, &json!({}))
                .expect("transport request binding verification")
                .expect_err("a referenced binary material without its sidecar must refuse");

            assert_eq!(refusal.reason_code, "transportedMaterialReferenceMissing");
        }
    }

    #[test]
    fn request_material_must_have_an_authenticated_canonical_stream() {
        let authenticated_material_root = protocol_hash('a');
        let authenticated_bytes = &[0x41_u8; 64];
        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL,
            CanonicalStreamDomain::PublicEvaluationKeyMaterial,
            &authenticated_material_root,
            authenticated_bytes,
            0x91,
        );
        let package = json!({
            "evaluationKeys": {
                "publicEvaluationKeyMaterialRoot": authenticated_material_root,
            },
        });
        let authenticated_request = json!({
            "transportedPublicEvaluationKeyMaterial": {
                "publicEvaluationKeyMaterials": [{
                    "publicEvaluationKeyMaterialRoot": authenticated_material_root,
                }],
            },
        });
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&authenticated_request);
            let authenticated_result =
                verify_setup_transport_request_bindings(&package, &authenticated_request)
                    .expect("authenticated transport request binding verification");
            assert!(authenticated_result.is_ok());
        }
        assert!(
            authenticated_setup_proof_material_stream_summary(
                PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
                &authenticated_material_root,
            )
            .expect("post-accept material lookup")
            .is_none()
        );

        let refusal = verify_setup_transport_request_bindings(&package, &authenticated_request)
            .expect("missing stream verification")
            .expect_err("an unauthenticated material reference must refuse");
        assert_eq!(
            refusal.reason_code,
            "transportedObjectAuthenticatedMaterialMissing"
        );
    }

    #[test]
    fn authenticated_summary_dispatch_covers_component_and_public_key_material_stores() {
        let component_material_root = protocol_hash('c');
        let component_bytes = [0x31_u8; 96];
        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_material_root,
            &component_bytes,
            0xa1,
        );
        let component_package = json!({
            "relinearizationKeyShareRounds": {
                "roundOneRecords": [{
                    "keySwitchComponentMaterialRoot": component_material_root,
                }],
            },
        });
        let component_request_for_family = |proof_family: &str| {
            json!({
                "transportedEvaluationKeyShareComponentMaterial": {
                    "componentMaterials": [{
                        "proofFamily": proof_family,
                        "keySwitchComponentMaterialRoot": component_material_root,
                    }],
                },
            })
        };

        let component_request = component_request_for_family("relinearization-key-share");
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&component_request);
            let result =
                verify_setup_transport_request_bindings(&component_package, &component_request)
                    .expect("authenticated component transport verification");
            assert!(result.is_ok());
        }
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("post-accept component material lookup")
            .is_none()
        );

        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_material_root,
            &component_bytes,
            0xa2,
        );
        let wrong_family_request = component_request_for_family("galois-key-share");
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&wrong_family_request);
            let refusal =
                verify_setup_transport_request_bindings(&component_package, &wrong_family_request)
                    .expect("wrong-family component transport verification")
                    .expect_err("a component root owned by another proof family must refuse");
            assert_eq!(
                refusal.reason_code,
                "transportedObjectAuthenticatedMaterialMismatch"
            );
        }
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("post-family-refusal component material lookup")
            .is_none()
        );

        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_material_root,
            &component_bytes,
            0xa3,
        );
        let mut missing_family_request = component_request_for_family("relinearization-key-share");
        missing_family_request["transportedEvaluationKeyShareComponentMaterial"]
            ["componentMaterials"][0]
            .as_object_mut()
            .expect("component material descriptor")
            .remove("proofFamily");
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&missing_family_request);
            let refusal = verify_setup_transport_request_bindings(
                &component_package,
                &missing_family_request,
            )
            .expect("missing-family component transport verification")
            .expect_err("component material without its proof family must refuse");
            assert_eq!(refusal.reason_code, "transportedMaterialProofFamilyMissing");
        }
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("post-missing-family-refusal component material lookup")
            .is_none()
        );

        let public_key_material_root = protocol_hash('d');
        let public_key_material_bytes = public_key_share_material_bytes();
        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL,
            CanonicalStreamDomain::PublicKeyShareMaterial,
            &public_key_material_root,
            &public_key_material_bytes,
            0xb1,
        );
        let public_key_package = json!({
            "publicKeyShareMaterial": {
                "materialEncoding": PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
                "publicKeyShareMaterialSetRoot": public_key_material_root,
            },
        });
        let public_key_request = json!({
            "transportedPublicKeyShareMaterial": {
                "publicKeyShareMaterialSetRoot": public_key_material_root,
            },
        });
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&public_key_request);
            let result =
                verify_setup_transport_request_bindings(&public_key_package, &public_key_request)
                    .expect("authenticated public-key material transport verification");
            assert!(result.is_ok());
        }
        assert!(
            authenticated_public_key_share_material_stream_summary(&public_key_material_root)
                .expect("post-accept public-key material lookup")
                .is_none()
        );
    }
}
