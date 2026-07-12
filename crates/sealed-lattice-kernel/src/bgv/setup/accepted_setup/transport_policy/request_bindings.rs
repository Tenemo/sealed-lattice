use super::binary_material::*;
use super::certificate::*;
use super::*;

pub(super) fn verify_setup_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
    transported_objects: &[SetupTransportedObjectBinding],
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let mut expected_transport_object_roots = BTreeSet::new();
    let referenced_public_key_material_roots =
        setup_transport_referenced_public_key_share_material_roots(setup_package)?;
    expected_transport_object_roots.extend(referenced_public_key_material_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_single_material_entry(
        transported_objects,
        request.get("transportedPublicKeyShareMaterial"),
        "transportedPublicKeyShareMaterial",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE,
            object_root: "publicKeyShareMaterialSetRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_public_key_material_roots,
        AuthenticatedSetupTransportMaterialSource::PublicKeyShareMaterial,
    ));

    let referenced_public_key_proof_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "publicKeyShareSuccinctProofs",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    expected_transport_object_roots.extend(referenced_public_key_proof_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        transported_objects,
        request.get("transportedPublicKeyShareProofMaterial"),
        "transportedPublicKeyShareProofMaterial",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_ROLE,
            object_root: "proofMaterialRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_public_key_proof_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(PUBLIC_KEY_SHARE_PROOF_FAMILY),
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
    expected_transport_object_roots.extend(referenced_vss_share_linkage_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        transported_objects,
        request.get("transportedVssShareLinkageProofMaterial"),
        "transportedVssShareLinkageProofMaterial",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_VSS_SHARE_LINKAGE_PROOF_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_VSS_SHARE_LINKAGE_PROOF_MATERIAL_ROLE,
            object_root: "proofMaterialRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_vss_share_linkage_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(VSS_SHARE_LINKAGE_PROOF_FAMILY),
    ));

    let referenced_same_secret_bridge_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "sameSecretBridgeProofMaterialSet",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    expected_transport_object_roots.extend(referenced_same_secret_bridge_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        transported_objects,
        request.get("transportedSameSecretBridgeProofMaterial"),
        "transportedSameSecretBridgeProofMaterial",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_SAME_SECRET_BRIDGE_PROOF_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_SAME_SECRET_BRIDGE_PROOF_MATERIAL_ROLE,
            object_root: "proofMaterialRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_same_secret_bridge_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ));

    let referenced_evaluation_key_proof_roots = setup_transport_referenced_proof_material_roots(
        setup_package,
        "trusteeEvaluationKeyProofs",
        "proofRecords",
        "proofMaterialRoot",
    )?;
    expected_transport_object_roots.extend(referenced_evaluation_key_proof_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_proof_material_entries(
        transported_objects,
        request.get("transportedEvaluationKeyShareProofMaterial"),
        "transportedEvaluationKeyShareProofMaterial",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_ROLE,
            object_root: "proofMaterialRoot",
            hash_fields: SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS,
        },
        &referenced_evaluation_key_proof_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,),
    ));

    let referenced_evaluation_key_component_roots =
        setup_transport_referenced_evaluation_key_material_roots(
            setup_package,
            "keySwitchComponentMaterialRoot",
        )?;
    expected_transport_object_roots
        .extend(referenced_evaluation_key_component_roots.iter().cloned());
    transport_canonical_try!(require_setup_transport_material_entries(
        transported_objects,
        request.get("transportedEvaluationKeyShareComponentMaterial"),
        "transportedEvaluationKeyShareComponentMaterial",
        "componentMaterials",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ROLE,
            object_root: "keySwitchComponentMaterialRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_evaluation_key_component_roots,
        AuthenticatedSetupTransportMaterialSource::EvaluationKeyComponent,
    ));

    let referenced_public_evaluation_key_material_roots =
        setup_transport_referenced_public_evaluation_key_material_roots(setup_package)?;
    expected_transport_object_roots.extend(
        referenced_public_evaluation_key_material_roots
            .iter()
            .cloned(),
    );
    transport_canonical_try!(require_setup_transport_material_entries(
        transported_objects,
        request.get("transportedPublicEvaluationKeyMaterial"),
        "transportedPublicEvaluationKeyMaterial",
        "publicEvaluationKeyMaterials",
        SetupTransportMaterialDescriptor {
            object_name: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_NAME,
            object_role: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_ROLE,
            object_root: "publicEvaluationKeyMaterialRoot",
            hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
        },
        &referenced_public_evaluation_key_material_roots,
        AuthenticatedSetupTransportMaterialSource::SetupProof(
            PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
        ),
    ));

    transport_canonical_try!(require_exact_setup_transport_object_set(
        transported_objects,
        &expected_transport_object_roots,
    ));

    Ok(Ok(()))
}

fn require_exact_setup_transport_object_set(
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    let transported_object_roots = transported_objects
        .iter()
        .map(|transported_object| transported_object.object_root.clone())
        .collect::<BTreeSet<_>>();
    if let Some(unexpected_root) = transported_object_roots
        .difference(expected_object_roots)
        .next()
    {
        return Ok(Err(Refusal::new(
            "transportedObjectUnexpected",
            format!(
                "setupTransportCertificate.transportedObjects contains unreferenced object root {unexpected_root}"
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    if let Some(missing_root) = expected_object_roots
        .difference(&transported_object_roots)
        .next()
    {
        return Ok(Err(Refusal::new(
            "transportedObjectBindingMissing",
            format!(
                "setupTransportCertificate.transportedObjects is missing referenced object root {missing_root}"
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

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
    transported_objects: &[SetupTransportedObjectBinding],
    material_set: Option<&Value>,
    material_set_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
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
        let expected_material = setup_transport_expected_material_with_root(
            proof_material,
            object_root,
            descriptor.object_name,
            descriptor.object_role,
            descriptor.hash_fields,
            object_path,
        )?;
        if let Err(refusal) = require_setup_transport_entry(transported_objects, &expected_material)
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = require_authenticated_setup_transport_entry(
            proof_material,
            &expected_material,
            authenticated_source,
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

fn require_setup_transport_material_entries(
    transported_objects: &[SetupTransportedObjectBinding],
    material_set: Option<&Value>,
    material_set_path: &'static str,
    material_array_field_name: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
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
        let expected_material = setup_transport_expected_material_with_root(
            material,
            object_root,
            descriptor.object_name,
            descriptor.object_role,
            descriptor.hash_fields,
            object_path,
        )?;
        if let Err(refusal) = require_setup_transport_entry(transported_objects, &expected_material)
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = require_authenticated_setup_transport_entry(
            material,
            &expected_material,
            authenticated_source,
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
    transported_objects: &[SetupTransportedObjectBinding],
    material: Option<&Value>,
    material_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    authenticated_source: AuthenticatedSetupTransportMaterialSource,
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
    let expected_material = setup_transport_expected_material_with_root(
        material,
        object_root,
        descriptor.object_name,
        descriptor.object_role,
        descriptor.hash_fields,
        material_path.to_string(),
    )?;
    if let Err(refusal) = require_setup_transport_entry(transported_objects, &expected_material) {
        return Ok(Err(refusal));
    }
    require_authenticated_setup_transport_entry(material, &expected_material, authenticated_source)
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
) -> CanonicalResult<Result<(), Refusal>> {
    let stream_summary = match source {
        AuthenticatedSetupTransportMaterialSource::SetupProof(proof_family) => {
            authenticated_setup_proof_material_stream_summary(proof_family, &expected.object_root)
        }
        AuthenticatedSetupTransportMaterialSource::EvaluationKeyComponent => {
            let Some(proof_family) = material.get("proofFamily").and_then(Value::as_str) else {
                return Ok(Err(Refusal::new(
                    "transportedMaterialProofFamilyMissing",
                    format!("{}.proofFamily is required", expected.object_path),
                    format!("{}.proofFamily", expected.object_path),
                )));
            };
            authenticated_evaluation_key_component_stream_summary(
                proof_family,
                &expected.object_root,
            )
        }
        AuthenticatedSetupTransportMaterialSource::PublicKeyShareMaterial => {
            authenticated_public_key_share_material_stream_summary(&expected.object_root)
        }
    };
    let stream_summary = match stream_summary {
        Ok(Some(summary)) => summary,
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
    };
    let authenticated_accounting = authenticated_setup_transport_accounting(&stream_summary)?;
    if authenticated_accounting.total_byte_length != expected.byte_length
        || authenticated_accounting.full_object_hash != expected.full_object_hash
        || authenticated_accounting.chunk_root != expected.chunk_root
        || authenticated_accounting.chunk_hashes != expected.chunk_hashes
    {
        return Ok(Err(Refusal::new(
            "transportedObjectAuthenticatedBindingMismatch",
            format!(
                "{} transport accounting must match the bytes authenticated by the canonical stream verifier",
                expected.object_path
            ),
            &expected.object_path,
        )));
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
    material: &Value,
    object_root: String,
    object_name: &'static str,
    object_role: &'static str,
    hash_fields: SetupTransportHashFieldNames,
    object_path: String,
) -> CanonicalResult<SetupTransportExpectedObject> {
    let byte_length = value_u64(material, hash_fields.byte_length)?;
    let full_object_hash = value_string(material, hash_fields.full_object_hash)?.to_string();
    validate_hash_string(
        &full_object_hash,
        &format!("{object_path}.{}", hash_fields.full_object_hash),
    )?;
    let chunk_root = value_string(material, hash_fields.chunk_root)?.to_string();
    validate_hash_string(
        &chunk_root,
        &format!("{object_path}.{}", hash_fields.chunk_root),
    )?;
    let chunk_hashes =
        setup_transport_expected_hash_array(material, hash_fields.chunk_hashes, &object_path)?;

    Ok(SetupTransportExpectedObject {
        object_name,
        object_role,
        object_root,
        byte_length,
        chunk_root,
        chunk_hashes,
        full_object_hash,
        object_path,
    })
}

fn require_setup_transport_entry(
    transported_objects: &[SetupTransportedObjectBinding],
    expected: &SetupTransportExpectedObject,
) -> Result<(), Refusal> {
    let Some(transported_object) = transported_objects
        .iter()
        .find(|transported_object| transported_object.object_root == expected.object_root)
    else {
        return Err(Refusal::new(
            "transportedObjectBindingMissing",
            format!(
                "setupTransportCertificate.transportedObjects must bind {}",
                expected.object_path
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        ));
    };
    if transported_object.object_name != expected.object_name
        || transported_object.object_role != expected.object_role
        || transported_object.byte_length != expected.byte_length
        || transported_object.chunk_root != expected.chunk_root
        || transported_object.chunk_hashes != expected.chunk_hashes
        || transported_object.full_object_hash != expected.full_object_hash
    {
        return Err(Refusal::new(
            "transportedObjectBindingMismatch",
            format!(
                "setupTransportCertificate.transportedObjects metadata must match {}",
                expected.object_path
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::setup::canonical_stream_transport::AuthenticatedSetupTransportAccounting,
        encoding::append_varuint,
        foundation::{
            CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CanonicalStreamDomain, FOUNDATION_PROFILE,
            derive_canonical_stream_descriptor,
        },
    };

    fn protocol_hash(character: char) -> String {
        character.to_string().repeat(128)
    }

    fn producer_transport_accounting(
        stream_domain: CanonicalStreamDomain,
        material_bytes: &[u8],
    ) -> AuthenticatedSetupTransportAccounting {
        let descriptor = derive_canonical_stream_descriptor(stream_domain, material_bytes)
            .expect("canonical material descriptor");
        let chunk_hashes = descriptor
            .ordered_chunk_digests
            .iter()
            .map(|digest| digest.to_lowercase_hex())
            .collect::<Vec<_>>();
        let full_object_hash = descriptor.full_object_digest.to_lowercase_hex();
        let total_byte_length = descriptor.total_byte_length;
        let chunk_root = derive_canonical_object_hash(&json!({
            "objectType": "SetupTransportChunkManifest",
            "chunkCount": chunk_hashes.len(),
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }))
        .expect("canonical material chunk manifest root");

        AuthenticatedSetupTransportAccounting {
            total_byte_length,
            full_object_hash,
            chunk_root,
            chunk_hashes,
        }
    }

    fn authenticate_bgv_material_stream(
        family_code: u32,
        stream_domain: CanonicalStreamDomain,
        material_root: &str,
        material_bytes: &[u8],
        capability_byte: u8,
    ) -> AuthenticatedSetupTransportAccounting {
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

        producer_transport_accounting(stream_domain, material_bytes)
    }

    fn transport_binding(
        object_name: &'static str,
        object_role: &'static str,
        material_root: &str,
        accounting: &AuthenticatedSetupTransportAccounting,
    ) -> SetupTransportedObjectBinding {
        SetupTransportedObjectBinding {
            object_name: object_name.to_string(),
            object_role: object_role.to_string(),
            object_root: material_root.to_string(),
            byte_length: accounting.total_byte_length,
            chunk_count: accounting.chunk_hashes.len() as u64,
            chunk_root: accounting.chunk_root.clone(),
            chunk_hashes: accounting.chunk_hashes.clone(),
            full_object_hash: accounting.full_object_hash.clone(),
        }
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
            let refusal = verify_setup_transport_request_bindings(&package, &json!({}), &[])
                .expect("transport request binding verification")
                .expect_err("a referenced binary material without its sidecar must refuse");

            assert_eq!(refusal.reason_code, "transportedMaterialReferenceMissing");
        }
    }

    #[test]
    fn transport_certificate_refuses_an_unreferenced_self_consistent_object() {
        let transported_object = SetupTransportedObjectBinding {
            object_name: "unreferencedMaterial".to_string(),
            object_role: "unreferenced-material".to_string(),
            object_root: protocol_hash('e'),
            byte_length: 64,
            chunk_count: 1,
            chunk_root: protocol_hash('f'),
            chunk_hashes: vec![protocol_hash('1')],
            full_object_hash: protocol_hash('2'),
        };

        let refusal =
            verify_setup_transport_request_bindings(&json!({}), &json!({}), &[transported_object])
                .expect("transport request binding verification")
                .expect_err("an unreferenced certificate object must refuse");
        assert_eq!(refusal.reason_code, "transportedObjectUnexpected");
    }

    #[test]
    fn transport_accounting_must_match_the_authenticated_canonical_stream_summary() {
        let authenticated_material_root = protocol_hash('a');
        let authenticated_bytes = &[0x41_u8; 64];
        let alternate_bytes = &[0x42_u8; 64];
        let authenticated_accounting = authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL,
            CanonicalStreamDomain::PublicEvaluationKeyMaterial,
            &authenticated_material_root,
            authenticated_bytes,
            0x91,
        );
        let alternate_accounting = producer_transport_accounting(
            CanonicalStreamDomain::PublicEvaluationKeyMaterial,
            alternate_bytes,
        );
        let package = json!({
            "evaluationKeys": {
                "publicEvaluationKeyMaterialRoot": authenticated_material_root,
            },
        });

        let request_and_binding = |accounting: &AuthenticatedSetupTransportAccounting| {
            let request = json!({
                "transportedPublicEvaluationKeyMaterial": {
                    "publicEvaluationKeyMaterials": [{
                        "publicEvaluationKeyMaterialRoot": authenticated_material_root,
                        "totalByteLength": accounting.total_byte_length,
                        "fullObjectHash": accounting.full_object_hash,
                        "chunkRoot": accounting.chunk_root,
                        "chunkHashes": accounting.chunk_hashes,
                    }],
                },
            });
            let binding = transport_binding(
                SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_NAME,
                SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_ROLE,
                &authenticated_material_root,
                accounting,
            );
            (request, binding)
        };

        let (authenticated_request, authenticated_binding) =
            request_and_binding(&authenticated_accounting);
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&authenticated_request);
            let authenticated_result = verify_setup_transport_request_bindings(
                &package,
                &authenticated_request,
                &[authenticated_binding],
            )
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

        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL,
            CanonicalStreamDomain::PublicEvaluationKeyMaterial,
            &authenticated_material_root,
            authenticated_bytes,
            0x92,
        );
        let (alternate_request, alternate_binding) = request_and_binding(&alternate_accounting);
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&alternate_request);
            let refusal = verify_setup_transport_request_bindings(
                &package,
                &alternate_request,
                &[alternate_binding],
            )
            .expect("alternate transport request binding verification")
            .expect_err("self-consistent accounting for different bytes must refuse");
            assert_eq!(
                refusal.reason_code,
                "transportedObjectAuthenticatedBindingMismatch"
            );
        }
        assert!(
            authenticated_setup_proof_material_stream_summary(
                PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
                &authenticated_material_root,
            )
            .expect("post-refusal material lookup")
            .is_none()
        );
    }

    #[test]
    fn authenticated_summary_dispatch_covers_component_and_public_key_material_stores() {
        let component_material_root = protocol_hash('c');
        let component_bytes = [0x31_u8; 96];
        let alternate_component_bytes = [0x32_u8; 96];
        let component_accounting = authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_material_root,
            &component_bytes,
            0xa1,
        );
        let alternate_component_accounting = producer_transport_accounting(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &alternate_component_bytes,
        );
        let component_package = json!({
            "relinearizationKeyShareRounds": {
                "roundOneRecords": [{
                    "keySwitchComponentMaterialRoot": component_material_root,
                }],
            },
        });
        let component_request_and_binding =
            |accounting: &AuthenticatedSetupTransportAccounting, proof_family: &str| {
                let request = json!({
                    "transportedEvaluationKeyShareComponentMaterial": {
                        "componentMaterials": [{
                            "proofFamily": proof_family,
                            "keySwitchComponentMaterialRoot": component_material_root,
                            "totalByteLength": accounting.total_byte_length,
                            "fullObjectHash": accounting.full_object_hash,
                            "chunkRoot": accounting.chunk_root,
                            "chunkHashes": accounting.chunk_hashes,
                        }],
                    },
                });
                let binding = transport_binding(
                    SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_NAME,
                    SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ROLE,
                    &component_material_root,
                    accounting,
                );
                (request, binding)
            };

        let (component_request, component_binding) =
            component_request_and_binding(&component_accounting, "relinearization-key-share");
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&component_request);
            let result = verify_setup_transport_request_bindings(
                &component_package,
                &component_request,
                &[component_binding],
            )
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
        let (alternate_component_request, alternate_component_binding) =
            component_request_and_binding(
                &alternate_component_accounting,
                "relinearization-key-share",
            );
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&alternate_component_request);
            let refusal = verify_setup_transport_request_bindings(
                &component_package,
                &alternate_component_request,
                &[alternate_component_binding],
            )
            .expect("alternate component transport verification")
            .expect_err("component accounting for different bytes must refuse");
            assert_eq!(
                refusal.reason_code,
                "transportedObjectAuthenticatedBindingMismatch"
            );
        }
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("post-refusal component material lookup")
            .is_none()
        );

        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
            CanonicalStreamDomain::EvaluatorKeyStore,
            &component_material_root,
            &component_bytes,
            0xa3,
        );
        let (wrong_family_request, wrong_family_binding) =
            component_request_and_binding(&component_accounting, "galois-key-share");
        {
            let _eviction_guard =
                VerifiedComponentMaterialEvictionGuard::for_request(&wrong_family_request);
            let refusal = verify_setup_transport_request_bindings(
                &component_package,
                &wrong_family_request,
                &[wrong_family_binding],
            )
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
            0xa4,
        );
        let (mut missing_family_request, missing_family_binding) =
            component_request_and_binding(&component_accounting, "relinearization-key-share");
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
                &[missing_family_binding],
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
        let mut alternate_public_key_material_bytes = public_key_material_bytes.clone();
        *alternate_public_key_material_bytes
            .last_mut()
            .expect("public-key share material is nonempty") ^= 1;
        let public_key_material_accounting = authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL,
            CanonicalStreamDomain::PublicKeyShareMaterial,
            &public_key_material_root,
            &public_key_material_bytes,
            0xb1,
        );
        let alternate_public_key_material_accounting = producer_transport_accounting(
            CanonicalStreamDomain::PublicKeyShareMaterial,
            &alternate_public_key_material_bytes,
        );
        let public_key_package = json!({
            "publicKeyShareMaterial": {
                "materialEncoding": PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
                "publicKeyShareMaterialSetRoot": public_key_material_root,
            },
        });
        let public_key_request_and_binding =
            |accounting: &AuthenticatedSetupTransportAccounting| {
                let request = json!({
                    "transportedPublicKeyShareMaterial": {
                        "publicKeyShareMaterialSetRoot": public_key_material_root,
                        "totalByteLength": accounting.total_byte_length,
                        "fullObjectHash": accounting.full_object_hash,
                        "chunkRoot": accounting.chunk_root,
                        "chunkHashes": accounting.chunk_hashes,
                    },
                });
                let binding = transport_binding(
                    SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME,
                    SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE,
                    &public_key_material_root,
                    accounting,
                );
                (request, binding)
            };

        let (public_key_request, public_key_binding) =
            public_key_request_and_binding(&public_key_material_accounting);
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&public_key_request);
            let result = verify_setup_transport_request_bindings(
                &public_key_package,
                &public_key_request,
                &[public_key_binding],
            )
            .expect("authenticated public-key material transport verification");
            assert!(result.is_ok());
        }
        assert!(
            authenticated_public_key_share_material_stream_summary(&public_key_material_root)
                .expect("post-accept public-key material lookup")
                .is_none()
        );

        authenticate_bgv_material_stream(
            crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL,
            CanonicalStreamDomain::PublicKeyShareMaterial,
            &public_key_material_root,
            &public_key_material_bytes,
            0xb2,
        );
        let (alternate_public_key_request, alternate_public_key_binding) =
            public_key_request_and_binding(&alternate_public_key_material_accounting);
        {
            let _eviction_guard =
                VerifiedSetupProofMaterialEvictionGuard::for_request(&alternate_public_key_request);
            let refusal = verify_setup_transport_request_bindings(
                &public_key_package,
                &alternate_public_key_request,
                &[alternate_public_key_binding],
            )
            .expect("alternate public-key material transport verification")
            .expect_err("public-key material accounting for different bytes must refuse");
            assert_eq!(
                refusal.reason_code,
                "transportedObjectAuthenticatedBindingMismatch"
            );
        }
        assert!(
            authenticated_public_key_share_material_stream_summary(&public_key_material_root)
                .expect("post-refusal public-key material lookup")
                .is_none()
        );
    }

    #[test]
    fn malformed_verification_requests_evict_every_finished_material_store_before_retry() {
        let proof_material_root = protocol_hash('6');
        let component_material_root = protocol_hash('7');
        let public_key_material_root = protocol_hash('8');
        let proof_bytes = [0x61_u8; 48];
        let component_bytes = [0x62_u8; 48];
        let public_key_bytes = public_key_share_material_bytes();
        let mut deeply_nested_proof_sidecar = json!({
            "publicEvaluationKeyMaterialRoot": proof_material_root,
        });
        for _ in 0..512 {
            deeply_nested_proof_sidecar = json!({
                "malformedNestedMaterial": deeply_nested_proof_sidecar,
            });
        }

        let stage_all_materials = |capability_offset: u8| {
            authenticate_bgv_material_stream(
                crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL,
                CanonicalStreamDomain::PublicEvaluationKeyMaterial,
                &proof_material_root,
                &proof_bytes,
                capability_offset,
            );
            authenticate_bgv_material_stream(
                crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT,
                CanonicalStreamDomain::EvaluatorKeyStore,
                &component_material_root,
                &component_bytes,
                capability_offset + 1,
            );
            authenticate_bgv_material_stream(
                crate::bgv::setup::canonical_stream_transport::BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL,
                CanonicalStreamDomain::PublicKeyShareMaterial,
                &public_key_material_root,
                &public_key_bytes,
                capability_offset + 2,
            );
        };
        let malformed_request = json!({
            "transportedPublicEvaluationKeyMaterial": {
                "publicEvaluationKeyMaterials": deeply_nested_proof_sidecar,
            },
            "transportedEvaluationKeyShareComponentMaterial": {
                "componentMaterials": [
                    "malformed item",
                    {
                        "malformedNestedMaterial": {
                            "keySwitchComponentMaterialRoot": component_material_root,
                        },
                    },
                ],
            },
            "transportedPublicKeyShareMaterial": {
                "malformedNestedMaterial": {
                    "publicKeyShareMaterialSetRoot": public_key_material_root,
                },
            },
        });

        stage_all_materials(0xc1);
        let error = verify_collective_bgv_setup_package_from_request(&malformed_request)
            .expect_err("a request without setupPackage must fail");
        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            authenticated_setup_proof_material_stream_summary(
                PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
                &proof_material_root,
            )
            .expect("malformed-request proof material lookup")
            .is_none()
        );
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("malformed-request component material lookup")
            .is_none()
        );
        assert!(
            authenticated_public_key_share_material_stream_summary(&public_key_material_root)
                .expect("malformed-request public-key material lookup")
                .is_none()
        );

        stage_all_materials(0xd1);
        let proof_eviction_guard =
            VerifiedSetupProofMaterialEvictionGuard::for_request(&malformed_request);
        let component_eviction_guard =
            VerifiedComponentMaterialEvictionGuard::for_request(&malformed_request);
        drop(component_eviction_guard);
        drop(proof_eviction_guard);
        assert!(
            authenticated_setup_proof_material_stream_summary(
                PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY,
                &proof_material_root,
            )
            .expect("retry proof material cleanup lookup")
            .is_none()
        );
        assert!(
            authenticated_evaluation_key_component_stream_summary(
                "relinearization-key-share",
                &component_material_root,
            )
            .expect("retry component material cleanup lookup")
            .is_none()
        );
        assert!(
            authenticated_public_key_share_material_stream_summary(&public_key_material_root)
                .expect("retry public-key material cleanup lookup")
                .is_none()
        );
    }
}
