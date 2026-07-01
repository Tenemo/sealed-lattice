use super::binary_material::*;
use super::certificate::*;
use super::*;

pub(super) fn verify_setup_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
    transported_objects: &[SetupTransportedObjectBinding],
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    if let Some(transported_material) = request.get("transportedVssCoefficientCommitmentMaterial") {
        transport_try!(require_setup_transport_entry(
            transported_objects,
            &setup_transport_expected_direct_material(
                transported_material,
                package_nested_hash(
                    setup_package,
                    "vssCoefficientCommitmentMaterial",
                    "vssCoefficientCommitmentMaterialRoot",
                )?,
                SETUP_TRANSPORTED_VSS_MATERIAL_NAME,
                SETUP_TRANSPORTED_VSS_MATERIAL_ROLE,
                SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
                "transportedVssCoefficientCommitmentMaterial",
            )?,
        ));
    }
    if let Some(transported_material) = request.get("transportedPublicKeyShareMaterial") {
        let Some(public_key_share_material_root) = setup_package
            .get("publicKeyShareMaterial")
            .and_then(|material| material.get("publicKeyShareMaterialSetRoot"))
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(Err(Refusal::new(
                "transportedObjectBindingMissing",
                "transportedPublicKeyShareMaterial requires setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
                "setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
            )));
        };
        validate_hash_string(
            public_key_share_material_root,
            "setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
        )?;
        transport_try!(require_setup_transport_entry(
            transported_objects,
            &setup_transport_expected_direct_material(
                transported_material,
                public_key_share_material_root.to_string(),
                SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME,
                SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE,
                SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
                "transportedPublicKeyShareMaterial",
            )?,
        ));
    }
    if let Some(material_set) = request.get("transportedSameSecretProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_proof_material_roots(
            setup_package,
            "sameSecretProofs",
            "proofRecords",
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedSameSecretProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedPublicKeyShareProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_proof_material_roots(
            setup_package,
            "publicKeyShareSuccinctProofs",
            "proofRecords",
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedPublicKeyShareProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedEvaluationKeyShareProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_proof_material_roots(
            setup_package,
            "trusteeEvaluationKeyProofs",
            "proofRecords",
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedEvaluationKeyShareProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS,
            },
            &referenced_material_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") {
        let referenced_material_roots = setup_transport_referenced_evaluation_key_material_roots(
            setup_package,
            "keySwitchComponentMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_material_entries(
            transported_objects,
            material_set,
            "transportedEvaluationKeyShareComponentMaterial",
            "componentMaterials",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ROLE,
                object_root: "keySwitchComponentMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedPublicEvaluationKeyMaterial") {
        let referenced_material_roots =
            setup_transport_referenced_public_evaluation_key_material_roots(setup_package)?;
        transport_canonical_try!(require_setup_transport_material_entries(
            transported_objects,
            material_set,
            "transportedPublicEvaluationKeyMaterial",
            "publicEvaluationKeyMaterials",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_ROLE,
                object_root: "publicEvaluationKeyMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
        ));
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
    material_set: &Value,
    material_set_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Ok(Err(Refusal::new(
            "transportedProofMaterialListMissing",
            format!(
                "{material_set_path}.proofMaterials must list transported proof material objects"
            ),
            format!("{material_set_path}.proofMaterials"),
        )));
    };
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
    }

    Ok(Ok(()))
}

fn require_setup_transport_material_entries(
    transported_objects: &[SetupTransportedObjectBinding],
    material_set: &Value,
    material_set_path: &'static str,
    material_array_field_name: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
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
    }

    Ok(Ok(()))
}

fn setup_transport_expected_direct_material(
    material: &Value,
    object_root: String,
    object_name: &'static str,
    object_role: &'static str,
    hash_fields: SetupTransportHashFieldNames,
    object_path: &'static str,
) -> CanonicalResult<SetupTransportExpectedObject> {
    setup_transport_expected_material_with_root(
        material,
        object_root,
        object_name,
        object_role,
        hash_fields,
        object_path.to_string(),
    )
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
