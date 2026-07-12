use super::binary_material::*;
use super::certificate::*;
use super::field_access::*;
use super::*;

const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE: &str = "VssCoefficientCommitmentMaterialSet";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_EMBEDDED_ENCODING: &str =
    "full-public-setup-commitment-values";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_NAME: &str = "vssCoefficientCommitmentMaterial";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_ROLE: &str =
    "public-vss-coefficient-commitment-material";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH: &str =
    "setupPackage.vssCoefficientCommitmentMaterial";

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

    transport_canonical_try!(verify_vss_coefficient_commitment_material_reference(
        setup_package,
        transported_objects,
    ));

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

fn verify_vss_coefficient_commitment_material_reference(
    setup_package: &Value,
    transported_objects: &[SetupTransportedObjectBinding],
) -> CanonicalResult<Result<(), Refusal>> {
    let matching_transport_objects = transported_objects
        .iter()
        .filter(|transported_object| {
            transported_object.object_name == VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_NAME
                || transported_object.object_role == VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_ROLE
        })
        .collect::<Vec<_>>();
    if matching_transport_objects.len() > 1 {
        return Ok(Err(vss_material_reference_refusal(
            "vssMaterialTransportReferenceMismatch",
            "SetupTransportCertificate must contain at most one VSS coefficient commitment material entry",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    let transported_object = matching_transport_objects.first().copied();
    let Some(material) = setup_package.get("vssCoefficientCommitmentMaterial") else {
        return Ok(match transported_object {
            Some(_) => Err(vss_material_reference_refusal(
                "vssMaterialTransportReferenceMissing",
                "setupPackage.vssCoefficientCommitmentMaterial must reference the material bound by SetupTransportCertificate",
                VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
            )),
            None => Ok(()),
        });
    };

    let material_object_type = match require_transport_non_empty_string_at(
        material,
        "objectType",
        "vssMaterialTransportReferenceMissing",
        "vssCoefficientCommitmentMaterial.objectType is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if material_object_type != VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE {
        return Ok(Err(vss_material_reference_refusal(
            "vssMaterialTransportReferenceMismatch",
            "vssCoefficientCommitmentMaterial.objectType must identify its material set",
            format!("{VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH}.objectType"),
        )));
    }
    let material_encoding = match require_transport_non_empty_string_at(
        material,
        "materialEncoding",
        "vssMaterialTransportReferenceMissing",
        "vssCoefficientCommitmentMaterial.materialEncoding is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if material_encoding != VSS_COEFFICIENT_COMMITMENT_MATERIAL_EMBEDDED_ENCODING
        && material_encoding != VSS_COEFFICIENT_COMMITMENT_MATERIAL_TRANSPORT_ENCODING
    {
        return Ok(Err(vss_material_reference_refusal(
            "vssMaterialTransportReferenceMismatch",
            "vssCoefficientCommitmentMaterial.materialEncoding is not a supported embedded or binary-chunked encoding",
            format!("{VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH}.materialEncoding"),
        )));
    }
    let material_root = match require_transport_hash_at(
        material,
        "vssCoefficientCommitmentMaterialRoot",
        "vssMaterialTransportReferenceMissing",
        "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let Some(transported_object) = transported_object else {
        return Ok(
            if material_encoding == VSS_COEFFICIENT_COMMITMENT_MATERIAL_TRANSPORT_ENCODING {
                Err(vss_material_reference_refusal(
                    "vssMaterialTransportReferenceMissing",
                    "SetupTransportCertificate must bind the binary-chunked VSS coefficient commitment material reference",
                    "setupPackage.setupTransportCertificate.transportedObjects",
                ))
            } else {
                Ok(())
            },
        );
    };
    if transported_object.object_name != VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_NAME
        || transported_object.object_role != VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_ROLE
        || transported_object.object_root != material_root
    {
        return Ok(Err(vss_material_reference_refusal(
            "vssMaterialTransportReferenceMismatch",
            "SetupTransportCertificate VSS material identity and root must match vssCoefficientCommitmentMaterial",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    if material_encoding == VSS_COEFFICIENT_COMMITMENT_MATERIAL_EMBEDDED_ENCODING {
        return Ok(Ok(()));
    }

    let total_byte_length = match require_positive_transport_u64_at(
        material,
        "totalByteLength",
        "vssMaterialTransportReferenceMissing",
        "binary-chunked VSS material totalByteLength is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let chunk_count = match require_positive_transport_u64_at(
        material,
        "chunkCount",
        "vssMaterialTransportReferenceMissing",
        "binary-chunked VSS material chunkCount is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let full_object_hash = match require_transport_hash_at(
        material,
        "fullObjectHash",
        "vssMaterialTransportReferenceMissing",
        "binary-chunked VSS material fullObjectHash is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let chunk_root = match require_transport_hash_at(
        material,
        "chunkRoot",
        "vssMaterialTransportReferenceMissing",
        "binary-chunked VSS material chunkRoot is required",
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let expected_chunk_count = usize::try_from(chunk_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS material transport chunkCount does not fit usize",
        )
    })?;
    let chunk_hashes = match transport_hashes_at(
        material,
        "chunkHashes",
        expected_chunk_count,
        VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
    )? {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if total_byte_length != transported_object.byte_length
        || chunk_count != transported_object.chunk_count
        || full_object_hash != transported_object.full_object_hash
        || chunk_root != transported_object.chunk_root
        || chunk_hashes != transported_object.chunk_hashes
    {
        return Ok(Err(vss_material_reference_refusal(
            "vssMaterialTransportReferenceMismatch",
            "binary-chunked VSS material metadata must match SetupTransportCertificate",
            VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH,
        )));
    }

    Ok(Ok(()))
}

fn vss_material_reference_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> Refusal {
    Refusal::new(reason_code, message, object_path)
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

    fn protocol_hash(character: char) -> String {
        character.to_string().repeat(128)
    }

    fn vss_transport_binding() -> SetupTransportedObjectBinding {
        SetupTransportedObjectBinding {
            object_name: VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_NAME.to_string(),
            object_role: VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_ROLE.to_string(),
            object_root: protocol_hash('1'),
            byte_length: 1_500_000,
            chunk_count: 2,
            chunk_root: protocol_hash('3'),
            chunk_hashes: vec![protocol_hash('4'), protocol_hash('5')],
            full_object_hash: protocol_hash('2'),
        }
    }

    fn binary_vss_material_reference() -> Value {
        json!({
            "objectType": VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE,
            "materialEncoding": VSS_COEFFICIENT_COMMITMENT_MATERIAL_TRANSPORT_ENCODING,
            "vssCoefficientCommitmentMaterialRoot": protocol_hash('1'),
            "chunkCount": 2,
            "totalByteLength": 1_500_000,
            "fullObjectHash": protocol_hash('2'),
            "chunkRoot": protocol_hash('3'),
            "chunkHashes": [protocol_hash('4'), protocol_hash('5')],
        })
    }

    #[test]
    fn binary_vss_material_reference_matches_transport_certificate_entry() {
        let package = json!({
            "vssCoefficientCommitmentMaterial": binary_vss_material_reference(),
        });
        let result = verify_vss_coefficient_commitment_material_reference(
            &package,
            &[vss_transport_binding()],
        )
        .expect("VSS transport reference verification");

        assert!(result.is_ok());
    }

    #[test]
    fn vss_transport_certificate_entry_requires_package_reference() {
        let refusal = verify_vss_coefficient_commitment_material_reference(
            &json!({}),
            &[vss_transport_binding()],
        )
        .expect("VSS transport reference verification")
        .expect_err("missing package reference must refuse");

        assert_eq!(refusal.reason_code, "vssMaterialTransportReferenceMissing");
        assert_eq!(
            refusal.object_path.as_deref(),
            Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_PATH)
        );
    }

    #[test]
    fn binary_vss_material_reference_requires_complete_metadata() {
        for field_name in [
            "objectType",
            "materialEncoding",
            "vssCoefficientCommitmentMaterialRoot",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
            "chunkHashes",
        ] {
            let mut reference = binary_vss_material_reference();
            reference
                .as_object_mut()
                .expect("VSS material reference")
                .remove(field_name);
            let package = json!({
                "vssCoefficientCommitmentMaterial": reference,
            });
            let refusal = verify_vss_coefficient_commitment_material_reference(
                &package,
                &[vss_transport_binding()],
            )
            .expect("VSS transport reference verification")
            .expect_err("incomplete package reference must refuse");

            assert!(
                matches!(
                    refusal.reason_code,
                    "vssMaterialTransportReferenceMissing" | "transportChunkHashesMissing"
                ),
                "unexpected refusal for missing {field_name}: {}",
                refusal.reason_code
            );
        }
    }

    #[test]
    fn binary_vss_material_reference_rejects_each_certificate_mismatch() {
        let mismatches = [
            ("objectType", json!("WrongMaterialType")),
            ("materialEncoding", json!("wrong-encoding")),
            (
                "vssCoefficientCommitmentMaterialRoot",
                json!(protocol_hash('6')),
            ),
            ("totalByteLength", json!(1_500_001)),
            ("fullObjectHash", json!(protocol_hash('6'))),
            ("chunkRoot", json!(protocol_hash('6'))),
            (
                "chunkHashes",
                json!([protocol_hash('6'), protocol_hash('7')]),
            ),
        ];
        for (field_name, field_value) in mismatches {
            let mut reference = binary_vss_material_reference();
            reference[field_name] = field_value;
            let package = json!({
                "vssCoefficientCommitmentMaterial": reference,
            });
            let refusal = verify_vss_coefficient_commitment_material_reference(
                &package,
                &[vss_transport_binding()],
            )
            .expect("VSS transport reference verification")
            .expect_err("mismatched package reference must refuse");

            assert_eq!(
                refusal.reason_code, "vssMaterialTransportReferenceMismatch",
                "unexpected refusal for mismatched {field_name}"
            );
        }

        let mut reference = binary_vss_material_reference();
        reference["chunkCount"] = json!(1);
        reference["chunkHashes"] = json!([protocol_hash('4')]);
        let package = json!({
            "vssCoefficientCommitmentMaterial": reference,
        });
        let refusal = verify_vss_coefficient_commitment_material_reference(
            &package,
            &[vss_transport_binding()],
        )
        .expect("VSS transport reference verification")
        .expect_err("mismatched chunkCount must refuse");
        assert_eq!(refusal.reason_code, "vssMaterialTransportReferenceMismatch");
    }
}
