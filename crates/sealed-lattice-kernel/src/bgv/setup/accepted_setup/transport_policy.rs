use super::*;

pub(in crate::bgv::setup) fn verify_profile_ring_material(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before profile-ring verification",
            )
        })?;
    if material_set.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64)
        || material_set.get("ringDegreeStatus").and_then(Value::as_str) != Some("profile-ring")
    {
        return Ok(Some(vss_material_outside_profile(
            "vssCoefficientCommitmentMaterial must use the accepted profile ring degree",
            "setupPackage.vssCoefficientCommitmentMaterial.ringDegree",
        )?));
    }
    if let Some(proof_set) = setup_package.get("sameSecretProofs")
        && let Some(response) = verify_profile_ring_records(
            proof_set,
            "proofRecords",
            "same-secret proof records must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.sameSecretProofs.proofRecords.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(material_set) = setup_package.get("publicKeyShareMaterial")
        && let Some(response) = verify_profile_ring_record(
            material_set,
            "public-key share material must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareMaterial.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(proof_set) = setup_package.get("publicKeyShareSuccinctProofs")
        && let Some(response) = verify_profile_ring_records(
            proof_set,
            "proofRecords",
            "public-key succinct proof records must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(collective_public_key) = setup_package.get("collectivePublicKey")
        && let Some(response) = verify_profile_ring_record(
            collective_public_key,
            "collective public-key material must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.collectivePublicKey.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") {
        for field_name in ["roundOneRecords", "roundTwoRecords"] {
            if let Some(response) = verify_profile_ring_records(
                rounds,
                field_name,
                "relinearization key-share proof records must use the accepted profile ring degree before terminal setup acceptance",
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}.ringDegree"),
            )? {
                return Ok(Some(response));
            }
        }
    }
    if let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in galois_batches {
            if let Some(response) = verify_profile_ring_records(
                batch,
                "galoisKeyShareMaterialRecords",
                "Galois key-share material records must use the accepted profile ring degree before terminal setup acceptance",
                "setupPackage.galoisKeyShareBatches.galoisKeyShareMaterialRecords.ringDegree",
            )? {
                return Ok(Some(response));
            }
        }
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn verify_terminal_setup_transport_policy(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material_set| material_set.get("materialEncoding"))
        .and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalVssMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked VSS coefficient commitment material",
            "setupPackage.vssCoefficientCommitmentMaterial.materialEncoding",
        )?));
    }
    if setup_package
        .get("publicKeyShareMaterial")
        .and_then(|material_set| material_set.get("materialEncoding"))
        .and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicKeyShareMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked public-key share material",
            "setupPackage.publicKeyShareMaterial.materialEncoding",
        )?));
    }
    for (record_set_name, records_field_name, object_path) in [
        (
            "sameSecretProofs",
            "proofRecords",
            "setupPackage.sameSecretProofs.proofRecords",
        ),
        (
            "publicKeyShareSuccinctProofs",
            "proofRecords",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        ),
        (
            "trusteeEvaluationKeyProofs",
            "proofRecords",
            "setupPackage.trusteeEvaluationKeyProofs.proofRecords",
        ),
    ] {
        if let Some(response) = verify_terminal_proof_material_transport_records(
            setup_package,
            record_set_name,
            records_field_name,
            object_path,
        )? {
            return Ok(Some(response));
        }
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundOneRecords",
        "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
    )? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundTwoRecords",
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
    )? {
        return Ok(Some(response));
    }
    for galois_batch in array_value(setup_package, "galoisKeyShareBatches")? {
        if let Some(response) = verify_terminal_key_switch_transport_records(
            galois_batch,
            "galoisKeyShareMaterialRecords",
            "setupPackage.galoisKeyShareBatches.galoisKeyShareMaterialRecords",
        )? {
            return Ok(Some(response));
        }
    }
    let evaluation_keys = setup_package.get("evaluationKeys").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluationKeys was required before terminal transport policy verification",
        )
    })?;
    for field_name in [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ] {
        if evaluation_keys.get(field_name).is_none() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalPublicEvaluationKeyMaterialTransportRequired",
                "terminal accepted setup requires transported public evaluation-key runtime material",
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys
        .get("publicEvaluationKeyMaterialEncoding")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicEvaluationKeyMaterialEncodingMismatch",
            "terminal accepted setup requires binary-chunked public evaluation-key material",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialEncoding",
        )?));
    }
    if let Some(response) = verify_terminal_vss_material_handle_policy(request)? {
        return Ok(Some(response));
    }

    Ok(None)
}

fn verify_terminal_vss_material_handle_policy(request: &Value) -> CanonicalResult<Option<Value>> {
    let Some(transported_material) = request.get("transportedVssCoefficientCommitmentMaterial")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["transportedVssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if transported_material.get("chunks").is_some() {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalVssMaterialHandleRequired",
            "terminal accepted setup requires a chunkless VSS material transport reference plus a stream-verified VSS material handle",
            "transportedVssCoefficientCommitmentMaterial.chunks",
        )?));
    }
    if request
        .get("verifiedVssCoefficientCommitmentMaterial")
        .is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn verify_terminal_proof_material_transport_records(
    setup_package: &Value,
    record_set_name: &str,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    let record_set = setup_package.get(record_set_name).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{record_set_name} was required before terminal transport policy verification"),
        )
    })?;
    for proof_record in array_value(record_set, records_field_name)? {
        if proof_record.get("proofBytesHex").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires transported setup proof bytes",
                format!("{object_path}.proofBytesHex"),
            )?));
        }
        if proof_record
            .get("proofBytesEncoding")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked setup proof bytes",
                format!("{object_path}.proofBytesEncoding"),
            )?));
        }
    }

    Ok(None)
}

fn verify_terminal_key_switch_transport_records(
    record_set: &Value,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    for proof_record in array_value(record_set, records_field_name)? {
        if proof_record.get("keySwitchComponentVectors").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires transported key-switch component material",
                format!("{object_path}.keySwitchComponentVectors"),
            )?));
        }
        if proof_record
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked key-switch component material",
                format!("{object_path}.keySwitchMaterialEncoding"),
            )?));
        }
    }

    Ok(None)
}

fn terminal_transport_policy_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_profile_ring_records(
    record_set: &Value,
    records_field_name: &str,
    message: impl Into<String> + Clone,
    object_path: impl Into<String> + Clone,
) -> CanonicalResult<Option<Value>> {
    for record in array_value(record_set, records_field_name)? {
        if let Some(response) =
            verify_profile_ring_record(record, message.clone(), object_path.clone())?
        {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn verify_profile_ring_record(
    record: &Value,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Option<Value>> {
    if record.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64) {
        return Ok(Some(vss_material_outside_profile(message, object_path)?));
    }

    Ok(None)
}

fn vss_material_outside_profile(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::OutsideProfile,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(
            "vssCoefficientCommitmentMaterialOutsideProfile",
            message,
            object_path,
        )],
        Vec::new(),
    )
}

pub(super) fn verify_transport_certificate(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(transport_certificate) = setup_package.get("setupTransportCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupTransportCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    match verify_transport_certificate_body(setup_package, request, transport_certificate)? {
        Ok(()) => {}
        Err(refusal) => {
            return Ok(Some(setup_transport_refusal(
                refusal.reason_code,
                refusal.message,
                refusal
                    .object_path
                    .unwrap_or_else(|| "setupPackage.setupTransportCertificate".to_string()),
            )?));
        }
    }

    Ok(None)
}

fn verify_transport_certificate_body(
    setup_package: &Value,
    request: &Value,
    transport_certificate: &Value,
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

    if !transport_certificate.is_object() {
        return Ok(Err(Refusal::new(
            "transportCertificateNotObject",
            "setupTransportCertificate must be a root-bound object",
            "setupPackage.setupTransportCertificate",
        )));
    }
    for (field_name, expected_value, reason_code, message) in [
        (
            "objectType",
            SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE,
            "transportCertificateTypeMismatch",
            "setupTransportCertificate.objectType must be SetupTransportCertificate",
        ),
        (
            "setupProfileId",
            COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportSetupProfileMismatch",
            "setupTransportCertificate.setupProfileId must match CollectiveBgvSetup-v1",
        ),
        (
            "transportProfileId",
            SETUP_TRANSPORT_PROFILE_ID,
            "transportProfileMismatch",
            "setupTransportCertificate must use verifier-enforced binary/chunked transport",
        ),
        (
            "largeObjectEncoding",
            "binary",
            "transportEncodingMismatch",
            "setupTransportCertificate.largeObjectEncoding must be binary",
        ),
        (
            "chunking",
            "required",
            "transportChunkingMissing",
            "setupTransportCertificate.chunking must be required",
        ),
        (
            "streamVerificationOrder",
            SETUP_TRANSPORT_STREAM_ORDER,
            "transportStreamOrderMismatch",
            "setupTransportCertificate.streamVerificationOrder must match the setup transport profile",
        ),
        (
            "resumePolicy",
            SETUP_TRANSPORT_RESUME_POLICY,
            "transportResumePolicyMismatch",
            "setupTransportCertificate.resumePolicy must match the setup transport profile",
        ),
        (
            "lazyLoadingPolicy",
            SETUP_TRANSPORT_LAZY_LOADING_POLICY,
            "transportLazyLoadingPolicyMismatch",
            "setupTransportCertificate.lazyLoadingPolicy must match the setup transport profile",
        ),
    ] {
        transport_try!(expect_transport_string(
            transport_certificate,
            field_name,
            expected_value,
            reason_code,
            message,
        ));
    }
    transport_try!(expect_transport_u64(
        transport_certificate,
        "objectVersion",
        1,
        "transportCertificateVersionMismatch",
        "setupTransportCertificate.objectVersion must be 1",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkSizeBytes",
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        "transportChunkSizeMismatch",
        "setupTransportCertificate.chunkSizeBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "storageQuotaBytes",
        SETUP_TRANSPORT_STORAGE_QUOTA_BYTES,
        "transportStorageQuotaMismatch",
        "setupTransportCertificate.storageQuotaBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "largestSingleBufferBytes",
        SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        "transportLargestBufferMismatch",
        "setupTransportCertificate.largestSingleBufferBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "copyCountLimit",
        SETUP_TRANSPORT_COPY_COUNT_LIMIT,
        "transportCopyCountMismatch",
        "setupTransportCertificate.copyCountLimit must match the setup transport profile",
    ));

    let setup_transport_profile_hash_value = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupTransportProfileHash",
        "transportProfileHashMissing",
        "setupTransportCertificate.setupTransportProfileHash is required",
    ));
    if setup_transport_profile_hash_value != setup_transport_profile_hash()?.as_str() {
        return Ok(Err(Refusal::new(
            "transportProfileHashMismatch",
            "setupTransportCertificate.setupTransportProfileHash must match the accepted setup transport profile",
            "setupPackage.setupTransportCertificate.setupTransportProfileHash",
        )));
    }

    let aggregate = transport_canonical_try!(verify_setup_transported_objects(
        setup_package,
        request,
        transport_certificate,
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "totalByteLength",
        aggregate.total_byte_length,
        "transportTotalByteLengthMismatch",
        "setupTransportCertificate.totalByteLength must match the aggregate byte count of transported setup objects",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkCount",
        aggregate.chunk_count,
        "transportChunkCountMismatch",
        "setupTransportCertificate.chunkCount must match the aggregate transported-object chunk count",
    ));
    let full_object_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "fullObjectHash",
        "transportFullObjectHashMissing",
        "setupTransportCertificate.fullObjectHash is required",
    ));
    if full_object_hash != aggregate.full_object_hash {
        return Ok(Err(Refusal::new(
            "transportFullObjectHashMismatch",
            "setupTransportCertificate.fullObjectHash must match the aggregate transported-object set hash",
            "setupPackage.setupTransportCertificate.fullObjectHash",
        )));
    }
    let chunk_hashes = transport_canonical_try!(transport_chunk_hashes(
        transport_certificate,
        aggregate.chunk_count as usize
    ));
    if chunk_hashes != aggregate.chunk_hashes {
        return Ok(Err(Refusal::new(
            "transportChunkHashesMismatch",
            "setupTransportCertificate.chunkHashes must concatenate the transported-object chunk hashes in order",
            "setupPackage.setupTransportCertificate.chunkHashes",
        )));
    }
    let chunk_root = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "chunkRoot",
        "transportChunkRootMissing",
        "setupTransportCertificate.chunkRoot is required",
    ));
    if chunk_root != aggregate.chunk_root {
        return Ok(Err(Refusal::new(
            "transportChunkRootMismatch",
            "setupTransportCertificate.chunkRoot must match the aggregate transported-object chunk manifest",
            "setupPackage.setupTransportCertificate.chunkRoot",
        )));
    }

    let certificate_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupTransportCertificateHash",
        "transportCertificateHashMissing",
        "setupTransportCertificate.setupTransportCertificateHash is required",
    ));
    let mut certificate_hash_input = transport_certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("transport certificate object was checked")
        .remove("setupTransportCertificateHash");
    let expected_certificate_hash =
        derive_protocol_hash("SetupTransportCertificateHash", &certificate_hash_input)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Err(Refusal::new(
            "transportCertificateHashMismatch",
            "setupTransportCertificateHash does not match the canonical setup transport certificate",
            "setupPackage.setupTransportCertificate.setupTransportCertificateHash",
        )));
    }

    Ok(Ok(()))
}

fn verify_setup_transported_objects(
    setup_package: &Value,
    request: &Value,
    transport_certificate: &Value,
) -> CanonicalResult<Result<SetupTransportAggregate, Refusal>> {
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let transported_object_values = match transport_certificate
        .get("transportedObjects")
        .and_then(Value::as_array)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "transportedObjectsMissing",
                "setupTransportCertificate.transportedObjects must list the transported setup objects",
                "setupPackage.setupTransportCertificate.transportedObjects",
            )));
        }
    };
    if transported_object_values.is_empty() {
        return Ok(Err(Refusal::new(
            "transportedObjectsEmpty",
            "setupTransportCertificate.transportedObjects must bind at least the full public VSS material object",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    let mut transported_objects = Vec::with_capacity(transported_object_values.len());
    let mut seen_object_roots = BTreeSet::new();
    let mut expected_chunk_start_index = 0_u64;
    for (object_index, transported_object_value) in transported_object_values.iter().enumerate() {
        let transported_object = transport_canonical_try!(setup_transported_object_binding(
            transported_object_value,
            object_index,
            expected_chunk_start_index,
            &mut seen_object_roots,
        ));
        expected_chunk_start_index = expected_chunk_start_index
            .checked_add(transported_object.chunk_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "setup transport chunk count overflowed",
                )
            })?;
        transported_objects.push(transported_object);
    }
    let total_byte_length =
        transported_objects
            .iter()
            .try_fold(0_u64, |byte_length, transported_object| {
                byte_length
                    .checked_add(transported_object.byte_length)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport total byte length overflowed",
                        )
                    })
            })?;
    let chunk_count =
        transported_objects
            .iter()
            .try_fold(0_u64, |chunk_count, transported_object| {
                chunk_count
                    .checked_add(transported_object.chunk_count)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport aggregate chunk count overflowed",
                        )
                    })
            })?;
    let chunk_hashes = transported_objects
        .iter()
        .flat_map(|transported_object| transported_object.chunk_hashes.clone())
        .collect::<Vec<_>>();
    let full_object_hash = setup_transport_full_object_set_hash(
        &transported_objects,
        total_byte_length,
        chunk_count,
        &chunk_hashes,
    )?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    let vss_material_root = package_nested_hash(
        setup_package,
        "vssCoefficientCommitmentMaterial",
        "vssCoefficientCommitmentMaterialRoot",
    )?;
    // TODO(dynamic-roster sweep): thread the validated roster from the setup
    // context so n != 10 transport verifies; first-closure keeps n = 10 exact.
    let expected_vss_material_byte_length =
        setup_transport_vss_material_byte_length_for_roster(&first_closure_roster_parameters())?;
    let expected_vss_chunk_count = setup_transport_chunk_count(expected_vss_material_byte_length)?;
    let Some(vss_object) = transported_objects.iter().find(|transported_object| {
        transported_object.object_name == SETUP_TRANSPORTED_VSS_MATERIAL_NAME
            && transported_object.object_role == SETUP_TRANSPORTED_VSS_MATERIAL_ROLE
            && transported_object.object_root == vss_material_root
    }) else {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMissing",
            "setupTransportCertificate.transportedObjects must bind vssCoefficientCommitmentMaterial",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    };
    if vss_object.byte_length != expected_vss_material_byte_length
        || vss_object.chunk_count != expected_vss_chunk_count
    {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMetadataMismatch",
            "vssCoefficientCommitmentMaterial transported object metadata must match the accepted setup profile",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    transport_canonical_try!(verify_binary_vss_material_transport_reference(
        setup_package,
        vss_object.byte_length,
        vss_object.chunk_count,
        &vss_object.chunk_root,
        &vss_object.full_object_hash,
    ));
    let mut expected_transported_object_roots = BTreeSet::new();
    expected_transported_object_roots.insert(vss_material_root);
    transport_canonical_try!(verify_setup_transport_request_bindings(
        setup_package,
        request,
        &transported_objects,
        &mut expected_transported_object_roots,
    ));
    transport_canonical_try!(refuse_unexpected_setup_transported_objects(
        &transported_objects,
        &expected_transported_object_roots,
    ));

    Ok(Ok(SetupTransportAggregate {
        total_byte_length,
        chunk_count,
        chunk_hashes,
        chunk_root,
        full_object_hash,
    }))
}

#[derive(Clone, Debug)]
struct SetupTransportedObjectBinding {
    object_name: String,
    object_role: String,
    object_root: String,
    byte_length: u64,
    chunk_start_index: u64,
    chunk_count: u64,
    chunk_root: String,
    chunk_hashes: Vec<String>,
    full_object_hash: String,
}

#[derive(Debug)]
struct SetupTransportAggregate {
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: Vec<String>,
    chunk_root: String,
    full_object_hash: String,
}

fn setup_transported_object_binding(
    transported_object: &Value,
    object_index: usize,
    expected_chunk_start_index: u64,
    seen_object_roots: &mut BTreeSet<String>,
) -> CanonicalResult<Result<SetupTransportedObjectBinding, Refusal>> {
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

    if !transported_object.is_object() {
        return Ok(Err(Refusal::new(
            "transportedObjectNotObject",
            "setupTransportCertificate.transportedObjects entries must be root-bound objects",
            format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]"),
        )));
    }
    let object_path =
        format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]");
    transport_try!(expect_transport_string_at(
        transported_object,
        "objectType",
        SETUP_TRANSPORTED_OBJECT_TYPE,
        "transportedObjectTypeMismatch",
        "transported object objectType must be SetupTransportedObject",
        &object_path,
    ));
    transport_try!(expect_transport_u64_at(
        transported_object,
        "objectVersion",
        1,
        "transportedObjectVersionMismatch",
        "transported object objectVersion must be 1",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "encoding",
        "binary",
        "transportedObjectEncodingMismatch",
        "transported object encoding must be binary",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "loadingPolicy",
        SETUP_TRANSPORTED_OBJECT_LOADING_POLICY,
        "transportedObjectLoadingPolicyMismatch",
        "transported object loading policy must match the setup transport profile",
        &object_path,
    ));
    let object_name = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectName",
        "transportedObjectNameMissing",
        "transported object objectName is required",
        &object_path,
    ));
    let object_role = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectRole",
        "transportedObjectRoleMissing",
        "transported object objectRole is required",
        &object_path,
    ));
    let object_root = transport_try!(require_transport_hash_at(
        transported_object,
        "objectRoot",
        "transportedObjectRootMissing",
        "transported object objectRoot is required",
        &object_path,
    ));
    if !seen_object_roots.insert(object_root.clone()) {
        return Ok(Err(Refusal::new(
            "transportedObjectRootDuplicate",
            "setupTransportCertificate.transportedObjects must not contain duplicate objectRoot entries",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    let byte_length = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "byteLength",
        "transportedObjectByteLengthInvalid",
        "transported object byteLength must be positive",
        &object_path,
    ));
    // Threading chunkStartIndex enforces a gap-free, non-overlapping, ordered global chunk stream, so transported objects cannot overlap, reorder, or leave holes while still matching the aggregate chunk count.
    let chunk_start_index = transport_try!(require_transport_u64_at(
        transported_object,
        "chunkStartIndex",
        "transportedObjectStartIndexMissing",
        "transported object chunkStartIndex is required",
        &object_path,
    ));
    if chunk_start_index != expected_chunk_start_index {
        return Ok(Err(Refusal::new(
            "transportedObjectStartIndexMismatch",
            "transported object chunkStartIndex must continue the aggregate transport stream",
            format!("{object_path}.chunkStartIndex"),
        )));
    }
    let chunk_count = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "chunkCount",
        "transportedObjectChunkCountInvalid",
        "transported object chunkCount must be positive",
        &object_path,
    ));
    let expected_chunk_count = setup_transport_chunk_count(byte_length)?;
    if chunk_count != expected_chunk_count {
        return Ok(Err(Refusal::new(
            "transportedObjectChunkCountMismatch",
            "transported object chunkCount must match byteLength and the setup transport chunk size",
            format!("{object_path}.chunkCount"),
        )));
    }
    let full_object_hash = transport_try!(require_transport_hash_at(
        transported_object,
        "fullObjectHash",
        "transportedObjectFullHashMissing",
        "transported object fullObjectHash is required",
        &object_path,
    ));
    let chunk_hashes = transport_canonical_try!(transport_hashes_at(
        transported_object,
        "chunkHashes",
        usize::try_from(chunk_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported object chunkCount does not fit usize",
            )
        })?,
        &object_path,
    ));
    let chunk_root = transport_try!(require_transport_hash_at(
        transported_object,
        "chunkRoot",
        "transportedObjectChunkRootMissing",
        "transported object chunkRoot is required",
        &object_path,
    ));

    Ok(Ok(SetupTransportedObjectBinding {
        object_name,
        object_role,
        object_root,
        byte_length,
        chunk_start_index,
        chunk_count,
        chunk_root,
        chunk_hashes,
        full_object_hash,
    }))
}

struct SetupTransportExpectedObject {
    object_name: &'static str,
    object_role: &'static str,
    object_root: String,
    byte_length: u64,
    chunk_root: String,
    chunk_hashes: Vec<String>,
    full_object_hash: String,
    object_path: String,
}

#[derive(Clone, Copy)]
struct SetupTransportHashFieldNames {
    byte_length: &'static str,
    full_object_hash: &'static str,
    chunk_root: &'static str,
    chunk_hashes: &'static str,
}

#[derive(Clone, Copy)]
struct SetupTransportMaterialDescriptor {
    object_name: &'static str,
    object_role: &'static str,
    object_root: &'static str,
    hash_fields: SetupTransportHashFieldNames,
}

const SETUP_TRANSPORT_DIRECT_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "totalByteLength",
        full_object_hash: "fullObjectHash",
        chunk_root: "chunkRoot",
        chunk_hashes: "chunkHashes",
    };

const SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS: SetupTransportHashFieldNames =
    SETUP_TRANSPORT_DIRECT_HASH_FIELDS;

const SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "proofTotalByteLength",
        full_object_hash: "proofFullObjectHash",
        chunk_root: "proofChunkRoot",
        chunk_hashes: "proofChunkHashes",
    };

fn verify_setup_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &mut BTreeSet<String>,
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
            expected_object_roots,
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
            expected_object_roots,
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
                hash_fields: SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
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
                hash_fields: SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
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
            expected_object_roots,
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
            expected_object_roots,
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
            expected_object_roots,
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
    expected_object_roots: &mut BTreeSet<String>,
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
        let expected_material =
            setup_transport_expected_material(proof_material, descriptor, object_path)?;
        if !referenced_material_roots.contains(&expected_material.object_root) {
            return Ok(Err(Refusal::new(
                "transportedObjectUnreferenced",
                format!(
                    "{material_set_path}.proofMaterials contains transported material not referenced by setupPackage records"
                ),
                expected_material.object_path,
            )));
        }
        if let Err(refusal) = require_setup_transport_entry(
            transported_objects,
            &expected_material,
            expected_object_roots,
        ) {
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
    expected_object_roots: &mut BTreeSet<String>,
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
        let expected_material =
            setup_transport_expected_material(material, descriptor, object_path)?;
        if !referenced_material_roots.contains(&expected_material.object_root) {
            return Ok(Err(Refusal::new(
                "transportedObjectUnreferenced",
                format!(
                    "{material_set_path}.{material_array_field_name} contains transported material not referenced by setupPackage records"
                ),
                expected_material.object_path,
            )));
        }
        if let Err(refusal) = require_setup_transport_entry(
            transported_objects,
            &expected_material,
            expected_object_roots,
        ) {
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

fn setup_transport_expected_material(
    material: &Value,
    descriptor: SetupTransportMaterialDescriptor,
    object_path: String,
) -> CanonicalResult<SetupTransportExpectedObject> {
    let object_root = value_string(material, descriptor.object_root)?.to_string();
    validate_hash_string(
        &object_root,
        &format!("{object_path}.{}", descriptor.object_root),
    )?;

    setup_transport_expected_material_with_root(
        material,
        object_root,
        descriptor.object_name,
        descriptor.object_role,
        descriptor.hash_fields,
        object_path,
    )
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
    expected_object_roots: &mut BTreeSet<String>,
) -> Result<(), Refusal> {
    expected_object_roots.insert(expected.object_root.clone());
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

fn refuse_unexpected_setup_transported_objects(
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    for transported_object in transported_objects {
        if expected_object_roots.contains(&transported_object.object_root) {
            continue;
        }

        return Ok(Err(Refusal::new(
            "transportedObjectUnexpected",
            format!(
                "setupTransportCertificate.transportedObjects contains unrequested transported object {} with role {}",
                transported_object.object_name, transported_object.object_role
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    Ok(Ok(()))
}

fn verify_binary_vss_material_transport_reference(
    setup_package: &Value,
    expected_byte_length: u64,
    expected_chunk_count: u64,
    expected_chunk_root: &str,
    expected_full_object_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before setup transport verification",
            )
        })?;
    if material_set.get("materialEncoding").and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Ok(()));
    }
    let transport = match material_set.get("transport") {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceMissing",
                "binary-chunked vssCoefficientCommitmentMaterial must include transport metadata bound to the setup transport certificate",
                "setupPackage.vssCoefficientCommitmentMaterial.transport",
            )));
        }
    };
    let Some(transport_object) = transport.as_object() else {
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceNotObject",
            "vssCoefficientCommitmentMaterial.transport must be an object",
            "setupPackage.vssCoefficientCommitmentMaterial.transport",
        )));
    };
    if transport_object
        .get("transportProfileId")
        .and_then(Value::as_str)
        != Some(SETUP_TRANSPORT_PROFILE_ID)
    {
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceProfileMismatch",
            "vssCoefficientCommitmentMaterial.transport.transportProfileId must match the setup transport profile",
            "setupPackage.vssCoefficientCommitmentMaterial.transport.transportProfileId",
        )));
    }
    for (field_name, expected_value) in [
        ("chunkSizeBytes", SETUP_TRANSPORT_CHUNK_SIZE_BYTES),
        ("chunkCount", expected_chunk_count),
        ("totalByteLength", expected_byte_length),
    ] {
        match transport_object.get(field_name).and_then(Value::as_u64) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(_) => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMismatch",
                    "vssCoefficientCommitmentMaterial.transport numeric metadata must match the setup transport certificate",
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
            None => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMissing",
                    format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
        }
    }
    for (field_name, expected_value) in [
        ("fullObjectHash", expected_full_object_hash),
        ("chunkRoot", expected_chunk_root),
    ] {
        let Some(observed_value) = transport_object.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMissing",
                format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        };
        validate_hash_string(
            observed_value,
            &format!("vssCoefficientCommitmentMaterial.transport.{field_name}"),
        )?;
        if observed_value != expected_value {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMismatch",
                "vssCoefficientCommitmentMaterial.transport hash metadata must match the setup transport certificate",
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        }
    }

    Ok(Ok(()))
}

fn transport_chunk_hashes(
    transport_certificate: &Value,
    expected_chunk_count: usize,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    transport_hashes_at(
        transport_certificate,
        "chunkHashes",
        expected_chunk_count,
        "setupPackage.setupTransportCertificate",
    )
}

fn transport_hashes_at(
    value: &Value,
    field_name: &'static str,
    expected_chunk_count: usize,
    object_path: &str,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    match transport_hash_array(value, field_name, object_path, Some(expected_chunk_count)) {
        Ok(value) => Ok(Ok(value)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

fn transport_hash_array(
    value: &Value,
    field_name: &'static str,
    object_path: &str,
    expected_chunk_count: Option<usize>,
) -> Result<Vec<String>, Refusal> {
    let chunk_hash_values = match value.get(field_name).and_then(Value::as_array) {
        Some(value) => value,
        None => {
            return Err(Refusal::new(
                "transportChunkHashesMissing",
                format!("{object_path}.{field_name} must list every setup transport chunk hash"),
                format!("{object_path}.{field_name}"),
            ));
        }
    };
    if let Some(expected_chunk_count) = expected_chunk_count
        && chunk_hash_values.len() != expected_chunk_count
    {
        return Err(Refusal::new(
            "transportChunkHashCountMismatch",
            format!("{object_path}.{field_name} length must match chunkCount"),
            format!("{object_path}.{field_name}"),
        ));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    let mut seen_chunk_hashes = BTreeSet::new();
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(Refusal::new(
                "transportChunkHashNotString",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        };
        if chunk_hash.len() != 128
            || !chunk_hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        {
            return Err(Refusal::new(
                "transportChunkHashInvalid",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        }
        if !seen_chunk_hashes.insert(chunk_hash.to_string()) {
            return Err(Refusal::new(
                "transportChunkHashDuplicate",
                format!("{object_path}.{field_name} must not contain duplicate chunk hashes"),
                format!("{object_path}.{field_name}"),
            ));
        }
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

fn setup_transport_expected_hash_array(
    value: &Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<Vec<String>> {
    let chunk_hash_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name} must list transported chunk hashes"),
            )
        })?;
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name}[{chunk_index}] must be a protocol hash"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{object_path}.{field_name}[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

fn setup_transport_full_object_set_hash(
    transported_objects: &[SetupTransportedObjectBinding],
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: &[String],
) -> CanonicalResult<String> {
    let transported_object_values = transported_objects
        .iter()
        .map(|transported_object| {
            json!({
                "objectName": transported_object.object_name,
                "objectRole": transported_object.object_role,
                "objectRoot": transported_object.object_root,
                "byteLength": transported_object.byte_length,
                "chunkStartIndex": transported_object.chunk_start_index,
                "chunkCount": transported_object.chunk_count,
                "chunkRoot": transported_object.chunk_root,
                "fullObjectHash": transported_object.full_object_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "transportedObjects": transported_object_values,
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
}

pub(super) fn setup_transport_chunk_manifest_root(
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &json!({
            "objectType": SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

pub(super) fn setup_transport_vss_material_byte_length_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<u64> {
    let participant_count = roster.participant_count;
    let decryption_threshold = roster.decryption_threshold;
    let mut header = Vec::new();
    header.extend(b"SLVSSMAT");
    crate::encoding::append_varuint(&mut header, 1);
    crate::encoding::append_varuint(&mut header, participant_count);
    crate::encoding::append_varuint(&mut header, decryption_threshold);
    crate::encoding::append_varuint(&mut header, DATA_PRIMES.len() as u64);
    crate::encoding::append_varuint(&mut header, POLYNOMIAL_DEGREE as u64);
    crate::encoding::append_varuint(
        &mut header,
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64,
    );
    crate::encoding::append_varuint(&mut header, SETUP_COMMITMENT_ROW_COUNT as u64);

    let coordinate_byte_length = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            (0..DATA_PRIMES.len()).flat_map(move |rns_limb_index| {
                (0..decryption_threshold).map(move |shamir_coefficient_index| {
                    let mut coordinate_bytes = Vec::new();
                    crate::encoding::append_varuint(
                        &mut coordinate_bytes,
                        source_trustee_roster_position,
                    );
                    crate::encoding::append_varuint(&mut coordinate_bytes, rns_limb_index as u64);
                    crate::encoding::append_varuint(
                        &mut coordinate_bytes,
                        shamir_coefficient_index,
                    );
                    coordinate_bytes.len() as u64
                })
            })
        })
        .sum::<u64>();
    let commitment_limb_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let mut index_bytes = Vec::new();
            crate::encoding::append_varuint(&mut index_bytes, *commitment_modulus_index as u64);
            index_bytes.len() as u64
                + 8
                + (SETUP_COMMITMENT_ROW_COUNT as u64 * POLYNOMIAL_DEGREE as u64 * 8)
        })
        .sum::<u64>();
    let material_record_count = participant_count * DATA_PRIMES.len() as u64 * decryption_threshold;

    Ok(header.len() as u64
        + coordinate_byte_length
        + material_record_count * commitment_limb_byte_length)
}

fn setup_transport_chunk_count(byte_length: u64) -> CanonicalResult<u64> {
    if SETUP_TRANSPORT_CHUNK_SIZE_BYTES == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size must be positive",
        ));
    }
    Ok(byte_length.div_ceil(SETUP_TRANSPORT_CHUNK_SIZE_BYTES))
}

fn expect_transport_string(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

fn expect_transport_u64(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

fn expect_transport_string_at(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

fn require_transport_non_empty_string_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(field_value) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if field_value.is_empty() {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value.to_string())
}

fn expect_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

fn require_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(reason_code, message, format!("{object_path}.{field_name}")))
}

fn require_positive_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    let field_value =
        require_transport_u64_at(value, field_name, reason_code, message, object_path)?;
    if field_value == 0 {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value)
}

fn require_transport_hash_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if hash.len() != 128
        || !hash
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} must be a protocol hash"),
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(hash.to_string())
}

fn require_transport_hash<'a>(
    value: &'a Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
) -> CanonicalResult<Result<&'a str, Refusal>> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Ok(Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )));
    };
    validate_hash_string(hash, &format!("setupTransportCertificate.{field_name}"))?;

    Ok(Ok(hash))
}

fn setup_transport_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
