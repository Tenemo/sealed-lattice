use super::*;

pub(super) fn validate_setup_package_internal_bindings(
    setup_package: &Value,
) -> CanonicalResult<()> {
    reject_forbidden_setup_package_secret_fields(setup_package)?;
    let profile_digest = profile_digest()?;
    let backend_profile_digest = backend_profile_digest()?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "profileId"],
        PROFILE_ID,
        "profile id",
    )?;
    compare_string_at_path(
        setup_package,
        &["profileBindings", "backendProfileId"],
        BACKEND_PROFILE_ID,
        "backend profile id",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "profileDigest"],
        &profile_digest,
        "profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "backendProfileDigest"],
        &backend_profile_digest,
        "backend profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionDigest"],
        &canonical_ciphertext_convention_digest()?,
        "canonical ciphertext convention digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchEncoderDigest"],
        &batch_encoder_digest()?,
        "batch encoder digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "batchLayoutBindingDigest"],
        &batch_layout_binding_digest()?,
        "batch layout binding digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "allowedEvaluatorOpsDigest"],
        &allowed_operation_registry_digest()?,
        "allowed evaluator operation digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutDigest"],
        &layout_digest()?,
        "encrypted aggregate input layout digest",
    )?;
    let expected_evaluator_bindings = m8_evaluator_context_bindings()?;
    for (field_name, description) in [
        (
            "encryptedAggregateBridgeDigest",
            "encrypted aggregate bridge digest",
        ),
        (
            "encryptedAggregateTargetBasisDataRoot",
            "encrypted aggregate target-basis data root",
        ),
        (
            "encryptedAggregateReconstructionDigest",
            "encrypted aggregate reconstruction digest",
        ),
        (
            "scoreBitDerivationCircuitDigest",
            "score-bit derivation circuit digest",
        ),
        (
            "comparisonInputDerivationCircuitDigest",
            "comparison-input derivation circuit digest",
        ),
        (
            "encryptedScoreBitInputDigest",
            "encrypted score-bit input digest",
        ),
        (
            "encryptedComparisonInputDigest",
            "encrypted comparison input digest",
        ),
        ("bitSlicedComparatorDigest", "bit-sliced comparator digest"),
        (
            "encryptedSparseTargetProjectionDigest",
            "encrypted sparse target projection digest",
        ),
        (
            "m8EvaluatorContextBindingDigest",
            "M8 evaluator context binding digest",
        ),
    ] {
        compare_digest_at_path(
            setup_package,
            &["profileBindings", field_name],
            string_at_path(&expected_evaluator_bindings, &[field_name])?,
            description,
        )?;
    }

    let threshold_decryption_profile_digest = derive_protocol_digest(
        "ThresholdDecryptionProfileDigest",
        &threshold_decryption_profile(&profile_digest)?,
    )?;
    let kllps_target_decryption_profile_digest = derive_protocol_digest(
        "KllpsTargetDecryptionProfileDigest",
        &json!({
            "profileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "profileStatus": "future-target-decryption-profile-binding",
        }),
    )?;
    compare_string_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileId"],
        THRESHOLD_DECRYPTION_PROFILE_ID,
        "threshold decryption profile id",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "thresholdDecryptionProfileDigest"],
        &threshold_decryption_profile_digest,
        "threshold decryption profile digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["kllpsCompatibility", "kllpsTargetDecryptionProfileDigest"],
        &kllps_target_decryption_profile_digest,
        "KLLPS target decryption profile digest",
    )?;

    let participant_bindings = validate_participant_setup_records(
        setup_package,
        &profile_digest,
        &backend_profile_digest,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
    )?;
    validate_collective_public_key(
        setup_package,
        &participant_bindings,
        &profile_digest,
        &backend_profile_digest,
    )?;
    validate_threshold_verification_material(
        setup_package,
        &participant_bindings,
        &threshold_decryption_profile_digest,
        &kllps_target_decryption_profile_digest,
    )?;
    validate_evaluation_keys(setup_package)?;
    validate_setup_certificates(setup_package)?;

    Ok(())
}

fn validate_participant_setup_records(
    setup_package: &Value,
    profile_digest: &str,
    backend_profile_digest: &str,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<Vec<VerifiedParticipantSetupBinding>> {
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?;
    let manifest_digest = digest_at_path(setup_package, &["setupInputs", "manifestDigest"])?;
    let roster_digest = digest_at_path(setup_package, &["setupInputs", "rosterDigest"])?;
    let threshold_profile_digest =
        digest_at_path(setup_package, &["setupInputs", "thresholdProfileDigest"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities =
        array_at_path(setup_package, &["setupInputs", "participantIdentities"])?;
    if participant_identities.len() != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant identities do not match participant records",
        ));
    }

    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    let mut verified_participants = Vec::with_capacity(participants.len());
    for (participant_index, participant_record) in participants.iter().enumerate() {
        compare_string_at_path(
            participant_record,
            &["objectType"],
            "ParticipantBgvSetupRecord",
            "participant record object type",
        )?;
        if unsigned_at_path(participant_record, &["objectVersion"])? != 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participant setup record object version must be 1",
            ));
        }
        compare_string_at_path(
            participant_record,
            &["setupProfileId"],
            PASSIVE_SETUP_PROFILE_ID,
            "participant setup profile id",
        )?;
        compare_string_at_path(
            participant_record,
            &["ceremonyId"],
            ceremony_id,
            "participant ceremony id",
        )?;
        compare_digest_at_path(
            participant_record,
            &["manifestDigest"],
            manifest_digest,
            "participant manifest digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["rosterDigest"],
            roster_digest,
            "participant roster digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["thresholdProfileDigest"],
            threshold_profile_digest,
            "participant threshold profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["profileDigest"],
            profile_digest,
            "participant profile digest",
        )?;
        compare_digest_at_path(
            participant_record,
            &["backendProfileDigest"],
            backend_profile_digest,
            "participant backend profile digest",
        )?;
        let trustee_identity = string_at_path(participant_record, &["trusteeIdentity"])?;
        ensure_nfc_identity(trustee_identity, "participant trusteeIdentity")?;
        let listed_identity = participant_identities[participant_index]
            .as_str()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupPackage participant identities must be strings",
                )
            })?;
        ensure_nfc_identity(listed_identity, "setupPackage participant identity")?;
        if listed_identity != trustee_identity {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setupPackage participant identity order does not match participant records",
            ));
        }
        let roster_position = usize_at_path(participant_record, &["rosterPosition"])?;
        if roster_position >= participants.len() || !roster_positions.insert(roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant roster positions must be unique and cover the frozen roster",
            ));
        }
        if !identities.insert(trustee_identity.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage participant identities must be unique",
            ));
        }
        let recovery_epoch = unsigned_at_path(participant_record, &["recoveryEpoch"])?;
        let device_epoch = unsigned_at_path(participant_record, &["deviceEpoch"])?;
        let public_key_share_root = digest_at_path(participant_record, &["publicKeyShareRoot"])?;
        let participant_setup_record_digest =
            digest_at_path(participant_record, &["participantSetupRecordDigest"])?;
        let trustee_threshold_verification_key_digest = digest_at_path(
            participant_record,
            &["trusteeThresholdVerificationKeyDigest"],
        )?;
        digest_at_path(participant_record, &["localSecretShareCommitmentDigest"])?;
        digest_at_path(participant_record, &["localErrorCommitmentDigest"])?;

        let mut participant_record_without_digest = participant_record.clone();
        participant_record_without_digest
            .as_object_mut()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "participant setup record must be an object",
                )
            })?
            .remove("participantSetupRecordDigest");
        compare_derived_digest(
            "ParticipantBgvSetupRecordDigest",
            &participant_record_without_digest,
            participant_setup_record_digest,
            "participant setup record digest",
        )?;

        let trustee_threshold_verification_key = json!({
            "objectType": "TrusteeThresholdVerificationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
            "ceremonyId": ceremony_id,
            "rosterDigest": roster_digest,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
            "publicKeyShareRoot": public_key_share_root,
            "verificationStatement": "passive-transcript-identity-profile-and-share-domain-binding",
            "maliciousDkgProofIncluded": false,
        });
        compare_derived_digest(
            "TrusteeThresholdVerificationKeyDigest",
            &trustee_threshold_verification_key,
            trustee_threshold_verification_key_digest,
            "trustee threshold verification key digest",
        )?;

        verified_participants.push(VerifiedParticipantSetupBinding {
            trustee_identity: trustee_identity.to_string(),
            roster_position,
            recovery_epoch,
            device_epoch,
            public_key_share_root: public_key_share_root.to_string(),
            participant_setup_record_digest: participant_setup_record_digest.to_string(),
            trustee_threshold_verification_key_digest: trustee_threshold_verification_key_digest
                .to_string(),
        });
    }

    Ok(verified_participants)
}

fn validate_collective_public_key(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    profile_digest: &str,
    backend_profile_digest: &str,
) -> CanonicalResult<()> {
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    compare_string_at_path(
        collective_public_key_record,
        &["objectType"],
        "BgvCollectivePublicKey",
        "collective public key object type",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["profileDigest"],
        profile_digest,
        "collective public key profile digest",
    )?;
    compare_digest_at_path(
        collective_public_key_record,
        &["backendProfileDigest"],
        backend_profile_digest,
        "collective public key backend profile digest",
    )?;
    if usize_at_path(collective_public_key_record, &["participantCount"])?
        != participant_bindings.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key participant count does not match participant records",
        ));
    }
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(collective_public_key_record, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key share roots do not match participant records",
        ));
    }

    let collective_public_key_root =
        digest_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    compare_derived_digest(
        "CollectivePublicKeyRoot",
        collective_public_key_record,
        collective_public_key_root,
        "collective public key root",
    )?;
    let expected_bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;
    compare_digest_at_path(
        collective_public_key,
        &["bgvPublicKeyRoot"],
        &expected_bgv_public_key_root,
        "BGV public key root",
    )
}

fn validate_threshold_verification_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
) -> CanonicalResult<()> {
    let threshold_material = value_at_path(setup_package, &["thresholdVerificationMaterial"])?;
    let verification_key_set = value_at_path(threshold_material, &["verificationKeySet"])?;
    let expected_participant_setup_record_digests = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.participant_setup_record_digest.clone()))
        .collect::<Vec<_>>();
    let expected_trustee_threshold_verification_key_digests = participant_bindings
        .iter()
        .map(|participant| {
            Value::String(
                participant
                    .trustee_threshold_verification_key_digest
                    .clone(),
            )
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantSetupRecordDigests"])?
        != &expected_participant_setup_record_digests
        || array_at_path(
            verification_key_set,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
        || array_at_path(
            threshold_material,
            &["trusteeThresholdVerificationKeyDigests"],
        )? != &expected_trustee_threshold_verification_key_digests
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold verification material does not match participant setup records",
        ));
    }

    let expected_interpolation_universe = participant_bindings
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantInterpolationUniverse"])?
        != &expected_interpolation_universe
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "threshold interpolation universe does not match participant setup records",
        ));
    }

    let threshold_share_verification_key_root =
        digest_at_path(threshold_material, &["thresholdShareVerificationKeyRoot"])?;
    compare_derived_digest(
        "ThresholdShareVerificationKeyRoot",
        verification_key_set,
        threshold_share_verification_key_root,
        "threshold share verification key root",
    )?;
    let expected_threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;
    compare_digest_at_path(
        threshold_material,
        &["thresholdShareVerificationKeyDigest"],
        &expected_threshold_share_verification_key_digest,
        "threshold share verification key digest",
    )
}

fn validate_evaluation_keys(setup_package: &Value) -> CanonicalResult<()> {
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let evaluation_key_record = value_at_path(evaluation_keys, &["record"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_digest = digest_at_path(evaluation_keys, &["rotSetDigest"])?;
    compare_derived_digest(
        "RotSetDigest",
        rot_set,
        rot_set_digest,
        "rotation set digest",
    )?;
    let key_switch_decomposition_digest =
        digest_at_path(evaluation_keys, &["keySwitchDecompositionDigest"])?;
    compare_digest_at_path(
        evaluation_key_record,
        &["keySwitchDecompositionDigest"],
        key_switch_decomposition_digest,
        "evaluation key decomposition digest",
    )?;
    compare_digest_at_path(
        setup_package,
        &["certificates", "keySwitchDecompositionDigest"],
        key_switch_decomposition_digest,
        "certificate key-switch decomposition digest",
    )?;
    let collective_public_key_root =
        digest_at_path(evaluation_key_record, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = digest_at_path(evaluation_key_record, &["bgvPublicKeyRoot"])?;
    compare_digest_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        collective_public_key_root,
        "evaluation key collective public key root",
    )?;
    compare_digest_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        bgv_public_key_root,
        "evaluation key BGV public key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["rotSetDigest"],
        rot_set_digest,
        "evaluation key rotation set digest",
    )?;
    let relinearization_arithmetic_fixture_digest = validate_development_key_arithmetic_fixture(
        value_at_path(evaluation_keys, &["relinearizationArithmeticFixture"])?,
        DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID,
        key_switch_decomposition_digest,
    )?;
    let key_switch_arithmetic_fixture_digest = validate_development_key_arithmetic_fixture(
        value_at_path(evaluation_keys, &["keySwitchArithmeticFixture"])?,
        DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID,
        key_switch_decomposition_digest,
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["relinearizationArithmeticFixtureDigest"],
        &relinearization_arithmetic_fixture_digest,
        "evaluation key relinearization arithmetic fixture digest",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["keySwitchArithmeticFixtureDigest"],
        &key_switch_arithmetic_fixture_digest,
        "evaluation key key-switch arithmetic fixture digest",
    )?;

    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "arithmeticFixtureDigest": relinearization_arithmetic_fixture_digest,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root = digest_at_path(evaluation_keys, &["relinearizationKeyRoot"])?;
    compare_derived_digest(
        "RelinearizationKeyRoot",
        &relinearization_key_record,
        relinearization_key_root,
        "relinearization key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["relinearizationKeyRoot"],
        relinearization_key_root,
        "evaluation key relinearization root",
    )?;

    let rotation_key_roots = array_at_path(evaluation_keys, &["rotationKeyRoots"])?;
    let rotations = array_at_path(rot_set, &["rotations"])?;
    if rotation_key_roots.len() != rotations.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rotation key root count does not match the provisional rotation set",
        ));
    }
    let mut exported_rotation_values = BTreeSet::new();
    for (rotation_index, rotation_key_root_record) in rotation_key_roots.iter().enumerate() {
        if value_at_path(rotation_key_root_record, &["rotation"])? != &rotations[rotation_index] {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "rotation key root order does not match the provisional rotation set",
            ));
        }
        exported_rotation_values.insert(integer_at_path(rotation_key_root_record, &["rotation"])?);
        let rotation_key_record = json!({
            "objectType": "BgvRotationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
            "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
            "collectivePublicKeyRoot": collective_public_key_root,
            "rotSetDigest": rot_set_digest,
            "rotation": rotations[rotation_index].clone(),
            "keySwitchDecompositionDigest": key_switch_decomposition_digest,
            "publicBasisId": BgvBasisKind::Extended.basis_id(),
            "publicRlweSampleCount": 1,
            "maliciousEvaluationKeyProofIncluded": false,
        });
        compare_derived_digest(
            "RotationKeyRoot",
            &rotation_key_record,
            digest_at_path(rotation_key_root_record, &["rotationKeyRoot"])?,
            "rotation key root",
        )?;
    }
    validate_required_rotation_groups(rot_set, &exported_rotation_values)?;
    if array_at_path(evaluation_key_record, &["rotationKeyRoots"])? != rotation_key_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key record rotation roots do not match exported rotation roots",
        ));
    }

    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": string_at_path(evaluation_key_record, &["ceremonyId"])?,
        "rosterDigest": digest_at_path(evaluation_key_record, &["rosterDigest"])?,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "arithmeticFixtureDigest": key_switch_arithmetic_fixture_digest,
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = digest_at_path(evaluation_keys, &["keySwitchKeyRoot"])?;
    compare_derived_digest(
        "KeySwitchKeyRoot",
        &key_switch_key_record,
        key_switch_key_root,
        "key-switch key root",
    )?;
    compare_digest_at_path(
        evaluation_key_record,
        &["keySwitchKeyRoot"],
        key_switch_key_root,
        "evaluation key key-switch root",
    )?;

    let evaluation_key_root = digest_at_path(evaluation_keys, &["evaluationKeyRoot"])?;
    compare_derived_digest(
        "EvalKeyRoot",
        evaluation_key_record,
        evaluation_key_root,
        "evaluation key root",
    )
}

fn validate_required_rotation_groups(
    rot_set: &Value,
    exported_rotation_values: &BTreeSet<i64>,
) -> CanonicalResult<()> {
    let declared_rotations = array_at_path(rot_set, &["rotations"])?
        .iter()
        .map(|rotation| {
            rotation.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "provisional rotation set entries must be signed integers",
                )
            })
        })
        .collect::<CanonicalResult<BTreeSet<_>>>()?;
    if &declared_rotations != exported_rotation_values {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "exported rotation keys must cover exactly the provisional rotation set",
        ));
    }

    let required_rotation_groups = array_at_path(rot_set, &["requiredRotationGroups"])?;
    let mut seen_purposes = BTreeSet::new();
    for group in required_rotation_groups {
        let purpose = string_at_path(group, &["purpose"])?;
        if !seen_purposes.insert(purpose.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "required rotation group purposes must be unique",
            ));
        }
        let expected_group_rotations =
            expected_required_rotation_group(purpose).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!("required rotation group {purpose} is not part of M8"),
                )
            })?;
        let mut actual_group_rotations = BTreeSet::new();
        for rotation in array_at_path(group, &["rotations"])? {
            let rotation_value = rotation.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "required rotation group entries must be signed integers",
                )
            })?;
            actual_group_rotations.insert(rotation_value);
            if !declared_rotations.contains(&rotation_value)
                || !exported_rotation_values.contains(&rotation_value)
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!(
                        "required rotation group {purpose} is missing rotation {rotation_value}"
                    ),
                ));
            }
        }
        if actual_group_rotations != expected_group_rotations {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("required rotation group {purpose} does not match the M8 fixture set"),
            ));
        }
    }
    for purpose in [
        "bit-sliced-projection",
        "score-bit-comparison-input-derivation",
        "rank-accumulation",
        "target-projection",
    ] {
        if !seen_purposes.contains(purpose) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("required rotation group {purpose} is missing"),
            ));
        }
    }

    Ok(())
}

fn expected_required_rotation_group(purpose: &str) -> Option<BTreeSet<i64>> {
    let rotations = match purpose {
        "bit-sliced-projection" => vec![1, 2, 4, 8, 16, -1, -2, -4, -8, -16],
        "score-bit-comparison-input-derivation" => vec![32, 64, 128, -32, -64, -128],
        "rank-accumulation" => vec![256, 512, 1024, 2048, -256, -512, -1024, -2048],
        "target-projection" => vec![4096, 8192, -4096, -8192],
        _ => return None,
    };

    Some(rotations.into_iter().collect())
}

fn validate_development_key_arithmetic_fixture(
    wrapped_fixture: &Value,
    expected_fixture_id: &str,
    expected_key_switch_decomposition_digest: &str,
) -> CanonicalResult<String> {
    let fixture_record = value_at_path(wrapped_fixture, &["fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["objectType"],
        "BgvDevelopmentKeyArithmeticFixture",
        "development key arithmetic fixture object type",
    )?;
    compare_string_at_path(
        fixture_record,
        &["fixtureId"],
        expected_fixture_id,
        "development key arithmetic fixture id",
    )?;
    compare_digest_at_path(
        fixture_record,
        &["keySwitchDecompositionDigest"],
        expected_key_switch_decomposition_digest,
        "development key arithmetic fixture decomposition digest",
    )?;
    compare_string_at_path(
        fixture_record,
        &["m7ArithmeticStatus"],
        "sampled-decompose-recompose-and-modmul-passed",
        "development key arithmetic status",
    )?;
    for sample in array_at_path(fixture_record, &["sampledCoefficientChecks"])? {
        if !bool_at_path(sample, &["recompositionMatches"])? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development key arithmetic fixture has a failed decomposition check",
            ));
        }
        let modulus = unsigned_at_path(sample, &["modulus"])?;
        let source_coefficient = unsigned_at_path(sample, &["sourceCoefficient"])?;
        let digits = array_at_path(sample, &["decompositionDigits"])?;
        if digits.len() != 3 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "development key arithmetic fixture must use three decomposition digits",
            ));
        }
        let digit_base = 1_u128 << 23;
        let first_digit = u128::from(digits[0].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let second_digit = u128::from(digits[1].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let third_digit = u128::from(digits[2].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development key arithmetic digits must be non-negative integers",
            )
        })?);
        let recomposed =
            ((first_digit + digit_base * second_digit + digit_base * digit_base * third_digit)
                % u128::from(modulus)) as u64;
        if recomposed != source_coefficient
            || unsigned_at_path(sample, &["recomposedCoefficient"])? != source_coefficient
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development key arithmetic fixture decomposition does not recompose",
            ));
        }
    }

    let fixture_digest = development_fixture_digest(fixture_record)?;
    compare_digest_at_path(
        wrapped_fixture,
        &["fixtureDigest"],
        &fixture_digest,
        "development key arithmetic fixture digest",
    )?;

    Ok(fixture_digest)
}

fn validate_setup_certificates(setup_package: &Value) -> CanonicalResult<()> {
    let certificates = value_at_path(setup_package, &["certificates"])?;
    compare_derived_digest(
        "CollectiveSecretDistributionCertificateDigest",
        value_at_path(certificates, &["collectiveSecretDistributionCertificate"])?,
        digest_at_path(
            certificates,
            &["collectiveSecretDistributionCertificateDigest"],
        )?,
        "collective secret distribution certificate digest",
    )?;
    compare_derived_digest(
        "ErrorDistributionCertificateDigest",
        value_at_path(certificates, &["errorDistributionCertificate"])?,
        digest_at_path(certificates, &["errorDistributionCertificateDigest"])?,
        "error distribution certificate digest",
    )?;
    compare_derived_digest(
        "KeySwitchDecompositionDigest",
        value_at_path(certificates, &["keySwitchDecomposition"])?,
        digest_at_path(certificates, &["keySwitchDecompositionDigest"])?,
        "key-switch decomposition digest",
    )?;
    compare_derived_digest(
        "EvaluationKeySizeProfileDigest",
        value_at_path(certificates, &["evaluationKeySizeCertificate"])?,
        digest_at_path(certificates, &["evaluationKeySizeProfileDigest"])?,
        "evaluation key size profile digest",
    )?;
    let evaluation_key_streaming_fixture_digest =
        validate_evaluation_key_streaming_fixture(certificates)?;
    compare_digest_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["evaluationKeyStreamingFixtureDigest"],
        &evaluation_key_streaming_fixture_digest,
        "setup parameter evaluation key streaming fixture digest",
    )?;
    compare_derived_digest(
        "BGVSetupParameterCertificateDigest",
        value_at_path(certificates, &["setupParameterCertificate"])?,
        digest_at_path(certificates, &["setupParameterCertificateDigest"])?,
        "setup parameter certificate digest",
    )?;
    compare_derived_digest(
        "BGVDevelopmentEncryptionFixtureDigest",
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?,
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "development encryption fixture digest",
    )?;
    validate_development_encryption_fixture(setup_package)?;
    compare_digest_at_path(
        certificates,
        &["developmentEncryptionFixtureDigest"],
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "certificate development encryption fixture digest",
    )
}

fn validate_evaluation_key_streaming_fixture(certificates: &Value) -> CanonicalResult<String> {
    let wrapped_fixture = value_at_path(certificates, &["evaluationKeyStreamingFixture"])?;
    let fixture_record = value_at_path(wrapped_fixture, &["fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["objectType"],
        "BgvEvaluationKeyStreamingFixture",
        "evaluation key streaming fixture object type",
    )?;
    compare_string_at_path(
        fixture_record,
        &["fixtureId"],
        EVALUATION_KEY_STREAMING_FIXTURE_ID,
        "evaluation key streaming fixture id",
    )?;
    if usize_at_path(fixture_record, &["chunkSizeBytes"])? != EVALUATION_KEY_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "evaluation key streaming fixture chunk size changed",
        ));
    }
    let stream_record = value_at_path(fixture_record, &["streamRecord"])?;
    let stream_bytes = canonical_json(stream_record)?.into_bytes();
    if usize_at_path(fixture_record, &["canonicalStreamByteLength"])? != stream_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation key streaming fixture byte length does not match its stream record",
        ));
    }
    compare_digest_at_path(
        fixture_record,
        &["chunkRoot"],
        &chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?,
        "evaluation key streaming fixture chunk root",
    )?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        fixture_record,
        &["storageQuotaFixture", "totalEvaluationKeyByteEstimate"],
    )?;
    let quota_bytes = usize_at_path(fixture_record, &["storageQuotaFixture", "quotaBytes"])?;
    let accepted = bool_at_path(fixture_record, &["storageQuotaFixture", "accepted"])?;
    if accepted != (total_evaluation_key_byte_estimate <= quota_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key streaming fixture storage quota decision is inconsistent",
        ));
    }
    let fixture_digest = development_fixture_digest(fixture_record)?;
    compare_digest_at_path(
        wrapped_fixture,
        &["fixtureDigest"],
        &fixture_digest,
        "evaluation key streaming fixture digest",
    )?;

    Ok(fixture_digest)
}

fn validate_development_encryption_fixture(setup_package: &Value) -> CanonicalResult<()> {
    let fixture_record =
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["fixtureScope"],
        "development-collective-public-key-encryption-fixture",
        "development encryption fixture scope",
    )?;
    if bool_at_path(fixture_record, &["m9BridgeEncryptionClaim"])?
        || bool_at_path(fixture_record, &["m10EvaluatorClaim"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "development encryption fixture must not claim M9 bridge or M10 evaluator closure",
        ));
    }
    compare_digest_at_path(
        fixture_record,
        &["collectivePublicKeyRoot"],
        digest_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "development encryption collective public key root",
    )?;
    compare_digest_at_path(
        fixture_record,
        &["bgvPublicKeyRoot"],
        digest_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "development encryption BGV public key root",
    )?;
    digest_at_path(fixture_record, &["publicKeyMaterialRoot"])?;
    digest_at_path(fixture_record, &["randomnessRoot"])?;
    digest_at_path(fixture_record, &["plaintextRoot"])?;
    digest_at_path(fixture_record, &["ciphertextRoot"])?;
    digest_at_path(fixture_record, &["canonicalBytesHash512"])?;
    if unsigned_at_path(fixture_record, &["canonicalByteLength"])? == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "development encryption fixture canonical byte length must be non-zero",
        ));
    }
    for relation_check in array_at_path(fixture_record, &["sampledPublicRelationChecks"])? {
        if !bool_at_path(relation_check, &["relationMatches"])? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development encryption fixture contains a failed public relation check",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_setup_package_shape(setup_package: &Value) -> CanonicalResult<()> {
    if setup_package.get("objectType").and_then(Value::as_str) != Some("BgvPassiveSetupPackage")
        || setup_package.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || setup_package.get("setupProfileId").and_then(Value::as_str)
            != Some(PASSIVE_SETUP_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is not an M8 passive BGV setup package",
        ));
    }
    if !bool_at_path(
        setup_package,
        &["kllpsCompatibility", "setupMaterialCompatibleWithKLLPS"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must be marked KLLPS-compatible",
        ));
    }
    if bool_at_path(
        setup_package,
        &["kllpsCompatibility", "KLLPSPartDecImplemented"],
    )? || bool_at_path(setup_package, &["kllpsCompatibility", "KLLPSC1C4Certified"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must not claim KLLPS PartDec or C1-C4 certification",
        ));
    }
    if bool_at_path(
        setup_package,
        &[
            "trustedDealerBoundary",
            "transcriptValidCentralizedSecretReconstruction",
        ],
    )? || bool_at_path(
        setup_package,
        &["trustedDealerBoundary", "rawSecretSharesExported"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must not claim centralized secret reconstruction or raw share export",
        ));
    }
    if string_at_path(
        setup_package,
        &[
            "certificates",
            "setupParameterCertificate",
            "finalSecurityStatus",
        ],
    )? != "pendingQTarget"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M8 setup package must keep final Appendix B security pending Q_target",
        ));
    }
    let participants = setup_package
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.participants must be an array",
            )
        })?;
    let participant_count = usize_at_path(setup_package, &["setupInputs", "participantCount"])?;
    if !(MINIMUM_PASSIVE_SETUP_ROSTER_SIZE..=MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE)
        .contains(&participant_count)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage participant count is outside the M8 passive setup roster bounds",
        ));
    }
    if participant_count != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setupPackage participant count does not match participant records",
        ));
    }

    Ok(())
}
