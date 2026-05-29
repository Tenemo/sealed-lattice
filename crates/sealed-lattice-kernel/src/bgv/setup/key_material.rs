use super::development_fixtures::development_key_arithmetic_fixture;
use super::*;

pub(super) struct CollectivePublicKeyCoefficients {
    pub(super) component_zero_coefficients: Vec<u64>,
    pub(super) component_one_coefficients: Vec<u64>,
}

pub(super) fn collective_public_key(
    input: &PassiveSetupInput,
    profile_hash: &str,
    backend_profile_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
) -> CanonicalResult<Value> {
    let participant_descriptors = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let participant_identities = input
        .participants
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    let coefficient_material = collective_public_key_coefficient_material(
        &input.setup_seed_hash,
        public_common_random_polynomial_root,
        public_key_share_roots,
        participant_descriptors,
        &participant_identities,
    )?;
    let collective_public_key_coefficient_root =
        collective_public_key_coefficient_root(&coefficient_material)?;
    let record_without_roots = json!({
        "objectType": "BgvCollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "profileHash": profile_hash,
        "backendProfileHash": backend_profile_hash,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "aggregationRule": "coefficient-wise-public-key-share-sum-with-shared-crp",
        "publicKeyComponentModel": "componentZero=sum_i(-a*s_i+e_i),componentOne=a-over-selected-BGV-RNS-data-basis",
        "publicKeyCoefficientMaterialBinding": "passive-transcript-derived-from-setup-seed-hash-and-public-key-share-roots",
        "participantCount": public_key_share_roots.len(),
        "centralizedSecretReconstruction": false,
        "rawSecretShareExported": false,
        "maliciousDkgProofIncluded": false,
    });
    let collective_public_key_root =
        derive_protocol_hash("CollectivePublicKeyRoot", &record_without_roots)?;
    let bgv_public_key_root = derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
            "profileHash": profile_hash,
            "backendProfileHash": backend_profile_hash,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;

    Ok(json!({
        "record": record_without_roots,
        "coefficientMaterial": coefficient_material,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "statusLabels": [
            "CollectivePublicKeyShareAggregationBound",
            "BgvPublicKeyCoefficientMaterialBound",
            "BgvAlgebraicPublicKeyProofMissing",
            "NoTrustedDealerSecretReconstruction"
        ],
    }))
}

pub(super) fn collective_public_key_coefficients_by_modulus_from_setup_package(
    setup_package: &Value,
) -> CanonicalResult<Vec<CollectivePublicKeyCoefficients>> {
    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities = participants
        .iter()
        .map(|participant| {
            string_at_path(participant, &["trusteeIdentity"]).map(ToString::to_string)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let (collective_secret_coefficients, collective_error_coefficients) =
        collective_signed_secret_and_error_coefficients(setup_seed_hash, &participant_identities);

    DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficients_from_signed(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                modulus,
            )
        })
        .collect()
}

pub(super) fn expected_collective_public_key_coefficient_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
) -> CanonicalResult<Value> {
    let setup_seed_hash = string_at_path(setup_package, &["setupInputs", "setupSeedHash"])?;
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    let public_common_random_polynomial_root = string_at_path(
        collective_public_key_record,
        &["publicCommonRandomPolynomialRoot"],
    )?;
    let public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| participant.public_key_share_root.clone())
        .collect::<Vec<_>>();
    let participant_descriptors = participant_bindings
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let participant_identities = participant_bindings
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();

    collective_public_key_coefficient_material(
        setup_seed_hash,
        public_common_random_polynomial_root,
        &public_key_share_roots,
        participant_descriptors,
        &participant_identities,
    )
}

pub(super) fn collective_public_key_coefficient_root(
    coefficient_material: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash("BGVPublicKeyRoot", coefficient_material)
}

fn collective_public_key_coefficient_material(
    setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_descriptors: Vec<Value>,
    participant_identities: &[String],
) -> CanonicalResult<Value> {
    let modulus_summaries = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficient_derivation_summary(
                setup_seed_hash,
                public_common_random_polynomial_root,
                public_key_share_roots,
                participant_identities,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "BgvCollectivePublicKeyCoefficientMaterial",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "componentModel": "componentZero=sum_i(-a*s_i+e_i),componentOne=a-over-selected-BGV-RNS-data-basis",
        "componentDerivation": "passive-transcript-derived-from-setup-seed-hash",
        "fullCoefficientVectorHashesComputed": false,
        "fullCoefficientExpansionOwner": "encrypted aggregate bridge relation arithmetic",
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "participantCount": participant_identities.len(),
        "participants": participant_descriptors,
        "modulusSummaries": modulus_summaries,
        "algebraicPublicKeyProofStatus": "BgvAlgebraicPublicKeyProofMissing",
        "rawSecretShareExported": false,
    }))
}

fn collective_public_key_coefficient_derivation_summary(
    setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_identities: &[String],
    modulus: u64,
) -> CanonicalResult<Value> {
    let modulus_bytes = modulus.to_le_bytes();
    let participant_count_bytes = (participant_identities.len() as u64).to_le_bytes();
    let public_key_share_root_count_bytes = (public_key_share_roots.len() as u64).to_le_bytes();
    let component_zero_derivation_hash = hash512_hex(
        "sealed-lattice-bgv-rns/collective-public-key-coefficient-derivation-v1",
        &[
            b"component-zero",
            setup_seed_hash.as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
            &modulus_bytes,
            &participant_count_bytes,
            &public_key_share_root_count_bytes,
        ],
    );
    let component_one_derivation_hash = hash512_hex(
        "sealed-lattice-bgv-rns/collective-public-key-coefficient-derivation-v1",
        &[
            b"component-one",
            setup_seed_hash.as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
            &modulus_bytes,
            &participant_count_bytes,
            &public_key_share_root_count_bytes,
        ],
    );
    let sampled_component_one_coefficients =
        sample_public_residues(setup_seed_hash, "public-common-random-polynomial", modulus);
    let sampled_component_zero_derivation_residues = sample_public_residues(
        setup_seed_hash,
        "collective-public-key-component-zero-derivation-diagnostic",
        modulus,
    );

    Ok(json!({
        "modulus": modulus,
        "componentZeroCoefficientDerivationHash512": component_zero_derivation_hash,
        "componentOneCoefficientDerivationHash512": component_one_derivation_hash,
        "sampledComponentZeroDerivationResidues": sampled_component_zero_derivation_residues,
        "sampledComponentOneCoefficients": sampled_component_one_coefficients,
        "fullCoefficientVectorHashStatus": "deferred-to-bridge-arithmetic-expansion",
    }))
}

fn collective_signed_secret_and_error_coefficients(
    setup_seed_hash: &str,
    participant_identities: &[String],
) -> (Vec<i64>, Vec<i64>) {
    let mut collective_secret_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
    let mut collective_error_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
    for participant_identity in participant_identities {
        let local_secret_coefficients = dense_small_coefficients(
            setup_seed_hash,
            participant_identity,
            "local-secret-share",
            -1,
            1,
        );
        let local_error_coefficients = dense_centered_binomial_coefficients(
            setup_seed_hash,
            participant_identity,
            "local-error",
        );
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            collective_secret_coefficients[coefficient_index] +=
                local_secret_coefficients[coefficient_index];
            collective_error_coefficients[coefficient_index] +=
                local_error_coefficients[coefficient_index];
        }
    }

    (
        collective_secret_coefficients,
        collective_error_coefficients,
    )
}

fn collective_public_key_coefficients_from_signed(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    collective_error_coefficients: &[i64],
    modulus: u64,
) -> CanonicalResult<CollectivePublicKeyCoefficients> {
    if collective_secret_coefficients.len() != POLYNOMIAL_DEGREE
        || collective_error_coefficients.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collective public key signed coefficient width is invalid",
        ));
    }
    let collective_secret_residues = collective_secret_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let collective_error_residues = collective_error_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let component_one_coefficients =
        dense_public_residues(setup_seed_hash, "public-common-random-polynomial", modulus);
    let public_sample_secret_product = negacyclic_product_mod(
        &component_one_coefficients,
        &collective_secret_residues,
        modulus,
    )?;
    let component_zero_coefficients = collective_error_residues
        .iter()
        .zip(public_sample_secret_product.iter())
        .map(|(error_residue, product_residue)| sub_mod(*error_residue, *product_residue, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(CollectivePublicKeyCoefficients {
        component_zero_coefficients,
        component_one_coefficients,
    })
}

pub(super) fn threshold_verification_material(
    input: &PassiveSetupInput,
    threshold_decryption_profile_hash: &str,
    kllps_target_decryption_profile_hash: &str,
    participant_setup_record_hashes: &[String],
    trustee_threshold_verification_key_hashes: &[String],
) -> CanonicalResult<Value> {
    let participant_points = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity.clone(),
                "rosterPosition": participant.roster_position,
                "interpolationPoint": participant.roster_position + 1,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let verification_key_set = json!({
        "objectType": "ThresholdShareVerificationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "thresholdDecryptionProfileId": THRESHOLD_DECRYPTION_PROFILE_ID,
        "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
        "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "participantSetupRecordHashes": participant_setup_record_hashes,
        "trusteeThresholdVerificationKeyHashes": trustee_threshold_verification_key_hashes,
        "participantInterpolationUniverse": participant_points,
        "secretShareDomain": "BGV-RNS-secret-share-polynomial-over-selected-Q-data",
        "passiveSetupVerificationScope": [
            "transcript-binding",
            "identity-binding",
            "roster-binding",
            "profile-binding",
            "recovery-device-epoch-binding"
        ],
        "maliciousDkgProofIncluded": false,
    });
    let threshold_share_verification_key_root =
        derive_protocol_hash("ThresholdShareVerificationKeyRoot", &verification_key_set)?;
    let threshold_share_verification_key_hash = derive_protocol_hash(
        "ThresholdShareVerificationKeyHash",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileHash": threshold_decryption_profile_hash,
            "kllpsTargetDecryptionProfileHash": kllps_target_decryption_profile_hash,
        }),
    )?;

    Ok(json!({
        "verificationKeySet": verification_key_set,
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHashes": trustee_threshold_verification_key_hashes,
        "statusLabels": [
            "ThresholdVerificationMaterialBound",
            "PassiveSetupVerificationScopeOnly",
            "KllpsVerificationRootsBound"
        ],
    }))
}

pub(super) fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_hash: &str,
) -> CanonicalResult<Value> {
    let rot_set = provisional_rotation_set()?;
    let rot_set_hash = derive_protocol_hash("RotSetHash", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let relinearization_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID,
        "relinearization-key-fixture",
        key_switch_decomposition_hash,
    )?;
    let key_switch_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID,
        "key-switch-fixture",
        key_switch_decomposition_hash,
    )?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "arithmeticFixtureHash": relinearization_arithmetic_fixture["fixtureHash"],
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root =
        derive_protocol_hash("RelinearizationKeyRoot", &relinearization_key_record)?;
    let rotation_key_records = rot_set["rotations"]
        .as_array()
        .expect("rotation set uses array")
        .iter()
        .map(|rotation| {
            let record = json!({
                "objectType": "BgvRotationKey",
                "objectVersion": 1,
                "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
                "ceremonyId": input.ceremony_id,
                "rosterHash": input.roster_hash,
                "collectivePublicKeyRoot": collective_public_key_root,
                "rotSetHash": rot_set_hash,
                "rotation": rotation,
                "keySwitchDecompositionHash": key_switch_decomposition_hash,
                "publicBasisId": BgvBasisKind::Extended.basis_id(),
                "publicRlweSampleCount": 1,
                "maliciousEvaluationKeyProofIncluded": false,
            });
            let root = derive_protocol_hash("RotationKeyRoot", &record)?;
            Ok(json!({
                "rotation": rotation,
                "rotationKeyRoot": root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "arithmeticFixtureHash": key_switch_arithmetic_fixture["fixtureHash"],
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = derive_protocol_hash("KeySwitchKeyRoot", &key_switch_key_record)?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "rotSetHash": rot_set_hash,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationArithmeticFixtureHash": relinearization_arithmetic_fixture["fixtureHash"],
        "rotationKeyRoots": rotation_key_records,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchArithmeticFixtureHash": key_switch_arithmetic_fixture["fixtureHash"],
        "generatedFor": "provisionalRotSet",
        "finalRotSetClosure": "encrypted-aggregate-evaluator-closure",
        "regenerateIfRotSetChanges": true,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let evaluation_key_root = derive_protocol_hash("EvalKeyRoot", &evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
        "rotSetHash": rot_set_hash,
        "keySwitchDecompositionHash": key_switch_decomposition_hash,
        "relinearizationKeyRoot": relinearization_key_root,
        "keySwitchKeyRoot": key_switch_key_root,
        "relinearizationArithmeticFixture": relinearization_arithmetic_fixture,
        "keySwitchArithmeticFixture": key_switch_arithmetic_fixture,
        "rotationKeyRoots": rotation_key_records,
        "evaluationKeyRoot": evaluation_key_root,
        "statusLabels": [
            "RelinearizationKeyMaterialBound",
            "RotationKeyMaterialBound",
            "KeySwitchMaterialBound",
            "ProvisionalRotSetBound"
        ],
    }))
}

fn provisional_rotation_set() -> CanonicalResult<Value> {
    Ok(json!({
        "rotSetId": PROVISIONAL_ROT_SET_ID,
        "sourceRdr": "internal-design-note-top-k-circuit-and-sparse-target",
        "generatedFor": "provisionalRotSet",
        "finalizedBy": "encrypted-aggregate-evaluator-closure",
        "regeneratePassiveSetupKeysIfChanged": true,
        "rotations": [
            1, 2, 4, 8, 16, 32, 64, 128,
            256, 512, 1024, 2048, 4096, 8192,
            -1, -2, -4, -8, -16, -32, -64, -128,
            -256, -512, -1024, -2048, -4096, -8192
        ],
        "dependencies": [
            "encrypted-aggregate-reconstruction",
            "encrypted-aggregate-score-bit-derivation",
            "bit-sliced-GT-EQ",
            "rank-accumulation",
            "encrypted-sparse-target-projection",
            "target-decryption-interface-checks"
        ],
        "requiredRotationGroups": [
            {
                "purpose": "bit-sliced-projection",
                "rotations": [1, 2, 4, 8, 16, -1, -2, -4, -8, -16]
            },
            {
                "purpose": "encrypted-aggregate-score-bit-derivation",
                "rotations": [32, 64, 128, -32, -64, -128]
            },
            {
                "purpose": "rank-accumulation",
                "rotations": [256, 512, 1024, 2048, -256, -512, -1024, -2048]
            },
            {
                "purpose": "target-projection",
                "rotations": [4096, 8192, -4096, -8192]
            }
        ],
    }))
}
