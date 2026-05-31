use super::*;
use crate::bgv::evaluator::{
    key_switch::{KEY_SWITCH_ERROR_DOMAIN, KEY_SWITCH_SAMPLE_DOMAIN},
    prg::DeterministicSampler,
    records::MAXIMUM_OPTION_COUNT,
    top_k::{
        DIRECT_COMPARISON_OUTPUT_LEVEL, aggregate_score_packing_galois_elements, galois_power,
        inverse_galois_element, packed_rank_galois_elements,
    },
};

const DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL: &str =
    "componentZero=sum_i(-a*s_i+p*e_i),componentOne=a-over-selected-BGV-RNS-data-basis";
const EVALUATION_KEY_STREAM_POLICY: &str =
    "sealed-lattice-deterministic-bgv-key-switch-material-stream-v1";

pub(super) struct CollectivePublicKeyCoefficients {
    pub(super) component_zero_coefficients: Vec<u64>,
    pub(super) component_one_coefficients: Vec<u64>,
}

struct EvaluationKeyMaterialBinding {
    record: Value,
    material_hash: String,
    relinearization_key_root: String,
    relinearization_key_record: Value,
    key_switch_key_root: String,
    key_switch_key_record: Value,
    rotation_key_roots: Vec<Value>,
    rotation_key_records: Vec<Value>,
}

struct RotationScheduleEntry {
    rotation: usize,
    level: usize,
    purpose: &'static str,
}

struct EvaluationKeyMaterialInput<'a> {
    setup_seed_hash: &'a str,
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    participant_identities: &'a [String],
    collective_public_key: &'a Value,
    key_switch_decomposition_hash: &'a str,
    rot_set: &'a Value,
    rot_set_hash: &'a str,
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
        "publicKeyComponentModel": DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL,
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
        "componentModel": DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL,
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

pub(super) fn collective_signed_secret_and_error_coefficients(
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

pub(super) fn collective_public_key_coefficients_from_signed(
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
    let collective_scaled_error_residues = collective_error_coefficients
        .iter()
        .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let component_one_coefficients =
        dense_public_residues(setup_seed_hash, "public-common-random-polynomial", modulus);
    let public_sample_secret_product = negacyclic_product_mod(
        &component_one_coefficients,
        &collective_secret_residues,
        modulus,
    )?;
    let component_zero_coefficients = collective_scaled_error_residues
        .iter()
        .zip(public_sample_secret_product.iter())
        .map(|(scaled_error_residue, product_residue)| {
            sub_mod(*scaled_error_residue, *product_residue, modulus)
        })
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

pub(super) fn expected_evaluation_key_material_binding(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_inputs = value_at_path(setup_package, &["setupInputs"])?;
    let participants = array_at_path(setup_package, &["participants"])?;
    let participant_identities = participants
        .iter()
        .map(|participant| {
            string_at_path(participant, &["trusteeIdentity"]).map(ToString::to_string)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let key_switch_decomposition_hash =
        string_at_path(evaluation_keys, &["keySwitchDecompositionHash"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = string_at_path(evaluation_keys, &["rotSetHash"])?;

    evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: string_at_path(setup_inputs, &["setupSeedHash"])?,
        ceremony_id: string_at_path(setup_inputs, &["ceremonyId"])?,
        manifest_hash: string_at_path(setup_inputs, &["manifestHash"])?,
        roster_hash: string_at_path(setup_inputs, &["rosterHash"])?,
        participant_identities: &participant_identities,
        collective_public_key,
        key_switch_decomposition_hash,
        rot_set,
        rot_set_hash,
    })
    .map(|binding| {
        json!({
            "record": binding.record,
            "materialHash": binding.material_hash,
            "relinearizationKeyRoot": binding.relinearization_key_root,
            "relinearizationKeyRecord": binding.relinearization_key_record,
            "keySwitchKeyRoot": binding.key_switch_key_root,
            "keySwitchKeyRecord": binding.key_switch_key_record,
            "rotationKeyRoots": binding.rotation_key_roots,
            "rotationKeyRecords": binding.rotation_key_records,
        })
    })
}

fn evaluation_key_material_binding(
    input: EvaluationKeyMaterialInput<'_>,
) -> CanonicalResult<EvaluationKeyMaterialBinding> {
    let collective_public_key_root =
        string_at_path(input.collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(input.collective_public_key, &["bgvPublicKeyRoot"])?;
    let collective_public_key_coefficient_root = string_at_path(
        input.collective_public_key,
        &["collectivePublicKeyCoefficientRoot"],
    )?;
    let relinearization_levels = selected_relinearization_levels()?;
    let rotation_schedule = selected_rotation_schedule_entries()?;
    let relinearization_stream_entries = relinearization_levels
        .iter()
        .map(|level| {
            let key_stream_seed =
                evaluation_key_stream_seed(input.setup_seed_hash, "relinearization", *level, None);
            json!({
                "level": level,
                "keyStreamSeed": key_stream_seed,
                "sourcePolynomial": "secret-square",
                "digitCount": level + 1,
            })
        })
        .collect::<Vec<_>>();
    let rotation_stream_entries = rotation_schedule
        .iter()
        .map(|entry| {
            let key_stream_seed = evaluation_key_stream_seed(
                input.setup_seed_hash,
                "rotation",
                entry.level,
                Some(entry.rotation),
            );
            json!({
                "rotation": entry.rotation,
                "level": entry.level,
                "purpose": entry.purpose,
                "keyStreamSeed": key_stream_seed,
                "sourcePolynomial": "automorphism(secret)",
                "digitCount": entry.level + 1,
            })
        })
        .collect::<Vec<_>>();
    let relinearization_stream_record = json!({
        "objectType": "BgvRelinearizationKeyMaterialStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "componentOrder": ["componentZeroB", "componentOneA"],
        "gadget": "crt-idempotent-per-active-data-prime",
        "entries": relinearization_stream_entries,
    });
    let rotation_stream_record = json!({
        "objectType": "BgvRotationKeyMaterialStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "rotSetHash": input.rot_set_hash,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "componentOrder": ["componentZeroB", "componentOneA"],
        "gadget": "crt-idempotent-per-active-data-prime",
        "entries": rotation_stream_entries,
    });
    let relinearization_stream_digest = evaluation_key_stream_digest(
        "relinearization-material-stream",
        &relinearization_stream_record,
    )?;
    let rotation_stream_digest =
        evaluation_key_stream_digest("rotation-material-stream", &rotation_stream_record)?;
    let sampled_relation_checks = sampled_evaluation_key_relation_checks(
        input.setup_seed_hash,
        input.participant_identities,
        &relinearization_levels,
        &rotation_schedule,
    )?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "levelSchedule": relinearization_levels,
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?),
        "keyMaterialStreamDigest": relinearization_stream_digest,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root =
        derive_protocol_hash("RelinearizationKeyRoot", &relinearization_key_record)?;
    let mut rotation_key_roots = Vec::with_capacity(rotation_schedule.len());
    let mut rotation_key_records = Vec::with_capacity(rotation_schedule.len());
    for entry in &rotation_schedule {
        let entry_stream_record = json!({
            "objectType": "BgvRotationKeyMaterialStreamEntry",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
            "collectivePublicKeyRoot": collective_public_key_root,
            "bgvPublicKeyRoot": bgv_public_key_root,
            "rotSetHash": input.rot_set_hash,
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "keyStreamSeed": evaluation_key_stream_seed(
                    input.setup_seed_hash,
                "rotation",
                entry.level,
                Some(entry.rotation),
            ),
            "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        });
        let entry_stream_digest =
            evaluation_key_stream_digest("rotation-material-stream-entry", &entry_stream_record)?;
        let record = json!({
            "objectType": "BgvRotationKey",
            "objectVersion": 1,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "ceremonyId": input.ceremony_id,
            "rosterHash": input.roster_hash,
            "collectivePublicKeyRoot": collective_public_key_root,
            "rotSetHash": input.rot_set_hash,
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
            "publicBasisId": BgvBasisKind::Extended.basis_id(),
            "publicRlweSampleCount": entry.level + 1,
            "keyMaterialStreamDigest": entry_stream_digest,
            "maliciousEvaluationKeyProofIncluded": false,
        });
        let root = derive_protocol_hash("RotationKeyRoot", &record)?;
        rotation_key_roots.push(json!({
            "rotation": entry.rotation,
            "level": entry.level,
            "purpose": entry.purpose,
            "rotationKeyRoot": root,
        }));
        rotation_key_records.push(record);
    }
    let key_switch_stream_record = json!({
        "objectType": "BgvEvaluationKeySwitchMaterialStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "relinearizationStreamDigest": relinearization_stream_digest,
        "rotationStreamDigest": rotation_stream_digest,
        "sampledRelationChecks": sampled_relation_checks,
    });
    let key_switch_stream_digest =
        evaluation_key_stream_digest("key-switch-material-stream", &key_switch_stream_record)?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?)
            + rotation_schedule.iter().map(|entry| entry.level + 1).sum::<usize>(),
        "keyMaterialStreamDigest": key_switch_stream_digest,
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = derive_protocol_hash("KeySwitchKeyRoot", &key_switch_key_record)?;
    let record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitment",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "rotSetHash": input.rot_set_hash,
        "rotSet": input.rot_set,
        "streamPolicy": EVALUATION_KEY_STREAM_POLICY,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationStreamDigest": relinearization_stream_digest,
        "rotationKeyRoots": rotation_key_roots,
        "rotationStreamDigest": rotation_stream_digest,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchStreamDigest": key_switch_stream_digest,
        "sampledRelationChecks": sampled_relation_checks,
        "fullCoefficientStreamMaterializedInSetupPackage": false,
        "rawSecretMaterialExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let material_hash = derive_protocol_hash("EvaluationKeySetDigest", &record)?;

    Ok(EvaluationKeyMaterialBinding {
        record,
        material_hash,
        relinearization_key_root,
        relinearization_key_record,
        key_switch_key_root,
        key_switch_key_record,
        rotation_key_roots,
        rotation_key_records,
    })
}

fn selected_relinearization_levels() -> CanonicalResult<Vec<usize>> {
    if DIRECT_COMPARISON_OUTPUT_LEVEL >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct comparison output level must fit the selected data basis",
        ));
    }

    Ok((1..DATA_PRIMES.len()).collect())
}

fn selected_rotation_schedule_entries() -> CanonicalResult<Vec<RotationScheduleEntry>> {
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in aggregate_score_packing_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .insert((rotation, DATA_PRIMES.len() - 1), "aggregate-score-packing");
    }
    for shift in 1..MAXIMUM_OPTION_COUNT {
        let forward = galois_power(shift);
        entries_by_rotation_and_level
            .entry((forward, DATA_PRIMES.len() - 1))
            .or_insert("generator-ordered-packed-rank-forward");
        entries_by_rotation_and_level.insert(
            (
                inverse_galois_element(forward)?,
                DIRECT_COMPARISON_OUTPUT_LEVEL,
            ),
            "generator-ordered-packed-rank-return",
        );
    }

    Ok(entries_by_rotation_and_level
        .into_iter()
        .map(|((rotation, level), purpose)| RotationScheduleEntry {
            rotation,
            level,
            purpose,
        })
        .collect())
}

fn total_digit_count(levels: &[usize]) -> usize {
    levels.iter().map(|level| level + 1).sum()
}

pub(super) fn evaluation_key_stream_seed(
    setup_seed_hash: &str,
    key_kind: &str,
    level: usize,
    rotation: Option<usize>,
) -> String {
    let level_text = level.to_string();
    let rotation_text = rotation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string());

    hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-seed-v1",
        &[
            setup_seed_hash.as_bytes(),
            key_kind.as_bytes(),
            level_text.as_bytes(),
            rotation_text.as_bytes(),
        ],
    )
}

fn evaluation_key_stream_digest(
    stream_label: &str,
    stream_record: &Value,
) -> CanonicalResult<String> {
    let canonical_stream_record = canonical_json(stream_record)?;

    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-digest-v1",
        &[stream_label.as_bytes(), canonical_stream_record.as_bytes()],
    ))
}

fn sampled_evaluation_key_relation_checks(
    setup_seed_hash: &str,
    participant_identities: &[String],
    relinearization_levels: &[usize],
    rotation_schedule: &[RotationScheduleEntry],
) -> CanonicalResult<Vec<Value>> {
    let (collective_secret_coefficients, _) =
        collective_signed_secret_and_error_coefficients(setup_seed_hash, participant_identities);
    let mut checks = Vec::new();
    let mut sampled_relinearization_levels = BTreeSet::new();
    if let Some(first_level) = relinearization_levels.first() {
        sampled_relinearization_levels.insert(*first_level);
    }
    sampled_relinearization_levels.insert(DIRECT_COMPARISON_OUTPUT_LEVEL);
    if let Some(last_level) = relinearization_levels.last() {
        sampled_relinearization_levels.insert(*last_level);
    }
    for level in sampled_relinearization_levels {
        let seed = evaluation_key_stream_seed(setup_seed_hash, "relinearization", level, None);
        checks.push(sampled_key_switch_relation_check(
            setup_seed_hash,
            &collective_secret_coefficients,
            "relinearization",
            "secret-square",
            level,
            None,
            &seed,
        )?);
    }
    let mut sampled_rotation_indexes = BTreeSet::new();
    if !rotation_schedule.is_empty() {
        sampled_rotation_indexes.insert(0_usize);
        sampled_rotation_indexes.insert(1_usize);
        sampled_rotation_indexes.insert(rotation_schedule.len() - 2);
        sampled_rotation_indexes.insert(rotation_schedule.len() - 1);
    }
    for required_purpose in [
        "aggregate-score-packing",
        "generator-ordered-packed-rank-forward",
        "generator-ordered-packed-rank-return",
    ] {
        if let Some((rotation_index, _)) = rotation_schedule
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.purpose == required_purpose)
        {
            sampled_rotation_indexes.insert(rotation_index);
        }
    }
    for rotation_index in sampled_rotation_indexes {
        let entry = &rotation_schedule[rotation_index];
        let seed = evaluation_key_stream_seed(
            setup_seed_hash,
            "rotation",
            entry.level,
            Some(entry.rotation),
        );
        checks.push(sampled_key_switch_relation_check(
            setup_seed_hash,
            &collective_secret_coefficients,
            "rotation",
            entry.purpose,
            entry.level,
            Some(entry.rotation),
            &seed,
        )?);
    }

    Ok(checks)
}

fn sampled_key_switch_relation_check(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    key_kind: &str,
    purpose: &str,
    level: usize,
    rotation: Option<usize>,
    seed: &str,
) -> CanonicalResult<Value> {
    let source_limbs =
        key_switch_source_limbs(collective_secret_coefficients, key_kind, rotation, level)?;
    let secret_residues = DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            collective_secret_coefficients
                .iter()
                .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let domain = match rotation {
        Some(galois_element) => format!("galois-{galois_element}"),
        None => "relinearization".to_string(),
    };
    let mut digit_indexes = BTreeSet::new();
    digit_indexes.insert(0_usize);
    digit_indexes.insert(level);
    let mut limb_indexes = BTreeSet::new();
    limb_indexes.insert(0_usize);
    limb_indexes.insert(level);
    let mut samples = Vec::new();
    for digit_index in digit_indexes {
        let digit_bytes = (digit_index as u64).to_le_bytes();
        let error = DeterministicSampler::new(
            KEY_SWITCH_ERROR_DOMAIN,
            &[domain.as_bytes(), seed.as_bytes(), &digit_bytes],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        for limb_index in limb_indexes.iter().copied() {
            let modulus = DATA_PRIMES[limb_index];
            let modulus_bytes = modulus.to_le_bytes();
            let public_sample = DeterministicSampler::new(
                KEY_SWITCH_SAMPLE_DOMAIN,
                &[
                    domain.as_bytes(),
                    seed.as_bytes(),
                    &digit_bytes,
                    &modulus_bytes,
                ],
            )
            .uniform_residues(modulus, POLYNOMIAL_DEGREE);
            let public_sample_secret_product =
                negacyclic_product_mod(&public_sample, &secret_residues[limb_index], modulus)?;
            for position in sample_positions() {
                let scaled_error = signed_to_plaintext_scaled_residue(error[position], modulus)?;
                let expected = if limb_index == digit_index {
                    add_mod(
                        scaled_error,
                        source_limbs[digit_index][position] % modulus,
                        modulus,
                    )?
                } else {
                    scaled_error
                };
                let component_zero = if limb_index == digit_index {
                    add_mod(
                        sub_mod(
                            scaled_error,
                            public_sample_secret_product[position],
                            modulus,
                        )?,
                        source_limbs[digit_index][position] % modulus,
                        modulus,
                    )?
                } else {
                    sub_mod(
                        scaled_error,
                        public_sample_secret_product[position],
                        modulus,
                    )?
                };
                let decrypted_key_limb = add_mod(
                    component_zero,
                    public_sample_secret_product[position],
                    modulus,
                )?;
                samples.push(json!({
                    "digitIndex": digit_index,
                    "limbIndex": limb_index,
                    "position": position,
                    "modulus": modulus,
                    "componentZeroCoefficient": component_zero,
                    "componentOneCoefficient": public_sample[position],
                    "decryptedKeyLimbCoefficient": decrypted_key_limb,
                    "expectedKeyLimbCoefficient": expected,
                    "relationMatches": decrypted_key_limb == expected,
                }));
            }
        }
    }

    Ok(json!({
        "keyKind": key_kind,
        "purpose": purpose,
        "level": level,
        "rotation": rotation,
        "keyStreamSeed": seed,
        "setupSeedHash": setup_seed_hash,
        "samples": samples,
    }))
}

fn key_switch_source_limbs(
    collective_secret_coefficients: &[i64],
    key_kind: &str,
    rotation: Option<usize>,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let secret_residues = DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            collective_secret_coefficients
                .iter()
                .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    match key_kind {
        "relinearization" => secret_residues
            .iter()
            .enumerate()
            .map(|(limb_index, limb)| negacyclic_product_mod(limb, limb, DATA_PRIMES[limb_index]))
            .collect(),
        "rotation" => {
            let galois_element = rotation.ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "rotation key material requires a Galois element",
                )
            })?;
            let rotated_secret =
                automorphism_signed(collective_secret_coefficients, galois_element);
            Ok(DATA_PRIMES[..=level]
                .iter()
                .map(|modulus| {
                    rotated_secret
                        .iter()
                        .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                        .collect::<Vec<_>>()
                })
                .collect())
        }
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "unknown evaluation key material source kind",
        )),
    }
}

fn automorphism_signed(input: &[i64], galois_element: usize) -> Vec<i64> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % ring_order;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] += value;
        } else {
            output[exponent - POLYNOMIAL_DEGREE] -= value;
        }
    }

    output
}

pub(super) fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_hash: &str,
) -> CanonicalResult<Value> {
    let rot_set = selected_rotation_set()?;
    let rot_set_hash = derive_protocol_hash("RotSetHash", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let participant_identities = input
        .participants
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    let material_binding = evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: &input.setup_seed_hash,
        ceremony_id: &input.ceremony_id,
        manifest_hash: &input.manifest_hash,
        roster_hash: &input.roster_hash,
        participant_identities: &participant_identities,
        collective_public_key,
        key_switch_decomposition_hash,
        rot_set: &rot_set,
        rot_set_hash: &rot_set_hash,
    })?;
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
        "evaluationKeyMaterialCommitmentHash": material_binding.material_hash,
        "relinearizationKeyRoot": material_binding.relinearization_key_root,
        "rotationKeyRoots": material_binding.rotation_key_roots,
        "keySwitchKeyRoot": material_binding.key_switch_key_root,
        "generatedFor": "aggregate-score-packing-direct-encrypted-score-comparison-generator-ordered-rank-packing",
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
        "evaluationKeyMaterialCommitment": {
            "record": material_binding.record,
            "materialHash": material_binding.material_hash,
            "relinearizationKeyRoot": material_binding.relinearization_key_root,
            "relinearizationKeyRecord": material_binding.relinearization_key_record,
            "keySwitchKeyRoot": material_binding.key_switch_key_root,
            "keySwitchKeyRecord": material_binding.key_switch_key_record,
            "rotationKeyRoots": material_binding.rotation_key_roots,
            "rotationKeyRecords": material_binding.rotation_key_records,
        },
        "evaluationKeyMaterialCommitmentHash": material_binding.material_hash,
        "relinearizationKeyRoot": material_binding.relinearization_key_root,
        "keySwitchKeyRoot": material_binding.key_switch_key_root,
        "rotationKeyRoots": material_binding.rotation_key_roots,
        "evaluationKeyRoot": evaluation_key_root,
        "statusLabels": [
            "RelinearizationKeyMaterialStreamBound",
            "RotationKeyMaterialStreamBound",
            "KeySwitchMaterialStreamBound",
            "SelectedRotSetBound"
        ],
    }))
}

fn selected_rotation_set() -> CanonicalResult<Value> {
    let aggregate_score_packing_rotations =
        aggregate_score_packing_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let packed_rank_rotations = packed_rank_galois_elements(MAXIMUM_OPTION_COUNT)?
        .into_iter()
        .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
        .collect::<Vec<_>>();
    let rotations = aggregate_score_packing_rotations
        .iter()
        .chain(packed_rank_rotations.iter())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(json!({
        "rotSetId": SELECTED_ROT_SET_ID,
        "sourceRdr": "internal-design-note-top-k-circuit-and-sparse-target",
        "generatedFor": "aggregate-score-packing-direct-encrypted-score-comparison-generator-ordered-rank-packing",
        "finalizedBy": "encrypted-aggregate-evaluator-closure",
        "regeneratePassiveSetupKeysIfChanged": true,
        "rotations": rotations.clone(),
        "dependencies": [
            "encrypted-aggregate-reconstruction",
            "aggregate-score-packing",
            "direct-encrypted-score-comparison",
            "generator-ordered-packed-rank-accumulation",
            "encrypted-sparse-target-projection"
        ],
        "requiredRotationGroups": [
            {
                "purpose": "aggregate-score-packing",
                "rotations": aggregate_score_packing_rotations
            },
            {
                "purpose": "generator-ordered-packed-rank",
                "rotations": packed_rank_rotations
            }
        ],
    }))
}
