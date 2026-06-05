use super::*;
use crate::bgv::evaluator::{
    key_switch::{KEY_SWITCH_ERROR_DOMAIN, KEY_SWITCH_SAMPLE_DOMAIN},
    prg::DeterministicSampler,
    records::MAXIMUM_OPTION_COUNT,
    top_k::{
        DIRECT_COMPARISON_OUTPUT_LEVEL, direct_score_packing_basis_galois_elements,
        packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
    },
};
use crate::bgv::setup::sampling::{
    bounded_collective_error_share_coefficient, bounded_collective_secret_share_coefficient,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

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
    sampled_relation_checks: Value,
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
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
        &input.private_setup_seed_hash,
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
        "publicKeyCoefficientMaterialBinding": "public-coefficients-bound-in-setup-package-with-private-share-derivation-unexported",
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
    let coefficient_tables = array_at_path(
        setup_package,
        &[
            "collectivePublicKey",
            "coefficientMaterial",
            "coefficientTables",
        ],
    )?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key coefficient table count does not match the selected data basis",
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        coefficient_tables
            .par_iter()
            .enumerate()
            .map(|(modulus_index, table)| {
                collective_public_key_coefficients_from_table(modulus_index, table)
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        coefficient_tables
            .iter()
            .enumerate()
            .map(|(modulus_index, table)| {
                collective_public_key_coefficients_from_table(modulus_index, table)
            })
            .collect()
    }
}

fn collective_public_key_coefficients_from_table(
    modulus_index: usize,
    table: &Value,
) -> CanonicalResult<CollectivePublicKeyCoefficients> {
    let modulus = unsigned_at_path(table, &["modulus"])?;
    if modulus != DATA_PRIMES[modulus_index] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient table modulus does not match the selected data basis",
        ));
    }
    let component_zero_coefficients =
        read_public_key_coefficient_vector(table, "componentZeroCoefficients")?;
    let component_one_coefficients =
        read_public_key_coefficient_vector(table, "componentOneCoefficients")?;
    compare_hash_at_path(
        table,
        &["componentZeroCoefficientHash512"],
        &coefficient_vector_hash512(&component_zero_coefficients),
        "collective public key component-zero coefficient hash",
    )?;
    compare_hash_at_path(
        table,
        &["componentOneCoefficientHash512"],
        &coefficient_vector_hash512(&component_one_coefficients),
        "collective public key component-one coefficient hash",
    )?;

    Ok(CollectivePublicKeyCoefficients {
        component_zero_coefficients,
        component_one_coefficients,
    })
}

pub(super) fn collective_public_key_coefficient_root(
    coefficient_material: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash("BGVPublicKeyRoot", coefficient_material)
}

fn collective_public_key_coefficient_material(
    setup_seed_hash: &str,
    private_setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_descriptors: Vec<Value>,
    participant_identities: &[String],
) -> CanonicalResult<Value> {
    let (collective_secret_coefficients, collective_error_coefficients) =
        collective_signed_secret_and_error_coefficients(
            private_setup_seed_hash,
            participant_identities,
        );
    #[cfg(not(target_arch = "wasm32"))]
    let coefficient_tables = DATA_PRIMES
        .par_iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficient_table(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let coefficient_tables = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficient_table(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(not(target_arch = "wasm32"))]
    let modulus_summaries = coefficient_tables
        .par_iter()
        .map(|table| {
            collective_public_key_coefficient_derivation_summary(
                setup_seed_hash,
                public_common_random_polynomial_root,
                public_key_share_roots,
                participant_identities,
                table,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let modulus_summaries = coefficient_tables
        .iter()
        .map(|table| {
            collective_public_key_coefficient_derivation_summary(
                setup_seed_hash,
                public_common_random_polynomial_root,
                public_key_share_roots,
                participant_identities,
                table,
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
        "componentDerivation": "public-coefficients-generated-from-private-setup-witness-and-bound-in-setup-package",
        "fullCoefficientVectorHashesComputed": true,
        "fullCoefficientExpansionOwner": "passive setup package public key material",
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "participantCount": participant_identities.len(),
        "participants": participant_descriptors,
        "modulusSummaries": modulus_summaries,
        "coefficientTables": coefficient_tables,
        "algebraicPublicKeyProofStatus": "BgvAlgebraicPublicKeyProofMissing",
        "rawSecretShareExported": false,
    }))
}

fn collective_public_key_coefficient_table(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    collective_error_coefficients: &[i64],
    modulus: u64,
) -> CanonicalResult<Value> {
    let coefficients = collective_public_key_coefficients_from_signed(
        setup_seed_hash,
        collective_secret_coefficients,
        collective_error_coefficients,
        modulus,
    )?;

    Ok(json!({
        "modulus": modulus,
        "componentZeroCoefficientHash512": coefficient_vector_hash512(&coefficients.component_zero_coefficients),
        "componentOneCoefficientHash512": coefficient_vector_hash512(&coefficients.component_one_coefficients),
        "componentZeroCoefficientsLeHex": coefficient_vector_le_hex(&coefficients.component_zero_coefficients),
        "componentOneCoefficientsLeHex": coefficient_vector_le_hex(&coefficients.component_one_coefficients),
        "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
    }))
}

fn collective_public_key_coefficient_derivation_summary(
    setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_identities: &[String],
    coefficient_table: &Value,
) -> CanonicalResult<Value> {
    let modulus = unsigned_at_path(coefficient_table, &["modulus"])?;
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
        "componentZeroCoefficientHash512": string_at_path(
            coefficient_table,
            &["componentZeroCoefficientHash512"],
        )?,
        "componentOneCoefficientHash512": string_at_path(
            coefficient_table,
            &["componentOneCoefficientHash512"],
        )?,
        "fullCoefficientVectorHashStatus": "bound-in-setup-package",
    }))
}

fn read_public_key_coefficient_vector(
    table: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<u64>> {
    let hex_field_name = match field_name {
        "componentZeroCoefficients" => "componentZeroCoefficientsLeHex",
        "componentOneCoefficients" => "componentOneCoefficientsLeHex",
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "unknown collective public key coefficient vector field",
            ));
        }
    };
    let bytes = crate::transcript_core::decode_hex(string_at_path(table, &[hex_field_name])?)?;
    if bytes.len() != POLYNOMIAL_DEGREE * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key coefficient vector width does not match the selected BGV profile",
        ));
    }
    let coefficients = bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect::<Vec<_>>();

    Ok(coefficients)
}

fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }

    bytes
}

fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
    crate::transcript_core::encode_hex(&coefficient_vector_bytes(coefficients))
}

fn coefficient_vector_hash512(coefficients: &[u64]) -> String {
    let bytes = coefficient_vector_bytes(coefficients);

    hash512_hex(
        "sealed-lattice-bgv-rns/public-key-coefficient-vector-v1",
        &[&bytes],
    )
}

pub(super) fn collective_signed_secret_and_error_coefficients(
    private_setup_seed_hash: &str,
    participant_identities: &[String],
) -> (Vec<i64>, Vec<i64>) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let coefficient_pairs = (0..POLYNOMIAL_DEGREE)
            .into_par_iter()
            .map(|coefficient_index| {
                collective_signed_secret_and_error_coefficient_pair(
                    private_setup_seed_hash,
                    participant_identities,
                    coefficient_index,
                )
            })
            .collect::<Vec<_>>();

        coefficient_pairs.into_iter().unzip()
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut collective_secret_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
        let mut collective_error_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
        for participant_identity in participant_identities {
            for coefficient_index in 0..POLYNOMIAL_DEGREE {
                collective_secret_coefficients[coefficient_index] +=
                    bounded_collective_secret_share_coefficient(
                        private_setup_seed_hash,
                        participant_identities,
                        participant_identity,
                        coefficient_index,
                    )
                    .expect("participant identity is drawn from the owner schedule");
                collective_error_coefficients[coefficient_index] +=
                    bounded_collective_error_share_coefficient(
                        private_setup_seed_hash,
                        participant_identities,
                        participant_identity,
                        coefficient_index,
                    )
                    .expect("participant identity is drawn from the owner schedule");
            }
        }

        (
            collective_secret_coefficients,
            collective_error_coefficients,
        )
    }
}

fn collective_signed_secret_and_error_coefficient_pair(
    private_setup_seed_hash: &str,
    participant_identities: &[String],
    coefficient_index: usize,
) -> (i64, i64) {
    let mut collective_secret_coefficient = 0_i64;
    let mut collective_error_coefficient = 0_i64;
    for participant_identity in participant_identities {
        collective_secret_coefficient += bounded_collective_secret_share_coefficient(
            private_setup_seed_hash,
            participant_identities,
            participant_identity,
            coefficient_index,
        )
        .expect("participant identity is drawn from the owner schedule");
        collective_error_coefficient += bounded_collective_error_share_coefficient(
            private_setup_seed_hash,
            participant_identities,
            participant_identity,
            coefficient_index,
        )
        .expect("participant identity is drawn from the owner schedule");
    }

    (collective_secret_coefficient, collective_error_coefficient)
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
    target_decryption_profile_hash: &str,
    target_decryption_profile_binding_hash: &str,
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
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
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
            "targetDecryptionProfileHash": target_decryption_profile_hash,
            "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
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
            "TargetDecryptionVerificationRootsBound"
        ],
    }))
}

pub(super) fn expected_evaluation_key_material_binding(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_inputs = value_at_path(setup_package, &["setupInputs"])?;
    let evaluation_keys = value_at_path(setup_package, &["evaluationKeys"])?;
    let actual_material = value_at_path(evaluation_keys, &["evaluationKeyMaterialCommitment"])?;
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let key_switch_decomposition_hash =
        string_at_path(evaluation_keys, &["keySwitchDecompositionHash"])?;
    let rot_set = value_at_path(evaluation_keys, &["rotSet"])?;
    let rot_set_hash = string_at_path(evaluation_keys, &["rotSetHash"])?;

    evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: string_at_path(setup_inputs, &["setupSeedHash"])?,
        sampled_relation_checks: value_at_path(
            actual_material,
            &["record", "sampledRelationChecks"],
        )?
        .clone(),
        ceremony_id: string_at_path(setup_inputs, &["ceremonyId"])?,
        manifest_hash: string_at_path(setup_inputs, &["manifestHash"])?,
        roster_hash: string_at_path(setup_inputs, &["rosterHash"])?,
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
        "publicBasisId": BgvBasisKind::Data.basis_id(),
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
        "publicBasisId": BgvBasisKind::Data.basis_id(),
        "componentOrder": ["componentZeroB", "componentOneA"],
        "gadget": "crt-idempotent-per-active-data-prime",
        "entries": rotation_stream_entries,
    });
    let relinearization_stream_hash = evaluation_key_stream_hash(
        "relinearization-material-stream",
        &relinearization_stream_record,
    )?;
    let rotation_stream_hash =
        evaluation_key_stream_hash("rotation-material-stream", &rotation_stream_record)?;
    let sampled_relation_checks = input.sampled_relation_checks;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Data.basis_id(),
        "levelSchedule": relinearization_levels,
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?),
        "keyMaterialStreamHash": relinearization_stream_hash,
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
        let entry_stream_hash =
            evaluation_key_stream_hash("rotation-material-stream-entry", &entry_stream_record)?;
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
            "publicBasisId": BgvBasisKind::Data.basis_id(),
            "publicRlweSampleCount": entry.level + 1,
            "keyMaterialStreamHash": entry_stream_hash,
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
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationStreamHash": rotation_stream_hash,
        "sampledRelationChecks": sampled_relation_checks,
    });
    let key_switch_stream_hash =
        evaluation_key_stream_hash("key-switch-material-stream", &key_switch_stream_record)?;
    let key_switch_key_record = json!({
        "objectType": "BgvKeySwitchKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterHash": input.roster_hash,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionHash": input.key_switch_decomposition_hash,
        "publicBasisId": BgvBasisKind::Data.basis_id(),
        "publicRlweSampleCount": total_digit_count(&selected_relinearization_levels()?)
            + rotation_schedule.iter().map(|entry| entry.level + 1).sum::<usize>(),
        "keyMaterialStreamHash": key_switch_stream_hash,
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
        "relinearizationStreamHash": relinearization_stream_hash,
        "rotationKeyRoots": rotation_key_roots,
        "rotationStreamHash": rotation_stream_hash,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchStreamHash": key_switch_stream_hash,
        "sampledRelationChecks": sampled_relation_checks,
        "fullCoefficientStreamMaterializedInSetupPackage": false,
        "rawSecretMaterialExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let material_hash = derive_protocol_hash("EvaluationKeySetHash", &record)?;

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
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, DATA_PRIMES.len() - 1),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, DATA_PRIMES.len() - 1))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, DIRECT_COMPARISON_OUTPUT_LEVEL),
            "generator-ordered-packed-rank-return-basis",
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

fn evaluation_key_stream_hash(
    stream_label: &str,
    stream_record: &Value,
) -> CanonicalResult<String> {
    let canonical_stream_record = canonical_json(stream_record)?;

    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-hash-v1",
        &[stream_label.as_bytes(), canonical_stream_record.as_bytes()],
    ))
}

fn sampled_evaluation_key_relation_checks(
    private_setup_seed_hash: &str,
    setup_seed_hash: &str,
    participant_identities: &[String],
    relinearization_levels: &[usize],
    rotation_schedule: &[RotationScheduleEntry],
) -> CanonicalResult<Vec<Value>> {
    let (collective_secret_coefficients, _) = collective_signed_secret_and_error_coefficients(
        private_setup_seed_hash,
        participant_identities,
    );
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
        "direct-score-packing-generator-basis",
        "generator-ordered-packed-rank-forward-basis",
        "generator-ordered-packed-rank-return-basis",
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
        "relinearization" => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                secret_residues
                    .par_iter()
                    .enumerate()
                    .map(|(limb_index, limb)| {
                        negacyclic_product_mod(limb, limb, DATA_PRIMES[limb_index])
                    })
                    .collect()
            }
            #[cfg(target_arch = "wasm32")]
            {
                secret_residues
                    .iter()
                    .enumerate()
                    .map(|(limb_index, limb)| {
                        negacyclic_product_mod(limb, limb, DATA_PRIMES[limb_index])
                    })
                    .collect()
            }
        }
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
    let relinearization_levels = selected_relinearization_levels()?;
    let rotation_schedule = selected_rotation_schedule_entries()?;
    let sampled_relation_checks = sampled_evaluation_key_relation_checks(
        &input.private_setup_seed_hash,
        &input.setup_seed_hash,
        &participant_identities,
        &relinearization_levels,
        &rotation_schedule,
    )?;
    let material_binding = evaluation_key_material_binding(EvaluationKeyMaterialInput {
        setup_seed_hash: &input.setup_seed_hash,
        sampled_relation_checks: Value::Array(sampled_relation_checks),
        ceremony_id: &input.ceremony_id,
        manifest_hash: &input.manifest_hash,
        roster_hash: &input.roster_hash,
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
        "generatedFor": "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing",
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
    let direct_score_packing_rotations =
        direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let packed_rank_forward_rotations =
        packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let packed_rank_return_rotations =
        packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let rotations = direct_score_packing_rotations
        .iter()
        .chain(packed_rank_forward_rotations.iter())
        .chain(packed_rank_return_rotations.iter())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(json!({
        "rotSetId": SELECTED_ROT_SET_ID,
        "generatedFor": "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing",
        "finalizedBy": "encrypted-aggregate-evaluator-closure",
        "regeneratePassiveSetupKeysIfChanged": true,
        "rotations": rotations.clone(),
        "dependencies": [
            "direct-encrypted-ballot-aggregation",
            "direct-score-packing",
            "direct-encrypted-score-comparison",
            "generator-ordered-packed-rank-accumulation",
            "encrypted-sparse-target-projection"
        ],
        "requiredRotationGroups": [
            {
                "purpose": "direct-score-packing-generator-basis",
                "rotations": direct_score_packing_rotations
            },
            {
                "purpose": "generator-ordered-packed-rank-forward-basis",
                "rotations": packed_rank_forward_rotations
            },
            {
                "purpose": "generator-ordered-packed-rank-return-basis",
                "rotations": packed_rank_return_rotations
            }
        ],
    }))
}
