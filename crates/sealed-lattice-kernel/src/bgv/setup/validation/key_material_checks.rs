use super::*;
use crate::bgv::setup::key_material::collective_public_key_coefficient_root;
use crate::hashing::derive_canonical_object_hash;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

pub(super) fn validate_collective_public_key(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    bgv_parameters_hash: &str,
) -> CanonicalResult<()> {
    let collective_public_key = value_at_path(setup_package, &["collectivePublicKey"])?;
    let collective_public_key_record = value_at_path(collective_public_key, &["record"])?;
    compare_string_at_path(
        collective_public_key_record,
        &["objectType"],
        "BgvCollectivePublicKey",
        "collective public key object type",
    )?;
    compare_hash_at_path(
        collective_public_key_record,
        &["bgvParametersHash"],
        bgv_parameters_hash,
        "collective public key BGV parameters hash",
    )?;
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(collective_public_key_record, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key share roots do not match participant records",
        ));
    }
    let coefficient_material = value_at_path(collective_public_key, &["coefficientMaterial"])?;
    validate_collective_public_key_coefficient_material(
        coefficient_material,
        collective_public_key_record,
        participant_bindings,
    )?;
    let expected_coefficient_root = collective_public_key_coefficient_root(coefficient_material)?;
    compare_hash_at_path(
        collective_public_key,
        &["collectivePublicKeyCoefficientRoot"],
        &expected_coefficient_root,
        "collective public key coefficient root",
    )?;
    compare_hash_at_path(
        collective_public_key_record,
        &["collectivePublicKeyCoefficientRoot"],
        &expected_coefficient_root,
        "collective public key record coefficient root",
    )?;

    let collective_public_key_root =
        hash_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    compare_derived_hash(
        collective_public_key_record,
        collective_public_key_root,
        "collective public key root",
    )?;
    let expected_bgv_public_key_root = derive_canonical_object_hash(&json!({
        "objectType": "BgvPublicKeyRoot",
        "collectivePublicKeyRoot": collective_public_key_root,
        "collectivePublicKeyCoefficientRoot": expected_coefficient_root,
        "bgvParametersHash": bgv_parameters_hash,
    }))?;
    compare_hash_at_path(
        collective_public_key,
        &["bgvPublicKeyRoot"],
        &expected_bgv_public_key_root,
        "BGV public key root",
    )
}

fn validate_collective_public_key_coefficient_material(
    coefficient_material: &Value,
    collective_public_key_record: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
) -> CanonicalResult<()> {
    compare_string_at_path(
        coefficient_material,
        &["objectType"],
        "BgvCollectivePublicKeyCoefficientMaterial",
        "collective public key coefficient material object type",
    )?;
    let expected_public_key_share_roots = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.public_key_share_root.clone()))
        .collect::<Vec<_>>();
    if array_at_path(coefficient_material, &["publicKeyShareRoots"])?
        != &expected_public_key_share_roots
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key coefficient material share roots do not match participant records",
        ));
    }
    compare_hash_at_path(
        coefficient_material,
        &["publicCommonRandomPolynomialRoot"],
        string_at_path(
            collective_public_key_record,
            &["publicCommonRandomPolynomialRoot"],
        )?,
        "collective public key coefficient material CRP root",
    )?;
    let expected_participants = participant_bindings
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
    if array_at_path(coefficient_material, &["participants"])? != &expected_participants {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key coefficient material participants do not match participant records",
        ));
    }

    let coefficient_tables = array_at_path(coefficient_material, &["coefficientTables"])?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key coefficient material must include one table per data prime",
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        DATA_PRIMES
            .par_iter()
            .enumerate()
            .try_for_each(|(modulus_index, modulus)| {
                validate_coefficient_table(&coefficient_tables[modulus_index], *modulus)
            })?;
    }
    #[cfg(target_arch = "wasm32")]
    {
        for (modulus_index, modulus) in DATA_PRIMES.iter().enumerate() {
            validate_coefficient_table(&coefficient_tables[modulus_index], *modulus)?;
        }
    }

    Ok(())
}

fn validate_coefficient_table(table: &Value, expected_modulus: u64) -> CanonicalResult<()> {
    if unsigned_at_path(table, &["modulus"])? != expected_modulus {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "collective public key coefficient table shape does not match the selected data basis",
        ));
    }
    for (hex_field_name, hash_field_name) in [
        (
            "componentZeroCoefficientsLeHex",
            "componentZeroCoefficientHash512",
        ),
        (
            "componentOneCoefficientsLeHex",
            "componentOneCoefficientHash512",
        ),
    ] {
        let bytes = crate::transcript_core::decode_hex(string_at_path(table, &[hex_field_name])?)?;
        if bytes.len() != POLYNOMIAL_DEGREE * 8 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public key coefficient table byte length is invalid",
            ));
        }
        let expected_hash = hash512_hex(
            "sealed-lattice-bgv-rns/public-key-coefficient-vector",
            &[&bytes],
        );
        compare_hash_at_path(
            table,
            &[hash_field_name],
            &expected_hash,
            "collective public key coefficient table hash",
        )?;
    }

    Ok(())
}

pub(super) fn validate_threshold_verification_material(
    setup_package: &Value,
    participant_bindings: &[VerifiedParticipantSetupBinding],
    target_decryption_parameters_hash: &str,
) -> CanonicalResult<()> {
    let threshold_material = value_at_path(setup_package, &["thresholdVerificationMaterial"])?;
    let verification_key_set = value_at_path(threshold_material, &["verificationKeySet"])?;
    compare_hash_at_path(
        verification_key_set,
        &["targetDecryptionParametersHash"],
        target_decryption_parameters_hash,
        "threshold verification target decryption parameters hash",
    )?;
    let expected_participant_setup_record_hashes = participant_bindings
        .iter()
        .map(|participant| Value::String(participant.participant_setup_record_hash.clone()))
        .collect::<Vec<_>>();
    let expected_trustee_threshold_verification_key_hashes = participant_bindings
        .iter()
        .map(|participant| {
            Value::String(participant.trustee_threshold_verification_key_hash.clone())
        })
        .collect::<Vec<_>>();
    if array_at_path(verification_key_set, &["participantSetupRecordHashes"])?
        != &expected_participant_setup_record_hashes
        || array_at_path(
            verification_key_set,
            &["trusteeThresholdVerificationKeyHashes"],
        )? != &expected_trustee_threshold_verification_key_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
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
            CanonicalErrorCode::ComponentMismatch,
            "threshold interpolation universe does not match participant setup records",
        ));
    }

    let threshold_share_verification_key_root =
        hash_at_path(threshold_material, &["thresholdShareVerificationKeyRoot"])?;
    compare_derived_hash(
        verification_key_set,
        threshold_share_verification_key_root,
        "threshold share verification key root",
    )
}
