use super::development_fixtures::development_key_arithmetic_fixture;
use super::*;

pub(super) fn collective_public_key(
    input: &PassiveSetupInput,
    profile_digest: &str,
    backend_profile_digest: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
) -> CanonicalResult<Value> {
    let record_without_roots = json!({
        "objectType": "BgvCollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "profileDigest": profile_digest,
        "backendProfileDigest": backend_profile_digest,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "aggregationRule": "coefficient-wise-public-key-share-sum-with-shared-crp",
        "participantCount": public_key_share_roots.len(),
        "centralizedSecretReconstruction": false,
        "rawSecretShareExported": false,
    });
    let collective_public_key_root =
        derive_protocol_digest("CollectivePublicKeyRoot", &record_without_roots)?;
    let bgv_public_key_root = derive_protocol_digest(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "profileDigest": profile_digest,
            "backendProfileDigest": backend_profile_digest,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;

    Ok(json!({
        "record": record_without_roots,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "statusLabels": [
            "CollectivePublicKeyShareAggregationBound",
            "BgvPublicKeyRootDigestOnly",
            "BgvAlgebraicPublicKeyProofMissing",
            "NoTrustedDealerSecretReconstruction"
        ],
    }))
}

pub(super) fn threshold_verification_material(
    input: &PassiveSetupInput,
    threshold_decryption_profile_digest: &str,
    kllps_target_decryption_profile_digest: &str,
    participant_setup_record_digests: &[String],
    trustee_threshold_verification_key_digests: &[String],
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
        "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
        "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "participantSetupRecordDigests": participant_setup_record_digests,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
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
        derive_protocol_digest("ThresholdShareVerificationKeyRoot", &verification_key_set)?;
    let threshold_share_verification_key_digest = derive_protocol_digest(
        "ThresholdShareVerificationKeyDigest",
        &json!({
            "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
            "thresholdDecryptionProfileDigest": threshold_decryption_profile_digest,
            "kllpsTargetDecryptionProfileDigest": kllps_target_decryption_profile_digest,
        }),
    )?;

    Ok(json!({
        "verificationKeySet": verification_key_set,
        "thresholdShareVerificationKeyRoot": threshold_share_verification_key_root,
        "thresholdShareVerificationKeyDigest": threshold_share_verification_key_digest,
        "trusteeThresholdVerificationKeyDigests": trustee_threshold_verification_key_digests,
        "statusLabels": [
            "ThresholdVerificationMaterialBound",
            "PassiveSetupVerificationScopeOnly",
            "KllpsCompatibleVerificationRootsBound"
        ],
    }))
}

pub(super) fn evaluation_keys(
    input: &PassiveSetupInput,
    collective_public_key: &Value,
    key_switch_decomposition_digest: &str,
) -> CanonicalResult<Value> {
    let rot_set = provisional_rotation_set()?;
    let rot_set_digest = derive_protocol_digest("RotSetDigest", &rot_set)?;
    let collective_public_key_root =
        string_at_path(collective_public_key, &["collectivePublicKeyRoot"])?;
    let bgv_public_key_root = string_at_path(collective_public_key, &["bgvPublicKeyRoot"])?;
    let relinearization_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_RELINEARIZATION_ARITHMETIC_FIXTURE_ID,
        "relinearization-key-fixture",
        key_switch_decomposition_digest,
    )?;
    let key_switch_arithmetic_fixture = development_key_arithmetic_fixture(
        input,
        DEVELOPMENT_KEY_SWITCH_ARITHMETIC_FIXTURE_ID,
        "key-switch-fixture",
        key_switch_decomposition_digest,
    )?;
    let relinearization_key_record = json!({
        "objectType": "BgvRelinearizationKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 2,
        "arithmeticFixtureDigest": relinearization_arithmetic_fixture["fixtureDigest"],
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let relinearization_key_root =
        derive_protocol_digest("RelinearizationKeyRoot", &relinearization_key_record)?;
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
                "rosterDigest": input.roster_digest,
                "collectivePublicKeyRoot": collective_public_key_root,
                "rotSetDigest": rot_set_digest,
                "rotation": rotation,
                "keySwitchDecompositionDigest": key_switch_decomposition_digest,
                "publicBasisId": BgvBasisKind::Extended.basis_id(),
                "publicRlweSampleCount": 1,
                "maliciousEvaluationKeyProofIncluded": false,
            });
            let root = derive_protocol_digest("RotationKeyRoot", &record)?;
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
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "publicBasisId": BgvBasisKind::Extended.basis_id(),
        "publicRlweSampleCount": 1,
        "arithmeticFixtureDigest": key_switch_arithmetic_fixture["fixtureDigest"],
        "genericKeySwitchApiExported": false,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let key_switch_key_root = derive_protocol_digest("KeySwitchKeyRoot", &key_switch_key_record)?;
    let evaluation_key_record = json!({
        "objectType": "BgvEvaluationKeySet",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestDigest": input.manifest_digest,
        "rosterDigest": input.roster_digest,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
        "rotSetDigest": rot_set_digest,
        "relinearizationKeyRoot": relinearization_key_root,
        "relinearizationArithmeticFixtureDigest": relinearization_arithmetic_fixture["fixtureDigest"],
        "rotationKeyRoots": rotation_key_records,
        "keySwitchKeyRoot": key_switch_key_root,
        "keySwitchArithmeticFixtureDigest": key_switch_arithmetic_fixture["fixtureDigest"],
        "generatedFor": "provisionalRotSet",
        "finalRotSetClosure": "M10-AppendixD",
        "regenerateIfRotSetChanges": true,
        "maliciousEvaluationKeyProofIncluded": false,
    });
    let evaluation_key_root = derive_protocol_digest("EvalKeyRoot", &evaluation_key_record)?;

    Ok(json!({
        "record": evaluation_key_record,
        "rotSet": rot_set,
        "rotSetDigest": rot_set_digest,
        "keySwitchDecompositionDigest": key_switch_decomposition_digest,
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
        "sourceRdr": "RDR-M10-Top-K-Circuit-And-Sparse-Target",
        "generatedFor": "provisionalRotSet",
        "finalizedBy": "M10-AppendixD",
        "regenerateM8KeysIfChanged": true,
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
