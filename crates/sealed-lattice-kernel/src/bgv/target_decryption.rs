use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::{
    bgv::{
        evaluator::{
            engine::{
                Ciphertext, DevelopmentBgvKey, decryption_accumulator_to_coefficients,
                negacyclic_mul,
            },
            prg::DeterministicSampler,
            records::MAXIMUM_OPTION_COUNT,
            top_k::{TIE_POLICY, packed_score_slot},
        },
        modular_arithmetic::{add_mod, add_mod_fast, inverse_mod, mul_mod, mul_mod_fast},
        ntt::forward_negacyclic_ntt,
        profile::{BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE},
        serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object},
        setup::{
            TARGET_DECRYPTION_PROFILE_ID, development_evaluator_key_from_passive_setup_package,
            validate_passive_setup_package_for_encrypted_evaluation,
        },
        setup_helpers::{
            array_at_path, bool_at_path, hash_at_path, reject_forbidden_setup_fields,
            string_at_path, unsigned_at_path, usize_at_path, value_at_path,
        },
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_protocol_hash, hash512_hex},
    transcript_core::{decode_hex, encode_hex},
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const TARGET_SHARE_PAYLOAD_ENCODING: &str =
    "coefficient-domain-u64-little-endian-partial-decryption-limbs";
const TARGET_SHARE_EQUATION: &str =
    "PartDec_i(C_target)=c1*s_i(x_i) over each active BGV data prime";
const SELECTED_SHARE_RULE: &str = "FirstValidSharesInCanonicalBoardOrder";

#[derive(Clone)]
struct TargetShareProfile {
    decryption_threshold: usize,
    minimum_shares_for_interpolation: usize,
    decryption_share_quorum: usize,
    hash: String,
}

struct ParticipantBinding {
    trustee_identity: String,
    roster_position: usize,
    interpolation_point: u64,
    recovery_epoch: u64,
    device_epoch: u64,
    trustee_threshold_verification_key_hash: String,
}

struct ThresholdVerificationBinding {
    threshold_share_verification_key_root: String,
    threshold_share_verification_key_hash: String,
}

struct SetupBinding {
    setup_package_hash: String,
    ceremony_id: String,
    election_manifest_hash: String,
    threshold_profile_hash: String,
    target_decryption_profile_hash: String,
    target_decryption_profile_binding_hash: String,
    participants: Vec<ParticipantBinding>,
    threshold_verification: ThresholdVerificationBinding,
}

struct TargetAcceptedBinding {
    target_accepted_record_hash: String,
    target_proposal_hash: String,
    target_preimage_hash: String,
    target_finality_record_hash: String,
    target_finality_checkpoint_hash: String,
    evaluator_replay_record_hash: String,
    target_context_hash: String,
    target_ciphertext_hash: String,
    target_layout_hash: String,
    target_decryption_profile_hash: String,
    target_basis_hash: String,
}

struct TargetCiphertextPair {
    target_id: Ciphertext,
    target_order: Ciphertext,
    target_id_root: String,
    target_order_root: String,
    target_ciphertext_hash: String,
    target_ciphertext_binding_hash: String,
}

#[derive(Clone)]
struct PartialDecryptionShare {
    record: Value,
    target_id_partials: Vec<Vec<u64>>,
    target_order_partials: Vec<Vec<u64>>,
    roster_position: usize,
    interpolation_point: u64,
}

pub(crate) fn generate_bgv_target_decryption_share_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupPackage",
            "setupPrivateWitness",
            "targetAcceptedRecord",
            "targetCiphertextBinding",
            "targetCiphertexts",
            "targetShareProfile",
            "trusteeIdentity",
        ],
        "generateBgvTargetDecryptionShare",
    )?;
    reject_forbidden_setup_fields(request)?;

    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption trusteeIdentity is not part of the setup roster",
            )
        })?;
    let private_setup_seed = string_at_path(request, &["setupPrivateWitness", "setupSeed"])?;
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, private_setup_seed)?;

    generate_target_decryption_share(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        participant,
        &evaluator_key,
        private_setup_seed,
    )
}

pub(crate) fn recombine_bgv_target_decryption_shares_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupPackage",
            "targetAcceptedRecord",
            "targetCiphertextBinding",
            "targetCiphertexts",
            "targetShareProfile",
            "decryptionShares",
        ],
        "recombineBgvTargetDecryptionShares",
    )?;
    reject_forbidden_setup_fields(request)?;

    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let share_records = request
        .get("decryptionShares")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "decryptionShares must be an array",
            )
        })?;
    let shares = share_records
        .iter()
        .map(|share| {
            read_partial_decryption_share(
                share,
                &setup_binding,
                &target_accepted,
                &target_ciphertexts,
                &target_share_profile,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    recombine_target_decryption_shares(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        shares,
    )
}

fn read_setup_binding(setup_package: &Value) -> CanonicalResult<SetupBinding> {
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    if !bool_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetPartDecImplemented"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target decryption requires setup material that marks target PartDec implemented",
        ));
    }
    if bool_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetC1C4StatusAccepted"],
    )? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target decryption setup must not claim C1-C4 certification until that gate is closed",
        ));
    }
    let setup_package_hash = hash_at_path(setup_package, &["setupPackageHash"])?.to_string();
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?.to_string();
    let election_manifest_hash =
        hash_at_path(setup_package, &["setupInputs", "manifestHash"])?.to_string();
    let threshold_profile_hash =
        hash_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?.to_string();
    let target_decryption_profile_hash = hash_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetDecryptionProfileHash"],
    )?
    .to_string();
    let target_decryption_profile_binding_hash = hash_at_path(
        setup_package,
        &[
            "targetDecryptionStatus",
            "targetDecryptionProfileBindingHash",
        ],
    )?
    .to_string();
    let threshold_share_verification_key_root = hash_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "thresholdShareVerificationKeyRoot",
        ],
    )?
    .to_string();
    let threshold_share_verification_key_hash = hash_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "thresholdShareVerificationKeyHash",
        ],
    )?
    .to_string();
    let participants = array_at_path(setup_package, &["participants"])?
        .iter()
        .map(|participant| {
            let roster_position = usize_at_path(participant, &["rosterPosition"])?;
            Ok(ParticipantBinding {
                trustee_identity: string_at_path(participant, &["trusteeIdentity"])?.to_string(),
                roster_position,
                interpolation_point: u64::try_from(roster_position + 1).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target decryption interpolation point does not fit u64",
                    )
                })?,
                recovery_epoch: unsigned_at_path(participant, &["recoveryEpoch"])?,
                device_epoch: unsigned_at_path(participant, &["deviceEpoch"])?,
                trustee_threshold_verification_key_hash: hash_at_path(
                    participant,
                    &["trusteeThresholdVerificationKeyHash"],
                )?
                .to_string(),
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(SetupBinding {
        setup_package_hash,
        ceremony_id,
        election_manifest_hash,
        threshold_profile_hash,
        target_decryption_profile_hash,
        target_decryption_profile_binding_hash,
        participants,
        threshold_verification: ThresholdVerificationBinding {
            threshold_share_verification_key_root,
            threshold_share_verification_key_hash,
        },
    })
}

fn read_target_accepted_binding(
    record: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetAcceptedBinding> {
    if string_at_path(record, &["objectType"])? != "TargetAcceptedRecord"
        || unsigned_at_path(record, &["objectVersion"])? != 1
        || string_at_path(record, &["acceptanceMode"])? != "evaluator-replay"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "targetAcceptedRecord must be a canonical evaluator-replay TargetAcceptedRecord",
        ));
    }
    if string_at_path(record, &["targetDecryptionProfileId"])? != TARGET_DECRYPTION_PROFILE_ID {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target accepted record uses an unsupported target decryption profile",
        ));
    }
    compare_string_field(
        record,
        "ceremonyId",
        &setup_binding.ceremony_id,
        "target accepted ceremony",
    )?;
    compare_hash_field(
        record,
        "electionManifestHash",
        &setup_binding.election_manifest_hash,
        "target accepted manifest hash",
    )?;
    compare_hash_field(
        record,
        "targetDecryptionProfileHash",
        &setup_binding.target_decryption_profile_hash,
        "target decryption profile hash",
    )?;
    let expected_record_hash = derive_protocol_hash(
        "TargetAcceptedRecordHash",
        &json!({
            "acceptanceMode": string_at_path(record, &["acceptanceMode"])?,
            "boardPosition": unsigned_at_path(record, &["boardPosition"])?,
            "boardSequence": unsigned_at_path(record, &["boardSequence"])?,
            "ceremonyId": string_at_path(record, &["ceremonyId"])?,
            "electionManifestHash": hash_at_path(record, &["electionManifestHash"])?,
            "evaluatorReplayProfileHash": hash_at_path(record, &["evaluatorReplayProfileHash"])?,
            "evaluatorReplayRecordHash": hash_at_path(record, &["evaluatorReplayRecordHash"])?,
            "objectType": string_at_path(record, &["objectType"])?,
            "objectVersion": unsigned_at_path(record, &["objectVersion"])?,
            "organizerIdentity": string_at_path(record, &["organizerIdentity"])?,
            "targetBasisHash": hash_at_path(record, &["targetBasisHash"])?,
            "targetCiphertextHash": hash_at_path(record, &["targetCiphertextHash"])?,
            "targetContextHash": hash_at_path(record, &["targetContextHash"])?,
            "targetDecryptionProfileHash": hash_at_path(record, &["targetDecryptionProfileHash"])?,
            "targetDecryptionProfileId": string_at_path(record, &["targetDecryptionProfileId"])?,
            "targetFinalityCheckpointHash": hash_at_path(record, &["targetFinalityCheckpointHash"])?,
            "targetFinalityRecordHash": hash_at_path(record, &["targetFinalityRecordHash"])?,
            "targetFinalityScope": string_at_path(record, &["targetFinalityScope"])?,
            "targetLayoutHash": hash_at_path(record, &["targetLayoutHash"])?,
            "targetPreimageHash": hash_at_path(record, &["targetPreimageHash"])?,
            "targetProposalHash": hash_at_path(record, &["targetProposalHash"])?,
        }),
    )?;
    compare_hash_field(
        record,
        "targetAcceptedRecordHash",
        &expected_record_hash,
        "target accepted record hash",
    )?;

    Ok(TargetAcceptedBinding {
        target_accepted_record_hash: expected_record_hash,
        target_proposal_hash: hash_at_path(record, &["targetProposalHash"])?.to_string(),
        target_preimage_hash: hash_at_path(record, &["targetPreimageHash"])?.to_string(),
        target_finality_record_hash: hash_at_path(record, &["targetFinalityRecordHash"])?
            .to_string(),
        target_finality_checkpoint_hash: hash_at_path(record, &["targetFinalityCheckpointHash"])?
            .to_string(),
        evaluator_replay_record_hash: hash_at_path(record, &["evaluatorReplayRecordHash"])?
            .to_string(),
        target_context_hash: hash_at_path(record, &["targetContextHash"])?.to_string(),
        target_ciphertext_hash: hash_at_path(record, &["targetCiphertextHash"])?.to_string(),
        target_layout_hash: hash_at_path(record, &["targetLayoutHash"])?.to_string(),
        target_decryption_profile_hash: hash_at_path(record, &["targetDecryptionProfileHash"])?
            .to_string(),
        target_basis_hash: hash_at_path(record, &["targetBasisHash"])?.to_string(),
    })
}

fn read_target_share_profile(
    value: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetShareProfile> {
    if string_at_path(value, &["objectType"])? != "TargetDecryptionShareProfile"
        || unsigned_at_path(value, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "targetShareProfile must be a TargetDecryptionShareProfile version 1 object",
        ));
    }
    compare_hash_field(
        value,
        "thresholdProfileHash",
        &setup_binding.threshold_profile_hash,
        "target share threshold profile hash",
    )?;
    compare_string_field(
        value,
        "targetDecryptionProfileId",
        TARGET_DECRYPTION_PROFILE_ID,
        "target decryption profile id",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionProfileHash",
        &setup_binding.target_decryption_profile_hash,
        "target decryption profile hash",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionProfileBindingHash",
        &setup_binding.target_decryption_profile_binding_hash,
        "target decryption profile binding hash",
    )?;
    compare_string_field(
        value,
        "selectedShareRule",
        SELECTED_SHARE_RULE,
        "target decryption share-selection rule",
    )?;
    let decryption_threshold = usize_field(value, "decryptionThreshold")?;
    let minimum_shares_for_interpolation = usize_field(value, "minimumSharesForInterpolation")?;
    let decryption_share_quorum = usize_field(value, "decryptionShareQuorum")?;
    let participant_count = setup_binding.participants.len();
    if decryption_threshold == 0
        || decryption_threshold > participant_count
        || minimum_shares_for_interpolation < decryption_threshold
        || minimum_shares_for_interpolation > decryption_share_quorum
        || decryption_share_quorum > participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "targetShareProfile quorum values are inconsistent with the setup roster",
        ));
    }

    let hash_input = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "thresholdProfileHash": setup_binding.threshold_profile_hash,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": setup_binding.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "decryptionThreshold": decryption_threshold,
        "minimumSharesForInterpolation": minimum_shares_for_interpolation,
        "decryptionShareQuorum": decryption_share_quorum,
        "selectedShareRule": SELECTED_SHARE_RULE,
    });
    let hash = derive_protocol_hash("TargetDecryptionShareProfileHash", &hash_input)?;
    compare_hash_field(
        value,
        "targetShareProfileHash",
        &hash,
        "target share profile hash",
    )?;

    Ok(TargetShareProfile {
        decryption_threshold,
        minimum_shares_for_interpolation,
        decryption_share_quorum,
        hash,
    })
}

fn read_target_ciphertext_pair(
    ciphertexts: &Value,
    binding: &Value,
    target_accepted: &TargetAcceptedBinding,
) -> CanonicalResult<TargetCiphertextPair> {
    let target_id = parse_target_ciphertext(
        string_at_path(ciphertexts, &["targetIdCanonicalBytesHex"])?,
        "target id ciphertext",
    )?;
    let target_order = parse_target_ciphertext(
        string_at_path(ciphertexts, &["targetOrderCanonicalBytesHex"])?,
        "target order ciphertext",
    )?;
    if target_id.ciphertext.level != target_order.ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target id and target order ciphertexts must use the same BGV level",
        ));
    }
    compare_hash_field(
        binding,
        "targetLayoutHash",
        &target_accepted.target_layout_hash,
        "target ciphertext layout hash",
    )?;
    let aggregate_ciphertext_root = hash_at_path(binding, &["aggregateCiphertextRoot"])?;
    let top_count = usize_field(binding, "topCount")?;
    if top_count == 0 || top_count > MAXIMUM_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target ciphertext binding topCount is outside the supported option count",
        ));
    }
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        aggregate_ciphertext_root,
        top_count,
        &target_accepted.target_layout_hash,
        &target_id.root,
        &target_order.root,
    )?;
    if target_ciphertext_hash != target_accepted.target_ciphertext_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target ciphertext pair does not match the accepted target ciphertext hash",
        ));
    }
    let target_ciphertext_binding_hash = derive_protocol_hash(
        "TargetDecryptionCiphertextBindingHash",
        &json!({
            "objectType": "TargetDecryptionCiphertextBinding",
            "objectVersion": 1,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "targetLayoutHash": target_accepted.target_layout_hash,
            "targetIdRoot": target_id.root,
            "targetOrderRoot": target_order.root,
            "targetCiphertextHash": target_ciphertext_hash,
        }),
    )?;

    Ok(TargetCiphertextPair {
        target_id: target_id.ciphertext,
        target_order: target_order.ciphertext,
        target_id_root: target_id.root,
        target_order_root: target_order.root,
        target_ciphertext_hash,
        target_ciphertext_binding_hash,
    })
}

struct ParsedTargetCiphertext {
    ciphertext: Ciphertext,
    root: String,
}

fn parse_target_ciphertext(
    canonical_bytes_hex_value: &str,
    label: &str,
) -> CanonicalResult<ParsedTargetCiphertext> {
    let bytes = decode_hex(canonical_bytes_hex_value)?;
    let object = parse_bgv_object(&bytes)?;
    if object.object_kind != BgvObjectKind::Ciphertext || object.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must be a two-component BGV ciphertext"),
        ));
    }
    let level = object.components[0].level;
    let basis_id = BgvBasisKind::Data.basis_id();
    let mut components = Vec::with_capacity(2);
    for component in object.components {
        if component.level != level || component.basis_id != basis_id {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{label} components must use the same data-basis level"),
            ));
        }
        components.push(component.residues_by_modulus);
    }

    Ok(ParsedTargetCiphertext {
        ciphertext: Ciphertext {
            components,
            level,
            decrypt_scaling: 1,
        },
        root: ciphertext_root(&bytes),
    })
}

fn generate_target_decryption_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
) -> CanonicalResult<Value> {
    let level = target_ciphertexts.target_id.level;
    let secret_share = derive_threshold_secret_share_by_limb(
        evaluator_key,
        &setup_binding.setup_package_hash,
        &target_share_profile.hash,
        private_setup_seed,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        level,
    )?;
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, &secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, &secret_share)?;
    let payload = share_payload(level, &target_id_partials, &target_order_partials)?;
    let share_root = derive_protocol_hash("BgvTargetDecryptionShareRoot", &payload)?;
    let record_hash_input = share_record_hash_input(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &share_root,
    );
    let target_decryption_share_hash =
        derive_protocol_hash("BgvTargetDecryptionShareHash", &record_hash_input)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShare",
        "objectVersion": 1,
        "targetDecryptionShareHash": target_decryption_share_hash,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetProposalHash": target_accepted.target_proposal_hash,
        "targetPreimageHash": target_accepted.target_preimage_hash,
        "targetFinalityRecordHash": target_accepted.target_finality_record_hash,
        "targetFinalityCheckpointHash": target_accepted.target_finality_checkpoint_hash,
        "evaluatorReplayRecordHash": target_accepted.evaluator_replay_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareEquation": TARGET_SHARE_EQUATION,
        "shareRoot": share_root,
        "sharePayload": payload,
        "statusLabels": [
            "TargetBoundPartDecComputed",
            "AcceptedTargetContextBound",
            "ShareProofCertificationPending"
        ],
    }))
}

fn derive_threshold_secret_share_by_limb(
    evaluator_key: &DevelopmentBgvKey,
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption ciphertext level is outside the selected data basis",
        ));
    }
    let secret = evaluator_key.secret();
    if secret.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption secret width does not match the selected BGV profile",
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        DATA_PRIMES[..=level]
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        DATA_PRIMES[..=level]
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_threshold_secret_share_limb(
    secret: &[i64],
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut share = secret
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let x = interpolation_point % modulus;
    let mut x_power = x;
    let limb_index_bytes = (limb_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    for polynomial_degree in 1..minimum_shares_for_interpolation {
        let degree_bytes = (polynomial_degree as u64).to_le_bytes();
        let mut sampler = DeterministicSampler::new(
            "sealed-lattice-bgv-rns/target-decryption-shamir-polynomial-v1",
            &[
                private_setup_seed.as_bytes(),
                setup_package_hash.as_bytes(),
                target_share_profile_hash.as_bytes(),
                &limb_index_bytes,
                &modulus_bytes,
                &degree_bytes,
            ],
        );
        let coefficients = sampler.uniform_residues(modulus, POLYNOMIAL_DEGREE);
        for (share_coefficient, polynomial_coefficient) in share.iter_mut().zip(coefficients) {
            let term = mul_mod_fast(polynomial_coefficient, x_power, modulus);
            *share_coefficient = add_mod_fast(*share_coefficient, term, modulus);
        }
        x_power = mul_mod(x_power, x, modulus)?;
    }

    Ok(share)
}

fn partial_decryption_by_limb(
    ciphertext: &Ciphertext,
    secret_share_by_limb: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if ciphertext.components.len() != 2 || secret_share_by_limb.len() != ciphertext.primes().len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target PartDec requires a two-component ciphertext and one secret-share limb per active prime",
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        ciphertext
            .primes()
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        ciphertext
            .primes()
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
}

fn recombine_target_decryption_shares(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    mut shares: Vec<PartialDecryptionShare>,
) -> CanonicalResult<Value> {
    if shares.len() < target_share_profile.minimum_shares_for_interpolation {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target recombination requires at least minimumSharesForInterpolation valid shares",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    for share in &shares {
        let trustee_identity = string_at_path(&share.record, &["trusteeIdentity"])?.to_string();
        if !identities.insert(trustee_identity) || !roster_positions.insert(share.roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target recombination rejects duplicate trustee shares",
            ));
        }
    }
    shares.sort_by_key(|share| share.roster_position);
    let selected = shares
        .into_iter()
        .take(target_share_profile.minimum_shares_for_interpolation)
        .collect::<Vec<_>>();
    let selected_positions = selected
        .iter()
        .map(|share| share.roster_position)
        .collect::<Vec<_>>();
    let target_id_slots =
        recombine_ciphertext_slots(&target_ciphertexts.target_id, &selected, |share| {
            &share.target_id_partials
        })?;
    let target_order_slots =
        recombine_ciphertext_slots(&target_ciphertexts.target_order, &selected, |share| {
            &share.target_order_partials
        })?;
    let decoded_target_ids = packed_target_values(&target_id_slots);
    let decoded_target_orders = packed_target_values(&target_order_slots);
    let target_result_root = derive_protocol_hash(
        "TargetDecryptionResultHash",
        &json!({
            "objectType": "TargetDecryptionResult",
            "objectVersion": 1,
            "setupPackageHash": setup_binding.setup_package_hash,
            "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
            "targetContextHash": target_accepted.target_context_hash,
            "targetCiphertextHash": target_accepted.target_ciphertext_hash,
            "targetShareProfileHash": target_share_profile.hash,
            "selectedRosterPositions": selected_positions,
            "decodedTargetIds": decoded_target_ids,
            "decodedTargetOrders": decoded_target_orders,
        }),
    )?;

    Ok(json!({
        "ok": true,
        "operation": "recombineBgvTargetDecryptionShares",
        "targetDecryptionResultHash": target_result_root,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "shareEquation": TARGET_SHARE_EQUATION,
        "recombinationEquation": "c0 + sum(lambda_i * PartDec_i(C_target)) over every active BGV data prime",
        "selectedShareRule": SELECTED_SHARE_RULE,
        "minimumSharesForInterpolation": target_share_profile.minimum_shares_for_interpolation,
        "decryptionThreshold": target_share_profile.decryption_threshold,
        "decryptionShareQuorum": target_share_profile.decryption_share_quorum,
        "selectedRosterPositions": selected_positions,
        "decodedTargetIds": decoded_target_ids,
        "decodedTargetOrders": decoded_target_orders,
        "decryptScaling": 1,
        "statusLabels": [
            "TargetBoundRecombinationComputed",
            "AcceptedTargetContextBound",
            "ShareProofCertificationPending"
        ],
    }))
}

fn recombine_ciphertext_slots<F>(
    ciphertext: &Ciphertext,
    shares: &[PartialDecryptionShare],
    partials: F,
) -> CanonicalResult<Vec<u64>>
where
    F: Fn(&PartialDecryptionShare) -> &[Vec<u64>],
{
    let mut accumulator = ciphertext.components[0].clone();
    for (limb_index, modulus) in ciphertext.primes().iter().enumerate() {
        let coefficients = lagrange_coefficients_at_zero_mod(shares, *modulus)?;
        for (share, lagrange_coefficient) in shares.iter().zip(coefficients) {
            let share_partials = partials(share);
            if share_partials.len() != ciphertext.primes().len()
                || share_partials[limb_index].len() != POLYNOMIAL_DEGREE
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target decryption share payload shape does not match the ciphertext level",
                ));
            }
            for coefficient_index in 0..POLYNOMIAL_DEGREE {
                let weighted = mul_mod(
                    share_partials[limb_index][coefficient_index],
                    lagrange_coefficient,
                    *modulus,
                )?;
                accumulator[limb_index][coefficient_index] = add_mod(
                    accumulator[limb_index][coefficient_index],
                    weighted,
                    *modulus,
                )?;
            }
        }
    }
    let coefficients = decryption_accumulator_to_coefficients(ciphertext, &accumulator)?;

    forward_negacyclic_ntt(&coefficients, crate::bgv::profile::PLAINTEXT_MODULUS)
}

fn lagrange_coefficients_at_zero_mod(
    shares: &[PartialDecryptionShare],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut coefficients = Vec::with_capacity(shares.len());
    for (share_index, share) in shares.iter().enumerate() {
        let x_i = share.interpolation_point % modulus;
        if x_i == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption interpolation point must be non-zero modulo the data prime",
            ));
        }
        let mut numerator = 1_u64;
        let mut denominator = 1_u64;
        for (other_index, other_share) in shares.iter().enumerate() {
            if other_index == share_index {
                continue;
            }
            let x_j = other_share.interpolation_point % modulus;
            if x_j == 0 || x_i == x_j {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target decryption interpolation points must be non-zero and distinct",
                ));
            }
            numerator = mul_mod(numerator, modulus - x_j, modulus)?;
            let difference = if x_i >= x_j {
                x_i - x_j
            } else {
                modulus - (x_j - x_i)
            };
            denominator = mul_mod(denominator, difference, modulus)?;
        }
        coefficients.push(mul_mod(
            numerator,
            inverse_mod(denominator, modulus)?,
            modulus,
        )?);
    }

    Ok(coefficients)
}

fn read_partial_decryption_share(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<PartialDecryptionShare> {
    if string_at_path(share, &["objectType"])? != "BgvTargetDecryptionShare"
        || unsigned_at_path(share, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target recombination accepts only BgvTargetDecryptionShare records",
        ));
    }
    let trustee_identity = string_at_path(share, &["trusteeIdentity"])?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption share trustee is not in the setup roster",
            )
        })?;
    compare_share_record_fields(
        share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
    )?;
    let payload = value_at_path(share, &["sharePayload"])?;
    let share_root = derive_protocol_hash("BgvTargetDecryptionShareRoot", payload)?;
    compare_hash_field(share, "shareRoot", &share_root, "target share root")?;
    let expected_hash = derive_protocol_hash(
        "BgvTargetDecryptionShareHash",
        &share_record_hash_input(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            &share_root,
        ),
    )?;
    compare_hash_field(
        share,
        "targetDecryptionShareHash",
        &expected_hash,
        "target decryption share hash",
    )?;

    Ok(PartialDecryptionShare {
        record: share.clone(),
        target_id_partials: read_partial_limb_set(
            payload,
            "targetId",
            target_ciphertexts.target_id.level,
        )?,
        target_order_partials: read_partial_limb_set(
            payload,
            "targetOrder",
            target_ciphertexts.target_order.level,
        )?,
        roster_position: participant.roster_position,
        interpolation_point: participant.interpolation_point,
    })
}

fn compare_share_record_fields(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
) -> CanonicalResult<()> {
    compare_hash_field(
        share,
        "setupPackageHash",
        &setup_binding.setup_package_hash,
        "target share setup package hash",
    )?;
    compare_string_field(
        share,
        "ceremonyId",
        &setup_binding.ceremony_id,
        "target share ceremony",
    )?;
    compare_hash_field(
        share,
        "electionManifestHash",
        &setup_binding.election_manifest_hash,
        "target share manifest hash",
    )?;
    compare_string_field(
        share,
        "trusteeIdentity",
        &participant.trustee_identity,
        "target share trustee identity",
    )?;
    compare_unsigned_field(
        share,
        "rosterPosition",
        participant.roster_position as u64,
        "target share roster position",
    )?;
    compare_unsigned_field(
        share,
        "interpolationPoint",
        participant.interpolation_point,
        "target share interpolation point",
    )?;
    compare_unsigned_field(
        share,
        "recoveryEpoch",
        participant.recovery_epoch,
        "target share recovery epoch",
    )?;
    compare_unsigned_field(
        share,
        "deviceEpoch",
        participant.device_epoch,
        "target share device epoch",
    )?;
    for (field_name, expected) in [
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
        ),
        (
            "targetProposalHash",
            target_accepted.target_proposal_hash.as_str(),
        ),
        (
            "targetPreimageHash",
            target_accepted.target_preimage_hash.as_str(),
        ),
        (
            "targetFinalityRecordHash",
            target_accepted.target_finality_record_hash.as_str(),
        ),
        (
            "targetFinalityCheckpointHash",
            target_accepted.target_finality_checkpoint_hash.as_str(),
        ),
        (
            "evaluatorReplayRecordHash",
            target_accepted.evaluator_replay_record_hash.as_str(),
        ),
        (
            "targetContextHash",
            target_accepted.target_context_hash.as_str(),
        ),
        (
            "targetCiphertextHash",
            target_accepted.target_ciphertext_hash.as_str(),
        ),
        (
            "targetDecryptionCiphertextHash",
            target_ciphertexts.target_ciphertext_hash.as_str(),
        ),
        (
            "targetCiphertextBindingHash",
            target_ciphertexts.target_ciphertext_binding_hash.as_str(),
        ),
        ("targetIdRoot", target_ciphertexts.target_id_root.as_str()),
        (
            "targetOrderRoot",
            target_ciphertexts.target_order_root.as_str(),
        ),
        (
            "targetDecryptionProfileHash",
            target_accepted.target_decryption_profile_hash.as_str(),
        ),
        (
            "targetDecryptionProfileBindingHash",
            setup_binding
                .target_decryption_profile_binding_hash
                .as_str(),
        ),
        ("targetShareProfileHash", target_share_profile.hash.as_str()),
        (
            "targetBasisHash",
            target_accepted.target_basis_hash.as_str(),
        ),
        (
            "thresholdShareVerificationKeyRoot",
            setup_binding
                .threshold_verification
                .threshold_share_verification_key_root
                .as_str(),
        ),
        (
            "thresholdShareVerificationKeyHash",
            setup_binding
                .threshold_verification
                .threshold_share_verification_key_hash
                .as_str(),
        ),
        (
            "trusteeThresholdVerificationKeyHash",
            participant.trustee_threshold_verification_key_hash.as_str(),
        ),
    ] {
        compare_hash_field(share, field_name, expected, field_name)?;
    }
    compare_string_field(
        share,
        "shareEquation",
        TARGET_SHARE_EQUATION,
        "target share equation",
    )
}

fn share_payload(
    level: usize,
    target_id_partials: &[Vec<u64>],
    target_order_partials: &[Vec<u64>],
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvTargetDecryptionSharePayload",
        "objectVersion": 1,
        "encoding": TARGET_SHARE_PAYLOAD_ENCODING,
        "level": level,
        "targetId": partial_limb_records(target_id_partials)?,
        "targetOrder": partial_limb_records(target_order_partials)?,
    }))
}

fn partial_limb_records(partials: &[Vec<u64>]) -> CanonicalResult<Vec<Value>> {
    partials
        .iter()
        .enumerate()
        .map(|(limb_index, coefficients)| {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target partial-decryption limb has the wrong coefficient count",
                ));
            }
            let encoded = coefficient_vector_le_hex(coefficients);
            Ok(json!({
                "limbIndex": limb_index,
                "modulus": DATA_PRIMES[limb_index],
                "partialDecryptionLeHex": encoded,
                "partialDecryptionHash512": hash512_hex(
                    "sealed-lattice-bgv-rns/target-partial-decryption-limb-v1",
                    &[&coefficient_vector_bytes(coefficients)]
                ),
            }))
        })
        .collect()
}

fn read_partial_limb_set(
    payload: &Value,
    role: &str,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if string_at_path(payload, &["objectType"])? != "BgvTargetDecryptionSharePayload"
        || unsigned_at_path(payload, &["objectVersion"])? != 1
        || string_at_path(payload, &["encoding"])? != TARGET_SHARE_PAYLOAD_ENCODING
        || usize_at_path(payload, &["level"])? != level
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target share payload header is not canonical for the target ciphertext level",
        ));
    }
    let records = array_at_path(payload, &[role])?;
    if records.len() != level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target share payload must include one partial-decryption limb per active prime",
        ));
    }
    records
        .iter()
        .enumerate()
        .map(|(limb_index, record)| {
            if usize_at_path(record, &["limbIndex"])? != limb_index
                || unsigned_at_path(record, &["modulus"])? != DATA_PRIMES[limb_index]
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target share payload limb order or modulus does not match the selected BGV basis",
                ));
            }
            let coefficients =
                coefficient_vector_from_le_hex(string_at_path(record, &["partialDecryptionLeHex"])?)?;
            let expected_hash = hash512_hex(
                "sealed-lattice-bgv-rns/target-partial-decryption-limb-v1",
                &[&coefficient_vector_bytes(&coefficients)],
            );
            compare_hash_field(
                record,
                "partialDecryptionHash512",
                &expected_hash,
                "target partial-decryption limb hash",
            )?;
            let modulus = DATA_PRIMES[limb_index];
            if coefficients.iter().any(|coefficient| *coefficient >= modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "target partial-decryption limb contains a non-canonical residue",
                ));
            }

            Ok(coefficients)
        })
        .collect()
}

fn share_record_hash_input(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    share_root: &str,
) -> Value {
    json!({
        "objectType": "BgvTargetDecryptionShare",
        "objectVersion": 1,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetProposalHash": target_accepted.target_proposal_hash,
        "targetPreimageHash": target_accepted.target_preimage_hash,
        "targetFinalityRecordHash": target_accepted.target_finality_record_hash,
        "targetFinalityCheckpointHash": target_accepted.target_finality_checkpoint_hash,
        "evaluatorReplayRecordHash": target_accepted.evaluator_replay_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareEquation": TARGET_SHARE_EQUATION,
        "shareRoot": share_root,
    })
}

fn direct_target_ciphertext_hash(
    aggregate_ciphertext_root: &str,
    top_count: usize,
    target_layout_hash: &str,
    target_id_root: &str,
    target_order_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedSparseTargetProjectionHash",
        &json!({
            "objectType": "EncryptedSparseTargetCiphertext",
            "objectVersion": 1,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "tiePolicy": TIE_POLICY,
            "targetLayoutHash": target_layout_hash,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "openedIntermediates": [],
        }),
    )
}

fn packed_target_values(slots: &[u64]) -> Vec<u64> {
    (0..MAXIMUM_OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}

fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes
}

fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
    encode_hex(&coefficient_vector_bytes(coefficients))
}

fn coefficient_vector_from_le_hex(value: &str) -> CanonicalResult<Vec<u64>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != POLYNOMIAL_DEGREE * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target partial-decryption coefficient vector byte length does not match the selected BGV profile",
        ));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect())
}

fn signed_residue(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative small value fits u64") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

fn required_string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.trim().is_empty())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-empty string"),
            )
        })
}

fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let unsigned = value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })?;
    usize::try_from(unsigned).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} does not fit usize"),
        )
    })
}

fn compare_hash_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = hash_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

fn compare_string_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

fn compare_unsigned_field(
    value: &Value,
    field_name: &str,
    expected: u64,
    description: &str,
) -> CanonicalResult<()> {
    let actual = unsigned_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        evaluator::engine::encode_slots_to_coefficients,
        evaluator::records::target_layout_hash,
        profile::{direct_comparison_profile_hash, profile_hash},
        setup::generate_passive_setup_package_from_request,
    };

    fn setup_request() -> Value {
        json!({
            "ceremonyId": "target-decryption-ceremony",
            "manifestHash": derive_protocol_hash(
                "ElectionManifestHash",
                &json!({ "manifest": "target-decryption-test" }),
            ).expect("manifest hash"),
            "rosterHash": derive_protocol_hash(
                "RosterHash",
                &json!({ "roster": "target-decryption-test" }),
            ).expect("roster hash"),
            "thresholdProfileHash": derive_protocol_hash(
                "ThresholdProfileHash",
                &json!({ "threshold": "target-decryption-test" }),
            ).expect("threshold hash"),
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
            ],
            "setupSeed": "target-decryption-setup-seed",
        })
    }

    fn setup_package() -> Value {
        generate_passive_setup_package_from_request(&setup_request()).expect("setup package")
    }

    fn target_share_profile(setup_package: &Value) -> Value {
        let profile = json!({
            "objectType": "TargetDecryptionShareProfile",
            "objectVersion": 1,
            "thresholdProfileHash": setup_package["setupInputs"]["thresholdProfileHash"],
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
            "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
            "targetDecryptionProfileBindingHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileBindingHash"],
            "decryptionThreshold": 2,
            "minimumSharesForInterpolation": 2,
            "decryptionShareQuorum": 2,
            "selectedShareRule": SELECTED_SHARE_RULE,
        });
        let mut with_hash = profile;
        with_hash["targetShareProfileHash"] = json!(
            derive_protocol_hash("TargetDecryptionShareProfileHash", &with_hash)
                .expect("target share profile hash")
        );
        with_hash
    }

    fn level_zero_ciphertext(key: &DevelopmentBgvKey, slots: &[u64], seed: &str) -> Ciphertext {
        let coefficients = encode_slots_to_coefficients(slots).expect("encode slots");
        let full = key
            .encrypt_coefficients(&coefficients, seed)
            .expect("encrypt coefficients");
        Ciphertext {
            components: vec![
                vec![full.components[0][0].clone()],
                vec![full.components[1][0].clone()],
            ],
            level: 0,
            decrypt_scaling: 1,
        }
    }

    fn sparse_target_slots(ids: &[u64], orders: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let mut target_ids = vec![0_u64; POLYNOMIAL_DEGREE];
        let mut target_orders = vec![0_u64; POLYNOMIAL_DEGREE];
        for option in 0..MAXIMUM_OPTION_COUNT {
            target_ids[packed_score_slot(option)] = ids[option];
            target_orders[packed_score_slot(option)] = orders[option];
        }
        (target_ids, target_orders)
    }

    fn accepted_record(
        setup_package: &Value,
        target_ciphertext_hash: &str,
        target_layout_hash: &str,
    ) -> Value {
        let mut record = json!({
            "objectType": "TargetAcceptedRecord",
            "objectVersion": 1,
            "ceremonyId": setup_package["setupInputs"]["ceremonyId"],
            "electionManifestHash": setup_package["setupInputs"]["manifestHash"],
            "targetFinalityScope": "target-decryption-test-finality",
            "targetProposalHash": derive_protocol_hash(
                "TargetProposalHash",
                &json!({ "target": "accepted" }),
            ).expect("proposal hash"),
            "evaluatorReplayRecordHash": derive_protocol_hash(
                "EvaluatorReplayRecordHash",
                &json!({ "replay": "accepted" }),
            ).expect("replay hash"),
            "targetContextHash": derive_protocol_hash(
                "TargetContextHash",
                &json!({ "context": "accepted target" }),
            ).expect("context hash"),
            "targetFinalityRecordHash": derive_protocol_hash(
                "TargetFinalityRecordHash",
                &json!({ "finality": "record" }),
            ).expect("record hash"),
            "targetFinalityCheckpointHash": derive_protocol_hash(
                "TargetFinalityCheckpointHash",
                &json!({ "finality": "checkpoint" }),
            ).expect("checkpoint hash"),
            "evaluatorReplayProfileHash": direct_comparison_profile_hash()
                .expect("direct comparison profile hash"),
            "targetPreimageHash": derive_protocol_hash(
                "TargetPreimageHash",
                &json!({ "preimage": "accepted" }),
            ).expect("preimage hash"),
            "targetCiphertextHash": target_ciphertext_hash,
            "targetLayoutHash": target_layout_hash,
            "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
            "targetBasisHash": derive_protocol_hash(
                "TargetBasisHash",
                &json!({ "basis": "test" }),
            ).expect("target basis hash"),
            "acceptanceMode": "evaluator-replay",
            "boardSequence": 0,
            "boardPosition": 0,
            "organizerIdentity": "organizer",
        });
        record["targetAcceptedRecordHash"] = json!(
            derive_protocol_hash("TargetAcceptedRecordHash", &record)
                .expect("target accepted record hash")
        );
        record
    }

    fn target_fixture() -> (Value, Value, Value, Value) {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            "target-decryption-setup-seed",
        )
        .expect("evaluator key");
        let mut ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
        let mut orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
        ids[0] = 1;
        ids[2] = 3;
        orders[0] = 1;
        orders[2] = 2;
        let (target_id_slots, target_order_slots) = sparse_target_slots(&ids, &orders);
        let target_id = level_zero_ciphertext(&evaluator_key, &target_id_slots, "target-id");
        let target_order =
            level_zero_ciphertext(&evaluator_key, &target_order_slots, "target-order");
        let target_id_root = crate::bgv::evaluator::engine::ciphertext_object_root(&target_id)
            .expect("target id root");
        let target_order_root =
            crate::bgv::evaluator::engine::ciphertext_object_root(&target_order)
                .expect("target order root");
        let aggregate_ciphertext_root = "a".repeat(128);
        let target_layout_hash = target_layout_hash(MAXIMUM_OPTION_COUNT).expect("layout hash");
        let target_ciphertext_hash = direct_target_ciphertext_hash(
            &aggregate_ciphertext_root,
            2,
            &target_layout_hash,
            &target_id_root,
            &target_order_root,
        )
        .expect("target ciphertext hash");
        let accepted_record =
            accepted_record(&setup_package, &target_ciphertext_hash, &target_layout_hash);
        let target_ciphertext_binding = json!({
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": 2,
            "targetLayoutHash": target_layout_hash,
        });
        let target_ciphertexts = json!({
            "targetIdCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_id)
                .expect("target id hex"),
            "targetOrderCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_order)
                .expect("target order hex"),
        });

        (
            setup_package,
            accepted_record,
            target_ciphertext_binding,
            target_ciphertexts,
        )
    }

    fn generate_share(
        setup_package: &Value,
        accepted_record: &Value,
        target_ciphertext_binding: &Value,
        target_ciphertexts: &Value,
        target_share_profile: &Value,
        trustee_identity: &str,
    ) -> Value {
        generate_bgv_target_decryption_share_from_request(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": "target-decryption-setup-seed",
            },
            "targetAcceptedRecord": accepted_record,
            "targetCiphertextBinding": target_ciphertext_binding,
            "targetCiphertexts": target_ciphertexts,
            "targetShareProfile": target_share_profile,
            "trusteeIdentity": trustee_identity,
        }))
        .expect("generate share")
    }

    #[test]
    fn target_partdec_recombines_selected_sparse_target() {
        let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
            target_fixture();
        let target_share_profile = target_share_profile(&setup_package);
        let first_share = generate_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile,
            "trustee-1",
        );
        let third_share = generate_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile,
            "trustee-3",
        );

        let recombined = recombine_bgv_target_decryption_shares_from_request(&json!({
            "setupPackage": setup_package,
            "targetAcceptedRecord": accepted_record,
            "targetCiphertextBinding": target_ciphertext_binding,
            "targetCiphertexts": target_ciphertexts,
            "targetShareProfile": target_share_profile,
            "decryptionShares": [third_share, first_share],
        }))
        .expect("recombine target");

        let decoded_ids = recombined["decodedTargetIds"]
            .as_array()
            .expect("target ids")
            .iter()
            .map(|value| value.as_u64().expect("id"))
            .collect::<Vec<_>>();
        let decoded_orders = recombined["decodedTargetOrders"]
            .as_array()
            .expect("target orders")
            .iter()
            .map(|value| value.as_u64().expect("order"))
            .collect::<Vec<_>>();

        assert_eq!(decoded_ids[0], 1);
        assert_eq!(decoded_ids[1], 0);
        assert_eq!(decoded_ids[2], 3);
        assert_eq!(decoded_orders[0], 1);
        assert_eq!(decoded_orders[1], 0);
        assert_eq!(decoded_orders[2], 2);
        assert_eq!(recombined["decryptScaling"], json!(1));
        assert_eq!(profile_hash().expect("profile hash").len(), 128);
    }

    #[test]
    fn target_recombination_rejects_wrong_target_and_duplicate_trustee() {
        let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
            target_fixture();
        let target_share_profile = target_share_profile(&setup_package);
        let first_share = generate_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile,
            "trustee-1",
        );
        let mut wrong_record = accepted_record.clone();
        wrong_record["targetCiphertextHash"] = json!("0".repeat(128));

        assert!(
            generate_bgv_target_decryption_share_from_request(&json!({
                "setupPackage": setup_package,
                "setupPrivateWitness": {
                    "setupSeed": "target-decryption-setup-seed",
                },
                "targetAcceptedRecord": wrong_record,
                "targetCiphertextBinding": target_ciphertext_binding,
                "targetCiphertexts": target_ciphertexts,
                "targetShareProfile": target_share_profile,
                "trusteeIdentity": "trustee-2",
            }))
            .is_err()
        );

        assert!(
            recombine_bgv_target_decryption_shares_from_request(&json!({
                "setupPackage": setup_package,
                "targetAcceptedRecord": accepted_record,
                "targetCiphertextBinding": target_ciphertext_binding,
                "targetCiphertexts": target_ciphertexts,
                "targetShareProfile": target_share_profile,
                "decryptionShares": [first_share.clone(), first_share],
            }))
            .is_err()
        );
    }
}
