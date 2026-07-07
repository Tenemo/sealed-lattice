mod common_randomness;
mod evaluation_key_material_transport;
mod evaluation_key_proof_checks;
mod evaluation_key_share_rounds;
mod evaluator_key_schedule;
mod nested_hash;
mod phase_transcript;
mod private_vss_envelopes;
mod public_key_share_material;
mod public_key_shares;
mod same_secret_bridge_verification;
mod same_secret_consistency;
mod setup_context;
mod threshold_share_commitment_checks;
mod transport_policy;
mod vss_coefficient_commitments;
mod vss_complaints_and_acceptances;
mod vss_public_material_verification;

pub(super) use self::transport_policy::{
    verify_full_ring_material, verify_terminal_setup_transport_policy,
};

#[cfg(test)]
pub(in crate::bgv::setup) use self::common_randomness::derive_collective_bgv_setup_public_derivations as derive_collective_bgv_setup_public_derivations_for_roster;
use self::common_randomness::{
    derive_bgv_public_a_polynomial, derive_collective_bgv_setup_public_derivations,
    verify_common_randomness,
};
use self::same_secret_bridge_verification::{
    SameSecretBridgeVerification, verify_optional_same_secret_bridge_statement_set,
};
// Re-exported for terminal proof fixtures, which build public-key-share and
// trustee evaluation-key statements against the verified same-secret bridge
// material that the accepted-setup verifier reconstructs.
use self::evaluation_key_material_transport::{
    evaluation_key_material_refusal,
    transported_evaluation_key_share_component_material_from_request,
    verify_public_evaluation_key_set, verify_required_public_evaluation_key_set,
};
use self::evaluation_key_proof_checks::verify_trustee_evaluation_key_proofs;
#[cfg(test)]
pub(in crate::bgv::setup) use self::evaluation_key_proof_checks::{
    TrusteeEvaluationKeyStatementInputs, accepted_key_switch_decomposition_hash,
    trustee_evaluation_key_statement_from_package,
};
use self::evaluation_key_share_rounds::{
    EvaluationKeyProofCommonBinding, evaluation_key_proof_common_binding,
    expected_galois_key_switch_seed, expected_relinearization_key_switch_seed,
    galois_key_share_material_for_schedule, relinearization_aggregate_roots_by_level,
    scheduled_relinearization_levels, verify_galois_key_share_batches,
    verify_galois_key_switch_sample_binding, verify_relinearization_key_share_rounds,
    verify_relinearization_key_switch_sample_binding,
};
use self::evaluator_key_schedule::{
    verify_context_fields_match, verify_evaluator_key_schedule, verify_generic_key_switch_policy,
    verify_pending_evaluation_key_material_boundary,
};
use self::nested_hash::{optional_nested_hash_value, package_nested_hash};
pub(crate) use self::phase_transcript::accepted_setup_participant_roster_from_package;
use self::phase_transcript::{
    setup_context_string, verify_abort_absence, verify_phase_transcript,
    verify_setup_intent_roster_hash,
};
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    verify_private_vss_envelope_commitments,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_share_material::accepted_setup_collective_public_key_from_package;
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_share_material::public_key_share_coefficient_vector_hash;
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, public_key_share_material_uses_transport,
    verify_collective_public_key_material, verify_collective_public_key_pair_consistency,
    verify_public_key_share_material_set,
};
use self::public_key_shares::{
    PublicKeyCommonBinding, public_key_common_binding, public_key_refusal,
    public_key_share_records_by_roster_position, verify_optional_public_key_share_succinct_proofs,
    verify_public_key_material_acceptance_boundary, verify_public_key_share_proofs,
    verify_public_key_shares,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::same_secret_bridge_verification::verified_same_secret_bridge_material_from_package;
use self::same_secret_consistency::{
    SameSecretProofBinding, SameSecretStatementBinding, same_secret_consistency_root_from_package,
    same_secret_proof_bindings_from_package, same_secret_proof_family_binding_root,
    same_secret_proof_set_root_from_package, same_secret_statement_bindings_from_package,
    same_secret_statement_records_by_roster_position, verify_optional_same_secret_proofs,
    verify_same_secret_consistency, verify_same_secret_context,
};
use self::setup_context::{q_share_value, verify_context, verify_q_share};
use self::threshold_share_commitment_checks::verify_threshold_share_commitments;
use self::transport_policy::{
    setup_transport_chunk_manifest_root, setup_transport_vss_material_byte_length_for_roster,
    verify_transport_certificate,
};
use self::vss_coefficient_commitments::expected_trustees_from_phase_transcript;
use self::vss_complaints_and_acceptances::{
    source_trustee_commitment_roots_from_vss_commitments, verify_vss_complaints,
    verify_vss_share_acceptances,
};
use self::vss_public_material_verification::{
    VssPublicMaterialVerification, verify_optional_vss_public_material,
};

use super::setup_proof;
use crate::bgv::setup_helpers::compare_required_string;

#[cfg(test)]
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
use unicode_normalization::UnicodeNormalization;

use super::*;
use super::{
    commitment::{
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
        setup_commitment_matrix_sampled_entries, setup_commitment_modulus_limb_values,
        setup_commitment_parameters_value,
    },
    evaluation_key_share_material::{
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        EvaluationKeyShareProofFamily, component_b_vectors_from_record,
    },
    setup_proof::{
        SETUP_PROOF_BYTES_DOMAIN, SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_SERIALIZATION,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES, SetupProofMaterialChunks,
        setup_proof_material_transport_hashes, verified_setup_proof_material_chunks_from_request,
    },
    vss::carry_aware_vss_share_relation_value,
};
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::bgv::evaluator::top_k::{
    SELECTED_EVALUATOR_WORKING_LEVEL, direct_score_packing_basis_galois_elements,
    packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
};
use crate::hashing::derive_canonical_object_hash;
use crate::protocol_signatures::{
    ProtocolSignatureExpectation, verify_protocol_signature_envelope,
};
use crate::transcript_core::decode_hex;

const SETUP_PACKAGE_OBJECT_TYPE: &str = "SetupPackage";
const SAME_SECRET_CONSISTENCY_OBJECT_TYPE: &str = "SameSecretConsistencyStatementSet";
const SAME_SECRET_STATEMENT_OBJECT_TYPE: &str = "SameSecretConsistencyStatement";
const SAME_SECRET_PROOF_FAMILY_BINDING_OBJECT_TYPE: &str = "SameSecretProofFamilyBinding";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterialSet";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterial";
const EVALUATION_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareProofMaterialSet";
const EVALUATION_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareProofMaterial";
const TRUSTEE_SECRET_COMMITMENT_OBJECT_TYPE: &str = "TrusteeSecretCommitment";
const PUBLIC_KEY_SHARE_SET_OBJECT_TYPE: &str = "PublicKeyShareSet";
const PUBLIC_KEY_SHARE_OBJECT_TYPE: &str = "PublicKeyShare";
const PUBLIC_KEY_SHARE_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareProofSet";
const PUBLIC_KEY_SHARE_PROOF_OBJECT_TYPE: &str = "PublicKeyShareProof";
const PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE: &str = "PublicKeyShareMaterialSet";
const PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "PublicKeyShareMaterial";
pub(super) const PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareMaterial";
const PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING: &str =
    "embedded-full-public-key-share-coefficients";
pub(super) const PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING: &str =
    "binary-chunked-full-public-key-share-coefficients";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC: &[u8; 8] = b"SLPKSMV1";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION: u64 = 1;
const PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareSuccinctProofSet";
const PUBLIC_KEY_SHARE_SUCCINCT_PROOF_OBJECT_TYPE: &str = "PublicKeyShareSuccinctProof";
const COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE: &str = "CollectivePublicKey";
const EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE: &str = "EvaluatorKeySchedule";
const REQUIRED_GALOIS_SET_OBJECT_TYPE: &str = "RequiredGaloisSet";
const RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE: &str = "RelinearizationKeyShareRounds";
const RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundOne";
const RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundTwo";
const GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE: &str = "GaloisKeyShareBatch";
const GALOIS_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "GaloisKeyShareMaterial";
const TRUSTEE_EVALUATION_KEY_PROOF_SET_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProofSet";
const TRUSTEE_EVALUATION_KEY_PROOF_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProof";
const PUBLIC_EVALUATION_KEY_SET_OBJECT_TYPE: &str = "PublicEvaluationKeySet";
pub(super) const PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPublicEvaluationKeyMaterialSet";
pub(super) const PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicEvaluationKeyMaterial";
const PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING: &str =
    "root-bound-public-key-switch-component-roots";
pub(super) const PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING: &str =
    "binary-chunked-public-evaluation-key-root-manifest";
const PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC: &[u8; 8] = b"SLEKPMV1";
use super::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY;
const PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitmentSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitment";
const PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE: &str = "PrivateVssEnvelopeAad";
const ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "EncryptedPrivateVssShareEnvelope";
const FIRST_ROSTER_PARTICIPANT_COUNT: u64 = 10;
const FIRST_ROSTER_DECRYPTION_THRESHOLD: u64 = 4;
// Supported parameterized roster range. The first setup/evaluator roster
// (n = 10) is the only benchmarked and certified instance; supported-phone
// evidence is still future work. The verifier accepts any 3 <= n <= 20 by
// deriving the canonical quorums and threshold from the roster size, but no
// runtime/security/mobile evidence is established for n != 10 until those
// rosters receive their own certificates and measurements.
pub(super) const MINIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 3;
pub(super) const MAXIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 20;

/// Validated roster parameters for a collective BGV setup. Every field is a
/// pure function of `participant_count`, so the setup-parameters hash is a
/// roster family with one distinct binding per supported roster size.
#[derive(Clone, Copy)]
pub(super) struct AcceptedRosterParameters {
    pub(super) participant_count: u64,
    pub(super) setup_completion_quorum: u64,
    pub(super) ballot_release_quorum: u64,
    pub(super) finality_quorum: u64,
    pub(super) decryption_threshold: u64,
}

/// q_dec = floor(n / 3) + 1: the current structural one-third helper convention
/// plus one (at n = 3 this is 2-of-3, never 1-of-3). Setup, ballot release, and
/// finality are full-roster (= n) under the secure-with-abort model. Rosters
/// outside n = 10 need their own certificate if a stricter backend threshold
/// theorem is used.
pub(super) const fn decryption_threshold_for_participant_count(participant_count: u64) -> u64 {
    participant_count / 3 + 1
}

pub(super) const fn participant_count_is_supported(participant_count: u64) -> bool {
    participant_count >= MINIMUM_SUPPORTED_PARTICIPANT_COUNT
        && participant_count <= MAXIMUM_SUPPORTED_PARTICIPANT_COUNT
}

pub(super) fn roster_parameters_from_participant_count(
    participant_count: u64,
) -> AcceptedRosterParameters {
    AcceptedRosterParameters {
        participant_count,
        setup_completion_quorum: participant_count,
        ballot_release_quorum: participant_count,
        finality_quorum: participant_count,
        decryption_threshold: decryption_threshold_for_participant_count(participant_count),
    }
}

pub(super) fn first_closure_roster_parameters() -> AcceptedRosterParameters {
    roster_parameters_from_participant_count(FIRST_ROSTER_PARTICIPANT_COUNT)
}

/// Roster parameters for the roster size declared in a verified setup context.
/// `verify_context` validates `participantCount` (range and derived quorums)
/// before any sub-verifier runs, so reading it back here is safe; the
/// n = 10 fallback keeps callers total if the context is absent.
pub(super) fn accepted_roster_from_setup_context(
    setup_context: &Value,
) -> AcceptedRosterParameters {
    let participant_count = setup_context
        .get("participantCount")
        .and_then(Value::as_u64)
        .unwrap_or(FIRST_ROSTER_PARTICIPANT_COUNT);
    roster_parameters_from_participant_count(participant_count)
}

pub(super) fn accepted_roster_from_package(setup_package: &Value) -> AcceptedRosterParameters {
    setup_package
        .get("setupContext")
        .map(accepted_roster_from_setup_context)
        .unwrap_or_else(first_closure_roster_parameters)
}
const SETUP_TRANSPORT_SCHEME_ID: &str = "sealed-lattice-setup-binary-chunked-transport-v1";
const SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE: &str = "SetupTransportCertificate";
const SETUP_TRANSPORTED_OBJECT_TYPE: &str = "SetupTransportedObject";
const SETUP_TRANSPORT_STORAGE_QUOTA_BYTES: u64 = 2_147_483_648;
const SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES: u64 = 1_572_864;
const SETUP_TRANSPORT_COPY_COUNT_LIMIT: u64 = 2;
const SETUP_TRANSPORT_STREAM_ORDER: &str = "ascending-chunk-index";
const SETUP_TRANSPORT_RESUME_POLICY: &str = "chunk-index-checkpointed-by-hash";
const SETUP_TRANSPORT_LAZY_LOADING_POLICY: &str = "root-addressed-large-object-loading";
const SETUP_TRANSPORTED_VSS_MATERIAL_NAME: &str = "vssCoefficientCommitmentMaterial";
const SETUP_TRANSPORTED_VSS_MATERIAL_ROLE: &str = "public-vss-coefficient-commitment-material";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME: &str = "publicKeyShareMaterial";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE: &str = "public-key-share-material";
const SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_NAME: &str = "sameSecretProofMaterial";
const SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_ROLE: &str = "same-secret-proof-material";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_NAME: &str = "publicKeyShareProofMaterial";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_ROLE: &str =
    "public-key-share-proof-material";
const SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_NAME: &str =
    "evaluationKeyShareProofMaterial";
const SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_ROLE: &str =
    "evaluation-key-share-proof-material";
const SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_NAME: &str =
    "evaluationKeyShareComponentMaterial";
const SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ROLE: &str =
    "evaluation-key-share-component-material";
const SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_NAME: &str = "publicEvaluationKeyMaterial";
const SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_ROLE: &str =
    "public-evaluation-key-runtime-material";
const SETUP_TRANSPORTED_OBJECT_LOADING_POLICY: &str = "stream-verified-before-object-use";
const PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER: u64 = 6;
const PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER: u64 = 7;
const EVALUATOR_REPLAY_SCHEME_LABEL: &str = "direct-encrypted-ballot-evaluator-replay";
const EVALUATOR_PACKING_SCHEME_LABEL: &str = "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing";
const SAME_SECRET_BOUND_PROOF_FAMILIES: &[&str] = &[
    "vss-constant-relation",
    "public-key-share",
    "relinearization-key-share",
    "galois-key-share",
];
const ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES: &[&str] = &[
    "same-secret-linkage-anchor",
    "public-key-share",
    "vss-opening-carry",
    "trustee-evaluation-key",
];

const REQUIRED_PHASES: &[(&str, u64)] = &[
    ("rosterFreeze", 1),
    ("setupIntent", 2),
    ("commonRandomnessCommit", 3),
    ("commonRandomnessReveal", 4),
    ("vssCoefficientCommitments", 5),
    ("privateVssEnvelopeDelivery", 6),
    ("recipientVssVerification", 7),
    ("vssAcceptanceOrComplaint", 8),
    ("publicKeyShareProofs", 9),
    ("relinearizationRoundOne", 10),
    ("relinearizationRoundTwo", 11),
    ("galoisKeyShareBatches", 12),
    ("trusteeEvaluationKeyProofs", 13),
    ("setupPackageAssembly", 14),
    ("setupPackageVerification", 15),
];

const REQUIRED_FINAL_OBJECTS: &[&str] = &[
    "qShare",
    "commonRandomness",
    "vssPublicCoefficientCommitmentSet",
    "vssPublicRecipientShareCommitmentSet",
    "vssPublicAggregateThresholdCommitmentSet",
    "vssShareLinkageStatement",
    "vssShareLinkageProofMaterialSet",
    "sameSecretBridgeStatementSet",
    "sameSecretBridgeProofMaterialSet",
    "privateVssEnvelopeCommitments",
    "privateVssEnvelopeCommitmentRoot",
    "vssShareAcceptances",
    "thresholdShareCommitments",
    "sameSecretConsistency",
    "sameSecretProofs",
    "publicKeyShares",
    "publicKeyShareProofs",
    "publicKeyShareMaterial",
    "publicKeyShareSuccinctProofs",
    "collectivePublicKey",
    "collectivePublicKeyRoot",
    "evaluatorKeySchedule",
    "relinearizationKeyShareRounds",
    "galoisKeyShareBatches",
    "trusteeEvaluationKeyProofs",
    "evaluationKeys",
    "setupTransportCertificate",
    "setupTransportCertificateHash",
];

struct Refusal {
    reason_code: &'static str,
    message: String,
    object_path: Option<String>,
}

impl Refusal {
    fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
            object_path: Some(object_path.into()),
        }
    }

    fn to_value(&self) -> Value {
        let mut value = json!({
            "reasonCode": self.reason_code,
            "message": self.message,
        });
        if let Some(object_path) = &self.object_path {
            value["objectPath"] = Value::String(object_path.clone());
        }

        value
    }
}

enum VerificationFlow {
    Continue,
    Stop(Value),
}

pub(crate) fn describe_collective_bgv_setup_parameters() -> CanonicalResult<Value> {
    describe_collective_bgv_setup_parameters_for_roster(&first_closure_roster_parameters())
}

pub(crate) fn describe_collective_bgv_setup_parameters_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    Ok(json!({
        "setupParametersHash": setup_parameters_hash_for_roster(roster)?,
        "canonicalTargetBasisHash": crate::bgv::evaluator::top_k::canonical_target_basis_hash()?,
        "objectType": SETUP_PACKAGE_OBJECT_TYPE,
        "adversaryModel": "active-static",
        "livenessModel": "secure-with-abort",
        "sharingModel": "recipient-verified-vss",
        "sharingDomain": "per-rns-prime",
        "completionRule": "full-roster",
        "participantCount": roster.participant_count,
        "qSetupComplete": roster.setup_completion_quorum,
        "qBallotRelease": roster.ballot_release_quorum,
        "qFinal": roster.finality_quorum,
        "qDec": roster.decryption_threshold,
        "qShare": q_share_value(),
        "carryAwareVssShareRelation": carry_aware_vss_share_relation_value(),
        "commitment": setup_commitment_parameters_value()?,
        "setupProof": setup_proof_parameters_value()?,
        "setupTransport": setup_transport_parameters_value_for_roster(roster)?,
        "evaluatorKeySchedule": evaluator_key_schedule_value_for_roster(roster)?,
        "phaseOrder": phase_order_value(),
        "phaseOrderHash": phase_order_hash()?,
        "requiredFinalObjects": REQUIRED_FINAL_OBJECTS,
        "transportSchemeId": SETUP_TRANSPORT_SCHEME_ID,
    }))
}

// The setup parameters for a reduced roster size, used by test fixtures that
// exercise the accepted-setup path at a smaller participant count than the first
// closure roster. The parameters hash and quorums are derived from the roster, so
// the reduced-roster setup context binds the hash the verifier recomputes.
pub(crate) fn describe_collective_bgv_setup_parameters_for_participant_count(
    participant_count: u64,
) -> CanonicalResult<Value> {
    describe_collective_bgv_setup_parameters_for_roster(&roster_parameters_from_participant_count(
        participant_count,
    ))
}

pub(crate) fn verify_collective_bgv_setup_package_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    verify_collective_bgv_setup_package(setup_package, request)
}

pub(crate) fn verify_collective_bgv_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Value> {
    if !setup_package.is_object() {
        return verification_response(
            None,
            Vec::new(),
            vec![Refusal::new(
                "setupPackageNotObject",
                "setupPackage must be a JSON object",
                "setupPackage".to_string(),
            )],
            Vec::new(),
        );
    }
    match verify_collective_setup_package(setup_package, request)? {
        VerificationFlow::Continue => accepted_setup_verification_response(setup_package),
        VerificationFlow::Stop(response) => Ok(response),
    }
}

pub(crate) fn derive_collective_bgv_setup_public_derivations_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let public_matrix_seed_hash = request
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicMatrixSeedHash is required",
            )
        })?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;

    // The standalone public-derivation command carries no setup context, so it
    // uses the n = 10 decryption threshold. Reduced-roster fixtures can pass
    // their decryption threshold so derivations match what the package verifier
    // recomputes.
    let decryption_threshold = request
        .get("decryptionThreshold")
        .and_then(Value::as_u64)
        .unwrap_or(FIRST_ROSTER_DECRYPTION_THRESHOLD);
    derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash, decryption_threshold)
}

fn verify_collective_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<VerificationFlow> {
    let Some(object_type) = setup_package.get("objectType").and_then(Value::as_str) else {
        return outside_accepted_parameters(
            "setupPackage.objectType is required",
            "setupPackage.objectType",
        );
    };
    if object_type != SETUP_PACKAGE_OBJECT_TYPE {
        return outside_accepted_parameters(
            format!(
                "setupPackage.objectType must be {SETUP_PACKAGE_OBJECT_TYPE}, not {object_type}"
            ),
            "setupPackage.objectType",
        );
    }
    if let Some(response) = verify_context(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_q_share(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_phase_transcript(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_intent_roster_hash(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_common_randomness(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_abort_absence(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_package_hash(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_private_vss_envelope_commitments(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_complaints(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_collective_public_key_pair_consistency(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_share_acceptances(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    let verified_vss_public_material =
        match verify_optional_vss_public_material(setup_package, request)? {
            VssPublicMaterialVerification::Absent => None,
            VssPublicMaterialVerification::Verified(verified_material) => Some(verified_material),
            VssPublicMaterialVerification::Refused(response) => {
                return Ok(VerificationFlow::Stop(response));
            }
        };
    if let Some(response) =
        verify_threshold_share_commitments(setup_package, verified_vss_public_material.as_ref())?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_same_secret_consistency(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    let verified_same_secret_bridge =
        match verify_optional_same_secret_bridge_statement_set(setup_package, request)? {
            SameSecretBridgeVerification::Absent => None,
            SameSecretBridgeVerification::Verified(verified_material) => Some(verified_material),
            SameSecretBridgeVerification::Refused(response) => {
                return Ok(VerificationFlow::Stop(response));
            }
        };
    if let Some(response) =
        verify_optional_same_secret_proofs(verified_same_secret_bridge.as_ref())?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_shares(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_share_proofs(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_optional_public_key_share_succinct_proofs(
        setup_package,
        request,
        verified_same_secret_bridge.as_ref(),
    )? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_collective_public_key_material(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_material_acceptance_boundary(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_evaluator_key_schedule(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_pending_evaluation_key_material_boundary(
        setup_package,
        request,
        verified_same_secret_bridge.as_ref(),
    )? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_generic_key_switch_policy(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_transport_certificate(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    let declares_public_runtime_material =
        setup_package_declares_public_runtime_material(setup_package);
    if declares_public_runtime_material
        && let Some(response) = verify_full_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_final_objects(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if !declares_public_runtime_material
        && let Some(response) = verify_full_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_terminal_setup_transport_policy(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_public_evaluation_key_set(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    Ok(VerificationFlow::Continue)
}

fn verify_setup_package_hash(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(setup_package_hash) = setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("setupPackageAssembly"),
            vec!["setupPackageHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(setup_package_hash, "setupPackage.setupPackageHash")?;

    let hash_input = setup_package_hash_input(setup_package);
    let expected_hash = derive_canonical_object_hash(&hash_input)?;
    if setup_package_hash != expected_hash {
        return Ok(Some(verification_response(
            Some("setupPackageAssembly"),
            Vec::new(),
            vec![Refusal::new(
                "setupPackageHashMismatch",
                "SetupPackageHash does not match the canonical setup package payload",
                "setupPackage.setupPackageHash".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if let Some(expected_hash_from_request) = request
        .get("expectedSetupPackageHash")
        .and_then(Value::as_str)
    {
        validate_hash_string(expected_hash_from_request, "expectedSetupPackageHash")?;
        if expected_hash_from_request != setup_package_hash {
            return Ok(Some(verification_response(
                Some("setupPackageAssembly"),
                Vec::new(),
                vec![Refusal::new(
                    "expectedSetupPackageHashMismatch",
                    "setup package hash does not match expectedSetupPackageHash",
                    "expectedSetupPackageHash".to_string(),
                )],
                Vec::new(),
            )?));
        }
    }

    Ok(None)
}

fn setup_package_hash_input(setup_package: &Value) -> Value {
    let mut hash_input = setup_package.clone();
    let hash_input_object = hash_input
        .as_object_mut()
        .expect("setup package object was checked");
    hash_input_object.remove("setupPackageHash");
    strip_private_vss_encrypted_envelopes_from_package_hash_input(&mut hash_input);

    hash_input
}

fn strip_private_vss_encrypted_envelopes_from_package_hash_input(hash_input: &mut Value) {
    let Some(private_vss_envelope_commitments) = hash_input
        .get_mut("privateVssEnvelopeCommitments")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let Some(envelope_references) = private_vss_envelope_commitments
        .get_mut("envelopeReferences")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for envelope_reference in envelope_references {
        if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
            envelope_reference_object.remove("encryptedEnvelope");
        }
    }
}

fn verify_required_final_objects(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let missing_objects = REQUIRED_FINAL_OBJECTS
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_none())
        .map(|field_name| (*field_name).to_string())
        .collect::<Vec<_>>();
    if missing_objects.is_empty() {
        return Ok(None);
    }

    Ok(Some(verification_response(
        Some("setupPackageVerification"),
        missing_objects,
        Vec::new(),
        Vec::new(),
    )?))
}

fn setup_package_declares_public_runtime_material(setup_package: &Value) -> bool {
    setup_package.get("collectivePublicKey").is_some()
        || setup_package
            .get("evaluationKeys")
            .and_then(Value::as_object)
            .is_some_and(|evaluation_keys| !evaluation_keys.is_empty())
}

fn accepted_setup_verification_response(setup_package: &Value) -> CanonicalResult<Value> {
    let mut response = verification_response(
        Some("setupPackageVerification"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    response
        .as_object_mut()
        .expect("verification response is a JSON object")
        .insert(
            "acceptedSetupHandoff".to_string(),
            accepted_setup_handoff_value(setup_package)?,
        );

    Ok(response)
}

fn accepted_setup_handoff_value(setup_package: &Value) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before accepted setup handoff construction",
        )
    })?;
    let mut handoff = json!({
        "objectType": "CollectiveBgvAcceptedSetupHandoff",
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupParametersHash": value_string(setup_context, "setupParametersHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupPackageHash": value_string(setup_package, "setupPackageHash")?,
        "directBallotEncryptionHandoff": {
            "collectivePublicKeyRoot": package_nested_hash(
                setup_package,
                "collectivePublicKey",
                "collectivePublicKeyRoot",
            )?,
            "publicKeyShareMaterialSetRoot": package_nested_hash(
                setup_package,
                "publicKeyShareMaterial",
                "publicKeyShareMaterialSetRoot",
            )?,
            "publicKeyShareSuccinctProofSetRoot": package_nested_hash(
                setup_package,
                "publicKeyShareSuccinctProofs",
                "publicKeyShareSuccinctProofSetRoot",
            )?,
        },
        "publicAggregationHandoff": {
            "thresholdShareCommitmentRoot": package_nested_hash(
                setup_package,
                "thresholdShareCommitments",
                "thresholdShareCommitmentRoot",
            )?,
        },
        "boundedEvaluatorReplayHandoff": {
            "evaluatorKeyScheduleRoot": package_nested_hash(
                setup_package,
                "evaluatorKeySchedule",
                "evaluatorKeyScheduleRoot",
            )?,
            "relinearizationKeyShareRoundsRoot": package_nested_hash(
                setup_package,
                "relinearizationKeyShareRounds",
                "relinearizationKeyShareRoundsRoot",
            )?,
            "trusteeEvaluationKeyProofSetRoot": package_nested_hash(
                setup_package,
                "trusteeEvaluationKeyProofs",
                "trusteeEvaluationKeyProofSetRoot",
            )?,
            "evaluationKeySetHash": package_nested_hash(
                setup_package,
                "evaluationKeys",
                "evaluationKeySetHash",
            )?,
            "publicEvaluationKeyMaterialRoot": optional_nested_hash_value(
                setup_package,
                "evaluationKeys",
                "publicEvaluationKeyMaterialRoot",
            )?,
        },
        "certificateRoots": {
            "setupTransportCertificateHash": value_string(
                setup_package,
                "setupTransportCertificateHash",
            )?,
        },
    });
    let handoff_root = derive_canonical_object_hash(&handoff)?;
    handoff
        .as_object_mut()
        .expect("accepted setup handoff is a JSON object")
        .insert("acceptedSetupHandoffRoot".to_string(), json!(handoff_root));

    Ok(handoff)
}

fn outside_accepted_parameters(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<VerificationFlow> {
    Ok(VerificationFlow::Stop(verification_response(
        None,
        Vec::new(),
        vec![Refusal::new(
            "outsideCollectiveBgvSetupParameters",
            message,
            object_path.into(),
        )],
        Vec::new(),
    )?))
}

fn verification_response(
    current_phase: Option<&str>,
    missing_objects: Vec<String>,
    refused_objects: Vec<Refusal>,
    _accepted_hashes: Vec<String>,
) -> CanonicalResult<Value> {
    let accepted = refused_objects.is_empty() && missing_objects.is_empty();

    Ok(json!({
        "isValid": accepted,
        "operation": "verifyCollectiveBgvSetupPackage",
        "currentPhase": current_phase,
        "phaseOrderHash": phase_order_hash()?,
        "missingObjects": missing_objects,
        "refusedObjects": refused_objects
            .into_iter()
            .map(|refusal| refusal.to_value())
            .collect::<Vec<_>>(),
    }))
}

fn phase_order_hash() -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvSetupPhaseOrder",
        "phaseOrder": phase_order_value(),
    }))
}

fn phase_order_value() -> Value {
    Value::Array(
        REQUIRED_PHASES
            .iter()
            .map(|(phase_identifier, phase_number)| {
                json!({
                    "phaseId": phase_identifier,
                    "phaseNumber": phase_number,
                })
            })
            .collect(),
    )
}

mod binding_checks;
mod setup_parameters;

use binding_checks::*;
use setup_parameters::*;

pub(super) use binding_checks::accepted_vss_coefficient_commitment_root;
pub(super) use setup_parameters::{setup_parameters_hash, setup_parameters_hash_for_roster};
