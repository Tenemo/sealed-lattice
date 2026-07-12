mod common_randomness;
mod evaluation_key_material_transport;
mod evaluation_key_proof_checks;
mod evaluation_key_share_rounds;
mod evaluator_key_schedule;
mod phase_transcript;
mod private_vss_envelopes;
mod public_key_share_material;
mod public_key_shares;
mod same_secret_bridge_verification;
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
pub(in crate::bgv::setup) use self::public_key_share_material::{
    CanonicalPublicKeyShareMaterialStream,
    absorb_verified_canonical_public_key_share_material_chunk,
    authenticated_public_key_share_material_stream_summary,
    begin_verified_canonical_public_key_share_material_stream,
    cancel_verified_canonical_public_key_share_material_stream,
    evict_verified_canonical_public_key_share_materials,
    finish_verified_canonical_public_key_share_material_stream,
};
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, public_key_share_material_uses_transport,
    verify_collective_public_key_material, verify_collective_public_key_pair_consistency,
    verify_public_key_share_material_set,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_shares::public_key_share_succinct_proof_material_root;
use self::public_key_shares::{
    PublicKeyCommonBinding, public_key_common_binding, public_key_refusal,
    public_key_share_records_by_roster_position, verify_optional_public_key_share_succinct_proofs,
    verify_public_key_share_proofs, verify_public_key_shares,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::same_secret_bridge_verification::verified_same_secret_bridge_material_from_package;
use self::setup_context::{q_share_value, verify_context, verify_q_share};
use self::threshold_share_commitment_checks::verify_threshold_share_commitments;
use self::transport_policy::verify_transport_certificate;
use self::vss_coefficient_commitments::expected_trustees_from_phase_transcript;
use self::vss_complaints_and_acceptances::{
    source_trustee_commitment_roots_from_vss_commitments, verify_vss_complaints,
    verify_vss_share_acceptances,
};
use self::vss_public_material_verification::{
    VssPublicMaterialVerification, verify_optional_vss_public_material,
};

use crate::bgv::setup_helpers::{compare_required_string, compare_required_u64};

#[cfg(test)]
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

use super::*;
use super::{
    commitment::{
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
        setup_commitment_matrix_sampled_entries, setup_commitment_modulus_limb_values,
        setup_commitment_parameters_value,
    },
    evaluation_key_share_material::{
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        EvaluationKeyShareProofFamily, VerifiedComponentMaterialEvictionGuard,
        authenticated_evaluation_key_component_stream_summary, component_b_vectors_from_record,
    },
    setup_proof::{
        SETUP_PROOF_BYTES_DOMAIN, SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_SERIALIZATION,
        SetupProofMaterialBytes, VerifiedSetupProofMaterialEvictionGuard,
        verified_setup_proof_material_bytes_from_request,
    },
    vss::carry_aware_vss_share_relation_value,
};
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
use crate::bgv::evaluator::top_k::{
    SELECTED_EVALUATOR_WORKING_LEVEL, direct_score_packing_basis_galois_elements,
    packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
};
use crate::hashing::{
    CanonicalJsonPathSegment, derive_canonical_object_hash,
    derive_canonical_object_hash_omitting_field_paths,
};
use crate::protocol_signatures::{
    ProtocolSignatureExpectation, verify_protocol_signature_envelope,
};
const SETUP_PACKAGE_OBJECT_TYPE: &str = "SetupPackage";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterialSet";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterial";
const EVALUATION_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareProofMaterialSet";
const EVALUATION_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareProofMaterial";
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
use super::trustee_evaluation_key_proof::{
    PUBLIC_KEY_SHARE_PROOF_FAMILY, SAME_SECRET_BRIDGE_PROOF_FAMILY,
    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY, VSS_SHARE_LINKAGE_PROOF_FAMILY,
};
const PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitmentSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitment";
const PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE: &str = "PrivateVssEnvelopeAad";
const ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "EncryptedPrivateVssShareEnvelope";
const FOUNDATION_ROSTER_PARTICIPANT_COUNT: u64 = 10;
const FOUNDATION_DECRYPTION_THRESHOLD: u64 = 4;
// Parameterized development roster range. The first setup/evaluator roster
// (n = 10) is the only benchmarked development instance; supported-phone
// evidence is still future work. The verifier accepts any 3 <= n <= 20 by
// deriving the canonical quorums and threshold from the roster size, but that
// structural acceptance is not cryptographic, runtime, or mobile evidence for
// any roster size.
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

pub(super) fn foundation_roster_parameters() -> AcceptedRosterParameters {
    roster_parameters_from_participant_count(FOUNDATION_ROSTER_PARTICIPANT_COUNT)
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
        .unwrap_or(FOUNDATION_ROSTER_PARTICIPANT_COUNT);
    roster_parameters_from_participant_count(participant_count)
}

pub(super) fn accepted_roster_from_package(setup_package: &Value) -> AcceptedRosterParameters {
    setup_package
        .get("setupContext")
        .map(accepted_roster_from_setup_context)
        .unwrap_or_else(foundation_roster_parameters)
}
const SETUP_TRANSPORT_SCHEME_ID: &str = "sealed-lattice-setup-binary-chunked-transport";
const SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE: &str = "SetupTransportCertificate";
const SETUP_TRANSPORTED_OBJECT_TYPE: &str = "SetupTransportedObject";
const SETUP_TRANSPORT_STREAM_ORDER: &str = "ascending-chunk-index";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME: &str = "publicKeyShareMaterial";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE: &str = "public-key-share-material";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_NAME: &str = "publicKeyShareProofMaterial";
const SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_ROLE: &str =
    "public-key-share-proof-material";
const SETUP_TRANSPORTED_VSS_SHARE_LINKAGE_PROOF_MATERIAL_NAME: &str =
    "vssShareLinkageProofMaterial";
const SETUP_TRANSPORTED_VSS_SHARE_LINKAGE_PROOF_MATERIAL_ROLE: &str =
    "vss-share-linkage-proof-material";
const SETUP_TRANSPORTED_SAME_SECRET_BRIDGE_PROOF_MATERIAL_NAME: &str =
    "sameSecretBridgeProofMaterial";
const SETUP_TRANSPORTED_SAME_SECRET_BRIDGE_PROOF_MATERIAL_ROLE: &str =
    "same-secret-bridge-proof-material";
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
const PUBLIC_EVALUATION_KEY_MATERIAL_STREAM_FAMILY: &str = "public-evaluation-key-material";
const PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER: u64 = 6;
const PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER: u64 = 7;
const EVALUATOR_REPLAY_SCHEME_LABEL: &str = "direct-encrypted-ballot-evaluator-replay";
const EVALUATOR_PACKING_SCHEME_LABEL: &str = "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing";
const ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES: &[&str] = &[
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
    describe_collective_bgv_setup_parameters_for_roster(&foundation_roster_parameters())
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
// exercise the accepted-setup path at a smaller participant count than the fixed
// foundation roster. The parameters hash and quorums are derived from the roster, so
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
    let _component_material_eviction_guard =
        VerifiedComponentMaterialEvictionGuard::for_request(request);
    let _setup_proof_material_eviction_guard =
        VerifiedSetupProofMaterialEvictionGuard::for_request(request);
    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    verify_collective_bgv_setup_package_inner(setup_package, request)
}

#[cfg(test)]
pub(crate) fn verify_collective_bgv_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Value> {
    // Evict this request's streamed evaluation-key component material from the
    // process-global store when verify returns by any path, so the browser wasm
    // runtime does not retain every verified package's material.
    let _component_material_eviction_guard =
        VerifiedComponentMaterialEvictionGuard::for_request(request);
    // Same lifecycle for this request's stream-verified setup proof material: the
    // SDK streams fresh sequence-numbered handles on every verify, so without
    // eviction the process-global store retains a full copy of every verified
    // package's share-linkage, same-secret bridge, public-key share, and
    // evaluation-key proof material.
    let _setup_proof_material_eviction_guard =
        VerifiedSetupProofMaterialEvictionGuard::for_request(request);
    verify_collective_bgv_setup_package_inner(setup_package, request)
}

fn verify_collective_bgv_setup_package_inner(
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
        VerificationFlow::Continue => accepted_setup_verification_response(),
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
        .unwrap_or(FOUNDATION_DECRYPTION_THRESHOLD);
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
    // These hash-bound policy checks consume only the canonical setup object
    // and request metadata, so their typed refusals can be determined without
    // requiring proof-material handles.
    if let Some(response) = verify_generic_key_switch_policy(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_transport_certificate(setup_package, request)? {
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
    let verified_same_secret_bridge =
        match verify_optional_same_secret_bridge_statement_set(setup_package, request)? {
            SameSecretBridgeVerification::Absent => None,
            SameSecretBridgeVerification::Verified(verified_material) => Some(verified_material),
            SameSecretBridgeVerification::Refused(response) => {
                return Ok(VerificationFlow::Stop(response));
            }
        };
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

    let expected_hash = derive_collective_setup_package_hash(setup_package)?;
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

pub(in crate::bgv::setup) fn derive_collective_setup_package_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash_omitting_field_paths(
        setup_package,
        &[
            &[CanonicalJsonPathSegment::ObjectField("setupPackageHash")],
            &[
                CanonicalJsonPathSegment::ObjectField("privateVssEnvelopeCommitments"),
                CanonicalJsonPathSegment::ObjectField("envelopeReferences"),
                CanonicalJsonPathSegment::ArrayElement,
                CanonicalJsonPathSegment::ObjectField("encryptedEnvelope"),
            ],
        ],
    )
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

fn accepted_setup_verification_response() -> CanonicalResult<Value> {
    verification_response(
        Some("setupPackageVerification"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
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
    _current_phase: Option<&str>,
    missing_objects: Vec<String>,
    mut refused_objects: Vec<Refusal>,
    _accepted_hashes: Vec<String>,
) -> CanonicalResult<Value> {
    refused_objects.extend(missing_objects.into_iter().map(|missing_object| {
        Refusal::new(
            "setupObjectMissing",
            "A required setup object is missing.",
            format!("setupPackage.{missing_object}"),
        )
    }));
    let accepted = refused_objects.is_empty();

    Ok(json!({
        "isValid": accepted,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collective_setup_package_hash_matches_clone_and_remove_reference() {
        let setup_package = json!({
            "objectType": "CollectiveBgvSetupPackage",
            "setupPackageHash": "excluded-self-hash",
            "privateVssEnvelopeCommitments": {
                "encryptedEnvelope": "bound-at-the-parent-object",
                "envelopeReferences": [
                    {
                        "encryptedEnvelope": {
                            "objectType": "PrivateVssEncryptedEnvelope",
                            "ciphertext": "excluded-private-envelope",
                        },
                        "encryptedEnvelopeHash": "bound-envelope-hash",
                    },
                    {
                        "encryptedEnvelope": null,
                        "encryptedEnvelopeHash": "second-bound-envelope-hash",
                    },
                ],
            },
            "nested": {
                "encryptedEnvelope": "bound-at-an-unrelated-path",
                "setupPackageHash": "bound-because-it-is-not-the-root-field",
            },
        });
        let mut reference_hash_input = setup_package.clone();
        reference_hash_input
            .as_object_mut()
            .expect("setup package object")
            .remove("setupPackageHash");
        for envelope_reference in
            reference_hash_input["privateVssEnvelopeCommitments"]["envelopeReferences"]
                .as_array_mut()
                .expect("envelope reference array")
        {
            envelope_reference
                .as_object_mut()
                .expect("envelope reference object")
                .remove("encryptedEnvelope");
        }

        let expected_hash =
            derive_canonical_object_hash(&reference_hash_input).expect("reference hash");
        assert_eq!(
            derive_collective_setup_package_hash(&setup_package).expect("filtered hash"),
            expected_hash
        );

        let mut changed_excluded_fields = setup_package.clone();
        changed_excluded_fields["setupPackageHash"] = json!("changed-excluded-self-hash");
        changed_excluded_fields["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
            ["ciphertext"] = json!("changed-excluded-private-envelope");
        assert_eq!(
            derive_collective_setup_package_hash(&changed_excluded_fields)
                .expect("hash with changed excluded fields"),
            expected_hash
        );

        let mut changed_unrelated_field = setup_package.clone();
        changed_unrelated_field["nested"]["encryptedEnvelope"] = json!("changed-bound-value");
        assert_ne!(
            derive_collective_setup_package_hash(&changed_unrelated_field)
                .expect("changed filtered hash"),
            expected_hash
        );

        let mut changed_nested_self_hash = setup_package.clone();
        changed_nested_self_hash["nested"]["setupPackageHash"] = json!("changed-bound-value");
        assert_ne!(
            derive_collective_setup_package_hash(&changed_nested_self_hash)
                .expect("hash with changed nested self-hash field"),
            expected_hash
        );

        let mut malformed_nested_array = setup_package.clone();
        malformed_nested_array["privateVssEnvelopeCommitments"]["envelopeReferences"] = json!([[{
            "encryptedEnvelope": "still-bound-inside-a-nested-array",
            "encryptedEnvelopeHash": "nested-envelope-hash",
        }]]);
        let mut malformed_nested_array_reference_input = malformed_nested_array.clone();
        malformed_nested_array_reference_input
            .as_object_mut()
            .expect("malformed setup package object")
            .remove("setupPackageHash");
        let malformed_nested_array_reference =
            derive_canonical_object_hash(&malformed_nested_array_reference_input)
                .expect("malformed reference hash");
        assert_eq!(
            derive_collective_setup_package_hash(&malformed_nested_array)
                .expect("filtered malformed hash"),
            malformed_nested_array_reference
        );

        for malformed_private_vss_envelope_commitments in [
            json!({
                "envelopeReferences": {
                    "encryptedEnvelope": "still-bound-without-an-array",
                },
            }),
            json!([{
                "envelopeReferences": {
                    "encryptedEnvelope": "still-bound-after-an-earlier-array",
                },
            }]),
        ] {
            let mut malformed_container = setup_package.clone();
            malformed_container["privateVssEnvelopeCommitments"] =
                malformed_private_vss_envelope_commitments;
            let mut malformed_container_reference_input = malformed_container.clone();
            malformed_container_reference_input
                .as_object_mut()
                .expect("malformed setup package object")
                .remove("setupPackageHash");
            let malformed_container_reference =
                derive_canonical_object_hash(&malformed_container_reference_input)
                    .expect("malformed container reference hash");
            assert_eq!(
                derive_collective_setup_package_hash(&malformed_container)
                    .expect("filtered malformed container hash"),
                malformed_container_reference
            );
        }
    }
}
