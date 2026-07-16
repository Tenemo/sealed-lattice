mod common_randomness;
mod evaluation_key_material_transport;
mod evaluation_key_proof_checks;
mod evaluation_key_share_rounds;
mod evaluator_key_schedule;
mod private_vss_envelopes;
mod public_key_share_material;
mod public_key_shares;
mod same_secret_bridge_verification;
mod setup_context;
mod setup_intent;
mod vss_complaints_and_acceptances;
mod vss_public_material_verification;

use self::common_randomness::verify_common_randomness;
use self::same_secret_bridge_verification::{
    SameSecretBridgeVerification, verify_same_secret_bridge_statement_set,
};
// Re-exported for terminal proof fixtures, which build public-key-share and
// trustee evaluation-key statements against the verified same-secret bridge
// material that the accepted-setup verifier reconstructs.
use self::evaluation_key_material_transport::evaluation_key_material_refusal;
use self::evaluation_key_proof_checks::verify_trustee_evaluation_key_proofs;
#[cfg(test)]
pub(in crate::bgv::setup) use self::evaluation_key_proof_checks::{
    TrusteeEvaluationKeyStatementInputs, trustee_evaluation_key_proof_verification_binding_hash,
    trustee_evaluation_key_statement_from_package,
};
pub(in crate::bgv::setup) use self::evaluation_key_share_rounds::{
    evaluation_key_proof_common_binding, expected_galois_key_switch_seed,
    expected_relinearization_key_switch_seed, scheduled_relinearization_levels,
};
use self::evaluation_key_share_rounds::{
    galois_key_share_material_for_schedule, verify_galois_key_share_batches,
    verify_galois_key_switch_sample_binding, verify_relinearization_key_share_rounds,
    verify_relinearization_key_switch_sample_binding,
};
use self::evaluator_key_schedule::verify_pending_evaluation_key_material_boundary;
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    private_vss_envelope_commitment_root, verify_private_vss_envelope_commitments,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_share_material::public_key_share_coefficient_vector_hash;
pub(in crate::bgv::setup) use self::public_key_share_material::{
    CanonicalPublicKeyShareMaterialStream, VerifiedCanonicalPublicKeyShareMaterialHandle,
    VerifiedCanonicalPublicKeyShareMaterialStoreEntry,
    absorb_verified_canonical_public_key_share_material_chunk,
    begin_verified_canonical_public_key_share_material_stream,
    cancel_verified_canonical_public_key_share_material_stream,
    finish_verified_canonical_public_key_share_material_stream,
};
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, verify_collective_public_key_material,
    verify_public_key_share_material_set,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_shares::public_key_share_succinct_proof_verification_binding_hash;
use self::public_key_shares::{
    PublicKeyCommonBinding, PublicKeyShareSuccinctProofVerification, public_key_refusal,
    verify_public_key_share_succinct_proofs, verify_public_key_shares,
};
pub(in crate::bgv::setup) use self::public_key_shares::{
    derive_public_key_share_root, derive_public_key_share_set_root,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::same_secret_bridge_verification::verified_same_secret_bridge_material_from_package;
use self::setup_context::verify_context;
#[cfg(test)]
pub(crate) use self::setup_intent::accepted_setup_participant_roster_from_package;
use self::setup_intent::{
    SetupIntentVerification, expected_trustees_from_setup_intent, verify_setup_intent,
    verify_setup_intent_roster_hash,
};
use self::vss_complaints_and_acceptances::{
    source_trustee_commitment_roots_from_vss_commitments, verify_vss_complaints,
    verify_vss_share_acceptances,
};
use self::vss_public_material_verification::{
    VssPublicMaterialVerification, verify_vss_public_material,
};

use crate::bgv::setup_helpers::{compare_required_string, compare_required_u64};

#[cfg(test)]
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

use super::*;
use super::{
    evaluation_key_share_material::{
        DecodedEvaluationKeyShareComponentMaterial, EvaluationKeyShareDerivedMaterialBinding,
        EvaluationKeyShareProofFamily, component_b_vectors_from_root,
    },
    setup_proof::SetupProofMaterialBytes,
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
const PUBLIC_KEY_SHARE_SET_OBJECT_TYPE: &str = "PublicKeyShareSet";
const PUBLIC_KEY_SHARE_OBJECT_TYPE: &str = "PublicKeyShare";
const PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE: &str = "PublicKeyShareMaterialSet";
const PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "PublicKeyShareMaterial";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC: &[u8; 8] = b"SLPKSMV2";
const PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareSuccinctProofSet";
const COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE: &str = "CollectivePublicKey";
const RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE: &str = "RelinearizationKeyShareRounds";
const GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE: &str = "GaloisKeyShareBatch";
const TRUSTEE_EVALUATION_KEY_PROOF_SET_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProofSet";
use super::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY;
const PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitmentSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitment";
const ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "EncryptedPrivateVssShareEnvelope";
const FOUNDATION_ROSTER_PARTICIPANT_COUNT: u64 = 10;
// Roster range accepted by the parameterized verifier. Quorums and the
// decryption threshold are derived canonically from the participant count.
pub(super) const MINIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 3;
pub(super) const MAXIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 20;

/// Validated roster parameters for a collective BGV setup. The decryption
/// threshold is a pure function of `participant_count`, so the setup-parameters
/// hash is a roster family with one distinct binding per supported roster size.
#[derive(Clone, Copy)]
pub(super) struct AcceptedRosterParameters {
    pub(super) participant_count: u64,
    pub(super) decryption_threshold: u64,
}

/// q_dec = floor(n / 3) + 1. Setup, ballot release, and finality use the full
/// roster (= n).
pub(in crate::bgv) const fn decryption_threshold_for_participant_count(
    participant_count: u64,
) -> u64 {
    participant_count / 3 + 1
}

pub(in crate::bgv) fn decryption_threshold_for_roster_length(
    participant_count: usize,
) -> CanonicalResult<usize> {
    let participant_count = u64::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "the setup participant count does not fit u64",
        )
    })?;
    usize::try_from(decryption_threshold_for_participant_count(
        participant_count,
    ))
    .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "the setup decryption threshold does not fit usize",
        )
    })
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
        decryption_threshold: decryption_threshold_for_participant_count(participant_count),
    }
}

pub(super) fn foundation_roster_parameters() -> AcceptedRosterParameters {
    roster_parameters_from_participant_count(FOUNDATION_ROSTER_PARTICIPANT_COUNT)
}

/// Roster parameters for the roster size declared in a setup context.
pub(super) fn accepted_roster_from_setup_context(
    setup_context: &Value,
) -> CanonicalResult<AcceptedRosterParameters> {
    let participant_count = setup_context
        .get("participantCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setupContext.participantCount is required and must be an unsigned integer",
            )
        })?;
    if !participant_count_is_supported(participant_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupContext.participantCount is outside the supported roster range",
        ));
    }
    Ok(roster_parameters_from_participant_count(participant_count))
}

pub(super) fn accepted_roster_from_package(
    setup_package: &Value,
) -> CanonicalResult<AcceptedRosterParameters> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupPackage.setupContext is required",
        )
    })?;
    accepted_roster_from_setup_context(setup_context)
}
#[derive(Debug, Clone)]
pub(super) struct Refusal {
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: String,
    object_path: String,
}

impl Refusal {
    pub(super) fn new(
        refusal_reason: crate::foundation::RefusalReason,
        reason_code: &'static str,
        message: impl Into<String>,
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            refusal_reason,
            reason_code,
            message: message.into(),
            object_path: object_path.into(),
        }
    }
}

fn protocol_signature_refusal_reason(reason_code: &str) -> crate::foundation::RefusalReason {
    match reason_code {
        "InvalidSignature" | "WrongPublicKey" | "InvalidSignedRoot" => {
            crate::foundation::RefusalReason::InvalidSignature
        }
        "WrongObjectType" => crate::foundation::RefusalReason::WrongTypeOrLength,
        _ => crate::foundation::RefusalReason::MalformedEncoding,
    }
}

pub(super) type Refusals = Vec<Refusal>;

enum SetupPackageVerification {
    Verified,
    Refused(Refusals),
}

pub(crate) fn describe_collective_bgv_setup_parameters() -> CanonicalResult<Value> {
    describe_collective_bgv_setup_parameters_for_roster(&foundation_roster_parameters())
}

fn q_share_description_value() -> Value {
    json!({
        "primes": DATA_PRIMES,
    })
}

pub(crate) fn describe_collective_bgv_setup_parameters_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    Ok(json!({
        "setupParametersHash": setup_parameters_hash_for_roster(roster)?,
        "participantCount": roster.participant_count,
        "qShare": q_share_description_value(),
        "evaluatorKeySchedule": evaluator_key_schedule_value()?,
        "boundedDomainEvaluator": bounded_domain_evaluator_value_for_roster(roster)?,
    }))
}

// The setup parameters for a reduced roster size, used by test fixtures that
// exercise the accepted-setup path at a smaller participant count than the fixed
// foundation roster. The parameters hash is derived from the roster, so the
// reduced-roster setup context binds the hash the verifier recomputes.
pub(crate) fn describe_collective_bgv_setup_parameters_for_participant_count(
    participant_count: u64,
) -> CanonicalResult<Value> {
    describe_collective_bgv_setup_parameters_for_roster(&roster_parameters_from_participant_count(
        participant_count,
    ))
}

pub(crate) fn verify_collective_bgv_setup_package_in_session_from_request(
    request: &Value,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Value> {
    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupPackage is required",
        )
    })?;
    verify_collective_bgv_setup_package_in_owned_session(
        setup_package,
        request,
        proof_binding_session,
        &[],
        POLYNOMIAL_DEGREE,
    )
}

#[cfg(test)]
pub(crate) fn verify_collective_bgv_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Value> {
    verify_collective_bgv_setup_package_inner(setup_package, request, &[])
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_collective_bgv_setup_intent_for_test(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    if let Some(refusals) = verify_context(setup_package, &json!({}))? {
        return Ok(verification_response(refusals));
    }
    let registrations = match verify_setup_intent(setup_package)? {
        SetupIntentVerification::Verified(registrations) => registrations,
        SetupIntentVerification::Refused(refusals) => {
            return Ok(verification_response(refusals));
        }
    };
    if let Some(refusals) = verify_setup_intent_roster_hash(setup_package, &registrations)? {
        return Ok(verification_response(refusals));
    }

    Ok(accepted_setup_verification_response())
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_collective_bgv_setup_package_for_test_ring_degree_in_proof_binding_session(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    expected_ring_degree: usize,
) -> CanonicalResult<Value> {
    verify_collective_bgv_setup_package_in_owned_session(
        setup_package,
        request,
        proof_binding_session,
        &[],
        expected_ring_degree,
    )
}

#[cfg(test)]
fn verify_collective_bgv_setup_package_inner(
    setup_package: &Value,
    request: &Value,
    proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
) -> CanonicalResult<Value> {
    let proof_binding_session = crate::bgv::setup::AcceptedSetupProofBindingSession::begin_fresh()?;
    verify_collective_bgv_setup_package_in_owned_session(
        setup_package,
        request,
        proof_binding_session,
        proof_binding_leases,
        POLYNOMIAL_DEGREE,
    )
}

fn verify_collective_bgv_setup_package_in_owned_session(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    #[cfg(test)] proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
    #[cfg(not(test))] _proof_binding_leases: &[()],
    expected_ring_degree: usize,
) -> CanonicalResult<Value> {
    #[cfg(test)]
    for proof_binding_lease in proof_binding_leases {
        if let Err(error) = crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
            proof_binding_session.session_handle,
            proof_binding_lease,
        ) {
            let _ = crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
            );
            return Err(error);
        }
    }

    if !setup_package.is_object() {
        let refusals = setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::MalformedEncoding,
                "setupPackageNotObject",
                "setupPackage must be a JSON object",
                "setupPackage".to_string(),
            )],
        );
        crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
            proof_binding_session.session_handle,
        )?;
        return Ok(verification_response(refusals));
    }
    match verify_collective_setup_package(
        setup_package,
        request,
        &proof_binding_session,
        expected_ring_degree,
    ) {
        Ok(SetupPackageVerification::Verified) => {
            crate::bgv::setup::finish_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
            )?;
            Ok(accepted_setup_verification_response())
        }
        Ok(SetupPackageVerification::Refused(refusals)) => {
            crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
            )?;
            Ok(verification_response(refusals))
        }
        Err(error) => {
            let _ = crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
                proof_binding_session.session_handle,
            );
            Err(error)
        }
    }
}

fn verify_collective_setup_package(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    expected_ring_degree: usize,
) -> CanonicalResult<SetupPackageVerification> {
    let Some(object_type) = setup_package.get("objectType").and_then(Value::as_str) else {
        return Ok(outside_accepted_parameters(
            "setupPackage.objectType is required",
            "setupPackage.objectType",
        ));
    };
    if object_type != SETUP_PACKAGE_OBJECT_TYPE {
        return Ok(outside_accepted_parameters(
            format!(
                "setupPackage.objectType must be {SETUP_PACKAGE_OBJECT_TYPE}, not {object_type}"
            ),
            "setupPackage.objectType",
        ));
    }
    if let Some(refusals) = verify_context(setup_package, request)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    let setup_intent_registrations = match verify_setup_intent(setup_package)? {
        SetupIntentVerification::Verified(registrations) => registrations,
        SetupIntentVerification::Refused(refusals) => {
            return Ok(SetupPackageVerification::Refused(refusals));
        }
    };
    if let Some(refusals) =
        verify_setup_intent_roster_hash(setup_package, &setup_intent_registrations)?
    {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_common_randomness(setup_package, &setup_intent_registrations)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_expected_setup_package_hash(setup_package, request)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) =
        verify_private_vss_envelope_commitments(setup_package, &setup_intent_registrations)?
    {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_vss_complaints(setup_package, &setup_intent_registrations)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) =
        verify_vss_share_acceptances(setup_package, &setup_intent_registrations)?
    {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_declared_vss_ring_degree(setup_package, expected_ring_degree) {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    let expected_setup_trustees = expected_trustees_from_setup_intent(&setup_intent_registrations);
    let verified_ring_degree = match verify_vss_public_material(
        setup_package,
        &expected_setup_trustees,
        Some(proof_binding_session),
    )? {
        VssPublicMaterialVerification::Verified { ring_degree } => ring_degree,
        VssPublicMaterialVerification::Refused(refusals) => {
            return Ok(SetupPackageVerification::Refused(refusals));
        }
    };
    let verified_same_secret_bridge = match verify_same_secret_bridge_statement_set(
        setup_package,
        Some(proof_binding_session),
    )? {
        SameSecretBridgeVerification::Verified(verified_material) => verified_material,
        SameSecretBridgeVerification::Refused(refusals) => {
            return Ok(SetupPackageVerification::Refused(refusals));
        }
    };
    if let Some(refusals) = verify_public_key_shares(setup_package, &setup_intent_registrations)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    let public_key_share_material_bindings = match verify_public_key_share_succinct_proofs(
        setup_package,
        Some(&verified_same_secret_bridge),
        verified_ring_degree,
        proof_binding_session,
    )? {
        PublicKeyShareSuccinctProofVerification::Verified(material_bindings) => material_bindings,
        PublicKeyShareSuccinctProofVerification::Refused(refusals) => {
            return Ok(SetupPackageVerification::Refused(refusals));
        }
    };
    if let Some(refusals) = verify_collective_public_key_material(
        setup_package,
        verified_ring_degree,
        &public_key_share_material_bindings,
    )? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_pending_evaluation_key_material_boundary(
        setup_package,
        Some(&verified_same_secret_bridge),
        proof_binding_session,
        &setup_intent_registrations,
    )? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    Ok(SetupPackageVerification::Verified)
}

fn verify_declared_vss_ring_degree(
    setup_package: &Value,
    expected_ring_degree: usize,
) -> Option<Refusals> {
    let Some(statement) = setup_package.get("vssShareLinkageStatement") else {
        return Some(setup_refusals(
            vec!["vssShareLinkageStatement".to_string()],
            Vec::new(),
        ));
    };
    if !statement.is_object() {
        return Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::MalformedEncoding,
                "vssShareLinkageStatementNotObject",
                "vssShareLinkageStatement must be an object",
                "setupPackage.vssShareLinkageStatement",
            )],
        ));
    }
    let Some(ring_degree_value) = statement.get("ringDegree") else {
        return Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "vssShareLinkageRingDegreeMissing",
                "vssShareLinkageStatement.ringDegree is required",
                "setupPackage.vssShareLinkageStatement.ringDegree",
            )],
        ));
    };
    let Some(ring_degree) = ring_degree_value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
    else {
        return Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::WrongTypeOrLength,
                "vssShareLinkageRingDegreeTypeMismatch",
                "vssShareLinkageStatement.ringDegree must be an unsigned integer that fits usize",
                "setupPackage.vssShareLinkageStatement.ringDegree",
            )],
        ));
    };
    if ring_degree != expected_ring_degree {
        return Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::OutsideSupportedProfile,
                "outsideCollectiveBgvSetupParameters",
                "the declared setup ring degree is outside the selected verification profile",
                "setupPackage.vssShareLinkageStatement.ringDegree",
            )],
        ));
    }

    None
}

fn verify_expected_setup_package_hash(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Refusals>> {
    let Some(expected_hash_from_request) = request.get("expectedSetupPackageHash") else {
        return Ok(None);
    };
    let expected_hash_from_request = expected_hash_from_request.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "expectedSetupPackageHash must be a string",
        )
    })?;
    validate_hash_string(expected_hash_from_request, "expectedSetupPackageHash")?;
    let setup_package_hash = derive_collective_setup_package_hash(setup_package)?;
    if expected_hash_from_request != setup_package_hash {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::WrongHashOrRoot,
                "expectedSetupPackageHashMismatch",
                "setup package hash does not match expectedSetupPackageHash",
                "expectedSetupPackageHash".to_string(),
            )],
        )));
    }

    Ok(None)
}

pub(in crate::bgv) fn derive_collective_setup_package_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash_omitting_field_paths(
        setup_package,
        &[&[
            CanonicalJsonPathSegment::ObjectField("privateVssEnvelopeCommitments"),
            CanonicalJsonPathSegment::ObjectField("envelopeReferences"),
            CanonicalJsonPathSegment::ArrayElement,
            CanonicalJsonPathSegment::ObjectField("encryptedEnvelope"),
        ]],
    )
}

fn accepted_setup_verification_response() -> Value {
    verification_response(Vec::new())
}

fn outside_accepted_parameters(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> SetupPackageVerification {
    SetupPackageVerification::Refused(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            crate::foundation::RefusalReason::OutsideSupportedProfile,
            "outsideCollectiveBgvSetupParameters",
            message,
            object_path.into(),
        )],
    ))
}

pub(super) fn setup_refusals(
    missing_objects: Vec<String>,
    mut refused_objects: Vec<Refusal>,
) -> Refusals {
    refused_objects.extend(missing_objects.into_iter().map(|missing_object| {
        Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "setupObjectMissing",
            "A required setup object is missing.",
            format!("setupPackage.{missing_object}"),
        )
    }));
    refused_objects
}

fn verification_response(refused_objects: Refusals) -> Value {
    match refused_objects.first() {
        None => json!({
            "isValid": true,
            "value": {},
        }),
        Some(refusal) => json!({
            "isValid": false,
            "refusalReason": refusal.refusal_reason.name(),
        }),
    }
}

mod binding_checks;
mod setup_parameters;

use binding_checks::*;
use setup_parameters::*;

pub(super) use binding_checks::{accepted_vss_coefficient_commitment_root, setup_context_hash};
pub(in crate::bgv::setup) use setup_parameters::expected_required_galois_key_schedule;
pub(super) use setup_parameters::setup_parameters_hash_for_roster;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collective_setup_package_hash_omits_only_transported_private_envelopes() {
        let setup_package = json!({
            "objectType": "CollectiveBgvSetupPackage",
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
            },
        });
        let mut reference_hash_input = setup_package.clone();
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
        changed_excluded_fields["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
            ["ciphertext"] = json!("changed-excluded-private-envelope");
        assert_eq!(
            derive_collective_setup_package_hash(&changed_excluded_fields)
                .expect("hash with changed excluded fields"),
            expected_hash
        );

        let mut changed_bound_field = setup_package.clone();
        changed_bound_field["nested"]["encryptedEnvelope"] = json!("changed-bound-value");
        assert_ne!(
            derive_collective_setup_package_hash(&changed_bound_field)
                .expect("changed filtered hash"),
            expected_hash
        );

        let mut malformed_nested_array = setup_package.clone();
        malformed_nested_array["privateVssEnvelopeCommitments"]["envelopeReferences"] = json!([[{
            "encryptedEnvelope": "still-bound-inside-a-nested-array",
            "encryptedEnvelopeHash": "nested-envelope-hash",
        }]]);
        let malformed_nested_array_reference =
            derive_canonical_object_hash(&malformed_nested_array)
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
            let malformed_container_reference = derive_canonical_object_hash(&malformed_container)
                .expect("malformed container reference hash");
            assert_eq!(
                derive_collective_setup_package_hash(&malformed_container)
                    .expect("filtered malformed container hash"),
                malformed_container_reference
            );
        }
    }

    #[test]
    fn expected_setup_package_hash_authenticates_canonical_package_bytes() {
        let setup_package = json!({
            "objectType": "SetupPackage",
            "payload": "package bytes",
        });
        let setup_package_hash =
            derive_collective_setup_package_hash(&setup_package).expect("setup package hash");
        let matching_request = json!({ "expectedSetupPackageHash": setup_package_hash });
        assert!(
            verify_expected_setup_package_hash(&setup_package, &matching_request)
                .expect("matching expected setup package hash")
                .is_none()
        );

        let mismatching_request = json!({ "expectedSetupPackageHash": "0".repeat(128) });
        let refusals = verify_expected_setup_package_hash(&setup_package, &mismatching_request)
            .expect("mismatching expected setup package hash")
            .expect("hash mismatch refusal");
        assert_eq!(
            refusals[0].refusal_reason,
            crate::foundation::RefusalReason::WrongHashOrRoot
        );
    }
}
