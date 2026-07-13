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
use self::evaluation_key_material_transport::{
    evaluation_key_material_refusal, verify_evaluation_key_share_component_material_transport,
};
use self::evaluation_key_proof_checks::verify_trustee_evaluation_key_proofs;
#[cfg(test)]
pub(in crate::bgv::setup) use self::evaluation_key_proof_checks::{
    TrusteeEvaluationKeyStatementInputs, trustee_evaluation_key_proof_verification_binding_hash,
    trustee_evaluation_key_statement_from_package,
};
use self::evaluation_key_share_rounds::{
    evaluation_key_proof_common_binding, expected_galois_key_switch_seed,
    expected_relinearization_key_switch_seed, galois_key_share_material_for_schedule,
    scheduled_relinearization_levels, verify_galois_key_share_batches,
    verify_galois_key_switch_sample_binding, verify_relinearization_key_share_rounds,
    verify_relinearization_key_switch_sample_binding,
};
use self::evaluator_key_schedule::{
    verify_context_fields_match, verify_evaluator_key_schedule,
    verify_pending_evaluation_key_material_boundary,
};
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    verify_private_vss_envelope_commitments,
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
use self::public_key_shares::{
    PublicKeyCommonBinding, public_key_common_binding, public_key_refusal,
    public_key_share_records_by_roster_position, verify_public_key_share_succinct_proofs,
    verify_public_key_shares,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_shares::{
    public_key_share_succinct_proof_material_root,
    public_key_share_succinct_proof_verification_binding_hash,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::same_secret_bridge_verification::verified_same_secret_bridge_material_from_package;
use self::setup_context::verify_context;
pub(crate) use self::setup_intent::accepted_setup_participant_roster_from_package;
use self::setup_intent::{
    SetupIntentVerification, expected_trustees_from_setup_intent, setup_context_string,
    verify_setup_intent, verify_setup_intent_roster_hash,
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
        DecodedEvaluationKeyShareComponentMaterial,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        EvaluationKeyShareDerivedMaterialBinding, EvaluationKeyShareProofFamily,
        component_b_vectors_from_record,
    },
    setup_proof::{
        SetupProofMaterialBytes, SetupProofMaterialMap, SetupProofMaterialTransportFamily,
    },
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
const PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE: &str = "PublicKeyShareMaterialSet";
const PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "PublicKeyShareMaterial";
pub(super) const PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareMaterial";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC: &[u8; 8] = b"SLPKSMV1";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION: u64 = 1;
const PUBLIC_KEY_SHARE_SUCCINCT_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareSuccinctProofSet";
const PUBLIC_KEY_SHARE_SUCCINCT_PROOF_OBJECT_TYPE: &str = "PublicKeyShareSuccinctProof";
const COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE: &str = "CollectivePublicKey";
const EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE: &str = "EvaluatorKeySchedule";
const RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE: &str = "RelinearizationKeyShareRounds";
const RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundOne";
const RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundTwo";
const GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE: &str = "GaloisKeyShareBatch";
const GALOIS_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "GaloisKeyShareMaterial";
const TRUSTEE_EVALUATION_KEY_PROOF_SET_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProofSet";
const TRUSTEE_EVALUATION_KEY_PROOF_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProof";
use super::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY;
const PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitmentSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitment";
const PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE: &str = "PrivateVssEnvelopeAad";
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
    reason_code: &'static str,
    message: String,
    object_path: String,
}

impl Refusal {
    pub(super) fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
            object_path: object_path.into(),
        }
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
        "objectType": "QSharePrimeList",
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
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    verify_collective_bgv_setup_package_in_owned_session(
        setup_package,
        request,
        proof_binding_session,
        &[],
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
pub(in crate::bgv::setup) fn verify_collective_bgv_setup_package_with_proof_binding_leases(
    setup_package: &Value,
    request: &Value,
    proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
) -> CanonicalResult<Value> {
    verify_collective_bgv_setup_package_inner(setup_package, request, proof_binding_leases)
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_collective_bgv_setup_package_in_proof_binding_session(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Value> {
    verify_collective_bgv_setup_package_in_owned_session(
        setup_package,
        request,
        proof_binding_session,
        &[],
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
    )
}

fn verify_collective_bgv_setup_package_in_owned_session(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    #[cfg(test)] proof_binding_leases: &[crate::bgv::setup::CanonicalSetupProofBindingLease],
    #[cfg(not(test))] _proof_binding_leases: &[()],
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
    match verify_collective_setup_package(setup_package, request, &proof_binding_session) {
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
    if let Some(refusals) = verify_setup_package_hash(setup_package, request)? {
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
    match verify_vss_public_material(setup_package, request, Some(proof_binding_session))? {
        VssPublicMaterialVerification::Verified => {}
        VssPublicMaterialVerification::Refused(refusals) => {
            return Ok(SetupPackageVerification::Refused(refusals));
        }
    }
    let verified_same_secret_bridge = match verify_same_secret_bridge_statement_set(
        setup_package,
        request,
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
    if let Some(refusals) = verify_public_key_share_succinct_proofs(
        setup_package,
        request,
        Some(&verified_same_secret_bridge),
        proof_binding_session,
    )? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) =
        verify_collective_public_key_material(setup_package, request, proof_binding_session)?
    {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_evaluator_key_schedule(setup_package)? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_pending_evaluation_key_material_boundary(
        setup_package,
        request,
        Some(&verified_same_secret_bridge),
        proof_binding_session,
        &setup_intent_registrations,
    )? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    if let Some(refusals) = verify_evaluation_key_share_component_material_transport(
        setup_package,
        request,
        proof_binding_session,
    )? {
        return Ok(SetupPackageVerification::Refused(refusals));
    }
    Ok(SetupPackageVerification::Verified)
}

fn verify_setup_package_hash(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Refusals>> {
    let Some(setup_package_hash) = setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(setup_refusals(
            vec!["setupPackageHash".to_string()],
            Vec::new(),
        )));
    };
    validate_hash_string(setup_package_hash, "setupPackage.setupPackageHash")?;

    let expected_hash = derive_collective_setup_package_hash(setup_package)?;
    if setup_package_hash != expected_hash {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                "setupPackageHashMismatch",
                "SetupPackageHash does not match the canonical setup package payload",
                "setupPackage.setupPackageHash".to_string(),
            )],
        )));
    }
    if let Some(expected_hash_from_request) = request
        .get("expectedSetupPackageHash")
        .and_then(Value::as_str)
    {
        validate_hash_string(expected_hash_from_request, "expectedSetupPackageHash")?;
        if expected_hash_from_request != setup_package_hash {
            return Ok(Some(setup_refusals(
                Vec::new(),
                vec![Refusal::new(
                    "expectedSetupPackageHashMismatch",
                    "setup package hash does not match expectedSetupPackageHash",
                    "expectedSetupPackageHash".to_string(),
                )],
            )));
        }
    }

    Ok(None)
}

pub(in crate::bgv) fn derive_collective_setup_package_hash(
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
            "setupObjectMissing",
            "A required setup object is missing.",
            format!("setupPackage.{missing_object}"),
        )
    }));
    refused_objects
}

fn verification_response(refused_objects: Refusals) -> Value {
    let accepted = refused_objects.is_empty();

    json!({
        "isValid": accepted,
        "refusedObjects": refused_objects
            .into_iter()
            .map(|refusal| json!({
                "reasonCode": refusal.reason_code,
                "message": refusal.message,
                "objectPath": refusal.object_path,
            }))
            .collect::<Vec<_>>(),
    })
}

mod binding_checks;
mod setup_parameters;

use binding_checks::*;
use setup_parameters::*;

pub(super) use binding_checks::{accepted_vss_coefficient_commitment_root, setup_context_hash};
pub(super) use setup_parameters::setup_parameters_hash_for_roster;

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
