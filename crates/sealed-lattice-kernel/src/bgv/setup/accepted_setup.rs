use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigUint;
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

use super::*;
use super::{
    commitment::{
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_PROFILE_ID,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
        SETUP_COMMITMENT_ROW_COUNT, parse_setup_commitment_full_value,
        setup_commitment_matrix_sampled_entries, setup_commitment_modulus_limb_values,
        setup_commitment_modulus_product, setup_commitment_profile_hash,
        setup_commitment_profile_value, setup_commitment_root,
    },
    public_key_share_proof::{
        PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS, PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        PublicKeyShareLnpProofVerificationInput, public_key_share_coefficient_vector_hash,
        public_key_share_lnp_relation_proof_bytes_hash, verify_public_key_share_lnp_relation_proof,
    },
    same_secret_proof::{
        SAME_SECRET_LNP_PROOF_MODEL_STATUS, SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        same_secret_lnp_relation_proof_bytes_hash, verify_same_secret_lnp_relation_proof,
    },
    sampling::reduce_unbiased_u64,
    setup_proof::{
        SETUP_PROOF_BYTES_DOMAIN, SETUP_PROOF_CHALLENGE_BITS,
        SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND, SETUP_PROOF_CHALLENGE_COUNT,
        SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS, SETUP_PROOF_CHALLENGE_DOMAIN,
        SETUP_PROOF_CHALLENGE_SAMPLER, SETUP_PROOF_CHALLENGE_SPACE, SETUP_PROOF_FAMILIES,
        SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS, SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS, SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_PROFILE_ID, SETUP_PROOF_SERIALIZATION,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES, SetupProofMaterialReferenceInput,
        setup_proof_material_reference_root, setup_proof_material_transport_hashes,
    },
    threshold_share_commitments::{
        derive_threshold_share_commitment_set_from_parts,
        derive_threshold_share_commitments_from_transport_request,
        verify_constant_vss_commitments_from_transport_request,
    },
    vss::{
        carry_aware_vss_share_relation_profile_hash, carry_aware_vss_share_relation_profile_value,
    },
};
use crate::bgv::coefficient_codec::coefficient_vector_from_le_hex;
use crate::bgv::evaluator::top_k::{
    DIRECT_COMPARISON_OUTPUT_LEVEL, direct_score_packing_basis_galois_elements,
    packed_rank_forward_basis_galois_elements, packed_rank_return_basis_galois_elements,
};
use crate::bgv::profile::SPECIAL_PRIME;
use crate::protocol_signatures::{
    ProtocolSignatureExpectation, verify_protocol_signature_envelope,
};
use crate::transcript_core::decode_hex;

pub(crate) const COLLECTIVE_BGV_SETUP_PROFILE_ID: &str = "CollectiveBgvSetup-v1";

const SETUP_PACKAGE_OBJECT_TYPE: &str = "SetupPackage";
const SAME_SECRET_CONSISTENCY_OBJECT_TYPE: &str = "SameSecretConsistencyStatementSet";
const SAME_SECRET_STATEMENT_OBJECT_TYPE: &str = "SameSecretConsistencyStatement";
const SAME_SECRET_PROOF_FAMILY_BINDING_OBJECT_TYPE: &str = "SameSecretProofFamilyBinding";
const SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretProofMaterialSet";
const SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE: &str = "SetupTransportedSameSecretProofMaterial";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterialSet";
const PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicKeyShareProofMaterial";
const TRUSTEE_SECRET_COMMITMENT_OBJECT_TYPE: &str = "TrusteeSecretCommitment";
const PUBLIC_KEY_SHARE_SET_OBJECT_TYPE: &str = "PublicKeyShareSet";
const PUBLIC_KEY_SHARE_OBJECT_TYPE: &str = "PublicKeyShare";
const PUBLIC_KEY_SHARE_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareProofSet";
const PUBLIC_KEY_SHARE_PROOF_OBJECT_TYPE: &str = "PublicKeyShareProof";
const PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE: &str = "PublicKeyShareMaterialSet";
const PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "PublicKeyShareMaterial";
const PUBLIC_KEY_SHARE_LNP_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareLnpProofSet";
const PUBLIC_KEY_SHARE_LNP_PROOF_OBJECT_TYPE: &str = "PublicKeyShareLnpProof";
const COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE: &str = "CollectivePublicKey";
const EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE: &str = "EvaluatorKeySchedule";
const REQUIRED_GALOIS_SET_OBJECT_TYPE: &str = "RequiredGaloisSet";
const RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE: &str = "RelinearizationKeyShareRounds";
const RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundOne";
const RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundTwo";
const GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE: &str = "GaloisKeyShareBatch";
const RELINEARIZATION_PROOF_VERIFICATION_STATUS: &str =
    "lnp-relinearization-proof-records-bound-review-gated";
const RELINEARIZATION_PROOF_MODEL_STATUS: &str = "round-one and round-two proof records are root-bound to the frozen evaluator schedule, accepted same-secret proof roots, same-secret proof-family root, public-key LNP proof-set root, relinearization CRP root, decomposition level, round-one aggregate root, and round-two share roots; algebraic LNP verifier and full tbox quadratic/range closure remain required before evaluation-key acceptance";
const GALOIS_PROOF_VERIFICATION_STATUS: &str = "lnp-galois-proof-records-bound-review-gated";
const GALOIS_PROOF_MODEL_STATUS: &str = "Galois proof batches are root-bound to the frozen evaluator schedule, RequiredGaloisSetHash, accepted same-secret proof roots, same-secret proof-family root, public-key LNP proof-set root, Galois CRP root, exact automorphism/level schedule, and per-trustee batch roots; algebraic LNP verifier and full tbox closure remain required before evaluation-key acceptance";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_SET_OBJECT_TYPE: &str =
    "VssCoefficientCommitmentMaterialSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitmentSet";
const PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE: &str = "PrivateVssEnvelopeCommitment";
const PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE: &str = "PrivateVssEnvelopeAad";
const ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE: &str = "EncryptedPrivateVssShareEnvelope";
const FIRST_PROFILE_PARTICIPANT_COUNT: u64 = 10;
const FIRST_PROFILE_SETUP_COMPLETION_QUORUM: u64 = 10;
const FIRST_PROFILE_BALLOT_RELEASE_QUORUM: u64 = 10;
const FIRST_PROFILE_FINALITY_QUORUM: u64 = 10;
const FIRST_PROFILE_DECRYPTION_THRESHOLD: u64 = 4;
const SETUP_TRANSPORT_PROFILE_ID: &str = "sealed-lattice-setup-binary-chunked-transport-v1";
const SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE: &str = "SetupTransportCertificate";
const SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupTransportChunkManifest";
const SETUP_TRANSPORTED_OBJECT_TYPE: &str = "SetupTransportedObject";
const SETUP_COMMITMENT_SECURITY_CERTIFICATE_OBJECT_TYPE: &str =
    "SetupCommitmentSecurityCertificate";
const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
const SETUP_TRANSPORT_STORAGE_QUOTA_BYTES: u64 = 2_147_483_648;
const SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES: u64 = 1_572_864;
const SETUP_TRANSPORT_COPY_COUNT_LIMIT: u64 = 2;
const SETUP_TRANSPORT_STREAM_ORDER: &str = "ascending-chunk-index";
const SETUP_TRANSPORT_RESUME_POLICY: &str = "chunk-index-checkpointed-by-hash";
const SETUP_TRANSPORT_LAZY_LOADING_POLICY: &str = "root-addressed-large-object-loading";
const SETUP_TRANSPORTED_VSS_MATERIAL_NAME: &str = "vssCoefficientCommitmentMaterial";
const SETUP_TRANSPORTED_VSS_MATERIAL_ROLE: &str = "public-vss-coefficient-commitment-material";
const SETUP_TRANSPORTED_OBJECT_LOADING_POLICY: &str = "stream-verified-before-object-use";
const HE_SECURITY_CERTIFICATE_OBJECT_TYPE: &str = "BgvHeSecurityCertificate";
const PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID: &str =
    "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1";
const PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER: u64 = 6;
const PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER: u64 = 7;
const EVALUATOR_REPLAY_PROFILE_LABEL: &str = "direct-encrypted-ballot-evaluator-replay";
const EVALUATOR_PACKING_PROFILE_LABEL: &str = "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing";
const SAME_SECRET_BOUND_PROOF_FAMILIES: &[&str] = &[
    "vss-constant-relation",
    "public-key-share",
    "relinearization-key-share",
    "galois-key-share",
];

const ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES: &[&str] = &[
    "setupSeed",
    "setupSeedHash",
    "privateSetupSeedHash",
    "setupPrivateWitness",
    "trustedDealerBoundary",
    "trustedDealerSetup",
    "lattigoSetupMaterial",
    "lattigoPublicKey",
    "lattigoRelinearizationKey",
    "lattigoGaloisKey",
    "dealerSuppliedThresholdShareCommitments",
    "dealerThresholdShareCommitments",
    "trustedThresholdShareCommitments",
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
    ("galoisKeyBatchProofs", 12),
    ("setupPackageAssembly", 13),
    ("setupPackageVerification", 14),
];

const REQUIRED_FINAL_OBJECTS: &[&str] = &[
    "qShare",
    "commonRandomness",
    "vssCoefficientCommitments",
    "vssCoefficientCommitmentMaterial",
    "privateVssEnvelopeCommitments",
    "privateVssEnvelopeCommitmentRoot",
    "vssShareAcceptances",
    "thresholdShareCommitments",
    "sameSecretConsistency",
    "publicKeyShares",
    "publicKeyShareProofs",
    "evaluatorKeySchedule",
    "relinearizationKeyShareRounds",
    "galoisKeyShareBatches",
    "evaluationKeys",
    "setupCommitmentSecurityCertificate",
    "setupCommitmentSecurityCertificateHash",
    "setupTransportCertificate",
    "setupTransportCertificateHash",
    "heSecurityCertificate",
    "heSecurityCertificateHash",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifierStatus {
    Accepted,
    Pending,
    Refused,
    Aborted,
    ForkDetected,
    OutsideProfile,
}

impl VerifierStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Refused => "refused",
            Self::Aborted => "aborted",
            Self::ForkDetected => "forkDetected",
            Self::OutsideProfile => "outsideProfile",
        }
    }
}

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

#[derive(Clone)]
struct PrivateVssEnvelopeBinding {
    dealer_identity: String,
    recipient_identity: String,
    dealer_commitment_root: String,
    private_envelope_hash: String,
    local_verification_root: String,
}

type PrivateVssEnvelopeBindingMap = BTreeMap<(u64, u64), PrivateVssEnvelopeBinding>;

struct MailboxPublicKeyBinding {
    public_key_hash: String,
    public_key_bytes_hash: String,
}

struct PhaseParticipantPayloadInput<'a> {
    phase_identifier: &'a str,
    phase_number: u64,
    setup_context: &'a Value,
    trustee_identity: &'a str,
    roster_position: u64,
    recovery_epoch: u64,
    device_epoch: u64,
    signing_public_key_hash: &'a str,
    private_vss_mailbox_public_key_hash: Option<&'a str>,
    private_vss_mailbox_public_key_bytes_hash: Option<&'a str>,
}

enum VerificationFlow {
    Continue,
    Stop(Value),
}

struct SameSecretTrusteeBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    vss_dealer_commitment_root: String,
    constant_commitment_roots: Vec<Value>,
}

struct SameSecretStatementBinding {
    trustee_identity: String,
    trustee_secret_commitment_root: String,
    same_secret_statement_root: String,
}

struct SameSecretProofBinding {
    trustee_identity: String,
    trustee_secret_commitment_root: String,
    same_secret_statement_root: String,
    same_secret_proof_family_binding_root: String,
    same_secret_proof_root: String,
}

struct PublicKeyCommonBinding {
    public_matrix_seed_hash: String,
    public_key_crp_root: String,
    public_a_polynomial_root: String,
}

struct PublicKeyShareBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    public_key_share_root: String,
    trustee_secret_commitment_root: String,
    same_secret_statement_root: String,
}

#[derive(Clone)]
struct PublicKeyShareMaterialBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    public_key_share_root: String,
    public_key_share_material_root: String,
    coefficients_by_limb: Vec<Vec<u64>>,
}

pub(crate) fn describe_collective_bgv_setup_profile() -> CanonicalResult<Value> {
    Ok(json!({
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "objectType": SETUP_PACKAGE_OBJECT_TYPE,
        "adversaryModel": "active-static",
        "livenessModel": "secure-with-abort",
        "sharingModel": "recipient-verified-vss",
        "sharingDomain": "per-rns-prime",
        "completionRule": "full-roster",
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "qSetupComplete": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
        "qBallotRelease": FIRST_PROFILE_BALLOT_RELEASE_QUORUM,
        "qFinal": FIRST_PROFILE_FINALITY_QUORUM,
        "qDec": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "qShare": q_share_value(),
        "qShareHash": q_share_hash()?,
        "carryAwareVssShareRelationProfile": carry_aware_vss_share_relation_profile_value(),
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash()?,
        "commitmentProfile": setup_commitment_profile_value()?,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "publicVssCommitmentMaterialSizeProfile": public_vss_commitment_material_size_profile_value()?,
        "publicVssCommitmentMaterialSizeProfileHash": public_vss_commitment_material_size_profile_hash()?,
        "setupProofProfile": setup_proof_profile_value()?,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "setupTransportProfile": setup_transport_profile_value()?,
        "setupTransportProfileHash": setup_transport_profile_hash()?,
        "evaluatorKeyScheduleProfile": evaluator_key_schedule_profile_value()?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash()?,
        "verifierStatuses": [
            "accepted",
            "pending",
            "refused",
            "aborted",
            "forkDetected",
            "outsideProfile"
        ],
        "phaseOrder": phase_order_value(),
        "phaseOrderHash": phase_order_hash()?,
        "requiredFinalObjects": REQUIRED_FINAL_OBJECTS,
        "genericKeySwitchPolicy": "refused-unless-explicitly-required-by-frozen-evaluator-schedule",
        "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
        "forbiddenAcceptedPathFields": ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES,
    }))
}

pub(crate) fn verify_collective_bgv_setup_package_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "expectedManifestHash",
            "expectedRosterHash",
            "expectedSetupPackageHash",
            "setupPackage",
            "transportedPublicKeyShareProofMaterial",
            "transportedSameSecretProofMaterial",
            "transportedVssCoefficientCommitmentMaterial",
        ],
        "verifyCollectiveBgvSetupPackage",
    )?;
    reject_forbidden_setup_fields_for_context(request, "accepted collective BGV setup")?;
    reject_accepted_setup_forbidden_request_fields(request)?;

    let setup_package = request.get("setupPackage").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage is required",
        )
    })?;
    if !setup_package.is_object() {
        return verification_response(
            VerifierStatus::OutsideProfile,
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
        VerificationFlow::Continue => Ok(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec![
                "carry-aware VSS commitment opening checks".to_string(),
                "same-secret LNP proof verification".to_string(),
                "public-key share proof checks".to_string(),
                "relinearization round proof checks".to_string(),
                "Galois key batch proof checks".to_string(),
                "full-profile setup material streaming certificate".to_string(),
            ],
            Vec::new(),
            accepted_hashes_from_package(setup_package),
        )?),
        VerificationFlow::Stop(response) => Ok(response),
    }
}

pub(crate) fn derive_collective_bgv_setup_public_derivations_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["publicMatrixSeedHash"],
        "deriveCollectiveBgvSetupPublicDerivations",
    )?;
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

    derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash)
}

fn verify_collective_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<VerificationFlow> {
    let Some(object_type) = setup_package.get("objectType").and_then(Value::as_str) else {
        return outside_profile(
            "setupPackage.objectType is required",
            "setupPackage.objectType",
        );
    };
    if object_type != SETUP_PACKAGE_OBJECT_TYPE {
        return outside_profile(
            format!(
                "setupPackage.objectType must be {SETUP_PACKAGE_OBJECT_TYPE}, not {object_type}"
            ),
            "setupPackage.objectType",
        );
    }
    if setup_package.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return outside_profile(
            "setupPackage.objectVersion must be 1",
            "setupPackage.objectVersion",
        );
    }
    let Some(setup_profile_id) = setup_package.get("setupProfileId").and_then(Value::as_str) else {
        return outside_profile(
            "setupPackage.setupProfileId is required",
            "setupPackage.setupProfileId",
        );
    };
    if setup_profile_id != COLLECTIVE_BGV_SETUP_PROFILE_ID {
        return outside_profile(
            format!(
                "setupPackage.setupProfileId must be {COLLECTIVE_BGV_SETUP_PROFILE_ID}, not {setup_profile_id}"
            ),
            "setupPackage.setupProfileId",
        );
    }
    if let Err(error) = reject_forbidden_setup_package_secret_fields_for_context(
        setup_package,
        "accepted collective BGV setup verification",
    ) {
        return Ok(VerificationFlow::Stop(verification_response(
            VerifierStatus::Refused,
            None,
            Vec::new(),
            vec![Refusal::new(
                "secretMaterialPresent",
                error.message,
                "setupPackage".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if let Err(error) = reject_accepted_setup_forbidden_fields(setup_package) {
        return Ok(VerificationFlow::Stop(verification_response(
            VerifierStatus::Refused,
            None,
            Vec::new(),
            vec![Refusal::new(
                "acceptedPathForbiddenField",
                error.message,
                "setupPackage".to_string(),
            )],
            Vec::new(),
        )?));
    }

    if let Some(response) = verify_setup_package_hash(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
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
    if let Some(response) = verify_common_randomness(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_abort_absence(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_coefficient_commitments(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_coefficient_commitment_material(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_private_vss_envelope_commitments(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_complaints(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_final_objects(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_vss_share_acceptances(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_threshold_share_commitments(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_same_secret_consistency(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_optional_same_secret_lnp_proofs(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_shares(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_share_proofs(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_optional_public_key_share_lnp_proofs(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_collective_public_key_material(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_material_acceptance_boundary(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_evaluator_key_schedule(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_pending_evaluation_key_material_boundary(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_generic_key_switch_policy(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_commitment_security_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_transport_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_he_security_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_profile_ring_material(setup_package)? {
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
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["setupPackageHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(setup_package_hash, "setupPackage.setupPackageHash")?;

    let mut hash_input = setup_package.clone();
    hash_input
        .as_object_mut()
        .expect("setup package object was checked")
        .remove("setupPackageHash");
    let expected_hash = derive_protocol_hash("SetupPackageHash", &hash_input)?;
    if setup_package_hash != expected_hash {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
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
                VerifierStatus::Refused,
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

fn verify_context(setup_package: &Value, request: &Value) -> CanonicalResult<Option<Value>> {
    let Some(setup_context) = setup_package.get("setupContext") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupIntent"),
            vec!["setupContext".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !setup_context.is_object() {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupContextNotObject",
                "setupContext must be a JSON object",
                "setupPackage.setupContext".to_string(),
            )],
            Vec::new(),
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if setup_context.get(field_name).is_none() {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("setupIntent"),
                vec![format!("setupContext.{field_name}")],
                Vec::new(),
                Vec::new(),
            )?));
        }
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
    ] {
        let Some(field_value) = setup_context.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some("setupIntent"),
                Vec::new(),
                vec![Refusal::new(
                    "setupContextHashMalformed",
                    format!("setupContext.{field_name} must be a protocol hash"),
                    format!("setupPackage.setupContext.{field_name}"),
                )],
                Vec::new(),
            )?));
        };
        validate_hash_string(field_value, &format!("setupContext.{field_name}"))?;
    }
    if setup_context
        .get("ceremonyId")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupContextCeremonyMissing",
                "setupContext.ceremonyId must be a non-empty string",
                "setupPackage.setupContext.ceremonyId".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_context
        .get("setupEpoch")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupContextEpochMissing",
                "setupContext.setupEpoch must be a non-empty string",
                "setupPackage.setupContext.setupEpoch".to_string(),
            )],
            Vec::new(),
        )?));
    }

    let expected_setup_profile_hash = setup_profile_hash()?;
    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(expected_setup_profile_hash.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupProfileHashMismatch",
                "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
                "setupPackage.setupContext.setupProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
    }

    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("qSetupComplete", FIRST_PROFILE_SETUP_COMPLETION_QUORUM),
        ("qBallotRelease", FIRST_PROFILE_BALLOT_RELEASE_QUORUM),
        ("qFinal", FIRST_PROFILE_FINALITY_QUORUM),
        ("qDec", FIRST_PROFILE_DECRYPTION_THRESHOLD),
    ] {
        match setup_context.get(field_name).and_then(Value::as_u64) {
            Some(actual_value) if actual_value == expected_value => {}
            Some(_) => {
                return Ok(Some(verification_response(
                    VerifierStatus::OutsideProfile,
                    Some("setupIntent"),
                    Vec::new(),
                    vec![Refusal::new(
                        "firstProfileParameterMismatch",
                        format!(
                            "setupContext.{field_name} does not match the first accepted profile"
                        ),
                        format!("setupPackage.setupContext.{field_name}"),
                    )],
                    Vec::new(),
                )?));
            }
            None => {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("setupIntent"),
                    vec![format!("setupContext.{field_name}")],
                    Vec::new(),
                    Vec::new(),
                )?));
            }
        }
    }
    if setup_context.get("qShareHash").and_then(Value::as_str) != Some(q_share_hash()?.as_str()) {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "qShareHashMismatch",
                "setupContext.qShareHash does not match the accepted Q_share prime list",
                "setupPackage.setupContext.qShareHash".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "carryAwareVssRelationProfileHashMismatch",
                "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
                "setupPackage.setupContext.carryAwareVssShareRelationProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "commitmentProfileHashMismatch",
                "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
                "setupPackage.setupContext.commitmentProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
    }

    compare_expected_hash(
        request,
        setup_context,
        "expectedManifestHash",
        "manifestHash",
    )?;
    compare_expected_hash(request, setup_context, "expectedRosterHash", "rosterHash")?;

    Ok(None)
}

fn verify_q_share(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(q_share) = setup_package.get("qShare") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupIntent"),
            vec!["qShare".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if q_share != &q_share_value() {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "qShareMismatch",
                "qShare must be the exact ordered accepted RNS prime list",
                "setupPackage.qShare".to_string(),
            )],
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn q_share_hash() -> CanonicalResult<String> {
    derive_protocol_hash("QSharePrimeListHash", &q_share_value())
}

pub(super) fn accepted_setup_profile_hash() -> CanonicalResult<String> {
    setup_profile_hash()
}

pub(super) fn accepted_q_share_hash() -> CanonicalResult<String> {
    q_share_hash()
}

fn q_share_value() -> Value {
    json!({
        "objectType": "QSharePrimeList",
        "objectVersion": 1,
        "sharingDomain": "per-rns-prime",
        "primeOrder": "profile-order",
        "targetDecryptionReadiness": "refused-until-q-target-certificate-closes",
        "primes": DATA_PRIMES,
    })
}

fn setup_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash("CollectiveBgvSetupProfileHash", &setup_profile_binding()?)
}

fn setup_profile_binding() -> CanonicalResult<Value> {
    Ok(json!({
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "adversaryModel": "active-static",
        "livenessModel": "secure-with-abort",
        "sharingModel": "recipient-verified-vss",
        "sharingDomain": "per-rns-prime",
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "qSetupComplete": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
        "qBallotRelease": FIRST_PROFILE_BALLOT_RELEASE_QUORUM,
        "qFinal": FIRST_PROFILE_FINALITY_QUORUM,
        "qDec": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash()?,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
        "setupTransportProfileHash": setup_transport_profile_hash()?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash()?,
    }))
}

fn setup_proof_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash("SetupProofProfileHash", &setup_proof_profile_value()?)
}

fn setup_transport_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupTransportProfileHash",
        &setup_transport_profile_value()?,
    )
}

fn evaluator_key_schedule_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluatorKeyScheduleProfileHash",
        &evaluator_key_schedule_profile_value()?,
    )
}

fn public_vss_commitment_material_size_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicVssCommitmentMaterialSizeProfileHash",
        &public_vss_commitment_material_size_profile_value()?,
    )
}

fn public_vss_commitment_material_size_profile_value() -> CanonicalResult<Value> {
    let commitment_modulus_limb_count = setup_commitment_modulus_limb_values().len();
    let bytes_per_residue = 8_usize;
    let single_commitment_coefficient_bytes = commitment_modulus_limb_count
        * SETUP_COMMITMENT_ROW_COUNT
        * POLYNOMIAL_DEGREE
        * bytes_per_residue;
    let commitment_count = usize::try_from(FIRST_PROFILE_PARTICIPANT_COUNT)
        .expect("first-profile participant count fits usize")
        * DATA_PRIMES.len()
        * usize::try_from(FIRST_PROFILE_DECRYPTION_THRESHOLD)
            .expect("first-profile threshold fits usize");
    let full_material_coefficient_bytes = single_commitment_coefficient_bytes
        .checked_mul(commitment_count)
        .expect("full-profile VSS commitment material byte count fits usize");
    let bytes_per_mebibyte = 1024_usize * 1024_usize;

    Ok(json!({
        "objectType": "PublicVssCommitmentMaterialSizeProfile",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "measurementKind": "static-full-profile-coefficient-byte-accounting",
        "ringDegree": POLYNOMIAL_DEGREE,
        "ringDegreeStatus": "profile-ring",
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "rnsLimbCount": DATA_PRIMES.len(),
        "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "commitmentModulusLimbCount": commitment_modulus_limb_count,
        "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
        "bytesPerResidue": bytes_per_residue,
        "singleCommitmentCoefficientBytes": single_commitment_coefficient_bytes,
        "publishedCommitmentCount": commitment_count,
        "fullMaterialCoefficientBytes": full_material_coefficient_bytes,
        "fullMaterialCoefficientMebibytes": full_material_coefficient_bytes / bytes_per_mebibyte,
        "jsonOverheadStatus": "excluded-from-lower-bound",
        "streamingRequirement": "binary-chunked-stream-verification-with-one-commitment-resident",
        "mobileClosureStatus": "not-accepted-until-transport-and-memory-certificate",
    }))
}

fn setup_transport_profile_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupTransportProfile",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        "storageQuotaBytes": SETUP_TRANSPORT_STORAGE_QUOTA_BYTES,
        "largestSingleBufferBytes": SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        "copyCountLimit": SETUP_TRANSPORT_COPY_COUNT_LIMIT,
        "streamVerificationOrder": SETUP_TRANSPORT_STREAM_ORDER,
        "resumePolicy": SETUP_TRANSPORT_RESUME_POLICY,
        "lazyLoadingPolicy": SETUP_TRANSPORT_LAZY_LOADING_POLICY,
        "requiredTransportedObjects": [
            {
                "objectName": SETUP_TRANSPORTED_VSS_MATERIAL_NAME,
                "objectRole": SETUP_TRANSPORTED_VSS_MATERIAL_ROLE,
                "minimumByteLength": setup_transport_vss_material_byte_length()?,
            }
        ],
    }))
}

fn evaluator_key_schedule_profile_value() -> CanonicalResult<Value> {
    let required_galois_key_schedule = expected_required_galois_key_schedule()?;
    let required_galois_set_hash =
        expected_required_galois_set_hash(&required_galois_key_schedule)?;

    Ok(json!({
        "objectType": "EvaluatorKeyScheduleProfile",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "evaluatorProfile": EVALUATOR_REPLAY_PROFILE_LABEL,
        "packingProfile": EVALUATOR_PACKING_PROFILE_LABEL,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "rnsLimbCount": DATA_PRIMES.len(),
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": required_galois_key_schedule,
        "requiredGaloisSetHash": required_galois_set_hash,
        "genericKeySwitchPolicy": "refused-unless-explicitly-required",
        "genericKeySwitchProofStatus": "not-required-for-first-profile",
        "scheduleBindingStatus": "relinearization-and-galois-proof-verifiers-pending",
    }))
}

fn expected_relinearization_level_schedule() -> Value {
    Value::Array(
        (1..DATA_PRIMES.len())
            .map(|level| {
                json!({
                    "level": level,
                    "proofFamily": "relinearization-key-share",
                    "keyShareRounds": ["round-one", "round-two"],
                })
            })
            .collect(),
    )
}

fn expected_required_galois_key_schedule() -> CanonicalResult<Value> {
    let full_level = DATA_PRIMES.len() - 1;
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, full_level),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, full_level))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, DIRECT_COMPARISON_OUTPUT_LEVEL),
            "generator-ordered-packed-rank-return-basis",
        );
    }

    Ok(Value::Array(
        entries_by_rotation_and_level
            .into_iter()
            .map(|((rotation, level), purpose)| {
                json!({
                    "rotation": rotation,
                    "level": level,
                    "purpose": purpose,
                    "proofFamily": "galois-key-share",
                })
            })
            .collect(),
    ))
}

fn expected_required_galois_set_hash(
    required_galois_key_schedule: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "RequiredGaloisSetHash",
        &required_galois_set_value(required_galois_key_schedule.clone()),
    )
}

fn required_galois_set_value(required_galois_key_schedule: Value) -> Value {
    json!({
        "objectType": REQUIRED_GALOIS_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "evaluatorProfile": EVALUATOR_REPLAY_PROFILE_LABEL,
        "packingProfile": EVALUATOR_PACKING_PROFILE_LABEL,
        "rnsLimbCount": DATA_PRIMES.len(),
        "entries": required_galois_key_schedule,
    })
}

fn setup_proof_profile_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofProfile",
        "objectVersion": 1,
        "profileId": SETUP_PROOF_PROFILE_ID,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "proofSystem": "fixed-lnp-linear-relation-subset",
        "proofBackendBoundary": "sealed-lattice-rust-wasm-fixed-relations-only",
        "arbitraryRelationApi": "not-exposed",
        "relationModel": {
            "applicationRing": "Z_q[X]/(X^N+1)",
            "applicationRingDegree": POLYNOMIAL_DEGREE,
            "lnpTboxRing": "Z_qproof[X]/(X^d+1)",
            "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            "ringDegreeMapping": "full BGV polynomials are mapped into proof-ring polynomial vectors by the fixed isoring split",
            "rnsLimbCount": DATA_PRIMES.len(),
            "qShareHash": q_share_hash()?,
            "commitmentProfileHash": setup_commitment_profile_hash()?,
            "statementEncoding": "canonical-json-roots-plus-binary-proof-chunks",
            "relationForm": "A*witness = target + q_l*carry over lifted integers with explicit no-wrap bounds",
            "limbHandling": "relations are checked per accepted Q_share limb and bind one shared trustee secret where required"
        },
        "challengeBinding": {
            "transform": "Fiat-Shamir",
            "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
            "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
            "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
            "challengeDomainHash": setup_proof_challenge_domain_hash()?,
            "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
            "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
            "lnpTboxChallengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
            "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
            "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
            "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
            "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
            "qromStatus": "review-required-before-claim-closure",
            "transcriptBinding": [
                "setupProfileHash",
                "manifestHash",
                "rosterHash",
                "setupEpoch",
                "publicMatrixSeedHash",
                "proofFamily",
                "statementRoot",
                "proofChunkRoot"
            ]
        },
        "challengeSpaceAudit": super::setup_proof::setup_proof_challenge_space_audit_value(SETUP_PROOF_LNP_PROOF_RING_DEGREE)?,
        "witnessBounds": {
            "trusteeSecret": {
                "distribution": "coefficientwise-centered-ternary",
                "infinityNormBound": 1,
                "rnsBinding": "one short trustee secret is reduced into every accepted Q_share limb"
            },
            "vssOpeningCarry": {
                "domain": "non-negative-bounded-integer",
                "boundSource": "carry-aware-vss-share-opening-profile"
            },
            "publicKeyError": {
                "distribution": "accepted-error-support-pending-certificate",
                "requiredBeforeAcceptance": "proof verifier rejects missing support certificate"
            },
            "keySwitchError": {
                "distribution": "accepted-evaluation-key-error-support-pending-certificate",
                "requiredBeforeAcceptance": "proof verifier rejects missing evaluation-key support certificate"
            },
            "noWrapCarry": {
                "domain": "bounded-lifted-integer",
                "requiredBeforeAcceptance": "proof verifier rejects missing carry bounds"
            }
        },
        "proofFamilies": setup_proof_family_profiles()?,
        "sameSecretTboxParameterProfile": super::setup_proof::same_secret_lnp_tbox_parameter_profile_value()?,
        "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfile": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_value()?,
        "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
        "proofSerialization": {
            "encoding": SETUP_PROOF_SERIALIZATION,
            "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
            "lnpTboxByteLayoutProfile": super::setup_proof::setup_proof_lnp_tbox_byte_layout_profile_value(),
            "chunking": "required-for-large-proof-material",
            "chunkRootRequired": true,
            "statementRootRequired": true,
            "canonicalJsonRole": "root-bound metadata only"
        },
        "matrixDerivation": {
            "crpComponent": "proof-matrix-crp",
            "entryStreamEncoding": "xof-unbiased-residue-from-coordinate",
            "coordinateAxes": [
                "proofFamily",
                "rnsLimbIndex",
                "ringCoefficientPosition"
            ],
            "coefficientModulus": "current Q_share limb prime",
            "sampledEntryPolicy": "profile exposes deterministic coordinate-bound audit samples"
        },
        "verificationPolicy": {
            "rejectionRules": [
                "wrong setup-proof profile",
                "wrong challenge domain",
                "wrong setup-proof record binding",
                "wrong statement root",
                "wrong proof chunk root",
                "missing witness bounds",
                "modulo-only relation check",
                "generic or undeclared proof family"
            ],
            "proofBytesAcceptedStatus": "same-secret-and-public-key-share-verifiers-implemented-other-family-verifiers-pending"
        }
    }))
}

fn setup_proof_challenge_domain_hash() -> CanonicalResult<String> {
    super::setup_proof::setup_proof_challenge_domain_hash(COLLECTIVE_BGV_SETUP_PROFILE_ID)
}

fn setup_proof_record_binding_value() -> CanonicalResult<Value> {
    super::setup_proof::setup_proof_record_binding_value(
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )
}

fn setup_proof_family_profiles() -> CanonicalResult<Vec<Value>> {
    let family_profiles = SETUP_PROOF_FAMILIES
        .iter()
        .map(|proof_family| {
            let (statement, witness, no_wrap_rule) = match *proof_family {
                "vss-opening-carry" => (
                    "private VSS share opens the homomorphic coefficient-commitment combination with explicit q_l carry",
                    "private share, coefficient openings, and bounded non-negative carry",
                    "unreduced lifted share relation must hold below the commitment modulus product",
                ),
                "same-secret-consistency" => (
                    "VSS constant commitments across all Q_share limbs encode one short trustee secret",
                    "one short trustee secret and openings to all accepted VSS constant commitments",
                    "limb reductions must be reductions of one short secret, not independent limb witnesses",
                ),
                "public-key-share" => (
                    "public-key share satisfies PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0",
                    "same short trustee secret, bounded error, and bounded no-wrap carry",
                    "proof must check lifted integer equality and error support, not only modulo p or q_l",
                ),
                "relinearization-key-share" => (
                    "linked relinearization round shares are generated from the same trustee secret and accepted round-one aggregate",
                    "same short trustee secret, round-one ephemeral secret, key-switch error, and carry witnesses",
                    "round-two proof must bind round-one aggregate and decomposition basis",
                ),
                "galois-key-share" => (
                    "Galois key batch shares are generated from the same trustee secret for the exact required automorphism set",
                    "same short trustee secret, key-switch error, automorphism witness binding, and carry witnesses",
                    "proof must bind RequiredGaloisSetHash and reject undeclared automorphisms",
                ),
                _ => unreachable!("SETUP_PROOF_FAMILIES is fixed in this module"),
            };
            Ok(json!({
                "proofFamily": proof_family,
                "statement": statement,
                "witness": witness,
                "noWrapRule": no_wrap_rule,
                "profileId": SETUP_PROOF_PROFILE_ID,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "verificationStatus": "family-verifier-required-before-proof-bytes-acceptance",
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(family_profiles)
}

fn verify_phase_transcript(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(phase_transcript) = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("rosterFreeze"),
            vec!["phaseTranscript".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };

    let mut seen_phase_hashes = BTreeMap::<String, String>::new();
    let mut seen_phase_numbers = BTreeSet::<u64>::new();
    let mut required_phase_index = 0_usize;
    let mut previous_phase_root: Option<String> = None;

    for phase_value in phase_transcript {
        let phase_object_hash = derive_protocol_hash("SetupPhaseObjectHash", phase_value)?;
        let Some(phase_identifier) = phase_value.get("phaseId").and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                None,
                Vec::new(),
                vec![Refusal::new(
                    "phaseIdMissing",
                    "phaseTranscript entries must include phaseId",
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        };
        let Some(phase_number) = phase_value.get("phaseNumber").and_then(Value::as_u64) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseNumberMissing",
                    "phaseTranscript entries must include phaseNumber",
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        };
        if let Some(previous_hash) = seen_phase_hashes.get(phase_identifier) {
            if previous_hash == &phase_object_hash {
                continue;
            }
            return Ok(Some(verification_response(
                VerifierStatus::ForkDetected,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseForkDetected",
                    format!("phase {phase_identifier} has two non-identical records"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        }

        let Some((expected_phase_identifier, expected_phase_number)) =
            REQUIRED_PHASES.get(required_phase_index)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "unexpectedExtraPhase",
                    format!("phase {phase_identifier} appears after setupPackageVerification"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        };
        if phase_identifier != *expected_phase_identifier || phase_number != *expected_phase_number
        {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(*expected_phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseOrderMismatch",
                    format!(
                        "expected phase {expected_phase_identifier} number {expected_phase_number}, got {phase_identifier} number {phase_number}"
                    ),
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        }
        if !seen_phase_numbers.insert(phase_number) {
            return Ok(Some(verification_response(
                VerifierStatus::ForkDetected,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseNumberForkDetected",
                    format!("phase number {phase_number} is used by more than one phase"),
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        }
        if let Some(response) = verify_phase_object_binding(
            setup_package,
            phase_value,
            phase_identifier,
            phase_number,
            previous_phase_root.as_deref(),
        )? {
            return Ok(Some(response));
        }
        let phase_root = phase_value
            .get("phaseRoot")
            .and_then(Value::as_str)
            .expect("phase root was checked");
        seen_phase_hashes.insert(phase_identifier.to_string(), phase_object_hash);
        previous_phase_root = Some(phase_root.to_string());
        required_phase_index += 1;
    }

    if required_phase_index < REQUIRED_PHASES.len() {
        let (next_phase_identifier, _) = REQUIRED_PHASES[required_phase_index];
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some(next_phase_identifier),
            vec![format!("phaseTranscript.{next_phase_identifier}")],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn verify_phase_object_binding(
    setup_package: &Value,
    phase_value: &Value,
    phase_identifier: &str,
    phase_number: u64,
    previous_phase_root: Option<&str>,
) -> CanonicalResult<Option<Value>> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before phase transcript verification",
        )
    })?;
    for (field_name, context_field_name) in [
        ("ceremonyId", "ceremonyId"),
        ("manifestHash", "manifestHash"),
        ("rosterHash", "rosterHash"),
        ("setupProfileHash", "setupProfileHash"),
        ("qShareHash", "qShareHash"),
        (
            "carryAwareVssShareRelationProfileHash",
            "carryAwareVssShareRelationProfileHash",
        ),
        ("commitmentProfileHash", "commitmentProfileHash"),
        ("setupEpoch", "setupEpoch"),
    ] {
        let Some(phase_binding) = phase_value.get(field_name) else {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseBindingMissing",
                format!("phase {phase_identifier} must bind {field_name}"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.{field_name}"),
            )?));
        };
        if phase_binding != &setup_context[context_field_name] {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseContextMismatch",
                format!("phase {phase_identifier} {field_name} does not match setupContext"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.{field_name}"),
            )?));
        }
    }

    match previous_phase_root {
        Some(expected_previous_phase_root) => {
            if phase_value.get("previousPhaseRoot").and_then(Value::as_str)
                != Some(expected_previous_phase_root)
            {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "previousPhaseRootMismatch",
                    format!("phase {phase_identifier} must bind the previous accepted phase root"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}.previousPhaseRoot"),
                )?));
            }
        }
        None => {
            if !phase_value
                .get("previousPhaseRoot")
                .is_some_and(Value::is_null)
            {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "previousPhaseRootMismatch",
                    format!("phase {phase_identifier} must bind null as the first phase root"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}.previousPhaseRoot"),
                )?));
            }
        }
    }

    let Some(phase_root) = phase_value.get("phaseRoot").and_then(Value::as_str) else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRootMissing",
            format!("phase {phase_identifier} must include phaseRoot"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.phaseRoot"),
        )?));
    };
    validate_hash_string(
        phase_root,
        &format!("phaseTranscript.{phase_identifier}.phaseRoot"),
    )?;
    let mut root_input = phase_value.clone();
    root_input
        .as_object_mut()
        .expect("phase transcript entry is an object")
        .remove("phaseRoot");
    let expected_phase_root = derive_protocol_hash("SetupPhaseRoot", &root_input)?;
    if phase_root != expected_phase_root {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRootMismatch",
            format!("phase {phase_identifier} root does not match its canonical phase payload"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.phaseRoot"),
        )?));
    }

    let Some(participant_phase_objects) = phase_value
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectsMissing",
            format!("phase {phase_identifier} must include participantPhaseObjects"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if participant_phase_objects.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectCountMismatch",
            format!("phase {phase_identifier} must include one signed root slot per participant"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for participant_phase_object in participant_phase_objects {
        if let Some(response) = verify_participant_phase_object(
            participant_phase_object,
            phase_identifier,
            phase_number,
            setup_context,
        )? {
            return Ok(Some(response));
        }
        let roster_position = participant_phase_object["rosterPosition"]
            .as_u64()
            .expect("roster position was checked");
        if !seen_roster_positions.insert(roster_position) {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseRosterPositionDuplicate",
                format!("phase {phase_identifier} contains duplicate roster positions"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
            )?));
        }
    }

    Ok(None)
}

fn verify_participant_phase_object(
    participant_phase_object: &Value,
    phase_identifier: &str,
    phase_number: u64,
    setup_context: &Value,
) -> CanonicalResult<Option<Value>> {
    if !participant_phase_object.is_object() {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectNotObject",
            format!("phase {phase_identifier} participant entry must be an object"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("objectType")
        .and_then(Value::as_str)
        != Some("SetupPhaseParticipantObject")
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectTypeMismatch",
            "participant phase object must use SetupPhaseParticipantObject",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectVersionMismatch",
            "participant phase object version must be 1",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("phaseId")
        .and_then(Value::as_str)
        != Some(phase_identifier)
        || participant_phase_object
            .get("phaseNumber")
            .and_then(Value::as_u64)
            != Some(phase_number)
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantPhaseMismatch",
            "participant phase object must bind the enclosing phase id and number",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if participant_phase_object.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseParticipantContextMismatch",
                format!("participant phase object {field_name} does not match setupContext"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
            )?));
        }
    }
    if participant_phase_object
        .get("signerRole")
        .and_then(Value::as_str)
        != Some("Trustee")
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantSignerRoleMismatch",
            "participant phase object signerRole must be Trustee",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(trustee_identity) = participant_phase_object
        .get("trusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantIdentityMissing",
            "participant phase object must bind trusteeIdentity",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantIdentityMalformed",
            "participant phase object trusteeIdentity must be non-empty NFC text",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(roster_position) = participant_phase_object
        .get("rosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRosterPositionMissing",
            "participant phase object must bind rosterPosition",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if roster_position >= FIRST_PROFILE_PARTICIPANT_COUNT {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRosterPositionOutsideProfile",
            "participant phase object rosterPosition is outside the first accepted profile",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(recovery_epoch) = participant_phase_object
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantEpochMissing",
            "participant phase object must bind recoveryEpoch",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let Some(device_epoch) = participant_phase_object
        .get("deviceEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantEpochMissing",
            "participant phase object must bind deviceEpoch",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let Some(signing_public_key_hash) = participant_phase_object
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind signingPublicKeyHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        &format!("phaseTranscript.{phase_identifier}.participantPhaseObjects.signingPublicKeyHash"),
    )?;
    let (private_vss_mailbox_public_key_hash, private_vss_mailbox_public_key_bytes_hash) =
        if phase_identifier == "setupIntent" {
            let Some(public_key_hash) = participant_phase_object
                .get("privateVssMailboxPublicKeyHash")
                .and_then(Value::as_str)
            else {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "phaseParticipantMailboxKeyMissing",
                    "setup intent participant object must bind privateVssMailboxPublicKeyHash",
                    format!(
                        "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyHash"
                    ),
                )?));
            };
            validate_hash_string(
                public_key_hash,
                &format!(
                    "phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyHash"
                ),
            )?;
            let Some(public_key_bytes_hash) = participant_phase_object
                .get("privateVssMailboxPublicKeyBytesHash")
                .and_then(Value::as_str)
            else {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "phaseParticipantMailboxKeyMissing",
                    "setup intent participant object must bind privateVssMailboxPublicKeyBytesHash",
                    format!(
                        "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyBytesHash"
                    ),
                )?));
            };
            validate_hash_string(
                public_key_bytes_hash,
                &format!(
                    "phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyBytesHash"
                ),
            )?;

            (Some(public_key_hash), Some(public_key_bytes_hash))
        } else {
            (None, None)
        };

    let phase_object_payload = phase_participant_payload_value(PhaseParticipantPayloadInput {
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        recovery_epoch,
        device_epoch,
        signing_public_key_hash,
        private_vss_mailbox_public_key_hash,
        private_vss_mailbox_public_key_bytes_hash,
    })?;
    let expected_phase_object_root =
        derive_protocol_hash("SetupPhaseObjectHash", &phase_object_payload)?;
    let expected_phase_object_byte_length =
        u64::try_from(canonical_json(&phase_object_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "phase participant payload length does not fit u64",
            )
        })?;
    let expected_phase_signature_context_hash = phase_signature_context_hash(
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        &expected_phase_object_root,
    )?;

    let Some(phase_object_root) = participant_phase_object
        .get("phaseObjectRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind phaseObjectRoot",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        phase_object_root,
        &format!("phaseTranscript.{phase_identifier}.participantPhaseObjects.phaseObjectRoot"),
    )?;
    if phase_object_root != expected_phase_object_root {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectRootMismatch",
            "participant phase object root does not match the canonical signed payload",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(phase_object_byte_length) = participant_phase_object
        .get("phaseObjectByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantByteLengthMissing",
            "participant phase object must bind phaseObjectByteLength",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if phase_object_byte_length != expected_phase_object_byte_length {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantByteLengthMismatch",
            "participant phase object byte length does not match the canonical signed payload",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(phase_signature_context_hash) = participant_phase_object
        .get("phaseSignatureContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind phaseSignatureContextHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        phase_signature_context_hash,
        &format!(
            "phaseTranscript.{phase_identifier}.participantPhaseObjects.phaseSignatureContextHash"
        ),
    )?;
    if phase_signature_context_hash != expected_phase_signature_context_hash {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantContextHashMismatch",
            "participant phase signature context hash does not match the setup phase binding",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(signature_envelope_hash) = participant_phase_object
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind signatureEnvelopeHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        &format!(
            "phaseTranscript.{phase_identifier}.participantPhaseObjects.signatureEnvelopeHash"
        ),
    )?;
    let Some(signature_envelope) = participant_phase_object.get("signatureEnvelope") else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseSignatureEnvelopeMissing",
            "participant phase object must include the signed ML-DSA envelope",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let manifest_hash = setup_context_string(setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "SetupPhaseParticipantObject",
            object_version: 1,
            signer_role: "Trustee",
            signer_identity: trustee_identity,
            ceremony_id,
            public_key_hash: signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(phase_object_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: phase_signature_context_hash,
            byte_length: phase_object_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(phase_refusal(
            phase_identifier,
            "phaseSignatureHashMismatch",
            "participant phase signature envelope hash does not match the verified envelope",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?)),
        Err(failure) => Ok(Some(phase_refusal(
            phase_identifier,
            failure.reason_code,
            failure.message,
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?)),
    }
}

fn phase_participant_payload_value(
    input: PhaseParticipantPayloadInput<'_>,
) -> CanonicalResult<Value> {
    let PhaseParticipantPayloadInput {
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        recovery_epoch,
        device_epoch,
        signing_public_key_hash,
        private_vss_mailbox_public_key_hash,
        private_vss_mailbox_public_key_bytes_hash,
    } = input;
    let mut payload = json!({
        "objectType": "SetupPhaseParticipantObject",
        "objectVersion": 1,
        "phaseId": phase_identifier,
        "phaseNumber": phase_number,
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
        "commitmentProfileHash": setup_context_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "signerRole": "Trustee",
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "recoveryEpoch": recovery_epoch,
        "deviceEpoch": device_epoch,
        "signingPublicKeyHash": signing_public_key_hash,
    });
    if let Some(public_key_hash) = private_vss_mailbox_public_key_hash {
        payload["privateVssMailboxPublicKeyHash"] = json!(public_key_hash);
    }
    if let Some(public_key_bytes_hash) = private_vss_mailbox_public_key_bytes_hash {
        payload["privateVssMailboxPublicKeyBytesHash"] = json!(public_key_bytes_hash);
    }

    Ok(payload)
}

fn phase_signature_context_hash(
    phase_identifier: &str,
    phase_number: u64,
    setup_context: &Value,
    trustee_identity: &str,
    roster_position: u64,
    phase_object_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPhaseObjectHash",
        &json!({
            "purpose": "setup-phase-signature-context",
            "phaseId": phase_identifier,
            "phaseNumber": phase_number,
            "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
            "manifestHash": setup_context_string(setup_context, "manifestHash")?,
            "rosterHash": setup_context_string(setup_context, "rosterHash")?,
            "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
            "qShareHash": setup_context_string(setup_context, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": setup_context_string(
                setup_context,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": setup_context_string(
                setup_context,
                "commitmentProfileHash",
            )?,
            "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "phaseObjectRoot": phase_object_root,
        }),
    )
}

fn setup_context_string<'a>(
    setup_context: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    setup_context
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupContext.{field_name} must be a string"),
            )
        })
}

fn verify_common_randomness(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(common_randomness) = setup_package.get("commonRandomness") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessCommit"),
            vec!["commonRandomness".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !common_randomness.is_object() {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessNotObject",
            "commonRandomness must be a JSON object",
            "setupPackage.commonRandomness",
        )?));
    }
    if common_randomness.get("objectType").and_then(Value::as_str) != Some("SetupCommonRandomness")
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessObjectTypeMismatch",
            "commonRandomness.objectType must be SetupCommonRandomness",
            "setupPackage.commonRandomness.objectType",
        )?));
    }
    if common_randomness
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessObjectVersionMismatch",
            "commonRandomness.objectVersion must be 1",
            "setupPackage.commonRandomness.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before common randomness verification",
        )
    })?;
    if let Some(response) = verify_common_randomness_context(common_randomness, setup_context)? {
        return Ok(Some(response));
    }

    let Some(commit_records) = common_randomness
        .get("commitRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessCommit"),
            vec!["commonRandomness.commitRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(reveal_records) = common_randomness
        .get("revealRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.revealRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if commit_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessCommitCountMismatch",
            "commonRandomness.commitRecords must contain one commit per participant",
            "setupPackage.commonRandomness.commitRecords",
        )?));
    }
    if reveal_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCountMismatch",
            "commonRandomness.revealRecords must contain one reveal per participant",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    let mut commit_reveal_hashes_by_position = BTreeMap::<u64, String>::new();
    for commit_record in commit_records {
        let (roster_position, reveal_hash) =
            verify_common_randomness_commit_record(commit_record, setup_context)?;
        if commit_reveal_hashes_by_position
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessCommitDuplicate",
                "commonRandomness.commitRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.commitRecords",
            )?));
        }
    }

    let mut ordered_reveal_hashes = BTreeMap::<u64, String>::new();
    for reveal_record in reveal_records {
        let (roster_position, reveal_hash) =
            verify_common_randomness_reveal_record(reveal_record, setup_context)?;
        let Some(committed_reveal_hash) = commit_reveal_hashes_by_position.get(&roster_position)
        else {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealWithoutCommit",
                "commonRandomness.revealRecords contains a reveal without a matching commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        };
        if committed_reveal_hash != &reveal_hash {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealHashMismatch",
                "common-randomness reveal hash does not match the participant commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
        if ordered_reveal_hashes
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealDuplicate",
                "commonRandomness.revealRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
    }
    if ordered_reveal_hashes.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCoverageMismatch",
            "commonRandomness.revealRecords must cover the full first-profile roster",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    let ordered_reveal_hash_values = ordered_reveal_hashes
        .values()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let expected_public_matrix_seed_hash = derive_protocol_hash(
        "SetupPublicMatrixSeedHash",
        &json!({
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupProfileHash": setup_context["setupProfileHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "orderedRevealHashes": ordered_reveal_hash_values,
        }),
    )?;
    if common_randomness
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(expected_public_matrix_seed_hash.as_str())
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessPublicMatrixSeedMismatch",
            "commonRandomness.publicMatrixSeedHash does not match the ordered reveal set",
            "setupPackage.commonRandomness.publicMatrixSeedHash",
        )?));
    }
    if let Some(response) =
        verify_public_derivations(common_randomness, &expected_public_matrix_seed_hash)?
    {
        return Ok(Some(response));
    }

    let Some(common_randomness_root) = common_randomness
        .get("commonRandomnessRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.commonRandomnessRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        common_randomness_root,
        "commonRandomness.commonRandomnessRoot",
    )?;
    let mut root_input = common_randomness.clone();
    root_input
        .as_object_mut()
        .expect("commonRandomness object was checked")
        .remove("commonRandomnessRoot");
    let expected_common_randomness_root =
        derive_protocol_hash("SetupCommonRandomnessRoot", &root_input)?;
    if common_randomness_root != expected_common_randomness_root {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRootMismatch",
            "commonRandomness.commonRandomnessRoot does not match the canonical payload",
            "setupPackage.commonRandomness.commonRandomnessRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_derivations(
    common_randomness: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Option<Value>> {
    let Some(public_derivations) = common_randomness.get("publicDerivations") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("commonRandomnessReveal"),
            vec!["commonRandomness.publicDerivations".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let expected_public_derivations =
        derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash)?;
    if public_derivations != &expected_public_derivations {
        return Ok(Some(common_randomness_refusal(
            "setupPublicDerivationsMismatch",
            "commonRandomness.publicDerivations does not match the accepted public matrix derivation recipe",
            "setupPackage.commonRandomness.publicDerivations",
        )?));
    }

    Ok(None)
}

fn derive_collective_bgv_setup_public_derivations(
    public_matrix_seed_hash: &str,
) -> CanonicalResult<Value> {
    let bgv_public_a = derive_bgv_public_a_polynomial(public_matrix_seed_hash)?;
    let public_matrices = derive_setup_public_matrices(public_matrix_seed_hash)?;
    let mut derivations = json!({
        "objectType": "SetupPublicDerivations",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "bgvPublicA": bgv_public_a,
        "publicMatrices": public_matrices,
        "crpRoots": {
            "publicKeyCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "public-key-crp")?,
            "relinearizationCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "relinearization-crp")?,
            "galoisKeyCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "galois-key-crp")?,
            "commitmentMatrixCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "commitment-matrix-crp")?,
            "proofMatrixCrpRoot": setup_public_derivation_root(public_matrix_seed_hash, "proof-matrix-crp")?,
        },
        "status": "deterministic-public-derivations-bound",
    });
    let derivation_root = derive_protocol_hash("SetupPublicDerivationRoot", &derivations)?;
    derivations["publicDerivationRoot"] = Value::String(derivation_root);

    Ok(derivations)
}

fn derive_bgv_public_a_polynomial(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let modulus_derivations = DATA_PRIMES
        .iter()
        .map(|modulus| {
            json!({
                "modulus": modulus,
                "coefficientDerivationHash": hash512_hex(
                    "sealed-lattice-bgv-rns/accepted-public-a-derivation-v1",
                    &[
                        public_matrix_seed_hash.as_bytes(),
                        "accepted-bgv-public-a".as_bytes(),
                        modulus.to_string().as_bytes(),
                    ],
                ),
            })
        })
        .collect::<Vec<_>>();
    let mut public_a = json!({
        "objectType": "BgvPublicAPolynomial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "derivationLabel": "accepted-bgv-public-a",
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "modulusDerivations": modulus_derivations,
        "sampledResidues": sample_public_residues(
            public_matrix_seed_hash,
            "accepted-bgv-public-a",
            DATA_PRIMES[0],
        ),
    });
    let public_polynomial_root =
        derive_protocol_hash("BGVPublicCommonRandomPolynomialRoot", &public_a)?;
    public_a["publicPolynomialRoot"] = Value::String(public_polynomial_root);

    Ok(public_a)
}

fn derive_setup_public_matrices(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let commitment_matrix = derive_setup_commitment_matrix(public_matrix_seed_hash)?;
    let setup_proof_matrix = derive_setup_proof_matrix(public_matrix_seed_hash)?;
    let mut public_matrices = json!({
        "objectType": "SetupPublicMatrixMaterial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "commitmentMatrix": commitment_matrix,
        "setupProofMatrix": setup_proof_matrix,
        "materializationStatus": "deterministic-entry-streams-bound",
    });
    let public_matrices_root = derive_protocol_hash("SetupPublicDerivationRoot", &public_matrices)?;
    public_matrices["publicMatricesRoot"] = Value::String(public_matrices_root);

    Ok(public_matrices)
}

fn derive_setup_commitment_matrix(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let crp_root = setup_public_derivation_root(public_matrix_seed_hash, "commitment-matrix-crp")?;
    let sampled_entries = commitment_matrix_sampled_entries(public_matrix_seed_hash)?;
    let mut matrix = json!({
        "objectType": "SetupPublicMatrix",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "matrixKind": "commitment",
        "profileId": SETUP_COMMITMENT_PROFILE_ID,
        "profileStatus": "commitment-profile-bound",
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "commitmentModulusLimbs": setup_commitment_modulus_limb_values(),
        "commitmentModuleRank": SETUP_COMMITMENT_MODULE_RANK,
        "commitmentRandomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "crpRoot": crp_root,
        "coordinateAxes": [
            "rnsLimbIndex",
            "commitmentModulusIndex",
            "matrixRowIndex",
            "randomnessColumnIndex",
            "ringCoefficientPosition"
        ],
        "rnsLimbCount": DATA_PRIMES.len(),
        "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "ringDegree": POLYNOMIAL_DEGREE,
        "entryStreamEncoding": "xof-unbiased-residue-from-coordinate",
        "sampledEntries": sampled_entries,
    });
    let matrix_root = derive_protocol_hash("SetupPublicDerivationRoot", &matrix)?;
    matrix["matrixRoot"] = Value::String(matrix_root);

    Ok(matrix)
}

fn derive_setup_proof_matrix(public_matrix_seed_hash: &str) -> CanonicalResult<Value> {
    let crp_root = setup_public_derivation_root(public_matrix_seed_hash, "proof-matrix-crp")?;
    let sampled_entries = proof_matrix_sampled_entries(public_matrix_seed_hash)?;
    let mut matrix = json!({
        "objectType": "SetupPublicMatrix",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "matrixKind": "setupProof",
        "profileId": SETUP_PROOF_PROFILE_ID,
        "profileStatus": "setup-proof-profile-bound",
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "challengeDomainHash": setup_proof_challenge_domain_hash()?,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "crpRoot": crp_root,
        "coordinateAxes": [
            "proofFamily",
            "rnsLimbIndex",
            "ringCoefficientPosition"
        ],
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": POLYNOMIAL_DEGREE,
        "entryStreamEncoding": "xof-unbiased-residue-from-coordinate",
        "sampledEntries": sampled_entries,
    });
    let matrix_root = derive_protocol_hash("SetupPublicDerivationRoot", &matrix)?;
    matrix["matrixRoot"] = Value::String(matrix_root);

    Ok(matrix)
}

fn commitment_matrix_sampled_entries(public_matrix_seed_hash: &str) -> CanonicalResult<Vec<Value>> {
    let limb_indices = [0_usize, DATA_PRIMES.len() - 1];
    setup_commitment_matrix_sampled_entries(
        public_matrix_seed_hash,
        &limb_indices,
        &sample_positions(),
    )
}

fn proof_matrix_sampled_entries(public_matrix_seed_hash: &str) -> CanonicalResult<Vec<Value>> {
    let limb_indices = [0_usize, DATA_PRIMES.len() - 1];
    let mut entries = Vec::new();
    for proof_family in SETUP_PROOF_FAMILIES {
        for limb_index in limb_indices {
            for ring_coefficient_position in sample_positions() {
                let coordinate = json!({
                    "proofFamily": proof_family,
                    "rnsLimbIndex": limb_index,
                    "rnsPrime": DATA_PRIMES[limb_index],
                    "ringCoefficientPosition": ring_coefficient_position,
                });
                let entry_derivation_hash = setup_public_matrix_entry_hash(
                    public_matrix_seed_hash,
                    "setupProof",
                    &coordinate,
                )?;
                let coefficient_value = setup_proof_matrix_coefficient(
                    public_matrix_seed_hash,
                    proof_family,
                    limb_index,
                    ring_coefficient_position,
                    DATA_PRIMES[limb_index],
                )?;
                entries.push(json!({
                    "coordinate": coordinate,
                    "coefficientValue": coefficient_value,
                    "entryDerivationHash": entry_derivation_hash,
                }));
            }
        }
    }

    Ok(entries)
}

fn setup_proof_matrix_coefficient(
    public_matrix_seed_hash: &str,
    proof_family: &str,
    rns_limb_index: usize,
    ring_coefficient_position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let rns_limb_text = rns_limb_index.to_string();
    let position_text = ring_coefficient_position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-lnp-setup-proof/matrix-coefficient-v1",
            &[
                public_matrix_seed_hash.as_bytes(),
                proof_family.as_bytes(),
                rns_limb_text.as_bytes(),
                position_text.as_bytes(),
                modulus_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), modulus) {
                return Ok(reduced_value);
            }
        }
        block_index = block_index.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setup-proof matrix sampling block index overflow",
            )
        })?;
    }
}

fn setup_public_matrix_entry_hash(
    public_matrix_seed_hash: &str,
    matrix_kind: &str,
    coordinate: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPublicDerivationRoot",
        &json!({
            "objectType": "SetupPublicMatrixEntryDerivation",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "matrixKind": matrix_kind,
            "coordinate": coordinate,
        }),
    )
}

fn setup_public_derivation_root(
    public_matrix_seed_hash: &str,
    component_name: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPublicDerivationRoot",
        &json!({
            "objectType": "SetupPublicDerivation",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "componentName": component_name,
        }),
    )
}

fn verify_common_randomness_context(
    value: &Value,
    setup_context: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessContextMismatch",
                format!("commonRandomness.{field_name} does not match setupContext"),
                format!("setupPackage.commonRandomness.{field_name}"),
            )?));
        }
    }

    Ok(None)
}

fn verify_common_randomness_commit_record(
    commit_record: &Value,
    setup_context: &Value,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        commit_record,
        setup_context,
        "CommonRandomnessCommit",
        "commonRandomness.commitRecords",
    )?;
    let Some(reveal_hash) = commit_record.get("revealHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.revealHash is required",
        ));
    };
    validate_hash_string(reveal_hash, "CommonRandomnessCommit.revealHash")?;
    let Some(commit_hash) = commit_record.get("commitHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.commitHash is required",
        ));
    };
    validate_hash_string(commit_hash, "CommonRandomnessCommit.commitHash")?;
    let mut hash_input = commit_record.clone();
    hash_input
        .as_object_mut()
        .expect("common-randomness commit object was checked")
        .remove("commitHash");
    let expected_commit_hash = derive_protocol_hash("CommonRandomnessCommitHash", &hash_input)?;
    if commit_hash != expected_commit_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.commitHash does not match its canonical payload",
        ));
    }

    Ok((
        commit_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash.to_string(),
    ))
}

fn verify_common_randomness_reveal_record(
    reveal_record: &Value,
    setup_context: &Value,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        reveal_record,
        setup_context,
        "CommonRandomnessReveal",
        "commonRandomness.revealRecords",
    )?;
    let Some(reveal_hex) = reveal_record.get("revealHex").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHex is required",
        ));
    };
    validate_common_randomness_reveal_hex(reveal_hex)?;
    let Some(reveal_hash) = reveal_record.get("revealHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHash is required",
        ));
    };
    validate_hash_string(reveal_hash, "CommonRandomnessReveal.revealHash")?;
    let mut hash_input = reveal_record.clone();
    hash_input
        .as_object_mut()
        .expect("common-randomness reveal object was checked")
        .remove("revealHash");
    let expected_reveal_hash = derive_protocol_hash("CommonRandomnessRevealHash", &hash_input)?;
    if reveal_hash != expected_reveal_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHash does not match its canonical payload",
        ));
    }

    Ok((
        reveal_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash.to_string(),
    ))
}

fn verify_common_randomness_participant_record_shape(
    record: &Value,
    setup_context: &Value,
    object_type: &str,
    object_path: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must be objects"),
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must use {object_type}"),
        ));
    }
    if record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.objectVersion must be 1"),
        ));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if record.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} does not match setupContext"),
            ));
        }
    }
    if record.get("signerRole").and_then(Value::as_str) != Some("Trustee") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.signerRole must be Trustee"),
        ));
    }
    let Some(trustee_identity) = record.get("trusteeIdentity").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity is required"),
        ));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity must be non-empty NFC text"),
        ));
    }
    let Some(roster_position) = record.get("rosterPosition").and_then(Value::as_u64) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is required"),
        ));
    };
    if roster_position >= FIRST_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is outside the first accepted profile"),
        ));
    }
    for field_name in ["recoveryEpoch", "deviceEpoch"] {
        if record.get(field_name).and_then(Value::as_u64).is_none() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} is required"),
            ));
        }
    }
    let Some(signature_envelope_hash) = record.get("signatureEnvelopeHash").and_then(Value::as_str)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.signatureEnvelopeHash is required"),
        ));
    };
    validate_hash_string(
        signature_envelope_hash,
        &format!("{object_type}.signatureEnvelopeHash"),
    )?;

    Ok(())
}

fn validate_common_randomness_reveal_hex(reveal_hex: &str) -> CanonicalResult<()> {
    if reveal_hex.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must contain 64 lowercase hex characters",
        ));
    }
    if !reveal_hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must be lowercase hexadecimal",
        ));
    }

    Ok(())
}

fn common_randomness_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("commonRandomnessReveal"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_abort_absence(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    if setup_package
        .get("complaints")
        .and_then(Value::as_array)
        .is_some_and(|complaints| !complaints.is_empty())
    {
        return Ok(Some(verification_response(
            VerifierStatus::Aborted,
            Some("vssAcceptanceOrComplaint"),
            Vec::new(),
            vec![Refusal::new(
                "validComplaintPresent",
                "a complaint aborts the first accepted setup profile",
                "setupPackage.complaints".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_package
        .get("abortRecords")
        .and_then(Value::as_array)
        .is_some_and(|abort_records| !abort_records.is_empty())
    {
        return Ok(Some(verification_response(
            VerifierStatus::Aborted,
            None,
            Vec::new(),
            vec![Refusal::new(
                "abortRecordPresent",
                "an abort record prevents first-profile setup acceptance",
                "setupPackage.abortRecords".to_string(),
            )],
            Vec::new(),
        )?));
    }

    Ok(None)
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
        VerifierStatus::Pending,
        Some("setupPackageVerification"),
        missing_objects,
        Vec::new(),
        Vec::new(),
    )?))
}

fn verify_vss_coefficient_commitments(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(commitment_set) = setup_package.get("vssCoefficientCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_set.is_object() {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentsNotObject",
            "vssCoefficientCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.vssCoefficientCommitments",
        )?));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some("VssCoefficientCommitmentSet")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSetTypeMismatch",
            "vssCoefficientCommitments.objectType must be VssCoefficientCommitmentSet",
            "setupPackage.vssCoefficientCommitments.objectType",
        )?));
    }
    if commitment_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSetVersionMismatch",
            "vssCoefficientCommitments.objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS commitment verification",
        )
    })?;
    if let Err(error) = verify_vss_commitment_context(commitment_set, setup_context) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentContextMismatch",
            error.message,
            "setupPackage.vssCoefficientCommitments",
        )?));
    }
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before VSS commitment verification",
            )
        })?;
    if commitment_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCommitmentPublicMatrixSeedMismatch",
            "vssCoefficientCommitments.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.vssCoefficientCommitments.publicMatrixSeedHash",
        )?));
    }
    if commitment_set
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCommitmentProfileHashMismatch",
            "vssCoefficientCommitments.commitmentProfileHash must match the accepted setup commitment profile",
            "setupPackage.vssCoefficientCommitments.commitmentProfileHash",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let Some(dealer_records) = commitment_set
        .get("dealerRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.dealerRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if dealer_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentCountMismatch",
            "vssCoefficientCommitments.dealerRecords must contain one record for every trustee",
            "setupPackage.vssCoefficientCommitments.dealerRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for dealer_record in dealer_records {
        if let Some(response) = verify_vss_dealer_commitment_record(
            dealer_record,
            setup_context,
            &expected_trustees,
            public_matrix_seed_hash,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(commitment_root) = commitment_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.vssCoefficientCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        commitment_root,
        "vssCoefficientCommitments.vssCoefficientCommitmentRoot",
    )?;
    let mut root_input = commitment_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS commitment set object was checked")
        .remove("vssCoefficientCommitmentRoot");
    let expected_root = derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if commitment_root != expected_root {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRootMismatch",
            "vssCoefficientCommitmentRoot does not match the canonical VSS commitment set",
            "setupPackage.vssCoefficientCommitments.vssCoefficientCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_commitment_context(
    commitment_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if commitment_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("vssCoefficientCommitments.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn verify_vss_coefficient_commitment_material(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(material_set) = setup_package.get("vssCoefficientCommitmentMaterial") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !material_set.is_object() {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialNotObject",
            "vssCoefficientCommitmentMaterial must be a root-bound object, not an array or scalar",
            "setupPackage.vssCoefficientCommitmentMaterial",
        )?));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_SET_OBJECT_TYPE)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialSetTypeMismatch",
            "vssCoefficientCommitmentMaterial.objectType must be VssCoefficientCommitmentMaterialSet",
            "setupPackage.vssCoefficientCommitmentMaterial.objectType",
        )?));
    }
    if material_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialSetVersionMismatch",
            "vssCoefficientCommitmentMaterial.objectVersion must be 1",
            "setupPackage.vssCoefficientCommitmentMaterial.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS coefficient commitment material verification",
        )
    })?;
    if let Err(error) = verify_vss_commitment_context(material_set, setup_context) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialContextMismatch",
            error.message,
            "setupPackage.vssCoefficientCommitmentMaterial",
        )?));
    }
    if material_set
        .get("commitmentProfileId")
        .and_then(Value::as_str)
        != Some(SETUP_COMMITMENT_PROFILE_ID)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialProfileMismatch",
            "vssCoefficientCommitmentMaterial.commitmentProfileId must match the accepted setup commitment profile",
            "setupPackage.vssCoefficientCommitmentMaterial.commitmentProfileId",
        )?));
    }
    if material_set
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialProfileHashMismatch",
            "vssCoefficientCommitmentMaterial.commitmentProfileHash must match the accepted setup commitment profile hash",
            "setupPackage.vssCoefficientCommitmentMaterial.commitmentProfileHash",
        )?));
    }
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.materialEncoding is required",
            )
        })?;
    if !matches!(
        material_encoding,
        "full-public-setup-commitment-values"
            | "binary-chunked-full-public-setup-commitment-values"
    ) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialEncodingMismatch",
            "vssCoefficientCommitmentMaterial.materialEncoding must be embedded full public values or binary-chunked full public values",
            "setupPackage.vssCoefficientCommitmentMaterial.materialEncoding",
        )?));
    }

    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before VSS coefficient commitment material verification",
            )
        })?;
    if material_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialPublicMatrixSeedMismatch",
            "vssCoefficientCommitmentMaterial.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.vssCoefficientCommitmentMaterial.publicMatrixSeedHash",
        )?));
    }
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before VSS coefficient commitment material verification",
            )
        })?;
    if material_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRootBindingMismatch",
            "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot must match accepted VSS coefficient commitments",
            "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot",
        )?));
    }
    if material_set.get("participantCount").and_then(Value::as_u64)
        != Some(FIRST_PROFILE_PARTICIPANT_COUNT)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialParticipantCountMismatch",
            "vssCoefficientCommitmentMaterial.participantCount must match the accepted setup profile",
            "setupPackage.vssCoefficientCommitmentMaterial.participantCount",
        )?));
    }
    if material_set.get("thresholdDegree").and_then(Value::as_u64)
        != Some(FIRST_PROFILE_DECRYPTION_THRESHOLD)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialThresholdMismatch",
            "vssCoefficientCommitmentMaterial.thresholdDegree must match the accepted setup profile",
            "setupPackage.vssCoefficientCommitmentMaterial.thresholdDegree",
        )?));
    }
    if material_set.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialLimbCountMismatch",
            "vssCoefficientCommitmentMaterial.rnsLimbCount must match the accepted Q_share limb count",
            "setupPackage.vssCoefficientCommitmentMaterial.rnsLimbCount",
        )?));
    }
    let expected_material_count = (FIRST_PROFILE_PARTICIPANT_COUNT
        * FIRST_PROFILE_DECRYPTION_THRESHOLD) as usize
        * DATA_PRIMES.len();
    if material_set
        .get("materialRecordCount")
        .and_then(Value::as_u64)
        != Some(expected_material_count as u64)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRecordCountMismatch",
            "vssCoefficientCommitmentMaterial.materialRecordCount must match coefficientCommitments length",
            "setupPackage.vssCoefficientCommitmentMaterial.materialRecordCount",
        )?));
    }
    if material_encoding == "full-public-setup-commitment-values" {
        let Some(coefficient_commitments) = material_set
            .get("coefficientCommitments")
            .and_then(Value::as_array)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("vssCoefficientCommitments"),
                vec!["vssCoefficientCommitmentMaterial.coefficientCommitments".to_string()],
                Vec::new(),
                Vec::new(),
            )?));
        };
        if coefficient_commitments.len() != expected_material_count {
            return Ok(Some(vss_material_refusal(
                "vssCoefficientCommitmentMaterialCountMismatch",
                "vssCoefficientCommitmentMaterial.coefficientCommitments must cover every dealer, Q_share limb, and Shamir coefficient",
                "setupPackage.vssCoefficientCommitmentMaterial.coefficientCommitments",
            )?));
        }
    } else {
        if material_set.get("coefficientCommitments").is_some() {
            return Ok(Some(vss_material_refusal(
                "vssCoefficientCommitmentMaterialEmbeddedMaterialInBinaryTransport",
                "binary-chunked VSS material must not embed coefficientCommitments in the setup package",
                "setupPackage.vssCoefficientCommitmentMaterial.coefficientCommitments",
            )?));
        }
        verify_binary_vss_material_transport_metadata(material_set)?;
    }

    let Some(material_root) = material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot".to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        material_root,
        "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
    )?;
    let mut root_input = material_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS coefficient commitment material set object was checked")
        .remove("vssCoefficientCommitmentMaterialRoot");
    let expected_root = derive_protocol_hash("VssCoefficientCommitmentMaterialRoot", &root_input)?;
    if material_root != expected_root {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRootMismatch",
            "vssCoefficientCommitmentMaterialRoot does not match the canonical material set",
            "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
        )?));
    }

    Ok(None)
}

fn verify_profile_ring_material(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before profile-ring verification",
            )
        })?;
    if material_set.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64)
        || material_set.get("ringDegreeStatus").and_then(Value::as_str) != Some("profile-ring")
    {
        return Ok(Some(vss_material_outside_profile(
            "vssCoefficientCommitmentMaterial must use the accepted profile ring degree",
            "setupPackage.vssCoefficientCommitmentMaterial.ringDegree",
        )?));
    }

    Ok(None)
}

fn vss_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_binary_vss_material_transport_metadata(material_set: &Value) -> CanonicalResult<()> {
    if material_set.get("binaryFormat").and_then(Value::as_str)
        != Some("sealed-lattice-vss-coefficient-commitment-material-binary-v1")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material must declare the accepted binary format",
        ));
    }
    let Some(transport) = material_set.get("transport") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material must include transport metadata",
        ));
    };
    if !transport.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material transport metadata must be an object",
        ));
    }
    if let Some(unexpected_field) = unexpected_field(
        transport,
        &[
            "transportProfileId",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
        ],
    ) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("binary VSS material transport contains unexpected field {unexpected_field}"),
        ));
    }
    if transport.get("transportProfileId").and_then(Value::as_str)
        != Some(SETUP_TRANSPORT_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material transportProfileId must match the accepted setup transport profile",
        ));
    }
    if transport.get("chunkSizeBytes").and_then(Value::as_u64)
        != Some(SETUP_TRANSPORT_CHUNK_SIZE_BYTES)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material chunkSizeBytes must match the accepted setup transport profile",
        ));
    }
    for field_name in ["chunkCount", "totalByteLength"] {
        let Some(value) = transport.get(field_name).and_then(Value::as_u64) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("binary VSS material transport.{field_name} is required"),
            ));
        };
        if value == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("binary VSS material transport.{field_name} must be positive"),
            ));
        }
    }
    for field_name in ["fullObjectHash", "chunkRoot"] {
        let hash = transport
            .get(field_name)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("binary VSS material transport.{field_name} is required"),
                )
            })?;
        validate_hash_string(
            hash,
            &format!("vssCoefficientCommitmentMaterial.transport.{field_name}"),
        )?;
    }

    Ok(())
}

fn vss_material_outside_profile(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::OutsideProfile,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(
            "vssCoefficientCommitmentMaterialOutsideProfile",
            message,
            object_path,
        )],
        Vec::new(),
    )
}

fn verify_vss_dealer_commitment_record(
    dealer_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if dealer_record.get("objectType").and_then(Value::as_str)
        != Some("VssDealerCoefficientCommitments")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentTypeMismatch",
            "dealer VSS commitment record objectType must be VssDealerCoefficientCommitments",
            "setupPackage.vssCoefficientCommitments.dealerRecords.objectType",
        )?));
    }
    if dealer_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentVersionMismatch",
            "dealer VSS commitment record objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.dealerRecords.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if dealer_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_commitment_refusal(
                "vssDealerCommitmentContextMismatch",
                format!("dealer VSS commitment {field_name} must match setupContext"),
                format!("setupPackage.vssCoefficientCommitments.dealerRecords.{field_name}"),
            )?));
        }
    }
    if dealer_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentPublicMatrixSeedMismatch",
            "dealer VSS commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.vssCoefficientCommitments.dealerRecords.publicMatrixSeedHash",
        )?));
    }
    let Some(dealer_identity) = dealer_record.get("dealerIdentity").and_then(Value::as_str) else {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerIdentityMissing",
            "dealer VSS commitment record must bind dealerIdentity",
            "setupPackage.vssCoefficientCommitments.dealerRecords.dealerIdentity",
        )?));
    };
    let Some(dealer_roster_position) = dealer_record
        .get("dealerRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerRosterPositionMissing",
            "dealer VSS commitment record must bind dealerRosterPosition",
            "setupPackage.vssCoefficientCommitments.dealerRecords.dealerRosterPosition",
        )?));
    };
    if !seen_roster_positions.insert(dealer_roster_position) {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentDuplicate",
            "dealer VSS commitment records must have distinct roster positions",
            "setupPackage.vssCoefficientCommitments.dealerRecords",
        )?));
    }
    if expected_trustees
        .get(&dealer_roster_position)
        .map(String::as_str)
        != Some(dealer_identity)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentTrusteeMismatch",
            "dealer VSS commitment record must match the phase transcript trustee identity",
            "setupPackage.vssCoefficientCommitments.dealerRecords.dealerIdentity",
        )?));
    }

    let Some(coefficient_commitments) = dealer_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.dealerRecords.coefficientCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let expected_coefficient_count =
        DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD as usize;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentCountMismatch",
            "dealer VSS commitment record must contain every Q_share limb and Shamir coefficient",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments",
        )?));
    }
    let mut seen_coefficients = BTreeSet::new();
    for coefficient_record in coefficient_commitments {
        if let Some(response) = verify_vss_coefficient_commitment_record(
            coefficient_record,
            setup_context,
            public_matrix_seed_hash,
            dealer_identity,
            dealer_roster_position,
            &mut seen_coefficients,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(dealer_commitment_root) = dealer_record
        .get("dealerCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.dealerRecords.dealerCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        dealer_commitment_root,
        "vssCoefficientCommitments.dealerRecords.dealerCommitmentRoot",
    )?;
    let mut root_input = dealer_record.clone();
    root_input
        .as_object_mut()
        .expect("VSS dealer commitment object was checked")
        .remove("dealerCommitmentRoot");
    let expected_root = derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if dealer_commitment_root != expected_root {
        return Ok(Some(vss_commitment_refusal(
            "vssDealerCommitmentRootMismatch",
            "dealerCommitmentRoot does not match the canonical dealer commitment record",
            "setupPackage.vssCoefficientCommitments.dealerRecords.dealerCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_coefficient_commitment_record(
    coefficient_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    dealer_identity: &str,
    dealer_roster_position: u64,
    seen_coefficients: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if coefficient_record.get("objectType").and_then(Value::as_str)
        != Some("VssCoefficientCommitment")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentTypeMismatch",
            "VSS coefficient commitment objectType must be VssCoefficientCommitment",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.objectType",
        )?));
    }
    if coefficient_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentVersionMismatch",
            "VSS coefficient commitment objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if coefficient_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_commitment_refusal(
                "vssCoefficientCommitmentContextMismatch",
                format!("VSS coefficient commitment {field_name} must match setupContext"),
                format!(
                    "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.{field_name}"
                ),
            )?));
        }
    }
    if coefficient_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentPublicMatrixSeedMismatch",
            "VSS coefficient commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.publicMatrixSeedHash",
        )?));
    }
    if coefficient_record
        .get("dealerIdentity")
        .and_then(Value::as_str)
        != Some(dealer_identity)
        || coefficient_record
            .get("dealerRosterPosition")
            .and_then(Value::as_u64)
            != Some(dealer_roster_position)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentDealerMismatch",
            "VSS coefficient commitment must bind its dealer record",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.dealerIdentity",
        )?));
    }
    let Some(rns_limb_index) = coefficient_record
        .get("rnsLimbIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbMissing",
            "VSS coefficient commitment must bind rnsLimbIndex",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.rnsLimbIndex",
        )?));
    };
    let Ok(rns_limb_index_usize) = usize::try_from(rns_limb_index) else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbInvalid",
            "VSS coefficient commitment rnsLimbIndex does not fit usize",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.rnsLimbIndex",
        )?));
    };
    if DATA_PRIMES.get(rns_limb_index_usize)
        != coefficient_record
            .get("rnsPrime")
            .and_then(Value::as_u64)
            .as_ref()
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsPrimeMismatch",
            "VSS coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.rnsPrime",
        )?));
    }
    let Some(shamir_coefficient_index) = coefficient_record
        .get("shamirCoefficientIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexMissing",
            "VSS coefficient commitment must bind shamirCoefficientIndex",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    };
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexInvalid",
            "VSS coefficient commitment shamirCoefficientIndex is outside the first-profile threshold degree",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    }
    if !seen_coefficients.insert((rns_limb_index, shamir_coefficient_index)) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentDuplicate",
            "dealer VSS coefficient commitments must have distinct limb/coefficient coordinates",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments",
        )?));
    }
    for field_name in [
        "commitmentRoot",
        "commitmentChunkRoot",
        "coefficientVectorHash512",
    ] {
        let Some(hash) = coefficient_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("vssCoefficientCommitments"),
                vec![format!(
                    "vssCoefficientCommitments.dealerRecords.coefficientCommitments.{field_name}"
                )],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            &format!("vssCoefficientCommitments.dealerRecords.coefficientCommitments.{field_name}"),
        )?;
    }
    if coefficient_record
        .get("openingVerificationStatus")
        .and_then(Value::as_str)
        != Some("pending-private-envelope-opening")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentOpeningStatusMismatch",
            "VSS coefficient commitment openingVerificationStatus must be pending-private-envelope-opening until private VSS envelopes are verified",
            "setupPackage.vssCoefficientCommitments.dealerRecords.coefficientCommitments.openingVerificationStatus",
        )?));
    }

    Ok(None)
}

fn expected_trustees_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before VSS commitment verification",
            )
        })?;
    let Some(first_phase) = phase_transcript.first() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "phaseTranscript was required before VSS commitment verification",
        ));
    };
    let participants = first_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant objects were required before VSS commitment verification",
            )
        })?;
    let mut trustees = BTreeMap::new();
    for participant in participants {
        let Some(roster_position) = participant.get("rosterPosition").and_then(Value::as_u64)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind rosterPosition",
            ));
        };
        let Some(trustee_identity) = participant.get("trusteeIdentity").and_then(Value::as_str)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind trusteeIdentity",
            ));
        };
        trustees.insert(roster_position, trustee_identity.to_string());
    }

    Ok(trustees)
}

fn setup_intent_mailbox_public_key_bindings_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, MailboxPublicKeyBinding>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before mailbox key binding verification",
            )
        })?;
    let setup_intent_phase = phase_transcript
        .iter()
        .find(|phase| phase.get("phaseId").and_then(Value::as_str) == Some("setupIntent"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent phase was required before mailbox key binding verification",
            )
        })?;
    let participants = setup_intent_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent participant objects were required before mailbox key binding verification",
            )
        })?;
    let mut mailbox_public_key_bindings = BTreeMap::new();
    for participant in participants {
        let roster_position = participant
            .get("rosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind rosterPosition",
                )
            })?;
        let public_key_hash = participant
            .get("privateVssMailboxPublicKeyHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind privateVssMailboxPublicKeyHash",
                )
            })?;
        let public_key_bytes_hash = participant
            .get("privateVssMailboxPublicKeyBytesHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind privateVssMailboxPublicKeyBytesHash",
                )
            })?;
        mailbox_public_key_bindings.insert(
            roster_position,
            MailboxPublicKeyBinding {
                public_key_hash: public_key_hash.to_string(),
                public_key_bytes_hash: public_key_bytes_hash.to_string(),
            },
        );
    }

    Ok(mailbox_public_key_bindings)
}

fn vss_commitment_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_private_vss_envelope_commitments(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(commitment_set) = setup_package.get("privateVssEnvelopeCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_set.is_object() {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentsNotObject",
            "privateVssEnvelopeCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.privateVssEnvelopeCommitments",
        )?));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentSetTypeMismatch",
            "privateVssEnvelopeCommitments.objectType must be PrivateVssEnvelopeCommitmentSet",
            "setupPackage.privateVssEnvelopeCommitments.objectType",
        )?));
    }
    if commitment_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentSetVersionMismatch",
            "privateVssEnvelopeCommitments.objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before private VSS envelope verification",
        )
    })?;
    if let Err(refusal) = verify_private_vss_envelope_context(
        commitment_set,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments",
    ) {
        return Ok(Some(private_vss_envelope_refusal(
            refusal.reason_code,
            refusal.message,
            refusal
                .object_path
                .unwrap_or_else(|| "setupPackage.privateVssEnvelopeCommitments".to_string()),
        )?));
    }

    let Some(package_root) = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(package_root, "privateVssEnvelopeCommitmentRoot")?;
    let Some(set_root) = commitment_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        set_root,
        "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
    )?;
    if set_root != package_root {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentRootMismatch",
            "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    if commitment_set
        .get("mailboxEncryptionProfileId")
        .and_then(Value::as_str)
        != Some(PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeMailboxProfileMismatch",
            "privateVssEnvelopeCommitments.mailboxEncryptionProfileId must match the accepted private VSS mailbox profile",
            "setupPackage.privateVssEnvelopeCommitments.mailboxEncryptionProfileId",
        )?));
    }
    if commitment_set
        .get("participantCount")
        .and_then(Value::as_u64)
        != Some(FIRST_PROFILE_PARTICIPANT_COUNT)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeParticipantCountMismatch",
            "privateVssEnvelopeCommitments.participantCount must match the accepted setup profile",
            "setupPackage.privateVssEnvelopeCommitments.participantCount",
        )?));
    }
    let expected_envelope_count = FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_PARTICIPANT_COUNT;
    if commitment_set.get("envelopeCount").and_then(Value::as_u64) != Some(expected_envelope_count)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCountMismatch",
            "privateVssEnvelopeCommitments.envelopeCount must cover every dealer-recipient trustee pair",
            "setupPackage.privateVssEnvelopeCommitments.envelopeCount",
        )?));
    }
    if commitment_set
        .get("deliveryPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeDeliveryPhaseMismatch",
            "privateVssEnvelopeCommitments.deliveryPhaseNumber must match the private envelope delivery phase",
            "setupPackage.privateVssEnvelopeCommitments.deliveryPhaseNumber",
        )?));
    }
    if commitment_set
        .get("verificationPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeVerificationPhaseMismatch",
            "privateVssEnvelopeCommitments.verificationPhaseNumber must match the recipient verification phase",
            "setupPackage.privateVssEnvelopeCommitments.verificationPhaseNumber",
        )?));
    }

    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before private VSS envelope verification",
            )
        })?;
    if commitment_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopePublicMatrixSeedMismatch",
            "privateVssEnvelopeCommitments.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.privateVssEnvelopeCommitments.publicMatrixSeedHash",
        )?));
    }
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before private VSS envelope verification",
            )
        })?;
    if commitment_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeVssCommitmentRootMismatch",
            "privateVssEnvelopeCommitments.vssCoefficientCommitmentRoot must match the accepted VSS coefficient commitments",
            "setupPackage.privateVssEnvelopeCommitments.vssCoefficientCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let setup_intent_mailbox_public_key_bindings =
        setup_intent_mailbox_public_key_bindings_from_phase_transcript(setup_package)?;
    let dealer_commitment_roots = dealer_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &setup_intent_mailbox_public_key_bindings,
        &dealer_commitment_roots,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => {
            if bindings.len() != expected_envelope_count as usize {
                return Ok(Some(private_vss_envelope_refusal(
                    "privateVssEnvelopeCountMismatch",
                    "privateVssEnvelopeCommitments.envelopeReferences must cover every dealer-recipient trustee pair",
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
                )?));
            }
        }
        Err(refusal) => {
            return Ok(Some(private_vss_envelope_refusal(
                refusal.reason_code,
                refusal.message,
                refusal
                    .object_path
                    .unwrap_or_else(|| "setupPackage.privateVssEnvelopeCommitments".to_string()),
            )?));
        }
    }

    let mut root_input = commitment_set.clone();
    root_input
        .as_object_mut()
        .expect("private VSS envelope commitment set object was checked")
        .remove("privateVssEnvelopeCommitmentRoot");
    let expected_root = derive_protocol_hash("PrivateVssEnvelopeCommitmentRoot", &root_input)?;
    if set_root != expected_root {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentRootMismatch",
            "privateVssEnvelopeCommitmentRoot does not match the canonical private VSS envelope commitment set",
            "setupPackage.privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_private_vss_envelope_context(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> Result<(), Refusal> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(Refusal::new(
                "privateVssEnvelopeContextMismatch",
                format!("{object_path}.{field_name} must match setupContext"),
                format!("{object_path}.{field_name}"),
            ));
        }
    }

    Ok(())
}

fn private_vss_envelope_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<PrivateVssEnvelopeBindingMap> {
    let commitment_set = setup_package
        .get("privateVssEnvelopeCommitments")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitments was required before private VSS binding extraction",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before private VSS binding extraction",
        )
    })?;
    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let setup_intent_mailbox_public_key_bindings =
        setup_intent_mailbox_public_key_bindings_from_phase_transcript(setup_package)?;
    let dealer_commitment_roots = dealer_commitment_roots_from_vss_commitments(setup_package)?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before private VSS binding extraction",
            )
        })?;
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before private VSS binding extraction",
            )
        })?;

    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &setup_intent_mailbox_public_key_bindings,
        &dealer_commitment_roots,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => Ok(bindings),
        Err(refusal) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            refusal.message,
        )),
    }
}

fn private_vss_envelope_bindings_from_set(
    commitment_set: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    setup_intent_mailbox_public_key_bindings: &BTreeMap<u64, MailboxPublicKeyBinding>,
    dealer_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBindingMap, Refusal>> {
    let Some(envelope_references) = commitment_set
        .get("envelopeReferences")
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferencesMissing",
            "privateVssEnvelopeCommitments.envelopeReferences must contain every dealer-recipient envelope commitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    };
    let expected_envelope_count =
        (FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_PARTICIPANT_COUNT) as usize;
    if envelope_references.len() != expected_envelope_count {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceCountMismatch",
            "privateVssEnvelopeCommitments.envelopeReferences must contain one record for every dealer-recipient trustee pair",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    }

    let mut bindings = BTreeMap::new();
    for envelope_reference in envelope_references {
        let binding = match private_vss_envelope_binding_from_reference(
            envelope_reference,
            setup_context,
            expected_trustees,
            setup_intent_mailbox_public_key_bindings,
            dealer_commitment_roots,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let dealer_roster_position = value_u64(envelope_reference, "dealerRosterPosition")?;
        let recipient_roster_position = value_u64(envelope_reference, "recipientRosterPosition")?;
        if bindings
            .insert((dealer_roster_position, recipient_roster_position), binding)
            .is_some()
        {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeReferenceDuplicate",
                "privateVssEnvelopeCommitments.envelopeReferences must have distinct dealer-recipient trustee pairs",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
            )));
        }
    }

    Ok(Ok(bindings))
}

fn private_vss_envelope_binding_from_reference(
    envelope_reference: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    setup_intent_mailbox_public_key_bindings: &BTreeMap<u64, MailboxPublicKeyBinding>,
    dealer_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBinding, Refusal>> {
    if envelope_reference.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceTypeMismatch",
            "private VSS envelope commitment objectType must be PrivateVssEnvelopeCommitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.objectType",
        )));
    }
    if envelope_reference
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVersionMismatch",
            "private VSS envelope commitment objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.objectVersion",
        )));
    }
    if let Err(refusal) = verify_private_vss_envelope_context(
        envelope_reference,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
    ) {
        return Ok(Err(refusal));
    }
    if envelope_reference
        .get("mailboxEncryptionProfileId")
        .and_then(Value::as_str)
        != Some(PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceMailboxProfileMismatch",
            "private VSS envelope commitment must bind the accepted mailbox encryption profile",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.mailboxEncryptionProfileId",
        )));
    }
    if envelope_reference
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferencePublicMatrixSeedMismatch",
            "private VSS envelope commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.publicMatrixSeedHash",
        )));
    }
    if envelope_reference
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVssCommitmentRootMismatch",
            "private VSS envelope commitment must bind the accepted VSS coefficient commitment root",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.vssCoefficientCommitmentRoot",
        )));
    }
    if envelope_reference
        .get("deliveryPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceDeliveryPhaseMismatch",
            "private VSS envelope commitment must bind the private envelope delivery phase",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.deliveryPhaseNumber",
        )));
    }
    if envelope_reference
        .get("verificationPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVerificationPhaseMismatch",
            "private VSS envelope commitment must bind the recipient verification phase",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.verificationPhaseNumber",
        )));
    }

    let dealer_identity = match envelope_reference
        .get("dealerIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeDealerMissing",
                "private VSS envelope commitment must bind dealerIdentity",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.dealerIdentity",
            )));
        }
    };
    let dealer_roster_position = match envelope_reference
        .get("dealerRosterPosition")
        .and_then(Value::as_u64)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeDealerPositionMissing",
                "private VSS envelope commitment must bind dealerRosterPosition",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.dealerRosterPosition",
            )));
        }
    };
    if expected_trustees
        .get(&dealer_roster_position)
        .map(String::as_str)
        != Some(dealer_identity)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeDealerMismatch",
            "private VSS envelope commitment dealer must match the phase transcript trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.dealerIdentity",
        )));
    }

    let recipient_identity = match envelope_reference
        .get("recipientIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeRecipientMissing",
                "private VSS envelope commitment must bind recipientIdentity",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientIdentity",
            )));
        }
    };
    let recipient_roster_position = match envelope_reference
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeRecipientPositionMissing",
                "private VSS envelope commitment must bind recipientRosterPosition",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientRosterPosition",
            )));
        }
    };
    if expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeRecipientMismatch",
            "private VSS envelope commitment recipient must match the phase transcript trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientIdentity",
        )));
    }
    let Some(expected_recipient_mailbox_public_key_binding) =
        setup_intent_mailbox_public_key_bindings.get(&recipient_roster_position)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupIntent mailbox public key binding missing for private VSS envelope recipient",
        ));
    };
    let expected_recipient_mailbox_public_key_hash = expected_recipient_mailbox_public_key_binding
        .public_key_hash
        .as_str();
    let expected_recipient_mailbox_public_key_bytes_hash =
        expected_recipient_mailbox_public_key_binding
            .public_key_bytes_hash
            .as_str();
    let Some(recipient_mailbox_public_key_hash) = envelope_reference
        .get("recipientMailboxPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeMailboxPublicKeyMissing",
            "private VSS envelope commitment must bind recipientMailboxPublicKeyHash",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
        )));
    };
    validate_hash_string(
        recipient_mailbox_public_key_hash,
        "privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
    )?;
    if recipient_mailbox_public_key_hash != expected_recipient_mailbox_public_key_hash {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeMailboxPublicKeyMismatch",
            "private VSS envelope commitment recipientMailboxPublicKeyHash must match the setup-intent mailbox key for the recipient",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
        )));
    }
    let expected_sequence_number =
        dealer_roster_position * FIRST_PROFILE_PARTICIPANT_COUNT + recipient_roster_position;
    if envelope_reference
        .get("envelopeSequenceNumber")
        .and_then(Value::as_u64)
        != Some(expected_sequence_number)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSequenceMismatch",
            "private VSS envelope commitment envelopeSequenceNumber must follow dealer-major roster order",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.envelopeSequenceNumber",
        )));
    }

    let expected_dealer_commitment_root = match dealer_commitment_roots
        .get(&dealer_roster_position)
        .map(String::as_str)
    {
        Some(value) => value,
        None => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "dealer commitment root missing for private VSS envelope verification",
            ));
        }
    };
    if envelope_reference
        .get("dealerCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_dealer_commitment_root)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeDealerCommitmentRootMismatch",
            "private VSS envelope commitment dealerCommitmentRoot must match the accepted dealer coefficient commitments",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.dealerCommitmentRoot",
        )));
    }

    for field_name in [
        "privateEnvelopeHash",
        "localVerificationRoot",
        "privateEnvelopeAadHash",
        "encryptedEnvelopeHash",
    ] {
        let Some(hash) = envelope_reference.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeHashMissing",
                format!("private VSS envelope commitment must bind {field_name}"),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.{field_name}"
                ),
            )));
        };
        validate_hash_string(
            hash,
            &format!("privateVssEnvelopeCommitments.envelopeReferences.{field_name}"),
        )?;
    }
    if envelope_reference
        .get("openingVerificationStatus")
        .and_then(Value::as_str)
        != Some("accepted-local-private-vss-opening")
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeOpeningStatusMismatch",
            "private VSS envelope commitment openingVerificationStatus must be accepted-local-private-vss-opening",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.openingVerificationStatus",
        )));
    }

    let expected_aad = private_vss_envelope_aad_value(
        setup_context,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
        dealer_identity,
        dealer_roster_position,
        recipient_identity,
        recipient_roster_position,
        expected_dealer_commitment_root,
        expected_sequence_number,
    )?;
    let Some(private_envelope_aad) = envelope_reference.get("privateEnvelopeAad") else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadMissing",
            "private VSS envelope commitment must publish its AEAD associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAad",
        )));
    };
    if private_envelope_aad != &expected_aad {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadMismatch",
            "private VSS envelope AEAD associated-data object does not match the accepted setup binding",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAad",
        )));
    }
    let expected_aad_hash =
        derive_protocol_hash("PrivateVssEnvelopeAadHash", private_envelope_aad)?;
    if envelope_reference
        .get("privateEnvelopeAadHash")
        .and_then(Value::as_str)
        != Some(expected_aad_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadHashMismatch",
            "privateEnvelopeAadHash does not match the canonical private VSS envelope associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAadHash",
        )));
    }

    let Some(encrypted_envelope) = envelope_reference.get("encryptedEnvelope") else {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeMissing",
            "private VSS envelope commitment must publish the encrypted envelope object it hashes",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
        )));
    };
    if let Err(refusal) = verify_encrypted_private_vss_envelope(
        encrypted_envelope,
        setup_context,
        &expected_aad,
        &expected_aad_hash,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
        dealer_identity,
        dealer_roster_position,
        recipient_identity,
        recipient_roster_position,
        expected_recipient_mailbox_public_key_hash,
        expected_recipient_mailbox_public_key_bytes_hash,
        expected_dealer_commitment_root,
        expected_sequence_number,
        value_string(envelope_reference, "privateEnvelopeHash")?,
        value_string(envelope_reference, "encryptedEnvelopeHash")?,
    )? {
        return Ok(Err(refusal));
    }

    let Some(private_envelope_commitment_root) = envelope_reference
        .get("privateEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeCommitmentRecordRootMissing",
            "private VSS envelope commitment must bind privateEnvelopeCommitmentRoot",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
        )));
    };
    validate_hash_string(
        private_envelope_commitment_root,
        "privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
    )?;
    let mut record_root_input = envelope_reference.clone();
    record_root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference object was checked")
        .remove("privateEnvelopeCommitmentRoot");
    let expected_record_root =
        derive_protocol_hash("PrivateVssEnvelopeCommitmentRoot", &record_root_input)?;
    if private_envelope_commitment_root != expected_record_root {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeCommitmentRecordRootMismatch",
            "privateEnvelopeCommitmentRoot does not match the canonical private VSS envelope commitment record",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
        )));
    }

    Ok(Ok(PrivateVssEnvelopeBinding {
        dealer_identity: dealer_identity.to_string(),
        recipient_identity: recipient_identity.to_string(),
        dealer_commitment_root: expected_dealer_commitment_root.to_string(),
        private_envelope_hash: value_string(envelope_reference, "privateEnvelopeHash")?.to_string(),
        local_verification_root: value_string(envelope_reference, "localVerificationRoot")?
            .to_string(),
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_encrypted_private_vss_envelope(
    encrypted_envelope: &Value,
    setup_context: &Value,
    expected_aad: &Value,
    expected_aad_hash: &str,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    dealer_identity: &str,
    dealer_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    expected_recipient_mailbox_public_key_hash: &str,
    expected_recipient_mailbox_public_key_bytes_hash: &str,
    dealer_commitment_root: &str,
    envelope_sequence_number: u64,
    private_envelope_hash: &str,
    encrypted_envelope_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    if !encrypted_envelope.is_object() {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeNotObject",
            "encryptedEnvelope must be a root-bound object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
        )));
    }
    if encrypted_envelope.get("objectType").and_then(Value::as_str)
        != Some(ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeTypeMismatch",
            "encryptedEnvelope.objectType must be EncryptedPrivateVssShareEnvelope",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.objectType",
        )));
    }
    if encrypted_envelope
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeVersionMismatch",
            "encryptedEnvelope.objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.objectVersion",
        )));
    }
    if let Err(refusal) = verify_private_vss_envelope_context(
        encrypted_envelope,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
    ) {
        return Ok(Err(refusal));
    }

    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        (
            "mailboxEncryptionProfileId",
            PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID,
        ),
        ("ciphertextContentType", "private-vss-share-envelope"),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
        (
            "vssCoefficientCommitmentRoot",
            vss_coefficient_commitment_root,
        ),
        ("dealerIdentity", dealer_identity),
        ("recipientIdentity", recipient_identity),
        (
            "recipientMailboxPublicKeyHash",
            expected_recipient_mailbox_public_key_hash,
        ),
        ("dealerCommitmentRoot", dealer_commitment_root),
        ("privateEnvelopeHash", private_envelope_hash),
        ("privateEnvelopeAadHash", expected_aad_hash),
    ] {
        if encrypted_envelope.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeBindingMismatch",
                format!(
                    "encryptedEnvelope.{field_name} must match the private envelope commitment binding"
                ),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        }
    }
    for (field_name, expected_value) in [
        ("dealerRosterPosition", dealer_roster_position),
        ("recipientRosterPosition", recipient_roster_position),
        ("envelopeSequenceNumber", envelope_sequence_number),
        (
            "deliveryPhaseNumber",
            PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER,
        ),
        (
            "verificationPhaseNumber",
            PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER,
        ),
        ("aeadTagLength", 128),
    ] {
        if encrypted_envelope.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeBindingMismatch",
                format!(
                    "encryptedEnvelope.{field_name} must match the private envelope commitment binding"
                ),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        }
    }

    if encrypted_envelope.get("privateEnvelopeAad") != Some(expected_aad) {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeAadMismatch",
            "encryptedEnvelope.privateEnvelopeAad must match the accepted private envelope associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.privateEnvelopeAad",
        )));
    }

    for field_name in [
        "recipientMailboxPublicKeyHash",
        "recipientMailboxPublicKeyBytesHash",
        "kemCiphertextHash",
        "ciphertextBytesHash",
    ] {
        let Some(hash) = encrypted_envelope.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeHashMissing",
                format!("encryptedEnvelope.{field_name} must be present"),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        };
        validate_hash_string(hash, &format!("encryptedEnvelope.{field_name}"))?;
    }
    if encrypted_envelope
        .get("recipientMailboxPublicKeyBytesHash")
        .and_then(Value::as_str)
        != Some(expected_recipient_mailbox_public_key_bytes_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch",
            "encryptedEnvelope.recipientMailboxPublicKeyBytesHash must match the setup-intent mailbox key bytes hash for the recipient",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.recipientMailboxPublicKeyBytesHash",
        )));
    }

    let Some(kem_ciphertext_bytes_hex) = encrypted_envelope
        .get("kemCiphertextBytesHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextMissing",
            "encryptedEnvelope.kemCiphertextBytesHex must be present",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.kemCiphertextBytesHex",
        )));
    };
    validate_lowercase_hex_length(
        kem_ciphertext_bytes_hex,
        1088,
        "encryptedEnvelope.kemCiphertextBytesHex",
    )?;
    let kem_ciphertext_bytes = crate::transcript_core::decode_hex(kem_ciphertext_bytes_hex)?;
    let expected_kem_ciphertext_hash = hash512_hex(
        "sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1",
        &[&kem_ciphertext_bytes],
    );
    if encrypted_envelope
        .get("kemCiphertextHash")
        .and_then(Value::as_str)
        != Some(expected_kem_ciphertext_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeKemCiphertextHashMismatch",
            "encryptedEnvelope.kemCiphertextHash must match kemCiphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.kemCiphertextHash",
        )));
    }
    let Some(aead_nonce_hex) = encrypted_envelope
        .get("aeadNonceHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeNonceMissing",
            "encryptedEnvelope.aeadNonceHex must be present",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.aeadNonceHex",
        )));
    };
    validate_lowercase_hex_length(aead_nonce_hex, 12, "encryptedEnvelope.aeadNonceHex")?;
    let Some(ciphertext_bytes_hex) = encrypted_envelope
        .get("ciphertextBytesHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextMissing",
            "encryptedEnvelope.ciphertextBytesHex must be present",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextBytesHex",
        )));
    };
    validate_lowercase_hex(ciphertext_bytes_hex, "encryptedEnvelope.ciphertextBytesHex")?;
    let ciphertext_bytes = crate::transcript_core::decode_hex(ciphertext_bytes_hex)?;
    let expected_ciphertext_bytes_hash = hash512_hex(
        "sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1",
        &[&ciphertext_bytes],
    );
    if encrypted_envelope
        .get("ciphertextBytesHash")
        .and_then(Value::as_str)
        != Some(expected_ciphertext_bytes_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch",
            "encryptedEnvelope.ciphertextBytesHash must match ciphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextBytesHash",
        )));
    }
    if encrypted_envelope
        .get("ciphertextByteLength")
        .and_then(Value::as_u64)
        != Some((ciphertext_bytes_hex.len() / 2) as u64)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextLengthMismatch",
            "encryptedEnvelope.ciphertextByteLength must match ciphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextByteLength",
        )));
    }

    if encrypted_envelope
        .get("encryptedEnvelopeHash")
        .and_then(Value::as_str)
        != Some(encrypted_envelope_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeHashMismatch",
            "encryptedEnvelope.encryptedEnvelopeHash must match the commitment reference",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.encryptedEnvelopeHash",
        )));
    }
    let mut encrypted_envelope_root_input = encrypted_envelope.clone();
    encrypted_envelope_root_input
        .as_object_mut()
        .expect("encrypted envelope object was checked")
        .remove("encryptedEnvelopeHash");
    let expected_encrypted_envelope_hash = derive_protocol_hash(
        "PrivateVssEncryptedEnvelopeHash",
        &encrypted_envelope_root_input,
    )?;
    if encrypted_envelope_hash != expected_encrypted_envelope_hash {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeHashMismatch",
            "encryptedEnvelopeHash does not match the canonical encrypted private VSS envelope object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelopeHash",
        )));
    }

    Ok(Ok(()))
}

#[allow(clippy::too_many_arguments)]
fn private_vss_envelope_aad_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    dealer_identity: &str,
    dealer_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    dealer_commitment_root: &str,
    envelope_sequence_number: u64,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "mailboxEncryptionProfileId": PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID,
        "privateEnvelopeObjectType": "PrivateVssShareEnvelope",
        "ciphertextContentType": "private-vss-share-envelope",
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
        "qShareHash": setup_context_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": setup_context_string(
            setup_context,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": setup_context_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "phaseOrderHash": phase_order_hash()?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "dealerIdentity": dealer_identity,
        "dealerRosterPosition": dealer_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "dealerCommitmentRoot": dealer_commitment_root,
        "envelopeSequenceNumber": envelope_sequence_number,
        "deliveryPhaseNumber": PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER,
        "verificationPhaseNumber": PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER,
        "recipientVerificationRequirement": "recipient-verifies-private-vss-opening-before-acceptance",
    }))
}

fn private_vss_envelope_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("privateVssEnvelopeDelivery"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_vss_complaints(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(complaint_set) = setup_package.get("vssComplaints") else {
        return Ok(None);
    };
    if !complaint_set.is_object() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintsNotObject",
            "vssComplaints must be a root-bound object, not an array or scalar",
            "setupPackage.vssComplaints",
        )?));
    }
    if complaint_set.get("objectType").and_then(Value::as_str) != Some("VssComplaintSet") {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSetTypeMismatch",
            "vssComplaints.objectType must be VssComplaintSet",
            "setupPackage.vssComplaints.objectType",
        )?));
    }
    if complaint_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSetVersionMismatch",
            "vssComplaints.objectVersion must be 1",
            "setupPackage.vssComplaints.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS complaint verification",
        )
    })?;
    if let Err(error) = verify_vss_complaint_context(complaint_set, setup_context) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextMismatch",
            error.message,
            "setupPackage.vssComplaints",
        )?));
    }

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitmentRoot was required before VSS complaint verification",
            )
        })?;
    validate_hash_string(
        private_vss_envelope_commitment_root,
        "privateVssEnvelopeCommitmentRoot",
    )?;
    if complaint_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRootMismatch",
            "vssComplaints.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssComplaints.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let dealer_commitment_roots = dealer_commitment_roots_from_vss_commitments(setup_package)?;
    let private_vss_envelope_bindings = private_vss_envelope_bindings_from_package(setup_package)?;
    let Some(complaint_records) = complaint_set
        .get("complaintRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsMissing",
            "vssComplaints.complaintRecords must contain at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    };
    if complaint_records.is_empty() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsEmpty",
            "vssComplaints must be omitted unless it contains at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    }

    let mut seen_complaints = BTreeSet::new();
    for complaint_record in complaint_records {
        if let Some(response) = verify_vss_complaint_record(
            complaint_record,
            setup_context,
            &expected_trustees,
            &dealer_commitment_roots,
            private_vss_envelope_commitment_root,
            &private_vss_envelope_bindings,
            &mut seen_complaints,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(complaint_root) = complaint_set
        .get("vssComplaintRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMissing",
            "vssComplaints.vssComplaintRoot must root-bind the complaint set",
            "setupPackage.vssComplaints.vssComplaintRoot",
        )?));
    };
    validate_hash_string(complaint_root, "vssComplaints.vssComplaintRoot")?;
    let mut root_input = complaint_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS complaint set object was checked")
        .remove("vssComplaintRoot");
    let expected_root = derive_protocol_hash("VssComplaintRoot", &root_input)?;
    if complaint_root != expected_root {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMismatch",
            "vssComplaintRoot does not match the canonical VSS complaint set",
            "setupPackage.vssComplaints.vssComplaintRoot",
        )?));
    }

    Ok(Some(verification_response(
        VerifierStatus::Aborted,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(
            "vssComplaintAcceptedAbort",
            "a valid VSS complaint aborts the first-profile setup ceremony",
            "setupPackage.vssComplaints",
        )],
        vec![complaint_root.to_string()],
    )?))
}

fn verify_vss_complaint_context(
    complaint_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if complaint_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("vssComplaints.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn verify_vss_complaint_record(
    complaint_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    dealer_commitment_roots: &BTreeMap<u64, String>,
    private_vss_envelope_commitment_root: &str,
    private_vss_envelope_bindings: &PrivateVssEnvelopeBindingMap,
    seen_complaints: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if complaint_record.get("objectType").and_then(Value::as_str) != Some("VssShareComplaint") {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintTypeMismatch",
            "VSS complaint objectType must be VssShareComplaint",
            "setupPackage.vssComplaints.complaintRecords.objectType",
        )?));
    }
    if complaint_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintVersionMismatch",
            "VSS complaint objectVersion must be 1",
            "setupPackage.vssComplaints.complaintRecords.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if complaint_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_complaint_refusal(
                "vssComplaintContextMismatch",
                format!("VSS complaint {field_name} must match setupContext"),
                format!("setupPackage.vssComplaints.complaintRecords.{field_name}"),
            )?));
        }
    }
    if complaint_record
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRootMismatch",
            "VSS complaint must bind setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssComplaints.complaintRecords.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let Some(dealer_identity) = complaint_record
        .get("dealerIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDealerMissing",
            "VSS complaint must bind dealerIdentity",
            "setupPackage.vssComplaints.complaintRecords.dealerIdentity",
        )?));
    };
    let Some(dealer_roster_position) = complaint_record
        .get("dealerRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDealerPositionMissing",
            "VSS complaint must bind dealerRosterPosition",
            "setupPackage.vssComplaints.complaintRecords.dealerRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&dealer_roster_position)
        .map(String::as_str)
        != Some(dealer_identity)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDealerMismatch",
            "VSS complaint dealer must match the phase transcript trustee identity",
            "setupPackage.vssComplaints.complaintRecords.dealerIdentity",
        )?));
    }

    let Some(recipient_identity) = complaint_record
        .get("recipientIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientMissing",
            "VSS complaint must bind recipientIdentity",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    };
    let Some(recipient_roster_position) = complaint_record
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientPositionMissing",
            "VSS complaint must bind recipientRosterPosition",
            "setupPackage.vssComplaints.complaintRecords.recipientRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientMismatch",
            "VSS complaint recipient must match the phase transcript trustee identity",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    }
    if !seen_complaints.insert((dealer_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDuplicate",
            "VSS complaint records must have distinct dealer-recipient trustee pairs",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    }

    let expected_dealer_commitment_root = dealer_commitment_roots
        .get(&dealer_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "dealer commitment root missing for VSS complaint verification",
            )
        })?;
    if complaint_record
        .get("dealerCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_dealer_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDealerCommitmentRootMismatch",
            "VSS complaint dealerCommitmentRoot must match the accepted dealer coefficient commitments",
            "setupPackage.vssComplaints.complaintRecords.dealerCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) =
        private_vss_envelope_bindings.get(&(dealer_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeBindingMissing",
            "VSS complaint must match a private VSS envelope commitment for the dealer-recipient pair",
            "setupPackage.vssComplaints.complaintRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.dealer_identity != dealer_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeDealerMismatch",
            "VSS complaint dealer must match the private VSS envelope commitment dealer",
            "setupPackage.vssComplaints.complaintRecords.dealerIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRecipientMismatch",
            "VSS complaint recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.dealer_commitment_root != expected_dealer_commitment_root {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeDealerCommitmentRootMismatch",
            "VSS complaint dealerCommitmentRoot must match the private VSS envelope commitment dealer root",
            "setupPackage.vssComplaints.complaintRecords.dealerCommitmentRoot",
        )?));
    }

    for field_name in ["privateEnvelopeHash", "complaintEvidenceRoot"] {
        let Some(hash) = complaint_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(vss_complaint_refusal(
                "vssComplaintHashMissing",
                format!("VSS complaint must bind {field_name}"),
                format!("setupPackage.vssComplaints.complaintRecords.{field_name}"),
            )?));
        };
        validate_hash_string(
            hash,
            &format!("vssComplaints.complaintRecords.{field_name}"),
        )?;
    }
    if complaint_record
        .get("privateEnvelopeHash")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_binding.private_envelope_hash.as_str())
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeHashMismatch",
            "VSS complaint privateEnvelopeHash must match the private VSS envelope commitment",
            "setupPackage.vssComplaints.complaintRecords.privateEnvelopeHash",
        )?));
    }
    if complaint_record
        .get("complaintReasonCode")
        .and_then(Value::as_str)
        .filter(|reason_code| !reason_code.is_empty())
        .is_none()
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintReasonMissing",
            "VSS complaint must bind a non-empty complaintReasonCode",
            "setupPackage.vssComplaints.complaintRecords.complaintReasonCode",
        )?));
    }
    if complaint_record
        .get("complaintStatus")
        .and_then(Value::as_str)
        != Some("valid-complaint-aborts-setup")
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintStatusMismatch",
            "VSS complaint complaintStatus must be valid-complaint-aborts-setup",
            "setupPackage.vssComplaints.complaintRecords.complaintStatus",
        )?));
    }

    let recovery_epoch = complaint_record
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint recoveryEpoch must be a non-negative integer",
            )
        })?;
    let device_epoch = complaint_record
        .get("deviceEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint deviceEpoch must be a non-negative integer",
            )
        })?;
    let Some(signing_public_key_hash) = complaint_record
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSigningKeyMissing",
            "VSS complaint must bind signingPublicKeyHash",
            "setupPackage.vssComplaints.complaintRecords.signingPublicKeyHash",
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "vssComplaints.complaintRecords.signingPublicKeyHash",
    )?;

    let complaint_payload = vss_complaint_payload_value(complaint_record)?;
    let expected_complaint_root = derive_protocol_hash("VssComplaintRoot", &complaint_payload)?;
    let Some(complaint_root) = complaint_record
        .get("complaintRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMissing",
            "VSS complaint must bind complaintRoot",
            "setupPackage.vssComplaints.complaintRecords.complaintRoot",
        )?));
    };
    validate_hash_string(
        complaint_root,
        "vssComplaints.complaintRecords.complaintRoot",
    )?;
    if complaint_root != expected_complaint_root {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMismatch",
            "VSS complaint root does not match the canonical complaint payload",
            "setupPackage.vssComplaints.complaintRecords.complaintRoot",
        )?));
    }

    let expected_byte_length =
        u64::try_from(canonical_json(&complaint_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint payload byte length does not fit u64",
            )
        })?;
    let Some(complaint_byte_length) = complaint_record
        .get("complaintByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintByteLengthMissing",
            "VSS complaint must bind complaintByteLength",
            "setupPackage.vssComplaints.complaintRecords.complaintByteLength",
        )?));
    };
    if complaint_byte_length != expected_byte_length {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintByteLengthMismatch",
            "VSS complaint byte length does not match the canonical complaint payload",
            "setupPackage.vssComplaints.complaintRecords.complaintByteLength",
        )?));
    }

    let expected_context_hash =
        vss_complaint_signature_context_hash(complaint_record, complaint_root)?;
    let Some(complaint_context_hash) = complaint_record
        .get("complaintContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextHashMissing",
            "VSS complaint must bind complaintContextHash",
            "setupPackage.vssComplaints.complaintRecords.complaintContextHash",
        )?));
    };
    validate_hash_string(
        complaint_context_hash,
        "vssComplaints.complaintRecords.complaintContextHash",
    )?;
    if complaint_context_hash != expected_context_hash {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextHashMismatch",
            "VSS complaint context hash does not match the signed complaint binding",
            "setupPackage.vssComplaints.complaintRecords.complaintContextHash",
        )?));
    }

    let Some(signature_envelope_hash) = complaint_record
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureHashMissing",
            "VSS complaint must bind signatureEnvelopeHash",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelopeHash",
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        "vssComplaints.complaintRecords.signatureEnvelopeHash",
    )?;
    let Some(signature_envelope) = complaint_record.get("signatureEnvelope") else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureMissing",
            "VSS complaint must include the signed ML-DSA envelope",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelope",
        )?));
    };
    let manifest_hash = setup_context_string(setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "VssShareComplaint",
            object_version: 1,
            signer_role: "Trustee",
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(complaint_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: complaint_context_hash,
            byte_length: complaint_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureHashMismatch",
            "VSS complaint signature envelope hash does not match the verified envelope",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelopeHash",
        )?)),
        Err(failure) => Ok(Some(vss_complaint_refusal(
            failure.reason_code,
            failure.message,
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelope",
        )?)),
    }
}

fn vss_complaint_payload_value(complaint_record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "VssShareComplaint",
        "objectVersion": 1,
        "ceremonyId": value_string(complaint_record, "ceremonyId")?,
        "manifestHash": value_string(complaint_record, "manifestHash")?,
        "rosterHash": value_string(complaint_record, "rosterHash")?,
        "setupProfileHash": value_string(complaint_record, "setupProfileHash")?,
        "qShareHash": value_string(complaint_record, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            complaint_record,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(complaint_record, "commitmentProfileHash")?,
        "setupEpoch": value_string(complaint_record, "setupEpoch")?,
        "dealerIdentity": value_string(complaint_record, "dealerIdentity")?,
        "dealerRosterPosition": value_u64(complaint_record, "dealerRosterPosition")?,
        "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
        "dealerCommitmentRoot": value_string(complaint_record, "dealerCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            complaint_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(complaint_record, "privateEnvelopeHash")?,
        "complaintEvidenceRoot": value_string(complaint_record, "complaintEvidenceRoot")?,
        "complaintReasonCode": value_string(complaint_record, "complaintReasonCode")?,
        "complaintStatus": "valid-complaint-aborts-setup",
        "recoveryEpoch": value_u64(complaint_record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(complaint_record, "deviceEpoch")?,
        "signingPublicKeyHash": value_string(complaint_record, "signingPublicKeyHash")?,
    }))
}

fn vss_complaint_signature_context_hash(
    complaint_record: &Value,
    complaint_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "VssComplaintRoot",
        &json!({
            "purpose": "vss-share-complaint-signature-context",
            "ceremonyId": value_string(complaint_record, "ceremonyId")?,
            "manifestHash": value_string(complaint_record, "manifestHash")?,
            "rosterHash": value_string(complaint_record, "rosterHash")?,
            "setupProfileHash": value_string(complaint_record, "setupProfileHash")?,
            "qShareHash": value_string(complaint_record, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": value_string(
                complaint_record,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": value_string(complaint_record, "commitmentProfileHash")?,
            "setupEpoch": value_string(complaint_record, "setupEpoch")?,
            "dealerIdentity": value_string(complaint_record, "dealerIdentity")?,
            "dealerRosterPosition": value_u64(complaint_record, "dealerRosterPosition")?,
            "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
            "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
            "dealerCommitmentRoot": value_string(complaint_record, "dealerCommitmentRoot")?,
            "privateVssEnvelopeCommitmentRoot": value_string(
                complaint_record,
                "privateVssEnvelopeCommitmentRoot",
            )?,
            "privateEnvelopeHash": value_string(complaint_record, "privateEnvelopeHash")?,
            "complaintEvidenceRoot": value_string(complaint_record, "complaintEvidenceRoot")?,
            "complaintReasonCode": value_string(complaint_record, "complaintReasonCode")?,
            "complaintRoot": complaint_root,
        }),
    )
}

fn vss_complaint_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_vss_share_acceptances(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(acceptance_set) = setup_package.get("vssShareAcceptances") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !acceptance_set.is_object() {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancesNotObject",
            "vssShareAcceptances must be a root-bound object, not an array or scalar",
            "setupPackage.vssShareAcceptances",
        )?));
    }
    if acceptance_set.get("objectType").and_then(Value::as_str) != Some("VssShareAcceptanceSet") {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSetTypeMismatch",
            "vssShareAcceptances.objectType must be VssShareAcceptanceSet",
            "setupPackage.vssShareAcceptances.objectType",
        )?));
    }
    if acceptance_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSetVersionMismatch",
            "vssShareAcceptances.objectVersion must be 1",
            "setupPackage.vssShareAcceptances.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS share acceptance verification",
        )
    })?;
    if let Err(error) = verify_vss_share_acceptance_context(acceptance_set, setup_context) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceContextMismatch",
            error.message,
            "setupPackage.vssShareAcceptances",
        )?));
    }

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitmentRoot was required before VSS share acceptance verification",
            )
        })?;
    validate_hash_string(
        private_vss_envelope_commitment_root,
        "privateVssEnvelopeCommitmentRoot",
    )?;
    if acceptance_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRootMismatch",
            "vssShareAcceptances.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssShareAcceptances.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let dealer_commitment_roots = dealer_commitment_roots_from_vss_commitments(setup_package)?;
    let private_vss_envelope_bindings = private_vss_envelope_bindings_from_package(setup_package)?;
    let Some(acceptance_records) = acceptance_set
        .get("acceptanceRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let expected_acceptance_count =
        (FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_PARTICIPANT_COUNT) as usize;
    if acceptance_records.len() != expected_acceptance_count {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceCountMismatch",
            "vssShareAcceptances.acceptanceRecords must contain one record for every dealer-recipient trustee pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let mut seen_acceptances = BTreeSet::new();
    for acceptance_record in acceptance_records {
        if let Some(response) = verify_vss_share_acceptance_record(
            acceptance_record,
            setup_context,
            &expected_trustees,
            &dealer_commitment_roots,
            private_vss_envelope_commitment_root,
            &private_vss_envelope_bindings,
            &mut seen_acceptances,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(acceptance_root) = acceptance_set
        .get("vssShareAcceptanceRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.vssShareAcceptanceRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_root,
        "vssShareAcceptances.vssShareAcceptanceRoot",
    )?;
    let mut root_input = acceptance_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS share acceptance set object was checked")
        .remove("vssShareAcceptanceRoot");
    let expected_root = derive_protocol_hash("VssShareAcceptanceRoot", &root_input)?;
    if acceptance_root != expected_root {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRootMismatch",
            "vssShareAcceptanceRoot does not match the canonical VSS share acceptance set",
            "setupPackage.vssShareAcceptances.vssShareAcceptanceRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_share_acceptance_context(
    acceptance_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if acceptance_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("vssShareAcceptances.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn dealer_commitment_roots_from_vss_commitments(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let dealer_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("dealerRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS dealer commitments were required before VSS share acceptance verification",
            )
        })?;
    let mut dealer_roots = BTreeMap::new();
    for dealer_record in dealer_records {
        let dealer_roster_position = dealer_record
            .get("dealerRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "dealer VSS commitment record must bind dealerRosterPosition",
                )
            })?;
        let dealer_commitment_root = dealer_record
            .get("dealerCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "dealer VSS commitment record must bind dealerCommitmentRoot",
                )
            })?;
        dealer_roots.insert(dealer_roster_position, dealer_commitment_root.to_string());
    }

    Ok(dealer_roots)
}

fn verify_vss_share_acceptance_record(
    acceptance_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    dealer_commitment_roots: &BTreeMap<u64, String>,
    private_vss_envelope_commitment_root: &str,
    private_vss_envelope_bindings: &PrivateVssEnvelopeBindingMap,
    seen_acceptances: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if acceptance_record.get("objectType").and_then(Value::as_str) != Some("VssShareAcceptance") {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceTypeMismatch",
            "VSS share acceptance objectType must be VssShareAcceptance",
            "setupPackage.vssShareAcceptances.acceptanceRecords.objectType",
        )?));
    }
    if acceptance_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceVersionMismatch",
            "VSS share acceptance objectVersion must be 1",
            "setupPackage.vssShareAcceptances.acceptanceRecords.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if acceptance_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_share_acceptance_refusal(
                "vssShareAcceptanceContextMismatch",
                format!("VSS share acceptance {field_name} must match setupContext"),
                format!("setupPackage.vssShareAcceptances.acceptanceRecords.{field_name}"),
            )?));
        }
    }
    if acceptance_record
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRootMismatch",
            "VSS share acceptance must bind setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let Some(dealer_identity) = acceptance_record
        .get("dealerIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDealerMissing",
            "VSS share acceptance must bind dealerIdentity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerIdentity",
        )?));
    };
    let Some(dealer_roster_position) = acceptance_record
        .get("dealerRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDealerPositionMissing",
            "VSS share acceptance must bind dealerRosterPosition",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&dealer_roster_position)
        .map(String::as_str)
        != Some(dealer_identity)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDealerMismatch",
            "VSS share acceptance dealer must match the phase transcript trustee identity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerIdentity",
        )?));
    }

    let Some(recipient_identity) = acceptance_record
        .get("recipientIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientMissing",
            "VSS share acceptance must bind recipientIdentity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    };
    let Some(recipient_roster_position) = acceptance_record
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientPositionMissing",
            "VSS share acceptance must bind recipientRosterPosition",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientMismatch",
            "VSS share acceptance recipient must match the phase transcript trustee identity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    }
    if !seen_acceptances.insert((dealer_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDuplicate",
            "VSS share acceptance records must have distinct dealer-recipient trustee pairs",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let expected_dealer_commitment_root = dealer_commitment_roots
        .get(&dealer_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "dealer commitment root missing for VSS share acceptance verification",
            )
        })?;
    if acceptance_record
        .get("dealerCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_dealer_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDealerCommitmentRootMismatch",
            "VSS share acceptance dealerCommitmentRoot must match the accepted dealer coefficient commitments",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) =
        private_vss_envelope_bindings.get(&(dealer_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeBindingMissing",
            "VSS share acceptance must match a private VSS envelope commitment for the dealer-recipient pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.dealer_identity != dealer_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeDealerMismatch",
            "VSS share acceptance dealer must match the private VSS envelope commitment dealer",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRecipientMismatch",
            "VSS share acceptance recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.dealer_commitment_root != expected_dealer_commitment_root {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeDealerCommitmentRootMismatch",
            "VSS share acceptance dealerCommitmentRoot must match the private VSS envelope commitment dealer root",
            "setupPackage.vssShareAcceptances.acceptanceRecords.dealerCommitmentRoot",
        )?));
    }

    for field_name in ["privateEnvelopeHash", "localVerificationRoot"] {
        let Some(hash) = acceptance_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("vssAcceptanceOrComplaint"),
                vec![format!(
                    "vssShareAcceptances.acceptanceRecords.{field_name}"
                )],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            &format!("vssShareAcceptances.acceptanceRecords.{field_name}"),
        )?;
    }
    if acceptance_record
        .get("privateEnvelopeHash")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_binding.private_envelope_hash.as_str())
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeHashMismatch",
            "VSS share acceptance privateEnvelopeHash must match the private VSS envelope commitment",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateEnvelopeHash",
        )?));
    }
    if acceptance_record
        .get("localVerificationRoot")
        .and_then(Value::as_str)
        != Some(
            private_vss_envelope_binding
                .local_verification_root
                .as_str(),
        )
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceLocalVerificationRootMismatch",
            "VSS share acceptance localVerificationRoot must match the private VSS envelope commitment",
            "setupPackage.vssShareAcceptances.acceptanceRecords.localVerificationRoot",
        )?));
    }
    if acceptance_record
        .get("verificationStatus")
        .and_then(Value::as_str)
        != Some("accepted")
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceStatusMismatch",
            "VSS share acceptance verificationStatus must be accepted",
            "setupPackage.vssShareAcceptances.acceptanceRecords.verificationStatus",
        )?));
    }

    let recovery_epoch = acceptance_record
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance recoveryEpoch must be a non-negative integer",
            )
        })?;
    let device_epoch = acceptance_record
        .get("deviceEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance deviceEpoch must be a non-negative integer",
            )
        })?;
    let Some(signing_public_key_hash) = acceptance_record
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSigningKeyMissing",
            "VSS share acceptance must bind signingPublicKeyHash",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signingPublicKeyHash",
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "vssShareAcceptances.acceptanceRecords.signingPublicKeyHash",
    )?;

    let acceptance_payload = vss_share_acceptance_payload_value(acceptance_record)?;
    let expected_acceptance_root =
        derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_payload)?;
    let Some(acceptance_root) = acceptance_record
        .get("acceptanceRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_root,
        "vssShareAcceptances.acceptanceRecords.acceptanceRoot",
    )?;
    if acceptance_root != expected_acceptance_root {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRootMismatch",
            "VSS share acceptance root does not match the canonical acceptance payload",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceRoot",
        )?));
    }

    let expected_byte_length =
        u64::try_from(canonical_json(&acceptance_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance payload byte length does not fit u64",
            )
        })?;
    let Some(acceptance_byte_length) = acceptance_record
        .get("acceptanceByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceByteLength".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if acceptance_byte_length != expected_byte_length {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceByteLengthMismatch",
            "VSS share acceptance byte length does not match the canonical acceptance payload",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceByteLength",
        )?));
    }

    let expected_context_hash =
        vss_share_acceptance_signature_context_hash(acceptance_record, acceptance_root)?;
    let Some(acceptance_context_hash) = acceptance_record
        .get("acceptanceContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceContextHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_context_hash,
        "vssShareAcceptances.acceptanceRecords.acceptanceContextHash",
    )?;
    if acceptance_context_hash != expected_context_hash {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceContextHashMismatch",
            "VSS share acceptance context hash does not match the signed acceptance binding",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceContextHash",
        )?));
    }

    let Some(signature_envelope_hash) = acceptance_record
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        "vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash",
    )?;
    let Some(signature_envelope) = acceptance_record.get("signatureEnvelope") else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSignatureMissing",
            "VSS share acceptance must include the signed ML-DSA envelope",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelope",
        )?));
    };
    let manifest_hash = setup_context_string(setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "VssShareAcceptance",
            object_version: 1,
            signer_role: "Trustee",
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(acceptance_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: acceptance_context_hash,
            byte_length: acceptance_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSignatureHashMismatch",
            "VSS share acceptance signature envelope hash does not match the verified envelope",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash",
        )?)),
        Err(failure) => Ok(Some(vss_share_acceptance_refusal(
            failure.reason_code,
            failure.message,
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelope",
        )?)),
    }
}

fn vss_share_acceptance_payload_value(acceptance_record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "VssShareAcceptance",
        "objectVersion": 1,
        "ceremonyId": value_string(acceptance_record, "ceremonyId")?,
        "manifestHash": value_string(acceptance_record, "manifestHash")?,
        "rosterHash": value_string(acceptance_record, "rosterHash")?,
        "setupProfileHash": value_string(acceptance_record, "setupProfileHash")?,
        "qShareHash": value_string(acceptance_record, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            acceptance_record,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(acceptance_record, "commitmentProfileHash")?,
        "setupEpoch": value_string(acceptance_record, "setupEpoch")?,
        "dealerIdentity": value_string(acceptance_record, "dealerIdentity")?,
        "dealerRosterPosition": value_u64(acceptance_record, "dealerRosterPosition")?,
        "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
        "dealerCommitmentRoot": value_string(acceptance_record, "dealerCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            acceptance_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(acceptance_record, "privateEnvelopeHash")?,
        "localVerificationRoot": value_string(acceptance_record, "localVerificationRoot")?,
        "verificationStatus": "accepted",
        "recoveryEpoch": value_u64(acceptance_record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(acceptance_record, "deviceEpoch")?,
        "signingPublicKeyHash": value_string(acceptance_record, "signingPublicKeyHash")?,
    }))
}

fn vss_share_acceptance_signature_context_hash(
    acceptance_record: &Value,
    acceptance_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "VssShareAcceptanceRoot",
        &json!({
            "purpose": "vss-share-acceptance-signature-context",
            "ceremonyId": value_string(acceptance_record, "ceremonyId")?,
            "manifestHash": value_string(acceptance_record, "manifestHash")?,
            "rosterHash": value_string(acceptance_record, "rosterHash")?,
            "setupProfileHash": value_string(acceptance_record, "setupProfileHash")?,
            "qShareHash": value_string(acceptance_record, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": value_string(
                acceptance_record,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": value_string(acceptance_record, "commitmentProfileHash")?,
            "setupEpoch": value_string(acceptance_record, "setupEpoch")?,
            "dealerIdentity": value_string(acceptance_record, "dealerIdentity")?,
            "dealerRosterPosition": value_u64(acceptance_record, "dealerRosterPosition")?,
            "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
            "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
            "dealerCommitmentRoot": value_string(acceptance_record, "dealerCommitmentRoot")?,
            "privateVssEnvelopeCommitmentRoot": value_string(
                acceptance_record,
                "privateVssEnvelopeCommitmentRoot",
            )?,
            "privateEnvelopeHash": value_string(acceptance_record, "privateEnvelopeHash")?,
            "localVerificationRoot": value_string(acceptance_record, "localVerificationRoot")?,
            "acceptanceRoot": acceptance_root,
        }),
    )
}

fn verify_threshold_share_commitments(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(threshold_share_commitments) = setup_package.get("thresholdShareCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("thresholdShareCommitments"),
            vec!["thresholdShareCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !threshold_share_commitments.is_object() {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentsNotObject",
            "thresholdShareCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.thresholdShareCommitments",
        )?));
    }
    if threshold_share_commitments
        .get("objectType")
        .and_then(Value::as_str)
        != Some("ThresholdShareCommitmentSet")
    {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetTypeMismatch",
            "thresholdShareCommitments.objectType must be ThresholdShareCommitmentSet",
            "setupPackage.thresholdShareCommitments.objectType",
        )?));
    }
    if threshold_share_commitments
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetVersionMismatch",
            "thresholdShareCommitments.objectVersion must be 1",
            "setupPackage.thresholdShareCommitments.objectVersion",
        )?));
    }
    let Some(threshold_share_commitment_root) = threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("thresholdShareCommitments"),
            vec!["thresholdShareCommitments.thresholdShareCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        threshold_share_commitment_root,
        "thresholdShareCommitments.thresholdShareCommitmentRoot",
    )?;

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before threshold-share commitment verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before threshold-share commitment verification",
            )
        })?;
    let dealer_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("dealerRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS dealer commitments were required before threshold-share commitment verification",
            )
        })?;
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material was required before threshold-share commitment verification",
            )
        })?;
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material encoding was required before threshold-share commitment verification",
            )
        })?;
    let expected_threshold_share_commitments = if material_encoding
        == "binary-chunked-full-public-setup-commitment-values"
    {
        let Some(transported_material) = request.get("transportedVssCoefficientCommitmentMaterial")
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("thresholdShareCommitments"),
                vec!["transportedVssCoefficientCommitmentMaterial".to_string()],
                Vec::new(),
                Vec::new(),
            )?));
        };
        let vss_coefficient_commitment_root = material_set
            .get("vssCoefficientCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS coefficient commitment root was required before transported threshold-share verification",
                )
            })?;
        let transport_result = match derive_threshold_share_commitments_from_transport_request(
            &json!({
                "setupContext": setup_context,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                "dealerCoefficientCommitmentRecords": dealer_records,
                "transportedVssCoefficientCommitmentMaterial": transported_material,
            }),
        ) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Some(threshold_share_refusal(
                    "thresholdShareCommitmentTransportDerivationMismatch",
                    format!(
                        "thresholdShareCommitments must be derived from verifier-checked transported VSS material: {}",
                        error.message
                    ),
                    "transportedVssCoefficientCommitmentMaterial",
                )?));
            }
        };
        let derived_material_root = transport_result
            .get("vssCoefficientCommitmentMaterial")
            .and_then(|value| value.get("vssCoefficientCommitmentMaterialRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transport derivation did not return a material root",
                )
            })?;
        let package_material_root = material_set
            .get("vssCoefficientCommitmentMaterialRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "package material root was required before transported threshold-share verification",
                )
            })?;
        if derived_material_root != package_material_root {
            return Ok(Some(threshold_share_refusal(
                "thresholdShareCommitmentTransportMaterialRootMismatch",
                "transported VSS material root must match setupPackage.vssCoefficientCommitmentMaterial",
                "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
            )?));
        }
        transport_result
            .get("thresholdShareCommitments")
            .cloned()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transport derivation did not return thresholdShareCommitments",
                )
            })?
    } else {
        let coefficient_commitments = material_set
            .get("coefficientCommitments")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS coefficient commitment material was required before threshold-share commitment verification",
                )
            })?;
        match derive_threshold_share_commitment_set_from_parts(
            setup_context,
            public_matrix_seed_hash,
            dealer_records,
            coefficient_commitments,
        ) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Some(threshold_share_refusal(
                    "thresholdShareCommitmentDerivationMismatch",
                    format!(
                        "thresholdShareCommitments must be derived from accepted public VSS coefficient material: {}",
                        error.message
                    ),
                    "setupPackage.thresholdShareCommitments",
                )?));
            }
        }
    };

    if threshold_share_commitments != &expected_threshold_share_commitments {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetMismatch",
            "thresholdShareCommitments must match the verifier-derived threshold-share commitment set",
            "setupPackage.thresholdShareCommitments",
        )?));
    }

    Ok(None)
}

fn threshold_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("thresholdShareCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_same_secret_consistency(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(statement_set) = setup_package.get("sameSecretConsistency") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !statement_set.is_object() {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyNotObject",
            "sameSecretConsistency must be a root-bound object, not an array or scalar",
            "setupPackage.sameSecretConsistency",
        )?));
    }
    if let Some(unexpected_field) = unexpected_same_secret_set_field(statement_set) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyUnexpectedField",
            format!("sameSecretConsistency contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretConsistency.{unexpected_field}"),
        )?));
    }
    if statement_set.get("objectType").and_then(Value::as_str)
        != Some(SAME_SECRET_CONSISTENCY_OBJECT_TYPE)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyTypeMismatch",
            "sameSecretConsistency.objectType must be SameSecretConsistencyStatementSet",
            "setupPackage.sameSecretConsistency.objectType",
        )?));
    }
    if statement_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyVersionMismatch",
            "sameSecretConsistency.objectVersion must be 1",
            "setupPackage.sameSecretConsistency.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before same-secret statement verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(statement_set, setup_context) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyContextMismatch",
            error.message,
            "setupPackage.sameSecretConsistency",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
        ("proofVerificationStatus", "lnp-proof-verification-pending"),
    ] {
        if statement_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyProfileMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
        ("thresholdDegree", FIRST_PROFILE_DECRYPTION_THRESHOLD),
    ] {
        if statement_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyCountMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }

    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitments| commitments.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentRoot was required before same-secret statement verification",
            )
        })?;
    if statement_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretVssCommitmentRootMismatch",
            "sameSecretConsistency.vssCoefficientCommitmentRoot must match the accepted VSS coefficient commitment set",
            "setupPackage.sameSecretConsistency.vssCoefficientCommitmentRoot",
        )?));
    }
    let expected_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    if statement_set
        .get("sameSecretProofFamilyBindingRoot")
        .and_then(Value::as_str)
        != Some(expected_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretProofFamilyBindingRootMismatch",
            "sameSecretConsistency.sameSecretProofFamilyBindingRoot must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.sameSecretProofFamilyBindingRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let trustee_bindings =
        same_secret_trustee_bindings_from_vss(setup_package, &expected_trustees)?;
    let Some(statement_records) = statement_set
        .get("statementRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if statement_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementCountMismatch",
            "sameSecretConsistency.statementRecords must contain one statement per trustee",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    let mut trustee_secret_commitment_roots = Vec::new();
    for statement_record in statement_records {
        let trustee_secret_commitment_root = match verify_same_secret_statement_record(
            statement_record,
            setup_context,
            &trustee_bindings,
            &mut seen_roster_positions,
        )? {
            Some(response) => return Ok(Some(response)),
            None => statement_record
                .get("trusteeSecretCommitmentRoot")
                .and_then(Value::as_str)
                .expect("trustee secret commitment root was verified")
                .to_string(),
        };
        trustee_secret_commitment_roots.push(json!({
            "trusteeIdentity": value_string(statement_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(statement_record, "trusteeRosterPosition")?,
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        }));
    }

    if statement_set.get("trusteeSecretCommitmentRoots")
        != Some(&Value::Array(trustee_secret_commitment_roots))
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretTrusteeRootListMismatch",
            "sameSecretConsistency.trusteeSecretCommitmentRoots must match the ordered statement records",
            "setupPackage.sameSecretConsistency.trusteeSecretCommitmentRoots",
        )?));
    }

    let Some(same_secret_consistency_root) = statement_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.sameSecretConsistencyRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        same_secret_consistency_root,
        "sameSecretConsistency.sameSecretConsistencyRoot",
    )?;
    let mut root_input = statement_set.clone();
    root_input
        .as_object_mut()
        .expect("same-secret statement set object was checked")
        .remove("sameSecretConsistencyRoot");
    let expected_root = derive_protocol_hash("SameSecretConsistencyRoot", &root_input)?;
    if same_secret_consistency_root != expected_root {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyRootMismatch",
            "sameSecretConsistencyRoot does not match the canonical same-secret statement set",
            "setupPackage.sameSecretConsistency.sameSecretConsistencyRoot",
        )?));
    }

    Ok(None)
}

fn verify_same_secret_statement_record(
    statement_record: &Value,
    setup_context: &Value,
    trustee_bindings: &BTreeMap<u64, SameSecretTrusteeBinding>,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !statement_record.is_object() {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementNotObject",
            "same-secret statement records must be objects",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    if let Some(unexpected_field) = unexpected_same_secret_statement_field(statement_record) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementUnexpectedField",
            format!("same-secret statement contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretConsistency.statementRecords.{unexpected_field}"),
        )?));
    }
    if statement_record.get("objectType").and_then(Value::as_str)
        != Some(SAME_SECRET_STATEMENT_OBJECT_TYPE)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTypeMismatch",
            "same-secret statement objectType must be SameSecretConsistencyStatement",
            "setupPackage.sameSecretConsistency.statementRecords.objectType",
        )?));
    }
    if statement_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementVersionMismatch",
            "same-secret statement objectVersion must be 1",
            "setupPackage.sameSecretConsistency.statementRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(statement_record, setup_context) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementContextMismatch",
            error.message,
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
        ("proofVerificationStatus", "lnp-proof-verification-pending"),
        (
            "sameSecretRelation",
            "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        ),
        (
            "genericKeySwitchBindingPolicy",
            "absent-unless-frozen-schedule-requires-proof-family",
        ),
        (
            "targetDecryptionBindingPolicy",
            "later-target-share-must-bind-threshold-share-commitment",
        ),
    ] {
        if statement_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretStatementProfileMismatch",
                format!("same-secret statement {field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.statementRecords.{field_name}"),
            )?));
        }
    }
    if statement_record.get("boundSecretDependentProofFamilies")
        != Some(&expected_same_secret_bound_proof_families_value())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretBoundProofFamiliesMismatch",
            "same-secret statement must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.statementRecords.boundSecretDependentProofFamilies",
        )?));
    }
    let expected_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    if statement_record
        .get("sameSecretProofFamilyBindingRoot")
        .and_then(Value::as_str)
        != Some(expected_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretProofFamilyBindingRootMismatch",
            "same-secret statement sameSecretProofFamilyBindingRoot must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.statementRecords.sameSecretProofFamilyBindingRoot",
        )?));
    }

    let trustee_identity = value_string(statement_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementDuplicate",
            "same-secret statement records must have distinct trustee roster positions",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    let Some(binding) = trustee_bindings.get(&trustee_roster_position) else {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTrusteeOutsideProfile",
            "same-secret statement trusteeRosterPosition is outside the accepted roster",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeRosterPosition",
        )?));
    };
    if binding.trustee_identity != trustee_identity {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTrusteeMismatch",
            "same-secret statement trusteeIdentity must match the accepted VSS dealer",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeIdentity",
        )?));
    }
    if statement_record
        .get("vssDealerCommitmentRoot")
        .and_then(Value::as_str)
        != Some(binding.vss_dealer_commitment_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretVssDealerRootMismatch",
            "same-secret statement vssDealerCommitmentRoot must match the accepted dealer VSS commitments",
            "setupPackage.sameSecretConsistency.statementRecords.vssDealerCommitmentRoot",
        )?));
    }
    if statement_record.get("constantCoefficientCommitmentRoots")
        != Some(&Value::Array(binding.constant_commitment_roots.clone()))
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretConstantCommitmentRootMismatch",
            "same-secret statement constant coefficient roots must match C_i,l,0 from VSS commitments",
            "setupPackage.sameSecretConsistency.statementRecords.constantCoefficientCommitmentRoots",
        )?));
    }

    let Some(trustee_secret_commitment_root) = statement_record
        .get("trusteeSecretCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        trustee_secret_commitment_root,
        "sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot",
    )?;
    let expected_trustee_secret_commitment_root = derive_protocol_hash(
        "TrusteeSecretCommitmentRoot",
        &trustee_secret_commitment_payload(setup_context, binding)?,
    )?;
    if trustee_secret_commitment_root != expected_trustee_secret_commitment_root {
        return Ok(Some(same_secret_refusal(
            "trusteeSecretCommitmentRootMismatch",
            "trusteeSecretCommitmentRoot does not match the VSS constant coefficient commitments",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot",
        )?));
    }

    let Some(same_secret_statement_root) = statement_record
        .get("sameSecretStatementRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords.sameSecretStatementRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        same_secret_statement_root,
        "sameSecretConsistency.statementRecords.sameSecretStatementRoot",
    )?;
    let mut statement_root_input = statement_record.clone();
    statement_root_input
        .as_object_mut()
        .expect("same-secret statement object was checked")
        .remove("sameSecretStatementRoot");
    let expected_statement_root =
        derive_protocol_hash("SameSecretConsistencyRoot", &statement_root_input)?;
    if same_secret_statement_root != expected_statement_root {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementRootMismatch",
            "sameSecretStatementRoot does not match the canonical same-secret statement",
            "setupPackage.sameSecretConsistency.statementRecords.sameSecretStatementRoot",
        )?));
    }

    Ok(None)
}

fn same_secret_trustee_bindings_from_vss(
    setup_package: &Value,
    expected_trustees: &BTreeMap<u64, String>,
) -> CanonicalResult<BTreeMap<u64, SameSecretTrusteeBinding>> {
    let dealer_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("dealerRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS dealer records were required before same-secret statement verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for dealer_record in dealer_records {
        let trustee_roster_position = value_u64(dealer_record, "dealerRosterPosition")?;
        let trustee_identity = value_string(dealer_record, "dealerIdentity")?.to_string();
        if expected_trustees
            .get(&trustee_roster_position)
            .map(String::as_str)
            != Some(trustee_identity.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS dealer record does not match the accepted setup roster",
            ));
        }
        let vss_dealer_commitment_root =
            value_string(dealer_record, "dealerCommitmentRoot")?.to_string();
        let constant_commitment_roots =
            same_secret_constant_commitment_roots_from_dealer(dealer_record)?;
        if bindings
            .insert(
                trustee_roster_position,
                SameSecretTrusteeBinding {
                    trustee_identity,
                    trustee_roster_position,
                    vss_dealer_commitment_root,
                    constant_commitment_roots,
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS dealer records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn same_secret_constant_commitment_roots_from_dealer(
    dealer_record: &Value,
) -> CanonicalResult<Vec<Value>> {
    let coefficient_commitments = dealer_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitments were required before same-secret statement verification",
            )
        })?;
    let mut roots = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let coefficient_record = coefficient_commitments
            .iter()
            .find(|coefficient_record| {
                coefficient_record
                    .get("rnsLimbIndex")
                    .and_then(Value::as_u64)
                    == Some(rns_limb_index as u64)
                    && coefficient_record
                        .get("shamirCoefficientIndex")
                        .and_then(Value::as_u64)
                        == Some(0)
            })
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS constant coefficient commitment was required before same-secret statement verification",
                )
            })?;
        if coefficient_record.get("rnsPrime").and_then(Value::as_u64) != Some(rns_prime) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS constant coefficient commitment RNS prime does not match Q_share",
            ));
        }
        roots.push(json!({
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shamirCoefficientIndex": 0,
            "commitmentRoot": value_string(coefficient_record, "commitmentRoot")?,
        }));
    }

    Ok(roots)
}

fn trustee_secret_commitment_payload(
    setup_context: &Value,
    binding: &SameSecretTrusteeBinding,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": TRUSTEE_SECRET_COMMITMENT_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            setup_context,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "vssDealerCommitmentRoot": binding.vss_dealer_commitment_root,
        "secretCommitmentSource": "vss-constant-coefficient-commitments",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "constantCoefficientCommitmentRoots": binding.constant_commitment_roots,
    }))
}

fn verify_optional_same_secret_lnp_proofs(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("sameSecretProofs") else {
        return Ok(None);
    };
    if !proof_set.is_object() {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofsNotObject",
            "sameSecretProofs must be a root-bound object",
            "setupPackage.sameSecretProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_same_secret_proof_set_field(proof_set) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetUnexpectedField",
            format!("sameSecretProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str) != Some("SameSecretProofSet") {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetTypeMismatch",
            "sameSecretProofs.objectType must be SameSecretProofSet",
            "setupPackage.sameSecretProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetVersionMismatch",
            "sameSecretProofs.objectVersion must be 1",
            "setupPackage.sameSecretProofs.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before same-secret proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetContextMismatch",
            error.message,
            "setupPackage.sameSecretProofs",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
        (
            "proofVerificationStatus",
            SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", SAME_SECRET_LNP_PROOF_MODEL_STATUS),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetProfileMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetCountMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    let Some(actual_setup_proof_binding) = proof_set.get("setupProofBinding") else {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetProfileMismatch",
            "sameSecretProofs.setupProofBinding must bind the fixed setup-proof profile",
            "setupPackage.sameSecretProofs.setupProofBinding",
        )?));
    };
    if let Err(error) = super::setup_proof::verify_setup_proof_record_binding(
        actual_setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    ) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetProfileMismatch",
            error.message,
            "setupPackage.sameSecretProofs.setupProofBinding",
        )?));
    }
    let expected_tbox_parameter_profile_hash =
        super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?;
    if proof_set
        .get("sameSecretTboxParameterProfileHash")
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetProfileMismatch",
            "sameSecretProofs.sameSecretTboxParameterProfileHash must match the accepted same-secret LNP tbox profile",
            "setupPackage.sameSecretProofs.sameSecretTboxParameterProfileHash",
        )?));
    }
    let expected_same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
        || proof_set
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(expected_same_secret_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofConsistencyRootMismatch",
            "sameSecretProofs must match accepted same-secret statements and proof-family binding",
            "setupPackage.sameSecretProofs",
        )?));
    }
    let material_root = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material| material.get("vssCoefficientCommitmentMaterialRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterialRoot was required before same-secret proof verification",
            )
        })?;
    if proof_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        != Some(material_root)
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofMaterialRootMismatch",
            "sameSecretProofs.vssCoefficientCommitmentMaterialRoot must match accepted public VSS material",
            "setupPackage.sameSecretProofs.vssCoefficientCommitmentMaterialRoot",
        )?));
    }

    let statement_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofCountMismatch",
            "sameSecretProofs.proofRecords must contain one proof per trustee",
            "setupPackage.sameSecretProofs.proofRecords",
        )?));
    }
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before same-secret proof verification",
            )
        })?;
    let mut seen_roster_positions = BTreeSet::new();
    let mut proof_roots = Vec::new();
    let verification_context = SameSecretLnpProofVerificationContext {
        setup_package,
        request,
        setup_context,
        public_matrix_seed_hash,
        statement_records: &statement_records,
        transported_constant_commitments: &transported_constant_commitments,
    };
    for proof_record in proof_records {
        if let Err(error) = verify_same_secret_lnp_proof_record(
            &verification_context,
            proof_record,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofVerificationFailed",
                error.message,
                "setupPackage.sameSecretProofs.proofRecords",
            )?));
        }
        proof_roots.push(json!({
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "sameSecretProofRoot": value_string(proof_record, "sameSecretProofRoot")?,
        }));
    }
    if proof_set.get("sameSecretProofRoots") != Some(&Value::Array(proof_roots)) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofRootListMismatch",
            "sameSecretProofs.sameSecretProofRoots must match the ordered proof records",
            "setupPackage.sameSecretProofs.sameSecretProofRoots",
        )?));
    }

    let Some(proof_set_root) = proof_set
        .get("sameSecretProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs.sameSecretProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(proof_set_root, "sameSecretProofs.sameSecretProofSetRoot")?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof set object was checked")
        .remove("sameSecretProofSetRoot");
    let expected_root = derive_protocol_hash("SameSecretProofRoot", &root_input)?;
    if proof_set_root != expected_root {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetRootMismatch",
            "sameSecretProofSetRoot does not match the canonical same-secret proof set",
            "setupPackage.sameSecretProofs.sameSecretProofSetRoot",
        )?));
    }

    Ok(None)
}

struct SameSecretLnpProofVerificationContext<'a> {
    setup_package: &'a Value,
    request: &'a Value,
    setup_context: &'a Value,
    public_matrix_seed_hash: &'a str,
    statement_records: &'a BTreeMap<u64, Value>,
    transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
}

fn verify_same_secret_lnp_proof_record(
    context: &SameSecretLnpProofVerificationContext<'_>,
    proof_record: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must be objects",
        ));
    }
    if let Some(unexpected_field) = unexpected_same_secret_proof_record_field(proof_record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("same-secret proof contains unexpected field {unexpected_field}"),
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str) != Some("SameSecretProof") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectType must be SameSecretProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectVersion must be 1",
        ));
    }
    verify_same_secret_context(proof_record, context.setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
        (
            "proofVerificationStatus",
            SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", SAME_SECRET_LNP_PROOF_MODEL_STATUS),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let expected_setup_proof_binding = setup_proof_record_binding_value()?;
    let actual_setup_proof_binding = proof_record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof setupProofBinding must bind the fixed setup-proof profile",
        )
    })?;
    if actual_setup_proof_binding != &expected_setup_proof_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "same-secret proof setupProofBinding must match the fixed setup-proof profile",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        actual_setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;
    let expected_tbox_parameter_profile_hash =
        super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?;
    if proof_record
        .get("sameSecretTboxParameterProfileHash")
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof sameSecretTboxParameterProfileHash must match the accepted same-secret LNP tbox profile",
        ));
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must have distinct trustee roster positions",
        ));
    }
    let statement_record = context
        .statement_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof trusteeRosterPosition must reference an accepted statement",
            )
        })?;
    for field_name in [
        "trusteeIdentity",
        "trusteeSecretCommitmentRoot",
        "sameSecretStatementRoot",
        "sameSecretProofFamilyBindingRoot",
    ] {
        if proof_record.get(field_name) != statement_record.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must match the accepted statement"),
            ));
        }
    }

    let proof_bytes = same_secret_proof_bytes_from_record(proof_record, context.request)?;
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofSizeBytes must match proofBytesHex",
        ));
    }
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    if proof_bytes_hash != same_secret_lnp_relation_proof_bytes_hash(&proof_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesHash must match proofBytesHex",
        ));
    }
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        context.setup_package,
        trustee_roster_position,
        context.transported_constant_commitments,
    )?;
    let verification = verify_same_secret_lnp_relation_proof(
        context.public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        actual_setup_proof_binding,
        &proof_bytes,
    )?;
    let verified_proof_size = u64::try_from(verification.proof_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret verified proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(verification.statement_hash_hex.as_str())
        || proof_record
            .get("relationCommitmentHash")
            .and_then(Value::as_str)
            != Some(verification.relation_commitment_hash_hex.as_str())
        || proof_record
            .get("tboxCommitmentPrefixHash")
            .and_then(Value::as_str)
            != Some(verification.tbox_commitment_prefix_hash.as_str())
        || proof_record.get("challenge").and_then(Value::as_u64) != Some(verification.challenge)
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof transcript metadata must match verified proof bytes",
        ));
    }
    let proof_root = value_string(proof_record, "sameSecretProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof record object was checked")
        .remove("sameSecretProofRoot");
    let expected_root = derive_protocol_hash("SameSecretProofRoot", &root_input)?;
    if proof_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sameSecretProofRoot does not match the canonical same-secret proof record",
        ));
    }

    Ok(())
}

fn same_secret_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(proof_material_root, "sameSecretProof.proofMaterialRoot")?;
    let chunks = transported_same_secret_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        "same-secret-consistency",
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_same_secret_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: COLLECTIVE_BGV_SETUP_PROFILE_ID,
            proof_family: "same-secret-consistency",
            trustee_identity: value_string(proof_record, "trusteeIdentity")?,
            trustee_roster_position: value_u64(proof_record, "trusteeRosterPosition")?,
            statement_hash_hex: value_string(proof_record, "statementHash")?,
            relation_commitment_hash_hex: value_string(proof_record, "relationCommitmentHash")?,
            tbox_commitment_prefix_hash: value_string(proof_record, "tboxCommitmentPrefixHash")?,
            proof_size_bytes: value_u64(proof_record, "proofSizeBytes")?,
            proof_bytes_hash: value_string(proof_record, "proofBytesHash")?,
            transport_hashes: &transport_hashes,
        })?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofTotalByteLength must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofSizeBytes must match transported proof byte length",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proofChunkHashes[{chunk_index}] must be a hash string"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("sameSecretProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_same_secret_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedSameSecretProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial was required by transported same-secret proof records",
            )
        })?;
    verify_transported_same_secret_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_same_secret_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = transported_same_secret_proof_chunks(proof_material)?;
        let transport_hashes = setup_proof_material_transport_hashes(
            "same-secret-consistency",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_proof_material_hashes(proof_material, &transport_hashes)?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_same_secret_proof_material_set_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transportedSameSecretProofMaterial contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("transportedSameSecretProofMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_same_secret_proof_material_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) = unexpected_transported_same_secret_proof_material_field(value) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transported same-secret proof material contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "same-secret-consistency"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported same-secret proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedSameSecretProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_same_secret_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if let Some(unexpected_field) =
            unexpected_transported_same_secret_proof_chunk_field(chunk_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported same-secret proof chunk contains unexpected field {unexpected_field}"
                ),
            ));
        }
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_same_secret_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}

fn public_key_share_lnp_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "publicKeyShareLnpProof.proofMaterialRoot",
    )?;
    let chunks = transported_public_key_share_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        "public-key-share",
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_public_key_share_lnp_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: COLLECTIVE_BGV_SETUP_PROFILE_ID,
            proof_family: "public-key-share",
            trustee_identity: value_string(proof_record, "trusteeIdentity")?,
            trustee_roster_position: value_u64(proof_record, "trusteeRosterPosition")?,
            statement_hash_hex: value_string(proof_record, "statementHash")?,
            relation_commitment_hash_hex: value_string(proof_record, "relationCommitmentHash")?,
            tbox_commitment_prefix_hash: value_string(proof_record, "tboxCommitmentPrefixHash")?,
            proof_size_bytes: value_u64(proof_record, "proofSizeBytes")?,
            proof_bytes_hash: value_string(proof_record, "proofBytesHash")?,
            transport_hashes: &transport_hashes,
        })?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

fn verify_public_key_share_lnp_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofChunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofTotalByteLength must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofSizeBytes must match transported proof byte length",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public-key LNP proofChunkHashes[{chunk_index}] must be a hash string"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("publicKeyShareLnpProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key LNP proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_public_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedPublicKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial was required by transported public-key LNP proof records",
            )
        })?;
    verify_transported_public_key_share_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_public_key_share_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = transported_public_key_share_proof_chunks(proof_material)?;
        let transport_hashes = setup_proof_material_transport_hashes(
            "public-key-share",
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_public_key_share_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_public_key_share_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_public_key_share_proof_material_set_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transportedPublicKeyShareProofMaterial contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        (
            "objectType",
            PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transportedPublicKeyShareProofMaterial.{field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_public_key_share_proof_material_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_public_key_share_proof_material_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transported public-key LNP proof material contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported public-key LNP proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedPublicKeyShareProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_public_key_share_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof material chunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key LNP proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if let Some(unexpected_field) =
            unexpected_transported_public_key_share_proof_chunk_field(chunk_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported public-key LNP proof chunk contains unexpected field {unexpected_field}"
                ),
            ));
        }
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key LNP proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_public_key_share_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key LNP proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key LNP proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}

fn same_secret_statement_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let statement_records = setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("statementRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretConsistency.statementRecords were required before same-secret proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for statement_record in statement_records {
        let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, statement_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret statements contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn same_secret_proof_set_root_from_package(setup_package: &Value) -> CanonicalResult<String> {
    setup_package
        .get("sameSecretProofs")
        .and_then(|proof_set| proof_set.get("sameSecretProofSetRoot"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretProofSetRoot was required before public-key proof verification",
            )
        })
}

fn same_secret_proof_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, SameSecretProofBinding>> {
    let proof_records = setup_package
        .get("sameSecretProofs")
        .and_then(|proof_set| proof_set.get("proofRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretProofs.proofRecords were required before public-key proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for proof_record in proof_records {
        let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
        let binding = SameSecretProofBinding {
            trustee_identity: value_string(proof_record, "trusteeIdentity")?.to_string(),
            trustee_secret_commitment_root: value_string(
                proof_record,
                "trusteeSecretCommitmentRoot",
            )?
            .to_string(),
            same_secret_statement_root: value_string(proof_record, "sameSecretStatementRoot")?
                .to_string(),
            same_secret_proof_family_binding_root: value_string(
                proof_record,
                "sameSecretProofFamilyBindingRoot",
            )?
            .to_string(),
            same_secret_proof_root: value_string(proof_record, "sameSecretProofRoot")?.to_string(),
        };
        if records.insert(trustee_roster_position, binding).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn same_secret_transported_constant_commitments_by_roster_position(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    if material_set.get("materialEncoding").and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(BTreeMap::new());
    }
    let transported_material = request
        .get("transportedVssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedVssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before transported same-secret proof verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before transported same-secret proof verification",
            )
        })?;
    let vss_coefficient_commitment_root = material_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot was required before transported same-secret proof verification",
            )
        })?;
    let dealer_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("dealerRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS dealer commitments were required before transported same-secret proof verification",
            )
        })?;
    let verified_transport = verify_constant_vss_commitments_from_transport_request(&json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "dealerCoefficientCommitmentRecords": dealer_records,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))?;
    let derived_material_root = verified_transport
        .material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret material verification did not return a material root",
            )
        })?;
    let package_material_root = material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "package material root was required before transported same-secret proof verification",
            )
        })?;
    if derived_material_root != package_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported VSS material root must match setupPackage.vssCoefficientCommitmentMaterial before same-secret proof verification",
        ));
    }

    Ok(verified_transport.constant_commitments_by_dealer)
}

fn same_secret_constant_commitment_values_from_material(
    setup_package: &Value,
    trustee_roster_position: u64,
    transported_constant_commitments: &BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
) -> CanonicalResult<Vec<super::commitment::SetupCommitmentValue>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.materialEncoding was required before same-secret proof verification",
            )
        })?;
    if material_encoding == "binary-chunked-full-public-setup-commitment-values" {
        return transported_constant_commitments
            .get(&trustee_roster_position)
            .cloned()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported same-secret proof material is missing trustee constant commitments",
                )
            });
    }
    if material_encoding != "full-public-setup-commitment-values" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret LNP proof verification requires embedded or binary-transported public VSS commitment material",
        ));
    }
    let material_records = material_set
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.coefficientCommitments were required before same-secret proof verification",
            )
        })?;
    let mut commitments_by_limb = BTreeMap::new();
    for material_record in material_records {
        if material_record
            .get("dealerRosterPosition")
            .and_then(Value::as_u64)
            != Some(trustee_roster_position)
            || material_record
                .get("shamirCoefficientIndex")
                .and_then(Value::as_u64)
                != Some(0)
        {
            continue;
        }
        let rns_limb_index = value_u64(material_record, "rnsLimbIndex")?;
        let commitment_value = material_record.get("commitment").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material record is missing commitment",
            )
        })?;
        let commitment = parse_setup_commitment_full_value(commitment_value)?;
        let commitment_root = setup_commitment_root(&commitment)?;
        if material_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            != Some(commitment_root.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof commitment material root does not match its public commitment",
            ));
        }
        if commitments_by_limb
            .insert(rns_limb_index, commitment)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material contains duplicate constant commitment limbs",
            ));
        }
    }
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for rns_limb_index in 0..DATA_PRIMES.len() as u64 {
        let commitment = commitments_by_limb.remove(&rns_limb_index).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material is missing a constant commitment limb",
            )
        })?;
        commitments.push(commitment);
    }

    Ok(commitments)
}

fn verify_same_secret_context(value: &Value, setup_context: &Value) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("same-secret {field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn expected_same_secret_bound_proof_families_value() -> Value {
    Value::Array(
        SAME_SECRET_BOUND_PROOF_FAMILIES
            .iter()
            .map(|family| Value::String((*family).to_string()))
            .collect(),
    )
}

fn same_secret_proof_family_binding_value() -> Value {
    json!({
        "objectType": SAME_SECRET_PROOF_FAMILY_BINDING_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "same-secret-consistency",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "boundSecretDependentProofFamilies": expected_same_secret_bound_proof_families_value(),
        "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
        "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
    })
}

fn same_secret_proof_family_binding_root() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &same_secret_proof_family_binding_value(),
    )
}

fn unexpected_same_secret_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "thresholdDegree",
            "vssCoefficientCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "trusteeSecretCommitmentRoots",
            "statementRecords",
            "sameSecretConsistencyRoot",
        ],
    )
}

fn unexpected_same_secret_statement_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "vssDealerCommitmentRoot",
            "constantCoefficientCommitmentRoots",
            "trusteeSecretCommitmentRoot",
            "boundSecretDependentProofFamilies",
            "genericKeySwitchBindingPolicy",
            "targetDecryptionBindingPolicy",
            "sameSecretProofFamilyBindingRoot",
            "sameSecretRelation",
            "sameSecretStatementRoot",
        ],
    )
}

fn unexpected_same_secret_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "sameSecretTboxParameterProfileHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "sameSecretConsistencyRoot",
            "sameSecretProofFamilyBindingRoot",
            "vssCoefficientCommitmentMaterialRoot",
            "setupProofBinding",
            "sameSecretProofRoots",
            "proofRecords",
            "sameSecretProofSetRoot",
        ],
    )
}

fn unexpected_same_secret_proof_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "sameSecretTboxParameterProfileHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "setupProofBinding",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "proofBytesHex",
            "sameSecretProofRoot",
        ],
    )
}

fn unexpected_transported_same_secret_proof_material_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterials",
        ],
    )
}

fn unexpected_transported_same_secret_proof_material_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterialRoot",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ],
    )
}

fn unexpected_transported_same_secret_proof_chunk_field(value: &Value) -> Option<String> {
    unexpected_field(value, &["chunkIndex", "bytesHex"])
}

fn unexpected_transported_public_key_share_proof_material_set_field(
    value: &Value,
) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterials",
        ],
    )
}

fn unexpected_transported_public_key_share_proof_material_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterialRoot",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ],
    )
}

fn unexpected_transported_public_key_share_proof_chunk_field(value: &Value) -> Option<String> {
    unexpected_field(value, &["chunkIndex", "bytesHex"])
}

fn unexpected_field(value: &Value, allowed_fields: &[&str]) -> Option<String> {
    value
        .as_object()
        .and_then(|fields| {
            fields
                .keys()
                .find(|field_name| !allowed_fields.contains(&field_name.as_str()))
        })
        .cloned()
}

fn same_secret_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn same_secret_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_public_key_shares(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(share_set) = setup_package.get("publicKeyShares") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !share_set.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeySharesNotObject",
            "publicKeyShares must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShares",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_set_field(share_set) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetUnexpectedField",
            format!("publicKeyShares contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShares.{unexpected_field}"),
        )?));
    }
    if share_set.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetTypeMismatch",
            "publicKeyShares.objectType must be PublicKeyShareSet",
            "setupPackage.publicKeyShares.objectType",
        )?));
    }
    if share_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetVersionMismatch",
            "publicKeyShares.objectVersion must be 1",
            "setupPackage.publicKeyShares.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(share_set, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShares",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofBindingStatus", "public-key-share-proof-required"),
    ] {
        if share_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetProfileMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if share_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetCountMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        share_set,
        &common_binding,
        "publicKeyShares",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if share_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretRootMismatch",
            "publicKeyShares.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShares.sameSecretConsistencyRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(share_records) = share_set.get("shareRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if share_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCountMismatch",
            "publicKeyShares.shareRecords must contain one share per trustee",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut public_key_share_roots = Vec::new();
    for share_record in share_records {
        if let Some(response) = verify_public_key_share_record(
            share_record,
            setup_context,
            &expected_trustees,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
        public_key_share_roots.push(json!({
            "trusteeIdentity": value_string(share_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(share_record, "trusteeRosterPosition")?,
            "publicKeyShareRoot": value_string(share_record, "publicKeyShareRoot")?,
        }));
    }
    if share_set.get("publicKeyShareRoots") != Some(&Value::Array(public_key_share_roots)) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootListMismatch",
            "publicKeyShares.publicKeyShareRoots must match the ordered share records",
            "setupPackage.publicKeyShares.publicKeyShareRoots",
        )?));
    }

    let Some(public_key_share_set_root) = share_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.publicKeyShareSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_set_root,
        "publicKeyShares.publicKeyShareSetRoot",
    )?;
    let mut root_input = share_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share set object was checked")
        .remove("publicKeyShareSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_set_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetRootMismatch",
            "publicKeyShareSetRoot does not match the canonical public-key share set",
            "setupPackage.publicKeyShares.publicKeyShareSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_record(
    share_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !share_record.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareNotObject",
            "public-key share records must be objects",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_field(share_record) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareUnexpectedField",
            format!("public-key share contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShares.shareRecords.{unexpected_field}"),
        )?));
    }
    if share_record.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTypeMismatch",
            "public-key share objectType must be PublicKeyShare",
            "setupPackage.publicKeyShares.shareRecords.objectType",
        )?));
    }
    if share_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareVersionMismatch",
            "public-key share objectVersion must be 1",
            "setupPackage.publicKeyShares.shareRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(share_record, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareContextMismatch",
            error.message,
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("shareComponent", "component-zero-b_i"),
        ("proofBindingStatus", "public-key-share-proof-required"),
    ] {
        if share_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareProfileMismatch",
                format!("public-key share {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.shareRecords.{field_name}"),
            )?));
        }
    }
    if share_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRnsLimbCountMismatch",
            "public-key share rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShares.shareRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        share_record,
        common_binding,
        "publicKeyShares.shareRecords",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareDuplicate",
            "public-key share records must have distinct trustee roster positions",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if expected_trustees
        .get(&trustee_roster_position)
        .map(String::as_str)
        != Some(trustee_identity)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTrusteeMismatch",
            "public-key share trustee identity must match the accepted setup roster",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretMissing",
            "public-key share must reference an accepted same-secret statement",
            "setupPackage.publicKeyShares.shareRecords.trusteeRosterPosition",
        )?));
    };
    if same_secret_binding.trustee_identity != trustee_identity {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretTrusteeMismatch",
            "public-key share trustee must match the same-secret statement trustee",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    if share_record
        .get("trusteeSecretCommitmentRoot")
        .and_then(Value::as_str)
        != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || share_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretBindingMismatch",
            "public-key share must bind the accepted trustee secret and same-secret statement roots",
            "setupPackage.publicKeyShares.shareRecords.sameSecretStatementRoot",
        )?));
    }
    if let Some(response) = verify_public_key_share_limb_hashes(
        share_record
            .get("shareCoefficientVectorHash512ByLimb")
            .and_then(Value::as_array),
    )? {
        return Ok(Some(response));
    }

    let Some(public_key_share_root) = share_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.publicKeyShareRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_root,
        "publicKeyShares.shareRecords.publicKeyShareRoot",
    )?;
    let mut root_input = share_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share object was checked")
        .remove("publicKeyShareRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootMismatch",
            "publicKeyShareRoot does not match the canonical public-key share",
            "setupPackage.publicKeyShares.shareRecords.publicKeyShareRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_proofs(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("publicKeyShareProofs") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !proof_set.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofsNotObject",
            "publicKeyShareProofs must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_proof_set_field(proof_set) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetUnexpectedField",
            format!("publicKeyShareProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetTypeMismatch",
            "publicKeyShareProofs.objectType must be PublicKeyShareProofSet",
            "setupPackage.publicKeyShareProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetVersionMismatch",
            "publicKeyShareProofs.objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        ("proofVerificationStatus", "lnp-proof-verification-pending"),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetProfileMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofSetCountMismatch",
                format!("publicKeyShareProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        proof_set,
        &common_binding,
        "publicKeyShareProofs",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretRootMismatch",
            "publicKeyShareProofs.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShareProofs.sameSecretConsistencyRoot",
        )?));
    }
    let public_key_share_set_root = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSetRoot was required before public-key share proof verification",
            )
        })?;
    if proof_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
        != Some(public_key_share_set_root)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareSetRootMismatch",
            "publicKeyShareProofs.publicKeyShareSetRoot must match publicKeyShares",
            "setupPackage.publicKeyShareProofs.publicKeyShareSetRoot",
        )?));
    }

    let share_bindings = public_key_share_bindings_from_package(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofCountMismatch",
            "publicKeyShareProofs.proofRecords must contain one proof statement per trustee",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut public_key_share_proof_roots = Vec::new();
    for proof_record in proof_records {
        if let Some(response) = verify_public_key_share_proof_record(
            proof_record,
            setup_context,
            &share_bindings,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
        public_key_share_proof_roots.push(json!({
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "publicKeyShareProofRoot": value_string(proof_record, "publicKeyShareProofRoot")?,
        }));
    }
    if proof_set.get("publicKeyShareProofRoots")
        != Some(&Value::Array(public_key_share_proof_roots))
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRootListMismatch",
            "publicKeyShareProofs.publicKeyShareProofRoots must match the ordered proof records",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofRoots",
        )?));
    }

    let Some(public_key_share_proof_set_root) = proof_set
        .get("publicKeyShareProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.publicKeyShareProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_proof_set_root,
        "publicKeyShareProofs.publicKeyShareProofSetRoot",
    )?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof set object was checked")
        .remove("publicKeyShareProofSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if public_key_share_proof_set_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSetRootMismatch",
            "publicKeyShareProofSetRoot does not match the canonical public-key share proof set",
            "setupPackage.publicKeyShareProofs.publicKeyShareProofSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_optional_public_key_share_lnp_proofs(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let material_set = setup_package.get("publicKeyShareMaterial");
    let proof_set = setup_package.get("publicKeyShareLnpProofs");
    if material_set.is_none() && proof_set.is_none() {
        return Ok(None);
    }
    let Some(material_set) = material_set else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(proof_set) = proof_set else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareLnpProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key LNP proof verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before public-key LNP proof verification",
            )
    })?;
    let common_binding = public_key_common_binding(setup_package)?;
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if setup_package.get("sameSecretProofs").is_none() {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    let same_secret_proof_set_root = same_secret_proof_set_root_from_package(setup_package)?;
    let same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let public_key_share_set_root = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSetRoot was required before public-key LNP proof verification",
            )
        })?;
    let public_key_share_proof_set_root = setup_package
        .get("publicKeyShareProofs")
        .and_then(|root_set| root_set.get("publicKeyShareProofSetRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareProofSetRoot was required before public-key LNP proof verification",
            )
        })?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let proof_records = public_key_share_proof_records_by_roster_position(setup_package)?;
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        public_key_share_set_root,
        &share_records,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(Some(public_key_share_lnp_proof_refusal(
                "publicKeyShareMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    if !proof_set.is_object() {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetNotObject",
            "publicKeyShareLnpProofs must be a root-bound object",
            "setupPackage.publicKeyShareLnpProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_lnp_proof_set_field(proof_set) {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetUnexpectedField",
            format!("publicKeyShareLnpProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareLnpProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_LNP_PROOF_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetTypeMismatch",
            "publicKeyShareLnpProofs.objectType must be PublicKeyShareLnpProofSet",
            "setupPackage.publicKeyShareLnpProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetVersionMismatch",
            "publicKeyShareLnpProofs.objectVersion must be 1",
            "setupPackage.publicKeyShareLnpProofs.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShareLnpProofs",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_lnp_proof_refusal(
                "publicKeyShareLnpProofSetProfileMismatch",
                format!("publicKeyShareLnpProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareLnpProofs.{field_name}"),
            )?));
        }
    }
    let expected_tbox_parameter_profile_hash =
        super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?;
    if proof_set
        .get("publicKeyShareTboxParameterProfileHash")
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetTboxProfileMismatch",
            "publicKeyShareLnpProofs.publicKeyShareTboxParameterProfileHash must match the accepted public-key share LNP tbox profile",
            "setupPackage.publicKeyShareLnpProofs.publicKeyShareTboxParameterProfileHash",
        )?));
    }
    let expected_setup_proof_binding = setup_proof_record_binding_value()?;
    let Some(actual_setup_proof_binding) = proof_set.get("setupProofBinding") else {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetBindingMissing",
            "publicKeyShareLnpProofs.setupProofBinding is required",
            "setupPackage.publicKeyShareLnpProofs.setupProofBinding",
        )?));
    };
    if actual_setup_proof_binding != &expected_setup_proof_binding {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetSetupProofBindingMismatch",
            "publicKeyShareLnpProofs.setupProofBinding must match the accepted setup-proof profile binding",
            "setupPackage.publicKeyShareLnpProofs.setupProofBinding",
        )?));
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_lnp_proof_refusal(
                "publicKeyShareLnpProofSetCountMismatch",
                format!("publicKeyShareLnpProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareLnpProofs.{field_name}"),
            )?));
        }
    }
    if proof_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || proof_set.get("publicKeyCrpRoot").and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || proof_set
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
        || proof_set
            .get("sameSecretConsistencyRoot")
            .and_then(Value::as_str)
            != Some(same_secret_consistency_root.as_str())
        || proof_set
            .get("sameSecretProofSetRoot")
            .and_then(Value::as_str)
            != Some(same_secret_proof_set_root.as_str())
        || proof_set
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(same_secret_proof_family_binding_root.as_str())
        || proof_set
            .get("publicKeyShareSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_set_root)
        || proof_set
            .get("publicKeyShareProofSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_proof_set_root)
        || proof_set
            .get("publicKeyShareMaterialSetRoot")
            .and_then(Value::as_str)
            != material_set
                .get("publicKeyShareMaterialSetRoot")
                .and_then(Value::as_str)
    {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetBindingMismatch",
            "publicKeyShareLnpProofs must bind accepted public randomness, same-secret, share, proof, and material roots",
            "setupPackage.publicKeyShareLnpProofs",
        )?));
    }
    let Some(proof_records_array) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareLnpProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records_array.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofCountMismatch",
            "publicKeyShareLnpProofs.proofRecords must contain one proof per trustee",
            "setupPackage.publicKeyShareLnpProofs.proofRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut proof_roots = Vec::new();
    for lnp_proof_record in proof_records_array {
        if let Err(error) = verify_public_key_share_lnp_proof_record(
            setup_package,
            setup_context,
            request,
            public_matrix_seed_hash,
            lnp_proof_record,
            &share_records,
            &proof_records,
            &same_secret_records,
            &same_secret_proof_bindings,
            &material_bindings,
            &transported_constant_commitments,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(public_key_share_lnp_proof_refusal(
                "publicKeyShareLnpProofVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareLnpProofs.proofRecords",
            )?));
        }
        proof_roots.push(json!({
            "trusteeIdentity": value_string(lnp_proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(lnp_proof_record, "trusteeRosterPosition")?,
            "publicKeyShareLnpProofRoot": value_string(
                lnp_proof_record,
                "publicKeyShareLnpProofRoot",
            )?,
        }));
    }
    if proof_set.get("publicKeyShareLnpProofRoots") != Some(&Value::Array(proof_roots)) {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofRootListMismatch",
            "publicKeyShareLnpProofs.publicKeyShareLnpProofRoots must match the ordered proof records",
            "setupPackage.publicKeyShareLnpProofs.publicKeyShareLnpProofRoots",
        )?));
    }
    let Some(lnp_proof_set_root) = proof_set
        .get("publicKeyShareLnpProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        lnp_proof_set_root,
        "publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot",
    )?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key LNP proof set object was checked")
        .remove("publicKeyShareLnpProofSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if lnp_proof_set_root != expected_root {
        return Ok(Some(public_key_share_lnp_proof_refusal(
            "publicKeyShareLnpProofSetRootMismatch",
            "publicKeyShareLnpProofSetRoot does not match the canonical public-key LNP proof set",
            "setupPackage.publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_material_acceptance_boundary(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in ["bgvPublicKey", "bgvPublicKeyRoot"] {
        if setup_package.get(field_name).is_some() {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyMaterialBeforeProofVerification",
                "raw BGV public-key material is not accepted until accepted public-key proof-byte verifiers pass",
                format!("setupPackage.{field_name}"),
            )?));
        }
    }

    Ok(None)
}

fn verify_collective_public_key_material(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let aggregate_object = setup_package.get("collectivePublicKey");
    let aggregate_root = setup_package.get("collectivePublicKeyRoot");
    if aggregate_object.is_none() && aggregate_root.is_none() {
        return Ok(None);
    }
    let Some(aggregate_object) = aggregate_object else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyMaterialBeforeProofVerification",
            "collective public-key material is not accepted unless it is root-bound to verified public-key share material and LNP proof records",
            "setupPackage.collectivePublicKeyRoot",
        )?));
    };
    if !aggregate_object.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyNotObject",
            "collectivePublicKey must be a root-bound object",
            "setupPackage.collectivePublicKey",
        )?));
    }
    if let Some(unexpected_field) = unexpected_collective_public_key_field(aggregate_object) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyUnexpectedField",
            format!("collectivePublicKey contains unexpected field {unexpected_field}"),
            format!("setupPackage.collectivePublicKey.{unexpected_field}"),
        )?));
    }
    if aggregate_object.get("objectType").and_then(Value::as_str)
        != Some(COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyTypeMismatch",
            "collectivePublicKey.objectType must be CollectivePublicKey",
            "setupPackage.collectivePublicKey.objectType",
        )?));
    }
    if aggregate_object
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyVersionMismatch",
            "collectivePublicKey.objectVersion must be 1",
            "setupPackage.collectivePublicKey.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before collective public-key verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(aggregate_object, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyContextMismatch",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
        ("aggregationStatus", "lnp-proof-aggregated-review-gated"),
        (
            "materialEncoding",
            "embedded-full-collective-public-key-coefficients",
        ),
    ] {
        if aggregate_object.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeyProfileMismatch",
                format!("collectivePublicKey.{field_name} must be {expected_value}"),
                format!("setupPackage.collectivePublicKey.{field_name}"),
            )?));
        }
    }
    let material_set = setup_package.get("publicKeyShareMaterial").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial was required before collective public-key verification",
        )
    })?;
    let lnp_proof_set = setup_package
        .get("publicKeyShareLnpProofs")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareLnpProofs was required before collective public-key verification",
            )
        })?;
    let common_binding = public_key_common_binding(setup_package)?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        value_string(
            setup_package.get("publicKeyShares").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShares was required before collective public-key verification",
                )
            })?,
            "publicKeyShareSetRoot",
        )?,
        &share_records,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeySourceMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    let ring_degree = value_u64(aggregate_object, "ringDegree")?;
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE as u64
        || aggregate_object
            .get("participantCount")
            .and_then(Value::as_u64)
            != Some(FIRST_PROFILE_PARTICIPANT_COUNT)
        || aggregate_object.get("rnsLimbCount").and_then(Value::as_u64)
            != Some(DATA_PRIMES.len() as u64)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyProfileCountMismatch",
            "collectivePublicKey participant count, limb count, and ring degree must match the selected setup profile",
            "setupPackage.collectivePublicKey",
        )?));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    let same_secret_proof_set_root = same_secret_proof_set_root_from_package(setup_package)?;
    let same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let expected_source_bindings = [
        (
            "publicMatrixSeedHash",
            Some(common_binding.public_matrix_seed_hash.as_str()),
        ),
        (
            "publicKeyCrpRoot",
            Some(common_binding.public_key_crp_root.as_str()),
        ),
        (
            "publicAPolynomialRoot",
            Some(common_binding.public_a_polynomial_root.as_str()),
        ),
        (
            "sameSecretConsistencyRoot",
            Some(same_secret_consistency_root.as_str()),
        ),
        (
            "sameSecretProofSetRoot",
            Some(same_secret_proof_set_root.as_str()),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            Some(same_secret_proof_family_binding_root.as_str()),
        ),
        (
            "publicKeyShareSetRoot",
            setup_package
                .get("publicKeyShares")
                .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareProofSetRoot",
            setup_package
                .get("publicKeyShareProofs")
                .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareMaterialSetRoot",
            material_set
                .get("publicKeyShareMaterialSetRoot")
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareLnpProofSetRoot",
            lnp_proof_set
                .get("publicKeyShareLnpProofSetRoot")
                .and_then(Value::as_str),
        ),
    ];
    for (field_name, expected_value) in expected_source_bindings {
        if aggregate_object.get(field_name).and_then(Value::as_str) != expected_value {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeySourceRootMismatch",
                format!("collectivePublicKey.{field_name} must bind the verified source root"),
                format!("setupPackage.collectivePublicKey.{field_name}"),
            )?));
        }
    }
    if let Err(error) = verify_collective_public_key_coefficients(
        aggregate_object,
        &material_bindings,
        usize::try_from(ring_degree).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public-key ring degree does not fit usize",
            )
        })?,
    ) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyVerificationFailed",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
    let collective_public_key_root = value_string(aggregate_object, "collectivePublicKeyRoot")?;
    validate_hash_string(
        collective_public_key_root,
        "collectivePublicKey.collectivePublicKeyRoot",
    )?;
    if aggregate_root.and_then(Value::as_str) != Some(collective_public_key_root) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyPackageRootMismatch",
            "setupPackage.collectivePublicKeyRoot must match collectivePublicKey.collectivePublicKeyRoot",
            "setupPackage.collectivePublicKeyRoot",
        )?));
    }
    let mut root_input = aggregate_object.clone();
    root_input
        .as_object_mut()
        .expect("collective public-key object was checked")
        .remove("collectivePublicKeyRoot");
    let expected_root = derive_protocol_hash("CollectivePublicKeyRoot", &root_input)?;
    if collective_public_key_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyRootMismatch",
            "collectivePublicKeyRoot does not match the canonical collective public key",
            "setupPackage.collectivePublicKey.collectivePublicKeyRoot",
        )?));
    }

    Ok(None)
}

fn verify_collective_public_key_coefficients(
    aggregate_object: &Value,
    material_bindings: &BTreeMap<u64, PublicKeyShareMaterialBinding>,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if material_bindings.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public-key aggregation requires one verified share material record per trustee",
        ));
    }
    let aggregate_limbs = aggregate_object
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one aggregate coefficient vector per Q_share limb",
        ));
    }
    let expected_share_material_roots = material_bindings
        .values()
        .map(|binding| {
            json!({
                "trusteeIdentity": binding.trustee_identity,
                "trusteeRosterPosition": binding.trustee_roster_position,
                "publicKeyShareRoot": binding.public_key_share_root,
                "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
            })
        })
        .collect::<Vec<_>>();
    if aggregate_object.get("sourceShareMaterialRoots")
        != Some(&Value::Array(expected_share_material_roots))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the ordered verified share material roots",
        ));
    }
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((ring_degree * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            ring_degree,
            "collective public-key coefficient vector width does not match the material ring degree",
        )?;
        let modulus = DATA_PRIMES[rns_limb_index];
        let mut expected_coefficients = vec![0_u64; ring_degree];
        for material_binding in material_bindings.values() {
            let share_coefficients = material_binding
                .coefficients_by_limb
                .get(rns_limb_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material is missing an aggregate limb",
                    )
                })?;
            if share_coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material width does not match collective public-key width",
                ));
            }
            for (coefficient_index, share_coefficient) in share_coefficients.iter().enumerate() {
                expected_coefficients[coefficient_index] = add_mod(
                    expected_coefficients[coefficient_index],
                    *share_coefficient,
                    modulus,
                )?;
            }
        }
        if coefficients != expected_coefficients {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate coefficients must equal the sum of verified public-key shares",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if aggregate_limb
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate coefficient hash must match the aggregate coefficients",
            ));
        }
    }

    Ok(())
}

fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareMaterialBinding>> {
    if !material_set.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial must be a root-bound object",
        ));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_material_set_field(material_set) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("publicKeyShareMaterial contains unexpected field {unexpected_field}"),
        ));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.objectType must be PublicKeyShareMaterialSet",
        ));
    }
    if material_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.objectVersion must be 1",
        ));
    }
    verify_same_secret_context(material_set, setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "materialEncoding",
            "embedded-full-public-key-share-coefficients",
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
    ] {
        if material_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if material_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    let ring_degree = usize::try_from(value_u64(material_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.ringDegree does not fit usize",
        )
    })?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial.ringDegree is outside the selected profile",
        ));
    }
    if material_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || material_set.get("publicKeyCrpRoot").and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || material_set
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
        || material_set
            .get("publicKeyShareSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_set_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial must bind accepted public randomness and public-key share set root",
        ));
    }
    let material_records = material_set
        .get("shareMaterialRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords are required",
            )
        })?;
    if material_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.shareMaterialRecords must contain one record per trustee",
        ));
    }
    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for material_record in material_records {
        let binding = verify_public_key_share_material_record(
            material_record,
            setup_context,
            common_binding,
            ring_degree,
            share_records,
        )?;
        if bindings
            .insert(binding.trustee_roster_position, binding.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords contain duplicate roster positions",
            ));
        }
        material_roots.push(json!({
            "trusteeIdentity": binding.trustee_identity,
            "trusteeRosterPosition": binding.trustee_roster_position,
            "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
        }));
    }
    if material_set.get("publicKeyShareMaterialRoots") != Some(&Value::Array(material_roots)) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial.publicKeyShareMaterialRoots must match the ordered material records",
        ));
    }
    let material_set_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_set_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let mut root_input = material_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material set object was checked")
        .remove("publicKeyShareMaterialSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if material_set_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialSetRoot does not match the canonical public-key share material set",
        ));
    }

    Ok(bindings)
}

fn verify_public_key_share_material_record(
    material_record: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<PublicKeyShareMaterialBinding> {
    if !material_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material records must be objects",
        ));
    }
    if let Some(unexpected_field) =
        unexpected_public_key_share_material_record_field(material_record)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("public-key share material contains unexpected field {unexpected_field}"),
        ));
    }
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material objectType must be PublicKeyShareMaterial",
        ));
    }
    if material_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material objectVersion must be 1",
        ));
    }
    verify_same_secret_context(material_record, setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "materialEncoding",
            "embedded-full-public-key-share-coefficients",
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
    ] {
        if material_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public-key share material {field_name} must be {expected_value}"),
            ));
        }
    }
    if material_record.get("ringDegree").and_then(Value::as_u64) != Some(ring_degree as u64)
        || material_record.get("rnsLimbCount").and_then(Value::as_u64)
            != Some(DATA_PRIMES.len() as u64)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material ring degree and limb count must match the material set",
        ));
    }
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || material_record
            .get("publicKeyCrpRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || material_record
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material must bind accepted public randomness",
        ));
    }
    let trustee_roster_position = value_u64(material_record, "trusteeRosterPosition")?;
    let trustee_identity = value_string(material_record, "trusteeIdentity")?.to_string();
    let share_record = share_records.get(&trustee_roster_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material must reference an accepted share record",
        )
    })?;
    if share_record.get("trusteeIdentity").and_then(Value::as_str)
        != Some(trustee_identity.as_str())
        || material_record
            .get("publicKeyShareRoot")
            .and_then(Value::as_str)
            != share_record
                .get("publicKeyShareRoot")
                .and_then(Value::as_str)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material trustee and share root must match the accepted share record",
        ));
    }
    let limbs = material_record
        .get("shareCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share material coefficients are required",
            )
        })?;
    if limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material must contain one coefficient vector per Q_share limb",
        ));
    }
    let share_hashes = share_record
        .get("shareCoefficientVectorHash512ByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public-key share hashes are required",
            )
        })?;
    let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, limb) in limbs.iter().enumerate() {
        if limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || limb.get("rnsPrime").and_then(Value::as_u64) != Some(DATA_PRIMES[rns_limb_index])
            || limb.get("component").and_then(Value::as_str) != Some("b_i")
            || limb.get("coefficientByteLength").and_then(Value::as_u64)
                != Some((ring_degree * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share material limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(limb, "coefficientsLeHex")?,
            ring_degree,
            "public-key share coefficient vector width does not match the material ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share coefficient vector contains a non-canonical residue",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if limb.get("coefficientVectorHash512").and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
            || share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                .and_then(Value::as_str)
                != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share material coefficient hash must match the accepted share record",
            ));
        }
        coefficients_by_limb.push(coefficients);
    }
    let public_key_share_material_root =
        value_string(material_record, "publicKeyShareMaterialRoot")?.to_string();
    validate_hash_string(
        &public_key_share_material_root,
        "publicKeyShareMaterial.shareMaterialRecords.publicKeyShareMaterialRoot",
    )?;
    let mut root_input = material_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material record object was checked")
        .remove("publicKeyShareMaterialRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_material_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialRoot does not match the canonical public-key share material",
        ));
    }

    Ok(PublicKeyShareMaterialBinding {
        trustee_identity,
        trustee_roster_position,
        public_key_share_root: value_string(material_record, "publicKeyShareRoot")?.to_string(),
        public_key_share_material_root,
        coefficients_by_limb,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_public_key_share_lnp_proof_record(
    setup_package: &Value,
    setup_context: &Value,
    request: &Value,
    public_matrix_seed_hash: &str,
    proof_record: &Value,
    share_records: &BTreeMap<u64, Value>,
    public_key_share_proof_records: &BTreeMap<u64, Value>,
    same_secret_records: &BTreeMap<u64, Value>,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    material_bindings: &BTreeMap<u64, PublicKeyShareMaterialBinding>,
    transported_constant_commitments: &BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof records must be objects",
        ));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_lnp_proof_record_field(proof_record)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("public-key LNP proof contains unexpected field {unexpected_field}"),
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_LNP_PROOF_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof objectType must be PublicKeyShareLnpProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof objectVersion must be 1",
        ));
    }
    verify_same_secret_context(proof_record, setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public-key LNP proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let expected_setup_proof_binding = setup_proof_record_binding_value()?;
    let actual_setup_proof_binding = proof_record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof setupProofBinding must bind the fixed setup-proof profile",
        )
    })?;
    if actual_setup_proof_binding != &expected_setup_proof_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key LNP proof setupProofBinding must match the fixed setup-proof profile",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        actual_setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;
    let expected_tbox_parameter_profile_hash =
        super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?;
    if proof_record
        .get("publicKeyShareTboxParameterProfileHash")
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof publicKeyShareTboxParameterProfileHash must match the accepted public-key share LNP tbox profile",
        ));
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof records must have distinct trustee roster positions",
        ));
    }
    let share_record = share_records.get(&trustee_roster_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof must reference an accepted share record",
        )
    })?;
    let public_key_share_proof_record = public_key_share_proof_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key LNP proof must reference an accepted public-key proof statement",
            )
        })?;
    let same_secret_record = same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key LNP proof must reference an accepted same-secret statement",
            )
        })?;
    let same_secret_proof_binding = same_secret_proof_bindings
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key LNP proof must reference a verified same-secret proof",
            )
        })?;
    let material_binding = material_bindings
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key LNP proof must reference accepted public-key share material",
            )
        })?;
    for field_name in [
        "trusteeIdentity",
        "publicKeyShareRoot",
        "sameSecretStatementRoot",
        "trusteeSecretCommitmentRoot",
    ] {
        if proof_record.get(field_name) != public_key_share_proof_record.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("public-key LNP proof {field_name} must match the proof statement"),
            ));
        }
    }
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(material_binding.public_key_share_root.as_str())
        || proof_record
            .get("publicKeyShareMaterialRoot")
            .and_then(Value::as_str)
            != Some(material_binding.public_key_share_material_root.as_str())
        || proof_record.get("publicKeyShareProofRoot")
            != public_key_share_proof_record.get("publicKeyShareProofRoot")
        || proof_record.get("sameSecretStatementRoot")
            != same_secret_record.get("sameSecretStatementRoot")
        || proof_record.get("trusteeSecretCommitmentRoot")
            != same_secret_record.get("trusteeSecretCommitmentRoot")
        || proof_record.get("trusteeIdentity") != same_secret_record.get("trusteeIdentity")
        || proof_record.get("trusteeIdentity") != share_record.get("trusteeIdentity")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key LNP proof must bind the accepted share, proof statement, material, and same-secret roots",
        ));
    }
    if proof_record
        .get("sameSecretProofRoot")
        .and_then(Value::as_str)
        != Some(same_secret_proof_binding.same_secret_proof_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .same_secret_statement_root
                    .as_str(),
            )
        || proof_record
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .same_secret_proof_family_binding_root
                    .as_str(),
            )
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(
                same_secret_proof_binding
                    .trustee_secret_commitment_root
                    .as_str(),
            )
        || proof_record.get("trusteeIdentity").and_then(Value::as_str)
            != Some(same_secret_proof_binding.trustee_identity.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key LNP proof must bind the verified same-secret proof root",
        ));
    }
    let proof_bytes = public_key_share_lnp_proof_bytes_from_record(proof_record, request)?;
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key LNP proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofSizeBytes must match supplied proof bytes",
        ));
    }
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    if proof_bytes_hash != public_key_share_lnp_relation_proof_bytes_hash(&proof_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proofBytesHash must match supplied proof bytes",
        ));
    }
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        setup_package,
        trustee_roster_position,
        transported_constant_commitments,
    )?;
    let verification =
        verify_public_key_share_lnp_relation_proof(PublicKeyShareLnpProofVerificationInput {
            public_matrix_seed_hash,
            public_key_share_record: share_record,
            public_key_share_proof_record,
            same_secret_statement_record: same_secret_record,
            constant_commitments: &constant_commitments,
            public_share_coefficients_by_limb: &material_binding.coefficients_by_limb,
            setup_proof_binding: actual_setup_proof_binding,
            proof_bytes: &proof_bytes,
        })?;
    let verified_proof_size = u64::try_from(verification.proof_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key verified proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(verification.statement_hash_hex.as_str())
        || proof_record
            .get("relationCommitmentHash")
            .and_then(Value::as_str)
            != Some(verification.relation_commitment_hash_hex.as_str())
        || proof_record
            .get("tboxCommitmentPrefixHash")
            .and_then(Value::as_str)
            != Some(verification.tbox_commitment_prefix_hash.as_str())
        || proof_record.get("challenge").and_then(Value::as_u64) != Some(verification.challenge)
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof transcript metadata must match verified proof bytes",
        ));
    }
    let proof_root = value_string(proof_record, "publicKeyShareLnpProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key LNP proof record object was checked")
        .remove("publicKeyShareLnpProofRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if proof_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareLnpProofRoot does not match the canonical public-key LNP proof record",
        ));
    }

    Ok(())
}

fn public_key_share_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShares.shareRecords were required before public-key LNP proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, share_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn public_key_share_proof_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let proof_records = setup_package
        .get("publicKeyShareProofs")
        .and_then(|proof_set| proof_set.get("proofRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareProofs.proofRecords were required before public-key LNP proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for proof_record in proof_records {
        let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, proof_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share proof records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

fn verify_public_key_share_proof_record(
    proof_record: &Value,
    setup_context: &Value,
    share_bindings: &BTreeMap<u64, PublicKeyShareBinding>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !proof_record.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofNotObject",
            "public-key share proof records must be objects",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_proof_field(proof_record) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofUnexpectedField",
            format!("public-key share proof contains unexpected field {unexpected_field}"),
            format!("setupPackage.publicKeyShareProofs.proofRecords.{unexpected_field}"),
        )?));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_PROOF_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTypeMismatch",
            "public-key share proof objectType must be PublicKeyShareProof",
            "setupPackage.publicKeyShareProofs.proofRecords.objectType",
        )?));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofVersionMismatch",
            "public-key share proof objectVersion must be 1",
            "setupPackage.publicKeyShareProofs.proofRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(proof_record, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofContextMismatch",
            error.message,
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        ("proofVerificationStatus", "lnp-proof-verification-pending"),
        (
            "noWrapRelation",
            "PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 over lifted integers",
        ),
        ("errorSupport", "checked-by-public-key-share-lnp-proof-set"),
        (
            "carryWitnessStatus",
            "checked-by-public-key-share-lnp-proof-set",
        ),
        (
            "proofBytesStatus",
            "supplied-by-public-key-share-lnp-proof-set",
        ),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "publicKeyShareProofProfileMismatch",
                format!("public-key share proof {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShareProofs.proofRecords.{field_name}"),
            )?));
        }
    }
    if proof_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRnsLimbCountMismatch",
            "public-key share proof rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShareProofs.proofRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        proof_record,
        common_binding,
        "publicKeyShareProofs.proofRecords",
        PublicKeyRefusalKind::Proof,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(proof_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofDuplicate",
            "public-key share proof records must have distinct trustee roster positions",
            "setupPackage.publicKeyShareProofs.proofRecords",
        )?));
    }
    let Some(share_binding) = share_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofShareMissing",
            "public-key share proof must reference an accepted public-key share",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofSameSecretMissing",
            "public-key share proof must reference an accepted same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeRosterPosition",
        )?));
    };
    if share_binding.trustee_roster_position != trustee_roster_position
        || share_binding.trustee_identity != trustee_identity
        || same_secret_binding.trustee_identity != trustee_identity
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofTrusteeMismatch",
            "public-key share proof trustee must match the accepted share and same-secret statement",
            "setupPackage.publicKeyShareProofs.proofRecords.trusteeIdentity",
        )?));
    }
    if proof_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
        != Some(share_binding.public_key_share_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("trusteeSecretCommitmentRoot")
            .and_then(Value::as_str)
            != Some(share_binding.trustee_secret_commitment_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
        || proof_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(share_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofBindingMismatch",
            "public-key share proof must bind the accepted share, trustee secret, and same-secret roots",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareRoot",
        )?));
    }

    let Some(public_key_share_proof_root) = proof_record
        .get("publicKeyShareProofRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShareProofs.proofRecords.publicKeyShareProofRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_proof_root,
        "publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
    )?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share proof object was checked")
        .remove("publicKeyShareProofRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareProofRoot", &root_input)?;
    if public_key_share_proof_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyShareProofRootMismatch",
            "publicKeyShareProofRoot does not match the canonical public-key share proof statement",
            "setupPackage.publicKeyShareProofs.proofRecords.publicKeyShareProofRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_limb_hashes(
    limb_values: Option<&Vec<Value>>,
) -> CanonicalResult<Option<Value>> {
    let Some(limb_values) = limb_values else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if limb_values.len() != DATA_PRIMES.len() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCoefficientLimbCountMismatch",
            "public-key share must bind one coefficient hash for every Q_share limb",
            "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
        )?));
    }
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let limb_value = &limb_values[rns_limb_index];
        if limb_value.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || limb_value.get("rnsPrime").and_then(Value::as_u64) != Some(rns_prime)
            || limb_value.get("component").and_then(Value::as_str) != Some("b_i")
        {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareCoefficientLimbMismatch",
                "public-key share coefficient hash entries must follow Q_share order",
                "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb",
            )?));
        }
        let Some(hash) = limb_value
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("publicKeyShareProofs"),
                vec![
                    "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512"
                        .to_string(),
                ],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb.coefficientVectorHash512",
        )?;
    }

    Ok(None)
}

fn public_key_common_binding(setup_package: &Value) -> CanonicalResult<PublicKeyCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before public-key share verification",
        )
    })?;
    let public_derivations = common_randomness.get("publicDerivations").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations was required before public-key share verification",
        )
    })?;
    Ok(PublicKeyCommonBinding {
        public_matrix_seed_hash: value_string(common_randomness, "publicMatrixSeedHash")?
            .to_string(),
        public_key_crp_root: public_derivations
            .get("crpRoots")
            .and_then(|crp_roots| crp_roots.get("publicKeyCrpRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public-key CRP root was required before public-key share verification",
                )
            })?
            .to_string(),
        public_a_polynomial_root: public_derivations
            .get("bgvPublicA")
            .and_then(|public_a| public_a.get("publicPolynomialRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "BGV public a root was required before public-key share verification",
                )
            })?
            .to_string(),
    })
}

#[derive(Clone, Copy)]
enum PublicKeyRefusalKind {
    Share,
    Proof,
}

fn verify_public_key_common_fields(
    value: &Value,
    common_binding: &PublicKeyCommonBinding,
    object_path: &str,
    refusal_kind: PublicKeyRefusalKind,
) -> CanonicalResult<Option<Value>> {
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            common_binding.public_matrix_seed_hash.as_str(),
        ),
        (
            "publicKeyCrpRoot",
            common_binding.public_key_crp_root.as_str(),
        ),
        (
            "publicAPolynomialRoot",
            common_binding.public_a_polynomial_root.as_str(),
        ),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            let message =
                format!("{object_path}.{field_name} must match accepted common randomness");
            let path = format!("setupPackage.{object_path}.{field_name}");
            return Ok(Some(match refusal_kind {
                PublicKeyRefusalKind::Share => {
                    public_key_share_refusal("publicKeyShareCommonBindingMismatch", message, path)?
                }
                PublicKeyRefusalKind::Proof => public_key_share_proof_refusal(
                    "publicKeyShareCommonBindingMismatch",
                    message,
                    path,
                )?,
            }));
        }
    }

    Ok(None)
}

fn same_secret_consistency_root_from_package(setup_package: &Value) -> CanonicalResult<String> {
    setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("sameSecretConsistencyRoot"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretConsistencyRoot was required before public-key share verification",
            )
        })
}

fn same_secret_statement_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, SameSecretStatementBinding>> {
    let statement_records = setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("statementRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret statement records were required before public-key share verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for statement_record in statement_records {
        let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
        if bindings
            .insert(
                trustee_roster_position,
                SameSecretStatementBinding {
                    trustee_identity: value_string(statement_record, "trusteeIdentity")?
                        .to_string(),
                    trustee_secret_commitment_root: value_string(
                        statement_record,
                        "trusteeSecretCommitmentRoot",
                    )?
                    .to_string(),
                    same_secret_statement_root: value_string(
                        statement_record,
                        "sameSecretStatementRoot",
                    )?
                    .to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "same-secret statement records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn public_key_share_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareBinding>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records were required before public-key share proof verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if bindings
            .insert(
                trustee_roster_position,
                PublicKeyShareBinding {
                    trustee_identity: value_string(share_record, "trusteeIdentity")?.to_string(),
                    trustee_roster_position,
                    public_key_share_root: value_string(share_record, "publicKeyShareRoot")?
                        .to_string(),
                    trustee_secret_commitment_root: value_string(
                        share_record,
                        "trusteeSecretCommitmentRoot",
                    )?
                    .to_string(),
                    same_secret_statement_root: value_string(
                        share_record,
                        "sameSecretStatementRoot",
                    )?
                    .to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn verify_evaluator_key_schedule(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(schedule) = setup_package.get("evaluatorKeySchedule") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("relinearizationRoundOne"),
            vec!["evaluatorKeySchedule".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !schedule.is_object() {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleNotObject",
            "evaluatorKeySchedule must be a root-bound object, not an array or scalar",
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    if let Some(unexpected_field) = unexpected_evaluator_key_schedule_field(schedule) {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleUnexpectedField",
            format!("evaluatorKeySchedule contains unexpected field {unexpected_field}"),
            format!("setupPackage.evaluatorKeySchedule.{unexpected_field}"),
        )?));
    }
    if schedule.get("objectType").and_then(Value::as_str)
        != Some(EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleTypeMismatch",
            "evaluatorKeySchedule.objectType must be EvaluatorKeySchedule",
            "setupPackage.evaluatorKeySchedule.objectType",
        )?));
    }
    if schedule.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleVersionMismatch",
            "evaluatorKeySchedule.objectVersion must be 1",
            "setupPackage.evaluatorKeySchedule.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before evaluator-key schedule verification",
        )
    })?;
    if let Err(error) = verify_context_fields_match(schedule, setup_context, "evaluatorKeySchedule")
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleContextMismatch",
            error.message,
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        (
            "genericKeySwitchPolicy",
            "refused-unless-explicitly-required",
        ),
        (
            "genericKeySwitchProofStatus",
            "not-required-for-first-profile",
        ),
        (
            "scheduleBindingStatus",
            "relinearization-and-galois-proof-verifiers-pending",
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleProfileMismatch",
                format!("evaluatorKeySchedule.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if schedule.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleCountMismatch",
                format!("evaluatorKeySchedule.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluator-key schedule verification",
        )
    })?;
    let public_derivations = common_randomness.get("publicDerivations").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations was required before evaluator-key schedule verification",
        )
    })?;
    let crp_roots = public_derivations.get("crpRoots").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations.crpRoots was required before evaluator-key schedule verification",
        )
    })?;
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            value_string(common_randomness, "publicMatrixSeedHash")?,
        ),
        (
            "relinearizationCrpRoot",
            value_string(crp_roots, "relinearizationCrpRoot")?,
        ),
        (
            "galoisKeyCrpRoot",
            value_string(crp_roots, "galoisKeyCrpRoot")?,
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeySchedulePublicBindingMismatch",
                format!("evaluatorKeySchedule.{field_name} must match accepted common randomness"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    for (field_name, expected_value, message) in [
        (
            "sameSecretConsistencyRoot",
            same_secret_consistency_root_from_package(setup_package)?,
            "same-secret statement root",
        ),
        (
            "publicKeyShareSetRoot",
            setup_package
                .get("publicKeyShares")
                .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "publicKeyShareSetRoot was required before evaluator-key schedule verification",
                    )
                })?
                .to_string(),
            "public-key share set root",
        ),
        (
            "publicKeyShareProofSetRoot",
            setup_package
                .get("publicKeyShareProofs")
                .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "publicKeyShareProofSetRoot was required before evaluator-key schedule verification",
                    )
                })?
                .to_string(),
            "public-key share proof set root",
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value.as_str()) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleSetupRootMismatch",
                format!("evaluatorKeySchedule.{field_name} must match accepted {message}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    let expected_relinearization_level_schedule = expected_relinearization_level_schedule();
    if schedule.get("relinearizationLevelSchedule")
        != Some(&expected_relinearization_level_schedule)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleRelinearizationMismatch",
            "evaluatorKeySchedule.relinearizationLevelSchedule must match the frozen first-profile relinearization levels",
            "setupPackage.evaluatorKeySchedule.relinearizationLevelSchedule",
        )?));
    }
    let expected_required_galois_key_schedule = expected_required_galois_key_schedule()?;
    if schedule.get("requiredGaloisKeySchedule") != Some(&expected_required_galois_key_schedule) {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleGaloisMismatch",
            "evaluatorKeySchedule.requiredGaloisKeySchedule must match the frozen first-profile Galois key schedule",
            "setupPackage.evaluatorKeySchedule.requiredGaloisKeySchedule",
        )?));
    }
    let expected_required_galois_set_hash =
        expected_required_galois_set_hash(&expected_required_galois_key_schedule)?;
    if schedule
        .get("requiredGaloisSetHash")
        .and_then(Value::as_str)
        != Some(expected_required_galois_set_hash.as_str())
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "requiredGaloisSetHashMismatch",
            "evaluatorKeySchedule.requiredGaloisSetHash does not match the frozen first-profile Galois set",
            "setupPackage.evaluatorKeySchedule.requiredGaloisSetHash",
        )?));
    }

    let Some(evaluator_key_schedule_root) = schedule
        .get("evaluatorKeyScheduleRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("relinearizationRoundOne"),
            vec!["evaluatorKeySchedule.evaluatorKeyScheduleRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        evaluator_key_schedule_root,
        "evaluatorKeySchedule.evaluatorKeyScheduleRoot",
    )?;
    let mut root_input = schedule.clone();
    root_input
        .as_object_mut()
        .expect("evaluator key schedule object was checked")
        .remove("evaluatorKeyScheduleRoot");
    let expected_root = derive_protocol_hash("EvaluatorKeyScheduleRoot", &root_input)?;
    if evaluator_key_schedule_root != expected_root {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleRootMismatch",
            "evaluatorKeyScheduleRoot does not match the canonical evaluator-key schedule",
            "setupPackage.evaluatorKeySchedule.evaluatorKeyScheduleRoot",
        )?));
    }

    Ok(None)
}

fn verify_context_fields_match(
    value: &Value,
    setup_context: &Value,
    value_name: &str,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{value_name}.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn unexpected_evaluator_key_schedule_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "relinearizationCrpRoot",
            "galoisKeyCrpRoot",
            "sameSecretConsistencyRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofSetRoot",
            "relinearizationLevelSchedule",
            "requiredGaloisKeySchedule",
            "requiredGaloisSetHash",
            "genericKeySwitchPolicy",
            "genericKeySwitchProofStatus",
            "scheduleBindingStatus",
            "evaluatorKeyScheduleRoot",
        ],
    )
}

fn evaluator_key_schedule_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("relinearizationRoundOne"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_pending_evaluation_key_material_boundary(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    if let Some(response) = verify_relinearization_key_share_rounds(setup_package)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_galois_key_share_batches(setup_package)? {
        return Ok(Some(response));
    }

    let evaluation_keys = setup_package.get("evaluationKeys").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluationKeys was required before evaluation-key material boundary verification",
        )
    })?;
    let Some(evaluation_keys) = evaluation_keys.as_object() else {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysNotObject",
            "evaluationKeys must be an object while proof verification is pending",
            "setupPackage.evaluationKeys",
        )?));
    };
    if !evaluation_keys.is_empty() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysBeforeAcceptedAssembly",
            "evaluation keys are refused until accepted relinearization and Galois proof records are consumed by the evaluation-key assembly verifier",
            "setupPackage.evaluationKeys",
        )?));
    }

    Ok(None)
}

fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("relinearizationRoundOne"),
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !rounds.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsNotObject",
            "relinearizationKeyShareRounds must be a root-bound object",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    if rounds.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(None);
    }
    if let Some(unexpected_field) = unexpected_relinearization_key_share_rounds_field(rounds) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsUnexpectedField",
            format!("relinearizationKeyShareRounds contains unexpected field {unexpected_field}"),
            format!("setupPackage.relinearizationKeyShareRounds.{unexpected_field}"),
        )?));
    }
    if rounds.get("objectType").and_then(Value::as_str)
        != Some(RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsTypeMismatch",
            "relinearizationKeyShareRounds.objectType must be RelinearizationKeyShareRounds",
            "setupPackage.relinearizationKeyShareRounds.objectType",
        )?));
    }
    if rounds.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsVersionMismatch",
            "relinearizationKeyShareRounds.objectVersion must be 1",
            "setupPackage.relinearizationKeyShareRounds.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before relinearization proof verification",
        )
    })?;
    if let Err(error) =
        verify_context_fields_match(rounds, setup_context, "relinearizationKeyShareRounds")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsContextMismatch",
            error.message,
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "relinearization-key-share"),
        (
            "proofVerificationStatus",
            RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", RELINEARIZATION_PROOF_MODEL_STATUS),
    ] {
        if rounds.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsProfileMismatch",
                format!("relinearizationKeyShareRounds.{field_name} must be {expected_value}"),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if rounds.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsCountMismatch",
                format!("relinearizationKeyShareRounds.{field_name} must be {expected_value}"),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretConsistencyRoot",
            binding.same_secret_consistency_root.as_str(),
        ),
        (
            "sameSecretProofSetRoot",
            binding.same_secret_proof_set_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareSetRoot",
            binding.public_key_share_set_root.as_str(),
        ),
        (
            "publicKeyShareLnpProofSetRoot",
            binding.public_key_share_lnp_proof_set_root.as_str(),
        ),
        (
            "relinearizationCrpRoot",
            binding.relinearization_crp_root.as_str(),
        ),
    ] {
        if rounds.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsBindingMismatch",
                format!(
                    "relinearizationKeyShareRounds.{field_name} must match the accepted setup binding"
                ),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    let expected_level_schedule = expected_relinearization_level_schedule();
    if rounds.get("relinearizationLevelSchedule") != Some(&expected_level_schedule) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsScheduleMismatch",
            "relinearizationKeyShareRounds.relinearizationLevelSchedule must match the frozen evaluator schedule",
            "setupPackage.relinearizationKeyShareRounds.relinearizationLevelSchedule",
        )?));
    }
    let expected_levels = expected_relinearization_levels();
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let round_one_records = array_value(rounds, "roundOneRecords")?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let expected_record_count = expected_levels.len() * FIRST_PROFILE_PARTICIPANT_COUNT as usize;
    if round_one_records.len() != expected_record_count
        || round_two_records.len() != expected_record_count
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundCountMismatch",
            "relinearization round-one and round-two records must contain one record per trustee and scheduled level",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }

    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    for record in round_one_records {
        let (level, trustee_roster_position, record_root, share_root) =
            match verify_relinearization_round_one_record(
                record,
                &binding,
                &same_secret_proof_bindings,
            ) {
                Ok(verified_record) => verified_record,
                Err(error) => {
                    return Ok(Some(evaluation_key_material_refusal(
                        "evaluationKeyMaterialVerificationFailed",
                        error.message,
                        "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
                    )?));
                }
            };
        if !expected_levels.contains(&level) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelOutsideSchedule",
                "relinearization round-one record level is not in the frozen schedule",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords.level",
            )?));
        }
        if round_one_record_roots
            .insert((level, trustee_roster_position), record_root.clone())
            .is_some()
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneDuplicate",
                "relinearization round-one records must not repeat a trustee and level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        }
        round_one_share_roots.insert((level, trustee_roster_position), share_root);
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_one_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "roundOneRecordRoot": record_root,
            }));
    }

    let supplied_round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    for level in &expected_levels {
        let Some(record_roots) = round_one_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelMissing",
                "relinearization round-one records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let expected_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "level": level,
                "roundOneRecordRoots": record_roots,
            }),
        )?;
        if supplied_round_one_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneAggregateRootMismatch",
                "relinearization round-one aggregate root must be derived from the ordered round-one records",
                "setupPackage.relinearizationKeyShareRounds.roundOneAggregateRoots",
            )?));
        }
    }

    let mut round_two_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut seen_round_two_records = BTreeSet::new();
    for record in round_two_records {
        let (level, trustee_roster_position, record_root) =
            match verify_relinearization_round_two_record(
                record,
                &binding,
                &same_secret_proof_bindings,
                &round_one_record_roots,
                &round_one_share_roots,
                &supplied_round_one_aggregate_roots,
            ) {
                Ok(verified_record) => verified_record,
                Err(error) => {
                    return Ok(Some(evaluation_key_material_refusal(
                        "evaluationKeyMaterialVerificationFailed",
                        error.message,
                        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
                    )?));
                }
            };
        if !expected_levels.contains(&level) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelOutsideSchedule",
                "relinearization round-two record level is not in the frozen schedule",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.level",
            )?));
        }
        if !seen_round_two_records.insert((level, trustee_roster_position)) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoDuplicate",
                "relinearization round-two records must not repeat a trustee and level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        }
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_two_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "roundTwoRecordRoot": record_root,
            }));
    }
    let supplied_round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;
    for level in &expected_levels {
        let Some(record_roots) = round_two_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelMissing",
                "relinearization round-two records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let expected_root = derive_protocol_hash(
            "RelinearizationRoundTwoAggregateRoot",
            &json!({
                "objectType": "RelinearizationRoundTwoAggregate",
                "objectVersion": 1,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "level": level,
                "roundOneAggregateRoot": supplied_round_one_aggregate_roots
                    .get(level)
                    .expect("round-one aggregate root exists after verification"),
                "roundTwoRecordRoots": record_roots,
            }),
        )?;
        if supplied_round_two_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoAggregateRootMismatch",
                "relinearization round-two aggregate root must be derived from the ordered round-two records and round-one aggregate root",
                "setupPackage.relinearizationKeyShareRounds.roundTwoAggregateRoots",
            )?));
        }
    }

    let supplied_root = value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let mut root_input = rounds.clone();
    root_input
        .as_object_mut()
        .expect("relinearization rounds object was checked")
        .remove("relinearizationKeyShareRoundsRoot");
    let expected_root = derive_protocol_hash("RelinearizationKeyShareRoundsRoot", &root_input)?;
    if supplied_root != expected_root {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsRootMismatch",
            "relinearizationKeyShareRoundsRoot does not match the canonical relinearization proof container",
            "setupPackage.relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot",
        )?));
    }

    Ok(None)
}

fn verify_galois_key_share_batches(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(batches) = setup_package.get("galoisKeyShareBatches") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("galoisKeyBatchProofs"),
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(batches) = batches.as_array() else {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchesNotArray",
            "galoisKeyShareBatches must be an array of root-bound trustee batches",
            "setupPackage.galoisKeyShareBatches",
        )?));
    };
    if batches.is_empty() {
        return Ok(None);
    }
    if batches.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchCountMismatch",
            "galoisKeyShareBatches must contain one batch per trustee",
            "setupPackage.galoisKeyShareBatches",
        )?));
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    let mut seen_roster_positions = BTreeSet::new();
    for batch in batches {
        if let Err(error) = verify_galois_key_share_batch(
            batch,
            &binding,
            &same_secret_proof_bindings,
            &expected_schedule,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeyMaterialVerificationFailed",
                error.message,
                "setupPackage.galoisKeyShareBatches",
            )?));
        }
    }

    Ok(None)
}

struct EvaluationKeyProofCommonBinding {
    evaluator_key_schedule_root: String,
    same_secret_consistency_root: String,
    same_secret_proof_set_root: String,
    same_secret_proof_family_binding_root: String,
    public_key_share_set_root: String,
    public_key_share_lnp_proof_set_root: String,
    relinearization_crp_root: String,
    galois_key_crp_root: String,
    required_galois_set_hash: String,
}

fn evaluation_key_proof_common_binding(
    setup_package: &Value,
) -> CanonicalResult<EvaluationKeyProofCommonBinding> {
    let evaluator_key_schedule = setup_package.get("evaluatorKeySchedule").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluatorKeySchedule was required before evaluation-key proof verification",
        )
    })?;
    let public_derivations = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicDerivations"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicDerivations was required before evaluation-key proof verification",
            )
        })?;
    let crp_roots = public_derivations.get("crpRoots").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations.crpRoots was required before evaluation-key proof verification",
        )
    })?;

    Ok(EvaluationKeyProofCommonBinding {
        evaluator_key_schedule_root: value_string(
            evaluator_key_schedule,
            "evaluatorKeyScheduleRoot",
        )?
        .to_string(),
        same_secret_consistency_root: same_secret_consistency_root_from_package(setup_package)?,
        same_secret_proof_set_root: same_secret_proof_set_root_from_package(setup_package)?,
        same_secret_proof_family_binding_root: same_secret_proof_family_binding_root()?,
        public_key_share_set_root: setup_package
            .get("publicKeyShares")
            .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShareSetRoot was required before evaluation-key proof verification",
                )
            })?
            .to_string(),
        public_key_share_lnp_proof_set_root: setup_package
            .get("publicKeyShareLnpProofs")
            .and_then(|proof_set| proof_set.get("publicKeyShareLnpProofSetRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShareLnpProofSetRoot was required before evaluation-key proof verification",
                )
            })?
            .to_string(),
        relinearization_crp_root: value_string(crp_roots, "relinearizationCrpRoot")?.to_string(),
        galois_key_crp_root: value_string(crp_roots, "galoisKeyCrpRoot")?.to_string(),
        required_galois_set_hash: value_string(evaluator_key_schedule, "requiredGaloisSetHash")?
            .to_string(),
    })
}

fn expected_relinearization_levels() -> Vec<u64> {
    (1..DATA_PRIMES.len()).map(|level| level as u64).collect()
}

fn array_value<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })
}

fn relinearization_aggregate_roots_by_level(
    rounds: &Value,
    field_name: &str,
    root_field_name: &str,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let mut roots = BTreeMap::new();
    for entry in array_value(rounds, field_name)? {
        let level = value_u64(entry, "level")?;
        let root = value_string(entry, root_field_name)?;
        validate_hash_string(root, root_field_name)?;
        if roots.insert(level, root.to_string()).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} contains duplicate relinearization levels"),
            ));
        }
    }

    Ok(roots)
}

fn verify_relinearization_round_one_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
) -> CanonicalResult<(u64, u64, String, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE,
        "relinearization-key-share",
        RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        RELINEARIZATION_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_relinearization_round_one_record_field(record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "relinearization round-one record contains unexpected field {unexpected_field}"
            ),
        ));
    }
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    let round_one_share_root = value_string(record, "roundOneShareRoot")?;
    validate_hash_string(round_one_share_root, "roundOneShareRoot")?;
    let round_one_proof_root = value_string(record, "roundOneProofRoot")?;
    validate_hash_string(round_one_proof_root, "roundOneProofRoot")?;
    let supplied_root = value_string(record, "roundOneRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-one record object was checked")
        .remove("roundOneRecordRoot");
    let expected_root = derive_protocol_hash("RelinearizationRoundOneRecordRoot", &root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "roundOneRecordRoot does not match the canonical relinearization round-one record",
        ));
    }

    Ok((
        level,
        trustee_roster_position,
        supplied_root.to_string(),
        round_one_share_root.to_string(),
    ))
}

fn verify_relinearization_round_two_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    round_one_record_roots: &BTreeMap<(u64, u64), String>,
    round_one_share_roots: &BTreeMap<(u64, u64), String>,
    round_one_aggregate_roots: &BTreeMap<u64, String>,
) -> CanonicalResult<(u64, u64, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE,
        "relinearization-key-share",
        RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        RELINEARIZATION_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_relinearization_round_two_record_field(record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "relinearization round-two record contains unexpected field {unexpected_field}"
            ),
        ));
    }
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    for field_name in [
        "roundOneShareRoot",
        "roundOneRecordRoot",
        "roundOneAggregateRoot",
        "roundTwoShareRoot",
        "roundTwoProofRoot",
    ] {
        validate_hash_string(value_string(record, field_name)?, field_name)?;
    }
    let key = (level, trustee_roster_position);
    if round_one_record_roots.get(&key).map(String::as_str)
        != Some(value_string(record, "roundOneRecordRoot")?)
        || round_one_share_roots.get(&key).map(String::as_str)
            != Some(value_string(record, "roundOneShareRoot")?)
        || round_one_aggregate_roots.get(&level).map(String::as_str)
            != Some(value_string(record, "roundOneAggregateRoot")?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization round-two record must bind the accepted round-one record, share, and aggregate roots",
        ));
    }
    let supplied_root = value_string(record, "roundTwoRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-two record object was checked")
        .remove("roundTwoRecordRoot");
    let expected_root = derive_protocol_hash("RelinearizationRoundTwoRecordRoot", &root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "roundTwoRecordRoot does not match the canonical relinearization round-two record",
        ));
    }

    Ok((level, trustee_roster_position, supplied_root.to_string()))
}

fn verify_galois_key_share_batch(
    batch: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    expected_schedule: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    verify_evaluation_key_record_object(
        batch,
        GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE,
        "galois-key-share",
        GALOIS_PROOF_VERIFICATION_STATUS,
        GALOIS_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_galois_key_share_batch_field(batch) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("Galois key share batch contains unexpected field {unexpected_field}"),
        ));
    }
    let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share batches must not repeat a trustee roster position",
        ));
    }
    verify_evaluation_key_record_common_bindings(
        batch,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "galoisKeyCrpRoot",
        binding.galois_key_crp_root.as_str(),
    )?;
    if batch.get("requiredGaloisSetHash").and_then(Value::as_str)
        != Some(binding.required_galois_set_hash.as_str())
        || batch.get("requiredGaloisKeySchedule") != Some(expected_schedule)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key share batch must bind the exact frozen RequiredGaloisSetHash and schedule",
        ));
    }
    let key_roots = array_value(batch, "galoisKeyShareRoots")?;
    let expected_entries = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected Galois key schedule must be an array",
        )
    })?;
    if key_roots.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one share root per required schedule entry",
        ));
    }
    for (root_entry, expected_entry) in key_roots.iter().zip(expected_entries) {
        if root_entry.get("rotation") != expected_entry.get("rotation")
            || root_entry.get("level") != expected_entry.get("level")
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "Galois key share roots must follow the frozen Galois key schedule order",
            ));
        }
        validate_hash_string(
            value_string(root_entry, "galoisKeyShareRoot")?,
            "galoisKeyShareRoot",
        )?;
    }
    validate_hash_string(
        value_string(batch, "galoisKeyBatchProofRoot")?,
        "galoisKeyBatchProofRoot",
    )?;
    let supplied_root = value_string(batch, "galoisKeyShareBatchRoot")?;
    let mut root_input = batch.clone();
    root_input
        .as_object_mut()
        .expect("Galois key share batch object was checked")
        .remove("galoisKeyShareBatchRoot");
    let expected_root = derive_protocol_hash("GaloisKeyShareBatchRoot", &root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyShareBatchRoot does not match the canonical Galois key share batch",
        ));
    }

    Ok(())
}

fn verify_evaluation_key_record_object(
    record: &Value,
    expected_object_type: &str,
    expected_proof_family: &str,
    expected_proof_verification_status: &str,
    expected_proof_model_status: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key proof record must be an object",
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(expected_object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("evaluation-key proof objectType must be {expected_object_type}"),
        ));
    }
    if record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key proof objectVersion must be 1",
        ));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", expected_proof_family),
        (
            "proofVerificationStatus",
            expected_proof_verification_status,
        ),
        ("proofModelStatus", expected_proof_model_status),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("evaluation-key proof {field_name} must be {expected_value}"),
            ));
        }
    }

    Ok(())
}

fn verify_evaluation_key_record_common_bindings(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    trustee_roster_position: u64,
    crp_root_field_name: &str,
    expected_crp_root: &str,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretConsistencyRoot",
            binding.same_secret_consistency_root.as_str(),
        ),
        (
            "sameSecretProofSetRoot",
            binding.same_secret_proof_set_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareLnpProofSetRoot",
            binding.public_key_share_lnp_proof_set_root.as_str(),
        ),
        (crp_root_field_name, expected_crp_root),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("evaluation-key proof {field_name} must match the accepted setup binding"),
            ));
        }
    }
    let Some(same_secret_binding) = same_secret_proof_bindings.get(&trustee_roster_position) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof trusteeRosterPosition must reference an accepted same-secret proof",
        ));
    };
    for (field_name, expected_value) in [
        (
            "trusteeIdentity",
            same_secret_binding.trustee_identity.as_str(),
        ),
        (
            "trusteeSecretCommitmentRoot",
            same_secret_binding.trustee_secret_commitment_root.as_str(),
        ),
        (
            "sameSecretStatementRoot",
            same_secret_binding.same_secret_statement_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            same_secret_binding
                .same_secret_proof_family_binding_root
                .as_str(),
        ),
        (
            "sameSecretProofRoot",
            same_secret_binding.same_secret_proof_root.as_str(),
        ),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "evaluation-key proof {field_name} must match the accepted trustee secret binding"
                ),
            ));
        }
    }

    Ok(())
}

fn unexpected_relinearization_key_share_rounds_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareLnpProofSetRoot",
            "relinearizationCrpRoot",
            "relinearizationLevelSchedule",
            "roundOneAggregateRoots",
            "roundOneRecords",
            "roundTwoAggregateRoots",
            "roundTwoRecords",
            "relinearizationKeyShareRoundsRoot",
        ],
    )
}

fn unexpected_relinearization_round_one_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "level",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "relinearizationCrpRoot",
            "roundOneShareRoot",
            "roundOneProofRoot",
            "roundOneRecordRoot",
        ],
    )
}

fn unexpected_relinearization_round_two_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "level",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "relinearizationCrpRoot",
            "roundOneShareRoot",
            "roundOneRecordRoot",
            "roundOneAggregateRoot",
            "roundTwoShareRoot",
            "roundTwoProofRoot",
            "roundTwoRecordRoot",
        ],
    )
}

fn unexpected_galois_key_share_batch_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "galoisKeyCrpRoot",
            "requiredGaloisSetHash",
            "requiredGaloisKeySchedule",
            "galoisKeyShareRoots",
            "galoisKeyBatchProofRoot",
            "galoisKeyShareBatchRoot",
        ],
    )
}

fn evaluation_key_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("relinearizationRoundOne"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn unexpected_public_key_share_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofBindingStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "publicKeyShareRoots",
            "shareRecords",
            "publicKeyShareSetRoot",
        ],
    )
}

fn unexpected_public_key_share_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "shareComponent",
            "rnsLimbCount",
            "shareCoefficientVectorHash512ByLimb",
            "proofBindingStatus",
            "publicKeyShareRoot",
        ],
    )
}

fn unexpected_public_key_share_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofRoots",
            "proofRecords",
            "publicKeyShareProofSetRoot",
        ],
    )
}

fn unexpected_public_key_share_proof_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "rnsLimbCount",
            "noWrapRelation",
            "errorSupport",
            "carryWitnessStatus",
            "proofBytesStatus",
            "publicKeyShareProofRoot",
        ],
    )
}

fn unexpected_public_key_share_material_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofModelStatus",
            "materialEncoding",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareMaterialRoots",
            "shareMaterialRecords",
            "publicKeyShareMaterialSetRoot",
        ],
    )
}

fn unexpected_public_key_share_material_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofModelStatus",
            "materialEncoding",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareRoot",
            "shareCoefficientVectorsByLimb",
            "publicKeyShareMaterialRoot",
        ],
    )
}

fn unexpected_public_key_share_lnp_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "setupProofBinding",
            "publicKeyShareTboxParameterProfileHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofSetRoot",
            "publicKeyShareMaterialSetRoot",
            "publicKeyShareLnpProofRoots",
            "proofRecords",
            "publicKeyShareLnpProofSetRoot",
        ],
    )
}

fn unexpected_public_key_share_lnp_proof_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "setupProofBinding",
            "publicKeyShareTboxParameterProfileHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "publicKeyShareRoot",
            "publicKeyShareProofRoot",
            "publicKeyShareMaterialRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "sameSecretProofRoot",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "proofBytesHex",
            "publicKeyShareLnpProofRoot",
        ],
    )
}

fn unexpected_collective_public_key_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "aggregationStatus",
            "materialEncoding",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofSetRoot",
            "publicKeyShareMaterialSetRoot",
            "publicKeyShareLnpProofSetRoot",
            "sourceShareMaterialRoots",
            "aggregateCoefficientVectorsByLimb",
            "collectivePublicKeyRoot",
        ],
    )
}

fn public_key_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn public_key_share_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn public_key_share_lnp_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn value_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

fn validate_lowercase_hex(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be lowercase canonical hex"),
    ))
}

fn validate_lowercase_hex_length(
    value: &str,
    expected_byte_length: usize,
    field_name: &str,
) -> CanonicalResult<()> {
    validate_lowercase_hex(value, field_name)?;
    if value.len() == expected_byte_length * 2 {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be {expected_byte_length} bytes"),
    ))
}

fn vss_share_acceptance_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_generic_key_switch_policy(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let evaluator_key_schedule = setup_package
        .get("evaluatorKeySchedule")
        .and_then(Value::as_object);
    let generic_key_switch_policy = evaluator_key_schedule
        .and_then(|schedule| schedule.get("genericKeySwitchPolicy"))
        .and_then(Value::as_str)
        .unwrap_or("refused-unless-explicitly-required");
    if setup_package.get("genericKeySwitchKeys").is_some()
        && generic_key_switch_policy != "explicitly-required-by-frozen-schedule"
    {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupPackageVerification"),
            Vec::new(),
            vec![Refusal::new(
                "genericKeySwitchOutsideProfile",
                "generic key-switch material is refused unless the frozen evaluator schedule explicitly requires it",
                "setupPackage.genericKeySwitchKeys".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if generic_key_switch_policy == "explicitly-required-by-frozen-schedule"
        && setup_package.get("genericKeySwitchProofs").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["genericKeySwitchProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn verify_commitment_security_certificate(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(commitment_certificate) = setup_package.get("setupCommitmentSecurityCertificate")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupCommitmentSecurityCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_certificate.is_object() {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificateNotObject",
            "setupCommitmentSecurityCertificate must be a root-bound object",
            "setupPackage.setupCommitmentSecurityCertificate",
        )?));
    }

    let certificate_hash = commitment_certificate
        .get("setupCommitmentSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
    )?;

    let mut certificate_body = commitment_certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("commitment certificate object was checked")
        .remove("setupCommitmentSecurityCertificateHash");
    let expected_body = setup_commitment_security_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificatePayloadMismatch",
            "setupCommitmentSecurityCertificate does not match the accepted commitment profile certificate",
            "setupPackage.setupCommitmentSecurityCertificate",
        )?));
    }

    let expected_certificate_hash = setup_commitment_security_certificate_hash()?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityCertificateHashMismatch",
            "setupCommitmentSecurityCertificateHash does not match the canonical commitment security certificate",
            "setupPackage.setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("setupCommitmentSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupCommitmentSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupCommitmentSecurityCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_commitment_certificate_refusal(
            "commitmentSecurityPackageCertificateHashMismatch",
            "setupPackage.setupCommitmentSecurityCertificateHash must match setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash",
            "setupPackage.setupCommitmentSecurityCertificateHash",
        )?));
    }

    Ok(None)
}

fn setup_commitment_security_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupCommitmentSecurityCertificateHash",
        &setup_commitment_security_certificate_value()?,
    )
}

fn setup_commitment_security_certificate_value() -> CanonicalResult<Value> {
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted Q_share prime list must not be empty",
        )
    })?;
    let recipient_scalar_sum = scalar_power_sum(
        FIRST_PROFILE_DECRYPTION_THRESHOLD,
        FIRST_PROFILE_PARTICIPANT_COUNT,
    )?;
    let threshold_scalar_sum = recipient_scalar_sum
        .checked_mul(u128::from(FIRST_PROFILE_PARTICIPANT_COUNT))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate threshold scalar sum overflow",
            )
        })?;
    let recipient_scalar_sum_u64 = u64::try_from(recipient_scalar_sum).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment certificate recipient scalar sum does not fit u64",
        )
    })?;
    let threshold_scalar_sum_u64 = u64::try_from(threshold_scalar_sum).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment certificate threshold scalar sum does not fit u64",
        )
    })?;
    let max_recipient_lifted_coefficient = u128::from(max_source_message_modulus - 1)
        .checked_mul(recipient_scalar_sum)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate recipient lifted coefficient bound overflow",
            )
        })?;
    let max_threshold_lifted_coefficient = u128::from(max_source_message_modulus - 1)
        .checked_mul(threshold_scalar_sum)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate threshold lifted coefficient bound overflow",
            )
        })?;
    let commitment_modulus_product = setup_commitment_modulus_product();
    if max_threshold_lifted_coefficient >= commitment_modulus_product {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "commitment modulus product does not cover threshold-share aggregate no-wrap bound",
        ));
    }
    let commitment_modulus_product_bits = ceil_log2_u128(commitment_modulus_product);

    Ok(json!({
        "objectType": SETUP_COMMITMENT_SECURITY_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "qShareHash": q_share_hash()?,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash()?,
        "certificateScope": "first-profile-BDLOP-LNP-commitment-parameters-and-opening-bounds",
        "acceptedUse": [
            "VSS coefficient commitment records",
            "recipient-local aggregate VSS opening checks",
            "verifier-derived threshold-share commitment roots",
            "same-secret trustee commitment roots",
        ],
        "nonClosure": [
            "same-secret proof still requires external AB-DLOP/LNP review and full tbox closure",
            "public-key share proof bytes still require no-wrap LNP verification",
            "relinearization and Galois proof bytes still require linked LNP verification",
            "setup-proof Fiat-Shamir/QROM composition certificate remains separate",
        ],
        "ringAndMatrixParameters": {
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "ringDegree": POLYNOMIAL_DEGREE,
            "sourceRnsLimbCount": DATA_PRIMES.len(),
            "sourceRnsPrimes": DATA_PRIMES,
            "commitmentModulusLimbs": setup_commitment_modulus_limb_values(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "publicMatrixSource": "full-roster-common-randomness-XOF-unbiased-residue-stream",
            "matrixHashBound": true,
        },
        "freshOpeningDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "rawOpeningExported": false,
            "perCoefficientOpeningExported": false,
        },
        "fullWidthMessageBound": {
            "messageSource": "per-RNS-prime-Shamir-coefficient-ring-element",
            "maxSourceMessageModulus": max_source_message_modulus,
            "maxFreshMessageCoefficientDecimal": (max_source_message_modulus - 1).to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "freshMessageNoWrap": u128::from(max_source_message_modulus - 1)
                < commitment_modulus_product,
            "status": "review-gated-full-width-per-rns-message-bound-recorded",
        },
        "aggregateOpeningBounds": {
            "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
            "maximumTrusteePoint": FIRST_PROFILE_PARTICIPANT_COUNT,
            "recipientScalarPowerSumDecimal": recipient_scalar_sum.to_string(),
            "recipientAggregateOpeningInfinityBound": recipient_scalar_sum_u64,
            "maxRecipientLiftedCoefficientDecimal": max_recipient_lifted_coefficient.to_string(),
            "dealerCountForThresholdAggregation": FIRST_PROFILE_PARTICIPANT_COUNT,
            "thresholdScalarPowerSumDecimal": threshold_scalar_sum.to_string(),
            "thresholdShareOpeningInfinityBound": threshold_scalar_sum_u64,
            "maxThresholdLiftedCoefficientDecimal": max_threshold_lifted_coefficient.to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "recipientAndThresholdNoWrap": true,
            "boundStatus": "review-gated-first-profile-homomorphic-opening-bounds-recorded",
        },
        "multiOpeningLeakage": {
            "recipientAggregateOpeningsArePublic": false,
            "recipientAggregateOpeningsAreMailboxPlaintext": false,
            "maxCorruptRecipientsBeforeThreshold": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "shamirPolynomialDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "rawCoefficientOpeningsExported": false,
            "perCoefficientRandomnessExported": false,
            "thresholdBoundary": "recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses",
            "status": "review-gated-active-static-threshold-leakage-bound-recorded",
        },
        "bindingAssumption": {
            "assumption": "Module-SIS",
            "boundTarget": "two-valid-openings-to-one-commitment-yield-short-module-SIS-solution",
            "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "commitmentModulusProductCeilBits": commitment_modulus_product_bits,
            "extractedOpeningInfinityBound": threshold_scalar_sum_u64,
            "referenceRows": [
                {
                    "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                    "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                    "sections": [
                        "Commitment schemes",
                        "Module-SIS and Module-LWE problems",
                        "ABDLOP commitment scheme and proofs of linear relations"
                    ]
                },
                {
                    "document": "FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting",
                    "localReferencePath": "reference-documents/FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting.txt",
                    "sections": [
                        "BDLOP commitment background",
                        "Module-LWE and Module-SIS definitions"
                    ]
                }
            ],
            "estimatorStatus": "review-gated-external-module-sis-parameter-certificate-required",
        },
        "hidingAssumption": {
            "assumption": "Module-LWE with recipient-hidden proof-witness opening leakage boundary",
            "openingDistribution": "coefficientwise-centered-ternary",
            "publicMatrixDistribution": "hash-derived-uniform-residue-stream",
            "lowEntropySecretHiding": true,
            "statisticalLeakageStatus": "review-gated-for-recipient-hidden-aggregate-opening-proof-witnesses",
            "estimatorStatus": "review-gated-external-module-lwe-parameter-certificate-required",
        },
        "estimatorRows": [
            {
                "rowId": "first-profile-module-sis-binding-row",
                "problem": "Module-SIS",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
                "modulusCeilBits": commitment_modulus_product_bits,
                "shortVectorInfinityBoundDecimal": threshold_scalar_sum.to_string(),
                "status": "review-gated"
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
                "status": "review-gated"
            }
        ],
        "certificateStatus": "review-gated-not-claim-bearing-until-external-parameter-certificate-and-setup-proof-verifiers",
    }))
}

fn scalar_power_sum(coefficient_count: u64, trustee_point: u64) -> CanonicalResult<u128> {
    let mut scalar_sum = 0_u128;
    let mut trustee_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        scalar_sum = scalar_sum.checked_add(trustee_power).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment certificate scalar sum overflow",
            )
        })?;
        if coefficient_index + 1 < coefficient_count {
            trustee_power = trustee_power
                .checked_mul(trustee_point_wide)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "commitment certificate trustee power overflow",
                    )
                })?;
        }
    }

    Ok(scalar_sum)
}

fn ceil_log2_u128(value: u128) -> u32 {
    if value <= 1 {
        0
    } else {
        u128::BITS - (value - 1).leading_zeros()
    }
}

fn setup_commitment_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_he_security_certificate(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("heSecurityCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["heSecurityCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateNotObject",
            "heSecurityCertificate must be a root-bound object",
            "setupPackage.heSecurityCertificate",
        )?));
    }
    let certificate_hash = certificate
        .get("heSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "heSecurityCertificate.heSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "heSecurityCertificate.heSecurityCertificateHash",
    )?;
    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("HE security certificate object was checked")
        .remove("heSecurityCertificateHash");
    let expected_body = accepted_he_security_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateMismatch",
            "heSecurityCertificate does not match the accepted direct evaluator replay security certificate",
            "setupPackage.heSecurityCertificate",
        )?));
    }
    let expected_hash = accepted_he_security_certificate_hash()?;
    if certificate_hash != expected_hash {
        return Ok(Some(he_security_certificate_refusal(
            "heSecurityCertificateHashMismatch",
            "heSecurityCertificateHash does not match the canonical HE security certificate",
            "setupPackage.heSecurityCertificate.heSecurityCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("heSecurityCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.heSecurityCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.heSecurityCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(he_security_certificate_refusal(
            "packageHeSecurityCertificateHashMismatch",
            "setupPackage.heSecurityCertificateHash must match heSecurityCertificate.heSecurityCertificateHash",
            "setupPackage.heSecurityCertificateHash",
        )?));
    }

    Ok(None)
}

pub(super) fn accepted_he_security_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BGVHeSecurityCertificateHash",
        &accepted_he_security_certificate_value()?,
    )
}

pub(super) fn accepted_he_security_certificate_value() -> CanonicalResult<Value> {
    let largest_exposed_modulus_bits = data_basis_modulus_bits();
    let extended_basis_bits = extended_basis_modulus_bits();
    let post_quantum_max_logq = 827_usize;
    let classical_max_logq = 881_usize;
    let post_quantum_accepted = largest_exposed_modulus_bits <= post_quantum_max_logq;
    let classical_accepted = largest_exposed_modulus_bits <= classical_max_logq;
    let required_galois_key_count = expected_required_galois_key_schedule()?
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let scheduled_relinearization_level_count = expected_relinearization_level_schedule()
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    Ok(json!({
        "objectType": HE_SECURITY_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "qShareHash": q_share_hash()?,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash()?,
        "certificateScope": "first-profile-accepted-setup-direct-evaluator-replay-Q-data-boundary",
        "reference": {
            "document": "ACC18 Homomorphic Encryption Standard",
            "localReferencePath": "reference-documents/ACC18_Homomorphic Encryption Standard.txt",
            "sections": [
                "Section 2.1.3 secret key distribution",
                "Table 1 BKZ.sieve ternary n=32768 row",
                "Table 2 BKZ.qsieve ternary n=32768 row"
            ],
            "tableScope": "power-of-two cyclotomic RLWE parameter table"
        },
        "assessedRing": {
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataBasisId": BgvBasisKind::Data.basis_id(),
            "dataPrimeCount": DATA_PRIMES.len(),
            "dataPrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "dataPrimeCeilLog2Product": largest_exposed_modulus_bits,
            "qSharePrimeCount": DATA_PRIMES.len(),
            "qSharePrimeProductDecimal": modulus_product_decimal(DATA_PRIMES.iter().copied()),
            "qShareCeilLog2Product": largest_exposed_modulus_bits,
            "specialPrime": SPECIAL_PRIME,
            "extendedUtilityCeilLog2Product": extended_basis_bits,
            "extendedUtilityExposureStatus": "not-exposed-by-current-accepted-direct-evaluator-replay-material",
            "largestExposedBasisClass": "Q_data",
            "largestExposedModulusBits": largest_exposed_modulus_bits
        },
        "secretDistribution": {
            "distributionKind": "standard-ternary-collective-secret",
            "support": [-1, 0, 1],
            "isPlainDenseTernary": true,
            "estimatorModel": "HE-standard-ternary",
            "source": "recipient-verified-VSS same-secret commitments"
        },
        "errorDistribution": {
            "distributionKind": "centered-binomial-eta2",
            "support": [-2, -1, 0, 1, 2],
            "keySwitchNoiseDistribution": "centered-binomial-eta2",
            "certificateStatus": "accepted-support-recorded-proof-family-checks-still-required"
        },
        "publicSampleAccounting": {
            "publicKeyCrpPolynomials": 1,
            "publicKeyShareCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedRelinearizationKeyPolynomials": 0,
            "acceptedGaloisKeyPolynomials": 0,
            "scheduledRelinearizationLevelCount": scheduled_relinearization_level_count,
            "scheduledGaloisKeyCount": required_galois_key_count,
            "evaluationKeyExposureStatus": "not-exposed-until-relinearization-and-galois-proof-verifiers-pass",
            "commitmentAndSetupProofPublicMatrices": "covered-by-setup-commitment-and-setup-proof profiles, not counted as HE RLWE public-key samples"
        },
        "standardRows": {
            "postQuantumTernary128": {
                "status": if post_quantum_accepted {
                    "accepted"
                } else {
                    "rejected-largest-exposed-modulus-exceeds-row"
                },
                "costModel": "BKZ.qsieve",
                "secretDistribution": "ternary",
                "polynomialDegree": 32768,
                "securityLevelBits": 128,
                "maximumLogQ": post_quantum_max_logq,
                "largestExposedModulusBits": largest_exposed_modulus_bits,
                "marginBits": post_quantum_max_logq.saturating_sub(largest_exposed_modulus_bits),
                "uSVPBits": "128.1",
                "decodingBits": "128.7",
                "dualBits": "128.4"
            },
            "classicalTernary128": {
                "status": if classical_accepted {
                    "accepted"
                } else {
                    "rejected-largest-exposed-modulus-exceeds-row"
                },
                "costModel": "BKZ.sieve",
                "secretDistribution": "ternary",
                "polynomialDegree": 32768,
                "securityLevelBits": 128,
                "maximumLogQ": classical_max_logq,
                "largestExposedModulusBits": largest_exposed_modulus_bits,
                "marginBits": classical_max_logq.saturating_sub(largest_exposed_modulus_bits),
                "uSVPBits": "128.5",
                "decodingBits": "129.1",
                "dualBits": "128.5"
            }
        },
        "estimatorBinding": {
            "status": if post_quantum_accepted && classical_accepted {
                "accepted-by-local-HE-standard-table-row"
            } else {
                "rejected-by-local-HE-standard-table-row"
            },
            "tool": "HE-standard published parameter table",
            "toolVersion": "ACC18 local text reference",
            "securityEstimatorInputHash": security_estimator_input_hash()?,
            "secretModel": "standard-ternary",
            "errorModel": "centered-binomial-eta2",
            "largestExposedModulusBits": largest_exposed_modulus_bits,
            "publicSamplesBound": true
        },
        "targetDecryptionStatus": {
            "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
            "qTargetKnown": false,
            "qTargetCoveredByCertificate": false,
            "targetC1ThroughC4Covered": false,
            "targetDecryptionReadiness": "refused-until-q-target-certificate-closes"
        },
        "acceptedForDirectEvaluatorReplay": post_quantum_accepted && classical_accepted,
        "acceptedForTargetDecryption": false,
        "statusLabels": if post_quantum_accepted && classical_accepted {
            vec![
                "HEStandardPostQuantum128Accepted",
                "HEStandardClassical128Accepted",
                "DataBasisLargestExposedModulusAccepted",
                "SpecialPrimeNotPubliclyExposedOnAcceptedPath",
                "TargetDecryptionReadinessRefusedUntilQTargetCertificate",
            ]
        } else {
            vec![
                "HEStandardSecurityRejected",
                "DataBasisLargestExposedModulusRejected",
            ]
        },
    }))
}

fn modulus_product_decimal(moduli: impl IntoIterator<Item = u64>) -> String {
    let mut product = BigUint::from(1_u8);
    for modulus in moduli {
        product *= BigUint::from(modulus);
    }

    product.to_str_radix(10)
}

fn he_security_certificate_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_transport_certificate(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(transport_certificate) = setup_package.get("setupTransportCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupTransportCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    match verify_transport_certificate_body(setup_package, transport_certificate)? {
        Ok(()) => {}
        Err(refusal) => {
            return Ok(Some(setup_transport_refusal(
                refusal.reason_code,
                refusal.message,
                refusal
                    .object_path
                    .unwrap_or_else(|| "setupPackage.setupTransportCertificate".to_string()),
            )?));
        }
    }

    Ok(None)
}

fn verify_transport_certificate_body(
    setup_package: &Value,
    transport_certificate: &Value,
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    if !transport_certificate.is_object() {
        return Ok(Err(Refusal::new(
            "transportCertificateNotObject",
            "setupTransportCertificate must be a root-bound object",
            "setupPackage.setupTransportCertificate",
        )));
    }
    if let Some(unexpected_field) =
        unexpected_setup_transport_certificate_field(transport_certificate)
    {
        return Ok(Err(Refusal::new(
            "transportCertificateUnexpectedField",
            format!("setupTransportCertificate contains unexpected field {unexpected_field}"),
            format!("setupPackage.setupTransportCertificate.{unexpected_field}"),
        )));
    }
    for (field_name, expected_value, reason_code, message) in [
        (
            "objectType",
            SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE,
            "transportCertificateTypeMismatch",
            "setupTransportCertificate.objectType must be SetupTransportCertificate",
        ),
        (
            "setupProfileId",
            COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportSetupProfileMismatch",
            "setupTransportCertificate.setupProfileId must match CollectiveBgvSetup-v1",
        ),
        (
            "transportProfileId",
            SETUP_TRANSPORT_PROFILE_ID,
            "transportProfileMismatch",
            "setupTransportCertificate must use verifier-enforced binary/chunked transport",
        ),
        (
            "largeObjectEncoding",
            "binary",
            "transportEncodingMismatch",
            "setupTransportCertificate.largeObjectEncoding must be binary",
        ),
        (
            "chunking",
            "required",
            "transportChunkingMissing",
            "setupTransportCertificate.chunking must be required",
        ),
        (
            "streamVerificationOrder",
            SETUP_TRANSPORT_STREAM_ORDER,
            "transportStreamOrderMismatch",
            "setupTransportCertificate.streamVerificationOrder must match the setup transport profile",
        ),
        (
            "resumePolicy",
            SETUP_TRANSPORT_RESUME_POLICY,
            "transportResumePolicyMismatch",
            "setupTransportCertificate.resumePolicy must match the setup transport profile",
        ),
        (
            "lazyLoadingPolicy",
            SETUP_TRANSPORT_LAZY_LOADING_POLICY,
            "transportLazyLoadingPolicyMismatch",
            "setupTransportCertificate.lazyLoadingPolicy must match the setup transport profile",
        ),
    ] {
        transport_try!(expect_transport_string(
            transport_certificate,
            field_name,
            expected_value,
            reason_code,
            message,
        ));
    }
    transport_try!(expect_transport_u64(
        transport_certificate,
        "objectVersion",
        1,
        "transportCertificateVersionMismatch",
        "setupTransportCertificate.objectVersion must be 1",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkSizeBytes",
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        "transportChunkSizeMismatch",
        "setupTransportCertificate.chunkSizeBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "storageQuotaBytes",
        SETUP_TRANSPORT_STORAGE_QUOTA_BYTES,
        "transportStorageQuotaMismatch",
        "setupTransportCertificate.storageQuotaBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "largestSingleBufferBytes",
        SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        "transportLargestBufferMismatch",
        "setupTransportCertificate.largestSingleBufferBytes must match the setup transport profile",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "copyCountLimit",
        SETUP_TRANSPORT_COPY_COUNT_LIMIT,
        "transportCopyCountMismatch",
        "setupTransportCertificate.copyCountLimit must match the setup transport profile",
    ));

    let expected_vss_material_byte_length = setup_transport_vss_material_byte_length()?;
    let expected_chunk_count = setup_transport_chunk_count(expected_vss_material_byte_length)?;
    transport_try!(expect_transport_u64(
        transport_certificate,
        "totalByteLength",
        expected_vss_material_byte_length,
        "transportTotalByteLengthMismatch",
        "setupTransportCertificate.totalByteLength must match the full-profile public VSS material byte count",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkCount",
        expected_chunk_count,
        "transportChunkCountMismatch",
        "setupTransportCertificate.chunkCount must match totalByteLength and chunkSizeBytes",
    ));

    let setup_transport_profile_hash_value = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupTransportProfileHash",
        "transportProfileHashMissing",
        "setupTransportCertificate.setupTransportProfileHash is required",
    ));
    if setup_transport_profile_hash_value != setup_transport_profile_hash()?.as_str() {
        return Ok(Err(Refusal::new(
            "transportProfileHashMismatch",
            "setupTransportCertificate.setupTransportProfileHash must match the accepted setup transport profile",
            "setupPackage.setupTransportCertificate.setupTransportProfileHash",
        )));
    }
    let full_object_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "fullObjectHash",
        "transportFullObjectHashMissing",
        "setupTransportCertificate.fullObjectHash is required",
    ))
    .to_string();
    let chunk_hashes = transport_canonical_try!(transport_chunk_hashes(
        transport_certificate,
        expected_chunk_count as usize
    ));
    let expected_chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        expected_chunk_count,
        expected_vss_material_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;
    let chunk_root = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "chunkRoot",
        "transportChunkRootMissing",
        "setupTransportCertificate.chunkRoot is required",
    ));
    if chunk_root != expected_chunk_root {
        return Ok(Err(Refusal::new(
            "transportChunkRootMismatch",
            "setupTransportCertificate.chunkRoot must match the canonical chunk manifest",
            "setupPackage.setupTransportCertificate.chunkRoot",
        )));
    }
    transport_canonical_try!(verify_setup_transported_objects(
        setup_package,
        transport_certificate,
        expected_vss_material_byte_length,
        expected_chunk_count,
        &expected_chunk_root,
        &full_object_hash,
    ));

    let certificate_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupTransportCertificateHash",
        "transportCertificateHashMissing",
        "setupTransportCertificate.setupTransportCertificateHash is required",
    ));
    let mut certificate_hash_input = transport_certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("transport certificate object was checked")
        .remove("setupTransportCertificateHash");
    let expected_certificate_hash =
        derive_protocol_hash("SetupTransportCertificateHash", &certificate_hash_input)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Err(Refusal::new(
            "transportCertificateHashMismatch",
            "setupTransportCertificateHash does not match the canonical setup transport certificate",
            "setupPackage.setupTransportCertificate.setupTransportCertificateHash",
        )));
    }
    let package_certificate_hash = transport_canonical_try!(require_transport_hash(
        setup_package,
        "setupTransportCertificateHash",
        "transportPackageCertificateHashMissing",
        "setupPackage.setupTransportCertificateHash is required",
    ));
    if package_certificate_hash != expected_certificate_hash {
        return Ok(Err(Refusal::new(
            "transportPackageCertificateHashMismatch",
            "setupPackage.setupTransportCertificateHash must match setupTransportCertificate.setupTransportCertificateHash",
            "setupPackage.setupTransportCertificateHash",
        )));
    }

    Ok(Ok(()))
}

fn unexpected_setup_transport_certificate_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "transportProfileId",
            "setupTransportProfileHash",
            "largeObjectEncoding",
            "chunking",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "storageQuotaBytes",
            "largestSingleBufferBytes",
            "copyCountLimit",
            "streamVerificationOrder",
            "resumePolicy",
            "lazyLoadingPolicy",
            "transportedObjects",
            "chunkHashes",
            "chunkRoot",
            "fullObjectHash",
            "setupTransportCertificateHash",
        ],
    )
}

fn unexpected_setup_transported_object_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "objectName",
            "objectRole",
            "objectRoot",
            "byteLength",
            "chunkStartIndex",
            "chunkCount",
            "chunkRoot",
            "fullObjectHash",
            "encoding",
            "loadingPolicy",
        ],
    )
}

fn verify_setup_transported_objects(
    setup_package: &Value,
    transport_certificate: &Value,
    expected_byte_length: u64,
    expected_chunk_count: u64,
    expected_chunk_root: &str,
    expected_full_object_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let transported_objects = match transport_certificate
        .get("transportedObjects")
        .and_then(Value::as_array)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "transportedObjectsMissing",
                "setupTransportCertificate.transportedObjects must list the transported setup objects",
                "setupPackage.setupTransportCertificate.transportedObjects",
            )));
        }
    };
    if transported_objects.len() != 1 {
        return Ok(Err(Refusal::new(
            "transportedObjectsCountMismatch",
            "setupTransportCertificate.transportedObjects must currently bind the full public VSS material object",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    let transported_object = &transported_objects[0];
    if !transported_object.is_object() {
        return Ok(Err(Refusal::new(
            "transportedObjectNotObject",
            "setupTransportCertificate.transportedObjects entries must be root-bound objects",
            "setupPackage.setupTransportCertificate.transportedObjects[0]",
        )));
    }
    if let Some(unexpected_field) = unexpected_setup_transported_object_field(transported_object) {
        return Ok(Err(Refusal::new(
            "transportedObjectUnexpectedField",
            format!("setup transported object contains unexpected field {unexpected_field}"),
            format!(
                "setupPackage.setupTransportCertificate.transportedObjects[0].{unexpected_field}"
            ),
        )));
    }
    for (field_name, expected_value, reason_code, message) in [
        (
            "objectType",
            SETUP_TRANSPORTED_OBJECT_TYPE,
            "transportedObjectTypeMismatch",
            "transported object objectType must be SetupTransportedObject",
        ),
        (
            "objectName",
            SETUP_TRANSPORTED_VSS_MATERIAL_NAME,
            "transportedObjectNameMismatch",
            "transported object must bind vssCoefficientCommitmentMaterial",
        ),
        (
            "objectRole",
            SETUP_TRANSPORTED_VSS_MATERIAL_ROLE,
            "transportedObjectRoleMismatch",
            "transported object role must be public VSS coefficient commitment material",
        ),
        (
            "encoding",
            "binary",
            "transportedObjectEncodingMismatch",
            "transported object encoding must be binary",
        ),
        (
            "loadingPolicy",
            SETUP_TRANSPORTED_OBJECT_LOADING_POLICY,
            "transportedObjectLoadingPolicyMismatch",
            "transported object loading policy must match the setup transport profile",
        ),
    ] {
        transport_try!(expect_transport_string(
            transported_object,
            field_name,
            expected_value,
            reason_code,
            message,
        ));
    }
    transport_try!(expect_transport_u64(
        transported_object,
        "objectVersion",
        1,
        "transportedObjectVersionMismatch",
        "transported object objectVersion must be 1",
    ));
    transport_try!(expect_transport_u64(
        transported_object,
        "byteLength",
        expected_byte_length,
        "transportedObjectByteLengthMismatch",
        "transported object byteLength must match the full-profile public VSS material byte count",
    ));
    transport_try!(expect_transport_u64(
        transported_object,
        "chunkStartIndex",
        0,
        "transportedObjectStartIndexMismatch",
        "transported object chunkStartIndex must be zero for the first setup transport object",
    ));
    transport_try!(expect_transport_u64(
        transported_object,
        "chunkCount",
        expected_chunk_count,
        "transportedObjectChunkCountMismatch",
        "transported object chunkCount must match the setup transport manifest",
    ));
    let object_root = transport_canonical_try!(require_transport_hash(
        transported_object,
        "objectRoot",
        "transportedObjectRootMissing",
        "transported object objectRoot is required",
    ));
    let expected_vss_material_root = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material_set| material_set.get("vssCoefficientCommitmentMaterialRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterialRoot was required before setup transport verification",
            )
        })?;
    if object_root != expected_vss_material_root {
        return Ok(Err(Refusal::new(
            "transportedObjectRootMismatch",
            "transported object objectRoot must match vssCoefficientCommitmentMaterialRoot",
            "setupPackage.setupTransportCertificate.transportedObjects[0].objectRoot",
        )));
    }
    for (field_name, expected_value, reason_code, message) in [
        (
            "chunkRoot",
            expected_chunk_root,
            "transportedObjectChunkRootMismatch",
            "transported object chunkRoot must match setupTransportCertificate.chunkRoot",
        ),
        (
            "fullObjectHash",
            expected_full_object_hash,
            "transportedObjectFullHashMismatch",
            "transported object fullObjectHash must match setupTransportCertificate.fullObjectHash",
        ),
    ] {
        let observed_value = transport_canonical_try!(require_transport_hash(
            transported_object,
            field_name,
            reason_code,
            message,
        ));
        if observed_value != expected_value {
            return Ok(Err(Refusal::new(
                reason_code,
                message,
                format!(
                    "setupPackage.setupTransportCertificate.transportedObjects[0].{field_name}"
                ),
            )));
        }
    }

    Ok(Ok(()))
}

fn transport_chunk_hashes(
    transport_certificate: &Value,
    expected_chunk_count: usize,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    let chunk_hash_values = match transport_certificate
        .get("chunkHashes")
        .and_then(Value::as_array)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "transportChunkHashesMissing",
                "setupTransportCertificate.chunkHashes must list every setup transport chunk hash",
                "setupPackage.setupTransportCertificate.chunkHashes",
            )));
        }
    };
    if chunk_hash_values.len() != expected_chunk_count {
        return Ok(Err(Refusal::new(
            "transportChunkHashCountMismatch",
            "setupTransportCertificate.chunkHashes length must match chunkCount",
            "setupPackage.setupTransportCertificate.chunkHashes",
        )));
    }
    let mut chunk_hashes = Vec::with_capacity(expected_chunk_count);
    let mut seen_chunk_hashes = BTreeSet::new();
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Ok(Err(Refusal::new(
                "transportChunkHashNotString",
                "setupTransportCertificate.chunkHashes entries must be protocol hashes",
                format!("setupPackage.setupTransportCertificate.chunkHashes[{chunk_index}]"),
            )));
        };
        validate_hash_string(
            chunk_hash,
            &format!("setupTransportCertificate.chunkHashes[{chunk_index}]"),
        )?;
        if !seen_chunk_hashes.insert(chunk_hash.to_string()) {
            return Ok(Err(Refusal::new(
                "transportChunkHashDuplicate",
                "setupTransportCertificate.chunkHashes must not contain duplicate chunk hashes",
                "setupPackage.setupTransportCertificate.chunkHashes",
            )));
        }
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(Ok(chunk_hashes))
}

fn setup_transport_chunk_manifest_root(
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &json!({
            "objectType": SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

fn setup_transport_vss_material_byte_length() -> CanonicalResult<u64> {
    let byte_length = public_vss_commitment_material_size_profile_value()?
        .get("fullMaterialCoefficientBytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public VSS material size profile did not expose fullMaterialCoefficientBytes",
            )
        })?;
    Ok(byte_length)
}

fn setup_transport_chunk_count(byte_length: u64) -> CanonicalResult<u64> {
    if SETUP_TRANSPORT_CHUNK_SIZE_BYTES == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size must be positive",
        ));
    }
    Ok(byte_length.div_ceil(SETUP_TRANSPORT_CHUNK_SIZE_BYTES))
}

fn expect_transport_string(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

fn expect_transport_u64(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

fn require_transport_hash<'a>(
    value: &'a Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
) -> CanonicalResult<Result<&'a str, Refusal>> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Ok(Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )));
    };
    validate_hash_string(hash, &format!("setupTransportCertificate.{field_name}"))?;

    Ok(Ok(hash))
}

fn setup_transport_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn compare_expected_hash(
    request: &Value,
    setup_context: &Value,
    expected_field_name: &str,
    context_field_name: &str,
) -> CanonicalResult<()> {
    let Some(expected_hash) = request.get(expected_field_name).and_then(Value::as_str) else {
        return Ok(());
    };
    validate_hash_string(expected_hash, expected_field_name)?;
    let actual_hash = setup_context
        .get(context_field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupContext.{context_field_name} must be a protocol hash"),
            )
        })?;
    if expected_hash != actual_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("setupContext.{context_field_name} does not match {expected_field_name}"),
        ));
    }

    Ok(())
}

pub(in crate::bgv::setup) fn accepted_hashes_from_package(setup_package: &Value) -> Vec<String> {
    let mut accepted_hashes = Vec::new();
    if let Some(setup_package_hash) = setup_package
        .get("setupPackageHash")
        .and_then(Value::as_str)
    {
        accepted_hashes.push(setup_package_hash.to_string());
    }
    for field_name in [
        "thresholdShareCommitmentRoot",
        "publicKeyShareSetRoot",
        "publicKeyShareProofSetRoot",
        "setupCommitmentSecurityCertificateHash",
        "setupTransportCertificateHash",
        "heSecurityCertificateHash",
    ] {
        if let Some(hash) = setup_package.get(field_name).and_then(Value::as_str) {
            accepted_hashes.push(hash.to_string());
        }
    }
    if let Some(hash) = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("thresholdShareCommitments")
        .and_then(|commitment_set| commitment_set.get("thresholdShareCommitmentRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("publicKeyShareProofs")
        .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("publicKeyShareMaterial")
        .and_then(|material_set| material_set.get("publicKeyShareMaterialSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("publicKeyShareLnpProofs")
        .and_then(|proof_set| proof_set.get("publicKeyShareLnpProofSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("collectivePublicKey")
        .and_then(|public_key| public_key.get("collectivePublicKeyRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("evaluatorKeySchedule")
        .and_then(|schedule| schedule.get("evaluatorKeyScheduleRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(|rounds| rounds.get("relinearizationKeyShareRoundsRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in batches {
            if let Some(hash) = batch.get("galoisKeyShareBatchRoot").and_then(Value::as_str) {
                accepted_hashes.push(hash.to_string());
            }
        }
    }

    accepted_hashes
}

fn outside_profile(
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<VerificationFlow> {
    Ok(VerificationFlow::Stop(verification_response(
        VerifierStatus::OutsideProfile,
        None,
        Vec::new(),
        vec![Refusal::new(
            "outsideCollectiveBgvSetupProfile",
            message,
            object_path.into(),
        )],
        Vec::new(),
    )?))
}

fn phase_refusal(
    phase_identifier: &str,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some(phase_identifier),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verification_response(
    verifier_status: VerifierStatus,
    current_phase: Option<&str>,
    missing_objects: Vec<String>,
    refused_objects: Vec<Refusal>,
    accepted_hashes: Vec<String>,
) -> CanonicalResult<Value> {
    Ok(json!({
        "ok": verifier_status == VerifierStatus::Accepted,
        "operation": "verifyCollectiveBgvSetupPackage",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "verifierStatus": verifier_status.as_str(),
        "currentPhase": current_phase,
        "phaseOrderHash": phase_order_hash()?,
        "acceptedHashes": accepted_hashes,
        "missingObjects": missing_objects,
        "refusedObjects": refused_objects
            .into_iter()
            .map(|refusal| refusal.to_value())
            .collect::<Vec<_>>(),
    }))
}

fn phase_order_hash() -> CanonicalResult<String> {
    derive_protocol_hash("CollectiveBgvSetupPhaseOrderHash", &phase_order_value())
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

fn reject_accepted_setup_forbidden_fields(value: &Value) -> CanonicalResult<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                reject_accepted_setup_forbidden_fields(item)?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str()) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "{field_name} cannot appear in accepted collective BGV setup material"
                        ),
                    ));
                }
                reject_accepted_setup_forbidden_fields(field_value)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn reject_accepted_setup_forbidden_request_fields(request: &Value) -> CanonicalResult<()> {
    let Some(request_object) = request.as_object() else {
        return Ok(());
    };
    for field_name in request_object.keys() {
        if field_name == "setupPackage" || field_name == "command" {
            continue;
        }
        if ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} cannot appear in accepted collective BGV setup requests"),
            ));
        }
    }

    Ok(())
}
