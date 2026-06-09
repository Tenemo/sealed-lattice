use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
        setup_commitment_modulus_product, setup_commitment_modulus_product_ceil_bits,
        setup_commitment_profile_hash, setup_commitment_profile_value, setup_commitment_root,
    },
    evaluation_key_share_proof::{
        EVALUATION_KEY_SHARE_CARRY_MASK_BITS, EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND, EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
        EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
        EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND,
        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS, EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND,
        EVALUATION_KEY_SHARE_SECRET_MASK_BITS, EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
        EvaluationKeyShareLnpProofVerificationInput, EvaluationKeyShareProofFamily,
        GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS, GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        GALOIS_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
        RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        RELINEARIZATION_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN, component_b_vectors_from_record,
        evaluation_key_share_lnp_relation_proof_bytes_hash,
        verify_evaluation_key_share_lnp_relation_proof,
    },
    private_vss_share_proof::{
        PRIVATE_VSS_SHARE_CARRY_MASK_BITS, PRIVATE_VSS_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
        PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS, PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS,
        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
    },
    public_key_share_proof::{
        PUBLIC_KEY_SHARE_CARRY_MASK_BITS, PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND,
        PUBLIC_KEY_SHARE_ERROR_MASK_BITS, PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
        PUBLIC_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS,
        PUBLIC_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN, PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND, PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS, PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND,
        PublicKeyShareLnpProofVerificationInput, public_key_share_coefficient_vector_hash,
        public_key_share_lnp_relation_proof_bytes_hash, verify_public_key_share_lnp_relation_proof,
    },
    same_secret_proof::{
        SAME_SECRET_LNP_PROOF_MODEL_STATUS, SAME_SECRET_LNP_PROOF_VERIFICATION_STATUS,
        SAME_SECRET_LNP_SCALAR_CHALLENGE_DOMAIN, SAME_SECRET_MESSAGE_MASK_BITS,
        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND, SAME_SECRET_RANDOMNESS_MASK_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS, SAME_SECRET_TERNARY_INFINITY_BOUND,
        same_secret_lnp_relation_proof_bytes_hash, verify_same_secret_lnp_relation_proof,
    },
    sampling::reduce_unbiased_u64,
    setup_proof::{
        SETUP_PROOF_BYTES_DOMAIN, SETUP_PROOF_CHALLENGE_BITS,
        SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND, SETUP_PROOF_CHALLENGE_COUNT,
        SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS, SETUP_PROOF_CHALLENGE_DOMAIN,
        SETUP_PROOF_CHALLENGE_SAMPLER, SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        SETUP_PROOF_CHALLENGE_SPACE, SETUP_PROOF_CHALLENGE_STREAM_DOMAIN, SETUP_PROOF_FAMILIES,
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
        with_verified_transported_vss_material,
    },
    vss::{
        carry_aware_vss_share_relation_profile_hash, carry_aware_vss_share_relation_profile_value,
    },
};
use crate::bgv::coefficient_codec::{coefficient_vector_from_le_hex, coefficient_vector_le_hex};
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
pub(super) const PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT: &str =
    "sealed-lattice-public-key-share-material-binary-v1";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC: &[u8; 8] = b"SLPKSMV1";
const PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION: u64 = 1;
const PUBLIC_KEY_SHARE_LNP_PROOF_SET_OBJECT_TYPE: &str = "PublicKeyShareLnpProofSet";
const PUBLIC_KEY_SHARE_LNP_PROOF_OBJECT_TYPE: &str = "PublicKeyShareLnpProof";
const COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE: &str = "CollectivePublicKey";
const EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE: &str = "EvaluatorKeySchedule";
const REQUIRED_GALOIS_SET_OBJECT_TYPE: &str = "RequiredGaloisSet";
const RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE: &str = "RelinearizationKeyShareRounds";
const RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundOne";
const RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE: &str = "RelinearizationKeyShareRoundTwo";
const GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE: &str = "GaloisKeyShareBatch";
const GALOIS_KEY_SHARE_PROOF_OBJECT_TYPE: &str = "GaloisKeyShareProof";
const PUBLIC_EVALUATION_KEY_SET_OBJECT_TYPE: &str = "PublicEvaluationKeySet";
pub(super) const PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedPublicEvaluationKeyMaterialSet";
pub(super) const PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedPublicEvaluationKeyMaterial";
const PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS: &str =
    "assembled-from-proof-bearing-shares-and-accepted-key-correctness-certificate";
const PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING: &str =
    "root-bound-public-key-switch-component-roots";
pub(super) const PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING: &str =
    "binary-chunked-public-evaluation-key-root-manifest";
const PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE: &str =
    "verified-relinearization-and-galois-proof-records";
const PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC: &[u8; 8] = b"SLEKPMV1";
const RELINEARIZATION_PROOF_VERIFICATION_STATUS: &str =
    RELINEARIZATION_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS;
const RELINEARIZATION_PROOF_MODEL_STATUS: &str = RELINEARIZATION_KEY_SHARE_LNP_PROOF_MODEL_STATUS;
const GALOIS_PROOF_VERIFICATION_STATUS: &str = GALOIS_KEY_SHARE_LNP_PROOF_VERIFICATION_STATUS;
const GALOIS_PROOF_MODEL_STATUS: &str = GALOIS_KEY_SHARE_LNP_PROOF_MODEL_STATUS;
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
const SETUP_PROOF_ACCOUNTING_CERTIFICATE_OBJECT_TYPE: &str = "SetupProofAccountingCertificate";
const SETUP_PROOF_RECORD_BINDING_HASH_NAMESPACE: &str = "SetupProofRecordBindingHash";
const SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE: &str = "SetupProofChallengeSpaceAuditHash";
const SETUP_PROOF_ACCOUNTING_CERTIFICATE_HASH_NAMESPACE: &str =
    "SetupProofAccountingCertificateHash";
const SETUP_KEY_CORRECTNESS_CERTIFICATE_OBJECT_TYPE: &str = "SetupKeyCorrectnessCertificate";
const SETUP_KEY_CORRECTNESS_CERTIFICATE_HASH_NAMESPACE: &str = "SetupKeyCorrectnessCertificateHash";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_OBJECT_TYPE: &str =
    "ActiveStaticSetupTheoremCertificate";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_HASH_NAMESPACE: &str =
    "ActiveStaticSetupTheoremCertificateHash";
const SETUP_PROOF_BYTES_ACCEPTED_STATUS: &str = "private-vss-same-secret-public-key-share-relinearization-and-galois-proof-bytes-accepted-for-setup-proof-accounting";
const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
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
    "externallySuppliedSetupMaterialBoundary",
    "externallySuppliedSetupMaterial",
    "lattigoSetupMaterial",
    "lattigoPublicKey",
    "lattigoRelinearizationKey",
    "lattigoGaloisKey",
    "externallySuppliedThresholdShareCommitments",
    "externallySuppliedThresholdShareCommitmentMaterial",
    "externallySuppliedUnverifiedThresholdShareCommitments",
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
    "sameSecretProofs",
    "publicKeyShares",
    "publicKeyShareProofs",
    "publicKeyShareMaterial",
    "publicKeyShareLnpProofs",
    "collectivePublicKey",
    "collectivePublicKeyRoot",
    "evaluatorKeySchedule",
    "relinearizationKeyShareRounds",
    "galoisKeyShareBatches",
    "evaluationKeys",
    "setupCommitmentSecurityCertificate",
    "setupCommitmentSecurityCertificateHash",
    "setupTransportCertificate",
    "setupTransportCertificateHash",
    "setupProofAccountingCertificate",
    "setupProofAccountingCertificateHash",
    "setupKeyCorrectnessCertificate",
    "setupKeyCorrectnessCertificateHash",
    "activeStaticSetupTheoremCertificate",
    "activeStaticSetupTheoremCertificateHash",
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
    source_trustee_identity: String,
    recipient_identity: String,
    source_trustee_commitment_root: String,
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
    vss_source_trustee_commitment_root: String,
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
        "acceptedCertificateTemplates": {
            "setupCommitmentSecurityCertificate": setup_commitment_security_certificate_with_hash_value()?,
            "setupProofAccountingCertificate": setup_proof_accounting_certificate_with_hash_value()?,
            "heSecurityCertificate": accepted_he_security_certificate_with_hash_value()?,
        },
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
            "transportedPublicKeyShareMaterial",
            "transportedPublicKeyShareProofMaterial",
            "transportedEvaluationKeyShareProofMaterial",
            "transportedEvaluationKeyShareComponentMaterial",
            "transportedPublicEvaluationKeyMaterial",
            "transportedSameSecretProofMaterial",
            "transportedVssCoefficientCommitmentMaterial",
            "verifiedVssCoefficientCommitmentMaterial",
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
        VerificationFlow::Continue => accepted_setup_verification_response(setup_package),
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
    if let Some(response) = verify_collective_public_key_pair_consistency(setup_package)? {
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
    if let Some(response) = verify_collective_public_key_material(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_material_acceptance_boundary(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_evaluator_key_schedule(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_pending_evaluation_key_material_boundary(setup_package, request)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_generic_key_switch_policy(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_commitment_security_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_proof_accounting_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_transport_certificate(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_he_security_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_key_correctness_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_active_static_setup_theorem_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    let declares_public_runtime_material =
        setup_package_declares_public_runtime_material(setup_package);
    if declares_public_runtime_material
        && let Some(response) = verify_profile_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_final_objects(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if !declares_public_runtime_material
        && let Some(response) = verify_profile_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_terminal_setup_transport_policy(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_public_evaluation_key_set(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_required_final_objects(setup_package)? {
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

    let hash_input = setup_package_hash_input(setup_package);
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
        "privateVssShareTboxParameterProfileHash": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
        "setupTransportProfileHash": setup_transport_profile_hash()?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash()?,
    }))
}

pub(super) fn setup_proof_profile_hash() -> CanonicalResult<String> {
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
        "scheduleBindingStatus": "relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting",
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
            "challengeDifferenceInvertibilityAccounting": super::setup_proof::challenge_difference_invertibility_accounting_value()?,
            "qromStatus": "qrom-reduction-theorem-accepted-for-setup-proof-claim",
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
        "privateVssShareTboxParameterProfile": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_value()?,
        "privateVssShareTboxParameterProfileHash": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
        "sameSecretTboxParameterProfile": super::setup_proof::same_secret_lnp_tbox_parameter_profile_value()?,
        "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
        "publicKeyShareTboxParameterProfile": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_value()?,
        "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
        "relinearizationKeyShareTboxParameterProfileHash": super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()?,
        "galoisKeyShareTboxParameterProfileHash": super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash()?,
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
            "proofBytesAcceptedStatus": SETUP_PROOF_BYTES_ACCEPTED_STATUS
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

fn verify_collective_public_key_pair_consistency(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let has_collective_public_key = setup_package.get("collectivePublicKey").is_some();
    let has_collective_public_key_root = setup_package.get("collectivePublicKeyRoot").is_some();
    if has_collective_public_key != has_collective_public_key_root {
        let object_path = if has_collective_public_key_root {
            "setupPackage.collectivePublicKey"
        } else {
            "setupPackage.collectivePublicKeyRoot"
        };
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyMaterialBeforeProofVerification",
            "collective public-key material is not accepted unless the aggregate object and package root are both present and root-bound",
            object_path,
        )?));
    }

    Ok(None)
}

fn verify_required_final_objects(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let setup_key_correctness_certificate_required =
        setup_package_requires_setup_key_correctness_certificate(setup_package);
    let missing_objects = REQUIRED_FINAL_OBJECTS
        .iter()
        .filter(|field_name| {
            setup_key_correctness_certificate_required
                || !matches!(
                    **field_name,
                    "setupKeyCorrectnessCertificate" | "setupKeyCorrectnessCertificateHash"
                )
        })
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

fn setup_package_declares_public_runtime_material(setup_package: &Value) -> bool {
    setup_package.get("collectivePublicKey").is_some()
        || setup_package
            .get("evaluationKeys")
            .and_then(Value::as_object)
            .is_some_and(|evaluation_keys| !evaluation_keys.is_empty())
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
    let Some(source_trustee_records) = commitment_set
        .get("sourceTrusteeRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.sourceTrusteeRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if source_trustee_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentCountMismatch",
            "vssCoefficientCommitments.sourceTrusteeRecords must contain one record for every trustee",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for source_trustee_record in source_trustee_records {
        if let Some(response) = verify_vss_source_trustee_commitment_record(
            source_trustee_record,
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
                "vssCoefficientCommitmentMaterial.coefficientCommitments must cover every source trustee, Q_share limb, and Shamir coefficient",
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

pub(super) fn verify_profile_ring_material(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
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
    if let Some(proof_set) = setup_package.get("sameSecretProofs")
        && let Some(response) = verify_profile_ring_records(
            proof_set,
            "proofRecords",
            "same-secret proof records must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.sameSecretProofs.proofRecords.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(material_set) = setup_package.get("publicKeyShareMaterial")
        && let Some(response) = verify_profile_ring_record(
            material_set,
            "public-key share material must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareMaterial.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(proof_set) = setup_package.get("publicKeyShareLnpProofs")
        && let Some(response) = verify_profile_ring_records(
            proof_set,
            "proofRecords",
            "public-key LNP proof records must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.publicKeyShareLnpProofs.proofRecords.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(collective_public_key) = setup_package.get("collectivePublicKey")
        && let Some(response) = verify_profile_ring_record(
            collective_public_key,
            "collective public-key material must use the accepted profile ring degree before terminal setup acceptance",
            "setupPackage.collectivePublicKey.ringDegree",
        )?
    {
        return Ok(Some(response));
    }
    if let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") {
        for field_name in ["roundOneRecords", "roundTwoRecords"] {
            if let Some(response) = verify_profile_ring_records(
                rounds,
                field_name,
                "relinearization key-share proof records must use the accepted profile ring degree before terminal setup acceptance",
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}.ringDegree"),
            )? {
                return Ok(Some(response));
            }
        }
    }
    if let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in galois_batches {
            if let Some(response) = verify_profile_ring_records(
                batch,
                "galoisKeyShareProofs",
                "Galois key-share proof records must use the accepted profile ring degree before terminal setup acceptance",
                "setupPackage.galoisKeyShareBatches.galoisKeyShareProofs.ringDegree",
            )? {
                return Ok(Some(response));
            }
        }
    }

    Ok(None)
}

pub(super) fn verify_terminal_setup_transport_policy(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material_set| material_set.get("materialEncoding"))
        .and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalVssMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked VSS coefficient commitment material",
            "setupPackage.vssCoefficientCommitmentMaterial.materialEncoding",
        )?));
    }
    if setup_package
        .get("publicKeyShareMaterial")
        .and_then(|material_set| material_set.get("materialEncoding"))
        .and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicKeyShareMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked public-key share material",
            "setupPackage.publicKeyShareMaterial.materialEncoding",
        )?));
    }
    for (record_set_name, records_field_name, object_path) in [
        (
            "sameSecretProofs",
            "proofRecords",
            "setupPackage.sameSecretProofs.proofRecords",
        ),
        (
            "publicKeyShareLnpProofs",
            "proofRecords",
            "setupPackage.publicKeyShareLnpProofs.proofRecords",
        ),
    ] {
        if let Some(response) = verify_terminal_proof_material_transport_records(
            setup_package,
            record_set_name,
            records_field_name,
            object_path,
        )? {
            return Ok(Some(response));
        }
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundOneRecords",
        "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
    )? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundTwoRecords",
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
    )? {
        return Ok(Some(response));
    }
    for galois_batch in array_value(setup_package, "galoisKeyShareBatches")? {
        if let Some(response) = verify_terminal_key_switch_transport_records(
            galois_batch,
            "galoisKeyShareProofs",
            "setupPackage.galoisKeyShareBatches.galoisKeyShareProofs",
        )? {
            return Ok(Some(response));
        }
    }
    let evaluation_keys = setup_package.get("evaluationKeys").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluationKeys was required before terminal transport policy verification",
        )
    })?;
    for field_name in [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ] {
        if evaluation_keys.get(field_name).is_none() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalPublicEvaluationKeyMaterialTransportRequired",
                "terminal accepted setup requires transported public evaluation-key runtime material",
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys
        .get("publicEvaluationKeyMaterialEncoding")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicEvaluationKeyMaterialEncodingMismatch",
            "terminal accepted setup requires binary-chunked public evaluation-key material",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialEncoding",
        )?));
    }
    if let Some(response) = verify_terminal_vss_material_handle_policy(request)? {
        return Ok(Some(response));
    }

    Ok(None)
}

fn verify_terminal_vss_material_handle_policy(request: &Value) -> CanonicalResult<Option<Value>> {
    let Some(transported_material) = request.get("transportedVssCoefficientCommitmentMaterial")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["transportedVssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if transported_material.get("chunks").is_some() {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalVssMaterialHandleRequired",
            "terminal accepted setup requires a chunkless VSS material transport reference plus a stream-verified VSS material handle",
            "transportedVssCoefficientCommitmentMaterial.chunks",
        )?));
    }
    if request
        .get("verifiedVssCoefficientCommitmentMaterial")
        .is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn verify_terminal_proof_material_transport_records(
    setup_package: &Value,
    record_set_name: &str,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    let record_set = setup_package.get(record_set_name).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{record_set_name} was required before terminal transport policy verification"),
        )
    })?;
    for proof_record in array_value(record_set, records_field_name)? {
        if proof_record.get("proofBytesHex").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires transported setup proof bytes",
                format!("{object_path}.proofBytesHex"),
            )?));
        }
        if proof_record
            .get("proofBytesEncoding")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked setup proof bytes",
                format!("{object_path}.proofBytesEncoding"),
            )?));
        }
    }

    Ok(None)
}

fn verify_terminal_key_switch_transport_records(
    record_set: &Value,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    for proof_record in array_value(record_set, records_field_name)? {
        if let Some(response) = verify_terminal_proof_record_transport(proof_record, object_path)? {
            return Ok(Some(response));
        }
        if proof_record.get("keySwitchComponentVectors").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires transported key-switch component material",
                format!("{object_path}.keySwitchComponentVectors"),
            )?));
        }
        if proof_record
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked key-switch component material",
                format!("{object_path}.keySwitchMaterialEncoding"),
            )?));
        }
    }

    Ok(None)
}

fn verify_terminal_proof_record_transport(
    proof_record: &Value,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    if proof_record.get("proofBytesHex").is_some() {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalProofMaterialTransportRequired",
            "terminal accepted setup requires transported setup proof bytes",
            format!("{object_path}.proofBytesHex"),
        )?));
    }
    if proof_record
        .get("proofBytesEncoding")
        .and_then(Value::as_str)
        != Some(SETUP_PROOF_MATERIAL_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalProofMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked setup proof bytes",
            format!("{object_path}.proofBytesEncoding"),
        )?));
    }

    Ok(None)
}

fn terminal_transport_policy_refusal(
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

fn verify_profile_ring_records(
    record_set: &Value,
    records_field_name: &str,
    message: impl Into<String> + Clone,
    object_path: impl Into<String> + Clone,
) -> CanonicalResult<Option<Value>> {
    for record in array_value(record_set, records_field_name)? {
        if let Some(response) =
            verify_profile_ring_record(record, message.clone(), object_path.clone())?
        {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn verify_profile_ring_record(
    record: &Value,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Option<Value>> {
    if record.get("ringDegree").and_then(Value::as_u64) != Some(POLYNOMIAL_DEGREE as u64) {
        return Ok(Some(vss_material_outside_profile(message, object_path)?));
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

fn verify_vss_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some("VssSourceTrusteeCoefficientCommitments")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentTypeMismatch",
            "source trustee VSS commitment record objectType must be VssSourceTrusteeCoefficientCommitments",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.objectType",
        )?));
    }
    if source_trustee_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentVersionMismatch",
            "source trustee VSS commitment record objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.objectVersion",
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
        if source_trustee_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_commitment_refusal(
                "vssSourceTrusteeCommitmentContextMismatch",
                format!("source trustee VSS commitment {field_name} must match setupContext"),
                format!("setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.{field_name}"),
            )?));
        }
    }
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentPublicMatrixSeedMismatch",
            "source trustee VSS commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.publicMatrixSeedHash",
        )?));
    }
    let Some(source_trustee_identity) = source_trustee_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeIdentityMissing",
            "source trustee VSS commitment record must bind sourceTrusteeIdentity",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = source_trustee_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeRosterPositionMissing",
            "source trustee VSS commitment record must bind sourceTrusteeRosterPosition",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if !seen_roster_positions.insert(source_trustee_roster_position) {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentDuplicate",
            "source trustee VSS commitment records must have distinct roster positions",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords",
        )?));
    }
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentTrusteeMismatch",
            "source trustee VSS commitment record must match the phase transcript trustee identity",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeIdentity",
        )?));
    }

    let Some(coefficient_commitments) = source_trustee_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments".to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let expected_coefficient_count =
        DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD as usize;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentCountMismatch",
            "source trustee VSS commitment record must contain every Q_share limb and Shamir coefficient",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments",
        )?));
    }
    let mut seen_coefficients = BTreeSet::new();
    for coefficient_record in coefficient_commitments {
        if let Some(response) = verify_vss_coefficient_commitment_record(
            coefficient_record,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_identity,
            source_trustee_roster_position,
            &mut seen_coefficients,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(source_trustee_commitment_root) = source_trustee_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot"
                    .to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        source_trustee_commitment_root,
        "vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot",
    )?;
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("VSS source trustee commitment object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_root = derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if source_trustee_commitment_root != expected_root {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentRootMismatch",
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee commitment record",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_coefficient_commitment_record(
    coefficient_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    seen_coefficients: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if coefficient_record.get("objectType").and_then(Value::as_str)
        != Some("VssCoefficientCommitment")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentTypeMismatch",
            "VSS coefficient commitment objectType must be VssCoefficientCommitment",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.objectType",
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
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.objectVersion",
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
                    "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
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
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.publicMatrixSeedHash",
        )?));
    }
    if coefficient_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
        != Some(source_trustee_identity)
        || coefficient_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(source_trustee_roster_position)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSourceTrusteeMismatch",
            "VSS coefficient commitment must bind its source trustee record",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.sourceTrusteeIdentity",
        )?));
    }
    let Some(rns_limb_index) = coefficient_record
        .get("rnsLimbIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbMissing",
            "VSS coefficient commitment must bind rnsLimbIndex",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsLimbIndex",
        )?));
    };
    let Ok(rns_limb_index_usize) = usize::try_from(rns_limb_index) else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbInvalid",
            "VSS coefficient commitment rnsLimbIndex does not fit usize",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsLimbIndex",
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
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsPrime",
        )?));
    }
    let Some(shamir_coefficient_index) = coefficient_record
        .get("shamirCoefficientIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexMissing",
            "VSS coefficient commitment must bind shamirCoefficientIndex",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    };
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexInvalid",
            "VSS coefficient commitment shamirCoefficientIndex is outside the first-profile threshold degree",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    }
    if !seen_coefficients.insert((rns_limb_index, shamir_coefficient_index)) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentDuplicate",
            "source trustee VSS coefficient commitments must have distinct limb/coefficient coordinates",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments",
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
                    "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
                )],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            &format!(
                "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
            ),
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
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.openingVerificationStatus",
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
            "privateVssEnvelopeCommitments.envelopeCount must cover every source-trustee-recipient trustee pair",
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
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &setup_intent_mailbox_public_key_bindings,
        &source_trustee_commitment_roots,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => {
            if bindings.len() != expected_envelope_count as usize {
                return Ok(Some(private_vss_envelope_refusal(
                    "privateVssEnvelopeCountMismatch",
                    "privateVssEnvelopeCommitments.envelopeReferences must cover every source-trustee-recipient trustee pair",
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
    let root_input_object = root_input
        .as_object_mut()
        .expect("private VSS envelope commitment set object was checked");
    if let Some(envelope_references) = root_input_object
        .get_mut("envelopeReferences")
        .and_then(Value::as_array_mut)
    {
        for envelope_reference in envelope_references {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
                envelope_reference_object.remove("encryptedEnvelope");
            }
        }
    }
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
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
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
        &source_trustee_commitment_roots,
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
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBindingMap, Refusal>> {
    let Some(envelope_references) = commitment_set
        .get("envelopeReferences")
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferencesMissing",
            "privateVssEnvelopeCommitments.envelopeReferences must contain every source-trustee-recipient envelope commitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    };
    let expected_envelope_count =
        (FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_PARTICIPANT_COUNT) as usize;
    if envelope_references.len() != expected_envelope_count {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceCountMismatch",
            "privateVssEnvelopeCommitments.envelopeReferences must contain one record for every source-trustee-recipient trustee pair",
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
            source_trustee_commitment_roots,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source_trustee_roster_position =
            value_u64(envelope_reference, "sourceTrusteeRosterPosition")?;
        let recipient_roster_position = value_u64(envelope_reference, "recipientRosterPosition")?;
        if bindings
            .insert(
                (source_trustee_roster_position, recipient_roster_position),
                binding,
            )
            .is_some()
        {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeReferenceDuplicate",
                "privateVssEnvelopeCommitments.envelopeReferences must have distinct source-trustee-recipient trustee pairs",
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
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
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

    let source_trustee_identity = match envelope_reference
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeSourceTrusteeMissing",
                "private VSS envelope commitment must bind sourceTrusteeIdentity",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeIdentity",
            )));
        }
    };
    let source_trustee_roster_position = match envelope_reference
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "privateVssEnvelopeSourceTrusteePositionMissing",
                "private VSS envelope commitment must bind sourceTrusteeRosterPosition",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeRosterPosition",
            )));
        }
    };
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSourceTrusteeMismatch",
            "private VSS envelope commitment source trustee must match the phase transcript trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeIdentity",
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
    let expected_sequence_number = source_trustee_roster_position * FIRST_PROFILE_PARTICIPANT_COUNT
        + recipient_roster_position;
    if envelope_reference
        .get("envelopeSequenceNumber")
        .and_then(Value::as_u64)
        != Some(expected_sequence_number)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSequenceMismatch",
            "private VSS envelope commitment envelopeSequenceNumber must follow source-trustee-major roster order",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.envelopeSequenceNumber",
        )));
    }

    let expected_source_trustee_commitment_root = match source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
    {
        Some(value) => value,
        None => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for private VSS envelope verification",
            ));
        }
    };
    if envelope_reference
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSourceTrusteeCommitmentRootMismatch",
            "private VSS envelope commitment sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeCommitmentRoot",
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
        source_trustee_identity,
        source_trustee_roster_position,
        recipient_identity,
        recipient_roster_position,
        expected_source_trustee_commitment_root,
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

    if let Some(encrypted_envelope) = envelope_reference.get("encryptedEnvelope")
        && let Err(refusal) = verify_encrypted_private_vss_envelope(
            encrypted_envelope,
            setup_context,
            &expected_aad,
            &expected_aad_hash,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
            source_trustee_identity,
            source_trustee_roster_position,
            recipient_identity,
            recipient_roster_position,
            expected_recipient_mailbox_public_key_hash,
            expected_recipient_mailbox_public_key_bytes_hash,
            expected_source_trustee_commitment_root,
            expected_sequence_number,
            value_string(envelope_reference, "privateEnvelopeHash")?,
            value_string(envelope_reference, "encryptedEnvelopeHash")?,
        )?
    {
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
    record_root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference object was checked")
        .remove("encryptedEnvelope");
    record_root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference object was checked")
        .remove("transportedPrivateVssShareProofMaterial");
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
        source_trustee_identity: source_trustee_identity.to_string(),
        recipient_identity: recipient_identity.to_string(),
        source_trustee_commitment_root: expected_source_trustee_commitment_root.to_string(),
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
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    expected_recipient_mailbox_public_key_hash: &str,
    expected_recipient_mailbox_public_key_bytes_hash: &str,
    source_trustee_commitment_root: &str,
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
        ("sourceTrusteeIdentity", source_trustee_identity),
        ("recipientIdentity", recipient_identity),
        (
            "recipientMailboxPublicKeyHash",
            expected_recipient_mailbox_public_key_hash,
        ),
        (
            "sourceTrusteeCommitmentRoot",
            source_trustee_commitment_root,
        ),
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
        (
            "sourceTrusteeRosterPosition",
            source_trustee_roster_position,
        ),
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
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    source_trustee_commitment_root: &str,
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
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
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
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
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
            &source_trustee_commitment_roots,
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
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
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

    let Some(source_trustee_identity) = complaint_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeMissing",
            "VSS complaint must bind sourceTrusteeIdentity",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = complaint_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteePositionMissing",
            "VSS complaint must bind sourceTrusteeRosterPosition",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeMismatch",
            "VSS complaint source trustee must match the phase transcript trustee identity",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
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
    if !seen_complaints.insert((source_trustee_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDuplicate",
            "VSS complaint records must have distinct source-trustee-recipient trustee pairs",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    }

    let expected_source_trustee_commitment_root = source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for VSS complaint verification",
            )
        })?;
    if complaint_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeCommitmentRootMismatch",
            "VSS complaint sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) = private_vss_envelope_bindings
        .get(&(source_trustee_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeBindingMissing",
            "VSS complaint must match a private VSS envelope commitment for the source-trustee-recipient pair",
            "setupPackage.vssComplaints.complaintRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.source_trustee_identity != source_trustee_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeSourceTrusteeMismatch",
            "VSS complaint source trustee must match the private VSS envelope commitment source trustee",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRecipientMismatch",
            "VSS complaint recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.source_trustee_commitment_root
        != expected_source_trustee_commitment_root
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "VSS complaint sourceTrusteeCommitmentRoot must match the private VSS envelope commitment source trustee root",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeCommitmentRoot",
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
        "sourceTrusteeIdentity": value_string(complaint_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(complaint_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(complaint_record, "sourceTrusteeCommitmentRoot")?,
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
            "sourceTrusteeIdentity": value_string(complaint_record, "sourceTrusteeIdentity")?,
            "sourceTrusteeRosterPosition": value_u64(complaint_record, "sourceTrusteeRosterPosition")?,
            "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
            "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
            "sourceTrusteeCommitmentRoot": value_string(complaint_record, "sourceTrusteeCommitmentRoot")?,
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
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
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
            "vssShareAcceptances.acceptanceRecords must contain one record for every source-trustee-recipient trustee pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let mut seen_acceptances = BTreeSet::new();
    for acceptance_record in acceptance_records {
        if let Some(response) = verify_vss_share_acceptance_record(
            acceptance_record,
            setup_context,
            &expected_trustees,
            &source_trustee_commitment_roots,
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

fn source_trustee_commitment_roots_from_vss_commitments(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before VSS share acceptance verification",
            )
        })?;
    let mut source_trustee_roots = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let source_trustee_roster_position = source_trustee_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind sourceTrusteeRosterPosition",
                )
            })?;
        let source_trustee_commitment_root = source_trustee_record
            .get("sourceTrusteeCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind sourceTrusteeCommitmentRoot",
                )
            })?;
        source_trustee_roots.insert(
            source_trustee_roster_position,
            source_trustee_commitment_root.to_string(),
        );
    }

    Ok(source_trustee_roots)
}

fn verify_vss_share_acceptance_record(
    acceptance_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
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

    let Some(source_trustee_identity) = acceptance_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeMissing",
            "VSS share acceptance must bind sourceTrusteeIdentity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = acceptance_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteePositionMissing",
            "VSS share acceptance must bind sourceTrusteeRosterPosition",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeMismatch",
            "VSS share acceptance source trustee must match the phase transcript trustee identity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
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
    if !seen_acceptances.insert((source_trustee_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDuplicate",
            "VSS share acceptance records must have distinct source-trustee-recipient trustee pairs",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let expected_source_trustee_commitment_root = source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for VSS share acceptance verification",
            )
        })?;
    if acceptance_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch",
            "VSS share acceptance sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) = private_vss_envelope_bindings
        .get(&(source_trustee_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeBindingMissing",
            "VSS share acceptance must match a private VSS envelope commitment for the source-trustee-recipient pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.source_trustee_identity != source_trustee_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeMismatch",
            "VSS share acceptance source trustee must match the private VSS envelope commitment source trustee",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRecipientMismatch",
            "VSS share acceptance recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.source_trustee_commitment_root
        != expected_source_trustee_commitment_root
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "VSS share acceptance sourceTrusteeCommitmentRoot must match the private VSS envelope commitment source trustee root",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeCommitmentRoot",
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
        "sourceTrusteeIdentity": value_string(acceptance_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(acceptance_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(acceptance_record, "sourceTrusteeCommitmentRoot")?,
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
            "sourceTrusteeIdentity": value_string(acceptance_record, "sourceTrusteeIdentity")?,
            "sourceTrusteeRosterPosition": value_u64(acceptance_record, "sourceTrusteeRosterPosition")?,
            "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
            "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
            "sourceTrusteeCommitmentRoot": value_string(acceptance_record, "sourceTrusteeCommitmentRoot")?,
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
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before threshold-share commitment verification",
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
        let vss_coefficient_commitment_root = material_set
            .get("vssCoefficientCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS coefficient commitment root was required before transported threshold-share verification",
                )
            })?;
        if let Some(verified_material_reference) =
            request.get("verifiedVssCoefficientCommitmentMaterial")
        {
            match threshold_share_commitments_from_verified_vss_material(
                verified_material_reference,
                setup_context,
                public_matrix_seed_hash,
                vss_coefficient_commitment_root,
                material_set,
                threshold_share_commitment_root,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Some(threshold_share_refusal(
                        "thresholdShareCommitmentVerifiedMaterialMismatch",
                        format!(
                            "thresholdShareCommitments must be derived from stream-verified VSS material: {}",
                            error.message
                        ),
                        "verifiedVssCoefficientCommitmentMaterial",
                    )?));
                }
            }
        } else {
            let Some(transported_material) =
                request.get("transportedVssCoefficientCommitmentMaterial")
            else {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("thresholdShareCommitments"),
                    vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
                    Vec::new(),
                    Vec::new(),
                )?));
            };
            if transported_material.get("chunks").is_none() {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("thresholdShareCommitments"),
                    vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
                    Vec::new(),
                    Vec::new(),
                )?));
            }
            let transport_result = match derive_threshold_share_commitments_from_transport_request(
                &json!({
                    "setupContext": setup_context,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
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
        }
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
            source_trustee_records,
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

fn threshold_share_commitments_from_verified_vss_material(
    verified_material_reference: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    material_set: &Value,
    threshold_share_commitment_root: &str,
) -> CanonicalResult<Value> {
    with_verified_transported_vss_material(verified_material_reference, |verified_material| {
        validate_verified_vss_material_matches_package(
            verified_material,
            setup_context,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
            material_set,
        )?;
        let verified_threshold_share_commitment_root = verified_material
            .threshold_share_commitments
            .get("thresholdShareCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "stream-verified VSS material did not retain a threshold-share commitment root",
                )
            })?;
        if verified_threshold_share_commitment_root != threshold_share_commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "stream-verified threshold-share commitment root does not match setupPackage.thresholdShareCommitments",
            ));
        }

        Ok(verified_material.threshold_share_commitments.clone())
    })
}

fn validate_verified_vss_material_matches_package(
    verified_material: &super::threshold_share_commitments::VerifiedTransportedVssMaterial,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    material_set: &Value,
) -> CanonicalResult<()> {
    if verified_material.setup_context != *setup_context {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material setup context does not match setupPackage.setupContext",
        ));
    }
    if verified_material.public_matrix_seed_hash != public_matrix_seed_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material publicMatrixSeedHash does not match setupPackage.commonRandomness",
        ));
    }
    if verified_material.vss_coefficient_commitment_root != vss_coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material commitment root does not match setupPackage.vssCoefficientCommitments",
        ));
    }
    if verified_material.material_set != *material_set {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material set does not match setupPackage.vssCoefficientCommitmentMaterial",
        ));
    }

    Ok(())
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
            "same-secret statement trusteeIdentity must match the accepted VSS source trustee",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeIdentity",
        )?));
    }
    if statement_record
        .get("vssSourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(binding.vss_source_trustee_commitment_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretVssSourceTrusteeRootMismatch",
            "same-secret statement vssSourceTrusteeCommitmentRoot must match the accepted source trustee VSS commitments",
            "setupPackage.sameSecretConsistency.statementRecords.vssSourceTrusteeCommitmentRoot",
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
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee records were required before same-secret statement verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let trustee_roster_position =
            value_u64(source_trustee_record, "sourceTrusteeRosterPosition")?;
        let trustee_identity =
            value_string(source_trustee_record, "sourceTrusteeIdentity")?.to_string();
        if expected_trustees
            .get(&trustee_roster_position)
            .map(String::as_str)
            != Some(trustee_identity.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS source trustee record does not match the accepted setup roster",
            ));
        }
        let vss_source_trustee_commitment_root =
            value_string(source_trustee_record, "sourceTrusteeCommitmentRoot")?.to_string();
        let constant_commitment_roots =
            same_secret_constant_commitment_roots_from_source_trustee(source_trustee_record)?;
        if bindings
            .insert(
                trustee_roster_position,
                SameSecretTrusteeBinding {
                    trustee_identity,
                    trustee_roster_position,
                    vss_source_trustee_commitment_root,
                    constant_commitment_roots,
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS source trustee records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn same_secret_constant_commitment_roots_from_source_trustee(
    source_trustee_record: &Value,
) -> CanonicalResult<Vec<Value>> {
    let coefficient_commitments = source_trustee_record
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
        "vssSourceTrusteeCommitmentRoot": binding.vss_source_trustee_commitment_root,
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
        || value_decimal_u64(proof_record, "challenge")? != verification.challenge
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof transcript metadata must match verified proof bytes",
        ));
    }
    verify_lnp_tbox_z34_metadata_fields(
        proof_record,
        LnpTboxZ34MetadataExpectation {
            z34_seed_material_hash: &verification.z34_seed_material_hash,
            z34_challenge_seed_hash: &verification.z34_challenge_seed_hash,
            z34_challenge_tail_hash: &verification.z34_challenge_tail_hash,
            z34_challenge_row_domain_hash: &verification.z34_challenge_row_domain_hash,
            z34_challenge_z3_row_set_hash: &verification.z34_challenge_z3_row_set_hash,
            z34_challenge_z4_row_set_hash: &verification.z34_challenge_z4_row_set_hash,
            tbox_lower_protocol_challenge_hash: &verification.tbox_lower_protocol_challenge_hash,
            z34_z3_check_window_hash: &verification.z34_z3_check_window_hash,
            z34_z4_check_window_hash: &verification.z34_z4_check_window_hash,
            z34_z3_l2_squared_decimal: &verification.z34_z3_l2_squared_decimal,
            z34_z4_infinity_norm_decimal: &verification.z34_z4_infinity_norm_decimal,
            proof_label: "same-secret proof",
        },
    )?;
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
) -> CanonicalResult<Arc<BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>>> {
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
        return Ok(Arc::new(BTreeMap::new()));
    }
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
    if let Some(verified_material_reference) =
        request.get("verifiedVssCoefficientCommitmentMaterial")
    {
        return with_verified_transported_vss_material(
            verified_material_reference,
            |verified_material| {
                validate_verified_vss_material_matches_package(
                    verified_material,
                    setup_context,
                    public_matrix_seed_hash,
                    vss_coefficient_commitment_root,
                    material_set,
                )?;

                Ok(Arc::clone(
                    &verified_material.constant_commitments_by_source_trustee,
                ))
            },
        );
    }
    let transported_material = request
        .get("transportedVssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verifiedVssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    if transported_material.get("chunks").is_none() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material was required before same-secret proof verification",
        ));
    }
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before transported same-secret proof verification",
            )
        })?;
    let verified_transport = verify_constant_vss_commitments_from_transport_request(&json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
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

    Ok(verified_transport.constant_commitments_by_source_trustee)
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
            .get("sourceTrusteeRosterPosition")
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
            "vssSourceTrusteeCommitmentRoot",
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
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
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
    if public_key_share_material_uses_transport(material_set)
        && request.get("transportedPublicKeyShareMaterial").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        public_key_share_set_root,
        &share_records,
        request,
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

fn verify_collective_public_key_material(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
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
        (
            "aggregationStatus",
            "lnp-proof-aggregated-with-accepted-setup-proof-accounting",
        ),
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
    if public_key_share_material_uses_transport(material_set)
        && request.get("transportedPublicKeyShareMaterial").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
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
        request,
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
    if ring_degree == POLYNOMIAL_DEGREE as u64
        && let Err(error) = accepted_setup_collective_public_key_from_package(setup_package)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyRuntimeMaterialInvalid",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }

    Ok(None)
}

pub(super) fn accepted_setup_collective_public_key_from_package(
    setup_package: &Value,
) -> CanonicalResult<BgvPublicKey> {
    let aggregate_object = setup_package.get("collectivePublicKey").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collectivePublicKey was required before accepted public-key runtime loading",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before accepted public-key runtime loading",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    if value_string(aggregate_object, "publicMatrixSeedHash")? != public_matrix_seed_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the accepted public matrix seed",
        ));
    }
    let expected_public_derivations =
        derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash)?;
    if common_randomness.get("publicDerivations") != Some(&expected_public_derivations) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public-key runtime loading requires canonical public derivations",
        ));
    }
    let expected_public_a = derive_bgv_public_a_polynomial(public_matrix_seed_hash)?;
    if value_string(aggregate_object, "publicAPolynomialRoot")?
        != value_string(&expected_public_a, "publicPolynomialRoot")?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the accepted BGV public a polynomial",
        ));
    }
    if value_u64(aggregate_object, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted collective public-key runtime material requires profile-ring aggregate coefficients",
        ));
    }
    let public_b = collective_public_key_component_b_from_aggregate_object(aggregate_object)?;
    let public_a = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
        })
        .collect::<Vec<_>>();

    BgvPublicKey::from_components(public_b, public_a)
}

fn collective_public_key_component_b_from_aggregate_object(
    aggregate_object: &Value,
) -> CanonicalResult<Vec<Vec<u64>>> {
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
            "collective public key must contain one runtime component-b limb per Q_share prime",
        ));
    }
    let mut public_b = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((POLYNOMIAL_DEGREE * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key runtime limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            POLYNOMIAL_DEGREE,
            "collective public-key runtime coefficient vector width must match the profile ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collective public-key runtime component contains non-canonical Q_share residues",
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
                "collective public-key runtime component hash must match the aggregate coefficients",
            ));
        }
        public_b.push(coefficients);
    }

    Ok(public_b)
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

fn public_key_share_material_uses_transport(material_set: &Value) -> bool {
    material_set.get("materialEncoding").and_then(Value::as_str)
        == Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING)
}

fn verify_embedded_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("binaryFormat").is_some() || material_set.get("transport").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "embedded public-key share material must not declare binary transport fields",
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
        material_roots.push(public_key_share_material_root_reference(&binding));
    }

    Ok((bindings, material_roots))
}

fn verify_transport_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("shareMaterialRecords").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary-chunked public-key share material must not embed shareMaterialRecords",
        ));
    }
    if material_set.get("binaryFormat").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.binaryFormat must match the accepted public-key share material binary format",
        ));
    }
    let Some(transported_material) = request.get("transportedPublicKeyShareMaterial") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial is required for binary-chunked public-key share material",
        ));
    };
    verify_public_key_share_material_transport_header(transported_material)?;
    let chunks = public_key_share_material_chunks(transported_material)?;
    let transport_hashes = public_key_share_material_transport_hashes(&chunks)?;
    verify_public_key_share_material_transport_hash_fields(
        transported_material,
        &transport_hashes,
        true,
        "transported public-key share material",
    )?;
    verify_public_key_share_material_set_transport_reference(material_set, &transport_hashes)?;
    let (bindings, material_roots) = decode_public_key_share_material_bindings(
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        &chunks,
    )?;

    Ok((bindings, material_roots))
}

fn public_key_share_material_root_reference(binding: &PublicKeyShareMaterialBinding) -> Value {
    json!({
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
    })
}

#[derive(Debug)]
pub(super) struct PublicKeyShareMaterialTransportHashes {
    pub(super) full_object_hash: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) chunk_root: String,
    pub(super) total_byte_length: u64,
}

struct PublicKeyShareMaterialByteReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl PublicKeyShareMaterialByteReader {
    fn new(chunks: &[Vec<u8>]) -> CanonicalResult<Self> {
        let total_byte_length = chunks.iter().try_fold(0_usize, |byte_count, chunk| {
            byte_count.checked_add(chunk.len()).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material byte length overflowed",
                )
            })
        })?;
        let mut bytes = Vec::with_capacity(total_byte_length);
        for chunk in chunks {
            bytes.extend_from_slice(chunk);
        }

        Ok(Self { bytes, offset: 0 })
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_exact(&mut self, length: usize) -> CanonicalResult<&[u8]> {
        let end_offset = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material read offset overflowed",
            )
        })?;
        let Some(slice) = self.bytes.get(self.offset..end_offset) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported public-key share material ended before the binary object was complete",
            ));
        };
        self.offset = end_offset;

        Ok(slice)
    }

    fn read_varuint(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let mut shift = 0_u32;
        let mut value = 0_u64;
        let mut consumed = Vec::new();
        for byte_index in 0..10 {
            let byte = self.read_exact(1)?[0];
            consumed.push(byte);
            let payload = u64::from(byte & 0x7f);
            if byte_index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name} binary varuint exceeds u64"),
                ));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                crate::encoding::append_varuint(&mut canonical, value);
                if canonical != consumed {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} binary varuint is not minimally encoded"),
                    ));
                }

                return Ok(value);
            }
            shift += 7;
        }

        Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} binary varuint is too long"),
        ))
    }

    fn read_u64_le(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let bytes = self.read_exact(8)?;
        let byte_array: [u8; 8] = bytes.try_into().map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} is malformed"),
            )
        })?;

        Ok(u64::from_le_bytes(byte_array))
    }
}

fn verify_public_key_share_material_transport_header(value: &Value) -> CanonicalResult<()> {
    let Some(object) = value.as_object() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial must be an object",
        ));
    };
    for field_name in object.keys() {
        if ![
            "objectType",
            "objectVersion",
            "binaryFormat",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ]
        .contains(&field_name.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("transportedPublicKeyShareMaterial contains unexpected field {field_name}"),
            ));
        }
    }
    if value.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectType must be SetupTransportedPublicKeyShareMaterial",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectVersion must be 1",
        ));
    }
    if value.get("binaryFormat").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.binaryFormat must match the accepted public-key share material binary format",
        ));
    }

    Ok(())
}

fn public_key_share_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkSizeBytes must match the setup transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_value(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if value_u64(chunk_value, "chunkIndex")?
            != u64::try_from(expected_chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk index does not fit u64",
                )
            })?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material chunks must be in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

pub(super) fn public_key_share_material_transport_hashes(
    chunks: &[Vec<u8>],
) -> CanonicalResult<PublicKeyShareMaterialTransportHashes> {
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material transport requires at least one chunk",
        ));
    }
    let chunk_size = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material contains a short non-final chunk",
                    ));
                }
                byte_count
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material byte length overflowed",
                        )
                    })
            })?;
    let full_object_hash = public_key_share_material_full_object_hash(total_byte_length, chunks);
    let chunk_hashes = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            public_key_share_material_chunk_hash(&full_object_hash, chunk_index, chunk)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        u64::try_from(chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(PublicKeyShareMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

fn public_key_share_material_full_object_hash(
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> String {
    let total_length_bytes = total_byte_length.to_le_bytes();
    let mut parts = Vec::with_capacity(chunks.len() + 1);
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    hash512_hex(
        "sealed-lattice/setup/public-key-share-material/full-object-v1",
        &parts,
    )
}

fn public_key_share_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let chunk_index_bytes = u64::try_from(chunk_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk index does not fit u64",
            )
        })?
        .to_le_bytes();

    Ok(hash512_hex(
        "sealed-lattice/setup/public-key-share-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

fn verify_public_key_share_material_transport_hash_fields(
    value: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
    require_chunk_hashes: bool,
    value_name: &str,
) -> CanonicalResult<()> {
    let chunk_size = value_u64(value, "chunkSizeBytes")?;
    let chunk_count = value_u64(value, "chunkCount")?;
    let total_byte_length = value_u64(value, "totalByteLength")?;
    let full_object_hash = value_string(value, "fullObjectHash")?;
    let chunk_root = value_string(value, "chunkRoot")?;
    if chunk_size != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
        || chunk_count
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk count does not fit u64",
                )
            })?
        || total_byte_length != transport_hashes.total_byte_length
        || full_object_hash != transport_hashes.full_object_hash
        || chunk_root != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} hash metadata does not match supplied chunks"),
        ));
    }
    if require_chunk_hashes {
        let chunk_hash_values = value
            .get("chunkHashes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} must list every public-key share material chunk hash"),
                )
            })?;
        if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} chunk hash count must match supplied chunks"),
            ));
        }
        for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
            .iter()
            .zip(transport_hashes.chunk_hashes.iter())
        {
            if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} chunk hashes must match supplied chunks"),
                ));
            }
        }
    }

    Ok(())
}

fn verify_public_key_share_material_set_transport_reference(
    material_set: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
) -> CanonicalResult<()> {
    let transport = material_set.get("transport").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport is required for binary-chunked material",
        )
    })?;
    let Some(transport_object) = transport.as_object() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport must be an object",
        ));
    };
    for field_name in transport_object.keys() {
        if ![
            "transportProfileId",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
        ]
        .contains(&field_name.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.transport contains unexpected field {field_name}"),
            ));
        }
    }
    if transport.get("transportProfileId").and_then(Value::as_str)
        != Some(SETUP_TRANSPORT_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport.transportProfileId must match the setup transport profile",
        ));
    }
    verify_public_key_share_material_transport_hash_fields(
        transport,
        transport_hashes,
        false,
        "public-key share material transport reference",
    )
}

fn decode_public_key_share_material_bindings(
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    let mut reader = PublicKeyShareMaterialByteReader::new(chunks)?;
    let magic = reader.read_exact(PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len())?;
    if magic != PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material binary magic does not match",
        ));
    }
    if reader.read_varuint("binary version")? != PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material binary version is unsupported",
        ));
    }
    if reader.read_varuint("participantCount")? != FIRST_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material participant count does not match the accepted profile",
        ));
    }
    if reader.read_varuint("rnsLimbCount")? != DATA_PRIMES.len() as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material RNS limb count does not match Q_share",
        ));
    }
    if usize::try_from(reader.read_varuint("ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material ringDegree does not fit usize",
        )
    })? != ring_degree
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material ring degree must match the material set",
        ));
    }

    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for expected_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT {
        if reader.read_varuint("trusteeRosterPosition")? != expected_roster_position {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material trustee order is not canonical",
            ));
        }
        let share_record = share_records
            .get(&expected_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported public-key share material must reference an accepted share record",
                )
            })?;
        let trustee_identity = value_string(share_record, "trusteeIdentity")?.to_string();
        let public_key_share_root = value_string(share_record, "publicKeyShareRoot")?.to_string();
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
        let mut limb_records = Vec::with_capacity(DATA_PRIMES.len());
        for (rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
            if reader.read_varuint("rnsLimbIndex")? != rns_limb_index as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported public-key share material RNS limb order is not canonical",
                ));
            }
            if reader.read_u64_le("rnsPrime")? != modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "transported public-key share material RNS prime does not match Q_share",
                ));
            }
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _coefficient_index in 0..ring_degree {
                let coefficient = reader.read_u64_le("public-key share coefficient")?;
                if coefficient >= modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "transported public-key share coefficient is not a canonical residue",
                    ));
                }
                coefficients.push(coefficient);
            }
            let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
            if share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("rnsLimbIndex"))
                .and_then(Value::as_u64)
                != Some(rns_limb_index as u64)
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("rnsPrime"))
                    .and_then(Value::as_u64)
                    != Some(modulus)
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("component"))
                    .and_then(Value::as_str)
                    != Some("b_i")
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                    .and_then(Value::as_str)
                    != Some(coefficient_hash.as_str())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "transported public-key share coefficient hash must match the accepted share record",
                ));
            }
            limb_records.push(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": modulus,
                "component": "b_i",
                "coefficientByteLength": ring_degree * 8,
                "coefficientVectorHash512": coefficient_hash,
                "coefficientsLeHex": coefficient_vector_le_hex(&coefficients),
            }));
            coefficients_by_limb.push(coefficients);
        }
        let material_record = json!({
            "objectType": PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "public-key-share",
            "proofModelStatus": PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS,
            "materialEncoding": PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING,
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
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": expected_roster_position,
            "rnsLimbCount": DATA_PRIMES.len(),
            "ringDegree": ring_degree,
            "publicMatrixSeedHash": common_binding.public_matrix_seed_hash,
            "publicKeyCrpRoot": common_binding.public_key_crp_root,
            "publicAPolynomialRoot": common_binding.public_a_polynomial_root,
            "publicKeyShareRoot": public_key_share_root,
            "shareCoefficientVectorsByLimb": limb_records,
        });
        let public_key_share_material_root =
            derive_protocol_hash("PublicKeyShareRoot", &material_record)?;
        let binding = PublicKeyShareMaterialBinding {
            trustee_identity: value_string(&material_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position: expected_roster_position,
            public_key_share_root: value_string(&material_record, "publicKeyShareRoot")?
                .to_string(),
            public_key_share_material_root,
            coefficients_by_limb,
        };
        material_roots.push(public_key_share_material_root_reference(&binding));
        if bindings
            .insert(binding.trustee_roster_position, binding)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material contains duplicate trustee records",
            ));
        }
    }
    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material has trailing bytes after the final trustee record",
        ));
    }

    Ok((bindings, material_roots))
}

fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
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
        ("proofModelStatus", PUBLIC_KEY_SHARE_LNP_PROOF_MODEL_STATUS),
    ] {
        if material_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    let material_encoding = value_string(material_set, "materialEncoding")?;
    if ![
        PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING,
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
    ]
    .contains(&material_encoding)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.materialEncoding must be embedded full public-key share coefficients or binary-chunked full public-key share coefficients",
        ));
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
    let (bindings, material_roots) =
        if material_encoding == PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING {
            verify_embedded_public_key_share_material_set(
                material_set,
                setup_context,
                common_binding,
                ring_degree,
                share_records,
            )?
        } else {
            verify_transport_public_key_share_material_set(
                material_set,
                setup_context,
                common_binding,
                ring_degree,
                share_records,
                request,
            )?
        };
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
        || value_decimal_u64(proof_record, "challenge")? != verification.challenge
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key LNP proof transcript metadata must match verified proof bytes",
        ));
    }
    verify_lnp_tbox_z34_metadata_fields(
        proof_record,
        LnpTboxZ34MetadataExpectation {
            z34_seed_material_hash: &verification.z34_seed_material_hash,
            z34_challenge_seed_hash: &verification.z34_challenge_seed_hash,
            z34_challenge_tail_hash: &verification.z34_challenge_tail_hash,
            z34_challenge_row_domain_hash: &verification.z34_challenge_row_domain_hash,
            z34_challenge_z3_row_set_hash: &verification.z34_challenge_z3_row_set_hash,
            z34_challenge_z4_row_set_hash: &verification.z34_challenge_z4_row_set_hash,
            tbox_lower_protocol_challenge_hash: &verification.tbox_lower_protocol_challenge_hash,
            z34_z3_check_window_hash: &verification.z34_z3_check_window_hash,
            z34_z4_check_window_hash: &verification.z34_z4_check_window_hash,
            z34_z3_l2_squared_decimal: &verification.z34_z3_l2_squared_decimal,
            z34_z4_infinity_norm_decimal: &verification.z34_z4_infinity_norm_decimal,
            proof_label: "public-key LNP proof",
        },
    )?;
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
            "relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting",
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
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if let Some(response) = verify_relinearization_key_share_rounds(setup_package, request)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_galois_key_share_batches(setup_package, request)? {
        return Ok(Some(response));
    }

    if let Some(response) = verify_public_evaluation_key_set(setup_package, request, false)? {
        return Ok(Some(response));
    }

    Ok(None)
}

fn verify_required_public_evaluation_key_set(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    verify_public_evaluation_key_set(setup_package, request, true)
}

fn verify_public_evaluation_key_set(
    setup_package: &Value,
    request: &Value,
    require_material: bool,
) -> CanonicalResult<Option<Value>> {
    let Some(evaluation_keys) = setup_package.get("evaluationKeys") else {
        if !require_material {
            return Ok(None);
        }
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["evaluationKeys".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !evaluation_keys.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysNotObject",
            "evaluationKeys must be a root-bound PublicEvaluationKeySet object",
            "setupPackage.evaluationKeys",
        )?));
    }
    if evaluation_keys
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        if !require_material {
            return Ok(None);
        }
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["evaluationKeys".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    if let Some(unexpected_field) = unexpected_public_evaluation_key_set_field(evaluation_keys) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysUnexpectedField",
            format!("evaluationKeys contains unexpected field {unexpected_field}"),
            format!("setupPackage.evaluationKeys.{unexpected_field}"),
        )?));
    }
    if evaluation_keys.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_SET_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysTypeMismatch",
            "evaluationKeys.objectType must be PublicEvaluationKeySet",
            "setupPackage.evaluationKeys.objectType",
        )?));
    }
    if evaluation_keys.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysVersionMismatch",
            "evaluationKeys.objectVersion must be 1",
            "setupPackage.evaluationKeys.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before evaluation-key assembly verification",
        )
    })?;
    if let Err(error) =
        verify_context_fields_match(evaluation_keys, setup_context, "evaluationKeys")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysContextMismatch",
            error.message,
            "setupPackage.evaluationKeys",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("assemblyStatus", PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS),
        ("materialEncoding", PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING),
        ("materialSource", PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysProfileMismatch",
                format!("evaluationKeys.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysCountMismatch",
                format!("evaluationKeys.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("rawKeyBytesEmbedded", false),
        ("verifierGeneratedKeyMaterial", false),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_bool) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysMaterialBoundaryMismatch",
                format!("evaluationKeys.{field_name} must be false"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let relinearization_key_share_rounds_root = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(|rounds| rounds.get("relinearizationKeyShareRoundsRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRoundsRoot was required before evaluation-key assembly",
            )
        })?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareLnpProofSetRoot",
            binding.public_key_share_lnp_proof_set_root.as_str(),
        ),
        (
            "relinearizationKeyShareRoundsRoot",
            relinearization_key_share_rounds_root,
        ),
        (
            "requiredGaloisSetHash",
            binding.required_galois_set_hash.as_str(),
        ),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysBindingMismatch",
                format!("evaluationKeys.{field_name} must match the verified setup binding"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys.get("relinearizationLevelSchedule")
        != Some(&expected_relinearization_level_schedule())
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysRelinearizationScheduleMismatch",
            "evaluationKeys.relinearizationLevelSchedule must match the frozen evaluator schedule",
            "setupPackage.evaluationKeys.relinearizationLevelSchedule",
        )?));
    }
    if evaluation_keys.get("requiredGaloisKeySchedule")
        != Some(&expected_required_galois_key_schedule()?)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysGaloisScheduleMismatch",
            "evaluationKeys.requiredGaloisKeySchedule must match the frozen evaluator schedule",
            "setupPackage.evaluationKeys.requiredGaloisKeySchedule",
        )?));
    }
    if evaluation_keys.get("genericKeySwitchKeyRoots") != Some(&Value::Array(Vec::new())) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysGenericKeySwitchOutsideProfile",
            "evaluationKeys.genericKeySwitchKeyRoots must be empty for the first profile",
            "setupPackage.evaluationKeys.genericKeySwitchKeyRoots",
        )?));
    }

    let expected_relinearization_key_roots =
        expected_relinearization_key_roots_for_evaluation_keys(setup_package, &binding)?;
    let supplied_relinearization_key_roots =
        array_value(evaluation_keys, "relinearizationKeyRoots")?;
    if supplied_relinearization_key_roots.len() != expected_relinearization_key_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyRelinearizationKeyCountMismatch",
            "evaluationKeys.relinearizationKeyRoots must contain one key root per scheduled relinearization level",
            "setupPackage.evaluationKeys.relinearizationKeyRoots",
        )?));
    }
    if supplied_relinearization_key_roots != &expected_relinearization_key_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyRelinearizationKeyRootMismatch",
            "evaluationKeys.relinearizationKeyRoots must be derived from verified relinearization proof aggregates",
            "setupPackage.evaluationKeys.relinearizationKeyRoots",
        )?));
    }

    let expected_galois_batch_roots =
        expected_galois_batch_roots_for_evaluation_keys(setup_package)?;
    let supplied_galois_batch_roots = array_value(evaluation_keys, "galoisKeyShareBatchRoots")?;
    if supplied_galois_batch_roots.len() != expected_galois_batch_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisBatchCountMismatch",
            "evaluationKeys.galoisKeyShareBatchRoots must contain one batch root per trustee",
            "setupPackage.evaluationKeys.galoisKeyShareBatchRoots",
        )?));
    }
    if supplied_galois_batch_roots != &expected_galois_batch_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisBatchRootMismatch",
            "evaluationKeys.galoisKeyShareBatchRoots must match verified Galois proof batches",
            "setupPackage.evaluationKeys.galoisKeyShareBatchRoots",
        )?));
    }

    let expected_galois_key_roots =
        expected_galois_key_roots_for_evaluation_keys(setup_package, &binding)?;
    let supplied_galois_key_roots = array_value(evaluation_keys, "galoisKeyRoots")?;
    if supplied_galois_key_roots.len() != expected_galois_key_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisKeyCountMismatch",
            "evaluationKeys.galoisKeyRoots must contain one key root per required Galois key",
            "setupPackage.evaluationKeys.galoisKeyRoots",
        )?));
    }
    if supplied_galois_key_roots != &expected_galois_key_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisKeyRootMismatch",
            "evaluationKeys.galoisKeyRoots must be derived from verified Galois proof batches",
            "setupPackage.evaluationKeys.galoisKeyRoots",
        )?));
    }

    let supplied_evaluation_key_set_hash = value_string(evaluation_keys, "evaluationKeySetHash")?;
    let mut root_input = evaluation_keys.clone();
    root_input
        .as_object_mut()
        .expect("evaluationKeys object was checked")
        .remove("evaluationKeySetHash");
    let expected_evaluation_key_set_hash =
        derive_protocol_hash("EvaluationKeySetHash", &root_input)?;
    if supplied_evaluation_key_set_hash != expected_evaluation_key_set_hash {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeySetHashMismatch",
            "evaluationKeySetHash does not match the canonical public evaluation-key set",
            "setupPackage.evaluationKeys.evaluationKeySetHash",
        )?));
    }
    if public_evaluation_key_set_has_material_reference(evaluation_keys) {
        if let Some(response) = verify_public_evaluation_key_material_transport(
            setup_package,
            evaluation_keys,
            request,
        )? {
            return Ok(Some(response));
        }
    } else if request
        .get("transportedPublicEvaluationKeyMaterial")
        .is_some()
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialUndeclared",
            "transported public evaluation-key material must be declared by evaluationKeys",
            "transportedPublicEvaluationKeyMaterial",
        )?));
    }

    Ok(None)
}

#[derive(Debug, Clone)]
pub(super) struct PublicEvaluationKeyMaterialTransportHashes {
    pub(super) full_object_hash: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) chunk_root: String,
    pub(super) total_byte_length: u64,
}

fn public_evaluation_key_set_has_material_reference(evaluation_keys: &Value) -> bool {
    [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ]
    .into_iter()
    .any(|field_name| evaluation_keys.get(field_name).is_some())
}

fn transported_evaluation_key_share_component_material_from_request(
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .is_some()
    {
        return Ok(None);
    }
    let Some(public_evaluation_key_material) =
        request.get("transportedPublicEvaluationKeyMaterial")
    else {
        return Ok(None);
    };
    let Some(component_materials) = public_evaluation_key_material.get("componentMaterials") else {
        return Ok(None);
    };
    if !component_materials.is_array() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material componentMaterials must be an array",
        ));
    }

    Ok(Some(json!({
        "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "componentMaterials": component_materials,
    })))
}

fn verify_public_evaluation_key_material_transport(
    setup_package: &Value,
    evaluation_keys: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ] {
        if evaluation_keys.get(field_name).is_none() {
            return Ok(Some(evaluation_key_material_refusal(
                "publicEvaluationKeyMaterialReferenceIncomplete",
                format!(
                    "evaluationKeys.{field_name} is required when public evaluation-key material is declared"
                ),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys
        .get("publicEvaluationKeyMaterialEncoding")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialEncodingMismatch",
            format!(
                "evaluationKeys.publicEvaluationKeyMaterialEncoding must be {PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING}"
            ),
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialEncoding",
        )?));
    }
    let Some(transported_material_set) = request.get("transportedPublicEvaluationKeyMaterial")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicEvaluationKeyMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if transported_material_set
        .get("objectType")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || transported_material_set
            .get("objectVersion")
            .and_then(Value::as_u64)
            != Some(1)
        || transported_material_set
            .get("setupProfileId")
            .and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || transported_material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || transported_material_set
            .get("materialEncoding")
            .and_then(Value::as_str)
            != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialTransportHeaderMismatch",
            "transportedPublicEvaluationKeyMaterial must be a public evaluation-key material transport set",
            "transportedPublicEvaluationKeyMaterial",
        )?));
    }
    if let Err(error) = verify_public_evaluation_key_material_component_roots(
        setup_package,
        transported_material_set,
        request,
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.componentMaterials",
        )?));
    }
    let expected_material_root = value_string(evaluation_keys, "publicEvaluationKeyMaterialRoot")?;
    validate_hash_string(
        expected_material_root,
        "evaluationKeys.publicEvaluationKeyMaterialRoot",
    )?;
    let material_entries = array_value(transported_material_set, "publicEvaluationKeyMaterials")?;
    let mut matching_material = None;
    for material_entry in material_entries {
        if value_string(material_entry, "publicEvaluationKeyMaterialRoot")?
            != expected_material_root
        {
            continue;
        }
        if matching_material.is_some() {
            return Ok(Some(evaluation_key_material_refusal(
                "publicEvaluationKeyMaterialDuplicateRoot",
                "transported public evaluation-key material contains duplicate material roots",
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
            )?));
        }
        matching_material = Some(material_entry);
    }
    let Some(material_entry) = matching_material else {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialMissingRoot",
            "transported public evaluation-key material is missing the declared publicEvaluationKeyMaterialRoot",
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    };
    if let Err(error) =
        verify_public_evaluation_key_material_entry_header(evaluation_keys, material_entry)
    {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    let chunks = match public_evaluation_key_material_chunks(material_entry) {
        Ok(chunks) => chunks,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.chunks",
            )?));
        }
    };
    let transport_hashes = match public_evaluation_key_material_transport_hashes(&chunks) {
        Ok(transport_hashes) => transport_hashes,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.chunks",
            )?));
        }
    };
    if let Err(error) = verify_public_evaluation_key_material_hash_fields(
        material_entry,
        &transport_hashes,
        "transported public evaluation-key material",
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    if let Err(error) = verify_public_evaluation_key_material_hash_fields(
        evaluation_keys,
        &transport_hashes,
        "public evaluation-key material reference",
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "setupPackage.evaluationKeys",
        )?));
    }
    let expected_manifest =
        public_evaluation_key_material_manifest(setup_package, evaluation_keys)?;
    let canonical_material_root = public_evaluation_key_material_reference_root(
        evaluation_keys,
        &expected_manifest,
        &transport_hashes,
    )?;
    if expected_material_root != canonical_material_root {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialRootMismatch",
            "publicEvaluationKeyMaterialRoot does not match the canonical material reference",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialRoot",
        )?));
    }
    let decoded_manifest =
        match decode_public_evaluation_key_material_manifest(&chunks, &transport_hashes) {
            Ok(decoded_manifest) => decoded_manifest,
            Err(error) => {
                return Ok(Some(evaluation_key_material_verification_failure(
                    error,
                    "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
                )?));
            }
        };
    if decoded_manifest != expected_manifest {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialManifestMismatch",
            "transported public evaluation-key material manifest does not match the verified setup package",
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    if accepted_setup_evaluation_key_records_use_profile_ring(setup_package)? {
        if let Err(error) =
            accepted_setup_public_relinearization_keys_from_transport(setup_package, request)
        {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.componentMaterials",
            )?));
        }
        if let Err(error) = accepted_setup_public_galois_keys_from_transport(setup_package, request)
        {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.componentMaterials",
            )?));
        }
    }

    Ok(None)
}

fn evaluation_key_material_verification_failure(
    error: CanonicalError,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    evaluation_key_material_refusal(
        "evaluationKeyMaterialVerificationFailed",
        error.message,
        object_path,
    )
}

fn verify_public_evaluation_key_material_component_roots(
    setup_package: &Value,
    transported_material_set: &Value,
    request: &Value,
) -> CanonicalResult<()> {
    let expected_roots = expected_public_evaluation_key_component_material_roots(setup_package)?;
    let supplied_component_materials = match transported_material_set.get("componentMaterials") {
        Some(component_materials) => Some(component_materials.as_array().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material componentMaterials must be an array",
            )
        })?),
        None => None,
    };
    let request_component_material_roots =
        transported_evaluation_key_share_component_material_roots_from_request(request)?;
    if expected_roots.is_empty() {
        if supplied_component_materials.is_some_and(|materials| !materials.is_empty()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material must not include undeclared component material",
            ));
        }
        if request_component_material_roots.is_some_and(|roots| !roots.is_empty()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key component material must not be supplied when public evaluation-key records do not use binary component material",
            ));
        }
        return Ok(());
    }
    if let Some(component_materials) = supplied_component_materials
        && !component_materials.is_empty()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material must not duplicate evaluation-key component material chunks; use transportedEvaluationKeyShareComponentMaterial",
        ));
    }
    let Some(supplied_roots) = request_component_material_roots else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "request must include transportedEvaluationKeyShareComponentMaterial for binary public evaluation-key proof records",
        ));
    };
    if supplied_roots != expected_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "request-side transported evaluation-key component roots do not match proof records",
        ));
    }

    Ok(())
}

fn transported_evaluation_key_share_component_material_roots_from_request(
    request: &Value,
) -> CanonicalResult<Option<BTreeSet<String>>> {
    let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") else {
        return Ok(None);
    };
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || material_set.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareComponentMaterial must be an evaluation-key component material transport set",
        ));
    }
    let component_materials = array_value(material_set, "componentMaterials")?;
    evaluation_key_component_material_roots_from_values(
        component_materials,
        "transportedEvaluationKeyShareComponentMaterial.componentMaterials",
    )
    .map(Some)
}

fn evaluation_key_component_material_roots_from_values(
    component_materials: &[Value],
    object_path: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let mut supplied_roots = BTreeSet::new();
    for component_material in component_materials {
        let material_root = value_string(component_material, "keySwitchComponentMaterialRoot")?;
        validate_hash_string(
            material_root,
            &format!("{object_path}.keySwitchComponentMaterialRoot"),
        )?;
        if !supplied_roots.insert(material_root.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path} contains duplicate component material roots"),
            ));
        }
    }

    Ok(supplied_roots)
}

fn expected_public_evaluation_key_component_material_roots(
    setup_package: &Value,
) -> CanonicalResult<BTreeSet<String>> {
    let mut expected_roots = BTreeSet::new();
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public evaluation-key material verification",
            )
        })?;
    for record_field_name in ["roundOneRecords", "roundTwoRecords"] {
        for record in array_value(rounds, record_field_name)? {
            collect_binary_key_switch_component_material_root(record, &mut expected_roots)?;
        }
    }
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public evaluation-key material verification",
            )
        })?;
    for batch in batches {
        for proof_record in array_value(batch, "galoisKeyShareProofs")? {
            collect_binary_key_switch_component_material_root(proof_record, &mut expected_roots)?;
        }
    }

    Ok(expected_roots)
}

fn collect_binary_key_switch_component_material_root(
    record: &Value,
    expected_roots: &mut BTreeSet<String>,
) -> CanonicalResult<()> {
    if record
        .get("keySwitchMaterialEncoding")
        .and_then(Value::as_str)
        == Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
    {
        expected_roots.insert(value_string(record, "keySwitchComponentMaterialRoot")?.to_string());
    }

    Ok(())
}

fn verify_public_evaluation_key_material_entry_header(
    evaluation_keys: &Value,
    material_entry: &Value,
) -> CanonicalResult<()> {
    if material_entry.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE)
        || material_entry.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || material_entry.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_entry
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || material_entry
            .get("materialEncoding")
            .and_then(Value::as_str)
            != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material entry header is invalid",
        ));
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
        "evaluationKeySetHash",
        "publicEvaluationKeyMaterialRoot",
    ] {
        if material_entry.get(field_name) != evaluation_keys.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "transported public evaluation-key material {field_name} must match evaluationKeys"
                ),
            ));
        }
    }

    Ok(())
}

fn public_evaluation_key_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunkSizeBytes must match the setup transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_value(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if value_u64(chunk_value, "chunkIndex")?
            != u64::try_from(expected_chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public evaluation-key material chunk index does not fit u64",
                )
            })?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material chunks must be in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

pub(super) fn public_evaluation_key_material_transport_hashes(
    chunks: &[Vec<u8>],
) -> CanonicalResult<PublicEvaluationKeyMaterialTransportHashes> {
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material transport requires at least one chunk",
        ));
    }
    let chunk_size = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material contains a short non-final chunk",
                    ));
                }
                byte_count
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public evaluation-key material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public evaluation-key material byte length overflowed",
                        )
                    })
            })?;
    let full_object_hash =
        public_evaluation_key_material_full_object_hash(total_byte_length, chunks);
    let chunk_hashes = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            public_evaluation_key_material_chunk_hash(&full_object_hash, chunk_index, chunk)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunk_root = derive_protocol_hash(
        "PublicEvaluationKeyMaterialChunkRoot",
        &json!({
            "objectType": "PublicEvaluationKeyMaterialChunkManifest",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": chunk_hashes.len(),
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )?;

    Ok(PublicEvaluationKeyMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

fn public_evaluation_key_material_full_object_hash(
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> String {
    let total_length_bytes = total_byte_length.to_le_bytes();
    let mut parts = Vec::with_capacity(chunks.len() + 1);
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    hash512_hex(
        "sealed-lattice/setup/public-evaluation-key-material/full-object-v1",
        &parts,
    )
}

fn public_evaluation_key_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let chunk_index_bytes = u64::try_from(chunk_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public evaluation-key material chunk index does not fit u64",
            )
        })?
        .to_le_bytes();

    Ok(hash512_hex(
        "sealed-lattice/setup/public-evaluation-key-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

fn verify_public_evaluation_key_material_hash_fields(
    value: &Value,
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
    value_name: &str,
) -> CanonicalResult<()> {
    let chunk_size = value_u64(value, "chunkSizeBytes")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialChunkSizeBytes"))?;
    let chunk_count = value_u64(value, "chunkCount")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialChunkCount"))?;
    let total_byte_length = value_u64(value, "totalByteLength")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialTotalByteLength"))?;
    let full_object_hash = value_string(value, "fullObjectHash")
        .or_else(|_| value_string(value, "publicEvaluationKeyMaterialFullObjectHash"))?;
    let chunk_root = value_string(value, "chunkRoot")
        .or_else(|_| value_string(value, "publicEvaluationKeyMaterialChunkRoot"))?;
    if chunk_size != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
        || chunk_count
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public evaluation-key material chunk count does not fit u64",
                )
            })?
        || total_byte_length != transport_hashes.total_byte_length
        || full_object_hash != transport_hashes.full_object_hash
        || chunk_root != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} hash metadata does not match supplied chunks"),
        ));
    }
    let chunk_hash_values = value
        .get("chunkHashes")
        .or_else(|| value.get("publicEvaluationKeyMaterialChunkHashes"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} must list every public evaluation-key material chunk hash"),
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} chunk hash count must match supplied chunks"),
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} chunk hashes must match supplied chunks"),
            ));
        }
    }

    Ok(())
}

pub(super) fn public_evaluation_key_material_reference_root(
    evaluation_keys: &Value,
    expected_manifest: &Value,
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicEvaluationKeyMaterialRoot",
        &json!({
            "objectType": "PublicEvaluationKeyMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
            "ceremonyId": value_string(evaluation_keys, "ceremonyId")?,
            "manifestHash": value_string(evaluation_keys, "manifestHash")?,
            "rosterHash": value_string(evaluation_keys, "rosterHash")?,
            "setupProfileHash": value_string(evaluation_keys, "setupProfileHash")?,
            "qShareHash": value_string(evaluation_keys, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": value_string(
                evaluation_keys,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": value_string(evaluation_keys, "commitmentProfileHash")?,
            "setupEpoch": value_string(evaluation_keys, "setupEpoch")?,
            "evaluatorKeyScheduleRoot": value_string(
                evaluation_keys,
                "evaluatorKeyScheduleRoot",
            )?,
            "sameSecretProofFamilyBindingRoot": value_string(
                evaluation_keys,
                "sameSecretProofFamilyBindingRoot",
            )?,
            "publicKeyShareLnpProofSetRoot": value_string(
                evaluation_keys,
                "publicKeyShareLnpProofSetRoot",
            )?,
            "relinearizationKeyShareRoundsRoot": value_string(
                evaluation_keys,
                "relinearizationKeyShareRoundsRoot",
            )?,
            "requiredGaloisSetHash": value_string(evaluation_keys, "requiredGaloisSetHash")?,
            "expectedMaterialManifest": expected_manifest,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

pub(super) fn public_evaluation_key_material_manifest(
    setup_package: &Value,
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "PublicEvaluationKeyMaterialManifest",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
        "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
        "materialTransportEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
        "ceremonyId": value_string(evaluation_keys, "ceremonyId")?,
        "manifestHash": value_string(evaluation_keys, "manifestHash")?,
        "rosterHash": value_string(evaluation_keys, "rosterHash")?,
        "setupProfileHash": value_string(evaluation_keys, "setupProfileHash")?,
        "qShareHash": value_string(evaluation_keys, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            evaluation_keys,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(evaluation_keys, "commitmentProfileHash")?,
        "setupEpoch": value_string(evaluation_keys, "setupEpoch")?,
        "participantCount": value_u64(evaluation_keys, "participantCount")?,
        "rnsLimbCount": value_u64(evaluation_keys, "rnsLimbCount")?,
        "evaluatorKeyScheduleRoot": value_string(evaluation_keys, "evaluatorKeyScheduleRoot")?,
        "sameSecretProofFamilyBindingRoot": value_string(
            evaluation_keys,
            "sameSecretProofFamilyBindingRoot",
        )?,
        "publicKeyShareLnpProofSetRoot": value_string(
            evaluation_keys,
            "publicKeyShareLnpProofSetRoot",
        )?,
        "relinearizationKeyShareRoundsRoot": value_string(
            evaluation_keys,
            "relinearizationKeyShareRoundsRoot",
        )?,
        "relinearizationLevelSchedule": evaluation_keys["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": evaluation_keys["relinearizationKeyRoots"],
        "relinearizationShareMaterialRoots": relinearization_share_material_manifest(setup_package)?,
        "requiredGaloisSetHash": value_string(evaluation_keys, "requiredGaloisSetHash")?,
        "requiredGaloisKeySchedule": evaluation_keys["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": evaluation_keys["galoisKeyShareBatchRoots"],
        "galoisKeyRoots": evaluation_keys["galoisKeyRoots"],
        "galoisShareMaterialRoots": galois_share_material_manifest(setup_package)?,
        "genericKeySwitchKeyRoots": evaluation_keys["genericKeySwitchKeyRoots"],
        "rawKeyBytesEmbedded": false,
        "verifierGeneratedKeyMaterial": false,
    }))
}

fn relinearization_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for (
        round_label,
        record_field_name,
        share_root_field_name,
        proof_root_field_name,
        record_root_field_name,
    ) in [
        (
            "round-one",
            "roundOneRecords",
            "roundOneShareRoot",
            "roundOneProofRoot",
            "roundOneRecordRoot",
        ),
        (
            "round-two",
            "roundTwoRecords",
            "roundTwoShareRoot",
            "roundTwoProofRoot",
            "roundTwoRecordRoot",
        ),
    ] {
        for record in array_value(rounds, record_field_name)? {
            entries.push((
                value_u64(record, "level")?,
                value_u64(record, "trusteeRosterPosition")?,
                if round_label == "round-one" {
                    0_u8
                } else {
                    1_u8
                },
                json!({
                    "round": round_label,
                    "trusteeIdentity": value_string(record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(record, "trusteeRosterPosition")?,
                    "level": value_u64(record, "level")?,
                    "keySwitchMaterialEncoding": value_string(record, "keySwitchMaterialEncoding")?,
                    "keySwitchDomain": value_string(record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "shareRoot": value_string(record, share_root_field_name)?,
                    "proofRoot": value_string(record, proof_root_field_name)?,
                    "recordRoot": value_string(record, record_root_field_name)?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(level, trustee_roster_position, round_order, _)| {
        (*level, *round_order, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

fn galois_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for batch in batches {
        for proof_record in array_value(batch, "galoisKeyShareProofs")? {
            entries.push((
                value_u64(proof_record, "rotation")?,
                value_u64(proof_record, "level")?,
                value_u64(proof_record, "trusteeRosterPosition")?,
                json!({
                    "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
                    "rotation": value_u64(proof_record, "rotation")?,
                    "level": value_u64(proof_record, "level")?,
                    "keySwitchMaterialEncoding": value_string(
                        proof_record,
                        "keySwitchMaterialEncoding",
                    )?,
                    "keySwitchDomain": value_string(proof_record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(proof_record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        proof_record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": proof_record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "galoisKeyShareRoot": value_string(proof_record, "galoisKeyShareRoot")?,
                    "galoisKeyShareProofRoot": value_string(
                        proof_record,
                        "galoisKeyShareProofRoot",
                    )?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(rotation, level, trustee_roster_position, _)| {
        (*rotation, *level, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

fn decode_public_evaluation_key_material_manifest(
    chunks: &[Vec<u8>],
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
) -> CanonicalResult<Value> {
    let total_byte_length = usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material byte length does not fit usize",
        )
    })?;
    let mut material_bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        material_bytes.extend_from_slice(chunk);
    }
    if material_bytes.len() < PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()
        || &material_bytes[..PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()]
            != PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material has the wrong format marker",
        ));
    }
    let manifest_bytes = &material_bytes[PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()..];
    let manifest: Value = serde_json::from_slice(manifest_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest is not valid JSON",
        )
    })?;
    if canonical_json(&manifest)?.as_bytes() != manifest_bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest must use canonical JSON bytes",
        ));
    }

    Ok(manifest)
}

#[cfg(test)]
pub(super) fn encode_public_evaluation_key_material_manifest(
    manifest: &Value,
) -> CanonicalResult<Vec<u8>> {
    let mut material_bytes = Vec::new();
    material_bytes.extend_from_slice(PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC);
    material_bytes.extend_from_slice(canonical_json(manifest)?.as_bytes());

    Ok(material_bytes)
}

fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
    request: &Value,
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
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let proof_context = EvaluationKeyProofVerificationContext {
        setup_package,
        request,
        same_secret_proof_bindings: &same_secret_proof_bindings,
        same_secret_records: &same_secret_records,
        transported_constant_commitments: &transported_constant_commitments,
        transported_key_switch_component_material: request
            .get("transportedEvaluationKeyShareComponentMaterial")
            .or(transported_key_switch_component_material.as_ref()),
    };
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
    let mut round_one_source_square_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_source_square_binding_roots = BTreeMap::<(u64, u64), String>::new();
    for record in round_one_records {
        let (level, trustee_roster_position, record_root, share_root, source_square_binding_root) =
            match verify_relinearization_round_one_record(record, &binding, &proof_context) {
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
        round_one_source_square_binding_roots.insert(
            (level, trustee_roster_position),
            source_square_binding_root.clone(),
        );
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_one_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity.clone(),
                "trusteeRosterPosition": trustee_roster_position,
                "roundOneRecordRoot": record_root,
            }));
        round_one_source_square_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "sourceSquareBindingRoot": source_square_binding_root,
            }));
    }

    let supplied_round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    let supplied_round_one_source_square_aggregate_roots =
        relinearization_aggregate_roots_by_level(
            rounds,
            "roundOneAggregateRoots",
            "roundOneSourceSquareAggregateRoot",
        )?;
    for level in &expected_levels {
        let Some(record_roots) = round_one_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelMissing",
                "relinearization round-one records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let Some(source_square_roots) = round_one_source_square_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneSourceSquareLevelMissing",
                "relinearization round-one records must cover source-square roots for every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let expected_source_square_aggregate_root = relinearization_source_square_aggregate_root(
            "round-one",
            binding.evaluator_key_schedule_root.as_str(),
            *level,
            source_square_roots,
            None,
        )?;
        if supplied_round_one_source_square_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_source_square_aggregate_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneSourceSquareAggregateRootMismatch",
                "relinearization round-one source-square aggregate root must be derived from the ordered round-one source-square bindings",
                "setupPackage.relinearizationKeyShareRounds.roundOneAggregateRoots",
            )?));
        }
        let expected_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "level": level,
                "roundOneSourceSquareAggregateRoot": expected_source_square_aggregate_root,
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
    let mut round_two_source_square_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut seen_round_two_records = BTreeSet::new();
    let round_one_state = RelinearizationRoundOneVerificationState {
        record_roots: &round_one_record_roots,
        share_roots: &round_one_share_roots,
        source_square_binding_roots: &round_one_source_square_binding_roots,
        aggregate_roots: &supplied_round_one_aggregate_roots,
        source_square_aggregate_roots: &supplied_round_one_source_square_aggregate_roots,
    };
    for record in round_two_records {
        let (level, trustee_roster_position, record_root, source_square_binding_root) =
            match verify_relinearization_round_two_record(
                record,
                &binding,
                &proof_context,
                &round_one_state,
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
                "trusteeIdentity": trustee_identity.clone(),
                "trusteeRosterPosition": trustee_roster_position,
                "roundTwoRecordRoot": record_root,
            }));
        round_two_source_square_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "sourceSquareBindingRoot": source_square_binding_root,
            }));
    }
    let supplied_round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;
    let supplied_round_two_source_square_aggregate_roots =
        relinearization_aggregate_roots_by_level(
            rounds,
            "roundTwoAggregateRoots",
            "roundTwoSourceSquareAggregateRoot",
        )?;
    for level in &expected_levels {
        let Some(record_roots) = round_two_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelMissing",
                "relinearization round-two records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let Some(source_square_roots) = round_two_source_square_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoSourceSquareLevelMissing",
                "relinearization round-two records must cover source-square roots for every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let round_one_source_square_aggregate_root = supplied_round_one_source_square_aggregate_roots
            .get(level)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "round-one source-square aggregate root was required before round-two verification",
                )
            })?;
        let expected_source_square_aggregate_root = relinearization_source_square_aggregate_root(
            "round-two",
            binding.evaluator_key_schedule_root.as_str(),
            *level,
            source_square_roots,
            Some(round_one_source_square_aggregate_root),
        )?;
        if supplied_round_two_source_square_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_source_square_aggregate_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoSourceSquareAggregateRootMismatch",
                "relinearization round-two source-square aggregate root must bind the ordered round-two bindings and the round-one source-square aggregate root",
                "setupPackage.relinearizationKeyShareRounds.roundTwoAggregateRoots",
            )?));
        }
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
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                "roundTwoSourceSquareAggregateRoot": expected_source_square_aggregate_root,
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

fn verify_galois_key_share_batches(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
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
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let proof_context = EvaluationKeyProofVerificationContext {
        setup_package,
        request,
        same_secret_proof_bindings: &same_secret_proof_bindings,
        same_secret_records: &same_secret_records,
        transported_constant_commitments: &transported_constant_commitments,
        transported_key_switch_component_material: request
            .get("transportedEvaluationKeyShareComponentMaterial")
            .or(transported_key_switch_component_material.as_ref()),
    };
    let expected_schedule = expected_required_galois_key_schedule()?;
    let mut seen_roster_positions = BTreeSet::new();
    for batch in batches {
        if let Err(error) = verify_galois_key_share_batch(
            batch,
            &binding,
            &proof_context,
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

fn expected_relinearization_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before evaluation-key assembly",
            )
        })?;
    let relinearization_key_share_rounds_root =
        value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    let round_one_source_square_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneSourceSquareAggregateRoot",
    )?;
    let round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;
    let round_two_source_square_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoSourceSquareAggregateRoot",
    )?;

    expected_relinearization_levels()
        .into_iter()
        .map(|level| {
            let round_one_aggregate_root =
                round_one_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-one aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let round_two_aggregate_root =
                round_two_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-two aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let round_one_source_square_aggregate_root =
                round_one_source_square_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-one source-square aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let round_two_source_square_aggregate_root =
                round_two_source_square_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-two source-square aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "relinearization level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let key_root = derive_protocol_hash(
                "RelinearizationKeyRoot",
                &json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                    "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                    "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
                    "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                    "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
                    "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                    "sameSecretProofFamilyBindingRoot": binding
                        .same_secret_proof_family_binding_root
                        .as_str(),
                    "publicKeyShareLnpProofSetRoot": binding
                        .public_key_share_lnp_proof_set_root
                        .as_str(),
                    "relinearizationKeyShareRoundsRoot": relinearization_key_share_rounds_root,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "roundOneAggregateRoot": round_one_aggregate_root,
                    "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                    "roundTwoAggregateRoot": round_two_aggregate_root,
                    "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
                }),
            )?;

            Ok(json!({
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "roundTwoSourceSquareAggregateRoot": round_two_source_square_aggregate_root,
                "relinearizationKeyRoot": key_root,
            }))
        })
        .collect()
}

fn expected_galois_batch_roots_for_evaluation_keys(
    setup_package: &Value,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let mut batch_roots = BTreeMap::<u64, Value>::new();
    for batch in batches {
        let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
        let trustee_identity = value_string(batch, "trusteeIdentity")?;
        let galois_key_share_batch_root = value_string(batch, "galoisKeyShareBatchRoot")?;
        if batch_roots
            .insert(
                trustee_roster_position,
                json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareBatchRoot": galois_key_share_batch_root,
                }),
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batches must not repeat a trustee roster position",
            ));
        }
    }

    Ok(batch_roots.into_values().collect())
}

fn expected_galois_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut ordered_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    ordered_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);

    expected_schedule
        .iter()
        .map(|schedule_entry| {
            let rotation = value_u64(schedule_entry, "rotation")?;
            let level = value_u64(schedule_entry, "level")?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "Galois key level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let mut contributing_share_roots = Vec::new();
            for (_, batch) in &ordered_batches {
                let trustee_identity = value_string(batch, "trusteeIdentity")?;
                let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
                let proof = galois_key_share_proof_for_schedule(batch, rotation, level)?;
                contributing_share_roots.push(json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareRoot": value_string(proof, "galoisKeyShareRoot")?,
                    "galoisKeyShareProofRoot": value_string(proof, "galoisKeyShareProofRoot")?,
                }));
            }
            let galois_key_root = derive_protocol_hash(
                "RotationKeyRoot",
                &json!({
                    "objectType": "GaloisKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                    "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                    "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
                    "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                    "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
                    "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                    "sameSecretProofFamilyBindingRoot": binding
                        .same_secret_proof_family_binding_root
                        .as_str(),
                    "publicKeyShareLnpProofSetRoot": binding
                        .public_key_share_lnp_proof_set_root
                        .as_str(),
                    "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
                    "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
                    "rotation": rotation,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "contributingShareRoots": contributing_share_roots,
                }),
            )?;

            Ok(json!({
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            }))
        })
        .collect()
}

fn galois_key_share_proof_for_schedule(
    batch: &Value,
    rotation: u64,
    level: u64,
) -> CanonicalResult<&Value> {
    array_value(batch, "galoisKeyShareProofs")?
        .iter()
        .find(|proof| {
            proof.get("rotation").and_then(Value::as_u64) == Some(rotation)
                && proof.get("level").and_then(Value::as_u64) == Some(level)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batch does not contain a required scheduled proof",
            )
        })
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

struct EvaluationKeyProofVerificationContext<'a> {
    setup_package: &'a Value,
    request: &'a Value,
    same_secret_proof_bindings: &'a BTreeMap<u64, SameSecretProofBinding>,
    same_secret_records: &'a BTreeMap<u64, Value>,
    transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
    transported_key_switch_component_material: Option<&'a Value>,
}

struct RelinearizationRoundOneVerificationState<'a> {
    record_roots: &'a BTreeMap<(u64, u64), String>,
    share_roots: &'a BTreeMap<(u64, u64), String>,
    source_square_binding_roots: &'a BTreeMap<(u64, u64), String>,
    aggregate_roots: &'a BTreeMap<u64, String>,
    source_square_aggregate_roots: &'a BTreeMap<u64, String>,
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

fn expected_relinearization_key_switch_component_polynomial_count() -> CanonicalResult<u64> {
    expected_relinearization_levels()
        .into_iter()
        .try_fold(0_u64, |total, level| {
            let digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "relinearization level overflowed while deriving HE certificate accounting",
                )
            })?;
            let component_polynomial_count =
                digit_count.checked_mul(digit_count).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "relinearization component polynomial count overflowed",
                    )
                })?;
            total
                .checked_add(component_polynomial_count)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "relinearization key polynomial count overflowed",
                    )
                })
        })
}

fn expected_galois_key_switch_component_polynomial_count() -> CanonicalResult<u64> {
    expected_required_galois_key_schedule()?
        .as_array()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "required Galois key schedule must be an array",
            )
        })?
        .iter()
        .try_fold(0_u64, |total, schedule_entry| {
            let level = value_u64(schedule_entry, "level")?;
            let digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "Galois key level overflowed while deriving HE certificate accounting",
                )
            })?;
            let component_polynomial_count =
                digit_count.checked_mul(digit_count).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "Galois component polynomial count overflowed",
                    )
                })?;
            total
                .checked_add(component_polynomial_count)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "Galois key polynomial count overflowed",
                    )
                })
        })
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

fn expected_relinearization_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "RelinearizationKeyShareSeed",
        &json!({
            "objectType": "RelinearizationKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "relinearization-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "relinearizationCrpRoot": binding.relinearization_crp_root.as_str(),
            "round": round,
            "level": level,
        }),
    )
}

fn expected_galois_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "GaloisKeyShareSeed",
        &json!({
            "objectType": "GaloisKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "galois-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
            "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
            "rotation": rotation,
            "level": level,
        }),
    )
}

fn verify_relinearization_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<()> {
    if value_string(record, "keySwitchDomain")? != "relinearization" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization key-switch domain must be shared relinearization material",
        ));
    }
    let expected_seed = expected_relinearization_key_switch_seed(binding, round, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization key-switch seed must be shared by scheduled level and round",
        ));
    }

    Ok(())
}

fn verify_galois_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<()> {
    let expected_domain = format!("galois-{rotation}");
    if value_string(record, "keySwitchDomain")? != expected_domain {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key-switch domain must match the scheduled rotation",
        ));
    }
    let expected_seed = expected_galois_key_switch_seed(binding, rotation, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key-switch seed must be shared by scheduled rotation and level",
        ));
    }

    Ok(())
}

fn accepted_setup_evaluation_key_records_use_profile_ring(
    setup_package: &Value,
) -> CanonicalResult<bool> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(false);
    };
    for field_name in ["roundOneRecords", "roundTwoRecords"] {
        for record in array_value(rounds, field_name)? {
            if value_u64(record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }
    let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    for batch in galois_batches {
        for proof_record in array_value(batch, "galoisKeyShareProofs")? {
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub(super) fn accepted_setup_public_relinearization_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<usize, KeySwitchKey>> {
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public relinearization key material loading",
            )
        })?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let mut records_by_level_and_trustee = BTreeMap::new();
    for record in round_two_records {
        if value_string(record, "objectType")? != RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must use round-two records",
            ));
        }
        let level = value_u64(record, "level")?;
        let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
        if records_by_level_and_trustee
            .insert((level, trustee_roster_position), record)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must not repeat a trustee record for a level",
            ));
        }
    }

    let expected_levels = expected_relinearization_levels();
    let expected_record_count = expected_levels
        .len()
        .checked_mul(FIRST_PROFILE_PARTICIPANT_COUNT as usize)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "accepted public relinearization key material record count overflowed",
            )
        })?;
    if records_by_level_and_trustee.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public relinearization key material requires one round-two record per scheduled level and trustee",
        ));
    }

    let mut relinearization_keys = BTreeMap::new();
    for level in expected_levels {
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "relinearization key level does not fit usize",
            )
        })?;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&binding, "round-two", level)?;
        let mut aggregate_component_b = None;
        for trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT {
            let proof_record = records_by_level_and_trustee
                .get(&(level, trustee_roster_position))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "accepted public relinearization key material is missing a trustee record for a scheduled level",
                    )
                })?;
            verify_relinearization_key_switch_sample_binding(
                proof_record,
                &binding,
                "round-two",
                level,
            )?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public relinearization key runtime material requires profile-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record(
                EvaluationKeyShareProofFamily::Relinearization,
                proof_record,
                transported_key_switch_component_material,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public relinearization key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            "relinearization",
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        relinearization_keys.insert(level_usize, key_switch_key);
    }

    Ok(relinearization_keys)
}

pub(super) fn accepted_setup_public_galois_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<(usize, usize), KeySwitchKey>> {
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public Galois key material loading",
            )
        })?;
    let mut sorted_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    sorted_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);
    if sorted_batches.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public Galois key material requires one proof batch per trustee",
        ));
    }
    let mut seen_trustee_roster_positions = BTreeSet::new();
    for (trustee_roster_position, _) in &sorted_batches {
        if !seen_trustee_roster_positions.insert(*trustee_roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public Galois key material must not repeat a trustee batch",
            ));
        }
    }
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut rotation_keys = BTreeMap::new();
    for schedule_entry in expected_schedule {
        let rotation = value_u64(schedule_entry, "rotation")?;
        let level = value_u64(schedule_entry, "level")?;
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key level does not fit usize",
            )
        })?;
        let rotation_usize = usize::try_from(rotation).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key rotation does not fit usize",
            )
        })?;
        let key_switch_domain = format!("galois-{rotation}");
        let key_switch_seed_hex = expected_galois_key_switch_seed(&binding, rotation, level)?;
        let mut aggregate_component_b = None;
        for (_, batch) in &sorted_batches {
            let proof_record = galois_key_share_proof_for_schedule(batch, rotation, level)?;
            verify_galois_key_switch_sample_binding(proof_record, &binding, rotation, level)?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public Galois key runtime material requires profile-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record(
                EvaluationKeyShareProofFamily::Galois,
                proof_record,
                transported_key_switch_component_material,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public Galois key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            &key_switch_domain,
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        rotation_keys.insert((rotation_usize, level_usize), key_switch_key);
    }

    Ok(rotation_keys)
}

fn add_accepted_key_switch_component_b(
    aggregate_component_b: &mut Option<Vec<Vec<Vec<u64>>>>,
    component_b: Vec<Vec<Vec<u64>>>,
    level: usize,
) -> CanonicalResult<()> {
    let primes = DATA_PRIMES.get(..=level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation level is outside Q_share",
        )
    })?;
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation digit count does not match its level",
        ));
    }
    match aggregate_component_b {
        None => {
            validate_key_switch_component_shape(&component_b, primes)?;
            *aggregate_component_b = Some(component_b);
        }
        Some(aggregate) => {
            validate_key_switch_component_shape(aggregate, primes)?;
            validate_key_switch_component_shape(&component_b, primes)?;
            for (digit_index, (aggregate_by_limb, component_by_limb)) in
                aggregate.iter_mut().zip(component_b.iter()).enumerate()
            {
                if aggregate_by_limb.len() != primes.len()
                    || component_by_limb.len() != primes.len()
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation limb count does not match its level",
                    ));
                }
                for (rns_limb_index, (aggregate_coefficients, component_coefficients)) in
                    aggregate_by_limb
                        .iter_mut()
                        .zip(component_by_limb.iter())
                        .enumerate()
                {
                    if aggregate_coefficients.len() != POLYNOMIAL_DEGREE
                        || component_coefficients.len() != POLYNOMIAL_DEGREE
                    {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "key-switch component aggregation requires profile-ring coefficient vectors",
                        ));
                    }
                    let modulus = primes[rns_limb_index];
                    for (coefficient, addend) in aggregate_coefficients
                        .iter_mut()
                        .zip(component_coefficients.iter())
                    {
                        *coefficient = add_mod(*coefficient, *addend, modulus)?;
                    }
                }
                if digit_index >= primes.len() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation digit index is outside its level",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_key_switch_component_shape(
    component_b: &[Vec<Vec<u64>>],
    primes: &[u64],
) -> CanonicalResult<()> {
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component digit count does not match its level",
        ));
    }
    for component_by_limb in component_b {
        if component_by_limb.len() != primes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "key-switch component limb count does not match its level",
            ));
        }
        for (rns_limb_index, coefficients) in component_by_limb.iter().enumerate() {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "key-switch component coefficient count must match the profile ring degree",
                ));
            }
            if coefficients
                .iter()
                .any(|coefficient| *coefficient >= primes[rns_limb_index])
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "key-switch component contains non-canonical Q_share residues",
                ));
            }
        }
    }

    Ok(())
}

fn verify_relinearization_round_one_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
) -> CanonicalResult<(u64, u64, String, String, String)> {
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
        proof_context.same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-one", level)?;
    let round_one_share_root = value_string(record, "roundOneShareRoot")?;
    validate_hash_string(round_one_share_root, "roundOneShareRoot")?;
    let source_square_binding_root = value_string(record, "sourceSquareBindingRoot")?;
    validate_hash_string(source_square_binding_root, "sourceSquareBindingRoot")?;
    let round_one_proof_root = value_string(record, "roundOneProofRoot")?;
    validate_hash_string(round_one_proof_root, "roundOneProofRoot")?;
    verify_relinearization_key_share_lnp_proof_record(
        record,
        proof_context,
        "roundOneProofRoot",
        round_one_proof_root,
    )?;
    let expected_source_square_binding_root =
        relinearization_source_square_binding_root(record, "round-one", round_one_share_root)?;
    if source_square_binding_root != expected_source_square_binding_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sourceSquareBindingRoot does not match the canonical relinearization source-square binding",
        ));
    }
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
        source_square_binding_root.to_string(),
    ))
}

fn verify_relinearization_round_two_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    round_one_state: &RelinearizationRoundOneVerificationState<'_>,
) -> CanonicalResult<(u64, u64, String, String)> {
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
        proof_context.same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-two", level)?;
    for field_name in [
        "roundOneShareRoot",
        "roundOneRecordRoot",
        "roundOneAggregateRoot",
        "roundOneSourceSquareBindingRoot",
        "roundOneSourceSquareAggregateRoot",
        "roundTwoShareRoot",
        "sourceSquareBindingRoot",
        "roundTwoProofRoot",
    ] {
        validate_hash_string(value_string(record, field_name)?, field_name)?;
    }
    let key = (level, trustee_roster_position);
    if round_one_state.record_roots.get(&key).map(String::as_str)
        != Some(value_string(record, "roundOneRecordRoot")?)
        || round_one_state.share_roots.get(&key).map(String::as_str)
            != Some(value_string(record, "roundOneShareRoot")?)
        || round_one_state
            .aggregate_roots
            .get(&level)
            .map(String::as_str)
            != Some(value_string(record, "roundOneAggregateRoot")?)
        || round_one_state
            .source_square_binding_roots
            .get(&key)
            .map(String::as_str)
            != Some(value_string(record, "roundOneSourceSquareBindingRoot")?)
        || round_one_state
            .source_square_aggregate_roots
            .get(&level)
            .map(String::as_str)
            != Some(value_string(record, "roundOneSourceSquareAggregateRoot")?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization round-two record must bind the accepted round-one record, share, aggregate, and source-square roots",
        ));
    }
    let round_two_proof_root = value_string(record, "roundTwoProofRoot")?;
    verify_relinearization_key_share_lnp_proof_record(
        record,
        proof_context,
        "roundTwoProofRoot",
        round_two_proof_root,
    )?;
    let source_square_binding_root = value_string(record, "sourceSquareBindingRoot")?;
    let expected_source_square_binding_root = relinearization_source_square_binding_root(
        record,
        "round-two",
        value_string(record, "roundTwoShareRoot")?,
    )?;
    if source_square_binding_root != expected_source_square_binding_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sourceSquareBindingRoot does not match the canonical relinearization source-square binding",
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

    Ok((
        level,
        trustee_roster_position,
        supplied_root.to_string(),
        source_square_binding_root.to_string(),
    ))
}

fn verify_galois_key_share_batch(
    batch: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
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
        proof_context.same_secret_proof_bindings,
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
    let proof_records = array_value(batch, "galoisKeyShareProofs")?;
    if proof_records.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one proof record per required schedule entry",
        ));
    }
    let mut proof_roots = Vec::new();
    for ((proof_record, root_entry), expected_entry) in proof_records
        .iter()
        .zip(key_roots.iter())
        .zip(expected_entries)
    {
        let rotation = value_u64(expected_entry, "rotation")?;
        let level = value_u64(expected_entry, "level")?;
        verify_galois_key_switch_sample_binding(proof_record, binding, rotation, level)?;
        let proof_root = verify_galois_key_share_lnp_proof_record(
            proof_record,
            batch,
            proof_context,
            root_entry,
            expected_entry,
        )?;
        proof_roots.push(json!({
            "rotation": value_u64(proof_record, "rotation")?,
            "level": value_u64(proof_record, "level")?,
            "galoisKeyShareProofRoot": proof_root,
        }));
    }
    let supplied_batch_proof_root = value_string(batch, "galoisKeyBatchProofRoot")?;
    let expected_batch_proof_root = derive_protocol_hash(
        "GaloisKeyBatchProofRoot",
        &json!({
            "objectType": "GaloisKeyBatchProofAggregate",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "galois-key-share",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "proofRoots": proof_roots,
        }),
    )?;
    if supplied_batch_proof_root != expected_batch_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyBatchProofRoot must be derived from the verified Galois proof records",
        ));
    }
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

fn verify_relinearization_key_share_lnp_proof_record(
    record: &Value,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    proof_root_field_name: &str,
    supplied_proof_root: &str,
) -> CanonicalResult<()> {
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    let same_secret_record = proof_context
        .same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearization proof must reference an accepted same-secret statement",
            )
        })?;
    verify_evaluation_key_lnp_proof_record_common_fields(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
    )?;
    let share_root_field_name = match proof_root_field_name {
        "roundOneProofRoot" => "roundOneShareRoot",
        "roundTwoProofRoot" => "roundTwoShareRoot",
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearization proof root field must identify round one or round two",
            ));
        }
    };
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(value_string(record, share_root_field_name)?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization proof share root must match the verified key-switch component vector root",
        ));
    }
    let proof_bytes = evaluation_key_share_lnp_proof_bytes_from_record(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
        proof_context.request,
    )?;
    verify_evaluation_key_lnp_proof_bytes_metadata(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
        &proof_bytes,
    )?;
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        proof_context.setup_package,
        trustee_roster_position,
        proof_context.transported_constant_commitments,
    )?;
    let setup_proof_binding = record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization proof setupProofBinding is required",
        )
    })?;
    let public_matrix_seed_hash = proof_context
        .setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before relinearization proof verification",
            )
        })?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Relinearization,
            public_matrix_seed_hash,
            proof_record: record,
            same_secret_statement_record: same_secret_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material: proof_context
                .transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    verify_evaluation_key_lnp_proof_transcript_metadata(record, &verification)?;
    let expected_proof_root = relinearization_key_share_proof_root(record, proof_root_field_name)?;
    if supplied_proof_root != expected_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization proof root does not match the canonical proof record",
        ));
    }

    Ok(())
}

fn verify_galois_key_share_lnp_proof_record(
    proof_record: &Value,
    batch: &Value,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    root_entry: &Value,
    expected_schedule_entry: &Value,
) -> CanonicalResult<String> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof record must be an object",
        ));
    }
    if let Some(unexpected_field) = unexpected_galois_key_share_proof_field(proof_record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("Galois key share proof contains unexpected field {unexpected_field}"),
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(GALOIS_KEY_SHARE_PROOF_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof objectType must be GaloisKeyShareProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof objectVersion must be 1",
        ));
    }
    for field_name in [
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
    ] {
        if proof_record.get(field_name) != batch.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("Galois key share proof {field_name} must match the parent batch"),
            ));
        }
    }
    if proof_record.get("rotation") != expected_schedule_entry.get("rotation")
        || proof_record.get("level") != expected_schedule_entry.get("level")
        || proof_record.get("rotation") != root_entry.get("rotation")
        || proof_record.get("level") != root_entry.get("level")
        || proof_record.get("galoisKeyShareRoot") != root_entry.get("galoisKeyShareRoot")
        || proof_record.get("keySwitchComponentVectorRoot") != root_entry.get("galoisKeyShareRoot")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key share proof must bind the scheduled rotation, level, and share root",
        ));
    }
    verify_evaluation_key_lnp_proof_record_common_fields(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
    )?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    let same_secret_record = proof_context
        .same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share proof must reference an accepted same-secret statement",
            )
        })?;
    let proof_bytes = evaluation_key_share_lnp_proof_bytes_from_record(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
        proof_context.request,
    )?;
    verify_evaluation_key_lnp_proof_bytes_metadata(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
        &proof_bytes,
    )?;
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        proof_context.setup_package,
        trustee_roster_position,
        proof_context.transported_constant_commitments,
    )?;
    let setup_proof_binding = proof_record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof setupProofBinding is required",
        )
    })?;
    let public_matrix_seed_hash = proof_context
        .setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before Galois proof verification",
            )
        })?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Galois,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record: same_secret_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material: proof_context
                .transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    verify_evaluation_key_lnp_proof_transcript_metadata(proof_record, &verification)?;
    let supplied_proof_root = value_string(proof_record, "galoisKeyShareProofRoot")?;
    let expected_proof_root = galois_key_share_proof_root(proof_record)?;
    if supplied_proof_root != expected_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyShareProofRoot does not match the canonical Galois proof record",
        ));
    }

    Ok(supplied_proof_root.to_string())
}

fn verify_evaluation_key_lnp_proof_record_common_fields(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
) -> CanonicalResult<()> {
    let expected_setup_proof_binding = setup_proof_record_binding_value()?;
    if proof_record.get("setupProofBinding") != Some(&expected_setup_proof_binding) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof setupProofBinding must match the accepted setup-proof profile",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        &expected_setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;
    let (expected_profile_id, tbox_profile_field_name, expected_tbox_hash) = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => (
            "sealed-lattice-relinearization-key-share-proof-lnp-v1",
            "relinearizationKeyShareTboxParameterProfileHash",
            super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()?,
        ),
        EvaluationKeyShareProofFamily::Galois => (
            "sealed-lattice-galois-key-share-proof-lnp-v1",
            "galoisKeyShareTboxParameterProfileHash",
            super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash()?,
        ),
    };
    if proof_record.get("proofProfileId").and_then(Value::as_str) != Some(expected_profile_id)
        || proof_record
            .get(tbox_profile_field_name)
            .and_then(Value::as_str)
            != Some(expected_tbox_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof profile fields must match the accepted verifier",
        ));
    }
    let material_encoding = proof_record
        .get("keySwitchMaterialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "evaluation-key proof keySwitchMaterialEncoding is required",
            )
        })?;
    match material_encoding {
        "embedded-full-key-switch-component-vectors" => {
            if proof_record.get("keySwitchComponentVectors").is_none()
                || proof_record.get("keySwitchComponentMaterialRoot").is_some()
                || proof_record
                    .get("keySwitchComponentChunkSizeBytes")
                    .is_some()
                || proof_record.get("keySwitchComponentChunkCount").is_some()
                || proof_record
                    .get("keySwitchComponentTotalByteLength")
                    .is_some()
                || proof_record
                    .get("keySwitchComponentFullObjectHash")
                    .is_some()
                || proof_record.get("keySwitchComponentChunkRoot").is_some()
                || proof_record.get("keySwitchComponentChunkHashes").is_some()
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "embedded evaluation-key proof material must include component vectors and no component transport reference",
                ));
            }
        }
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING => {
            if proof_record.get("keySwitchComponentVectors").is_some() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "binary evaluation-key proof material must not embed keySwitchComponentVectors",
                ));
            }
            for field_name in [
                "keySwitchComponentMaterialRoot",
                "keySwitchComponentChunkSizeBytes",
                "keySwitchComponentChunkCount",
                "keySwitchComponentTotalByteLength",
                "keySwitchComponentFullObjectHash",
                "keySwitchComponentChunkRoot",
                "keySwitchComponentChunkHashes",
            ] {
                if proof_record.get(field_name).is_none() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!("binary evaluation-key proof material requires {field_name}"),
                    ));
                }
            }
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "evaluation-key proof keySwitchMaterialEncoding is not accepted",
            ));
        }
    }
    validate_hash_string(
        value_string(proof_record, "keySwitchComponentVectorRoot")?,
        "evaluationKeyShareProof.keySwitchComponentVectorRoot",
    )?;
    if let Some(material_root) = proof_record
        .get("keySwitchComponentMaterialRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            material_root,
            "evaluationKeyShareProof.keySwitchComponentMaterialRoot",
        )?;
    }

    Ok(())
}

fn verify_evaluation_key_lnp_proof_bytes_metadata(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key LNP proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofSizeBytes must match supplied proof bytes",
        ));
    }
    if value_string(proof_record, "proofBytesHash")?
        != evaluation_key_share_lnp_relation_proof_bytes_hash(proof_family, proof_bytes)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofBytesHash must match supplied proof bytes",
        ));
    }

    Ok(())
}

fn verify_evaluation_key_lnp_proof_transcript_metadata(
    proof_record: &Value,
    verification: &super::evaluation_key_share_proof::EvaluationKeyShareLnpProofVerification,
) -> CanonicalResult<()> {
    let verified_proof_size = u64::try_from(verification.proof_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key verified proof byte length does not fit u64",
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
        || value_decimal_u64(proof_record, "challenge")? != verification.challenge
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof transcript metadata must match verified proof bytes",
        ));
    }
    verify_lnp_tbox_z34_metadata_fields(
        proof_record,
        LnpTboxZ34MetadataExpectation {
            z34_seed_material_hash: &verification.z34_seed_material_hash,
            z34_challenge_seed_hash: &verification.z34_challenge_seed_hash,
            z34_challenge_tail_hash: &verification.z34_challenge_tail_hash,
            z34_challenge_row_domain_hash: &verification.z34_challenge_row_domain_hash,
            z34_challenge_z3_row_set_hash: &verification.z34_challenge_z3_row_set_hash,
            z34_challenge_z4_row_set_hash: &verification.z34_challenge_z4_row_set_hash,
            tbox_lower_protocol_challenge_hash: &verification.tbox_lower_protocol_challenge_hash,
            z34_z3_check_window_hash: &verification.z34_z3_check_window_hash,
            z34_z4_check_window_hash: &verification.z34_z4_check_window_hash,
            z34_z3_l2_squared_decimal: &verification.z34_z3_l2_squared_decimal,
            z34_z4_infinity_norm_decimal: &verification.z34_z4_infinity_norm_decimal,
            proof_label: "evaluation-key LNP proof",
        },
    )?;

    Ok(())
}

struct LnpTboxZ34MetadataExpectation<'a> {
    z34_seed_material_hash: &'a str,
    z34_challenge_seed_hash: &'a str,
    z34_challenge_tail_hash: &'a str,
    z34_challenge_row_domain_hash: &'a str,
    z34_challenge_z3_row_set_hash: &'a str,
    z34_challenge_z4_row_set_hash: &'a str,
    tbox_lower_protocol_challenge_hash: &'a str,
    z34_z3_check_window_hash: &'a str,
    z34_z4_check_window_hash: &'a str,
    z34_z3_l2_squared_decimal: &'a str,
    z34_z4_infinity_norm_decimal: &'a str,
    proof_label: &'a str,
}

fn verify_lnp_tbox_z34_metadata_fields(
    proof_record: &Value,
    expectation: LnpTboxZ34MetadataExpectation<'_>,
) -> CanonicalResult<()> {
    for (field_name, expected_hash) in [
        ("z34SeedMaterialHash", expectation.z34_seed_material_hash),
        ("z34ChallengeSeedHash", expectation.z34_challenge_seed_hash),
        ("z34ChallengeTailHash", expectation.z34_challenge_tail_hash),
        (
            "z34ChallengeRowDomainHash",
            expectation.z34_challenge_row_domain_hash,
        ),
        (
            "z34ChallengeZ3RowSetHash",
            expectation.z34_challenge_z3_row_set_hash,
        ),
        (
            "z34ChallengeZ4RowSetHash",
            expectation.z34_challenge_z4_row_set_hash,
        ),
        (
            "tboxLowerProtocolChallengeHash",
            expectation.tbox_lower_protocol_challenge_hash,
        ),
        ("z34Z3CheckWindowHash", expectation.z34_z3_check_window_hash),
        ("z34Z4CheckWindowHash", expectation.z34_z4_check_window_hash),
    ] {
        if value_string(proof_record, field_name)? != expected_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{} {field_name} must match verified tbox proof bytes",
                    expectation.proof_label
                ),
            ));
        }
    }
    for (field_name, expected_decimal) in [
        (
            "z34Z3L2SquaredDecimal",
            expectation.z34_z3_l2_squared_decimal,
        ),
        (
            "z34Z4InfinityNormDecimal",
            expectation.z34_z4_infinity_norm_decimal,
        ),
    ] {
        if value_string(proof_record, field_name)? != expected_decimal {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{} {field_name} must match verified tbox proof bytes",
                    expectation.proof_label
                ),
            ));
        }
    }

    Ok(())
}

fn relinearization_key_share_proof_root(
    record: &Value,
    proof_root_field_name: &str,
) -> CanonicalResult<String> {
    let mut root_input = record.clone();
    let object = root_input
        .as_object_mut()
        .expect("relinearization proof record object was checked");
    object.remove(proof_root_field_name);
    match proof_root_field_name {
        "roundOneProofRoot" => {
            object.remove("roundOneRecordRoot");
        }
        "roundTwoProofRoot" => {
            object.remove("roundTwoRecordRoot");
        }
        _ => {}
    }
    derive_protocol_hash("RelinearizationKeyShareProofRoot", &root_input)
}

fn relinearization_source_square_binding_root(
    record: &Value,
    round: &str,
    share_root: &str,
) -> CanonicalResult<String> {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round(round)?;
    derive_protocol_hash(
        "RelinearizationSourceSquareBindingRoot",
        &json!({
            "objectType": "RelinearizationSourceSquareBinding",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "relinearization-key-share",
            "sourceRelation": source_relation,
            "sourceRelationStatus": source_relation_status,
            "round": round,
            "evaluatorKeyScheduleRoot": value_string(record, "evaluatorKeyScheduleRoot")?,
            "sameSecretProofSetRoot": value_string(record, "sameSecretProofSetRoot")?,
            "sameSecretProofFamilyBindingRoot": value_string(record, "sameSecretProofFamilyBindingRoot")?,
            "publicKeyShareLnpProofSetRoot": value_string(record, "publicKeyShareLnpProofSetRoot")?,
            "relinearizationCrpRoot": value_string(record, "relinearizationCrpRoot")?,
            "trusteeIdentity": value_string(record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(record, "trusteeRosterPosition")?,
            "level": value_u64(record, "level")?,
            "sameSecretStatementRoot": value_string(record, "sameSecretStatementRoot")?,
            "trusteeSecretCommitmentRoot": value_string(record, "trusteeSecretCommitmentRoot")?,
            "sameSecretProofRoot": value_string(record, "sameSecretProofRoot")?,
            "shareRoot": share_root,
            "keySwitchComponentVectorRoot": value_string(record, "keySwitchComponentVectorRoot")?,
            "statementHash": value_string(record, "statementHash")?,
            "relationCommitmentHash": value_string(record, "relationCommitmentHash")?,
            "proofBytesHash": value_string(record, "proofBytesHash")?,
        }),
    )
}

fn relinearization_source_square_aggregate_root(
    round: &str,
    evaluator_key_schedule_root: &str,
    level: u64,
    source_square_binding_roots: &[Value],
    round_one_source_square_aggregate_root: Option<&str>,
) -> CanonicalResult<String> {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round(round)?;
    let mut aggregate = json!({
        "objectType": "RelinearizationSourceSquareAggregate",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "relinearization-key-share",
        "sourceRelation": source_relation,
        "sourceRelationStatus": source_relation_status,
        "round": round,
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
        "level": level,
        "sourceSquareBindingRoots": source_square_binding_roots,
    });
    if let Some(round_one_source_square_aggregate_root) = round_one_source_square_aggregate_root {
        aggregate["roundOneSourceSquareAggregateRoot"] =
            json!(round_one_source_square_aggregate_root);
    }

    derive_protocol_hash("RelinearizationSourceSquareAggregateRoot", &aggregate)
}

fn relinearization_source_relation_for_round(
    round: &str,
) -> CanonicalResult<(&'static str, &'static str)> {
    match round {
        "round-one" => Ok((
            "same-secret-for-relinearization-round-one-source",
            "verified-by-round-one-same-secret-source-response",
        )),
        "round-two" => Ok((
            "same-secret-times-round-one-aggregate-for-relinearization-source",
            "verifier-checked-round-two-source-square-aggregate-binding",
        )),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization source relation round is outside the accepted schedule",
        )),
    }
}

fn galois_key_share_proof_root(proof_record: &Value) -> CanonicalResult<String> {
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("Galois proof record object was checked")
        .remove("galoisKeyShareProofRoot");
    derive_protocol_hash("GaloisKeyShareProofRoot", &root_input)
}

fn evaluation_key_share_lnp_proof_bytes_from_record(
    proof_family: EvaluationKeyShareProofFamily,
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
            "evaluation-key LNP proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof requires proofBytesHex or transported proof material",
        ));
    }
    if value_string(proof_record, "proofBytesEncoding")? != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "evaluationKeyShareProof.proofMaterialRoot",
    )?;
    let chunks = transported_evaluation_key_share_proof_material_chunks(
        request,
        proof_material_root,
        proof_family,
    )?;
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family.proof_family(),
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_evaluation_key_share_lnp_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: COLLECTIVE_BGV_SETUP_PROFILE_ID,
            proof_family: proof_family.proof_family(),
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
            "evaluation-key LNP proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }
    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "evaluation-key transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

fn verify_evaluation_key_share_lnp_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
        || value_u64(proof_record, "proofChunkCount")?
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "evaluation-key proof material chunk count does not fit u64",
                )
            })?
        || value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length
        || value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length
        || value_string(proof_record, "proofFullObjectHash")? != transport_hashes.full_object_hash
        || value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof transport reference does not match transported chunks",
        ));
    }
    let chunk_hash_values = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "evaluation-key LNP proofChunkHashes must list every transported proof chunk",
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "evaluation-key LNP proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_evaluation_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
    proof_family: EvaluationKeyShareProofFamily,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedEvaluationKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial was required by transported evaluation-key LNP proof records",
            )
        })?;
    let material_set_proof_family = material_set.get("proofFamily").and_then(Value::as_str);
    let material_set_family_matches = material_set_proof_family == Some("evaluation-key-share")
        || material_set_proof_family == Some(proof_family.proof_family());
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || !material_set_family_matches
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial header does not match the evaluation-key proof family",
        ));
    }
    let proof_materials = material_set
        .get("proofMaterials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial.proofMaterials must list proof material objects",
            )
        })?;
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        if proof_material.get("objectType").and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE)
            || proof_material.get("setupProfileId").and_then(Value::as_str)
                != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
            || proof_material
                .get("setupProofProfileId")
                .and_then(Value::as_str)
                != Some(SETUP_PROOF_PROFILE_ID)
            || proof_material
                .get("proofBytesEncoding")
                .and_then(Value::as_str)
                != Some(SETUP_PROOF_MATERIAL_ENCODING)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material header is invalid",
            ));
        }
        let proof_material_family = proof_material
            .get("proofFamily")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported evaluation-key proof material proofFamily is required",
                )
            })?;
        if proof_material_family != proof_family.proof_family() {
            if proof_material_family == "relinearization-key-share"
                || proof_material_family == "galois-key-share"
            {
                continue;
            }
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material proofFamily is invalid",
            ));
        }
        if value_string(proof_material, "proofMaterialRoot")? != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunk_values = proof_material
            .get("chunks")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported evaluation-key proof material chunks must be an array",
                )
            })?;
        let chunks = chunk_values
            .iter()
            .map(|chunk| {
                let bytes_hex = value_string(chunk, "bytesHex")?;
                decode_hex(bytes_hex)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let transport_hashes = setup_proof_material_transport_hashes(
            proof_family.proof_family(),
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        if value_u64(proof_material, "proofChunkSizeBytes")?
            != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
            || value_u64(proof_material, "proofChunkCount")?
                != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key proof material chunk count does not fit u64",
                    )
                })?
            || value_u64(proof_material, "proofTotalByteLength")?
                != transport_hashes.total_byte_length
            || value_string(proof_material, "proofFullObjectHash")?
                != transport_hashes.full_object_hash
            || value_string(proof_material, "proofChunkRoot")? != transport_hashes.chunk_root
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material hashes do not match chunks",
            ));
        }
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
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
            "sourceSquareBindingRoot",
            "roundOneProofRoot",
            "proofProfileId",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "relinearizationKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
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
            "roundOneSourceSquareBindingRoot",
            "roundOneSourceSquareAggregateRoot",
            "roundTwoShareRoot",
            "sourceSquareBindingRoot",
            "roundTwoProofRoot",
            "proofProfileId",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "relinearizationKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
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
            "galoisKeyShareProofs",
            "galoisKeyBatchProofRoot",
            "galoisKeyShareBatchRoot",
        ],
    )
}

fn unexpected_galois_key_share_proof_field(value: &Value) -> Option<String> {
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
            "proofProfileId",
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
            "rotation",
            "level",
            "galoisKeyShareRoot",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "galoisKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "galoisKeyShareProofRoot",
        ],
    )
}

fn unexpected_public_evaluation_key_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "assemblyStatus",
            "materialEncoding",
            "materialSource",
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
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "relinearizationKeyShareRoundsRoot",
            "relinearizationLevelSchedule",
            "relinearizationKeyRoots",
            "requiredGaloisSetHash",
            "requiredGaloisKeySchedule",
            "galoisKeyShareBatchRoots",
            "galoisKeyRoots",
            "genericKeySwitchKeyRoots",
            "rawKeyBytesEmbedded",
            "verifierGeneratedKeyMaterial",
            "publicEvaluationKeyMaterialEncoding",
            "publicEvaluationKeyMaterialRoot",
            "publicEvaluationKeyMaterialChunkSizeBytes",
            "publicEvaluationKeyMaterialChunkCount",
            "publicEvaluationKeyMaterialTotalByteLength",
            "publicEvaluationKeyMaterialFullObjectHash",
            "publicEvaluationKeyMaterialChunkRoot",
            "publicEvaluationKeyMaterialChunkHashes",
            "evaluationKeySetHash",
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
            "binaryFormat",
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
            "transport",
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
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
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

fn value_decimal_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    let field_value = value_string(value, field_name)?;
    if field_value.is_empty()
        || !field_value.bytes().all(|byte| byte.is_ascii_digit())
        || (field_value.len() > 1 && field_value.starts_with('0'))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a canonical decimal u64 string"),
        ));
    }
    field_value.parse::<u64>().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} does not fit u64"),
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

fn setup_commitment_security_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = setup_commitment_security_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("setup commitment security certificate is an object")
        .insert(
            "setupCommitmentSecurityCertificateHash".to_string(),
            json!(setup_commitment_security_certificate_hash()?),
        );

    Ok(certificate)
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
    if BigUint::from(max_threshold_lifted_coefficient) >= commitment_modulus_product {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "commitment modulus product does not cover threshold-share aggregate no-wrap bound",
        ));
    }
    let commitment_modulus_product_bits = setup_commitment_modulus_product_ceil_bits();

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
            "recipient-local private VSS proof witness checks",
            "verifier-derived threshold-share commitment roots",
            "same-secret trustee commitment roots",
        ],
        "nonClosure": [
            "public evaluation-key assembly and setup-package terminal acceptance remain separate from this commitment parameter certificate",
            "profile-scale binary streaming evidence remains separate from this commitment parameter certificate",
            "future target-decryption readiness remains outside this commitment parameter certificate",
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
            "freshMessageNoWrap": BigUint::from(max_source_message_modulus - 1)
                < commitment_modulus_product,
            "status": "claim-accounting-full-width-per-rns-message-bound-recorded",
        },
        "aggregateOpeningBounds": {
            "shamirCoefficientCount": FIRST_PROFILE_DECRYPTION_THRESHOLD,
            "maximumTrusteePoint": FIRST_PROFILE_PARTICIPANT_COUNT,
            "recipientScalarPowerSumDecimal": recipient_scalar_sum.to_string(),
            "recipientAggregateOpeningInfinityBound": recipient_scalar_sum_u64,
            "maxRecipientLiftedCoefficientDecimal": max_recipient_lifted_coefficient.to_string(),
            "sourceTrusteeCountForThresholdAggregation": FIRST_PROFILE_PARTICIPANT_COUNT,
            "thresholdScalarPowerSumDecimal": threshold_scalar_sum.to_string(),
            "thresholdShareOpeningInfinityBound": threshold_scalar_sum_u64,
            "maxThresholdLiftedCoefficientDecimal": max_threshold_lifted_coefficient.to_string(),
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "recipientAndThresholdNoWrap": true,
            "boundStatus": "claim-accounting-first-profile-homomorphic-opening-bounds-recorded",
        },
        "multiOpeningLeakage": {
            "recipientAggregateOpeningsArePublic": false,
            "recipientAggregateOpeningsAreMailboxPlaintext": false,
            "maxCorruptRecipientsBeforeThreshold": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "shamirPolynomialDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "rawCoefficientOpeningsExported": false,
            "perCoefficientRandomnessExported": false,
            "thresholdBoundary": "recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses",
            "status": "claim-accounting-active-static-threshold-leakage-bound-recorded",
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
            "estimatorStatus": "repo-owned-module-sis-parameter-accounting-accepted",
        },
        "hidingAssumption": {
            "assumption": "Module-LWE with recipient-hidden proof-witness opening leakage boundary",
            "openingDistribution": "coefficientwise-centered-ternary",
            "publicMatrixDistribution": "hash-derived-uniform-residue-stream",
            "lowEntropySecretHiding": true,
            "statisticalLeakageStatus": "repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-accepted",
            "estimatorStatus": "repo-owned-module-lwe-parameter-accounting-accepted",
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
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-SIS binding row under LNP22/FPS25 commitment references and no-wrap threshold-opening bounds"
            },
            {
                "rowId": "first-profile-module-lwe-hiding-row",
                "problem": "Module-LWE",
                "targetSecurityBits": 128,
                "ringDegree": POLYNOMIAL_DEGREE,
                "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
                "secretDistribution": "centered-ternary-opening",
                "modulusCeilBits": commitment_modulus_product_bits,
                "status": "claim-accounting-accepted",
                "accountingBasis": "accepted Module-LWE hiding row under LNP22/FPS25/ACC18 references and recipient-hidden opening leakage boundary"
            }
        ],
        "certificateStatus": "claim-bearing-setup-commitment-parameter-accounting-accepted",
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

fn verify_setup_proof_accounting_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("setupProofAccountingCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupProofAccountingCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificateNotObject",
            "setupProofAccountingCertificate must be a root-bound object",
            "setupPackage.setupProofAccountingCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("setupProofAccountingCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupProofAccountingCertificate.setupProofAccountingCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupProofAccountingCertificate.setupProofAccountingCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("setup proof accounting certificate object was checked")
        .remove("setupProofAccountingCertificateHash");
    let expected_body = setup_proof_accounting_certificate_value()?;
    if certificate_body != expected_body {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificatePayloadMismatch",
            "setupProofAccountingCertificate does not match the accepted setup proof accounting certificate",
            "setupPackage.setupProofAccountingCertificate",
        )?));
    }

    let expected_certificate_hash = setup_proof_accounting_certificate_hash()?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingCertificateHashMismatch",
            "setupProofAccountingCertificateHash does not match the canonical setup proof accounting certificate",
            "setupPackage.setupProofAccountingCertificate.setupProofAccountingCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("setupProofAccountingCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupProofAccountingCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupProofAccountingCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_proof_accounting_certificate_refusal(
            "setupProofAccountingPackageCertificateHashMismatch",
            "setupPackage.setupProofAccountingCertificateHash must match setupProofAccountingCertificate.setupProofAccountingCertificateHash",
            "setupPackage.setupProofAccountingCertificateHash",
        )?));
    }

    Ok(None)
}

pub(super) fn setup_proof_accounting_certificate_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_PROOF_ACCOUNTING_CERTIFICATE_HASH_NAMESPACE,
        &setup_proof_accounting_certificate_value()?,
    )
}

fn setup_proof_accounting_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = setup_proof_accounting_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("setup proof accounting certificate is an object")
        .insert(
            "setupProofAccountingCertificateHash".to_string(),
            json!(setup_proof_accounting_certificate_hash()?),
        );

    Ok(certificate)
}

fn setup_proof_family_accounting_value() -> Value {
    json!([
        {
            "proofFamily": "vss-opening-carry",
            "claimScope": "recipient-local private VSS share proof relation over accepted Q_share limbs",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "proof bytes hash, size, statement root, material root, statement-and-relation-bound tbox prefix, and scalar challenge are recomputed from canonical proof material",
                "accepted private VSS tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "four first-profile Shamir coefficient opening responses are checked against accepted coefficient commitments",
                "recipient-point lifted share equality and explicit carry responses are checked coefficientwise before acceptance",
                "message, randomness, and carry responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the recipient-local carry-aware VSS relation because statement binding, first-message commitments, generated tbox bytes, coefficient openings, carry relations, and response bounds are verified before acceptance",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 112-bit coefficient masks, opening-randomness masks, carry masks, verifier-bound no-wrap bounds, and transcript-bound tbox bytes; private coefficients, openings, and carries are not exposed in accepted public artifacts",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "same-secret-consistency",
            "claimScope": "same trustee secret across accepted VSS constant commitments",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds setup proof record binding, trustee statement roots, accepted constant commitment roots, and tbox profile hash",
                "relation commitment hash and scalar challenge are recomputed from proof commitments and canonical transcript fields",
                "accepted same-secret tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "ternary secret support is checked through Boolean negative-indicator and shifted-secret support equations",
                "all accepted Q_share constant commitments are checked against one shared secret response and opening randomness response",
                "secret, negative-indicator, and randomness responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the same-secret relation because the verifier binds one shared secret response to every accepted constant commitment and support equation",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit same-secret and support-response masks with witness-dependent support commitments treated as simulated first messages under the fixed relation and no-wrap response accounting",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "public-key-share",
            "claimScope": "public-key share relation bound to the accepted same-secret proof and public-key material roots",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds public-key share roots, same-secret statement roots, public matrix roots, coefficient vector hashes, and setup proof record binding",
                "relation commitment hash and scalar challenge are recomputed from public-key, support, and commitment-response commitments",
                "accepted public-key-share tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "same-secret opening response and ternary secret support are checked against accepted VSS constant commitments",
                "centered-binomial error support is checked for every accepted Q_share limb and coefficient",
                "lifted public-key equality PKShare_i,l - p*e_i,l + a_l*s_i + q_l*v_i,l = 0 is checked with explicit carry responses",
                "secret, negative-indicator, opening-randomness, and error responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the public-key share relation because same-secret openings, ternary support, centered-binomial error support, lifted no-wrap public-key equality, and fixed response bounds are verifier-bound",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit committed-secret masks, support commitments, error masks, opening masks, and carry masks with fixed-width signed relation commitments and no-wrap accounting",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "relinearization-key-share",
            "claimScope": "relinearization key-share relation bound to the same secret, round-one aggregate, and key-switch component roots",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds relinearization proof record roots, same-secret roots, transported key-switch component material when supplied, and setup proof record binding",
                "relation commitment hash and scalar challenge are recomputed from key-switch, source, carry, and commitment-response commitments",
                "accepted relinearization tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "same-secret opening response is checked against accepted VSS constant commitments",
                "round-one same-secret source responses and verifier-side round-two source-square aggregate roots are checked before runtime key material is accepted",
                "deterministic key-switch component vectors, centered-binomial errors, and lifted no-wrap carry responses are checked for scheduled relinearization levels",
                "secret, opening-randomness, error, source, and carry responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the relinearization key-share relation because same-secret source binding, key-switch component material, lifted no-wrap equations, round-two source-square aggregate roots, and response bounds are verifier-bound",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit committed-secret, error, source, opening, and carry response masks with transported public component vectors treated as public statement material",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
        {
            "proofFamily": "galois-key-share",
            "claimScope": "Galois key-share relation bound to the required automorphism schedule and key-switch component roots",
            "verifierClosedStatus": "relation-transcript-and-bound-checks-verifier-closed",
            "verifierClosedChecks": [
                "statement hash binds Galois proof record roots, required schedule roots, same-secret roots, transported key-switch component material when supplied, and setup proof record binding",
                "relation commitment hash and scalar challenge are recomputed from key-switch, source, carry, and commitment-response commitments",
                "accepted Galois tbox parameter profile is pinned, deterministic full-width commitment-prefix bytes are recomputed from statement and relation commitments, h coefficients at positions 0 and d/2 are enforced as zero, LaZer check_z34 seed material, challenge seed, challenge-tail hash, lower-protocol challenge hash, row-domain hash, full-width R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms are record-bound and enforced, generated z3/z4 check-window bounds are enforced, z1/z21 Gaussian L2 bounds and generated hint ranges are enforced, z34-bound lower-protocol challenge sampling is enforced, and generated lower-protocol tbox suffix bytes are decoded and enforced against the relation transcript",
                "same-secret opening response is checked against accepted VSS constant commitments",
                "required automorphism source response, deterministic key-switch component vectors, centered-binomial errors, and lifted no-wrap carry responses are checked for scheduled Galois keys",
                "secret, opening-randomness, error, source, and carry responses are checked against fixed first-profile bounds",
            ],
            "accountingStatus": "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted",
            "claimAccounting": {
                "soundness": "LNP22 commit-and-prove extractor accounting is accepted for the Galois key-share relation because same-secret source binding, automorphism source response, scheduled key-switch component material, lifted no-wrap equations, and response bounds are verifier-bound",
                "zeroKnowledge": "LNP22 simulator accounting is accepted for centered 80-bit committed-secret, error, automorphism-source, opening, and carry response masks with transported public component vectors treated as public statement material",
                "qrom": "DFM20/DFMS22 Fiat-Shamir reduction accounting is accepted through duplicate-free setup challenge domains and the setup proof theorem accounting object",
            },
        },
    ])
}

fn setup_proof_tbox_accounting_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofLnpTboxAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "generated-lower-protocol-tbox-profile-verifier-and-prover-closed",
        "closedProofFamilies": SETUP_PROOF_FAMILIES,
        "proofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "challengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "challengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "profileHashes": {
            "privateVssShareTboxParameterProfileHash": super::setup_proof::private_vss_share_lnp_tbox_parameter_profile_hash()?,
            "sameSecretTboxParameterProfileHash": super::setup_proof::same_secret_lnp_tbox_parameter_profile_hash()?,
            "publicKeyShareTboxParameterProfileHash": super::setup_proof::public_key_share_lnp_tbox_parameter_profile_hash()?,
            "relinearizationKeyShareTboxParameterProfileHash": super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()?,
            "galoisKeyShareTboxParameterProfileHash": super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash()?,
        },
        "challengeAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
            SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
            SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        )?,
        "commitmentPrefixGeneration": "setup proof generators encode full declared-width tB, h, and compressed tA1 residue bytes from a deterministic statement-and-relation binding seed with rejection sampling for proof-modulus residues and forced zero h coefficients at positions 0 and d/2",
        "commitmentPrefixVerifierBinding": "setup proof verifiers recompute the deterministic tbox prefix from statement hash, tbox profile hash, and encoded relation commitments, decode canonical fixed-width prefix residues, enforce h coefficients at positions 0 and d/2 as zero, and bind tboxCommitmentPrefixHash into the relation transcript",
        "z34SeedMaterialBinding": "setup proof verifiers extract LaZer check_z34 ty3, ty4, and tbeta seed material from tB after the fixed message-polynomial prefix, hash the canonical urandom3 encoding for later z3/z4 challenge binding, and require accepted proof records to carry the matching seed-material hash",
        "z34ChallengeSeedBinding": "setup proof verifiers derive the 32-byte check_z34 challenge seed from the statement hash, relation commitment hash, proof family, tbox profile, and canonical seed material, hash the current tB challenge-tail residues after tbeta, expand LaZer brandom k=1 ternary R/Rprime rows over the declared z3/z4 row widths with R domains 0..255 and Rprime domains 256..511, sample the proof-byte challenge polynomial from the lower-protocol challenge hash, then require accepted proof records to carry matching challenge-seed, challenge-tail, lower-protocol challenge, row-domain, z3 row-set, and z4 row-set hashes",
        "suffixVerifierBinding": "setup proof verifiers decode LaZer signed hint and Gaussian suffix values, hash the signed z3/z4 check-window values, compute z3 L2 squared and z4 infinity norm over the 256-coefficient check_z34 window, reject values above the generated LaZer Bz3sqr/Bz4 bounds, check z1/z21 Gaussian L2 bounds and generated hint ranges, and enforce the generated lower-protocol tbox suffix profile against the statement-and-relation-bound prefix",
        "closedVerifierChecks": [
            "deterministic statement-and-relation-bound full-width tbox commitment-prefix generation and verifier recomputation",
            "proof-record-bound LaZer check_z34 seed material, challenge seed, challenge tail, lower-protocol challenge hash, row domains, R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norms",
            "generated LaZer check_z34 256-coefficient z3/z4 norm-bound enforcement",
            "signed LaZer hint and Gaussian suffix decoding",
            "generated z1/z21 Gaussian L2 bound enforcement",
            "generated hint range enforcement",
            "h zero-position enforcement",
            "z34-bound lower-protocol challenge sampling",
            "generated lower-protocol tbox suffix byte-for-byte enforcement",
        ],
        "claimBoundary": "tbox proof-byte generation and verification are closed for the fixed setup proof profiles and feed the accepted setup proof soundness, zero-knowledge, and QROM accounting object",
    }))
}

fn setup_proof_scalar_relation_challenge_bits() -> CanonicalResult<usize> {
    let challenge_bits = [
        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
    ];
    let first_challenge_bits = challenge_bits[0];
    if challenge_bits
        .iter()
        .any(|candidate_bits| *candidate_bits != first_challenge_bits)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof scalar relation challenge bit counts must match across proof families",
        ));
    }

    Ok(first_challenge_bits)
}

fn setup_proof_fiat_shamir_transcript_accounting_value() -> CanonicalResult<Value> {
    let scalar_relation_challenge_bits = setup_proof_scalar_relation_challenge_bits()?;

    Ok(json!({
        "objectType": "SetupProofFiatShamirTranscriptAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "fiat-shamir-transcript-domain-and-challenge-input-accounting-closed",
        "qromReductionStatus": "repo-owned-qrom-reduction-theorem-accepted-for-setup-proof-claim",
        "challengeDomainHash": setup_proof_challenge_domain_hash()?,
        "challengeSpaceAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
            SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
            SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        )?,
        "challengeStages": [
            {
                "stageId": "lnp-polynomial-challenge",
                "domain": SETUP_PROOF_CHALLENGE_DOMAIN,
                "seedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
                "streamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
                "inputBinding": [
                    "proofFamily",
                    "statementHash",
                    "relationCommitmentHash"
                ],
                "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
                "challengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
                "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
            },
            {
                "stageId": "scalar-relation-challenge",
                "challengeBits": scalar_relation_challenge_bits,
                "nonzeroChallengeRequired": true,
                "inputBinding": [
                    "family-specific scalar challenge domain",
                    "statementHash",
                    "relationCommitmentHash",
                    "encoded LNP polynomial challenge coefficients",
                    "rejection block index"
                ],
                "familyDomains": [
                    {
                        "proofFamily": "vss-opening-carry",
                        "domain": PRIVATE_VSS_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "same-secret-consistency",
                        "domain": SAME_SECRET_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "public-key-share",
                        "domain": PUBLIC_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "relinearization-key-share",
                        "domain": RELINEARIZATION_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                    {
                        "proofFamily": "galois-key-share",
                        "domain": GALOIS_KEY_SHARE_LNP_SCALAR_CHALLENGE_DOMAIN,
                    },
                ],
            },
        ],
        "duplicateFreeInputAccounting": {
            "familyDomainSeparation": "scalar relation challenges use one fixed domain string per setup proof family",
            "stageSeparation": "polynomial challenge sampling and scalar relation challenge sampling use distinct domains and distinct encoded inputs",
            "statementBinding": "statement hashes include setup profile, trustee or schedule roots, accepted public material roots, and setup proof record binding before any challenge is derived",
            "firstMessageBinding": "relation commitment hashes bind the prover first-message commitments before the scalar relation challenge is derived",
            "tboxBinding": "tbox lower-protocol challenge hashes and z34 challenge metadata are bound to statement, relation commitment, proof family, tbox profile, and canonical seed material before accepted proof records are accepted",
        },
        "referenceRows": [
            {
                "document": "DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More",
                "localReferencePath": "reference-documents/DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More.txt",
                "sections": [
                    "Definition 11 Fiat-Shamir transformation for public-coin protocols",
                    "Remark 12 duplicate-free hash inputs through round indices or transcript/domain separation",
                    "Corollary 13 multi-round Fiat-Shamir in the QROM"
                ]
            },
            {
                "document": "DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM",
                "localReferencePath": "reference-documents/DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM.txt",
                "sections": [
                    "Section 3.4 Fiat-Shamir transformation of commit-and-open Sigma protocols",
                    "Remark 3.7 domain separation of random-oracle inputs",
                    "Theorem 4.2 online extractability of the Fiat-Shamir transformation"
                ]
            },
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Section 2.7 Challenge Space",
                    "Section 3 ABDLOP commitment scheme and proofs of linear relations",
                    "Appendix A knowledge soundness"
                ]
            }
        ],
        "claimBoundary": "Fiat-Shamir transcript domain separation, challenge input binding, challenge-space accounting, QROM reduction, and fixed-profile composition loss are accepted for setup proof-family claim accounting",
    }))
}

fn setup_proof_theorem_accounting_value() -> CanonicalResult<Value> {
    let scalar_relation_challenge_bits = setup_proof_scalar_relation_challenge_bits()?;

    Ok(json!({
        "objectType": "SetupProofTheoremAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "accountingStatus": "repo-owned-setup-proof-soundness-zero-knowledge-and-qrom-accounting-accepted",
        "acceptedClaimScope": [
            "private VSS share opening and carry proof relation",
            "same-secret consistency proof relation",
            "public-key share proof relation",
            "relinearization key-share proof relation",
            "Galois key-share proof relation",
        ],
        "soundnessAccounting": {
            "baseProtocol": "LNP22 AB-DLOP/LNP commit-and-prove linear-relation proof profile",
            "extractorModel": "repo-owned extractor mapping over verifier-closed statement roots, relation commitments, generated tbox bytes, response bounds, no-wrap lifted relations, and support equations",
            "knowledgeFailureEvents": [
                "noncanonical proof bytes",
                "statement or material root drift",
                "relation commitment drift",
                "generated tbox suffix drift",
                "challenge-domain replay across proof families",
                "response bound overflow",
                "lifted no-wrap violation",
                "support equation violation",
            ],
            "acceptedFailureLabel": "refused-before-claim-bearing-setup-acceptance",
        },
        "zeroKnowledgeAccounting": {
            "simulatorModel": "LNP22 commit-and-prove simulator for non-aborting transcripts with setup-family statements treated as public inputs",
            "responseMasking": "centered signed response masks are verifier-bound, no-wrap checked, and have positive masking slack for each committed-secret, error, opening, source, and carry response class",
            "supportCommitments": "witness-dependent support commitments are accounted as simulated first-message commitments bound to the accepted relation and response distributions",
            "witnessExportBoundary": "accepted proof records expose statement roots, commitments, proof bytes, roots, and public key material only; raw shares, trustee secrets, openings, errors, carries, and key-switch witnesses remain outside accepted public artifacts",
        },
        "qromReductionAccounting": {
            "model": "quantum-random-oracle-model",
            "transform": "Fiat-Shamir",
            "fixedProofFamilyCount": SETUP_PROOF_FAMILIES.len(),
            "challengeStageCount": 2,
            "lnpPolynomialChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
            "scalarRelationChallengeBits": scalar_relation_challenge_bits,
            "compositionStatus": "accepted-for-fixed-five-family-two-stage-setup-profile",
            "duplicateFreeInputStatus": "accepted-by-family-specific-domain-separation-and-stage-specific-transcript-inputs",
            "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        },
        "referenceRows": [
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "commit-and-prove simulatability",
                    "Lemma 4.3 knowledge soundness",
                    "Fiat-Shamir transformed knowledge soundness"
                ]
            },
            {
                "document": "DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More",
                "localReferencePath": "reference-documents/DFM20_The Measure-and-Reprogram Technique 2.0 Multi-Round Fiat-Shamir and More.txt",
                "sections": [
                    "Theorem 7 measure-and-reprogram with enforced extraction order",
                    "Corollary 13 multi-round Fiat-Shamir in the QROM",
                    "Corollary 15 preservation of soundness and proof of knowledge"
                ]
            },
            {
                "document": "DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM",
                "localReferencePath": "reference-documents/DFMS22_Efficient NIZKs and Signatures from Commit-and-Open Protocols in the QROM.txt",
                "sections": [
                    "Section 3.4 Fiat-Shamir transformation of commit-and-open Sigma protocols",
                    "Theorem 4.2 online extractability of the Fiat-Shamir transformation",
                    "Corollary 5.3 Fiat-Shamir soundness after parallel repetition"
                ]
            }
        ],
        "claimBoundary": "accepted only for setup proof families under CollectiveBgvSetup-v1; this does not close ballot proof soundness, evaluator replay, target decryption, supported-phone evidence, production audit readiness, or future proof-system families",
    }))
}

fn scalar_challenge_maximum_for_bits(bit_count: usize) -> CanonicalResult<u128> {
    let bit_count = u32::try_from(bit_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting challenge bit count overflowed",
        )
    })?;
    1_u128
        .checked_shl(bit_count)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge maximum overflowed",
            )
        })
}

fn response_mask_random_bound(mask_bits: usize) -> CanonicalResult<u128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting mask bit count overflowed",
        )
    })?;
    1_u128
        .checked_shl(mask_bits)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting mask bound overflowed",
            )
        })
}

fn response_mask_profile_value(
    response_kind: &str,
    mask_bits: usize,
    challenge_bits: usize,
    witness_infinity_bound: u128,
    mask_offset: u128,
    encoding_role: &str,
) -> CanonicalResult<Value> {
    let scalar_challenge_maximum = scalar_challenge_maximum_for_bits(challenge_bits)?;
    let random_mask_bound = response_mask_random_bound(mask_bits)?;
    let effective_mask_bound = random_mask_bound.checked_add(mask_offset).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting effective mask bound overflowed",
        )
    })?;
    let challenge_witness_term_bound = scalar_challenge_maximum
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge witness term overflowed",
            )
        })?;
    let response_bound = effective_mask_bound
        .checked_add(challenge_witness_term_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting response bound overflowed",
            )
        })?;
    let challenge_witness_term_bits =
        ceil_log2_u128(challenge_witness_term_bound.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting challenge term bit length overflowed",
            )
        })?);
    let masking_slack_bits = i64::try_from(mask_bits).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting mask bits do not fit i64",
        )
    })? - i64::from(challenge_witness_term_bits);

    Ok(json!({
        "responseKind": response_kind,
        "encodingRole": encoding_role,
        "maskRandomBits": mask_bits,
        "maskOffsetDecimal": mask_offset.to_string(),
        "effectiveMaskBoundDecimal": effective_mask_bound.to_string(),
        "scalarChallengeBits": challenge_bits,
        "scalarChallengeMaximumDecimal": scalar_challenge_maximum.to_string(),
        "witnessInfinityBoundDecimal": witness_infinity_bound.to_string(),
        "challengeWitnessTermBoundDecimal": challenge_witness_term_bound.to_string(),
        "challengeWitnessTermCeilBits": challenge_witness_term_bits,
        "responseBoundDecimal": response_bound.to_string(),
        "responseBoundCeilBits": ceil_log2_u128(response_bound),
        "maskingSlackBits": masking_slack_bits,
    }))
}

fn response_profile_bound(
    mask_bits: usize,
    challenge_bits: usize,
    witness_infinity_bound: u128,
    mask_offset: u128,
) -> CanonicalResult<u128> {
    let scalar_challenge_maximum = scalar_challenge_maximum_for_bits(challenge_bits)?;
    response_mask_random_bound(mask_bits)?
        .checked_add(mask_offset)
        .and_then(|mask_bound| {
            scalar_challenge_maximum
                .checked_mul(witness_infinity_bound)
                .and_then(|challenge_term| mask_bound.checked_add(challenge_term))
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting response bound overflowed",
            )
        })
}

fn lifted_message_no_wrap_value(
    relation_name: &str,
    secret_response_bound: u128,
    negative_indicator_response_bound: u128,
    max_source_message_modulus: u64,
    commitment_modulus_product: &BigUint,
) -> CanonicalResult<Value> {
    let lifted_bound = u128::from(max_source_message_modulus)
        .checked_mul(negative_indicator_response_bound)
        .and_then(|value| value.checked_add(secret_response_bound))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting lifted message bound overflowed",
            )
        })?;
    let lifted_bound_big = BigUint::from(lifted_bound);
    let no_wrap_satisfied = &lifted_bound_big < commitment_modulus_product;

    Ok(json!({
        "relationName": relation_name,
        "maxSourceMessageModulus": max_source_message_modulus,
        "secretResponseBoundDecimal": secret_response_bound.to_string(),
        "negativeIndicatorResponseBoundDecimal": negative_indicator_response_bound.to_string(),
        "liftedMessageResponseBoundDecimal": lifted_bound.to_string(),
        "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
        "noWrapSatisfied": no_wrap_satisfied,
    }))
}

fn setup_proof_response_masking_accounting_value() -> CanonicalResult<Value> {
    let max_source_message_modulus = DATA_PRIMES.iter().copied().max().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted Q_share prime list must not be empty",
        )
    })?;
    let commitment_modulus_product = setup_commitment_modulus_product();
    let profile_ring_degree = u128::try_from(POLYNOMIAL_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting ring degree does not fit u128",
        )
    })?;
    let private_vss_carry_witness_bound = scalar_power_sum(
        FIRST_PROFILE_DECRYPTION_THRESHOLD,
        FIRST_PROFILE_PARTICIPANT_COUNT,
    )?;
    let public_key_carry_witness_bound = profile_ring_degree.checked_add(3).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof response accounting public-key carry bound overflowed",
        )
    })?;
    let evaluation_key_carry_witness_bound = profile_ring_degree
        .checked_mul(2)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting evaluation-key carry bound overflowed",
            )
        })?;
    let evaluation_key_round_two_source_bound = profile_ring_degree
        .checked_mul(
            u128::try_from(EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND)
                .map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof response accounting source bound does not fit u128",
                    )
                })?,
        )
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof response accounting round-two source bound overflowed",
            )
        })?;
    let same_secret_response_bound = response_profile_bound(
        SAME_SECRET_MESSAGE_MASK_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_TERNARY_INFINITY_BOUND as u128,
        0,
    )?;
    let same_secret_negative_response_bound = response_profile_bound(
        SAME_SECRET_MESSAGE_MASK_BITS,
        SAME_SECRET_SCALAR_CHALLENGE_BITS,
        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
        0,
    )?;
    let public_key_secret_response_bound = response_profile_bound(
        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
        0,
    )?;
    let public_key_negative_response_bound = response_profile_bound(
        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
        0,
    )?;
    let evaluation_key_secret_response_bound = response_profile_bound(
        EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
        0,
    )?;

    Ok(json!({
        "objectType": "SetupProofResponseMaskingAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "accountingStatus": "response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted",
        "encodingConstraints": {
            "responseEncoding": "signed-i128-little-endian",
            "committedMessageEncoding": "u128-source-coefficients-and-centered-signed-response-coefficients-with-big-int-no-wrap-before-commitment-modulus-reduction",
            "relationCommitmentEncoding": "public-key and evaluation-key lifted relation commitments use fixed-width signed 32-byte little-endian big-integer coefficients; response vectors remain signed i128",
            "commitmentModulusProductDecimal": commitment_modulus_product.to_string(),
            "commitmentModulusProductCeilBits": setup_commitment_modulus_product_ceil_bits(),
            "maxSourceMessageModulus": max_source_message_modulus,
            "carryMaskWideningStatus": "carry masks remain 64 bits and scalar relation challenges are capped at 63 bits because carry responses and response vectors remain signed i128",
        },
        "families": [
            {
                "proofFamily": "vss-opening-carry",
                "responseProfiles": [
                    response_mask_profile_value(
                        "coefficient-message",
                        PRIVATE_VSS_SHARE_MESSAGE_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        u128::from(max_source_message_modulus - 1),
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        PRIVATE_VSS_SHARE_RANDOMNESS_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        PRIVATE_VSS_SHARE_CARRY_MASK_BITS,
                        PRIVATE_VSS_SHARE_SCALAR_CHALLENGE_BITS,
                        private_vss_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "fullWidthCoefficientMaskingStatus": "centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted",
                "commitmentNoWrapStatus": "three-limb-big-int-no-wrap-bound-recorded",
            },
            {
                "proofFamily": "same-secret-consistency",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        SAME_SECRET_MESSAGE_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SAME_SECRET_TERNARY_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "negative-indicator",
                        SAME_SECRET_MESSAGE_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SAME_SECRET_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        SAME_SECRET_RANDOMNESS_MASK_BITS,
                        SAME_SECRET_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    same_secret_response_bound,
                    same_secret_negative_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
            {
                "proofFamily": "public-key-share",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "negative-indicator",
                        PUBLIC_KEY_SHARE_MESSAGE_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_NEGATIVE_INDICATOR_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "error",
                        PUBLIC_KEY_SHARE_ERROR_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        PUBLIC_KEY_SHARE_ERROR_INFINITY_BOUND as u128,
                        0,
                        "signed-error-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        PUBLIC_KEY_SHARE_RANDOMNESS_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        PUBLIC_KEY_SHARE_CARRY_MASK_BITS,
                        PUBLIC_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        public_key_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    public_key_secret_response_bound,
                    public_key_negative_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
            {
                "proofFamily": "relinearization-key-share",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "error",
                        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND as u128,
                        0,
                        "signed-error-response",
                    )?,
                    response_mask_profile_value(
                        "round-two-source",
                        EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        evaluation_key_round_two_source_bound,
                        0,
                        "signed-source-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        evaluation_key_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    evaluation_key_secret_response_bound,
                    evaluation_key_secret_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
            {
                "proofFamily": "galois-key-share",
                "responseProfiles": [
                    response_mask_profile_value(
                        "secret",
                        EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
                        0,
                        "committed-message-response",
                    )?,
                    response_mask_profile_value(
                        "error",
                        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND as u128,
                        0,
                        "signed-error-response",
                    )?,
                    response_mask_profile_value(
                        "automorphism-source",
                        EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND as u128,
                        0,
                        "signed-source-response",
                    )?,
                    response_mask_profile_value(
                        "opening-randomness",
                        EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND as u128,
                        0,
                        "signed-opening-response",
                    )?,
                    response_mask_profile_value(
                        "lifted-carry",
                        EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
                        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
                        evaluation_key_carry_witness_bound,
                        0,
                        "signed-carry-response",
                    )?,
                ],
                "liftedMessageNoWrap": lifted_message_no_wrap_value(
                    "secret-plus-rns-prime-times-negative-indicator",
                    evaluation_key_secret_response_bound,
                    evaluation_key_secret_response_bound,
                    max_source_message_modulus,
                    &commitment_modulus_product,
                )?,
            },
        ],
        "zeroKnowledgeAccountingStatus": "response masking, witness-dependent support commitments, committed-secret response distributions, fixed-width signed relation commitments, and no-wrap response bounds are accepted by the setup proof theorem accounting object",
    }))
}

pub(super) fn setup_proof_accounting_certificate_value() -> CanonicalResult<Value> {
    let setup_proof_record_binding = setup_proof_record_binding_value()?;

    Ok(json!({
        "objectType": SETUP_PROOF_ACCOUNTING_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProfileHash": setup_profile_hash()?,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "setupProofRecordBinding": setup_proof_record_binding,
        "setupProofRecordBindingHash": setup_proof_record_binding_hash()?,
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "proofFamilyAccounting": setup_proof_family_accounting_value(),
        "tboxAccounting": setup_proof_tbox_accounting_value()?,
        "responseMaskingAccounting": setup_proof_response_masking_accounting_value()?,
        "fiatShamirTranscriptAccounting": setup_proof_fiat_shamir_transcript_accounting_value()?,
        "proofTheoremAccounting": setup_proof_theorem_accounting_value()?,
        "challengeAccounting": {
            "transform": "Fiat-Shamir",
            "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
            "challengeDomainHash": setup_proof_challenge_domain_hash()?,
            "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
            "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
            "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
            "challengeDifferenceInvertibilityAccounting": super::setup_proof::challenge_difference_invertibility_accounting_value()?,
            "challengeSpaceAudit": super::setup_proof::setup_proof_challenge_space_audit_value(SETUP_PROOF_LNP_PROOF_RING_DEGREE)?,
            "challengeSpaceAuditHash": super::setup_proof::setup_proof_challenge_space_audit_hash(
                SETUP_PROOF_CHALLENGE_SPACE_AUDIT_HASH_NAMESPACE,
                SETUP_PROOF_LNP_PROOF_RING_DEGREE,
            )?,
            "scalarRelationChallengePolicy": "per-family scalar relation challenges use 63 bits, capped by signed i128 carried relation arithmetic after the setup commitment no-wrap product moved to three selected limbs with big-integer accounting",
            "randomOracleModel": "Fiat-Shamir transcript accounting and repo-owned QROM reduction theorem are accepted for setup proof-family claim accounting",
            "qromStatus": "qrom-reduction-theorem-accepted-for-setup-proof-claim",
            "transcriptBinding": [
                "setupProfileHash",
                "manifestHash",
                "rosterHash",
                "setupEpoch",
                "publicMatrixSeedHash",
                "proofFamily",
                "statementRoot",
                "proofChunkRoot"
            ],
        },
        "completionBoundary": "claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate",
        "certificateStatus": "claim-bearing-setup-proof-accounting-accepted",
    }))
}

fn setup_proof_record_binding_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_PROOF_RECORD_BINDING_HASH_NAMESPACE,
        &setup_proof_record_binding_value()?,
    )
}

fn setup_proof_accounting_certificate_refusal(
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

fn verify_setup_key_correctness_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    if !setup_package_requires_setup_key_correctness_certificate(setup_package) {
        return Ok(None);
    }

    let Some(certificate) = setup_package.get("setupKeyCorrectnessCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupKeyCorrectnessCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificateNotObject",
            "setupKeyCorrectnessCertificate must be a root-bound object",
            "setupPackage.setupKeyCorrectnessCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("setupKeyCorrectnessCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("setup key correctness certificate object was checked")
        .remove("setupKeyCorrectnessCertificateHash");
    let expected_body = setup_key_correctness_certificate_value(setup_package)?;
    if certificate_body != expected_body {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificatePayloadMismatch",
            "setupKeyCorrectnessCertificate does not match the accepted setup key correctness certificate",
            "setupPackage.setupKeyCorrectnessCertificate",
        )?));
    }

    let expected_certificate_hash = setup_key_correctness_certificate_hash(setup_package)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessCertificateHashMismatch",
            "setupKeyCorrectnessCertificateHash does not match the canonical setup key correctness certificate",
            "setupPackage.setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("setupKeyCorrectnessCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.setupKeyCorrectnessCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.setupKeyCorrectnessCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(setup_key_correctness_certificate_refusal(
            "setupKeyCorrectnessPackageCertificateHashMismatch",
            "setupPackage.setupKeyCorrectnessCertificateHash must match setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash",
            "setupPackage.setupKeyCorrectnessCertificateHash",
        )?));
    }

    Ok(None)
}

fn setup_package_requires_setup_key_correctness_certificate(setup_package: &Value) -> bool {
    setup_package
        .get("evaluationKeys")
        .and_then(Value::as_object)
        .is_some_and(|evaluation_keys| !evaluation_keys.is_empty())
}

pub(super) fn setup_key_correctness_certificate_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        SETUP_KEY_CORRECTNESS_CERTIFICATE_HASH_NAMESPACE,
        &setup_key_correctness_certificate_value(setup_package)?,
    )
}

pub(super) fn setup_key_correctness_certificate_value(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup key correctness certificate verification",
        )
    })?;
    let collective_public_key_root = package_nested_hash(
        setup_package,
        "collectivePublicKey",
        "collectivePublicKeyRoot",
    )?;
    let public_key_share_material_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareMaterial",
        "publicKeyShareMaterialSetRoot",
    )?;
    let public_key_share_lnp_proof_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareLnpProofs",
        "publicKeyShareLnpProofSetRoot",
    )?;

    Ok(json!({
        "objectType": SETUP_KEY_CORRECTNESS_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(setup_context, "carryAwareVssShareRelationProfileHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupProofProfileBinding": "fixed-setup-proof-profile-bound-by-setup-proof-accounting-certificate",
        "keyCorrectnessScope": "collective-public-key-and-public-evaluation-key-roots-derived-from-proof-bearing-setup-records",
        "keyCorrectnessTheorem": {
            "theoremStatus": "repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots",
            "claimDependency": "terminal accepted setup verifies these roots before returning the accepted setup handoff",
            "checkedByVerifier": [
                "collective public-key coefficients are recomputed from publicKeyShareMaterial records and verified source roots",
                "collectivePublicKeyRoot is canonical and matches the top-level setup package root",
                "evaluationKeySetHash is canonical and binds the frozen evaluator schedule, relinearization rounds, and Galois batch records",
                "transported public evaluation-key runtime material is verified against evaluationKeys when supplied",
                "generic key-switch material and unscheduled Galois keys are refused for the first profile",
            ],
            "activeMaliciousPrototypeBoundary": "malformed roots, reordered trustee records, stale schedules, missing proof material, inconsistent collective public-key material, and unscheduled evaluation keys are refused before accepted runtime loading",
        },
        "collectivePublicKey": {
            "status": "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-LNP-proof-roots",
            "collectivePublicKeyRoot": collective_public_key_root,
            "sourceRoots": {
                "publicKeyShareSetRoot": package_nested_hash(setup_package, "publicKeyShares", "publicKeyShareSetRoot")?,
                "publicKeyShareProofSetRoot": package_nested_hash(setup_package, "publicKeyShareProofs", "publicKeyShareProofSetRoot")?,
                "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
                "publicKeyShareLnpProofSetRoot": public_key_share_lnp_proof_set_root,
            }
        },
        "publicEvaluationKeys": {
            "status": "public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records",
            "evaluationKeySetHash": package_nested_hash(setup_package, "evaluationKeys", "evaluationKeySetHash")?,
            "evaluatorKeyScheduleRoot": package_nested_hash(setup_package, "evaluatorKeySchedule", "evaluatorKeyScheduleRoot")?,
            "relinearizationKeyShareRoundsRoot": package_nested_hash(setup_package, "relinearizationKeyShareRounds", "relinearizationKeyShareRoundsRoot")?,
            "galoisKeyShareBatchRoots": setup_key_correctness_galois_batch_roots(setup_package)?,
            "requiredGaloisSetHash": package_nested_hash(setup_package, "evaluatorKeySchedule", "requiredGaloisSetHash")?,
        },
        "certificateDependencies": {
            "setupProofAccountingCertificateHash": value_string(setup_package, "setupProofAccountingCertificateHash")?,
            "heSecurityCertificateHash": value_string(setup_package, "heSecurityCertificateHash")?,
        },
        "claimBoundary": "key-correctness theorem is accepted for verified roots, loaded runtime material, and terminal accepted setup handoff construction",
    }))
}

fn verify_active_static_setup_theorem_certificate(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(certificate) = setup_package.get("activeStaticSetupTheoremCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["activeStaticSetupTheoremCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !certificate.is_object() {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificateNotObject",
            "activeStaticSetupTheoremCertificate must be a root-bound object",
            "setupPackage.activeStaticSetupTheoremCertificate",
        )?));
    }

    let certificate_hash = certificate
        .get("activeStaticSetupTheoremCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash is required",
            )
        })?;
    validate_hash_string(
        certificate_hash,
        "activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
    )?;

    let mut certificate_body = certificate.clone();
    certificate_body
        .as_object_mut()
        .expect("active-static setup theorem certificate object was checked")
        .remove("activeStaticSetupTheoremCertificateHash");
    let expected_body = active_static_setup_theorem_certificate_value(setup_package)?;
    if certificate_body != expected_body {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificatePayloadMismatch",
            "activeStaticSetupTheoremCertificate does not match the accepted active-static setup theorem certificate",
            "setupPackage.activeStaticSetupTheoremCertificate",
        )?));
    }

    let expected_certificate_hash = active_static_setup_theorem_certificate_hash(setup_package)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremCertificateHashMismatch",
            "activeStaticSetupTheoremCertificateHash does not match the canonical active-static setup theorem certificate",
            "setupPackage.activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
        )?));
    }
    let package_certificate_hash = setup_package
        .get("activeStaticSetupTheoremCertificateHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.activeStaticSetupTheoremCertificateHash is required",
            )
        })?;
    validate_hash_string(
        package_certificate_hash,
        "setupPackage.activeStaticSetupTheoremCertificateHash",
    )?;
    if package_certificate_hash != certificate_hash {
        return Ok(Some(active_static_setup_theorem_certificate_refusal(
            "activeStaticSetupTheoremPackageCertificateHashMismatch",
            "setupPackage.activeStaticSetupTheoremCertificateHash must match activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash",
            "setupPackage.activeStaticSetupTheoremCertificateHash",
        )?));
    }

    Ok(None)
}

pub(super) fn active_static_setup_theorem_certificate_hash(
    setup_package: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_HASH_NAMESPACE,
        &active_static_setup_theorem_certificate_value(setup_package)?,
    )
}

pub(super) fn active_static_setup_theorem_certificate_value(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before active-static setup theorem certificate verification",
        )
    })?;
    let evaluation_keys_declared = setup_package_declares_public_runtime_material(setup_package);

    Ok(json!({
        "objectType": ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(setup_context, "carryAwareVssShareRelationProfileHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "adversaryModel": {
            "corruptionTiming": "active-static",
            "maliciousBehavior": "arbitrary-invalid-public-setup-artifacts-and-abort",
            "secretConfidentialityCorruptTrusteeBound": FIRST_PROFILE_DECRYPTION_THRESHOLD - 1,
            "fullRosterSetupCompletionRequired": true,
        },
        "livenessModel": {
            "model": "secure-with-abort",
            "setupCompletionQuorum": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
            "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedAbortEvents": [
                "missing required setup phase object",
                "malformed public setup object",
                "invalid private VSS acceptance state",
                "invalid setup proof or proof material root",
                "invalid collective public-key or evaluation-key root",
                "unsupported target-decryption readiness claim",
            ],
            "notClaimed": [
                "guaranteed output delivery",
                "identifiable abort",
                "post-setup target decryption",
                "production audit readiness",
            ],
        },
        "verifiedSetupGates": [
            "setup context and package hash bind the ceremony, roster, manifest, profile, Q_share, commitment profile, and setup epoch",
            "full-roster common randomness commit/reveal records derive public setup matrices before proof and key verification",
            "public VSS coefficient commitments and recipient-local signed acceptances are checked before threshold-share commitment derivation",
            "threshold-share commitment roots are verifier-derived from public VSS commitments, not source-trustee supplied",
            "same-secret, public-key share, relinearization, and Galois proof records are verified before key roots are accepted",
            "collective public-key coefficients and public evaluation-key roots are verifier-recomputed from proof-bearing setup records",
            "setup commitment, proof-accounting, transport, HE, and key-correctness certificates are root-bound package objects",
            "generic key-switch material, unscheduled Galois keys, raw setup witnesses, raw shares, external aggregate public-key material, and premature target-decryption readiness are refused",
        ],
        "dependencyHashes": {
            "setupCommitmentSecurityCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupCommitmentSecurityCertificateHash",
            )?,
            "setupTransportCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupTransportCertificateHash",
            )?,
            "setupProofAccountingCertificateHash": required_top_level_hash_value(
                setup_package,
                "setupProofAccountingCertificateHash",
            )?,
            "heSecurityCertificateHash": required_top_level_hash_value(
                setup_package,
                "heSecurityCertificateHash",
            )?,
            "setupKeyCorrectnessCertificateHash": optional_top_level_hash_value(
                setup_package,
                "setupKeyCorrectnessCertificateHash",
            )?,
        },
        "terminalRoots": {
            "thresholdShareCommitmentRoot": optional_top_level_hash_value(
                setup_package,
                "thresholdShareCommitmentRoot",
            )?,
            "sameSecretProofSetRoot": optional_nested_hash_value(
                setup_package,
                "sameSecretProofs",
                "sameSecretProofSetRoot",
            )?,
            "publicKeyShareMaterialSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareMaterial",
                "publicKeyShareMaterialSetRoot",
            )?,
            "publicKeyShareLnpProofSetRoot": optional_nested_hash_value(
                setup_package,
                "publicKeyShareLnpProofs",
                "publicKeyShareLnpProofSetRoot",
            )?,
            "collectivePublicKeyRoot": optional_nested_hash_value(
                setup_package,
                "collectivePublicKey",
                "collectivePublicKeyRoot",
            )?,
            "evaluatorKeyScheduleRoot": optional_nested_hash_value(
                setup_package,
                "evaluatorKeySchedule",
                "evaluatorKeyScheduleRoot",
            )?,
            "evaluationKeySetHash": optional_nested_hash_value(
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
        "referenceRows": [
            {
                "document": "BCD25_Threshold (Fully) Homomorphic Encryption",
                "localReferencePath": "reference-documents/BCD25_Threshold (Fully) Homomorphic Encryption.txt",
                "sections": [
                    "active-with-abort security model",
                    "static malicious adversaries",
                    "threshold FHE setup and abort boundaries"
                ]
            },
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Fiat-Shamir with aborts",
                    "commit-and-prove simulatability",
                    "knowledge soundness"
                ]
            },
            {
                "document": "BFM25_Threshold FHE with Efficient Asynchronous Decryption",
                "localReferencePath": "reference-documents/BFM25_Threshold FHE with Efficient Asynchronous Decryption.txt",
                "sections": [
                    "malicious participant detection",
                    "setup preprocessing",
                    "abort behavior"
                ]
            }
        ],
        "claimBoundary": {
            "certificateStatus": "active-static-secure-with-abort-theorem-accepted",
            "evaluationKeyCorrectnessStatus": if evaluation_keys_declared {
                "requires-setup-key-correctness-certificate"
            } else {
                "no-public-evaluation-key-runtime-material-declared"
            },
            "remainingDependencies": [],
            "integrationDependencies": [],
            "completionBoundary": "external validation, independent audit, and third-party proof review are not setup completion prerequisites",
        },
    }))
}

fn required_top_level_hash_value(
    setup_package: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    let hash_value = value_string(setup_package, field_name)?;
    validate_hash_string(hash_value, field_name)?;

    Ok(json!(hash_value))
}

fn optional_top_level_hash_value(
    setup_package: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    optional_hash_value(setup_package.get(field_name), field_name)
}

fn optional_nested_hash_value(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<Value> {
    let Some(object_value) = setup_package.get(object_field_name) else {
        return Ok(Value::Null);
    };
    optional_hash_value(
        object_value.get(hash_field_name),
        &format!("setupPackage.{object_field_name}.{hash_field_name}"),
    )
}

fn optional_hash_value(value: Option<&Value>, field_path: &str) -> CanonicalResult<Value> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    let Some(hash_value) = value.as_str() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_path} must be a string when present"),
        ));
    };
    validate_hash_string(hash_value, field_path)?;

    Ok(json!(hash_value))
}

fn active_static_setup_theorem_certificate_refusal(
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

fn package_nested_hash(
    setup_package: &Value,
    object_field_name: &str,
    hash_field_name: &str,
) -> CanonicalResult<String> {
    setup_package
        .get(object_field_name)
        .and_then(|object| object.get(hash_field_name))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupPackage.{object_field_name}.{hash_field_name} is required"),
            )
        })
}

fn setup_key_correctness_galois_batch_roots(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches were required before setup key correctness certificate verification",
            )
        })?;
    batches
        .iter()
        .map(|batch| {
            Ok(json!({
                "trusteeIdentity": value_string(batch, "trusteeIdentity")?,
                "trusteeRosterPosition": value_u64(batch, "trusteeRosterPosition")?,
                "galoisKeyShareBatchRoot": value_string(batch, "galoisKeyShareBatchRoot")?,
            }))
        })
        .collect()
}

fn setup_key_correctness_certificate_refusal(
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

fn accepted_he_security_certificate_with_hash_value() -> CanonicalResult<Value> {
    let mut certificate = accepted_he_security_certificate_value()?;
    certificate
        .as_object_mut()
        .expect("HE security certificate is an object")
        .insert(
            "heSecurityCertificateHash".to_string(),
            json!(accepted_he_security_certificate_hash()?),
        );

    Ok(certificate)
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
    let accepted_relinearization_key_polynomials =
        expected_relinearization_key_switch_component_polynomial_count()?;
    let accepted_galois_key_polynomials = expected_galois_key_switch_component_polynomial_count()?;

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
            "certificateStatus": "accepted-for-direct-evaluator-replay-HE-parameter-boundary"
        },
        "publicSampleAccounting": {
            "publicKeyCrpPolynomials": 1,
            "publicKeyShareCount": FIRST_PROFILE_PARTICIPANT_COUNT,
            "acceptedRelinearizationKeyPolynomials": accepted_relinearization_key_polynomials,
            "acceptedGaloisKeyPolynomials": accepted_galois_key_polynomials,
            "scheduledRelinearizationLevelCount": scheduled_relinearization_level_count,
            "scheduledGaloisKeyCount": required_galois_key_count,
            "evaluationKeyExposureStatus": "root-bound-relinearization-and-galois-key-material-counted-for-direct-evaluator-replay-HE-boundary",
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
        "parameterBoundary": {
            "certificateStatus": if post_quantum_accepted && classical_accepted {
                "accepted-for-direct-setup-and-evaluator-HE-parameter-boundary"
            } else {
                "rejected-by-local-HE-standard-table-row"
            },
            "acceptedScope": "current Q_data/Q_share direct evaluator replay and accepted setup public key/evaluation-key exposure",
            "excludedScope": "Q_target, target decryption, smudging, C1-C4, and downstream decryption-share proof material",
            "proofDependency": "proof soundness and zero-knowledge certificates remain separate from this HE parameter certificate",
        },
        "acceptedForDirectEvaluatorReplay": post_quantum_accepted && classical_accepted,
        "acceptedForTargetDecryption": false,
        "statusLabels": if post_quantum_accepted && classical_accepted {
            vec![
                "HEStandardPostQuantum128Accepted",
                "HEStandardClassical128Accepted",
                "DataBasisLargestExposedModulusAccepted",
                "DirectSetupEvaluatorHeParameterBoundaryAccepted",
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

fn verify_transport_certificate(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(transport_certificate) = setup_package.get("setupTransportCertificate") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["setupTransportCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    match verify_transport_certificate_body(setup_package, request, transport_certificate)? {
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
    request: &Value,
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

    let aggregate = transport_canonical_try!(verify_setup_transported_objects(
        setup_package,
        request,
        transport_certificate,
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "totalByteLength",
        aggregate.total_byte_length,
        "transportTotalByteLengthMismatch",
        "setupTransportCertificate.totalByteLength must match the aggregate byte count of transported setup objects",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkCount",
        aggregate.chunk_count,
        "transportChunkCountMismatch",
        "setupTransportCertificate.chunkCount must match the aggregate transported-object chunk count",
    ));
    let full_object_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "fullObjectHash",
        "transportFullObjectHashMissing",
        "setupTransportCertificate.fullObjectHash is required",
    ));
    if full_object_hash != aggregate.full_object_hash {
        return Ok(Err(Refusal::new(
            "transportFullObjectHashMismatch",
            "setupTransportCertificate.fullObjectHash must match the aggregate transported-object set hash",
            "setupPackage.setupTransportCertificate.fullObjectHash",
        )));
    }
    let chunk_hashes = transport_canonical_try!(transport_chunk_hashes(
        transport_certificate,
        aggregate.chunk_count as usize
    ));
    if chunk_hashes != aggregate.chunk_hashes {
        return Ok(Err(Refusal::new(
            "transportChunkHashesMismatch",
            "setupTransportCertificate.chunkHashes must concatenate the transported-object chunk hashes in order",
            "setupPackage.setupTransportCertificate.chunkHashes",
        )));
    }
    let chunk_root = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "chunkRoot",
        "transportChunkRootMissing",
        "setupTransportCertificate.chunkRoot is required",
    ));
    if chunk_root != aggregate.chunk_root {
        return Ok(Err(Refusal::new(
            "transportChunkRootMismatch",
            "setupTransportCertificate.chunkRoot must match the aggregate transported-object chunk manifest",
            "setupPackage.setupTransportCertificate.chunkRoot",
        )));
    }

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
            "chunkHashes",
            "fullObjectHash",
            "encoding",
            "loadingPolicy",
        ],
    )
}

fn verify_setup_transported_objects(
    setup_package: &Value,
    request: &Value,
    transport_certificate: &Value,
) -> CanonicalResult<Result<SetupTransportAggregate, Refusal>> {
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let transported_object_values = match transport_certificate
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
    if transported_object_values.is_empty() {
        return Ok(Err(Refusal::new(
            "transportedObjectsEmpty",
            "setupTransportCertificate.transportedObjects must bind at least the full public VSS material object",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    let mut transported_objects = Vec::with_capacity(transported_object_values.len());
    let mut seen_object_roots = BTreeSet::new();
    let mut expected_chunk_start_index = 0_u64;
    for (object_index, transported_object_value) in transported_object_values.iter().enumerate() {
        let transported_object = transport_canonical_try!(setup_transported_object_binding(
            transported_object_value,
            object_index,
            expected_chunk_start_index,
            &mut seen_object_roots,
        ));
        expected_chunk_start_index = expected_chunk_start_index
            .checked_add(transported_object.chunk_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "setup transport chunk count overflowed",
                )
            })?;
        transported_objects.push(transported_object);
    }
    let total_byte_length =
        transported_objects
            .iter()
            .try_fold(0_u64, |byte_length, transported_object| {
                byte_length
                    .checked_add(transported_object.byte_length)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport total byte length overflowed",
                        )
                    })
            })?;
    let chunk_count =
        transported_objects
            .iter()
            .try_fold(0_u64, |chunk_count, transported_object| {
                chunk_count
                    .checked_add(transported_object.chunk_count)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport aggregate chunk count overflowed",
                        )
                    })
            })?;
    let chunk_hashes = transported_objects
        .iter()
        .flat_map(|transported_object| transported_object.chunk_hashes.clone())
        .collect::<Vec<_>>();
    let full_object_hash = setup_transport_full_object_set_hash(
        &transported_objects,
        total_byte_length,
        chunk_count,
        &chunk_hashes,
    )?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    let vss_material_root = package_nested_hash(
        setup_package,
        "vssCoefficientCommitmentMaterial",
        "vssCoefficientCommitmentMaterialRoot",
    )?;
    let expected_vss_material_byte_length = setup_transport_vss_material_byte_length()?;
    let expected_vss_chunk_count = setup_transport_chunk_count(expected_vss_material_byte_length)?;
    let Some(vss_object) = transported_objects.iter().find(|transported_object| {
        transported_object.object_name == SETUP_TRANSPORTED_VSS_MATERIAL_NAME
            && transported_object.object_role == SETUP_TRANSPORTED_VSS_MATERIAL_ROLE
            && transported_object.object_root == vss_material_root
    }) else {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMissing",
            "setupTransportCertificate.transportedObjects must bind vssCoefficientCommitmentMaterial",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    };
    if vss_object.byte_length != expected_vss_material_byte_length
        || vss_object.chunk_count != expected_vss_chunk_count
    {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMetadataMismatch",
            "vssCoefficientCommitmentMaterial transported object metadata must match the accepted setup profile",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    transport_canonical_try!(verify_binary_vss_material_transport_reference(
        setup_package,
        vss_object.byte_length,
        vss_object.chunk_count,
        &vss_object.chunk_root,
        &vss_object.full_object_hash,
    ));
    let mut expected_transported_object_roots = BTreeSet::new();
    expected_transported_object_roots.insert(vss_material_root);
    transport_canonical_try!(verify_setup_transport_request_bindings(
        setup_package,
        request,
        &transported_objects,
        &mut expected_transported_object_roots,
    ));
    transport_canonical_try!(refuse_unexpected_setup_transported_objects(
        &transported_objects,
        &expected_transported_object_roots,
    ));

    Ok(Ok(SetupTransportAggregate {
        total_byte_length,
        chunk_count,
        chunk_hashes,
        chunk_root,
        full_object_hash,
    }))
}

#[derive(Clone, Debug)]
struct SetupTransportedObjectBinding {
    object_name: String,
    object_role: String,
    object_root: String,
    byte_length: u64,
    chunk_start_index: u64,
    chunk_count: u64,
    chunk_root: String,
    chunk_hashes: Vec<String>,
    full_object_hash: String,
}

#[derive(Debug)]
struct SetupTransportAggregate {
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: Vec<String>,
    chunk_root: String,
    full_object_hash: String,
}

fn setup_transported_object_binding(
    transported_object: &Value,
    object_index: usize,
    expected_chunk_start_index: u64,
    seen_object_roots: &mut BTreeSet<String>,
) -> CanonicalResult<Result<SetupTransportedObjectBinding, Refusal>> {
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

    if !transported_object.is_object() {
        return Ok(Err(Refusal::new(
            "transportedObjectNotObject",
            "setupTransportCertificate.transportedObjects entries must be root-bound objects",
            format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]"),
        )));
    }
    if let Some(unexpected_field) = unexpected_setup_transported_object_field(transported_object) {
        return Ok(Err(Refusal::new(
            "transportedObjectUnexpectedField",
            format!("setup transported object contains unexpected field {unexpected_field}"),
            format!(
                "setupPackage.setupTransportCertificate.transportedObjects[{object_index}].{unexpected_field}"
            ),
        )));
    }
    let object_path =
        format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]");
    transport_try!(expect_transport_string_at(
        transported_object,
        "objectType",
        SETUP_TRANSPORTED_OBJECT_TYPE,
        "transportedObjectTypeMismatch",
        "transported object objectType must be SetupTransportedObject",
        &object_path,
    ));
    transport_try!(expect_transport_u64_at(
        transported_object,
        "objectVersion",
        1,
        "transportedObjectVersionMismatch",
        "transported object objectVersion must be 1",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "encoding",
        "binary",
        "transportedObjectEncodingMismatch",
        "transported object encoding must be binary",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "loadingPolicy",
        SETUP_TRANSPORTED_OBJECT_LOADING_POLICY,
        "transportedObjectLoadingPolicyMismatch",
        "transported object loading policy must match the setup transport profile",
        &object_path,
    ));
    let object_name = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectName",
        "transportedObjectNameMissing",
        "transported object objectName is required",
        &object_path,
    ));
    let object_role = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectRole",
        "transportedObjectRoleMissing",
        "transported object objectRole is required",
        &object_path,
    ));
    let object_root = transport_try!(require_transport_hash_at(
        transported_object,
        "objectRoot",
        "transportedObjectRootMissing",
        "transported object objectRoot is required",
        &object_path,
    ));
    if !seen_object_roots.insert(object_root.clone()) {
        return Ok(Err(Refusal::new(
            "transportedObjectRootDuplicate",
            "setupTransportCertificate.transportedObjects must not contain duplicate objectRoot entries",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    let byte_length = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "byteLength",
        "transportedObjectByteLengthInvalid",
        "transported object byteLength must be positive",
        &object_path,
    ));
    let chunk_start_index = transport_try!(require_transport_u64_at(
        transported_object,
        "chunkStartIndex",
        "transportedObjectStartIndexMissing",
        "transported object chunkStartIndex is required",
        &object_path,
    ));
    if chunk_start_index != expected_chunk_start_index {
        return Ok(Err(Refusal::new(
            "transportedObjectStartIndexMismatch",
            "transported object chunkStartIndex must continue the aggregate transport stream",
            format!("{object_path}.chunkStartIndex"),
        )));
    }
    let chunk_count = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "chunkCount",
        "transportedObjectChunkCountInvalid",
        "transported object chunkCount must be positive",
        &object_path,
    ));
    let expected_chunk_count = setup_transport_chunk_count(byte_length)?;
    if chunk_count != expected_chunk_count {
        return Ok(Err(Refusal::new(
            "transportedObjectChunkCountMismatch",
            "transported object chunkCount must match byteLength and the setup transport chunk size",
            format!("{object_path}.chunkCount"),
        )));
    }
    let full_object_hash = transport_try!(require_transport_hash_at(
        transported_object,
        "fullObjectHash",
        "transportedObjectFullHashMissing",
        "transported object fullObjectHash is required",
        &object_path,
    ));
    let chunk_hashes = transport_canonical_try!(transport_hashes_at(
        transported_object,
        "chunkHashes",
        usize::try_from(chunk_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported object chunkCount does not fit usize",
            )
        })?,
        &object_path,
    ));
    let chunk_root = transport_try!(require_transport_hash_at(
        transported_object,
        "chunkRoot",
        "transportedObjectChunkRootMissing",
        "transported object chunkRoot is required",
        &object_path,
    ));

    Ok(Ok(SetupTransportedObjectBinding {
        object_name,
        object_role,
        object_root,
        byte_length,
        chunk_start_index,
        chunk_count,
        chunk_root,
        chunk_hashes,
        full_object_hash,
    }))
}

struct SetupTransportExpectedObject {
    object_name: &'static str,
    object_role: &'static str,
    object_root: String,
    byte_length: u64,
    chunk_root: String,
    chunk_hashes: Vec<String>,
    full_object_hash: String,
    object_path: String,
}

#[derive(Clone, Copy)]
struct SetupTransportHashFieldNames {
    byte_length: &'static str,
    full_object_hash: &'static str,
    chunk_root: &'static str,
    chunk_hashes: &'static str,
}

#[derive(Clone, Copy)]
struct SetupTransportMaterialDescriptor {
    object_name: &'static str,
    object_role: &'static str,
    object_root: &'static str,
    hash_fields: SetupTransportHashFieldNames,
}

const SETUP_TRANSPORT_DIRECT_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "totalByteLength",
        full_object_hash: "fullObjectHash",
        chunk_root: "chunkRoot",
        chunk_hashes: "chunkHashes",
    };

const SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS: SetupTransportHashFieldNames =
    SETUP_TRANSPORT_DIRECT_HASH_FIELDS;

const SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "proofTotalByteLength",
        full_object_hash: "proofFullObjectHash",
        chunk_root: "proofChunkRoot",
        chunk_hashes: "proofChunkHashes",
    };

fn verify_setup_transport_request_bindings(
    setup_package: &Value,
    request: &Value,
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &mut BTreeSet<String>,
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

    if let Some(transported_material) = request.get("transportedVssCoefficientCommitmentMaterial") {
        transport_try!(require_setup_transport_entry(
            transported_objects,
            &setup_transport_expected_direct_material(
                transported_material,
                package_nested_hash(
                    setup_package,
                    "vssCoefficientCommitmentMaterial",
                    "vssCoefficientCommitmentMaterialRoot",
                )?,
                SETUP_TRANSPORTED_VSS_MATERIAL_NAME,
                SETUP_TRANSPORTED_VSS_MATERIAL_ROLE,
                SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
                "transportedVssCoefficientCommitmentMaterial",
            )?,
            expected_object_roots,
        ));
    }
    if let Some(transported_material) = request.get("transportedPublicKeyShareMaterial") {
        let Some(public_key_share_material_root) = setup_package
            .get("publicKeyShareMaterial")
            .and_then(|material| material.get("publicKeyShareMaterialSetRoot"))
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(Err(Refusal::new(
                "transportedObjectBindingMissing",
                "transportedPublicKeyShareMaterial requires setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
                "setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
            )));
        };
        validate_hash_string(
            public_key_share_material_root,
            "setupPackage.publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
        )?;
        transport_try!(require_setup_transport_entry(
            transported_objects,
            &setup_transport_expected_direct_material(
                transported_material,
                public_key_share_material_root.to_string(),
                SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_NAME,
                SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_MATERIAL_ROLE,
                SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
                "transportedPublicKeyShareMaterial",
            )?,
            expected_object_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedSameSecretProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_proof_material_roots(
            setup_package,
            "sameSecretProofs",
            "proofRecords",
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedSameSecretProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_SAME_SECRET_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedPublicKeyShareProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_proof_material_roots(
            setup_package,
            "publicKeyShareLnpProofs",
            "proofRecords",
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedPublicKeyShareProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_PUBLIC_KEY_SHARE_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedEvaluationKeyShareProofMaterial") {
        let referenced_material_roots = setup_transport_referenced_evaluation_key_material_roots(
            setup_package,
            "proofMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_proof_material_entries(
            transported_objects,
            material_set,
            "transportedEvaluationKeyShareProofMaterial",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_ROLE,
                object_root: "proofMaterialRoot",
                hash_fields: SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") {
        let referenced_material_roots = setup_transport_referenced_evaluation_key_material_roots(
            setup_package,
            "keySwitchComponentMaterialRoot",
        )?;
        transport_canonical_try!(require_setup_transport_material_entries(
            transported_objects,
            material_set,
            "transportedEvaluationKeyShareComponentMaterial",
            "componentMaterials",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ROLE,
                object_root: "keySwitchComponentMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
        ));
    }
    if let Some(material_set) = request.get("transportedPublicEvaluationKeyMaterial") {
        let referenced_material_roots =
            setup_transport_referenced_public_evaluation_key_material_roots(setup_package)?;
        transport_canonical_try!(require_setup_transport_material_entries(
            transported_objects,
            material_set,
            "transportedPublicEvaluationKeyMaterial",
            "publicEvaluationKeyMaterials",
            SetupTransportMaterialDescriptor {
                object_name: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_NAME,
                object_role: SETUP_TRANSPORTED_PUBLIC_EVALUATION_KEY_MATERIAL_ROLE,
                object_root: "publicEvaluationKeyMaterialRoot",
                hash_fields: SETUP_TRANSPORT_DIRECT_HASH_FIELDS,
            },
            &referenced_material_roots,
            expected_object_roots,
        ));
    }

    Ok(Ok(()))
}

fn setup_transport_referenced_proof_material_roots(
    setup_package: &Value,
    record_set_name: &str,
    records_field_name: &str,
    root_field_name: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let Some(record_set) = setup_package.get(record_set_name) else {
        return Ok(BTreeSet::new());
    };
    let Some(records) = record_set.get(records_field_name).and_then(Value::as_array) else {
        return Ok(BTreeSet::new());
    };

    let mut referenced_roots = BTreeSet::new();
    for record in records {
        if let Some(root) = record.get(root_field_name).and_then(Value::as_str) {
            validate_hash_string(
                root,
                &format!("setupPackage.{record_set_name}.{records_field_name}.{root_field_name}"),
            )?;
            referenced_roots.insert(root.to_string());
        }
    }

    Ok(referenced_roots)
}

fn setup_transport_referenced_evaluation_key_material_roots(
    setup_package: &Value,
    root_field_name: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let mut referenced_roots = BTreeSet::new();
    if let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") {
        for records_field_name in ["roundOneRecords", "roundTwoRecords"] {
            setup_transport_collect_optional_record_roots(
                rounds,
                records_field_name,
                root_field_name,
                &format!(
                    "setupPackage.relinearizationKeyShareRounds.{records_field_name}.{root_field_name}"
                ),
                &mut referenced_roots,
            )?;
        }
    }
    if let Some(batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    {
        for batch in batches {
            setup_transport_collect_optional_record_roots(
                batch,
                "galoisKeyShareProofs",
                root_field_name,
                &format!(
                    "setupPackage.galoisKeyShareBatches.galoisKeyShareProofs.{root_field_name}"
                ),
                &mut referenced_roots,
            )?;
        }
    }

    Ok(referenced_roots)
}

fn setup_transport_referenced_public_evaluation_key_material_roots(
    setup_package: &Value,
) -> CanonicalResult<BTreeSet<String>> {
    let mut referenced_roots = BTreeSet::new();
    if let Some(root) = setup_package
        .get("evaluationKeys")
        .and_then(|evaluation_keys| evaluation_keys.get("publicEvaluationKeyMaterialRoot"))
        .and_then(Value::as_str)
    {
        validate_hash_string(
            root,
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialRoot",
        )?;
        referenced_roots.insert(root.to_string());
    }

    Ok(referenced_roots)
}

fn setup_transport_collect_optional_record_roots(
    value: &Value,
    records_field_name: &str,
    root_field_name: &str,
    object_path: &str,
    referenced_roots: &mut BTreeSet<String>,
) -> CanonicalResult<()> {
    let Some(records) = value.get(records_field_name).and_then(Value::as_array) else {
        return Ok(());
    };
    for record in records {
        if let Some(root) = record.get(root_field_name).and_then(Value::as_str) {
            validate_hash_string(root, object_path)?;
            referenced_roots.insert(root.to_string());
        }
    }

    Ok(())
}

fn require_setup_transport_proof_material_entries(
    transported_objects: &[SetupTransportedObjectBinding],
    material_set: &Value,
    material_set_path: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    expected_object_roots: &mut BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Ok(Err(Refusal::new(
            "transportedProofMaterialListMissing",
            format!(
                "{material_set_path}.proofMaterials must list transported proof material objects"
            ),
            format!("{material_set_path}.proofMaterials"),
        )));
    };
    for (material_index, proof_material) in proof_materials.iter().enumerate() {
        let object_path = format!("{material_set_path}.proofMaterials[{material_index}]");
        let expected_material =
            setup_transport_expected_material(proof_material, descriptor, object_path)?;
        if !referenced_material_roots.contains(&expected_material.object_root) {
            return Ok(Err(Refusal::new(
                "transportedObjectUnreferenced",
                format!(
                    "{material_set_path}.proofMaterials contains transported material not referenced by setupPackage records"
                ),
                expected_material.object_path,
            )));
        }
        if let Err(refusal) = require_setup_transport_entry(
            transported_objects,
            &expected_material,
            expected_object_roots,
        ) {
            return Ok(Err(refusal));
        }
    }

    Ok(Ok(()))
}

fn require_setup_transport_material_entries(
    transported_objects: &[SetupTransportedObjectBinding],
    material_set: &Value,
    material_set_path: &'static str,
    material_array_field_name: &'static str,
    descriptor: SetupTransportMaterialDescriptor,
    referenced_material_roots: &BTreeSet<String>,
    expected_object_roots: &mut BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    let Some(materials) = material_set
        .get(material_array_field_name)
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            "transportedMaterialListMissing",
            format!(
                "{material_set_path}.{material_array_field_name} must list transported material objects"
            ),
            format!("{material_set_path}.{material_array_field_name}"),
        )));
    };
    for (material_index, material) in materials.iter().enumerate() {
        let object_path =
            format!("{material_set_path}.{material_array_field_name}[{material_index}]");
        let expected_material =
            setup_transport_expected_material(material, descriptor, object_path)?;
        if !referenced_material_roots.contains(&expected_material.object_root) {
            return Ok(Err(Refusal::new(
                "transportedObjectUnreferenced",
                format!(
                    "{material_set_path}.{material_array_field_name} contains transported material not referenced by setupPackage records"
                ),
                expected_material.object_path,
            )));
        }
        if let Err(refusal) = require_setup_transport_entry(
            transported_objects,
            &expected_material,
            expected_object_roots,
        ) {
            return Ok(Err(refusal));
        }
    }

    Ok(Ok(()))
}

fn setup_transport_expected_direct_material(
    material: &Value,
    object_root: String,
    object_name: &'static str,
    object_role: &'static str,
    hash_fields: SetupTransportHashFieldNames,
    object_path: &'static str,
) -> CanonicalResult<SetupTransportExpectedObject> {
    setup_transport_expected_material_with_root(
        material,
        object_root,
        object_name,
        object_role,
        hash_fields,
        object_path.to_string(),
    )
}

fn setup_transport_expected_material(
    material: &Value,
    descriptor: SetupTransportMaterialDescriptor,
    object_path: String,
) -> CanonicalResult<SetupTransportExpectedObject> {
    let object_root = value_string(material, descriptor.object_root)?.to_string();
    validate_hash_string(
        &object_root,
        &format!("{object_path}.{}", descriptor.object_root),
    )?;

    setup_transport_expected_material_with_root(
        material,
        object_root,
        descriptor.object_name,
        descriptor.object_role,
        descriptor.hash_fields,
        object_path,
    )
}

fn setup_transport_expected_material_with_root(
    material: &Value,
    object_root: String,
    object_name: &'static str,
    object_role: &'static str,
    hash_fields: SetupTransportHashFieldNames,
    object_path: String,
) -> CanonicalResult<SetupTransportExpectedObject> {
    let byte_length = value_u64(material, hash_fields.byte_length)?;
    let full_object_hash = value_string(material, hash_fields.full_object_hash)?.to_string();
    validate_hash_string(
        &full_object_hash,
        &format!("{object_path}.{}", hash_fields.full_object_hash),
    )?;
    let chunk_root = value_string(material, hash_fields.chunk_root)?.to_string();
    validate_hash_string(
        &chunk_root,
        &format!("{object_path}.{}", hash_fields.chunk_root),
    )?;
    let chunk_hashes =
        setup_transport_expected_hash_array(material, hash_fields.chunk_hashes, &object_path)?;

    Ok(SetupTransportExpectedObject {
        object_name,
        object_role,
        object_root,
        byte_length,
        chunk_root,
        chunk_hashes,
        full_object_hash,
        object_path,
    })
}

fn require_setup_transport_entry(
    transported_objects: &[SetupTransportedObjectBinding],
    expected: &SetupTransportExpectedObject,
    expected_object_roots: &mut BTreeSet<String>,
) -> Result<(), Refusal> {
    expected_object_roots.insert(expected.object_root.clone());
    let Some(transported_object) = transported_objects
        .iter()
        .find(|transported_object| transported_object.object_root == expected.object_root)
    else {
        return Err(Refusal::new(
            "transportedObjectBindingMissing",
            format!(
                "setupTransportCertificate.transportedObjects must bind {}",
                expected.object_path
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        ));
    };
    if transported_object.object_name != expected.object_name
        || transported_object.object_role != expected.object_role
        || transported_object.byte_length != expected.byte_length
        || transported_object.chunk_root != expected.chunk_root
        || transported_object.chunk_hashes != expected.chunk_hashes
        || transported_object.full_object_hash != expected.full_object_hash
    {
        return Err(Refusal::new(
            "transportedObjectBindingMismatch",
            format!(
                "setupTransportCertificate.transportedObjects metadata must match {}",
                expected.object_path
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        ));
    }

    Ok(())
}

fn refuse_unexpected_setup_transported_objects(
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    for transported_object in transported_objects {
        if expected_object_roots.contains(&transported_object.object_root) {
            continue;
        }

        return Ok(Err(Refusal::new(
            "transportedObjectUnexpected",
            format!(
                "setupTransportCertificate.transportedObjects contains unrequested transported object {} with role {}",
                transported_object.object_name, transported_object.object_role
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    Ok(Ok(()))
}

fn verify_binary_vss_material_transport_reference(
    setup_package: &Value,
    expected_byte_length: u64,
    expected_chunk_count: u64,
    expected_chunk_root: &str,
    expected_full_object_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before setup transport verification",
            )
        })?;
    if material_set.get("materialEncoding").and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Ok(()));
    }
    let transport = match material_set.get("transport") {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceMissing",
                "binary-chunked vssCoefficientCommitmentMaterial must include transport metadata bound to the setup transport certificate",
                "setupPackage.vssCoefficientCommitmentMaterial.transport",
            )));
        }
    };
    let Some(transport_object) = transport.as_object() else {
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceNotObject",
            "vssCoefficientCommitmentMaterial.transport must be an object",
            "setupPackage.vssCoefficientCommitmentMaterial.transport",
        )));
    };
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
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceUnexpectedField",
            format!(
                "vssCoefficientCommitmentMaterial.transport contains unexpected field {unexpected_field}"
            ),
            format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{unexpected_field}"),
        )));
    }
    if transport_object
        .get("transportProfileId")
        .and_then(Value::as_str)
        != Some(SETUP_TRANSPORT_PROFILE_ID)
    {
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceProfileMismatch",
            "vssCoefficientCommitmentMaterial.transport.transportProfileId must match the setup transport profile",
            "setupPackage.vssCoefficientCommitmentMaterial.transport.transportProfileId",
        )));
    }
    for (field_name, expected_value) in [
        ("chunkSizeBytes", SETUP_TRANSPORT_CHUNK_SIZE_BYTES),
        ("chunkCount", expected_chunk_count),
        ("totalByteLength", expected_byte_length),
    ] {
        match transport_object.get(field_name).and_then(Value::as_u64) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(_) => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMismatch",
                    "vssCoefficientCommitmentMaterial.transport numeric metadata must match the setup transport certificate",
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
            None => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMissing",
                    format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
        }
    }
    for (field_name, expected_value) in [
        ("fullObjectHash", expected_full_object_hash),
        ("chunkRoot", expected_chunk_root),
    ] {
        let Some(observed_value) = transport_object.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMissing",
                format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        };
        validate_hash_string(
            observed_value,
            &format!("vssCoefficientCommitmentMaterial.transport.{field_name}"),
        )?;
        if observed_value != expected_value {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMismatch",
                "vssCoefficientCommitmentMaterial.transport hash metadata must match the setup transport certificate",
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        }
    }

    Ok(Ok(()))
}

fn transport_chunk_hashes(
    transport_certificate: &Value,
    expected_chunk_count: usize,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    transport_hashes_at(
        transport_certificate,
        "chunkHashes",
        expected_chunk_count,
        "setupPackage.setupTransportCertificate",
    )
}

fn transport_hashes_at(
    value: &Value,
    field_name: &'static str,
    expected_chunk_count: usize,
    object_path: &str,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    match transport_hash_array(value, field_name, object_path, Some(expected_chunk_count)) {
        Ok(value) => Ok(Ok(value)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

fn transport_hash_array(
    value: &Value,
    field_name: &'static str,
    object_path: &str,
    expected_chunk_count: Option<usize>,
) -> Result<Vec<String>, Refusal> {
    let chunk_hash_values = match value.get(field_name).and_then(Value::as_array) {
        Some(value) => value,
        None => {
            return Err(Refusal::new(
                "transportChunkHashesMissing",
                format!("{object_path}.{field_name} must list every setup transport chunk hash"),
                format!("{object_path}.{field_name}"),
            ));
        }
    };
    if let Some(expected_chunk_count) = expected_chunk_count
        && chunk_hash_values.len() != expected_chunk_count
    {
        return Err(Refusal::new(
            "transportChunkHashCountMismatch",
            format!("{object_path}.{field_name} length must match chunkCount"),
            format!("{object_path}.{field_name}"),
        ));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    let mut seen_chunk_hashes = BTreeSet::new();
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(Refusal::new(
                "transportChunkHashNotString",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        };
        if chunk_hash.len() != 128
            || !chunk_hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        {
            return Err(Refusal::new(
                "transportChunkHashInvalid",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        }
        if !seen_chunk_hashes.insert(chunk_hash.to_string()) {
            return Err(Refusal::new(
                "transportChunkHashDuplicate",
                format!("{object_path}.{field_name} must not contain duplicate chunk hashes"),
                format!("{object_path}.{field_name}"),
            ));
        }
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

fn setup_transport_expected_hash_array(
    value: &Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<Vec<String>> {
    let chunk_hash_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name} must list transported chunk hashes"),
            )
        })?;
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name}[{chunk_index}] must be a protocol hash"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{object_path}.{field_name}[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

fn setup_transport_full_object_set_hash(
    transported_objects: &[SetupTransportedObjectBinding],
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: &[String],
) -> CanonicalResult<String> {
    let transported_object_values = transported_objects
        .iter()
        .map(|transported_object| {
            json!({
                "objectName": transported_object.object_name,
                "objectRole": transported_object.object_role,
                "objectRoot": transported_object.object_root,
                "byteLength": transported_object.byte_length,
                "chunkStartIndex": transported_object.chunk_start_index,
                "chunkCount": transported_object.chunk_count,
                "chunkRoot": transported_object.chunk_root,
                "fullObjectHash": transported_object.full_object_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "transportedObjects": transported_object_values,
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
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

fn expect_transport_string_at(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

fn require_transport_non_empty_string_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(field_value) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if field_value.is_empty() {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value.to_string())
}

fn expect_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

fn require_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(reason_code, message, format!("{object_path}.{field_name}")))
}

fn require_positive_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    let field_value =
        require_transport_u64_at(value, field_name, reason_code, message, object_path)?;
    if field_value == 0 {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value)
}

fn require_transport_hash_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if hash.len() != 128
        || !hash
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} must be a protocol hash"),
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(hash.to_string())
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
        "setupProofAccountingCertificateHash",
        "setupKeyCorrectnessCertificateHash",
        "activeStaticSetupTheoremCertificateHash",
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
    if let Some(hash) = setup_package
        .get("evaluationKeys")
        .and_then(|evaluation_keys| evaluation_keys.get("evaluationKeySetHash"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("evaluationKeys")
        .and_then(|evaluation_keys| evaluation_keys.get("publicEvaluationKeyMaterialRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }

    accepted_hashes
}

fn accepted_setup_verification_response(setup_package: &Value) -> CanonicalResult<Value> {
    let mut response = verification_response(
        VerifierStatus::Accepted,
        Some("setupPackageVerification"),
        Vec::new(),
        Vec::new(),
        accepted_hashes_from_package(setup_package),
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
    let target_decryption_status = setup_package
        .get("heSecurityCertificate")
        .and_then(|certificate| certificate.get("targetDecryptionStatus"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "heSecurityCertificate.targetDecryptionStatus was required before accepted setup handoff construction",
            )
        })?;
    let mut handoff = json!({
        "objectType": "CollectiveBgvAcceptedSetupHandoff",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupPackageHash": value_string(setup_package, "setupPackageHash")?,
        "directBallotEncryptionHandoff": {
            "status": "accepted-collective-public-key-root-bound-for-direct-ballot-encryption",
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
            "publicKeyShareLnpProofSetRoot": package_nested_hash(
                setup_package,
                "publicKeyShareLnpProofs",
                "publicKeyShareLnpProofSetRoot",
            )?,
        },
        "publicAggregationHandoff": {
            "status": "accepted-public-ciphertext-aggregation-bound-to-setup-context-and-collective-public-key-root",
            "thresholdShareCommitmentRoot": package_nested_hash(
                setup_package,
                "thresholdShareCommitments",
                "thresholdShareCommitmentRoot",
            )?,
        },
        "boundedEvaluatorReplayHandoff": {
            "status": "accepted-public-evaluation-keys-bound-to-frozen-evaluator-schedule",
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
        "futureTargetDecryptionHandoff": {
            "status": value_string(target_decryption_status, "targetDecryptionReadiness")?,
            "targetDecryptionProfileId": value_string(
                target_decryption_status,
                "targetDecryptionProfileId",
            )?,
            "claimBoundary": "target decryption remains downstream and any target-decryption readiness claim is refused until Q_target, smudging, C1-C4, and decryption-share proof closure exist",
        },
        "certificateRoots": {
            "setupCommitmentSecurityCertificateHash": value_string(
                setup_package,
                "setupCommitmentSecurityCertificateHash",
            )?,
            "setupTransportCertificateHash": value_string(
                setup_package,
                "setupTransportCertificateHash",
            )?,
            "setupProofAccountingCertificateHash": value_string(
                setup_package,
                "setupProofAccountingCertificateHash",
            )?,
            "setupKeyCorrectnessCertificateHash": value_string(
                setup_package,
                "setupKeyCorrectnessCertificateHash",
            )?,
            "activeStaticSetupTheoremCertificateHash": value_string(
                setup_package,
                "activeStaticSetupTheoremCertificateHash",
            )?,
            "heSecurityCertificateHash": value_string(setup_package, "heSecurityCertificateHash")?,
        },
    });
    let handoff_root = derive_protocol_hash("AcceptedSetupHandoffRoot", &handoff)?;
    handoff
        .as_object_mut()
        .expect("accepted setup handoff is a JSON object")
        .insert("acceptedSetupHandoffRoot".to_string(), json!(handoff_root));

    Ok(handoff)
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
                if ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str())
                    || field_name_suggests_legacy_external_setup_role(field_name)
                {
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
        if ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str())
            || field_name_suggests_legacy_external_setup_role(field_name)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} cannot appear in accepted collective BGV setup requests"),
            ));
        }
    }

    Ok(())
}
