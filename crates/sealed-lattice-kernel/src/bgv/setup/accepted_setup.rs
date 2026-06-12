mod accepted_certificates;
mod common_randomness;
mod evaluation_key_material_transport;
mod evaluation_key_proof_checks;
mod evaluation_key_share_rounds;
mod evaluator_key_schedule;
mod phase_transcript;
mod private_vss_envelopes;
mod public_key_share_material;
mod public_key_shares;
mod same_secret_consistency;
mod setup_context;
mod threshold_share_commitment_checks;
mod transport_policy;
mod vss_coefficient_commitments;
mod vss_complaints_and_acceptances;

#[cfg(test)]
pub(super) use self::accepted_certificates::{
    accepted_he_security_certificate_hash, accepted_he_security_certificate_value,
    active_static_setup_theorem_certificate_hash, active_static_setup_theorem_certificate_value,
    setup_key_correctness_certificate_hash, setup_key_correctness_certificate_value,
    setup_proof_accounting_certificate_hash, setup_proof_accounting_certificate_value,
};
#[cfg(test)]
pub(super) use self::evaluation_key_material_transport::encode_public_evaluation_key_material_manifest;
#[cfg(test)]
pub(super) use self::evaluation_key_material_transport::{
    accepted_setup_public_galois_keys_from_transport,
    accepted_setup_public_relinearization_keys_from_transport,
    public_evaluation_key_material_manifest, public_evaluation_key_material_reference_root,
    public_evaluation_key_material_transport_hashes,
};
#[cfg(test)]
pub(super) use self::public_key_share_material::{
    accepted_setup_collective_public_key_from_package, public_key_share_material_transport_hashes,
};
pub(super) use self::transport_policy::{
    verify_profile_ring_material, verify_terminal_setup_transport_policy,
};

use self::accepted_certificates::{
    accepted_he_security_certificate_with_hash_value, optional_nested_hash_value,
    package_nested_hash, setup_commitment_security_certificate_with_hash_value,
    setup_package_requires_setup_key_correctness_certificate,
    setup_proof_accounting_certificate_with_hash_value,
    verify_active_static_setup_theorem_certificate, verify_commitment_security_certificate,
    verify_he_security_certificate, verify_setup_key_correctness_certificate,
    verify_setup_proof_accounting_certificate,
};
use self::common_randomness::{
    derive_bgv_public_a_polynomial, derive_collective_bgv_setup_public_derivations,
    verify_common_randomness,
};
use self::evaluation_key_material_transport::{
    evaluation_key_material_refusal,
    transported_evaluation_key_share_component_material_from_request,
    verify_public_evaluation_key_set, verify_required_public_evaluation_key_set,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::evaluation_key_proof_checks::{
    TrusteeEvaluationKeyStatementInputs, accepted_key_switch_decomposition_hash,
    register_verified_trustee_evaluation_key_proof_material_chunks,
    round_one_public_aggregate_diagonals_from_package, trustee_evaluation_key_proof_material_root,
    trustee_evaluation_key_statement_from_package,
};
use self::evaluation_key_proof_checks::verify_trustee_evaluation_key_proofs;
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
use self::phase_transcript::{setup_context_string, verify_abort_absence, verify_phase_transcript};
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    verify_private_vss_envelope_commitments,
};
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, public_key_share_material_uses_transport,
    verify_collective_public_key_material, verify_collective_public_key_pair_consistency,
    verify_public_key_share_material_set,
};
use self::public_key_shares::{
    PublicKeyCommonBinding, public_key_common_binding, public_key_share_proof_refusal,
    public_key_share_records_by_roster_position, verify_optional_public_key_share_lnp_proofs,
    verify_public_key_material_acceptance_boundary, verify_public_key_share_proofs,
    verify_public_key_shares,
};
use self::same_secret_consistency::{
    LnpTboxZ34MetadataExpectation, SameSecretProofBinding, SameSecretStatementBinding,
    same_secret_consistency_root_from_package, verify_lnp_tbox_z34_metadata_fields,
    same_secret_constant_commitment_values_from_material, same_secret_proof_bindings_from_package,
    same_secret_proof_family_binding_root, same_secret_proof_set_root_from_package,
    same_secret_statement_bindings_from_package, same_secret_statement_records_by_roster_position,
    same_secret_transported_constant_commitments_by_roster_position,
    verify_optional_same_secret_lnp_proofs, verify_same_secret_consistency,
    verify_same_secret_context,
};
use self::setup_context::{q_share_hash, q_share_value, verify_context, verify_q_share};
use self::threshold_share_commitment_checks::{
    validate_verified_vss_material_matches_package, verify_threshold_share_commitments,
};
use self::transport_policy::{
    setup_transport_chunk_manifest_root, setup_transport_vss_material_byte_length,
    verify_transport_certificate,
};
use self::vss_coefficient_commitments::{
    expected_trustees_from_phase_transcript, verify_vss_coefficient_commitment_material,
    verify_vss_coefficient_commitments,
};
use self::vss_complaints_and_acceptances::{
    source_trustee_commitment_roots_from_vss_commitments, verify_vss_complaints,
    verify_vss_share_acceptances,
};

use super::{commitment, setup_proof, threshold_share_commitments};

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
#[cfg(test)]
use std::{fs, io::Write};

use num_bigint::BigUint;
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

use super::*;
use super::{
    commitment::{
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
        SETUP_COMMITMENT_PROFILE_ID, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
        parse_setup_commitment_full_value, setup_commitment_matrix_sampled_entries,
        setup_commitment_modulus_limb_values, setup_commitment_modulus_product,
        setup_commitment_modulus_product_ceil_bits, setup_commitment_profile_hash,
        setup_commitment_profile_value, setup_commitment_root,
    },
    evaluation_key_share_material::{
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        EvaluationKeyShareProofFamily, component_b_vectors_from_record,
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
    SELECTED_EVALUATOR_WORKING_LEVEL, direct_score_packing_basis_galois_elements,
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
const GALOIS_KEY_SHARE_MATERIAL_OBJECT_TYPE: &str = "GaloisKeyShareMaterial";
const TRUSTEE_EVALUATION_KEY_PROOF_SET_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProofSet";
const TRUSTEE_EVALUATION_KEY_PROOF_OBJECT_TYPE: &str = "TrusteeEvaluationKeyProof";
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
// Share records carry no proof fields: their correctness claim is the
// per-trustee succinct argument, so every record pins this status pair.
pub(in crate::bgv::setup) const EVALUATION_KEY_SHARE_RECORD_VERIFICATION_STATUS: &str =
    "share-records-bound-to-trustee-evaluation-key-argument";
use super::trustee_evaluation_key_proof::{
    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY, TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS,
    TRUSTEE_EVALUATION_KEY_PROOF_VERIFICATION_STATUS,
};
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
const SETUP_PROOF_BYTES_ACCEPTED_STATUS: &str = "private-vss-same-secret-public-key-share-and-trustee-evaluation-key-proof-bytes-accepted-for-setup-proof-accounting";
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
    ("galoisKeyShareBatches", 12),
    ("trusteeEvaluationKeyProofs", 13),
    ("setupPackageAssembly", 14),
    ("setupPackageVerification", 15),
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
    "trusteeEvaluationKeyProofs",
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

enum VerificationFlow {
    Continue,
    Stop(Value),
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

pub(super) fn accepted_setup_profile_hash() -> CanonicalResult<String> {
    setup_profile_hash()
}

pub(super) fn accepted_q_share_hash() -> CanonicalResult<String> {
    q_share_hash()
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

// One relinearization key per round at the selected evaluator working level:
// lower levels reuse the same key through CRT-idempotent truncation, so the
// schedule carries no per-level entries.
fn expected_relinearization_level_schedule() -> Value {
    Value::Array(vec![json!({
        "level": SELECTED_EVALUATOR_WORKING_LEVEL,
        "proofFamily": "relinearization-key-share",
        "keyShareRounds": ["round-one", "round-two"],
    })])
}

fn expected_required_galois_key_schedule() -> CanonicalResult<Value> {
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, SELECTED_EVALUATOR_WORKING_LEVEL))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
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
        "trusteeEvaluationKeyProofAccountingHash":
            super::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
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
        .get("trusteeEvaluationKeyProofs")
        .and_then(|proof_set| proof_set.get("trusteeEvaluationKeyProofSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
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
