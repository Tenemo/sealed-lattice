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
    setup_assembly_provenance_certificate_hash, setup_assembly_provenance_certificate_value,
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
    verify_he_security_certificate, verify_setup_assembly_provenance_certificate,
    verify_setup_key_correctness_certificate, verify_setup_proof_accounting_certificate,
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
use self::evaluation_key_proof_checks::verify_trustee_evaluation_key_proofs;
#[cfg(test)]
pub(in crate::bgv::setup) use self::evaluation_key_proof_checks::{
    TrusteeEvaluationKeyStatementInputs, accepted_key_switch_decomposition_hash,
    register_verified_trustee_evaluation_key_proof_material_chunks,
    round_one_public_aggregate_diagonals_from_package, trustee_evaluation_key_proof_material_root,
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
use self::phase_transcript::{setup_context_string, verify_abort_absence, verify_phase_transcript};
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    verify_private_vss_envelope_commitments,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_share_material::public_key_share_coefficient_vector_hash;
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, accepted_setup_collective_public_key_from_material,
    public_key_share_material_uses_transport, verify_collective_public_key_material,
    verify_collective_public_key_pair_consistency, verify_public_key_share_material_set,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_shares::public_key_share_succinct_proof_material_root;
use self::public_key_shares::{
    PublicKeyCommonBinding, public_key_common_binding, public_key_share_proof_refusal,
    public_key_share_records_by_roster_position, verify_optional_public_key_share_succinct_proofs,
    verify_public_key_material_acceptance_boundary, verify_public_key_share_proofs,
    verify_public_key_shares,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::same_secret_consistency::same_secret_anchor_proof_material_root;
use self::same_secret_consistency::{
    SameSecretProofBinding, SameSecretStatementBinding, same_secret_consistency_root_from_package,
    same_secret_constant_commitment_values_from_material, same_secret_proof_bindings_from_package,
    same_secret_proof_family_binding_root, same_secret_proof_set_root_from_package,
    same_secret_statement_bindings_from_package, same_secret_statement_records_by_roster_position,
    same_secret_transported_constant_commitments_by_roster_position,
    verify_optional_same_secret_proofs, verify_same_secret_consistency, verify_same_secret_context,
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
        EvaluationKeyShareComponentMaterialCache, EvaluationKeyShareProofFamily,
        component_b_vectors_from_record_with_cache,
    },
    setup_proof::{
        SETUP_PROOF_BYTES_DOMAIN, SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_PROFILE_ID,
        SETUP_PROOF_SERIALIZATION, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        setup_proof_material_transport_hashes, verified_setup_proof_material_chunks_from_request,
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
use crate::bgv::direct_ballots::{
    DIRECT_BALLOT_MAXIMUM_SCORE, DIRECT_BALLOT_MINIMUM_SCORE, DIRECT_BALLOT_OPTION_COUNT,
    DIRECT_BALLOT_SCORE_BUCKET_COUNT, direct_ballot_arithmetic_certificate_hash,
    direct_ballot_encoder_matrix_root, direct_ballot_relation_proof_profile_hash,
    direct_ballot_reserved_slot_rule_hash, direct_ballot_reserved_slot_rule_value,
    direct_ballot_soundness_certificate_hash, direct_ballot_witness_partition_profile_hash,
};
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
const SETUP_PROOF_ACCOUNTING_CERTIFICATE_HASH_NAMESPACE: &str =
    "SetupProofAccountingCertificateHash";
const SETUP_ASSEMBLY_PROVENANCE_CERTIFICATE_OBJECT_TYPE: &str =
    "SetupAssemblyProvenanceCertificate";
const SETUP_ASSEMBLY_PROVENANCE_CERTIFICATE_HASH_NAMESPACE: &str =
    "SetupAssemblyProvenanceCertificateHash";
const SETUP_KEY_CORRECTNESS_CERTIFICATE_OBJECT_TYPE: &str = "SetupKeyCorrectnessCertificate";
const SETUP_KEY_CORRECTNESS_CERTIFICATE_HASH_NAMESPACE: &str = "SetupKeyCorrectnessCertificateHash";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_OBJECT_TYPE: &str =
    "ActiveStaticSetupTheoremCertificate";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_HASH_NAMESPACE: &str =
    "ActiveStaticSetupTheoremCertificateHash";
const SETUP_PROOF_BYTES_ACCEPTED_STATUS: &str = "private-vss-public-key-share-same-secret-linkage-anchor-and-trustee-evaluation-key-proof-bytes-accepted-for-setup-proof-accounting";
const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
const SETUP_TRANSPORT_STORAGE_QUOTA_BYTES: u64 = 2_147_483_648;
const SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES: u64 = 1_572_864;
const SETUP_TRANSPORT_COPY_COUNT_LIMIT: u64 = 2;
const SETUP_TRANSPORT_STREAM_ORDER: &str = "ascending-chunk-index";
const SETUP_TRANSPORT_RESUME_POLICY: &str = "chunk-index-checkpointed-by-hash";
const SETUP_TRANSPORT_LAZY_LOADING_POLICY: &str = "root-addressed-large-object-loading";
const SETUP_TRANSPORTED_VSS_MATERIAL_NAME: &str = "vssCoefficientCommitmentMaterial";
const SETUP_TRANSPORT_MEASUREMENT_ROW_OBJECT_TYPE: &str = "SetupTransportMeasurementRow";
const SETUP_TRANSPORT_MEASUREMENT_SUMMARY_OBJECT_TYPE: &str = "SetupTransportMeasurementSummary";
const SETUP_TRANSPORT_MEASUREMENT_KIND: &str = "static-profile-transport-manifest-accounting";
const SETUP_TRANSPORT_PROFILE_SCALE_STATUS: &str =
    "profile-scale-transport-manifest-bound-to-current-package-shape";
const SETUP_TRANSPORT_NATIVE_RELEASE_BOUNDARY: &str =
    "native-release-verifier-runtime-measurements-are-recorded-outside-this-certificate";
const SETUP_TRANSPORT_NODE_WASM_BOUNDARY: &str =
    "node-wasm-bridge-runtime-measurements-are-recorded-outside-this-certificate";
const SETUP_TRANSPORT_SUPPORTED_PHONE_BOUNDARY: &str =
    "supported-phone-runtime-evidence-is-deferred-and-not-required-by-this-setup-certificate";
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
const ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES: &[&str] = &[
    "same-secret-linkage-anchor",
    "public-key-share",
    "vss-opening-carry",
    "trustee-evaluation-key",
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
    "proofGeneration",
    "proofRandomness",
    "proofRandomnessNonceHex",
    "proofRandomnessSeedHex",
    "proofRandomnessSource",
    "externallySuppliedThresholdShareCommitments",
    "externallySuppliedThresholdShareCommitmentMaterial",
    "externallySuppliedUnverifiedThresholdShareCommitments",
];

const ACCEPTED_SETUP_TOP_LEVEL_FORBIDDEN_FIELD_NAMES: &[&str] = &[
    "targetDecryptionStatus",
    "targetDecryptionReadiness",
    "targetDecryptionCertificate",
    "targetDecryptionCertificateHash",
    "targetDecryptionClosure",
    "targetDecryptionClosureCertificate",
    "targetDecryptionShareProofs",
    "targetDecryptionShares",
    "targetPartDecRecords",
    "targetC1C4Certificate",
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
    "publicKeyShareSuccinctProofs",
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
    "setupAssemblyProvenanceCertificate",
    "setupAssemblyProvenanceCertificateHash",
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
        "thresholdProfile": accepted_setup_threshold_profile_value(),
        "thresholdProfileHash": accepted_setup_threshold_profile_hash()?,
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
        "topLevelForbiddenAcceptedPathFields": ACCEPTED_SETUP_TOP_LEVEL_FORBIDDEN_FIELD_NAMES,
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
            "verifiedSetupProofMaterials",
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

pub(crate) fn public_bgv_key_from_accepted_setup_public_key_material(
    accepted_public_key_material: &Value,
) -> CanonicalResult<BgvPublicKey> {
    let common_randomness = accepted_public_key_material
        .get("commonRandomness")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "acceptedPublicKeyMaterial.commonRandomness is required",
            )
        })?;
    let collective_public_key = accepted_public_key_material
        .get("collectivePublicKey")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "acceptedPublicKeyMaterial.collectivePublicKey is required",
            )
        })?;

    accepted_setup_collective_public_key_from_material(common_randomness, collective_public_key)
}

#[cfg(test)]
fn accepted_setup_verifier_phase(message: &str) {
    if !matches!(
        std::env::var("SEALED_LATTICE_TRACE_ACCEPTED_SETUP_VERIFIER").as_deref(),
        Ok("1")
    ) {
        return;
    }
    static ACCEPTED_SETUP_VERIFIER_PHASE_CLOCK: OnceLock<std::time::Instant> = OnceLock::new();
    let started = ACCEPTED_SETUP_VERIFIER_PHASE_CLOCK.get_or_init(std::time::Instant::now);
    println!(
        "accepted-setup-verifier-phase [+{}s] {message}",
        started.elapsed().as_secs()
    );
}

#[cfg(not(test))]
fn accepted_setup_verifier_phase(_message: &str) {}

fn verify_collective_setup_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<VerificationFlow> {
    accepted_setup_verifier_phase("start collective setup package verification");
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
    accepted_setup_verifier_phase("verified setup package hash");
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
    accepted_setup_verifier_phase("verified threshold share commitments");
    if let Some(response) = verify_same_secret_consistency(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_optional_same_secret_proofs(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified optional same-secret proofs");
    if let Some(response) = verify_public_key_shares(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_public_key_share_proofs(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) =
        verify_optional_public_key_share_succinct_proofs(setup_package, request)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified optional public-key share proofs");
    if let Some(response) = verify_collective_public_key_material(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified collective public-key material");
    accepted_setup_verifier_phase("checking public-key material acceptance boundary");
    if let Some(response) = verify_public_key_material_acceptance_boundary(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified public-key material acceptance boundary");
    accepted_setup_verifier_phase("checking evaluator key schedule");
    if let Some(response) = verify_evaluator_key_schedule(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified evaluator key schedule");
    accepted_setup_verifier_phase("checking pending evaluation-key material boundary");
    if let Some(response) = verify_pending_evaluation_key_material_boundary(setup_package, request)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified evaluation-key schedule boundary");
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
    if let Some(response) = verify_setup_assembly_provenance_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_key_correctness_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_active_static_setup_theorem_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified setup certificates");
    let declares_public_runtime_material =
        setup_package_declares_public_runtime_material(setup_package);
    accepted_setup_verifier_phase("checking profile-ring material");
    if declares_public_runtime_material
        && let Some(response) = verify_profile_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified first profile-ring material check");
    if let Some(response) = verify_required_final_objects(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if !declares_public_runtime_material
        && let Some(response) = verify_profile_ring_material(setup_package)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified final-object and profile-ring boundaries");
    accepted_setup_verifier_phase("checking terminal setup transport policy");
    if let Some(response) = verify_terminal_setup_transport_policy(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified terminal setup transport policy");
    accepted_setup_verifier_phase("checking required public evaluation-key set");
    if let Some(response) = verify_required_public_evaluation_key_set(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("verified required public evaluation-key set");
    if let Some(response) = verify_required_final_objects(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    accepted_setup_verifier_phase("completed collective setup package verification");
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

fn accepted_setup_threshold_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "CollectiveBgvSetupThresholdProfileHash",
        &accepted_setup_threshold_profile_value(),
    )
}

fn accepted_setup_threshold_profile_value() -> Value {
    json!({
        "objectType": "CollectiveBgvSetupThresholdProfile",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "setupCompletionQuorum": FIRST_PROFILE_SETUP_COMPLETION_QUORUM,
        "ballotReleaseQuorum": FIRST_PROFILE_BALLOT_RELEASE_QUORUM,
        "finalityQuorum": FIRST_PROFILE_FINALITY_QUORUM,
        "decryptionThreshold": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "completionRule": "full-roster",
        "livenessModel": "secure-with-abort",
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
        "privateVssShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
        "publicKeyShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
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
        "proofBackendBoundary": "sealed-lattice-rust-wasm-fixed-relations-only",
        "arbitraryRelationApi": "not-exposed",
        "relationModel": {
            "applicationRing": "Z_q[X]/(X^N+1)",
            "applicationRingDegree": POLYNOMIAL_DEGREE,
            "ringDegreeMapping": "full BGV polynomials are mapped into proof-ring polynomial vectors by the fixed isoring split",
            "rnsLimbCount": DATA_PRIMES.len(),
            "qShareHash": q_share_hash()?,
            "commitmentProfileHash": setup_commitment_profile_hash()?,
            "statementEncoding": "canonical-json-roots-plus-binary-proof-chunks",
            "relationForm": "A*witness = target + q_l*carry over lifted integers with explicit no-wrap bounds",
            "limbHandling": "relations are checked per accepted Q_share limb and bind one shared trustee secret where required"
        },
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
        "privateVssShareProofAccounting": super::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_value()?,
        "privateVssShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
        "publicKeyShareProofAccounting": super::trustee_evaluation_key_proof::succinct_public_key_share_accounting_value()?,
        "publicKeyShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
        "sameSecretLinkageAnchorProofAccountingHash":
            super::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
        "trusteeEvaluationKeyProofAccountingHash":
            super::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
        "proofSerialization": {
            "encoding": SETUP_PROOF_SERIALIZATION,
            "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
            "succinctProofByteLayout": {
                "encoding": "sealed-lattice-succinct-setup-proof-bytes",
                "canonicalFieldElementStatus": "decoder-rejects-non-canonical-base-and-extension-field-coordinates",
                "transportRootStatus": "embedded-and-binary-chunked-proof-material-roots-bind-proof-size-bytes-proof-bytes-hash-and-statement-hash"
            },
            "chunking": "required-for-large-proof-material",
            "chunkRootRequired": true,
            "statementRootRequired": true,
            "canonicalJsonRole": "root-bound metadata only"
        },
        "verificationPolicy": {
            "rejectionRules": [
                "wrong setup-proof profile",
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

fn setup_proof_record_binding_value() -> CanonicalResult<Value> {
    super::setup_proof::setup_proof_record_binding_value(
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )
}

fn setup_proof_family_profiles() -> CanonicalResult<Vec<Value>> {
    let family_profiles = ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES
        .iter()
        .map(|proof_family| {
            let (statement, witness, no_wrap_rule, proof_accounting_hash) = match *proof_family {
                "same-secret-linkage-anchor" => (
                    "same-secret linkage anchor opens every accepted VSS constant commitment to one short trustee secret",
                    "one ternary trustee secret, negative indicators, and opening randomness for every accepted Q_share constant commitment",
                    "commitment openings are checked over the accepted commitment-modulus fields and cross-limb consistency binds one centered integer secret",
                    super::trustee_evaluation_key_proof::succinct_same_secret_linkage_anchor_accounting_hash()?,
                ),
                "public-key-share" => (
                    "public-key share relation proves b_l + a_l*s - p*e = 0 over every accepted Q_share limb",
                    "one ternary trustee secret, one centered-binomial error vector, and the selected limb-zero commitment opening randomness",
                    "the selected limb-zero opening links the share secret to the same-secret anchor; ternary support makes the congruent secrets equal",
                    super::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
                ),
                "vss-opening-carry" => (
                    "private VSS share opens the homomorphic coefficient-commitment combination with explicit q_l carry",
                    "private share, coefficient openings, and bounded non-negative carry",
                    "unreduced lifted share relation must hold below the commitment modulus product",
                    super::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
                ),
                "trustee-evaluation-key" => (
                    "trustee evaluation-key relation proves every scheduled relinearization and Galois share against the committed trustee secret",
                    "one trustee secret, schedule-bound key-switch source witnesses, component openings, carry witnesses, and same-secret linkage openings",
                    "round-one, round-two, and Galois source relations are enforced against the frozen evaluator schedule and recomputed public aggregates",
                    super::trustee_evaluation_key_proof::succinct_evaluation_key_proof_accounting_hash()?,
                ),
                _ => unreachable!("ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES is fixed in this module"),
            };
            Ok(json!({
                "proofFamily": proof_family,
                "statement": statement,
                "witness": witness,
                "noWrapRule": no_wrap_rule,
                "profileId": SETUP_PROOF_PROFILE_ID,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "verificationStatus": "family-verifier-required-before-proof-bytes-acceptance",
                "proofAccountingHash": proof_accounting_hash,
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
        "setupAssemblyProvenanceCertificateHash",
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
        .get("publicKeyShareSuccinctProofs")
        .and_then(|proof_set| proof_set.get("publicKeyShareSuccinctProofSetRoot"))
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
    let accepted_setup_handoff = accepted_setup_handoff_value(setup_package)?;
    let accepted_public_key_material =
        direct_ballot_accepted_public_key_material_value(setup_package, &accepted_setup_handoff)?;
    let mut response = verification_response(
        VerifierStatus::Accepted,
        Some("setupPackageVerification"),
        Vec::new(),
        Vec::new(),
        accepted_hashes_from_package(setup_package),
    )?;
    let response_object = response
        .as_object_mut()
        .expect("verification response is a JSON object");
    response_object.insert("acceptedSetupHandoff".to_string(), accepted_setup_handoff);
    response_object.insert(
        "acceptedPublicKeyMaterial".to_string(),
        accepted_public_key_material,
    );

    Ok(response)
}

#[cfg(test)]
pub(crate) fn accepted_setup_verification_response_for_test(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    accepted_setup_verification_response(setup_package)
}

pub(crate) fn direct_ballot_creation_policy_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectEncryptedBallotCreationPolicyHash",
        &direct_ballot_creation_policy_value()?,
    )
}

pub(crate) fn direct_ballot_creation_policy_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "DirectEncryptedBallotCreationPolicy",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "acceptedPackageObjectType": "EncryptedBallotPackage",
        "validityStatementId": "BallotValidityStatement-v1",
        "proofProfileHash": direct_ballot_relation_proof_profile_hash()?,
        "bgvProfileHash": profile_hash()?,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
        "batchEncoderHash": batch_encoder_hash()?,
        "batchLayoutBindingHash": batch_layout_binding_hash()?,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
        "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()?,
        "directBallotReservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()?,
        "directBallotEncoderMatrixRoot": direct_ballot_encoder_matrix_root()?,
        "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
        "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
        "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
        "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
        "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?,
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreDomain": {
            "minimum": DIRECT_BALLOT_MINIMUM_SCORE,
            "maximum": DIRECT_BALLOT_MAXIMUM_SCORE,
            "bucketCount": DIRECT_BALLOT_SCORE_BUCKET_COUNT,
            "unsetUiValue": DIRECT_BALLOT_MINIMUM_SCORE,
        },
        "reservedSlotRule": direct_ballot_reserved_slot_rule_value()?,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "randomnessBoundary": "platform CSPRNG material is required; caller-supplied seeds, fixture-labelled randomness, overlapping randomness, and reused randomness are refused",
        "creatorReturnPolicy": "accepted ballot creation returns public package data, proof chunks, public roots, timing, memory, and proof-size reports only",
        "forbiddenPackageFields": [
            "scoreHash",
            "plaintextScores",
            "scoreCommitment",
            "encryptionRandomness",
            "proofWitness",
            "proofRandomnessSeed",
            "fixtureSeed",
            "oracleResult",
            "developmentPlaintext"
        ],
    }))
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
    let collective_public_key_root = package_nested_hash(
        setup_package,
        "collectivePublicKey",
        "collectivePublicKeyRoot",
    )?;
    let bgv_public_key_root = direct_ballot_bgv_public_key_root_from_setup_package(setup_package)?;
    let public_key_share_material_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareMaterial",
        "publicKeyShareMaterialSetRoot",
    )?;
    let public_key_share_succinct_proof_set_root = package_nested_hash(
        setup_package,
        "publicKeyShareSuccinctProofs",
        "publicKeyShareSuccinctProofSetRoot",
    )?;
    let mut handoff = json!({
        "objectType": "CollectiveBgvAcceptedSetupHandoff",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "thresholdProfileHash": accepted_setup_threshold_profile_hash()?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupPackageHash": value_string(setup_package, "setupPackageHash")?,
        "directBallotEncryptionHandoff": {
            "status": "accepted-collective-public-key-root-bound-for-direct-ballot-encryption",
            "collectivePublicKeyRoot": collective_public_key_root.as_str(),
            "bgvPublicKeyRoot": bgv_public_key_root.as_str(),
            "bgvProfileHash": profile_hash()?,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "batchEncoderHash": batch_encoder_hash()?,
            "batchLayoutBindingHash": batch_layout_binding_hash()?,
            "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
            "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()?,
            "directBallotReservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()?,
            "directBallotEncoderMatrixRoot": direct_ballot_encoder_matrix_root()?,
            "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()?,
            "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
            "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
            "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
            "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?,
            "ballotValidityProofProfileHash": direct_ballot_relation_proof_profile_hash()?,
            "publicKeyShareMaterialSetRoot": public_key_share_material_set_root.as_str(),
            "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root.as_str(),
            "acceptedPublicKeyMaterial": {
                "materialSource": "accepted public-key share material with accepted public-key share proofs",
                "collectivePublicKeyRoot": collective_public_key_root.as_str(),
                "bgvPublicKeyRoot": bgv_public_key_root.as_str(),
                "publicKeyShareMaterialSetRoot": public_key_share_material_set_root.as_str(),
                "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root.as_str(),
            },
            "supportedBallotCreationPolicyHash": direct_ballot_creation_policy_hash()?,
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
            "setupAssemblyProvenanceCertificateHash": value_string(
                setup_package,
                "setupAssemblyProvenanceCertificateHash",
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

fn direct_ballot_accepted_public_key_material_value(
    setup_package: &Value,
    accepted_setup_handoff: &Value,
) -> CanonicalResult<Value> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before accepted public-key material construction",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before accepted public-key material construction",
        )
    })?;
    let collective_public_key = setup_package.get("collectivePublicKey").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collectivePublicKey was required before accepted public-key material construction",
        )
    })?;
    let direct_ballot_handoff = accepted_setup_handoff
        .get("directBallotEncryptionHandoff")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "directBallotEncryptionHandoff was required before accepted public-key material construction",
            )
        })?;

    Ok(json!({
        "objectType": "DirectBallotAcceptedPublicKeyMaterial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "thresholdProfileHash": accepted_setup_threshold_profile_hash()?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "setupPackageHash": value_string(setup_package, "setupPackageHash")?,
        "acceptedSetupHandoffRoot": value_string(accepted_setup_handoff, "acceptedSetupHandoffRoot")?,
        "bgvProfileHash": value_string(direct_ballot_handoff, "bgvProfileHash")?,
        "batchEncoderHash": value_string(direct_ballot_handoff, "batchEncoderHash")?,
        "batchLayoutBindingHash": value_string(direct_ballot_handoff, "batchLayoutBindingHash")?,
        "ballotScoreEncodingProfileHash": value_string(
            direct_ballot_handoff,
            "ballotScoreEncodingProfileHash",
        )?,
        "encryptedBallotLayoutHash": value_string(direct_ballot_handoff, "encryptedBallotLayoutHash")?,
        "directBallotReservedSlotRuleHash": value_string(
            direct_ballot_handoff,
            "directBallotReservedSlotRuleHash",
        )?,
        "directBallotEncoderMatrixRoot": value_string(
            direct_ballot_handoff,
            "directBallotEncoderMatrixRoot",
        )?,
        "arithmeticCertificateHash": value_string(direct_ballot_handoff, "arithmeticCertificateHash")?,
        "soundnessCertificateHash": value_string(direct_ballot_handoff, "soundnessCertificateHash")?,
        "zeroKnowledgeCertificateHash": value_string(
            direct_ballot_handoff,
            "zeroKnowledgeCertificateHash",
        )?,
        "verifierCertificateHash": value_string(direct_ballot_handoff, "verifierCertificateHash")?,
        "ballotValidityProofProfileHash": value_string(
            direct_ballot_handoff,
            "ballotValidityProofProfileHash",
        )?,
        "collectivePublicKeyRoot": value_string(direct_ballot_handoff, "collectivePublicKeyRoot")?,
        "bgvPublicKeyRoot": value_string(direct_ballot_handoff, "bgvPublicKeyRoot")?,
        "publicKeyShareMaterialSetRoot": value_string(
            direct_ballot_handoff,
            "publicKeyShareMaterialSetRoot",
        )?,
        "publicKeyShareSuccinctProofSetRoot": value_string(
            direct_ballot_handoff,
            "publicKeyShareSuccinctProofSetRoot",
        )?,
        "commonRandomness": common_randomness,
        "collectivePublicKey": collective_public_key,
    }))
}

fn direct_ballot_bgv_public_key_root_from_setup_package(
    setup_package: &Value,
) -> CanonicalResult<String> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage.commonRandomness is required",
        )
    })?;
    let collective_public_key = setup_package.get("collectivePublicKey").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupPackage.collectivePublicKey is required",
        )
    })?;
    let aggregate_limb_hashes = collective_public_key
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupPackage.collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?
        .iter()
        .map(|aggregate_limb| {
            Ok(json!({
                "rnsLimbIndex": value_u64(aggregate_limb, "rnsLimbIndex")?,
                "rnsPrime": value_u64(aggregate_limb, "rnsPrime")?,
                "component": value_string(aggregate_limb, "component")?,
                "coefficientByteLength": value_u64(aggregate_limb, "coefficientByteLength")?,
                "coefficientVectorHash512": value_string(
                    aggregate_limb,
                    "coefficientVectorHash512",
                )?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "objectType": "AcceptedBgvPublicKeyRootBinding",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "bgvProfileHash": profile_hash()?,
            "collectivePublicKeyRoot": value_string(
                collective_public_key,
                "collectivePublicKeyRoot",
            )?,
            "publicMatrixSeedHash": value_string(common_randomness, "publicMatrixSeedHash")?,
            "publicAPolynomialRoot": value_string(collective_public_key, "publicAPolynomialRoot")?,
            "publicKeyShareMaterialSetRoot": value_string(
                collective_public_key,
                "publicKeyShareMaterialSetRoot",
            )?,
            "publicKeyShareSuccinctProofSetRoot": value_string(
                collective_public_key,
                "publicKeyShareSuccinctProofSetRoot",
            )?,
            "aggregateCoefficientVectorHashesByLimb": aggregate_limb_hashes,
        }),
    )
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
    if let Some(fields) = value.as_object() {
        for field_name in fields.keys() {
            if ACCEPTED_SETUP_TOP_LEVEL_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str()) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    format!(
                        "{field_name} cannot appear as a top-level accepted collective BGV setup field"
                    ),
                ));
            }
        }
    }
    reject_accepted_setup_forbidden_fields_recursively(value)
}

fn reject_accepted_setup_forbidden_fields_recursively(value: &Value) -> CanonicalResult<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                reject_accepted_setup_forbidden_fields_recursively(item)?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str()) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidProtocolObject,
                        format!(
                            "{field_name} cannot appear in accepted collective BGV setup material"
                        ),
                    ));
                }
                reject_accepted_setup_forbidden_fields_recursively(field_value)?;
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
        if ACCEPTED_SETUP_TOP_LEVEL_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str())
            || ACCEPTED_SETUP_FORBIDDEN_FIELD_NAMES.contains(&field_name.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{field_name} cannot appear in accepted collective BGV setup requests"),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod accepted_setup_response_tests {
    use super::*;

    #[test]
    fn accepted_setup_response_returns_direct_ballot_material_bound_to_handoff() {
        let public_key_share_material_set_root =
            unit_hash("public key share material set root").expect("material root");
        let public_key_share_succinct_proof_set_root =
            unit_hash("public key share succinct proof set root").expect("proof root");
        let public_matrix_seed_hash =
            unit_hash("public matrix seed hash").expect("public matrix seed hash");
        let public_a_polynomial_root =
            unit_hash("public A polynomial root").expect("public A polynomial root");

        let mut collective_public_key = json!({
            "objectType": "CollectivePublicKey",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
            "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root,
            "aggregateCoefficientVectorsByLimb": [{
                "rnsLimbIndex": 0,
                "rnsPrime": 65537,
                "component": "b",
                "coefficientByteLength": 8,
                "coefficientVectorHash512": unit_hash("aggregate coefficient vector")
                    .expect("aggregate coefficient vector hash"),
            }],
        });
        let collective_public_key_root =
            derive_protocol_hash("CollectivePublicKeyRoot", &collective_public_key)
                .expect("collective public key root");
        collective_public_key["collectivePublicKeyRoot"] = json!(collective_public_key_root);

        let package = json!({
            "objectType": SETUP_PACKAGE_OBJECT_TYPE,
            "setupContext": {
                "ceremonyId": "accepted-setup-response-test",
                "manifestHash": unit_hash("manifest").expect("manifest hash"),
                "rosterHash": unit_hash("roster").expect("roster hash"),
                "setupProfileHash": unit_hash("setup profile").expect("setup profile hash"),
                "qShareHash": unit_hash("Q share").expect("Q share hash"),
                "commitmentProfileHash": unit_hash("commitment profile")
                    .expect("commitment profile hash"),
                "setupEpoch": "0",
            },
            "setupPackageHash": unit_hash("setup package").expect("setup package hash"),
            "commonRandomness": {
                "objectType": "SetupCommonRandomness",
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "publicDerivations": {},
            },
            "collectivePublicKey": collective_public_key,
            "publicKeyShareMaterial": {
                "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
            },
            "publicKeyShareSuccinctProofs": {
                "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root,
            },
            "thresholdShareCommitments": {
                "thresholdShareCommitmentRoot": unit_hash("threshold share commitments")
                    .expect("threshold share commitment root"),
            },
            "evaluatorKeySchedule": {
                "evaluatorKeyScheduleRoot": unit_hash("evaluator key schedule")
                    .expect("evaluator key schedule root"),
            },
            "relinearizationKeyShareRounds": {
                "relinearizationKeyShareRoundsRoot": unit_hash("relinearization key share rounds")
                    .expect("relinearization key share rounds root"),
            },
            "trusteeEvaluationKeyProofs": {
                "trusteeEvaluationKeyProofSetRoot": unit_hash("trustee evaluation-key proofs")
                    .expect("trustee evaluation-key proof set root"),
            },
            "evaluationKeys": {
                "evaluationKeySetHash": unit_hash("evaluation keys")
                    .expect("evaluation key set hash"),
            },
            "heSecurityCertificate": {
                "targetDecryptionStatus": {
                    "targetDecryptionReadiness": "downstream",
                    "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
                },
            },
            "setupCommitmentSecurityCertificateHash": unit_hash("setup commitment certificate")
                .expect("setup commitment certificate hash"),
            "setupTransportCertificateHash": unit_hash("setup transport certificate")
                .expect("setup transport certificate hash"),
            "setupProofAccountingCertificateHash": unit_hash("setup proof accounting certificate")
                .expect("setup proof accounting certificate hash"),
            "setupAssemblyProvenanceCertificateHash": unit_hash(
                "setup assembly provenance certificate",
            )
            .expect("setup assembly provenance certificate hash"),
            "setupKeyCorrectnessCertificateHash": unit_hash("setup key correctness certificate")
                .expect("setup key correctness certificate hash"),
            "activeStaticSetupTheoremCertificateHash": unit_hash("active static theorem certificate")
                .expect("active static theorem certificate hash"),
            "heSecurityCertificateHash": unit_hash("HE security certificate")
                .expect("HE security certificate hash"),
        });

        let response =
            accepted_setup_verification_response(&package).expect("accepted setup response");
        let accepted_setup_handoff = &response["acceptedSetupHandoff"];
        let accepted_public_key_material = &response["acceptedPublicKeyMaterial"];
        let expected_bgv_public_key_root =
            direct_ballot_bgv_public_key_root_from_setup_package(&package)
                .expect("direct ballot BGV public key root");

        assert_eq!(response["verifierStatus"], "accepted");
        assert_eq!(
            accepted_public_key_material["objectType"],
            "DirectBallotAcceptedPublicKeyMaterial"
        );
        assert_eq!(
            accepted_public_key_material["acceptedSetupHandoffRoot"],
            accepted_setup_handoff["acceptedSetupHandoffRoot"]
        );
        assert_eq!(
            accepted_public_key_material["setupPackageHash"],
            package["setupPackageHash"]
        );
        assert_eq!(
            accepted_public_key_material["commonRandomness"],
            package["commonRandomness"]
        );
        assert_eq!(
            accepted_public_key_material["collectivePublicKey"],
            package["collectivePublicKey"]
        );
        assert_eq!(
            accepted_public_key_material["bgvPublicKeyRoot"],
            expected_bgv_public_key_root
        );
        assert_eq!(
            accepted_setup_handoff["directBallotEncryptionHandoff"]["bgvPublicKeyRoot"],
            expected_bgv_public_key_root
        );
        assert!(
            accepted_setup_handoff["directBallotEncryptionHandoff"]
                .get("supportedBallotCreationPolicy")
                .is_none(),
            "accepted setup handoff must bind the direct ballot creation policy by hash, not embed the policy body"
        );
        assert_eq!(
            accepted_setup_handoff["directBallotEncryptionHandoff"]["supportedBallotCreationPolicyHash"],
            direct_ballot_creation_policy_hash().expect("direct ballot creation policy hash")
        );
        let accepted_setup_handoff_json =
            serde_json::to_string(accepted_setup_handoff).expect("accepted setup handoff JSON");
        for forbidden_fragment in [
            "setupSeed",
            "setupPrivateWitness",
            "proofRandomnessSeedHex",
            "developmentPlaintext",
        ] {
            assert!(
                !accepted_setup_handoff_json.contains(forbidden_fragment),
                "accepted setup handoff must not contain {forbidden_fragment}"
            );
        }
        assert!(
            package["collectivePublicKey"]
                .get("bgvPublicKeyRoot")
                .is_none(),
            "accepted setup response must derive the direct ballot BGV public-key root instead of requiring a package field"
        );
    }

    fn unit_hash(label: &str) -> CanonicalResult<String> {
        Ok(crate::hashing::hash512_hex(
            "sealed-lattice/accepted-setup-response-test-hash-v1",
            &[label.as_bytes()],
        ))
    }
}
