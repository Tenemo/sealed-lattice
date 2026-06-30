mod accepted_certificates;
mod common_randomness;
mod compact_same_secret_bridge_verification;
mod compact_vss_public_material_verification;
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
pub(in crate::bgv::setup) use self::accepted_certificates::{
    accepted_he_security_certificate_hash_for_roster,
    accepted_he_security_certificate_value_for_roster,
};
#[cfg(test)]
pub(super) use self::accepted_certificates::{
    accepted_he_security_certificate_value, active_static_setup_theorem_certificate_hash,
    active_static_setup_theorem_certificate_value, setup_key_correctness_certificate_hash,
    setup_key_correctness_certificate_value, setup_proof_accounting_certificate_hash,
    setup_proof_accounting_certificate_value,
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
#[cfg(test)]
pub(in crate::bgv::setup) use self::common_randomness::derive_collective_bgv_setup_public_derivations as derive_collective_bgv_setup_public_derivations_for_roster;
use self::common_randomness::{
    derive_bgv_public_a_polynomial, derive_collective_bgv_setup_public_derivations,
    verify_common_randomness,
};
use self::compact_same_secret_bridge_verification::verify_optional_compact_same_secret_bridge_statement_set;
use self::compact_vss_public_material_verification::verify_optional_compact_vss_public_material;
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
    round_one_public_aggregate_diagonals_from_package,
    stored_verified_trustee_evaluation_key_proof_material_chunks_for_test,
    trustee_evaluation_key_proof_material_root, trustee_evaluation_key_statement_from_package,
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
use self::phase_transcript::{
    setup_context_string, verify_abort_absence, verify_phase_transcript,
    verify_setup_intent_roster_hash,
};
use self::private_vss_envelopes::{
    PrivateVssEnvelopeBindingMap, private_vss_envelope_bindings_from_package,
    verify_private_vss_envelope_commitments,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::public_key_share_material::public_key_share_coefficient_vector_hash;
use self::public_key_share_material::{
    PublicKeyShareMaterialBinding, public_key_share_material_uses_transport,
    verify_collective_public_key_material, verify_collective_public_key_pair_consistency,
    verify_public_key_share_material_set,
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
    setup_transport_chunk_manifest_root, setup_transport_vss_material_byte_length_for_roster,
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
use crate::bgv::evaluator::top_k::{
    SELECTED_EVALUATOR_WORKING_LEVEL, canonical_target_basis_hash, canonical_target_basis_value,
    direct_score_packing_basis_galois_elements, packed_rank_forward_basis_galois_elements,
    packed_rank_return_basis_galois_elements,
};
use crate::bgv::profile::SPECIAL_PRIME;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    CLAIM_MASK_DIGIT_COUNT, CLAIM_MASK_RADIX, COMPACT_VSS_CARRY_CLAIM_MASK_DIGIT_COUNT,
    COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS, COMPACT_VSS_CONSISTENCY_REPETITIONS,
    COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT, CONSISTENCY_COEFFICIENT_BITS,
    CONSISTENCY_REPETITIONS, TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
    TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT,
    TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
};
use crate::bgv::target_decryption::TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
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
const PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING: &str =
    "root-bound-public-key-switch-component-roots";
pub(super) const PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING: &str =
    "binary-chunked-public-evaluation-key-root-manifest";
const PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC: &[u8; 8] = b"SLEKPMV1";
use super::trustee_evaluation_key_proof::TRUSTEE_EVALUATION_KEY_PROOF_FAMILY;
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
// Supported parameterized roster range. The first closure profile (n = 10) is
// the only benchmarked, mobile-certified instance; the verifier
// accepts any 3 <= n <= 20 by deriving the canonical quorums and threshold from
// the roster size, but no runtime/security/mobile evidence is established for
// n != 10 until those profiles receive their own certificates and measurements.
pub(super) const MINIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 3;
pub(super) const MAXIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 20;

/// Validated roster parameters for a collective BGV setup profile. Every field
/// is a pure function of `participant_count`, so the profile hash is a roster
/// family: distinct per n, byte-identical to the historical first-profile
/// binding at n = 10.
#[derive(Clone, Copy)]
pub(super) struct AcceptedRosterParameters {
    pub(super) participant_count: u64,
    pub(super) setup_completion_quorum: u64,
    pub(super) ballot_release_quorum: u64,
    pub(super) finality_quorum: u64,
    pub(super) decryption_threshold: u64,
}

/// q_dec = floor(n / 3) + 1: the structural one-third privacy bound plus one
/// (the stronger-privacy, non-degenerate convention; at n = 3 this is 2-of-3,
/// never 1-of-3). Setup, ballot release, and finality are full-roster (= n)
/// under the secure-with-abort model.
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
    roster_parameters_from_participant_count(FIRST_PROFILE_PARTICIPANT_COUNT)
}

/// Roster parameters for the roster size declared in a verified setup context.
/// `verify_context` validates `participantCount` (range and derived quorums)
/// before any sub-verifier runs, so reading it back here is safe; the
/// first-closure fallback keeps callers total if the context is absent.
pub(super) fn accepted_roster_from_setup_context(
    setup_context: &Value,
) -> AcceptedRosterParameters {
    let participant_count = setup_context
        .get("participantCount")
        .and_then(Value::as_u64)
        .unwrap_or(FIRST_PROFILE_PARTICIPANT_COUNT);
    roster_parameters_from_participant_count(participant_count)
}

pub(super) fn accepted_roster_from_package(setup_package: &Value) -> AcceptedRosterParameters {
    setup_package
        .get("setupContext")
        .map(accepted_roster_from_setup_context)
        .unwrap_or_else(first_closure_roster_parameters)
}
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
const SETUP_KEY_CORRECTNESS_CERTIFICATE_OBJECT_TYPE: &str = "SetupKeyCorrectnessCertificate";
const SETUP_KEY_CORRECTNESS_CERTIFICATE_HASH_NAMESPACE: &str = "SetupKeyCorrectnessCertificateHash";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_OBJECT_TYPE: &str =
    "ActiveStaticSetupTheoremCertificate";
const ACTIVE_STATIC_SETUP_THEOREM_CERTIFICATE_HASH_NAMESPACE: &str =
    "ActiveStaticSetupTheoremCertificateHash";
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
        "canonicalTargetBasis": canonical_target_basis_value()?,
        "canonicalTargetBasisHash": canonical_target_basis_hash()?,
        "compactVssMatrixExpansionProfile": compact_vss_matrix_expansion_profile_value(),
        "compactVssMatrixExpansionProfileHash": compact_vss_matrix_expansion_profile_hash()?,
        "compactVssParameterCertificateInputBinding": compact_vss_parameter_certificate_input_binding_value()?,
        "compactVssParameterCertificateInputBindingHash": compact_vss_parameter_certificate_input_binding_hash()?,
        "currentVssMaterialBaselineReport": current_vss_material_baseline_report_value()?,
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
        "phaseOrder": phase_order_value(),
        "phaseOrderHash": phase_order_hash()?,
        "requiredFinalObjects": REQUIRED_FINAL_OBJECTS,
        "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
    }))
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
    // falls back to the first-closure roster decryption threshold, mirroring
    // accepted_roster_from_package when no setupContext is present.
    derive_collective_bgv_setup_public_derivations(
        public_matrix_seed_hash,
        FIRST_PROFILE_DECRYPTION_THRESHOLD,
    )
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_required_public_evaluation_key_set_for_test(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    verify_required_public_evaluation_key_set(setup_package, request)
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_setup_key_correctness_certificate_for_test(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    verify_setup_key_correctness_certificate(setup_package)
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
    if let Some(response) = verify_optional_compact_vss_public_material(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_same_secret_consistency(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_optional_same_secret_proofs(setup_package, request)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) =
        verify_optional_compact_same_secret_bridge_statement_set(setup_package, request)?
    {
        return Ok(VerificationFlow::Stop(response));
    }
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
    if let Some(response) = verify_he_security_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_setup_key_correctness_certificate(setup_package)? {
        return Ok(VerificationFlow::Stop(response));
    }
    if let Some(response) = verify_transport_certificate(setup_package, request)? {
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

pub(super) fn accepted_q_share_hash() -> CanonicalResult<String> {
    q_share_hash()
}

fn setup_profile_hash() -> CanonicalResult<String> {
    setup_profile_hash_for_roster(&first_closure_roster_parameters())
}

pub(super) fn setup_profile_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "CollectiveBgvSetupProfileHash",
        &setup_profile_binding(roster)?,
    )
}

fn setup_profile_binding(roster: &AcceptedRosterParameters) -> CanonicalResult<Value> {
    Ok(json!({
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "adversaryModel": "active-static",
        "livenessModel": "secure-with-abort",
        "sharingModel": "recipient-verified-vss",
        "sharingDomain": "per-rns-prime",
        "participantCount": roster.participant_count,
        "qSetupComplete": roster.setup_completion_quorum,
        "qBallotRelease": roster.ballot_release_quorum,
        "qFinal": roster.finality_quorum,
        "qDec": roster.decryption_threshold,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash()?,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "setupProofProfileHash": setup_proof_profile_hash()?,
        "privateVssShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_private_vss_share_accounting_hash()?,
        "publicKeyShareProofAccountingHash": super::trustee_evaluation_key_proof::succinct_public_key_share_accounting_hash()?,
        "setupTransportProfileHash": setup_transport_profile_hash_for_roster(roster)?,
        "evaluatorKeyScheduleProfileHash": evaluator_key_schedule_profile_hash_for_roster(roster)?,
    }))
}

pub(super) fn setup_proof_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash("SetupProofProfileHash", &setup_proof_profile_value()?)
}

fn setup_transport_profile_hash() -> CanonicalResult<String> {
    setup_transport_profile_hash_for_roster(&first_closure_roster_parameters())
}

fn setup_transport_profile_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupTransportProfileHash",
        &setup_transport_profile_value_for_roster(roster)?,
    )
}

fn evaluator_key_schedule_profile_hash() -> CanonicalResult<String> {
    evaluator_key_schedule_profile_hash_for_roster(&first_closure_roster_parameters())
}

fn evaluator_key_schedule_profile_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluatorKeyScheduleProfileHash",
        &evaluator_key_schedule_profile_value_for_roster(roster)?,
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
        "ringDegree": POLYNOMIAL_DEGREE,
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
    }))
}

fn compact_vss_matrix_expansion_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "CompactVssMatrixExpansionProfileHash",
        &compact_vss_matrix_expansion_profile_value(),
    )
}

fn compact_vss_matrix_expansion_profile_value() -> Value {
    let commitment_modulus_limb_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64;
    let output_coordinate_count = 16_u64;
    let projection_weight = 32_u64;
    let randomness_column_count = 2_u64;
    let message_column_count =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT as u64;
    let input_column_count = message_column_count + randomness_column_count;
    let coordinate_count_per_commitment = commitment_modulus_limb_count * output_coordinate_count;
    let sampled_matrix_residues_per_coordinate = input_column_count * projection_weight;
    let sampled_projection_indices_per_coordinate = sampled_matrix_residues_per_coordinate;
    let sampled_matrix_residues_per_commitment =
        coordinate_count_per_commitment * sampled_matrix_residues_per_coordinate;
    let sampled_projection_indices_per_commitment =
        coordinate_count_per_commitment * sampled_projection_indices_per_coordinate;
    let input_column_labels = (0..message_column_count)
        .map(|digit_index| json!(format!("message:{digit_index}")))
        .chain(
            (0..randomness_column_count)
                .map(|column_index| json!(format!("randomness:{column_index}"))),
        )
        .collect::<Vec<_>>();

    json!({
        "objectType": "CompactVssMatrixExpansionProfile",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
        "matrixKind": "compact-vss-commitment-key",
        "ringDegree": POLYNOMIAL_DEGREE,
        "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
        "outputCoordinateCount": output_coordinate_count,
        "projectionWeight": projection_weight,
        "randomnessColumnCount": randomness_column_count,
        "inputColumnLabels": input_column_labels,
        "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
        "projectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
        "rejectionSamplingRule": "sample little-endian 64-bit chunks and reject values at or above 2^64 - (2^64 mod modulus or ringDegree)",
        "matrixResiduePreimageFields": [
            "publicMatrixSeedHash",
            "profileId",
            "rnsLimbIndex",
            "commitmentModulusIndex",
            "outputCoordinateIndex",
            "inputColumn",
            "projectionTermIndex",
            "modulus",
            "blockIndex"
        ],
        "projectionIndexPreimageFields": [
            "publicMatrixSeedHash",
            "profileId",
            "rnsLimbIndex",
            "commitmentModulusIndex",
            "outputCoordinateIndex",
            "inputColumn",
            "projectionTermIndex",
            "ringDegree",
            "blockIndex"
        ],
        "coordinateCountPerCommitment": coordinate_count_per_commitment,
        "sampledMatrixResiduesPerCoordinate": sampled_matrix_residues_per_coordinate,
        "sampledProjectionIndicesPerCoordinate": sampled_projection_indices_per_coordinate,
        "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
        "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
        "residueMultiplyAddsPerCommitment": sampled_matrix_residues_per_commitment,
    })
}

fn compact_vss_parameter_certificate_input_binding_hash() -> CanonicalResult<String> {
    let roster = first_closure_roster_parameters();
    compact_vss_parameter_certificate_input_binding_hash_for_roster(&roster)
}

fn compact_vss_parameter_certificate_input_binding_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "CompactVssParameterCertificateInputBindingHash",
        &compact_vss_parameter_certificate_input_binding_body_value_for_roster(roster)?,
    )
}

fn compact_vss_parameter_certificate_input_binding_value() -> CanonicalResult<Value> {
    let roster = first_closure_roster_parameters();
    compact_vss_parameter_certificate_input_binding_value_for_roster(&roster)
}

fn compact_vss_parameter_certificate_input_binding_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let mut binding =
        compact_vss_parameter_certificate_input_binding_body_value_for_roster(roster)?;
    let binding_hash = compact_vss_parameter_certificate_input_binding_hash_for_roster(roster)?;
    let binding_object = binding.as_object_mut().ok_or_else(|| {
        static_accounting_error("compact VSS parameter certificate input binding is not an object")
    })?;
    binding_object.insert(
        "compactVssParameterCertificateInputBindingHash".to_owned(),
        Value::String(binding_hash),
    );

    Ok(binding)
}

fn compact_vss_parameter_certificate_input_binding_body_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let source_rns_limb_count = DATA_PRIMES.len() as u64;
    let target_rns_limb_count =
        (crate::bgv::evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1) as u64;
    let commitment_modulus_limb_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64;
    let output_coordinate_count =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT as u64;
    let randomness_column_count =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT as u64;
    let message_column_count =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT as u64;
    let projection_weight =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_PROJECTION_WEIGHT as u64;
    let input_column_count = message_column_count
        .checked_add(randomness_column_count)
        .ok_or_else(|| static_accounting_error("compact VSS input column count overflowed"))?;
    let coordinate_count_per_commitment = commitment_modulus_limb_count
        .checked_mul(output_coordinate_count)
        .ok_or_else(|| {
            static_accounting_error("compact VSS coordinate count per commitment overflowed")
        })?;
    let sampled_matrix_residues_per_coordinate = input_column_count
        .checked_mul(projection_weight)
        .ok_or_else(|| {
            static_accounting_error("compact VSS sampled matrix residues per coordinate overflowed")
        })?;
    let sampled_projection_indices_per_coordinate = sampled_matrix_residues_per_coordinate;
    let sampled_matrix_residues_per_commitment = coordinate_count_per_commitment
        .checked_mul(sampled_matrix_residues_per_coordinate)
        .ok_or_else(|| {
            static_accounting_error("compact VSS sampled matrix residues per commitment overflowed")
        })?;
    let sampled_projection_indices_per_commitment = coordinate_count_per_commitment
        .checked_mul(sampled_projection_indices_per_coordinate)
        .ok_or_else(|| {
            static_accounting_error(
                "compact VSS sampled projection indices per commitment overflowed",
            )
        })?;
    let maximum_recipient_trustee_point = roster.participant_count;
    let maximum_one_source_shamir_scalar_l1 = shamir_scalar_l1_amplification(
        maximum_recipient_trustee_point,
        roster.decryption_threshold,
    )?;
    let one_recipient_aggregate_shamir_scalar_l1 = maximum_one_source_shamir_scalar_l1
        .checked_mul(roster.participant_count)
        .ok_or_else(|| {
            static_accounting_error("aggregate Shamir scalar L1 amplification overflowed")
        })?;
    let ring_degree = POLYNOMIAL_DEGREE as u64;
    let fresh_opening_witness_coefficient_count =
        input_column_count.checked_mul(ring_degree).ok_or_else(|| {
            static_accounting_error(
                "fresh compact VSS opening witness coefficient count overflowed",
            )
        })?;
    let aggregate_randomness_difference_infinity_bound =
        roster.participant_count.checked_mul(2).ok_or_else(|| {
            static_accounting_error("aggregate compact VSS randomness difference bound overflowed")
        })?;
    let recipient_shamir_relation_l1 = maximum_one_source_shamir_scalar_l1
        .checked_add(1)
        .ok_or_else(|| static_accounting_error("recipient Shamir relation L1 overflowed"))?;
    let aggregate_sum_relation_l1 = roster
        .participant_count
        .checked_add(1)
        .ok_or_else(|| static_accounting_error("aggregate sum relation L1 overflowed"))?;
    let compact_vss_message_digit_maximum =
        crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE - 1;
    let setup_consistency_coefficient_maximum =
        consistency_coefficient_maximum(CONSISTENCY_COEFFICIENT_BITS)?;
    let compact_vss_consistency_coefficient_maximum =
        consistency_coefficient_maximum(COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS)?;
    let largest_target_rns_prime = DATA_PRIMES
        .iter()
        .take(target_rns_limb_count as usize)
        .copied()
        .max()
        .ok_or_else(|| static_accounting_error("compact VSS target RNS limb set is empty"))?;
    let aggregate_target_message_coefficient_bound = u128::from(largest_target_rns_prime)
        .checked_mul(u128::from(roster.participant_count))
        .ok_or_else(|| {
            static_accounting_error("aggregate target message coefficient bound overflowed")
        })?;
    let aggregate_target_message_bound_u64 =
        u64::try_from(aggregate_target_message_coefficient_bound).map_err(|_| {
            static_accounting_error("aggregate target message coefficient bound overflowed")
        })?;
    let aggregate_target_message_digit_maximum = (0..message_column_count as usize)
        .map(|digit_index| {
            crate::bgv::setup::compact_vss_commitment::compact_vss_message_digit_bound(
                aggregate_target_message_bound_u64,
                digit_index,
            )
            .map(|digit_bound| digit_bound.saturating_sub(1))
            .map_err(|error| static_accounting_error(error.message))
        })
        .collect::<CanonicalResult<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let target_decryption_smudging_message_coefficient_bound =
        u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND)
            .map_err(|_| static_accounting_error("target smudging bound must be positive"))?
            .checked_mul(2)
            .and_then(|bound| bound.checked_add(1))
            .ok_or_else(|| {
                static_accounting_error("target smudging message coefficient bound overflowed")
            })?;
    let smudging_target_message_digit_maximum = (0..message_column_count as usize)
        .map(|digit_index| {
            crate::bgv::setup::compact_vss_commitment::compact_vss_message_digit_bound(
                target_decryption_smudging_message_coefficient_bound,
                digit_index,
            )
            .map(|digit_bound| digit_bound.saturating_sub(1))
            .map_err(|error| static_accounting_error(error.message))
        })
        .collect::<CanonicalResult<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let compact_share_linkage_carry_clear_claim_bound_decimal = masked_claim_clear_bound_decimal(
        u128::from(maximum_one_source_shamir_scalar_l1),
        ring_degree,
        COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
    )?;
    let compact_share_linkage_digit_clear_claim_bound_decimal = masked_claim_clear_bound_decimal(
        u128::from(compact_vss_message_digit_maximum),
        ring_degree,
        COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
    )?;
    let bridge_non_digit_clear_claim_bound_decimal =
        masked_claim_clear_bound_decimal(2, ring_degree, CONSISTENCY_COEFFICIENT_BITS)?;
    let bridge_digit_clear_claim_bound_decimal = masked_claim_clear_bound_decimal(
        u128::from(compact_vss_message_digit_maximum),
        ring_degree,
        CONSISTENCY_COEFFICIENT_BITS,
    )?;
    let aggregate_target_message_digit_clear_claim_bound_decimal =
        masked_claim_clear_bound_decimal(
            u128::from(aggregate_target_message_digit_maximum),
            ring_degree,
            CONSISTENCY_COEFFICIENT_BITS,
        )?;
    let smudging_target_message_digit_clear_claim_bound_decimal = masked_claim_clear_bound_decimal(
        u128::from(smudging_target_message_digit_maximum),
        ring_degree,
        CONSISTENCY_COEFFICIENT_BITS,
    )?;
    let target_randomness_clear_claim_bound_decimal =
        masked_claim_clear_bound_decimal(1, ring_degree, CONSISTENCY_COEFFICIENT_BITS)?;
    let bridge_direct_digit_vector_count = target_rns_limb_count
        .checked_mul(message_column_count)
        .ok_or_else(|| static_accounting_error("bridge direct digit vector count overflowed"))?;
    let commitment_modulus_limbs = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": DATA_PRIMES[*commitment_modulus_index],
            })
        })
        .collect::<Vec<_>>();
    let target_rns_primes = DATA_PRIMES
        .iter()
        .take(target_rns_limb_count as usize)
        .copied()
        .collect::<Vec<_>>();
    let input_column_labels = (0..message_column_count)
        .map(|digit_index| json!(format!("message:{digit_index}")))
        .chain(
            (0..randomness_column_count)
                .map(|column_index| json!(format!("randomness:{column_index}"))),
        )
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "CompactVssParameterCertificateInputBinding",
        "objectVersion": 3,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
        "participantCount": roster.participant_count,
        "sourceRnsLimbCount": source_rns_limb_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": roster.decryption_threshold,
        "ringDegree": POLYNOMIAL_DEGREE,
        "commitmentRelation": {
            "relation": "C = A_message * m + A_randomness * r mod q_c",
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
            "commitmentModulusLimbs": commitment_modulus_limbs,
            "outputCoordinateCount": output_coordinate_count,
            "messageWidth": message_column_count,
            "randomnessWidth": randomness_column_count,
            "projectionWeight": projection_weight,
            "coordinateCountPerCommitment": coordinate_count_per_commitment,
            "inputColumnLabels": input_column_labels,
            "homomorphicAdditionRule": "commitments combine linearly only when profile, public matrix seed, source limb, and commitment modulus order match",
            "homomorphicScalarRule": "public Shamir and aggregation scalars multiply both message and randomness columns over the same commitment key",
        },
        "commonCommitmentKey": {
            "matrixResidueHashDomain": "sealed-lattice-compact-vss-commitment/matrix-residue-v1",
            "projectionIndexHashDomain": "sealed-lattice-compact-vss-commitment/projection-index-v1",
            "rejectionSamplingRule": "sample little-endian 64-bit chunks and reject values at or above 2^64 - (2^64 mod modulus or ringDegree)",
            "matrixResiduePreimageFields": [
                "publicMatrixSeedHash",
                "profileId",
                "rnsLimbIndex",
                "commitmentModulusIndex",
                "outputCoordinateIndex",
                "inputColumn",
                "projectionTermIndex",
                "modulus",
                "blockIndex"
            ],
            "projectionIndexPreimageFields": [
                "publicMatrixSeedHash",
                "profileId",
                "rnsLimbIndex",
                "commitmentModulusIndex",
                "outputCoordinateIndex",
                "inputColumn",
                "projectionTermIndex",
                "ringDegree",
                "blockIndex"
            ],
            "sparseProjectionShape": {
                "inputColumnCount": input_column_count,
                "projectionWeight": projection_weight,
                "coordinateCountPerCommitment": coordinate_count_per_commitment,
                "sampledMatrixResiduesPerCoordinate": sampled_matrix_residues_per_coordinate,
                "sampledProjectionIndicesPerCoordinate": sampled_projection_indices_per_coordinate,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
        },
        "messageEncoding": {
            "sourceCoefficientRepresentation": "canonical residue modulo the selected source RNS prime",
            "targetCoefficientRepresentation": "canonical residue modulo the selected target RNS prime",
            "signedRepresentativeConvention": "same-secret bridge witnesses use the setup proof signed representative convention before reduction into each RNS prime",
            "paddingAndBlockOrder": "two base-3^17 little-endian digit coefficients per message ring position",
            "freshEncodingRule": "exact canonical residue encoding into two message digit columns",
            "proofRangeEncodingRule": "share-linkage, same-secret bridge, and target-decryption rows bind message digit columns directly with masked consistency claims",
            "derivedEncodingRule": "Shamir recipient-share and aggregate threshold openings bind carried public-sum messages through decoded message digit columns and private carry witnesses",
        },
        "normInputClasses": [
            {
                "className": "shamirScalarL1Amplification",
                "maximumRecipientTrusteePoint": maximum_recipient_trustee_point,
                "shamirCoefficientCount": roster.decryption_threshold,
                "maximumOneSourceShamirScalarL1": maximum_one_source_shamir_scalar_l1,
                "oneRecipientAggregateShamirScalarL1": one_recipient_aggregate_shamir_scalar_l1,
            },
            {
                "className": "messageEncodingNorm",
                "sourceCoefficientUpperBoundMultiplier": 1_u64,
                "recipientShareCoefficientUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                "aggregateCoefficientUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
            },
            {
                "className": "openingRandomnessNorm",
                "randomnessColumnCount": randomness_column_count,
            },
            {
                "className": "aggregateDealerCount",
                "sourceTrusteeCount": roster.participant_count,
            },
        ],
        "parameterReviewInputs": {
            "inputVersion": 1,
            "coefficientRing": {
                "ringPolynomial": "X^N+1",
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
            },
            "openingWitnessRows": [
                {
                    "rowId": "compact-vss-fresh-opening-witness",
                    "commitmentRoles": [
                        "coefficient",
                        "recipient-share"
                    ],
                    "messageCoefficientBound": "selectedRnsPrime times the recipient Shamir scalar L1 for recipient-share openings",
                    "messageCoefficientUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                    "messageDifferenceUpperBoundMultiplier": maximum_one_source_shamir_scalar_l1,
                    "randomnessDistribution": "balanced-ternary-per-column-coefficient",
                    "randomnessCoefficientInfinityBound": 1_u64,
                    "randomnessDifferenceInfinityBound": 2_u64,
                    "messageColumnCount": message_column_count,
                    "randomnessColumnCount": randomness_column_count,
                    "witnessColumnCount": input_column_count,
                    "witnessCoefficientCount": fresh_opening_witness_coefficient_count,
                },
                {
                    "rowId": "compact-vss-aggregate-opening-witness",
                    "commitmentRoles": [
                        "aggregate-threshold-share"
                    ],
                    "messageCoefficientBound": "selectedRnsPrime times the all-source recipient Shamir scalar L1",
                    "messageCoefficientUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
                    "messageDifferenceUpperBoundMultiplier": one_recipient_aggregate_shamir_scalar_l1,
                    "randomnessDistribution": "sum-of-source-balanced-ternary-openings",
                    "randomnessCoefficientInfinityBound": roster.participant_count,
                    "randomnessDifferenceInfinityBound": aggregate_randomness_difference_infinity_bound,
                    "messageColumnCount": message_column_count,
                    "randomnessColumnCount": randomness_column_count,
                    "witnessColumnCount": input_column_count,
                    "witnessCoefficientCount": fresh_opening_witness_coefficient_count,
                },
            ],
            "linearRelationRows": [
                {
                    "rowId": "compact-vss-recipient-share-shamir-evaluation",
                    "relation": "recipient share opening equals Shamir evaluation of source coefficient openings",
                    "sourceOpeningCount": roster.decryption_threshold,
                    "recipientOpeningTermCount": 1_u64,
                    "maximumRecipientTrusteePoint": maximum_recipient_trustee_point,
                    "sourceShamirScalarL1": maximum_one_source_shamir_scalar_l1,
                    "combinedRelationTermL1": recipient_shamir_relation_l1,
                    "appliesToColumns": input_column_labels,
                },
                {
                    "rowId": "compact-vss-aggregate-threshold-public-sum",
                    "relation": "aggregate threshold opening equals public sum of source-recipient openings",
                    "sourceTrusteeCount": roster.participant_count,
                    "aggregateOpeningTermCount": 1_u64,
                    "sourceOpeningScalarL1": roster.participant_count,
                    "combinedRelationTermL1": aggregate_sum_relation_l1,
                    "appliesToColumns": input_column_labels,
                },
                {
                    "rowId": "compact-vss-one-recipient-aggregate-from-source-coefficients",
                    "relation": "one recipient aggregate opening as a sum of all source Shamir evaluations",
                    "sourceTrusteeCount": roster.participant_count,
                    "sourceCoefficientCountPerTrustee": roster.decryption_threshold,
                    "oneRecipientAggregateShamirScalarL1": one_recipient_aggregate_shamir_scalar_l1,
                    "appliesToColumns": input_column_labels,
                },
            ],
            "maskedClaimNormRows": [
                {
                    "rowId": "compact-vss-share-linkage-carry-claim",
                    "proofFamily": "compact-vss-share-linkage",
                    "claimVectorClass": "packed-opening-carry",
                    "appliesToRelations": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "witnessInfinityBound": maximum_one_source_shamir_scalar_l1,
                    "clearClaimBoundDecimal": compact_share_linkage_carry_clear_claim_bound_decimal,
                    "consistencyRepetitions": COMPACT_VSS_CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": compact_vss_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_CARRY_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "carry claims use the lifted Shamir carry bound for each packed item",
                },
                {
                    "rowId": "compact-vss-share-linkage-message-digit-claim",
                    "proofFamily": "compact-vss-share-linkage",
                    "claimVectorClass": "message-digit",
                    "appliesToRelations": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": compact_share_linkage_digit_clear_claim_bound_decimal,
                    "consistencyRepetitions": COMPACT_VSS_CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": COMPACT_VSS_CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": compact_vss_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "direct masked claims bind committed base-3^17 digit columns without trit decoder columns",
                },
                {
                    "rowId": "compact-vss-same-secret-bridge-non-digit-claim",
                    "proofFamily": "compact-same-secret-bridge",
                    "claimVectorClass": "secret-indicator-or-randomness",
                    "appliesToRelations": [
                        "compact-vss-same-secret-bridge-target-reduction"
                    ],
                    "witnessInfinityBound": 2_u64,
                    "clearClaimBoundDecimal": bridge_non_digit_clear_claim_bound_decimal,
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "non-digit bridge claims keep the setup-family consistency mask",
                },
                {
                    "rowId": "compact-vss-same-secret-bridge-message-digit-claim",
                    "proofFamily": "compact-same-secret-bridge",
                    "claimVectorClass": "target-message-digit",
                    "appliesToRelations": [
                        "compact-vss-same-secret-bridge-target-reduction"
                    ],
                    "targetRnsLimbCount": target_rns_limb_count,
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "directDigitVectorCount": bridge_direct_digit_vector_count,
                    "witnessInfinityBoundDecimal": compact_vss_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": bridge_digit_clear_claim_bound_decimal,
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": COMPACT_VSS_DIGIT_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "bridge target messages use direct digit claims and do not add message trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-aggregate-message-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "aggregate-opening-message-digit",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "targetRnsLimbCount": target_rns_limb_count,
                    "largestTargetRnsPrime": largest_target_rns_prime,
                    "aggregateMessageCoefficientBoundDecimal": aggregate_target_message_coefficient_bound.to_string(),
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": aggregate_target_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": aggregate_target_message_digit_clear_claim_bound_decimal,
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target aggregate messages use direct masked claims for each committed base-3^17 digit without trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-smudging-message-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "smudging-opening-message-digit",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "smudgingMessageCoefficientBound": target_decryption_smudging_message_coefficient_bound,
                    "messageDigitBaseDecimal": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_BASE.to_string(),
                    "messageDigitCount": message_column_count,
                    "witnessInfinityBoundDecimal": smudging_target_message_digit_maximum.to_string(),
                    "clearClaimBoundDecimal": smudging_target_message_digit_clear_claim_bound_decimal,
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target smudging messages use direct masked claims for each committed base-3^17 digit without trit decoder columns",
                },
                {
                    "rowId": "compact-vss-target-decryption-randomness-claim",
                    "proofFamily": "target-decryption-share",
                    "claimVectorClass": "target-opening-randomness",
                    "appliesToRelations": [
                        "target-decryption-share-proof"
                    ],
                    "witnessInfinityBound": 1_u64,
                    "clearClaimBoundDecimal": target_randomness_clear_claim_bound_decimal,
                    "consistencyRepetitions": CONSISTENCY_REPETITIONS,
                    "consistencyCoefficientBits": CONSISTENCY_COEFFICIENT_BITS,
                    "consistencyCoefficientMaximumDecimal": setup_consistency_coefficient_maximum.to_string(),
                    "claimMaskRadix": CLAIM_MASK_RADIX,
                    "maskDigitCount": TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT,
                    "rangeEvidenceRule": "target opening randomness claims use ternary witness columns and the target randomness mask",
                },
            ],
            "targetBasisReductionRows": [
                {
                    "rowId": "compact-vss-same-secret-bridge-target-reduction",
                    "sourceSecretDistribution": "standard-ternary",
                    "sourceSignedRepresentativeInfinityBound": 1_u64,
                    "targetRnsLimbCount": target_rns_limb_count,
                    "targetRnsPrimes": target_rns_primes,
                    "targetBasisHash": canonical_target_basis_hash()?,
                    "targetBasisLimbOrder": "profile-order-prefix",
                    "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root()?,
                },
            ],
            "reviewReductionRows": [
                {
                    "rowId": "compact-vss-module-sis-binding-review-input",
                    "problem": "Module-SIS",
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "linearRelationRows": [
                        "compact-vss-recipient-share-shamir-evaluation",
                        "compact-vss-aggregate-threshold-public-sum",
                        "compact-vss-one-recipient-aggregate-from-source-coefficients"
                    ],
                    "maskedClaimNormRows": [
                        "compact-vss-share-linkage-carry-claim",
                        "compact-vss-share-linkage-message-digit-claim",
                        "compact-vss-same-secret-bridge-non-digit-claim",
                        "compact-vss-same-secret-bridge-message-digit-claim",
                        "compact-vss-target-decryption-aggregate-message-claim",
                        "compact-vss-target-decryption-smudging-message-claim",
                        "compact-vss-target-decryption-randomness-claim"
                    ],
                    "collisionDifferenceRule": "subtract two accepted openings over the integers before reducing to the commitment modulus",
                },
                {
                    "rowId": "compact-vss-module-lwe-hiding-review-input",
                    "problem": "Module-LWE",
                    "openingWitnessRows": [
                        "compact-vss-fresh-opening-witness",
                        "compact-vss-aggregate-opening-witness"
                    ],
                    "maskedClaimNormRows": [
                        "compact-vss-share-linkage-carry-claim",
                        "compact-vss-share-linkage-message-digit-claim",
                        "compact-vss-same-secret-bridge-non-digit-claim",
                        "compact-vss-same-secret-bridge-message-digit-claim",
                        "compact-vss-target-decryption-aggregate-message-claim",
                        "compact-vss-target-decryption-smudging-message-claim",
                        "compact-vss-target-decryption-randomness-claim"
                    ],
                    "randomnessSource": "balanced-ternary opening columns before public linear aggregation",
                    "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
                },
            ],
        },
        "estimatorInputRows": [
            {
                "rowId": "compact-vss-module-sis-binding-input",
                "problem": "Module-SIS",
                "targetSecurityBits": 128_u64,
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
                "outputCoordinateCount": output_coordinate_count,
                "messageWidth": message_column_count,
                "randomnessWidth": randomness_column_count,
                "projectionWeight": projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
            {
                "rowId": "compact-vss-module-lwe-hiding-input",
                "problem": "Module-LWE",
                "targetSecurityBits": 128_u64,
                "ringDegree": POLYNOMIAL_DEGREE,
                "commitmentModulusLimbIndices": SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
                "commitmentModulusLimbs": commitment_modulus_limbs,
                "outputCoordinateCount": output_coordinate_count,
                "messageWidth": message_column_count,
                "randomnessWidth": randomness_column_count,
                "projectionWeight": projection_weight,
                "sampledMatrixResiduesPerCommitment": sampled_matrix_residues_per_commitment,
                "sampledProjectionIndicesPerCommitment": sampled_projection_indices_per_commitment,
            },
        ],
        "sameSecretBridgeInput": {
            "targetBasisHash": canonical_target_basis_hash()?,
            "targetRnsPrimes": target_rns_primes,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root()?,
            "targetBasisLimbOrder": "profile-order-prefix",
        },
    }))
}

fn current_vss_material_baseline_report_value() -> CanonicalResult<Value> {
    let roster = first_closure_roster_parameters();
    let commitment_modulus_limb_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64;
    let commitment_row_count = SETUP_COMMITMENT_ROW_COUNT as u64;
    let ring_degree = POLYNOMIAL_DEGREE as u64;
    let bytes_per_residue = 8_u64;
    let single_commitment_coefficient_bytes = checked_accounting_product(
        &[
            commitment_modulus_limb_count,
            commitment_row_count,
            ring_degree,
            bytes_per_residue,
        ],
        "single VSS commitment coefficient byte count",
    )?;
    let material_record_count = checked_accounting_product(
        &[
            roster.participant_count,
            DATA_PRIMES.len() as u64,
            roster.decryption_threshold,
        ],
        "VSS material record count",
    )?;
    let full_material_coefficient_bytes = checked_accounting_product(
        &[single_commitment_coefficient_bytes, material_record_count],
        "full VSS coefficient material byte count",
    )?;
    let exact_binary_transport_bytes =
        setup_transport_vss_material_byte_length_for_roster(&roster, ring_degree)?;
    let binary_transport_metadata_bytes = exact_binary_transport_bytes
        .checked_sub(full_material_coefficient_bytes)
        .ok_or_else(|| static_accounting_error("VSS transport metadata byte count underflowed"))?;
    let maximum_recipient_roster_position = roster.participant_count - 1;
    let maximum_recipient_trustee_point = maximum_recipient_roster_position + 1;
    let maximum_one_source_shamir_scalar_l1 = shamir_scalar_l1_amplification(
        maximum_recipient_trustee_point,
        roster.decryption_threshold,
    )?;
    let one_recipient_aggregate_shamir_scalar_l1 = maximum_one_source_shamir_scalar_l1
        .checked_mul(roster.participant_count)
        .ok_or_else(|| {
            static_accounting_error("aggregate Shamir scalar L1 amplification overflowed")
        })?;
    let public_verifier_memory_lower_bound_bytes = single_commitment_coefficient_bytes
        .checked_add(SETUP_TRANSPORT_CHUNK_SIZE_BYTES)
        .ok_or_else(|| static_accounting_error("public verifier memory estimate overflowed"))?;

    Ok(json!({
        "objectType": "CurrentVssMaterialBaselineReport",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "shamirCoefficientCount": roster.decryption_threshold,
        "ringDegree": POLYNOMIAL_DEGREE,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "commitmentModulusLimbCount": commitment_modulus_limb_count,
        "commitmentRowCount": commitment_row_count,
        "bytesPerResidue": bytes_per_residue,
        "materialRecordCount": material_record_count,
        "singleCommitmentCoefficientBytes": single_commitment_coefficient_bytes,
        "fullMaterialCoefficientBytes": full_material_coefficient_bytes,
        "exactBinaryTransportBytes": exact_binary_transport_bytes,
        "binaryTransportMetadataBytes": binary_transport_metadata_bytes,
        "publicVerificationMemoryEstimate": {
            "estimateKind": "streaming lower bound with one full commitment payload and one transport chunk resident",
            "residentCommitmentCoefficientBytes": single_commitment_coefficient_bytes,
            "transportChunkBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "lowerBoundBytes": public_verifier_memory_lower_bound_bytes,
            "largestWasmBoundaryCopyBytes": SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        },
        "trusteePointScalarBounds": {
            "trusteePointRule": "roster-position-plus-one",
            "maximumRecipientRosterPosition": maximum_recipient_roster_position,
            "maximumRecipientTrusteePoint": maximum_recipient_trustee_point,
            "shamirCoefficientCount": roster.decryption_threshold,
            "oneSourceMaximumShamirScalarL1": maximum_one_source_shamir_scalar_l1,
            "oneRecipientAggregateSourceCount": roster.participant_count,
            "oneRecipientAggregateShamirScalarL1": one_recipient_aggregate_shamir_scalar_l1,
        },
        "normModel": {
            "shamirScalarL1Amplification": maximum_one_source_shamir_scalar_l1,
            "messageEncodingNorm": {
                "source": "per-rns-prime coefficient residues",
                "coefficientRange": "0 <= messageCoefficient < sourceRnsPrime",
            },
            "openingRandomnessNorm": {
                "distribution": "coefficientwise-centered-ternary",
                "infinityNormBound": SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
                "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            },
            "aggregateDealerCount": roster.participant_count,
        },
    }))
}

fn shamir_scalar_l1_amplification(
    trustee_point: u64,
    coefficient_count: u64,
) -> CanonicalResult<u64> {
    let mut amplification = 0_u64;
    let mut trustee_point_power = 1_u64;
    for _ in 0..coefficient_count {
        amplification = amplification
            .checked_add(trustee_point_power)
            .ok_or_else(|| static_accounting_error("Shamir scalar L1 amplification overflowed"))?;
        trustee_point_power = trustee_point_power
            .checked_mul(trustee_point)
            .ok_or_else(|| static_accounting_error("Shamir trustee-point power overflowed"))?;
    }

    Ok(amplification)
}

fn consistency_coefficient_maximum(coefficient_bits: u32) -> CanonicalResult<u128> {
    if coefficient_bits >= u128::BITS {
        return Err(static_accounting_error(
            "consistency coefficient bit width overflowed",
        ));
    }

    Ok((1_u128 << coefficient_bits) - 1)
}

fn masked_claim_clear_bound_decimal(
    witness_infinity_bound: u128,
    ring_degree: u64,
    consistency_coefficient_bits: u32,
) -> CanonicalResult<String> {
    let consistency_coefficient_maximum =
        consistency_coefficient_maximum(consistency_coefficient_bits)?;
    let clear_bound = witness_infinity_bound
        .checked_mul(u128::from(ring_degree))
        .and_then(|bound| bound.checked_mul(consistency_coefficient_maximum))
        .ok_or_else(|| static_accounting_error("masked claim clear bound overflowed"))?;

    Ok(clear_bound.to_string())
}

fn checked_accounting_product(values: &[u64], label: &str) -> CanonicalResult<u64> {
    values.iter().try_fold(1_u64, |accumulated_product, value| {
        accumulated_product
            .checked_mul(*value)
            .ok_or_else(|| static_accounting_error(format!("{label} overflowed")))
    })
}

fn static_accounting_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

fn setup_transport_profile_value() -> CanonicalResult<Value> {
    setup_transport_profile_value_for_roster(&first_closure_roster_parameters())
}

fn setup_transport_profile_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
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
                // The transport profile's minimum is the profile-ring full-material
                // size, independent of any development-reduced-ring package; this
                // keeps the transport profile hash a pure function of the roster.
                "minimumByteLength": setup_transport_vss_material_byte_length_for_roster(
                    roster,
                    POLYNOMIAL_DEGREE as u64,
                )?,
            }
        ],
    }))
}

fn evaluator_key_schedule_profile_value() -> CanonicalResult<Value> {
    evaluator_key_schedule_profile_value_for_roster(&first_closure_roster_parameters())
}

fn evaluator_key_schedule_profile_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
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
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": required_galois_key_schedule,
        "requiredGaloisSetHash": required_galois_set_hash,
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
            },
            "chunking": "required-for-large-proof-material",
            "chunkRootRequired": true,
            "statementRootRequired": true,
            "canonicalJsonRole": "root-bound metadata only"
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
        .get("compactVssCoefficientCommitmentSet")
        .and_then(|commitment_set| commitment_set.get("coefficientCommitmentRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("compactVssRecipientShareCommitmentSet")
        .and_then(|commitment_set| commitment_set.get("recipientShareCommitmentRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("compactVssAggregateThresholdCommitmentSet")
        .and_then(|commitment_set| commitment_set.get("aggregateThresholdCommitmentRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("compactVssShareLinkageStatement")
        .and_then(|statement| statement.get("statementRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("compactVssShareLinkageProofMaterialSet")
        .and_then(|material_set| material_set.get("proofMaterialSetRoot"))
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
        .get("compactSameSecretBridgeStatementSet")
        .and_then(|statement_set| statement_set.get("compactSameSecretBridgeStatementSetRoot"))
        .and_then(Value::as_str)
    {
        accepted_hashes.push(hash.to_string());
    }
    if let Some(hash) = setup_package
        .get("compactSameSecretBridgeProofMaterialSet")
        .and_then(|material_set| material_set.get("proofMaterialSetRoot"))
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
    let accepted_hashes = if verifier_status == VerifierStatus::Accepted {
        accepted_hashes
    } else {
        Vec::new()
    };

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
