//! Canonical-carrier and absolute-resource compiler for the unactivated direct-MPC candidate.
//!
//! The compiler instantiates the repository's canonical tuple framing for every
//! message shape and maps the resulting byte language onto the existing
//! authenticated checkpoint store. It is a rejection screen only: it mints no
//! capability and does not authorize protocol dispatch.

use core::fmt;

use fips203::ml_kem_768;
use fips204::ml_dsa_65;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
};

use super::direct_mpc_candidate_compiler::{
    CompiledDirectMpcCandidate, DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH, DIRECT_MPC_SCORE_BIT_COUNT,
    DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH, DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH,
    DIRECT_MPC_VALIDATION_REPETITION_COUNT, DirectMpcCandidateError, DirectMpcRoundKind,
};
use super::direct_mpc_field_stream::{
    DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION, DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH,
};

const HASH512_BYTE_LENGTH: u64 = Hash512::BYTE_LENGTH as u64;
const ML_DSA_65_SIGNATURE_BYTE_LENGTH: u64 = ml_dsa_65::SIG_LEN as u64;
const ML_KEM_768_CIPHERTEXT_BYTE_LENGTH: u64 = ml_kem_768::CT_LEN as u64;
const PRIVATE_CARRIER_AUTHENTICATION_TAG_BYTE_LENGTH: u64 = 16;
const COMMITMENT_SALT_BYTE_LENGTH: u64 = 64;
const FIELD_CANONICAL_BYTE_LENGTH: u64 = 3;
const KECCAK_F1600_RATE_BYTE_LENGTH: u64 = 136;
const KMACXOF_RIGHT_ENCODE_ZERO_BYTE_LENGTH: u64 = 2;
const RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH: u64 = 54;
const STORAGE_INDEX_VALUE_BYTE_LENGTH: u64 = 256;
const AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH: u64 = 68;
const STORAGE_OBJECT_KEY_BYTE_LENGTH: u64 = 256;
const CHECKPOINT_STORED_MANIFEST_HEADER_BYTE_LENGTH: u64 = 38;
const CHECKPOINT_JOURNAL_BASE_BYTE_LENGTH: u64 = 1_024;
const CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH: u64 = 32;
const CHECKPOINT_PUBLICATION_IDENTIFIER_BYTE_LENGTH: u64 = 32;
const CHECKPOINT_CHUNK_DIGEST_HEX_BYTE_LENGTH: u64 = 128;
const CHECKPOINT_CHUNK_INDEX_HEX_BYTE_LENGTH: u64 = 8;
const CHECKPOINT_SOURCE_DIGEST_COUNT: u64 = 5;
const CHECKPOINT_RUNTIME_RANDOMNESS_IDENTIFIER_BYTE_LENGTH: u64 = 32;
const DEGREE_THREE_CODEWORD_CHECK_MULTIPLICATION_COUNT: u64 = 28;
const DEGREE_SIX_CODEWORD_CHECK_MULTIPLICATION_COUNT: u64 = 28;

const PUBLIC_MESSAGE_BODY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/public-message-body";
const PUBLIC_MESSAGE_ENVELOPE_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/public-message-envelope";
const PRIVATE_MESSAGE_BODY_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/private-message-body";
const PRIVATE_MESSAGE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc/private-message-envelope";
const PRIVATE_CARRIER_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/private-carrier";
const PUBLIC_MESSAGE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/v1/direct-mpc/public-message";
const PRIVATE_MESSAGE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/v1/direct-mpc/private-message";
const CHECKPOINT_STATE_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/checkpoint-state";
const CHECKPOINT_CURSOR_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/checkpoint-cursor";

const PUBLIC_CORPUS_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
const PARTICIPANT_DOWNLOAD_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
const PARTICIPANT_UPLOAD_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
const ROSTER_UPLOAD_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
const PERSISTENT_STORAGE_PLANNING_TARGET_BYTE_LENGTH: u64 = 2_147_483_648;
const SCRATCH_PLANNING_TARGET_BYTE_LENGTH: u64 = 268_435_456;
const COPIED_PAYLOAD_PLANNING_TARGET_BYTE_LENGTH: u64 = 1_572_864;
const WASM_MEMORY_PLANNING_TARGET_BYTE_LENGTH: u64 = 402_653_184;
const JAVASCRIPT_HEAP_PLANNING_TARGET_BYTE_LENGTH: u64 = 134_217_728;
const BROWSER_PRIVATE_MEMORY_PLANNING_TARGET_BYTE_LENGTH: u64 = 671_088_640;
const MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH: u64 = 4_294_967_291;
const MAXIMUM_WASM_MEMORY_BYTE_LENGTH: u64 = 671_088_640;
const REQUIRED_AGGREGATE_FIELD_SAMPLING_SECURITY_BITS: u64 = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcCarrierCompilerError {
    Candidate(DirectMpcCandidateError),
    Canonical(CanonicalCodecError),
    ArithmeticOverflow,
    GeometryMismatch,
    ResourceBoundExceeded {
        resource: &'static str,
        actual: u64,
        bound: u64,
    },
    SecurityTargetNotMet {
        actual_bits: u64,
        required_bits: u64,
    },
}

impl fmt::Display for DirectMpcCarrierCompilerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => write!(formatter, "direct MPC candidate error: {error}"),
            Self::Canonical(error) => write!(formatter, "canonical carrier error: {error}"),
            Self::ArithmeticOverflow => {
                formatter.write_str("direct MPC carrier arithmetic overflow")
            }
            Self::GeometryMismatch => {
                formatter.write_str("direct MPC carrier geometry is internally inconsistent")
            }
            Self::ResourceBoundExceeded {
                resource,
                actual,
                bound,
            } => write!(
                formatter,
                "direct MPC {resource} uses {actual} bytes or calls; bound is {bound}"
            ),
            Self::SecurityTargetNotMet {
                actual_bits,
                required_bits,
            } => write!(
                formatter,
                "direct MPC aggregate field sampling provides {actual_bits} bits; {required_bits} bits are required"
            ),
        }
    }
}

impl std::error::Error for DirectMpcCarrierCompilerError {}

impl From<DirectMpcCandidateError> for DirectMpcCarrierCompilerError {
    fn from(error: DirectMpcCandidateError) -> Self {
        Self::Candidate(error)
    }
}

impl From<CanonicalCodecError> for DirectMpcCarrierCompilerError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcCarrierGeometry {
    participant_count: u64,
    remote_participant_count: u64,
    ballot_field_count_per_submission: u64,
    ballot_share_commitment_count_per_submission: u64,
    seed_opening_count_per_participant: u64,
    subset_opening_count_per_seed_mailbox: u64,
}

impl DirectMpcCarrierGeometry {
    fn derive(
        candidate: &CompiledDirectMpcCandidate,
    ) -> Result<Self, DirectMpcCarrierCompilerError> {
        let resource = candidate.resource_model()?;
        let participant_count = u64::from(candidate.profile().participant_count());
        if resource.participant_count != participant_count
            || resource.field_canonical_byte_length != FIELD_CANONICAL_BYTE_LENGTH
            || resource.field_sample_byte_length != DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH
        {
            return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
        }
        let remote_participant_count = checked_sub(participant_count, 1)?;
        let ballot_field_count_per_submission = checked_multiply(
            u64::from(candidate.profile().option_count()),
            u64::try_from(DIRECT_MPC_SCORE_BIT_COUNT)
                .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        )?;
        if checked_multiply(ballot_field_count_per_submission, participant_count)?
            != resource.source_consistency_mask_count
        {
            return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
        }
        let ballot_share_commitment_count_per_submission =
            checked_multiply(ballot_field_count_per_submission, participant_count)?;
        let seed_opening_count_per_participant =
            checked_add(resource.authorized_subset_count_per_participant, 1)?;
        let subset_opening_count_per_seed_mailbox = checked_binomial_coefficient(
            checked_sub(participant_count, 2)?,
            checked_sub(resource.authorized_subset_size, 2)?,
        )?;
        if checked_multiply(
            subset_opening_count_per_seed_mailbox,
            remote_participant_count,
        )? != checked_multiply(
            resource.authorized_subset_count_per_participant,
            checked_sub(resource.authorized_subset_size, 1)?,
        )? {
            return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
        }
        Ok(Self {
            participant_count,
            remote_participant_count,
            ballot_field_count_per_submission,
            ballot_share_commitment_count_per_submission,
            seed_opening_count_per_participant,
            subset_opening_count_per_seed_mailbox,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcPathResourceLedger {
    pub(crate) submission_count: u64,
    pub(crate) interaction_round_count: u64,
    pub(crate) public_message_count: u64,
    pub(crate) private_message_count: u64,
    pub(crate) public_raw_field_element_count: u64,
    pub(crate) public_carrier_byte_length: u64,
    pub(crate) private_carrier_byte_length: u64,
    pub(crate) complete_roster_transfer_byte_length: u64,
    pub(crate) maximum_participant_download_byte_length: u64,
    pub(crate) maximum_participant_upload_byte_length: u64,
    pub(crate) maximum_participant_retained_protocol_byte_length: u64,
    pub(crate) maximum_participant_retained_carrier_count: u64,
    pub(crate) maximum_single_carrier_byte_length: u64,
    pub(crate) checkpoint_boundary_count_per_participant: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcFaultPathResourceLedger {
    pub(crate) public_message_count: u64,
    pub(crate) private_message_count: u64,
    pub(crate) public_raw_field_element_count: u64,
    pub(crate) public_carrier_byte_length: u64,
    pub(crate) private_carrier_byte_length: u64,
    pub(crate) maximum_staged_untrusted_carrier_byte_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcCheckpointResourceLedger {
    pub(crate) checkpoint_state_byte_length: u64,
    pub(crate) checkpoint_chunk_count: u64,
    pub(crate) state_stream_descriptor_byte_length: u64,
    pub(crate) deterministic_cursor_byte_length: u64,
    pub(crate) canonical_manifest_byte_length: u64,
    pub(crate) journal_plaintext_byte_length: u64,
    pub(crate) retained_and_staged_stored_value_capacity_byte_length: u64,
    pub(crate) authenticated_repair_head_plaintext_capacity_byte_length: u64,
    pub(crate) maximum_owned_record_count: u64,
    pub(crate) seal_call_count_per_publication: u64,
    pub(crate) cumulative_sealed_plaintext_byte_length_per_participant: u64,
    pub(crate) cold_restart_traffic_byte_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcFixedFunctionResourceLedger {
    pub(crate) unique_field_sample_count: u64,
    pub(crate) aggregate_field_sampling_security_bits: u64,
    pub(crate) field_stream_query_byte_length: u64,
    pub(crate) field_stream_customization_byte_length: u64,
    pub(crate) kmacxof256_query_count_per_participant: u64,
    pub(crate) kmacxof256_absorbed_byte_length_per_participant: u64,
    pub(crate) kmacxof256_permutation_count_per_participant: u64,
    pub(crate) validation_cshakexof256_query_count_per_participant: u64,
    pub(crate) validation_cshakexof256_permutation_count_per_participant: u64,
    pub(crate) maximum_uninterrupted_permutation_count: u64,
    pub(crate) maximum_uninterrupted_field_reduction_count: u64,
    pub(crate) maximum_lost_or_replayed_xof_output_byte_length: u64,
    pub(crate) public_signature_context_byte_length: u64,
    pub(crate) private_signature_context_byte_length: u64,
    pub(crate) signature_generation_count_complete_roster: u64,
    pub(crate) signature_verification_count_per_participant: u64,
    pub(crate) kem_encapsulation_count_complete_roster: u64,
    pub(crate) kem_decapsulation_count_complete_roster: u64,
    pub(crate) aead_seal_count_complete_roster: u64,
    pub(crate) aead_open_count_complete_roster: u64,
    pub(crate) commitment_hash_generation_count_per_participant: u64,
    pub(crate) commitment_hash_verification_count_per_participant: u64,
    pub(crate) transcript_leaf_hash_count_per_participant: u64,
    pub(crate) private_carrier_hash_count_per_participant: u64,
    pub(crate) round_root_hash_count_per_participant: u64,
    pub(crate) computation_target_hash_count_per_participant: u64,
    pub(crate) foundation_hash_call_count_per_participant: u64,
    pub(crate) seed_commitment_hash_preimage_byte_length: u64,
    pub(crate) ballot_share_commitment_hash_preimage_byte_length: u64,
    pub(crate) maximum_transcript_leaf_hash_preimage_byte_length: u64,
    pub(crate) maximum_round_root_hash_preimage_byte_length: u64,
    pub(crate) computation_target_hash_preimage_byte_length: u64,
    pub(crate) checkpoint_hash_call_count_per_participant: u64,
    pub(crate) prss_basis_precomputation_field_multiplication_count_per_participant: u64,
    pub(crate) prss_ordinary_basis_modular_inverse_count_per_participant: u64,
    pub(crate) prss_weight_field_multiplication_count_per_participant: u64,
    pub(crate) prss_accumulation_field_addition_count_per_participant: u64,
    pub(crate) maximum_field_multiplication_count_per_participant: u64,
    pub(crate) all_abstention_field_multiplication_count_per_participant: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcLiveSetResourceLedger {
    pub(crate) persistent_secret_byte_length_per_participant: u64,
    pub(crate) arithmetic_wire_byte_length_per_participant: u64,
    pub(crate) prss_basis_weight_byte_length_per_participant: u64,
    pub(crate) scratch_byte_length: u64,
    pub(crate) maximum_contiguous_allocation_byte_length: u64,
    pub(crate) candidate_owned_wasm_live_set_byte_length: u64,
    pub(crate) candidate_owned_javascript_live_set_byte_length: u64,
    pub(crate) candidate_owned_browser_private_live_set_byte_length: u64,
    pub(crate) persistent_storage_with_repair_byte_length: u64,
    pub(crate) restart_and_repair_traffic_byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcCandidateCarrierLedger {
    pub(crate) maximum_success: DirectMpcPathResourceLedger,
    pub(crate) one_submission: DirectMpcPathResourceLedger,
    pub(crate) all_abstention: DirectMpcPathResourceLedger,
    pub(crate) withholding: DirectMpcFaultPathResourceLedger,
    pub(crate) authenticated_burn: DirectMpcFaultPathResourceLedger,
    pub(crate) rollback_retirement: DirectMpcFaultPathResourceLedger,
    pub(crate) checkpoint: DirectMpcCheckpointResourceLedger,
    pub(crate) fixed_function: DirectMpcFixedFunctionResourceLedger,
    pub(crate) live_set: DirectMpcLiveSetResourceLedger,
    pub(crate) seed_catalog_public_carrier_byte_length: u64,
    pub(crate) seed_private_carrier_byte_length: u64,
    pub(crate) submitted_ballot_declaration_carrier_byte_length: u64,
    pub(crate) abstaining_ballot_declaration_carrier_byte_length: u64,
    pub(crate) ballot_source_private_carrier_byte_length: u64,
    pub(crate) maximum_field_opening_carrier_byte_length: u64,
}

impl DirectMpcCandidateCarrierLedger {
    pub(crate) fn require_within_static_bounds(&self) -> Result<(), DirectMpcCarrierCompilerError> {
        require_bound(
            "public corpus",
            self.maximum_success.public_carrier_byte_length,
            PUBLIC_CORPUS_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "participant download",
            self.maximum_success
                .maximum_participant_download_byte_length,
            PARTICIPANT_DOWNLOAD_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "participant upload",
            self.maximum_success.maximum_participant_upload_byte_length,
            PARTICIPANT_UPLOAD_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "complete-roster upload",
            self.maximum_success.complete_roster_transfer_byte_length,
            ROSTER_UPLOAD_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "persistent storage",
            self.live_set.persistent_storage_with_repair_byte_length,
            PERSISTENT_STORAGE_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "scratch",
            self.live_set.scratch_byte_length,
            SCRATCH_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "copied payload",
            self.live_set.maximum_contiguous_allocation_byte_length,
            COPIED_PAYLOAD_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "candidate-owned WebAssembly live set",
            self.live_set.candidate_owned_wasm_live_set_byte_length,
            WASM_MEMORY_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "candidate-owned JavaScript live set",
            self.live_set
                .candidate_owned_javascript_live_set_byte_length,
            JAVASCRIPT_HEAP_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "candidate-owned browser private live set",
            self.live_set
                .candidate_owned_browser_private_live_set_byte_length,
            BROWSER_PRIVATE_MEMORY_PLANNING_TARGET_BYTE_LENGTH,
        )?;
        require_bound(
            "canonical transport stream",
            self.maximum_success.maximum_single_carrier_byte_length,
            MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        )?;
        require_bound(
            "copied JavaScript/WebAssembly buffer",
            self.live_set.maximum_contiguous_allocation_byte_length,
            FOUNDATION_PROFILE.maximum_copied_buffer_byte_length as u64,
        )?;
        require_bound(
            "WebAssembly linear memory",
            self.live_set.candidate_owned_wasm_live_set_byte_length,
            MAXIMUM_WASM_MEMORY_BYTE_LENGTH,
        )?;
        require_bound(
            "local-record seal calls",
            self.maximum_success
                .checkpoint_boundary_count_per_participant
                .checked_mul(self.checkpoint.seal_call_count_per_publication)
                .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
            1_u64 << 30,
        )?;
        require_bound(
            "local-record sealed plaintext",
            self.checkpoint
                .cumulative_sealed_plaintext_byte_length_per_participant,
            1_u64 << 40,
        )?;
        if self.fixed_function.aggregate_field_sampling_security_bits
            < REQUIRED_AGGREGATE_FIELD_SAMPLING_SECURITY_BITS
        {
            return Err(DirectMpcCarrierCompilerError::SecurityTargetNotMet {
                actual_bits: self.fixed_function.aggregate_field_sampling_security_bits,
                required_bits: REQUIRED_AGGREGATE_FIELD_SAMPLING_SECURITY_BITS,
            });
        }
        Ok(())
    }
}

pub(crate) fn compile_direct_mpc_candidate_carrier_ledger(
    candidate: &CompiledDirectMpcCandidate,
) -> Result<DirectMpcCandidateCarrierLedger, DirectMpcCarrierCompilerError> {
    let resource = candidate.resource_model()?;
    let carrier_geometry = DirectMpcCarrierGeometry::derive(candidate)?;

    let maximum_success = compile_nonempty_path(candidate, carrier_geometry.participant_count)?;
    let one_submission = compile_nonempty_path(candidate, 1)?;
    let all_abstention = compile_all_abstention_path(candidate)?;
    let maximum_field_opening_carrier_byte_length = public_field_message_byte_length(
        4,
        4,
        resource.beaver_triple_count,
        "sealed-lattice/v1/direct-mpc/triple-preparation-opening",
    )?;
    let result_opening_carrier_byte_length = public_field_message_byte_length(
        30,
        15,
        u64::from(candidate.profile().top_count()),
        "sealed-lattice/v1/direct-mpc/result-opening",
    )?;
    let result_witness_carrier_byte_length = public_message_byte_length(
        31,
        16,
        hash_payload("sealed-lattice/v1/direct-mpc/result-witness", 2)?,
    )?;
    let burn_witness_carrier_byte_length = public_message_byte_length(
        31,
        17,
        hash_and_code_payload("sealed-lattice/v1/direct-mpc/authenticated-burn-witness")?,
    )?;
    let retirement_witness_carrier_byte_length = public_message_byte_length(
        31,
        18,
        participant_and_hash_payload("sealed-lattice/v1/direct-mpc/rollback-retirement-witness")?,
    )?;
    let withholding = DirectMpcFaultPathResourceLedger {
        public_message_count: checked_sub(
            maximum_success.public_message_count,
            checked_add(resource.state_witness_quorum, 1)?,
        )?,
        private_message_count: maximum_success.private_message_count,
        public_raw_field_element_count: checked_sub(
            maximum_success.public_raw_field_element_count,
            u64::from(candidate.profile().top_count()),
        )?,
        public_carrier_byte_length: checked_sub(
            checked_sub(
                maximum_success.public_carrier_byte_length,
                checked_multiply(
                    resource.state_witness_quorum,
                    result_witness_carrier_byte_length,
                )?,
            )?,
            result_opening_carrier_byte_length,
        )?,
        private_carrier_byte_length: maximum_success.private_carrier_byte_length,
        maximum_staged_untrusted_carrier_byte_length: maximum_success
            .maximum_single_carrier_byte_length,
    };
    let authenticated_burn = DirectMpcFaultPathResourceLedger {
        public_message_count: maximum_success.public_message_count,
        private_message_count: maximum_success.private_message_count,
        public_raw_field_element_count: maximum_success.public_raw_field_element_count,
        public_carrier_byte_length: checked_add(
            checked_sub(
                maximum_success.public_carrier_byte_length,
                checked_multiply(
                    resource.state_witness_quorum,
                    result_witness_carrier_byte_length,
                )?,
            )?,
            checked_multiply(
                resource.state_witness_quorum,
                burn_witness_carrier_byte_length,
            )?,
        )?,
        private_carrier_byte_length: maximum_success.private_carrier_byte_length,
        maximum_staged_untrusted_carrier_byte_length: maximum_success
            .maximum_single_carrier_byte_length,
    };
    let rollback_retirement = DirectMpcFaultPathResourceLedger {
        public_message_count: maximum_success.public_message_count,
        private_message_count: maximum_success.private_message_count,
        public_raw_field_element_count: maximum_success.public_raw_field_element_count,
        public_carrier_byte_length: checked_add(
            checked_sub(
                maximum_success.public_carrier_byte_length,
                checked_multiply(
                    resource.state_witness_quorum,
                    result_witness_carrier_byte_length,
                )?,
            )?,
            checked_multiply(
                resource.state_witness_quorum,
                retirement_witness_carrier_byte_length,
            )?,
        )?,
        private_carrier_byte_length: maximum_success.private_carrier_byte_length,
        maximum_staged_untrusted_carrier_byte_length: maximum_success
            .maximum_single_carrier_byte_length,
    };

    let persistent_seed_opening_byte_length = checked_multiply(
        carrier_geometry.seed_opening_count_per_participant,
        checked_add(
            DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH,
            COMMITMENT_SALT_BYTE_LENGTH,
        )?,
    )?;
    let persistent_ballot_opening_byte_length = checked_multiply(
        carrier_geometry.ballot_share_commitment_count_per_submission,
        checked_add(FIELD_CANONICAL_BYTE_LENGTH, COMMITMENT_SALT_BYTE_LENGTH)?,
    )?
    .checked_add(checked_multiply(
        checked_multiply(
            carrier_geometry.remote_participant_count,
            carrier_geometry.ballot_field_count_per_submission,
        )?,
        checked_add(FIELD_CANONICAL_BYTE_LENGTH, COMMITMENT_SALT_BYTE_LENGTH)?,
    )?)
    .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)?;
    let arithmetic_wire_byte_length =
        checked_multiply(resource.total_wire_count, FIELD_CANONICAL_BYTE_LENGTH)?;
    let checkpoint_state_byte_length = checkpoint_state_byte_length(
        resource.persistent_secret_field_byte_length_per_participant,
        resource.joined_subset_master_byte_length_per_participant,
        persistent_seed_opening_byte_length,
        persistent_ballot_opening_byte_length,
        arithmetic_wire_byte_length,
    )?;
    let checkpoint = compile_checkpoint_resource_ledger(
        checkpoint_state_byte_length,
        maximum_success.checkpoint_boundary_count_per_participant,
    )?;

    let unique_prss_field_sample_count = checked_add(
        checked_multiply(
            resource.random_degree_three_sharing_count,
            resource.authorized_subset_count,
        )?,
        checked_multiply(
            checked_multiply(
                resource.random_degree_six_zero_sharing_count,
                resource.authorized_subset_count,
            )?,
            resource.active_fault_bound,
        )?,
    )?;
    let unique_field_sample_count = checked_add(
        unique_prss_field_sample_count,
        resource.validation_challenge_coefficient_count,
    )?;
    let sample_bit_length = checked_multiply(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH, 8)?;
    let aggregate_field_sampling_security_bits =
        checked_sub(sample_bit_length, ceiling_log2(unique_field_sample_count)?)?;
    let ordinary_stream_output_byte_length = checked_multiply(
        resource.random_degree_three_sharing_count,
        DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
    )?;
    let zero_stream_output_byte_length = checked_multiply(
        resource.random_degree_six_zero_sharing_count,
        DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
    )?;
    let kmac_absorbed_byte_length_per_query = checked_add(
        checked_multiply(2, KECCAK_F1600_RATE_BYTE_LENGTH)?,
        checked_multiply(
            ceiling_divide(
                checked_add(
                    DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH as u64,
                    KMACXOF_RIGHT_ENCODE_ZERO_BYTE_LENGTH,
                )?,
                KECCAK_F1600_RATE_BYTE_LENGTH,
            )?,
            KECCAK_F1600_RATE_BYTE_LENGTH,
        )?,
    )?;
    let ordinary_stream_permutation_count = kmac_permutation_count(
        DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH as u64,
        ordinary_stream_output_byte_length,
    )?;
    let zero_stream_permutation_count = kmac_permutation_count(
        DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH as u64,
        zero_stream_output_byte_length,
    )?;
    let zero_stream_count_per_participant = checked_multiply(
        resource.authorized_subset_count_per_participant,
        resource.active_fault_bound,
    )?;
    let kmacxof256_permutation_count_per_participant = checked_add(
        checked_multiply(
            resource.authorized_subset_count_per_participant,
            ordinary_stream_permutation_count,
        )?,
        checked_multiply(
            zero_stream_count_per_participant,
            zero_stream_permutation_count,
        )?,
    )?;
    let validation_output_byte_length = checked_multiply(
        resource.validation_challenge_coefficient_count,
        DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
    )?;
    let validation_cshakexof256_permutation_count = cshake_permutation_count(
        checked_add(
            6,
            DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH as u64,
        )?,
        validation_output_byte_length,
    )?;
    let degree_three_opened_value_count = checked_add(
        checked_add(
            resource.source_consistency_mask_count,
            checked_multiply(2, resource.beaver_triple_count)?,
        )?,
        checked_add(
            checked_add(
                carrier_geometry.participant_count,
                DIRECT_MPC_VALIDATION_REPETITION_COUNT as u64,
            )?,
            u64::from(candidate.profile().top_count()),
        )?,
    )?;
    let ordinary_basis_precomputation_field_multiplication_count = checked_multiply(
        resource.authorized_subset_count_per_participant,
        checked_add(resource.active_fault_bound, 1)?,
    )?;
    let zero_basis_precomputation_field_multiplication_count = checked_multiply(
        resource.authorized_subset_count_per_participant,
        checked_sub(checked_multiply(resource.active_fault_bound, 2)?, 1)?,
    )?;
    let prss_basis_precomputation_field_multiplication_count_per_participant = checked_add(
        ordinary_basis_precomputation_field_multiplication_count,
        zero_basis_precomputation_field_multiplication_count,
    )?;
    let prss_accumulation_field_addition_count_per_participant = checked_add(
        checked_multiply(
            resource.random_degree_three_sharing_count,
            checked_sub(resource.authorized_subset_count_per_participant, 1)?,
        )?,
        checked_multiply(
            resource.random_degree_six_zero_sharing_count,
            checked_sub(zero_stream_count_per_participant, 1)?,
        )?,
    )?;
    let maximum_field_multiplication_count_per_participant = [
        resource.total_prss_field_output_count_per_participant,
        prss_basis_precomputation_field_multiplication_count_per_participant,
        resource.beaver_triple_count,
        checked_multiply(3, resource.beaver_triple_count)?,
        resource.affine_term_count,
        resource.public_scale_operation_count,
        resource.validation_challenge_coefficient_count,
        checked_multiply(
            resource.beaver_triple_count,
            DEGREE_SIX_CODEWORD_CHECK_MULTIPLICATION_COUNT,
        )?,
        checked_multiply(
            degree_three_opened_value_count,
            DEGREE_THREE_CODEWORD_CHECK_MULTIPLICATION_COUNT,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let all_abstention_field_multiplication_count_per_participant = checked_add(
        checked_add(
            resource.total_prss_field_output_count_per_participant,
            prss_basis_precomputation_field_multiplication_count_per_participant,
        )?,
        checked_add(
            resource.beaver_triple_count,
            checked_multiply(
                resource.beaver_triple_count,
                DEGREE_SIX_CODEWORD_CHECK_MULTIPLICATION_COUNT,
            )?,
        )?,
    )?;
    let transcript_leaf_hash_count_per_participant = maximum_success.public_message_count;
    let private_message_involvement_count_per_participant = checked_multiply(
        checked_multiply(2, carrier_geometry.remote_participant_count)?,
        2,
    )?;
    let private_carrier_hash_count_per_participant =
        checked_multiply(private_message_involvement_count_per_participant, 2)?;
    let round_root_hash_count_per_participant = maximum_success.interaction_round_count;
    let computation_target_hash_count_per_participant = 1;
    let checkpoint_hash_call_count_per_participant =
        checked_multiply(maximum_success.checkpoint_boundary_count_per_participant, 3)?;
    let foundation_hash_call_count_per_participant = [
        carrier_geometry.seed_opening_count_per_participant,
        carrier_geometry.ballot_share_commitment_count_per_submission,
        checked_add(
            checked_add(
                checked_multiply(
                    resource.authorized_subset_count_per_participant,
                    resource.authorized_subset_size,
                )?,
                carrier_geometry.participant_count,
            )?,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
        transcript_leaf_hash_count_per_participant,
        private_carrier_hash_count_per_participant,
        round_root_hash_count_per_participant,
        computation_target_hash_count_per_participant,
        checkpoint_hash_call_count_per_participant,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let fixed_function = DirectMpcFixedFunctionResourceLedger {
        unique_field_sample_count,
        aggregate_field_sampling_security_bits,
        field_stream_query_byte_length: direct_mpc_field_stream_query_byte_length(
            candidate.profile().participant_count(),
        )?,
        field_stream_customization_byte_length: DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION.len() as u64,
        kmacxof256_query_count_per_participant: resource
            .prss_kmacxof256_query_count_per_participant,
        kmacxof256_absorbed_byte_length_per_participant: checked_multiply(
            resource.prss_kmacxof256_query_count_per_participant,
            kmac_absorbed_byte_length_per_query,
        )?,
        kmacxof256_permutation_count_per_participant,
        validation_cshakexof256_query_count_per_participant: 1,
        validation_cshakexof256_permutation_count_per_participant:
            validation_cshakexof256_permutation_count,
        maximum_uninterrupted_permutation_count: ordinary_stream_permutation_count,
        maximum_uninterrupted_field_reduction_count: resource.random_degree_three_sharing_count,
        maximum_lost_or_replayed_xof_output_byte_length: ordinary_stream_output_byte_length,
        public_signature_context_byte_length: PUBLIC_MESSAGE_SIGNATURE_CONTEXT.len() as u64,
        private_signature_context_byte_length: PRIVATE_MESSAGE_SIGNATURE_CONTEXT.len() as u64,
        signature_generation_count_complete_roster: maximum_success
            .public_message_count
            .checked_add(maximum_success.private_message_count)
            .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        signature_verification_count_per_participant: checked_add(
            maximum_success.public_message_count,
            checked_multiply(2, carrier_geometry.remote_participant_count)?,
        )?,
        kem_encapsulation_count_complete_roster: maximum_success.private_message_count,
        kem_decapsulation_count_complete_roster: maximum_success.private_message_count,
        aead_seal_count_complete_roster: maximum_success.private_message_count,
        aead_open_count_complete_roster: maximum_success.private_message_count,
        commitment_hash_generation_count_per_participant: checked_add(
            carrier_geometry.seed_opening_count_per_participant,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
        commitment_hash_verification_count_per_participant: checked_add(
            checked_add(
                checked_multiply(
                    resource.authorized_subset_count_per_participant,
                    resource.authorized_subset_size,
                )?,
                carrier_geometry.participant_count,
            )?,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
        transcript_leaf_hash_count_per_participant,
        private_carrier_hash_count_per_participant,
        round_root_hash_count_per_participant,
        computation_target_hash_count_per_participant,
        foundation_hash_call_count_per_participant,
        seed_commitment_hash_preimage_byte_length: seed_commitment_hash_preimage_byte_length()?,
        ballot_share_commitment_hash_preimage_byte_length:
            ballot_share_commitment_hash_preimage_byte_length()?,
        maximum_transcript_leaf_hash_preimage_byte_length: hash_preimage_byte_length(
            "sealed-lattice/v1/direct-mpc/transcript-message-leaf",
            maximum_success.maximum_single_carrier_byte_length,
        )?,
        maximum_round_root_hash_preimage_byte_length: round_root_hash_preimage_byte_length(
            resource.participant_count,
        )?,
        computation_target_hash_preimage_byte_length: computation_target_hash_preimage_byte_length(
        )?,
        checkpoint_hash_call_count_per_participant,
        prss_basis_precomputation_field_multiplication_count_per_participant,
        prss_ordinary_basis_modular_inverse_count_per_participant: resource
            .authorized_subset_count_per_participant,
        prss_weight_field_multiplication_count_per_participant: resource
            .total_prss_field_output_count_per_participant,
        prss_accumulation_field_addition_count_per_participant,
        maximum_field_multiplication_count_per_participant,
        all_abstention_field_multiplication_count_per_participant,
    };

    let persistent_secret_byte_length_per_participant = [
        resource.persistent_secret_field_byte_length_per_participant,
        resource.joined_subset_master_byte_length_per_participant,
        persistent_seed_opening_byte_length,
        persistent_ballot_opening_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let prss_basis_weight_byte_length_per_participant = checked_multiply(
        checked_add(
            resource.authorized_subset_count_per_participant,
            zero_stream_count_per_participant,
        )?,
        FIELD_CANONICAL_BYTE_LENGTH,
    )?;
    let maximum_carrier_byte_length = maximum_success
        .maximum_single_carrier_byte_length
        .max(checkpoint_state_byte_length);
    let configured_transport_chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length as u64;
    let scratch_byte_length = [
        resource.maximum_prss_xof_output_allocation_byte_length,
        resource.maximum_prss_accumulator_allocation_byte_length,
        prss_basis_weight_byte_length_per_participant,
        maximum_success.maximum_single_carrier_byte_length,
        checkpoint_state_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let candidate_owned_wasm_live_set_byte_length = [
        persistent_secret_byte_length_per_participant,
        arithmetic_wire_byte_length,
        prss_basis_weight_byte_length_per_participant,
        resource.maximum_prss_xof_output_allocation_byte_length,
        resource.maximum_prss_accumulator_allocation_byte_length,
        maximum_success.maximum_single_carrier_byte_length,
        checkpoint_state_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let candidate_owned_javascript_live_set_byte_length = checked_add(
        checked_multiply(2, configured_transport_chunk_byte_length)?,
        maximum_carrier_byte_length,
    )?;
    let protocol_storage_byte_length = protocol_storage_byte_length(&maximum_success)?;
    let persistent_storage_with_repair_byte_length = [
        protocol_storage_byte_length,
        checkpoint.retained_and_staged_stored_value_capacity_byte_length,
        checkpoint.authenticated_repair_head_plaintext_capacity_byte_length,
        RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        STORAGE_INDEX_VALUE_BYTE_LENGTH,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let restart_and_repair_traffic_byte_length = checked_add(
        checkpoint.cold_restart_traffic_byte_length,
        maximum_success.maximum_participant_retained_protocol_byte_length,
    )?;
    let live_set = DirectMpcLiveSetResourceLedger {
        persistent_secret_byte_length_per_participant,
        arithmetic_wire_byte_length_per_participant: arithmetic_wire_byte_length,
        prss_basis_weight_byte_length_per_participant,
        scratch_byte_length,
        maximum_contiguous_allocation_byte_length: configured_transport_chunk_byte_length.max(
            resource
                .maximum_prss_xof_output_allocation_byte_length
                .max(maximum_carrier_byte_length),
        ),
        candidate_owned_wasm_live_set_byte_length,
        candidate_owned_javascript_live_set_byte_length,
        candidate_owned_browser_private_live_set_byte_length: checked_add(
            candidate_owned_wasm_live_set_byte_length,
            candidate_owned_javascript_live_set_byte_length,
        )?,
        persistent_storage_with_repair_byte_length,
        restart_and_repair_traffic_byte_length,
    };

    let ledger = DirectMpcCandidateCarrierLedger {
        maximum_success,
        one_submission,
        all_abstention,
        withholding,
        authenticated_burn,
        rollback_retirement,
        checkpoint,
        fixed_function,
        live_set,
        seed_catalog_public_carrier_byte_length: public_message_byte_length(
            1,
            1,
            seed_catalog_payload(
                resource.authorized_subset_count_per_participant,
                carrier_geometry.seed_opening_count_per_participant,
            )?,
        )?,
        seed_private_carrier_byte_length: private_message_carrier_byte_length(
            2,
            101,
            seed_private_payload(carrier_geometry.subset_opening_count_per_seed_mailbox)?,
        )?,
        submitted_ballot_declaration_carrier_byte_length: public_message_byte_length(
            5,
            5,
            ballot_declaration_payload(
                true,
                carrier_geometry.ballot_share_commitment_count_per_submission,
            )?,
        )?,
        abstaining_ballot_declaration_carrier_byte_length: public_message_byte_length(
            5,
            5,
            ballot_declaration_payload(
                false,
                carrier_geometry.ballot_share_commitment_count_per_submission,
            )?,
        )?,
        ballot_source_private_carrier_byte_length: private_message_carrier_byte_length(
            5,
            102,
            ballot_source_private_payload(carrier_geometry.ballot_field_count_per_submission)?,
        )?,
        maximum_field_opening_carrier_byte_length,
    };
    ledger.require_within_static_bounds()?;
    Ok(ledger)
}

fn compile_nonempty_path(
    candidate: &CompiledDirectMpcCandidate,
    submission_count: u64,
) -> Result<DirectMpcPathResourceLedger, DirectMpcCarrierCompilerError> {
    let resource = candidate.resource_model()?;
    let carrier_geometry = DirectMpcCarrierGeometry::derive(candidate)?;
    if submission_count == 0 || submission_count > carrier_geometry.participant_count {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    let interaction = candidate.interaction_graph()?;
    let participant_count = resource.participant_count;
    let submitted_participant_count = submission_count;
    let abstaining_participant_count = checked_sub(participant_count, submission_count)?;

    let seed_catalog_message = public_message_byte_length(
        1,
        1,
        seed_catalog_payload(
            resource.authorized_subset_count_per_participant,
            carrier_geometry.seed_opening_count_per_participant,
        )?,
    )?;
    let seed_receipt_message = public_message_byte_length(
        3,
        3,
        receipt_payload(
            "sealed-lattice/v1/direct-mpc/seed-mailbox-receipt",
            carrier_geometry.remote_participant_count,
        )?,
    )?;
    let triple_opening_message = public_field_message_byte_length(
        4,
        4,
        resource.beaver_triple_count,
        "sealed-lattice/v1/direct-mpc/triple-preparation-opening",
    )?;
    let submitted_declaration_message = public_message_byte_length(
        5,
        5,
        ballot_declaration_payload(
            true,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
    )?;
    let abstaining_declaration_message = public_message_byte_length(
        5,
        5,
        ballot_declaration_payload(
            false,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
    )?;
    let source_field_count_per_participant = checked_multiply(
        submission_count,
        carrier_geometry.ballot_field_count_per_submission,
    )?;
    let submitted_source_receipt_message = public_message_byte_length(
        6,
        6,
        receipt_and_field_payload(
            "sealed-lattice/v1/direct-mpc/ballot-source-receipt-and-consistency-opening",
            checked_sub(submission_count, 1)?,
            source_field_count_per_participant,
        )?,
    )?;
    let abstaining_source_receipt_message = public_message_byte_length(
        6,
        6,
        receipt_and_field_payload(
            "sealed-lattice/v1/direct-mpc/ballot-source-receipt-and-consistency-opening",
            submission_count,
            source_field_count_per_participant,
        )?,
    )?;
    let challenge_opening_message =
        public_message_byte_length(7, 7, collective_coin_opening_payload()?)?;
    let validation_output_field_count = checked_add(
        participant_count,
        DIRECT_MPC_VALIDATION_REPETITION_COUNT as u64,
    )?;
    let validation_output_message = public_field_message_byte_length(
        15,
        9,
        validation_output_field_count,
        "sealed-lattice/v1/direct-mpc/validation-output-opening",
    )?;
    let selected_set_message = public_message_byte_length(
        16,
        10,
        hash_payload("sealed-lattice/v1/direct-mpc/selected-set-authorization", 2)?,
    )?;
    let target_finality_message = public_message_byte_length(
        17,
        11,
        hash_payload("sealed-lattice/v1/direct-mpc/target-finality", 3)?,
    )?;
    let result_opening_message = public_field_message_byte_length(
        30,
        15,
        u64::from(candidate.profile().top_count()),
        "sealed-lattice/v1/direct-mpc/result-opening",
    )?;
    let result_witness_message = public_message_byte_length(
        31,
        16,
        hash_payload("sealed-lattice/v1/direct-mpc/result-witness", 2)?,
    )?;

    let mut public_carrier_byte_length = 0_u64;
    let mut submitted_participant_public_upload_byte_length = 0_u64;
    let mut abstaining_participant_public_upload_byte_length = 0_u64;
    let mut maximum_single_carrier_byte_length = 0_u64;
    let common_all_participant_messages = [
        seed_catalog_message,
        seed_receipt_message,
        triple_opening_message,
        challenge_opening_message,
        validation_output_message,
        result_opening_message,
    ];
    for message_byte_length in common_all_participant_messages {
        public_carrier_byte_length = checked_add(
            public_carrier_byte_length,
            checked_multiply(participant_count, message_byte_length)?,
        )?;
        submitted_participant_public_upload_byte_length = checked_add(
            submitted_participant_public_upload_byte_length,
            message_byte_length,
        )?;
        abstaining_participant_public_upload_byte_length = checked_add(
            abstaining_participant_public_upload_byte_length,
            message_byte_length,
        )?;
        maximum_single_carrier_byte_length =
            maximum_single_carrier_byte_length.max(message_byte_length);
    }
    public_carrier_byte_length = checked_add(
        public_carrier_byte_length,
        checked_add(
            checked_multiply(submitted_participant_count, submitted_declaration_message)?,
            checked_multiply(abstaining_participant_count, abstaining_declaration_message)?,
        )?,
    )?;
    submitted_participant_public_upload_byte_length = checked_add(
        submitted_participant_public_upload_byte_length,
        submitted_declaration_message,
    )?;
    abstaining_participant_public_upload_byte_length = checked_add(
        abstaining_participant_public_upload_byte_length,
        abstaining_declaration_message,
    )?;
    maximum_single_carrier_byte_length = maximum_single_carrier_byte_length
        .max(submitted_declaration_message)
        .max(abstaining_declaration_message);
    public_carrier_byte_length = checked_add(
        public_carrier_byte_length,
        checked_add(
            checked_multiply(
                submitted_participant_count,
                submitted_source_receipt_message,
            )?,
            checked_multiply(
                abstaining_participant_count,
                abstaining_source_receipt_message,
            )?,
        )?,
    )?;
    submitted_participant_public_upload_byte_length = checked_add(
        submitted_participant_public_upload_byte_length,
        submitted_source_receipt_message,
    )?;
    abstaining_participant_public_upload_byte_length = checked_add(
        abstaining_participant_public_upload_byte_length,
        abstaining_source_receipt_message,
    )?;
    maximum_single_carrier_byte_length = maximum_single_carrier_byte_length
        .max(submitted_source_receipt_message)
        .max(abstaining_source_receipt_message);

    for round in &interaction.success_rounds {
        let (kind_code, payload_domain) = match round.kind {
            DirectMpcRoundKind::ValidationMultiplicationOpenings { .. } => (
                8,
                "sealed-lattice/v1/direct-mpc/validation-multiplication-opening",
            ),
            DirectMpcRoundKind::EvaluationMultiplicationOpenings { .. } => (
                14,
                "sealed-lattice/v1/direct-mpc/evaluation-multiplication-opening",
            ),
            _ => continue,
        };
        if round.public_message_count != participant_count
            || !round
                .public_field_element_count
                .is_multiple_of(participant_count)
        {
            return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
        }
        let field_count_per_participant = round.public_field_element_count / participant_count;
        let message_byte_length = public_field_message_byte_length(
            round.ordinal,
            kind_code,
            field_count_per_participant,
            payload_domain,
        )?;
        public_carrier_byte_length = checked_add(
            public_carrier_byte_length,
            checked_multiply(participant_count, message_byte_length)?,
        )?;
        submitted_participant_public_upload_byte_length = checked_add(
            submitted_participant_public_upload_byte_length,
            message_byte_length,
        )?;
        abstaining_participant_public_upload_byte_length = checked_add(
            abstaining_participant_public_upload_byte_length,
            message_byte_length,
        )?;
        maximum_single_carrier_byte_length =
            maximum_single_carrier_byte_length.max(message_byte_length);
    }

    for (quorum_message, quorum) in [
        (selected_set_message, resource.selected_set_quorum),
        (target_finality_message, resource.finality_quorum),
        (result_witness_message, resource.state_witness_quorum),
    ] {
        public_carrier_byte_length = checked_add(
            public_carrier_byte_length,
            checked_multiply(quorum, quorum_message)?,
        )?;
        submitted_participant_public_upload_byte_length = checked_add(
            submitted_participant_public_upload_byte_length,
            quorum_message,
        )?;
        abstaining_participant_public_upload_byte_length = checked_add(
            abstaining_participant_public_upload_byte_length,
            quorum_message,
        )?;
        maximum_single_carrier_byte_length = maximum_single_carrier_byte_length.max(quorum_message);
    }

    let seed_private_carrier = private_message_carrier_byte_length(
        2,
        101,
        seed_private_payload(carrier_geometry.subset_opening_count_per_seed_mailbox)?,
    )?;
    let ballot_private_carrier = private_message_carrier_byte_length(
        5,
        102,
        ballot_source_private_payload(carrier_geometry.ballot_field_count_per_submission)?,
    )?;
    maximum_single_carrier_byte_length = maximum_single_carrier_byte_length
        .max(seed_private_carrier)
        .max(ballot_private_carrier);
    let seed_private_message_count =
        checked_multiply(participant_count, carrier_geometry.remote_participant_count)?;
    let ballot_private_message_count =
        checked_multiply(submission_count, carrier_geometry.remote_participant_count)?;
    let private_message_count =
        checked_add(seed_private_message_count, ballot_private_message_count)?;
    let private_carrier_byte_length = checked_add(
        checked_multiply(seed_private_message_count, seed_private_carrier)?,
        checked_multiply(ballot_private_message_count, ballot_private_carrier)?,
    )?;
    let public_message_count = interaction
        .success_rounds
        .iter()
        .try_fold(0_u64, |sum, round| {
            checked_add(sum, round.public_message_count)
        })?;
    let expected_maximum_private_message_count = interaction
        .success_rounds
        .iter()
        .try_fold(0_u64, |sum, round| {
            checked_add(sum, round.private_message_count)
        })?;
    if submission_count == participant_count
        && expected_maximum_private_message_count != private_message_count
    {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    let public_raw_field_element_count = checked_add(
        checked_sub(
            resource.public_raw_field_element_count,
            checked_multiply(resource.source_consistency_mask_count, participant_count)?,
        )?,
        checked_multiply(
            checked_multiply(
                submission_count,
                carrier_geometry.ballot_field_count_per_submission,
            )?,
            participant_count,
        )?,
    )?;

    let submitted_private_upload_byte_length = checked_add(
        checked_multiply(
            carrier_geometry.remote_participant_count,
            seed_private_carrier,
        )?,
        checked_multiply(
            carrier_geometry.remote_participant_count,
            ballot_private_carrier,
        )?,
    )?;
    let abstaining_private_upload_byte_length = checked_multiply(
        carrier_geometry.remote_participant_count,
        seed_private_carrier,
    )?;
    let maximum_participant_upload_byte_length = checked_add(
        submitted_participant_public_upload_byte_length,
        submitted_private_upload_byte_length,
    )?
    .max(checked_add(
        abstaining_participant_public_upload_byte_length,
        abstaining_private_upload_byte_length,
    )?);
    let submitted_private_download_byte_length = checked_add(
        checked_multiply(
            carrier_geometry.remote_participant_count,
            seed_private_carrier,
        )?,
        checked_multiply(checked_sub(submission_count, 1)?, ballot_private_carrier)?,
    )?;
    let abstaining_private_download_byte_length = checked_add(
        checked_multiply(
            carrier_geometry.remote_participant_count,
            seed_private_carrier,
        )?,
        checked_multiply(submission_count, ballot_private_carrier)?,
    )?;
    let maximum_participant_download_byte_length = if abstaining_participant_count == 0 {
        checked_add(
            public_carrier_byte_length,
            submitted_private_download_byte_length,
        )?
    } else {
        checked_add(
            public_carrier_byte_length,
            submitted_private_download_byte_length.max(abstaining_private_download_byte_length),
        )?
    };
    let submitted_retained_private_byte_length = checked_add(
        checked_multiply(
            checked_multiply(2, carrier_geometry.remote_participant_count)?,
            seed_private_carrier,
        )?,
        checked_multiply(
            checked_add(
                carrier_geometry.remote_participant_count,
                checked_sub(submission_count, 1)?,
            )?,
            ballot_private_carrier,
        )?,
    )?;
    let abstaining_retained_private_byte_length = checked_add(
        checked_multiply(
            checked_multiply(2, carrier_geometry.remote_participant_count)?,
            seed_private_carrier,
        )?,
        checked_multiply(submission_count, ballot_private_carrier)?,
    )?;
    let maximum_retained_private_byte_length = if abstaining_participant_count == 0 {
        submitted_retained_private_byte_length
    } else {
        submitted_retained_private_byte_length.max(abstaining_retained_private_byte_length)
    };
    let submitted_retained_private_carrier_count = checked_add(
        checked_multiply(2, carrier_geometry.remote_participant_count)?,
        checked_add(
            carrier_geometry.remote_participant_count,
            checked_sub(submission_count, 1)?,
        )?,
    )?;
    let abstaining_retained_private_carrier_count = checked_add(
        checked_multiply(2, carrier_geometry.remote_participant_count)?,
        submission_count,
    )?;
    let maximum_retained_private_carrier_count = if abstaining_participant_count == 0 {
        submitted_retained_private_carrier_count
    } else {
        submitted_retained_private_carrier_count.max(abstaining_retained_private_carrier_count)
    };

    Ok(DirectMpcPathResourceLedger {
        submission_count,
        interaction_round_count: u64::try_from(interaction.success_rounds.len())
            .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        public_message_count,
        private_message_count,
        public_raw_field_element_count,
        public_carrier_byte_length,
        private_carrier_byte_length,
        complete_roster_transfer_byte_length: checked_add(
            public_carrier_byte_length,
            private_carrier_byte_length,
        )?,
        maximum_participant_download_byte_length,
        maximum_participant_upload_byte_length,
        maximum_participant_retained_protocol_byte_length: checked_add(
            public_carrier_byte_length,
            maximum_retained_private_byte_length,
        )?,
        maximum_participant_retained_carrier_count: checked_add(
            public_message_count,
            maximum_retained_private_carrier_count,
        )?,
        maximum_single_carrier_byte_length,
        checkpoint_boundary_count_per_participant: checked_add(
            resource.prss_work_checkpoint_count_per_participant,
            u64::try_from(interaction.success_rounds.len())
                .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        )?,
    })
}

fn compile_all_abstention_path(
    candidate: &CompiledDirectMpcCandidate,
) -> Result<DirectMpcPathResourceLedger, DirectMpcCarrierCompilerError> {
    let resource = candidate.resource_model()?;
    let carrier_geometry = DirectMpcCarrierGeometry::derive(candidate)?;
    let interaction = candidate.interaction_graph()?;
    let participant_count = resource.participant_count;
    let seed_catalog_message = public_message_byte_length(
        1,
        1,
        seed_catalog_payload(
            resource.authorized_subset_count_per_participant,
            carrier_geometry.seed_opening_count_per_participant,
        )?,
    )?;
    let seed_receipt_message = public_message_byte_length(
        3,
        3,
        receipt_payload(
            "sealed-lattice/v1/direct-mpc/seed-mailbox-receipt",
            carrier_geometry.remote_participant_count,
        )?,
    )?;
    let triple_opening_message = public_field_message_byte_length(
        4,
        4,
        resource.beaver_triple_count,
        "sealed-lattice/v1/direct-mpc/triple-preparation-opening",
    )?;
    let abstaining_declaration_message = public_message_byte_length(
        5,
        5,
        ballot_declaration_payload(
            false,
            carrier_geometry.ballot_share_commitment_count_per_submission,
        )?,
    )?;
    let no_result_witness_message = public_message_byte_length(
        6,
        19,
        hash_payload("sealed-lattice/v1/direct-mpc/no-result-witness", 1)?,
    )?;
    let seed_private_carrier = private_message_carrier_byte_length(
        2,
        101,
        seed_private_payload(carrier_geometry.subset_opening_count_per_seed_mailbox)?,
    )?;

    let public_carrier_byte_length = checked_add(
        checked_multiply(
            participant_count,
            [
                seed_catalog_message,
                seed_receipt_message,
                triple_opening_message,
                abstaining_declaration_message,
            ]
            .into_iter()
            .try_fold(0_u64, checked_add)?,
        )?,
        checked_multiply(resource.state_witness_quorum, no_result_witness_message)?,
    )?;
    let private_message_count =
        checked_multiply(participant_count, carrier_geometry.remote_participant_count)?;
    let private_carrier_byte_length =
        checked_multiply(private_message_count, seed_private_carrier)?;
    let public_message_count = interaction
        .all_abstention_rounds
        .iter()
        .try_fold(0_u64, |sum, round| {
            checked_add(sum, round.public_message_count)
        })?;
    let expected_private_message_count = interaction
        .all_abstention_rounds
        .iter()
        .try_fold(0_u64, |sum, round| {
            checked_add(sum, round.private_message_count)
        })?;
    let public_raw_field_element_count = interaction
        .all_abstention_rounds
        .iter()
        .try_fold(0_u64, |sum, round| {
            checked_add(sum, round.public_field_element_count)
        })?;
    if expected_private_message_count != private_message_count {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    let participant_public_upload_byte_length = checked_add(
        [
            seed_catalog_message,
            seed_receipt_message,
            triple_opening_message,
            abstaining_declaration_message,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?,
        no_result_witness_message,
    )?;
    let participant_private_direction_byte_length = checked_multiply(
        carrier_geometry.remote_participant_count,
        seed_private_carrier,
    )?;
    let maximum_participant_retained_protocol_byte_length = checked_add(
        public_carrier_byte_length,
        checked_multiply(2, participant_private_direction_byte_length)?,
    )?;
    let maximum_single_carrier_byte_length = [
        seed_catalog_message,
        seed_receipt_message,
        triple_opening_message,
        abstaining_declaration_message,
        no_result_witness_message,
        seed_private_carrier,
    ]
    .into_iter()
    .max()
    .ok_or(DirectMpcCarrierCompilerError::GeometryMismatch)?;

    Ok(DirectMpcPathResourceLedger {
        submission_count: 0,
        interaction_round_count: u64::try_from(interaction.all_abstention_rounds.len())
            .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        public_message_count,
        private_message_count,
        public_raw_field_element_count,
        public_carrier_byte_length,
        private_carrier_byte_length,
        complete_roster_transfer_byte_length: checked_add(
            public_carrier_byte_length,
            private_carrier_byte_length,
        )?,
        maximum_participant_download_byte_length: checked_add(
            public_carrier_byte_length,
            participant_private_direction_byte_length,
        )?,
        maximum_participant_upload_byte_length: checked_add(
            participant_public_upload_byte_length,
            participant_private_direction_byte_length,
        )?,
        maximum_participant_retained_protocol_byte_length,
        maximum_participant_retained_carrier_count: checked_add(
            public_message_count,
            checked_multiply(2, carrier_geometry.remote_participant_count)?,
        )?,
        maximum_single_carrier_byte_length,
        checkpoint_boundary_count_per_participant: checked_add(
            resource.prss_work_checkpoint_count_per_participant,
            u64::try_from(interaction.all_abstention_rounds.len())
                .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        )?,
    })
}

fn compile_checkpoint_resource_ledger(
    checkpoint_state_byte_length: u64,
    publication_count: u64,
) -> Result<DirectMpcCheckpointResourceLedger, DirectMpcCarrierCompilerError> {
    let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length as u64;
    let checkpoint_chunk_count = ceiling_divide(checkpoint_state_byte_length, chunk_byte_length)?;
    let state_stream_descriptor = checkpoint_state_stream_descriptor(checkpoint_chunk_count)?;
    let state_stream_descriptor_byte_length = u64::try_from(state_stream_descriptor.len())
        .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?;
    let deterministic_cursor = checkpoint_cursor_bytes()?;
    let deterministic_cursor_byte_length = u64::try_from(deterministic_cursor.len())
        .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?;
    let canonical_manifest_byte_length =
        checkpoint_manifest_byte_length(&deterministic_cursor, &state_stream_descriptor)?;
    let maximum_chunk_record_key_byte_length = [
        "checkpoint/chunk/".len() as u64,
        2 * CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH,
        1,
        2 * CHECKPOINT_PUBLICATION_IDENTIFIER_BYTE_LENGTH,
        1,
        CHECKPOINT_CHUNK_INDEX_HEX_BYTE_LENGTH,
        1,
        CHECKPOINT_CHUNK_DIGEST_HEX_BYTE_LENGTH,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let maximum_manifest_record_key_byte_length = checked_add(
        "checkpoint/manifest/".len() as u64,
        2 * CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH,
    )?;
    let maximum_journal_record_key_byte_length = checked_add(
        "checkpoint/journal/".len() as u64,
        2 * CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH,
    )?;
    let maximum_logical_record_key_byte_length = maximum_chunk_record_key_byte_length
        .max(maximum_manifest_record_key_byte_length)
        .max(maximum_journal_record_key_byte_length);
    let simultaneous_logical_record_count =
        checked_add(checked_multiply(checkpoint_chunk_count, 2)?, 2)?;
    let checkpoint_chunk_stored_value_byte_length = checked_add(
        checked_multiply(checkpoint_state_byte_length, 2)?,
        checked_multiply(
            checked_multiply(checkpoint_chunk_count, 2)?,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
    )?;
    let manifest_plaintext_byte_length = checked_add(
        canonical_manifest_byte_length,
        CHECKPOINT_STORED_MANIFEST_HEADER_BYTE_LENGTH,
    )?;
    let manifest_stored_value_byte_length = checked_multiply(
        checked_add(
            manifest_plaintext_byte_length,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
        2,
    )?;
    let journal_plaintext_byte_length = checked_add(
        CHECKPOINT_JOURNAL_BASE_BYTE_LENGTH,
        checked_multiply(
            checked_multiply(checkpoint_chunk_count, 2)?,
            checked_add(maximum_chunk_record_key_byte_length, 4)?,
        )?,
    )?;
    let journal_stored_value_byte_length = checked_multiply(
        checked_add(
            journal_plaintext_byte_length,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
        2,
    )?;
    let index_stored_value_byte_length = checked_multiply(
        simultaneous_logical_record_count,
        STORAGE_INDEX_VALUE_BYTE_LENGTH,
    )?;
    let retained_and_staged_stored_value_capacity_byte_length = [
        checkpoint_chunk_stored_value_byte_length,
        manifest_stored_value_byte_length,
        journal_stored_value_byte_length,
        index_stored_value_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let authenticated_repair_head_plaintext_capacity_byte_length = checked_multiply(
        simultaneous_logical_record_count,
        checked_add(
            checked_add(
                AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH,
                maximum_logical_record_key_byte_length,
            )?,
            STORAGE_OBJECT_KEY_BYTE_LENGTH,
        )?,
    )?;
    let seal_call_count_per_publication = checked_add(checkpoint_chunk_count, 2)?;
    let sealed_plaintext_byte_length_per_publication = [
        checkpoint_state_byte_length,
        manifest_plaintext_byte_length,
        journal_plaintext_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let cold_restart_traffic_byte_length = checked_add(
        checked_add(
            checkpoint_state_byte_length,
            checked_multiply(
                checkpoint_chunk_count,
                RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
            )?,
        )?,
        checked_add(
            manifest_plaintext_byte_length,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
    )?;
    Ok(DirectMpcCheckpointResourceLedger {
        checkpoint_state_byte_length,
        checkpoint_chunk_count,
        state_stream_descriptor_byte_length,
        deterministic_cursor_byte_length,
        canonical_manifest_byte_length,
        journal_plaintext_byte_length,
        retained_and_staged_stored_value_capacity_byte_length,
        authenticated_repair_head_plaintext_capacity_byte_length,
        maximum_owned_record_count: checked_add(
            checked_multiply(simultaneous_logical_record_count, 2)?,
            2,
        )?,
        seal_call_count_per_publication,
        cumulative_sealed_plaintext_byte_length_per_participant: checked_multiply(
            publication_count,
            sealed_plaintext_byte_length_per_publication,
        )?,
        cold_restart_traffic_byte_length,
    })
}

fn seed_catalog_payload(
    subset_commitment_count: u64,
    total_commitment_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/seed-catalog")?,
        CanonicalItem::unsigned64(subset_commitment_count),
        CanonicalItem::unsigned16(1),
        homogeneous_hashes(total_commitment_count)?,
    ]))
}

fn seed_private_payload(
    subset_opening_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/seed-delivery")?,
        CanonicalItem::unsigned64(subset_opening_count),
        homogeneous_fixed_values(CanonicalItemType::Unsigned32, subset_opening_count, 4)?,
        homogeneous_fixed_values(
            CanonicalItemType::RawBytes,
            subset_opening_count,
            DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH,
        )?,
        homogeneous_fixed_values(
            CanonicalItemType::RawBytes,
            subset_opening_count,
            COMMITMENT_SALT_BYTE_LENGTH,
        )?,
    ]))
}

fn ballot_declaration_payload(
    submitted: bool,
    submitted_commitment_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    let commitment_count = if submitted {
        submitted_commitment_count
    } else {
        0
    };
    Ok(tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/ballot-declaration")?,
        CanonicalItem::boolean(submitted),
        CanonicalItem::unsigned64(commitment_count),
        homogeneous_hashes(commitment_count)?,
    ]))
}

fn ballot_source_private_payload(
    field_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/ballot-source-delivery")?,
        CanonicalItem::unsigned64(field_count),
        homogeneous_fixed_values(
            CanonicalItemType::RawBytes,
            field_count,
            FIELD_CANONICAL_BYTE_LENGTH,
        )?,
        homogeneous_fixed_values(
            CanonicalItemType::RawBytes,
            field_count,
            COMMITMENT_SALT_BYTE_LENGTH,
        )?,
    ]))
}

fn collective_coin_opening_payload() -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/ballot-source-terminal-and-challenge-opening")?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::fixed_bytes(vec![
            0_u8;
            usize_from_u64(DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH)?
        ])?,
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(COMMITMENT_SALT_BYTE_LENGTH)?])?,
    ]))
}

fn receipt_payload(
    domain: &str,
    receipt_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii(domain)?,
        homogeneous_hashes(receipt_count)?,
    ]))
}

fn receipt_and_field_payload(
    domain: &str,
    receipt_count: u64,
    field_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii(domain)?,
        homogeneous_hashes(receipt_count)?,
        CanonicalItem::unsigned64(field_count),
        CanonicalItem::variable_bytes(vec![
            0_u8;
            usize::try_from(checked_multiply(
                field_count,
                FIELD_CANONICAL_BYTE_LENGTH,
            )?)
            .map_err(|_| {
                DirectMpcCarrierCompilerError::ArithmeticOverflow
            })?
        ])?,
    ]))
}

fn field_payload(
    domain: &str,
    field_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii(domain)?,
        CanonicalItem::unsigned64(field_count),
        CanonicalItem::variable_bytes(vec![
            0_u8;
            usize::try_from(checked_multiply(
                field_count,
                FIELD_CANONICAL_BYTE_LENGTH,
            )?)
            .map_err(|_| {
                DirectMpcCarrierCompilerError::ArithmeticOverflow
            })?
        ])?,
    ]))
}

fn hash_payload(
    domain: &str,
    hash_count: u64,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    let mut items = Vec::with_capacity(
        usize::try_from(checked_add(hash_count, 1)?)
            .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
    );
    items.push(ascii(domain)?);
    for _ in 0..hash_count {
        items.push(CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]));
    }
    Ok(tuple(items))
}

fn hash_and_code_payload(domain: &str) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii(domain)?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(1),
    ]))
}

fn participant_and_hash_payload(
    domain: &str,
) -> Result<CanonicalTuple, DirectMpcCarrierCompilerError> {
    Ok(tuple(vec![
        ascii(domain)?,
        CanonicalItem::unsigned16(0),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
    ]))
}

fn public_field_message_byte_length(
    round_ordinal: u16,
    kind_code: u16,
    field_count: u64,
    payload_domain: &str,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    public_message_byte_length(
        round_ordinal,
        kind_code,
        field_payload(payload_domain, field_count)?,
    )
}

fn public_message_byte_length(
    round_ordinal: u16,
    kind_code: u16,
    payload: CanonicalTuple,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let body = tuple(vec![
        ascii(PUBLIC_MESSAGE_BODY_DOMAIN)?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(round_ordinal),
        CanonicalItem::unsigned16(kind_code),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::nested_tuple(&payload)?,
    ])
    .encode()?;
    let envelope = tuple(vec![
        ascii(PUBLIC_MESSAGE_ENVELOPE_DOMAIN)?,
        CanonicalItem::variable_bytes(body)?,
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(ML_DSA_65_SIGNATURE_BYTE_LENGTH)?])?,
    ])
    .encode()?;
    u64::try_from(envelope.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn private_message_carrier_byte_length(
    round_ordinal: u16,
    kind_code: u16,
    payload: CanonicalTuple,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let body = tuple(vec![
        ascii(PRIVATE_MESSAGE_BODY_DOMAIN)?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(round_ordinal),
        CanonicalItem::unsigned16(kind_code),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(1),
        CanonicalItem::nested_tuple(&payload)?,
    ])
    .encode()?;
    let signed_plaintext = tuple(vec![
        ascii(PRIVATE_MESSAGE_ENVELOPE_DOMAIN)?,
        CanonicalItem::variable_bytes(body)?,
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(ML_DSA_65_SIGNATURE_BYTE_LENGTH)?])?,
    ])
    .encode()?;
    let ciphertext_byte_length = checked_add(
        u64::try_from(signed_plaintext.len())
            .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?,
        PRIVATE_CARRIER_AUTHENTICATION_TAG_BYTE_LENGTH,
    )?;
    let carrier = tuple(vec![
        ascii(PRIVATE_CARRIER_DOMAIN)?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(round_ordinal),
        CanonicalItem::unsigned16(kind_code),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned16(0),
        CanonicalItem::fixed_bytes(vec![
            0_u8;
            usize_from_u64(ML_KEM_768_CIPHERTEXT_BYTE_LENGTH)?
        ])?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(ciphertext_byte_length)?])?,
    ])
    .encode()?;
    u64::try_from(carrier.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn checkpoint_cursor_bytes() -> Result<Vec<u8>, DirectMpcCarrierCompilerError> {
    let cursor = tuple(vec![
        ascii(CHECKPOINT_CURSOR_DOMAIN)?,
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned16(1),
    ])
    .encode()?;
    Ok(cursor)
}

fn checkpoint_state_stream_descriptor(
    chunk_count: u64,
) -> Result<Vec<u8>, DirectMpcCarrierCompilerError> {
    let descriptor = CanonicalTuple::new(
        0x1800,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::unsigned64(1),
            homogeneous_hashes(chunk_count)?,
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        ],
    )
    .encode()?;
    Ok(descriptor)
}

fn checkpoint_manifest_byte_length(
    deterministic_cursor: &[u8],
    state_stream_descriptor: &[u8],
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let descriptor = CanonicalTuple::decode(
        state_stream_descriptor,
        &crate::foundation::CanonicalDecodeLimits::default(),
    )?;
    let manifest = CanonicalTuple::new(
        0x1805,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::participant_identity([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::fixed_bytes(vec![
                0_u8;
                usize_from_u64(
                    CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH
                )?
            ])?,
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned32(0),
            homogeneous_hashes(CHECKPOINT_SOURCE_DIGEST_COUNT)?,
            CanonicalItem::fixed_bytes(deterministic_cursor)?,
            CanonicalItem::fixed_bytes(vec![
                0_u8;
                usize_from_u64(
                    CHECKPOINT_RUNTIME_RANDOMNESS_IDENTIFIER_BYTE_LENGTH
                )?
            ])?,
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::unsigned64(1),
            CanonicalItem::nested_tuple(&descriptor)?,
        ],
    )
    .encode()?;
    u64::try_from(manifest.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn checkpoint_state_byte_length(
    persistent_field_byte_length: u64,
    joined_subset_master_byte_length: u64,
    seed_opening_byte_length: u64,
    ballot_opening_byte_length: u64,
    arithmetic_wire_byte_length: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let checkpoint = tuple(vec![
        ascii(CHECKPOINT_STATE_DOMAIN)?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(0),
        CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(persistent_field_byte_length)?])?,
        CanonicalItem::variable_bytes(vec![
            0_u8;
            usize_from_u64(joined_subset_master_byte_length)?
        ])?,
        CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(seed_opening_byte_length)?])?,
        CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(ballot_opening_byte_length)?])?,
        CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(arithmetic_wire_byte_length)?])?,
    ])
    .encode()?;
    u64::try_from(checkpoint.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn direct_mpc_field_stream_query_byte_length(
    participant_count: u16,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let query = tuple(vec![
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned16(participant_count),
        CanonicalItem::unsigned32(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned64(1),
        CanonicalItem::unsigned64(0),
        CanonicalItem::unsigned64(1),
    ])
    .encode()?;
    u64::try_from(query.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn seed_commitment_hash_preimage_byte_length() -> Result<u64, DirectMpcCarrierCompilerError> {
    let preimage = tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/seed-opening-commitment")?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned32(0),
        CanonicalItem::fixed_bytes(vec![
            0_u8;
            usize_from_u64(DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH)?
        ])?,
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(COMMITMENT_SALT_BYTE_LENGTH)?])?,
    ])
    .encode()?;
    u64::try_from(preimage.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn ballot_share_commitment_hash_preimage_byte_length() -> Result<u64, DirectMpcCarrierCompilerError>
{
    let preimage = tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/ballot-share-commitment")?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned16(0),
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(FIELD_CANONICAL_BYTE_LENGTH)?])?,
        CanonicalItem::fixed_bytes(vec![0_u8; usize_from_u64(COMMITMENT_SALT_BYTE_LENGTH)?])?,
    ])
    .encode()?;
    u64::try_from(preimage.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn hash_preimage_byte_length(
    domain: &str,
    value_byte_length: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let preimage = tuple(vec![
        ascii(domain)?,
        CanonicalItem::variable_bytes(vec![
            0_u8;
            usize::try_from(value_byte_length).map_err(|_| {
                DirectMpcCarrierCompilerError::ArithmeticOverflow
            })?
        ])?,
    ])
    .encode()?;
    u64::try_from(preimage.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn round_root_hash_preimage_byte_length(
    message_count: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let preimage = tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/round-root")?,
        CanonicalItem::unsigned16(1),
        homogeneous_hashes(message_count)?,
    ])
    .encode()?;
    u64::try_from(preimage.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn computation_target_hash_preimage_byte_length() -> Result<u64, DirectMpcCarrierCompilerError> {
    let preimage = tuple(vec![
        ascii("sealed-lattice/v1/direct-mpc/computation-target")?,
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
        CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
    ])
    .encode()?;
    u64::try_from(preimage.len()).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn homogeneous_hashes(count: u64) -> Result<CanonicalItem, DirectMpcCarrierCompilerError> {
    homogeneous_fixed_values(CanonicalItemType::Hash512, count, HASH512_BYTE_LENGTH)
}

fn homogeneous_fixed_values(
    item_type: CanonicalItemType,
    count: u64,
    value_byte_length: u64,
) -> Result<CanonicalItem, DirectMpcCarrierCompilerError> {
    let count =
        usize::try_from(count).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?;
    let value_byte_length = usize::try_from(value_byte_length)
        .map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)?;
    let values = (0..count)
        .map(|_| match item_type {
            CanonicalItemType::Hash512 => Ok(CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH])),
            CanonicalItemType::Unsigned32 => Ok(CanonicalItem::unsigned32(0)),
            CanonicalItemType::RawBytes => {
                Ok(CanonicalItem::fixed_bytes(vec![0_u8; value_byte_length])?)
            }
            _ => Err(DirectMpcCarrierCompilerError::GeometryMismatch),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CanonicalItem::homogeneous_list(item_type, &values)?)
}

fn ascii(value: &str) -> Result<CanonicalItem, CanonicalCodecError> {
    CanonicalItem::nonempty_ascii(value)
}

fn tuple(items: Vec<CanonicalItem>) -> CanonicalTuple {
    CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
}

fn protocol_storage_byte_length(
    path: &DirectMpcPathResourceLedger,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let retained_record_byte_length = checked_add(
        path.maximum_participant_retained_protocol_byte_length,
        checked_multiply(
            path.maximum_participant_retained_carrier_count,
            checked_add(
                RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
                STORAGE_INDEX_VALUE_BYTE_LENGTH,
            )?,
        )?,
    )?;
    let staged_and_orphanable_record_byte_length = checked_multiply(
        2,
        checked_add(
            path.maximum_single_carrier_byte_length,
            checked_add(
                RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
                STORAGE_INDEX_VALUE_BYTE_LENGTH,
            )?,
        )?,
    )?;
    let repair_head_byte_length = checked_multiply(
        path.maximum_participant_retained_carrier_count,
        checked_add(
            checked_add(
                AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH,
                STORAGE_OBJECT_KEY_BYTE_LENGTH,
            )?,
            STORAGE_OBJECT_KEY_BYTE_LENGTH,
        )?,
    )?;
    [
        retained_record_byte_length,
        staged_and_orphanable_record_byte_length,
        repair_head_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)
}

fn kmac_permutation_count(
    query_byte_length: u64,
    output_byte_length: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let message_block_count = ceiling_divide(
        checked_add(query_byte_length, KMACXOF_RIGHT_ENCODE_ZERO_BYTE_LENGTH)?,
        KECCAK_F1600_RATE_BYTE_LENGTH,
    )?;
    let output_block_count = ceiling_divide(output_byte_length, KECCAK_F1600_RATE_BYTE_LENGTH)?;
    checked_sub(
        checked_add(checked_add(2, message_block_count)?, output_block_count)?,
        1,
    )
}

fn cshake_permutation_count(
    query_byte_length: u64,
    output_byte_length: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    let message_block_count = ceiling_divide(query_byte_length, KECCAK_F1600_RATE_BYTE_LENGTH)?;
    let output_block_count = ceiling_divide(output_byte_length, KECCAK_F1600_RATE_BYTE_LENGTH)?;
    checked_sub(
        checked_add(checked_add(1, message_block_count)?, output_block_count)?,
        1,
    )
}

fn ceiling_log2(value: u64) -> Result<u64, DirectMpcCarrierCompilerError> {
    if value == 0 {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    Ok(u64::from(value.ilog2()) + u64::from(!value.is_power_of_two()))
}

fn checked_binomial_coefficient(
    population: u64,
    selected: u64,
) -> Result<u64, DirectMpcCarrierCompilerError> {
    if selected > population {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    let smaller_selection = selected.min(population - selected);
    (1..=smaller_selection).try_fold(1_u64, |coefficient, divisor| {
        let numerator = population - smaller_selection + divisor;
        let multiplied = checked_multiply(coefficient, numerator)?;
        if !multiplied.is_multiple_of(divisor) {
            return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
        }
        Ok(multiplied / divisor)
    })
}

fn ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, DirectMpcCarrierCompilerError> {
    if divisor == 0 {
        return Err(DirectMpcCarrierCompilerError::GeometryMismatch);
    }
    checked_add(
        dividend / divisor,
        u64::from(!dividend.is_multiple_of(divisor)),
    )
}

fn checked_add(left: u64, right: u64) -> Result<u64, DirectMpcCarrierCompilerError> {
    left.checked_add(right)
        .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn checked_sub(left: u64, right: u64) -> Result<u64, DirectMpcCarrierCompilerError> {
    left.checked_sub(right)
        .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, DirectMpcCarrierCompilerError> {
    left.checked_mul(right)
        .ok_or(DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn usize_from_u64(value: u64) -> Result<usize, DirectMpcCarrierCompilerError> {
    usize::try_from(value).map_err(|_| DirectMpcCarrierCompilerError::ArithmeticOverflow)
}

fn require_bound(
    resource: &'static str,
    actual: u64,
    bound: u64,
) -> Result<(), DirectMpcCarrierCompilerError> {
    if actual > bound {
        return Err(DirectMpcCarrierCompilerError::ResourceBoundExceeded {
            resource,
            actual,
            bound,
        });
    }
    Ok(())
}

const _: () = assert!(ML_DSA_65_SIGNATURE_BYTE_LENGTH == 3_309);
const _: () = assert!(ML_KEM_768_CIPHERTEXT_BYTE_LENGTH == 1_088);
