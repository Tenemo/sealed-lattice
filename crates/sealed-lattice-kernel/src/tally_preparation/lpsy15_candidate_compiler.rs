use std::collections::BTreeSet;

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
        CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
        derive_foundation_roster_parameters,
    },
    tally_circuit::{
        BooleanOperation, CompiledTallyCircuit, TallyCircuitError, TallyCircuitProfile, WireIndex,
    },
};

use super::{
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_mailbox_320::{
        ML_KEM_768_CIPHERTEXT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH,
    },
};

const SECURITY_BIT_LENGTH: u64 = 320;
const PRIME_FIELD_ELEMENT_BYTE_LENGTH: u64 = 41;
const PRIME_FIELD_ARITHMETIC_BYTE_LENGTH: u64 = 48;
const PRIME_FIELD_SAMPLE_BYTE_LENGTH: u64 = SECURITY_BIT_LENGTH / 8;
const PRIME_FIELD_MODULUS_EXCESS: u64 = 27;
const TABLE_ROW_COUNT: u64 = 4;
const PRF_BRANCH_COUNT: u64 = 2;
const KEY_ALTERNATIVE_COUNT: u64 = 2;
const INPUT_WIRE_ROLE_COUNT_PER_GATE: u64 = 2;
const SHARING_DEGREE: u64 = 3;
const PRODUCT_SHARING_DEGREE: u64 = 6;
const FIXED_FALSE_SOURCE_COUNT: u64 = 1;
const PAPER_ROUND_RECONCILIATION_COUNT: u64 = 12;
const COLLECTIVE_COIN_SALT_BYTE_LENGTH: usize = 64;
const SHAKE256_RATE_BYTE_LENGTH: u64 = 136;
const LPSY15_PRF_KEY_BYTE_LENGTH: u64 = SECURITY_BIT_LENGTH / 8;
const LPSY15_PRF_OUTPUT_BYTE_LENGTH: u64 = SECURITY_BIT_LENGTH / 8;
const LPSY15_PRF_RIGHT_ENCODE_BYTE_LENGTH: u64 = 3;
const FIELD_WORK_BATCH_ELEMENT_COUNT: u64 = 4_096;
const CHECKPOINT_ORDERED_SOURCE_DIGEST_COUNT: u64 = 5;
// These are the exact current authenticated-checkpoint-store reservation
// fields. Candidate storage remains unactivated; changing the production store
// invalidates this compiler's storage result and requires new parity evidence.
const RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH: u64 = 2 + 32 + 4 + 16;
const CHECKPOINT_STORAGE_INDEX_VALUE_BYTE_LENGTH: u64 = 256;
const AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH: u64 = 68;
const CHECKPOINT_STORAGE_OBJECT_KEY_BYTE_LENGTH: u64 = 256;
const AUTHENTICATED_REPAIR_HEAD_FIXED_BYTE_LENGTH: u64 = 4 + 2 + 8 + 32 + 64 + 64 + 4;
const CHECKPOINT_STORED_MANIFEST_FIXED_BYTE_LENGTH: u64 = 2 + 32 + 4;
const CHECKPOINT_JOURNAL_CAPACITY_FIXED_BYTE_LENGTH: u64 = 1_024;
const CHECKPOINT_CHUNK_RECORD_KEY_BYTE_LENGTH: u64 = 284;
const CHECKPOINT_MANIFEST_RECORD_KEY_BYTE_LENGTH: u64 = 84;
const CHECKPOINT_JOURNAL_RECORD_KEY_BYTE_LENGTH: u64 = 83;
const TRANSCRIPT_STORAGE_INDEX_VALUE_BYTE_LENGTH: u64 = 256;
const TRANSCRIPT_STORAGE_OBJECT_KEY_BYTE_LENGTH: u64 = 256;
// Transcript logical keys are the lowercase hexadecimal encoding of a
// 32-byte record identity, independent of relay-provided names.
const TRANSCRIPT_LOGICAL_RECORD_KEY_BYTE_LENGTH: u64 = 64;
const LPSY15_PRF_CUSTOMIZATION: &[u8] = b"sealed-lattice/v1/lpsy15/bmr-prf";
const LPSY15_PRF_MESSAGE_DOMAIN: &str = "sealed-lattice/v1/preparation/lpsy15-bmr-prf-input";
const RANDOMNESS_XOF_MESSAGE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-randomness-source";
const CHECKPOINT_CURSOR_DOMAIN: &str = "sealed-lattice/v1/preparation/lpsy15-checkpoint-cursor";
const ROUND_ROOT_DOMAIN: &str = "sealed-lattice/v1/preparation/lpsy15-round-root";
const PRIVATE_STREAM_HEADER_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-private-field-stream-header";
const PRIVATE_STREAM_MANIFEST_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-private-field-stream-manifest";
const PRIVATE_STREAM_SIGNATURE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-private-field-stream-signature-body";
const PRIVATE_STREAM_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-private-field-stream-signature-envelope";
const PUBLIC_STREAM_HEADER_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-public-field-stream-header";
const PUBLIC_STREAM_MANIFEST_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-public-field-stream-manifest";
const PUBLIC_STREAM_SIGNATURE_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-public-field-stream-signature-body";
const PUBLIC_STREAM_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-public-field-stream-signature-envelope";
const SOURCE_DELIVERY_CONTROL_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-source-delivery-control";
const DELIVERY_RECEIPT_CONTROL_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-delivery-receipt-control";
const COLLECTIVE_COIN_OPENING_CONTROL_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-collective-coin-opening";
const EVALUATION_SUCCESS_CLAIM_DOMAIN: &str = "sealed-lattice/v1/evaluation/lpsy15-success-claim";
const AUTHENTICATED_FAILURE_CLAIM_DOMAIN: &str =
    "sealed-lattice/v1/preparation/lpsy15-authenticated-failure-claim";

const PUBLIC_PAYLOAD_CHUNK_BYTE_LENGTH: u64 = (FOUNDATION_PROFILE.stream_chunk_byte_length as u64
    / PRIME_FIELD_ELEMENT_BYTE_LENGTH)
    * PRIME_FIELD_ELEMENT_BYTE_LENGTH;
const PRIVATE_PLAINTEXT_CHUNK_BYTE_LENGTH: u64 = ((FOUNDATION_PROFILE.stream_chunk_byte_length
    - PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)
    as u64
    / PRIME_FIELD_ELEMENT_BYTE_LENGTH)
    * PRIME_FIELD_ELEMENT_BYTE_LENGTH;

pub(crate) const LPSY15_PRIME_MODULUS_DECIMAL: &str = "2135987035920910082395021706169552114602704522356652769947041607822219725780640550022962086936603";

pub(crate) const LPSY15_PRIME_MODULUS_LITTLE_ENDIAN: [u8; 41] = {
    let mut modulus = [0_u8; 41];
    modulus[0] = 27;
    modulus[40] = 1;
    modulus
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lpsy15CandidateCompilerError {
    ArithmeticOverflow,
    IntegerConversion,
    MissingFixedConstantSource,
    InvalidLogicalWireReference {
        wire: WireIndex,
        available_wire_count: usize,
    },
    Circuit(TallyCircuitError),
    Canonical(CanonicalCodecError),
}

impl From<TallyCircuitError> for Lpsy15CandidateCompilerError {
    fn from(error: TallyCircuitError) -> Self {
        Self::Circuit(error)
    }
}

impl From<CanonicalCodecError> for Lpsy15CandidateCompilerError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15BallotInputRole {
    Presence {
        participant_position: u16,
    },
    ScoreBit {
        participant_position: u16,
        option_position: u16,
        bit_position: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15PhysicalWireSource {
    BallotInput(Lpsy15BallotInputRole),
    FixedFalse,
    GateOutput { gate_index: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15PhysicalWireRole {
    pub(crate) wire_index: u32,
    pub(crate) source: Lpsy15PhysicalWireSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15LogicalWireRole {
    pub(crate) logical_wire_index: WireIndex,
    pub(crate) physical_wire_index: u32,
    pub(crate) is_inverted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15GateKind {
    ExclusiveOr,
    Nonlinear {
        /// Low-to-high bits encode outputs for physical inputs 00, 01, 10, 11.
        truth_table: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15GateRole {
    pub(crate) gate_index: u32,
    pub(crate) logical_output_wire_index: WireIndex,
    pub(crate) physical_output_wire_index: u32,
    pub(crate) left_physical_wire_index: u32,
    pub(crate) right_physical_wire_index: u32,
    pub(crate) kind: Lpsy15GateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15InputWireSide {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15MaskRandomBitRole {
    pub(crate) contributor_position: u16,
    pub(crate) physical_wire_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15FieldKeyRole {
    pub(crate) owner_position: u16,
    pub(crate) physical_wire_index: u32,
    pub(crate) alternative: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15OfflinePrfOutputInputRole {
    pub(crate) key_owner_position: u16,
    pub(crate) gate_index: u32,
    pub(crate) input_side: Lpsy15InputWireSide,
    pub(crate) input_physical_wire_index: u32,
    pub(crate) key_alternative: bool,
    pub(crate) branch: bool,
    pub(crate) output_component_position: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15OnlinePrfCallRole {
    pub(crate) evaluator_position: u16,
    pub(crate) gate_index: u32,
    pub(crate) input_side: Lpsy15InputWireSide,
    pub(crate) input_physical_wire_index: u32,
    pub(crate) key_owner_position: u16,
    pub(crate) output_component_position: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15SourcePolynomialKind {
    PrivateInput,
    RandomSource,
    DoubleSourceDegreeThree,
    DoubleSourceDegreeSix,
    OrdinaryCheckMask,
    PairedCheckDegreeThree,
    PairedCheckDegreeSix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15SourcePolynomialRole {
    pub(crate) dealer_position: u16,
    pub(crate) kind: Lpsy15SourcePolynomialKind,
    pub(crate) ordinal_within_kind: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15MultiplicationKind {
    MaskProduct,
    MaskCheckOrGateInput,
    Indicator,
    TableSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15MultiplicationRole {
    pub(crate) multiplication_ordinal: u64,
    pub(crate) layer_index: u16,
    pub(crate) ordinal_within_layer: u64,
    pub(crate) kind: Lpsy15MultiplicationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15OutputKind {
    Nonempty,
    OrderedOptionPositionBit {
        output_position: u16,
        bit_position: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15OutputRole {
    pub(crate) kind: Lpsy15OutputKind,
    pub(crate) logical_wire_index: WireIndex,
    pub(crate) physical_wire_index: u32,
    pub(crate) is_inverted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15RoundKind {
    SourceDeliveryAndCoinCommitment,
    DeliveryReceiptRoot,
    CoinOpening,
    BatchedSharingCheck,
    TripleProductOpening,
    MultiplicationLayer { layer_index: u16 },
    PreparationOutputOpening,
    PreparationTerminalWitness,
    TargetFinality,
    ActivationAndTableOpening,
    ActiveKeyOpening,
    EvaluationClaim,
    ResultTerminalWitness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15RoundParticipation {
    CompleteRoster,
    StateWitnessQuorum,
    FinalityQuorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15Round {
    pub(crate) round_index: u16,
    pub(crate) kind: Lpsy15RoundKind,
    pub(crate) participation: Lpsy15RoundParticipation,
    pub(crate) private_field_elements_per_participant: u64,
    pub(crate) public_field_elements_per_participant: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15CandidateStreamKind {
    PrivateSourceDelivery,
    PublicRound(Lpsy15RoundKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15CandidateStream {
    pub(crate) kind: Lpsy15CandidateStreamKind,
    pub(crate) round_index: u16,
    pub(crate) sender_position: u16,
    pub(crate) recipient_position: Option<u16>,
    pub(crate) field_element_count: u64,
    pub(crate) control_payload_byte_length: u64,
    pub(crate) payload_byte_length: u64,
    pub(crate) maximum_payload_chunk_byte_length: u64,
    pub(crate) chunk_count: u64,
    pub(crate) header_byte_length: u64,
    pub(crate) manifest_byte_length: u64,
    pub(crate) signature_envelope_byte_length: u64,
    pub(crate) authentication_tag_byte_length: u64,
    pub(crate) carrier_byte_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15StateIntentKind {
    PreparationRound,
    PreparationTerminal,
    TargetFinality,
    EvaluationRound,
    ResultTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15StatePredecessorKind {
    PreparationAttempt,
    PreviousRound,
    PreparationAndSelectedSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15StateIntent {
    pub(crate) round_index: u16,
    pub(crate) round_kind: Lpsy15RoundKind,
    pub(crate) kind: Lpsy15StateIntentKind,
    pub(crate) predecessor_kind: Lpsy15StatePredecessorKind,
    pub(crate) predecessor_count: u64,
    pub(crate) sender_stream_identity_count: u64,
    pub(crate) round_root_body_byte_length: u64,
    pub(crate) permits_clear_output_material: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15CandidatePathKind {
    Success,
    AllAbstention,
    Withholding { affected_round_index: u16 },
    UnauthenticatedMalformed { affected_round_index: u16 },
    AuthenticatedInconsistency { affected_round_index: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15CandidatePathTerminal {
    Result,
    NoResult,
    Pending,
    Burn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15CandidatePath {
    pub(crate) kind: Lpsy15CandidatePathKind,
    pub(crate) terminal: Lpsy15CandidatePathTerminal,
    pub(crate) verified_prefix_stream_count: u64,
    pub(crate) downloaded_carrier_byte_length: u64,
    pub(crate) verified_prefix_carrier_byte_length: u64,
    pub(crate) additional_terminal_stream_count: u64,
    pub(crate) additional_terminal_carrier_byte_length: u64,
}

impl Lpsy15CandidateStream {
    pub(crate) const fn is_private(self) -> bool {
        matches!(self.kind, Lpsy15CandidateStreamKind::PrivateSourceDelivery)
    }

    pub(crate) const fn signature_count(self) -> u64 {
        1
    }

    pub(crate) const fn encapsulation_count(self) -> u64 {
        if self.is_private() { 1 } else { 0 }
    }

    pub(crate) const fn authenticated_encryption_count(self) -> u64 {
        if self.is_private() {
            self.chunk_count
        } else {
            0
        }
    }

    pub(crate) const fn identity_hash_count(self) -> u64 {
        // Header identity, every ordered chunk digest, and manifest identity.
        self.chunk_count + 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lpsy15CandidateResourceLedger {
    pub(crate) participant_count: u64,
    pub(crate) corruption_bound: u64,
    pub(crate) sharing_degree: u64,
    pub(crate) product_sharing_degree: u64,
    pub(crate) security_bit_length: u64,
    pub(crate) prime_field_element_byte_length: u64,
    pub(crate) logical_wire_count: u64,
    pub(crate) physical_wire_count: u64,
    pub(crate) ballot_input_wire_count: u64,
    pub(crate) fixed_false_source_count: u64,
    pub(crate) conjunction_gate_count: u64,
    pub(crate) exclusive_or_gate_count: u64,
    pub(crate) eliminated_negation_count: u64,
    pub(crate) binary_gate_count: u64,
    pub(crate) logical_output_bit_count: u64,
    pub(crate) unique_output_physical_wire_count: u64,
    pub(crate) mask_random_bit_count_per_participant: u64,
    pub(crate) independent_field_sample_count_per_participant: u64,
    pub(crate) complete_independent_field_sample_count: u64,
    pub(crate) field_sampling_statistical_numerator: u64,
    pub(crate) randomness_xof_message_byte_length: u64,
    pub(crate) randomness_xof_output_byte_length_per_participant: u64,
    pub(crate) randomness_xof_rate_block_count_per_participant: u64,
    pub(crate) randomness_xof_permutation_count_per_participant: u64,
    pub(crate) degree_three_polynomial_count_per_participant: u64,
    pub(crate) degree_six_polynomial_count_per_participant: u64,
    pub(crate) polynomial_evaluation_multiplication_count_per_participant: u64,
    pub(crate) polynomial_evaluation_addition_count_per_participant: u64,
    pub(crate) source_extraction_multiplication_count_per_participant: u64,
    pub(crate) source_extraction_addition_count_per_participant: u64,
    pub(crate) sharing_check_multiplication_count_per_participant: u64,
    pub(crate) sharing_check_addition_count_per_participant: u64,
    pub(crate) degree_three_codeword_check_count_per_participant: u64,
    pub(crate) degree_six_codeword_check_count_per_participant: u64,
    pub(crate) codeword_check_multiplication_count_per_participant: u64,
    pub(crate) codeword_check_addition_count_per_participant: u64,
    pub(crate) triple_generation_multiplication_count_per_participant: u64,
    pub(crate) triple_generation_addition_count_per_participant: u64,
    pub(crate) beaver_evaluation_multiplication_count_per_participant: u64,
    pub(crate) beaver_evaluation_addition_count_per_participant: u64,
    pub(crate) garbling_affine_addition_count_per_participant: u64,
    pub(crate) mask_conversion_constant_multiplication_count_per_participant: u64,
    pub(crate) online_evaluation_addition_count_per_participant: u64,
    pub(crate) complete_field_multiplication_count_per_participant: u64,
    pub(crate) complete_field_addition_count_per_participant: u64,
    pub(crate) paper_gate_multiplication_count: u64,
    pub(crate) mask_generation_multiplication_count: u64,
    pub(crate) source_bound_activation_addition_count: u64,
    pub(crate) total_multiplication_count: u64,
    pub(crate) multiplication_count_by_layer: Vec<u64>,
    pub(crate) prf_output_input_count_per_participant: u64,
    pub(crate) complete_prf_output_input_count: u64,
    pub(crate) online_prf_call_count_per_participant: u64,
    pub(crate) complete_online_prf_call_count: u64,
    pub(crate) prf_message_byte_length: u64,
    pub(crate) prf_kmac_permutation_count_per_call: u64,
    pub(crate) complete_prf_call_count_per_participant: u64,
    pub(crate) complete_prf_kmac_permutation_count_per_participant: u64,
    pub(crate) table_field_element_count: u64,
    pub(crate) paper_style_raw_table_byte_length: u64,
    pub(crate) canonical_table_byte_length: u64,
    pub(crate) private_mpc_input_count: u64,
    pub(crate) random_source_polynomial_count_per_participant: u64,
    pub(crate) double_source_pair_count_per_participant: u64,
    pub(crate) sharing_check_mask_polynomial_count: u64,
    pub(crate) source_polynomial_count: u64,
    pub(crate) total_polynomial_count: u64,
    pub(crate) remote_private_share_field_element_count: u64,
    pub(crate) remote_private_share_payload_byte_length: u64,
    pub(crate) public_opening_field_element_count: u64,
    pub(crate) public_opening_payload_byte_length: u64,
    pub(crate) active_key_opening_field_element_count: u64,
    pub(crate) raw_upload_payload_byte_length: u64,
    pub(crate) private_stream_count: u64,
    pub(crate) public_stream_count: u64,
    pub(crate) network_signature_count: u64,
    pub(crate) encapsulation_count: u64,
    pub(crate) authenticated_encryption_count: u64,
    pub(crate) stream_identity_hash_count: u64,
    pub(crate) private_stream_carrier_byte_length: u64,
    pub(crate) public_stream_carrier_byte_length: u64,
    pub(crate) complete_upload_carrier_byte_length: u64,
    pub(crate) maximum_canonical_stream_byte_length: u64,
    pub(crate) maximum_participant_upload_carrier_byte_length: u64,
    pub(crate) clean_state_participant_download_carrier_byte_length: u64,
    pub(crate) evaluation_success_claim_byte_length: u64,
    pub(crate) authenticated_failure_claim_byte_length: u64,
    pub(crate) round_root_derivation_count: u64,
    pub(crate) burn_terminal_stream_count: u64,
    pub(crate) burn_terminal_carrier_byte_length: u64,
    pub(crate) maximum_authenticated_failure_path_carrier_byte_length: u64,
    pub(crate) paper_round_reconciliation_count: u64,
    pub(crate) preparation_complete_roster_round_count: u64,
    pub(crate) online_complete_roster_round_count: u64,
    pub(crate) minimum_dependency_separated_visit_count: u64,
    pub(crate) maximum_dependency_separated_visit_count: u64,
    pub(crate) maximum_live_active_wire_count: u64,
    pub(crate) maximum_live_active_key_byte_length: u64,
    pub(crate) field_work_batch_element_count: u64,
    pub(crate) maximum_field_work_batch_byte_length: u64,
    pub(crate) participant_share_state_byte_length: u64,
    pub(crate) participant_source_staging_byte_length: u64,
    pub(crate) participant_share_checkpoint_storage_byte_length: u64,
    pub(crate) participant_source_checkpoint_storage_byte_length: u64,
    pub(crate) retained_transcript_with_cleanup_lag_byte_length: u64,
    pub(crate) persistent_storage_with_repair_and_cleanup_lag_byte_length: u64,
    pub(crate) maximum_contiguous_allocation_byte_length: u64,
    pub(crate) maximum_wasm_data_live_set_byte_length: u64,
    pub(crate) maximum_javascript_data_live_set_byte_length: u64,
    pub(crate) maximum_browser_process_data_live_set_byte_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lpsy15CheckpointStateKind {
    SourceStaging,
    ParticipantShareState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lpsy15CheckpointStorageIntent {
    pub(crate) kind: Lpsy15CheckpointStateKind,
    pub(crate) state_byte_length: u64,
    pub(crate) state_chunk_count: u64,
    pub(crate) cursor_byte_length: u64,
    pub(crate) stream_descriptor_byte_length: u64,
    pub(crate) canonical_manifest_byte_length: u64,
    pub(crate) maximum_journal_byte_length: u64,
    pub(crate) configured_manifest_limit_byte_length: u64,
    pub(crate) copy_on_write_stored_value_byte_length: u64,
    pub(crate) repair_head_overlap_byte_length: u64,
    pub(crate) complete_storage_byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lpsy15CandidateCompilation {
    profile: TallyCircuitProfile,
    logical_wire_roles: Vec<Lpsy15LogicalWireRole>,
    physical_wire_roles: Vec<Lpsy15PhysicalWireRole>,
    gate_roles: Vec<Lpsy15GateRole>,
    output_roles: Vec<Lpsy15OutputRole>,
    rounds: Vec<Lpsy15Round>,
    streams: Vec<Lpsy15CandidateStream>,
    state_intents: Vec<Lpsy15StateIntent>,
    candidate_paths: Vec<Lpsy15CandidatePath>,
    checkpoint_storage_intents: [Lpsy15CheckpointStorageIntent; 2],
    resource_ledger: Lpsy15CandidateResourceLedger,
}

impl Lpsy15CandidateCompilation {
    pub(crate) fn compile(
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, Lpsy15CandidateCompilerError> {
        let profile = circuit.profile();
        let participant_count = u64::from(profile.participant_count());
        let roster_parameters = derive_foundation_roster_parameters(profile.participant_count())
            .ok_or(Lpsy15CandidateCompilerError::IntegerConversion)?;
        let corruption_bound = u64::from(roster_parameters.active_fault_bound);
        let extraction_width = participant_count
            .checked_sub(corruption_bound)
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;

        let ballot_input_wire_count = u64_from_usize(circuit.geometry().input_bit_count)?;
        let mut logical_wire_roles = Vec::with_capacity(circuit.geometry().total_wire_count);
        let mut physical_wire_roles = Vec::new();
        for logical_wire_position in 0..circuit.geometry().input_bit_count {
            let logical_wire_index = wire_index_from_usize(logical_wire_position)?;
            let physical_wire_index = u32_from_usize(physical_wire_roles.len())?;
            let input_role = ballot_input_role(circuit, logical_wire_position)?;
            physical_wire_roles.push(Lpsy15PhysicalWireRole {
                wire_index: physical_wire_index,
                source: Lpsy15PhysicalWireSource::BallotInput(input_role),
            });
            logical_wire_roles.push(Lpsy15LogicalWireRole {
                logical_wire_index,
                physical_wire_index,
                is_inverted: false,
            });
        }

        let mut fixed_false_physical_wire = None;
        let mut gate_roles = Vec::new();
        for (operation_position, operation) in circuit.operations().iter().enumerate() {
            let logical_wire_position = circuit
                .geometry()
                .input_bit_count
                .checked_add(operation_position)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
            let logical_wire_index = wire_index_from_usize(logical_wire_position)?;
            let logical_role = match operation {
                BooleanOperation::Constant(value) => {
                    let physical_wire_index = if let Some(wire_index) = fixed_false_physical_wire {
                        wire_index
                    } else {
                        let wire_index = u32_from_usize(physical_wire_roles.len())?;
                        physical_wire_roles.push(Lpsy15PhysicalWireRole {
                            wire_index,
                            source: Lpsy15PhysicalWireSource::FixedFalse,
                        });
                        fixed_false_physical_wire = Some(wire_index);
                        wire_index
                    };
                    Lpsy15LogicalWireRole {
                        logical_wire_index,
                        physical_wire_index,
                        is_inverted: *value,
                    }
                }
                BooleanOperation::Negation { input_wire } => {
                    let input_role = logical_role(&logical_wire_roles, *input_wire)?;
                    Lpsy15LogicalWireRole {
                        logical_wire_index,
                        physical_wire_index: input_role.physical_wire_index,
                        is_inverted: !input_role.is_inverted,
                    }
                }
                BooleanOperation::ExclusiveOr {
                    left_wire,
                    right_wire,
                } => {
                    let left_role = logical_role(&logical_wire_roles, *left_wire)?;
                    let right_role = logical_role(&logical_wire_roles, *right_wire)?;
                    let gate_index = u32_from_usize(gate_roles.len())?;
                    let physical_output_wire_index = u32_from_usize(physical_wire_roles.len())?;
                    gate_roles.push(Lpsy15GateRole {
                        gate_index,
                        logical_output_wire_index: logical_wire_index,
                        physical_output_wire_index,
                        left_physical_wire_index: left_role.physical_wire_index,
                        right_physical_wire_index: right_role.physical_wire_index,
                        kind: Lpsy15GateKind::ExclusiveOr,
                    });
                    physical_wire_roles.push(Lpsy15PhysicalWireRole {
                        wire_index: physical_output_wire_index,
                        source: Lpsy15PhysicalWireSource::GateOutput { gate_index },
                    });
                    Lpsy15LogicalWireRole {
                        logical_wire_index,
                        physical_wire_index: physical_output_wire_index,
                        is_inverted: left_role.is_inverted ^ right_role.is_inverted,
                    }
                }
                BooleanOperation::Conjunction {
                    left_wire,
                    right_wire,
                } => {
                    let left_role = logical_role(&logical_wire_roles, *left_wire)?;
                    let right_role = logical_role(&logical_wire_roles, *right_wire)?;
                    let gate_index = u32_from_usize(gate_roles.len())?;
                    let physical_output_wire_index = u32_from_usize(physical_wire_roles.len())?;
                    gate_roles.push(Lpsy15GateRole {
                        gate_index,
                        logical_output_wire_index: logical_wire_index,
                        physical_output_wire_index,
                        left_physical_wire_index: left_role.physical_wire_index,
                        right_physical_wire_index: right_role.physical_wire_index,
                        kind: Lpsy15GateKind::Nonlinear {
                            truth_table: conjunction_truth_table(
                                left_role.is_inverted,
                                right_role.is_inverted,
                            ),
                        },
                    });
                    physical_wire_roles.push(Lpsy15PhysicalWireRole {
                        wire_index: physical_output_wire_index,
                        source: Lpsy15PhysicalWireSource::GateOutput { gate_index },
                    });
                    Lpsy15LogicalWireRole {
                        logical_wire_index,
                        physical_wire_index: physical_output_wire_index,
                        is_inverted: false,
                    }
                }
            };
            logical_wire_roles.push(logical_role);
        }

        if fixed_false_physical_wire.is_none() {
            return Err(Lpsy15CandidateCompilerError::MissingFixedConstantSource);
        }

        let output_roles = output_roles(circuit, &logical_wire_roles)?;
        let unique_output_physical_wire_count = u64_from_usize(
            output_roles
                .iter()
                .map(|role| role.physical_wire_index)
                .collect::<BTreeSet<_>>()
                .len(),
        )?;
        let logical_wire_count = u64_from_usize(logical_wire_roles.len())?;
        let physical_wire_count = u64_from_usize(physical_wire_roles.len())?;
        let conjunction_gate_count = u64_from_usize(
            gate_roles
                .iter()
                .filter(|gate| matches!(gate.kind, Lpsy15GateKind::Nonlinear { .. }))
                .count(),
        )?;
        let exclusive_or_gate_count = u64_from_usize(
            gate_roles
                .iter()
                .filter(|gate| matches!(gate.kind, Lpsy15GateKind::ExclusiveOr))
                .count(),
        )?;
        let eliminated_negation_count = u64_from_usize(circuit.geometry().negation_gate_count)?;
        let binary_gate_count = checked_add(conjunction_gate_count, exclusive_or_gate_count)?;
        let logical_output_bit_count = u64_from_usize(output_roles.len())?;
        let garbling_affine_addition_count_per_participant =
            garbling_affine_addition_count(&gate_roles, participant_count)?;
        let maximum_live_active_wire_count =
            maximum_live_active_wire_count(&physical_wire_roles, &gate_roles, &output_roles)?;
        let maximum_live_active_key_byte_length = checked_multiply(
            checked_multiply(maximum_live_active_wire_count, participant_count)?,
            PRIME_FIELD_ARITHMETIC_BYTE_LENGTH,
        )?;

        let paper_gate_multiplication_count = checked_add(
            checked_multiply(
                conjunction_gate_count,
                checked_add(checked_multiply(4, participant_count)?, 5)?,
            )?,
            checked_multiply(
                exclusive_or_gate_count,
                checked_add(checked_multiply(2, participant_count)?, 3)?,
            )?,
        )?;
        let mask_generation_multiplication_count =
            checked_multiply(physical_wire_count, participant_count)?;
        // Source-authenticated ballot shares are added to the corresponding
        // wire-mask sharings and opened only after target finality. This is an
        // affine activation, not one multiplication per ballot bit.
        let source_bound_activation_addition_count = ballot_input_wire_count;
        let total_multiplication_count = checked_add(
            paper_gate_multiplication_count,
            mask_generation_multiplication_count,
        )?;
        let mut multiplication_count_by_layer = Vec::new();
        let mut remaining_mask_factors = participant_count;
        while remaining_mask_factors > 1 {
            multiplication_count_by_layer.push(checked_multiply(
                physical_wire_count,
                remaining_mask_factors / 2,
            )?);
            remaining_mask_factors = checked_ceiling_divide(remaining_mask_factors, 2)?;
        }
        multiplication_count_by_layer.extend([
            checked_add(physical_wire_count, binary_gate_count)?,
            checked_add(
                checked_multiply(conjunction_gate_count, 4)?,
                checked_multiply(exclusive_or_gate_count, 2)?,
            )?,
            checked_add(
                checked_multiply(
                    checked_multiply(conjunction_gate_count, 4)?,
                    participant_count,
                )?,
                checked_multiply(
                    checked_multiply(exclusive_or_gate_count, 2)?,
                    participant_count,
                )?,
            )?,
        ]);
        if checked_sum(&multiplication_count_by_layer)?
            != checked_add(
                paper_gate_multiplication_count,
                mask_generation_multiplication_count,
            )?
        {
            return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
        }

        let prf_output_input_count_per_participant = checked_multiply(
            checked_multiply(
                checked_multiply(
                    checked_multiply(INPUT_WIRE_ROLE_COUNT_PER_GATE, KEY_ALTERNATIVE_COUNT)?,
                    PRF_BRANCH_COUNT,
                )?,
                binary_gate_count,
            )?,
            participant_count,
        )?;
        let complete_prf_output_input_count =
            checked_multiply(prf_output_input_count_per_participant, participant_count)?;
        let online_prf_call_count_per_participant = checked_multiply(
            checked_multiply(
                checked_multiply(INPUT_WIRE_ROLE_COUNT_PER_GATE, participant_count)?,
                participant_count,
            )?,
            binary_gate_count,
        )?;
        let complete_online_prf_call_count =
            checked_multiply(online_prf_call_count_per_participant, participant_count)?;
        let prf_message_byte_length = lpsy15_prf_message_byte_length()?;
        let prf_kmac_permutation_count_per_call =
            lpsy15_prf_kmac_permutation_count(prf_message_byte_length)?;
        let complete_prf_call_count_per_participant = checked_add(
            prf_output_input_count_per_participant,
            online_prf_call_count_per_participant,
        )?;
        let complete_prf_kmac_permutation_count_per_participant = checked_multiply(
            complete_prf_call_count_per_participant,
            prf_kmac_permutation_count_per_call,
        )?;
        let table_field_element_count = checked_multiply(
            checked_multiply(TABLE_ROW_COUNT, binary_gate_count)?,
            participant_count,
        )?;
        let paper_style_raw_table_byte_length =
            checked_multiply(table_field_element_count, SECURITY_BIT_LENGTH / 8)?;
        let canonical_table_byte_length =
            checked_multiply(table_field_element_count, PRIME_FIELD_ELEMENT_BYTE_LENGTH)?;

        let mask_input_count = checked_multiply(physical_wire_count, participant_count)?;
        let key_input_count = checked_multiply(
            checked_multiply(KEY_ALTERNATIVE_COUNT, physical_wire_count)?,
            participant_count,
        )?;
        let private_mpc_input_count = checked_sum(&[
            mask_input_count,
            key_input_count,
            complete_prf_output_input_count,
        ])?;
        let private_mpc_input_count_per_participant = private_mpc_input_count
            .checked_div(participant_count)
            .filter(|_| private_mpc_input_count.is_multiple_of(participant_count))
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let random_source_polynomial_count_per_participant = checked_ceiling_divide(
            checked_multiply(2, total_multiplication_count)?,
            extraction_width,
        )?;
        let double_source_pair_count_per_participant =
            checked_ceiling_divide(total_multiplication_count, extraction_width)?;
        let extracted_source_polynomial_count = checked_multiply(
            participant_count,
            checked_add(
                random_source_polynomial_count_per_participant,
                checked_multiply(2, double_source_pair_count_per_participant)?,
            )?,
        )?;
        // Each dealer has one degree-three mask for the combined ordinary
        // sharing check and one matched degree-three/degree-six mask pair for
        // the double-sharing check. The checks share one post-root coin but
        // retain separate masked openings, so cross-dealer cancellation is
        // impossible.
        let sharing_check_mask_polynomial_count = checked_multiply(participant_count, 3)?;
        let source_polynomial_count = checked_add(
            extracted_source_polynomial_count,
            sharing_check_mask_polynomial_count,
        )?;
        let total_polynomial_count = checked_add(private_mpc_input_count, source_polynomial_count)?;
        let degree_three_polynomial_count_per_participant = checked_sum(&[
            private_mpc_input_count_per_participant,
            random_source_polynomial_count_per_participant,
            double_source_pair_count_per_participant,
            2,
        ])?;
        let degree_six_polynomial_count_per_participant =
            checked_add(double_source_pair_count_per_participant, 1)?;
        if checked_multiply(
            checked_add(
                degree_three_polynomial_count_per_participant,
                degree_six_polynomial_count_per_participant,
            )?,
            participant_count,
        )? != total_polynomial_count
        {
            return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
        }

        let private_input_coefficient_sample_count =
            checked_multiply(SHARING_DEGREE, private_mpc_input_count_per_participant)?;
        let random_source_sample_count = checked_multiply(
            SHARING_DEGREE + 1,
            random_source_polynomial_count_per_participant,
        )?;
        let double_source_sample_count = checked_multiply(
            1 + SHARING_DEGREE + PRODUCT_SHARING_DEGREE,
            double_source_pair_count_per_participant,
        )?;
        let sharing_check_mask_sample_count =
            (SHARING_DEGREE + 1) + (1 + SHARING_DEGREE + PRODUCT_SHARING_DEGREE);
        let key_sample_count = checked_multiply(KEY_ALTERNATIVE_COUNT, physical_wire_count)?;
        let independent_field_sample_count_per_participant = checked_sum(&[
            private_input_coefficient_sample_count,
            random_source_sample_count,
            double_source_sample_count,
            sharing_check_mask_sample_count,
            key_sample_count,
        ])?;
        let complete_independent_field_sample_count = checked_multiply(
            independent_field_sample_count_per_participant,
            participant_count,
        )?;
        let field_sampling_statistical_numerator = checked_multiply(
            complete_independent_field_sample_count,
            PRIME_FIELD_MODULUS_EXCESS,
        )?;
        let mask_random_bit_count_per_participant = physical_wire_count;
        let mask_random_byte_length_per_participant =
            checked_ceiling_divide(mask_random_bit_count_per_participant, 8)?;
        let randomness_xof_output_byte_length_per_participant = checked_add(
            checked_multiply(
                independent_field_sample_count_per_participant,
                PRIME_FIELD_SAMPLE_BYTE_LENGTH,
            )?,
            mask_random_byte_length_per_participant,
        )?;
        let randomness_xof_message_byte_length = randomness_xof_message_byte_length()?;
        let randomness_xof_rate_block_count_per_participant = checked_ceiling_divide(
            randomness_xof_output_byte_length_per_participant,
            SHAKE256_RATE_BYTE_LENGTH,
        )?;
        let randomness_xof_absorb_block_count = checked_add(
            randomness_xof_message_byte_length / SHAKE256_RATE_BYTE_LENGTH,
            1,
        )?;
        let randomness_xof_permutation_count_per_participant = checked_add(
            randomness_xof_absorb_block_count,
            randomness_xof_rate_block_count_per_participant,
        )?
        .checked_sub(1)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;

        let polynomial_evaluation_multiplication_count_per_participant = checked_multiply(
            participant_count,
            checked_add(
                checked_multiply(
                    SHARING_DEGREE,
                    degree_three_polynomial_count_per_participant,
                )?,
                checked_multiply(
                    PRODUCT_SHARING_DEGREE,
                    degree_six_polynomial_count_per_participant,
                )?,
            )?,
        )?;
        let polynomial_evaluation_addition_count_per_participant =
            polynomial_evaluation_multiplication_count_per_participant;
        let source_extraction_multiplication_count_per_participant = checked_multiply(
            checked_multiply(total_multiplication_count, 4)?,
            participant_count,
        )?;
        let source_extraction_addition_count_per_participant = checked_multiply(
            checked_multiply(total_multiplication_count, 4)?,
            participant_count
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )?;
        let sharing_check_multiplication_count_per_participant = checked_sum(&[
            checked_multiply(
                participant_count,
                private_mpc_input_count_per_participant
                    .checked_add(random_source_polynomial_count_per_participant)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?
                    .checked_sub(1)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            )?,
            checked_multiply(
                checked_multiply(2, participant_count)?,
                double_source_pair_count_per_participant
                    .checked_sub(1)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            )?,
            private_mpc_input_count_per_participant
                .checked_add(random_source_polynomial_count_per_participant)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        ])?;
        let sharing_check_addition_count_per_participant = checked_add(
            checked_multiply(
                participant_count,
                private_mpc_input_count_per_participant
                    .checked_add(random_source_polynomial_count_per_participant)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            )?,
            checked_multiply(
                checked_multiply(2, participant_count)?,
                double_source_pair_count_per_participant,
            )?,
        )?;
        let remote_private_share_field_element_count = checked_multiply(
            total_polynomial_count,
            participant_count
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )?;
        let remote_private_share_payload_byte_length = checked_multiply(
            remote_private_share_field_element_count,
            PRIME_FIELD_ELEMENT_BYTE_LENGTH,
        )?;

        // For each dealer, the roster publishes one combined degree-three
        // codeword and one matched degree-three/degree-six pair. A dealer echo
        // vector is useful only for dispute attribution and retry, neither of
        // which exists in this one-shot accepted-or-burn mapping.
        let batch_check_field_element_count =
            checked_multiply(checked_multiply(participant_count, participant_count)?, 3)?;
        let triple_product_opening_field_element_count =
            checked_multiply(total_multiplication_count, participant_count)?;
        let multiplication_opening_field_element_count = checked_multiply(
            checked_multiply(2, total_multiplication_count)?,
            participant_count,
        )?;
        let mask_check_opening_field_element_count =
            checked_multiply(physical_wire_count, participant_count)?;
        let table_opening_field_element_count =
            checked_multiply(table_field_element_count, participant_count)?;
        let output_mask_opening_field_element_count =
            checked_multiply(unique_output_physical_wire_count, participant_count)?;
        let activated_signal_opening_field_element_count = checked_multiply(
            checked_add(ballot_input_wire_count, FIXED_FALSE_SOURCE_COUNT)?,
            participant_count,
        )?;
        let active_key_opening_field_element_count = checked_multiply(
            checked_add(ballot_input_wire_count, FIXED_FALSE_SOURCE_COUNT)?,
            checked_multiply(participant_count, participant_count)?,
        )?;
        let degree_three_codeword_check_count_per_participant = checked_sum(&[
            checked_multiply(2, total_multiplication_count)?,
            physical_wire_count,
            table_field_element_count,
            unique_output_physical_wire_count,
            checked_add(ballot_input_wire_count, FIXED_FALSE_SOURCE_COUNT)?,
            active_key_opening_field_element_count
                .checked_div(participant_count)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            checked_multiply(participant_count, 2)?,
        ])?;
        let degree_six_codeword_check_count_per_participant =
            checked_add(total_multiplication_count, participant_count)?;
        let degree_three_codeword_check_multiplication_count =
            exact_codeword_check_multiplication_count(participant_count, SHARING_DEGREE)?;
        let degree_six_codeword_check_multiplication_count =
            exact_codeword_check_multiplication_count(participant_count, PRODUCT_SHARING_DEGREE)?;
        let degree_three_codeword_check_addition_count =
            exact_codeword_check_addition_count(participant_count, SHARING_DEGREE)?;
        let degree_six_codeword_check_addition_count =
            exact_codeword_check_addition_count(participant_count, PRODUCT_SHARING_DEGREE)?;
        let codeword_check_multiplication_count_per_participant = checked_add(
            checked_multiply(
                degree_three_codeword_check_count_per_participant,
                degree_three_codeword_check_multiplication_count,
            )?,
            checked_multiply(
                degree_six_codeword_check_count_per_participant,
                degree_six_codeword_check_multiplication_count,
            )?,
        )?;
        let codeword_check_addition_count_per_participant = checked_add(
            checked_multiply(
                degree_three_codeword_check_count_per_participant,
                degree_three_codeword_check_addition_count,
            )?,
            checked_multiply(
                degree_six_codeword_check_count_per_participant,
                degree_six_codeword_check_addition_count,
            )?,
        )?;
        let triple_generation_multiplication_count_per_participant = total_multiplication_count;
        let triple_generation_addition_count_per_participant =
            checked_multiply(2, total_multiplication_count)?;
        let beaver_evaluation_multiplication_count_per_participant =
            checked_multiply(3, total_multiplication_count)?;
        let beaver_evaluation_addition_count_per_participant =
            checked_multiply(5, total_multiplication_count)?;
        let mask_conversion_constant_multiplication_count_per_participant = physical_wire_count;
        let mask_conversion_addition_count_per_participant =
            checked_multiply(2, physical_wire_count)?;
        let online_evaluation_addition_count_per_participant =
            online_prf_call_count_per_participant;
        let complete_field_multiplication_count_per_participant = checked_sum(&[
            polynomial_evaluation_multiplication_count_per_participant,
            source_extraction_multiplication_count_per_participant,
            sharing_check_multiplication_count_per_participant,
            triple_generation_multiplication_count_per_participant,
            beaver_evaluation_multiplication_count_per_participant,
            codeword_check_multiplication_count_per_participant,
            mask_conversion_constant_multiplication_count_per_participant,
        ])?;
        let complete_field_addition_count_per_participant = checked_sum(&[
            polynomial_evaluation_addition_count_per_participant,
            source_extraction_addition_count_per_participant,
            sharing_check_addition_count_per_participant,
            triple_generation_addition_count_per_participant,
            beaver_evaluation_addition_count_per_participant,
            codeword_check_addition_count_per_participant,
            mask_conversion_addition_count_per_participant,
            garbling_affine_addition_count_per_participant,
            source_bound_activation_addition_count,
            online_evaluation_addition_count_per_participant,
        ])?;
        let public_opening_field_element_count = checked_sum(&[
            batch_check_field_element_count,
            triple_product_opening_field_element_count,
            multiplication_opening_field_element_count,
            mask_check_opening_field_element_count,
            table_opening_field_element_count,
            output_mask_opening_field_element_count,
            activated_signal_opening_field_element_count,
            active_key_opening_field_element_count,
        ])?;
        let public_opening_payload_byte_length = checked_multiply(
            public_opening_field_element_count,
            PRIME_FIELD_ELEMENT_BYTE_LENGTH,
        )?;
        let raw_upload_payload_byte_length = checked_add(
            remote_private_share_payload_byte_length,
            public_opening_payload_byte_length,
        )?;

        let rounds = compile_rounds(Lpsy15RoundCompilerInputs {
            participant_count,
            ballot_input_wire_count,
            physical_wire_count,
            unique_output_physical_wire_count,
            table_field_element_count,
            total_polynomial_count,
            total_multiplication_count,
            multiplication_count_by_layer: &multiplication_count_by_layer,
        })?;
        let preparation_complete_roster_round_count = u64_from_usize(
            rounds
                .iter()
                .filter(|round| {
                    matches!(
                        round.kind,
                        Lpsy15RoundKind::SourceDeliveryAndCoinCommitment
                            | Lpsy15RoundKind::DeliveryReceiptRoot
                            | Lpsy15RoundKind::CoinOpening
                            | Lpsy15RoundKind::BatchedSharingCheck
                            | Lpsy15RoundKind::TripleProductOpening
                            | Lpsy15RoundKind::MultiplicationLayer { .. }
                            | Lpsy15RoundKind::PreparationOutputOpening
                    ) && round.participation == Lpsy15RoundParticipation::CompleteRoster
                })
                .count(),
        )?;
        let online_complete_roster_round_count = u64_from_usize(
            rounds
                .iter()
                .filter(|round| {
                    matches!(
                        round.kind,
                        Lpsy15RoundKind::ActivationAndTableOpening
                            | Lpsy15RoundKind::ActiveKeyOpening
                            | Lpsy15RoundKind::EvaluationClaim
                    ) && round.participation == Lpsy15RoundParticipation::CompleteRoster
                })
                .count(),
        )?;
        let witness_quorum = u64::from(roster_parameters.state_witness_quorum);
        let finality_quorum = u64::from(roster_parameters.finality_quorum);
        let minimum_dependency_separated_visit_count =
            minimum_visit_count(&rounds, participant_count, witness_quorum, finality_quorum)?;
        let maximum_dependency_separated_visit_count =
            maximum_visit_count(&rounds, participant_count, witness_quorum, finality_quorum)?;

        let evaluation_success_claim_byte_length =
            evaluation_success_claim_byte_length(profile.top_count())?;
        let authenticated_failure_claim_byte_length = authenticated_failure_claim_byte_length()?;
        let streams = compile_streams(
            &rounds,
            participant_count,
            total_polynomial_count,
            profile.top_count(),
            witness_quorum,
            finality_quorum,
        )?;
        let state_intents = compile_state_intents(&rounds, &streams)?;
        let round_root_derivation_count = u64_from_usize(state_intents.len())?;
        let (burn_terminal_stream_count, burn_terminal_carrier_byte_length) =
            burn_terminal_resources(authenticated_failure_claim_byte_length, witness_quorum)?;
        let candidate_paths = compile_candidate_paths(
            &rounds,
            &streams,
            burn_terminal_stream_count,
            burn_terminal_carrier_byte_length,
        )?;
        let maximum_authenticated_failure_path_carrier_byte_length = candidate_paths
            .iter()
            .filter(|path| {
                matches!(
                    path.kind,
                    Lpsy15CandidatePathKind::AuthenticatedInconsistency { .. }
                )
            })
            .map(|path| path.downloaded_carrier_byte_length)
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let private_streams = streams
            .iter()
            .filter(|stream| stream.is_private())
            .copied()
            .collect::<Vec<_>>();
        let public_streams = streams
            .iter()
            .filter(|stream| !stream.is_private())
            .copied()
            .collect::<Vec<_>>();
        let private_stream_count = u64_from_usize(private_streams.len())?;
        let public_stream_count = u64_from_usize(public_streams.len())?;
        let network_signature_count = checked_sum(
            &streams
                .iter()
                .map(|stream| stream.signature_count())
                .collect::<Vec<_>>(),
        )?;
        let encapsulation_count = checked_sum(
            &streams
                .iter()
                .map(|stream| stream.encapsulation_count())
                .collect::<Vec<_>>(),
        )?;
        let authenticated_encryption_count = checked_sum(
            &streams
                .iter()
                .map(|stream| stream.authenticated_encryption_count())
                .collect::<Vec<_>>(),
        )?;
        let stream_identity_hash_count = checked_sum(
            &streams
                .iter()
                .map(|stream| stream.identity_hash_count())
                .collect::<Vec<_>>(),
        )?;
        let private_stream_carrier_byte_length = stream_carrier_sum(&private_streams)?;
        let public_stream_carrier_byte_length = stream_carrier_sum(&public_streams)?;
        let complete_upload_carrier_byte_length = checked_add(
            private_stream_carrier_byte_length,
            public_stream_carrier_byte_length,
        )?;
        let maximum_canonical_stream_byte_length = streams
            .iter()
            .map(|stream| stream.carrier_byte_length)
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let maximum_participant_upload_carrier_byte_length = (0..participant_count)
            .map(|participant_position| {
                stream_carrier_sum(
                    &streams
                        .iter()
                        .filter(|stream| u64::from(stream.sender_position) == participant_position)
                        .copied()
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let maximum_incoming_private_carrier_byte_length = (0..participant_count)
            .map(|participant_position| {
                stream_carrier_sum(
                    &private_streams
                        .iter()
                        .filter(|stream| {
                            stream.recipient_position.map(u64::from) == Some(participant_position)
                        })
                        .copied()
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let clean_state_participant_download_carrier_byte_length = checked_add(
            public_stream_carrier_byte_length,
            maximum_incoming_private_carrier_byte_length,
        )?;

        let participant_share_state_byte_length =
            checked_multiply(total_polynomial_count, PRIME_FIELD_ELEMENT_BYTE_LENGTH)?;
        let participant_source_staging_byte_length = checked_add(
            checked_multiply(
                checked_add(
                    independent_field_sample_count_per_participant,
                    prf_output_input_count_per_participant,
                )?,
                PRIME_FIELD_ELEMENT_BYTE_LENGTH,
            )?,
            mask_random_byte_length_per_participant,
        )?;
        let source_checkpoint_storage_intent = checkpoint_storage_intent(
            Lpsy15CheckpointStateKind::SourceStaging,
            participant_source_staging_byte_length,
        )?;
        let share_checkpoint_storage_intent = checkpoint_storage_intent(
            Lpsy15CheckpointStateKind::ParticipantShareState,
            participant_share_state_byte_length,
        )?;
        let checkpoint_storage_intents = [
            source_checkpoint_storage_intent,
            share_checkpoint_storage_intent,
        ];
        let participant_source_checkpoint_storage_byte_length =
            source_checkpoint_storage_intent.complete_storage_byte_length;
        let participant_share_checkpoint_storage_byte_length =
            share_checkpoint_storage_intent.complete_storage_byte_length;

        let maximum_outgoing_private_carrier_byte_length =
            maximum_incoming_private_carrier_byte_length;
        let retained_transcript_with_cleanup_lag_byte_length = checked_sum(&[
            public_stream_carrier_byte_length,
            maximum_incoming_private_carrier_byte_length,
            maximum_outgoing_private_carrier_byte_length,
        ])?;
        let transcript_record_count = checked_sum(&[
            storage_record_count(&public_streams)?,
            checked_multiply(
                2,
                storage_record_count(&private_streams)? / participant_count,
            )?,
        ])?;
        let transcript_index_byte_length = checked_multiply(
            transcript_record_count,
            TRANSCRIPT_STORAGE_INDEX_VALUE_BYTE_LENGTH,
        )?;
        let transcript_repair_head_plaintext_byte_length = checked_add(
            AUTHENTICATED_REPAIR_HEAD_FIXED_BYTE_LENGTH,
            checked_multiply(
                transcript_record_count,
                checked_sum(&[
                    AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH,
                    TRANSCRIPT_LOGICAL_RECORD_KEY_BYTE_LENGTH,
                    TRANSCRIPT_STORAGE_OBJECT_KEY_BYTE_LENGTH,
                ])?,
            )?,
        )?;
        let transcript_repair_head_overlap_byte_length = checked_multiply(
            2,
            checked_add(
                transcript_repair_head_plaintext_byte_length,
                RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
            )?,
        )?;
        let persistent_storage_with_repair_and_cleanup_lag_byte_length = checked_sum(&[
            retained_transcript_with_cleanup_lag_byte_length,
            transcript_index_byte_length,
            transcript_repair_head_overlap_byte_length,
            participant_source_checkpoint_storage_byte_length,
            participant_share_checkpoint_storage_byte_length,
        ])?;
        let maximum_field_work_batch_byte_length = checked_multiply(
            checked_multiply(
                participant_count
                    .checked_sub(SHARING_DEGREE)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
                FIELD_WORK_BATCH_ELEMENT_COUNT,
            )?,
            PRIME_FIELD_ARITHMETIC_BYTE_LENGTH,
        )?;
        let maximum_contiguous_allocation_byte_length = std::cmp::max(
            u64_from_usize(FOUNDATION_PROFILE.stream_chunk_byte_length)?,
            maximum_field_work_batch_byte_length,
        );
        let maximum_wasm_data_live_set_byte_length = checked_sum(&[
            checked_multiply(
                2,
                u64_from_usize(FOUNDATION_PROFILE.stream_chunk_byte_length)?,
            )?,
            maximum_field_work_batch_byte_length,
            maximum_live_active_key_byte_length,
        ])?;
        let maximum_checkpoint_manifest_byte_length = checkpoint_storage_intents
            .iter()
            .map(|intent| intent.configured_manifest_limit_byte_length)
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let maximum_javascript_data_live_set_byte_length = checked_add(
            checked_multiply(
                2,
                u64_from_usize(FOUNDATION_PROFILE.stream_chunk_byte_length)?,
            )?,
            maximum_checkpoint_manifest_byte_length,
        )?;
        let maximum_browser_process_data_live_set_byte_length = checked_add(
            maximum_wasm_data_live_set_byte_length,
            maximum_javascript_data_live_set_byte_length,
        )?;

        let resource_ledger = Lpsy15CandidateResourceLedger {
            participant_count,
            corruption_bound,
            sharing_degree: SHARING_DEGREE,
            product_sharing_degree: PRODUCT_SHARING_DEGREE,
            security_bit_length: SECURITY_BIT_LENGTH,
            prime_field_element_byte_length: PRIME_FIELD_ELEMENT_BYTE_LENGTH,
            logical_wire_count,
            physical_wire_count,
            ballot_input_wire_count,
            fixed_false_source_count: FIXED_FALSE_SOURCE_COUNT,
            conjunction_gate_count,
            exclusive_or_gate_count,
            eliminated_negation_count,
            binary_gate_count,
            logical_output_bit_count,
            unique_output_physical_wire_count,
            mask_random_bit_count_per_participant,
            independent_field_sample_count_per_participant,
            complete_independent_field_sample_count,
            field_sampling_statistical_numerator,
            randomness_xof_message_byte_length,
            randomness_xof_output_byte_length_per_participant,
            randomness_xof_rate_block_count_per_participant,
            randomness_xof_permutation_count_per_participant,
            degree_three_polynomial_count_per_participant,
            degree_six_polynomial_count_per_participant,
            polynomial_evaluation_multiplication_count_per_participant,
            polynomial_evaluation_addition_count_per_participant,
            source_extraction_multiplication_count_per_participant,
            source_extraction_addition_count_per_participant,
            sharing_check_multiplication_count_per_participant,
            sharing_check_addition_count_per_participant,
            degree_three_codeword_check_count_per_participant,
            degree_six_codeword_check_count_per_participant,
            codeword_check_multiplication_count_per_participant,
            codeword_check_addition_count_per_participant,
            triple_generation_multiplication_count_per_participant,
            triple_generation_addition_count_per_participant,
            beaver_evaluation_multiplication_count_per_participant,
            beaver_evaluation_addition_count_per_participant,
            garbling_affine_addition_count_per_participant,
            mask_conversion_constant_multiplication_count_per_participant,
            online_evaluation_addition_count_per_participant,
            complete_field_multiplication_count_per_participant,
            complete_field_addition_count_per_participant,
            paper_gate_multiplication_count,
            mask_generation_multiplication_count,
            source_bound_activation_addition_count,
            total_multiplication_count,
            multiplication_count_by_layer,
            prf_output_input_count_per_participant,
            complete_prf_output_input_count,
            online_prf_call_count_per_participant,
            complete_online_prf_call_count,
            prf_message_byte_length,
            prf_kmac_permutation_count_per_call,
            complete_prf_call_count_per_participant,
            complete_prf_kmac_permutation_count_per_participant,
            table_field_element_count,
            paper_style_raw_table_byte_length,
            canonical_table_byte_length,
            private_mpc_input_count,
            random_source_polynomial_count_per_participant,
            double_source_pair_count_per_participant,
            sharing_check_mask_polynomial_count,
            source_polynomial_count,
            total_polynomial_count,
            remote_private_share_field_element_count,
            remote_private_share_payload_byte_length,
            public_opening_field_element_count,
            public_opening_payload_byte_length,
            active_key_opening_field_element_count,
            raw_upload_payload_byte_length,
            private_stream_count,
            public_stream_count,
            network_signature_count,
            encapsulation_count,
            authenticated_encryption_count,
            stream_identity_hash_count,
            private_stream_carrier_byte_length,
            public_stream_carrier_byte_length,
            complete_upload_carrier_byte_length,
            maximum_canonical_stream_byte_length,
            maximum_participant_upload_carrier_byte_length,
            clean_state_participant_download_carrier_byte_length,
            evaluation_success_claim_byte_length,
            authenticated_failure_claim_byte_length,
            round_root_derivation_count,
            burn_terminal_stream_count,
            burn_terminal_carrier_byte_length,
            maximum_authenticated_failure_path_carrier_byte_length,
            paper_round_reconciliation_count: PAPER_ROUND_RECONCILIATION_COUNT,
            preparation_complete_roster_round_count,
            online_complete_roster_round_count,
            minimum_dependency_separated_visit_count,
            maximum_dependency_separated_visit_count,
            maximum_live_active_wire_count,
            maximum_live_active_key_byte_length,
            field_work_batch_element_count: FIELD_WORK_BATCH_ELEMENT_COUNT,
            maximum_field_work_batch_byte_length,
            participant_share_state_byte_length,
            participant_source_staging_byte_length,
            participant_share_checkpoint_storage_byte_length,
            participant_source_checkpoint_storage_byte_length,
            retained_transcript_with_cleanup_lag_byte_length,
            persistent_storage_with_repair_and_cleanup_lag_byte_length,
            maximum_contiguous_allocation_byte_length,
            maximum_wasm_data_live_set_byte_length,
            maximum_javascript_data_live_set_byte_length,
            maximum_browser_process_data_live_set_byte_length,
        };

        Ok(Self {
            profile,
            logical_wire_roles,
            physical_wire_roles,
            gate_roles,
            output_roles,
            rounds,
            streams,
            state_intents,
            candidate_paths,
            checkpoint_storage_intents,
            resource_ledger,
        })
    }

    pub(crate) const fn profile(&self) -> TallyCircuitProfile {
        self.profile
    }

    pub(crate) fn logical_wire_roles(&self) -> &[Lpsy15LogicalWireRole] {
        &self.logical_wire_roles
    }

    pub(crate) fn physical_wire_roles(&self) -> &[Lpsy15PhysicalWireRole] {
        &self.physical_wire_roles
    }

    pub(crate) fn gate_roles(&self) -> &[Lpsy15GateRole] {
        &self.gate_roles
    }

    pub(crate) fn output_roles(&self) -> &[Lpsy15OutputRole] {
        &self.output_roles
    }

    pub(crate) fn rounds(&self) -> &[Lpsy15Round] {
        &self.rounds
    }

    pub(crate) fn streams(&self) -> &[Lpsy15CandidateStream] {
        &self.streams
    }

    pub(crate) fn state_intents(&self) -> &[Lpsy15StateIntent] {
        &self.state_intents
    }

    pub(crate) fn candidate_paths(&self) -> &[Lpsy15CandidatePath] {
        &self.candidate_paths
    }

    pub(crate) fn checkpoint_storage_intents(&self) -> &[Lpsy15CheckpointStorageIntent; 2] {
        &self.checkpoint_storage_intents
    }

    pub(crate) fn mask_random_bit_role(
        &self,
        role_ordinal: u64,
    ) -> Option<Lpsy15MaskRandomBitRole> {
        let physical_wire_count = u64::try_from(self.physical_wire_roles.len()).ok()?;
        let role_count =
            physical_wire_count.checked_mul(u64::from(self.profile.participant_count()))?;
        if role_ordinal >= role_count {
            return None;
        }
        Some(Lpsy15MaskRandomBitRole {
            contributor_position: u16::try_from(role_ordinal / physical_wire_count).ok()?,
            physical_wire_index: u32::try_from(role_ordinal % physical_wire_count).ok()?,
        })
    }

    pub(crate) fn field_key_role(&self, role_ordinal: u64) -> Option<Lpsy15FieldKeyRole> {
        let physical_wire_count = u64::try_from(self.physical_wire_roles.len()).ok()?;
        let role_count = physical_wire_count
            .checked_mul(u64::from(self.profile.participant_count()))?
            .checked_mul(KEY_ALTERNATIVE_COUNT)?;
        if role_ordinal >= role_count {
            return None;
        }
        let alternative = role_ordinal % KEY_ALTERNATIVE_COUNT;
        let wire_major_ordinal = role_ordinal / KEY_ALTERNATIVE_COUNT;
        Some(Lpsy15FieldKeyRole {
            owner_position: u16::try_from(wire_major_ordinal / physical_wire_count).ok()?,
            physical_wire_index: u32::try_from(wire_major_ordinal % physical_wire_count).ok()?,
            alternative: alternative == 1,
        })
    }

    pub(crate) fn offline_prf_output_input_role(
        &self,
        role_ordinal: u64,
    ) -> Option<Lpsy15OfflinePrfOutputInputRole> {
        if role_ordinal >= self.resource_ledger.complete_prf_output_input_count {
            return None;
        }
        let participant_count = u64::from(self.profile.participant_count());
        let output_component_position = role_ordinal % participant_count;
        let mut remaining = role_ordinal / participant_count;
        let branch = remaining % PRF_BRANCH_COUNT;
        remaining /= PRF_BRANCH_COUNT;
        let key_alternative = remaining % KEY_ALTERNATIVE_COUNT;
        remaining /= KEY_ALTERNATIVE_COUNT;
        let input_side_ordinal = remaining % INPUT_WIRE_ROLE_COUNT_PER_GATE;
        remaining /= INPUT_WIRE_ROLE_COUNT_PER_GATE;
        let gate_count = u64::try_from(self.gate_roles.len()).ok()?;
        let gate_position = remaining % gate_count;
        let key_owner_position = remaining / gate_count;
        let gate = *self.gate_roles.get(usize::try_from(gate_position).ok()?)?;
        let (input_side, input_physical_wire_index) = if input_side_ordinal == 0 {
            (Lpsy15InputWireSide::Left, gate.left_physical_wire_index)
        } else {
            (Lpsy15InputWireSide::Right, gate.right_physical_wire_index)
        };
        Some(Lpsy15OfflinePrfOutputInputRole {
            key_owner_position: u16::try_from(key_owner_position).ok()?,
            gate_index: gate.gate_index,
            input_side,
            input_physical_wire_index,
            key_alternative: key_alternative == 1,
            branch: branch == 1,
            output_component_position: u16::try_from(output_component_position).ok()?,
        })
    }

    pub(crate) fn online_prf_call_role(
        &self,
        role_ordinal: u64,
    ) -> Option<Lpsy15OnlinePrfCallRole> {
        if role_ordinal >= self.resource_ledger.complete_online_prf_call_count {
            return None;
        }
        let participant_count = u64::from(self.profile.participant_count());
        let output_component_position = role_ordinal % participant_count;
        let mut remaining = role_ordinal / participant_count;
        let key_owner_position = remaining % participant_count;
        remaining /= participant_count;
        let input_side_ordinal = remaining % INPUT_WIRE_ROLE_COUNT_PER_GATE;
        remaining /= INPUT_WIRE_ROLE_COUNT_PER_GATE;
        let gate_count = u64::try_from(self.gate_roles.len()).ok()?;
        let gate_position = remaining % gate_count;
        let evaluator_position = remaining / gate_count;
        let gate = *self.gate_roles.get(usize::try_from(gate_position).ok()?)?;
        let (input_side, input_physical_wire_index) = if input_side_ordinal == 0 {
            (Lpsy15InputWireSide::Left, gate.left_physical_wire_index)
        } else {
            (Lpsy15InputWireSide::Right, gate.right_physical_wire_index)
        };
        Some(Lpsy15OnlinePrfCallRole {
            evaluator_position: u16::try_from(evaluator_position).ok()?,
            gate_index: gate.gate_index,
            input_side,
            input_physical_wire_index,
            key_owner_position: u16::try_from(key_owner_position).ok()?,
            output_component_position: u16::try_from(output_component_position).ok()?,
        })
    }

    pub(crate) fn source_polynomial_role(
        &self,
        role_ordinal: u64,
    ) -> Option<Lpsy15SourcePolynomialRole> {
        if role_ordinal >= self.resource_ledger.total_polynomial_count {
            return None;
        }
        let participant_count = u64::from(self.profile.participant_count());
        let polynomial_count_per_participant = self
            .resource_ledger
            .total_polynomial_count
            .checked_div(participant_count)?;
        let dealer_position = role_ordinal / polynomial_count_per_participant;
        let mut ordinal_within_dealer = role_ordinal % polynomial_count_per_participant;
        let private_input_count_per_participant = self
            .resource_ledger
            .private_mpc_input_count
            .checked_div(participant_count)?;
        let kinds = [
            (
                Lpsy15SourcePolynomialKind::PrivateInput,
                private_input_count_per_participant,
            ),
            (
                Lpsy15SourcePolynomialKind::RandomSource,
                self.resource_ledger
                    .random_source_polynomial_count_per_participant,
            ),
            (
                Lpsy15SourcePolynomialKind::DoubleSourceDegreeThree,
                self.resource_ledger
                    .double_source_pair_count_per_participant,
            ),
            (
                Lpsy15SourcePolynomialKind::DoubleSourceDegreeSix,
                self.resource_ledger
                    .double_source_pair_count_per_participant,
            ),
            (Lpsy15SourcePolynomialKind::OrdinaryCheckMask, 1),
            (Lpsy15SourcePolynomialKind::PairedCheckDegreeThree, 1),
            (Lpsy15SourcePolynomialKind::PairedCheckDegreeSix, 1),
        ];
        for (kind, count) in kinds {
            if ordinal_within_dealer < count {
                return Some(Lpsy15SourcePolynomialRole {
                    dealer_position: u16::try_from(dealer_position).ok()?,
                    kind,
                    ordinal_within_kind: ordinal_within_dealer,
                });
            }
            ordinal_within_dealer = ordinal_within_dealer.checked_sub(count)?;
        }
        None
    }

    pub(crate) fn multiplication_role(
        &self,
        multiplication_ordinal: u64,
    ) -> Option<Lpsy15MultiplicationRole> {
        if multiplication_ordinal >= self.resource_ledger.total_multiplication_count {
            return None;
        }
        let mut remaining = multiplication_ordinal;
        for (layer_position, layer_count) in self
            .resource_ledger
            .multiplication_count_by_layer
            .iter()
            .copied()
            .enumerate()
        {
            if remaining < layer_count {
                let layer_index = u16::try_from(layer_position + 1).ok()?;
                let kind = match layer_index {
                    1..=4 => Lpsy15MultiplicationKind::MaskProduct,
                    5 => Lpsy15MultiplicationKind::MaskCheckOrGateInput,
                    6 => Lpsy15MultiplicationKind::Indicator,
                    7 => Lpsy15MultiplicationKind::TableSelector,
                    _ => return None,
                };
                return Some(Lpsy15MultiplicationRole {
                    multiplication_ordinal,
                    layer_index,
                    ordinal_within_layer: remaining,
                    kind,
                });
            }
            remaining = remaining.checked_sub(layer_count)?;
        }
        None
    }

    pub(crate) const fn resource_ledger(&self) -> &Lpsy15CandidateResourceLedger {
        &self.resource_ledger
    }
}

fn garbling_affine_addition_count(
    gates: &[Lpsy15GateRole],
    participant_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let table_addition_count_per_gate = checked_multiply(
        checked_multiply(TABLE_ROW_COUNT, participant_count)?,
        checked_multiply(2, participant_count)?,
    )?;
    gates.iter().try_fold(0_u64, |total, gate| {
        let gate_addition_count = match gate.kind {
            Lpsy15GateKind::ExclusiveOr => checked_sum(&[
                9,
                checked_multiply(checked_multiply(2, participant_count)?, 2)?,
                table_addition_count_per_gate,
            ])?,
            Lpsy15GateKind::Nonlinear { truth_table } => checked_sum(&[
                9,
                nonlinear_input_inversion_count(truth_table)?,
                checked_multiply(checked_multiply(4, participant_count)?, 2)?,
                table_addition_count_per_gate,
            ])?,
        };
        checked_add(total, gate_addition_count)
    })
}

fn nonlinear_input_inversion_count(truth_table: u8) -> Result<u64, Lpsy15CandidateCompilerError> {
    if !matches!(truth_table, 0b0001 | 0b0010 | 0b0100 | 0b1000) {
        return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
    }
    let true_input_position = u64::from(truth_table.trailing_zeros());
    Ok(2 - u64::from(true_input_position.count_ones()))
}

fn maximum_live_active_wire_count(
    physical_wires: &[Lpsy15PhysicalWireRole],
    gates: &[Lpsy15GateRole],
    outputs: &[Lpsy15OutputRole],
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let mut last_use_by_wire = vec![None; physical_wires.len()];
    for (gate_position, gate) in gates.iter().enumerate() {
        for wire_index in [
            gate.left_physical_wire_index,
            gate.right_physical_wire_index,
        ] {
            let wire_position = usize::try_from(wire_index)
                .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
            let last_use = last_use_by_wire.get_mut(wire_position).ok_or(
                Lpsy15CandidateCompilerError::InvalidLogicalWireReference {
                    wire: wire_index,
                    available_wire_count: physical_wires.len(),
                },
            )?;
            *last_use = Some(gate_position);
        }
    }
    let retained_output_wires = outputs
        .iter()
        .map(|output| output.physical_wire_index)
        .collect::<BTreeSet<_>>();
    let mut live = physical_wires
        .iter()
        .map(|wire| {
            matches!(
                wire.source,
                Lpsy15PhysicalWireSource::BallotInput(_) | Lpsy15PhysicalWireSource::FixedFalse
            )
        })
        .collect::<Vec<_>>();
    let mut live_count = u64_from_usize(live.iter().filter(|is_live| **is_live).count())?;
    let mut maximum_live_count = live_count;
    for (gate_position, gate) in gates.iter().enumerate() {
        let output_position = usize::try_from(gate.physical_output_wire_index)
            .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
        let output_live = live.get_mut(output_position).ok_or(
            Lpsy15CandidateCompilerError::InvalidLogicalWireReference {
                wire: gate.physical_output_wire_index,
                available_wire_count: physical_wires.len(),
            },
        )?;
        if *output_live {
            return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
        }
        *output_live = true;
        live_count = checked_add(live_count, 1)?;
        maximum_live_count = maximum_live_count.max(live_count);

        let consumed_wires = [
            gate.left_physical_wire_index,
            gate.right_physical_wire_index,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        for wire_index in consumed_wires {
            let wire_position = usize::try_from(wire_index)
                .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
            if last_use_by_wire.get(wire_position).copied().flatten() == Some(gate_position)
                && !retained_output_wires.contains(&wire_index)
            {
                let is_live = live.get_mut(wire_position).ok_or(
                    Lpsy15CandidateCompilerError::InvalidLogicalWireReference {
                        wire: wire_index,
                        available_wire_count: physical_wires.len(),
                    },
                )?;
                if !*is_live {
                    return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
                }
                *is_live = false;
                live_count = live_count
                    .checked_sub(1)
                    .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
            }
        }
        if last_use_by_wire
            .get(output_position)
            .copied()
            .flatten()
            .is_none()
            && !retained_output_wires.contains(&gate.physical_output_wire_index)
        {
            live[output_position] = false;
            live_count = live_count
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        }
    }
    Ok(maximum_live_count)
}

fn exact_codeword_check_multiplication_count(
    participant_count: u64,
    degree: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    checked_multiply(
        participant_count
            .checked_sub(degree)
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        checked_add(degree, 1)?,
    )
}

fn exact_codeword_check_addition_count(
    participant_count: u64,
    degree: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    checked_multiply(
        participant_count
            .checked_sub(degree)
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        degree,
    )
}

fn lpsy15_prf_message_byte_length() -> Result<u64, Lpsy15CandidateCompilerError> {
    // The five hashes are ordered candidate identity, roster root, circuit
    // identity, preparation-attempt root, and complete predecessor root. The
    // remaining coordinates are gate, input side, output component, and PRF
    // branch. Key owner and alternative are bound by the selected 40-byte key.
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(LPSY15_PRF_MESSAGE_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned32(u32::MAX),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned16(u16::MAX),
    ])
}

fn lpsy15_prf_kmac_permutation_count(
    message_byte_length: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    // Both the cSHAKE function/customization prefix and the 40-byte KMAC key
    // bytepad occupy exactly one 136-byte absorb block under this fixed
    // language. The final message always consumes one padded block beyond its
    // complete rate blocks; the 40-byte output consumes one squeeze block.
    if LPSY15_PRF_CUSTOMIZATION.len() > 100
        || LPSY15_PRF_KEY_BYTE_LENGTH >= SHAKE256_RATE_BYTE_LENGTH
        || LPSY15_PRF_OUTPUT_BYTE_LENGTH >= SHAKE256_RATE_BYTE_LENGTH
    {
        return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
    }
    let final_message_absorb_block_count = checked_add(
        checked_add(message_byte_length, LPSY15_PRF_RIGHT_ENCODE_BYTE_LENGTH)?
            / SHAKE256_RATE_BYTE_LENGTH,
        1,
    )?;
    checked_add(final_message_absorb_block_count, 2)
}

fn randomness_xof_message_byte_length() -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(RANDOMNESS_XOF_MESSAGE_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::fixed_bytes([0_u8; 64])?,
    ])
}

fn checkpoint_storage_intent(
    kind: Lpsy15CheckpointStateKind,
    state_byte_length: u64,
) -> Result<Lpsy15CheckpointStorageIntent, Lpsy15CandidateCompilerError> {
    let stream_chunk_byte_length = u64_from_usize(FOUNDATION_PROFILE.stream_chunk_byte_length)?;
    let state_chunk_count = checked_ceiling_divide(state_byte_length, stream_chunk_byte_length)?;
    let cursor_byte_length = checkpoint_cursor_byte_length()?;
    let stream_descriptor = CanonicalTuple::new(
        0x1800,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::unsigned64(state_byte_length),
            CanonicalItem::homogeneous_list(
                CanonicalItemType::Hash512,
                &(0..state_chunk_count)
                    .map(|_| zero_hash_item())
                    .collect::<Vec<_>>(),
            )?,
            zero_hash_item(),
        ],
    );
    let stream_descriptor_byte_length = u64_from_usize(stream_descriptor.encode()?.len())?;
    let canonical_manifest_byte_length = u64_from_usize(
        CanonicalTuple::new(
            0x1805,
            CANONICAL_TUPLE_VERSION,
            vec![
                zero_hash_item(),
                zero_hash_item(),
                zero_hash_item(),
                zero_hash_item(),
                CanonicalItem::participant_identity([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::variable_bytes(vec![0_u8; 32])?,
                CanonicalItem::unsigned16(u16::MAX),
                CanonicalItem::unsigned32(u32::MAX),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::Hash512,
                    &(0..CHECKPOINT_ORDERED_SOURCE_DIGEST_COUNT)
                        .map(|_| zero_hash_item())
                        .collect::<Vec<_>>(),
                )?,
                CanonicalItem::variable_bytes(vec![0_u8; usize_from_u64(cursor_byte_length)?])?,
                CanonicalItem::variable_bytes(vec![0_u8; 32])?,
                zero_hash_item(),
                CanonicalItem::unsigned64(u64::MAX),
                CanonicalItem::nested_tuple(&stream_descriptor)?,
            ],
        )
        .encode()?
        .len(),
    )?;
    let maximum_journal_byte_length = checked_add(
        4 + 2 + 32 + 32,
        checked_multiply(
            2,
            checked_add(
                4,
                checked_multiply(
                    state_chunk_count,
                    checked_add(2, CHECKPOINT_CHUNK_RECORD_KEY_BYTE_LENGTH)?,
                )?,
            )?,
        )?,
    )?;
    let configured_manifest_limit_byte_length =
        canonical_manifest_byte_length.max(maximum_journal_byte_length);
    let simultaneous_logical_record_count =
        checked_add(checked_multiply(2, state_chunk_count)?, 2)?;
    let chunk_stored_value_byte_length = checked_add(
        checked_multiply(2, state_byte_length)?,
        checked_multiply(
            checked_multiply(2, state_chunk_count)?,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
    )?;
    let manifest_stored_value_byte_length = checked_multiply(
        2,
        checked_sum(&[
            configured_manifest_limit_byte_length,
            CHECKPOINT_STORED_MANIFEST_FIXED_BYTE_LENGTH,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        ])?,
    )?;
    let journal_stored_value_byte_length = checked_multiply(
        2,
        checked_sum(&[
            CHECKPOINT_JOURNAL_CAPACITY_FIXED_BYTE_LENGTH,
            checked_multiply(
                checked_multiply(2, state_chunk_count)?,
                checked_add(CHECKPOINT_CHUNK_RECORD_KEY_BYTE_LENGTH, 4)?,
            )?,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        ])?,
    )?;
    let index_stored_value_byte_length = checked_multiply(
        simultaneous_logical_record_count,
        CHECKPOINT_STORAGE_INDEX_VALUE_BYTE_LENGTH,
    )?;
    let copy_on_write_stored_value_byte_length = checked_sum(&[
        chunk_stored_value_byte_length,
        manifest_stored_value_byte_length,
        journal_stored_value_byte_length,
        index_stored_value_byte_length,
    ])?;
    let maximum_checkpoint_logical_record_key_byte_length = CHECKPOINT_CHUNK_RECORD_KEY_BYTE_LENGTH
        .max(CHECKPOINT_MANIFEST_RECORD_KEY_BYTE_LENGTH)
        .max(CHECKPOINT_JOURNAL_RECORD_KEY_BYTE_LENGTH);
    let repair_head_plaintext_byte_length = checked_add(
        AUTHENTICATED_REPAIR_HEAD_FIXED_BYTE_LENGTH,
        checked_multiply(
            simultaneous_logical_record_count,
            checked_sum(&[
                AUTHENTICATED_REPAIR_RECORD_FIXED_BYTE_LENGTH,
                maximum_checkpoint_logical_record_key_byte_length,
                CHECKPOINT_STORAGE_OBJECT_KEY_BYTE_LENGTH,
            ])?,
        )?,
    )?;
    let repair_head_overlap_byte_length = checked_multiply(
        2,
        checked_add(
            repair_head_plaintext_byte_length,
            RUNTIME_RECORD_ENVELOPE_OVERHEAD_BYTE_LENGTH,
        )?,
    )?;
    let complete_storage_byte_length = checked_add(
        copy_on_write_stored_value_byte_length,
        repair_head_overlap_byte_length,
    )?;
    Ok(Lpsy15CheckpointStorageIntent {
        kind,
        state_byte_length,
        state_chunk_count,
        cursor_byte_length,
        stream_descriptor_byte_length,
        canonical_manifest_byte_length,
        maximum_journal_byte_length,
        configured_manifest_limit_byte_length,
        copy_on_write_stored_value_byte_length,
        repair_head_overlap_byte_length,
        complete_storage_byte_length,
    })
}

fn checkpoint_cursor_byte_length() -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(CHECKPOINT_CURSOR_DOMAIN)?,
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned16(u16::MAX),
        CanonicalItem::unsigned64(u64::MAX),
        CanonicalItem::unsigned64(u64::MAX),
        CanonicalItem::unsigned64(u64::MAX),
        CanonicalItem::unsigned32(u32::MAX),
        zero_hash_item(),
    ])
}

fn storage_record_count(
    streams: &[Lpsy15CandidateStream],
) -> Result<u64, Lpsy15CandidateCompilerError> {
    checked_sum(
        &streams
            .iter()
            .map(|stream| checked_add(stream.chunk_count, 3))
            .collect::<Result<Vec<_>, _>>()?,
    )
}

fn usize_from_u64(value: u64) -> Result<usize, Lpsy15CandidateCompilerError> {
    usize::try_from(value).map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)
}

fn ballot_input_role(
    circuit: &CompiledTallyCircuit,
    logical_wire_position: usize,
) -> Result<Lpsy15BallotInputRole, Lpsy15CandidateCompilerError> {
    let input_count_per_participant = 1_usize
        .checked_add(
            usize::from(circuit.profile().option_count())
                .checked_mul(circuit.geometry().score_bit_width)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let participant_position = logical_wire_position / input_count_per_participant;
    let participant_input_position = logical_wire_position % input_count_per_participant;
    let participant_position = u16::try_from(participant_position)
        .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
    if participant_input_position == 0 {
        return Ok(Lpsy15BallotInputRole::Presence {
            participant_position,
        });
    }
    let score_position = participant_input_position - 1;
    let option_position = score_position / circuit.geometry().score_bit_width;
    let bit_position = score_position % circuit.geometry().score_bit_width;
    Ok(Lpsy15BallotInputRole::ScoreBit {
        participant_position,
        option_position: u16::try_from(option_position)
            .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
        bit_position: u16::try_from(bit_position)
            .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
    })
}

fn output_roles(
    circuit: &CompiledTallyCircuit,
    logical_wire_roles: &[Lpsy15LogicalWireRole],
) -> Result<Vec<Lpsy15OutputRole>, Lpsy15CandidateCompilerError> {
    let mut roles = Vec::with_capacity(
        1_usize
            .checked_add(circuit.geometry().private_result_bit_count)
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
    );
    let nonempty_logical_role = logical_role(logical_wire_roles, circuit.nonempty_output_wire())?;
    roles.push(Lpsy15OutputRole {
        kind: Lpsy15OutputKind::Nonempty,
        logical_wire_index: nonempty_logical_role.logical_wire_index,
        physical_wire_index: nonempty_logical_role.physical_wire_index,
        is_inverted: nonempty_logical_role.is_inverted,
    });
    for (output_position, output_wires) in
        circuit.ordered_option_position_wires().iter().enumerate()
    {
        for (bit_position, logical_wire_index) in output_wires.iter().copied().enumerate() {
            let logical_role = logical_role(logical_wire_roles, logical_wire_index)?;
            roles.push(Lpsy15OutputRole {
                kind: Lpsy15OutputKind::OrderedOptionPositionBit {
                    output_position: u16::try_from(output_position)
                        .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
                    bit_position: u16::try_from(bit_position)
                        .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
                },
                logical_wire_index,
                physical_wire_index: logical_role.physical_wire_index,
                is_inverted: logical_role.is_inverted,
            });
        }
    }
    Ok(roles)
}

struct Lpsy15RoundCompilerInputs<'a> {
    participant_count: u64,
    ballot_input_wire_count: u64,
    physical_wire_count: u64,
    unique_output_physical_wire_count: u64,
    table_field_element_count: u64,
    total_polynomial_count: u64,
    total_multiplication_count: u64,
    multiplication_count_by_layer: &'a [u64],
}

fn compile_rounds(
    inputs: Lpsy15RoundCompilerInputs<'_>,
) -> Result<Vec<Lpsy15Round>, Lpsy15CandidateCompilerError> {
    let private_field_elements_per_participant = inputs
        .total_polynomial_count
        .checked_div(inputs.participant_count)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?
        .checked_mul(
            inputs
                .participant_count
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let mut rounds = vec![
        Lpsy15Round {
            round_index: 0,
            kind: Lpsy15RoundKind::SourceDeliveryAndCoinCommitment,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: 1,
            kind: Lpsy15RoundKind::DeliveryReceiptRoot,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: 2,
            kind: Lpsy15RoundKind::CoinOpening,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: 3,
            kind: Lpsy15RoundKind::BatchedSharingCheck,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: checked_multiply(inputs.participant_count, 3)?,
        },
        Lpsy15Round {
            round_index: 4,
            kind: Lpsy15RoundKind::TripleProductOpening,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: inputs.total_multiplication_count,
        },
    ];
    for (layer_position, multiplication_count) in inputs
        .multiplication_count_by_layer
        .iter()
        .copied()
        .enumerate()
    {
        rounds.push(Lpsy15Round {
            round_index: u16::try_from(5 + layer_position)
                .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
            kind: Lpsy15RoundKind::MultiplicationLayer {
                layer_index: u16::try_from(layer_position + 1)
                    .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
            },
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: checked_multiply(2, multiplication_count)?,
        });
    }
    let preparation_output_round_index = u16::try_from(
        5_usize
            .checked_add(inputs.multiplication_count_by_layer.len())
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
    )
    .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
    let preparation_witness_round_index = preparation_output_round_index
        .checked_add(1)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let finality_round_index = preparation_witness_round_index
        .checked_add(1)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let activation_round_index = finality_round_index
        .checked_add(1)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    rounds.extend([
        Lpsy15Round {
            round_index: preparation_output_round_index,
            kind: Lpsy15RoundKind::PreparationOutputOpening,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: checked_add(
                inputs.physical_wire_count,
                inputs.unique_output_physical_wire_count,
            )?,
        },
        Lpsy15Round {
            round_index: preparation_witness_round_index,
            kind: Lpsy15RoundKind::PreparationTerminalWitness,
            participation: Lpsy15RoundParticipation::StateWitnessQuorum,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: finality_round_index,
            kind: Lpsy15RoundKind::TargetFinality,
            participation: Lpsy15RoundParticipation::FinalityQuorum,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: activation_round_index,
            kind: Lpsy15RoundKind::ActivationAndTableOpening,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: checked_add(
                checked_add(inputs.ballot_input_wire_count, FIXED_FALSE_SOURCE_COUNT)?,
                inputs.table_field_element_count,
            )?,
        },
        Lpsy15Round {
            round_index: activation_round_index
                .checked_add(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            kind: Lpsy15RoundKind::ActiveKeyOpening,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: checked_multiply(
                checked_add(inputs.ballot_input_wire_count, FIXED_FALSE_SOURCE_COUNT)?,
                inputs.participant_count,
            )?,
        },
        Lpsy15Round {
            round_index: activation_round_index
                .checked_add(2)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            kind: Lpsy15RoundKind::EvaluationClaim,
            participation: Lpsy15RoundParticipation::CompleteRoster,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
        Lpsy15Round {
            round_index: activation_round_index
                .checked_add(3)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
            kind: Lpsy15RoundKind::ResultTerminalWitness,
            participation: Lpsy15RoundParticipation::StateWitnessQuorum,
            private_field_elements_per_participant: 0,
            public_field_elements_per_participant: 0,
        },
    ]);
    Ok(rounds)
}

fn compile_streams(
    rounds: &[Lpsy15Round],
    participant_count: u64,
    total_polynomial_count: u64,
    top_count: u16,
    witness_quorum: u64,
    finality_quorum: u64,
) -> Result<Vec<Lpsy15CandidateStream>, Lpsy15CandidateCompilerError> {
    let private_field_element_count = total_polynomial_count
        .checked_div(participant_count)
        .filter(|_| total_polynomial_count.is_multiple_of(participant_count))
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let mut streams = Vec::new();
    for sender_position in 0..participant_count {
        for recipient_position in 0..participant_count {
            if sender_position == recipient_position {
                continue;
            }
            streams.push(private_stream(
                u16::try_from(sender_position)
                    .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
                u16::try_from(recipient_position)
                    .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
                private_field_element_count,
            )?);
        }
    }
    for round in rounds {
        let sender_count = round_participant_requirement(
            round.participation,
            participant_count,
            witness_quorum,
            finality_quorum,
        );
        let control_payload_byte_length =
            round_control_payload_byte_length(round.kind, participant_count, top_count)?;
        for sender_position in 0..sender_count {
            streams.push(public_stream(
                *round,
                u16::try_from(sender_position)
                    .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
                control_payload_byte_length,
            )?);
        }
    }
    Ok(streams)
}

fn compile_state_intents(
    rounds: &[Lpsy15Round],
    streams: &[Lpsy15CandidateStream],
) -> Result<Vec<Lpsy15StateIntent>, Lpsy15CandidateCompilerError> {
    rounds
        .iter()
        .map(|round| {
            let kind = match round.kind {
                Lpsy15RoundKind::SourceDeliveryAndCoinCommitment
                | Lpsy15RoundKind::DeliveryReceiptRoot
                | Lpsy15RoundKind::CoinOpening
                | Lpsy15RoundKind::BatchedSharingCheck
                | Lpsy15RoundKind::TripleProductOpening
                | Lpsy15RoundKind::MultiplicationLayer { .. }
                | Lpsy15RoundKind::PreparationOutputOpening => {
                    Lpsy15StateIntentKind::PreparationRound
                }
                Lpsy15RoundKind::PreparationTerminalWitness => {
                    Lpsy15StateIntentKind::PreparationTerminal
                }
                Lpsy15RoundKind::TargetFinality => Lpsy15StateIntentKind::TargetFinality,
                Lpsy15RoundKind::ActivationAndTableOpening
                | Lpsy15RoundKind::ActiveKeyOpening
                | Lpsy15RoundKind::EvaluationClaim => Lpsy15StateIntentKind::EvaluationRound,
                Lpsy15RoundKind::ResultTerminalWitness => Lpsy15StateIntentKind::ResultTerminal,
            };
            let (predecessor_kind, predecessor_count) = match round.kind {
                Lpsy15RoundKind::SourceDeliveryAndCoinCommitment => {
                    (Lpsy15StatePredecessorKind::PreparationAttempt, 1)
                }
                Lpsy15RoundKind::TargetFinality => {
                    (Lpsy15StatePredecessorKind::PreparationAndSelectedSet, 3)
                }
                _ => (Lpsy15StatePredecessorKind::PreviousRound, 1),
            };
            let sender_stream_identity_count = u64_from_usize(
                streams
                    .iter()
                    .filter(|stream| stream.round_index == round.round_index)
                    .count(),
            )?;
            if sender_stream_identity_count == 0 {
                return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
            }
            Ok(Lpsy15StateIntent {
                round_index: round.round_index,
                round_kind: round.kind,
                kind,
                predecessor_kind,
                predecessor_count,
                sender_stream_identity_count,
                round_root_body_byte_length: round_root_body_byte_length(
                    round.round_index,
                    predecessor_count,
                    sender_stream_identity_count,
                )?,
                permits_clear_output_material: matches!(
                    round.kind,
                    Lpsy15RoundKind::ActivationAndTableOpening
                        | Lpsy15RoundKind::ActiveKeyOpening
                        | Lpsy15RoundKind::EvaluationClaim
                        | Lpsy15RoundKind::ResultTerminalWitness
                ),
            })
        })
        .collect()
}

fn round_root_body_byte_length(
    round_index: u16,
    predecessor_count: u64,
    sender_stream_identity_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let predecessor_identities = (0..predecessor_count)
        .map(|_| zero_hash_item())
        .collect::<Vec<_>>();
    let sender_stream_identities = (0..sender_stream_identity_count)
        .map(|_| zero_hash_item())
        .collect::<Vec<_>>();
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(ROUND_ROOT_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &predecessor_identities)?,
        CanonicalItem::unsigned16(round_index),
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &sender_stream_identities)?,
    ])
}

fn burn_terminal_resources(
    authenticated_failure_claim_byte_length: u64,
    witness_quorum: u64,
) -> Result<(u64, u64), Lpsy15CandidateCompilerError> {
    let failure_claim_round = Lpsy15Round {
        round_index: u16::MAX - 1,
        kind: Lpsy15RoundKind::EvaluationClaim,
        participation: Lpsy15RoundParticipation::CompleteRoster,
        private_field_elements_per_participant: 0,
        public_field_elements_per_participant: 0,
    };
    let burn_terminal_round = Lpsy15Round {
        round_index: u16::MAX,
        kind: Lpsy15RoundKind::ResultTerminalWitness,
        participation: Lpsy15RoundParticipation::StateWitnessQuorum,
        private_field_elements_per_participant: 0,
        public_field_elements_per_participant: 0,
    };
    let mut streams = vec![public_stream(
        failure_claim_round,
        0,
        authenticated_failure_claim_byte_length,
    )?];
    for witness_position in 0..witness_quorum {
        streams.push(public_stream(
            burn_terminal_round,
            u16::try_from(witness_position)
                .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?,
            0,
        )?);
    }
    Ok((
        u64_from_usize(streams.len())?,
        stream_carrier_sum(&streams)?,
    ))
}

fn compile_candidate_paths(
    rounds: &[Lpsy15Round],
    streams: &[Lpsy15CandidateStream],
    burn_terminal_stream_count: u64,
    burn_terminal_carrier_byte_length: u64,
) -> Result<Vec<Lpsy15CandidatePath>, Lpsy15CandidateCompilerError> {
    let complete_carrier_byte_length = stream_carrier_sum(streams)?;
    let complete_stream_count = u64_from_usize(streams.len())?;
    let target_finality_round_index = rounds
        .iter()
        .find(|round| matches!(round.kind, Lpsy15RoundKind::TargetFinality))
        .map(|round| round.round_index)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let all_abstention_streams = streams
        .iter()
        .filter(|stream| stream.round_index < target_finality_round_index)
        .copied()
        .collect::<Vec<_>>();
    let all_abstention_carrier_byte_length = stream_carrier_sum(&all_abstention_streams)?;
    let all_abstention_stream_count = u64_from_usize(all_abstention_streams.len())?;
    let mut paths = vec![
        Lpsy15CandidatePath {
            kind: Lpsy15CandidatePathKind::Success,
            terminal: Lpsy15CandidatePathTerminal::Result,
            verified_prefix_stream_count: complete_stream_count,
            downloaded_carrier_byte_length: complete_carrier_byte_length,
            verified_prefix_carrier_byte_length: complete_carrier_byte_length,
            additional_terminal_stream_count: 0,
            additional_terminal_carrier_byte_length: 0,
        },
        Lpsy15CandidatePath {
            kind: Lpsy15CandidatePathKind::AllAbstention,
            terminal: Lpsy15CandidatePathTerminal::NoResult,
            verified_prefix_stream_count: all_abstention_stream_count,
            downloaded_carrier_byte_length: all_abstention_carrier_byte_length,
            verified_prefix_carrier_byte_length: all_abstention_carrier_byte_length,
            additional_terminal_stream_count: 0,
            additional_terminal_carrier_byte_length: 0,
        },
    ];

    for round in rounds {
        let prior_streams = streams
            .iter()
            .filter(|stream| stream.round_index < round.round_index)
            .copied()
            .collect::<Vec<_>>();
        let affected_round_streams = streams
            .iter()
            .filter(|stream| stream.round_index == round.round_index)
            .copied()
            .collect::<Vec<_>>();
        let prior_carrier_byte_length = stream_carrier_sum(&prior_streams)?;
        let affected_round_carrier_byte_length = stream_carrier_sum(&affected_round_streams)?;
        let affected_round_stream_count = u64_from_usize(affected_round_streams.len())?;
        let minimum_affected_stream_byte_length = affected_round_streams
            .iter()
            .map(|stream| stream.carrier_byte_length)
            .min()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let maximum_affected_stream_byte_length = affected_round_streams
            .iter()
            .map(|stream| stream.carrier_byte_length)
            .max()
            .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
        let accepted_prefix_byte_length = checked_add(
            prior_carrier_byte_length,
            affected_round_carrier_byte_length
                .checked_sub(minimum_affected_stream_byte_length)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )?;
        let accepted_prefix_stream_count = checked_add(
            u64_from_usize(prior_streams.len())?,
            affected_round_stream_count
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?,
        )?;
        paths.push(Lpsy15CandidatePath {
            kind: Lpsy15CandidatePathKind::Withholding {
                affected_round_index: round.round_index,
            },
            terminal: Lpsy15CandidatePathTerminal::Pending,
            verified_prefix_stream_count: accepted_prefix_stream_count,
            downloaded_carrier_byte_length: accepted_prefix_byte_length,
            verified_prefix_carrier_byte_length: accepted_prefix_byte_length,
            additional_terminal_stream_count: 0,
            additional_terminal_carrier_byte_length: 0,
        });
        paths.push(Lpsy15CandidatePath {
            kind: Lpsy15CandidatePathKind::UnauthenticatedMalformed {
                affected_round_index: round.round_index,
            },
            terminal: Lpsy15CandidatePathTerminal::Pending,
            verified_prefix_stream_count: accepted_prefix_stream_count,
            downloaded_carrier_byte_length: checked_add(
                accepted_prefix_byte_length,
                maximum_affected_stream_byte_length,
            )?,
            verified_prefix_carrier_byte_length: accepted_prefix_byte_length,
            additional_terminal_stream_count: 0,
            additional_terminal_carrier_byte_length: 0,
        });
        let complete_affected_round_carrier_byte_length = checked_add(
            prior_carrier_byte_length,
            affected_round_carrier_byte_length,
        )?;
        paths.push(Lpsy15CandidatePath {
            kind: Lpsy15CandidatePathKind::AuthenticatedInconsistency {
                affected_round_index: round.round_index,
            },
            terminal: Lpsy15CandidatePathTerminal::Burn,
            verified_prefix_stream_count: accepted_prefix_stream_count,
            downloaded_carrier_byte_length: checked_add(
                complete_affected_round_carrier_byte_length,
                burn_terminal_carrier_byte_length,
            )?,
            verified_prefix_carrier_byte_length: accepted_prefix_byte_length,
            additional_terminal_stream_count: burn_terminal_stream_count,
            additional_terminal_carrier_byte_length: burn_terminal_carrier_byte_length,
        });
    }
    Ok(paths)
}

fn private_stream(
    sender_position: u16,
    recipient_position: u16,
    field_element_count: u64,
) -> Result<Lpsy15CandidateStream, Lpsy15CandidateCompilerError> {
    let payload_byte_length =
        checked_multiply(field_element_count, PRIME_FIELD_ELEMENT_BYTE_LENGTH)?;
    let chunk_count =
        checked_chunk_count(payload_byte_length, PRIVATE_PLAINTEXT_CHUNK_BYTE_LENGTH)?;
    let authentication_tag_byte_length = checked_multiply(
        chunk_count,
        u64_from_usize(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_AUTHENTICATION_TAG_BYTE_LENGTH)?,
    )?;
    let encrypted_payload_byte_length =
        checked_add(payload_byte_length, authentication_tag_byte_length)?;
    let header_byte_length = private_stream_header_byte_length(
        sender_position,
        recipient_position,
        field_element_count,
        payload_byte_length,
        chunk_count,
        encrypted_payload_byte_length,
    )?;
    let manifest_byte_length =
        stream_manifest_byte_length(PRIVATE_STREAM_MANIFEST_DOMAIN, chunk_count)?;
    let signature_envelope_byte_length =
        private_stream_signature_envelope_byte_length(sender_position, recipient_position)?;
    let carrier_byte_length = checked_sum(&[
        header_byte_length,
        manifest_byte_length,
        signature_envelope_byte_length,
        encrypted_payload_byte_length,
    ])?;
    Ok(Lpsy15CandidateStream {
        kind: Lpsy15CandidateStreamKind::PrivateSourceDelivery,
        round_index: 0,
        sender_position,
        recipient_position: Some(recipient_position),
        field_element_count,
        control_payload_byte_length: 0,
        payload_byte_length,
        maximum_payload_chunk_byte_length: PRIVATE_PLAINTEXT_CHUNK_BYTE_LENGTH,
        chunk_count,
        header_byte_length,
        manifest_byte_length,
        signature_envelope_byte_length,
        authentication_tag_byte_length,
        carrier_byte_length,
    })
}

fn public_stream(
    round: Lpsy15Round,
    sender_position: u16,
    control_payload_byte_length: u64,
) -> Result<Lpsy15CandidateStream, Lpsy15CandidateCompilerError> {
    let field_payload_byte_length = checked_multiply(
        round.public_field_elements_per_participant,
        PRIME_FIELD_ELEMENT_BYTE_LENGTH,
    )?;
    let payload_byte_length = checked_add(control_payload_byte_length, field_payload_byte_length)?;
    let chunk_count = checked_chunk_count(payload_byte_length, PUBLIC_PAYLOAD_CHUNK_BYTE_LENGTH)?;
    let header_byte_length = public_stream_header_byte_length(
        round,
        sender_position,
        control_payload_byte_length,
        payload_byte_length,
        chunk_count,
    )?;
    let manifest_byte_length =
        stream_manifest_byte_length(PUBLIC_STREAM_MANIFEST_DOMAIN, chunk_count)?;
    let signature_envelope_byte_length =
        public_stream_signature_envelope_byte_length(round, sender_position)?;
    let carrier_byte_length = checked_sum(&[
        header_byte_length,
        manifest_byte_length,
        signature_envelope_byte_length,
        payload_byte_length,
    ])?;
    Ok(Lpsy15CandidateStream {
        kind: Lpsy15CandidateStreamKind::PublicRound(round.kind),
        round_index: round.round_index,
        sender_position,
        recipient_position: None,
        field_element_count: round.public_field_elements_per_participant,
        control_payload_byte_length,
        payload_byte_length,
        maximum_payload_chunk_byte_length: PUBLIC_PAYLOAD_CHUNK_BYTE_LENGTH,
        chunk_count,
        header_byte_length,
        manifest_byte_length,
        signature_envelope_byte_length,
        authentication_tag_byte_length: 0,
        carrier_byte_length,
    })
}

fn private_stream_header_byte_length(
    sender_position: u16,
    recipient_position: u16,
    field_element_count: u64,
    payload_byte_length: u64,
    chunk_count: u64,
    encrypted_payload_byte_length: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(PRIVATE_STREAM_HEADER_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned16(sender_position),
        CanonicalItem::unsigned16(recipient_position),
        CanonicalItem::unsigned16(0),
        CanonicalItem::unsigned64(field_element_count),
        CanonicalItem::unsigned64(payload_byte_length),
        CanonicalItem::unsigned64(PRIVATE_PLAINTEXT_CHUNK_BYTE_LENGTH),
        CanonicalItem::unsigned64(chunk_count),
        CanonicalItem::unsigned64(encrypted_payload_byte_length),
        CanonicalItem::fixed_bytes([0_u8; ML_KEM_768_CIPHERTEXT_BYTE_LENGTH])?,
    ])
}

fn public_stream_header_byte_length(
    round: Lpsy15Round,
    sender_position: u16,
    control_payload_byte_length: u64,
    payload_byte_length: u64,
    chunk_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(PUBLIC_STREAM_HEADER_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned16(round.round_index),
        CanonicalItem::unsigned16(sender_position),
        CanonicalItem::unsigned64(round.public_field_elements_per_participant),
        CanonicalItem::unsigned64(control_payload_byte_length),
        CanonicalItem::unsigned64(payload_byte_length),
        CanonicalItem::unsigned64(PUBLIC_PAYLOAD_CHUNK_BYTE_LENGTH),
        CanonicalItem::unsigned64(chunk_count),
    ])
}

fn stream_manifest_byte_length(
    domain: &str,
    chunk_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let chunk_digests = (0..chunk_count)
        .map(|_| zero_hash_item())
        .collect::<Vec<_>>();
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(domain)?,
        zero_hash_item(),
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &chunk_digests)?,
    ])
}

fn private_stream_signature_envelope_byte_length(
    sender_position: u16,
    recipient_position: u16,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let body_byte_length = canonical_tuple_bytes(vec![
        CanonicalItem::nonempty_ascii(PRIVATE_STREAM_SIGNATURE_BODY_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned16(sender_position),
        CanonicalItem::unsigned16(recipient_position),
        CanonicalItem::unsigned16(0),
    ])?;
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(PRIVATE_STREAM_SIGNATURE_ENVELOPE_DOMAIN)?,
        CanonicalItem::variable_bytes(body_byte_length)?,
        CanonicalItem::fixed_bytes([0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH])?,
    ])
}

fn public_stream_signature_envelope_byte_length(
    round: Lpsy15Round,
    sender_position: u16,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let body_byte_length = canonical_tuple_bytes(vec![
        CanonicalItem::nonempty_ascii(PUBLIC_STREAM_SIGNATURE_BODY_DOMAIN)?,
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        zero_hash_item(),
        CanonicalItem::unsigned16(round.round_index),
        CanonicalItem::unsigned16(sender_position),
    ])?;
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(PUBLIC_STREAM_SIGNATURE_ENVELOPE_DOMAIN)?,
        CanonicalItem::variable_bytes(body_byte_length)?,
        CanonicalItem::fixed_bytes([0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH])?,
    ])
}

fn round_control_payload_byte_length(
    kind: Lpsy15RoundKind,
    participant_count: u64,
    top_count: u16,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    match kind {
        Lpsy15RoundKind::SourceDeliveryAndCoinCommitment => {
            source_delivery_control_byte_length(participant_count)
        }
        Lpsy15RoundKind::DeliveryReceiptRoot => {
            delivery_receipt_control_byte_length(participant_count)
        }
        Lpsy15RoundKind::CoinOpening => collective_coin_opening_byte_length(),
        Lpsy15RoundKind::EvaluationClaim => evaluation_success_claim_byte_length(top_count),
        _ => Ok(0),
    }
}

fn source_delivery_control_byte_length(
    participant_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let outgoing_manifest_identities = roster_peer_hash_items(participant_count)?;
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(SOURCE_DELIVERY_CONTROL_DOMAIN)?,
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &outgoing_manifest_identities)?,
        zero_hash_item(),
    ])
}

fn delivery_receipt_control_byte_length(
    participant_count: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let incoming_manifest_identities = roster_peer_hash_items(participant_count)?;
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(DELIVERY_RECEIPT_CONTROL_DOMAIN)?,
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &incoming_manifest_identities)?,
    ])
}

fn collective_coin_opening_byte_length() -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(COLLECTIVE_COIN_OPENING_CONTROL_DOMAIN)?,
        CanonicalItem::fixed_bytes([0_u8; PRIME_FIELD_ELEMENT_BYTE_LENGTH as usize])?,
        CanonicalItem::fixed_bytes([0_u8; COLLECTIVE_COIN_SALT_BYTE_LENGTH])?,
    ])
}

fn evaluation_success_claim_byte_length(
    top_count: u16,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let ordered_option_identifiers = (0..top_count)
        .map(CanonicalItem::unsigned16)
        .collect::<Vec<_>>();
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(EVALUATION_SUCCESS_CLAIM_DOMAIN)?,
        zero_hash_item(),
        CanonicalItem::homogeneous_list(
            CanonicalItemType::Unsigned16,
            &ordered_option_identifiers,
        )?,
    ])
}

fn authenticated_failure_claim_byte_length() -> Result<u64, Lpsy15CandidateCompilerError> {
    canonical_tuple_byte_length(vec![
        CanonicalItem::nonempty_ascii(AUTHENTICATED_FAILURE_CLAIM_DOMAIN)?,
        zero_hash_item(),
        CanonicalItem::unsigned16(1),
        CanonicalItem::unsigned32(u32::MAX),
    ])
}

fn roster_peer_hash_items(
    participant_count: u64,
) -> Result<Vec<CanonicalItem>, Lpsy15CandidateCompilerError> {
    let peer_count = participant_count
        .checked_sub(1)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    Ok((0..peer_count).map(|_| zero_hash_item()).collect())
}

fn zero_hash_item() -> CanonicalItem {
    CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH])
}

fn canonical_tuple_byte_length(
    items: Vec<CanonicalItem>,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    u64_from_usize(canonical_tuple_bytes(items)?.len())
}

fn canonical_tuple_bytes(
    items: Vec<CanonicalItem>,
) -> Result<Vec<u8>, Lpsy15CandidateCompilerError> {
    Ok(CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
    .encode()?)
}

fn checked_chunk_count(
    payload_byte_length: u64,
    maximum_chunk_byte_length: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    if payload_byte_length == 0 {
        return Ok(0);
    }
    checked_ceiling_divide(payload_byte_length, maximum_chunk_byte_length)
}

fn stream_carrier_sum(
    streams: &[Lpsy15CandidateStream],
) -> Result<u64, Lpsy15CandidateCompilerError> {
    checked_sum(
        &streams
            .iter()
            .map(|stream| stream.carrier_byte_length)
            .collect::<Vec<_>>(),
    )
}

fn minimum_visit_count(
    rounds: &[Lpsy15Round],
    participant_count: u64,
    witness_quorum: u64,
    finality_quorum: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    let mut rounds = rounds.iter();
    let first_round = rounds
        .next()
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?;
    let mut visit_count = round_participant_requirement(
        first_round.participation,
        participant_count,
        witness_quorum,
        finality_quorum,
    );
    for round in rounds {
        let participant_requirement = round_participant_requirement(
            round.participation,
            participant_count,
            witness_quorum,
            finality_quorum,
        );
        let added_visits = if matches!(round.kind, Lpsy15RoundKind::TargetFinality) {
            // Ballot custody and selected-set authorization are external causal
            // predecessors. Their completion prevents the last preparation
            // witness from producing target finality in that earlier visit.
            participant_requirement
        } else {
            participant_requirement
                .checked_sub(1)
                .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)?
        };
        visit_count = checked_add(visit_count, added_visits)?;
    }
    Ok(visit_count)
}

fn maximum_visit_count(
    rounds: &[Lpsy15Round],
    participant_count: u64,
    witness_quorum: u64,
    finality_quorum: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    checked_sum(
        &rounds
            .iter()
            .map(|round| {
                round_participant_requirement(
                    round.participation,
                    participant_count,
                    witness_quorum,
                    finality_quorum,
                )
            })
            .collect::<Vec<_>>(),
    )
}

const fn round_participant_requirement(
    participation: Lpsy15RoundParticipation,
    participant_count: u64,
    witness_quorum: u64,
    finality_quorum: u64,
) -> u64 {
    match participation {
        Lpsy15RoundParticipation::CompleteRoster => participant_count,
        Lpsy15RoundParticipation::StateWitnessQuorum => witness_quorum,
        Lpsy15RoundParticipation::FinalityQuorum => finality_quorum,
    }
}

fn logical_role(
    roles: &[Lpsy15LogicalWireRole],
    logical_wire_index: WireIndex,
) -> Result<Lpsy15LogicalWireRole, Lpsy15CandidateCompilerError> {
    let logical_wire_position = usize::try_from(logical_wire_index)
        .map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)?;
    roles.get(logical_wire_position).copied().ok_or(
        Lpsy15CandidateCompilerError::InvalidLogicalWireReference {
            wire: logical_wire_index,
            available_wire_count: roles.len(),
        },
    )
}

fn conjunction_truth_table(left_is_inverted: bool, right_is_inverted: bool) -> u8 {
    let mut truth_table = 0_u8;
    for physical_left in [false, true] {
        for physical_right in [false, true] {
            let output = (physical_left ^ left_is_inverted) & (physical_right ^ right_is_inverted);
            if output {
                let bit_position = usize::from(physical_left) * 2 + usize::from(physical_right);
                truth_table |= 1 << bit_position;
            }
        }
    }
    truth_table
}

fn checked_add(left: u64, right: u64) -> Result<u64, Lpsy15CandidateCompilerError> {
    left.checked_add(right)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, Lpsy15CandidateCompilerError> {
    left.checked_mul(right)
        .ok_or(Lpsy15CandidateCompilerError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, Lpsy15CandidateCompilerError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}

fn checked_ceiling_divide(
    numerator: u64,
    denominator: u64,
) -> Result<u64, Lpsy15CandidateCompilerError> {
    if denominator == 0 {
        return Err(Lpsy15CandidateCompilerError::ArithmeticOverflow);
    }
    checked_add(numerator, denominator - 1).map(|value| value / denominator)
}

fn u64_from_usize(value: usize) -> Result<u64, Lpsy15CandidateCompilerError> {
    u64::try_from(value).map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)
}

fn u32_from_usize(value: usize) -> Result<u32, Lpsy15CandidateCompilerError> {
    u32::try_from(value).map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)
}

fn wire_index_from_usize(value: usize) -> Result<WireIndex, Lpsy15CandidateCompilerError> {
    WireIndex::try_from(value).map_err(|_| Lpsy15CandidateCompilerError::IntegerConversion)
}
