//! Deterministic, test-only static resource-accounting evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    bgv::{
        direct_ballots::{
            PAIR_CHARACTER_CIPHERTEXT_COUNT, selected_pair_character_lane_assignments,
        },
        evaluator::{
            ballot_aggregation::{
                TwoStreamPairCharacterProductAccounting,
                canonical_two_stream_pair_character_product_accounting,
            },
            program::{
                SelectedEvaluatorExecutionResourceTotals,
                selected_evaluator_execution_resource_ledger, selected_evaluator_program_set,
            },
        },
        parameters::{
            PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT, PLAINTEXT_MODULUS,
            POLYNOMIAL_DEGREE, bgv_parameters_hash,
        },
        target_decryption::static_accounting::{
            SelectedTargetReleaseStaticAccounting, derive_selected_target_release_static_accounting,
        },
    },
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
        MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    },
    hashing::{StreamingHash512, hash_framed_parts_512, to_hex},
};

use super::{
    FIRST_PROFILE_APPLICATION_FAMILIES, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, selected_proof_profile_set,
};
use super::{
    external_memory::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
    phase_liveness_accounting::{
        SelectedCompleteActionPhaseLivenessAccounting,
        derive_selected_complete_action_phase_liveness_accounting,
    },
    selected_accounting::{
        SelectedCompleteActionMaterialResourceAccounting,
        SelectedProofExternalMemoryDiagnosticError,
        SelectedProofExternalMemoryDiagnosticRequirement, SelectedProofQueryTreeResourceAccounting,
        SelectedProofResidentPhaseResourceAccounting,
        derive_selected_complete_action_material_resource_accounting,
        derive_selected_proof_family_application_inventory,
        selected_proof_external_memory_diagnostic_report,
    },
    selected_material_transport_accounting::{
        SelectedAggregatePublicCarrierAccounting, SelectedEvaluatorReplayPublicCarrierAccounting,
        SelectedExactEvaluatorReplayCarrierAccounting,
        SelectedPrivateVssMailboxTransportAccounting, SelectedUnsignedPublicCarrierAccounting,
        derive_selected_private_vss_mailbox_transport_accounting,
        derive_selected_unsigned_public_carrier_accounting,
    },
};

const RECORD_KIND: &str = "pair-character-candidate-static-resource-accounting";
const RECORD_VERSION: u16 = 2;
const RECORD_HASH_DOMAIN: &str = "sealed-lattice/pair-character-static-resource-accounting/v2";
const SOURCE_HASH_DOMAIN: &str =
    "sealed-lattice/pair-character-static-resource-accounting/source/v1";
const BUILD_HASH_DOMAIN: &str = "sealed-lattice/pair-character-static-resource-accounting/build/v1";
const CANDIDATE_INPUT_HASH_DOMAIN: &str =
    "sealed-lattice/pair-character-static-resource-accounting/input/v1";
const ATTACHMENT_FILE_NAME: &str = "pair-character-candidate-static-resource-accounting.json";
const MAXIMUM_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticResourceAccountingEnvelope {
    record_kind: String,
    record_version: u16,
    record_byte_length: u64,
    record_shake256_hex: String,
    record: StaticResourceAccountingRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticResourceAccountingRecord {
    source_identity: SourceIdentity,
    build_identity: BuildIdentity,
    candidate_input: CandidateInputIdentity,
    caps: StaticResourceCaps,
    physical_proof_families: DerivedSection<PhysicalProofTopology>,
    proof_variants: DerivedSection<ProofVariantAccounting>,
    target_release: DerivedSection<SelectedTargetReleaseStaticAccounting>,
    known_material_subtotals: DerivedSection<KnownMaterialSubtotals>,
    private_vss_mailbox_transport: DerivedSection<PrivateVssMailboxTransport>,
    unsigned_public_carriers: DerivedSection<UnsignedPublicCarrierAccounting>,
    product_alternatives: DerivedSection<ProductAlternatives>,
    evaluator_alternatives: DerivedSection<EvaluatorAlternatives>,
    phase_liveness: DerivedSection<SelectedCompleteActionPhaseLivenessAccounting>,
    derivation_errors: Vec<DerivationErrorRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DerivedSection<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derivation_error: Option<DerivationErrorRow>,
}

impl<T> DerivedSection<T> {
    fn derived(data: T) -> Self {
        Self {
            data: Some(data),
            derivation_error: None,
        }
    }

    fn failed(error: DerivationErrorRow) -> Self {
        Self {
            data: None,
            derivation_error: Some(error),
        }
    }

    fn require_exactly_one_branch(&self, location: &str) -> Result<(), String> {
        match (&self.data, &self.derivation_error) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err(format!("{location} contains both data and derivationError")),
            (None, None) => Err(format!(
                "{location} contains neither data nor derivationError"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DerivationErrorRow {
    dimension: String,
    reason_code: String,
    required_carrier: String,
}

fn derivation_error(
    dimension: impl Into<String>,
    reason_code: impl Into<String>,
    required_carrier: impl Into<String>,
) -> DerivationErrorRow {
    DerivationErrorRow {
        dimension: dimension.into(),
        reason_code: reason_code.into(),
        required_carrier: required_carrier.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceIdentity {
    file_count: u32,
    byte_length: u64,
    shake256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildIdentity {
    package_name: String,
    package_version: String,
    target_architecture: String,
    target_operating_system: String,
    debug_assertions: bool,
    test_executable_byte_length: u64,
    test_executable_shake256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateInputIdentity {
    selected_parameters: SelectedCandidateParameters,
    bgv_parameters_canonical_object_hash_hex: String,
    proof_profile_byte_length: u64,
    evaluator_program_byte_length: u64,
    combined_input_shake256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedCandidateParameters {
    participant_count: u16,
    polynomial_degree: u32,
    plaintext_modulus: u64,
    plaintext_extension_degree: u16,
    plaintext_extension_lane_count: u16,
    pair_character_ciphertext_count: u16,
    pair_character_counts: Vec<u16>,
    option_count: u16,
    minimum_score: u16,
    maximum_score: u16,
    maximum_accepted_ballot_count: u16,
    maximum_ballot_attempts_per_participant: u16,
    maximum_candidate_packages_per_action: u32,
    stream_chunk_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticResourceCaps {
    maximum_proof_byte_length: u64,
    maximum_proof_output_chunk_byte_length: u64,
    maximum_external_memory_transaction_chunk_byte_length: u64,
    maximum_external_memory_object_count: u64,
    maximum_external_memory_stored_byte_length: u64,
    maximum_proof_wasm_resident_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
    maximum_local_record_seal_invocations_per_active_root: u64,
    maximum_local_record_sealed_plaintext_bytes_per_active_root: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhysicalProofTopology {
    ordered_families: Vec<PhysicalProofFamily>,
    total_physical_proof_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhysicalProofFamily {
    application_statement_schema_identifier: u16,
    physical_proof_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofVariantAccounting {
    compiler_variant_count: u32,
    ordered_variants: Vec<ProofVariantRow>,
    ordered_family_totals: Vec<ProofFamilyTotals>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete_action_totals: Option<ProofCompleteActionTotals>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofVariantRow {
    application_statement_schema_identifier: u16,
    selector: ProofVariantSelector,
    relation_column_count: u32,
    relation_constraint_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement: Option<ProofVariantRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derivation_error: Option<DerivationErrorRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ProofVariantSelector {
    Unparameterized,
    SchedulePosition { schedule_position: u32 },
    TopCount { top_count: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofVariantRequirement {
    complete_action_application_multiplicity: u32,
    logical_entry_count: u32,
    opening_claim_count: u32,
    relation_geometry: ProofRelationGeometry,
    proof_byte_length_ceiling: u64,
    canonical_header_byte_length_ceiling: u64,
    body_prefix_byte_length_ceiling: u64,
    query_section_byte_length_ceiling: u64,
    proof_components: ProofComponentByteAccounting,
    query_resources: ProofQueryResources,
    resident_memory: ProofResidentMemoryAccounting,
    maximum_proof_output_chunk_byte_length_ceiling: u64,
    proof_output_chunk_count_ceiling: u64,
    external_memory: ProofExternalMemoryRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofRelationGeometry {
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    verifier_sequence_relation_column_count: u32,
    bound_tree_relation_column_count: u32,
    prover_relation_column_count: u32,
    quotient_decomposition_stride: u64,
    quotient_component_degree_bound_exclusive: u64,
    quotient_component_count: u16,
    fri_fold_count: u16,
    terminal_coefficient_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofQueryResources {
    unique_query_count: u32,
    query_orbit_count: u64,
    bound_public_tree_count: u32,
    total_materialized_row_width: u64,
    maximum_prefetched_query_byte_length_ceiling: u64,
    ordered_trees: Vec<ProofQueryTreeResourceAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofQueryTreeResourceAccounting {
    tree_catalog_index: u16,
    is_bound_public_tree: bool,
    materialized_row_width: u64,
    leaf_count: u64,
    minimum_opened_leaf_count: u64,
    maximum_opened_leaf_count: u64,
    opened_leaf_count_at_ceiling: u64,
    authentication_frontier_node_count_at_ceiling: u64,
    opened_leaf_payload_byte_length_ceiling: u64,
    authentication_frontier_digest_byte_length_ceiling: u64,
    canonical_framing_byte_length_ceiling: u64,
    byte_length_ceiling: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofResidentMemoryAccounting {
    maximum_combined_wasm_resident_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
    ordered_phases: Vec<ProofResidentPhaseResourceAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofResidentPhaseResourceAccounting {
    phase_code: u8,
    phase_name: String,
    prover_resident_byte_length: u64,
    source_provider_persistent_resident_byte_length: u64,
    source_provider_loading_transient_byte_length: u64,
    application_runtime_persistent_resident_byte_length: u64,
    application_runtime_boundary_overlap_byte_length: u64,
    checkpoint_custody_byte_length: u64,
    combined_wasm_resident_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofComponentByteAccounting {
    canonical_framing_byte_length_ceiling: u64,
    relation_commitments_and_openings_byte_length_ceiling: u64,
    quotient_commitments_and_openings_byte_length_ceiling: u64,
    transcript_opening_claims_byte_length_ceiling: u64,
    fri_byte_length_ceiling: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofExternalMemoryRequirement {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofFamilyTotals {
    application_statement_schema_identifier: u16,
    physical_proof_count: u32,
    logical_entry_count: u64,
    proof_byte_length_ceiling: u64,
    canonical_header_byte_length_ceiling: u64,
    body_prefix_byte_length_ceiling: u64,
    query_section_byte_length_ceiling: u64,
    canonical_framing_byte_length_ceiling: u64,
    relation_commitments_and_openings_byte_length_ceiling: u64,
    quotient_commitments_and_openings_byte_length_ceiling: u64,
    transcript_opening_claims_byte_length_ceiling: u64,
    fri_byte_length_ceiling: u64,
    proof_output_chunk_count_ceiling: u64,
    external_memory_step_count: u64,
    external_memory_distinct_physical_object_count: u64,
    external_memory_object_lifecycle_count: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    external_memory_local_record_seal_invocation_count: u64,
    external_memory_local_record_sealed_plaintext_byte_length: u64,
    maximum_external_memory_object_count_per_proof: u32,
    maximum_external_memory_peak_stored_byte_length_per_proof: u64,
    maximum_external_memory_transaction_payload_byte_length: u64,
    maximum_combined_wasm_resident_byte_length_per_proof: u64,
    maximum_prefetched_query_byte_length_per_proof_ceiling: u64,
    maximum_copied_buffer_byte_length_per_proof: u64,
    maximum_local_record_seal_invocation_count_per_proof: u64,
    maximum_local_record_sealed_plaintext_byte_length_per_proof: u64,
    ordered_resident_phase_maxima: Vec<ProofResidentPhaseResourceAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofCompleteActionTotals {
    physical_proof_count: u32,
    logical_entry_count: u64,
    proof_byte_length_ceiling: u64,
    canonical_header_byte_length_ceiling: u64,
    body_prefix_byte_length_ceiling: u64,
    query_section_byte_length_ceiling: u64,
    canonical_framing_byte_length_ceiling: u64,
    relation_commitments_and_openings_byte_length_ceiling: u64,
    quotient_commitments_and_openings_byte_length_ceiling: u64,
    transcript_opening_claims_byte_length_ceiling: u64,
    fri_byte_length_ceiling: u64,
    proof_output_chunk_count_ceiling: u64,
    external_memory_step_count: u64,
    external_memory_distinct_physical_object_count: u64,
    external_memory_object_lifecycle_count: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    external_memory_local_record_seal_invocation_count: u64,
    external_memory_local_record_sealed_plaintext_byte_length: u64,
    maximum_external_memory_object_count_per_proof: u32,
    maximum_external_memory_peak_stored_byte_length_per_proof: u64,
    maximum_external_memory_transaction_payload_byte_length: u64,
    maximum_combined_wasm_resident_byte_length_per_proof: u64,
    maximum_prefetched_query_byte_length_per_proof_ceiling: u64,
    maximum_copied_buffer_byte_length_per_proof: u64,
    maximum_local_record_seal_invocation_count_per_proof: u64,
    maximum_local_record_sealed_plaintext_byte_length_per_proof: u64,
    ordered_resident_phase_maxima: Vec<ProofResidentPhaseResourceAccounting>,
}

#[derive(Clone, Debug, Default)]
struct ProofTotalsAccumulator {
    physical_proof_count: u32,
    logical_entry_count: u64,
    proof_byte_length_ceiling: u64,
    canonical_header_byte_length_ceiling: u64,
    body_prefix_byte_length_ceiling: u64,
    query_section_byte_length_ceiling: u64,
    canonical_framing_byte_length_ceiling: u64,
    relation_commitments_and_openings_byte_length_ceiling: u64,
    quotient_commitments_and_openings_byte_length_ceiling: u64,
    transcript_opening_claims_byte_length_ceiling: u64,
    fri_byte_length_ceiling: u64,
    proof_output_chunk_count_ceiling: u64,
    external_memory_step_count: u64,
    external_memory_distinct_physical_object_count: u64,
    external_memory_object_lifecycle_count: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    external_memory_local_record_seal_invocation_count: u64,
    external_memory_local_record_sealed_plaintext_byte_length: u64,
    maximum_external_memory_object_count_per_proof: u32,
    maximum_external_memory_peak_stored_byte_length_per_proof: u64,
    maximum_external_memory_transaction_payload_byte_length: u64,
    maximum_combined_wasm_resident_byte_length_per_proof: u64,
    maximum_prefetched_query_byte_length_per_proof_ceiling: u64,
    maximum_copied_buffer_byte_length_per_proof: u64,
    maximum_local_record_seal_invocation_count_per_proof: u64,
    maximum_local_record_sealed_plaintext_byte_length_per_proof: u64,
    resident_phase_maxima: BTreeMap<u8, ProofResidentPhaseResourceAccounting>,
}

impl ProofTotalsAccumulator {
    fn include(&mut self, requirement: &ProofVariantRequirement) -> Result<(), String> {
        let multiplicity = requirement.complete_action_application_multiplicity;
        self.physical_proof_count = self
            .physical_proof_count
            .checked_add(multiplicity)
            .ok_or_else(|| "physical proof count overflow".to_owned())?;
        let multiplicity_u64 = u64::from(multiplicity);
        macro_rules! add_scaled {
            ($field:ident, $value:expr) => {{
                let scaled = ($value)
                    .checked_mul(multiplicity_u64)
                    .ok_or_else(|| concat!(stringify!($field), " product overflow").to_owned())?;
                self.$field = self
                    .$field
                    .checked_add(scaled)
                    .ok_or_else(|| concat!(stringify!($field), " sum overflow").to_owned())?;
            }};
        }
        add_scaled!(
            logical_entry_count,
            u64::from(requirement.logical_entry_count)
        );
        add_scaled!(
            proof_byte_length_ceiling,
            requirement.proof_byte_length_ceiling
        );
        add_scaled!(
            canonical_header_byte_length_ceiling,
            requirement.canonical_header_byte_length_ceiling
        );
        add_scaled!(
            body_prefix_byte_length_ceiling,
            requirement.body_prefix_byte_length_ceiling
        );
        add_scaled!(
            query_section_byte_length_ceiling,
            requirement.query_section_byte_length_ceiling
        );
        add_scaled!(
            canonical_framing_byte_length_ceiling,
            requirement
                .proof_components
                .canonical_framing_byte_length_ceiling
        );
        add_scaled!(
            relation_commitments_and_openings_byte_length_ceiling,
            requirement
                .proof_components
                .relation_commitments_and_openings_byte_length_ceiling
        );
        add_scaled!(
            quotient_commitments_and_openings_byte_length_ceiling,
            requirement
                .proof_components
                .quotient_commitments_and_openings_byte_length_ceiling
        );
        add_scaled!(
            transcript_opening_claims_byte_length_ceiling,
            requirement
                .proof_components
                .transcript_opening_claims_byte_length_ceiling
        );
        add_scaled!(
            fri_byte_length_ceiling,
            requirement.proof_components.fri_byte_length_ceiling
        );
        add_scaled!(
            proof_output_chunk_count_ceiling,
            requirement.proof_output_chunk_count_ceiling
        );
        add_scaled!(
            external_memory_step_count,
            u64::from(requirement.external_memory.step_count)
        );
        add_scaled!(
            external_memory_distinct_physical_object_count,
            u64::from(requirement.external_memory.distinct_physical_object_count)
        );
        add_scaled!(
            external_memory_object_lifecycle_count,
            u64::from(requirement.external_memory.object_lifecycle_count)
        );
        add_scaled!(
            external_memory_total_written_byte_length,
            requirement.external_memory.total_written_byte_length
        );
        add_scaled!(
            external_memory_total_read_byte_length,
            requirement.external_memory.total_read_byte_length
        );
        add_scaled!(
            external_memory_transaction_count,
            requirement.external_memory.transaction_count
        );
        add_scaled!(
            external_memory_local_record_seal_invocation_count,
            requirement
                .external_memory
                .local_record_seal_invocation_count
        );
        add_scaled!(
            external_memory_local_record_sealed_plaintext_byte_length,
            requirement
                .external_memory
                .local_record_sealed_plaintext_byte_length
        );
        if multiplicity != 0 {
            self.maximum_external_memory_object_count_per_proof = self
                .maximum_external_memory_object_count_per_proof
                .max(requirement.external_memory.distinct_physical_object_count);
            self.maximum_external_memory_peak_stored_byte_length_per_proof = self
                .maximum_external_memory_peak_stored_byte_length_per_proof
                .max(requirement.external_memory.peak_stored_byte_length);
            self.maximum_external_memory_transaction_payload_byte_length = self
                .maximum_external_memory_transaction_payload_byte_length
                .max(
                    requirement
                        .external_memory
                        .maximum_transaction_payload_byte_length,
                );
            self.maximum_combined_wasm_resident_byte_length_per_proof = self
                .maximum_combined_wasm_resident_byte_length_per_proof
                .max(
                    requirement
                        .resident_memory
                        .maximum_combined_wasm_resident_byte_length,
                );
            self.maximum_prefetched_query_byte_length_per_proof_ceiling = self
                .maximum_prefetched_query_byte_length_per_proof_ceiling
                .max(
                    requirement
                        .query_resources
                        .maximum_prefetched_query_byte_length_ceiling,
                );
            self.maximum_copied_buffer_byte_length_per_proof =
                self.maximum_copied_buffer_byte_length_per_proof.max(
                    requirement
                        .resident_memory
                        .maximum_copied_buffer_byte_length,
                );
            self.maximum_local_record_seal_invocation_count_per_proof = self
                .maximum_local_record_seal_invocation_count_per_proof
                .max(
                    requirement
                        .external_memory
                        .local_record_seal_invocation_count,
                );
            self.maximum_local_record_sealed_plaintext_byte_length_per_proof = self
                .maximum_local_record_sealed_plaintext_byte_length_per_proof
                .max(
                    requirement
                        .external_memory
                        .local_record_sealed_plaintext_byte_length,
                );
            for phase in &requirement.resident_memory.ordered_phases {
                match self.resident_phase_maxima.entry(phase.phase_code) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(phase.clone());
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        include_resident_phase_maximum(entry.get_mut(), phase)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn require_custody_totals(
        &self,
        external_memory_local_record_seal_invocation_count: u64,
        external_memory_local_record_sealed_plaintext_byte_length: u64,
        maximum_local_record_seal_invocation_count_per_proof: u64,
        maximum_local_record_sealed_plaintext_byte_length_per_proof: u64,
        location: &str,
    ) -> Result<(), String> {
        if self.external_memory_local_record_seal_invocation_count
            != external_memory_local_record_seal_invocation_count
            || self.external_memory_local_record_sealed_plaintext_byte_length
                != external_memory_local_record_sealed_plaintext_byte_length
            || self.maximum_local_record_seal_invocation_count_per_proof
                != maximum_local_record_seal_invocation_count_per_proof
            || self.maximum_local_record_sealed_plaintext_byte_length_per_proof
                != maximum_local_record_sealed_plaintext_byte_length_per_proof
        {
            return Err(format!(
                "{location} does not recompute its multiplicity-scaled seal-custody ledger"
            ));
        }
        Ok(())
    }

    fn family_totals(self, application_statement_schema_identifier: u16) -> ProofFamilyTotals {
        ProofFamilyTotals {
            application_statement_schema_identifier,
            physical_proof_count: self.physical_proof_count,
            logical_entry_count: self.logical_entry_count,
            proof_byte_length_ceiling: self.proof_byte_length_ceiling,
            canonical_header_byte_length_ceiling: self.canonical_header_byte_length_ceiling,
            body_prefix_byte_length_ceiling: self.body_prefix_byte_length_ceiling,
            query_section_byte_length_ceiling: self.query_section_byte_length_ceiling,
            canonical_framing_byte_length_ceiling: self.canonical_framing_byte_length_ceiling,
            relation_commitments_and_openings_byte_length_ceiling: self
                .relation_commitments_and_openings_byte_length_ceiling,
            quotient_commitments_and_openings_byte_length_ceiling: self
                .quotient_commitments_and_openings_byte_length_ceiling,
            transcript_opening_claims_byte_length_ceiling: self
                .transcript_opening_claims_byte_length_ceiling,
            fri_byte_length_ceiling: self.fri_byte_length_ceiling,
            proof_output_chunk_count_ceiling: self.proof_output_chunk_count_ceiling,
            external_memory_step_count: self.external_memory_step_count,
            external_memory_distinct_physical_object_count: self
                .external_memory_distinct_physical_object_count,
            external_memory_object_lifecycle_count: self.external_memory_object_lifecycle_count,
            external_memory_total_written_byte_length: self
                .external_memory_total_written_byte_length,
            external_memory_total_read_byte_length: self.external_memory_total_read_byte_length,
            external_memory_transaction_count: self.external_memory_transaction_count,
            external_memory_local_record_seal_invocation_count: self
                .external_memory_local_record_seal_invocation_count,
            external_memory_local_record_sealed_plaintext_byte_length: self
                .external_memory_local_record_sealed_plaintext_byte_length,
            maximum_external_memory_object_count_per_proof: self
                .maximum_external_memory_object_count_per_proof,
            maximum_external_memory_peak_stored_byte_length_per_proof: self
                .maximum_external_memory_peak_stored_byte_length_per_proof,
            maximum_external_memory_transaction_payload_byte_length: self
                .maximum_external_memory_transaction_payload_byte_length,
            maximum_combined_wasm_resident_byte_length_per_proof: self
                .maximum_combined_wasm_resident_byte_length_per_proof,
            maximum_prefetched_query_byte_length_per_proof_ceiling: self
                .maximum_prefetched_query_byte_length_per_proof_ceiling,
            maximum_copied_buffer_byte_length_per_proof: self
                .maximum_copied_buffer_byte_length_per_proof,
            maximum_local_record_seal_invocation_count_per_proof: self
                .maximum_local_record_seal_invocation_count_per_proof,
            maximum_local_record_sealed_plaintext_byte_length_per_proof: self
                .maximum_local_record_sealed_plaintext_byte_length_per_proof,
            ordered_resident_phase_maxima: self.resident_phase_maxima.into_values().collect(),
        }
    }

    fn complete_action_totals(self) -> ProofCompleteActionTotals {
        ProofCompleteActionTotals {
            physical_proof_count: self.physical_proof_count,
            logical_entry_count: self.logical_entry_count,
            proof_byte_length_ceiling: self.proof_byte_length_ceiling,
            canonical_header_byte_length_ceiling: self.canonical_header_byte_length_ceiling,
            body_prefix_byte_length_ceiling: self.body_prefix_byte_length_ceiling,
            query_section_byte_length_ceiling: self.query_section_byte_length_ceiling,
            canonical_framing_byte_length_ceiling: self.canonical_framing_byte_length_ceiling,
            relation_commitments_and_openings_byte_length_ceiling: self
                .relation_commitments_and_openings_byte_length_ceiling,
            quotient_commitments_and_openings_byte_length_ceiling: self
                .quotient_commitments_and_openings_byte_length_ceiling,
            transcript_opening_claims_byte_length_ceiling: self
                .transcript_opening_claims_byte_length_ceiling,
            fri_byte_length_ceiling: self.fri_byte_length_ceiling,
            proof_output_chunk_count_ceiling: self.proof_output_chunk_count_ceiling,
            external_memory_step_count: self.external_memory_step_count,
            external_memory_distinct_physical_object_count: self
                .external_memory_distinct_physical_object_count,
            external_memory_object_lifecycle_count: self.external_memory_object_lifecycle_count,
            external_memory_total_written_byte_length: self
                .external_memory_total_written_byte_length,
            external_memory_total_read_byte_length: self.external_memory_total_read_byte_length,
            external_memory_transaction_count: self.external_memory_transaction_count,
            external_memory_local_record_seal_invocation_count: self
                .external_memory_local_record_seal_invocation_count,
            external_memory_local_record_sealed_plaintext_byte_length: self
                .external_memory_local_record_sealed_plaintext_byte_length,
            maximum_external_memory_object_count_per_proof: self
                .maximum_external_memory_object_count_per_proof,
            maximum_external_memory_peak_stored_byte_length_per_proof: self
                .maximum_external_memory_peak_stored_byte_length_per_proof,
            maximum_external_memory_transaction_payload_byte_length: self
                .maximum_external_memory_transaction_payload_byte_length,
            maximum_combined_wasm_resident_byte_length_per_proof: self
                .maximum_combined_wasm_resident_byte_length_per_proof,
            maximum_prefetched_query_byte_length_per_proof_ceiling: self
                .maximum_prefetched_query_byte_length_per_proof_ceiling,
            maximum_copied_buffer_byte_length_per_proof: self
                .maximum_copied_buffer_byte_length_per_proof,
            maximum_local_record_seal_invocation_count_per_proof: self
                .maximum_local_record_seal_invocation_count_per_proof,
            maximum_local_record_sealed_plaintext_byte_length_per_proof: self
                .maximum_local_record_sealed_plaintext_byte_length_per_proof,
            ordered_resident_phase_maxima: self.resident_phase_maxima.into_values().collect(),
        }
    }
}

fn include_resident_phase_maximum(
    maximum: &mut ProofResidentPhaseResourceAccounting,
    row: &ProofResidentPhaseResourceAccounting,
) -> Result<(), String> {
    if maximum.phase_code != row.phase_code || maximum.phase_name != row.phase_name {
        return Err(format!(
            "resident phase identity mismatch for phase code {}",
            row.phase_code
        ));
    }
    require_resident_phase_sum(maximum)?;
    require_resident_phase_sum(row)?;
    if resident_phase_selection_key(row) > resident_phase_selection_key(maximum) {
        *maximum = row.clone();
    }
    Ok(())
}

fn require_resident_phase_sum(row: &ProofResidentPhaseResourceAccounting) -> Result<(), String> {
    let recomputed = row
        .prover_resident_byte_length
        .checked_add(row.source_provider_persistent_resident_byte_length)
        .and_then(|length| length.checked_add(row.source_provider_loading_transient_byte_length))
        .and_then(|length| {
            length.checked_add(row.application_runtime_persistent_resident_byte_length)
        })
        .and_then(|length| length.checked_add(row.application_runtime_boundary_overlap_byte_length))
        .and_then(|length| length.checked_add(row.checkpoint_custody_byte_length))
        .ok_or_else(|| {
            format!(
                "resident phase {} byte-length sum overflows",
                row.phase_name
            )
        })?;
    if recomputed != row.combined_wasm_resident_byte_length {
        return Err(format!(
            "resident phase {} combined byte length does not equal its component sum",
            row.phase_name
        ));
    }
    Ok(())
}

fn resident_phase_selection_key(row: &ProofResidentPhaseResourceAccounting) -> [u64; 7] {
    [
        row.combined_wasm_resident_byte_length,
        row.prover_resident_byte_length,
        row.source_provider_persistent_resident_byte_length,
        row.source_provider_loading_transient_byte_length,
        row.application_runtime_persistent_resident_byte_length,
        row.application_runtime_boundary_overlap_byte_length,
        row.checkpoint_custody_byte_length,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnownMaterialSubtotals {
    one_dealer_recipient_private_vss_payload_byte_length: u64,
    one_dealer_private_vss_payload_upload_byte_length: u64,
    one_recipient_private_vss_payload_download_byte_length: u64,
    ceremony_private_vss_payload_byte_length: u64,
    evaluator_source_wire_byte_length_per_participant: u64,
    evaluator_source_resident_byte_length_per_participant: u64,
    final_evaluator_key_store_wire_byte_length: u64,
    final_evaluator_key_store_resident_byte_length: u64,
    ceremony_evaluator_setup_wire_byte_length: u64,
    ceremony_evaluator_source_and_final_resident_volume_byte_length: u64,
    one_ballot_ciphertext_stream_byte_length: u64,
    one_ballot_ciphertext_stream_chunk_count: u32,
    complete_action_ballot_candidate_package_corpus_byte_length: u64,
    complete_action_ballot_candidate_package_corpus_chunk_count: u64,
    ballot_prover_material_live_set_peak_byte_length: u64,
    one_target_ciphertext_canonical_byte_length_ceiling: u64,
    paired_target_ciphertext_canonical_byte_length_ceiling: u64,
    one_target_partial_stream_byte_length: u64,
    one_participant_paired_target_partial_stream_byte_length: u64,
    ceremony_paired_target_partial_stream_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateVssMailboxTransport {
    participant_count: u16,
    physical_payload_stream_count: u64,
    ordered_material_root_count_per_envelope: u64,
    canonical_transport_primitive: CanonicalTransportPrimitive,
    complete_mailbox_byte_length: u64,
    one_dealer_upload_byte_length: u64,
    one_recipient_download_byte_length: u64,
    ceremony_upload_byte_length: u64,
    ceremony_download_byte_length: u64,
    private_mailbox_corpus_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalTransportPrimitive {
    payload_byte_length: u64,
    stream_chunk_count: u64,
    stream_descriptor_byte_length: u64,
    mailbox_associated_data_byte_length: u64,
    mailbox_kem_ciphertext_byte_length: u64,
    mailbox_gcm_tag_byte_length: u64,
    mailbox_source_signature_byte_length: u64,
    mailbox_fixed_cryptographic_material_byte_length: u64,
    signed_mailbox_envelope_byte_length: u64,
    boundary_transfer_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
    indexed_db_serialized_byte_length: u64,
    indexed_db_additional_copy_peak_byte_length: u64,
    indexed_db_serialization_buffer_peak_byte_length: u64,
    indexed_db_readback_buffer_peak_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnsignedPublicCarrierAccounting {
    unsigned_public_carrier_count: u64,
    unsigned_public_physical_stream_count: u64,
    aggregate_public_carrier: AggregatePublicCarrierAccounting,
    evaluator_replay_codec_ceiling: EvaluatorReplayCarrierCodecCeiling,
    exact_evaluator_replay: DerivedSection<EvaluatorReplayPublicCarrierAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AggregatePublicCarrierAccounting {
    selected_ballot_object_hash_count: u64,
    payload_binding_hash_count: u64,
    physical_ciphertext_stream_count: u64,
    one_ciphertext_stream_byte_length: u64,
    one_ciphertext_stream_chunk_count: u64,
    one_stream_descriptor_hash_count: u64,
    one_stream_descriptor_byte_length: u64,
    ciphertext_stream_corpus_byte_length: u64,
    ciphertext_stream_corpus_chunk_count: u64,
    canonical_payload_byte_length: u64,
    canonical_payload_framing_byte_length: u64,
    canonical_envelope_binding_hash_count: u64,
    canonical_envelope_byte_length: u64,
    canonical_envelope_framing_byte_length: u64,
    complete_public_object_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluatorReplayCarrierCodecCeiling {
    target_ciphertext_stream_byte_length_ceiling: u64,
    target_ciphertext_stream_chunk_count_ceiling: u64,
    canonical_envelope_byte_length_ceiling: u64,
    complete_public_object_byte_length_ceiling: u64,
    carrier_accounting_at_codec_ceiling: EvaluatorReplayPublicCarrierAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluatorReplayPublicCarrierAccounting {
    payload_binding_hash_count: u64,
    physical_ciphertext_stream_count: u64,
    target_identifier_stream_byte_length: u64,
    target_identifier_stream_chunk_count: u64,
    target_identifier_stream_descriptor_hash_count: u64,
    target_identifier_stream_descriptor_byte_length: u64,
    target_order_stream_byte_length: u64,
    target_order_stream_chunk_count: u64,
    target_order_stream_descriptor_hash_count: u64,
    target_order_stream_descriptor_byte_length: u64,
    ciphertext_stream_corpus_byte_length: u64,
    ciphertext_stream_corpus_chunk_count: u64,
    canonical_payload_byte_length: u64,
    canonical_payload_framing_byte_length: u64,
    canonical_envelope_binding_hash_count: u64,
    canonical_envelope_byte_length: u64,
    canonical_envelope_framing_byte_length: u64,
    complete_public_object_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductAlternatives {
    selected_complete_action_ballot_count: u16,
    ordered_ballot_counts: Vec<ProductAccountingRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductAccountingRow {
    ballot_count: u16,
    ballot_ciphertext_count: u32,
    ciphertext_multiplication_count: u32,
    relinearization_count: u32,
    normalization_plaintext_multiplication_count: u32,
    modulus_switch_count: u32,
    modulus_drop_count: u32,
    maximum_resident_ciphertext_count: u32,
    relinearization_key_load_count: u32,
    key_store_read_byte_count: u64,
    key_ntt_transform_count: u32,
    memory: ProductMemoryAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductMemoryAccounting {
    maximum_live_ciphertext_coefficient_byte_length: u64,
    relinearization_key_component_wire_byte_length: u64,
    resident_relinearization_key_coefficient_byte_length: u64,
    maximum_key_store_chunk_byte_length: u64,
    final_key_store_chunk_byte_length: u64,
    key_replay_limb_buffer_byte_length: u64,
    peak_key_replay_wasm_resident_byte_length: u64,
    maximum_ciphertext_tensor_transient_byte_length: u64,
    maximum_ciphertext_tensor_scratch_byte_length: u64,
    maximum_relinearization_transient_byte_length: u64,
    maximum_relinearization_scratch_byte_length: u64,
    maximum_plaintext_multiplication_transient_byte_length: u64,
    maximum_plaintext_multiplication_scratch_byte_length: u64,
    maximum_modulus_switch_transient_byte_length: u64,
    maximum_modulus_switch_scratch_byte_length: u64,
    maximum_operation_transient_byte_length: u64,
    maximum_operation_scratch_byte_length: u64,
    peak_combined_wasm_resident_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluatorAlternatives {
    ordered_top_counts: Vec<EvaluatorAccountingRow>,
    complete_action_maxima: EvaluatorResourceTotals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluatorAccountingRow {
    top_count: u16,
    totals: EvaluatorResourceTotals,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluatorResourceTotals {
    instruction_count: u64,
    key_operation_count: u64,
    key_load_count: u64,
    key_store_read_request_count: u64,
    key_store_reread_request_count: u64,
    key_store_read_byte_count: u64,
    key_store_reread_byte_count: u64,
    key_ntt_transform_count: u64,
    rotation_count: u64,
    ciphertext_multiplication_count: u64,
    plaintext_multiplication_count: u64,
    modulus_switch_count: u64,
    maximum_live_ciphertext_byte_count: u64,
    maximum_resident_key_byte_count: u64,
    maximum_operation_scratch_byte_count: u64,
    peak_combined_wasm_resident_byte_count: u64,
}

impl EvaluatorResourceTotals {
    fn include_maximum(&mut self, row: &Self) {
        self.instruction_count = self.instruction_count.max(row.instruction_count);
        self.key_operation_count = self.key_operation_count.max(row.key_operation_count);
        self.key_load_count = self.key_load_count.max(row.key_load_count);
        self.key_store_read_request_count = self
            .key_store_read_request_count
            .max(row.key_store_read_request_count);
        self.key_store_reread_request_count = self
            .key_store_reread_request_count
            .max(row.key_store_reread_request_count);
        self.key_store_read_byte_count = self
            .key_store_read_byte_count
            .max(row.key_store_read_byte_count);
        self.key_store_reread_byte_count = self
            .key_store_reread_byte_count
            .max(row.key_store_reread_byte_count);
        self.key_ntt_transform_count = self
            .key_ntt_transform_count
            .max(row.key_ntt_transform_count);
        self.rotation_count = self.rotation_count.max(row.rotation_count);
        self.ciphertext_multiplication_count = self
            .ciphertext_multiplication_count
            .max(row.ciphertext_multiplication_count);
        self.plaintext_multiplication_count = self
            .plaintext_multiplication_count
            .max(row.plaintext_multiplication_count);
        self.modulus_switch_count = self.modulus_switch_count.max(row.modulus_switch_count);
        self.maximum_live_ciphertext_byte_count = self
            .maximum_live_ciphertext_byte_count
            .max(row.maximum_live_ciphertext_byte_count);
        self.maximum_resident_key_byte_count = self
            .maximum_resident_key_byte_count
            .max(row.maximum_resident_key_byte_count);
        self.maximum_operation_scratch_byte_count = self
            .maximum_operation_scratch_byte_count
            .max(row.maximum_operation_scratch_byte_count);
        self.peak_combined_wasm_resident_byte_count = self
            .peak_combined_wasm_resident_byte_count
            .max(row.peak_combined_wasm_resident_byte_count);
    }
}

fn derive_static_resource_accounting_record() -> Result<StaticResourceAccountingRecord, String> {
    let source_identity = derive_source_identity()?;
    let build_identity = derive_build_identity()?;
    let candidate_input = derive_candidate_input_identity()?;
    let caps = derive_caps()?;
    let mut derivation_errors = required_missing_dimension_errors();

    let physical_proof_families = section(
        derive_physical_proof_topology(),
        "physical-proof-topology",
        "physical-proof-topology-derivation-failed",
        "ProofApplicationSlotCeilings derived from the selected evaluator schedules",
        &mut derivation_errors,
    );
    let proof_variants = section(
        derive_proof_variant_accounting(&mut derivation_errors),
        "proof-variant-accounting",
        "proof-variant-report-derivation-failed",
        "cap-neutral selected proof diagnostic report",
        &mut derivation_errors,
    );
    let target_release = section(
        selected_target_share_proof_byte_length_ceiling(&proof_variants).and_then(
            |proof_byte_length_ceiling| {
                derive_target_release_accounting(proof_byte_length_ceiling, &mut derivation_errors)
            },
        ),
        "target-release-static-accounting",
        "target-release-static-accounting-derivation-failed",
        "selected target-release static accounting using the target-share proof byte-length ceiling",
        &mut derivation_errors,
    );
    let known_material_subtotals = section(
        derive_known_material_subtotals(),
        "known-material-subtotals",
        "known-material-subtotal-derivation-failed",
        "selected complete-action material subtotal derivation",
        &mut derivation_errors,
    );
    let private_vss_mailbox_transport = section(
        derive_private_vss_mailbox_transport(),
        "private-vss-mailbox-transport",
        "private-vss-mailbox-transport-derivation-failed",
        "selected recipient-private VSS canonical mailbox transport accounting",
        &mut derivation_errors,
    );
    let unsigned_public_carriers = section(
        derive_unsigned_public_carriers(&mut derivation_errors),
        "unsigned-public-carriers",
        "unsigned-public-carrier-derivation-failed",
        "production aggregate carrier and evaluator-replay codec accounting",
        &mut derivation_errors,
    );
    let product_alternatives = section(
        derive_product_alternatives(),
        "two-stream-product-alternatives",
        "two-stream-product-accounting-derivation-failed",
        "canonical two-stream pair-character product accounting",
        &mut derivation_errors,
    );
    let evaluator_alternatives = section(
        derive_evaluator_alternatives(),
        "evaluator-alternatives",
        "evaluator-accounting-derivation-failed",
        "selected evaluator execution resource ledger",
        &mut derivation_errors,
    );
    let phase_liveness = section(
        derive_phase_liveness(&mut derivation_errors),
        "complete-action-phase-liveness",
        "phase-liveness-derivation-failed",
        "selected complete-action phase-liveness accounting",
        &mut derivation_errors,
    );
    deduplicate_top_level_derivation_errors(&mut derivation_errors);

    Ok(StaticResourceAccountingRecord {
        source_identity,
        build_identity,
        candidate_input,
        caps,
        physical_proof_families,
        proof_variants,
        target_release,
        known_material_subtotals,
        private_vss_mailbox_transport,
        unsigned_public_carriers,
        product_alternatives,
        evaluator_alternatives,
        phase_liveness,
        derivation_errors,
    })
}

fn deduplicate_top_level_derivation_errors(errors: &mut Vec<DerivationErrorRow>) {
    let mut observed = BTreeSet::new();
    errors.retain(|error| {
        observed.insert((
            error.dimension.clone(),
            error.reason_code.clone(),
            error.required_carrier.clone(),
        ))
    });
}

fn derive_phase_liveness(
    derivation_errors: &mut Vec<DerivationErrorRow>,
) -> Result<SelectedCompleteActionPhaseLivenessAccounting, String> {
    let accounting = derive_selected_complete_action_phase_liveness_accounting()
        .map_err(|error| format!("selected phase liveness does not derive: {error:?}"))?;
    derivation_errors.extend(accounting.missing_carriers().iter().map(|carrier| {
        derivation_error(
            carrier.dimension(),
            carrier.reason_code(),
            carrier.required_carrier(),
        )
    }));
    Ok(accounting)
}

fn section<T>(
    result: Result<T, String>,
    dimension: &str,
    reason_code: &str,
    required_carrier: &str,
    errors: &mut Vec<DerivationErrorRow>,
) -> DerivedSection<T> {
    match result {
        Ok(data) => DerivedSection::derived(data),
        Err(error) => {
            let row = derivation_error(
                dimension,
                reason_code,
                format!("{required_carrier}: {error}"),
            );
            errors.push(row.clone());
            DerivedSection::failed(row)
        }
    }
}

fn required_missing_dimension_errors() -> Vec<DerivationErrorRow> {
    vec![
        derivation_error(
            "canonical-material-transport",
            "remaining-material-transport-carriers-absent",
            "production-derived route and ordered-root topology for every material family beyond recipient-private VSS and the exact aggregate public carrier; exact evaluator replay is tracked separately",
        ),
        derivation_error(
            "directional-ceremony-traffic",
            "remaining-directional-traffic-carriers-absent",
            "per-participant upload and download plus public routing and multiplicity beyond the recipient-private VSS mailbox",
        ),
        derivation_error(
            "public-transcript-corpus",
            "public-transcript-corpus-carrier-absent",
            "complete public setup, state, finality, ballot, evaluator, and target-release corpus topology beyond the exact aggregate object",
        ),
        derivation_error(
            "non-proof-persistence-and-io",
            "complete-persistence-carrier-absent",
            "persistent storage, temporary scratch, allocation volume, total reads, total writes, and transaction counts for every non-proof family",
        ),
        derivation_error(
            "browser-boundary-memory",
            "browser-copy-carrier-absent",
            "per-family JavaScript, WebAssembly, transfer, IndexedDB serialization, and IndexedDB readback overlap accounting",
        ),
    ]
}

fn derive_source_identity() -> Result<SourceIdentity, String> {
    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository_root = manifest_directory
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "kernel manifest directory has no repository root".to_owned())?;
    let mut source_paths = Vec::new();
    collect_rust_source_paths(&manifest_directory.join("src"), &mut source_paths)?;
    source_paths.extend([
        repository_root.join("Cargo.toml"),
        repository_root.join("Cargo.lock"),
        repository_root.join("rust-toolchain.toml"),
        manifest_directory.join("Cargo.toml"),
    ]);
    source_paths.sort();
    source_paths.dedup();
    if source_paths.is_empty() {
        return Err("source identity has no input files".to_owned());
    }
    let part_count = u64::try_from(source_paths.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| "source identity part count overflow".to_owned())?;
    let mut hasher = StreamingHash512::new(SOURCE_HASH_DOMAIN, part_count);
    let mut total_byte_length = 0_u64;
    for source_path in &source_paths {
        let relative_path = normalized_relative_path(repository_root, source_path)?;
        hasher.absorb_part(relative_path.as_bytes());
        total_byte_length = total_byte_length
            .checked_add(absorb_file_part(&mut hasher, source_path)?)
            .ok_or_else(|| "source identity byte length overflow".to_owned())?;
    }
    Ok(SourceIdentity {
        file_count: u32::try_from(source_paths.len())
            .map_err(|_| "source identity file count does not fit u32".to_owned())?,
        byte_length: total_byte_length,
        shake256_hex: to_hex(&hasher.finalize()),
    })
}

fn collect_rust_source_paths(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot read source directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read source directory entry in {}: {error}",
                directory.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "cannot inspect source path {}: {error}",
                entry.path().display()
            )
        })?;
        if file_type.is_symlink() {
            return Err(format!(
                "source identity refuses symbolic link {}",
                entry.path().display()
            ));
        }
        if file_type.is_dir() {
            collect_rust_source_paths(&entry.path(), output)?;
        } else if file_type.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
        {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn normalized_relative_path(repository_root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(repository_root).map_err(|_| {
        format!(
            "source path {} is outside repository root {}",
            path.display(),
            repository_root.display()
        )
    })?;
    relative
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("source path {} is not valid UTF-8", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn absorb_file_part(hasher: &mut StreamingHash512, path: &Path) -> Result<u64, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open identity input {}: {error}", path.display()))?;
    let declared_byte_length = file
        .metadata()
        .map_err(|error| format!("cannot stat identity input {}: {error}", path.display()))?
        .len();
    hasher.begin_part(declared_byte_length);
    let mut observed_byte_length = 0_u64;
    let mut buffer = [0_u8; 1_048_576];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read identity input {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.absorb_raw(&buffer[..count]);
        observed_byte_length = observed_byte_length
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| "identity read length does not fit u64".to_owned())?,
            )
            .ok_or_else(|| "identity read length overflow".to_owned())?;
    }
    if observed_byte_length != declared_byte_length {
        return Err(format!(
            "identity input {} changed while it was hashed",
            path.display()
        ));
    }
    Ok(observed_byte_length)
}

fn derive_build_identity() -> Result<BuildIdentity, String> {
    let executable_path = env::current_exe()
        .map_err(|error| format!("cannot resolve current test executable: {error}"))?;
    let mut hasher = StreamingHash512::new(BUILD_HASH_DOMAIN, 1);
    let test_executable_byte_length = absorb_file_part(&mut hasher, &executable_path)?;
    Ok(BuildIdentity {
        package_name: env!("CARGO_PKG_NAME").to_owned(),
        package_version: env!("CARGO_PKG_VERSION").to_owned(),
        target_architecture: env::consts::ARCH.to_owned(),
        target_operating_system: env::consts::OS.to_owned(),
        debug_assertions: cfg!(debug_assertions),
        test_executable_byte_length,
        test_executable_shake256_hex: to_hex(&hasher.finalize()),
    })
}

fn derive_candidate_input_identity() -> Result<CandidateInputIdentity, String> {
    let mut pair_character_counts = vec![0_u16; PAIR_CHARACTER_CIPHERTEXT_COUNT];
    for assignment in selected_pair_character_lane_assignments()
        .map_err(|error| format!("pair-character catalog does not derive: {error:?}"))?
    {
        let count = pair_character_counts
            .get_mut(usize::from(assignment.ciphertext_ordinal()))
            .ok_or_else(|| "pair-character catalog has an invalid ciphertext ordinal".to_owned())?;
        *count = count
            .checked_add(1)
            .ok_or_else(|| "pair-character count overflow".to_owned())?;
    }
    if pair_character_counts.contains(&0) {
        return Err("pair-character catalog leaves an empty ciphertext".to_owned());
    }
    let selected_parameters = SelectedCandidateParameters {
        participant_count: FOUNDATION_PROFILE.participant_count,
        polynomial_degree: u32::try_from(POLYNOMIAL_DEGREE)
            .map_err(|_| "polynomial degree does not fit u32".to_owned())?,
        plaintext_modulus: PLAINTEXT_MODULUS,
        plaintext_extension_degree: u16::try_from(PLAINTEXT_EXTENSION_DEGREE)
            .map_err(|_| "plaintext extension degree does not fit u16".to_owned())?,
        plaintext_extension_lane_count: u16::try_from(PLAINTEXT_EXTENSION_LANE_COUNT)
            .map_err(|_| "plaintext extension lane count does not fit u16".to_owned())?,
        pair_character_ciphertext_count: u16::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .map_err(|_| "pair-character ciphertext count does not fit u16".to_owned())?,
        pair_character_counts,
        option_count: FOUNDATION_PROFILE.option_count,
        minimum_score: FOUNDATION_PROFILE.minimum_score,
        maximum_score: FOUNDATION_PROFILE.maximum_score,
        maximum_accepted_ballot_count: FOUNDATION_PROFILE.participant_count,
        maximum_ballot_attempts_per_participant: SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        maximum_candidate_packages_per_action: SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        stream_chunk_byte_length: u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| "stream chunk byte length does not fit u64".to_owned())?,
        maximum_copied_buffer_byte_length: u64::try_from(
            FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
        )
        .map_err(|_| "maximum copied buffer byte length does not fit u64".to_owned())?,
    };
    let bgv_parameters_canonical_object_hash_hex = bgv_parameters_hash()
        .map_err(|error| format!("BGV parameter hash does not derive: {error}"))?;
    let proof_profile_bytes =
        selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
            .map_err(|error| format!("selected proof profile does not derive: {error:?}"))?
            .canonical_bytes()
            .map_err(|error| format!("selected proof profile does not encode: {error:?}"))?;
    let evaluator_program_bytes = selected_evaluator_program_set()
        .map_err(|error| format!("selected evaluator program does not derive: {error}"))?
        .encode()
        .map_err(|error| format!("selected evaluator program does not encode: {error}"))?;
    let selected_parameter_bytes = serde_json::to_vec(&selected_parameters)
        .map_err(|error| format!("selected candidate parameters do not serialize: {error}"))?;
    let combined_input_shake256_hex = to_hex(&hash_framed_parts_512(
        CANDIDATE_INPUT_HASH_DOMAIN,
        &[
            bgv_parameters_canonical_object_hash_hex.as_bytes(),
            &proof_profile_bytes,
            &evaluator_program_bytes,
            &selected_parameter_bytes,
        ],
    ));
    Ok(CandidateInputIdentity {
        selected_parameters,
        bgv_parameters_canonical_object_hash_hex,
        proof_profile_byte_length: u64::try_from(proof_profile_bytes.len())
            .map_err(|_| "proof profile byte length does not fit u64".to_owned())?,
        evaluator_program_byte_length: u64::try_from(evaluator_program_bytes.len())
            .map_err(|_| "evaluator program byte length does not fit u64".to_owned())?,
        combined_input_shake256_hex,
    })
}

fn derive_caps() -> Result<StaticResourceCaps, String> {
    Ok(StaticResourceCaps {
        maximum_proof_byte_length: u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .map_err(|_| "maximum proof byte length does not fit u64".to_owned())?,
        maximum_proof_output_chunk_byte_length: u64::try_from(
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .map_err(|_| "maximum proof output chunk does not fit u64".to_owned())?,
        maximum_external_memory_transaction_chunk_byte_length: u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        ),
        maximum_external_memory_object_count: u64::try_from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        )
        .map_err(|_| "external-memory object cap does not fit u64".to_owned())?,
        maximum_external_memory_stored_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        maximum_proof_wasm_resident_byte_length: MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        maximum_copied_buffer_byte_length: u64::try_from(
            FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
        )
        .map_err(|_| "maximum copied buffer cap does not fit u64".to_owned())?,
        maximum_local_record_seal_invocations_per_active_root:
            MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
        maximum_local_record_sealed_plaintext_bytes_per_active_root:
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
    })
}

fn derive_physical_proof_topology() -> Result<PhysicalProofTopology, String> {
    let proof_family_inventory =
        derive_selected_proof_family_application_inventory().map_err(|error| {
            format!("proof-family application inventory does not derive: {error:?}")
        })?;
    let ordered_families = proof_family_inventory
        .ordered_family_entries()
        .iter()
        .map(|family| PhysicalProofFamily {
            application_statement_schema_identifier: family
                .application_statement_schema_identifier(),
            physical_proof_count: family.physical_proof_application_count(),
        })
        .collect::<Vec<_>>();
    let total_physical_proof_count = proof_family_inventory
        .total_physical_proof_application_count()
        .map_err(|error| format!("physical proof-application total does not derive: {error}"))?;
    Ok(PhysicalProofTopology {
        ordered_families,
        total_physical_proof_count,
    })
}

fn derive_proof_variant_accounting(
    derivation_errors: &mut Vec<DerivationErrorRow>,
) -> Result<ProofVariantAccounting, String> {
    let proof_family_inventory =
        derive_selected_proof_family_application_inventory().map_err(|error| {
            format!("proof-family application inventory does not derive: {error:?}")
        })?;
    let expected_physical_proof_application_count = proof_family_inventory
        .total_physical_proof_application_count()
        .map_err(|error| format!("physical proof-application total does not derive: {error}"))?;
    let expected_logical_relation_instance_count = u64::from(
        proof_family_inventory
            .total_logical_relation_instance_count()
            .map_err(|error| format!("logical relation-instance total does not derive: {error}"))?,
    );
    let diagnostic_rows = selected_proof_external_memory_diagnostic_report()
        .map_err(|error| format!("cap-neutral proof diagnostic does not derive: {error:?}"))?;
    let mut ordered_variants = Vec::with_capacity(diagnostic_rows.len());
    let mut family_accumulators = BTreeMap::<u16, ProofTotalsAccumulator>::new();
    let mut complete_action_accumulator = ProofTotalsAccumulator::default();
    let mut has_variant_error = false;
    for row in &diagnostic_rows {
        let selector = proof_variant_selector(row.schedule_position(), row.top_count())?;
        let schema_identifier = row.application_statement_schema_identifier();
        let relation_column_count = u32::try_from(row.relation_column_count())
            .map_err(|_| "relation column count does not fit u32".to_owned())?;
        let relation_constraint_count = u32::try_from(row.relation_constraint_count())
            .map_err(|_| "relation constraint count does not fit u32".to_owned())?;
        match row.outcome() {
            Ok(requirement) => {
                let requirement = proof_variant_requirement(requirement)?;
                family_accumulators
                    .entry(schema_identifier)
                    .or_default()
                    .include(&requirement)?;
                complete_action_accumulator.include(&requirement)?;
                ordered_variants.push(ProofVariantRow {
                    application_statement_schema_identifier: schema_identifier,
                    selector,
                    relation_column_count,
                    relation_constraint_count,
                    requirement: Some(requirement),
                    derivation_error: None,
                });
            }
            Err(error) => {
                has_variant_error = true;
                let error_row = proof_variant_derivation_error(schema_identifier, &selector, error);
                derivation_errors.push(error_row.clone());
                ordered_variants.push(ProofVariantRow {
                    application_statement_schema_identifier: schema_identifier,
                    selector,
                    relation_column_count,
                    relation_constraint_count,
                    requirement: None,
                    derivation_error: Some(error_row),
                });
            }
        }
    }
    if ordered_variants.len() != 31 {
        let error = derivation_error(
            "proof-variant-selector-inventory",
            "unexpected-proof-variant-count",
            format!(
                "selected proof profile must provide 31 variants, observed {}",
                ordered_variants.len()
            ),
        );
        derivation_errors.push(error);
        has_variant_error = true;
    }
    require_ordered_proof_variant_inventory(&ordered_variants)?;
    let mut ordered_family_totals = Vec::with_capacity(FIRST_PROFILE_APPLICATION_FAMILIES.len());
    for schema_identifier in FIRST_PROFILE_APPLICATION_FAMILIES {
        let accumulator = family_accumulators
            .remove(&schema_identifier)
            .ok_or_else(|| {
                format!("proof family 0x{schema_identifier:04x} has no successful diagnostic row")
            })?;
        let family_totals = accumulator.family_totals(schema_identifier);
        let expected_family = proof_family_inventory
            .family_entry(schema_identifier)
            .ok_or_else(|| {
                format!(
                    "proof-family application inventory has no schema 0x{schema_identifier:04x}"
                )
            })?;
        if family_totals.physical_proof_count != expected_family.physical_proof_application_count()
            || family_totals.logical_entry_count
                != u64::from(expected_family.logical_relation_instance_count())
        {
            derivation_errors.push(derivation_error(
                format!("proof-family-0x{schema_identifier:04x}-totals"),
                "unexpected-proof-family-count",
                format!(
                    "proof-family inventory requires {} physical applications and {} logical relation instances, observed {} and {}",
                    expected_family.physical_proof_application_count(),
                    expected_family.logical_relation_instance_count(),
                    family_totals.physical_proof_count,
                    family_totals.logical_entry_count,
                ),
            ));
            has_variant_error = true;
        }
        ordered_family_totals.push(family_totals);
    }
    if !family_accumulators.is_empty() {
        return Err("proof diagnostics contain an unknown family".to_owned());
    }
    let complete_action_totals = if has_variant_error {
        None
    } else {
        let totals = complete_action_accumulator.complete_action_totals();
        if totals.physical_proof_count != expected_physical_proof_application_count
            || totals.logical_entry_count != expected_logical_relation_instance_count
        {
            let error = derivation_error(
                "proof-complete-action-totals",
                "unexpected-proof-complete-action-count",
                format!(
                    "proof-family inventory requires {} physical applications and {} logical relation instances, observed {} and {}",
                    expected_physical_proof_application_count,
                    expected_logical_relation_instance_count,
                    totals.physical_proof_count,
                    totals.logical_entry_count,
                ),
            );
            derivation_errors.push(error);
            None
        } else {
            Some(totals)
        }
    };
    Ok(ProofVariantAccounting {
        compiler_variant_count: u32::try_from(ordered_variants.len())
            .map_err(|_| "proof variant count does not fit u32".to_owned())?,
        ordered_variants,
        ordered_family_totals,
        complete_action_totals,
    })
}

fn require_ordered_proof_variant_inventory(
    ordered_variants: &[ProofVariantRow],
) -> Result<(), String> {
    let evaluator_schema_identifier =
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let mut cursor = 0_usize;
    for schema_identifier in FIRST_PROFILE_APPLICATION_FAMILIES {
        let variant_count = if schema_identifier == evaluator_schema_identifier {
            usize::from(FOUNDATION_PROFILE.option_count)
        } else {
            1
        };
        for variant_ordinal in 0..variant_count {
            let row = ordered_variants.get(cursor).ok_or_else(|| {
                format!(
                    "proof variant inventory ended before schema 0x{schema_identifier:04x} variant {variant_ordinal}"
                )
            })?;
            if row.application_statement_schema_identifier != schema_identifier {
                return Err(format!(
                    "proof variant inventory expected schema 0x{schema_identifier:04x} at ordinal {cursor}, observed 0x{:04x}",
                    row.application_statement_schema_identifier
                ));
            }
            if schema_identifier == evaluator_schema_identifier {
                let expected_top_count = u16::try_from(variant_ordinal)
                    .ok()
                    .and_then(|ordinal| ordinal.checked_add(1))
                    .ok_or_else(|| "evaluator top-count ordinal overflow".to_owned())?;
                if row.selector
                    != (ProofVariantSelector::TopCount {
                        top_count: expected_top_count,
                    })
                {
                    return Err(format!(
                        "evaluator proof variant ordinal {cursor} does not carry top count {expected_top_count}"
                    ));
                }
            } else if matches!(row.selector, ProofVariantSelector::TopCount { .. }) {
                return Err(format!(
                    "non-evaluator proof schema 0x{schema_identifier:04x} carries a top-count selector"
                ));
            }
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| "proof variant inventory cursor overflow".to_owned())?;
        }
    }
    if cursor != ordered_variants.len() {
        return Err(format!(
            "proof variant inventory has {} trailing rows",
            ordered_variants.len() - cursor
        ));
    }
    Ok(())
}

fn selected_target_share_proof_byte_length_ceiling(
    proof_variants: &DerivedSection<ProofVariantAccounting>,
) -> Result<u64, String> {
    let accounting = proof_variants.data.as_ref().ok_or_else(|| {
        "proof variant accounting is unavailable for target-release accounting".to_owned()
    })?;
    let target_schema_identifier =
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;
    let mut matching_rows = accounting
        .ordered_variants
        .iter()
        .filter(|row| row.application_statement_schema_identifier == target_schema_identifier);
    let row = matching_rows
        .next()
        .ok_or_else(|| "target-share proof diagnostic row is absent".to_owned())?;
    if matching_rows.next().is_some() {
        return Err("target-share proof diagnostic row is not unique".to_owned());
    }
    if row.selector != ProofVariantSelector::Unparameterized {
        return Err("target-share proof diagnostic row has an unexpected selector".to_owned());
    }
    let requirement = row
        .requirement
        .as_ref()
        .ok_or_else(|| "target-share proof diagnostic requirement did not derive".to_owned())?;
    if requirement.complete_action_application_multiplicity
        != u32::from(FOUNDATION_PROFILE.participant_count)
        || requirement.logical_entry_count != 1
        || requirement.proof_byte_length_ceiling == 0
    {
        return Err(
            "target-share proof diagnostic topology is not the selected topology".to_owned(),
        );
    }
    Ok(requirement.proof_byte_length_ceiling)
}

fn derive_target_release_accounting(
    target_share_proof_byte_length_ceiling: u64,
    derivation_errors: &mut Vec<DerivationErrorRow>,
) -> Result<SelectedTargetReleaseStaticAccounting, String> {
    let accounting =
        derive_selected_target_release_static_accounting(target_share_proof_byte_length_ceiling)
            .map_err(|error| format!("selected target-release accounting failed: {error:?}"))?;
    derivation_errors.extend(
        accounting.gaps.iter().copied().map(|gap| {
            derivation_error(gap.dimension(), gap.reason_code(), gap.required_carrier())
        }),
    );
    Ok(accounting)
}

fn proof_variant_selector(
    schedule_position: Option<u32>,
    top_count: Option<u16>,
) -> Result<ProofVariantSelector, String> {
    match (schedule_position, top_count) {
        (None, None) => Ok(ProofVariantSelector::Unparameterized),
        (Some(schedule_position), None) => {
            Ok(ProofVariantSelector::SchedulePosition { schedule_position })
        }
        (None, Some(top_count)) => Ok(ProofVariantSelector::TopCount { top_count }),
        (Some(_), Some(_)) => {
            Err("proof variant cannot carry both a schedule position and a top count".to_owned())
        }
    }
}

fn proof_variant_requirement(
    requirement: SelectedProofExternalMemoryDiagnosticRequirement,
) -> Result<ProofVariantRequirement, String> {
    let components = requirement.proof_component_byte_accounting();
    let external_memory = requirement.external_memory_requirement();
    if requirement.maximum_external_memory_transaction_payload_byte_length()
        != external_memory.maximum_transaction_payload_byte_length()
    {
        return Err(
            "proof transport and external-memory transaction payload maxima differ".to_owned(),
        );
    }
    let exceeds_active_root_seal_custody_budget = external_memory
        .local_record_seal_invocation_count()
        > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
        || external_memory.local_record_sealed_plaintext_byte_length()
            > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT;
    if external_memory.exceeds_active_root_seal_custody_budget()
        != exceeds_active_root_seal_custody_budget
    {
        return Err("proof external-memory seal-custody comparison does not recompute".to_owned());
    }
    let query_resources = proof_query_resources(
        requirement.ordered_query_trees(),
        requirement.unique_query_count(),
        requirement.query_orbit_count(),
        requirement.bound_public_tree_count(),
        requirement.total_materialized_row_width(),
        requirement.maximum_prefetched_query_byte_length(),
    )?;
    let resident_memory = proof_resident_memory_accounting(
        requirement.resident_phases(),
        requirement.maximum_combined_wasm_resident_byte_length(),
        requirement.maximum_copied_buffer_byte_length(),
    )?;
    Ok(ProofVariantRequirement {
        complete_action_application_multiplicity: requirement
            .complete_action_application_multiplicity(),
        logical_entry_count: requirement.logical_entry_count(),
        opening_claim_count: requirement.opening_claim_count(),
        relation_geometry: ProofRelationGeometry {
            evaluation_domain_size: requirement.evaluation_domain_size(),
            opening_degree_bound_exclusive: requirement.opening_degree_bound_exclusive(),
            verifier_sequence_relation_column_count: requirement
                .verifier_sequence_relation_column_count(),
            bound_tree_relation_column_count: requirement.bound_tree_relation_column_count(),
            prover_relation_column_count: requirement.prover_relation_column_count(),
            quotient_decomposition_stride: requirement.quotient_decomposition_stride(),
            quotient_component_degree_bound_exclusive: requirement
                .quotient_component_degree_bound_exclusive(),
            quotient_component_count: requirement.quotient_component_count(),
            fri_fold_count: requirement.fri_fold_count(),
            terminal_coefficient_count: requirement.terminal_coefficient_count(),
        },
        proof_byte_length_ceiling: u64::try_from(requirement.proof_byte_length_ceiling())
            .map_err(|_| "proof byte length does not fit u64".to_owned())?,
        canonical_header_byte_length_ceiling: requirement.canonical_header_byte_length_ceiling(),
        body_prefix_byte_length_ceiling: requirement.body_prefix_byte_length_ceiling(),
        query_section_byte_length_ceiling: requirement.query_section_byte_length_ceiling(),
        proof_components: ProofComponentByteAccounting {
            canonical_framing_byte_length_ceiling: components
                .canonical_framing_byte_length_ceiling(),
            relation_commitments_and_openings_byte_length_ceiling: components
                .relation_commitments_and_openings_byte_length_ceiling(),
            quotient_commitments_and_openings_byte_length_ceiling: components
                .quotient_commitments_and_openings_byte_length_ceiling(),
            transcript_opening_claims_byte_length_ceiling: components
                .transcript_opening_claims_byte_length_ceiling(),
            fri_byte_length_ceiling: components.fri_byte_length_ceiling(),
        },
        query_resources,
        resident_memory,
        maximum_proof_output_chunk_byte_length_ceiling: requirement
            .maximum_proof_output_chunk_byte_length_ceiling(),
        proof_output_chunk_count_ceiling: requirement.proof_output_chunk_count_ceiling(),
        external_memory: ProofExternalMemoryRequirement {
            step_count: external_memory.step_count(),
            maximum_chunk_byte_length: external_memory.maximum_chunk_byte_length(),
            maximum_transaction_payload_byte_length: external_memory
                .maximum_transaction_payload_byte_length(),
            distinct_physical_object_count: external_memory.distinct_physical_object_count(),
            object_lifecycle_count: external_memory.object_lifecycle_count(),
            peak_stored_byte_length: external_memory.peak_stored_byte_length(),
            total_written_byte_length: external_memory.total_written_byte_length(),
            total_read_byte_length: external_memory.total_read_byte_length(),
            transaction_count: external_memory.transaction_count(),
            local_record_seal_invocation_count: external_memory
                .local_record_seal_invocation_count(),
            local_record_sealed_plaintext_byte_length: external_memory
                .local_record_sealed_plaintext_byte_length(),
        },
    })
}

fn proof_query_resources(
    ordered_query_trees: &[SelectedProofQueryTreeResourceAccounting],
    unique_query_count: u32,
    query_orbit_count: u64,
    expected_bound_public_tree_count: u32,
    expected_total_materialized_row_width: u64,
    expected_maximum_prefetched_query_byte_length_ceiling: u64,
) -> Result<ProofQueryResources, String> {
    if ordered_query_trees.is_empty() || unique_query_count == 0 || query_orbit_count == 0 {
        return Err("proof query accounting must be non-empty".to_owned());
    }
    let mut rows = Vec::with_capacity(ordered_query_trees.len());
    let mut bound_public_tree_count = 0_u32;
    let mut total_materialized_row_width = 0_u64;
    let mut maximum_prefetched_query_byte_length_ceiling = 0_u64;
    for (ordinal, tree) in ordered_query_trees.iter().copied().enumerate() {
        let expected_catalog_index = u16::try_from(ordinal)
            .map_err(|_| "proof query-tree ordinal does not fit u16".to_owned())?;
        if tree.tree_catalog_index() != expected_catalog_index {
            return Err(format!(
                "proof query-tree catalog index {} is out of order at ordinal {ordinal}",
                tree.tree_catalog_index()
            ));
        }
        if tree.minimum_opened_leaf_count() > tree.opened_leaf_count_at_ceiling()
            || tree.opened_leaf_count_at_ceiling() > tree.maximum_opened_leaf_count()
            || tree.maximum_opened_leaf_count() > tree.leaf_count()
        {
            return Err(format!(
                "proof query-tree {} has invalid opened-leaf bounds",
                tree.tree_catalog_index()
            ));
        }
        let byte_length = tree
            .opened_leaf_payload_byte_length_ceiling()
            .checked_add(tree.authentication_frontier_digest_byte_length_ceiling())
            .and_then(|length| length.checked_add(tree.canonical_framing_byte_length_ceiling()))
            .ok_or_else(|| "proof query-tree byte length overflow".to_owned())?;
        if byte_length != tree.byte_length_ceiling() {
            return Err(format!(
                "proof query-tree {} byte components do not sum to its byte length",
                tree.tree_catalog_index()
            ));
        }
        let prefetched_byte_length = tree
            .opened_leaf_payload_byte_length_ceiling()
            .checked_add(tree.authentication_frontier_digest_byte_length_ceiling())
            .ok_or_else(|| "proof prefetched query byte length overflow".to_owned())?;
        maximum_prefetched_query_byte_length_ceiling =
            maximum_prefetched_query_byte_length_ceiling.max(prefetched_byte_length);
        bound_public_tree_count = bound_public_tree_count
            .checked_add(u32::from(tree.is_bound_public_tree()))
            .ok_or_else(|| "bound public query-tree count overflow".to_owned())?;
        total_materialized_row_width = total_materialized_row_width
            .checked_add(tree.materialized_row_width())
            .ok_or_else(|| "total materialized query-tree row width overflow".to_owned())?;
        rows.push(ProofQueryTreeResourceAccounting {
            tree_catalog_index: tree.tree_catalog_index(),
            is_bound_public_tree: tree.is_bound_public_tree(),
            materialized_row_width: tree.materialized_row_width(),
            leaf_count: tree.leaf_count(),
            minimum_opened_leaf_count: tree.minimum_opened_leaf_count(),
            maximum_opened_leaf_count: tree.maximum_opened_leaf_count(),
            opened_leaf_count_at_ceiling: tree.opened_leaf_count_at_ceiling(),
            authentication_frontier_node_count_at_ceiling: tree
                .authentication_frontier_node_count_at_ceiling(),
            opened_leaf_payload_byte_length_ceiling: tree.opened_leaf_payload_byte_length_ceiling(),
            authentication_frontier_digest_byte_length_ceiling: tree
                .authentication_frontier_digest_byte_length_ceiling(),
            canonical_framing_byte_length_ceiling: tree.canonical_framing_byte_length_ceiling(),
            byte_length_ceiling: tree.byte_length_ceiling(),
        });
    }
    if bound_public_tree_count != expected_bound_public_tree_count
        || total_materialized_row_width != expected_total_materialized_row_width
        || maximum_prefetched_query_byte_length_ceiling
            != expected_maximum_prefetched_query_byte_length_ceiling
    {
        return Err("proof query-tree aggregate accounting does not recompute".to_owned());
    }
    Ok(ProofQueryResources {
        unique_query_count,
        query_orbit_count,
        bound_public_tree_count,
        total_materialized_row_width,
        maximum_prefetched_query_byte_length_ceiling,
        ordered_trees: rows,
    })
}

fn proof_resident_memory_accounting(
    resident_phases: &[SelectedProofResidentPhaseResourceAccounting],
    expected_maximum_combined_wasm_resident_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
) -> Result<ProofResidentMemoryAccounting, String> {
    if resident_phases.len() != 14 {
        return Err(format!(
            "proof resident accounting must contain 14 ordered phases, observed {}",
            resident_phases.len()
        ));
    }
    let mut ordered_phases = Vec::with_capacity(resident_phases.len());
    let mut maximum_combined_wasm_resident_byte_length = 0_u64;
    let mut previous_phase_code = None;
    for phase in resident_phases.iter().copied() {
        if previous_phase_code.is_some_and(|previous| previous >= phase.phase_code()) {
            return Err("proof resident phase codes are not strictly increasing".to_owned());
        }
        previous_phase_code = Some(phase.phase_code());
        let combined_byte_length = phase
            .prover_resident_byte_length()
            .checked_add(phase.source_provider_persistent_resident_byte_length())
            .and_then(|length| {
                length.checked_add(phase.source_provider_loading_transient_byte_length())
            })
            .and_then(|length| {
                length.checked_add(phase.application_runtime_persistent_resident_byte_length())
            })
            .and_then(|length| {
                length.checked_add(phase.application_runtime_boundary_overlap_byte_length())
            })
            .and_then(|length| length.checked_add(phase.checkpoint_custody_byte_length()))
            .ok_or_else(|| "proof resident phase byte length overflow".to_owned())?;
        if combined_byte_length != phase.combined_wasm_resident_byte_length() {
            return Err(format!(
                "proof resident phase {} does not recompute",
                phase.phase_name()
            ));
        }
        maximum_combined_wasm_resident_byte_length =
            maximum_combined_wasm_resident_byte_length.max(combined_byte_length);
        ordered_phases.push(ProofResidentPhaseResourceAccounting {
            phase_code: phase.phase_code(),
            phase_name: phase.phase_name().to_owned(),
            prover_resident_byte_length: phase.prover_resident_byte_length(),
            source_provider_persistent_resident_byte_length: phase
                .source_provider_persistent_resident_byte_length(),
            source_provider_loading_transient_byte_length: phase
                .source_provider_loading_transient_byte_length(),
            application_runtime_persistent_resident_byte_length: phase
                .application_runtime_persistent_resident_byte_length(),
            application_runtime_boundary_overlap_byte_length: phase
                .application_runtime_boundary_overlap_byte_length(),
            checkpoint_custody_byte_length: phase.checkpoint_custody_byte_length(),
            combined_wasm_resident_byte_length: phase.combined_wasm_resident_byte_length(),
        });
    }
    if maximum_combined_wasm_resident_byte_length
        != expected_maximum_combined_wasm_resident_byte_length
    {
        return Err("proof resident peak does not recompute from ordered phases".to_owned());
    }
    Ok(ProofResidentMemoryAccounting {
        maximum_combined_wasm_resident_byte_length,
        maximum_copied_buffer_byte_length,
        ordered_phases,
    })
}

fn proof_variant_derivation_error(
    schema_identifier: u16,
    selector: &ProofVariantSelector,
    error: SelectedProofExternalMemoryDiagnosticError,
) -> DerivationErrorRow {
    let selector_text = match selector {
        ProofVariantSelector::Unparameterized => "unparameterized".to_owned(),
        ProofVariantSelector::SchedulePosition { schedule_position } => {
            format!("schedule-position-{schedule_position}")
        }
        ProofVariantSelector::TopCount { top_count } => format!("top-count-{top_count}"),
    };
    derivation_error(
        format!("proof-variant-0x{schema_identifier:04x}-{selector_text}"),
        format!("proof-{}", error.stage()),
        "one complete cap-neutral proof diagnostic requirement",
    )
}

fn derive_known_material_subtotals() -> Result<KnownMaterialSubtotals, String> {
    let accounting = derive_selected_complete_action_material_resource_accounting()
        .map_err(|error| format!("selected material subtotals do not derive: {error:?}"))?;
    Ok(known_material_subtotals(accounting))
}

fn known_material_subtotals(
    accounting: SelectedCompleteActionMaterialResourceAccounting,
) -> KnownMaterialSubtotals {
    KnownMaterialSubtotals {
        one_dealer_recipient_private_vss_payload_byte_length: accounting
            .one_dealer_recipient_private_vss_payload_byte_length(),
        one_dealer_private_vss_payload_upload_byte_length: accounting
            .one_dealer_private_vss_payload_upload_byte_length(),
        one_recipient_private_vss_payload_download_byte_length: accounting
            .one_recipient_private_vss_payload_download_byte_length(),
        ceremony_private_vss_payload_byte_length: accounting
            .ceremony_private_vss_payload_byte_length(),
        evaluator_source_wire_byte_length_per_participant: accounting
            .evaluator_source_wire_byte_length_per_participant(),
        evaluator_source_resident_byte_length_per_participant: accounting
            .evaluator_source_resident_byte_length_per_participant(),
        final_evaluator_key_store_wire_byte_length: accounting
            .final_evaluator_key_store_wire_byte_length(),
        final_evaluator_key_store_resident_byte_length: accounting
            .final_evaluator_key_store_resident_byte_length(),
        ceremony_evaluator_setup_wire_byte_length: accounting
            .ceremony_evaluator_setup_wire_byte_length(),
        ceremony_evaluator_source_and_final_resident_volume_byte_length: accounting
            .ceremony_evaluator_source_and_final_resident_volume_byte_length(),
        one_ballot_ciphertext_stream_byte_length: accounting
            .one_ballot_ciphertext_stream_byte_length(),
        one_ballot_ciphertext_stream_chunk_count: accounting
            .one_ballot_ciphertext_stream_chunk_count(),
        complete_action_ballot_candidate_package_corpus_byte_length: accounting
            .complete_action_ballot_candidate_package_corpus_byte_length(),
        complete_action_ballot_candidate_package_corpus_chunk_count: accounting
            .complete_action_ballot_candidate_package_corpus_chunk_count(),
        ballot_prover_material_live_set_peak_byte_length: accounting
            .ballot_prover_material_live_set_peak_byte_length(),
        one_target_ciphertext_canonical_byte_length_ceiling: accounting
            .one_target_ciphertext_canonical_byte_length_ceiling(),
        paired_target_ciphertext_canonical_byte_length_ceiling: accounting
            .paired_target_ciphertext_canonical_byte_length_ceiling(),
        one_target_partial_stream_byte_length: accounting.one_target_partial_stream_byte_length(),
        one_participant_paired_target_partial_stream_byte_length: accounting
            .one_participant_paired_target_partial_stream_byte_length(),
        ceremony_paired_target_partial_stream_byte_length: accounting
            .ceremony_paired_target_partial_stream_byte_length(),
    }
}

fn derive_private_vss_mailbox_transport() -> Result<PrivateVssMailboxTransport, String> {
    let accounting = derive_selected_private_vss_mailbox_transport_accounting()
        .map_err(|error| format!("selected private VSS mailbox transport failed: {error:?}"))?;
    Ok(private_vss_mailbox_transport(accounting))
}

fn private_vss_mailbox_transport(
    accounting: SelectedPrivateVssMailboxTransportAccounting,
) -> PrivateVssMailboxTransport {
    let transport = accounting.canonical_transport_primitive();
    PrivateVssMailboxTransport {
        participant_count: accounting.participant_count(),
        physical_payload_stream_count: accounting.physical_payload_stream_count(),
        ordered_material_root_count_per_envelope: accounting
            .ordered_material_root_count_per_envelope(),
        canonical_transport_primitive: CanonicalTransportPrimitive {
            payload_byte_length: transport.payload_byte_length(),
            stream_chunk_count: transport.stream_chunk_count(),
            stream_descriptor_byte_length: transport.stream_descriptor_byte_length(),
            mailbox_associated_data_byte_length: transport.mailbox_associated_data_byte_length(),
            mailbox_kem_ciphertext_byte_length: transport.mailbox_kem_ciphertext_byte_length(),
            mailbox_gcm_tag_byte_length: transport.mailbox_gcm_tag_byte_length(),
            mailbox_source_signature_byte_length: transport.mailbox_source_signature_byte_length(),
            mailbox_fixed_cryptographic_material_byte_length: transport
                .mailbox_fixed_cryptographic_material_byte_length(),
            signed_mailbox_envelope_byte_length: transport.signed_mailbox_envelope_byte_length(),
            boundary_transfer_byte_length: transport.boundary_transfer_byte_length(),
            maximum_boundary_copied_buffer_byte_length: transport
                .maximum_boundary_copied_buffer_byte_length(),
            indexed_db_serialized_byte_length: transport.indexed_db_serialized_byte_length(),
            indexed_db_additional_copy_peak_byte_length: transport
                .indexed_db_additional_copy_peak_byte_length(),
            indexed_db_serialization_buffer_peak_byte_length: transport
                .indexed_db_serialization_buffer_peak_byte_length(),
            indexed_db_readback_buffer_peak_byte_length: transport
                .indexed_db_readback_buffer_peak_byte_length(),
        },
        complete_mailbox_byte_length: accounting.complete_mailbox_byte_length(),
        one_dealer_upload_byte_length: accounting.one_dealer_upload_byte_length(),
        one_recipient_download_byte_length: accounting.one_recipient_download_byte_length(),
        ceremony_upload_byte_length: accounting.ceremony_upload_byte_length(),
        ceremony_download_byte_length: accounting.ceremony_download_byte_length(),
        private_mailbox_corpus_byte_length: accounting.private_mailbox_corpus_byte_length(),
    }
}

fn derive_unsigned_public_carriers(
    derivation_errors: &mut Vec<DerivationErrorRow>,
) -> Result<UnsignedPublicCarrierAccounting, String> {
    let accounting = derive_selected_unsigned_public_carrier_accounting()
        .map_err(|error| format!("selected unsigned public carriers failed: {error:?}"))?;
    unsigned_public_carriers(accounting, derivation_errors)
}

fn unsigned_public_carriers(
    accounting: SelectedUnsignedPublicCarrierAccounting,
    derivation_errors: &mut Vec<DerivationErrorRow>,
) -> Result<UnsignedPublicCarrierAccounting, String> {
    let aggregate = accounting.aggregate_public_carrier();
    let replay_ceiling = accounting.evaluator_replay_codec_ceiling();
    let replay_at_ceiling = replay_ceiling.carrier_accounting_at_codec_ceiling();
    if accounting.unsigned_public_carrier_count() != 2
        || accounting.unsigned_public_physical_stream_count() != 4
        || aggregate.physical_ciphertext_stream_count() != 2
        || replay_at_ceiling.physical_ciphertext_stream_count() != 2
    {
        return Err(
            "selected unsigned public carrier topology is not two two-stream carriers".to_owned(),
        );
    }
    let exact_evaluator_replay = match accounting.exact_evaluator_replay() {
        SelectedExactEvaluatorReplayCarrierAccounting::Available(exact) => {
            DerivedSection::derived(evaluator_replay_public_carrier(exact))
        }
        SelectedExactEvaluatorReplayCarrierAccounting::MissingGeneratedEvaluatorReplayDescriptors => {
            let error = derivation_error(
                "evaluator-replay-exact-public-carrier",
                "missing-generated-evaluator-replay-descriptors",
                "both production-generated target ciphertext stream descriptors from evaluator execution",
            );
            derivation_errors.push(error.clone());
            DerivedSection::failed(error)
        }
    };
    Ok(UnsignedPublicCarrierAccounting {
        unsigned_public_carrier_count: accounting.unsigned_public_carrier_count(),
        unsigned_public_physical_stream_count: accounting.unsigned_public_physical_stream_count(),
        aggregate_public_carrier: aggregate_public_carrier(aggregate),
        evaluator_replay_codec_ceiling: EvaluatorReplayCarrierCodecCeiling {
            target_ciphertext_stream_byte_length_ceiling: replay_ceiling
                .target_ciphertext_stream_byte_length_ceiling(),
            target_ciphertext_stream_chunk_count_ceiling: replay_ceiling
                .target_ciphertext_stream_chunk_count_ceiling(),
            canonical_envelope_byte_length_ceiling: replay_ceiling
                .canonical_envelope_byte_length_ceiling(),
            complete_public_object_byte_length_ceiling: replay_ceiling
                .complete_public_object_byte_length_ceiling(),
            carrier_accounting_at_codec_ceiling: evaluator_replay_public_carrier(replay_at_ceiling),
        },
        exact_evaluator_replay,
    })
}

fn aggregate_public_carrier(
    accounting: SelectedAggregatePublicCarrierAccounting,
) -> AggregatePublicCarrierAccounting {
    AggregatePublicCarrierAccounting {
        selected_ballot_object_hash_count: accounting.selected_ballot_object_hash_count(),
        payload_binding_hash_count: accounting.payload_binding_hash_count(),
        physical_ciphertext_stream_count: accounting.physical_ciphertext_stream_count(),
        one_ciphertext_stream_byte_length: accounting.one_ciphertext_stream_byte_length(),
        one_ciphertext_stream_chunk_count: accounting.one_ciphertext_stream_chunk_count(),
        one_stream_descriptor_hash_count: accounting.one_stream_descriptor_hash_count(),
        one_stream_descriptor_byte_length: accounting.one_stream_descriptor_byte_length(),
        ciphertext_stream_corpus_byte_length: accounting.ciphertext_stream_corpus_byte_length(),
        ciphertext_stream_corpus_chunk_count: accounting.ciphertext_stream_corpus_chunk_count(),
        canonical_payload_byte_length: accounting.canonical_payload_byte_length(),
        canonical_payload_framing_byte_length: accounting.canonical_payload_framing_byte_length(),
        canonical_envelope_binding_hash_count: accounting.canonical_envelope_binding_hash_count(),
        canonical_envelope_byte_length: accounting.canonical_envelope_byte_length(),
        canonical_envelope_framing_byte_length: accounting.canonical_envelope_framing_byte_length(),
        complete_public_object_byte_length: accounting.complete_public_object_byte_length(),
    }
}

fn evaluator_replay_public_carrier(
    accounting: SelectedEvaluatorReplayPublicCarrierAccounting,
) -> EvaluatorReplayPublicCarrierAccounting {
    EvaluatorReplayPublicCarrierAccounting {
        payload_binding_hash_count: accounting.payload_binding_hash_count(),
        physical_ciphertext_stream_count: accounting.physical_ciphertext_stream_count(),
        target_identifier_stream_byte_length: accounting.target_identifier_stream_byte_length(),
        target_identifier_stream_chunk_count: accounting.target_identifier_stream_chunk_count(),
        target_identifier_stream_descriptor_hash_count: accounting
            .target_identifier_stream_descriptor_hash_count(),
        target_identifier_stream_descriptor_byte_length: accounting
            .target_identifier_stream_descriptor_byte_length(),
        target_order_stream_byte_length: accounting.target_order_stream_byte_length(),
        target_order_stream_chunk_count: accounting.target_order_stream_chunk_count(),
        target_order_stream_descriptor_hash_count: accounting
            .target_order_stream_descriptor_hash_count(),
        target_order_stream_descriptor_byte_length: accounting
            .target_order_stream_descriptor_byte_length(),
        ciphertext_stream_corpus_byte_length: accounting.ciphertext_stream_corpus_byte_length(),
        ciphertext_stream_corpus_chunk_count: accounting.ciphertext_stream_corpus_chunk_count(),
        canonical_payload_byte_length: accounting.canonical_payload_byte_length(),
        canonical_payload_framing_byte_length: accounting.canonical_payload_framing_byte_length(),
        canonical_envelope_binding_hash_count: accounting.canonical_envelope_binding_hash_count(),
        canonical_envelope_byte_length: accounting.canonical_envelope_byte_length(),
        canonical_envelope_framing_byte_length: accounting.canonical_envelope_framing_byte_length(),
        complete_public_object_byte_length: accounting.complete_public_object_byte_length(),
    }
}

fn derive_product_alternatives() -> Result<ProductAlternatives, String> {
    let maximum_ballot_count = FOUNDATION_PROFILE.participant_count;
    let mut ordered_ballot_counts = Vec::with_capacity(usize::from(maximum_ballot_count));
    for ballot_count in 1..=maximum_ballot_count {
        let accounting =
            canonical_two_stream_pair_character_product_accounting(usize::from(ballot_count))
                .map_err(|error| {
                    format!(
                        "two-stream product accounting for {ballot_count} ballots failed: {error:?}"
                    )
                })?;
        ordered_ballot_counts.push(product_accounting_row(ballot_count, accounting)?);
    }
    Ok(ProductAlternatives {
        selected_complete_action_ballot_count: maximum_ballot_count,
        ordered_ballot_counts,
    })
}

fn product_accounting_row(
    ballot_count: u16,
    accounting: TwoStreamPairCharacterProductAccounting,
) -> Result<ProductAccountingRow, String> {
    let memory = accounting.memory;
    Ok(ProductAccountingRow {
        ballot_count,
        ballot_ciphertext_count: u32::try_from(accounting.ballot_ciphertext_count)
            .map_err(|_| "product ballot ciphertext count does not fit u32".to_owned())?,
        ciphertext_multiplication_count: u32::try_from(accounting.ciphertext_multiplication_count)
            .map_err(|_| "product multiplication count does not fit u32".to_owned())?,
        relinearization_count: u32::try_from(accounting.relinearization_count)
            .map_err(|_| "product relinearization count does not fit u32".to_owned())?,
        normalization_plaintext_multiplication_count: u32::try_from(
            accounting.normalization_plaintext_multiplication_count,
        )
        .map_err(|_| "product normalization count does not fit u32".to_owned())?,
        modulus_switch_count: u32::try_from(accounting.modulus_switch_count)
            .map_err(|_| "product modulus switch count does not fit u32".to_owned())?,
        modulus_drop_count: u32::try_from(accounting.modulus_drop_count)
            .map_err(|_| "product modulus drop count does not fit u32".to_owned())?,
        maximum_resident_ciphertext_count: u32::try_from(
            accounting.maximum_resident_ciphertext_count,
        )
        .map_err(|_| "product resident ciphertext count does not fit u32".to_owned())?,
        relinearization_key_load_count: u32::try_from(accounting.relinearization_key_load_count)
            .map_err(|_| "product key load count does not fit u32".to_owned())?,
        key_store_read_byte_count: accounting.key_store_read_byte_count,
        key_ntt_transform_count: u32::try_from(accounting.key_ntt_transform_count)
            .map_err(|_| "product key NTT count does not fit u32".to_owned())?,
        memory: ProductMemoryAccounting {
            maximum_live_ciphertext_coefficient_byte_length: memory
                .maximum_live_ciphertext_coefficient_byte_length,
            relinearization_key_component_wire_byte_length: memory
                .relinearization_key_component_wire_byte_length,
            resident_relinearization_key_coefficient_byte_length: memory
                .resident_relinearization_key_coefficient_byte_length,
            maximum_key_store_chunk_byte_length: memory.maximum_key_store_chunk_byte_length,
            final_key_store_chunk_byte_length: memory.final_key_store_chunk_byte_length,
            key_replay_limb_buffer_byte_length: memory.key_replay_limb_buffer_byte_length,
            peak_key_replay_wasm_resident_byte_length: memory
                .peak_key_replay_wasm_resident_byte_length,
            maximum_ciphertext_tensor_transient_byte_length: memory
                .maximum_ciphertext_tensor_transient_byte_length,
            maximum_ciphertext_tensor_scratch_byte_length: memory
                .maximum_ciphertext_tensor_scratch_byte_length,
            maximum_relinearization_transient_byte_length: memory
                .maximum_relinearization_transient_byte_length,
            maximum_relinearization_scratch_byte_length: memory
                .maximum_relinearization_scratch_byte_length,
            maximum_plaintext_multiplication_transient_byte_length: memory
                .maximum_plaintext_multiplication_transient_byte_length,
            maximum_plaintext_multiplication_scratch_byte_length: memory
                .maximum_plaintext_multiplication_scratch_byte_length,
            maximum_modulus_switch_transient_byte_length: memory
                .maximum_modulus_switch_transient_byte_length,
            maximum_modulus_switch_scratch_byte_length: memory
                .maximum_modulus_switch_scratch_byte_length,
            maximum_operation_transient_byte_length: memory.maximum_operation_transient_byte_length,
            maximum_operation_scratch_byte_length: memory.maximum_operation_scratch_byte_length,
            peak_combined_wasm_resident_byte_length: memory.peak_combined_wasm_resident_byte_length,
        },
    })
}

fn derive_evaluator_alternatives() -> Result<EvaluatorAlternatives, String> {
    let ledger = selected_evaluator_execution_resource_ledger()
        .map_err(|error| format!("selected evaluator resource ledger failed: {error:?}"))?;
    let mut ordered_top_counts = Vec::with_capacity(ledger.ordered_streams().len());
    let mut complete_action_maxima = EvaluatorResourceTotals::default();
    for (stream_ordinal, row) in ledger.ordered_streams().iter().copied().enumerate() {
        let expected_top_count = u16::try_from(stream_ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_add(1))
            .ok_or_else(|| "evaluator stream ordinal does not fit u16".to_owned())?;
        if row.top_count() != expected_top_count {
            return Err(format!(
                "evaluator row {} has top count {}",
                stream_ordinal,
                row.top_count()
            ));
        }
        let totals = evaluator_resource_totals(row.totals())?;
        complete_action_maxima.include_maximum(&totals);
        ordered_top_counts.push(EvaluatorAccountingRow {
            top_count: row.top_count(),
            totals,
        });
    }
    if ordered_top_counts.len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(format!(
            "evaluator resource ledger has {} alternatives instead of {}",
            ordered_top_counts.len(),
            FOUNDATION_PROFILE.option_count
        ));
    }
    Ok(EvaluatorAlternatives {
        ordered_top_counts,
        complete_action_maxima,
    })
}

fn evaluator_resource_totals(
    totals: SelectedEvaluatorExecutionResourceTotals,
) -> Result<EvaluatorResourceTotals, String> {
    Ok(EvaluatorResourceTotals {
        instruction_count: u64::try_from(totals.instruction_count())
            .map_err(|_| "evaluator instruction count does not fit u64".to_owned())?,
        key_operation_count: u64::try_from(totals.key_operation_count())
            .map_err(|_| "evaluator key operation count does not fit u64".to_owned())?,
        key_load_count: u64::try_from(totals.key_load_count())
            .map_err(|_| "evaluator key load count does not fit u64".to_owned())?,
        key_store_read_request_count: totals.key_store_read_request_count(),
        key_store_reread_request_count: totals.key_store_reread_request_count(),
        key_store_read_byte_count: totals.key_store_read_byte_count(),
        key_store_reread_byte_count: totals.key_store_reread_byte_count(),
        key_ntt_transform_count: u64::try_from(totals.key_ntt_transform_count())
            .map_err(|_| "evaluator key NTT count does not fit u64".to_owned())?,
        rotation_count: u64::try_from(totals.rotation_count())
            .map_err(|_| "evaluator rotation count does not fit u64".to_owned())?,
        ciphertext_multiplication_count: u64::try_from(totals.ciphertext_multiplication_count())
            .map_err(|_| "evaluator ciphertext multiplication count does not fit u64".to_owned())?,
        plaintext_multiplication_count: u64::try_from(totals.plaintext_multiplication_count())
            .map_err(|_| "evaluator plaintext multiplication count does not fit u64".to_owned())?,
        modulus_switch_count: u64::try_from(totals.modulus_switch_count())
            .map_err(|_| "evaluator modulus switch count does not fit u64".to_owned())?,
        maximum_live_ciphertext_byte_count: totals.maximum_live_ciphertext_byte_count(),
        maximum_resident_key_byte_count: totals.maximum_resident_key_byte_count(),
        maximum_operation_scratch_byte_count: totals.maximum_operation_scratch_byte_count(),
        peak_combined_wasm_resident_byte_count: totals.peak_combined_wasm_resident_byte_count(),
    })
}

fn evidence_envelope(
    record: StaticResourceAccountingRecord,
) -> Result<StaticResourceAccountingEnvelope, String> {
    require_valid_derived_sections(&record)?;
    let record_value = serde_json::to_value(&record)
        .map_err(|error| format!("static resource record does not serialize: {error}"))?;
    require_exact_json_integers(&record_value, "record")?;
    let record_bytes = serde_json::to_vec(&record)
        .map_err(|error| format!("static resource record does not serialize: {error}"))?;
    Ok(StaticResourceAccountingEnvelope {
        record_kind: RECORD_KIND.to_owned(),
        record_version: RECORD_VERSION,
        record_byte_length: u64::try_from(record_bytes.len())
            .map_err(|_| "record byte length does not fit u64".to_owned())?,
        record_shake256_hex: to_hex(&hash_framed_parts_512(RECORD_HASH_DOMAIN, &[&record_bytes])),
        record,
    })
}

fn verify_envelope(envelope: &StaticResourceAccountingEnvelope) -> Result<(), String> {
    if envelope.record_kind != RECORD_KIND || envelope.record_version != RECORD_VERSION {
        return Err("static resource evidence kind or version is not canonical".to_owned());
    }
    require_valid_derived_sections(&envelope.record)?;
    let record_value = serde_json::to_value(&envelope.record)
        .map_err(|error| format!("decoded static resource record does not serialize: {error}"))?;
    require_exact_json_integers(&record_value, "record")?;
    let record_bytes = serde_json::to_vec(&envelope.record)
        .map_err(|error| format!("decoded static resource record does not serialize: {error}"))?;
    if envelope.record_byte_length
        != u64::try_from(record_bytes.len())
            .map_err(|_| "decoded record byte length does not fit u64".to_owned())?
    {
        return Err("static resource evidence record byte length does not match".to_owned());
    }
    let recomputed_hash = to_hex(&hash_framed_parts_512(RECORD_HASH_DOMAIN, &[&record_bytes]));
    if envelope.record_shake256_hex != recomputed_hash {
        return Err("static resource evidence record hash does not match".to_owned());
    }
    Ok(())
}

fn require_valid_derived_sections(record: &StaticResourceAccountingRecord) -> Result<(), String> {
    if record.caps != derive_caps()? {
        return Err("record.caps differs from the unchanged absolute caps".to_owned());
    }
    record
        .physical_proof_families
        .require_exactly_one_branch("record.physicalProofFamilies")?;
    record
        .proof_variants
        .require_exactly_one_branch("record.proofVariants")?;
    if let Some(proof_variants) = record.proof_variants.data.as_ref() {
        require_proof_custody_totals(proof_variants)?;
    }
    record
        .target_release
        .require_exactly_one_branch("record.targetRelease")?;
    record
        .known_material_subtotals
        .require_exactly_one_branch("record.knownMaterialSubtotals")?;
    record
        .private_vss_mailbox_transport
        .require_exactly_one_branch("record.privateVssMailboxTransport")?;
    record
        .unsigned_public_carriers
        .require_exactly_one_branch("record.unsignedPublicCarriers")?;
    if let Some(unsigned_public_carriers) = record.unsigned_public_carriers.data.as_ref() {
        unsigned_public_carriers
            .exact_evaluator_replay
            .require_exactly_one_branch(
                "record.unsignedPublicCarriers.data.exactEvaluatorReplay",
            )?;
    }
    record
        .product_alternatives
        .require_exactly_one_branch("record.productAlternatives")?;
    record
        .evaluator_alternatives
        .require_exactly_one_branch("record.evaluatorAlternatives")?;
    record
        .phase_liveness
        .require_exactly_one_branch("record.phaseLiveness")?;
    Ok(())
}

fn require_proof_custody_totals(accounting: &ProofVariantAccounting) -> Result<(), String> {
    let mut family_accumulators = BTreeMap::<u16, ProofTotalsAccumulator>::new();
    let mut complete_action_accumulator = ProofTotalsAccumulator::default();
    for row in &accounting.ordered_variants {
        let Some(requirement) = row.requirement.as_ref() else {
            continue;
        };
        family_accumulators
            .entry(row.application_statement_schema_identifier)
            .or_default()
            .include(requirement)?;
        complete_action_accumulator.include(requirement)?;
    }
    for family_totals in &accounting.ordered_family_totals {
        let accumulator = family_accumulators
            .remove(&family_totals.application_statement_schema_identifier)
            .ok_or_else(|| {
                format!(
                    "proof family 0x{:04x} custody totals have no matching requirement row",
                    family_totals.application_statement_schema_identifier
                )
            })?;
        accumulator.require_custody_totals(
            family_totals.external_memory_local_record_seal_invocation_count,
            family_totals.external_memory_local_record_sealed_plaintext_byte_length,
            family_totals.maximum_local_record_seal_invocation_count_per_proof,
            family_totals.maximum_local_record_sealed_plaintext_byte_length_per_proof,
            &format!(
                "proof family 0x{:04x} totals",
                family_totals.application_statement_schema_identifier
            ),
        )?;
    }
    if !family_accumulators.is_empty() {
        return Err("proof requirements contain a family without custody totals".to_owned());
    }
    if let Some(complete_action_totals) = accounting.complete_action_totals.as_ref() {
        complete_action_accumulator.require_custody_totals(
            complete_action_totals.external_memory_local_record_seal_invocation_count,
            complete_action_totals.external_memory_local_record_sealed_plaintext_byte_length,
            complete_action_totals.maximum_local_record_seal_invocation_count_per_proof,
            complete_action_totals.maximum_local_record_sealed_plaintext_byte_length_per_proof,
            "proof complete-action totals",
        )?;
    }
    Ok(())
}

fn require_exact_json_integers(value: &serde_json::Value, location: &str) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                require_exact_json_integers(child, &format!("{location}[{index}]"))?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, child) in values {
                require_exact_json_integers(child, &format!("{location}.{key}"))?;
            }
        }
        serde_json::Value::Number(number) => {
            let unsigned = number.as_u64().ok_or_else(|| {
                format!("{location} is not a non-negative integer representable as u64")
            })?;
            if unsigned > MAXIMUM_EXACT_JSON_INTEGER {
                return Err(format!(
                    "{location} exceeds the exact JSON integer range: {unsigned}"
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn write_run_attachment(bytes: &[u8]) -> Result<PathBuf, String> {
    let run_directory = env::var_os("SEALED_LATTICE_RUN_DIRECTORY")
        .map(PathBuf::from)
        .ok_or_else(|| "SEALED_LATTICE_RUN_DIRECTORY is required".to_owned())?;
    let attachment_directory = run_directory.join("attachments").join("rust-measurements");
    fs::create_dir_all(&attachment_directory).map_err(|error| {
        format!(
            "cannot create static resource attachment directory {}: {error}",
            attachment_directory.display()
        )
    })?;
    let target_path = attachment_directory.join(ATTACHMENT_FILE_NAME);
    if target_path.exists() {
        let existing = fs::read(&target_path).map_err(|error| {
            format!(
                "cannot read existing static resource attachment {}: {error}",
                target_path.display()
            )
        })?;
        if existing != bytes {
            return Err(format!(
                "existing static resource attachment {} differs",
                target_path.display()
            ));
        }
        return Ok(target_path);
    }
    let temporary_path = attachment_directory.join(format!(
        ".{ATTACHMENT_FILE_NAME}.temporary-{}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .map_err(|error| {
                format!(
                    "cannot create temporary static resource attachment {}: {error}",
                    temporary_path.display()
                )
            })?;
        file.write_all(bytes).map_err(|error| {
            format!(
                "cannot write temporary static resource attachment {}: {error}",
                temporary_path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "cannot synchronize temporary static resource attachment {}: {error}",
                temporary_path.display()
            )
        })?;
        fs::rename(&temporary_path, &target_path).map_err(|error| {
            format!(
                "cannot publish static resource attachment {}: {error}",
                target_path.display()
            )
        })?;
        Ok::<(), String>(())
    })();
    if result.is_err() && temporary_path.exists() {
        let _ = fs::remove_file(&temporary_path);
    }
    result?;
    Ok(target_path)
}

fn assert_no_result_claim_fields(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if matches!(
                    key.as_str(),
                    "status" | "verdict" | "accepted" | "isValid" | "fits"
                ) {
                    return Err(format!(
                        "static resource evidence contains result-claim field {key}"
                    ));
                }
                assert_no_result_claim_fields(child)?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                assert_no_result_claim_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resident_phase_row(
        prover_resident_byte_length: u64,
        source_provider_persistent_resident_byte_length: u64,
        combined_wasm_resident_byte_length: u64,
    ) -> ProofResidentPhaseResourceAccounting {
        ProofResidentPhaseResourceAccounting {
            phase_code: 7,
            phase_name: "query-opening".to_owned(),
            prover_resident_byte_length,
            source_provider_persistent_resident_byte_length,
            source_provider_loading_transient_byte_length: 0,
            application_runtime_persistent_resident_byte_length: 0,
            application_runtime_boundary_overlap_byte_length: 0,
            checkpoint_custody_byte_length: 0,
            combined_wasm_resident_byte_length,
        }
    }

    fn rebind_envelope_record(envelope: &mut StaticResourceAccountingEnvelope) {
        let record_bytes = serde_json::to_vec(&envelope.record)
            .expect("mutated static resource record serializes");
        envelope.record_byte_length =
            u64::try_from(record_bytes.len()).expect("mutated record byte length fits u64");
        envelope.record_shake256_hex =
            to_hex(&hash_framed_parts_512(RECORD_HASH_DOMAIN, &[&record_bytes]));
    }

    const DEFERRED_PHASE_LIVENESS_CARRIER_INVENTORY: [(&str, &str); 20] = [
        (
            "canonical-material-transport",
            "remaining-material-transport-carriers-absent",
        ),
        (
            "directional-ceremony-traffic",
            "remaining-directional-traffic-carriers-absent",
        ),
        (
            "public-transcript-corpus",
            "public-transcript-corpus-carrier-absent",
        ),
        (
            "non-proof-persistence-and-io",
            "complete-persistence-carrier-absent",
        ),
        ("browser-boundary-memory", "browser-copy-carrier-absent"),
        (
            "target-release-proof-output-store",
            "proof-output-store-lifetime-not-production-fixed",
        ),
        (
            "target-release-partial-output-store",
            "partial-output-store-lifetime-not-production-fixed",
        ),
        (
            "target-release-state-certification-traffic",
            "state-certification-traffic-not-production-fixed",
        ),
        (
            "target-release-public-share-distribution",
            "public-share-distribution-fanout-not-production-fixed",
        ),
        (
            "target-release-result-transition",
            "reconstructed-result-transition-not-production-fixed",
        ),
        (
            "evaluator-replay-exact-public-carrier",
            "missing-generated-evaluator-replay-descriptors",
        ),
        (
            "evaluator-replay-exact-canonical-transport",
            "missing-generated-evaluator-replay-descriptors",
        ),
        (
            "remaining-complete-action-canonical-transport-catalog",
            "missing-production-carrier-constructors",
        ),
        (
            "remaining-complete-action-host-boundary-storage-lifetimes",
            "missing-production-cross-runtime-state-transitions",
        ),
        (
            "two-stream-product-allocation-volume",
            "missing-production-allocation-event-type",
        ),
        (
            "evaluator-execution-allocation-volume",
            "missing-production-allocation-event-type",
        ),
        (
            "proof-generation-allocation-volume",
            "missing-production-allocation-event-type",
        ),
        (
            "target-release-allocation-volume",
            "missing-production-allocation-event-type",
        ),
        (
            "fresh-proof-generation-work",
            "missing-production-boundary-indexed-work-schedule",
        ),
        (
            "resumed-proof-generation-work",
            "missing-production-boundary-indexed-work-schedule",
        ),
    ];

    fn require_exact_deferred_phase_liveness_carrier_inventory(errors: &[DerivationErrorRow]) {
        let observed = errors
            .iter()
            .map(|error| (error.dimension.as_str(), error.reason_code.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            observed, DEFERRED_PHASE_LIVENESS_CARRIER_INVENTORY,
            "static resource accounting contains an added, removed, reordered, or reclassified missing carrier"
        );
        assert!(
            errors
                .iter()
                .all(|error| !error.required_carrier.is_empty()),
            "every deferred missing carrier identifies its required production carrier"
        );
    }

    #[test]
    fn physical_proof_topology_preserves_the_proof_family_inventory() {
        let proof_family_inventory = derive_selected_proof_family_application_inventory()
            .expect("the selected proof-family inventory derives");
        let physical_proof_topology =
            derive_physical_proof_topology().expect("the physical proof topology derives");
        let expected_families = proof_family_inventory
            .ordered_family_entries()
            .iter()
            .map(|family| PhysicalProofFamily {
                application_statement_schema_identifier: family
                    .application_statement_schema_identifier(),
                physical_proof_count: family.physical_proof_application_count(),
            })
            .collect::<Vec<_>>();
        assert_eq!(physical_proof_topology.ordered_families, expected_families);
        assert_eq!(
            physical_proof_topology.total_physical_proof_count,
            proof_family_inventory
                .total_physical_proof_application_count()
                .expect("the selected physical proof-application count derives")
        );
    }

    #[test]
    fn resident_phase_maximum_retains_one_complete_row_when_component_peaks_conflict() {
        let largest_combined_row = resident_phase_row(100, 0, 100);
        let smaller_conflicting_row = resident_phase_row(0, 99, 99);
        let equal_combined_tie_row = resident_phase_row(99, 1, 100);

        let mut selected = smaller_conflicting_row.clone();
        include_resident_phase_maximum(&mut selected, &largest_combined_row)
            .expect("larger complete phase row is selected");
        include_resident_phase_maximum(&mut selected, &equal_combined_tie_row)
            .expect("stable phase-row tie break derives");
        assert_eq!(selected, largest_combined_row);
        require_resident_phase_sum(&selected).expect("selected phase row recomputes");

        let mut reverse_order_selected = equal_combined_tie_row;
        include_resident_phase_maximum(&mut reverse_order_selected, &smaller_conflicting_row)
            .expect("smaller conflicting phase row does not replace the peak");
        include_resident_phase_maximum(&mut reverse_order_selected, &largest_combined_row)
            .expect("tie break is independent of input order");
        assert_eq!(reverse_order_selected, largest_combined_row);

        let malformed_row = resident_phase_row(0, 99, 100);
        assert_eq!(
            include_resident_phase_maximum(&mut selected, &malformed_row),
            Err(
                "resident phase query-opening combined byte length does not equal its component sum"
                    .to_owned()
            )
        );
    }

    #[test]
    #[ignore = "guarded selected static resource-accounting evidence"]
    fn selected_candidate_static_resource_accounting_emits_run_attachment() {
        let first_record = derive_static_resource_accounting_record()
            .expect("selected static resource-accounting record derives");
        let second_record = derive_static_resource_accounting_record()
            .expect("selected static resource-accounting record re-derives");
        let first_bytes = serde_json::to_vec(&first_record)
            .expect("selected static resource-accounting record serializes");
        let second_bytes = serde_json::to_vec(&second_record)
            .expect("selected static resource-accounting record reserializes");
        assert_eq!(
            first_bytes, second_bytes,
            "static derivation is deterministic"
        );

        let envelope = evidence_envelope(first_record)
            .expect("selected static resource-accounting envelope derives");
        verify_envelope(&envelope).expect("selected static resource-accounting envelope verifies");
        let compact_envelope = serde_json::to_vec(&envelope)
            .expect("selected static resource-accounting envelope serializes");
        let decoded: StaticResourceAccountingEnvelope = serde_json::from_slice(&compact_envelope)
            .expect("selected static resource-accounting envelope decodes");
        assert_eq!(decoded, envelope);
        verify_envelope(&decoded)
            .expect("decoded selected static resource-accounting envelope verifies");

        let mut both_branches = decoded.clone();
        both_branches
            .record
            .physical_proof_families
            .derivation_error = Some(derivation_error(
            "derived-section-mutation",
            "both-branches-present",
            "exactly one derived-section branch",
        ));
        rebind_envelope_record(&mut both_branches);
        assert_eq!(
            verify_envelope(&both_branches),
            Err("record.physicalProofFamilies contains both data and derivationError".to_owned())
        );

        let mut neither_branch = decoded.clone();
        neither_branch.record.physical_proof_families.data = None;
        neither_branch
            .record
            .physical_proof_families
            .derivation_error = None;
        rebind_envelope_record(&mut neither_branch);
        assert_eq!(
            verify_envelope(&neither_branch),
            Err(
                "record.physicalProofFamilies contains neither data nor derivationError".to_owned()
            )
        );

        let mut inconsistent_custody_totals = decoded.clone();
        let proof_accounting = inconsistent_custody_totals
            .record
            .proof_variants
            .data
            .as_mut()
            .expect("selected proof accounting derives");
        let mutated_schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let mutated_family_totals = proof_accounting
            .ordered_family_totals
            .iter_mut()
            .find(|family_totals| {
                family_totals.application_statement_schema_identifier == mutated_schema_identifier
            })
            .expect("same-secret proof-family accounting derives");
        mutated_family_totals.external_memory_local_record_seal_invocation_count += 1;
        rebind_envelope_record(&mut inconsistent_custody_totals);
        assert_eq!(
            verify_envelope(&inconsistent_custody_totals),
            Err(format!(
                "proof family 0x{mutated_schema_identifier:04x} totals does not recompute its multiplicity-scaled seal-custody ledger"
            ))
        );

        let value = serde_json::to_value(&decoded)
            .expect("selected static resource-accounting evidence converts to JSON");
        assert_no_result_claim_fields(&value)
            .expect("selected static resource-accounting evidence has no result claims");

        let mut attachment_bytes = serde_json::to_vec_pretty(&decoded)
            .expect("selected static resource-accounting attachment serializes");
        attachment_bytes.push(b'\n');
        let attachment_path = write_run_attachment(&attachment_bytes)
            .expect("selected static resource-accounting attachment writes");
        println!(
            "selected static resource-accounting attachment: {}",
            attachment_path.display()
        );
        require_exact_deferred_phase_liveness_carrier_inventory(&decoded.record.derivation_errors);
    }

    #[test]
    #[ignore = "guarded selected complete-action phase-liveness closure evidence"]
    fn selected_candidate_static_resource_accounting_closes_every_missing_carrier() {
        let record = derive_static_resource_accounting_record()
            .expect("selected static resource-accounting record derives");
        assert!(
            record.derivation_errors.is_empty(),
            "static resource accounting retains {} typed missing carriers",
            record.derivation_errors.len()
        );
    }
}
