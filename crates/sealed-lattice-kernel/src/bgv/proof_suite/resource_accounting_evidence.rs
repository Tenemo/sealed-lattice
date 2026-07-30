//! Deterministic, test-only static resource-accounting evidence.

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    bgv::{
        evaluator::program::selected_evaluator_program_set,
        parameters::bgv_parameters_hash,
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
    AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, FIRST_PROFILE_APPLICATION_FAMILIES,
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    external_memory::{
        AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
    field::PROOF_CHALLENGE_EXTENSION_DEGREE,
    phase_liveness_accounting::{
        SelectedCompleteActionPhaseLivenessAccounting,
        derive_selected_complete_action_phase_liveness_accounting,
    },
    row_code_whir::{
        AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH,
        NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH,
        ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW, RowCodeWhirSelectedParameters,
    },
    selected_accounting::resource_accounting::{
        SelectedCompleteActionMaterialResourceAccounting,
        derive_selected_complete_action_material_resource_accounting,
        selected_complete_proof_resource_accounting, selected_proof_variant_resource_inventory,
    },
    selected_proof_profile_set,
};

const RECORD_KIND: &str = "pair-character-candidate-static-resource-accounting";
const RECORD_VERSION: u16 = 6;
const RECORD_HASH_DOMAIN: &str = "sealed-lattice/pair-character-static-resource-accounting/v6";
const SOURCE_HASH_DOMAIN: &str =
    "sealed-lattice/pair-character-static-resource-accounting/source/v1";
const BUILD_HASH_DOMAIN: &str = "sealed-lattice/pair-character-static-resource-accounting/build/v1";
const CANDIDATE_INPUT_HASH_DOMAIN: &str =
    "sealed-lattice/pair-character-static-resource-accounting/input/v2";
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
    ordered_proof_variants: Vec<ProofVariantAccounting>,
    complete_action: CompleteActionAccounting,
    phase_liveness: SelectedCompleteActionPhaseLivenessAccounting,
    target_release: SelectedTargetReleaseStaticAccounting,
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
    participant_count: u16,
    option_count: u16,
    maximum_ballot_attempts_per_participant: u32,
    maximum_candidate_packages_per_action: u32,
    bgv_parameters_canonical_object_hash_hex: String,
    proof_profile_byte_length: u64,
    evaluator_program_byte_length: u64,
    evaluator_program_hash_hex: String,
    combined_input_shake256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticResourceCaps {
    nominal_proof_byte_length: u64,
    automatic_proof_acceptance_byte_length: u64,
    common_authenticated_stream_hard_limit_byte_length: u64,
    maximum_proof_output_chunk_byte_length: u64,
    maximum_external_memory_transaction_chunk_byte_length: u64,
    maximum_external_memory_object_count: u64,
    nominal_external_memory_stored_byte_length: u64,
    automatic_external_memory_stored_byte_length: u64,
    maximum_external_memory_stored_byte_length: u64,
    nominal_proof_wasm_resident_byte_length: u64,
    automatic_proof_wasm_resident_byte_length: u64,
    maximum_proof_wasm_resident_byte_length: u64,
    maximum_local_record_seal_invocations_per_active_root: u64,
    maximum_local_record_sealed_plaintext_bytes_per_active_root: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofVariantSelector {
    schedule_position: Option<u32>,
    top_count: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofVariantAccounting {
    application_statement_schema_identifier: u16,
    selector: ProofVariantSelector,
    complete_action_application_multiplicity: u32,
    logical_entry_count: u32,
    relation_column_count: u32,
    verifier_sequence_relation_column_count: u32,
    bound_tree_relation_column_count: u32,
    prover_relation_column_count: u32,
    relation_constraint_count: u32,
    opening_claim_count: u32,
    canonical_header_byte_length: u64,
    canonical_family_body_byte_length: u64,
    canonical_proof_byte_length: u64,
    nominal_proof_overage_byte_length: u64,
    nominal_proof_headroom_byte_length: u64,
    automatic_acceptance_overage_byte_length: u64,
    automatic_acceptance_headroom_byte_length: u64,
    absolute_bound_headroom_byte_length: u64,
    maximum_verifier_resident_byte_length: u64,
    generation_wasm_resident_hard_bound_byte_length: u64,
    external_memory: ExternalMemoryAccounting,
    construction: ConstructionAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalMemoryAccounting {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    peak_stored_byte_length: u64,
    nominal_stored_overage_byte_length: u64,
    nominal_stored_headroom_byte_length: u64,
    automatic_stored_overage_byte_length: u64,
    automatic_stored_headroom_byte_length: u64,
    absolute_stored_headroom_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConstructionAccounting {
    construction_identity_byte_length: u64,
    construction_identity_hash_hex: String,
    logical_polynomials_per_physical_row: u64,
    outer_query_count: u32,
    direct_bound_query_count: u32,
    prior_proof_bound_query_count: u32,
    aggregate_logical_column_count: u32,
    aggregate_table_width: u32,
    opening_batch_count: u32,
    scalar_opening_count: u32,
    transcript_operation_count: u32,
    ordered_proof_sections: Vec<ProofSectionAccounting>,
    ordered_checkpoints: Vec<CheckpointAccounting>,
    ordered_query_epochs: Vec<QueryEpochAccounting>,
    compact_frontiers: Vec<CompactFrontierAccounting>,
    aggregate_opening_sections: Vec<AggregateOpeningSectionAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofSectionAccounting {
    section_ordinal: u32,
    role_code: u16,
    role_name: String,
    phase_code: Option<u8>,
    associated_ordinal: Option<u32>,
    item_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointAccounting {
    checkpoint_ordinal: u32,
    boundary_code: u16,
    boundary_name: String,
    phase_code: Option<u8>,
    round_ordinal: Option<u32>,
    next_transcript_operation_ordinal: u32,
    next_proof_section_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QueryEpochAccounting {
    epoch_ordinal: u32,
    bit_length: u32,
    domain_size: u64,
    query_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactFrontierAccounting {
    role_code: u16,
    role_name: String,
    phase_code: Option<u8>,
    associated_ordinal: Option<u32>,
    leaf_count: u64,
    query_count: u32,
    opened_value_byte_length: u64,
    maximum_frontier_node_count: u32,
    frontier_byte_length: u64,
    canonical_opening_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AggregateOpeningSectionAccounting {
    section_name: String,
    byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteActionAccounting {
    ordered_proof_families: Vec<ProofFamilyAccounting>,
    physical_proof_count: u32,
    logical_entry_count: u64,
    proof_byte_ceiling: u64,
    setup_physical_proof_count: u32,
    setup_proof_byte_ceiling: u64,
    ballot_physical_proof_count: u32,
    ballot_proof_byte_ceiling: u64,
    target_release_physical_proof_count: u32,
    target_release_proof_byte_ceiling: u64,
    maximum_one_browser_wasm_resident_byte_length: u64,
    material: CompleteActionMaterialAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofFamilyAccounting {
    application_statement_schema_identifier: u16,
    physical_proof_count: u32,
    compiler_variant_count: u32,
    selected_variant_count: u32,
    maximum_logical_entry_count_per_proof: u32,
    complete_action_logical_entry_count: u64,
    maximum_proof_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteActionMaterialAccounting {
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

fn derive_static_resource_accounting_record() -> Result<StaticResourceAccountingRecord, String> {
    let record = StaticResourceAccountingRecord {
        source_identity: derive_source_identity()?,
        build_identity: derive_build_identity()?,
        candidate_input: derive_candidate_input_identity()?,
        caps: derive_caps()?,
        ordered_proof_variants: derive_proof_variants()?,
        complete_action: derive_complete_action()?,
        phase_liveness: derive_selected_complete_action_phase_liveness_accounting()?,
        target_release: derive_selected_target_release_static_accounting(
            selected_target_share_proof_byte_length_ceiling()?,
        )
        .map_err(|error| format!("derive target-release accounting: {error:?}"))?,
    };
    verify_record(&record)?;
    Ok(record)
}

fn derive_candidate_input_identity() -> Result<CandidateInputIdentity, String> {
    let proof_profile_bytes =
        selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
            .map_err(|error| format!("derive selected proof profile: {error:?}"))?
            .canonical_bytes()
            .map_err(|error| format!("encode selected proof profile: {error:?}"))?;
    let evaluator_program_bytes = selected_evaluator_program_set()
        .map_err(|error| format!("derive selected evaluator program: {error}"))?
        .encode()
        .map_err(|error| format!("encode selected evaluator program: {error}"))?;
    let bgv_parameters_canonical_object_hash_hex =
        bgv_parameters_hash().map_err(|error| format!("derive BGV parameter hash: {error}"))?;
    let evaluator_program_hash_hex = to_hex(&hash_framed_parts_512(
        "sealed-lattice/evaluator-program/static-resource-accounting/v1",
        &[&evaluator_program_bytes],
    ));
    let combined_input_shake256_hex = to_hex(&hash_framed_parts_512(
        CANDIDATE_INPUT_HASH_DOMAIN,
        &[
            bgv_parameters_canonical_object_hash_hex.as_bytes(),
            &proof_profile_bytes,
            &evaluator_program_bytes,
            evaluator_program_hash_hex.as_bytes(),
        ],
    ));
    Ok(CandidateInputIdentity {
        participant_count: FOUNDATION_PROFILE.participant_count,
        option_count: FOUNDATION_PROFILE.option_count,
        maximum_ballot_attempts_per_participant: u32::from(
            SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        ),
        maximum_candidate_packages_per_action: SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
        bgv_parameters_canonical_object_hash_hex,
        proof_profile_byte_length: u64::try_from(proof_profile_bytes.len())
            .map_err(|_| "proof profile length exceeds u64".to_owned())?,
        evaluator_program_byte_length: u64::try_from(evaluator_program_bytes.len())
            .map_err(|_| "evaluator program length exceeds u64".to_owned())?,
        evaluator_program_hash_hex,
        combined_input_shake256_hex,
    })
}

fn selected_target_share_proof_byte_length_ceiling() -> Result<u64, String> {
    selected_proof_variant_resource_inventory()
        .map_err(|error| format!("derive selected proof variants: {error:?}"))?
        .iter()
        .filter(|variant| {
            variant.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
        })
        .map(|variant| variant.canonical_proof_byte_length())
        .max()
        .ok_or_else(|| "selected target-share proof family is missing".to_owned())
}

fn derive_caps() -> Result<StaticResourceCaps, String> {
    Ok(StaticResourceCaps {
        nominal_proof_byte_length: u64::try_from(NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH)
            .map_err(|_| "nominal proof length exceeds u64".to_owned())?,
        automatic_proof_acceptance_byte_length: u64::try_from(
            AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH,
        )
        .map_err(|_| "automatic proof acceptance length exceeds u64".to_owned())?,
        common_authenticated_stream_hard_limit_byte_length: u64::try_from(
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        )
        .map_err(|_| "common proof limit exceeds u64".to_owned())?,
        maximum_proof_output_chunk_byte_length: u64::try_from(
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .map_err(|_| "proof chunk length exceeds u64".to_owned())?,
        maximum_external_memory_transaction_chunk_byte_length: u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        ),
        maximum_external_memory_object_count: u64::try_from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        )
        .map_err(|_| "external-memory object count exceeds u64".to_owned())?,
        nominal_external_memory_stored_byte_length:
            NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        automatic_external_memory_stored_byte_length:
            AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        maximum_external_memory_stored_byte_length:
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        nominal_proof_wasm_resident_byte_length: NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        automatic_proof_wasm_resident_byte_length: AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        maximum_proof_wasm_resident_byte_length: MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        maximum_local_record_seal_invocations_per_active_root:
            MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
        maximum_local_record_sealed_plaintext_bytes_per_active_root:
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
    })
}

fn derive_proof_variants() -> Result<Vec<ProofVariantAccounting>, String> {
    selected_proof_variant_resource_inventory()
        .map_err(|error| format!("derive selected proof variants: {error:?}"))?
        .iter()
        .map(|variant| {
            let external = variant.external_memory_requirement();
            let construction = variant.construction();
            Ok(ProofVariantAccounting {
                application_statement_schema_identifier: variant
                    .application_statement_schema_identifier(),
                selector: ProofVariantSelector {
                    schedule_position: variant.schedule_position(),
                    top_count: variant.top_count(),
                },
                complete_action_application_multiplicity: variant
                    .complete_action_application_multiplicity(),
                logical_entry_count: variant.logical_entry_count(),
                relation_column_count: variant.relation_column_count(),
                verifier_sequence_relation_column_count: variant
                    .verifier_sequence_relation_column_count(),
                bound_tree_relation_column_count: variant.bound_tree_relation_column_count(),
                prover_relation_column_count: variant.prover_relation_column_count(),
                relation_constraint_count: variant.relation_constraint_count(),
                opening_claim_count: variant.opening_claim_count(),
                canonical_header_byte_length: variant.canonical_header_byte_length(),
                canonical_family_body_byte_length: variant.canonical_family_body_byte_length(),
                canonical_proof_byte_length: variant.canonical_proof_byte_length(),
                nominal_proof_overage_byte_length: variant.nominal_proof_overage_byte_length(),
                nominal_proof_headroom_byte_length: variant.nominal_proof_headroom_byte_length(),
                automatic_acceptance_overage_byte_length: variant
                    .automatic_acceptance_overage_byte_length(),
                automatic_acceptance_headroom_byte_length: variant
                    .automatic_acceptance_headroom_byte_length(),
                absolute_bound_headroom_byte_length: variant.absolute_bound_headroom_byte_length(),
                maximum_verifier_resident_byte_length: variant
                    .maximum_verifier_resident_byte_length(),
                generation_wasm_resident_hard_bound_byte_length: variant
                    .generation_wasm_resident_hard_bound_byte_length(),
                external_memory: ExternalMemoryAccounting {
                    step_count: external.step_count(),
                    maximum_chunk_byte_length: external.maximum_chunk_byte_length(),
                    maximum_transaction_payload_byte_length: external
                        .maximum_transaction_payload_byte_length(),
                    distinct_physical_object_count: external.distinct_physical_object_count(),
                    object_lifecycle_count: external.object_lifecycle_count(),
                    peak_stored_byte_length: external.peak_stored_byte_length(),
                    nominal_stored_overage_byte_length: external
                        .peak_stored_byte_length()
                        .saturating_sub(NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
                    nominal_stored_headroom_byte_length:
                        NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                            .saturating_sub(external.peak_stored_byte_length()),
                    automatic_stored_overage_byte_length: external
                        .peak_stored_byte_length()
                        .saturating_sub(AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
                    automatic_stored_headroom_byte_length:
                        AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                            .saturating_sub(external.peak_stored_byte_length()),
                    absolute_stored_headroom_byte_length:
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                            .saturating_sub(external.peak_stored_byte_length()),
                    total_written_byte_length: external.total_written_byte_length(),
                    total_read_byte_length: external.total_read_byte_length(),
                    transaction_count: external.transaction_count(),
                    local_record_seal_invocation_count: external
                        .local_record_seal_invocation_count(),
                    local_record_sealed_plaintext_byte_length: external
                        .local_record_sealed_plaintext_byte_length(),
                },
                construction: ConstructionAccounting {
                    construction_identity_byte_length: construction
                        .construction_identity_byte_length(),
                    construction_identity_hash_hex: to_hex(
                        &construction.construction_identity_hash(),
                    ),
                    logical_polynomials_per_physical_row: construction
                        .logical_polynomials_per_physical_row(),
                    outer_query_count: construction.outer_query_count(),
                    direct_bound_query_count: construction.direct_bound_query_count(),
                    prior_proof_bound_query_count: construction.prior_proof_bound_query_count(),
                    aggregate_logical_column_count: construction.aggregate_logical_column_count(),
                    aggregate_table_width: construction.aggregate_table_width(),
                    opening_batch_count: construction.opening_batch_count(),
                    scalar_opening_count: construction.scalar_opening_count(),
                    transcript_operation_count: construction.transcript_operation_count(),
                    ordered_proof_sections: construction
                        .ordered_proof_sections()
                        .iter()
                        .map(|section| ProofSectionAccounting {
                            section_ordinal: section.section_ordinal(),
                            role_code: section.role_code(),
                            role_name: section.role_name().to_owned(),
                            phase_code: section.phase_code(),
                            associated_ordinal: section.associated_ordinal(),
                            item_count: section.item_count(),
                        })
                        .collect(),
                    ordered_checkpoints: construction
                        .ordered_checkpoints()
                        .iter()
                        .map(|checkpoint| CheckpointAccounting {
                            checkpoint_ordinal: checkpoint.checkpoint_ordinal(),
                            boundary_code: checkpoint.boundary_code(),
                            boundary_name: checkpoint.boundary_name().to_owned(),
                            phase_code: checkpoint.phase_code(),
                            round_ordinal: checkpoint.round_ordinal(),
                            next_transcript_operation_ordinal: checkpoint
                                .next_transcript_operation_ordinal(),
                            next_proof_section_ordinal: checkpoint.next_proof_section_ordinal(),
                        })
                        .collect(),
                    ordered_query_epochs: construction
                        .ordered_query_epochs()
                        .iter()
                        .map(|epoch| QueryEpochAccounting {
                            epoch_ordinal: epoch.epoch_ordinal(),
                            bit_length: epoch.bit_length(),
                            domain_size: epoch.domain_size(),
                            query_count: epoch.query_count(),
                        })
                        .collect(),
                    compact_frontiers: construction
                        .compact_frontiers()
                        .iter()
                        .map(|frontier| CompactFrontierAccounting {
                            role_code: frontier.role_code(),
                            role_name: frontier.role_name().to_owned(),
                            phase_code: frontier.phase_code(),
                            associated_ordinal: frontier.associated_ordinal(),
                            leaf_count: frontier.leaf_count(),
                            query_count: frontier.query_count(),
                            opened_value_byte_length: frontier.opened_value_byte_length(),
                            maximum_frontier_node_count: frontier.maximum_frontier_node_count(),
                            frontier_byte_length: frontier.frontier_byte_length(),
                            canonical_opening_byte_length: frontier.canonical_opening_byte_length(),
                        })
                        .collect(),
                    aggregate_opening_sections: construction
                        .aggregate_opening_sections()
                        .iter()
                        .map(|section| AggregateOpeningSectionAccounting {
                            section_name: section.section_name().to_owned(),
                            byte_length: section.byte_length(),
                        })
                        .collect(),
                },
            })
        })
        .collect()
}

fn derive_complete_action() -> Result<CompleteActionAccounting, String> {
    let accounting = selected_complete_proof_resource_accounting()
        .map_err(|error| format!("derive complete proof accounting: {error:?}"))?;
    Ok(CompleteActionAccounting {
        ordered_proof_families: accounting
            .ordered_families()
            .iter()
            .map(|family| ProofFamilyAccounting {
                application_statement_schema_identifier: family
                    .application_statement_schema_identifier(),
                physical_proof_count: family.physical_proof_count(),
                compiler_variant_count: family.compiler_variant_count(),
                selected_variant_count: family.selected_variant_count(),
                maximum_logical_entry_count_per_proof: family
                    .maximum_logical_entry_count_per_proof(),
                complete_action_logical_entry_count: family.complete_action_logical_entry_count(),
                maximum_proof_byte_length: family.maximum_proof_byte_length(),
            })
            .collect(),
        physical_proof_count: accounting.physical_proof_count(),
        logical_entry_count: accounting.complete_action_logical_entry_count(),
        proof_byte_ceiling: accounting.complete_action_proof_byte_ceiling(),
        setup_physical_proof_count: accounting.setup_physical_proof_count(),
        setup_proof_byte_ceiling: accounting.setup_proof_byte_ceiling(),
        ballot_physical_proof_count: accounting.ballot_physical_proof_count(),
        ballot_proof_byte_ceiling: accounting.ballot_proof_byte_ceiling(),
        target_release_physical_proof_count: accounting.target_release_physical_proof_count(),
        target_release_proof_byte_ceiling: accounting.target_release_proof_byte_ceiling(),
        maximum_one_browser_wasm_resident_byte_length: accounting
            .maximum_one_browser_wasm_resident_byte_length(),
        material: material_accounting(accounting.material_resources()),
    })
}

fn material_accounting(
    material: SelectedCompleteActionMaterialResourceAccounting,
) -> CompleteActionMaterialAccounting {
    CompleteActionMaterialAccounting {
        one_dealer_recipient_private_vss_payload_byte_length: material
            .one_dealer_recipient_private_vss_payload_byte_length(),
        one_dealer_private_vss_payload_upload_byte_length: material
            .one_dealer_private_vss_payload_upload_byte_length(),
        one_recipient_private_vss_payload_download_byte_length: material
            .one_recipient_private_vss_payload_download_byte_length(),
        ceremony_private_vss_payload_byte_length: material
            .ceremony_private_vss_payload_byte_length(),
        evaluator_source_wire_byte_length_per_participant: material
            .evaluator_source_wire_byte_length_per_participant(),
        evaluator_source_resident_byte_length_per_participant: material
            .evaluator_source_resident_byte_length_per_participant(),
        final_evaluator_key_store_wire_byte_length: material
            .final_evaluator_key_store_wire_byte_length(),
        final_evaluator_key_store_resident_byte_length: material
            .final_evaluator_key_store_resident_byte_length(),
        ceremony_evaluator_setup_wire_byte_length: material
            .ceremony_evaluator_setup_wire_byte_length(),
        ceremony_evaluator_source_and_final_resident_volume_byte_length: material
            .ceremony_evaluator_source_and_final_resident_volume_byte_length(),
        one_ballot_ciphertext_stream_byte_length: material
            .one_ballot_ciphertext_stream_byte_length(),
        one_ballot_ciphertext_stream_chunk_count: material
            .one_ballot_ciphertext_stream_chunk_count(),
        complete_action_ballot_candidate_package_corpus_byte_length: material
            .complete_action_ballot_candidate_package_corpus_byte_length(),
        complete_action_ballot_candidate_package_corpus_chunk_count: material
            .complete_action_ballot_candidate_package_corpus_chunk_count(),
        ballot_prover_material_live_set_peak_byte_length: material
            .ballot_prover_material_live_set_peak_byte_length(),
        one_target_ciphertext_canonical_byte_length_ceiling: material
            .one_target_ciphertext_canonical_byte_length_ceiling(),
        paired_target_ciphertext_canonical_byte_length_ceiling: material
            .paired_target_ciphertext_canonical_byte_length_ceiling(),
        one_target_partial_stream_byte_length: material.one_target_partial_stream_byte_length(),
        one_participant_paired_target_partial_stream_byte_length: material
            .one_participant_paired_target_partial_stream_byte_length(),
        ceremony_paired_target_partial_stream_byte_length: material
            .ceremony_paired_target_partial_stream_byte_length(),
    }
}

fn verify_record(record: &StaticResourceAccountingRecord) -> Result<(), String> {
    let nominal_proof_byte_length = u64::try_from(NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH)
        .map_err(|_| "nominal proof length exceeds u64".to_owned())?;
    let automatic_proof_acceptance_byte_length =
        u64::try_from(AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH)
            .map_err(|_| "automatic proof acceptance length exceeds u64".to_owned())?;
    if record.caps.nominal_proof_byte_length != nominal_proof_byte_length
        || record.caps.automatic_proof_acceptance_byte_length
            != automatic_proof_acceptance_byte_length
        || record.caps.automatic_proof_acceptance_byte_length
            > record
                .caps
                .common_authenticated_stream_hard_limit_byte_length
        || record.caps.nominal_external_memory_stored_byte_length
            != NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || record.caps.automatic_external_memory_stored_byte_length
            != AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || record.caps.maximum_external_memory_stored_byte_length
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || record.caps.nominal_external_memory_stored_byte_length
            > record.caps.automatic_external_memory_stored_byte_length
        || record.caps.automatic_external_memory_stored_byte_length
            > record.caps.maximum_external_memory_stored_byte_length
        || record.caps.nominal_proof_wasm_resident_byte_length
            != NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || record.caps.automatic_proof_wasm_resident_byte_length
            != AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || record.caps.maximum_proof_wasm_resident_byte_length
            != MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || record.caps.nominal_proof_wasm_resident_byte_length
            > record.caps.automatic_proof_wasm_resident_byte_length
        || record.caps.automatic_proof_wasm_resident_byte_length
            > record.caps.maximum_proof_wasm_resident_byte_length
        || record.candidate_input.participant_count != 10
        || record.ordered_proof_variants.len() != 31
        || record.complete_action.ordered_proof_families.len()
            != FIRST_PROFILE_APPLICATION_FAMILIES.len()
        || record.complete_action.physical_proof_count != 103
        || record
            .complete_action
            .maximum_one_browser_wasm_resident_byte_length
            > record.caps.maximum_proof_wasm_resident_byte_length
        || record.phase_liveness.physical_proof_count()
            != record.complete_action.physical_proof_count
        || record.phase_liveness.complete_action_proof_byte_ceiling()
            != record.complete_action.proof_byte_ceiling
    {
        return Err("selected complete-action accounting has inconsistent topology".to_owned());
    }
    let family_identifiers = record
        .complete_action
        .ordered_proof_families
        .iter()
        .map(|family| family.application_statement_schema_identifier)
        .collect::<BTreeSet<_>>();
    if family_identifiers
        != FIRST_PROFILE_APPLICATION_FAMILIES
            .into_iter()
            .collect::<BTreeSet<_>>()
    {
        return Err("selected proof-family inventory is incomplete".to_owned());
    }
    let mut selectors = BTreeSet::new();
    let mut physical_count = 0_u32;
    let mut logical_count = 0_u64;
    let mut proof_byte_ceiling = 0_u64;
    for variant in &record.ordered_proof_variants {
        let expected_logical_polynomials_per_physical_row = if matches!(
            variant.application_statement_schema_identifier,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        ) {
            u64::try_from(ROW_CODE_WHIR_COMPACT_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW)
                .map_err(|_| "compact row width exceeds u64".to_owned())?
        } else {
            u64::try_from(
                RowCodeWhirSelectedParameters::selected()
                    .logical_polynomials_per_physical_row,
            )
            .map_err(|_| "maximum row width exceeds u64".to_owned())?
        };
        let opening_evaluation_byte_length = variant
            .construction
            .aggregate_opening_sections
            .iter()
            .find(|section| section.section_name == "opening-evaluations")
            .map(|section| section.byte_length);
        if !selectors.insert((
            variant.application_statement_schema_identifier,
            variant.selector.schedule_position,
            variant.selector.top_count,
        )) || variant.canonical_header_byte_length == 0
            || variant.canonical_family_body_byte_length == 0
            || variant
                .canonical_header_byte_length
                .checked_add(variant.canonical_family_body_byte_length)
                != Some(variant.canonical_proof_byte_length)
            || variant.canonical_proof_byte_length == 0
            || variant.canonical_proof_byte_length
                > record
                    .caps
                    .common_authenticated_stream_hard_limit_byte_length
            || variant.nominal_proof_headroom_byte_length
                != record
                    .caps
                    .nominal_proof_byte_length
                    .saturating_sub(variant.canonical_proof_byte_length)
            || variant.nominal_proof_overage_byte_length
                != variant
                    .canonical_proof_byte_length
                    .saturating_sub(record.caps.nominal_proof_byte_length)
            || variant.automatic_acceptance_overage_byte_length
                != variant
                    .canonical_proof_byte_length
                    .saturating_sub(record.caps.automatic_proof_acceptance_byte_length)
            || variant.automatic_acceptance_headroom_byte_length
                != record
                    .caps
                    .automatic_proof_acceptance_byte_length
                    .saturating_sub(variant.canonical_proof_byte_length)
            || variant.absolute_bound_headroom_byte_length
                != record
                    .caps
                    .common_authenticated_stream_hard_limit_byte_length
                    .saturating_sub(variant.canonical_proof_byte_length)
            || variant.maximum_verifier_resident_byte_length
                > record.caps.maximum_proof_wasm_resident_byte_length
            || variant.construction.construction_identity_byte_length == 0
            || variant.construction.logical_polynomials_per_physical_row
                != expected_logical_polynomials_per_physical_row
            || variant.construction.aggregate_logical_column_count
                > variant.construction.aggregate_table_width
            || variant.construction.scalar_opening_count == 0
            || opening_evaluation_byte_length
                != Some(
                    u64::from(variant.construction.scalar_opening_count)
                        * u64::try_from(
                            PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>(),
                        )
                        .map_err(|_| "challenge-field wire width exceeds u64".to_owned())?,
                )
            || variant.construction.compact_frontiers.is_empty()
            || variant.construction.aggregate_opening_sections.is_empty()
        {
            return Err("selected proof variant accounting is inconsistent".to_owned());
        }
        for frontier in &variant.construction.compact_frontiers {
            if frontier.leaf_count == 0
                || !frontier.leaf_count.is_power_of_two()
                || frontier.query_count == 0
                || frontier.frontier_byte_length
                    != u64::from(frontier.maximum_frontier_node_count) * 64 + 4
                || frontier.canonical_opening_byte_length
                    != frontier.opened_value_byte_length + frontier.frontier_byte_length
            {
                return Err(
                    "coordinate-derived compact-frontier accounting is inconsistent".to_owned(),
                );
            }
        }
        let external = &variant.external_memory;
        if external.maximum_chunk_byte_length
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || usize::try_from(external.distinct_physical_object_count)
                .ok()
                .is_none_or(|count| count > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
            || external.peak_stored_byte_length
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            || external.nominal_stored_overage_byte_length
                != external
                    .peak_stored_byte_length
                    .saturating_sub(record.caps.nominal_external_memory_stored_byte_length)
            || external.nominal_stored_headroom_byte_length
                != record
                    .caps
                    .nominal_external_memory_stored_byte_length
                    .saturating_sub(external.peak_stored_byte_length)
            || external.automatic_stored_overage_byte_length
                != external
                    .peak_stored_byte_length
                    .saturating_sub(record.caps.automatic_external_memory_stored_byte_length)
            || external.automatic_stored_headroom_byte_length
                != record
                    .caps
                    .automatic_external_memory_stored_byte_length
                    .saturating_sub(external.peak_stored_byte_length)
            || external.absolute_stored_headroom_byte_length
                != record
                    .caps
                    .maximum_external_memory_stored_byte_length
                    .saturating_sub(external.peak_stored_byte_length)
            || external.local_record_seal_invocation_count
                > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
            || external.local_record_sealed_plaintext_byte_length
                > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
        {
            return Err("selected proof external-memory accounting exceeds its bound".to_owned());
        }
        let multiplicity = variant.complete_action_application_multiplicity;
        physical_count = physical_count
            .checked_add(multiplicity)
            .ok_or_else(|| "physical proof count overflowed".to_owned())?;
        logical_count = logical_count
            .checked_add(
                u64::from(variant.logical_entry_count)
                    .checked_mul(u64::from(multiplicity))
                    .ok_or_else(|| "logical proof count overflowed".to_owned())?,
            )
            .ok_or_else(|| "complete logical proof count overflowed".to_owned())?;
        proof_byte_ceiling = proof_byte_ceiling
            .checked_add(
                variant
                    .canonical_proof_byte_length
                    .checked_mul(u64::from(multiplicity))
                    .ok_or_else(|| "proof byte ceiling overflowed".to_owned())?,
            )
            .ok_or_else(|| "complete proof byte ceiling overflowed".to_owned())?;
    }
    if physical_count != record.complete_action.physical_proof_count
        || logical_count != record.complete_action.logical_entry_count
        || proof_byte_ceiling != record.complete_action.proof_byte_ceiling
    {
        return Err(
            "complete-action proof totals do not reconcile variant multiplicities".to_owned(),
        );
    }
    let value = serde_json::to_value(record)
        .map_err(|error| format!("convert accounting record to JSON: {error}"))?;
    require_exact_json_integers(&value, "record")
}

fn evidence_envelope(
    record: StaticResourceAccountingRecord,
) -> Result<StaticResourceAccountingEnvelope, String> {
    let bytes = serde_json::to_vec(&record)
        .map_err(|error| format!("serialize accounting record: {error}"))?;
    Ok(StaticResourceAccountingEnvelope {
        record_kind: RECORD_KIND.to_owned(),
        record_version: RECORD_VERSION,
        record_byte_length: u64::try_from(bytes.len())
            .map_err(|_| "accounting record length exceeds u64".to_owned())?,
        record_shake256_hex: to_hex(&hash_framed_parts_512(RECORD_HASH_DOMAIN, &[&bytes])),
        record,
    })
}

fn verify_envelope(envelope: &StaticResourceAccountingEnvelope) -> Result<(), String> {
    if envelope.record_kind != RECORD_KIND || envelope.record_version != RECORD_VERSION {
        return Err("static resource-accounting envelope has the wrong identity".to_owned());
    }
    verify_record(&envelope.record)?;
    let bytes = serde_json::to_vec(&envelope.record)
        .map_err(|error| format!("serialize accounting record: {error}"))?;
    if envelope.record_byte_length
        != u64::try_from(bytes.len()).map_err(|_| "record length exceeds u64".to_owned())?
        || envelope.record_shake256_hex
            != to_hex(&hash_framed_parts_512(RECORD_HASH_DOMAIN, &[&bytes]))
    {
        return Err("static resource-accounting envelope binding is invalid".to_owned());
    }
    Ok(())
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
    let part_count = u64::try_from(source_paths.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| "source identity part count overflowed".to_owned())?;
    let mut hasher = StreamingHash512::new(SOURCE_HASH_DOMAIN, part_count);
    let mut total_byte_length = 0_u64;
    for path in &source_paths {
        hasher.absorb_part(normalized_relative_path(repository_root, path)?.as_bytes());
        total_byte_length = total_byte_length
            .checked_add(absorb_file_part(&mut hasher, path)?)
            .ok_or_else(|| "source identity byte length overflowed".to_owned())?;
    }
    Ok(SourceIdentity {
        file_count: u32::try_from(source_paths.len())
            .map_err(|_| "source identity file count exceeds u32".to_owned())?,
        byte_length: total_byte_length,
        shake256_hex: to_hex(&hasher.finalize()),
    })
}

fn collect_rust_source_paths(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read source directory {}: {error}", directory.display()))?
    {
        let entry = entry
            .map_err(|error| format!("read source entry in {}: {error}", directory.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect source path {}: {error}", entry.path().display()))?;
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
    path.strip_prefix(repository_root)
        .map_err(|_| format!("source path {} is outside the repository", path.display()))?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("source path {} is not UTF-8", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn absorb_file_part(hasher: &mut StreamingHash512, path: &Path) -> Result<u64, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("open identity input {}: {error}", path.display()))?;
    let declared_byte_length = file
        .metadata()
        .map_err(|error| format!("stat identity input {}: {error}", path.display()))?
        .len();
    hasher.begin_part(declared_byte_length);
    let mut observed_byte_length = 0_u64;
    let mut buffer = [0_u8; 1_048_576];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read identity input {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.absorb_raw(&buffer[..count]);
        observed_byte_length = observed_byte_length
            .checked_add(u64::try_from(count).map_err(|_| "read length exceeds u64".to_owned())?)
            .ok_or_else(|| "identity read length overflowed".to_owned())?;
    }
    if observed_byte_length != declared_byte_length {
        return Err(format!(
            "identity input {} changed while hashing",
            path.display()
        ));
    }
    Ok(observed_byte_length)
}

fn derive_build_identity() -> Result<BuildIdentity, String> {
    let executable_path =
        env::current_exe().map_err(|error| format!("resolve current test executable: {error}"))?;
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
                return Err(format!("{location} exceeds the exact JSON integer range"));
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
            "create attachment directory {}: {error}",
            attachment_directory.display()
        )
    })?;
    let target_path = attachment_directory.join(ATTACHMENT_FILE_NAME);
    if target_path.exists() {
        let existing = fs::read(&target_path)
            .map_err(|error| format!("read attachment {}: {error}", target_path.display()))?;
        if existing != bytes {
            return Err(format!(
                "existing attachment {} differs",
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
            .map_err(|error| format!("create attachment {}: {error}", temporary_path.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write attachment {}: {error}", temporary_path.display()))?;
        file.sync_all().map_err(|error| {
            format!(
                "synchronize attachment {}: {error}",
                temporary_path.display()
            )
        })?;
        fs::rename(&temporary_path, &target_path)
            .map_err(|error| format!("publish attachment {}: {error}", target_path.display()))
    })();
    if result.is_err() && temporary_path.exists() {
        let _ = fs::remove_file(&temporary_path);
    }
    result?;
    Ok(target_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_resource_accounting_rejects_mutated_proof_and_frontier_totals() {
        let record = derive_static_resource_accounting_record()
            .expect("selected static resource accounting derives");
        let mut oversized = record.clone();
        let oversized_proof_byte_length = oversized
            .caps
            .common_authenticated_stream_hard_limit_byte_length
            .checked_add(1)
            .expect("the oversized proof length fits u64");
        let nominal_proof_byte_length = oversized.caps.nominal_proof_byte_length;
        let automatic_proof_acceptance_byte_length =
            oversized.caps.automatic_proof_acceptance_byte_length;
        let oversized_variant = &mut oversized.ordered_proof_variants[0];
        oversized_variant.canonical_family_body_byte_length = oversized_proof_byte_length
            .checked_sub(oversized_variant.canonical_header_byte_length)
            .expect("the oversized proof exceeds its header");
        oversized_variant.canonical_proof_byte_length = oversized_proof_byte_length;
        oversized_variant.nominal_proof_overage_byte_length =
            oversized_proof_byte_length.saturating_sub(nominal_proof_byte_length);
        oversized_variant.nominal_proof_headroom_byte_length = 0;
        oversized_variant.automatic_acceptance_overage_byte_length =
            oversized_proof_byte_length.saturating_sub(automatic_proof_acceptance_byte_length);
        oversized_variant.automatic_acceptance_headroom_byte_length = 0;
        oversized_variant.absolute_bound_headroom_byte_length = 0;
        assert_eq!(
            verify_record(&oversized),
            Err("selected proof variant accounting is inconsistent".to_owned()),
        );

        let mut wrong_variance = record.clone();
        wrong_variance.ordered_proof_variants[0].nominal_proof_overage_byte_length += 1;
        assert_eq!(
            verify_record(&wrong_variance),
            Err("selected proof variant accounting is inconsistent".to_owned()),
        );

        let mut wrong_scratch_variance = record.clone();
        wrong_scratch_variance.ordered_proof_variants[0]
            .external_memory
            .absolute_stored_headroom_byte_length += 1;
        assert_eq!(
            verify_record(&wrong_scratch_variance),
            Err("selected proof external-memory accounting exceeds its bound".to_owned()),
        );

        let mut wrong_scalar_opening_count = record.clone();
        wrong_scalar_opening_count.ordered_proof_variants[0]
            .construction
            .scalar_opening_count += 1;
        assert_eq!(
            verify_record(&wrong_scalar_opening_count),
            Err("selected proof variant accounting is inconsistent".to_owned()),
        );

        let mut wrong_row_width = record.clone();
        wrong_row_width.ordered_proof_variants[0]
            .construction
            .logical_polynomials_per_physical_row += 1;
        assert_eq!(
            verify_record(&wrong_row_width),
            Err("selected proof variant accounting is inconsistent".to_owned()),
        );

        let mut malformed_frontier = record;
        malformed_frontier.ordered_proof_variants[0]
            .construction
            .compact_frontiers[0]
            .frontier_byte_length += 64;
        assert_eq!(
            verify_record(&malformed_frontier),
            Err("coordinate-derived compact-frontier accounting is inconsistent".to_owned()),
        );
    }

    #[test]
    #[ignore = "guarded selected static resource-accounting evidence"]
    fn selected_candidate_static_resource_accounting_emits_run_attachment() {
        let first = derive_static_resource_accounting_record()
            .expect("selected static resource accounting derives");
        let second = derive_static_resource_accounting_record()
            .expect("selected static resource accounting re-derives");
        assert_eq!(first, second, "static derivation is deterministic");

        let envelope =
            evidence_envelope(first).expect("selected static resource-accounting envelope derives");
        verify_envelope(&envelope).expect("selected static resource-accounting envelope verifies");
        let compact = serde_json::to_vec(&envelope)
            .expect("selected static resource-accounting envelope serializes");
        let decoded: StaticResourceAccountingEnvelope = serde_json::from_slice(&compact)
            .expect("selected static resource-accounting envelope decodes");
        assert_eq!(decoded, envelope);

        let mut wrong_hash = decoded.clone();
        wrong_hash.record_shake256_hex = "00".repeat(64);
        assert_eq!(
            verify_envelope(&wrong_hash),
            Err("static resource-accounting envelope binding is invalid".to_owned()),
        );

        let mut attachment_bytes = serde_json::to_vec_pretty(&decoded)
            .expect("selected static resource-accounting attachment serializes");
        attachment_bytes.push(b'\n');
        let path = write_run_attachment(&attachment_bytes)
            .expect("selected static resource-accounting attachment writes");
        println!(
            "selected static resource-accounting attachment: {}",
            path.display()
        );
    }

    #[test]
    #[ignore = "guarded selected complete-action phase-liveness closure evidence"]
    fn selected_candidate_static_resource_accounting_closes_every_missing_carrier() {
        let record = derive_static_resource_accounting_record()
            .expect("selected static resource accounting derives without missing carriers");
        verify_record(&record).expect("selected static resource accounting closes");
        assert_eq!(record.candidate_input.participant_count, 10);
        assert_eq!(record.ordered_proof_variants.len(), 31);
        assert_eq!(
            record.caps.nominal_proof_byte_length,
            u64::try_from(NOMINAL_ROW_CODE_WHIR_PROOF_BYTE_LENGTH)
                .expect("the nominal proof length fits u64"),
        );
        assert_eq!(
            record.caps.automatic_proof_acceptance_byte_length,
            u64::try_from(AUTOMATIC_ROW_CODE_WHIR_PROOF_ACCEPTANCE_BYTE_LENGTH)
                .expect("the automatic proof acceptance length fits u64"),
        );
        assert!(record.ordered_proof_variants.iter().all(|variant| {
            variant.canonical_proof_byte_length
                <= record
                    .caps
                    .common_authenticated_stream_hard_limit_byte_length
        }));
        let same_secret = record
            .ordered_proof_variants
            .iter()
            .find(|variant| {
                variant.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            })
            .expect("the same-secret accounting row exists");
        assert_eq!(same_secret.canonical_proof_byte_length, 5_309_850);
        assert_eq!(same_secret.nominal_proof_overage_byte_length, 66_970);
        assert_eq!(same_secret.automatic_acceptance_overage_byte_length, 0);
        assert_eq!(
            same_secret.external_memory.peak_stored_byte_length,
            849_756_760
        );
        assert_eq!(
            same_secret
                .external_memory
                .nominal_stored_overage_byte_length,
            581_321_304,
        );
        assert_eq!(
            same_secret
                .external_memory
                .automatic_stored_overage_byte_length,
            447_103_576,
        );
        assert_eq!(
            same_secret
                .external_memory
                .absolute_stored_headroom_byte_length,
            223_985_064,
        );
        let engineering_review_rows = record
            .ordered_proof_variants
            .iter()
            .filter(|variant| variant.automatic_acceptance_overage_byte_length > 0)
            .map(|variant| {
                (
                    variant.application_statement_schema_identifier,
                    variant.canonical_proof_byte_length,
                    variant.automatic_acceptance_overage_byte_length,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            engineering_review_rows,
            vec![(
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                7_916_724,
                52_404,
            )],
        );
        let material = derive_selected_complete_action_material_resource_accounting()
            .expect("selected material accounting closes");
        assert_eq!(
            record.complete_action.material,
            material_accounting(material),
        );
    }
}
