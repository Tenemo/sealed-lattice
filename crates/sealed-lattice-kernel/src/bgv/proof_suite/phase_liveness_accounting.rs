//! Deterministic, test-only accounting for complete-action live-memory paths.
//!
//! Production accounting supplies exact alternative-local peaks and proof-phase
//! live sets. This module deliberately does not add maxima from mutually
//! exclusive alternatives or from phases whose overlap has not been derived by
//! a production lifetime carrier. Missing cross-subsystem lifetimes remain
//! explicit derivation inputs rather than becoming zero-byte assumptions.

use serde::{Deserialize, Serialize};

use crate::{
    bgv::{
        evaluator::{
            ballot_aggregation::{
                TwoStreamPairCharacterProductAccounting,
                canonical_two_stream_pair_character_product_accounting,
            },
            ballot_aggregation_runtime::selected_evaluator_pipeline_handoff_accounting,
            program::{
                SelectedEvaluatorExecutionResourceTotals,
                selected_evaluator_execution_resource_ledger,
            },
        },
        target_decryption::static_accounting::{
            SelectedTargetReleaseStaticAccounting, derive_selected_target_release_static_accounting,
        },
    },
    foundation::{FOUNDATION_PROFILE, ProofApplicationSlotCeilings},
};

use super::selected_accounting::{
    SelectedProofExternalMemoryDiagnosticError, SelectedProofExternalMemoryDiagnosticRequirement,
    SelectedProofExternalMemoryDiagnosticRow, SelectedProofResidentPhaseResourceAccounting,
    selected_proof_external_memory_diagnostic_report,
};
use super::selected_material_transport_accounting::{
    SelectedAggregatePublicCarrierAccounting, SelectedEvaluatorReplayCarrierCodecCeilingAccounting,
    SelectedEvaluatorReplayPublicCarrierAccounting, SelectedExactEvaluatorReplayCarrierAccounting,
    SelectedPrivateVssMailboxTransportAccounting,
    derive_selected_private_vss_mailbox_transport_accounting,
    derive_selected_unsigned_public_carrier_accounting,
};
use super::{
    CommonProofGenerationAttemptStart, CommonProofGenerationCumulativeWorkRule,
    CommonProofGenerationResumePrefixExecution, CommonProofGenerationResumeStateRestoration,
    common_proof_generation_attempt_topology,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedPhaseLivenessAccountingError {
    ProductAlternative,
    EvaluatorAlternative,
    MaterialTransport,
    ProofDiagnostic,
    InvalidTopology,
    CountOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedCompleteActionPhaseLivenessAccounting {
    ordered_product_alternatives: Box<[SelectedProductPhaseAlternative]>,
    ordered_evaluator_alternatives: Box<[SelectedEvaluatorPhaseAlternative]>,
    product_evaluator_handoff: SelectedProductEvaluatorHandoffAccounting,
    ordered_known_transport_paths: Box<[SelectedCanonicalTransportPhasePath]>,
    aggregate_public_transport: SelectedAggregatePublicTransportPhasePath,
    evaluator_replay_exact_transport: Option<SelectedEvaluatorReplayPublicTransportPhasePath>,
    evaluator_replay_transport_codec_ceiling: SelectedEvaluatorReplayTransportCodecCeiling,
    ordered_proof_variant_paths: Box<[SelectedProofVariantPhasePath]>,
    proof_generation_attempt_topology: SelectedProofGenerationAttemptTopology,
    target_release: SelectedTargetReleasePhasePathOutcome,
    missing_carriers: Box<[SelectedMissingPhaseLivenessCarrier]>,
}

impl SelectedCompleteActionPhaseLivenessAccounting {
    pub(crate) fn missing_carriers(&self) -> &[SelectedMissingPhaseLivenessCarrier] {
        &self.missing_carriers
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProductPhaseAlternative {
    ballot_count: u16,
    work: SelectedProductWorkAccounting,
    store_boundary: SelectedProductStoreBoundaryAccounting,
    peak_live_memory: SelectedProductPeakLiveMemoryAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedProductWorkAccounting {
    ballot_ciphertext_count: u64,
    ciphertext_multiplication_count: u64,
    relinearization_count: u64,
    normalization_plaintext_multiplication_count: u64,
    modulus_switch_count: u64,
    modulus_drop_count: u64,
    maximum_resident_ciphertext_count: u64,
    relinearization_key_load_count: u64,
    key_ntt_transform_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedProductStoreBoundaryAccounting {
    key_store_read_byte_length: u64,
    relinearization_key_component_wire_byte_length: u64,
    maximum_key_store_chunk_byte_length: u64,
    final_key_store_chunk_byte_length: u64,
    key_replay_limb_buffer_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedProductPeakLiveMemoryAccounting {
    maximum_live_ciphertext_coefficient_byte_length: u64,
    resident_relinearization_key_coefficient_byte_length: u64,
    peak_key_replay_wasm_resident_byte_length: u64,
    maximum_operation_transient_byte_length: u64,
    maximum_operation_scratch_byte_length: u64,
    peak_combined_wasm_resident_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedEvaluatorPhaseAlternative {
    top_count: u16,
    work: SelectedEvaluatorWorkAccounting,
    store_boundary: SelectedEvaluatorStoreBoundaryAccounting,
    peak_live_memory: SelectedEvaluatorPeakLiveMemoryAccounting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedEvaluatorWorkAccounting {
    instruction_count: u64,
    key_operation_count: u64,
    key_load_count: u64,
    key_ntt_transform_count: u64,
    rotation_count: u64,
    ciphertext_multiplication_count: u64,
    plaintext_multiplication_count: u64,
    modulus_switch_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedEvaluatorStoreBoundaryAccounting {
    key_store_read_request_count: u64,
    key_store_reread_request_count: u64,
    key_store_read_byte_length: u64,
    key_store_reread_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedEvaluatorPeakLiveMemoryAccounting {
    maximum_live_ciphertext_byte_length: u64,
    maximum_resident_key_byte_length: u64,
    maximum_operation_scratch_byte_length: u64,
    peak_combined_wasm_resident_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProductEvaluatorHandoffAccounting {
    transferred_ciphertext_count: u16,
    transferred_ciphertext_coefficient_byte_length: u64,
    coefficient_payload_copy_count: u16,
    aggregation_resident_key_byte_length_after_prepare: u64,
    evaluator_resident_key_byte_length_before_first_instruction: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedCanonicalTransportPhasePath {
    carrier_kind: String,
    physical_payload_stream_count: u64,
    ordered_material_root_count_per_envelope: u64,
    payload_byte_length_per_stream: u64,
    stream_chunk_count_per_stream: u64,
    stream_descriptor_byte_length_per_stream: u64,
    signed_mailbox_envelope_byte_length_per_stream: u64,
    complete_mailbox_byte_length_per_stream: u64,
    ceremony_upload_byte_length: u64,
    ceremony_download_byte_length: u64,
    private_mailbox_corpus_byte_length: u64,
    boundary_transfer_byte_length_per_direction_per_stream: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
    indexed_db_serialized_byte_length_per_operation: u64,
    indexed_db_additional_copy_peak_byte_length: u64,
    indexed_db_serialization_buffer_peak_byte_length: u64,
    indexed_db_readback_buffer_peak_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedAggregatePublicTransportPhasePath {
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
pub(crate) struct SelectedEvaluatorReplayTransportCodecCeiling {
    target_ciphertext_stream_byte_length_ceiling: u64,
    target_ciphertext_stream_chunk_count_ceiling: u64,
    canonical_envelope_byte_length_ceiling: u64,
    complete_public_object_byte_length_ceiling: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedEvaluatorReplayPublicTransportPhasePath {
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
pub(crate) struct SelectedProofVariantPhasePath {
    application_statement_schema_identifier: u16,
    selector: SelectedProofVariantPhaseSelector,
    relation_column_count: u64,
    relation_constraint_count: u64,
    outcome: SelectedProofVariantPhasePathOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum SelectedProofVariantPhaseSelector {
    Unparameterized,
    SchedulePosition { schedule_position: u32 },
    TopCount { top_count: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SelectedProofVariantPhasePathOutcome {
    Requirement {
        requirement: SelectedProofVariantPhaseLivenessRequirement,
    },
    DerivationError {
        reason_code: String,
        required_carrier: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProofVariantPhaseLivenessRequirement {
    complete_action_application_multiplicity: u32,
    proof_byte_length_ceiling: u64,
    proof_output_chunk_count_ceiling: u64,
    maximum_proof_output_chunk_byte_length: u64,
    maximum_prefetched_query_byte_length: u64,
    maximum_external_memory_transaction_payload_byte_length: u64,
    maximum_copied_buffer_byte_length: u64,
    maximum_combined_wasm_resident_byte_length: u64,
    fri_fold_count: u16,
    checkpoint_safe_boundary_count: u16,
    ordered_phases: Box<[SelectedProofResidentPhaseLivenessAccounting]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProofResidentPhaseLivenessAccounting {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedProofGenerationAttemptStart {
    CheckpointGenesis,
    CheckpointGenesisWithAuthenticatedResumeTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedProofGenerationResumePrefixExecution {
    DeterministicReplayFromGenesisThroughAuthenticatedTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedProofGenerationResumeStateRestoration {
    CheckpointTargetComparisonAndAuthenticatedTranscriptCursorRestoration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SelectedProofGenerationCumulativeWorkRule {
    PriorPrefixPlusReplayedPrefixPlusRemainingSuffix,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProofGenerationAttemptTopology {
    fresh_start: SelectedProofGenerationAttemptStart,
    resumed_start: SelectedProofGenerationAttemptStart,
    resumed_prefix_execution: SelectedProofGenerationResumePrefixExecution,
    resumed_state_restoration: SelectedProofGenerationResumeStateRestoration,
    cumulative_work_rule: SelectedProofGenerationCumulativeWorkRule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SelectedTargetReleasePhasePathOutcome {
    Accounting {
        accounting: Box<SelectedTargetReleaseStaticAccounting>,
    },
    DerivationError {
        reason_code: String,
        required_carrier: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedMissingPhaseLivenessCarrier {
    dimension: String,
    reason_code: String,
    required_carrier: String,
}

impl SelectedMissingPhaseLivenessCarrier {
    pub(crate) fn dimension(&self) -> &str {
        &self.dimension
    }

    pub(crate) fn reason_code(&self) -> &str {
        &self.reason_code
    }

    pub(crate) fn required_carrier(&self) -> &str {
        &self.required_carrier
    }
}

pub(crate) fn derive_selected_complete_action_phase_liveness_accounting()
-> Result<SelectedCompleteActionPhaseLivenessAccounting, SelectedPhaseLivenessAccountingError> {
    let ordered_product_alternatives = derive_product_alternatives()?;
    let ordered_evaluator_alternatives = derive_evaluator_alternatives()?;
    let product_evaluator_handoff = derive_product_evaluator_handoff()?;
    let ordered_known_transport_paths = derive_known_transport_paths()?;
    let (
        aggregate_public_transport,
        evaluator_replay_transport_codec_ceiling,
        evaluator_replay_exact_transport,
    ) = derive_unsigned_public_transport()?;
    let (ordered_proof_variant_paths, mut missing_carriers) = derive_proof_variant_paths()?;
    let (target_release, target_release_missing_carriers) =
        derive_target_release_phase_path(&ordered_proof_variant_paths);
    missing_carriers.extend(target_release_missing_carriers);
    if evaluator_replay_exact_transport.is_none() {
        missing_carriers.push(missing_carrier(
            "evaluator-replay-exact-canonical-transport",
            "missing-generated-evaluator-replay-descriptors",
            "the two value-dependent production evaluator replay stream descriptors emitted by one exact selected evaluator execution",
        ));
    }
    missing_carriers.extend(missing_cross_subsystem_carriers());

    require_ordered_alternative_topology(
        &ordered_product_alternatives,
        &ordered_evaluator_alternatives,
    )?;

    Ok(SelectedCompleteActionPhaseLivenessAccounting {
        ordered_product_alternatives: ordered_product_alternatives.into_boxed_slice(),
        ordered_evaluator_alternatives: ordered_evaluator_alternatives.into_boxed_slice(),
        product_evaluator_handoff,
        ordered_known_transport_paths: ordered_known_transport_paths.into_boxed_slice(),
        aggregate_public_transport,
        evaluator_replay_exact_transport,
        evaluator_replay_transport_codec_ceiling,
        ordered_proof_variant_paths: ordered_proof_variant_paths.into_boxed_slice(),
        proof_generation_attempt_topology: derive_proof_generation_attempt_topology(),
        target_release,
        missing_carriers: missing_carriers.into_boxed_slice(),
    })
}

fn derive_target_release_phase_path(
    proof_variant_paths: &[SelectedProofVariantPhasePath],
) -> (
    SelectedTargetReleasePhasePathOutcome,
    Vec<SelectedMissingPhaseLivenessCarrier>,
) {
    let target_schema_identifier =
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;
    let mut proof_byte_length_ceiling = None;
    for path in proof_variant_paths
        .iter()
        .filter(|path| path.application_statement_schema_identifier == target_schema_identifier)
    {
        let requirement = match &path.outcome {
            SelectedProofVariantPhasePathOutcome::Requirement { requirement } => requirement,
            SelectedProofVariantPhasePathOutcome::DerivationError {
                reason_code,
                required_carrier,
            } => {
                return target_release_derivation_error(reason_code, required_carrier);
            }
        };
        if proof_byte_length_ceiling
            .replace(requirement.proof_byte_length_ceiling)
            .is_some_and(|previous| previous != requirement.proof_byte_length_ceiling)
        {
            return target_release_derivation_error(
                "target-share-proof-length-inconsistent",
                "one schema-0x1621 proof stream byte-length ceiling shared by every selected compiler variant",
            );
        }
    }
    let Some(proof_byte_length_ceiling) = proof_byte_length_ceiling else {
        return target_release_derivation_error(
            "target-share-proof-diagnostic-absent",
            "at least one schema-0x1621 cap-neutral proof requirement",
        );
    };
    let accounting = match derive_selected_target_release_static_accounting(
        proof_byte_length_ceiling,
    ) {
        Ok(accounting) => accounting,
        Err(error) => {
            return target_release_derivation_error(
                error.reason_code(),
                "selected target-release accounting derived from the schema-0x1621 proof stream byte-length ceiling",
            );
        }
    };
    (
        SelectedTargetReleasePhasePathOutcome::Accounting {
            accounting: Box::new(accounting),
        },
        Vec::new(),
    )
}

fn target_release_derivation_error(
    reason_code: &str,
    required_carrier: &str,
) -> (
    SelectedTargetReleasePhasePathOutcome,
    Vec<SelectedMissingPhaseLivenessCarrier>,
) {
    let missing = missing_carrier(
        "target-release-static-accounting",
        reason_code,
        required_carrier,
    );
    (
        SelectedTargetReleasePhasePathOutcome::DerivationError {
            reason_code: missing.reason_code.clone(),
            required_carrier: missing.required_carrier.clone(),
        },
        vec![missing],
    )
}

fn derive_product_evaluator_handoff()
-> Result<SelectedProductEvaluatorHandoffAccounting, SelectedPhaseLivenessAccountingError> {
    let accounting = selected_evaluator_pipeline_handoff_accounting()
        .map_err(|_| SelectedPhaseLivenessAccountingError::EvaluatorAlternative)?;
    Ok(SelectedProductEvaluatorHandoffAccounting {
        transferred_ciphertext_count: accounting.transferred_ciphertext_count(),
        transferred_ciphertext_coefficient_byte_length: accounting
            .transferred_ciphertext_coefficient_byte_count(),
        coefficient_payload_copy_count: accounting.coefficient_payload_copy_count(),
        aggregation_resident_key_byte_length_after_prepare: accounting
            .aggregation_resident_key_byte_count_after_prepare(),
        evaluator_resident_key_byte_length_before_first_instruction: accounting
            .evaluator_resident_key_byte_count_before_first_instruction(),
    })
}

fn derive_known_transport_paths()
-> Result<Vec<SelectedCanonicalTransportPhasePath>, SelectedPhaseLivenessAccountingError> {
    let accounting = derive_selected_private_vss_mailbox_transport_accounting()
        .map_err(|_| SelectedPhaseLivenessAccountingError::MaterialTransport)?;
    Ok(vec![private_vss_transport_phase_path(accounting)])
}

fn derive_unsigned_public_transport() -> Result<
    (
        SelectedAggregatePublicTransportPhasePath,
        SelectedEvaluatorReplayTransportCodecCeiling,
        Option<SelectedEvaluatorReplayPublicTransportPhasePath>,
    ),
    SelectedPhaseLivenessAccountingError,
> {
    let accounting = derive_selected_unsigned_public_carrier_accounting()
        .map_err(|_| SelectedPhaseLivenessAccountingError::MaterialTransport)?;
    let exact_evaluator_replay = match accounting.exact_evaluator_replay() {
        SelectedExactEvaluatorReplayCarrierAccounting::Available(exact) => {
            Some(evaluator_replay_public_transport_path(exact))
        }
        SelectedExactEvaluatorReplayCarrierAccounting::MissingGeneratedEvaluatorReplayDescriptors => {
            None
        }
    };
    Ok((
        aggregate_public_transport_path(accounting.aggregate_public_carrier()),
        evaluator_replay_transport_codec_ceiling(accounting.evaluator_replay_codec_ceiling()),
        exact_evaluator_replay,
    ))
}

fn evaluator_replay_public_transport_path(
    accounting: SelectedEvaluatorReplayPublicCarrierAccounting,
) -> SelectedEvaluatorReplayPublicTransportPhasePath {
    SelectedEvaluatorReplayPublicTransportPhasePath {
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

fn aggregate_public_transport_path(
    accounting: SelectedAggregatePublicCarrierAccounting,
) -> SelectedAggregatePublicTransportPhasePath {
    SelectedAggregatePublicTransportPhasePath {
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

fn evaluator_replay_transport_codec_ceiling(
    accounting: SelectedEvaluatorReplayCarrierCodecCeilingAccounting,
) -> SelectedEvaluatorReplayTransportCodecCeiling {
    SelectedEvaluatorReplayTransportCodecCeiling {
        target_ciphertext_stream_byte_length_ceiling: accounting
            .target_ciphertext_stream_byte_length_ceiling(),
        target_ciphertext_stream_chunk_count_ceiling: accounting
            .target_ciphertext_stream_chunk_count_ceiling(),
        canonical_envelope_byte_length_ceiling: accounting.canonical_envelope_byte_length_ceiling(),
        complete_public_object_byte_length_ceiling: accounting
            .complete_public_object_byte_length_ceiling(),
    }
}

fn private_vss_transport_phase_path(
    accounting: SelectedPrivateVssMailboxTransportAccounting,
) -> SelectedCanonicalTransportPhasePath {
    let transport = accounting.canonical_transport_primitive();
    SelectedCanonicalTransportPhasePath {
        carrier_kind: "private-vss-mailbox-payload".to_owned(),
        physical_payload_stream_count: accounting.physical_payload_stream_count(),
        ordered_material_root_count_per_envelope: accounting
            .ordered_material_root_count_per_envelope(),
        payload_byte_length_per_stream: transport.payload_byte_length(),
        stream_chunk_count_per_stream: transport.stream_chunk_count(),
        stream_descriptor_byte_length_per_stream: transport.stream_descriptor_byte_length(),
        signed_mailbox_envelope_byte_length_per_stream: transport
            .signed_mailbox_envelope_byte_length(),
        complete_mailbox_byte_length_per_stream: accounting.complete_mailbox_byte_length(),
        ceremony_upload_byte_length: accounting.ceremony_upload_byte_length(),
        ceremony_download_byte_length: accounting.ceremony_download_byte_length(),
        private_mailbox_corpus_byte_length: accounting.private_mailbox_corpus_byte_length(),
        boundary_transfer_byte_length_per_direction_per_stream: transport
            .boundary_transfer_byte_length(),
        maximum_boundary_copied_buffer_byte_length: transport
            .maximum_boundary_copied_buffer_byte_length(),
        indexed_db_serialized_byte_length_per_operation: transport
            .indexed_db_serialized_byte_length(),
        indexed_db_additional_copy_peak_byte_length: transport
            .indexed_db_additional_copy_peak_byte_length(),
        indexed_db_serialization_buffer_peak_byte_length: transport
            .indexed_db_serialization_buffer_peak_byte_length(),
        indexed_db_readback_buffer_peak_byte_length: transport
            .indexed_db_readback_buffer_peak_byte_length(),
    }
}

fn derive_product_alternatives()
-> Result<Vec<SelectedProductPhaseAlternative>, SelectedPhaseLivenessAccountingError> {
    let mut alternatives = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    for ballot_count in 1..=FOUNDATION_PROFILE.participant_count {
        let accounting =
            canonical_two_stream_pair_character_product_accounting(usize::from(ballot_count))
                .map_err(|_| SelectedPhaseLivenessAccountingError::ProductAlternative)?;
        alternatives.push(product_alternative(ballot_count, accounting)?);
    }
    Ok(alternatives)
}

fn product_alternative(
    ballot_count: u16,
    accounting: TwoStreamPairCharacterProductAccounting,
) -> Result<SelectedProductPhaseAlternative, SelectedPhaseLivenessAccountingError> {
    let memory = accounting.memory;
    Ok(SelectedProductPhaseAlternative {
        ballot_count,
        work: SelectedProductWorkAccounting {
            ballot_ciphertext_count: count_to_u64(accounting.ballot_ciphertext_count)?,
            ciphertext_multiplication_count: count_to_u64(
                accounting.ciphertext_multiplication_count,
            )?,
            relinearization_count: count_to_u64(accounting.relinearization_count)?,
            normalization_plaintext_multiplication_count: count_to_u64(
                accounting.normalization_plaintext_multiplication_count,
            )?,
            modulus_switch_count: count_to_u64(accounting.modulus_switch_count)?,
            modulus_drop_count: count_to_u64(accounting.modulus_drop_count)?,
            maximum_resident_ciphertext_count: count_to_u64(
                accounting.maximum_resident_ciphertext_count,
            )?,
            relinearization_key_load_count: count_to_u64(
                accounting.relinearization_key_load_count,
            )?,
            key_ntt_transform_count: count_to_u64(accounting.key_ntt_transform_count)?,
        },
        store_boundary: SelectedProductStoreBoundaryAccounting {
            key_store_read_byte_length: accounting.key_store_read_byte_count,
            relinearization_key_component_wire_byte_length: memory
                .relinearization_key_component_wire_byte_length,
            maximum_key_store_chunk_byte_length: memory.maximum_key_store_chunk_byte_length,
            final_key_store_chunk_byte_length: memory.final_key_store_chunk_byte_length,
            key_replay_limb_buffer_byte_length: memory.key_replay_limb_buffer_byte_length,
        },
        peak_live_memory: SelectedProductPeakLiveMemoryAccounting {
            maximum_live_ciphertext_coefficient_byte_length: memory
                .maximum_live_ciphertext_coefficient_byte_length,
            resident_relinearization_key_coefficient_byte_length: memory
                .resident_relinearization_key_coefficient_byte_length,
            peak_key_replay_wasm_resident_byte_length: memory
                .peak_key_replay_wasm_resident_byte_length,
            maximum_operation_transient_byte_length: memory.maximum_operation_transient_byte_length,
            maximum_operation_scratch_byte_length: memory.maximum_operation_scratch_byte_length,
            peak_combined_wasm_resident_byte_length: memory.peak_combined_wasm_resident_byte_length,
        },
    })
}

fn derive_evaluator_alternatives()
-> Result<Vec<SelectedEvaluatorPhaseAlternative>, SelectedPhaseLivenessAccountingError> {
    let ledger = selected_evaluator_execution_resource_ledger()
        .map_err(|_| SelectedPhaseLivenessAccountingError::EvaluatorAlternative)?;
    ledger
        .ordered_streams()
        .iter()
        .map(|row| evaluator_alternative(row.top_count(), row.totals()))
        .collect()
}

fn evaluator_alternative(
    top_count: u16,
    totals: SelectedEvaluatorExecutionResourceTotals,
) -> Result<SelectedEvaluatorPhaseAlternative, SelectedPhaseLivenessAccountingError> {
    Ok(SelectedEvaluatorPhaseAlternative {
        top_count,
        work: SelectedEvaluatorWorkAccounting {
            instruction_count: count_to_u64(totals.instruction_count())?,
            key_operation_count: count_to_u64(totals.key_operation_count())?,
            key_load_count: count_to_u64(totals.key_load_count())?,
            key_ntt_transform_count: count_to_u64(totals.key_ntt_transform_count())?,
            rotation_count: count_to_u64(totals.rotation_count())?,
            ciphertext_multiplication_count: count_to_u64(
                totals.ciphertext_multiplication_count(),
            )?,
            plaintext_multiplication_count: count_to_u64(totals.plaintext_multiplication_count())?,
            modulus_switch_count: count_to_u64(totals.modulus_switch_count())?,
        },
        store_boundary: SelectedEvaluatorStoreBoundaryAccounting {
            key_store_read_request_count: totals.key_store_read_request_count(),
            key_store_reread_request_count: totals.key_store_reread_request_count(),
            key_store_read_byte_length: totals.key_store_read_byte_count(),
            key_store_reread_byte_length: totals.key_store_reread_byte_count(),
        },
        peak_live_memory: SelectedEvaluatorPeakLiveMemoryAccounting {
            maximum_live_ciphertext_byte_length: totals.maximum_live_ciphertext_byte_count(),
            maximum_resident_key_byte_length: totals.maximum_resident_key_byte_count(),
            maximum_operation_scratch_byte_length: totals.maximum_operation_scratch_byte_count(),
            peak_combined_wasm_resident_byte_length: totals
                .peak_combined_wasm_resident_byte_count(),
        },
    })
}

fn derive_proof_variant_paths() -> Result<
    (
        Vec<SelectedProofVariantPhasePath>,
        Vec<SelectedMissingPhaseLivenessCarrier>,
    ),
    SelectedPhaseLivenessAccountingError,
> {
    let diagnostic_rows = selected_proof_external_memory_diagnostic_report()
        .map_err(|_| SelectedPhaseLivenessAccountingError::ProofDiagnostic)?;
    let mut paths = Vec::with_capacity(diagnostic_rows.len());
    let mut missing_carriers = Vec::new();
    for row in diagnostic_rows.iter() {
        let selector = proof_variant_selector(row)?;
        let outcome = match row.outcome() {
            Ok(requirement) => SelectedProofVariantPhasePathOutcome::Requirement {
                requirement: proof_phase_liveness_requirement(&requirement)?,
            },
            Err(error) => {
                let missing = proof_diagnostic_missing_carrier(row, selector, &error);
                let outcome = SelectedProofVariantPhasePathOutcome::DerivationError {
                    reason_code: missing.reason_code.clone(),
                    required_carrier: missing.required_carrier.clone(),
                };
                missing_carriers.push(missing);
                outcome
            }
        };
        paths.push(SelectedProofVariantPhasePath {
            application_statement_schema_identifier: row.application_statement_schema_identifier(),
            selector,
            relation_column_count: count_to_u64(row.relation_column_count())?,
            relation_constraint_count: count_to_u64(row.relation_constraint_count())?,
            outcome,
        });
    }
    if paths.is_empty() {
        return Err(SelectedPhaseLivenessAccountingError::InvalidTopology);
    }
    Ok((paths, missing_carriers))
}

fn proof_variant_selector(
    row: &SelectedProofExternalMemoryDiagnosticRow,
) -> Result<SelectedProofVariantPhaseSelector, SelectedPhaseLivenessAccountingError> {
    match (row.schedule_position(), row.top_count()) {
        (None, None) => Ok(SelectedProofVariantPhaseSelector::Unparameterized),
        (Some(schedule_position), None) => {
            Ok(SelectedProofVariantPhaseSelector::SchedulePosition { schedule_position })
        }
        (None, Some(top_count)) => Ok(SelectedProofVariantPhaseSelector::TopCount { top_count }),
        (Some(_), Some(_)) => Err(SelectedPhaseLivenessAccountingError::InvalidTopology),
    }
}

fn proof_phase_liveness_requirement(
    requirement: &SelectedProofExternalMemoryDiagnosticRequirement,
) -> Result<SelectedProofVariantPhaseLivenessRequirement, SelectedPhaseLivenessAccountingError> {
    let ordered_phases = requirement
        .resident_phases()
        .iter()
        .map(proof_resident_phase)
        .collect::<Result<Vec<_>, _>>()?;
    if ordered_phases.len() != 14
        || ordered_phases
            .iter()
            .enumerate()
            .any(|(phase_ordinal, phase)| {
                usize::from(phase.phase_code) != phase_ordinal.saturating_add(1)
            })
    {
        return Err(SelectedPhaseLivenessAccountingError::InvalidTopology);
    }
    let maximum_combined_wasm_resident_byte_length = ordered_phases
        .iter()
        .map(|phase| phase.combined_wasm_resident_byte_length)
        .max()
        .ok_or(SelectedPhaseLivenessAccountingError::InvalidTopology)?;
    if maximum_combined_wasm_resident_byte_length
        != requirement.maximum_combined_wasm_resident_byte_length()
    {
        return Err(SelectedPhaseLivenessAccountingError::InvalidTopology);
    }
    let fri_fold_count = requirement.fri_fold_count();
    let checkpoint_safe_boundary_count = fri_fold_count
        .saturating_sub(1)
        .checked_add(4_u16)
        .ok_or(SelectedPhaseLivenessAccountingError::CountOverflow)?;
    Ok(SelectedProofVariantPhaseLivenessRequirement {
        complete_action_application_multiplicity: requirement
            .complete_action_application_multiplicity(),
        proof_byte_length_ceiling: u64::try_from(requirement.proof_byte_length_ceiling())
            .map_err(|_| SelectedPhaseLivenessAccountingError::CountOverflow)?,
        proof_output_chunk_count_ceiling: requirement.proof_output_chunk_count_ceiling(),
        maximum_proof_output_chunk_byte_length: requirement
            .maximum_proof_output_chunk_byte_length_ceiling(),
        maximum_prefetched_query_byte_length: requirement.maximum_prefetched_query_byte_length(),
        maximum_external_memory_transaction_payload_byte_length: requirement
            .maximum_external_memory_transaction_payload_byte_length(),
        maximum_copied_buffer_byte_length: requirement.maximum_copied_buffer_byte_length(),
        maximum_combined_wasm_resident_byte_length,
        fri_fold_count,
        checkpoint_safe_boundary_count,
        ordered_phases: ordered_phases.into_boxed_slice(),
    })
}

fn derive_proof_generation_attempt_topology() -> SelectedProofGenerationAttemptTopology {
    let topology = common_proof_generation_attempt_topology();
    SelectedProofGenerationAttemptTopology {
        fresh_start: match topology.fresh_start() {
            CommonProofGenerationAttemptStart::CheckpointGenesis => {
                SelectedProofGenerationAttemptStart::CheckpointGenesis
            }
            CommonProofGenerationAttemptStart::CheckpointGenesisWithAuthenticatedResumeTarget => {
                SelectedProofGenerationAttemptStart::CheckpointGenesisWithAuthenticatedResumeTarget
            }
        },
        resumed_start: match topology.resumed_start() {
            CommonProofGenerationAttemptStart::CheckpointGenesis => {
                SelectedProofGenerationAttemptStart::CheckpointGenesis
            }
            CommonProofGenerationAttemptStart::CheckpointGenesisWithAuthenticatedResumeTarget => {
                SelectedProofGenerationAttemptStart::CheckpointGenesisWithAuthenticatedResumeTarget
            }
        },
        resumed_prefix_execution: match topology.resumed_prefix_execution() {
            CommonProofGenerationResumePrefixExecution::DeterministicReplayFromGenesisThroughAuthenticatedTarget => {
                SelectedProofGenerationResumePrefixExecution::DeterministicReplayFromGenesisThroughAuthenticatedTarget
            }
        },
        resumed_state_restoration: match topology.resumed_state_restoration() {
            CommonProofGenerationResumeStateRestoration::CheckpointTargetComparisonAndAuthenticatedTranscriptCursorRestoration => {
                SelectedProofGenerationResumeStateRestoration::CheckpointTargetComparisonAndAuthenticatedTranscriptCursorRestoration
            }
        },
        cumulative_work_rule: match topology.cumulative_work_rule() {
            CommonProofGenerationCumulativeWorkRule::PriorPrefixPlusReplayedPrefixPlusRemainingSuffix => {
                SelectedProofGenerationCumulativeWorkRule::PriorPrefixPlusReplayedPrefixPlusRemainingSuffix
            }
        },
    }
}

fn proof_resident_phase(
    phase: &SelectedProofResidentPhaseResourceAccounting,
) -> Result<SelectedProofResidentPhaseLivenessAccounting, SelectedPhaseLivenessAccountingError> {
    let combined_wasm_resident_byte_length = phase
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
        .ok_or(SelectedPhaseLivenessAccountingError::CountOverflow)?;
    if combined_wasm_resident_byte_length != phase.combined_wasm_resident_byte_length() {
        return Err(SelectedPhaseLivenessAccountingError::InvalidTopology);
    }
    Ok(SelectedProofResidentPhaseLivenessAccounting {
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
        combined_wasm_resident_byte_length,
    })
}

fn proof_diagnostic_missing_carrier(
    row: &SelectedProofExternalMemoryDiagnosticRow,
    selector: SelectedProofVariantPhaseSelector,
    error: &SelectedProofExternalMemoryDiagnosticError,
) -> SelectedMissingPhaseLivenessCarrier {
    let selector_name = match selector {
        SelectedProofVariantPhaseSelector::Unparameterized => "unparameterized".to_owned(),
        SelectedProofVariantPhaseSelector::SchedulePosition { schedule_position } => {
            format!("schedule-position-{schedule_position}")
        }
        SelectedProofVariantPhaseSelector::TopCount { top_count } => {
            format!("top-count-{top_count}")
        }
    };
    missing_carrier(
        format!(
            "proof-variant-0x{:04x}-{selector_name}-phase-liveness",
            row.application_statement_schema_identifier()
        ),
        format!("proof-{}", error.detail_code()),
        "one complete cap-neutral proof resident-phase diagnostic requirement",
    )
}

fn missing_cross_subsystem_carriers() -> Vec<SelectedMissingPhaseLivenessCarrier> {
    vec![
        missing_carrier(
            "remaining-complete-action-host-boundary-storage-lifetimes",
            "missing-production-cross-runtime-state-transitions",
            "production JavaScript/WebAssembly/IndexedDB state transitions for the complete canonical carrier catalog, including exact buffer ownership across serialization, commit, readback, and release; Rust/WASM constructors and the known VSS per-operation copy peaks are already reported",
        ),
        missing_carrier(
            "two-stream-product-allocation-volume",
            "missing-production-allocation-event-type",
            "a production allocation-event and buffer-reuse schedule for the two-stream product executor; TwoStreamPairCharacterProductMemoryAccounting records operation counts and concurrent maxima only",
        ),
        missing_carrier(
            "evaluator-execution-allocation-volume",
            "missing-production-allocation-event-type",
            "a production per-instruction allocation-event, key-replay allocation, and buffer-reuse schedule; evaluator operation scratch records a concurrent peak rather than cumulative allocation volume",
        ),
        missing_carrier(
            "proof-generation-allocation-volume",
            "missing-production-allocation-event-type",
            "a production per-phase internal allocation-event and buffer-reuse schedule separate from proof resident phases and external-memory transaction traffic",
        ),
        missing_carrier(
            "target-release-allocation-volume",
            "missing-production-allocation-event-type",
            "a production allocation-event and buffer-reuse schedule for target-share derivation, proof generation, recombination, and output streaming; arithmetic counts and live-byte ceilings do not determine allocation volume",
        ),
        missing_carrier(
            "fresh-proof-generation-work",
            "missing-production-boundary-indexed-work-schedule",
            "a production fresh-attempt schedule that binds arithmetic, storage transactions, output chunks, checkpoint construction, and allocations to each of the derived checkpoint-safe boundaries",
        ),
        missing_carrier(
            "resumed-proof-generation-work",
            "missing-production-boundary-indexed-work-schedule",
            "a production schedule for each authenticated resume target that counts the deterministic replay from genesis through that boundary separately from the remaining suffix; the no-subtraction topology is already reported",
        ),
    ]
}

fn missing_carrier(
    dimension: impl Into<String>,
    reason_code: impl Into<String>,
    required_carrier: impl Into<String>,
) -> SelectedMissingPhaseLivenessCarrier {
    SelectedMissingPhaseLivenessCarrier {
        dimension: dimension.into(),
        reason_code: reason_code.into(),
        required_carrier: required_carrier.into(),
    }
}

fn require_ordered_alternative_topology(
    product_alternatives: &[SelectedProductPhaseAlternative],
    evaluator_alternatives: &[SelectedEvaluatorPhaseAlternative],
) -> Result<(), SelectedPhaseLivenessAccountingError> {
    if product_alternatives.len() != usize::from(FOUNDATION_PROFILE.participant_count)
        || product_alternatives
            .iter()
            .enumerate()
            .any(|(ordinal, row)| usize::from(row.ballot_count) != ordinal.saturating_add(1))
        || evaluator_alternatives.len() != usize::from(FOUNDATION_PROFILE.option_count)
        || evaluator_alternatives
            .iter()
            .enumerate()
            .any(|(ordinal, row)| usize::from(row.top_count) != ordinal.saturating_add(1))
    {
        return Err(SelectedPhaseLivenessAccountingError::InvalidTopology);
    }
    Ok(())
}

fn count_to_u64(count: usize) -> Result<u64, SelectedPhaseLivenessAccountingError> {
    u64::try_from(count).map_err(|_| SelectedPhaseLivenessAccountingError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_complete_action_liveness_preserves_alternatives_and_replayed_prefix_work() {
        let accounting = derive_selected_complete_action_phase_liveness_accounting()
            .expect("selected complete-action liveness derives fail-closed diagnostics");

        assert_eq!(
            accounting.ordered_product_alternatives.len(),
            usize::from(FOUNDATION_PROFILE.participant_count)
        );
        assert!(
            accounting
                .ordered_product_alternatives
                .iter()
                .enumerate()
                .all(|(ordinal, alternative)| {
                    usize::from(alternative.ballot_count) == ordinal + 1
                        && alternative
                            .peak_live_memory
                            .peak_combined_wasm_resident_byte_length
                            >= alternative
                                .peak_live_memory
                                .maximum_live_ciphertext_coefficient_byte_length
                })
        );
        assert_eq!(
            accounting.ordered_evaluator_alternatives.len(),
            usize::from(FOUNDATION_PROFILE.option_count)
        );
        assert!(
            accounting
                .ordered_evaluator_alternatives
                .iter()
                .enumerate()
                .all(|(ordinal, alternative)| {
                    usize::from(alternative.top_count) == ordinal + 1
                        && alternative
                            .peak_live_memory
                            .peak_combined_wasm_resident_byte_length
                            >= alternative
                                .peak_live_memory
                                .maximum_live_ciphertext_byte_length
                })
        );

        assert_eq!(
            accounting
                .product_evaluator_handoff
                .transferred_ciphertext_count,
            2
        );
        assert!(
            accounting
                .product_evaluator_handoff
                .transferred_ciphertext_coefficient_byte_length
                > 0
        );
        assert_eq!(
            accounting
                .product_evaluator_handoff
                .coefficient_payload_copy_count,
            0
        );
        assert_eq!(
            accounting
                .product_evaluator_handoff
                .aggregation_resident_key_byte_length_after_prepare,
            0
        );
        assert_eq!(
            accounting
                .product_evaluator_handoff
                .evaluator_resident_key_byte_length_before_first_instruction,
            0
        );

        assert_eq!(accounting.ordered_known_transport_paths.len(), 1);
        let private_vss = &accounting.ordered_known_transport_paths[0];
        assert_eq!(private_vss.carrier_kind, "private-vss-mailbox-payload");
        assert_eq!(
            private_vss.physical_payload_stream_count,
            u64::from(FOUNDATION_PROFILE.participant_count).pow(2)
        );
        assert_eq!(
            accounting
                .aggregate_public_transport
                .physical_ciphertext_stream_count,
            2
        );
        assert!(accounting.evaluator_replay_exact_transport.is_none());
        assert!(
            accounting
                .evaluator_replay_transport_codec_ceiling
                .complete_public_object_byte_length_ceiling
                > accounting
                    .evaluator_replay_transport_codec_ceiling
                    .canonical_envelope_byte_length_ceiling
        );

        assert_eq!(
            accounting.proof_generation_attempt_topology.fresh_start,
            SelectedProofGenerationAttemptStart::CheckpointGenesis
        );
        assert_eq!(
            accounting.proof_generation_attempt_topology.resumed_start,
            SelectedProofGenerationAttemptStart::CheckpointGenesisWithAuthenticatedResumeTarget
        );
        assert_eq!(
            accounting
                .proof_generation_attempt_topology
                .resumed_prefix_execution,
            SelectedProofGenerationResumePrefixExecution::DeterministicReplayFromGenesisThroughAuthenticatedTarget
        );
        assert_eq!(
            accounting
                .proof_generation_attempt_topology
                .resumed_state_restoration,
            SelectedProofGenerationResumeStateRestoration::CheckpointTargetComparisonAndAuthenticatedTranscriptCursorRestoration
        );
        assert_eq!(
            accounting
                .proof_generation_attempt_topology
                .cumulative_work_rule,
            SelectedProofGenerationCumulativeWorkRule::PriorPrefixPlusReplayedPrefixPlusRemainingSuffix
        );

        for path in &accounting.ordered_proof_variant_paths {
            if let SelectedProofVariantPhasePathOutcome::Requirement { requirement } = &path.outcome
            {
                assert_eq!(
                    requirement.checkpoint_safe_boundary_count,
                    requirement.fri_fold_count.saturating_sub(1) + 4
                );
                assert_eq!(requirement.ordered_phases.len(), 14);
                assert_eq!(
                    requirement.maximum_combined_wasm_resident_byte_length,
                    requirement
                        .ordered_phases
                        .iter()
                        .map(|phase| phase.combined_wasm_resident_byte_length)
                        .max()
                        .expect("a proof requirement has resident phases")
                );
            }
        }

        let SelectedTargetReleasePhasePathOutcome::Accounting {
            accounting: target_release,
        } = &accounting.target_release
        else {
            panic!(
                "selected target-release static accounting must derive: {:?}",
                accounting.target_release,
            )
        };
        assert_eq!(target_release.participant_count, 10);
        assert_eq!(target_release.reconstruction_threshold, 4);
        assert_eq!(
            target_release.fresh_generation.operations.preparation_count,
            1
        );
        assert_eq!(
            target_release
                .resumed_generation
                .operations
                .preparation_count,
            2
        );
        assert_eq!(
            target_release
                .reconstruction_subset_operations
                .valid_subset_count,
            210
        );
        assert_eq!(target_release.proof_output_store.store_count, 1);
        assert_eq!(target_release.partial_output_store.store_count, 2);
        assert_eq!(
            target_release
                .state_certification_transport
                .certification_round_count,
            2
        );
        assert_eq!(target_release.public_distribution.publication_count, 10);
        assert_eq!(target_release.result_transition.transition_count, 1);

        let missing_dimensions = accounting
            .missing_carriers
            .iter()
            .map(|carrier| carrier.dimension.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(missing_dimensions.contains("fresh-proof-generation-work"));
        assert!(missing_dimensions.contains("resumed-proof-generation-work"));
        assert!(!missing_dimensions.contains("target-release-proof-output-store"));
        assert!(!missing_dimensions.contains("target-release-partial-output-store"));
        assert!(!missing_dimensions.contains("target-release-state-certification-traffic"));
        assert!(!missing_dimensions.contains("target-release-public-share-distribution"));
        assert!(!missing_dimensions.contains("target-release-result-transition"));
        assert!(!missing_dimensions.contains("fresh-resumed-work-partition"));
        assert!(!missing_dimensions.contains("two-stream-product-evaluator-handoff-live-set"));
    }
}
