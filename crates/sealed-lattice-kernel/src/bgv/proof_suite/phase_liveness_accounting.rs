//! Construction-derived proof phase and external-memory liveness evidence.

use serde::{Deserialize, Serialize};

use super::{
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    selected_accounting::resource_accounting::{
        selected_complete_proof_resource_accounting, selected_proof_variant_resource_inventory,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedProofPhaseLivenessRow {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    complete_action_application_multiplicity: u32,
    proof_byte_length_ceiling: u64,
    verifier_resident_byte_length_ceiling: u64,
    proof_section_count: u32,
    checkpoint_count: u32,
    query_epoch_count: u32,
    compact_frontier_count: u32,
    maximum_compact_opening_byte_length: u64,
    external_memory_step_count: u32,
    external_memory_distinct_physical_object_count: u32,
    external_memory_object_lifecycle_count: u32,
    external_memory_peak_stored_byte_length: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    local_record_seal_invocation_count: u64,
    local_record_sealed_plaintext_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectedCompleteActionPhaseLivenessAccounting {
    ordered_variants: Vec<SelectedProofPhaseLivenessRow>,
    physical_proof_count: u32,
    complete_action_proof_byte_ceiling: u64,
    maximum_one_browser_wasm_resident_byte_length: u64,
    maximum_external_memory_peak_stored_byte_length_per_proof: u64,
    complete_action_external_memory_total_written_byte_length: u64,
    complete_action_external_memory_total_read_byte_length: u64,
    complete_action_external_memory_transaction_count: u64,
    complete_action_local_record_seal_invocation_count: u64,
    complete_action_local_record_sealed_plaintext_byte_length: u64,
}

impl SelectedCompleteActionPhaseLivenessAccounting {
    pub(crate) fn ordered_variants(&self) -> &[SelectedProofPhaseLivenessRow] {
        &self.ordered_variants
    }

    pub(crate) const fn physical_proof_count(&self) -> u32 {
        self.physical_proof_count
    }

    pub(crate) const fn complete_action_proof_byte_ceiling(&self) -> u64 {
        self.complete_action_proof_byte_ceiling
    }

    pub(crate) const fn maximum_one_browser_wasm_resident_byte_length(&self) -> u64 {
        self.maximum_one_browser_wasm_resident_byte_length
    }
}

pub(crate) fn derive_selected_complete_action_phase_liveness_accounting()
-> Result<SelectedCompleteActionPhaseLivenessAccounting, String> {
    let variants = selected_proof_variant_resource_inventory()
        .map_err(|error| format!("derive selected proof variants: {error:?}"))?;
    let complete = selected_complete_proof_resource_accounting()
        .map_err(|error| format!("derive selected complete proof accounting: {error:?}"))?;
    let mut ordered_variants = Vec::with_capacity(variants.len());
    let mut maximum_external_memory_peak_stored_byte_length_per_proof = 0_u64;
    let mut complete_action_external_memory_total_written_byte_length = 0_u64;
    let mut complete_action_external_memory_total_read_byte_length = 0_u64;
    let mut complete_action_external_memory_transaction_count = 0_u64;
    let mut complete_action_local_record_seal_invocation_count = 0_u64;
    let mut complete_action_local_record_sealed_plaintext_byte_length = 0_u64;

    for variant in variants {
        let construction = variant.construction();
        let sections = construction.ordered_proof_sections();
        let checkpoints = construction.ordered_checkpoints();
        let query_epochs = construction.ordered_query_epochs();
        if sections.is_empty()
            || checkpoints.is_empty()
            || query_epochs.is_empty()
            || sections.iter().enumerate().any(|(ordinal, section)| {
                u32::try_from(ordinal).ok() != Some(section.section_ordinal())
                    || section.item_count() == 0
            })
            || checkpoints.iter().enumerate().any(|(ordinal, checkpoint)| {
                u32::try_from(ordinal).ok() != Some(checkpoint.checkpoint_ordinal())
            })
            || checkpoints.windows(2).any(|pair| {
                pair[0].next_transcript_operation_ordinal()
                    > pair[1].next_transcript_operation_ordinal()
                    || pair[0].next_proof_section_ordinal() > pair[1].next_proof_section_ordinal()
            })
            || query_epochs.iter().enumerate().any(|(ordinal, epoch)| {
                u32::try_from(ordinal).ok() != Some(epoch.epoch_ordinal())
                    || epoch.domain_size() == 0
                    || epoch.query_count() == 0
            })
        {
            return Err("selected proof liveness schedule is not canonical".to_owned());
        }
        let external = variant.external_memory_requirement();
        let multiplicity = u64::from(variant.complete_action_application_multiplicity());
        maximum_external_memory_peak_stored_byte_length_per_proof =
            maximum_external_memory_peak_stored_byte_length_per_proof
                .max(external.peak_stored_byte_length());
        complete_action_external_memory_total_written_byte_length =
            complete_action_external_memory_total_written_byte_length
                .checked_add(
                    external
                        .total_written_byte_length()
                        .checked_mul(multiplicity)
                        .ok_or_else(|| "proof write-volume accounting overflowed".to_owned())?,
                )
                .ok_or_else(|| "complete proof write-volume accounting overflowed".to_owned())?;
        complete_action_external_memory_total_read_byte_length =
            complete_action_external_memory_total_read_byte_length
                .checked_add(
                    external
                        .total_read_byte_length()
                        .checked_mul(multiplicity)
                        .ok_or_else(|| "proof read-volume accounting overflowed".to_owned())?,
                )
                .ok_or_else(|| "complete proof read-volume accounting overflowed".to_owned())?;
        complete_action_external_memory_transaction_count =
            complete_action_external_memory_transaction_count
                .checked_add(
                    external
                        .transaction_count()
                        .checked_mul(multiplicity)
                        .ok_or_else(|| "proof transaction accounting overflowed".to_owned())?,
                )
                .ok_or_else(|| "complete proof transaction accounting overflowed".to_owned())?;
        complete_action_local_record_seal_invocation_count =
            complete_action_local_record_seal_invocation_count
                .checked_add(
                    external
                        .local_record_seal_invocation_count()
                        .checked_mul(multiplicity)
                        .ok_or_else(|| "proof seal accounting overflowed".to_owned())?,
                )
                .ok_or_else(|| "complete proof seal accounting overflowed".to_owned())?;
        complete_action_local_record_sealed_plaintext_byte_length =
            complete_action_local_record_sealed_plaintext_byte_length
                .checked_add(
                    external
                        .local_record_sealed_plaintext_byte_length()
                        .checked_mul(multiplicity)
                        .ok_or_else(|| "proof sealed-byte accounting overflowed".to_owned())?,
                )
                .ok_or_else(|| "complete proof sealed-byte accounting overflowed".to_owned())?;
        ordered_variants.push(SelectedProofPhaseLivenessRow {
            application_statement_schema_identifier: variant
                .application_statement_schema_identifier(),
            schedule_position: variant.schedule_position(),
            top_count: variant.top_count(),
            complete_action_application_multiplicity: variant
                .complete_action_application_multiplicity(),
            proof_byte_length_ceiling: variant.canonical_proof_byte_length(),
            verifier_resident_byte_length_ceiling: variant.maximum_verifier_resident_byte_length(),
            proof_section_count: u32::try_from(sections.len())
                .map_err(|_| "proof section count exceeds u32".to_owned())?,
            checkpoint_count: u32::try_from(checkpoints.len())
                .map_err(|_| "checkpoint count exceeds u32".to_owned())?,
            query_epoch_count: u32::try_from(query_epochs.len())
                .map_err(|_| "query epoch count exceeds u32".to_owned())?,
            compact_frontier_count: u32::try_from(construction.compact_frontiers().len())
                .map_err(|_| "compact frontier count exceeds u32".to_owned())?,
            maximum_compact_opening_byte_length: construction
                .compact_frontiers()
                .iter()
                .map(|frontier| frontier.canonical_opening_byte_length())
                .max()
                .ok_or_else(|| "proof has no compact opening frontier".to_owned())?,
            external_memory_step_count: external.step_count(),
            external_memory_distinct_physical_object_count: external
                .distinct_physical_object_count(),
            external_memory_object_lifecycle_count: external.object_lifecycle_count(),
            external_memory_peak_stored_byte_length: external.peak_stored_byte_length(),
            external_memory_total_written_byte_length: external.total_written_byte_length(),
            external_memory_total_read_byte_length: external.total_read_byte_length(),
            external_memory_transaction_count: external.transaction_count(),
            local_record_seal_invocation_count: external.local_record_seal_invocation_count(),
            local_record_sealed_plaintext_byte_length: external
                .local_record_sealed_plaintext_byte_length(),
        });
    }
    if ordered_variants.is_empty()
        || complete.maximum_one_browser_wasm_resident_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err("selected complete proof liveness accounting exceeds its bound".to_owned());
    }
    Ok(SelectedCompleteActionPhaseLivenessAccounting {
        ordered_variants,
        physical_proof_count: complete.physical_proof_count(),
        complete_action_proof_byte_ceiling: complete.complete_action_proof_byte_ceiling(),
        maximum_one_browser_wasm_resident_byte_length: complete
            .maximum_one_browser_wasm_resident_byte_length(),
        maximum_external_memory_peak_stored_byte_length_per_proof,
        complete_action_external_memory_total_written_byte_length,
        complete_action_external_memory_total_read_byte_length,
        complete_action_external_memory_transaction_count,
        complete_action_local_record_seal_invocation_count,
        complete_action_local_record_sealed_plaintext_byte_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "guarded complete selected-action phase-liveness evidence"]
    fn construction_driven_phase_liveness_closes_every_selected_variant() {
        let accounting = derive_selected_complete_action_phase_liveness_accounting()
            .expect("construction-driven phase liveness derives");
        assert_eq!(accounting.ordered_variants().len(), 31);
        assert_eq!(accounting.physical_proof_count(), 103);
        assert!(accounting.complete_action_proof_byte_ceiling() > 0);
        assert_eq!(
            accounting.maximum_one_browser_wasm_resident_byte_length(),
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        );
    }
}
