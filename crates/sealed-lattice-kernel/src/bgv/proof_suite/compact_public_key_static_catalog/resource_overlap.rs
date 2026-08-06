//!
//! Exact source-loading ownership for the standalone compact public-key
//! development slice. The provider geometry is re-derived from the selected
//! production relation and compact request profile. The authority allocation
//! is independently reconstructed from the selected production shapes and is
//! checked against the live allocation when that authority is created.

use crate::{
    bgv::{
        proof_suite::{
            canonical_selected_public_key_share_statement,
            compile_public_key_share_relation_with_source_layout,
            relation_plan::{
                CompactPublicKeyRelationCatalog,
                compact_public_key_assignment_prepared_source_control_byte_length,
            },
            selected_public_key_share_relation_plan_input, selected_relation_plan_check_context,
        },
        setup::selected_setup_generation_compact_public_key_development_retained_payload_byte_length,
    },
    foundation::ProofApplicationSlotCeilings,
};

use crate::bgv::proof_suite::relation_plan::compact_public_key_assignment_source_provider_memory_accounting;

use super::row_source_lifecycle::RowSourceLifecycleCatalog;
use super::{CompactStaticCatalogError, checked_add, checked_product};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactPublicKeyProviderOverlapCatalog {
    authority_payload_byte_length: u64,
    base_loading_persistent_byte_length: u64,
    base_post_finish_persistent_byte_length: u64,
    loading_persistent_byte_length: u64,
    post_finish_persistent_byte_length: u64,
    additional_loading_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactPublicKeyResourceOverlapCatalog {
    provider: CompactPublicKeyProviderOverlapCatalog,
    base_assignment_payload_byte_length: u64,
    completed_assignment_payload_byte_length: u64,
    prepared_source_control_byte_length: u64,
    source_polynomial_transform_overlap_byte_length: u64,
    source_loading_peak_byte_length: u64,
    lookup_materialization_peak_byte_length: u64,
    row_source_preparation_peak_byte_length: u64,
    ready_row_source_peak_byte_length: u64,
    maximum_preproof_peak_byte_length: u64,
    provider_release_before_lookup_is_implemented: bool,
    prepared_source_control_overlap_is_complete: bool,
}

impl CompactPublicKeyResourceOverlapCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        row_source_lifecycle: &RowSourceLifecycleCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let provider = CompactPublicKeyProviderOverlapCatalog::derive()?;
        let base_assignment_payload_byte_length =
            row_source_lifecycle.base_assignment_payload_byte_length();
        let completed_assignment_payload_byte_length =
            row_source_lifecycle.completed_assignment_payload_byte_length();
        let prepared_source_control_byte_length =
            selected_prepared_source_control_byte_length(relation)?;
        let source_polynomial_transform_overlap_byte_length =
            checked_product(&[2, provider.maximum_returned_source_polynomial_byte_length])?
                .max(provider.additional_loading_transient_byte_length);
        let source_loading_peak_byte_length = [
            provider.loading_persistent_byte_length,
            base_assignment_payload_byte_length,
            prepared_source_control_byte_length,
            source_polynomial_transform_overlap_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let lookup_materialization_peak_byte_length = checked_add(
            row_source_lifecycle.relation_resident_owned_byte_length(),
            row_source_lifecycle.lookup_materializer_resident_owned_byte_length(),
        )?;
        let row_source_preparation_peak_byte_length =
            row_source_lifecycle.maximum_preparation_resident_owned_byte_length();
        let ready_row_source_peak_byte_length =
            row_source_lifecycle.ready_row_source_resident_owned_byte_length();
        let maximum_preproof_peak_byte_length = source_loading_peak_byte_length
            .max(lookup_materialization_peak_byte_length)
            .max(row_source_preparation_peak_byte_length)
            .max(ready_row_source_peak_byte_length);
        let catalog = Self {
            provider,
            base_assignment_payload_byte_length,
            completed_assignment_payload_byte_length,
            prepared_source_control_byte_length,
            source_polynomial_transform_overlap_byte_length,
            source_loading_peak_byte_length,
            lookup_materialization_peak_byte_length,
            row_source_preparation_peak_byte_length,
            ready_row_source_peak_byte_length,
            maximum_preproof_peak_byte_length,
            // The source-loading cursor and adapter are consumed together.
            // Initial preparation requires an exclusively owned authority, so
            // this transition drops the provider and its authority before the
            // lookup allocation begins.
            provider_release_before_lookup_is_implemented: true,
            // The source wrapper, compact relation, cloned checked variant,
            // assignment cursor, matrix catalog, row preparation, and ready
            // row-source controls now have allocator-independent ledgers.
            prepared_source_control_overlap_is_complete: true,
        };
        catalog.check(relation, row_source_lifecycle)?;
        Ok(catalog)
    }

    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        row_source_lifecycle: &RowSourceLifecycleCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected_source_loading_peak_byte_length = [
            self.provider.loading_persistent_byte_length,
            row_source_lifecycle.base_assignment_payload_byte_length(),
            selected_prepared_source_control_byte_length(relation)?,
            checked_product(&[
                2,
                self.provider.maximum_returned_source_polynomial_byte_length,
            ])?
            .max(self.provider.additional_loading_transient_byte_length),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let expected_lookup_materialization_peak_byte_length = checked_add(
            row_source_lifecycle.relation_resident_owned_byte_length(),
            row_source_lifecycle.lookup_materializer_resident_owned_byte_length(),
        )?;
        let expected_row_source_preparation_peak_byte_length =
            row_source_lifecycle.maximum_preparation_resident_owned_byte_length();
        let expected_ready_row_source_peak_byte_length =
            row_source_lifecycle.ready_row_source_resident_owned_byte_length();
        if self.provider != CompactPublicKeyProviderOverlapCatalog::derive()?
            || self.base_assignment_payload_byte_length
                != row_source_lifecycle.base_assignment_payload_byte_length()
            || self.completed_assignment_payload_byte_length
                != row_source_lifecycle.completed_assignment_payload_byte_length()
            || self.prepared_source_control_byte_length
                != selected_prepared_source_control_byte_length(relation)?
            || self.source_polynomial_transform_overlap_byte_length
                != checked_product(&[
                    2,
                    self.provider.maximum_returned_source_polynomial_byte_length,
                ])?
                .max(self.provider.additional_loading_transient_byte_length)
            || self.source_loading_peak_byte_length != expected_source_loading_peak_byte_length
            || self.lookup_materialization_peak_byte_length
                != expected_lookup_materialization_peak_byte_length
            || self.row_source_preparation_peak_byte_length
                != expected_row_source_preparation_peak_byte_length
            || self.ready_row_source_peak_byte_length != expected_ready_row_source_peak_byte_length
            || self.maximum_preproof_peak_byte_length
                != self
                    .source_loading_peak_byte_length
                    .max(self.lookup_materialization_peak_byte_length)
                    .max(self.row_source_preparation_peak_byte_length)
                    .max(self.ready_row_source_peak_byte_length)
            || !self.provider_release_before_lookup_is_implemented
            || !self.prepared_source_control_overlap_is_complete
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) const fn ready_row_source_peak_byte_length(&self) -> u64 {
        self.ready_row_source_peak_byte_length
    }

    pub(super) const fn maximum_preproof_peak_byte_length(&self) -> u64 {
        self.maximum_preproof_peak_byte_length
    }
}

fn selected_prepared_source_control_byte_length(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<u64, CompactStaticCatalogError> {
    let input = selected_public_key_share_relation_plan_input()
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let compiled = compile_public_key_share_relation_with_source_layout(&input, &relation_context)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    compiled
        .relation_plan
        .check(&relation_context)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    let retained_relation_plan_variant = compiled
        .relation_plan
        .select_variant(None, None)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?
        .clone();
    compact_public_key_assignment_prepared_source_control_byte_length(
        relation,
        &retained_relation_plan_variant,
    )
    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)
}

impl CompactPublicKeyProviderOverlapCatalog {
    pub(super) fn derive() -> Result<Self, CompactStaticCatalogError> {
        let input = selected_public_key_share_relation_plan_input()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let relation_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let compiled =
            compile_public_key_share_relation_with_source_layout(&input, &relation_context)
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        compiled
            .relation_plan
            .check(&relation_context)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        // The preparation path owns a clone of the selected variant. Cloning
        // normalizes every vector capacity to its live length, so accounting
        // the compiler's still-overallocated construction buffers would charge
        // memory that is not retained by the source provider.
        let relation_plan_variant = compiled
            .relation_plan
            .select_variant(None, None)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?
            .clone();
        // Preparation likewise clones the checked context into the adapter.
        // Its resolved-modulus vector must therefore be charged at the cloned
        // length-sized capacity, not at the compiler context's spare capacity.
        let retained_relation_context = relation_context.clone();
        let canonical_statement_byte_length = canonical_selected_public_key_share_statement(
            [0_u8; 64],
            [0_u8; 64],
            0,
            &[[0_u8; 64]; 3],
            [0_u8; 64],
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?
        .len();
        let provider = compact_public_key_assignment_source_provider_memory_accounting(
            &relation_plan_variant,
            &retained_relation_context,
            input.ring_degree,
            &compiled.source_layout,
            canonical_statement_byte_length,
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let authority_payload_byte_length =
            selected_setup_generation_compact_public_key_development_retained_payload_byte_length()
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let catalog = Self {
            authority_payload_byte_length,
            base_loading_persistent_byte_length: provider.loading_persistent_resident_byte_length(),
            base_post_finish_persistent_byte_length: provider
                .post_source_polynomial_finish_persistent_resident_byte_length(),
            loading_persistent_byte_length: checked_add(
                provider.loading_persistent_resident_byte_length(),
                authority_payload_byte_length,
            )?,
            post_finish_persistent_byte_length: checked_add(
                provider.post_source_polynomial_finish_persistent_resident_byte_length(),
                authority_payload_byte_length,
            )?,
            additional_loading_transient_byte_length: provider
                .additional_loading_transient_byte_length(),
            maximum_returned_source_polynomial_byte_length: provider
                .maximum_returned_source_polynomial_byte_length(),
        };
        catalog.check()?;
        Ok(catalog)
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        if self.authority_payload_byte_length == 0
            || self.loading_persistent_byte_length
                != checked_add(
                    self.base_loading_persistent_byte_length,
                    self.authority_payload_byte_length,
                )?
            || self.post_finish_persistent_byte_length
                != checked_add(
                    self.base_post_finish_persistent_byte_length,
                    self.authority_payload_byte_length,
                )?
            || self.loading_persistent_byte_length <= self.post_finish_persistent_byte_length
            || self.additional_loading_transient_byte_length == 0
            || self.maximum_returned_source_polynomial_byte_length == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_provider_overlap_is_derived_from_production_shapes() {
        let catalog = CompactPublicKeyProviderOverlapCatalog::derive()
            .expect("selected compact public-key provider overlap");
        assert_eq!(catalog.authority_payload_byte_length, 7_179_410);
        assert_eq!(catalog.base_loading_persistent_byte_length, 10_570_434);
        assert_eq!(catalog.base_post_finish_persistent_byte_length, 10_046_146);
        assert_eq!(catalog.loading_persistent_byte_length, 17_749_844);
        assert_eq!(catalog.post_finish_persistent_byte_length, 17_225_556);
        assert_eq!(catalog.additional_loading_transient_byte_length, 4_837_360);
        assert_eq!(
            catalog.maximum_returned_source_polynomial_byte_length,
            131_072
        );
    }

    #[test]
    fn selected_preproof_overlap_names_every_current_resident_phase() {
        let relation =
            crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog()
                .expect("selected compact public-key relation");
        let row_source_lifecycle =
            RowSourceLifecycleCatalog::derive(&relation).expect("selected row-source lifecycle");
        let catalog =
            CompactPublicKeyResourceOverlapCatalog::derive(&relation, &row_source_lifecycle)
                .expect("selected compact resource overlap");

        assert_eq!(catalog.base_assignment_payload_byte_length, 30_933_000);
        assert_eq!(catalog.completed_assignment_payload_byte_length, 68_943_880);
        assert_eq!(
            (
                catalog.prepared_source_control_byte_length,
                catalog.source_polynomial_transform_overlap_byte_length,
                catalog.source_loading_peak_byte_length,
                catalog.lookup_materialization_peak_byte_length,
                catalog.row_source_preparation_peak_byte_length,
                catalog.ready_row_source_peak_byte_length,
                catalog.maximum_preproof_peak_byte_length,
            ),
            (
                10_062_648, 4_837_360, 63_582_852, 68_956_968, 78_399_896, 77_348_928, 78_399_896,
            )
        );
        assert!(catalog.provider_release_before_lookup_is_implemented);
        assert!(catalog.prepared_source_control_overlap_is_complete);
    }
}
