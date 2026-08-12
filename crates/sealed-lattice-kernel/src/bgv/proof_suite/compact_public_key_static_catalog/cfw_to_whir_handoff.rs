//! Logical extension-field payload at the CFW-to-WHIR boundary.
//!
//! The runtime reduction consumes compact point-and-target opening claims and
//! emits one dense source covector plus the short CFW mask covectors. This
//! catalog independently derives those element counts from the selected
//! relation and checks them against the runtime geometry. Byte lengths use the
//! canonical five-coordinate field payload. Rust container headers, allocator
//! metadata, and release-WASM target layout remain separate accounting owners.

use crate::bgv::proof_suite::{
    compact_cfw::{COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry, CompactCfwToWhirPayloadGeometry},
    relation_plan::CompactPublicKeyRelationCatalog,
};

use super::{
    CompactStaticCatalogError, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    cfw_reduction::CfwReductionCatalog, checked_add, checked_product,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CfwToWhirHandoffCatalog {
    source_variable_count: u64,
    preceding_opening_claim_count: u64,
    preceding_opening_claim_extension_element_count: u64,
    cfw_claim_batch_extension_element_count: u64,
    source_covector_extension_element_count: u64,
    cross_epoch_mask_covector_extension_element_count: u64,
    inner_mask_covector_extension_element_count: u64,
    outer_mask_covector_extension_element_count: u64,
    combined_relation_extension_element_count: u64,
    combined_relation_claim_count: u64,
    transition_live_extension_element_count: u64,
    retained_combined_relation_payload_byte_length: u64,
}

impl CfwToWhirHandoffCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
        preceding_opening_claim_count: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        let source_covector_extension_element_count = relation.padded_witness_element_count();
        if source_covector_extension_element_count == 0
            || !source_covector_extension_element_count.is_power_of_two()
            || preceding_opening_claim_count != 2
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let source_variable_count = u64::from(source_covector_extension_element_count.ilog2());
        let cross_epoch_copy = relation
            .cross_epoch_copy_geometry()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        if cross_epoch_copy.main_message_element_count() != source_covector_extension_element_count
            || u64::from(cross_epoch_copy.point_coordinate_count()) + 1 != source_variable_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let preceding_opening_claim_extension_element_count = checked_product(&[
            preceding_opening_claim_count,
            checked_add(source_variable_count, 1)?,
        ])?;
        let cfw_claim_batch_extension_element_count = [
            1,
            u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            u64::from(cfw_reduction.sumcheck_round_count()),
            cfw_reduction.outer_mask_count(),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let inner_mask_covector_extension_element_count = checked_product(&[
            cfw_reduction.inner_mask_count(),
            cfw_reduction.inner_mask_message_length(),
        ])?;
        let outer_mask_covector_extension_element_count = checked_product(&[
            cfw_reduction.outer_mask_count(),
            cfw_reduction.outer_mask_message_length(),
        ])?;
        let cross_epoch_mask_covector_extension_element_count = 2;
        let combined_relation_extension_element_count = [
            source_covector_extension_element_count,
            1,
            cross_epoch_mask_covector_extension_element_count,
            inner_mask_covector_extension_element_count,
            outer_mask_covector_extension_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let combined_relation_claim_count = checked_add(
            preceding_opening_claim_count,
            cfw_reduction.generalized_committed_relation_claim_count(),
        )?;
        let transition_live_extension_element_count = [
            preceding_opening_claim_extension_element_count,
            cfw_claim_batch_extension_element_count,
            combined_relation_extension_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let retained_combined_relation_payload_byte_length = checked_product(&[
            combined_relation_extension_element_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let catalog = Self {
            source_variable_count,
            preceding_opening_claim_count,
            preceding_opening_claim_extension_element_count,
            cfw_claim_batch_extension_element_count,
            source_covector_extension_element_count,
            cross_epoch_mask_covector_extension_element_count,
            inner_mask_covector_extension_element_count,
            outer_mask_covector_extension_element_count,
            combined_relation_extension_element_count,
            combined_relation_claim_count,
            transition_live_extension_element_count,
            retained_combined_relation_payload_byte_length,
        };
        catalog.check_runtime_correspondence(relation)?;
        Ok(catalog)
    }

    fn check_runtime_correspondence(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let runtime_geometry =
            CompactCfwToWhirPayloadGeometry::derive_with_preceding_mask_covector_element_count(
                CompactCfwGeometry::derive(
                    usize::try_from(relation.padded_witness_element_count())
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                )
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?,
                usize::try_from(self.preceding_opening_claim_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                usize::try_from(self.cross_epoch_mask_covector_extension_element_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        if self.source_variable_count
            != u64::try_from(runtime_geometry.source_variable_count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.preceding_opening_claim_extension_element_count
                != u64::try_from(runtime_geometry.preceding_opening_claim_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw_claim_batch_extension_element_count
                != u64::try_from(runtime_geometry.cfw_claim_batch_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.source_covector_extension_element_count
                != u64::try_from(runtime_geometry.source_covector_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cross_epoch_mask_covector_extension_element_count
                != u64::try_from(runtime_geometry.preceding_mask_covector_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.inner_mask_covector_extension_element_count
                != u64::try_from(runtime_geometry.inner_mask_covector_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.outer_mask_covector_extension_element_count
                != u64::try_from(runtime_geometry.outer_mask_covector_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.combined_relation_extension_element_count
                != u64::try_from(runtime_geometry.combined_relation_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.transition_live_extension_element_count
                != u64::try_from(runtime_geometry.transition_live_extension_element_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) const fn retained_combined_relation_payload_byte_length(&self) -> u64 {
        self.retained_combined_relation_payload_byte_length
    }

    pub(super) const fn combined_relation_extension_element_count(&self) -> u64 {
        self.combined_relation_extension_element_count
    }

    pub(super) const fn combined_relation_claim_count(&self) -> u64 {
        self.combined_relation_claim_count
    }

    pub(super) const fn source_covector_extension_element_count(&self) -> u64 {
        self.source_covector_extension_element_count
    }

    pub(super) const fn preceding_opening_claim_count(&self) -> u64 {
        self.preceding_opening_claim_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog;

    #[test]
    fn selected_handoff_has_one_dense_covector_and_compact_preceding_claims() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let cfw_reduction = CfwReductionCatalog::derive(&relation).expect("selected CFW reduction");
        let catalog = CfwToWhirHandoffCatalog::derive(&relation, &cfw_reduction, 2)
            .expect("selected CFW-to-WHIR handoff");

        assert_eq!(catalog.source_variable_count, 22);
        assert_eq!(catalog.preceding_opening_claim_count, 2);
        assert_eq!(catalog.preceding_opening_claim_extension_element_count, 46);
        assert_eq!(catalog.cfw_claim_batch_extension_element_count, 50);
        assert_eq!(catalog.source_covector_extension_element_count, 4_194_304);
        assert_eq!(catalog.cross_epoch_mask_covector_extension_element_count, 2);
        assert_eq!(catalog.inner_mask_covector_extension_element_count, 276);
        assert_eq!(catalog.outer_mask_covector_extension_element_count, 184);
        assert_eq!(catalog.combined_relation_extension_element_count, 4_194_767);
        assert_eq!(catalog.combined_relation_claim_count, 164);
        assert_eq!(catalog.transition_live_extension_element_count, 4_194_863);
        assert_eq!(
            catalog.retained_combined_relation_payload_byte_length,
            167_790_680
        );
    }
}
