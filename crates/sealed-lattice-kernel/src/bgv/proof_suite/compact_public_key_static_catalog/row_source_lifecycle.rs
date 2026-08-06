//! Bounded preparation ledger for the compact structured R1CS row source.
//!
//! The production preparation state machine advances elementwise work in
//! fixed chunks and isolates every transform in its own poll. Completed
//! product-cache persistence is not implemented yet, so this catalog records
//! full preparation replay as the honest restart bound and cannot close the
//! static gate by itself.

use crate::bgv::proof_suite::relation_plan::{
    CompactAuthenticatedAssignmentMemoryGeometry, CompactPublicKeyRelationCatalog,
    CompactStructuredR1csRowSourceGeometry, compact_authenticated_assignment_memory_geometry,
    compact_structured_r1cs_row_source_geometry,
};

use super::{CompactStaticCatalogError, checked_add, checked_product};

pub(super) const ROW_SOURCE_PREPARATION_ELEMENT_CHUNK_COUNT: u64 = 8_192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowSourceLifecycleCatalog {
    assignment_memory: CompactAuthenticatedAssignmentMemoryGeometry,
    row_source_geometry: CompactStructuredR1csRowSourceGeometry,
    element_chunk_count: u64,
    lookup_inverse_sum_poll_count: u64,
    lookup_table_prefix_poll_count: u64,
    lookup_table_inversion_poll_count: u64,
    lookup_table_reverse_poll_count: u64,
    private_polynomial_fill_poll_count: u64,
    private_polynomial_transform_poll_count: u64,
    public_polynomial_fill_poll_count: u64,
    public_polynomial_transform_poll_count: u64,
    pointwise_product_poll_count: u64,
    inverse_product_transform_poll_count: u64,
    negacyclic_product_fold_poll_count: u64,
    deterministic_preparation_poll_count: u64,
    maximum_uninterrupted_elementwise_work_unit_count: u64,
    maximum_uninterrupted_transform_butterfly_count: u64,
    preparation_transform_butterfly_count: u64,
    preparation_pointwise_multiplication_count: u64,
    preparation_fold_subtraction_count: u64,
    preparation_lookup_extension_multiplication_count: u64,
    completed_assignment_payload_byte_length: u64,
    product_cache_payload_byte_length: u64,
    product_cache_catalog_byte_length: u64,
    product_cache_resident_owned_byte_length: u64,
    ready_row_source_payload_byte_length: u64,
    relation_resident_owned_byte_length: u64,
    ready_row_source_resident_owned_byte_length: u64,
    maximum_preparation_resident_owned_byte_length: u64,
    authenticated_restart_record_count: u64,
    authenticated_restart_write_byte_length: u64,
    authenticated_restart_read_byte_length: u64,
    maximum_restart_recomputed_transform_butterfly_count: u64,
    maximum_restart_recomputed_pointwise_multiplication_count: u64,
    maximum_restart_recomputed_fold_subtraction_count: u64,
    maximum_restart_recomputed_lookup_extension_multiplication_count: u64,
    durable_product_cache_restart_is_implemented: bool,
}

impl RowSourceLifecycleCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let catalog = Self::derive_without_check(relation)?;
        catalog.check(relation)?;
        Ok(catalog)
    }

    fn derive_without_check(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let assignment_memory = compact_authenticated_assignment_memory_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let row_source_geometry = compact_structured_r1cs_row_source_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let element_chunk_count = ROW_SOURCE_PREPARATION_ELEMENT_CHUNK_COUNT;
        let lookup_inverse_sum_poll_count = row_source_geometry
            .lookup_inverse_element_count()
            .div_ceil(element_chunk_count);
        let lookup_table_prefix_poll_count = row_source_geometry
            .lookup_table_value_count()
            .div_ceil(element_chunk_count);
        let lookup_table_inversion_poll_count = 1;
        let lookup_table_reverse_poll_count = lookup_table_prefix_poll_count;
        let private_polynomial_fill_poll_count = checked_product(&[
            row_source_geometry.distinct_centered_private_vector_count(),
            row_source_geometry
                .ring_degree()
                .div_ceil(element_chunk_count),
        ])?;
        let private_polynomial_transform_poll_count =
            row_source_geometry.distinct_centered_private_vector_count();
        let public_polynomial_fill_poll_count = checked_product(&[
            row_source_geometry.negacyclic_product_count(),
            row_source_geometry
                .ring_degree()
                .div_ceil(element_chunk_count),
        ])?;
        let public_polynomial_transform_poll_count = row_source_geometry.negacyclic_product_count();
        let pointwise_product_poll_count = checked_product(&[
            row_source_geometry.negacyclic_product_count(),
            row_source_geometry
                .transform_domain_size()
                .div_ceil(element_chunk_count),
        ])?;
        let inverse_product_transform_poll_count = row_source_geometry.negacyclic_product_count();
        let negacyclic_product_fold_poll_count = public_polynomial_fill_poll_count;
        let deterministic_preparation_poll_count = [
            lookup_inverse_sum_poll_count,
            lookup_table_prefix_poll_count,
            lookup_table_inversion_poll_count,
            lookup_table_reverse_poll_count,
            private_polynomial_fill_poll_count,
            private_polynomial_transform_poll_count,
            public_polynomial_fill_poll_count,
            public_polynomial_transform_poll_count,
            pointwise_product_poll_count,
            inverse_product_transform_poll_count,
            negacyclic_product_fold_poll_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_uninterrupted_transform_butterfly_count = row_source_geometry
            .transform_domain_size()
            .checked_div(2)
            .and_then(|count| {
                count.checked_mul(u64::from(
                    row_source_geometry.transform_domain_size().ilog2(),
                ))
            })
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let completed_assignment_payload_byte_length =
            assignment_memory.completed_assignment_payload_byte_length();
        let product_cache_payload_byte_length =
            row_source_geometry.product_cache_payload_byte_length();
        let product_cache_catalog_byte_length =
            row_source_geometry.product_cache_catalog_byte_length();
        let product_cache_resident_owned_byte_length =
            row_source_geometry.product_cache_resident_owned_byte_length();
        let ready_row_source_payload_byte_length = checked_add(
            completed_assignment_payload_byte_length,
            product_cache_resident_owned_byte_length,
        )?;
        let relation_resident_owned_byte_length = relation
            .resident_owned_byte_length()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let ready_row_source_resident_owned_byte_length = [
            relation_resident_owned_byte_length,
            assignment_memory.completed_assignment_resident_owned_byte_length(),
            product_cache_resident_owned_byte_length,
            row_source_geometry.ready_row_source_control_byte_length(),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let maximum_preparation_resident_owned_byte_length = [
            relation_resident_owned_byte_length,
            assignment_memory.completed_assignment_resident_owned_byte_length(),
            row_source_geometry.peak_additional_resident_owned_byte_length(),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let preparation_lookup_extension_multiplication_count = checked_add(
            row_source_geometry.lookup_inverse_element_count(),
            row_source_geometry.lookup_table_batch_extension_multiplication_count(),
        )?;

        Ok(Self {
            assignment_memory,
            row_source_geometry,
            element_chunk_count,
            lookup_inverse_sum_poll_count,
            lookup_table_prefix_poll_count,
            lookup_table_inversion_poll_count,
            lookup_table_reverse_poll_count,
            private_polynomial_fill_poll_count,
            private_polynomial_transform_poll_count,
            public_polynomial_fill_poll_count,
            public_polynomial_transform_poll_count,
            pointwise_product_poll_count,
            inverse_product_transform_poll_count,
            negacyclic_product_fold_poll_count,
            deterministic_preparation_poll_count,
            maximum_uninterrupted_elementwise_work_unit_count: element_chunk_count,
            maximum_uninterrupted_transform_butterfly_count,
            preparation_transform_butterfly_count: row_source_geometry.transform_butterfly_count(),
            preparation_pointwise_multiplication_count: row_source_geometry
                .pointwise_multiplication_count(),
            preparation_fold_subtraction_count: row_source_geometry
                .negacyclic_fold_subtraction_count(),
            preparation_lookup_extension_multiplication_count,
            completed_assignment_payload_byte_length,
            product_cache_payload_byte_length,
            product_cache_catalog_byte_length,
            product_cache_resident_owned_byte_length,
            ready_row_source_payload_byte_length,
            relation_resident_owned_byte_length,
            ready_row_source_resident_owned_byte_length,
            maximum_preparation_resident_owned_byte_length,
            authenticated_restart_record_count: 0,
            authenticated_restart_write_byte_length: 0,
            authenticated_restart_read_byte_length: 0,
            maximum_restart_recomputed_transform_butterfly_count: row_source_geometry
                .transform_butterfly_count(),
            maximum_restart_recomputed_pointwise_multiplication_count: row_source_geometry
                .pointwise_multiplication_count(),
            maximum_restart_recomputed_fold_subtraction_count: row_source_geometry
                .negacyclic_fold_subtraction_count(),
            maximum_restart_recomputed_lookup_extension_multiplication_count:
                preparation_lookup_extension_multiplication_count,
            durable_product_cache_restart_is_implemented: false,
        })
    }

    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        if self != &Self::derive_without_check(relation)?
            || self.element_chunk_count == 0
            || self.deterministic_preparation_poll_count == 0
            || self.maximum_uninterrupted_elementwise_work_unit_count != self.element_chunk_count
            || self.maximum_uninterrupted_transform_butterfly_count == 0
            || self.completed_assignment_payload_byte_length
                != self
                    .assignment_memory
                    .completed_assignment_payload_byte_length()
            || self.product_cache_payload_byte_length
                != self.row_source_geometry.product_cache_payload_byte_length()
            || self.product_cache_catalog_byte_length
                != self.row_source_geometry.product_cache_catalog_byte_length()
            || self.product_cache_resident_owned_byte_length
                != self
                    .row_source_geometry
                    .product_cache_resident_owned_byte_length()
            || self.ready_row_source_payload_byte_length
                != checked_add(
                    self.completed_assignment_payload_byte_length,
                    self.product_cache_resident_owned_byte_length,
                )?
            || self.authenticated_restart_record_count != 0
            || self.authenticated_restart_write_byte_length != 0
            || self.authenticated_restart_read_byte_length != 0
            || self.durable_product_cache_restart_is_implemented
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    pub(super) const fn deterministic_preparation_poll_count(&self) -> u64 {
        self.deterministic_preparation_poll_count
    }

    pub(super) const fn base_assignment_payload_byte_length(&self) -> u64 {
        self.assignment_memory.base_assignment_payload_byte_length()
    }

    pub(super) const fn completed_assignment_payload_byte_length(&self) -> u64 {
        self.completed_assignment_payload_byte_length
    }

    pub(super) const fn lookup_materializer_resident_owned_byte_length(&self) -> u64 {
        self.assignment_memory
            .lookup_materializer_resident_owned_byte_length()
    }

    pub(super) const fn maximum_preparation_resident_owned_byte_length(&self) -> u64 {
        self.maximum_preparation_resident_owned_byte_length
    }

    pub(super) const fn relation_resident_owned_byte_length(&self) -> u64 {
        self.relation_resident_owned_byte_length
    }

    pub(super) const fn ready_row_source_resident_owned_byte_length(&self) -> u64 {
        self.ready_row_source_resident_owned_byte_length
    }

    pub(super) const fn maximum_uninterrupted_elementwise_work_unit_count(&self) -> u64 {
        self.maximum_uninterrupted_elementwise_work_unit_count
    }

    pub(super) const fn maximum_uninterrupted_transform_butterfly_count(&self) -> u64 {
        self.maximum_uninterrupted_transform_butterfly_count
    }
}

#[cfg(test)]
mod tests {
    use crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog;

    use super::*;

    #[test]
    fn row_source_preparation_lifecycle_is_exact_and_restart_honest() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog = RowSourceLifecycleCatalog::derive(&relation)
            .expect("compact row-source preparation lifecycle");

        assert_eq!(catalog.element_chunk_count, 8_192);
        assert_eq!(catalog.lookup_inverse_sum_poll_count, 116);
        assert_eq!(catalog.lookup_table_prefix_poll_count, 16);
        assert_eq!(catalog.lookup_table_inversion_poll_count, 1);
        assert_eq!(catalog.lookup_table_reverse_poll_count, 16);
        assert_eq!(catalog.private_polynomial_fill_poll_count, 28);
        assert_eq!(catalog.private_polynomial_transform_poll_count, 7);
        assert_eq!(catalog.public_polynomial_fill_poll_count, 128);
        assert_eq!(catalog.public_polynomial_transform_poll_count, 32);
        assert_eq!(catalog.pointwise_product_poll_count, 256);
        assert_eq!(catalog.inverse_product_transform_poll_count, 32);
        assert_eq!(catalog.negacyclic_product_fold_poll_count, 128);
        assert_eq!(catalog.deterministic_preparation_poll_count, 760);
        assert_eq!(
            catalog.maximum_uninterrupted_elementwise_work_unit_count,
            8_192
        );
        assert_eq!(
            catalog.maximum_uninterrupted_transform_butterfly_count,
            524_288
        );
        assert_eq!(catalog.preparation_transform_butterfly_count, 37_224_448);
        assert_eq!(
            catalog.preparation_pointwise_multiplication_count,
            2_097_152
        );
        assert_eq!(catalog.preparation_fold_subtraction_count, 1_048_576);
        assert_eq!(
            catalog.preparation_lookup_extension_multiplication_count,
            1_474_560
        );
        assert_eq!(catalog.completed_assignment_payload_byte_length, 68_943_880);
        assert_eq!(catalog.product_cache_payload_byte_length, 8_388_608);
        assert_eq!(catalog.product_cache_catalog_byte_length, 1_536);
        assert_eq!(catalog.product_cache_resident_owned_byte_length, 8_390_144);
        assert_eq!(catalog.ready_row_source_payload_byte_length, 77_334_024);
        assert_eq!(
            (
                catalog.relation_resident_owned_byte_length,
                catalog.ready_row_source_resident_owned_byte_length,
                catalog.maximum_preparation_resident_owned_byte_length,
            ),
            (12_784, 77_348_928, 78_399_896)
        );
        assert_eq!(catalog.authenticated_restart_record_count, 0);
        assert_eq!(catalog.authenticated_restart_write_byte_length, 0);
        assert_eq!(catalog.authenticated_restart_read_byte_length, 0);
        assert_eq!(
            catalog.maximum_restart_recomputed_transform_butterfly_count,
            catalog.preparation_transform_butterfly_count
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_pointwise_multiplication_count,
            catalog.preparation_pointwise_multiplication_count
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_fold_subtraction_count,
            catalog.preparation_fold_subtraction_count
        );
        assert_eq!(
            catalog.maximum_restart_recomputed_lookup_extension_multiplication_count,
            catalog.preparation_lookup_extension_multiplication_count
        );
        assert!(!catalog.durable_product_cache_restart_is_implemented);
    }

    #[test]
    fn row_source_preparation_lifecycle_refuses_mutated_counts() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog = RowSourceLifecycleCatalog::derive(&relation)
            .expect("compact row-source preparation lifecycle");

        let mut wrong_poll_count = catalog.clone();
        wrong_poll_count.pointwise_product_poll_count += 1;
        assert_eq!(
            wrong_poll_count.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut false_restart_claim = catalog;
        false_restart_claim.durable_product_cache_restart_is_implemented = true;
        assert_eq!(
            false_restart_claim.check(&relation),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
