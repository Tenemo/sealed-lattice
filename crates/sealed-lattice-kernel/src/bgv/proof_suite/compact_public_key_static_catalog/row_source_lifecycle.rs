//! Bounded preparation ledger for the compact structured R1CS row source.
//!
//! The production preparation state machine advances elementwise work in
//! fixed chunks and isolates every transform in its own poll.

use crate::bgv::proof_suite::relation_plan::{
    CompactPublicKeyRelationCatalog, compact_structured_r1cs_row_source_geometry,
};

use super::{CompactStaticCatalogError, checked_add, checked_product};

pub(super) const ROW_SOURCE_PREPARATION_ELEMENT_CHUNK_COUNT: u64 = 8_192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RowSourceLifecycleCatalog {
    deterministic_preparation_poll_count: u64,
    maximum_uninterrupted_elementwise_work_unit_count: u64,
    maximum_uninterrupted_transform_butterfly_count: u64,
}

impl RowSourceLifecycleCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
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
        Ok(Self {
            deterministic_preparation_poll_count,
            maximum_uninterrupted_elementwise_work_unit_count: element_chunk_count,
            maximum_uninterrupted_transform_butterfly_count,
        })
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
    fn row_source_preparation_lifecycle_is_exact() {
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let catalog = RowSourceLifecycleCatalog::derive(&relation)
            .expect("compact row-source preparation lifecycle");

        assert_eq!(catalog.deterministic_preparation_poll_count, 760);
        assert_eq!(
            catalog.maximum_uninterrupted_elementwise_work_unit_count,
            8_192
        );
        assert_eq!(
            catalog.maximum_uninterrupted_transform_butterfly_count,
            524_288
        );
    }
}
