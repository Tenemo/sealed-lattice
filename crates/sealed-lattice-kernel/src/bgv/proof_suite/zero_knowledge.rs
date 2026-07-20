//! Structural zero-knowledge checks for generated secret-bearing relations.
//!
//! These checks are part of suite generation. They are not proof fields and
//! do not turn a verifier result into an assurance claim. Their purpose is to
//! prevent a generated plan from committing a secret polynomial with too few
//! fresh mask coefficients for the complete verifier-visible opening set.

use std::collections::{BTreeMap, BTreeSet};

use super::relation_plan::{
    ProofPrivacyMode, RelationColumnOrigin, RelationMaskKind, RelationMaskTargetClass,
    RelationOpeningSourceClass,
};
use super::{RelationPlanCheckContext, RelationPlanError, RelationPlanVariant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TraceMaskQueryPhase {
    First,
    Opposite,
}

/// One base-field coordinate of the verifier-visible image of a trace mask.
///
/// An extension-field opening is represented by its complete Galois closure.
/// A query-tree leaf contributes only the two physical evaluations encoded in
/// that leaf. Relation rotations affect the DEEP claim catalog, but they do
/// not create extra query-tree evaluations of a committed polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TraceMaskObservationCoordinate {
    DeepGaloisClosure {
        opening_point_ordinal: u32,
        deep_point_ordinal: u16,
        trace_rotation_is_negative: bool,
        trace_rotation_magnitude: u64,
        descriptor_conjugate_index: u16,
        galois_conjugate_index: u16,
    },
    QueryPhasePair {
        query_ordinal: u32,
        phase: TraceMaskQueryPhase,
    },
}

/// Exact symbolic observation catalog for one committed trace column in one
/// proof invocation.
///
/// The catalog is deliberately not serialized or transcript-bound. It is a
/// checked derivation from the relation plan and field schedule used to prove
/// that the suite allocates enough independent mask coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceMaskObservationCoordinateCatalog {
    #[cfg(test)]
    column_ordinal: u32,
    challenge_extension_degree: u16,
    coordinates: Vec<TraceMaskObservationCoordinate>,
}

impl TraceMaskObservationCoordinateCatalog {
    pub(crate) fn derive(
        variant: &RelationPlanVariant,
        column_ordinal: u32,
        challenge_extension_degree: u16,
        unique_query_count: u32,
    ) -> Result<Self, RelationPlanError> {
        if challenge_extension_degree == 0
            || variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .is_none()
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }

        let opening_point_ordinals = variant
            .ordered_opening_claims()
            .iter()
            .filter(|claim| {
                claim.source_class() == RelationOpeningSourceClass::TreeColumn
                    && claim.column_ordinal() == Some(column_ordinal)
            })
            .map(|claim| claim.opening_point_ordinal())
            .collect::<BTreeSet<_>>();
        if opening_point_ordinals.is_empty() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }

        let deep_coordinate_count = opening_point_ordinals
            .len()
            .checked_mul(usize::from(challenge_extension_degree))
            .ok_or(RelationPlanError::CountOverflow)?;
        let query_coordinate_count = usize::try_from(unique_query_count)
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        let mut coordinates = Vec::new();
        coordinates
            .try_reserve_exact(
                deep_coordinate_count
                    .checked_add(query_coordinate_count)
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;

        for opening_point_ordinal in opening_point_ordinals {
            let opening_point = variant
                .ordered_opening_points()
                .get(
                    usize::try_from(opening_point_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .copied()
                .ok_or(RelationPlanError::InvalidMaskGrammar)?;
            let (trace_rotation_is_negative, trace_rotation_magnitude) =
                opening_point.trace_rotation();
            for galois_conjugate_index in 0..challenge_extension_degree {
                coordinates.push(TraceMaskObservationCoordinate::DeepGaloisClosure {
                    opening_point_ordinal,
                    deep_point_ordinal: opening_point.deep_point_ordinal(),
                    trace_rotation_is_negative,
                    trace_rotation_magnitude,
                    descriptor_conjugate_index: opening_point.conjugate_index(),
                    galois_conjugate_index,
                });
            }
        }
        for query_ordinal in 0..unique_query_count {
            coordinates.push(TraceMaskObservationCoordinate::QueryPhasePair {
                query_ordinal,
                phase: TraceMaskQueryPhase::First,
            });
            coordinates.push(TraceMaskObservationCoordinate::QueryPhasePair {
                query_ordinal,
                phase: TraceMaskQueryPhase::Opposite,
            });
        }

        Ok(Self {
            #[cfg(test)]
            column_ordinal,
            challenge_extension_degree,
            coordinates,
        })
    }

    #[cfg(test)]
    pub(crate) const fn column_ordinal(&self) -> u32 {
        self.column_ordinal
    }

    pub(crate) const fn challenge_extension_degree(&self) -> u16 {
        self.challenge_extension_degree
    }

    pub(crate) fn coordinates(&self) -> &[TraceMaskObservationCoordinate] {
        &self.coordinates
    }

    pub(crate) fn base_coordinate_count(&self) -> Result<u64, RelationPlanError> {
        u64::try_from(self.coordinates.len()).map_err(|_| RelationPlanError::CountOverflow)
    }
}

/// Computation-derived rank-ceiling check for the direct evaluations of one
/// base-field mask polynomial represented by one or more observation catalogs.
///
/// For each DEEP opening the catalog contains the complete Galois closure, and
/// every query coordinate lies in the base field. Their union is therefore
/// Frobenius closed. Subject to the sampler's separate trace-domain,
/// full-degree, disjoint-orbit, and coprimality checks, Habock-Al Kindi's
/// evaluation-image lemma identifies the direct-evaluation rank over the base
/// field with the number of distinct coordinates. Summing the catalogs is a
/// conservative upper bound even when separate proof invocations happen to
/// observe the same point. Passing this check does not establish a simulator
/// for nonlinear quotient, lookup, fold, or auxiliary-input views. This value
/// is suite-generation state, not proof output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TraceMaskSurjectivityCertificate {
    #[cfg(test)]
    mask_coefficient_count: u64,
    #[cfg(test)]
    evaluation_image_rank_ceiling: u64,
    #[cfg(test)]
    proof_view_count: u32,
}

impl TraceMaskSurjectivityCertificate {
    pub(crate) fn derive(
        mask_coefficient_count: u64,
        catalogs: &[TraceMaskObservationCoordinateCatalog],
    ) -> Result<Self, RelationPlanError> {
        if mask_coefficient_count == 0 || catalogs.is_empty() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let challenge_extension_degree = catalogs[0].challenge_extension_degree();
        if challenge_extension_degree == 0
            || catalogs.iter().any(|catalog| {
                catalog.challenge_extension_degree() != challenge_extension_degree
                    || catalog.coordinates().is_empty()
            })
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let evaluation_image_rank_ceiling =
            catalogs
                .iter()
                .try_fold(0_u64, |coordinate_count, catalog| {
                    coordinate_count
                        .checked_add(catalog.base_coordinate_count()?)
                        .ok_or(RelationPlanError::CountOverflow)
                })?;
        if mask_coefficient_count < evaluation_image_rank_ceiling {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        Ok(Self {
            #[cfg(test)]
            mask_coefficient_count,
            #[cfg(test)]
            evaluation_image_rank_ceiling,
            #[cfg(test)]
            proof_view_count: u32::try_from(catalogs.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    #[cfg(test)]
    pub(crate) const fn mask_coefficient_count(self) -> u64 {
        self.mask_coefficient_count
    }

    #[cfg(test)]
    pub(crate) const fn evaluation_image_rank_ceiling(self) -> u64 {
        self.evaluation_image_rank_ceiling
    }

    #[cfg(test)]
    pub(crate) const fn proof_view_count(self) -> u32 {
        self.proof_view_count
    }
}

/// Checks the evaluation-image dimensions required by the common masking
/// grammar. All coordinates come from the checked plan and field schedule.
///
/// Telescoping and opening-batch masks have extension-field coefficients, so
/// their image argument is the ordinary Vandermonde argument over distinct
/// visible points. The bounds below count their complete visible geometry.
pub(crate) fn validate_zero_knowledge_mask_image(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(());
    }

    let phase_pair_query_coordinate_count = u64::from(context.unique_query_count)
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let trace_mask_degree_by_column = variant
        .ordered_masks()
        .iter()
        .filter(|mask| {
            mask.mask_kind() == RelationMaskKind::Trace
                && mask.target_class() == RelationMaskTargetClass::Column
        })
        .map(|mask| (mask.target_ordinal(), mask.mask_degree_bound_exclusive()))
        .collect::<BTreeMap<_, _>>();

    for (column_ordinal, column) in variant.ordered_columns().iter().enumerate() {
        if !matches!(column.origin(), RelationColumnOrigin::Prover) {
            continue;
        }
        let column_ordinal =
            u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        let catalog = TraceMaskObservationCoordinateCatalog::derive(
            variant,
            column_ordinal,
            context.challenge_extension_degree,
            context.unique_query_count,
        )?;
        let actual_trace_mask_degree = trace_mask_degree_by_column
            .get(&column_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if actual_trace_mask_degree > variant.trace_domain_size() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        TraceMaskSurjectivityCertificate::derive(actual_trace_mask_degree, &[catalog])?;
    }

    let minimum_telescoping_mask_degree = u64::from(context.deep_point_count)
        .checked_add(phase_pair_query_coordinate_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut telescoping_mask_count = 0_u32;
    for mask in variant.ordered_masks().iter().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Telescoping
            && mask.target_class() == RelationMaskTargetClass::QuotientComponent
    }) {
        if mask.mask_degree_bound_exclusive() < minimum_telescoping_mask_degree {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        telescoping_mask_count = telescoping_mask_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    if telescoping_mask_count
        .checked_add(1)
        .ok_or(RelationPlanError::CountOverflow)?
        != context.quotient_component_count
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }

    let minimum_opening_batch_mask_degree = phase_pair_query_coordinate_count
        .checked_add(1)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut opening_batch_masks = variant.ordered_masks().iter().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
    });
    let opening_batch_mask = opening_batch_masks
        .next()
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    if opening_batch_masks.next().is_some()
        || opening_batch_mask.mask_degree_bound_exclusive() < minimum_opening_batch_mask_degree
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_catalog(
        column_ordinal: u32,
        opening_point_ordinals: &[u32],
        unique_query_count: u32,
    ) -> TraceMaskObservationCoordinateCatalog {
        let mut coordinates = Vec::new();
        for opening_point_ordinal in opening_point_ordinals {
            for galois_conjugate_index in 0..5 {
                coordinates.push(TraceMaskObservationCoordinate::DeepGaloisClosure {
                    opening_point_ordinal: *opening_point_ordinal,
                    deep_point_ordinal: 0,
                    trace_rotation_is_negative: false,
                    trace_rotation_magnitude: u64::from(*opening_point_ordinal),
                    descriptor_conjugate_index: 0,
                    galois_conjugate_index,
                });
            }
        }
        for query_ordinal in 0..unique_query_count {
            coordinates.push(TraceMaskObservationCoordinate::QueryPhasePair {
                query_ordinal,
                phase: TraceMaskQueryPhase::First,
            });
            coordinates.push(TraceMaskObservationCoordinate::QueryPhasePair {
                query_ordinal,
                phase: TraceMaskQueryPhase::Opposite,
            });
        }
        TraceMaskObservationCoordinateCatalog {
            column_ordinal,
            challenge_extension_degree: 5,
            coordinates,
        }
    }

    #[test]
    fn query_tree_geometry_contributes_one_phase_pair_per_query() {
        let catalog = synthetic_catalog(4, &[2, 7, 11], 14);

        assert_eq!(catalog.column_ordinal(), 4);
        assert_eq!(catalog.base_coordinate_count(), Ok(3 * 5 + 2 * 14));
        assert_eq!(
            catalog
                .coordinates()
                .iter()
                .filter(|coordinate| matches!(
                    coordinate,
                    TraceMaskObservationCoordinate::QueryPhasePair { .. }
                ))
                .count(),
            2 * 14
        );
    }

    #[test]
    fn joint_persistent_views_are_covered_per_physical_column() {
        let producer = synthetic_catalog(3, &[0, 1], 192);
        let first_consumer = synthetic_catalog(8, &[0], 192);
        let second_consumer = synthetic_catalog(12, &[0, 1, 2], 168);
        let exact_catalog_ceiling = producer.base_coordinate_count().unwrap()
            + first_consumer.base_coordinate_count().unwrap()
            + second_consumer.base_coordinate_count().unwrap();

        let certificate = TraceMaskSurjectivityCertificate::derive(
            exact_catalog_ceiling,
            &[producer, first_consumer, second_consumer],
        )
        .expect("the joint image fits the independently sampled mask");

        assert_eq!(certificate.mask_coefficient_count(), exact_catalog_ceiling);
        assert_eq!(
            certificate.evaluation_image_rank_ceiling(),
            exact_catalog_ceiling
        );
        assert_eq!(certificate.proof_view_count(), 3);
    }

    #[test]
    fn one_missing_mask_coefficient_refuses_the_joint_view() {
        let producer = synthetic_catalog(3, &[0, 1], 192);
        let consumer = synthetic_catalog(8, &[0, 1], 192);
        let required =
            producer.base_coordinate_count().unwrap() + consumer.base_coordinate_count().unwrap();

        assert_eq!(
            TraceMaskSurjectivityCertificate::derive(required - 1, &[producer, consumer]),
            Err(RelationPlanError::InvalidMaskGrammar)
        );
    }

    #[test]
    fn incompatible_extension_catalogs_refuse_composition() {
        let first = synthetic_catalog(3, &[0], 4);
        let mut second = synthetic_catalog(8, &[0], 4);
        second.challenge_extension_degree = 1;

        assert_eq!(
            TraceMaskSurjectivityCertificate::derive(1_000, &[first, second]),
            Err(RelationPlanError::InvalidMaskGrammar)
        );
    }
}
