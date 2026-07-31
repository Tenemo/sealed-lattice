//! Construction-level masking correspondence for secret-bearing relations.
//!
//! These checks are part of suite generation. They derive the complete generic
//! catalog of verifier-visible construction views and their mask-source
//! dependencies from the checked relation plan. Direct trace coordinates,
//! quotient telescoping, opening masks, reset ownership, and the exact rank
//! obligations are checked here. The challenge-dependent aggregate matrix is
//! recomputed by both production prover and verifier and must have the rank
//! recorded by this certificate before a proof can be emitted or accepted.
//!
//! This module does not claim a family-specific simulator, cross-proof
//! composition, or ceremony zero knowledge. Those arguments remain with the
//! family and workflow that owns the corresponding witness language.

use std::collections::{BTreeMap, BTreeSet};

use super::relation_plan::{
    ProofPrivacyMode, RelationColumnOrigin, RelationMaskDescriptor, RelationMaskKind,
    RelationMaskTargetClass, RelationOpeningSourceClass, RelationTreeDescriptor,
};
use super::row_code_whir::construction_plan::RowCodeWhirSelectedParameters;
use super::{RelationPlanCheckContext, RelationPlanError, RelationPlanVariant};

/// One base-field coordinate of the verifier-visible image of a trace mask.
///
/// An extension-field opening is represented by its complete Galois closure.
/// The row-code phase commitment contributes one base-field coordinate for
/// each phase-column query. A bound-tree leaf contains two evaluations of each
/// physical column, so its checked catalog contributes two coordinates for
/// every selected bound query. Relation rotations affect the out-of-domain
/// claim catalog, but they do not create extra queried evaluations of a
/// committed polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TraceMaskObservationCoordinate {
    OutOfDomainGaloisClosure {
        opening_point_ordinal: u32,
        out_of_domain_point_ordinal: u16,
        trace_rotation_is_negative: bool,
        trace_rotation_magnitude: u64,
        descriptor_conjugate_index: u16,
        galois_conjugate_index: u16,
    },
    PhaseColumnQuery {
        query_ordinal: u32,
    },
    #[cfg(test)]
    BoundTreeLeafQuery {
        query_ordinal: u32,
        leaf_coordinate_ordinal: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceMaskQueryGeometry {
    PhaseColumn,
    #[cfg(test)]
    BoundTreeLeafPair,
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
    fn query_coordinate_count(
        query_count: u32,
        query_geometry: TraceMaskQueryGeometry,
    ) -> Result<u32, RelationPlanError> {
        match query_geometry {
            TraceMaskQueryGeometry::PhaseColumn => Ok(query_count),
            #[cfg(test)]
            TraceMaskQueryGeometry::BoundTreeLeafPair => query_count
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow),
        }
    }

    pub(crate) fn derive(
        variant: &RelationPlanVariant,
        column_ordinal: u32,
        challenge_extension_degree: u16,
        phase_column_query_coordinate_count: u32,
    ) -> Result<Self, RelationPlanError> {
        Self::derive_with_query_geometry(
            variant,
            column_ordinal,
            challenge_extension_degree,
            phase_column_query_coordinate_count,
            TraceMaskQueryGeometry::PhaseColumn,
        )
    }

    #[cfg(test)]
    pub(crate) fn derive_for_bound_tree(
        variant: &RelationPlanVariant,
        column_ordinal: u32,
        challenge_extension_degree: u16,
        bound_tree_query_count: u32,
    ) -> Result<Self, RelationPlanError> {
        Self::derive_with_query_geometry(
            variant,
            column_ordinal,
            challenge_extension_degree,
            bound_tree_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        )
    }

    fn derive_with_query_geometry(
        variant: &RelationPlanVariant,
        column_ordinal: u32,
        challenge_extension_degree: u16,
        query_count: u32,
        query_geometry: TraceMaskQueryGeometry,
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

        let out_of_domain_coordinate_count = opening_point_ordinals
            .len()
            .checked_mul(usize::from(challenge_extension_degree))
            .ok_or(RelationPlanError::CountOverflow)?;
        let query_coordinate_count = Self::query_coordinate_count(query_count, query_geometry)?;
        let query_coordinate_count_usize = usize::try_from(query_coordinate_count)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let mut coordinates = Vec::new();
        coordinates
            .try_reserve_exact(
                out_of_domain_coordinate_count
                    .checked_add(query_coordinate_count_usize)
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
                coordinates.push(TraceMaskObservationCoordinate::OutOfDomainGaloisClosure {
                    opening_point_ordinal,
                    out_of_domain_point_ordinal: opening_point.out_of_domain_point_ordinal(),
                    trace_rotation_is_negative,
                    trace_rotation_magnitude,
                    descriptor_conjugate_index: opening_point.conjugate_index(),
                    galois_conjugate_index,
                });
            }
        }
        for query_ordinal in 0..query_count {
            match query_geometry {
                TraceMaskQueryGeometry::PhaseColumn => coordinates
                    .push(TraceMaskObservationCoordinate::PhaseColumnQuery { query_ordinal }),
                #[cfg(test)]
                TraceMaskQueryGeometry::BoundTreeLeafPair => {
                    for leaf_coordinate_ordinal in 0..2 {
                        coordinates.push(TraceMaskObservationCoordinate::BoundTreeLeafQuery {
                            query_ordinal,
                            leaf_coordinate_ordinal,
                        });
                    }
                }
            }
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
/// For each out-of-domain opening the catalog contains the complete Galois
/// closure, and every phase-column query coordinate lies in the base field.
/// Their union is therefore Frobenius closed. Subject to the sampler's
/// separate trace-domain, full-degree, disjoint-orbit, and coprimality checks,
/// Habock-Al Kindi's evaluation-image lemma identifies the direct-evaluation
/// rank over the base field with the number of distinct coordinates. Summing
/// the catalogs is a conservative upper bound even when separate proof
/// invocations happen to observe the same point. Passing this check does not
/// establish a simulator for nonlinear quotient, lookup, fold, or
/// auxiliary-input views. This value is suite-generation state, not proof
/// output.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskingPhase {
    Base,
    Auxiliary,
    Quotient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite) enum ConstructionSecretViewIdentifier {
    Phase {
        column_ordinal: u32,
    },
    Auxiliary {
        column_ordinal: u32,
    },
    Quotient {
        component_ordinal: u32,
    },
    Bound {
        relation_tree_ordinal: u32,
        column_ordinal: u32,
    },
    Mask {
        mask_ordinal: u32,
    },
    Aggregate {
        opening_point_ordinal: u32,
    },
    Opening {
        source_class: u16,
        source_ordinal: u32,
        column_ordinal: Option<u32>,
        opening_point_ordinal: u32,
    },
    FoldClosure,
    ExplicitPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionSecretViewAlgebra {
    Affine,
    Nonlinear,
    IndependentMask,
    DerivedLinear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskSourceIdentifier {
    RelationMask {
        purpose_class: u16,
        mask_ordinal: u32,
        target_class: u16,
        target_ordinal: u32,
    },
    RowPad {
        phase: ConstructionMaskingPhase,
    },
    BoundColumn {
        relation_tree_ordinal: u32,
        column_ordinal: u32,
        root_use: u16,
    },
    /// The one private aggregate-wide pad committed before the opening
    /// argument samples any claim-dependent challenge.
    AggregateWidePad,
}

impl ConstructionMaskSourceIdentifier {
    const fn relation_mask(mask: RelationMaskDescriptor) -> ConstructionMaskSourceIdentifier {
        ConstructionMaskSourceIdentifier::RelationMask {
            purpose_class: mask.mask_coordinate().purpose_class(),
            mask_ordinal: mask.mask_coordinate().mask_ordinal(),
            target_class: mask.target_class() as u16,
            target_ordinal: mask.target_ordinal(),
        }
    }

    const fn is_direct_relation_mask(self) -> bool {
        matches!(self, Self::RelationMask { .. })
    }

    const fn is_opening_batch_mask(self) -> bool {
        matches!(
            self,
            Self::RelationMask {
                purpose_class,
                target_class,
                target_ordinal: 0,
                ..
            } if purpose_class == RelationMaskKind::OpeningBatch as u16
                && target_class == RelationMaskTargetClass::Batch as u16
        )
    }

    const fn is_telescoping_mask(self) -> bool {
        matches!(
            self,
            Self::RelationMask {
                purpose_class,
                target_class,
                ..
            } if purpose_class == RelationMaskKind::Telescoping as u16
                && target_class == RelationMaskTargetClass::QuotientComponent as u16
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskSourceAuthority {
    FreshAttemptCoins,
    AuthenticatedPersistentObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskSourceLifetime {
    Attempt,
    PersistentObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskResumeRule {
    PreserveAttemptIdentity,
    ImmutableAuthenticatedObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ConstructionMaskSourceDescriptor {
    pub(in crate::bgv::proof_suite) identifier: ConstructionMaskSourceIdentifier,
    pub(in crate::bgv::proof_suite) authority: ConstructionMaskSourceAuthority,
    pub(in crate::bgv::proof_suite) lifetime: ConstructionMaskSourceLifetime,
    pub(in crate::bgv::proof_suite) resume_rule: ConstructionMaskResumeRule,
    pub(in crate::bgv::proof_suite) checkpoint_excludes_secret: bool,
    pub(in crate::bgv::proof_suite) telemetry_excludes_secret: bool,
}

impl ConstructionMaskSourceDescriptor {
    pub(in crate::bgv::proof_suite) const fn current_attempt(
        identifier: ConstructionMaskSourceIdentifier,
    ) -> Self {
        Self {
            identifier,
            authority: ConstructionMaskSourceAuthority::FreshAttemptCoins,
            lifetime: ConstructionMaskSourceLifetime::Attempt,
            resume_rule: ConstructionMaskResumeRule::PreserveAttemptIdentity,
            checkpoint_excludes_secret: true,
            telemetry_excludes_secret: true,
        }
    }

    pub(in crate::bgv::proof_suite) const fn authenticated_persistent_object(
        identifier: ConstructionMaskSourceIdentifier,
    ) -> Self {
        Self {
            identifier,
            authority: ConstructionMaskSourceAuthority::AuthenticatedPersistentObject,
            lifetime: ConstructionMaskSourceLifetime::PersistentObject,
            resume_rule: ConstructionMaskResumeRule::ImmutableAuthenticatedObject,
            checkpoint_excludes_secret: true,
            telemetry_excludes_secret: true,
        }
    }

    const fn has_reset_safe_ownership(self) -> bool {
        matches!(
            (
                self.authority,
                self.lifetime,
                self.resume_rule,
                self.checkpoint_excludes_secret,
                self.telemetry_excludes_secret,
            ),
            (
                ConstructionMaskSourceAuthority::FreshAttemptCoins,
                ConstructionMaskSourceLifetime::Attempt,
                ConstructionMaskResumeRule::PreserveAttemptIdentity,
                true,
                true,
            ) | (
                ConstructionMaskSourceAuthority::AuthenticatedPersistentObject,
                ConstructionMaskSourceLifetime::PersistentObject,
                ConstructionMaskResumeRule::ImmutableAuthenticatedObject,
                true,
                true,
            )
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ConstructionMaskDependency {
    pub(in crate::bgv::proof_suite) source: ConstructionMaskSourceIdentifier,
    pub(in crate::bgv::proof_suite) coefficient: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ConstructionSecretViewDescriptor {
    pub(in crate::bgv::proof_suite) identifier: ConstructionSecretViewIdentifier,
    pub(in crate::bgv::proof_suite) algebra: ConstructionSecretViewAlgebra,
    pub(in crate::bgv::proof_suite) direct_mask_dependencies: Vec<ConstructionMaskDependency>,
    pub(in crate::bgv::proof_suite) inherited_mask_sources:
        BTreeSet<ConstructionMaskSourceIdentifier>,
}

impl ConstructionSecretViewDescriptor {
    pub(in crate::bgv::proof_suite) fn all_mask_sources(
        &self,
    ) -> BTreeSet<ConstructionMaskSourceIdentifier> {
        self.direct_mask_dependencies
            .iter()
            .map(|dependency| dependency.source)
            .chain(self.inherited_mask_sources.iter().copied())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskingRankKind {
    RowPadEvaluation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ConstructionMaskingRankVerification {
    DistinctPointVandermonde,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ConstructionMaskingRankRequirement {
    pub(in crate::bgv::proof_suite) kind: ConstructionMaskingRankKind,
    pub(in crate::bgv::proof_suite) source_dimension: u64,
    pub(in crate::bgv::proof_suite) required_rank: u64,
    pub(in crate::bgv::proof_suite) verification: ConstructionMaskingRankVerification,
}

impl ConstructionMaskingRankRequirement {
    const fn validate_shape(self) -> Result<(), RelationPlanError> {
        if self.source_dimension == 0
            || self.required_rank == 0
            || self.source_dimension < self.required_rank
            || !matches!(
                (self.kind, self.verification),
                (
                    ConstructionMaskingRankKind::RowPadEvaluation,
                    ConstructionMaskingRankVerification::DistinctPointVandermonde,
                )
            )
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct ConstructionMaskingCorrespondence {
    pub(in crate::bgv::proof_suite) sources: Vec<ConstructionMaskSourceDescriptor>,
    pub(in crate::bgv::proof_suite) views: Vec<ConstructionSecretViewDescriptor>,
    pub(in crate::bgv::proof_suite) rank_requirements: [ConstructionMaskingRankRequirement; 1],
    pub(in crate::bgv::proof_suite) opening_batch_mask_source: ConstructionMaskSourceIdentifier,
    pub(in crate::bgv::proof_suite) aggregate_wide_pad_source: ConstructionMaskSourceIdentifier,
}

fn checked_modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("a residue modulo u64 fits u64")
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = checked_modular_product(result, base, modulus);
        }
        base = checked_modular_product(base, base, modulus);
        exponent >>= 1;
    }
    result
}

/// Computes the rank of a checked rectangular matrix over the relation base
/// field. The suite checker uses this for the telescoping-mask map; the
/// challenge-time aggregate map uses the same operation on its sampled row
/// weights before a proof can be published.
pub(crate) fn construction_masking_matrix_rank(
    matrix: &[Vec<u64>],
    modulus: u64,
) -> Result<usize, RelationPlanError> {
    if modulus < 3 || matrix.is_empty() || matrix[0].is_empty() {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    let column_count = matrix[0].len();
    if matrix
        .iter()
        .any(|row| row.len() != column_count || row.iter().any(|value| *value >= modulus))
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }

    let mut reduced = matrix.to_vec();
    let mut pivot_row = 0_usize;
    for column_ordinal in 0..column_count {
        let Some(nonzero_offset) = reduced[pivot_row..]
            .iter()
            .position(|row| row[column_ordinal] != 0)
        else {
            continue;
        };
        reduced.swap(pivot_row, pivot_row + nonzero_offset);
        let inverse = modular_power(reduced[pivot_row][column_ordinal], modulus - 2, modulus);
        if checked_modular_product(reduced[pivot_row][column_ordinal], inverse, modulus) != 1 {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        for value in &mut reduced[pivot_row][column_ordinal..] {
            *value = checked_modular_product(*value, inverse, modulus);
        }
        let normalized_pivot = reduced[pivot_row][column_ordinal..].to_vec();
        for (row_ordinal, row) in reduced.iter_mut().enumerate() {
            if row_ordinal == pivot_row {
                continue;
            }
            let scale = row[column_ordinal];
            for (value, pivot_value) in row[column_ordinal..].iter_mut().zip(&normalized_pivot) {
                let product = checked_modular_product(scale, *pivot_value, modulus);
                *value = if *value >= product {
                    *value - product
                } else {
                    modulus - (product - *value)
                };
            }
        }
        pivot_row += 1;
        if pivot_row == reduced.len() {
            break;
        }
    }
    Ok(pivot_row)
}

fn construction_phase_by_prover_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, ConstructionMaskingPhase>, RelationPlanError> {
    let mut phases = BTreeMap::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        let phase = match *proof_tree_role {
            1 => ConstructionMaskingPhase::Base,
            2 => ConstructionMaskingPhase::Auxiliary,
            _ => return Err(RelationPlanError::InvalidMaskGrammar),
        };
        for column_ordinal in ordered_column_ordinals {
            let column_index =
                usize::try_from(*column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            if !matches!(
                variant
                    .ordered_columns()
                    .get(column_index)
                    .map(|column| column.origin()),
                Some(RelationColumnOrigin::Prover)
            ) || phases.insert(*column_ordinal, phase).is_some()
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
        }
    }
    let prover_column_count = variant
        .ordered_columns()
        .iter()
        .filter(|column| matches!(column.origin(), RelationColumnOrigin::Prover))
        .count();
    if phases.len() != prover_column_count {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    Ok(phases)
}

fn row_pad_coefficient_count(
    variant: &RelationPlanVariant,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<u64, RelationPlanError> {
    let witness_value_count = parameters
        .logical_polynomial_coefficient_count
        .checked_mul(parameters.logical_polynomials_per_physical_row)
        .ok_or(RelationPlanError::CountOverflow)?;
    let expected_evaluation_domain_size = 1_u64
        .checked_shl(
            u32::try_from(parameters.polynomial_commitment_variable_count)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        )
        .ok_or(RelationPlanError::CountOverflow)?;
    let expected_opening_degree_bound =
        u64::try_from(witness_value_count).map_err(|_| RelationPlanError::CountOverflow)?;
    if parameters.logical_polynomial_coefficient_count == 0
        || !parameters
            .logical_polynomial_coefficient_count
            .is_power_of_two()
        || parameters.logical_polynomials_per_physical_row == 0
        || !parameters
            .logical_polynomials_per_physical_row
            .is_power_of_two()
        || parameters.physical_row_witness_variable_count
            != usize::try_from(witness_value_count.ilog2())
                .map_err(|_| RelationPlanError::CountOverflow)?
        || parameters.table_variable_count
            != parameters
                .physical_row_witness_variable_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?
        || parameters.polynomial_commitment_variable_count
            != parameters
                .table_variable_count
                .checked_add(parameters.row_code_log_inverse_rate)
                .ok_or(RelationPlanError::CountOverflow)?
        || variant.evaluation_domain_size() != expected_evaluation_domain_size
        || variant.opening_degree_bound_exclusive() != expected_opening_degree_bound
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    Ok(expected_opening_degree_bound)
}

fn quotient_mask_dependency_matrix(
    correspondence: &ConstructionMaskingCorrespondence,
    quotient_component_count: u32,
    modulus: u64,
) -> Result<Vec<Vec<u64>>, RelationPlanError> {
    let telescoping_sources = correspondence
        .sources
        .iter()
        .map(|source| source.identifier)
        .filter(|source| source.is_telescoping_mask())
        .collect::<Vec<_>>();
    let expected_source_count = quotient_component_count
        .checked_sub(1)
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    if telescoping_sources.len()
        != usize::try_from(expected_source_count).map_err(|_| RelationPlanError::CountOverflow)?
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    let source_ordinals = telescoping_sources
        .iter()
        .copied()
        .enumerate()
        .map(|(source_ordinal, source)| (source, source_ordinal))
        .collect::<BTreeMap<_, _>>();
    let mut matrix = vec![
        vec![0_u64; telescoping_sources.len()];
        usize::try_from(quotient_component_count)
            .map_err(|_| RelationPlanError::CountOverflow)?
    ];
    for view in &correspondence.views {
        let ConstructionSecretViewIdentifier::Quotient { component_ordinal } = view.identifier
        else {
            continue;
        };
        let row = matrix
            .get_mut(
                usize::try_from(component_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        for dependency in &view.direct_mask_dependencies {
            let Some(source_ordinal) = source_ordinals.get(&dependency.source).copied() else {
                continue;
            };
            if row[source_ordinal] != 0 {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            row[source_ordinal] = dependency.coefficient;
        }
    }
    let expected_last_coefficient = modulus - 1;
    for (component_ordinal, row) in matrix.iter().enumerate() {
        if component_ordinal + 1 < matrix.len() {
            if row.iter().filter(|coefficient| **coefficient != 0).count() != 1
                || row[component_ordinal] != 1
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
        } else if row
            .iter()
            .any(|coefficient| *coefficient != expected_last_coefficient)
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
    }
    Ok(matrix)
}

impl ConstructionMaskingCorrespondence {
    fn derive(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
        parameters: RowCodeWhirSelectedParameters,
    ) -> Result<Self, RelationPlanError> {
        let phase_by_column = construction_phase_by_prover_column(variant)?;
        let mut source_descriptors = BTreeMap::new();
        let mut trace_source_by_column = BTreeMap::new();
        let mut telescoping_source_by_component = BTreeMap::new();
        let mut opening_batch_mask_source = None;

        for mask in variant.ordered_masks().iter().copied() {
            let source = ConstructionMaskSourceIdentifier::relation_mask(mask);
            if source_descriptors
                .insert(
                    source,
                    ConstructionMaskSourceDescriptor::current_attempt(source),
                )
                .is_some()
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            match (mask.mask_kind(), mask.target_class()) {
                (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                    if trace_source_by_column
                        .insert(mask.target_ordinal(), source)
                        .is_some()
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent) => {
                    if telescoping_source_by_component
                        .insert(mask.target_ordinal(), source)
                        .is_some()
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                    if opening_batch_mask_source.replace(source).is_some() {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                _ => return Err(RelationPlanError::InvalidMaskGrammar),
            }
        }
        let opening_batch_mask_source =
            opening_batch_mask_source.ok_or(RelationPlanError::InvalidMaskGrammar)?;

        let mut row_pad_sources = BTreeMap::new();
        for phase in phase_by_column
            .values()
            .copied()
            .chain([ConstructionMaskingPhase::Quotient])
            .collect::<BTreeSet<_>>()
        {
            let source = ConstructionMaskSourceIdentifier::RowPad { phase };
            source_descriptors.insert(
                source,
                ConstructionMaskSourceDescriptor::current_attempt(source),
            );
            row_pad_sources.insert(phase, source);
        }

        let aggregate_wide_pad_source = ConstructionMaskSourceIdentifier::AggregateWidePad;
        if source_descriptors
            .insert(
                aggregate_wide_pad_source,
                ConstructionMaskSourceDescriptor::current_attempt(aggregate_wide_pad_source),
            )
            .is_some()
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }

        let mut bound_source_by_tree_and_column = BTreeMap::new();
        for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
                ..
            } = tree
            else {
                continue;
            };
            let relation_tree_ordinal =
                u32::try_from(tree_index).map_err(|_| RelationPlanError::CountOverflow)?;
            for column_ordinal in ordered_column_ordinals {
                let column_index = usize::try_from(*column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                if !matches!(
                    variant.ordered_columns().get(column_index).map(|column| column.origin()),
                    Some(RelationColumnOrigin::BoundTree {
                        expected_root_source_ordinal: column_root_source,
                    }) if column_root_source == expected_root_source_ordinal
                ) {
                    return Err(RelationPlanError::InvalidMaskGrammar);
                }
                let source = ConstructionMaskSourceIdentifier::BoundColumn {
                    relation_tree_ordinal,
                    column_ordinal: *column_ordinal,
                    root_use: *root_use as u16,
                };
                let descriptor =
                    ConstructionMaskSourceDescriptor::authenticated_persistent_object(source);
                if source_descriptors.insert(source, descriptor).is_some()
                    || bound_source_by_tree_and_column
                        .insert((relation_tree_ordinal, *column_ordinal), source)
                        .is_some()
                {
                    return Err(RelationPlanError::InvalidMaskGrammar);
                }
            }
        }

        let one = 1_u64;
        let mut views = Vec::new();
        for (column_ordinal, phase) in &phase_by_column {
            let trace_source = trace_source_by_column
                .get(column_ordinal)
                .copied()
                .ok_or(RelationPlanError::InvalidMaskGrammar)?;
            let row_pad_source = row_pad_sources
                .get(phase)
                .copied()
                .ok_or(RelationPlanError::InvalidMaskGrammar)?;
            views.push(ConstructionSecretViewDescriptor {
                identifier: match phase {
                    ConstructionMaskingPhase::Base => ConstructionSecretViewIdentifier::Phase {
                        column_ordinal: *column_ordinal,
                    },
                    ConstructionMaskingPhase::Auxiliary => {
                        ConstructionSecretViewIdentifier::Auxiliary {
                            column_ordinal: *column_ordinal,
                        }
                    }
                    ConstructionMaskingPhase::Quotient => {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                },
                algebra: match phase {
                    ConstructionMaskingPhase::Base => ConstructionSecretViewAlgebra::Affine,
                    ConstructionMaskingPhase::Auxiliary => ConstructionSecretViewAlgebra::Nonlinear,
                    ConstructionMaskingPhase::Quotient => {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                },
                direct_mask_dependencies: vec![
                    ConstructionMaskDependency {
                        source: trace_source,
                        coefficient: one,
                    },
                    ConstructionMaskDependency {
                        source: row_pad_source,
                        coefficient: one,
                    },
                ],
                inherited_mask_sources: BTreeSet::new(),
            });
        }

        let trace_sources = trace_source_by_column
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let quotient_row_pad_source = row_pad_sources
            .get(&ConstructionMaskingPhase::Quotient)
            .copied()
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        for component_ordinal in 0..context.quotient_component_count {
            let mut direct_mask_dependencies = vec![ConstructionMaskDependency {
                source: quotient_row_pad_source,
                coefficient: one,
            }];
            if component_ordinal + 1 < context.quotient_component_count {
                direct_mask_dependencies.push(ConstructionMaskDependency {
                    source: telescoping_source_by_component
                        .get(&component_ordinal)
                        .copied()
                        .ok_or(RelationPlanError::InvalidMaskGrammar)?,
                    coefficient: one,
                });
            } else {
                for source in telescoping_source_by_component.values().copied() {
                    direct_mask_dependencies.push(ConstructionMaskDependency {
                        source,
                        coefficient: context.base_field_modulus - 1,
                    });
                }
            }
            views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Quotient { component_ordinal },
                algebra: ConstructionSecretViewAlgebra::Nonlinear,
                direct_mask_dependencies,
                inherited_mask_sources: trace_sources.clone(),
            });
        }

        for ((relation_tree_ordinal, column_ordinal), source) in &bound_source_by_tree_and_column {
            views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Bound {
                    relation_tree_ordinal: *relation_tree_ordinal,
                    column_ordinal: *column_ordinal,
                },
                algebra: ConstructionSecretViewAlgebra::Affine,
                direct_mask_dependencies: vec![ConstructionMaskDependency {
                    source: *source,
                    coefficient: one,
                }],
                inherited_mask_sources: BTreeSet::new(),
            });
        }

        let opening_batch_mask_ordinal = match opening_batch_mask_source {
            ConstructionMaskSourceIdentifier::RelationMask { mask_ordinal, .. } => mask_ordinal,
            _ => return Err(RelationPlanError::InvalidMaskGrammar),
        };
        views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::Mask {
                mask_ordinal: opening_batch_mask_ordinal,
            },
            algebra: ConstructionSecretViewAlgebra::IndependentMask,
            direct_mask_dependencies: vec![ConstructionMaskDependency {
                source: opening_batch_mask_source,
                coefficient: one,
            }],
            inherited_mask_sources: BTreeSet::new(),
        });

        let quotient_views = views
            .iter()
            .filter_map(|view| match view.identifier {
                ConstructionSecretViewIdentifier::Quotient { component_ordinal } => {
                    Some((component_ordinal, view.clone()))
                }
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        for claim in variant.ordered_opening_claims() {
            let (direct_mask_dependencies, inherited_mask_sources) = match claim.source_class() {
                RelationOpeningSourceClass::TreeColumn => {
                    let column_ordinal = claim
                        .column_ordinal()
                        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
                    if let Some(trace_source) = trace_source_by_column.get(&column_ordinal).copied()
                    {
                        let phase = phase_by_column
                            .get(&column_ordinal)
                            .copied()
                            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
                        let row_pad_source = row_pad_sources
                            .get(&phase)
                            .copied()
                            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
                        (
                            vec![
                                ConstructionMaskDependency {
                                    source: trace_source,
                                    coefficient: one,
                                },
                                ConstructionMaskDependency {
                                    source: row_pad_source,
                                    coefficient: one,
                                },
                            ],
                            BTreeSet::new(),
                        )
                    } else {
                        let relation_tree_ordinal = claim.source_ordinal();
                        let Some(bound_source) = bound_source_by_tree_and_column
                            .get(&(relation_tree_ordinal, column_ordinal))
                            .copied()
                        else {
                            continue;
                        };
                        (
                            vec![ConstructionMaskDependency {
                                source: bound_source,
                                coefficient: one,
                            }],
                            BTreeSet::new(),
                        )
                    }
                }
                RelationOpeningSourceClass::Quotient => {
                    let quotient_view = quotient_views
                        .get(&claim.source_ordinal())
                        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
                    (
                        quotient_view.direct_mask_dependencies.clone(),
                        quotient_view.inherited_mask_sources.clone(),
                    )
                }
                RelationOpeningSourceClass::BatchMask => (
                    vec![ConstructionMaskDependency {
                        source: opening_batch_mask_source,
                        coefficient: one,
                    }],
                    BTreeSet::new(),
                ),
            };
            views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Opening {
                    source_class: claim.source_class() as u16,
                    source_ordinal: claim.source_ordinal(),
                    column_ordinal: claim.column_ordinal(),
                    opening_point_ordinal: claim.opening_point_ordinal(),
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies,
                inherited_mask_sources,
            });
        }

        // Each aggregate claim is a verifier-derived linear combination of
        // the relation openings at the same point. It therefore exposes no
        // view beyond those already covered openings and needs no second,
        // challenge-time rank condition on the physical row pads.
        for opening_point_index in 0..variant.ordered_opening_points().len() {
            let opening_point_ordinal =
                u32::try_from(opening_point_index).map_err(|_| RelationPlanError::CountOverflow)?;
            let inherited_mask_sources = views
                .iter()
                .filter(|view| {
                    matches!(
                        view.identifier,
                        ConstructionSecretViewIdentifier::Opening {
                            opening_point_ordinal: candidate,
                            ..
                        } if candidate == opening_point_ordinal
                    )
                })
                .flat_map(ConstructionSecretViewDescriptor::all_mask_sources)
                .collect::<BTreeSet<_>>();
            if inherited_mask_sources.is_empty() {
                continue;
            }
            views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Aggregate {
                    opening_point_ordinal,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: Vec::new(),
                inherited_mask_sources,
            });
        }

        // Fold, spot-check, and terminal views are not relation openings. The
        // selected aggregate-wide construction owns them through one fresh
        // private pad committed before its claim-dependent challenges.
        let aggregate_wide_pad_dependency = ConstructionMaskDependency {
            source: aggregate_wide_pad_source,
            coefficient: one,
        };
        views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::FoldClosure,
            algebra: ConstructionSecretViewAlgebra::DerivedLinear,
            direct_mask_dependencies: vec![aggregate_wide_pad_dependency.clone()],
            inherited_mask_sources: BTreeSet::new(),
        });
        views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::ExplicitPoint,
            algebra: ConstructionSecretViewAlgebra::DerivedLinear,
            direct_mask_dependencies: vec![aggregate_wide_pad_dependency],
            inherited_mask_sources: BTreeSet::new(),
        });

        let row_pad_source_dimension = row_pad_coefficient_count(variant, parameters)?;
        let first_fold_opening_count = u64::from(context.phase_column_query_coordinate_count)
            .checked_shl(
                u32::try_from(parameters.folding_factor)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        let row_pad_required_rank = u64::from(context.phase_column_query_coordinate_count)
            .checked_add(first_fold_opening_count)
            .ok_or(RelationPlanError::CountOverflow)?;

        Ok(Self {
            sources: source_descriptors.into_values().collect(),
            views,
            rank_requirements: [ConstructionMaskingRankRequirement {
                kind: ConstructionMaskingRankKind::RowPadEvaluation,
                source_dimension: row_pad_source_dimension,
                required_rank: row_pad_required_rank,
                verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
            }],
            opening_batch_mask_source,
            aggregate_wide_pad_source,
        })
    }

    fn validate_graph(
        &self,
        expected_view_identifiers: &BTreeSet<ConstructionSecretViewIdentifier>,
        quotient_component_count: u32,
        modulus: u64,
    ) -> Result<(), RelationPlanError> {
        let mut source_identifiers = BTreeSet::new();
        for source in &self.sources {
            if !source.has_reset_safe_ownership() || !source_identifiers.insert(source.identifier) {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
        }
        if !source_identifiers.contains(&self.opening_batch_mask_source)
            || !self.opening_batch_mask_source.is_opening_batch_mask()
            || self.aggregate_wide_pad_source != ConstructionMaskSourceIdentifier::AggregateWidePad
            || !source_identifiers.contains(&self.aggregate_wide_pad_source)
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }

        let mut actual_view_identifiers = BTreeSet::new();
        for view in &self.views {
            if !actual_view_identifiers.insert(view.identifier) {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            let mut direct_sources = BTreeSet::new();
            for dependency in &view.direct_mask_dependencies {
                if dependency.coefficient == 0
                    || dependency.coefficient >= modulus
                    || !source_identifiers.contains(&dependency.source)
                    || !direct_sources.insert(dependency.source)
                {
                    return Err(RelationPlanError::InvalidMaskGrammar);
                }
            }
            if view
                .inherited_mask_sources
                .iter()
                .any(|source| !source_identifiers.contains(source))
                || view.all_mask_sources().is_empty()
                || (view.algebra == ConstructionSecretViewAlgebra::Nonlinear
                    && !view
                        .direct_mask_dependencies
                        .iter()
                        .any(|dependency| dependency.source.is_direct_relation_mask()))
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            match view.identifier {
                ConstructionSecretViewIdentifier::Phase { column_ordinal }
                | ConstructionSecretViewIdentifier::Auxiliary { column_ordinal } => {
                    let expected_phase = match view.identifier {
                        ConstructionSecretViewIdentifier::Phase { .. } => {
                            ConstructionMaskingPhase::Base
                        }
                        ConstructionSecretViewIdentifier::Auxiliary { .. } => {
                            ConstructionMaskingPhase::Auxiliary
                        }
                        _ => unreachable!("matched phase or auxiliary view"),
                    };
                    let has_matching_trace_mask = direct_sources.iter().any(|source| {
                        matches!(
                            source,
                            ConstructionMaskSourceIdentifier::RelationMask {
                                purpose_class,
                                target_class,
                                target_ordinal,
                                ..
                            } if *purpose_class == RelationMaskKind::Trace as u16
                                && *target_class == RelationMaskTargetClass::Column as u16
                                && *target_ordinal == column_ordinal
                        )
                    });
                    if !has_matching_trace_mask
                        || !direct_sources.contains(&ConstructionMaskSourceIdentifier::RowPad {
                            phase: expected_phase,
                        })
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::Bound {
                    relation_tree_ordinal,
                    column_ordinal,
                } => {
                    if !direct_sources.iter().any(|source| {
                        matches!(
                            source,
                            ConstructionMaskSourceIdentifier::BoundColumn {
                                relation_tree_ordinal: source_tree,
                                column_ordinal: source_column,
                                ..
                            } if *source_tree == relation_tree_ordinal
                                && *source_column == column_ordinal
                        )
                    }) {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::Mask { .. } => {
                    if direct_sources != BTreeSet::from([self.opening_batch_mask_source]) {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::Aggregate {
                    opening_point_ordinal,
                } => {
                    let expected_sources = self
                        .views
                        .iter()
                        .filter(|candidate| {
                            matches!(
                                candidate.identifier,
                                ConstructionSecretViewIdentifier::Opening {
                                    opening_point_ordinal: candidate_point,
                                    ..
                                } if candidate_point == opening_point_ordinal
                            )
                        })
                        .flat_map(ConstructionSecretViewDescriptor::all_mask_sources)
                        .collect::<BTreeSet<_>>();
                    if !direct_sources.is_empty()
                        || expected_sources.is_empty()
                        || view.inherited_mask_sources != expected_sources
                        || expected_sources.contains(&self.aggregate_wide_pad_source)
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::FoldClosure
                | ConstructionSecretViewIdentifier::ExplicitPoint => {
                    if direct_sources != BTreeSet::from([self.aggregate_wide_pad_source])
                        || !view.inherited_mask_sources.is_empty()
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::Opening { source_class, .. }
                    if source_class == RelationOpeningSourceClass::BatchMask as u16 =>
                {
                    if direct_sources != BTreeSet::from([self.opening_batch_mask_source]) {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                }
                ConstructionSecretViewIdentifier::Quotient { .. }
                | ConstructionSecretViewIdentifier::Opening { .. } => {}
            }
        }
        if &actual_view_identifiers != expected_view_identifiers {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }

        for requirement in self.rank_requirements {
            requirement.validate_shape()?;
        }
        let quotient_matrix =
            quotient_mask_dependency_matrix(self, quotient_component_count, modulus)?;
        if construction_masking_matrix_rank(&quotient_matrix, modulus)?
            != usize::try_from(
                quotient_component_count
                    .checked_sub(1)
                    .ok_or(RelationPlanError::InvalidMaskGrammar)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        Ok(())
    }
}

fn expected_construction_secret_view_identifiers(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<BTreeSet<ConstructionSecretViewIdentifier>, RelationPlanError> {
    let phase_by_column = construction_phase_by_prover_column(variant)?;
    let mut expected = BTreeSet::new();
    for (column_ordinal, phase) in phase_by_column {
        let identifier = match phase {
            ConstructionMaskingPhase::Base => {
                ConstructionSecretViewIdentifier::Phase { column_ordinal }
            }
            ConstructionMaskingPhase::Auxiliary => {
                ConstructionSecretViewIdentifier::Auxiliary { column_ordinal }
            }
            ConstructionMaskingPhase::Quotient => {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
        };
        if !expected.insert(identifier) {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
    }
    for component_ordinal in 0..context.quotient_component_count {
        expected.insert(ConstructionSecretViewIdentifier::Quotient { component_ordinal });
    }
    for (relation_tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::BoundPublic {
            ordered_column_ordinals,
            ..
        } = tree
        else {
            continue;
        };
        let relation_tree_ordinal =
            u32::try_from(relation_tree_index).map_err(|_| RelationPlanError::CountOverflow)?;
        for column_ordinal in ordered_column_ordinals {
            expected.insert(ConstructionSecretViewIdentifier::Bound {
                relation_tree_ordinal,
                column_ordinal: *column_ordinal,
            });
        }
    }
    let mut opening_batch_masks = variant.ordered_masks().iter().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
    });
    let opening_batch_mask = opening_batch_masks
        .next()
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    if opening_batch_masks.next().is_some() {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    expected.insert(ConstructionSecretViewIdentifier::Mask {
        mask_ordinal: opening_batch_mask.mask_coordinate().mask_ordinal(),
    });
    let aggregate_opening_point_ordinals = variant
        .ordered_opening_claims()
        .iter()
        .map(|claim| claim.opening_point_ordinal())
        .collect::<BTreeSet<_>>();
    for opening_point_ordinal in aggregate_opening_point_ordinals {
        if usize::try_from(opening_point_ordinal).map_err(|_| RelationPlanError::CountOverflow)?
            >= variant.ordered_opening_points().len()
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        expected.insert(ConstructionSecretViewIdentifier::Aggregate {
            opening_point_ordinal,
        });
    }
    for claim in variant.ordered_opening_claims() {
        expected.insert(ConstructionSecretViewIdentifier::Opening {
            source_class: claim.source_class() as u16,
            source_ordinal: claim.source_ordinal(),
            column_ordinal: claim.column_ordinal(),
            opening_point_ordinal: claim.opening_point_ordinal(),
        });
    }
    expected.insert(ConstructionSecretViewIdentifier::FoldClosure);
    expected.insert(ConstructionSecretViewIdentifier::ExplicitPoint);
    Ok(expected)
}

/// Checked generic masking correspondence for one secret-bearing relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConstructionMaskingCertificate {
    public_only: bool,
    source_count: usize,
    view_count: usize,
    direct_dependency_count: usize,
    inherited_dependency_count: usize,
    trace_mask_count: usize,
    trace_base_coordinate_count: u64,
    maximum_trace_base_coordinate_count: u64,
    quotient_dependency_rank: usize,
    quotient_dependency_required_rank: usize,
    row_pad_source_dimension: u64,
    row_pad_required_rank: u64,
    aggregate_claims_factor_through_masked_openings: bool,
    aggregate_wide_views_delegate_to_precommitted_pad: bool,
    all_sources_have_reset_safe_ownership: bool,
    all_views_have_mask_sources: bool,
    complete_view_catalog: bool,
}

impl ConstructionMaskingCertificate {
    fn public_only() -> Self {
        Self {
            public_only: true,
            source_count: 0,
            view_count: 0,
            direct_dependency_count: 0,
            inherited_dependency_count: 0,
            trace_mask_count: 0,
            trace_base_coordinate_count: 0,
            maximum_trace_base_coordinate_count: 0,
            quotient_dependency_rank: 0,
            quotient_dependency_required_rank: 0,
            row_pad_source_dimension: 0,
            row_pad_required_rank: 0,
            aggregate_claims_factor_through_masked_openings: true,
            aggregate_wide_views_delegate_to_precommitted_pad: true,
            all_sources_have_reset_safe_ownership: true,
            all_views_have_mask_sources: true,
            complete_view_catalog: true,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.all_sources_have_reset_safe_ownership
            && self.all_views_have_mask_sources
            && self.complete_view_catalog
            && (self.public_only
                || (self.source_count > 0
                    && self.view_count > 0
                    && self.direct_dependency_count > 0
                    && self.trace_mask_count > 0
                    && self.trace_base_coordinate_count > 0
                    && self.maximum_trace_base_coordinate_count > 0
                    && self.quotient_dependency_rank == self.quotient_dependency_required_rank
                    && self.row_pad_source_dimension >= self.row_pad_required_rank
                    && self.aggregate_claims_factor_through_masked_openings
                    && self.aggregate_wide_views_delegate_to_precommitted_pad))
    }

    #[cfg(test)]
    pub(crate) const fn aggregate_claims_factor_through_masked_openings(&self) -> bool {
        self.aggregate_claims_factor_through_masked_openings
    }

    #[cfg(test)]
    pub(crate) const fn aggregate_wide_views_delegate_to_precommitted_pad(&self) -> bool {
        self.aggregate_wide_views_delegate_to_precommitted_pad
    }
}

/// Checks the construction-level masking correspondence required by the
/// common proof grammar. All views, sources, and dimensions come from the
/// checked relation plan and field schedule.
///
/// Telescoping and opening-batch masks have extension-field coefficients, so
/// their image argument is the ordinary Vandermonde argument over distinct
/// visible points. The dependency graph additionally covers nonlinear
/// auxiliary and quotient views, bound material, the aggregate, every opening,
/// and the handoff to the aggregate-wide precommitted pad. Aggregate claims are
/// derived from the already masked openings; the linked aggregate-wide
/// certificate owns every later fold, query, and terminal view. This does not
/// claim family zero knowledge or cross-proof composition.
fn masking_parameters_for_relation_validation(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<RowCodeWhirSelectedParameters, RelationPlanError> {
    if let Ok(parameters) = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant) {
        return Ok(parameters);
    }
    #[cfg(test)]
    {
        RowCodeWhirSelectedParameters::for_checked_fixture(variant, context)
            .map_err(|_| RelationPlanError::InvalidMaskGrammar)
    }
    #[cfg(not(test))]
    {
        let _ = context;
        Err(RelationPlanError::InvalidMaskGrammar)
    }
}

fn checked_zero_knowledge_mask_image_with_validated_parameters(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<ConstructionMaskingCertificate, RelationPlanError> {
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(ConstructionMaskingCertificate::public_only());
    }

    let construction_correspondence =
        ConstructionMaskingCorrespondence::derive(variant, context, parameters)?;

    let phase_column_query_coordinate_count =
        u64::from(context.phase_column_query_coordinate_count);
    let trace_mask_degree_by_column = variant
        .ordered_masks()
        .iter()
        .filter(|mask| {
            mask.mask_kind() == RelationMaskKind::Trace
                && mask.target_class() == RelationMaskTargetClass::Column
        })
        .map(|mask| (mask.target_ordinal(), mask.mask_degree_bound_exclusive()))
        .collect::<BTreeMap<_, _>>();

    let mut trace_mask_count = 0_usize;
    let mut trace_base_coordinate_count = 0_u64;
    let mut maximum_trace_base_coordinate_count = 0_u64;
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
            context.phase_column_query_coordinate_count,
        )?;
        let actual_trace_mask_degree = trace_mask_degree_by_column
            .get(&column_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if actual_trace_mask_degree > variant.trace_domain_size() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let base_coordinate_count = catalog.base_coordinate_count()?;
        TraceMaskSurjectivityCertificate::derive(actual_trace_mask_degree, &[catalog])?;
        trace_mask_count = trace_mask_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        trace_base_coordinate_count = trace_base_coordinate_count
            .checked_add(base_coordinate_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        maximum_trace_base_coordinate_count =
            maximum_trace_base_coordinate_count.max(base_coordinate_count);
    }

    let minimum_telescoping_mask_degree = u64::from(context.out_of_domain_point_count)
        .checked_add(phase_column_query_coordinate_count)
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

    let minimum_opening_batch_mask_degree = phase_column_query_coordinate_count
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
    let expected_view_identifiers =
        expected_construction_secret_view_identifiers(variant, context)?;
    construction_correspondence.validate_graph(
        &expected_view_identifiers,
        context.quotient_component_count,
        context.base_field_modulus,
    )?;

    let quotient_matrix = quotient_mask_dependency_matrix(
        &construction_correspondence,
        context.quotient_component_count,
        context.base_field_modulus,
    )?;
    let quotient_dependency_rank =
        construction_masking_matrix_rank(&quotient_matrix, context.base_field_modulus)?;
    let quotient_dependency_required_rank = usize::try_from(
        context
            .quotient_component_count
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?,
    )
    .map_err(|_| RelationPlanError::CountOverflow)?;
    let row_pad_requirement = construction_correspondence
        .rank_requirements
        .iter()
        .find(|requirement| requirement.kind == ConstructionMaskingRankKind::RowPadEvaluation)
        .copied()
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    let aggregate_claims_factor_through_masked_openings = construction_correspondence
        .views
        .iter()
        .filter(|view| {
            matches!(
                view.identifier,
                ConstructionSecretViewIdentifier::Aggregate { .. }
            )
        })
        .all(|aggregate_view| {
            aggregate_view.direct_mask_dependencies.is_empty()
                && !aggregate_view.inherited_mask_sources.is_empty()
                && !aggregate_view
                    .inherited_mask_sources
                    .contains(&construction_correspondence.aggregate_wide_pad_source)
        });
    let aggregate_wide_views_delegate_to_precommitted_pad = construction_correspondence
        .views
        .iter()
        .filter(|view| {
            matches!(
                view.identifier,
                ConstructionSecretViewIdentifier::FoldClosure
                    | ConstructionSecretViewIdentifier::ExplicitPoint
            )
        })
        .all(|view| {
            view.direct_mask_dependencies.as_slice()
                == [ConstructionMaskDependency {
                    source: construction_correspondence.aggregate_wide_pad_source,
                    coefficient: 1,
                }]
                && view.inherited_mask_sources.is_empty()
        });
    let certificate = ConstructionMaskingCertificate {
        public_only: false,
        source_count: construction_correspondence.sources.len(),
        view_count: construction_correspondence.views.len(),
        direct_dependency_count: construction_correspondence
            .views
            .iter()
            .map(|view| view.direct_mask_dependencies.len())
            .sum(),
        inherited_dependency_count: construction_correspondence
            .views
            .iter()
            .map(|view| view.inherited_mask_sources.len())
            .sum(),
        trace_mask_count,
        trace_base_coordinate_count,
        maximum_trace_base_coordinate_count,
        quotient_dependency_rank,
        quotient_dependency_required_rank,
        row_pad_source_dimension: row_pad_requirement.source_dimension,
        row_pad_required_rank: row_pad_requirement.required_rank,
        aggregate_claims_factor_through_masked_openings,
        aggregate_wide_views_delegate_to_precommitted_pad,
        all_sources_have_reset_safe_ownership: construction_correspondence
            .sources
            .iter()
            .copied()
            .all(ConstructionMaskSourceDescriptor::has_reset_safe_ownership),
        all_views_have_mask_sources: construction_correspondence
            .views
            .iter()
            .all(|view| !view.all_mask_sources().is_empty()),
        complete_view_catalog: construction_correspondence
            .views
            .iter()
            .map(|view| view.identifier)
            .collect::<BTreeSet<_>>()
            == expected_view_identifiers,
    };
    if !certificate.is_complete() {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    Ok(certificate)
}

fn checked_zero_knowledge_mask_image(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<ConstructionMaskingCertificate, RelationPlanError> {
    let parameters = masking_parameters_for_relation_validation(variant, context)?;
    checked_zero_knowledge_mask_image_with_validated_parameters(variant, context, parameters)
}

#[cfg(test)]
pub(in crate::bgv::proof_suite) fn checked_zero_knowledge_mask_image_for_parameters(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<ConstructionMaskingCertificate, RelationPlanError> {
    let expected_parameters = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant)
        .map_err(|_| RelationPlanError::InvalidMaskGrammar)?;
    if parameters != expected_parameters {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    checked_zero_knowledge_mask_image_with_validated_parameters(variant, context, parameters)
}

#[cfg(test)]
pub(in crate::bgv::proof_suite) fn checked_construction_masking_correspondence_for_parameters(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    parameters: RowCodeWhirSelectedParameters,
) -> Result<Option<ConstructionMaskingCorrespondence>, RelationPlanError> {
    let expected_parameters = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant)
        .map_err(|_| RelationPlanError::InvalidMaskGrammar)?;
    if parameters != expected_parameters {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(None);
    }
    let correspondence = ConstructionMaskingCorrespondence::derive(variant, context, parameters)?;
    let expected_view_identifiers =
        expected_construction_secret_view_identifiers(variant, context)?;
    correspondence.validate_graph(
        &expected_view_identifiers,
        context.quotient_component_count,
        context.base_field_modulus,
    )?;
    Ok(Some(correspondence))
}

pub(crate) fn validate_zero_knowledge_mask_image(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    checked_zero_knowledge_mask_image(variant, context).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::super::relation_plan::BoundTreeRootUse;
    use super::super::{
        ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
        selected_ballot_validity_relation_compilation, selected_relation_plan_check_context,
        selected_same_secret_relation_plan_input,
    };
    use super::*;
    use crate::foundation::ProofApplicationSlotCeilings;

    fn synthetic_catalog(
        column_ordinal: u32,
        opening_point_ordinals: &[u32],
        query_count: u32,
        query_geometry: TraceMaskQueryGeometry,
    ) -> TraceMaskObservationCoordinateCatalog {
        let mut coordinates = Vec::new();
        for opening_point_ordinal in opening_point_ordinals {
            for galois_conjugate_index in 0..5 {
                coordinates.push(TraceMaskObservationCoordinate::OutOfDomainGaloisClosure {
                    opening_point_ordinal: *opening_point_ordinal,
                    out_of_domain_point_ordinal: 0,
                    trace_rotation_is_negative: false,
                    trace_rotation_magnitude: u64::from(*opening_point_ordinal),
                    descriptor_conjugate_index: 0,
                    galois_conjugate_index,
                });
            }
        }
        for query_ordinal in 0..query_count {
            match query_geometry {
                TraceMaskQueryGeometry::PhaseColumn => coordinates
                    .push(TraceMaskObservationCoordinate::PhaseColumnQuery { query_ordinal }),
                TraceMaskQueryGeometry::BoundTreeLeafPair => {
                    for leaf_coordinate_ordinal in 0..2 {
                        coordinates.push(TraceMaskObservationCoordinate::BoundTreeLeafQuery {
                            query_ordinal,
                            leaf_coordinate_ordinal,
                        });
                    }
                }
            }
        }
        TraceMaskObservationCoordinateCatalog {
            column_ordinal,
            challenge_extension_degree: 5,
            coordinates,
        }
    }

    #[test]
    fn row_code_geometry_contributes_one_coordinate_per_phase_column_query() {
        let catalog = synthetic_catalog(4, &[2, 7, 11], 387, TraceMaskQueryGeometry::PhaseColumn);

        assert_eq!(catalog.column_ordinal(), 4);
        assert_eq!(catalog.base_coordinate_count(), Ok(3 * 5 + 387));
        assert_eq!(
            catalog
                .coordinates()
                .iter()
                .filter(|coordinate| matches!(
                    coordinate,
                    TraceMaskObservationCoordinate::PhaseColumnQuery { .. }
                ))
                .count(),
            387
        );
    }

    #[test]
    fn selected_same_secret_direct_view_catalog_has_rank_ceiling_397() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected same-secret relation context");
        let relation_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("compile selected same-secret relation");
        let variant = relation_plan
            .select_variant(None, None)
            .expect("select same-secret relation variant");
        let trace_mask_degree_by_column = variant
            .ordered_masks()
            .iter()
            .filter(|mask| mask.mask_kind() == RelationMaskKind::Trace)
            .map(|mask| (mask.target_ordinal(), mask.mask_degree_bound_exclusive()))
            .collect::<BTreeMap<_, _>>();

        let mut maximum_direct_view_rank = 0_u64;
        let mut saw_two_rotation_column = false;
        let selected_trace_mask_degree_bound_exclusive =
            RowCodeWhirSelectedParameters::selected().trace_mask_degree_bound_exclusive;
        for (column_index, column) in variant.ordered_columns().iter().enumerate() {
            if !matches!(column.origin(), RelationColumnOrigin::Prover) {
                continue;
            }
            let column_ordinal =
                u32::try_from(column_index).expect("selected column ordinal fits u32");
            let catalog = TraceMaskObservationCoordinateCatalog::derive(
                variant,
                column_ordinal,
                context.challenge_extension_degree,
                context.phase_column_query_coordinate_count,
            )
            .expect("selected direct-view catalog derives");
            let query_coordinate_count = catalog
                .coordinates()
                .iter()
                .filter(|coordinate| {
                    matches!(
                        coordinate,
                        TraceMaskObservationCoordinate::PhaseColumnQuery { .. }
                    )
                })
                .count();
            assert_eq!(query_coordinate_count, 387);
            let direct_view_rank = catalog
                .base_coordinate_count()
                .expect("selected direct-view count fits u64");
            saw_two_rotation_column |= direct_view_rank == 397;
            maximum_direct_view_rank = maximum_direct_view_rank.max(direct_view_rank);
            assert_eq!(
                trace_mask_degree_by_column.get(&column_ordinal),
                Some(&selected_trace_mask_degree_bound_exclusive),
            );
            assert!(direct_view_rank <= selected_trace_mask_degree_bound_exclusive);
        }

        assert!(saw_two_rotation_column);
        assert_eq!(maximum_direct_view_rank, 397);
    }

    #[test]
    fn selected_same_secret_masking_certificate_is_complete_and_independently_censused() {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected same-secret relation context");
        let relation_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("compile selected same-secret relation");
        let variant = relation_plan
            .select_variant(None, None)
            .expect("select same-secret relation variant");
        let certificate = checked_zero_knowledge_mask_image(variant, &context)
            .expect("selected masking certificate");

        assert!(certificate.is_complete());
        assert!(!certificate.public_only);
        assert!(certificate.source_count > 0);
        assert!(certificate.view_count > certificate.source_count);
        assert!(certificate.direct_dependency_count > certificate.view_count);
        assert!(certificate.inherited_dependency_count > 0);
        assert_eq!(certificate.maximum_trace_base_coordinate_count, 397);
        assert_eq!(certificate.quotient_dependency_rank, 7);
        assert_eq!(certificate.quotient_dependency_required_rank, 7);
        assert!(certificate.aggregate_claims_factor_through_masked_openings());
        assert!(certificate.aggregate_wide_views_delegate_to_precommitted_pad());

        let parameters = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant)
            .expect("selected row-code parameters derive");
        let correspondence =
            ConstructionMaskingCorrespondence::derive(variant, &context, parameters)
                .expect("selected construction masking correspondence");
        let expected = expected_construction_secret_view_identifiers(variant, &context)
            .expect("independent selected view census");
        assert_eq!(correspondence.views.len(), expected.len());

        let mut missing_view = correspondence;
        missing_view.views.pop();
        assert_eq!(
            missing_view.validate_graph(
                &expected,
                context.quotient_component_count,
                context.base_field_modulus,
            ),
            Err(RelationPlanError::InvalidMaskGrammar),
        );
    }

    #[test]
    fn compact_masking_correspondence_uses_the_variant_owned_row_capacity() {
        let compilation = selected_ballot_validity_relation_compilation()
            .expect("the selected ballot relation compiles");
        let compiled_plan = compilation.relation_plan().clone();
        let context = selected_relation_plan_check_context(
            compiled_plan.application_statement_schema_identifier(),
        )
        .expect("the selected ballot context exists");
        let artifact =
            ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
                .expect("the selected ballot relation validates");
        let variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("the selected ballot variant exists");
        let parameters = RowCodeWhirSelectedParameters::for_selected_variant_geometry(variant)
            .expect("the selected ballot row geometry derives");
        let certificate =
            checked_zero_knowledge_mask_image_for_parameters(variant, &context, parameters)
                .expect("the compact masking correspondence derives");

        assert_eq!(parameters.logical_polynomials_per_physical_row, 8);
        assert_eq!(parameters.row_code_log_inverse_rate, 5);
        assert_eq!(
            certificate.row_pad_source_dimension,
            variant.opening_degree_bound_exclusive(),
        );

        let mut wrong_width = parameters;
        wrong_width.logical_polynomials_per_physical_row = 64;
        assert_eq!(
            checked_zero_knowledge_mask_image_for_parameters(variant, &context, wrong_width),
            Err(RelationPlanError::InvalidMaskGrammar),
            "a width-64 global default cannot certify the compact construction",
        );
    }

    #[test]
    fn bound_tree_catalogs_count_both_leaf_coordinates_for_each_selected_query() {
        let parameters = super::super::row_code_whir::RowCodeWhirSelectedParameters::selected();
        let direct_catalog = synthetic_catalog(
            4,
            &[2],
            u32::try_from(parameters.direct_bound_query_count)
                .expect("the selected direct query count fits u32"),
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
        let prior_vss_catalog = synthetic_catalog(
            4,
            &[2],
            u32::try_from(parameters.prior_proof_bound_query_count)
                .expect("the selected prior-VSS query count fits u32"),
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );

        assert_eq!(direct_catalog.base_coordinate_count(), Ok(537));
        assert_eq!(prior_vss_catalog.base_coordinate_count(), Ok(85));
        assert_eq!(
            direct_catalog
                .coordinates()
                .iter()
                .filter(|coordinate| matches!(
                    coordinate,
                    TraceMaskObservationCoordinate::BoundTreeLeafQuery { .. }
                ))
                .count(),
            532,
        );
    }

    #[test]
    fn bound_tree_catalog_rejects_a_query_geometry_that_cannot_be_doubled() {
        assert_eq!(
            TraceMaskObservationCoordinateCatalog::query_coordinate_count(
                u32::MAX,
                TraceMaskQueryGeometry::BoundTreeLeafPair,
            ),
            Err(RelationPlanError::CountOverflow),
        );
    }

    #[test]
    fn joint_persistent_views_are_covered_per_physical_column() {
        let parameters = super::super::row_code_whir::RowCodeWhirSelectedParameters::selected();
        let direct_query_count = u32::try_from(parameters.direct_bound_query_count)
            .expect("the selected direct query count fits u32");
        let prior_vss_query_count = u32::try_from(parameters.prior_proof_bound_query_count)
            .expect("the selected prior-VSS query count fits u32");
        let producer = synthetic_catalog(
            3,
            &[0, 1],
            direct_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
        let first_consumer = synthetic_catalog(
            8,
            &[0],
            prior_vss_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
        let second_consumer = synthetic_catalog(
            12,
            &[0, 1, 2],
            direct_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
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
        let direct_query_count = u32::try_from(
            super::super::row_code_whir::RowCodeWhirSelectedParameters::selected()
                .direct_bound_query_count,
        )
        .expect("the selected direct query count fits u32");
        let producer = synthetic_catalog(
            3,
            &[0, 1],
            direct_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
        let consumer = synthetic_catalog(
            8,
            &[0, 1],
            direct_query_count,
            TraceMaskQueryGeometry::BoundTreeLeafPair,
        );
        let required =
            producer.base_coordinate_count().unwrap() + consumer.base_coordinate_count().unwrap();

        assert_eq!(
            TraceMaskSurjectivityCertificate::derive(required - 1, &[producer, consumer]),
            Err(RelationPlanError::InvalidMaskGrammar)
        );
    }

    #[test]
    fn incompatible_extension_catalogs_refuse_composition() {
        let first = synthetic_catalog(3, &[0], 4, TraceMaskQueryGeometry::PhaseColumn);
        let mut second = synthetic_catalog(8, &[0], 4, TraceMaskQueryGeometry::PhaseColumn);
        second.challenge_extension_degree = 1;

        assert_eq!(
            TraceMaskSurjectivityCertificate::derive(1_000, &[first, second]),
            Err(RelationPlanError::InvalidMaskGrammar)
        );
    }

    fn synthetic_relation_mask_source(
        mask_kind: RelationMaskKind,
        mask_ordinal: u32,
        target_class: RelationMaskTargetClass,
        target_ordinal: u32,
    ) -> ConstructionMaskSourceIdentifier {
        ConstructionMaskSourceIdentifier::RelationMask {
            purpose_class: mask_kind as u16,
            mask_ordinal,
            target_class: target_class as u16,
            target_ordinal,
        }
    }

    fn synthetic_dependency(
        source: ConstructionMaskSourceIdentifier,
        coefficient: u64,
    ) -> ConstructionMaskDependency {
        ConstructionMaskDependency {
            source,
            coefficient,
        }
    }

    fn synthetic_construction_correspondence(
        modulus: u64,
    ) -> (
        ConstructionMaskingCorrespondence,
        BTreeSet<ConstructionSecretViewIdentifier>,
    ) {
        let base_trace_source = synthetic_relation_mask_source(
            RelationMaskKind::Trace,
            0,
            RelationMaskTargetClass::Column,
            0,
        );
        let auxiliary_trace_source = synthetic_relation_mask_source(
            RelationMaskKind::Trace,
            1,
            RelationMaskTargetClass::Column,
            1,
        );
        let telescoping_source = synthetic_relation_mask_source(
            RelationMaskKind::Telescoping,
            0,
            RelationMaskTargetClass::QuotientComponent,
            0,
        );
        let opening_batch_source = synthetic_relation_mask_source(
            RelationMaskKind::OpeningBatch,
            0,
            RelationMaskTargetClass::Batch,
            0,
        );
        let base_row_pad_source = ConstructionMaskSourceIdentifier::RowPad {
            phase: ConstructionMaskingPhase::Base,
        };
        let auxiliary_row_pad_source = ConstructionMaskSourceIdentifier::RowPad {
            phase: ConstructionMaskingPhase::Auxiliary,
        };
        let quotient_row_pad_source = ConstructionMaskSourceIdentifier::RowPad {
            phase: ConstructionMaskingPhase::Quotient,
        };
        let bound_source = ConstructionMaskSourceIdentifier::BoundColumn {
            relation_tree_ordinal: 2,
            column_ordinal: 2,
            root_use: BoundTreeRootUse::Input as u16,
        };
        let aggregate_wide_pad_source = ConstructionMaskSourceIdentifier::AggregateWidePad;
        let sources = [
            base_trace_source,
            auxiliary_trace_source,
            telescoping_source,
            opening_batch_source,
            base_row_pad_source,
            auxiliary_row_pad_source,
            quotient_row_pad_source,
            aggregate_wide_pad_source,
        ]
        .into_iter()
        .map(ConstructionMaskSourceDescriptor::current_attempt)
        .chain([ConstructionMaskSourceDescriptor::authenticated_persistent_object(bound_source)])
        .collect::<Vec<_>>();
        let trace_sources = BTreeSet::from([base_trace_source, auxiliary_trace_source]);
        let aggregate_inherited_sources = BTreeSet::from([
            base_trace_source,
            auxiliary_trace_source,
            telescoping_source,
            opening_batch_source,
            base_row_pad_source,
            quotient_row_pad_source,
        ]);
        let quotient_zero_dependencies = vec![
            synthetic_dependency(quotient_row_pad_source, 1),
            synthetic_dependency(telescoping_source, 1),
        ];
        let quotient_one_dependencies = vec![
            synthetic_dependency(quotient_row_pad_source, 1),
            synthetic_dependency(telescoping_source, modulus - 1),
        ];
        let views = vec![
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Phase { column_ordinal: 0 },
                algebra: ConstructionSecretViewAlgebra::Affine,
                direct_mask_dependencies: vec![
                    synthetic_dependency(base_trace_source, 1),
                    synthetic_dependency(base_row_pad_source, 1),
                ],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Auxiliary { column_ordinal: 1 },
                algebra: ConstructionSecretViewAlgebra::Nonlinear,
                direct_mask_dependencies: vec![
                    synthetic_dependency(auxiliary_trace_source, 1),
                    synthetic_dependency(auxiliary_row_pad_source, 1),
                ],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Quotient {
                    component_ordinal: 0,
                },
                algebra: ConstructionSecretViewAlgebra::Nonlinear,
                direct_mask_dependencies: quotient_zero_dependencies.clone(),
                inherited_mask_sources: trace_sources.clone(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Quotient {
                    component_ordinal: 1,
                },
                algebra: ConstructionSecretViewAlgebra::Nonlinear,
                direct_mask_dependencies: quotient_one_dependencies,
                inherited_mask_sources: trace_sources,
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Bound {
                    relation_tree_ordinal: 2,
                    column_ordinal: 2,
                },
                algebra: ConstructionSecretViewAlgebra::Affine,
                direct_mask_dependencies: vec![synthetic_dependency(bound_source, 1)],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Mask { mask_ordinal: 0 },
                algebra: ConstructionSecretViewAlgebra::IndependentMask,
                direct_mask_dependencies: vec![synthetic_dependency(opening_batch_source, 1)],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Aggregate {
                    opening_point_ordinal: 0,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: Vec::new(),
                inherited_mask_sources: aggregate_inherited_sources,
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Opening {
                    source_class: RelationOpeningSourceClass::TreeColumn as u16,
                    source_ordinal: 0,
                    column_ordinal: Some(0),
                    opening_point_ordinal: 0,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: vec![
                    synthetic_dependency(base_trace_source, 1),
                    synthetic_dependency(base_row_pad_source, 1),
                ],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Opening {
                    source_class: RelationOpeningSourceClass::Quotient as u16,
                    source_ordinal: 0,
                    column_ordinal: None,
                    opening_point_ordinal: 0,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: quotient_zero_dependencies,
                inherited_mask_sources: BTreeSet::from([base_trace_source, auxiliary_trace_source]),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Opening {
                    source_class: RelationOpeningSourceClass::BatchMask as u16,
                    source_ordinal: 0,
                    column_ordinal: None,
                    opening_point_ordinal: 0,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: vec![synthetic_dependency(opening_batch_source, 1)],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::FoldClosure,
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: vec![synthetic_dependency(aggregate_wide_pad_source, 1)],
                inherited_mask_sources: BTreeSet::new(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::ExplicitPoint,
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: vec![synthetic_dependency(aggregate_wide_pad_source, 1)],
                inherited_mask_sources: BTreeSet::new(),
            },
        ];
        let expected_view_identifiers = views.iter().map(|view| view.identifier).collect();
        (
            ConstructionMaskingCorrespondence {
                sources,
                views,
                rank_requirements: [ConstructionMaskingRankRequirement {
                    kind: ConstructionMaskingRankKind::RowPadEvaluation,
                    source_dimension: 8,
                    required_rank: 4,
                    verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
                }],
                opening_batch_mask_source: opening_batch_source,
                aggregate_wide_pad_source,
            },
            expected_view_identifiers,
        )
    }

    fn assert_synthetic_correspondence_refused(
        correspondence: &ConstructionMaskingCorrespondence,
        expected_view_identifiers: &BTreeSet<ConstructionSecretViewIdentifier>,
        modulus: u64,
    ) {
        assert_eq!(
            correspondence.validate_graph(expected_view_identifiers, 2, modulus),
            Err(RelationPlanError::InvalidMaskGrammar),
        );
    }

    #[test]
    fn construction_catalog_covers_every_secret_derived_view_class() {
        let modulus = 17;
        let (correspondence, expected_view_identifiers) =
            synthetic_construction_correspondence(modulus);

        correspondence
            .validate_graph(&expected_view_identifiers, 2, modulus)
            .expect("the complete construction view has a valid mask graph");
        for view_is_present in [
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Phase { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Auxiliary { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Quotient { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Bound { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Mask { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Aggregate { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Opening { .. }
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::FoldClosure
                )
            }),
            correspondence.views.iter().any(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::ExplicitPoint
                )
            }),
        ] {
            assert!(view_is_present);
        }
    }

    #[test]
    fn mask_graph_refuses_reused_omitted_and_uncovered_nonlinear_sources() {
        let modulus = 17;
        let (correspondence, expected_view_identifiers) =
            synthetic_construction_correspondence(modulus);
        let base_trace_source = correspondence
            .sources
            .iter()
            .map(|source| source.identifier)
            .find(|source| {
                matches!(
                    source,
                    ConstructionMaskSourceIdentifier::RelationMask {
                        purpose_class,
                        target_ordinal: 0,
                        ..
                    } if *purpose_class == RelationMaskKind::Trace as u16
                )
            })
            .expect("base trace source");

        let mut reused = correspondence.clone();
        let auxiliary = reused
            .views
            .iter_mut()
            .find(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Auxiliary { .. }
                )
            })
            .expect("auxiliary view");
        auxiliary.direct_mask_dependencies[0].source = base_trace_source;
        assert_synthetic_correspondence_refused(&reused, &expected_view_identifiers, modulus);

        let mut omitted = correspondence.clone();
        omitted
            .views
            .iter_mut()
            .find(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Bound { .. }
                )
            })
            .expect("bound view")
            .direct_mask_dependencies
            .clear();
        assert_synthetic_correspondence_refused(&omitted, &expected_view_identifiers, modulus);

        let mut nonlinear_uncovered = correspondence;
        let auxiliary = nonlinear_uncovered
            .views
            .iter_mut()
            .find(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Auxiliary { .. }
                )
            })
            .expect("auxiliary view");
        auxiliary
            .direct_mask_dependencies
            .retain(|dependency| !dependency.source.is_direct_relation_mask());
        assert_synthetic_correspondence_refused(
            &nonlinear_uncovered,
            &expected_view_identifiers,
            modulus,
        );
    }

    #[test]
    fn telescoping_and_opening_batch_correspondence_rejects_changed_edges() {
        let modulus = 17;
        let (correspondence, expected_view_identifiers) =
            synthetic_construction_correspondence(modulus);

        let mut correlated_telescoping = correspondence.clone();
        let final_quotient = correlated_telescoping
            .views
            .iter_mut()
            .find(|view| {
                view.identifier
                    == ConstructionSecretViewIdentifier::Quotient {
                        component_ordinal: 1,
                    }
            })
            .expect("final quotient view");
        let telescoping_dependency = final_quotient
            .direct_mask_dependencies
            .iter_mut()
            .find(|dependency| dependency.source.is_telescoping_mask())
            .expect("final telescoping dependency");
        telescoping_dependency.coefficient = 1;
        assert_synthetic_correspondence_refused(
            &correlated_telescoping,
            &expected_view_identifiers,
            modulus,
        );

        let mut changed_opening_batch = correspondence;
        let wrong_opening_source = synthetic_relation_mask_source(
            RelationMaskKind::OpeningBatch,
            1,
            RelationMaskTargetClass::Batch,
            0,
        );
        changed_opening_batch
            .sources
            .push(ConstructionMaskSourceDescriptor::current_attempt(
                wrong_opening_source,
            ));
        changed_opening_batch
            .views
            .iter_mut()
            .find(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Mask { .. }
                )
            })
            .expect("mask view")
            .direct_mask_dependencies[0]
            .source = wrong_opening_source;
        assert_synthetic_correspondence_refused(
            &changed_opening_batch,
            &expected_view_identifiers,
            modulus,
        );
    }

    #[test]
    fn aggregate_handoff_rejects_unfactored_claims_and_the_wrong_pad_source() {
        let modulus = 17;
        let (correspondence, expected_view_identifiers) =
            synthetic_construction_correspondence(modulus);

        let mut unfactored_aggregate = correspondence.clone();
        let opening_batch_mask_source = unfactored_aggregate.opening_batch_mask_source;
        unfactored_aggregate
            .views
            .iter_mut()
            .find(|view| {
                matches!(
                    view.identifier,
                    ConstructionSecretViewIdentifier::Aggregate { .. }
                )
            })
            .expect("aggregate view")
            .inherited_mask_sources
            .remove(&opening_batch_mask_source);
        assert_synthetic_correspondence_refused(
            &unfactored_aggregate,
            &expected_view_identifiers,
            modulus,
        );

        let mut wrong_fold_pad = correspondence.clone();
        let opening_batch_mask_source = wrong_fold_pad.opening_batch_mask_source;
        wrong_fold_pad
            .views
            .iter_mut()
            .find(|view| view.identifier == ConstructionSecretViewIdentifier::FoldClosure)
            .expect("fold-closure view")
            .direct_mask_dependencies[0]
            .source = opening_batch_mask_source;
        assert_synthetic_correspondence_refused(
            &wrong_fold_pad,
            &expected_view_identifiers,
            modulus,
        );

        let mut missing_pad_source = correspondence;
        let aggregate_wide_pad_source = missing_pad_source.aggregate_wide_pad_source;
        missing_pad_source
            .sources
            .retain(|source| source.identifier != aggregate_wide_pad_source);
        assert_synthetic_correspondence_refused(
            &missing_pad_source,
            &expected_view_identifiers,
            modulus,
        );
    }

    #[test]
    fn proof_coins_are_attempt_owned_and_excluded_from_checkpoint_and_telemetry() {
        let modulus = 17;
        let (correspondence, expected_view_identifiers) =
            synthetic_construction_correspondence(modulus);
        let current_attempt_source_index = correspondence
            .sources
            .iter()
            .position(|source| {
                source.authority == ConstructionMaskSourceAuthority::FreshAttemptCoins
            })
            .expect("current-attempt source");

        let mut persistent_lifetime = correspondence.clone();
        persistent_lifetime.sources[current_attempt_source_index].lifetime =
            ConstructionMaskSourceLifetime::PersistentObject;
        assert_synthetic_correspondence_refused(
            &persistent_lifetime,
            &expected_view_identifiers,
            modulus,
        );

        let mut changed_resume = correspondence.clone();
        changed_resume.sources[current_attempt_source_index].resume_rule =
            ConstructionMaskResumeRule::ImmutableAuthenticatedObject;
        assert_synthetic_correspondence_refused(
            &changed_resume,
            &expected_view_identifiers,
            modulus,
        );

        let mut checkpoint_leak = correspondence.clone();
        checkpoint_leak.sources[current_attempt_source_index].checkpoint_excludes_secret = false;
        assert_synthetic_correspondence_refused(
            &checkpoint_leak,
            &expected_view_identifiers,
            modulus,
        );

        let mut telemetry_leak = correspondence;
        telemetry_leak.sources[current_attempt_source_index].telemetry_excludes_secret = false;
        assert_synthetic_correspondence_refused(
            &telemetry_leak,
            &expected_view_identifiers,
            modulus,
        );
    }

    fn matrix_output(matrix: &[Vec<u64>], input: &[u64], modulus: u64) -> Vec<u64> {
        matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(input)
                    .fold(0_u64, |sum, (coefficient, value)| {
                        (sum + coefficient * value) % modulus
                    })
            })
            .collect()
    }

    fn enumerate_vectors(modulus: u64, coordinate_count: usize, mut consume: impl FnMut(&[u64])) {
        let vector_count = usize::try_from(modulus)
            .expect("small modulus fits usize")
            .pow(u32::try_from(coordinate_count).expect("small coordinate count fits u32"));
        for encoded_vector in 0..vector_count {
            let mut remaining = encoded_vector;
            let mut vector = vec![0_u64; coordinate_count];
            for coordinate in &mut vector {
                *coordinate = u64::try_from(
                    remaining % usize::try_from(modulus).expect("small modulus fits usize"),
                )
                .expect("small residue fits u64");
                remaining /= usize::try_from(modulus).expect("small modulus fits usize");
            }
            consume(&vector);
        }
    }

    fn exhaustive_linear_image_count(matrix: &[Vec<u64>], modulus: u64) -> usize {
        let mut image = BTreeSet::new();
        enumerate_vectors(modulus, matrix[0].len(), |input| {
            image.insert(matrix_output(matrix, input, modulus));
        });
        image.len()
    }

    #[test]
    fn modular_rank_matches_an_independent_exhaustive_small_field_oracle() {
        let modulus = 3_u64;
        enumerate_vectors(modulus, 4, |entries| {
            let matrix = vec![vec![entries[0], entries[1]], vec![entries[2], entries[3]]];
            let rank = construction_masking_matrix_rank(&matrix, modulus)
                .expect("the exhaustive matrix is canonical");
            assert_eq!(
                exhaustive_linear_image_count(&matrix, modulus),
                usize::try_from(modulus)
                    .expect("small modulus fits usize")
                    .pow(u32::try_from(rank).expect("matrix rank fits u32")),
            );
        });
    }

    #[test]
    fn row_pad_and_aggregate_maps_require_full_rank() {
        let modulus = 17;
        let row_pad_evaluation_matrix = [1_u64, 2, 4]
            .into_iter()
            .map(|point| {
                (0..4)
                    .map(|power| modular_power(point, power, modulus))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            construction_masking_matrix_rank(&row_pad_evaluation_matrix, modulus),
            Ok(3),
        );

        let aggregate_matrix = vec![vec![1, 0, 2, 4], vec![0, 1, 3, 5], vec![0, 0, 1, 6]];
        assert_eq!(
            construction_masking_matrix_rank(&aggregate_matrix, modulus),
            Ok(3),
        );

        let mut correlated_aggregate_matrix = aggregate_matrix;
        correlated_aggregate_matrix[2] = correlated_aggregate_matrix[1].clone();
        assert_eq!(
            construction_masking_matrix_rank(&correlated_aggregate_matrix, modulus),
            Ok(2),
        );
        let repeated_point_matrix = vec![
            row_pad_evaluation_matrix[0].clone(),
            row_pad_evaluation_matrix[1].clone(),
            row_pad_evaluation_matrix[1].clone(),
        ];
        assert_eq!(
            construction_masking_matrix_rank(&repeated_point_matrix, modulus),
            Ok(2),
        );
    }

    fn nonlinear_view_distribution(
        secret: u64,
        modulus: u64,
        correlated_pair: bool,
    ) -> BTreeMap<Vec<u64>, usize> {
        let mut distribution = BTreeMap::new();
        for first_mask in 0..modulus {
            let second_mask_range = if correlated_pair { 0..1 } else { 0..modulus };
            for second_mask_offset in second_mask_range {
                let second_mask = if correlated_pair {
                    first_mask
                } else {
                    second_mask_offset
                };
                let output = vec![
                    (secret + first_mask) % modulus,
                    (secret * secret + second_mask) % modulus,
                ];
                *distribution.entry(output).or_insert(0) += 1;
            }
        }
        distribution
    }

    #[test]
    fn exhaustive_nonlinear_oracle_detects_correlated_and_omitted_masks() {
        let modulus = 5;
        let independent_zero = nonlinear_view_distribution(0, modulus, false);
        let independent_three = nonlinear_view_distribution(3, modulus, false);
        assert_eq!(independent_zero, independent_three);

        let correlated_zero = nonlinear_view_distribution(0, modulus, true);
        let correlated_three = nonlinear_view_distribution(3, modulus, true);
        assert_ne!(correlated_zero, correlated_three);

        let omitted_zero = BTreeMap::from([(vec![0_u64], 1_usize)]);
        let omitted_three = BTreeMap::from([(vec![(3_u64 * 3) % modulus], 1_usize)]);
        assert_ne!(omitted_zero, omitted_three);
    }
}
