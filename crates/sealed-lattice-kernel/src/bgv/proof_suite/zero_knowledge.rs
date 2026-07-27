//! Construction-level masking correspondence for secret-bearing relations.
//!
//! These checks are part of suite generation. They derive a necessary
//! category-level catalog of verifier-visible construction views and their
//! mask-source dependencies from the checked relation plan. They are not the
//! exhaustive affine-coordinate partition, nonlinear simulator, family
//! zero-knowledge proof, or ceremony-composition argument. The construction
//! plan must refine this catalog to exact coordinates, and challenge-dependent
//! aggregate maps must satisfy the rank obligation recorded here before the
//! prover commits the aggregate.

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
enum ConstructionMaskingPhase {
    Base,
    Auxiliary,
    Quotient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ConstructionSecretViewIdentifier {
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
enum ConstructionSecretViewAlgebra {
    Affine,
    Nonlinear,
    IndependentMask,
    DerivedLinear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ConstructionMaskSourceIdentifier {
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
enum ConstructionMaskSourceAuthority {
    FreshAttemptCoins,
    AuthenticatedPersistentObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionMaskSourceLifetime {
    Attempt,
    PersistentObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionMaskResumeRule {
    PreserveAttemptIdentity,
    ImmutableAuthenticatedObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConstructionMaskSourceDescriptor {
    identifier: ConstructionMaskSourceIdentifier,
    authority: ConstructionMaskSourceAuthority,
    lifetime: ConstructionMaskSourceLifetime,
    resume_rule: ConstructionMaskResumeRule,
    checkpoint_excludes_secret: bool,
    telemetry_excludes_secret: bool,
}

impl ConstructionMaskSourceDescriptor {
    const fn current_attempt(identifier: ConstructionMaskSourceIdentifier) -> Self {
        Self {
            identifier,
            authority: ConstructionMaskSourceAuthority::FreshAttemptCoins,
            lifetime: ConstructionMaskSourceLifetime::Attempt,
            resume_rule: ConstructionMaskResumeRule::PreserveAttemptIdentity,
            checkpoint_excludes_secret: true,
            telemetry_excludes_secret: true,
        }
    }

    const fn authenticated_persistent_object(identifier: ConstructionMaskSourceIdentifier) -> Self {
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
struct ConstructionMaskDependency {
    source: ConstructionMaskSourceIdentifier,
    coefficient: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConstructionSecretViewDescriptor {
    identifier: ConstructionSecretViewIdentifier,
    algebra: ConstructionSecretViewAlgebra,
    direct_mask_dependencies: Vec<ConstructionMaskDependency>,
    inherited_mask_sources: BTreeSet<ConstructionMaskSourceIdentifier>,
}

impl ConstructionSecretViewDescriptor {
    fn all_mask_sources(&self) -> BTreeSet<ConstructionMaskSourceIdentifier> {
        self.direct_mask_dependencies
            .iter()
            .map(|dependency| dependency.source)
            .chain(self.inherited_mask_sources.iter().copied())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionMaskingRankKind {
    RowPadEvaluation,
    AggregateCoefficientMap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionMaskingRankVerification {
    DistinctPointVandermonde,
    SampledMatrixRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConstructionMaskingRankRequirement {
    kind: ConstructionMaskingRankKind,
    source_dimension: u64,
    required_rank: u64,
    verification: ConstructionMaskingRankVerification,
}

impl ConstructionMaskingRankRequirement {
    const fn validate_shape(self) -> Result<(), RelationPlanError> {
        if self.source_dimension == 0
            || self.required_rank == 0
            || self.source_dimension < self.required_rank
            || matches!(
                (self.kind, self.verification),
                (
                    ConstructionMaskingRankKind::RowPadEvaluation,
                    ConstructionMaskingRankVerification::SampledMatrixRequired,
                ) | (
                    ConstructionMaskingRankKind::AggregateCoefficientMap,
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
struct ConstructionMaskingCorrespondence {
    sources: Vec<ConstructionMaskSourceDescriptor>,
    views: Vec<ConstructionSecretViewDescriptor>,
    rank_requirements: [ConstructionMaskingRankRequirement; 2],
    opening_batch_mask_source: ConstructionMaskSourceIdentifier,
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
    let inverse_rate_factor = 1_usize
        .checked_shl(
            u32::try_from(parameters.row_code_log_inverse_rate)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        )
        .ok_or(RelationPlanError::CountOverflow)?;
    let row_encoding_expansion_factor = parameters
        .logical_polynomials_per_physical_row
        .checked_mul(2)
        .and_then(|factor| factor.checked_mul(inverse_rate_factor))
        .ok_or(RelationPlanError::CountOverflow)?;
    let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let logical_polynomial_coefficient_count = evaluation_domain_size
        .checked_div(row_encoding_expansion_factor)
        .filter(|coefficient_count| {
            *coefficient_count > 0
                && coefficient_count.is_power_of_two()
                && coefficient_count
                    .checked_mul(row_encoding_expansion_factor)
                    .is_some_and(|encoded_count| encoded_count == evaluation_domain_size)
        })
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    let row_pad_coefficient_count = logical_polynomial_coefficient_count
        .checked_mul(parameters.logical_polynomials_per_physical_row)
        .ok_or(RelationPlanError::CountOverflow)?;
    u64::try_from(row_pad_coefficient_count).map_err(|_| RelationPlanError::CountOverflow)
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
    ) -> Result<Self, RelationPlanError> {
        let phase_by_column = construction_phase_by_prover_column(variant)?;
        let parameters = RowCodeWhirSelectedParameters::selected();
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

        let aggregate_direct_dependencies = row_pad_sources
            .values()
            .copied()
            .map(|source| ConstructionMaskDependency {
                source,
                coefficient: one,
            })
            .collect::<Vec<_>>();
        let aggregate_inherited_sources = source_descriptors
            .keys()
            .copied()
            .filter(|source| !matches!(source, ConstructionMaskSourceIdentifier::RowPad { .. }))
            .collect::<BTreeSet<_>>();
        for opening_point_index in 0..variant.ordered_opening_points().len() {
            views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Aggregate {
                    opening_point_ordinal: u32::try_from(opening_point_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: aggregate_direct_dependencies.clone(),
                inherited_mask_sources: aggregate_inherited_sources.clone(),
            });
        }

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

        let aggregate_mask_sources = aggregate_direct_dependencies
            .iter()
            .map(|dependency| dependency.source)
            .chain(aggregate_inherited_sources.iter().copied())
            .collect::<BTreeSet<_>>();
        views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::FoldClosure,
            algebra: ConstructionSecretViewAlgebra::DerivedLinear,
            direct_mask_dependencies: Vec::new(),
            inherited_mask_sources: aggregate_mask_sources.clone(),
        });
        views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::ExplicitPoint,
            algebra: ConstructionSecretViewAlgebra::DerivedLinear,
            direct_mask_dependencies: Vec::new(),
            inherited_mask_sources: aggregate_mask_sources,
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

        let physical_row_packing = u64::try_from(parameters.logical_polynomials_per_physical_row)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let phase_row_source_dimension = [
            ConstructionMaskingPhase::Base,
            ConstructionMaskingPhase::Auxiliary,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, phase| {
            let column_count = u64::try_from(
                phase_by_column
                    .values()
                    .filter(|candidate| **candidate == phase)
                    .count(),
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
            let row_count = column_count
                .checked_add(physical_row_packing - 1)
                .ok_or(RelationPlanError::CountOverflow)?
                / physical_row_packing;
            sum.checked_add(row_count)
                .ok_or(RelationPlanError::CountOverflow)
        })?;
        let quotient_group_count = u64::from(context.quotient_component_count)
            .checked_add(physical_row_packing - 1)
            .ok_or(RelationPlanError::CountOverflow)?
            / physical_row_packing;
        let quotient_row_source_dimension = quotient_group_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(u64::from(context.challenge_extension_degree)))
            .ok_or(RelationPlanError::CountOverflow)?;
        let aggregate_source_dimension = phase_row_source_dimension
            .checked_add(quotient_row_source_dimension)
            .ok_or(RelationPlanError::CountOverflow)?;
        let aggregate_required_rank = u64::try_from(variant.ordered_opening_points().len())
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_mul(u64::from(context.challenge_extension_degree))
            .ok_or(RelationPlanError::CountOverflow)?;

        Ok(Self {
            sources: source_descriptors.into_values().collect(),
            views,
            rank_requirements: [
                ConstructionMaskingRankRequirement {
                    kind: ConstructionMaskingRankKind::RowPadEvaluation,
                    source_dimension: row_pad_source_dimension,
                    required_rank: row_pad_required_rank,
                    verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
                },
                ConstructionMaskingRankRequirement {
                    kind: ConstructionMaskingRankKind::AggregateCoefficientMap,
                    source_dimension: aggregate_source_dimension,
                    required_rank: aggregate_required_rank,
                    verification: ConstructionMaskingRankVerification::SampledMatrixRequired,
                },
            ],
            opening_batch_mask_source,
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
                ConstructionSecretViewIdentifier::Aggregate { .. }
                | ConstructionSecretViewIdentifier::FoldClosure
                | ConstructionSecretViewIdentifier::ExplicitPoint => {
                    if !view
                        .all_mask_sources()
                        .contains(&self.opening_batch_mask_source)
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

/// Checks the construction-level masking correspondence required by the
/// common proof grammar. All views, sources, and dimensions come from the
/// checked relation plan and field schedule.
///
/// Telescoping and opening-batch masks have extension-field coefficients, so
/// their image argument is the ordinary Vandermonde argument over distinct
/// visible points. The dependency graph additionally covers nonlinear
/// auxiliary and quotient views, bound material, the aggregate, every opening,
/// the WHIR fold closure, and the explicit-point opening. This does not claim
/// family zero knowledge or cross-proof composition.
pub(crate) fn validate_zero_knowledge_mask_image(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(());
    }

    let construction_correspondence = ConstructionMaskingCorrespondence::derive(variant, context)?;

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
        TraceMaskSurjectivityCertificate::derive(actual_trace_mask_degree, &[catalog])?;
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
    let expected_view_identifiers = construction_correspondence
        .views
        .iter()
        .map(|view| view.identifier)
        .collect::<BTreeSet<_>>();
    construction_correspondence.validate_graph(
        &expected_view_identifiers,
        context.quotient_component_count,
        context.base_field_modulus,
    )
}

#[cfg(test)]
mod tests {
    use super::super::relation_plan::BoundTreeRootUse;
    use super::super::{
        compile_same_secret_relation_plan, selected_relation_plan_check_context,
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
            u32::try_from(parameters.verified_vss_bound_query_count)
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
        let prior_vss_query_count = u32::try_from(parameters.verified_vss_bound_query_count)
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
        let sources = [
            base_trace_source,
            auxiliary_trace_source,
            telescoping_source,
            opening_batch_source,
            base_row_pad_source,
            auxiliary_row_pad_source,
            quotient_row_pad_source,
        ]
        .into_iter()
        .map(ConstructionMaskSourceDescriptor::current_attempt)
        .chain([ConstructionMaskSourceDescriptor::authenticated_persistent_object(bound_source)])
        .collect::<Vec<_>>();
        let trace_sources = BTreeSet::from([base_trace_source, auxiliary_trace_source]);
        let aggregate_direct_dependencies = vec![
            synthetic_dependency(base_row_pad_source, 1),
            synthetic_dependency(auxiliary_row_pad_source, 1),
            synthetic_dependency(quotient_row_pad_source, 1),
        ];
        let aggregate_inherited_sources = BTreeSet::from([
            base_trace_source,
            auxiliary_trace_source,
            telescoping_source,
            opening_batch_source,
            bound_source,
        ]);
        let aggregate_mask_sources = aggregate_direct_dependencies
            .iter()
            .map(|dependency| dependency.source)
            .chain(aggregate_inherited_sources.iter().copied())
            .collect::<BTreeSet<_>>();
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
                direct_mask_dependencies: aggregate_direct_dependencies,
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
                direct_mask_dependencies: Vec::new(),
                inherited_mask_sources: aggregate_mask_sources.clone(),
            },
            ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::ExplicitPoint,
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: Vec::new(),
                inherited_mask_sources: aggregate_mask_sources,
            },
        ];
        let expected_view_identifiers = views.iter().map(|view| view.identifier).collect();
        (
            ConstructionMaskingCorrespondence {
                sources,
                views,
                rank_requirements: [
                    ConstructionMaskingRankRequirement {
                        kind: ConstructionMaskingRankKind::RowPadEvaluation,
                        source_dimension: 8,
                        required_rank: 4,
                        verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
                    },
                    ConstructionMaskingRankRequirement {
                        kind: ConstructionMaskingRankKind::AggregateCoefficientMap,
                        source_dimension: 4,
                        required_rank: 1,
                        verification: ConstructionMaskingRankVerification::SampledMatrixRequired,
                    },
                ],
                opening_batch_mask_source: opening_batch_source,
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
