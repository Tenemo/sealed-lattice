//! Checked production source geometry for every selected row-code relation.
//!
//! This module deliberately exposes no decoder or serialization surface. The
//! manifest is derived only from the checked relation and construction owners,
//! then retained as an opaque generation capability. Proof bytes never carry
//! the source, reversal, or persistent-salt census.

use std::collections::BTreeSet;

use crate::hashing::StreamingHash512;

use super::super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
    prover::{
        CommonProofProverError, authenticated_pre_challenge_source_coefficient_position_counts,
        persisted_pre_challenge_column_coefficient_position_counts,
        relation_reversed_column_bindings, requested_pre_challenge_source_column_ordinals,
    },
    relation_plan::{
        BoundTreeConstructionKind, BoundTreeRootUse, RelationColumnDescriptor,
        RelationColumnOrigin, RelationColumnValueType, RelationPlanCheckContext, RelationPlanError,
        RelationPlanVariant, RelationTreeDescriptor, SuiteModulusReference,
    },
    selected_profile::selected_relation_plan_check_context,
};
use super::construction_plan::{
    RowCodeWhirBoundLowDegreeMode, RowCodeWhirConstructionPlan, RowCodeWhirConstructionPlanError,
};

const SAME_SECRET_AUTHENTICATED_SOURCE_MANIFEST_HASH_DOMAIN: &str =
    "sealed-lattice/proof/authenticated-source-manifest/v3";
const SAME_SECRET_AUTHENTICATED_SOURCE_MANIFEST_VERSION: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum SameSecretAuthenticatedSourceManifestError {
    WrongSelectedContext,
    ConstructionPlanMismatch,
    RelationVariantMismatch,
    SourceCatalogMismatch,
    ReversedColumnCatalogMismatch,
    BoundMaterialCatalogMismatch,
    SourceOrderMismatch,
    SourceDescriptorMismatch,
    ReversedColumnOrderMismatch,
    BoundMaterialCoordinateMismatch,
    CountOverflow,
}

impl From<RowCodeWhirConstructionPlanError> for SameSecretAuthenticatedSourceManifestError {
    fn from(_: RowCodeWhirConstructionPlanError) -> Self {
        Self::ConstructionPlanMismatch
    }
}

impl From<RelationPlanError> for SameSecretAuthenticatedSourceManifestError {
    fn from(_: RelationPlanError) -> Self {
        Self::RelationVariantMismatch
    }
}

impl From<CommonProofProverError> for SameSecretAuthenticatedSourceManifestError {
    fn from(_: CommonProofProverError) -> Self {
        Self::SourceCatalogMismatch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SameSecretAuthenticatedSourceRecipeBinding {
    VerifierSequence {
        verifier_source_ordinal: u32,
        first_logical_element_index: u64,
        logical_element_stride: u64,
    },
    BoundTree {
        expected_root_source_ordinal: u32,
    },
    Prover,
}

impl SameSecretAuthenticatedSourceRecipeBinding {
    fn from_origin(origin: &RelationColumnOrigin) -> Self {
        match origin {
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } => Self::VerifierSequence {
                verifier_source_ordinal: *verifier_source_ordinal,
                first_logical_element_index: *first_logical_element_index,
                logical_element_stride: *logical_element_stride,
            },
            RelationColumnOrigin::BoundTree {
                expected_root_source_ordinal,
            } => Self::BoundTree {
                expected_root_source_ordinal: *expected_root_source_ordinal,
            },
            RelationColumnOrigin::Prover => Self::Prover,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SameSecretAuthenticatedSourceDescriptor {
    column_ordinal: u32,
    value_type: RelationColumnValueType,
    raw_coefficient_position_count: u64,
    persisted_coefficient_position_count: u64,
    canonical_residue_modulus: Option<SuiteModulusReference>,
    recipe_binding: SameSecretAuthenticatedSourceRecipeBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SameSecretReversedColumnBinding {
    source_column_ordinal: u32,
    reversed_column_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SameSecretBoundMaterialSaltTreeDescriptor {
    relation_tree_ordinal: u32,
    bound_tree_ordinal: u32,
    expected_root_source_ordinal: u32,
    root_use: BoundTreeRootUse,
    source_trace_domain_size: u64,
    evaluation_domain_size: u64,
    leaf_count: u64,
    low_degree_mode: RowCodeWhirBoundLowDegreeMode,
    encoded_query_salt_count: u64,
    ordered_column_ordinals: Box<[u32]>,
}

/// Opaque, non-serializable authority for the exact production source flow.
///
/// Construction is private to the proof suite. All headline counts are
/// methods over the derived catalogs rather than independently accepted or
/// proof-carried fields.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct SameSecretAuthenticatedSourceManifest {
    construction_identity: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    catalog_hash: [u8; 64],
    authenticated_sources: Box<[SameSecretAuthenticatedSourceDescriptor]>,
    reversed_column_bindings: Box<[SameSecretReversedColumnBinding]>,
    bound_material_salt_trees: Box<[SameSecretBoundMaterialSaltTreeDescriptor]>,
}

impl SameSecretAuthenticatedSourceManifest {
    pub(in crate::bgv::proof_suite) fn resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        fn slice_byte_length<T>(
            length: usize,
        ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
            u64::try_from(length)
                .ok()
                .and_then(|count| {
                    u64::try_from(core::mem::size_of::<T>())
                        .ok()
                        .and_then(|element_byte_length| count.checked_mul(element_byte_length))
                })
                .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)
        }

        let mut total = slice_byte_length::<SameSecretAuthenticatedSourceDescriptor>(
            self.authenticated_sources.len(),
        )?
        .checked_add(slice_byte_length::<SameSecretReversedColumnBinding>(
            self.reversed_column_bindings.len(),
        )?)
        .and_then(|total| {
            slice_byte_length::<SameSecretBoundMaterialSaltTreeDescriptor>(
                self.bound_material_salt_trees.len(),
            )
            .ok()
            .and_then(|byte_length| total.checked_add(byte_length))
        })
        .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)?;
        for tree in &self.bound_material_salt_trees {
            total = total
                .checked_add(slice_byte_length::<u32>(
                    tree.ordered_column_ordinals.len(),
                )?)
                .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)?;
        }
        Ok(total)
    }

    pub(in crate::bgv::proof_suite) fn derive(
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
    ) -> Result<Self, SameSecretAuthenticatedSourceManifestError> {
        validate_selected_owners(construction_plan, relation_variant, relation_context)?;
        let construction_identity = construction_plan.canonical_identity_hash()?;
        let relation_plan_variant_hash = relation_variant.canonical_hash()?;
        let authenticated_sources =
            derive_authenticated_source_catalog(construction_plan, relation_variant)?;
        let reversed_column_bindings =
            derive_reversed_column_catalog(relation_variant, &authenticated_sources)?;
        let bound_material_salt_trees =
            derive_bound_material_salt_catalog(construction_plan, relation_variant)?;
        let catalog_hash = source_manifest_catalog_hash(
            construction_identity,
            relation_plan_variant_hash,
            &authenticated_sources,
            &reversed_column_bindings,
            &bound_material_salt_trees,
        )?;
        Ok(Self {
            construction_identity,
            relation_plan_variant_hash,
            catalog_hash,
            authenticated_sources: authenticated_sources.into_boxed_slice(),
            reversed_column_bindings: reversed_column_bindings.into_boxed_slice(),
            bound_material_salt_trees: bound_material_salt_trees.into_boxed_slice(),
        })
    }

    pub(in crate::bgv::proof_suite) fn validate_against(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
        relation_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        let derived = Self::derive(construction_plan, relation_variant, relation_context)?;
        if self.construction_identity != derived.construction_identity
            || self.relation_plan_variant_hash != derived.relation_plan_variant_hash
        {
            return Err(SameSecretAuthenticatedSourceManifestError::ConstructionPlanMismatch);
        }
        if self.authenticated_sources != derived.authenticated_sources {
            return Err(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch);
        }
        if self.reversed_column_bindings != derived.reversed_column_bindings {
            return Err(SameSecretAuthenticatedSourceManifestError::ReversedColumnCatalogMismatch);
        }
        if self.bound_material_salt_trees != derived.bound_material_salt_trees {
            return Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch);
        }
        if self.catalog_hash != derived.catalog_hash {
            return Err(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) const fn construction_identity(&self) -> [u8; 64] {
        self.construction_identity
    }

    pub(in crate::bgv::proof_suite) const fn catalog_hash(&self) -> [u8; 64] {
        self.catalog_hash
    }

    pub(in crate::bgv::proof_suite) fn authenticated_source_polynomial_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_len(self.authenticated_sources.len())
    }

    pub(in crate::bgv::proof_suite) fn raw_authenticated_source_coefficient_position_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        self.authenticated_sources
            .iter()
            .try_fold(0_u64, |total, source| {
                checked_add(total, source.raw_coefficient_position_count)
            })
    }

    pub(in crate::bgv::proof_suite) fn persisted_pre_challenge_source_coefficient_position_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        self.authenticated_sources
            .iter()
            .try_fold(0_u64, |total, source| {
                checked_add(total, source.persisted_coefficient_position_count)
            })
    }

    pub(in crate::bgv::proof_suite) fn deterministic_reversed_column_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_len(self.reversed_column_bindings.len())
    }

    pub(in crate::bgv::proof_suite) fn stored_pre_challenge_column_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_add(
            self.authenticated_source_polynomial_count()?,
            self.deterministic_reversed_column_count()?,
        )
    }

    pub(in crate::bgv::proof_suite) fn bound_material_tree_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_len(self.bound_material_salt_trees.len())
    }

    pub(in crate::bgv::proof_suite) fn logical_bound_material_leaf_salt_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        self.bound_material_salt_trees
            .iter()
            .try_fold(0_u64, |total, tree| checked_add(total, tree.leaf_count))
    }

    pub(in crate::bgv::proof_suite) fn logical_bound_material_leaf_salt_byte_length(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_multiply(
            self.logical_bound_material_leaf_salt_count()?,
            checked_len(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)?,
        )
    }

    pub(in crate::bgv::proof_suite) fn encoded_queried_bound_material_leaf_salt_count(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        self.bound_material_salt_trees
            .iter()
            .try_fold(0_u64, |total, tree| {
                checked_add(total, tree.encoded_query_salt_count)
            })
    }

    pub(in crate::bgv::proof_suite) fn encoded_queried_bound_material_leaf_salt_byte_length(
        &self,
    ) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
        checked_multiply(
            self.encoded_queried_bound_material_leaf_salt_count()?,
            checked_len(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)?,
        )
    }

    pub(in crate::bgv::proof_suite) fn begin_validation(
        &self,
    ) -> SameSecretAuthenticatedSourceManifestValidationCursor<'_> {
        SameSecretAuthenticatedSourceManifestValidationCursor {
            manifest: self,
            next_source_index: 0,
            next_reversed_column_index: 0,
        }
    }

    pub(in crate::bgv::proof_suite) fn validate_authenticated_source_at(
        &self,
        source_index: usize,
        column_ordinal: u32,
        descriptor: &RelationColumnDescriptor,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        let expected = self
            .authenticated_sources
            .get(source_index)
            .ok_or(SameSecretAuthenticatedSourceManifestError::SourceOrderMismatch)?;
        let observed = authenticated_source_descriptor(
            column_ordinal,
            descriptor,
            expected.raw_coefficient_position_count,
            expected.persisted_coefficient_position_count,
        )?;
        if expected != &observed {
            return Err(SameSecretAuthenticatedSourceManifestError::SourceDescriptorMismatch);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn validate_reversed_column_at(
        &self,
        reversed_column_index: usize,
        source_column_ordinal: u32,
        reversed_column_ordinal: u32,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        let expected = self
            .reversed_column_bindings
            .get(reversed_column_index)
            .ok_or(SameSecretAuthenticatedSourceManifestError::ReversedColumnOrderMismatch)?;
        if expected.source_column_ordinal != source_column_ordinal
            || expected.reversed_column_ordinal != reversed_column_ordinal
        {
            return Err(SameSecretAuthenticatedSourceManifestError::ReversedColumnOrderMismatch);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn validate_bound_material_leaf_salt_coordinate(
        &self,
        relation_tree_ordinal: u32,
        expected_root_source_ordinal: u32,
        root_use: BoundTreeRootUse,
        leaf_index: u64,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        // Root bytes remain owned by the canonical application object. The
        // manifest binds their statement source ordinal; the authenticated
        // source provider separately compares every request's root bytes.
        let tree = self
            .bound_material_salt_trees
            .iter()
            .find(|tree| tree.relation_tree_ordinal == relation_tree_ordinal)
            .ok_or(SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch)?;
        if tree.expected_root_source_ordinal != expected_root_source_ordinal
            || tree.root_use != root_use
            || leaf_index >= tree.leaf_count
        {
            return Err(
                SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch,
            );
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn validate_encoded_bound_material_query_coordinate(
        &self,
        relation_tree_ordinal: u32,
        query_ordinal: u64,
        leaf_index: u64,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        let tree = self
            .bound_material_salt_trees
            .iter()
            .find(|tree| tree.relation_tree_ordinal == relation_tree_ordinal)
            .ok_or(SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch)?;
        if query_ordinal >= tree.encoded_query_salt_count || leaf_index >= tree.leaf_count {
            return Err(
                SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch,
            );
        }
        Ok(())
    }
}

/// Single-use order validator for the source and deterministic-reversal flow.
pub(in crate::bgv::proof_suite) struct SameSecretAuthenticatedSourceManifestValidationCursor<'a> {
    manifest: &'a SameSecretAuthenticatedSourceManifest,
    next_source_index: usize,
    next_reversed_column_index: usize,
}

impl SameSecretAuthenticatedSourceManifestValidationCursor<'_> {
    pub(in crate::bgv::proof_suite) fn validate_next_authenticated_source(
        &mut self,
        column_ordinal: u32,
        descriptor: &RelationColumnDescriptor,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        self.manifest.validate_authenticated_source_at(
            self.next_source_index,
            column_ordinal,
            descriptor,
        )?;
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)?;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn validate_next_reversed_column(
        &mut self,
        source_column_ordinal: u32,
        reversed_column_ordinal: u32,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        if self.next_source_index != self.manifest.authenticated_sources.len() {
            return Err(SameSecretAuthenticatedSourceManifestError::SourceOrderMismatch);
        }
        self.manifest.validate_reversed_column_at(
            self.next_reversed_column_index,
            source_column_ordinal,
            reversed_column_ordinal,
        )?;
        self.next_reversed_column_index = self
            .next_reversed_column_index
            .checked_add(1)
            .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)?;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn finish(
        self,
    ) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
        if self.next_source_index != self.manifest.authenticated_sources.len() {
            return Err(SameSecretAuthenticatedSourceManifestError::SourceOrderMismatch);
        }
        if self.next_reversed_column_index != self.manifest.reversed_column_bindings.len() {
            return Err(SameSecretAuthenticatedSourceManifestError::ReversedColumnOrderMismatch);
        }
        Ok(())
    }
}

fn validate_selected_owners(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<(), SameSecretAuthenticatedSourceManifestError> {
    let schema_identifier = construction_plan.application_statement_schema_identifier();
    let selected_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or(SameSecretAuthenticatedSourceManifestError::WrongSelectedContext)?;
    if relation_context != &selected_context {
        return Err(SameSecretAuthenticatedSourceManifestError::WrongSelectedContext);
    }
    let relation_variant_hash = relation_variant.canonical_hash()?;
    if construction_plan.relation_plan_variant_hash() != relation_variant_hash
        || construction_plan.schedule_position != relation_variant.schedule_position()
        || construction_plan.top_count != relation_variant.top_count()
        || construction_plan.trace_domain_size != relation_variant.trace_domain_size()
        || construction_plan.evaluation_domain_size != relation_variant.evaluation_domain_size()
        || construction_plan.opening_degree_bound_exclusive
            != relation_variant.opening_degree_bound_exclusive()
        || construction_plan.proof_privacy_mode != relation_variant.proof_privacy_mode()
    {
        return Err(SameSecretAuthenticatedSourceManifestError::RelationVariantMismatch);
    }
    Ok(())
}

fn authenticated_source_descriptor(
    column_ordinal: u32,
    descriptor: &RelationColumnDescriptor,
    raw_coefficient_position_count: u64,
    persisted_coefficient_position_count: u64,
) -> Result<SameSecretAuthenticatedSourceDescriptor, SameSecretAuthenticatedSourceManifestError> {
    if raw_coefficient_position_count == 0
        || raw_coefficient_position_count > persisted_coefficient_position_count
        || persisted_coefficient_position_count > descriptor.source_degree_bound_exclusive()
    {
        return Err(SameSecretAuthenticatedSourceManifestError::SourceDescriptorMismatch);
    }
    Ok(SameSecretAuthenticatedSourceDescriptor {
        column_ordinal,
        value_type: descriptor.value_type(),
        raw_coefficient_position_count,
        persisted_coefficient_position_count,
        canonical_residue_modulus: descriptor.canonical_residue_modulus(),
        recipe_binding: SameSecretAuthenticatedSourceRecipeBinding::from_origin(
            descriptor.origin(),
        ),
    })
}

fn derive_authenticated_source_catalog(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<Vec<SameSecretAuthenticatedSourceDescriptor>, SameSecretAuthenticatedSourceManifestError>
{
    let ordered_source_column_ordinals =
        requested_pre_challenge_source_column_ordinals(relation_variant)?;
    let raw_coefficient_position_counts =
        authenticated_pre_challenge_source_coefficient_position_counts(relation_variant)?;
    let persisted_coefficient_position_counts =
        persisted_pre_challenge_column_coefficient_position_counts(relation_variant)?;
    if ordered_source_column_ordinals != construction_plan.requested_source_column_ordinals
        || raw_coefficient_position_counts.len() != ordered_source_column_ordinals.len()
        || persisted_coefficient_position_counts.len() != ordered_source_column_ordinals.len()
        || ordered_source_column_ordinals
            .windows(2)
            .any(|window| window[0] >= window[1])
    {
        return Err(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch);
    }
    ordered_source_column_ordinals
        .into_iter()
        .map(|column_ordinal| {
            let descriptor = relation_variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
                )
                .ok_or(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch)?;
            let raw_coefficient_position_count = raw_coefficient_position_counts
                .get(&column_ordinal)
                .copied()
                .ok_or(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch)?;
            let persisted_coefficient_position_count = persisted_coefficient_position_counts
                .get(&column_ordinal)
                .copied()
                .ok_or(SameSecretAuthenticatedSourceManifestError::SourceCatalogMismatch)?;
            authenticated_source_descriptor(
                column_ordinal,
                descriptor,
                raw_coefficient_position_count,
                persisted_coefficient_position_count,
            )
        })
        .collect()
}

fn derive_reversed_column_catalog(
    relation_variant: &RelationPlanVariant,
    authenticated_sources: &[SameSecretAuthenticatedSourceDescriptor],
) -> Result<Vec<SameSecretReversedColumnBinding>, SameSecretAuthenticatedSourceManifestError> {
    let authenticated_source_ordinals = authenticated_sources
        .iter()
        .map(|source| source.column_ordinal)
        .collect::<BTreeSet<_>>();
    let mut reversed_column_ordinals = BTreeSet::new();
    let bindings = relation_reversed_column_bindings(relation_variant)?;
    let mut output = Vec::with_capacity(bindings.len());
    for (source_column_ordinal, reversed_column_ordinal) in bindings {
        if !authenticated_source_ordinals.contains(&source_column_ordinal)
            || authenticated_source_ordinals.contains(&reversed_column_ordinal)
            || !reversed_column_ordinals.insert(reversed_column_ordinal)
        {
            return Err(SameSecretAuthenticatedSourceManifestError::ReversedColumnCatalogMismatch);
        }
        let source_descriptor = relation_variant
            .ordered_columns()
            .get(
                usize::try_from(source_column_ordinal)
                    .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
            )
            .ok_or(SameSecretAuthenticatedSourceManifestError::ReversedColumnCatalogMismatch)?;
        let reversed_descriptor = relation_variant
            .ordered_columns()
            .get(
                usize::try_from(reversed_column_ordinal)
                    .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
            )
            .ok_or(SameSecretAuthenticatedSourceManifestError::ReversedColumnCatalogMismatch)?;
        if source_descriptor.value_type() != RelationColumnValueType::BaseField
            || reversed_descriptor.value_type() != RelationColumnValueType::BaseField
            || !matches!(reversed_descriptor.origin(), RelationColumnOrigin::Prover)
        {
            return Err(SameSecretAuthenticatedSourceManifestError::ReversedColumnCatalogMismatch);
        }
        output.push(SameSecretReversedColumnBinding {
            source_column_ordinal,
            reversed_column_ordinal,
        });
    }
    Ok(output)
}

fn derive_bound_material_salt_catalog(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<
    Vec<SameSecretBoundMaterialSaltTreeDescriptor>,
    SameSecretAuthenticatedSourceManifestError,
> {
    let mut output = Vec::new();
    for tree in &construction_plan.bound_trees {
        if tree.construction_kind != BoundTreeConstructionKind::CommittedMaterial {
            continue;
        }
        let expected_query_count = match tree.low_degree_mode {
            RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
            | RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired => {
                construction_plan.parameters.prior_proof_bound_query_count
            }
            RowCodeWhirBoundLowDegreeMode::Direct => {
                construction_plan.parameters.direct_bound_query_count
            }
        };
        if tree.query_count != expected_query_count
            || tree.query_count == 0
            || tree.leaf_count == 0
            || !tree.leaf_count.is_power_of_two()
            || tree.query_count > tree.leaf_count
            || tree.evaluation_domain_size != construction_plan.evaluation_domain_size
            || tree.source_trace_domain_size == 0
        {
            return Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch);
        }
        let relation_tree = relation_variant
            .ordered_trees()
            .get(
                usize::try_from(tree.relation_tree_ordinal)
                    .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
            )
            .ok_or(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch)?;
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } = relation_tree
        else {
            return Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch);
        };
        if *construction_kind != tree.construction_kind
            || *expected_root_source_ordinal != tree.expected_root_source_ordinal
            || *root_use != tree.root_use
            || ordered_column_ordinals.len() != tree.ordered_columns.len()
        {
            return Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch);
        }
        for (column_ordinal, planned_column) in
            ordered_column_ordinals.iter().zip(&tree.ordered_columns)
        {
            let relation_column = relation_variant
                .ordered_columns()
                .get(
                    usize::try_from(*column_ordinal)
                        .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
                )
                .ok_or(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch)?;
            if planned_column.column_ordinal != *column_ordinal
                || planned_column.value_type != relation_column.value_type()
                || planned_column.source_degree_bound_exclusive
                    != relation_column.source_degree_bound_exclusive()
                || !matches!(
                    relation_column.origin(),
                    RelationColumnOrigin::BoundTree {
                        expected_root_source_ordinal: column_root_source_ordinal,
                    } if *column_root_source_ordinal == tree.expected_root_source_ordinal
                )
            {
                return Err(
                    SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch,
                );
            }
        }
        output.push(SameSecretBoundMaterialSaltTreeDescriptor {
            relation_tree_ordinal: tree.relation_tree_ordinal,
            bound_tree_ordinal: tree.bound_tree_ordinal,
            expected_root_source_ordinal: tree.expected_root_source_ordinal,
            root_use: tree.root_use,
            source_trace_domain_size: tree.source_trace_domain_size,
            evaluation_domain_size: tree.evaluation_domain_size,
            leaf_count: u64::try_from(tree.leaf_count)
                .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
            low_degree_mode: tree.low_degree_mode,
            encoded_query_salt_count: u64::try_from(tree.query_count)
                .map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)?,
            ordered_column_ordinals: ordered_column_ordinals.to_vec().into_boxed_slice(),
        });
    }
    if output
        .windows(2)
        .any(|window| window[0].bound_tree_ordinal >= window[1].bound_tree_ordinal)
    {
        return Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCatalogMismatch);
    }
    Ok(output)
}

fn source_manifest_catalog_hash(
    construction_identity: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    authenticated_sources: &[SameSecretAuthenticatedSourceDescriptor],
    reversed_column_bindings: &[SameSecretReversedColumnBinding],
    bound_material_salt_trees: &[SameSecretBoundMaterialSaltTreeDescriptor],
) -> Result<[u8; 64], SameSecretAuthenticatedSourceManifestError> {
    let catalog_part_count = checked_add(
        checked_add(
            checked_add(3, checked_len(authenticated_sources.len())?)?,
            checked_len(reversed_column_bindings.len())?,
        )?,
        checked_len(bound_material_salt_trees.len())?,
    )?;
    let mut hasher = StreamingHash512::new(
        SAME_SECRET_AUTHENTICATED_SOURCE_MANIFEST_HASH_DOMAIN,
        catalog_part_count,
    );
    let mut header = Vec::with_capacity(2 + 8 * 4);
    header.extend_from_slice(&SAME_SECRET_AUTHENTICATED_SOURCE_MANIFEST_VERSION.to_le_bytes());
    header.extend_from_slice(&checked_len(authenticated_sources.len())?.to_le_bytes());
    header.extend_from_slice(&checked_len(reversed_column_bindings.len())?.to_le_bytes());
    header.extend_from_slice(&checked_len(bound_material_salt_trees.len())?.to_le_bytes());
    header
        .extend_from_slice(&checked_len(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)?.to_le_bytes());
    hasher.absorb_part(&header);
    hasher.absorb_part(&construction_identity);
    hasher.absorb_part(&relation_plan_variant_hash);
    for source in authenticated_sources {
        hasher.absorb_part(&encode_authenticated_source_descriptor(source));
    }
    for binding in reversed_column_bindings {
        let mut encoded = [0_u8; 8];
        encoded[..4].copy_from_slice(&binding.source_column_ordinal.to_le_bytes());
        encoded[4..].copy_from_slice(&binding.reversed_column_ordinal.to_le_bytes());
        hasher.absorb_part(&encoded);
    }
    for tree in bound_material_salt_trees {
        hasher.absorb_part(&encode_bound_material_salt_tree(tree)?);
    }
    Ok(hasher.finalize())
}

fn encode_authenticated_source_descriptor(
    source: &SameSecretAuthenticatedSourceDescriptor,
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(&source.column_ordinal.to_le_bytes());
    encoded.extend_from_slice(&(source.value_type as u16).to_le_bytes());
    encoded.extend_from_slice(&source.raw_coefficient_position_count.to_le_bytes());
    encoded.extend_from_slice(&source.persisted_coefficient_position_count.to_le_bytes());
    encoded.push(u8::from(source.canonical_residue_modulus.is_some()));
    match source.recipe_binding {
        SameSecretAuthenticatedSourceRecipeBinding::VerifierSequence {
            verifier_source_ordinal,
            first_logical_element_index,
            logical_element_stride,
        } => {
            encoded.extend_from_slice(&1_u16.to_le_bytes());
            encoded.extend_from_slice(&verifier_source_ordinal.to_le_bytes());
            encoded.extend_from_slice(&first_logical_element_index.to_le_bytes());
            encoded.extend_from_slice(&logical_element_stride.to_le_bytes());
        }
        SameSecretAuthenticatedSourceRecipeBinding::BoundTree {
            expected_root_source_ordinal,
        } => {
            encoded.extend_from_slice(&2_u16.to_le_bytes());
            encoded.extend_from_slice(&expected_root_source_ordinal.to_le_bytes());
        }
        SameSecretAuthenticatedSourceRecipeBinding::Prover => {
            encoded.extend_from_slice(&3_u16.to_le_bytes());
        }
    }
    encoded
}

fn encode_bound_material_salt_tree(
    tree: &SameSecretBoundMaterialSaltTreeDescriptor,
) -> Result<Vec<u8>, SameSecretAuthenticatedSourceManifestError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&tree.relation_tree_ordinal.to_le_bytes());
    encoded.extend_from_slice(&tree.bound_tree_ordinal.to_le_bytes());
    encoded.extend_from_slice(&tree.expected_root_source_ordinal.to_le_bytes());
    encoded.extend_from_slice(&(tree.root_use as u16).to_le_bytes());
    encoded.extend_from_slice(&tree.source_trace_domain_size.to_le_bytes());
    encoded.extend_from_slice(&tree.evaluation_domain_size.to_le_bytes());
    encoded.extend_from_slice(&tree.leaf_count.to_le_bytes());
    encoded.extend_from_slice(
        &match tree.low_degree_mode {
            RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired => 1_u16,
            RowCodeWhirBoundLowDegreeMode::Direct => 2_u16,
            RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired => 3_u16,
        }
        .to_le_bytes(),
    );
    encoded.extend_from_slice(&tree.encoded_query_salt_count.to_le_bytes());
    encoded.extend_from_slice(&checked_len(tree.ordered_column_ordinals.len())?.to_le_bytes());
    for column_ordinal in &tree.ordered_column_ordinals {
        encoded.extend_from_slice(&column_ordinal.to_le_bytes());
    }
    Ok(encoded)
}

fn checked_len(length: usize) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
    u64::try_from(length).map_err(|_| SameSecretAuthenticatedSourceManifestError::CountOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
    left.checked_add(right)
        .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)
}

fn checked_multiply(
    left: u64,
    right: u64,
) -> Result<u64, SameSecretAuthenticatedSourceManifestError> {
    left.checked_mul(right)
        .ok_or(SameSecretAuthenticatedSourceManifestError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use crate::{
        bgv::proof_suite::{
            ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
            selected_relation_plan_check_context, selected_relation_plans,
            selected_same_secret_relation_plan_input,
        },
        foundation::ProofApplicationSlotCeilings,
        hashing::hash_framed_parts_512,
    };

    use super::*;

    fn selected_manifest_inputs() -> (
        ValidatedRelationPlanArtifact,
        RowCodeWhirConstructionPlan,
        RelationPlanCheckContext,
    ) {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret context exists");
        let relation_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &relation_context,
        )
        .expect("the selected same-secret relation compiles");
        let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            relation_plan,
            &relation_context,
        )
        .expect("the selected same-secret relation validates");
        let relation_variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("the selected same-secret variant exists");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            relation_variant.schedule_position(),
            relation_variant.top_count(),
        )
        .expect("the selected same-secret construction derives");
        (artifact, construction_plan, relation_context)
    }

    #[test]
    fn selected_manifest_recomputes_the_complete_source_and_salt_census() {
        let (artifact, construction_plan, relation_context) = selected_manifest_inputs();
        let relation_variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("the selected same-secret variant exists");
        let manifest = SameSecretAuthenticatedSourceManifest::derive(
            &construction_plan,
            relation_variant,
            &relation_context,
        )
        .expect("the selected source manifest derives");
        let bound_material_trees = construction_plan
            .bound_trees
            .iter()
            .filter(|tree| tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial)
            .collect::<Vec<_>>();
        assert_eq!(bound_material_trees.len(), 8);
        assert!(bound_material_trees.iter().all(|tree| {
            tree.root_use == BoundTreeRootUse::Input
                && tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired
                && tree.leaf_count == 8_388_608
                && tree.query_count == construction_plan.parameters.prior_proof_bound_query_count
        }));
        let independently_derived_logical_salt_count = bound_material_trees
            .iter()
            .try_fold(0_u64, |total, tree| {
                total.checked_add(
                    u64::try_from(tree.leaf_count)
                        .expect("the selected material-tree leaf count fits u64"),
                )
            })
            .expect("the selected logical salt count fits u64");
        assert_eq!(independently_derived_logical_salt_count, 67_108_864);

        assert_eq!(manifest.authenticated_source_polynomial_count(), Ok(2_018));
        assert_eq!(
            manifest.raw_authenticated_source_coefficient_position_count(),
            Ok(33_128_448),
        );
        assert_eq!(
            manifest.persisted_pre_challenge_source_coefficient_position_count(),
            Ok(34_462_440),
        );
        assert_eq!(manifest.deterministic_reversed_column_count(), Ok(12));
        assert_eq!(manifest.stored_pre_challenge_column_count(), Ok(2_030));
        assert_eq!(manifest.bound_material_tree_count(), Ok(8));
        assert_eq!(
            manifest.logical_bound_material_leaf_salt_count(),
            Ok(independently_derived_logical_salt_count),
        );
        assert_eq!(
            manifest.logical_bound_material_leaf_salt_byte_length(),
            Ok(8_589_934_592),
        );
        assert_eq!(
            manifest.encoded_queried_bound_material_leaf_salt_count(),
            Ok(320),
        );
        assert_eq!(
            manifest.encoded_queried_bound_material_leaf_salt_byte_length(),
            Ok(40_960),
        );
        assert_ne!(manifest.catalog_hash(), [0_u8; 64]);
        assert_eq!(
            manifest.construction_identity(),
            construction_plan
                .canonical_identity_hash()
                .expect("the construction identity derives"),
        );

        let mut validation = manifest.begin_validation();
        for source in &manifest.authenticated_sources {
            let descriptor = relation_variant
                .ordered_columns()
                .get(
                    usize::try_from(source.column_ordinal)
                        .expect("the selected source ordinal fits usize"),
                )
                .expect("the source descriptor exists");
            validation
                .validate_next_authenticated_source(source.column_ordinal, descriptor)
                .expect("the source order validates");
        }
        for binding in &manifest.reversed_column_bindings {
            validation
                .validate_next_reversed_column(
                    binding.source_column_ordinal,
                    binding.reversed_column_ordinal,
                )
                .expect("the reversal order validates");
        }
        validation
            .finish()
            .expect("the complete source flow validates");

        for tree in &manifest.bound_material_salt_trees {
            manifest
                .validate_bound_material_leaf_salt_coordinate(
                    tree.relation_tree_ordinal,
                    tree.expected_root_source_ordinal,
                    tree.root_use,
                    tree.leaf_count - 1,
                )
                .expect("the final logical salt coordinate validates");
            manifest
                .validate_encoded_bound_material_query_coordinate(
                    tree.relation_tree_ordinal,
                    tree.encoded_query_salt_count - 1,
                    tree.leaf_count - 1,
                )
                .expect("the final encoded-query coordinate validates");
        }
    }

    #[test]
    fn manifest_rejects_source_reversal_and_bound_material_catalog_mutations() {
        let (artifact, construction_plan, relation_context) = selected_manifest_inputs();
        let relation_variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("the selected same-secret variant exists");

        let mutate_and_require_rejection =
            |mutate: fn(&mut SameSecretAuthenticatedSourceManifest)| {
                let mut manifest = SameSecretAuthenticatedSourceManifest::derive(
                    &construction_plan,
                    relation_variant,
                    &relation_context,
                )
                .expect("the selected source manifest derives");
                mutate(&mut manifest);
                assert!(
                    manifest
                        .validate_against(&construction_plan, relation_variant, &relation_context,)
                        .is_err(),
                );
            };

        mutate_and_require_rejection(|manifest| {
            manifest.authenticated_sources[0].column_ordinal += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.authenticated_sources = manifest.authenticated_sources
                [..manifest.authenticated_sources.len() - 1]
                .to_vec()
                .into_boxed_slice();
        });
        mutate_and_require_rejection(|manifest| {
            manifest.authenticated_sources[0].raw_coefficient_position_count += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.authenticated_sources[0].persisted_coefficient_position_count += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.authenticated_sources[0].value_type =
                RelationColumnValueType::ChallengeExtension;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.reversed_column_bindings[0].source_column_ordinal += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.reversed_column_bindings[0].reversed_column_ordinal += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.bound_material_salt_trees[0].expected_root_source_ordinal += 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.bound_material_salt_trees[0].root_use = BoundTreeRootUse::Output;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.bound_material_salt_trees[0].leaf_count -= 1;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.bound_material_salt_trees[0].low_degree_mode =
                RowCodeWhirBoundLowDegreeMode::Direct;
        });
        mutate_and_require_rejection(|manifest| {
            manifest.bound_material_salt_trees[0].encoded_query_salt_count -= 1;
        });
    }

    #[test]
    fn selected_family_manifests_bind_each_candidate_specific_material_catalog() {
        let artifacts = selected_relation_plans().expect("the selected relation plans derive");
        let mut observed_vss_manifest = false;
        let mut observed_empty_material_catalog = false;

        for artifact in &artifacts {
            let schema_identifier = artifact.application_statement_schema_identifier();
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .expect("each selected family has an exact relation context");
            for relation_variant in artifact.compiled_plan().variants() {
                let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
                    artifact,
                    relation_variant.schedule_position(),
                    relation_variant.top_count(),
                )
                .expect("each candidate-specific construction plan derives");
                let manifest = SameSecretAuthenticatedSourceManifest::derive(
                    &construction_plan,
                    relation_variant,
                    &relation_context,
                )
                .unwrap_or_else(|error| {
                    panic!("schema {schema_identifier:#06x} source manifest failed: {error:?}")
                });
                let expected_material_trees = construction_plan
                    .bound_trees
                    .iter()
                    .filter(|tree| {
                        tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    manifest.bound_material_tree_count(),
                    Ok(u64::try_from(expected_material_trees.len())
                        .expect("the selected material-tree count fits u64")),
                );
                for (manifest_tree, construction_tree) in manifest
                    .bound_material_salt_trees
                    .iter()
                    .zip(expected_material_trees)
                {
                    assert_eq!(
                        manifest_tree.relation_tree_ordinal,
                        construction_tree.relation_tree_ordinal
                    );
                    assert_eq!(manifest_tree.root_use, construction_tree.root_use);
                    assert_eq!(
                        manifest_tree.low_degree_mode,
                        construction_tree.low_degree_mode
                    );
                    assert_eq!(
                        manifest_tree.encoded_query_salt_count,
                        u64::try_from(construction_tree.query_count)
                            .expect("the selected query count fits u64"),
                    );
                }

                if schema_identifier
                    == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                {
                    observed_vss_manifest = true;
                    assert_eq!(manifest.bound_material_tree_count(), Ok(112));
                    assert!(manifest.bound_material_salt_trees.iter().all(|tree| {
                        tree.root_use == BoundTreeRootUse::Output
                            && tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::Direct
                    }));
                }
                observed_empty_material_catalog |= manifest.bound_material_salt_trees.is_empty();
            }
        }

        assert!(observed_vss_manifest);
        assert!(observed_empty_material_catalog);
    }

    #[test]
    fn manifest_hash_is_bound_to_cryptographic_not_implementation_scheduling_identity() {
        let (artifact, construction_plan, relation_context) = selected_manifest_inputs();
        let relation_variant = artifact
            .compiled_plan()
            .select_variant(None, None)
            .expect("the selected same-secret variant exists");
        let manifest = SameSecretAuthenticatedSourceManifest::derive(
            &construction_plan,
            relation_variant,
            &relation_context,
        )
        .expect("the selected source manifest derives");

        let mut implementation_rescheduled_plan = construction_plan.clone();
        implementation_rescheduled_plan.checkpoints.reverse();
        let implementation_rescheduled_manifest = SameSecretAuthenticatedSourceManifest::derive(
            &implementation_rescheduled_plan,
            relation_variant,
            &relation_context,
        )
        .expect("implementation rescheduling preserves the source manifest");
        assert_eq!(
            implementation_rescheduled_manifest.catalog_hash(),
            manifest.catalog_hash(),
        );

        let mut cryptographically_changed_plan = construction_plan;
        cryptographically_changed_plan.relation_plan_hash[0] ^= 1;
        assert!(
            manifest
                .validate_against(
                    &cryptographically_changed_plan,
                    relation_variant,
                    &relation_context,
                )
                .is_err(),
        );
        let cryptographically_changed_manifest = SameSecretAuthenticatedSourceManifest::derive(
            &cryptographically_changed_plan,
            relation_variant,
            &relation_context,
        )
        .expect("the private mutation remains structurally representable for the regression");
        assert_ne!(
            cryptographically_changed_manifest.catalog_hash(),
            manifest.catalog_hash(),
        );

        let first_tree = manifest
            .bound_material_salt_trees
            .first()
            .expect("the selected manifest has bound material");
        assert_eq!(
            manifest.validate_bound_material_leaf_salt_coordinate(
                first_tree.relation_tree_ordinal,
                first_tree.expected_root_source_ordinal ^ 1,
                first_tree.root_use,
                0,
            ),
            Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch),
        );
        assert_eq!(
            manifest.validate_encoded_bound_material_query_coordinate(
                first_tree.relation_tree_ordinal,
                first_tree.encoded_query_salt_count,
                0,
            ),
            Err(SameSecretAuthenticatedSourceManifestError::BoundMaterialCoordinateMismatch),
        );

        assert_ne!(
            manifest.catalog_hash(),
            hash_framed_parts_512(
                SAME_SECRET_AUTHENTICATED_SOURCE_MANIFEST_HASH_DOMAIN,
                &[&manifest.construction_identity()],
            ),
        );
    }
}
