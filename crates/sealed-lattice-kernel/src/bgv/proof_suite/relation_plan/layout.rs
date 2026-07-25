use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::super::transcript::{
    CommonProofApplicationChallengeGroup, CommonProofChallenge, CommonProofPrivacyMode,
    CommonProofTranscriptSchedule,
};
#[cfg(test)]
use super::bounds::RelationBoundCertificate;
use super::{
    bounds::{RelationConstraintDescriptor, SemanticCellDescriptor},
    compiled_plan::RelationPlanCheckContext,
    expressions::{
        RelationExpressionInstruction, canonical_nested_list, checked_resident_payload_add,
        encode_generated_tuple, hash_generated_variable_bytes, resident_vec_storage_byte_length,
        validate_challenge_catalog,
    },
    integer_lift::{
        RelationCoefficientLocalIdentityBatchDescriptor, RelationIntegerLiftBatchDescriptor,
    },
    model::{
        ProofPrivacyMode, RelationChallengeDescriptor, RelationChallengeEpochCatalog,
        RelationChallengeEpochPrecedingMessage, RelationChallengeModulusSelector,
        RelationChallengeRole, RelationChallengeSampling, RelationColumnDescriptor,
        RelationPlanError, RelationPublicSamplerDescriptor, RelationRadixConvolutionDescriptor,
        RelationTreeDescriptor, RelationVerifierSource, SuiteModulusReference,
        canonical_encoding_error,
    },
    schema::{
        RELATION_MASK_SCHEMA_IDENTIFIER, RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER,
        RELATION_OPENING_POINT_SCHEMA_IDENTIFIER, RELATION_PLAN_VARIANT_HASH_DOMAIN,
        RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER, SCHEMA_VERSION,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationOpeningPointDescriptor {
    pub(super) deep_point_ordinal: u16,
    pub(super) trace_rotation_is_negative: bool,
    pub(super) trace_rotation_magnitude: u64,
    pub(super) conjugate_index: u16,
}

impl RelationOpeningPointDescriptor {
    pub(crate) const fn deep_point_ordinal(self) -> u16 {
        self.deep_point_ordinal
    }

    pub(crate) const fn trace_rotation(self) -> (bool, u64) {
        (
            self.trace_rotation_is_negative,
            self.trace_rotation_magnitude,
        )
    }

    pub(crate) const fn conjugate_index(self) -> u16 {
        self.conjugate_index
    }

    pub(super) fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_OPENING_POINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.deep_point_ordinal),
                CanonicalItem::unsigned8(u8::from(self.trace_rotation_is_negative)),
                CanonicalItem::unsigned64(self.trace_rotation_magnitude),
                CanonicalItem::unsigned16(self.conjugate_index),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationOpeningSourceClass {
    TreeColumn = 1,
    Quotient = 2,
    BatchMask = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationOpeningClaimDescriptor {
    pub(super) source_class: RelationOpeningSourceClass,
    pub(super) source_ordinal: u32,
    pub(super) column_ordinal: Option<u32>,
    pub(super) opening_point_ordinal: u32,
    pub(super) source_degree_bound_exclusive: u64,
}

impl RelationOpeningClaimDescriptor {
    pub(crate) const fn source_class(self) -> RelationOpeningSourceClass {
        self.source_class
    }

    pub(crate) const fn source_ordinal(self) -> u32 {
        self.source_ordinal
    }

    pub(crate) const fn column_ordinal(self) -> Option<u32> {
        self.column_ordinal
    }

    pub(crate) const fn opening_point_ordinal(self) -> u32 {
        self.opening_point_ordinal
    }

    pub(crate) const fn source_degree_bound_exclusive(self) -> u64 {
        self.source_degree_bound_exclusive
    }

    pub(super) fn canonical_tuple(self) -> Result<CanonicalTuple, RelationPlanError> {
        let column_item = self.column_ordinal.map(CanonicalItem::unsigned32);
        Ok(CanonicalTuple::new(
            RELATION_OPENING_CLAIM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.source_class as u16),
                CanonicalItem::unsigned32(self.source_ordinal),
                CanonicalItem::optional(CanonicalItemType::Unsigned32, column_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned32(self.opening_point_ordinal),
                CanonicalItem::unsigned64(self.source_degree_bound_exclusive),
            ],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationMaskKind {
    Trace = 1,
    Telescoping = 2,
    OpeningBatch = 3,
}

/// The private-randomness stream class is derived from the mask grammar. The
/// family remains in the foundation randomness domain, while the compiler-
/// assigned ordinal distinguishes every mask in one class without imposing a
/// `u16` ceiling on the relation width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationMaskCoordinate {
    purpose_class: u16,
    mask_ordinal: u32,
}

impl RelationMaskCoordinate {
    pub(crate) const fn purpose_class(self) -> u16 {
        self.purpose_class
    }

    pub(crate) const fn mask_ordinal(self) -> u32 {
        self.mask_ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationMaskTargetClass {
    Column = 1,
    QuotientComponent = 2,
    Batch = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationMaskDescriptor {
    pub(super) mask_ordinal: u32,
    pub(super) mask_kind: RelationMaskKind,
    pub(super) target_class: RelationMaskTargetClass,
    pub(super) target_ordinal: u32,
    pub(super) mask_degree_bound_exclusive: u64,
}

impl RelationMaskDescriptor {
    pub(crate) const fn mask_coordinate(self) -> RelationMaskCoordinate {
        RelationMaskCoordinate {
            purpose_class: self.mask_kind as u16,
            mask_ordinal: self.mask_ordinal,
        }
    }

    pub(crate) const fn mask_kind(self) -> RelationMaskKind {
        self.mask_kind
    }

    pub(crate) const fn target_class(self) -> RelationMaskTargetClass {
        self.target_class
    }

    pub(crate) const fn target_ordinal(self) -> u32 {
        self.target_ordinal
    }

    pub(crate) const fn mask_degree_bound_exclusive(self) -> u64 {
        self.mask_degree_bound_exclusive
    }

    pub(super) fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            RELATION_MASK_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.mask_ordinal),
                CanonicalItem::unsigned16(self.mask_kind as u16),
                CanonicalItem::unsigned16(self.target_class as u16),
                CanonicalItem::unsigned32(self.target_ordinal),
                CanonicalItem::unsigned64(self.mask_degree_bound_exclusive),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationPlanVariant {
    pub(super) schedule_position: Option<u32>,
    pub(super) top_count: Option<u16>,
    pub(super) proof_privacy_mode: ProofPrivacyMode,
    pub(super) trace_domain_size: u64,
    pub(super) evaluation_domain_size: u64,
    pub(super) opening_degree_bound_exclusive: u64,
    pub(super) ordered_non_native_moduli: Vec<SuiteModulusReference>,
    pub(super) ordered_verifier_sources: Vec<RelationVerifierSource>,
    pub(super) ordered_public_samplers: Vec<RelationPublicSamplerDescriptor>,
    pub(super) ordered_columns: Vec<RelationColumnDescriptor>,
    pub(super) ordered_semantic_cells: Vec<SemanticCellDescriptor>,
    pub(super) ordered_radix_convolutions: Vec<RelationRadixConvolutionDescriptor>,
    pub(super) ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    pub(super) ordered_coefficient_local_identity_batches:
        Vec<RelationCoefficientLocalIdentityBatchDescriptor>,
    pub(super) ordered_trees: Vec<RelationTreeDescriptor>,
    pub(super) ordered_constraints: Vec<RelationConstraintDescriptor>,
    pub(super) ordered_opening_points: Vec<RelationOpeningPointDescriptor>,
    pub(super) ordered_opening_claims: Vec<RelationOpeningClaimDescriptor>,
    pub(super) ordered_masks: Vec<RelationMaskDescriptor>,
}

impl RelationPlanVariant {
    /// Exact source-owned resident payload of the selected typed relation
    /// catalog. Top-level descriptor arrays, recursively owned vectors,
    /// strings, boxes, and semantic big-integer limbs are counted once. The
    /// inline `RelationPlanVariant` headers are owned by the generation state
    /// machine and are deliberately not repeated here.
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        let mut total = [
            resident_vec_storage_byte_length(&self.ordered_non_native_moduli)?,
            resident_vec_storage_byte_length(&self.ordered_verifier_sources)?,
            resident_vec_storage_byte_length(&self.ordered_public_samplers)?,
            resident_vec_storage_byte_length(&self.ordered_columns)?,
            resident_vec_storage_byte_length(&self.ordered_semantic_cells)?,
            resident_vec_storage_byte_length(&self.ordered_radix_convolutions)?,
            resident_vec_storage_byte_length(&self.ordered_integer_lift_batches)?,
            resident_vec_storage_byte_length(&self.ordered_coefficient_local_identity_batches)?,
            resident_vec_storage_byte_length(&self.ordered_trees)?,
            resident_vec_storage_byte_length(&self.ordered_constraints)?,
            resident_vec_storage_byte_length(&self.ordered_opening_points)?,
            resident_vec_storage_byte_length(&self.ordered_opening_claims)?,
            resident_vec_storage_byte_length(&self.ordered_masks)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_resident_payload_add)?;
        for source in &self.ordered_verifier_sources {
            total =
                checked_resident_payload_add(total, source.resident_owned_payload_byte_length()?)?;
        }
        for sampler in &self.ordered_public_samplers {
            total =
                checked_resident_payload_add(total, sampler.resident_owned_payload_byte_length()?)?;
        }
        for cell in &self.ordered_semantic_cells {
            total =
                checked_resident_payload_add(total, cell.resident_owned_payload_byte_length()?)?;
        }
        for convolution in &self.ordered_radix_convolutions {
            total = checked_resident_payload_add(
                total,
                convolution.resident_owned_payload_byte_length()?,
            )?;
        }
        for batch in &self.ordered_integer_lift_batches {
            total =
                checked_resident_payload_add(total, batch.resident_owned_payload_byte_length()?)?;
        }
        for batch in &self.ordered_coefficient_local_identity_batches {
            total =
                checked_resident_payload_add(total, batch.resident_owned_payload_byte_length()?)?;
        }
        for tree in &self.ordered_trees {
            total =
                checked_resident_payload_add(total, tree.resident_owned_payload_byte_length()?)?;
        }
        for constraint in &self.ordered_constraints {
            total = checked_resident_payload_add(
                total,
                constraint.resident_owned_payload_byte_length()?,
            )?;
        }
        Ok(total)
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        encode_generated_tuple(&self.canonical_tuple()?)
    }

    pub(crate) fn canonical_hash(&self) -> Result<[u8; 64], RelationPlanError> {
        hash_generated_variable_bytes(RELATION_PLAN_VARIANT_HASH_DOMAIN, &self.canonical_bytes()?)
    }

    pub(crate) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(&self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn proof_privacy_mode(&self) -> ProofPrivacyMode {
        self.proof_privacy_mode
    }

    pub(crate) const fn trace_domain_size(&self) -> u64 {
        self.trace_domain_size
    }

    pub(crate) const fn evaluation_domain_size(&self) -> u64 {
        self.evaluation_domain_size
    }

    pub(crate) const fn opening_degree_bound_exclusive(&self) -> u64 {
        self.opening_degree_bound_exclusive
    }

    pub(crate) fn non_native_modulus_ordinal(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u16, RelationPlanError> {
        u16::try_from(
            self.ordered_non_native_moduli
                .binary_search(&modulus_reference)
                .map_err(|_| RelationPlanError::MissingModulus)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(crate) fn ordered_columns(&self) -> &[RelationColumnDescriptor] {
        &self.ordered_columns
    }

    pub(crate) fn verifier_source(&self, ordinal: u32) -> Option<&RelationVerifierSource> {
        self.ordered_verifier_sources.get(ordinal as usize)
    }

    pub(crate) fn ordered_trees(&self) -> &[RelationTreeDescriptor] {
        &self.ordered_trees
    }

    #[cfg(test)]
    pub(crate) const fn ordered_constraint_count(&self) -> usize {
        self.ordered_constraints.len()
    }

    pub(crate) fn ordered_integer_lift_batches(&self) -> &[RelationIntegerLiftBatchDescriptor] {
        &self.ordered_integer_lift_batches
    }

    pub(crate) fn ordered_coefficient_local_identity_batches(
        &self,
    ) -> &[RelationCoefficientLocalIdentityBatchDescriptor] {
        &self.ordered_coefficient_local_identity_batches
    }

    pub(crate) fn ordered_opening_points(&self) -> &[RelationOpeningPointDescriptor] {
        &self.ordered_opening_points
    }

    pub(crate) fn ordered_opening_claims(&self) -> &[RelationOpeningClaimDescriptor] {
        &self.ordered_opening_claims
    }

    pub(crate) fn ordered_masks(&self) -> &[RelationMaskDescriptor] {
        &self.ordered_masks
    }

    #[cfg(test)]
    pub(crate) fn radix_digit_and_carry_column_counts(&self) -> (usize, usize) {
        let mut digit_columns = BTreeSet::new();
        let mut carry_columns = BTreeSet::new();
        for semantic_cell in &self.ordered_semantic_cells {
            match &semantic_cell.bound_certificate {
                RelationBoundCertificate::UnsignedRadixRecomposition {
                    ordered_digit_column_ordinals,
                    ..
                }
                | RelationBoundCertificate::ShiftedRadixRecomposition {
                    ordered_digit_column_ordinals,
                    ..
                } => {
                    digit_columns.extend(ordered_digit_column_ordinals.iter().copied());
                }
                RelationBoundCertificate::CanonicalModulusRecomposition {
                    ordered_digit_column_ordinals,
                    ordered_difference_digit_column_ordinals,
                    ordered_borrow_column_ordinals,
                    ..
                } => {
                    digit_columns.extend(ordered_digit_column_ordinals.iter().copied());
                    digit_columns.extend(ordered_difference_digit_column_ordinals.iter().copied());
                    carry_columns.extend(ordered_borrow_column_ordinals.iter().copied());
                }
                RelationBoundCertificate::Trinary { .. }
                | RelationBoundCertificate::Binary { .. }
                | RelationBoundCertificate::FiniteIntegerSet { .. } => {}
            }
        }
        (digit_columns.len(), carry_columns.len())
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let schedule_item = self.schedule_position.map(CanonicalItem::unsigned32);
        let top_count_item = self.top_count.map(CanonicalItem::unsigned16);
        Ok(CanonicalTuple::new(
            RELATION_PLAN_VARIANT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::optional(CanonicalItemType::Unsigned32, schedule_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::optional(CanonicalItemType::Unsigned16, top_count_item.as_ref())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.proof_privacy_mode as u16),
                CanonicalItem::unsigned64(self.trace_domain_size),
                CanonicalItem::unsigned64(self.evaluation_domain_size),
                CanonicalItem::unsigned64(self.opening_degree_bound_exclusive),
                canonical_nested_list(
                    self.ordered_non_native_moduli
                        .iter()
                        .copied()
                        .map(SuiteModulusReference::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_verifier_sources
                        .iter()
                        .map(RelationVerifierSource::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_public_samplers
                        .iter()
                        .map(RelationPublicSamplerDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_columns
                        .iter()
                        .map(RelationColumnDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_semantic_cells
                        .iter()
                        .map(SemanticCellDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_radix_convolutions
                        .iter()
                        .map(RelationRadixConvolutionDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_integer_lift_batches
                        .iter()
                        .map(RelationIntegerLiftBatchDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_coefficient_local_identity_batches
                        .iter()
                        .map(RelationCoefficientLocalIdentityBatchDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_trees
                        .iter()
                        .map(RelationTreeDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_constraints
                        .iter()
                        .map(RelationConstraintDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_opening_points
                        .iter()
                        .copied()
                        .map(RelationOpeningPointDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_opening_claims
                        .iter()
                        .copied()
                        .map(RelationOpeningClaimDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_masks
                        .iter()
                        .copied()
                        .map(RelationMaskDescriptor::canonical_tuple),
                )?,
            ],
        ))
    }

    pub(crate) fn derived_challenge_catalog(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationChallengeDescriptor>, RelationPlanError> {
        let mut catalog = BTreeSet::new();
        for constraint in &self.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                if let RelationExpressionInstruction::TranscriptChallenge {
                    challenge_role,
                    role_coordinates,
                } = instruction
                {
                    catalog.insert(challenge_descriptor(
                        *challenge_role,
                        role_coordinates.clone(),
                        1,
                        self,
                        context,
                    )?);
                }
            }
        }
        for constraint_ordinal in 0..self.ordered_constraints.len() {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::ConstraintComposition,
                vec![constraint_ordinal as u64],
                1,
                self,
                context,
            )?);
        }
        for deep_point_ordinal in 0..context.deep_point_count {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::DeepPoint,
                vec![u64::from(deep_point_ordinal)],
                1,
                self,
                context,
            )?);
        }
        catalog.insert(challenge_descriptor(
            RelationChallengeRole::OpeningBatch,
            vec![0],
            u32::try_from(self.ordered_opening_claims.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            self,
            context,
        )?);
        for fold_ordinal in 0..context.fri_fold_count {
            catalog.insert(challenge_descriptor(
                RelationChallengeRole::FriFold,
                vec![u64::from(fold_ordinal)],
                1,
                self,
                context,
            )?);
        }
        catalog.insert(challenge_descriptor(
            RelationChallengeRole::QueryPosition,
            vec![0],
            context.unique_query_count,
            self,
            context,
        )?);
        let catalog = catalog.into_iter().collect::<Vec<_>>();
        validate_challenge_catalog(&catalog, self, context)?;
        Ok(catalog)
    }

    pub(crate) fn derived_challenge_epoch_catalogs(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationChallengeEpochCatalog>, RelationPlanError> {
        let mut descriptors_by_epoch = BTreeMap::<u16, Vec<_>>::new();
        for descriptor in self.derived_challenge_catalog(context)? {
            descriptors_by_epoch
                .entry(descriptor.epoch)
                .or_default()
                .push(descriptor);
        }
        let query_epoch = 4_u16
            .checked_add(context.fri_fold_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        descriptors_by_epoch
            .into_iter()
            .map(|(epoch, ordered_descriptors)| {
                let preceding_message = match epoch {
                    1 => RelationChallengeEpochPrecedingMessage::BaseRoots,
                    2 => RelationChallengeEpochPrecedingMessage::AuxiliaryRoots,
                    3 => RelationChallengeEpochPrecedingMessage::QuotientRoots,
                    4 => RelationChallengeEpochPrecedingMessage::DeepValuesAndOpeningBatchMask,
                    value if value == query_epoch => {
                        RelationChallengeEpochPrecedingMessage::FriTerminal
                    }
                    value if value > 4 && value < query_epoch => {
                        RelationChallengeEpochPrecedingMessage::FriLayerRoot(value - 5)
                    }
                    _ => return Err(RelationPlanError::InvalidChallengeCatalog),
                };
                Ok(RelationChallengeEpochCatalog {
                    epoch,
                    preceding_message,
                    ordered_descriptors,
                })
            })
            .collect()
    }

    pub(crate) fn common_proof_transcript_schedule(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<CommonProofTranscriptSchedule, RelationPlanError> {
        let mut next_base_tree_ordinal = 0_u16;
        let mut next_auxiliary_tree_ordinal = 0_u16;
        let mut ordered_base_tree_ordinals = Vec::new();
        let mut ordered_auxiliary_tree_ordinals = Vec::new();
        for tree in &self.ordered_trees {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role, ..
            } = tree
            else {
                continue;
            };
            match *proof_tree_role {
                1 => {
                    ordered_base_tree_ordinals.push(next_base_tree_ordinal);
                    next_base_tree_ordinal = next_base_tree_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                }
                2 => {
                    ordered_auxiliary_tree_ordinals.push(next_auxiliary_tree_ordinal);
                    next_auxiliary_tree_ordinal = next_auxiliary_tree_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                }
                _ => return Err(RelationPlanError::InvalidRoot),
            }
        }

        let mut application_group_inputs =
            BTreeMap::<CommonProofChallenge, (u64, BTreeSet<u16>)>::new();
        for descriptor in
            self.derived_challenge_catalog(context)?
                .into_iter()
                .filter(|descriptor| {
                    matches!(
                        descriptor.role,
                        RelationChallengeRole::NonNativeTheta
                            | RelationChallengeRole::NonNativeAlpha
                    )
                })
        {
            let modulus_ordinal = u16::try_from(descriptor.role_coordinates[0])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let repetition_ordinal = u16::try_from(descriptor.role_coordinates[1])
                .map_err(|_| RelationPlanError::CountOverflow)?;
            let challenge = match descriptor.role {
                RelationChallengeRole::NonNativeTheta => {
                    CommonProofChallenge::Theta { modulus_ordinal }
                }
                RelationChallengeRole::NonNativeAlpha => {
                    CommonProofChallenge::Alpha { modulus_ordinal }
                }
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            let sampling = descriptor.resolved_sampling(self, context)?;
            let expected_repetition_count = match descriptor.role {
                RelationChallengeRole::NonNativeTheta => context.non_native_theta_repetition_count,
                RelationChallengeRole::NonNativeAlpha => context.non_native_alpha_repetition_count,
                _ => return Err(RelationPlanError::InvalidChallengeCatalog),
            };
            if sampling.coordinate_count != expected_repetition_count {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            let (group_modulus, repetition_ordinals) = application_group_inputs
                .entry(challenge)
                .or_insert_with(|| (sampling.coordinate_modulus, BTreeSet::new()));
            if *group_modulus != sampling.coordinate_modulus {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }
            repetition_ordinals.insert(repetition_ordinal);
        }
        let ordered_application_challenge_groups = application_group_inputs
            .into_iter()
            .map(|(challenge, (modulus, repetition_ordinals))| {
                let expected_repetition_count = match challenge {
                    CommonProofChallenge::Theta { .. } => context.non_native_theta_repetition_count,
                    CommonProofChallenge::Alpha { .. } => context.non_native_alpha_repetition_count,
                    _ => return Err(RelationPlanError::InvalidChallengeCatalog),
                };
                let expected_repetition_ordinals =
                    (0..expected_repetition_count).collect::<BTreeSet<_>>();
                if repetition_ordinals != expected_repetition_ordinals {
                    return Err(RelationPlanError::InvalidChallengeCatalog);
                }
                CommonProofApplicationChallengeGroup::new(
                    challenge,
                    modulus,
                    expected_repetition_count,
                )
                .map_err(|_| RelationPlanError::InvalidChallengeCatalog)
            })
            .collect::<Result<Vec<_>, _>>()?;

        CommonProofTranscriptSchedule::new(
            ordered_base_tree_ordinals,
            ordered_application_challenge_groups,
            ordered_auxiliary_tree_ordinals,
            u32::try_from(self.ordered_constraints.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            u16::try_from(context.quotient_component_count)
                .map_err(|_| RelationPlanError::CountOverflow)?,
            context.deep_point_count,
            u32::try_from(self.ordered_opening_claims.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            context.fri_fold_count,
            context.final_polynomial_degree_bound_exclusive,
            context.unique_query_count,
            self.evaluation_domain_size
                .checked_div(2)
                .filter(|count| *count > 0)
                .ok_or(RelationPlanError::InvalidDomain)?,
            context.maximum_fiat_shamir_candidate_draws_per_output,
            match self.proof_privacy_mode {
                ProofPrivacyMode::PublicOnly => CommonProofPrivacyMode::PublicOnly,
                ProofPrivacyMode::SecretBearing => CommonProofPrivacyMode::SecretBearing,
            },
        )
        .map_err(|_| RelationPlanError::InvalidChallengeCatalog)
    }
}

pub(super) fn challenge_descriptor(
    role: RelationChallengeRole,
    role_coordinates: Vec<u64>,
    value_count: u32,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<RelationChallengeDescriptor, RelationPlanError> {
    let epoch = match role {
        RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha => 1,
        RelationChallengeRole::ConstraintComposition => 2,
        RelationChallengeRole::DeepPoint => 3,
        RelationChallengeRole::OpeningBatch => 4,
        RelationChallengeRole::FriFold => 4_u16
            .checked_add(
                role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| u16::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?,
        RelationChallengeRole::QueryPosition => 4_u16
            .checked_add(context.fri_fold_count)
            .ok_or(RelationPlanError::CountOverflow)?,
    };
    let sampling = match role {
        RelationChallengeRole::NonNativeTheta => {
            RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::BaseField,
                coordinate_count: context.non_native_theta_repetition_count,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            }
        }
        RelationChallengeRole::NonNativeAlpha => {
            let modulus_ordinal = role_coordinates
                .first()
                .copied()
                .and_then(|ordinal| u16::try_from(ordinal).ok())
                .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
            RelationChallengeSampling::PowerOfProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(
                    modulus_ordinal,
                ),
                coordinate_count: context.non_native_alpha_repetition_count,
                maximum_candidate_draws_per_output: context
                    .maximum_fiat_shamir_candidate_draws_per_output,
            }
        }
        RelationChallengeRole::ConstraintComposition
        | RelationChallengeRole::OpeningBatch
        | RelationChallengeRole::FriFold => RelationChallengeSampling::IndependentResidues {
            modulus_selector: RelationChallengeModulusSelector::BaseField,
            coordinate_count: context.challenge_extension_degree,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
        RelationChallengeRole::DeepPoint => RelationChallengeSampling::NonzeroExtensionVectors {
            base_modulus_selector: RelationChallengeModulusSelector::BaseField,
            coordinate_count: context.challenge_extension_degree,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
        RelationChallengeRole::QueryPosition => RelationChallengeSampling::DistinctPositions {
            position_count_selector: RelationChallengeModulusSelector::QueryOrbitCount,
            maximum_candidate_draws_per_output: context
                .maximum_fiat_shamir_candidate_draws_per_output,
        },
    };
    let descriptor = RelationChallengeDescriptor {
        epoch,
        role,
        role_coordinates,
        value_count,
        sampling,
    };
    descriptor.validate(variant, context)?;
    Ok(descriptor)
}
