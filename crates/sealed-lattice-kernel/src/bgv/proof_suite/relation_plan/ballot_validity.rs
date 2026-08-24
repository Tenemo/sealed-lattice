use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use super::*;
use crate::{
    bgv::direct_ballots::{
        PAIR_CHARACTER_AUXILIARY_COUNT, PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT,
        PAIR_CHARACTER_PLAINTEXT_MODULUS, PAIR_CHARACTER_RING_DEGREE, SCORE_BUCKET_COUNT,
        pair_character_encoder_profile_sequence,
    },
    foundation::FOUNDATION_PROFILE,
};

#[cfg(test)]
use crate::bgv::direct_ballots::pair_character_plaintexts;

const BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
const VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL: u64 = 7;
const BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL: u64 = 8;
const OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
const MINIMUM_SCORE: u64 = FOUNDATION_PROFILE.minimum_score as u64;
const MAXIMUM_SCORE: u64 = FOUNDATION_PROFILE.maximum_score as u64;
const RESERVED_SLOT_RULE: u16 = 1;
const RADIX: u64 = 3;

/// One exact ballot witness vector from which a genuine pre-challenge source
/// column is derived. Public-key and ciphertext columns are verifier sequences
/// and therefore never enter this catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BallotValidityWitnessValueSource {
    ScoreIndicator {
        option_ordinal: u16,
        score_bucket_ordinal: u16,
    },
    PairCharacterAuxiliaryCoefficient {
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
    },
    ReversedRandomizerShifted {
        ciphertext_ordinal: u16,
    },
    ErrorShifted {
        ciphertext_ordinal: u16,
        component_ordinal: u16,
    },
    EncoderReduction {
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
    },
    PairCharacterProductQuotient {
        ciphertext_ordinal: u16,
    },
    EncryptionQuotient {
        ciphertext_ordinal: u16,
        data_modulus_index: u16,
        component_ordinal: u16,
    },
}

/// A plan-derived transformation of one exact witness vector. Keeping the
/// transformation in the compiled source plan makes restarts independent of
/// any host-supplied polynomial cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BallotValidityColumnTransform {
    Identity,
    UnsignedRadixDigit { digit_ordinal: u16 },
    ShiftedRadixDigit { offset: u64, digit_ordinal: u16 },
    UpperBoundDifferenceDigit { maximum: u64, digit_ordinal: u16 },
    UpperBoundBorrow { maximum: u64, digit_ordinal: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BallotValiditySourceColumnRecipe {
    value_source: BallotValidityWitnessValueSource,
    transform: BallotValidityColumnTransform,
}

impl BallotValiditySourceColumnRecipe {
    pub(crate) const fn value_source(self) -> BallotValidityWitnessValueSource {
        self.value_source
    }

    pub(crate) const fn transform(self) -> BallotValidityColumnTransform {
        self.transform
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BallotValiditySourcePlan {
    ring_degree: u64,
    active_data_modulus_indices: Box<[u16]>,
    data_moduli: Box<[u64]>,
    plaintext_modulus: u64,
    encoder_reduction_maxima:
        [[u64; PAIR_CHARACTER_AUXILIARY_COUNT - 1]; PAIR_CHARACTER_CIPHERTEXT_COUNT],
    pair_character_product_quotient_absolute_bound: u64,
    recipes_by_column: Box<[Option<BallotValiditySourceColumnRecipe>]>,
    verifier_sources_by_column: Box<[Option<BallotValidityVerifierColumnSource>]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BallotValidityVerifierColumnSource {
    AuthenticatedPolynomial {
        source_kind: u16,
        ciphertext_ordinal: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
    },
    PairCharacterEncoderProfile {
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        option_ordinal: u16,
    },
}

impl BallotValiditySourcePlan {
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Option<u64> {
        let payload = |count: usize, value_byte_length: usize| {
            u64::try_from(count)
                .ok()?
                .checked_mul(u64::try_from(value_byte_length).ok()?)
        };
        [
            payload(
                self.active_data_modulus_indices.len(),
                core::mem::size_of::<u16>(),
            )?,
            payload(self.data_moduli.len(), core::mem::size_of::<u64>())?,
            payload(
                self.recipes_by_column.len(),
                core::mem::size_of::<Option<BallotValiditySourceColumnRecipe>>(),
            )?,
            payload(
                self.verifier_sources_by_column.len(),
                core::mem::size_of::<Option<BallotValidityVerifierColumnSource>>(),
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }

    pub(crate) const fn ring_degree(&self) -> u64 {
        self.ring_degree
    }

    pub(crate) fn active_data_modulus_indices(&self) -> &[u16] {
        &self.active_data_modulus_indices
    }

    pub(crate) fn data_moduli(&self) -> &[u64] {
        &self.data_moduli
    }

    pub(crate) const fn plaintext_modulus(&self) -> u64 {
        self.plaintext_modulus
    }

    pub(crate) fn encoder_profile_sequence(
        &self,
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        option_ordinal: u16,
    ) -> Option<Vec<u64>> {
        pair_character_encoder_profile_sequence(
            ciphertext_ordinal,
            auxiliary_ordinal,
            option_ordinal,
        )
        .ok()
    }

    pub(crate) fn encoder_reductions_for_scores(
        &self,
        scores: &[u64],
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        auxiliary_coefficients: &[u64],
    ) -> Option<Vec<u64>> {
        if scores.len() != OPTION_COUNT
            || auxiliary_coefficients.len() != usize::try_from(self.ring_degree).ok()?
            || usize::from(ciphertext_ordinal) >= PAIR_CHARACTER_CIPHERTEXT_COUNT
            || usize::from(auxiliary_ordinal) >= PAIR_CHARACTER_AUXILIARY_COUNT - 1
        {
            return None;
        }
        let encoder_profiles = scores
            .iter()
            .enumerate()
            .map(|(option_ordinal, _)| {
                self.encoder_profile_sequence(
                    ciphertext_ordinal,
                    auxiliary_ordinal,
                    u16::try_from(option_ordinal).ok()?,
                )
            })
            .collect::<Option<Vec<_>>>()?;
        let mut reductions = Vec::with_capacity(auxiliary_coefficients.len());
        for (coefficient_ordinal, auxiliary_coefficient) in
            auxiliary_coefficients.iter().copied().enumerate()
        {
            let weighted_sum = encoder_profiles
                .iter()
                .zip(scores.iter().copied())
                .try_fold(0_u128, |sum, (encoder_profile, score)| {
                    let score_bucket_ordinal =
                        usize::try_from(score.checked_sub(MINIMUM_SCORE)?).ok()?;
                    let value = rotated_encoder_profile_value(
                        encoder_profile,
                        usize::from(auxiliary_ordinal),
                        score_bucket_ordinal,
                        coefficient_ordinal,
                    )
                    .ok()?;
                    sum.checked_add(u128::from(value))
                })?;
            let numerator = weighted_sum.checked_sub(u128::from(auxiliary_coefficient))?;
            if !numerator.is_multiple_of(u128::from(self.plaintext_modulus)) {
                return None;
            }
            let reduction = u64::try_from(numerator / u128::from(self.plaintext_modulus)).ok()?;
            if reduction
                > self.encoder_reduction_maxima[usize::from(ciphertext_ordinal)]
                    [usize::from(auxiliary_ordinal)]
            {
                return None;
            }
            reductions.push(reduction);
        }
        Some(reductions)
    }

    pub(crate) const fn pair_character_product_quotient_absolute_bound(&self) -> u64 {
        self.pair_character_product_quotient_absolute_bound
    }

    pub(crate) fn recipe(&self, column_ordinal: u32) -> Option<BallotValiditySourceColumnRecipe> {
        self.recipes_by_column
            .get(usize::try_from(column_ordinal).ok()?)
            .copied()
            .flatten()
    }

    pub(crate) fn verifier_source(
        &self,
        column_ordinal: u32,
    ) -> Option<BallotValidityVerifierColumnSource> {
        self.verifier_sources_by_column
            .get(usize::try_from(column_ordinal).ok()?)
            .copied()
            .flatten()
    }

    pub(crate) fn provided_column_count(&self) -> usize {
        self.recipes_by_column
            .iter()
            .zip(self.verifier_sources_by_column.iter())
            .filter(|(recipe, verifier_source)| recipe.is_some() ^ verifier_source.is_some())
            .count()
    }

    /// Heap payload of the immutable, boxed source-plan catalogs. The owner
    /// itself is counted by the provider's fixed-size accounting.
    pub(crate) fn owned_catalog_byte_length(&self) -> Option<u64> {
        [
            self.active_data_modulus_indices
                .len()
                .checked_mul(core::mem::size_of::<u16>()),
            self.data_moduli
                .len()
                .checked_mul(core::mem::size_of::<u64>()),
            self.recipes_by_column
                .len()
                .checked_mul(core::mem::size_of::<Option<BallotValiditySourceColumnRecipe>>()),
            self.verifier_sources_by_column
                .len()
                .checked_mul(core::mem::size_of::<
                    Option<BallotValidityVerifierColumnSource>,
                >()),
        ]
        .into_iter()
        .try_fold(0_usize, |total, length| total.checked_add(length?))
        .and_then(|length| u64::try_from(length).ok())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledBallotValidityRelation {
    relation_plan: CompiledRelationPlan,
    source_plan: BallotValiditySourcePlan,
}

impl CompiledBallotValidityRelation {
    pub(crate) const fn relation_plan(&self) -> &CompiledRelationPlan {
        &self.relation_plan
    }

    pub(crate) const fn source_plan(&self) -> &BallotValiditySourcePlan {
        &self.source_plan
    }

    pub(crate) fn into_relation_plan(self) -> CompiledRelationPlan {
        self.relation_plan
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BallotValidityRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) active_data_modulus_indices: Vec<u16>,
    pub(crate) plaintext_modulus: u64,
    pub(crate) reserved_slot_rule: u16,
}

#[derive(Clone, Debug)]
struct ValidatedBallotGeometry {
    data_moduli: Vec<u64>,
    encoder_reduction_maxima:
        [[u64; PAIR_CHARACTER_AUXILIARY_COUNT - 1]; PAIR_CHARACTER_CIPHERTEXT_COUNT],
    pair_character_product_quotient_absolute_bound: u64,
}

impl BallotValidityRelationPlanInput {
    fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<ValidatedBallotGeometry, RelationPlanError> {
        RelationPlanChecker::new(context).check_context()?;
        if self.ring_degree != u64::try_from(PAIR_CHARACTER_RING_DEGREE).unwrap_or(u64::MAX)
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.active_data_modulus_indices.is_empty()
            || self.plaintext_modulus != PAIR_CHARACTER_PLAINTEXT_MODULUS
            || self.reserved_slot_rule != RESERVED_SLOT_RULE
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        let expected_data_modulus_indices = (0..self.active_data_modulus_indices.len())
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        if self.active_data_modulus_indices != expected_data_modulus_indices {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        if context.resolved_modulus(SuiteModulusReference::plaintext())? != self.plaintext_modulus {
            return Err(RelationPlanError::InvalidModulus);
        }

        let data_moduli = self
            .active_data_modulus_indices
            .iter()
            .copied()
            .map(|modulus_index| {
                let modulus =
                    context.resolved_modulus(SuiteModulusReference::data(modulus_index))?;
                if modulus <= self.plaintext_modulus || modulus >= context.base_field_modulus {
                    return Err(RelationPlanError::InvalidModulus);
                }
                validate_radix_capacity(modulus, context.base_field_modulus)?;
                Ok(modulus)
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_radix_capacity(self.plaintext_modulus, context.base_field_modulus)?;

        let ring_degree =
            usize::try_from(self.ring_degree).map_err(|_| RelationPlanError::CountOverflow)?;
        let mut encoder_reduction_maxima =
            [[0_u64; PAIR_CHARACTER_AUXILIARY_COUNT - 1]; PAIR_CHARACTER_CIPHERTEXT_COUNT];
        for (ciphertext_ordinal, auxiliary_maxima) in
            encoder_reduction_maxima.iter_mut().enumerate()
        {
            for (auxiliary_ordinal, maximum) in auxiliary_maxima.iter_mut().enumerate() {
                let mut maximum_weight_sum_by_row = vec![0_u64; ring_degree];
                for option_ordinal in 0..OPTION_COUNT {
                    let encoder_profile = pair_character_encoder_profile_sequence(
                        u16::try_from(ciphertext_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        u16::try_from(auxiliary_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        u16::try_from(option_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .map_err(|_| RelationPlanError::InvalidDomain)?;
                    for (coefficient_ordinal, maximum_weight_sum) in
                        maximum_weight_sum_by_row.iter_mut().enumerate()
                    {
                        let option_maximum = (0..SCORE_BUCKET_COUNT)
                            .map(|score_bucket_ordinal| {
                                rotated_encoder_profile_value(
                                    &encoder_profile,
                                    auxiliary_ordinal,
                                    score_bucket_ordinal,
                                    coefficient_ordinal,
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .max()
                            .ok_or(RelationPlanError::InvalidDomain)?;
                        *maximum_weight_sum = maximum_weight_sum
                            .checked_add(option_maximum)
                            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
                    }
                }
                *maximum = maximum_weight_sum_by_row
                    .into_iter()
                    .map(|weight_sum| weight_sum / self.plaintext_modulus)
                    .max()
                    .filter(|maximum| *maximum != 0)
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?;
            }
        }
        let product_absolute_bound = u128::from(self.ring_degree)
            .checked_mul(u128::from(self.plaintext_modulus - 1).pow(2))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        if product_absolute_bound >= u128::from(context.base_field_modulus / 2) {
            return Err(RelationPlanError::NoWrapBoundViolated);
        }
        let pair_character_product_quotient_absolute_bound = u64::try_from(
            product_absolute_bound
                .checked_add(u128::from(self.plaintext_modulus - 1))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?
                / u128::from(self.plaintext_modulus),
        )
        .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;

        Ok(ValidatedBallotGeometry {
            data_moduli,
            encoder_reduction_maxima,
            pair_character_product_quotient_absolute_bound,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BallotVerifierSourceKey {
    PublicKey {
        component_ordinal: u16,
        data_modulus_index: u16,
    },
    Ciphertext {
        ciphertext_ordinal: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
    },
    PairCharacterEncoderProfile {
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        option_ordinal: u16,
    },
}

#[derive(Clone, Copy)]
enum ProofTreePhase {
    Base,
    Auxiliary,
}

#[derive(Clone)]
struct BoundedUnsignedColumn {
    target_column_ordinal: u32,
    ordered_digit_column_ordinals: Vec<u32>,
}

#[derive(Clone)]
struct PublicDataLimbColumns {
    public_key_component_zero: u32,
    public_key_component_one: u32,
    ciphertext_components: [[u32; 2]; PAIR_CHARACTER_CIPHERTEXT_COUNT],
}

#[derive(Clone, Copy)]
struct EncryptionQuotientColumns {
    components: [[u32; 2]; PAIR_CHARACTER_CIPHERTEXT_COUNT],
}

struct PairCharacterEncoderSourceColumns {
    score_indicators: Vec<Vec<u32>>,
    profiles_by_ciphertext_and_auxiliary:
        [[Vec<u32>; PAIR_CHARACTER_AUXILIARY_COUNT - 1]; PAIR_CHARACTER_CIPHERTEXT_COUNT],
}

struct BallotValidityPlanBuilder<'context> {
    input: &'context BallotValidityRelationPlanInput,
    context: &'context RelationPlanCheckContext,
    geometry: ValidatedBallotGeometry,
    ordered_non_native_moduli: Vec<SuiteModulusReference>,
    ordered_verifier_sources: Vec<RelationVerifierSource>,
    verifier_source_ordinals: BTreeMap<BallotVerifierSourceKey, u32>,
    ordered_columns: Vec<RelationColumnDescriptor>,
    source_recipes_by_column: Vec<Option<BallotValiditySourceColumnRecipe>>,
    verifier_sources_by_column: Vec<Option<BallotValidityVerifierColumnSource>>,
    semantic_cells_by_column: BTreeMap<u32, (SignedIntegerInterval, RelationBoundCertificate)>,
    ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
    base_tree_columns: Vec<u32>,
    auxiliary_tree_columns: Vec<u32>,
}

impl<'context> BallotValidityPlanBuilder<'context> {
    fn new(
        input: &'context BallotValidityRelationPlanInput,
        context: &'context RelationPlanCheckContext,
    ) -> Result<Self, RelationPlanError> {
        let geometry = input.validate(context)?;
        let (ordered_verifier_sources, verifier_source_ordinals) =
            canonical_ballot_verifier_sources(input)?;
        let mut ordered_non_native_moduli = input
            .active_data_modulus_indices
            .iter()
            .copied()
            .map(SuiteModulusReference::data)
            .collect::<Vec<_>>();
        ordered_non_native_moduli.push(SuiteModulusReference::plaintext());
        Ok(Self {
            input,
            context,
            geometry,
            ordered_non_native_moduli,
            ordered_verifier_sources,
            verifier_source_ordinals,
            ordered_columns: Vec::new(),
            source_recipes_by_column: Vec::new(),
            verifier_sources_by_column: Vec::new(),
            semantic_cells_by_column: BTreeMap::new(),
            ordered_integer_lift_batches: Vec::new(),
            ordered_constraints: Vec::new(),
            base_tree_columns: Vec::new(),
            auxiliary_tree_columns: Vec::new(),
        })
    }

    fn push_column(
        &mut self,
        origin: RelationColumnOrigin,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let is_virtual_verifier_sequence =
            matches!(origin, RelationColumnOrigin::VerifierSequence { .. });
        let source_degree_bound_exclusive = self.input.ring_degree;
        let column_ordinal = u32::try_from(self.ordered_columns.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_columns.push(RelationColumnDescriptor {
            origin,
            value_type: RelationColumnValueType::BaseField,
            source_degree_bound_exclusive,
            canonical_residue_modulus: None,
        });
        self.source_recipes_by_column.push(None);
        self.verifier_sources_by_column.push(None);
        if !is_virtual_verifier_sequence {
            match phase {
                ProofTreePhase::Base => self.base_tree_columns.push(column_ordinal),
                ProofTreePhase::Auxiliary => self.auxiliary_tree_columns.push(column_ordinal),
            }
        }
        Ok(column_ordinal)
    }

    fn push_prover_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        self.push_column(RelationColumnOrigin::Prover, phase)
    }

    fn assign_source_recipe(
        &mut self,
        column_ordinal: u32,
        value_source: BallotValidityWitnessValueSource,
        transform: BallotValidityColumnTransform,
    ) -> Result<(), RelationPlanError> {
        let recipe_slot = self
            .source_recipes_by_column
            .get_mut(usize::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
            .ok_or(RelationPlanError::InvalidColumn)?;
        if recipe_slot
            .replace(BallotValiditySourceColumnRecipe {
                value_source,
                transform,
            })
            .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        Ok(())
    }

    fn assign_bounded_unsigned_source_recipes(
        &mut self,
        columns: &BoundedUnsignedColumn,
        maximum: u64,
        value_source: BallotValidityWitnessValueSource,
    ) -> Result<(), RelationPlanError> {
        self.assign_source_recipe(
            columns.target_column_ordinal,
            value_source,
            BallotValidityColumnTransform::Identity,
        )?;
        for (digit_ordinal, column_ordinal) in columns
            .ordered_digit_column_ordinals
            .iter()
            .copied()
            .enumerate()
        {
            self.assign_source_recipe(
                column_ordinal,
                value_source,
                BallotValidityColumnTransform::UnsignedRadixDigit {
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        let digit_count = columns.ordered_digit_column_ordinals.len();
        if checked_radix_power(digit_count)? - 1 == maximum {
            return Ok(());
        }
        let first_difference_column = usize::try_from(columns.target_column_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_add(1)
            .and_then(|ordinal| ordinal.checked_add(digit_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        for digit_ordinal in 0..digit_count {
            self.assign_source_recipe(
                u32::try_from(first_difference_column + digit_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                value_source,
                BallotValidityColumnTransform::UpperBoundDifferenceDigit {
                    maximum,
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        let first_borrow_column = first_difference_column
            .checked_add(digit_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        for digit_ordinal in 0..digit_count.saturating_sub(1) {
            self.assign_source_recipe(
                u32::try_from(first_borrow_column + digit_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                value_source,
                BallotValidityColumnTransform::UpperBoundBorrow {
                    maximum,
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        Ok(())
    }

    fn assign_canonical_modulus_source_recipes(
        &mut self,
        columns: &BoundedUnsignedColumn,
        modulus_reference: SuiteModulusReference,
        value_source: BallotValidityWitnessValueSource,
    ) -> Result<(), RelationPlanError> {
        let maximum = self
            .context
            .resolved_modulus(modulus_reference)?
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?;
        self.assign_source_recipe(
            columns.target_column_ordinal,
            value_source,
            BallotValidityColumnTransform::Identity,
        )?;
        for (digit_ordinal, column_ordinal) in columns
            .ordered_digit_column_ordinals
            .iter()
            .copied()
            .enumerate()
        {
            self.assign_source_recipe(
                column_ordinal,
                value_source,
                BallotValidityColumnTransform::UnsignedRadixDigit {
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        let digit_count = columns.ordered_digit_column_ordinals.len();
        let first_difference_column = usize::try_from(columns.target_column_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_add(1)
            .and_then(|ordinal| ordinal.checked_add(digit_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        for digit_ordinal in 0..digit_count {
            self.assign_source_recipe(
                u32::try_from(first_difference_column + digit_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                value_source,
                BallotValidityColumnTransform::UpperBoundDifferenceDigit {
                    maximum,
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        let first_borrow_column = first_difference_column
            .checked_add(digit_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        for digit_ordinal in 0..digit_count.saturating_sub(1) {
            self.assign_source_recipe(
                u32::try_from(first_borrow_column + digit_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                value_source,
                BallotValidityColumnTransform::UpperBoundBorrow {
                    maximum,
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        Ok(())
    }

    fn assign_signed_integer_source_recipes(
        &mut self,
        target_column_ordinal: u32,
        absolute_bound: u128,
        value_source: BallotValidityWitnessValueSource,
    ) -> Result<(), RelationPlanError> {
        self.assign_source_recipe(
            target_column_ordinal,
            value_source,
            BallotValidityColumnTransform::Identity,
        )?;
        let digit_count = signed_radix_digit_count(absolute_bound)?;
        let offset = checked_radix_power(digit_count)?
            .checked_sub(1)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?
            / 2;
        for digit_ordinal in 0..digit_count {
            let column_ordinal = usize::try_from(target_column_ordinal)
                .map_err(|_| RelationPlanError::CountOverflow)?
                .checked_add(1)
                .and_then(|ordinal| ordinal.checked_add(digit_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            self.assign_source_recipe(
                u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                value_source,
                BallotValidityColumnTransform::ShiftedRadixDigit {
                    offset,
                    digit_ordinal: u16::try_from(digit_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
            )?;
        }
        Ok(())
    }

    fn push_verifier_column(
        &mut self,
        source_key: BallotVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u32, RelationPlanError> {
        let verifier_source_ordinal = self
            .verifier_source_ordinals
            .get(&source_key)
            .copied()
            .ok_or(RelationPlanError::InvalidSource)?;
        let column_ordinal = self.push_column(
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index: 0,
                logical_element_stride: 1,
            },
            ProofTreePhase::Base,
        )?;
        self.ordered_columns
            .get_mut(column_ordinal as usize)
            .ok_or(RelationPlanError::InvalidColumn)?
            .canonical_residue_modulus = Some(modulus_reference);
        let verifier_source = match source_key {
            BallotVerifierSourceKey::PublicKey {
                component_ordinal,
                data_modulus_index,
            } => BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
                source_kind: 1,
                ciphertext_ordinal: 0,
                component_ordinal,
                data_modulus_index,
            },
            BallotVerifierSourceKey::Ciphertext {
                ciphertext_ordinal,
                component_ordinal,
                data_modulus_index,
            } => BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
                source_kind: 2,
                ciphertext_ordinal,
                component_ordinal,
                data_modulus_index,
            },
            BallotVerifierSourceKey::PairCharacterEncoderProfile {
                ciphertext_ordinal,
                auxiliary_ordinal,
                option_ordinal,
            } => BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                ciphertext_ordinal,
                auxiliary_ordinal,
                option_ordinal,
            },
        };
        let verifier_source_slot = self
            .verifier_sources_by_column
            .get_mut(usize::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
            .ok_or(RelationPlanError::InvalidColumn)?;
        if verifier_source_slot.replace(verifier_source).is_some() {
            return Err(RelationPlanError::DuplicateItem);
        }
        Ok(column_ordinal)
    }

    fn add_constraint(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        let constraint_ordinal = u32::try_from(self.ordered_constraints.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_constraints.push(RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: vec![u64::from(constraint_ordinal)],
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            ordered_injective_integer_factor_expressions: Vec::new(),
        });
        Ok(constraint_ordinal)
    }

    fn add_full_trace_constraint(
        &mut self,
        expression: Vec<RelationExpressionInstruction>,
        enforce_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint(
            expression,
            full_trace_zeroifier_expression(self.input.ring_degree),
            enforce_no_wrap,
        )
    }

    fn insert_semantic_cell(
        &mut self,
        column_ordinal: u32,
        interval: SignedIntegerInterval,
        certificate: RelationBoundCertificate,
    ) -> Result<(), RelationPlanError> {
        if self
            .semantic_cells_by_column
            .insert(column_ordinal, (interval, certificate))
            .is_some()
        {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(())
    }

    fn add_trit_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        let column_ordinal = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(trinary_constraint_expression(column_ordinal), false)?;
        self.insert_semantic_cell(
            column_ordinal,
            SignedIntegerInterval::new(0, 2),
            RelationBoundCertificate::Trinary { constraint_ordinal },
        )?;
        Ok(column_ordinal)
    }

    fn add_binary_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        let column_ordinal = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(binary_constraint_expression(column_ordinal), false)?;
        self.insert_semantic_cell(
            column_ordinal,
            SignedIntegerInterval::new(0, 1),
            RelationBoundCertificate::Binary { constraint_ordinal },
        )?;
        Ok(column_ordinal)
    }

    fn add_trit_columns(
        &mut self,
        count: usize,
        phase: ProofTreePhase,
    ) -> Result<Vec<u32>, RelationPlanError> {
        (0..count).map(|_| self.add_trit_column(phase)).collect()
    }

    fn certify_unsigned_recomposition(
        &mut self,
        target_column_ordinal: u32,
        ordered_digit_column_ordinals: &[u32],
    ) -> Result<(), RelationPlanError> {
        let expression = radix_recomposition_expression(
            target_column_ordinal,
            RADIX,
            None,
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = checked_radix_power(ordered_digit_column_ordinals.len())?
            .checked_sub(1)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix: RADIX,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    fn certify_shifted_recomposition(
        &mut self,
        target_column_ordinal: u32,
        offset: u64,
        ordered_digit_column_ordinals: &[u32],
    ) -> Result<(), RelationPlanError> {
        let offset_magnitude = BigUint::from(offset);
        let expression = radix_recomposition_expression(
            target_column_ordinal,
            RADIX,
            Some(&offset_magnitude),
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = checked_radix_power(ordered_digit_column_ordinals.len())?
            .checked_sub(1)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(
                -BigInt::from(offset),
                BigInt::from(maximum) - BigInt::from(offset),
            )?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: RADIX,
                offset: offset_magnitude,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    fn add_bounded_unsigned_column(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        let target_column_ordinal = self.push_prover_column(phase)?;
        self.certify_existing_bounded_unsigned_column(target_column_ordinal, maximum, phase)
    }

    fn certify_existing_bounded_unsigned_column(
        &mut self,
        target_column_ordinal: u32,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        let digit_count = radix_digit_count(maximum)?;
        let ordered_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        self.certify_unsigned_recomposition(target_column_ordinal, &ordered_digit_column_ordinals)?;
        if checked_radix_power(digit_count)? - 1 != maximum {
            self.add_upper_bound_comparator(&ordered_digit_column_ordinals, maximum, phase)?;
        }
        Ok(BoundedUnsignedColumn {
            target_column_ordinal,
            ordered_digit_column_ordinals,
        })
    }

    fn add_canonical_modulus_column(
        &mut self,
        modulus_reference: SuiteModulusReference,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        let target_column_ordinal = self.push_prover_column(phase)?;
        self.certify_existing_canonical_modulus_column(
            target_column_ordinal,
            modulus_reference,
            phase,
        )
    }

    fn certify_existing_canonical_modulus_column(
        &mut self,
        target_column_ordinal: u32,
        modulus_reference: SuiteModulusReference,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        let maximum = self
            .context
            .resolved_modulus(modulus_reference)?
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?;
        let digit_count = radix_digit_count(maximum)?;
        let ordered_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let recomposition_constraint_ordinal = self.add_full_trace_constraint(
            radix_recomposition_expression(
                target_column_ordinal,
                RADIX,
                None,
                &ordered_digit_column_ordinals,
                self.context.base_field_modulus,
            )?,
            false,
        )?;
        let maximum_digits = fixed_radix_digits(maximum, digit_count)?;
        let ordered_difference_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let ordered_borrow_column_ordinals = (0..digit_count.saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ordered_comparator_constraint_ordinals = Vec::with_capacity(digit_count);
        for digit_ordinal in 0..digit_count {
            ordered_comparator_constraint_ordinals.push(
                self.add_full_trace_constraint(
                    unsigned_radix_comparator_digit_expression(
                        maximum_digits[digit_ordinal],
                        ordered_digit_column_ordinals[digit_ordinal],
                        ordered_difference_digit_column_ordinals[digit_ordinal],
                        digit_ordinal
                            .checked_sub(1)
                            .map(|ordinal| ordered_borrow_column_ordinals[ordinal]),
                        (digit_ordinal + 1 < digit_count)
                            .then(|| ordered_borrow_column_ordinals[digit_ordinal]),
                        RADIX,
                    ),
                    true,
                )?,
            );
        }
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                modulus_reference,
                radix: RADIX,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.clone(),
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
            },
        )?;
        Ok(BoundedUnsignedColumn {
            target_column_ordinal,
            ordered_digit_column_ordinals,
        })
    }

    fn add_upper_bound_comparator(
        &mut self,
        value_digits: &[u32],
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<(), RelationPlanError> {
        if value_digits.is_empty() {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
        let maximum_digits = fixed_radix_digits(maximum, value_digits.len())?;
        let difference_digits = self.add_trit_columns(value_digits.len(), phase)?;
        let internal_borrows = (0..value_digits.len().saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        for digit_ordinal in 0..value_digits.len() {
            let mut terms = vec![integer_constant_term(maximum_digits[digit_ordinal], false)];
            terms.push(integer_column_term(
                value_digits[digit_ordinal],
                false,
                0,
                true,
            ));
            if digit_ordinal > 0 {
                terms.push(integer_column_term(
                    internal_borrows[digit_ordinal - 1],
                    false,
                    0,
                    true,
                ));
            }
            if digit_ordinal + 1 < value_digits.len() {
                terms.push(integer_scaled_column_term(
                    internal_borrows[digit_ordinal],
                    RADIX,
                    false,
                    0,
                    false,
                ));
            }
            terms.push(integer_column_term(
                difference_digits[digit_ordinal],
                false,
                0,
                true,
            ));
            let expression = sum_integer_terms(terms)?;
            self.add_full_trace_constraint(expression, true)?;
        }
        Ok(())
    }

    fn add_signed_integer_column(
        &mut self,
        absolute_bound: u128,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let digit_count = signed_radix_digit_count(absolute_bound)?;
        let target_column_ordinal = self.push_prover_column(phase)?;
        let ordered_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let radix_power = checked_radix_power(digit_count)?;
        let offset = (radix_power - 1) / 2;
        if u128::from(offset) < absolute_bound {
            return Err(RelationPlanError::IntegerBoundOverflow);
        }
        self.certify_shifted_recomposition(
            target_column_ordinal,
            offset,
            &ordered_digit_column_ordinals,
        )?;
        Ok(target_column_ordinal)
    }
}

impl<'context> BallotValidityPlanBuilder<'context> {
    fn add_public_data_limb_columns(
        &mut self,
        data_modulus_index: u16,
    ) -> Result<PublicDataLimbColumns, RelationPlanError> {
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let public_key_component_zero = self.push_verifier_column(
            BallotVerifierSourceKey::PublicKey {
                component_ordinal: 0,
                data_modulus_index,
            },
            modulus_reference,
        )?;
        let public_key_component_one = self.push_verifier_column(
            BallotVerifierSourceKey::PublicKey {
                component_ordinal: 1,
                data_modulus_index,
            },
            modulus_reference,
        )?;
        let mut ciphertext_components = [[0_u32; 2]; PAIR_CHARACTER_CIPHERTEXT_COUNT];
        for (ciphertext_ordinal, components) in ciphertext_components.iter_mut().enumerate() {
            for (component_ordinal, column_ordinal) in components.iter_mut().enumerate() {
                *column_ordinal = self.push_verifier_column(
                    BallotVerifierSourceKey::Ciphertext {
                        ciphertext_ordinal: u16::try_from(ciphertext_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        component_ordinal: u16::try_from(component_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        data_modulus_index,
                    },
                    modulus_reference,
                )?;
            }
        }
        Ok(PublicDataLimbColumns {
            public_key_component_zero,
            public_key_component_one,
            ciphertext_components,
        })
    }

    fn add_pair_character_encoder_source_columns(
        &mut self,
    ) -> Result<PairCharacterEncoderSourceColumns, RelationPlanError> {
        let mut score_indicators = Vec::with_capacity(OPTION_COUNT);
        let mut profiles_by_ciphertext_and_auxiliary =
            core::array::from_fn(|_| core::array::from_fn(|_| Vec::with_capacity(OPTION_COUNT)));
        for option_ordinal in 0..OPTION_COUNT {
            for (ciphertext_ordinal, profiles_by_auxiliary) in
                profiles_by_ciphertext_and_auxiliary.iter_mut().enumerate()
            {
                for (auxiliary_ordinal, profile_columns) in
                    profiles_by_auxiliary.iter_mut().enumerate()
                {
                    profile_columns.push(
                        self.push_verifier_column(
                            BallotVerifierSourceKey::PairCharacterEncoderProfile {
                                ciphertext_ordinal: u16::try_from(ciphertext_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                                auxiliary_ordinal: u16::try_from(auxiliary_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                                option_ordinal: u16::try_from(option_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                            },
                            SuiteModulusReference::plaintext(),
                        )?,
                    );
                }
            }
            let mut option_indicators = Vec::with_capacity(SCORE_BUCKET_COUNT);
            for score_bucket_ordinal in 0..SCORE_BUCKET_COUNT {
                let column_ordinal = self.add_binary_column(ProofTreePhase::Base)?;
                self.assign_source_recipe(
                    column_ordinal,
                    BallotValidityWitnessValueSource::ScoreIndicator {
                        option_ordinal: u16::try_from(option_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        score_bucket_ordinal: u16::try_from(score_bucket_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    BallotValidityColumnTransform::Identity,
                )?;
                self.add_full_trace_constraint(
                    subtract_rotated_columns(column_ordinal, false, 1, column_ordinal, false, 0),
                    true,
                )?;
                option_indicators.push(column_ordinal);
            }
            let mut one_hot_terms = option_indicators
                .iter()
                .copied()
                .map(|column_ordinal| integer_column_term(column_ordinal, false, 0, false))
                .collect::<Vec<_>>();
            one_hot_terms.push(integer_constant_term(1, true));
            self.add_full_trace_constraint(sum_integer_terms(one_hot_terms)?, true)?;
            score_indicators.push(option_indicators);
        }
        Ok(PairCharacterEncoderSourceColumns {
            score_indicators,
            profiles_by_ciphertext_and_auxiliary,
        })
    }

    fn add_exact_encoder_identity(
        &mut self,
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        encoder_source_columns: &PairCharacterEncoderSourceColumns,
        auxiliary_coefficients: &BoundedUnsignedColumn,
        encoder_reduction: &BoundedUnsignedColumn,
    ) -> Result<(), RelationPlanError> {
        let score_indicators = &encoder_source_columns.score_indicators;
        let profile_columns = encoder_source_columns
            .profiles_by_ciphertext_and_auxiliary
            .get(usize::from(ciphertext_ordinal))
            .and_then(|profiles| profiles.get(usize::from(auxiliary_ordinal)))
            .ok_or(RelationPlanError::InvalidConstraint)?;
        if score_indicators.len() != OPTION_COUNT
            || profile_columns.len() != OPTION_COUNT
            || score_indicators
                .iter()
                .any(|indicators| indicators.len() != SCORE_BUCKET_COUNT)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut ordered_product_terms = Vec::with_capacity(OPTION_COUNT * SCORE_BUCKET_COUNT);
        for (option_ordinal, indicators) in score_indicators.iter().enumerate() {
            let encoder_profile_column = *profile_columns
                .get(option_ordinal)
                .ok_or(RelationPlanError::InvalidConstraint)?;
            for (score_bucket_ordinal, indicator_column_ordinal) in
                indicators.iter().copied().enumerate()
            {
                let score = MINIMUM_SCORE
                    .checked_add(
                        u64::try_from(score_bucket_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?;
                let (rotation_is_negative, rotation_magnitude) = match auxiliary_ordinal {
                    0 => (
                        true,
                        score
                            .checked_add(MAXIMUM_SCORE - MINIMUM_SCORE)
                            .ok_or(RelationPlanError::CountOverflow)?,
                    ),
                    1 => (false, score),
                    _ => return Err(RelationPlanError::InvalidConstraint),
                };
                ordered_product_terms.push(RelationConstantColumnVerifierSequenceProductTerm {
                    constant_column_ordinal: indicator_column_ordinal,
                    verifier_sequence_column_ordinal: encoder_profile_column,
                    verifier_sequence_rotation_is_negative: rotation_is_negative,
                    verifier_sequence_rotation_magnitude: rotation_magnitude,
                });
            }
        }
        ordered_product_terms.sort_unstable();
        if !strictly_sorted_unique(&ordered_product_terms) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let mut terms = vec![IntegerTerm {
            expression: vec![
                RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                    coefficient_period: u16::try_from(PAIR_CHARACTER_LANE_COUNT)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    ordered_terms: ordered_product_terms,
                },
            ],
            negative: false,
        }];
        terms.push(integer_column_term(
            auxiliary_coefficients.target_column_ordinal,
            false,
            0,
            true,
        ));
        terms.push(integer_modulus_scaled_column_term(
            encoder_reduction.target_column_ordinal,
            SuiteModulusReference::plaintext(),
            1,
            false,
            0,
            true,
        ));
        let expression = sum_integer_terms(terms)?;
        self.add_full_trace_constraint(expression, true)?;
        Ok(())
    }

    fn add_encryption_quotient_columns(
        &mut self,
        modulus: u64,
        data_modulus_index: u16,
    ) -> Result<EncryptionQuotientColumns, RelationPlanError> {
        let ring_degree = u128::from(self.input.ring_degree);
        let modulus = u128::from(modulus);
        let plaintext_modulus = u128::from(self.input.plaintext_modulus);
        let positive_numerator_bound = ring_degree
            .checked_add(1)
            .and_then(|factor| factor.checked_mul(modulus - 1))
            .and_then(|bound| bound.checked_add(2 * plaintext_modulus))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        let negative_numerator_bound = ring_degree
            .checked_mul(modulus - 1)
            .and_then(|bound| bound.checked_add(3 * plaintext_modulus - 1))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        let absolute_bound = positive_numerator_bound.max(negative_numerator_bound) / modulus;
        let mut components = [[0_u32; 2]; PAIR_CHARACTER_CIPHERTEXT_COUNT];
        for (ciphertext_ordinal, ciphertext_components) in components.iter_mut().enumerate() {
            for (component_ordinal, column_ordinal) in ciphertext_components.iter_mut().enumerate()
            {
                *column_ordinal =
                    self.add_signed_integer_column(absolute_bound, ProofTreePhase::Base)?;
                self.assign_signed_integer_source_recipes(
                    *column_ordinal,
                    absolute_bound,
                    BallotValidityWitnessValueSource::EncryptionQuotient {
                        ciphertext_ordinal: u16::try_from(ciphertext_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        data_modulus_index,
                        component_ordinal: u16::try_from(component_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                )?;
            }
        }
        Ok(EncryptionQuotientColumns { components })
    }

    #[allow(clippy::too_many_arguments)]
    fn add_integer_lift_batch(
        &mut self,
        modulus_ordinal: usize,
        challenge_ordinal: u16,
        public_columns: &PublicDataLimbColumns,
        quotient_columns: EncryptionQuotientColumns,
        message_coefficients: &[BoundedUnsignedColumn],
        reversed_randomizers_shifted: &[BoundedUnsignedColumn],
        error_columns_shifted: &[[BoundedUnsignedColumn; 2]],
    ) -> Result<(), RelationPlanError> {
        let modulus_reference = self
            .ordered_non_native_moduli
            .get(modulus_ordinal)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)?;
        if message_coefficients.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
            || reversed_randomizers_shifted.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
            || error_columns_shifted.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut components = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT * 2);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            for component_ordinal in 0..2 {
                let ciphertext_column_ordinal =
                    public_columns.ciphertext_components[ciphertext_ordinal][component_ordinal];
                let public_key_column_ordinal = match component_ordinal {
                    0 => public_columns.public_key_component_zero,
                    1 => public_columns.public_key_component_one,
                    _ => unreachable!(),
                };
                let quotient_column_ordinal =
                    quotient_columns.components[ciphertext_ordinal][component_ordinal];
                let error_column_ordinal = error_columns_shifted[ciphertext_ordinal]
                    [component_ordinal]
                    .target_column_ordinal;
                let mut ordered_linear_terms = vec![
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: quotient_column_ordinal,
                        column_offset: 0,
                        coefficient: RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference,
                            multiplier: 1,
                        },
                    },
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: false,
                        column_ordinal: ciphertext_column_ordinal,
                        column_offset: 0,
                        coefficient: RelationIntegerLiftCoefficient::Constant(1),
                    },
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: error_column_ordinal,
                        column_offset: 2,
                        coefficient: RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference: SuiteModulusReference::plaintext(),
                            multiplier: 1,
                        },
                    },
                ];
                if component_ordinal == 0 {
                    ordered_linear_terms.push(RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: message_coefficients[ciphertext_ordinal]
                            .target_column_ordinal,
                        column_offset: 0,
                        coefficient: RelationIntegerLiftCoefficient::Constant(1),
                    });
                }
                let mut keyed_linear_terms = ordered_linear_terms
                    .into_iter()
                    .map(|term| Ok((term.canonical_bytes()?, term)))
                    .collect::<Result<Vec<_>, RelationPlanError>>()?;
                keyed_linear_terms.sort_by(|left, right| left.0.cmp(&right.0));
                if keyed_linear_terms
                    .windows(2)
                    .any(|window| window[0].0 >= window[1].0)
                {
                    return Err(RelationPlanError::DuplicateItem);
                }
                let ordered_linear_terms = keyed_linear_terms
                    .into_iter()
                    .map(|(_, term)| term)
                    .collect();

                let ordered_convolution_products =
                    vec![RelationIntegerLiftConvolutionProductDescriptor {
                        negative: true,
                        convolution_kind: RelationIntegerLiftConvolutionKind::Negacyclic,
                        multiplicand_column_ordinal: public_key_column_ordinal,
                        reversed_multiplier_column_ordinal: reversed_randomizers_shifted
                            [ciphertext_ordinal]
                            .target_column_ordinal,
                        multiplier_offset: 1,
                        suffix_evaluation_column_ordinal: self
                            .push_prover_column(ProofTreePhase::Auxiliary)?,
                        reversed_transpose_column_ordinal: self
                            .push_prover_column(ProofTreePhase::Auxiliary)?,
                    }];
                components.push(RelationIntegerLiftComponentDescriptor {
                    ordered_linear_terms,
                    ordered_convolution_products,
                    ordered_full_ring_negacyclic_products: Vec::new(),
                    linear_evaluation_column_ordinal: self
                        .push_prover_column(ProofTreePhase::Auxiliary)?,
                    product_accumulator_column_ordinal: self
                        .push_prover_column(ProofTreePhase::Auxiliary)?,
                });
            }
        }
        let mut keyed_components = components
            .into_iter()
            .map(|component| Ok((component.canonical_bytes()?, component)))
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        keyed_components.sort_by(|left, right| left.0.cmp(&right.0));
        if keyed_components
            .windows(2)
            .any(|window| window[0].0 >= window[1].0)
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        let ordered_components = keyed_components
            .into_iter()
            .map(|(_, component)| component)
            .collect();

        let batch = RelationIntegerLiftBatchDescriptor {
            modulus_reference,
            challenge_ordinal,
            ordered_reversed_column_bindings: Vec::new(),
            ordered_negacyclic_automorphism_permutations: Vec::new(),
            ordered_components,
        };
        let modulus_ordinal =
            u16::try_from(modulus_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        for program in batch.constraint_programs(
            modulus_ordinal,
            self.input.ring_degree,
            self.input.evaluation_domain_size,
            self.context,
        )? {
            self.add_constraint(
                program.numerator_postfix_expression,
                program.zeroifier_postfix_expression,
                false,
            )?;
        }
        self.ordered_integer_lift_batches.push(batch);
        Ok(())
    }

    fn add_pair_character_product_batch(
        &mut self,
        modulus_ordinal: usize,
        challenge_ordinal: u16,
        auxiliary_columns: &[Vec<BoundedUnsignedColumn>],
        reversed_right_column_ordinals: &[u32],
        product_quotient_columns: &[u32],
    ) -> Result<(), RelationPlanError> {
        if auxiliary_columns.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
            || auxiliary_columns
                .iter()
                .any(|columns| columns.len() != PAIR_CHARACTER_AUXILIARY_COUNT)
            || reversed_right_column_ordinals.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
            || product_quotient_columns.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut reversed_bindings = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut components = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            reversed_bindings.push(RelationIntegerLiftReversedColumnBindingDescriptor {
                source_column_ordinal: auxiliary_columns[ciphertext_ordinal][1]
                    .target_column_ordinal,
                reversed_column_ordinal: reversed_right_column_ordinals[ciphertext_ordinal],
                source_prefix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                reversed_suffix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            });
            let mut ordered_linear_terms = vec![
                RelationIntegerLiftLinearTermDescriptor {
                    negative: false,
                    column_ordinal: auxiliary_columns[ciphertext_ordinal][2].target_column_ordinal,
                    column_offset: 0,
                    coefficient: RelationIntegerLiftCoefficient::Constant(1),
                },
                RelationIntegerLiftLinearTermDescriptor {
                    negative: true,
                    column_ordinal: product_quotient_columns[ciphertext_ordinal],
                    column_offset: 0,
                    coefficient: RelationIntegerLiftCoefficient::Modulus {
                        modulus_reference: SuiteModulusReference::plaintext(),
                        multiplier: 1,
                    },
                },
            ];
            ordered_linear_terms.sort_by(|left, right| {
                left.canonical_bytes()
                    .expect("relation term canonical encoding")
                    .cmp(
                        &right
                            .canonical_bytes()
                            .expect("relation term canonical encoding"),
                    )
            });
            components.push(RelationIntegerLiftComponentDescriptor {
                ordered_linear_terms,
                ordered_convolution_products: vec![
                    RelationIntegerLiftConvolutionProductDescriptor {
                        negative: true,
                        convolution_kind: RelationIntegerLiftConvolutionKind::Negacyclic,
                        multiplicand_column_ordinal: auxiliary_columns[ciphertext_ordinal][0]
                            .target_column_ordinal,
                        reversed_multiplier_column_ordinal: reversed_right_column_ordinals
                            [ciphertext_ordinal],
                        multiplier_offset: 0,
                        suffix_evaluation_column_ordinal: self
                            .push_prover_column(ProofTreePhase::Auxiliary)?,
                        reversed_transpose_column_ordinal: self
                            .push_prover_column(ProofTreePhase::Auxiliary)?,
                    },
                ],
                ordered_full_ring_negacyclic_products: Vec::new(),
                linear_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                product_accumulator_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            });
        }
        let mut canonically_keyed_bindings = reversed_bindings
            .into_iter()
            .map(|binding| Ok((binding.canonical_bytes()?, binding)))
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        canonically_keyed_bindings.sort_by(|left, right| left.0.cmp(&right.0));
        let ordered_reversed_column_bindings = canonically_keyed_bindings
            .into_iter()
            .map(|(_, binding)| binding)
            .collect();
        let mut canonically_keyed_components = components
            .into_iter()
            .map(|component| Ok((component.canonical_bytes()?, component)))
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        canonically_keyed_components.sort_by(|left, right| left.0.cmp(&right.0));
        let ordered_components = canonically_keyed_components
            .into_iter()
            .map(|(_, component)| component)
            .collect();
        let batch = RelationIntegerLiftBatchDescriptor {
            modulus_reference: SuiteModulusReference::plaintext(),
            challenge_ordinal,
            ordered_reversed_column_bindings,
            ordered_negacyclic_automorphism_permutations: Vec::new(),
            ordered_components,
        };
        let modulus_ordinal =
            u16::try_from(modulus_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        for program in batch.constraint_programs(
            modulus_ordinal,
            self.input.ring_degree,
            self.input.evaluation_domain_size,
            self.context,
        )? {
            self.add_constraint(
                program.numerator_postfix_expression,
                program.zeroifier_postfix_expression,
                false,
            )?;
        }
        self.ordered_integer_lift_batches.push(batch);
        Ok(())
    }

    fn compile(mut self) -> Result<CompiledBallotValidityRelation, RelationPlanError> {
        let mut public_limb_columns = Vec::with_capacity(self.geometry.data_moduli.len());
        let mut quotient_limb_columns = Vec::with_capacity(self.geometry.data_moduli.len());
        let data_moduli = self.geometry.data_moduli.clone();
        for (limb_ordinal, data_modulus) in data_moduli.iter().copied().enumerate() {
            let data_modulus_index = self.input.active_data_modulus_indices[limb_ordinal];
            public_limb_columns.push(self.add_public_data_limb_columns(data_modulus_index)?);
            quotient_limb_columns
                .push(self.add_encryption_quotient_columns(data_modulus, data_modulus_index)?);
        }

        let encoder_source_columns = self.add_pair_character_encoder_source_columns()?;
        let mut auxiliary_columns = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut reversed_right_column_ordinals =
            Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut product_quotient_columns = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut reversed_randomizers_shifted = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut error_columns_shifted = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let ciphertext_ordinal_u16 =
                u16::try_from(ciphertext_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            let mut ciphertext_auxiliary_columns =
                Vec::with_capacity(PAIR_CHARACTER_AUXILIARY_COUNT);
            for auxiliary_ordinal in 0..PAIR_CHARACTER_AUXILIARY_COUNT {
                let column = self.add_canonical_modulus_column(
                    SuiteModulusReference::plaintext(),
                    ProofTreePhase::Base,
                )?;
                self.assign_canonical_modulus_source_recipes(
                    &column,
                    SuiteModulusReference::plaintext(),
                    BallotValidityWitnessValueSource::PairCharacterAuxiliaryCoefficient {
                        ciphertext_ordinal: ciphertext_ordinal_u16,
                        auxiliary_ordinal: u16::try_from(auxiliary_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                )?;
                ciphertext_auxiliary_columns.push(column);
            }
            let reversed_right_column_ordinal = self.push_prover_column(ProofTreePhase::Base)?;
            reversed_right_column_ordinals.push(reversed_right_column_ordinal);

            let product_quotient_absolute_bound =
                u128::from(self.geometry.pair_character_product_quotient_absolute_bound);
            let product_quotient = self
                .add_signed_integer_column(product_quotient_absolute_bound, ProofTreePhase::Base)?;
            self.assign_signed_integer_source_recipes(
                product_quotient,
                product_quotient_absolute_bound,
                BallotValidityWitnessValueSource::PairCharacterProductQuotient {
                    ciphertext_ordinal: ciphertext_ordinal_u16,
                },
            )?;
            product_quotient_columns.push(product_quotient);

            let reversed_randomizer_shifted =
                self.add_bounded_unsigned_column(2, ProofTreePhase::Base)?;
            self.assign_bounded_unsigned_source_recipes(
                &reversed_randomizer_shifted,
                2,
                BallotValidityWitnessValueSource::ReversedRandomizerShifted {
                    ciphertext_ordinal: ciphertext_ordinal_u16,
                },
            )?;
            reversed_randomizers_shifted.push(reversed_randomizer_shifted);

            let error_zero_shifted = self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?;
            self.assign_bounded_unsigned_source_recipes(
                &error_zero_shifted,
                4,
                BallotValidityWitnessValueSource::ErrorShifted {
                    ciphertext_ordinal: ciphertext_ordinal_u16,
                    component_ordinal: 0,
                },
            )?;
            let error_one_shifted = self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?;
            self.assign_bounded_unsigned_source_recipes(
                &error_one_shifted,
                4,
                BallotValidityWitnessValueSource::ErrorShifted {
                    ciphertext_ordinal: ciphertext_ordinal_u16,
                    component_ordinal: 1,
                },
            )?;
            error_columns_shifted.push([error_zero_shifted, error_one_shifted]);

            for (auxiliary_ordinal, ciphertext_auxiliary_column) in ciphertext_auxiliary_columns
                .iter()
                .enumerate()
                .take(PAIR_CHARACTER_AUXILIARY_COUNT - 1)
            {
                let maximum =
                    self.geometry.encoder_reduction_maxima[ciphertext_ordinal][auxiliary_ordinal];
                let encoder_reduction =
                    self.add_bounded_unsigned_column(maximum, ProofTreePhase::Base)?;
                self.assign_bounded_unsigned_source_recipes(
                    &encoder_reduction,
                    maximum,
                    BallotValidityWitnessValueSource::EncoderReduction {
                        ciphertext_ordinal: ciphertext_ordinal_u16,
                        auxiliary_ordinal: u16::try_from(auxiliary_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                )?;
                self.add_exact_encoder_identity(
                    ciphertext_ordinal_u16,
                    u16::try_from(auxiliary_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    &encoder_source_columns,
                    ciphertext_auxiliary_column,
                    &encoder_reduction,
                )?;
            }
            auxiliary_columns.push(ciphertext_auxiliary_columns);
        }

        for challenge_ordinal in 0..self.context.non_native_theta_repetition_count {
            self.add_pair_character_product_batch(
                self.geometry.data_moduli.len(),
                challenge_ordinal,
                &auxiliary_columns,
                &reversed_right_column_ordinals,
                &product_quotient_columns,
            )?;
        }
        let message_coefficients = auxiliary_columns
            .iter()
            .map(|columns| columns[2].clone())
            .collect::<Vec<_>>();

        for (modulus_ordinal, (public_columns, quotient_columns)) in public_limb_columns
            .iter()
            .zip(quotient_limb_columns.iter().copied())
            .enumerate()
        {
            for challenge_ordinal in 0..self.context.non_native_theta_repetition_count {
                self.add_integer_lift_batch(
                    modulus_ordinal,
                    challenge_ordinal,
                    public_columns,
                    quotient_columns,
                    &message_coefficients,
                    &reversed_randomizers_shifted,
                    &error_columns_shifted,
                )?;
            }
        }
        let mut keyed_batches = self
            .ordered_integer_lift_batches
            .drain(..)
            .map(|batch| Ok((batch.canonical_bytes()?, batch)))
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        keyed_batches.sort_by(|left, right| left.0.cmp(&right.0));
        if keyed_batches
            .windows(2)
            .any(|window| window[0].0 >= window[1].0)
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        self.ordered_integer_lift_batches =
            keyed_batches.into_iter().map(|(_, batch)| batch).collect();
        self.finish()
    }

    fn finish(mut self) -> Result<CompiledBallotValidityRelation, RelationPlanError> {
        if self.base_tree_columns.is_empty() || self.auxiliary_tree_columns.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        if self.source_recipes_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidColumn);
        }
        if self.verifier_sources_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidColumn);
        }
        let base_tree_column_set = self
            .base_tree_columns
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let auxiliary_tree_column_set = self
            .auxiliary_tree_columns
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let derived_reversed_column_set = self
            .ordered_integer_lift_batches
            .iter()
            .flat_map(|batch| {
                batch
                    .ordered_reversed_column_bindings
                    .iter()
                    .map(|binding| binding.reversed_column_ordinal)
            })
            .collect::<BTreeSet<_>>();
        for (column_index, ((column, recipe), verifier_source)) in self
            .ordered_columns
            .iter()
            .zip(&self.source_recipes_by_column)
            .zip(&self.verifier_sources_by_column)
            .enumerate()
        {
            let column_ordinal =
                u32::try_from(column_index).map_err(|_| RelationPlanError::CountOverflow)?;
            let expects_witness_source = matches!(column.origin, RelationColumnOrigin::Prover)
                && base_tree_column_set.contains(&column_ordinal)
                && !derived_reversed_column_set.contains(&column_ordinal);
            let expects_verifier_source =
                matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    && !base_tree_column_set.contains(&column_ordinal)
                    && !auxiliary_tree_column_set.contains(&column_ordinal);
            if recipe.is_some() != expects_witness_source
                || verifier_source.is_some() != expects_verifier_source
                || (auxiliary_tree_column_set.contains(&column_ordinal)
                    && (recipe.is_some() || verifier_source.is_some()))
            {
                return Err(RelationPlanError::InvalidColumn);
            }
        }
        let required_rotations_by_column =
            required_column_rotations(&self.ordered_constraints, &[])?;
        if required_rotations_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let used_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        if !used_rotations.contains(&(false, 0)) {
            return Err(RelationPlanError::InvalidOpening);
        }
        let minimum_direct_view_rank = self
            .ordered_columns
            .iter()
            .enumerate()
            .filter(|(_, column)| matches!(column.origin, RelationColumnOrigin::Prover))
            .map(|(column_ordinal, _)| {
                let distinct_rotation_count = required_rotations_by_column
                    .get(
                        &u32::try_from(column_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::InvalidOpening)?
                    .len();
                let translated_opening_count = u64::from(self.context.out_of_domain_point_count)
                    .checked_mul(
                        u64::try_from(distinct_rotation_count)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?;
                let view_count = u64::from(self.context.challenge_extension_degree)
                    .checked_mul(translated_opening_count)
                    .and_then(|count| {
                        count.checked_add(u64::from(
                            self.context.phase_column_query_coordinate_count,
                        ))
                    })
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                Ok(view_count)
            })
            .collect::<Result<Vec<_>, RelationPlanError>>()?
            .into_iter()
            .max()
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let trace_mask_degree_bound_exclusive =
            super::key_relation::construction_owned_trace_mask_degree_bound(
                BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                minimum_direct_view_rank,
                self.input.ring_degree,
                self.context,
            )?;
        let prover_column_degree_bound_exclusive = self
            .input
            .ring_degree
            .checked_add(trace_mask_degree_bound_exclusive)
            .filter(|degree| *degree <= self.input.opening_degree_bound_exclusive)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        for column in &mut self.ordered_columns {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                column.source_degree_bound_exclusive = prover_column_degree_bound_exclusive;
            }
        }
        let ordered_trees = vec![
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 1,
                ordered_column_ordinals: self.base_tree_columns,
            },
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role: 2,
                ordered_column_ordinals: self.auxiliary_tree_columns,
            },
        ];
        let ordered_semantic_cells = self
            .semantic_cells_by_column
            .into_iter()
            .enumerate()
            .map(
                |(
                    semantic_cell_ordinal,
                    (column_ordinal, (claimed_interval, bound_certificate)),
                )| {
                    Ok(SemanticCellDescriptor {
                        semantic_cell_ordinal: u32::try_from(semantic_cell_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        column_ordinal,
                        claimed_interval,
                        bound_certificate,
                    })
                },
            )
            .collect::<Result<Vec<_>, RelationPlanError>>()?;

        let ordered_opening_points = (0..self.context.out_of_domain_point_count)
            .flat_map(|out_of_domain_point_ordinal| {
                used_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<Vec<_>>();
        let opening_point_ordinals = ordered_opening_points
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, point)| {
                Ok((
                    point,
                    u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RelationPlanError>>()?;
        let mut ordered_opening_claims = Vec::new();
        for (tree_ordinal, tree) in ordered_trees.iter().enumerate() {
            for column_ordinal in tree.ordered_column_ordinals() {
                let source_degree_bound_exclusive = self
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidOpening)?
                    .source_degree_bound_exclusive;
                for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                    for rotation in required_rotations_by_column
                        .get(column_ordinal)
                        .ok_or(RelationPlanError::InvalidOpening)?
                    {
                        let opening_point_ordinal = opening_point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                out_of_domain_point_ordinal,
                                trace_rotation_is_negative: rotation.0,
                                trace_rotation_magnitude: rotation.1,
                                conjugate_index: 0,
                            })
                            .copied()
                            .ok_or(RelationPlanError::InvalidOpening)?;
                        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                            source_class: RelationOpeningSourceClass::TreeColumn,
                            source_ordinal: u32::try_from(tree_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                            column_ordinal: Some(*column_ordinal),
                            opening_point_ordinal,
                            source_degree_bound_exclusive,
                        });
                    }
                }
            }
        }
        for quotient_ordinal in 0..self.context.quotient_component_count {
            for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                let opening_point_ordinal = opening_point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: false,
                        trace_rotation_magnitude: 0,
                        conjugate_index: 0,
                    })
                    .copied()
                    .ok_or(RelationPlanError::InvalidOpening)?;
                ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                    source_class: RelationOpeningSourceClass::Quotient,
                    source_ordinal: quotient_ordinal,
                    column_ordinal: None,
                    opening_point_ordinal,
                    source_degree_bound_exclusive: self
                        .context
                        .quotient_component_degree_bound_exclusive,
                });
            }
        }
        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
            source_class: RelationOpeningSourceClass::BatchMask,
            source_ordinal: 0,
            column_ordinal: None,
            opening_point_ordinal: 0,
            source_degree_bound_exclusive: self
                .input
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });

        let mut next_trace_mask_ordinal = 0_u32;
        let mut ordered_masks = Vec::new();
        for (column_ordinal, column) in self.ordered_columns.iter().enumerate() {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                ordered_masks.push(RelationMaskDescriptor {
                    mask_ordinal: next_trace_mask_ordinal,
                    mask_kind: RelationMaskKind::Trace,
                    target_class: RelationMaskTargetClass::Column,
                    target_ordinal: u32::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    mask_degree_bound_exclusive: trace_mask_degree_bound_exclusive,
                });
                next_trace_mask_ordinal = next_trace_mask_ordinal
                    .checked_add(1)
                    .ok_or(RelationPlanError::CountOverflow)?;
            }
        }
        let quotient_component_count = self.context.quotient_component_count;
        let component_count = u128::from(quotient_component_count);
        let rounded_mask_degree = component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(u128::from(trace_mask_degree_bound_exclusive)))
            .and_then(|degree| degree.checked_add(component_count - 1))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?
            / component_count;
        let decomposition_stride = self
            .input
            .ring_degree
            .checked_add(
                u64::try_from(rounded_mask_degree)
                    .map_err(|_| RelationPlanError::DegreeBoundExceeded)?,
            )
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let telescoping_degree = self
            .context
            .quotient_component_degree_bound_exclusive
            .checked_sub(decomposition_stride)
            .filter(|degree| *degree != 0)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        for quotient_ordinal in 0..quotient_component_count - 1 {
            ordered_masks.push(RelationMaskDescriptor {
                mask_ordinal: quotient_ordinal,
                mask_kind: RelationMaskKind::Telescoping,
                target_class: RelationMaskTargetClass::QuotientComponent,
                target_ordinal: quotient_ordinal,
                mask_degree_bound_exclusive: telescoping_degree,
            });
        }
        ordered_masks.push(RelationMaskDescriptor {
            mask_ordinal: 0,
            mask_kind: RelationMaskKind::OpeningBatch,
            target_class: RelationMaskTargetClass::Batch,
            target_ordinal: 0,
            mask_degree_bound_exclusive: self
                .input
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });

        let source_plan = BallotValiditySourcePlan {
            ring_degree: self.input.ring_degree,
            active_data_modulus_indices: self
                .input
                .active_data_modulus_indices
                .clone()
                .into_boxed_slice(),
            data_moduli: self.geometry.data_moduli.clone().into_boxed_slice(),
            plaintext_modulus: self.input.plaintext_modulus,
            encoder_reduction_maxima: self.geometry.encoder_reduction_maxima,
            pair_character_product_quotient_absolute_bound: self
                .geometry
                .pair_character_product_quotient_absolute_bound,
            recipes_by_column: self.source_recipes_by_column.into_boxed_slice(),
            verifier_sources_by_column: self.verifier_sources_by_column.into_boxed_slice(),
        };
        let compiled = CompiledRelationPlan {
            plan: RelationPlan {
                application_statement_schema_identifier:
                    BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                variants: vec![RelationPlanVariant {
                    schedule_position: None,
                    top_count: None,
                    proof_privacy_mode: ProofPrivacyMode::SecretBearing,
                    trace_domain_size: self.input.ring_degree,
                    evaluation_domain_size: self.input.evaluation_domain_size,
                    opening_degree_bound_exclusive: self.input.opening_degree_bound_exclusive,
                    ordered_non_native_moduli: self.ordered_non_native_moduli,
                    ordered_verifier_sources: self.ordered_verifier_sources,
                    ordered_public_samplers: Vec::new(),
                    ordered_columns: self.ordered_columns,
                    ordered_semantic_cells,
                    ordered_radix_convolutions: Vec::new(),
                    ordered_integer_lift_batches: self.ordered_integer_lift_batches,
                    ordered_coefficient_local_identity_batches: Vec::new(),
                    ordered_trees,
                    ordered_constraints: self.ordered_constraints,
                    ordered_opening_points,
                    ordered_opening_claims,
                    ordered_masks,
                }],
            },
        };
        compiled.check(self.context)?;
        Ok(CompiledBallotValidityRelation {
            relation_plan: compiled,
            source_plan,
        })
    }
}

pub(crate) fn compile_ballot_validity_relation(
    input: &BallotValidityRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledBallotValidityRelation, RelationPlanError> {
    BallotValidityPlanBuilder::new(input, context)?.compile()
}

pub(crate) fn compile_ballot_validity_relation_plan(
    input: &BallotValidityRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_ballot_validity_relation(input, context)
        .map(CompiledBallotValidityRelation::into_relation_plan)
}

fn canonical_ballot_verifier_sources(
    input: &BallotValidityRelationPlanInput,
) -> Result<
    (
        Vec<RelationVerifierSource>,
        BTreeMap<BallotVerifierSourceKey, u32>,
    ),
    RelationPlanError,
> {
    let mut keyed_sources = Vec::new();
    for data_modulus_index in input.active_data_modulus_indices.iter().copied() {
        for component_ordinal in 0..2_u16 {
            let value_layout = RelationValueLayout {
                element_kind: RelationElementKind::Residue,
                residue_modulus: Some(SuiteModulusReference::data(data_modulus_index)),
                shape: vec![input.ring_degree],
                embedding_kind: RelationEmbeddingKind::LeastNonnegative,
            };
            keyed_sources.push((
                BallotVerifierSourceKey::PublicKey {
                    component_ordinal,
                    data_modulus_index,
                },
                RelationVerifierSource::Protocol {
                    protocol_source_kind: 1,
                    source_coordinates: vec![
                        u64::from(component_ordinal),
                        u64::from(data_modulus_index),
                    ],
                    statement_binding_path: vec![RelationSelectorPathStep::tuple_field(
                        VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL,
                    )],
                    value_layout: value_layout.clone(),
                },
            ));
            for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
                let ciphertext_ordinal = u16::try_from(ciphertext_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let flattened_component_ordinal = u64::from(ciphertext_ordinal)
                    .checked_mul(2)
                    .and_then(|ordinal| ordinal.checked_add(u64::from(component_ordinal)))
                    .ok_or(RelationPlanError::CountOverflow)?;
                keyed_sources.push((
                    BallotVerifierSourceKey::Ciphertext {
                        ciphertext_ordinal,
                        component_ordinal,
                        data_modulus_index,
                    },
                    RelationVerifierSource::Protocol {
                        protocol_source_kind: 2,
                        source_coordinates: vec![
                            flattened_component_ordinal,
                            u64::from(data_modulus_index),
                        ],
                        statement_binding_path: vec![RelationSelectorPathStep::tuple_field(
                            BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL,
                        )],
                        value_layout: value_layout.clone(),
                    },
                ));
            }
        }
    }
    for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
        for auxiliary_ordinal in 0..PAIR_CHARACTER_AUXILIARY_COUNT - 1 {
            for option_ordinal in 0..OPTION_COUNT {
                let ciphertext_ordinal = u16::try_from(ciphertext_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let auxiliary_ordinal = u16::try_from(auxiliary_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                let option_ordinal =
                    u16::try_from(option_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
                let key = BallotVerifierSourceKey::PairCharacterEncoderProfile {
                    ciphertext_ordinal,
                    auxiliary_ordinal,
                    option_ordinal,
                };
                keyed_sources.push((
                    key,
                    RelationVerifierSource::DirectBallotPairCharacterEncoderProfile {
                        ring_degree: input.ring_degree,
                        plaintext_modulus: input.plaintext_modulus,
                        ciphertext_ordinal,
                        auxiliary_ordinal,
                        option_count: u16::try_from(OPTION_COUNT)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        option_ordinal,
                    },
                ));
            }
        }
    }
    let mut canonically_keyed_sources = keyed_sources
        .into_iter()
        .map(|(source_key, source)| Ok((source.canonical_bytes()?, source_key, source)))
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    canonically_keyed_sources.sort_by(|left, right| left.0.cmp(&right.0));
    if !canonically_keyed_sources
        .windows(2)
        .all(|window| window[0].0 < window[1].0)
    {
        return Err(RelationPlanError::NonCanonicalOrder);
    }
    let mut source_ordinals = BTreeMap::new();
    let mut sources = Vec::with_capacity(canonically_keyed_sources.len());
    for (source_ordinal, (_, source_key, source)) in
        canonically_keyed_sources.into_iter().enumerate()
    {
        if source_ordinals
            .insert(
                source_key,
                u32::try_from(source_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        sources.push(source);
    }
    Ok((sources, source_ordinals))
}

fn rotated_encoder_profile_value(
    encoder_profile: &[u64],
    auxiliary_ordinal: usize,
    score_bucket_ordinal: usize,
    row_ordinal: usize,
) -> Result<u64, RelationPlanError> {
    if encoder_profile.len() != PAIR_CHARACTER_RING_DEGREE
        || score_bucket_ordinal >= SCORE_BUCKET_COUNT
        || row_ordinal >= encoder_profile.len()
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let score = usize::try_from(MINIMUM_SCORE)
        .map_err(|_| RelationPlanError::CountOverflow)?
        .checked_add(score_bucket_ordinal)
        .ok_or(RelationPlanError::CountOverflow)?;
    let rotation_magnitude = match auxiliary_ordinal {
        0 => score
            .checked_add(
                usize::try_from(MAXIMUM_SCORE - MINIMUM_SCORE)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?,
        1 => score,
        _ => return Err(RelationPlanError::InvalidDomain),
    };
    let profile_row_ordinal = match auxiliary_ordinal {
        0 => {
            row_ordinal
                .checked_add(encoder_profile.len())
                .and_then(|ordinal| ordinal.checked_sub(rotation_magnitude))
                .ok_or(RelationPlanError::CountOverflow)?
                % encoder_profile.len()
        }
        1 => {
            row_ordinal
                .checked_add(rotation_magnitude)
                .ok_or(RelationPlanError::CountOverflow)?
                % encoder_profile.len()
        }
        _ => return Err(RelationPlanError::InvalidDomain),
    };
    encoder_profile
        .get(profile_row_ordinal)
        .copied()
        .ok_or(RelationPlanError::InvalidDomain)
}

fn validate_radix_capacity(
    maximum_value: u64,
    proof_base_field_modulus: u64,
) -> Result<(), RelationPlanError> {
    let digit_count = radix_digit_count(maximum_value)?;
    if checked_radix_power(digit_count)? >= proof_base_field_modulus {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    Ok(())
}

fn radix_digit_count(maximum: u64) -> Result<usize, RelationPlanError> {
    let mut digit_count = 1_usize;
    let mut capacity = RADIX;
    while capacity <= maximum {
        capacity = capacity
            .checked_mul(RADIX)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(digit_count)
}

fn checked_radix_power(exponent: usize) -> Result<u64, RelationPlanError> {
    (0..exponent).try_fold(1_u64, |power, _| {
        power
            .checked_mul(RADIX)
            .ok_or(RelationPlanError::IntegerBoundOverflow)
    })
}

fn fixed_radix_digits(mut value: u64, digit_count: usize) -> Result<Vec<u64>, RelationPlanError> {
    if digit_count == 0 {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let mut digits = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        digits.push(value % RADIX);
        value /= RADIX;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn signed_radix_digit_count(absolute_bound: u128) -> Result<usize, RelationPlanError> {
    let mut radix_power = u128::from(RADIX);
    let mut digit_count = 1_usize;
    while (radix_power - 1) / 2 < absolute_bound {
        radix_power = radix_power
            .checked_mul(u128::from(RADIX))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(digit_count)
}

#[derive(Clone)]
struct IntegerTerm {
    expression: Vec<RelationExpressionInstruction>,
    negative: bool,
}

fn integer_constant_term(value: u64, negative: bool) -> IntegerTerm {
    IntegerTerm {
        expression: vec![RelationExpressionInstruction::BaseFieldConstant(value)],
        negative,
    }
}

fn integer_column_term(
    column_ordinal: u32,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    negative: bool,
) -> IntegerTerm {
    IntegerTerm {
        expression: vec![RelationExpressionInstruction::ColumnValue {
            column_ordinal,
            rotation_is_negative,
            rotation_magnitude,
        }],
        negative,
    }
}

fn integer_scaled_column_term(
    column_ordinal: u32,
    scale: u64,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    negative: bool,
) -> IntegerTerm {
    let mut term = integer_column_term(
        column_ordinal,
        rotation_is_negative,
        rotation_magnitude,
        negative,
    );
    term.expression
        .push(RelationExpressionInstruction::BaseFieldConstant(scale));
    term.expression
        .push(RelationExpressionInstruction::Multiplication);
    term
}

fn integer_modulus_scaled_column_term(
    column_ordinal: u32,
    modulus_reference: SuiteModulusReference,
    multiplier: u16,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    negative: bool,
) -> IntegerTerm {
    let mut term = integer_column_term(
        column_ordinal,
        rotation_is_negative,
        rotation_magnitude,
        negative,
    );
    term.expression
        .push(RelationExpressionInstruction::NonNativeModulusConstant {
            modulus_reference,
            multiplier,
        });
    term.expression
        .push(RelationExpressionInstruction::Multiplication);
    term
}

fn sum_integer_terms(
    terms: Vec<IntegerTerm>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expression = Vec::new();
    for (term_ordinal, term) in terms.into_iter().enumerate() {
        if term.expression.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        expression.extend(term.expression);
        if term.negative {
            expression.push(RelationExpressionInstruction::Negation);
        }
        if term_ordinal > 0 {
            expression.push(RelationExpressionInstruction::Addition);
        }
    }
    if expression.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(expression)
}

fn subtract_rotated_columns(
    left: u32,
    left_rotation_is_negative: bool,
    left_rotation_magnitude: u64,
    right: u32,
    right_rotation_is_negative: bool,
    right_rotation_magnitude: u64,
) -> Vec<RelationExpressionInstruction> {
    vec![
        RelationExpressionInstruction::ColumnValue {
            column_ordinal: left,
            rotation_is_negative: left_rotation_is_negative,
            rotation_magnitude: left_rotation_magnitude,
        },
        RelationExpressionInstruction::ColumnValue {
            column_ordinal: right,
            rotation_is_negative: right_rotation_is_negative,
            rotation_magnitude: right_rotation_magnitude,
        },
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofChallenge, CommonProofTranscript, PROOF_BASE_FIELD_MODULUS,
        sample_relation_application_challenges,
    };

    const TEST_RING_DEGREE: u64 = PAIR_CHARACTER_RING_DEGREE as u64;
    const TEST_PLAINTEXT_MODULUS: u64 = PAIR_CHARACTER_PLAINTEXT_MODULUS;
    const TEST_EVALUATION_DOMAIN_SIZE: u64 =
        crate::bgv::proof_suite::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE;

    fn check_context() -> RelationPlanCheckContext {
        crate::bgv::proof_suite::selected_profile::selected_relation_plan_check_context(
            BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected ballot relation context")
    }

    fn relation_input() -> BallotValidityRelationPlanInput {
        BallotValidityRelationPlanInput {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive:
                crate::bgv::proof_suite::selected_profile::SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: vec![0],
            plaintext_modulus: TEST_PLAINTEXT_MODULUS,
            reserved_slot_rule: RESERVED_SLOT_RULE,
        }
    }

    #[test]
    fn exact_ballot_plan_binds_only_data_limbs_to_non_native_challenges() {
        let context = check_context();
        let compilation = compile_ballot_validity_relation(&relation_input(), &context)
            .expect("the exact ballot relation must compile");
        let compiled = compilation.relation_plan();
        compiled
            .check(&context)
            .expect("the compiled relation must pass its independent checker");
        assert_eq!(
            compiled.application_statement_schema_identifier(),
            BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
        );

        let variant = compiled
            .select_variant(None, None)
            .expect("the ballot relation has one unparameterized variant");
        assert_eq!(
            variant.proof_privacy_mode(),
            ProofPrivacyMode::SecretBearing
        );
        assert_eq!(
            variant.ordered_non_native_moduli,
            vec![
                SuiteModulusReference::data(0),
                SuiteModulusReference::plaintext(),
            ]
        );
        assert_eq!(
            variant.ordered_verifier_sources.len(),
            6 + PAIR_CHARACTER_CIPHERTEXT_COUNT
                * (PAIR_CHARACTER_AUXILIARY_COUNT - 1)
                * OPTION_COUNT
        );
        assert!(variant.ordered_public_samplers.is_empty());

        assert_eq!(
            compilation.source_plan().recipes_by_column.len(),
            variant.ordered_columns.len()
        );
        let base_tree_columns = variant
            .ordered_trees
            .iter()
            .find_map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } if *proof_tree_role == 1 => Some(
                    ordered_column_ordinals
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                ),
                _ => None,
            })
            .expect("the ballot relation has a base tree");
        let derived_reversed_columns = variant
            .ordered_integer_lift_batches
            .iter()
            .flat_map(|batch| {
                batch
                    .ordered_reversed_column_bindings
                    .iter()
                    .map(|binding| binding.reversed_column_ordinal)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            compilation
                .source_plan()
                .verifier_sources_by_column
                .iter()
                .filter(|source| source.is_some())
                .count(),
            variant.ordered_verifier_sources.len()
        );
        let verifier_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(column_ordinal, column)| {
                matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    .then_some(u32::try_from(column_ordinal).unwrap())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            compilation.source_plan().provided_column_count(),
            base_tree_columns.len() - derived_reversed_columns.len() + verifier_columns.len()
        );
        assert!(variant.ordered_trees.iter().all(|tree| {
            tree.ordered_column_ordinals()
                .iter()
                .all(|column_ordinal| !verifier_columns.contains(column_ordinal))
        }));
        assert!(variant.ordered_opening_claims.iter().all(|claim| {
            claim
                .column_ordinal
                .is_none_or(|column_ordinal| !verifier_columns.contains(&column_ordinal))
        }));
        for (column_index, column) in variant.ordered_columns.iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).unwrap();
            assert_eq!(
                compilation.source_plan().recipe(column_ordinal).is_some(),
                matches!(column.origin, RelationColumnOrigin::Prover)
                    && base_tree_columns.contains(&column_ordinal)
                    && !derived_reversed_columns.contains(&column_ordinal),
                "column {column_ordinal} has the wrong family-source ownership"
            );
            assert_eq!(
                compilation
                    .source_plan()
                    .verifier_source(column_ordinal)
                    .is_some(),
                matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    && !base_tree_columns.contains(&column_ordinal),
                "column {column_ordinal} has the wrong verifier-source ownership"
            );
            assert!(
                !(compilation.source_plan().recipe(column_ordinal).is_some()
                    && compilation
                        .source_plan()
                        .verifier_source(column_ordinal)
                        .is_some()),
                "column {column_ordinal} cannot have two provider sources"
            );
        }
        assert!(
            (0..u32::try_from(variant.ordered_columns.len()).unwrap())
                .filter_map(|column_ordinal| compilation.source_plan().recipe(column_ordinal))
                .any(|recipe| matches!(
                    recipe.value_source(),
                    BallotValidityWitnessValueSource::EncryptionQuotient {
                        ciphertext_ordinal: _,
                        data_modulus_index: 0,
                        component_ordinal: 1,
                    }
                ) && matches!(
                    recipe.transform(),
                    BallotValidityColumnTransform::ShiftedRadixDigit { .. }
                ))
        );

        let mut source_bindings = variant
            .ordered_verifier_sources
            .iter()
            .filter_map(|source| match source {
                RelationVerifierSource::Protocol {
                    protocol_source_kind,
                    source_coordinates,
                    statement_binding_path,
                    value_layout,
                } => {
                    assert_eq!(
                        value_layout.residue_modulus,
                        Some(SuiteModulusReference::data(0))
                    );
                    assert_eq!(value_layout.shape, vec![TEST_RING_DEGREE]);
                    assert_eq!(
                        value_layout.embedding_kind,
                        RelationEmbeddingKind::LeastNonnegative
                    );
                    assert_eq!(statement_binding_path.len(), 1);
                    assert_eq!(
                        statement_binding_path[0].step_kind,
                        SelectorPathStepKind::TupleField
                    );
                    Some((
                        *protocol_source_kind,
                        source_coordinates.clone(),
                        statement_binding_path[0].argument,
                    ))
                }
                RelationVerifierSource::DirectBallotPairCharacterEncoderProfile { .. } => None,
                _ => panic!("ballot public inputs must use closed protocol or plan-owned sources"),
            })
            .collect::<Vec<_>>();
        source_bindings.sort_unstable();
        assert_eq!(
            source_bindings,
            vec![
                (1, vec![0, 0], VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL),
                (1, vec![1, 0], VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL),
                (2, vec![0, 0], BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL),
                (2, vec![1, 0], BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL),
                (2, vec![2, 0], BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL),
                (2, vec![3, 0], BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL),
            ]
        );
        let mut encoder_profile_source_coordinates = variant
            .ordered_verifier_sources
            .iter()
            .filter_map(|source| match source {
                RelationVerifierSource::DirectBallotPairCharacterEncoderProfile {
                    ring_degree,
                    plaintext_modulus,
                    ciphertext_ordinal,
                    auxiliary_ordinal,
                    option_count,
                    option_ordinal,
                } => {
                    assert_eq!(*ring_degree, TEST_RING_DEGREE);
                    assert_eq!(*plaintext_modulus, TEST_PLAINTEXT_MODULUS);
                    assert_eq!(usize::from(*option_count), OPTION_COUNT);
                    Some((*ciphertext_ordinal, *auxiliary_ordinal, *option_ordinal))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        encoder_profile_source_coordinates.sort_unstable();
        assert_eq!(
            encoder_profile_source_coordinates,
            (0..PAIR_CHARACTER_CIPHERTEXT_COUNT)
                .flat_map(|ciphertext_ordinal| {
                    (0..PAIR_CHARACTER_AUXILIARY_COUNT - 1).flat_map(move |auxiliary_ordinal| {
                        (0..OPTION_COUNT).map(move |option_ordinal| {
                            (
                                u16::try_from(ciphertext_ordinal).unwrap(),
                                u16::try_from(auxiliary_ordinal).unwrap(),
                                u16::try_from(option_ordinal).unwrap(),
                            )
                        })
                    })
                })
                .collect::<Vec<_>>()
        );

        let fused_encoder_instructions = variant
            .ordered_constraints
            .iter()
            .flat_map(|constraint| &constraint.numerator_postfix_expression)
            .filter_map(|instruction| match instruction {
                RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                    coefficient_period,
                    ordered_terms,
                } => Some((*coefficient_period, ordered_terms)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut preceding_option_last_column = None;
        for option_ordinal in 0..OPTION_COUNT {
            let option_ordinal = u16::try_from(option_ordinal).unwrap();
            let mut profile_column_ordinals = (0..variant.ordered_columns.len())
                .filter_map(|column_index| {
                    let column_ordinal = u32::try_from(column_index).ok()?;
                    matches!(
                        compilation.source_plan().verifier_source(column_ordinal),
                        Some(BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                            option_ordinal: declared_option_ordinal,
                            ..
                        }) if declared_option_ordinal == option_ordinal
                    )
                    .then_some(column_ordinal)
                })
                .collect::<Vec<_>>();
            let mut indicator_column_ordinals = (0..variant.ordered_columns.len())
                .filter_map(|column_index| {
                    let column_ordinal = u32::try_from(column_index).ok()?;
                    matches!(
                        compilation
                            .source_plan()
                            .recipe(column_ordinal)
                            .map(BallotValiditySourceColumnRecipe::value_source),
                        Some(BallotValidityWitnessValueSource::ScoreIndicator {
                            option_ordinal: declared_option_ordinal,
                            ..
                        }) if declared_option_ordinal == option_ordinal
                    )
                    .then_some(column_ordinal)
                })
                .collect::<Vec<_>>();
            profile_column_ordinals.sort_unstable();
            indicator_column_ordinals.sort_unstable();
            assert_eq!(
                profile_column_ordinals.len(),
                PAIR_CHARACTER_CIPHERTEXT_COUNT * (PAIR_CHARACTER_AUXILIARY_COUNT - 1),
            );
            assert_eq!(indicator_column_ordinals.len(), SCORE_BUCKET_COUNT);
            assert!(profile_column_ordinals.last() < indicator_column_ordinals.first());
            if let Some(preceding_last_column) = preceding_option_last_column {
                assert!(Some(&preceding_last_column) < profile_column_ordinals.first());
            }
            preceding_option_last_column = indicator_column_ordinals.last().copied();
        }
        assert_eq!(
            fused_encoder_instructions.len(),
            PAIR_CHARACTER_CIPHERTEXT_COUNT * (PAIR_CHARACTER_AUXILIARY_COUNT - 1),
        );
        let mut fused_identity_coordinates = BTreeSet::new();
        for (coefficient_period, ordered_terms) in fused_encoder_instructions {
            assert_eq!(usize::from(coefficient_period), PAIR_CHARACTER_LANE_COUNT);
            assert_eq!(ordered_terms.len(), OPTION_COUNT * SCORE_BUCKET_COUNT);
            assert!(strictly_sorted_unique(ordered_terms));
            let mut covered_score_coordinates = BTreeSet::new();
            let mut identity_coordinates = None;
            for term in ordered_terms {
                assert!(
                    term.verifier_sequence_column_ordinal < term.constant_column_ordinal,
                    "each option's four profiles must precede its ten indicators",
                );
                let BallotValidityWitnessValueSource::ScoreIndicator {
                    option_ordinal,
                    score_bucket_ordinal,
                } = compilation
                    .source_plan()
                    .recipe(term.constant_column_ordinal)
                    .expect("constant score-indicator recipe")
                    .value_source()
                else {
                    panic!("fused encoder term must use a score indicator");
                };
                let BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                    ciphertext_ordinal,
                    auxiliary_ordinal,
                    option_ordinal: profile_option_ordinal,
                } = compilation
                    .source_plan()
                    .verifier_source(term.verifier_sequence_column_ordinal)
                    .expect("deterministic encoder profile")
                else {
                    panic!("fused encoder term must use a pair-character profile");
                };
                assert_eq!(profile_option_ordinal, option_ordinal);
                let expected_score = MINIMUM_SCORE + u64::from(score_bucket_ordinal);
                let (expected_rotation_is_negative, expected_rotation_magnitude) =
                    match auxiliary_ordinal {
                        0 => (true, expected_score + MAXIMUM_SCORE - MINIMUM_SCORE),
                        1 => (false, expected_score),
                        _ => panic!("unknown pair-character auxiliary"),
                    };
                assert_eq!(
                    term.verifier_sequence_rotation_is_negative,
                    expected_rotation_is_negative,
                );
                assert_eq!(
                    term.verifier_sequence_rotation_magnitude,
                    expected_rotation_magnitude,
                );
                assert!(covered_score_coordinates.insert((option_ordinal, score_bucket_ordinal)));
                assert_eq!(
                    identity_coordinates.get_or_insert((ciphertext_ordinal, auxiliary_ordinal)),
                    &(ciphertext_ordinal, auxiliary_ordinal),
                );
            }
            assert_eq!(
                covered_score_coordinates.len(),
                OPTION_COUNT * SCORE_BUCKET_COUNT
            );
            assert!(fused_identity_coordinates.insert(
                identity_coordinates.expect("a fused encoder identity has deterministic terms")
            ));
        }
        assert_eq!(
            fused_identity_coordinates,
            (0..PAIR_CHARACTER_CIPHERTEXT_COUNT)
                .flat_map(|ciphertext_ordinal| {
                    (0..PAIR_CHARACTER_AUXILIARY_COUNT - 1).map(move |auxiliary_ordinal| {
                        (
                            u16::try_from(ciphertext_ordinal).unwrap(),
                            u16::try_from(auxiliary_ordinal).unwrap(),
                        )
                    })
                })
                .collect::<BTreeSet<_>>(),
        );

        let typed_expression_modulus_multiples = variant
            .ordered_constraints
            .iter()
            .flat_map(|constraint| &constraint.numerator_postfix_expression)
            .filter_map(|instruction| match instruction {
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier,
                } => Some((*modulus_reference, *multiplier)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert!(
            typed_expression_modulus_multiples.contains(&(SuiteModulusReference::plaintext(), 1,))
        );
        assert!(typed_expression_modulus_multiples.contains(&(SuiteModulusReference::data(0), 1,)));
        assert!(variant.ordered_radix_convolutions.is_empty());
        assert_eq!(
            variant.ordered_integer_lift_batches.len(),
            2 * usize::from(context.non_native_theta_repetition_count)
        );
        assert!(variant.ordered_integer_lift_batches.iter().all(|batch| {
            batch
                .theta_bad_polynomial_degree(variant.trace_domain_size)
                .expect("the exact ballot theta degree derives")
                == 65_534
        }));
        let semantically_certified_columns = variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| cell.column_ordinal)
            .collect::<BTreeSet<_>>();
        let batch = variant
            .ordered_integer_lift_batches
            .iter()
            .find(|batch| batch.modulus_reference == SuiteModulusReference::data(0))
            .expect("data-modulus encryption batch");
        assert_eq!(batch.modulus_reference, SuiteModulusReference::data(0));
        assert_eq!(batch.challenge_ordinal, 0);
        assert_eq!(batch.ordered_components.len(), 4);
        assert!(batch.ordered_reversed_column_bindings.is_empty());
        assert!(batch.ordered_components.iter().all(|component| {
            component.ordered_linear_terms.iter().any(|term| {
                term.negative
                    && matches!(
                        term.coefficient,
                        RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference,
                            multiplier: 1,
                        } if modulus_reference == batch.modulus_reference
                    )
            }) && component.ordered_convolution_products.len() == 1
                && component.ordered_convolution_products[0].negative
                && component.ordered_convolution_products[0].convolution_kind
                    == RelationIntegerLiftConvolutionKind::Negacyclic
                && component.ordered_convolution_products[0].multiplier_offset == 1
                && semantically_certified_columns.contains(
                    &component.ordered_convolution_products[0].reversed_multiplier_column_ordinal,
                )
        }));
        let product_batch = variant
            .ordered_integer_lift_batches
            .iter()
            .find(|batch| batch.modulus_reference == SuiteModulusReference::plaintext())
            .expect("plaintext pair-character product batch");
        assert_eq!(product_batch.ordered_components.len(), 2);
        assert_eq!(product_batch.ordered_reversed_column_bindings.len(), 2);
        assert!(
            product_batch
                .ordered_reversed_column_bindings
                .iter()
                .all(|binding| {
                    let source_semantic_cell = variant
                        .ordered_semantic_cells
                        .iter()
                        .find(|cell| cell.column_ordinal == binding.source_column_ordinal)
                        .expect("the pair-character source has a canonical plaintext bound");
                    base_tree_columns.contains(&binding.reversed_column_ordinal)
                        && source_semantic_cell.claimed_interval
                            == SignedIntegerInterval::new(0, 256)
                        && !semantically_certified_columns
                            .contains(&binding.reversed_column_ordinal)
                        && variant.ordered_columns[binding.reversed_column_ordinal as usize]
                            .canonical_residue_modulus
                            .is_none()
                        && compilation
                            .source_plan()
                            .recipe(binding.reversed_column_ordinal)
                            .is_none()
                })
        );
        assert!(product_batch.ordered_components.iter().all(|component| {
            component.ordered_convolution_products.len() == 1
                && component.ordered_convolution_products[0].negative
                && component.ordered_convolution_products[0].convolution_kind
                    == RelationIntegerLiftConvolutionKind::Negacyclic
                && component.ordered_convolution_products[0].multiplier_offset == 0
        }));

        let non_native_challenges = variant
            .derived_relation_prefix_challenge_catalog(&context)
            .expect("challenge derivation must succeed")
            .into_iter()
            .filter(|challenge| {
                matches!(
                    challenge.role,
                    RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(context.non_native_theta_repetition_count, 5);
        assert_eq!(
            non_native_challenges.len(),
            2 * usize::from(context.non_native_theta_repetition_count)
        );
        assert_eq!(
            non_native_challenges
                .iter()
                .filter(|challenge| challenge.role == RelationChallengeRole::NonNativeTheta)
                .map(|challenge| challenge.role_coordinates.clone())
                .collect::<Vec<_>>(),
            (0_u64..2)
                .flat_map(|modulus_ordinal| {
                    (0..u64::from(context.non_native_theta_repetition_count))
                        .map(move |repetition_ordinal| vec![modulus_ordinal, repetition_ordinal])
                })
                .collect::<Vec<_>>()
        );
        assert!(
            non_native_challenges
                .iter()
                .all(|challenge| challenge.role != RelationChallengeRole::NonNativeAlpha)
        );
        assert!(non_native_challenges.iter().all(|challenge| matches!(
            challenge.sampling,
            RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::BaseField,
                coordinate_count: 5,
                maximum_candidate_draws_per_output: 128,
            }
        )));
        let mut truncated_plaintext_theta = non_native_challenges
            .iter()
            .find(|challenge| challenge.role_coordinates == vec![1, 0])
            .expect("the plaintext theta descriptor exists")
            .clone();
        truncated_plaintext_theta.sampling =
            RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(1),
                coordinate_count: context.non_native_theta_repetition_count,
                maximum_candidate_draws_per_output: 128,
            };
        assert_eq!(
            truncated_plaintext_theta.validate(variant, &context),
            Err(RelationPlanError::InvalidChallengeCatalog),
            "the catalog must reject the removed arithmetic-modulus theta domain",
        );
        assert_eq!(
            context
                .resolved_modulus(SuiteModulusReference::plaintext())
                .expect("the plaintext arithmetic modulus resolves"),
            257
        );

        let relation_prefix_schedule = variant
            .common_proof_relation_prefix_schedule(&context)
            .expect("the exact ballot relation-prefix schedule derives");
        assert_eq!(
            relation_prefix_schedule
                .ordered_application_challenge_groups()
                .len(),
            2
        );
        assert!(
            relation_prefix_schedule
                .ordered_application_challenge_groups()
                .iter()
                .all(|group| {
                    matches!(group.challenge(), CommonProofChallenge::Theta { .. })
                        && group.modulus() == PROOF_BASE_FIELD_MODULUS
                        && group.coordinate_count() == context.non_native_theta_repetition_count
                })
        );
        let derive_assignments = || {
            let mut transcript = CommonProofTranscript::new_relation_prefix(
                1,
                [0x31; 64],
                [0x47; 64],
                BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                b"exact-ballot-theta-vector",
                relation_prefix_schedule.clone(),
            )
            .expect("the exact ballot transcript initializes");
            for tree_ordinal in relation_prefix_schedule.ordered_base_tree_ordinals() {
                transcript
                    .absorb_base_root(*tree_ordinal, [*tree_ordinal as u8; 64])
                    .expect("the exact ballot base root is ordered");
            }
            let assignments =
                sample_relation_application_challenges(&mut transcript, &relation_prefix_schedule)
                    .expect("the exact ballot theta vectors derive");
            for tree_ordinal in relation_prefix_schedule.ordered_auxiliary_tree_ordinals() {
                transcript
                    .absorb_auxiliary_root(*tree_ordinal, [*tree_ordinal as u8; 64])
                    .expect("the exact ballot auxiliary root follows theta");
            }
            (assignments, transcript.transcript_state_for_test())
        };
        let first_derivation = derive_assignments();
        let second_derivation = derive_assignments();
        assert_eq!(first_derivation, second_derivation);
        assert_eq!(
            first_derivation.0.len(),
            2 * usize::from(context.non_native_theta_repetition_count)
        );
        assert!(
            first_derivation
                .0
                .iter()
                .all(|assignment| assignment.value() < PROOF_BASE_FIELD_MODULUS)
        );
        assert!(
            first_derivation
                .0
                .iter()
                .any(|assignment| assignment.value() > 256),
            "the full-field theta vector must not be truncated to the plaintext modulus"
        );

        let prover_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(column_ordinal, column)| {
                matches!(column.origin, RelationColumnOrigin::Prover)
                    .then_some(column_ordinal as u32)
            })
            .collect::<BTreeSet<_>>();
        let masked_columns = variant
            .ordered_masks
            .iter()
            .filter_map(|mask| {
                (mask.mask_kind == RelationMaskKind::Trace
                    && mask.target_class == RelationMaskTargetClass::Column)
                    .then_some(mask.target_ordinal)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(masked_columns, prover_columns);
        let maximum_translated_opening_count = prover_columns
            .iter()
            .map(|column_ordinal| {
                variant
                    .ordered_opening_claims
                    .iter()
                    .filter(|claim| {
                        claim.source_class == RelationOpeningSourceClass::TreeColumn
                            && claim.column_ordinal == Some(*column_ordinal)
                    })
                    .count()
            })
            .max()
            .expect("the secret-bearing plan has prover columns");
        let expected_trace_mask_degree = u64::from(context.challenge_extension_degree)
            * u64::try_from(maximum_translated_opening_count).expect("the opening count fits u64")
            + u64::from(context.phase_column_query_coordinate_count);
        assert!(expected_trace_mask_degree > 0 && expected_trace_mask_degree <= TEST_RING_DEGREE);
        let construction_trace_mask_degree = variant
            .ordered_masks
            .iter()
            .find(|mask| mask.mask_kind == RelationMaskKind::Trace)
            .expect("the secret-bearing plan has trace masks")
            .mask_degree_bound_exclusive;
        assert!(construction_trace_mask_degree >= expected_trace_mask_degree);
        assert!(variant.ordered_masks.iter().all(|mask| {
            mask.mask_kind != RelationMaskKind::Trace
                || mask.mask_degree_bound_exclusive == construction_trace_mask_degree
        }));
        assert!(variant.ordered_columns.iter().all(|column| {
            !matches!(column.origin, RelationColumnOrigin::Prover)
                || column.source_degree_bound_exclusive
                    == TEST_RING_DEGREE + construction_trace_mask_degree
        }));

        let tuple = compiled
            .canonical_tuple()
            .expect("the generated relation tuple must encode");
        assert_eq!(
            compiled
                .canonical_bytes()
                .expect("the generated relation bytes must encode"),
            compiled
                .encode_canonical_tuple(&tuple)
                .expect("encoding the generated tuple must be deterministic")
        );
    }

    #[test]
    fn rotated_pair_character_encoder_profiles_reconstruct_all_four_auxiliaries() {
        let context = check_context();
        let compilation = compile_ballot_validity_relation(&relation_input(), &context)
            .expect("the direct ballot relation must compile");
        let source_plan = compilation.source_plan();
        let scores = [1_u64, 10, 2, 9, 3, 8, 4, 7, 5, 6];
        let plaintexts = pair_character_plaintexts(
            &scores,
            source_plan.plaintext_modulus(),
            usize::try_from(source_plan.ring_degree()).unwrap(),
        )
        .expect("the bounded scores must encode");
        assert!(source_plan.encoder_profile_sequence(2, 0, 0).is_none());
        assert!(source_plan.encoder_profile_sequence(0, 2, 0).is_none());
        assert!(
            source_plan
                .encoder_profile_sequence(0, 0, u16::try_from(scores.len()).unwrap())
                .is_none()
        );

        for (ciphertext_ordinal, plaintext) in plaintexts.iter().enumerate() {
            for (auxiliary_ordinal, auxiliary_coefficients) in [
                plaintext.auxiliary_left_coefficients(),
                plaintext.auxiliary_right_coefficients(),
            ]
            .into_iter()
            .enumerate()
            {
                let reductions = source_plan
                    .encoder_reductions_for_scores(
                        &scores,
                        u16::try_from(ciphertext_ordinal).unwrap(),
                        u16::try_from(auxiliary_ordinal).unwrap(),
                        auxiliary_coefficients,
                    )
                    .expect("the exact integer reductions must exist");
                let selected_profiles = scores
                    .iter()
                    .enumerate()
                    .map(|(option_ordinal, _)| {
                        source_plan
                            .encoder_profile_sequence(
                                u16::try_from(ciphertext_ordinal).unwrap(),
                                u16::try_from(auxiliary_ordinal).unwrap(),
                                u16::try_from(option_ordinal).unwrap(),
                            )
                            .expect("selected encoder profile")
                    })
                    .collect::<Vec<_>>();
                for coefficient_ordinal in 0..usize::try_from(TEST_RING_DEGREE).unwrap() {
                    let weighted_sum = selected_profiles.iter().zip(scores.iter().copied()).fold(
                        0_u128,
                        |sum, (encoder_profile, score)| {
                            sum + u128::from(
                                rotated_encoder_profile_value(
                                    encoder_profile,
                                    auxiliary_ordinal,
                                    usize::try_from(score - MINIMUM_SCORE).unwrap(),
                                    coefficient_ordinal,
                                )
                                .expect("rotated profile value"),
                            )
                        },
                    );
                    assert_eq!(
                        weighted_sum,
                        u128::from(auxiliary_coefficients[coefficient_ordinal])
                            + u128::from(TEST_PLAINTEXT_MODULUS)
                                * u128::from(reductions[coefficient_ordinal]),
                        "ciphertext {ciphertext_ordinal}, auxiliary {auxiliary_ordinal}, coefficient {coefficient_ordinal}"
                    );
                }
            }
        }
    }

    #[test]
    fn ballot_geometry_rejects_noncanonical_or_inexact_encoder_domains() {
        let context = check_context();

        let mut insufficient_pair_slots = relation_input();
        insufficient_pair_slots.ring_degree = 128;
        assert_eq!(
            compile_ballot_validity_relation_plan(&insufficient_pair_slots, &context),
            Err(RelationPlanError::InvalidDomain)
        );

        let mut noncanonical_data_basis = relation_input();
        noncanonical_data_basis.active_data_modulus_indices = vec![1];
        assert_eq!(
            compile_ballot_validity_relation_plan(&noncanonical_data_basis, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut unknown_reserved_slot_rule = relation_input();
        unknown_reserved_slot_rule.reserved_slot_rule = RESERVED_SLOT_RULE + 1;
        assert_eq!(
            compile_ballot_validity_relation_plan(&unknown_reserved_slot_rule, &context),
            Err(RelationPlanError::InvalidDomain)
        );
    }
}
