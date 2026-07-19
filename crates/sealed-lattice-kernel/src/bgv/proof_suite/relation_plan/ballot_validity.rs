use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use super::*;
use crate::foundation::FOUNDATION_PROFILE;

const BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
const VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL: u64 = 7;
const BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL: u64 = 8;
const OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
const MINIMUM_SCORE: u64 = FOUNDATION_PROFILE.minimum_score as u64;
const MAXIMUM_SCORE: u64 = FOUNDATION_PROFILE.maximum_score as u64;
const RESERVED_SLOT_RULE: u16 = 1;
const RADIX: u64 = 3;

/// One exact ballot witness vector from which a genuine pre-challenge source
/// column is derived. Public-key and ciphertext columns are verifier sequences
/// and therefore never enter this catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BallotValidityWitnessValueSource {
    ScoreOffset {
        option_ordinal: u16,
    },
    PlaintextCoefficient,
    ReversedRandomizerShifted,
    ErrorZeroShifted,
    ErrorOneShifted,
    EncoderReduction,
    EncryptionQuotient {
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
    primitive_two_n_root: u64,
    slot_generator: u16,
    inverse_ring_degree: u64,
    pair_slot_inverse_roots: Box<[u64]>,
    encoder_reduction_maximum: u64,
    recipes_by_column: Box<[Option<BallotValiditySourceColumnRecipe>]>,
    verifier_sources_by_column: Box<[Option<BallotValidityVerifierColumnSource>]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BallotValidityVerifierColumnSource {
    AuthenticatedPolynomial {
        source_kind: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
    },
    PairDifferenceEncoderWeight {
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
                self.pair_slot_inverse_roots.len(),
                core::mem::size_of::<u64>(),
            )?,
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

    pub(crate) const fn primitive_two_n_root(&self) -> u64 {
        self.primitive_two_n_root
    }

    pub(crate) const fn slot_generator(&self) -> u16 {
        self.slot_generator
    }

    pub(crate) fn encoder_weight_sequence(&self, option_ordinal: u16) -> Option<Vec<u64>> {
        let option_index = usize::from(option_ordinal);
        if option_index >= OPTION_COUNT {
            return None;
        }
        let mut cursor = self.encoder_weight_cursor()?;
        let mut sequence = Vec::with_capacity(usize::try_from(self.ring_degree).ok()?);
        while let Some(row) = cursor.next_row() {
            sequence.push(row[option_index]);
        }
        Some(sequence)
    }

    pub(crate) fn plaintext_coefficients_for_scores(&self, scores: &[u64]) -> Option<Vec<u64>> {
        if scores.len() != OPTION_COUNT
            || scores
                .iter()
                .any(|score| !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(score))
        {
            return None;
        }
        let mut cursor = self.encoder_weight_cursor()?;
        let mut coefficients = Vec::with_capacity(usize::try_from(self.ring_degree).ok()?);
        while let Some(row) = cursor.next_row() {
            let coefficient = scores.iter().zip(row).fold(0_u64, |sum, (score, weight)| {
                let score_offset = score - MINIMUM_SCORE;
                modular_sum(
                    sum,
                    modular_product(score_offset, weight, self.plaintext_modulus),
                    self.plaintext_modulus,
                )
            });
            coefficients.push(coefficient);
        }
        Some(coefficients)
    }

    pub(crate) fn encoder_reductions_for_scores(
        &self,
        scores: &[u64],
        plaintext_coefficients: &[u64],
    ) -> Option<Vec<u64>> {
        if scores.len() != OPTION_COUNT
            || plaintext_coefficients.len() != usize::try_from(self.ring_degree).ok()?
        {
            return None;
        }
        let mut cursor = self.encoder_weight_cursor()?;
        let mut reductions = Vec::with_capacity(plaintext_coefficients.len());
        for plaintext_coefficient in plaintext_coefficients.iter().copied() {
            let row = cursor.next_row()?;
            let weighted_sum =
                scores
                    .iter()
                    .zip(row)
                    .try_fold(0_u128, |sum, (score, weight)| {
                        sum.checked_add(u128::from(score - MINIMUM_SCORE) * u128::from(weight))
                    })?;
            let numerator = weighted_sum.checked_sub(u128::from(plaintext_coefficient))?;
            if !numerator.is_multiple_of(u128::from(self.plaintext_modulus)) {
                return None;
            }
            let reduction = u64::try_from(numerator / u128::from(self.plaintext_modulus)).ok()?;
            if reduction > self.encoder_reduction_maximum {
                return None;
            }
            reductions.push(reduction);
        }
        (cursor.next_row().is_none()).then_some(reductions)
    }

    fn encoder_weight_cursor(&self) -> Option<PairDifferenceEncoderWeightCursor<'_>> {
        PairDifferenceEncoderWeightCursor::new(
            self.ring_degree,
            self.plaintext_modulus,
            self.inverse_ring_degree,
            &self.pair_slot_inverse_roots,
        )
    }

    pub(crate) const fn encoder_reduction_maximum(&self) -> u64 {
        self.encoder_reduction_maximum
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

    pub(crate) fn has_source(&self, column_ordinal: u32) -> bool {
        self.recipe(column_ordinal).is_some() || self.verifier_source(column_ordinal).is_some()
    }

    pub(crate) fn column_count(&self) -> usize {
        self.recipes_by_column.len()
    }

    pub(crate) fn provided_column_count(&self) -> usize {
        (0..self.recipes_by_column.len())
            .filter(|column_index| {
                self.recipes_by_column[*column_index].is_some()
                    || self.verifier_sources_by_column[*column_index].is_some()
            })
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
            self.pair_slot_inverse_roots
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
    pub(crate) primitive_two_n_root: u64,
    pub(crate) slot_generator: u16,
    pub(crate) reserved_slot_rule: u16,
}

#[derive(Clone, Debug)]
struct ValidatedBallotGeometry {
    data_moduli: Vec<u64>,
    inverse_ring_degree: u64,
    pair_slot_inverse_roots: Vec<u64>,
    encoder_reduction_maximum: u64,
}

struct PairDifferenceEncoderWeightCursor<'roots> {
    ring_degree: u64,
    plaintext_modulus: u64,
    pair_slot_inverse_roots: &'roots [u64],
    current_pair_slot_weights: Vec<u64>,
    coefficient_ordinal: u64,
}

impl<'roots> PairDifferenceEncoderWeightCursor<'roots> {
    fn new(
        ring_degree: u64,
        plaintext_modulus: u64,
        inverse_ring_degree: u64,
        pair_slot_inverse_roots: &'roots [u64],
    ) -> Option<Self> {
        if ring_degree < u64::try_from(PAIR_COUNT).ok()?
            || plaintext_modulus < 2
            || inverse_ring_degree >= plaintext_modulus
            || pair_slot_inverse_roots.len() != PAIR_COUNT
            || pair_slot_inverse_roots
                .iter()
                .any(|root| *root == 0 || *root >= plaintext_modulus)
        {
            return None;
        }
        Some(Self {
            ring_degree,
            plaintext_modulus,
            pair_slot_inverse_roots,
            current_pair_slot_weights: vec![inverse_ring_degree; PAIR_COUNT],
            coefficient_ordinal: 0,
        })
    }

    fn next_row(&mut self) -> Option<[u64; OPTION_COUNT]> {
        if self.coefficient_ordinal >= self.ring_degree {
            return None;
        }
        let mut option_weights = [0_u64; OPTION_COUNT];
        let mut pair_slot_ordinal = 0_usize;
        for shift in 1..OPTION_COUNT {
            for lower_option_ordinal in 0..OPTION_COUNT - shift {
                let higher_option_ordinal = lower_option_ordinal + shift;
                let weight = self.current_pair_slot_weights[pair_slot_ordinal];
                option_weights[lower_option_ordinal] = modular_sum(
                    option_weights[lower_option_ordinal],
                    weight,
                    self.plaintext_modulus,
                );
                option_weights[higher_option_ordinal] = modular_difference_residue(
                    option_weights[higher_option_ordinal],
                    weight,
                    self.plaintext_modulus,
                );
                pair_slot_ordinal += 1;
            }
        }
        for (weight, inverse_root) in self
            .current_pair_slot_weights
            .iter_mut()
            .zip(self.pair_slot_inverse_roots)
        {
            *weight = modular_product(*weight, *inverse_root, self.plaintext_modulus);
        }
        self.coefficient_ordinal += 1;
        Some(option_weights)
    }
}

impl BallotValidityRelationPlanInput {
    fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<ValidatedBallotGeometry, RelationPlanError> {
        RelationPlanChecker::new(context).check_context()?;
        if self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
            || self.ring_degree < u64::try_from(PAIR_COUNT).unwrap_or(u64::MAX)
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.active_data_modulus_indices.is_empty()
            || self.plaintext_modulus < 3
            || self.primitive_two_n_root == 0
            || self.primitive_two_n_root >= self.plaintext_modulus
            || self.slot_generator < 2
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

        let two_n = self
            .ring_degree
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        if modular_power(self.primitive_two_n_root, two_n, self.plaintext_modulus) != 1
            || modular_power(
                self.primitive_two_n_root,
                self.ring_degree,
                self.plaintext_modulus,
            ) == 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        validate_slot_generator(self.ring_degree, self.slot_generator)?;

        let inverse_ring_degree = modular_inverse(
            self.ring_degree % self.plaintext_modulus,
            self.plaintext_modulus,
        )?;
        let positive_slot_count = self.ring_degree / 2;
        let mut pair_slot_inverse_roots = Vec::with_capacity(PAIR_COUNT);
        for pair_slot_ordinal in 0..PAIR_COUNT {
            let pair_slot_ordinal =
                u64::try_from(pair_slot_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            let positive_slot_ordinal = pair_slot_ordinal % positive_slot_count;
            let positive_slot_exponent =
                modular_power(u64::from(self.slot_generator), positive_slot_ordinal, two_n);
            let slot_exponent = if pair_slot_ordinal < positive_slot_count {
                positive_slot_exponent
            } else {
                two_n - positive_slot_exponent
            };
            let slot_root = modular_power(
                self.primitive_two_n_root,
                slot_exponent,
                self.plaintext_modulus,
            );
            pair_slot_inverse_roots.push(modular_inverse(slot_root, self.plaintext_modulus)?);
        }

        let mut encoder_reduction_maximum = 0_u64;
        let mut encoder_weight_cursor = PairDifferenceEncoderWeightCursor::new(
            self.ring_degree,
            self.plaintext_modulus,
            inverse_ring_degree,
            &pair_slot_inverse_roots,
        )
        .ok_or(RelationPlanError::InvalidDomain)?;
        while let Some(option_weights) = encoder_weight_cursor.next_row() {
            let weight_sum = option_weights.iter().try_fold(0_u128, |sum, weight| {
                sum.checked_add(u128::from(*weight))
                    .ok_or(RelationPlanError::IntegerBoundOverflow)
            })?;
            let reduction = u64::try_from(
                u128::from(MAXIMUM_SCORE - MINIMUM_SCORE)
                    .checked_mul(weight_sum)
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?
                    / u128::from(self.plaintext_modulus),
            )
            .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
            encoder_reduction_maximum = encoder_reduction_maximum.max(reduction);
        }
        if encoder_reduction_maximum == 0 {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }

        Ok(ValidatedBallotGeometry {
            data_moduli,
            inverse_ring_degree,
            pair_slot_inverse_roots,
            encoder_reduction_maximum,
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
        component_ordinal: u16,
        data_modulus_index: u16,
    },
    PairDifferenceEncoderWeight {
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
    ciphertext_component_zero: u32,
    ciphertext_component_one: u32,
}

#[derive(Clone, Copy)]
struct EncryptionQuotientColumns {
    component_zero: u32,
    component_one: u32,
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
        match phase {
            ProofTreePhase::Base => self.base_tree_columns.push(column_ordinal),
            ProofTreePhase::Auxiliary => self.auxiliary_tree_columns.push(column_ordinal),
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
                component_ordinal,
                data_modulus_index,
            },
            BallotVerifierSourceKey::Ciphertext {
                component_ordinal,
                data_modulus_index,
            } => BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
                source_kind: 2,
                component_ordinal,
                data_modulus_index,
            },
            BallotVerifierSourceKey::PairDifferenceEncoderWeight { option_ordinal } => {
                BallotValidityVerifierColumnSource::PairDifferenceEncoderWeight { option_ordinal }
            }
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

    fn trace_root(&self, row_ordinal: u64) -> Result<u64, RelationPlanError> {
        if row_ordinal >= self.input.ring_degree
            || !self
                .input
                .evaluation_domain_size
                .is_multiple_of(self.input.ring_degree)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let trace_generator = modular_power(
            self.context.evaluation_domain_generator,
            self.input.evaluation_domain_size / self.input.ring_degree,
            self.context.base_field_modulus,
        );
        Ok(modular_power(
            trace_generator,
            row_ordinal,
            self.context.base_field_modulus,
        ))
    }

    fn point_zeroifier(
        &self,
        row_ordinal: u64,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        let root = self.trace_root(row_ordinal)?;
        Ok(vec![
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(root),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ])
    }

    fn trace_except_rows_zeroifier(
        &self,
        excluded_rows: &[u64],
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        if excluded_rows.is_empty() {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        let mut excluded_roots = excluded_rows
            .iter()
            .copied()
            .map(|row_ordinal| self.trace_root(row_ordinal))
            .collect::<Result<Vec<_>, _>>()?;
        excluded_roots.sort_unstable();
        if !strictly_sorted_unique(&excluded_roots) {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        Ok(vec![
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size: self.input.ring_degree,
                ordered_excluded_roots: excluded_roots,
            },
        ])
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
        let ciphertext_component_zero = self.push_verifier_column(
            BallotVerifierSourceKey::Ciphertext {
                component_ordinal: 0,
                data_modulus_index,
            },
            modulus_reference,
        )?;
        let ciphertext_component_one = self.push_verifier_column(
            BallotVerifierSourceKey::Ciphertext {
                component_ordinal: 1,
                data_modulus_index,
            },
            modulus_reference,
        )?;
        Ok(PublicDataLimbColumns {
            public_key_component_zero,
            public_key_component_one,
            ciphertext_component_zero,
            ciphertext_component_one,
        })
    }

    fn add_score_and_encoder_columns(
        &mut self,
    ) -> Result<(Vec<BoundedUnsignedColumn>, Vec<u32>), RelationPlanError> {
        let score_offset_maximum = MAXIMUM_SCORE
            .checked_sub(MINIMUM_SCORE)
            .ok_or(RelationPlanError::InvalidBoundCertificate)?;
        let mut score_offsets = Vec::with_capacity(OPTION_COUNT);
        let mut encoder_weight_columns = Vec::with_capacity(OPTION_COUNT);
        for option_ordinal in 0..OPTION_COUNT {
            let score_offset =
                self.add_bounded_unsigned_column(score_offset_maximum, ProofTreePhase::Base)?;
            let option_ordinal_u16 =
                u16::try_from(option_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            self.assign_bounded_unsigned_source_recipes(
                &score_offset,
                score_offset_maximum,
                BallotValidityWitnessValueSource::ScoreOffset {
                    option_ordinal: option_ordinal_u16,
                },
            )?;
            self.add_full_trace_constraint(
                subtract_rotated_columns(
                    score_offset.target_column_ordinal,
                    false,
                    1,
                    score_offset.target_column_ordinal,
                    false,
                    0,
                ),
                true,
            )?;
            score_offsets.push(score_offset);

            let encoder_weight_column = self.push_verifier_column(
                BallotVerifierSourceKey::PairDifferenceEncoderWeight {
                    option_ordinal: option_ordinal_u16,
                },
                SuiteModulusReference::plaintext(),
            )?;
            encoder_weight_columns.push(encoder_weight_column);
        }
        Ok((score_offsets, encoder_weight_columns))
    }

    fn add_exact_encoder_identity(
        &mut self,
        score_offsets: &[BoundedUnsignedColumn],
        encoder_weight_columns: &[u32],
        plaintext_coefficients: &BoundedUnsignedColumn,
        encoder_reduction: &BoundedUnsignedColumn,
    ) -> Result<(), RelationPlanError> {
        if score_offsets.len() != OPTION_COUNT || encoder_weight_columns.len() != OPTION_COUNT {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut terms = Vec::with_capacity(OPTION_COUNT * 2 + 2);
        for (score_offset, encoder_weight_column) in
            score_offsets.iter().zip(encoder_weight_columns)
        {
            terms.push(IntegerTerm {
                expression: vec![
                    unrotated_column_expression(*encoder_weight_column),
                    unrotated_column_expression(score_offset.target_column_ordinal),
                    RelationExpressionInstruction::Multiplication,
                ],
                negative: false,
            });
        }
        terms.push(integer_column_term(
            plaintext_coefficients.target_column_ordinal,
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
        let component_zero =
            self.add_signed_integer_column(absolute_bound, ProofTreePhase::Base)?;
        self.assign_signed_integer_source_recipes(
            component_zero,
            absolute_bound,
            BallotValidityWitnessValueSource::EncryptionQuotient {
                data_modulus_index,
                component_ordinal: 0,
            },
        )?;
        let component_one = self.add_signed_integer_column(absolute_bound, ProofTreePhase::Base)?;
        self.assign_signed_integer_source_recipes(
            component_one,
            absolute_bound,
            BallotValidityWitnessValueSource::EncryptionQuotient {
                data_modulus_index,
                component_ordinal: 1,
            },
        )?;
        Ok(EncryptionQuotientColumns {
            component_zero,
            component_one,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn add_integer_lift_batch(
        &mut self,
        modulus_ordinal: usize,
        challenge_ordinal: u16,
        public_columns: &PublicDataLimbColumns,
        quotient_columns: EncryptionQuotientColumns,
        plaintext_coefficients: &BoundedUnsignedColumn,
        reversed_randomizer_shifted: &BoundedUnsignedColumn,
        error_zero_shifted: &BoundedUnsignedColumn,
        error_one_shifted: &BoundedUnsignedColumn,
    ) -> Result<(), RelationPlanError> {
        let modulus_reference = self
            .ordered_non_native_moduli
            .get(modulus_ordinal)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)?;
        let mut components = Vec::with_capacity(2);
        for (
            ciphertext_column_ordinal,
            public_key_column_ordinal,
            quotient_column_ordinal,
            error_column_ordinal,
            include_plaintext,
        ) in [
            (
                public_columns.ciphertext_component_zero,
                public_columns.public_key_component_zero,
                quotient_columns.component_zero,
                error_zero_shifted.target_column_ordinal,
                true,
            ),
            (
                public_columns.ciphertext_component_one,
                public_columns.public_key_component_one,
                quotient_columns.component_one,
                error_one_shifted.target_column_ordinal,
                false,
            ),
        ] {
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
            if include_plaintext {
                ordered_linear_terms.push(RelationIntegerLiftLinearTermDescriptor {
                    negative: true,
                    column_ordinal: plaintext_coefficients.target_column_ordinal,
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
                    reversed_multiplier_column_ordinal: reversed_randomizer_shifted
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

        let (score_offsets, encoder_weight_columns) = self.add_score_and_encoder_columns()?;
        let plaintext_coefficients = self.add_canonical_modulus_column(
            SuiteModulusReference::plaintext(),
            ProofTreePhase::Base,
        )?;
        self.assign_canonical_modulus_source_recipes(
            &plaintext_coefficients,
            SuiteModulusReference::plaintext(),
            BallotValidityWitnessValueSource::PlaintextCoefficient,
        )?;
        let reversed_randomizer_shifted =
            self.add_bounded_unsigned_column(2, ProofTreePhase::Base)?;
        self.assign_bounded_unsigned_source_recipes(
            &reversed_randomizer_shifted,
            2,
            BallotValidityWitnessValueSource::ReversedRandomizerShifted,
        )?;
        let error_zero_shifted = self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?;
        self.assign_bounded_unsigned_source_recipes(
            &error_zero_shifted,
            4,
            BallotValidityWitnessValueSource::ErrorZeroShifted,
        )?;
        let error_one_shifted = self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?;
        self.assign_bounded_unsigned_source_recipes(
            &error_one_shifted,
            4,
            BallotValidityWitnessValueSource::ErrorOneShifted,
        )?;
        let encoder_reduction = self.add_bounded_unsigned_column(
            self.geometry.encoder_reduction_maximum,
            ProofTreePhase::Base,
        )?;
        self.assign_bounded_unsigned_source_recipes(
            &encoder_reduction,
            self.geometry.encoder_reduction_maximum,
            BallotValidityWitnessValueSource::EncoderReduction,
        )?;
        self.add_exact_encoder_identity(
            &score_offsets,
            &encoder_weight_columns,
            &plaintext_coefficients,
            &encoder_reduction,
        )?;

        for (modulus_ordinal, (public_columns, quotient_columns)) in public_limb_columns
            .iter()
            .zip(quotient_limb_columns.iter().copied())
            .enumerate()
        {
            for challenge_ordinal in 0..self.context.non_native_modular_identity_challenge_count {
                self.add_integer_lift_batch(
                    modulus_ordinal,
                    challenge_ordinal,
                    public_columns,
                    quotient_columns,
                    &plaintext_coefficients,
                    &reversed_randomizer_shifted,
                    &error_zero_shifted,
                    &error_one_shifted,
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
                && base_tree_column_set.contains(&column_ordinal);
            let expects_verifier_source =
                matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    && base_tree_column_set.contains(&column_ordinal);
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
        let trace_mask_degree_bound_exclusive = self
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
                let translated_opening_count = u64::from(self.context.deep_point_count)
                    .checked_mul(
                        u64::try_from(distinct_rotation_count)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?;
                let view_count = u64::from(self.context.challenge_extension_degree)
                    .checked_mul(translated_opening_count)
                    .and_then(|count| {
                        count.checked_add(
                            2_u64.checked_mul(u64::from(self.context.unique_query_count))?,
                        )
                    })
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                view_count
                    .checked_mul(2)
                    .ok_or(RelationPlanError::DegreeBoundExceeded)
            })
            .collect::<Result<Vec<_>, RelationPlanError>>()?
            .into_iter()
            .max()
            .filter(|degree| *degree != 0 && *degree <= self.input.ring_degree)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
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

        let ordered_opening_points = (0..self.context.deep_point_count)
            .flat_map(|deep_point_ordinal| {
                used_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        deep_point_ordinal,
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
                for deep_point_ordinal in 0..self.context.deep_point_count {
                    for rotation in required_rotations_by_column
                        .get(column_ordinal)
                        .ok_or(RelationPlanError::InvalidOpening)?
                    {
                        let opening_point_ordinal = opening_point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                deep_point_ordinal,
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
            for deep_point_ordinal in 0..self.context.deep_point_count {
                let opening_point_ordinal = opening_point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        deep_point_ordinal,
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
            primitive_two_n_root: self.input.primitive_two_n_root,
            slot_generator: self.input.slot_generator,
            inverse_ring_degree: self.geometry.inverse_ring_degree,
            pair_slot_inverse_roots: self
                .geometry
                .pair_slot_inverse_roots
                .clone()
                .into_boxed_slice(),
            encoder_reduction_maximum: self.geometry.encoder_reduction_maximum,
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
            keyed_sources.push((
                BallotVerifierSourceKey::Ciphertext {
                    component_ordinal,
                    data_modulus_index,
                },
                RelationVerifierSource::Protocol {
                    protocol_source_kind: 2,
                    source_coordinates: vec![
                        u64::from(component_ordinal),
                        u64::from(data_modulus_index),
                    ],
                    statement_binding_path: vec![RelationSelectorPathStep::tuple_field(
                        BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL,
                    )],
                    value_layout,
                },
            ));
        }
    }
    for option_ordinal in 0..OPTION_COUNT {
        let option_ordinal =
            u16::try_from(option_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        keyed_sources.push((
            BallotVerifierSourceKey::PairDifferenceEncoderWeight { option_ordinal },
            RelationVerifierSource::DirectBallotPairDifferenceEncoderWeights {
                ring_degree: input.ring_degree,
                primitive_two_n_root: input.primitive_two_n_root,
                slot_generator: input.slot_generator,
                option_count: u16::try_from(OPTION_COUNT)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                option_ordinal,
            },
        ));
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

fn validate_slot_generator(ring_degree: u64, slot_generator: u16) -> Result<(), RelationPlanError> {
    let two_n = ring_degree
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let positive_slot_count = ring_degree / 2;
    let generator = u64::from(slot_generator);
    if generator >= two_n
        || generator.is_multiple_of(2)
        || modular_power(generator, positive_slot_count, two_n) != 1
        || (positive_slot_count > 1
            && modular_power(generator, positive_slot_count / 2, two_n) == 1)
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let mut positive_exponents = BTreeSet::new();
    let mut exponent = 1_u64;
    for _ in 0..positive_slot_count {
        if exponent.is_multiple_of(2) || !positive_exponents.insert(exponent) {
            return Err(RelationPlanError::InvalidDomain);
        }
        exponent = modular_product(exponent, generator, two_n);
    }
    let negative_exponents = positive_exponents
        .iter()
        .copied()
        .map(|positive| two_n - positive)
        .collect::<BTreeSet<_>>();
    if !positive_exponents.is_disjoint(&negative_exponents)
        || positive_exponents.len() + negative_exponents.len()
            != usize::try_from(ring_degree).map_err(|_| RelationPlanError::CountOverflow)?
        || positive_exponents
            .union(&negative_exponents)
            .copied()
            .ne((1..two_n).step_by(2))
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    Ok(())
}

fn modular_sum(left: u64, right: u64, modulus: u64) -> u64 {
    let threshold = modulus - right;
    if left >= threshold {
        left - threshold
    } else {
        left + right
    }
}

fn modular_difference_residue(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn modular_inverse(value: u64, modulus: u64) -> Result<u64, RelationPlanError> {
    if value == 0 || value >= modulus || modulus < 3 {
        return Err(RelationPlanError::InvalidModulus);
    }
    let inverse = modular_power(value, modulus - 2, modulus);
    if modular_product(value, inverse, modulus) != 1 {
        return Err(RelationPlanError::InvalidModulus);
    }
    Ok(inverse)
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

    const TEST_RING_DEGREE: u64 = 256;
    const TEST_PLAINTEXT_MODULUS: u64 = 12_289;
    const TEST_DATA_MODULUS: u64 = 65_537;
    const TEST_EVALUATION_DOMAIN_SIZE: u64 = 1_024;

    fn check_context() -> RelationPlanCheckContext {
        let maximum_two_adic_order = 1_u64 << 32;
        RelationPlanCheckContext {
            base_field_modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                maximum_two_adic_order / TEST_EVALUATION_DOMAIN_SIZE,
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 256,
            fri_fold_count: 6,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_modular_identity_challenge_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), TEST_DATA_MODULUS),
                ResolvedSuiteModulus::new(
                    SuiteModulusReference::plaintext(),
                    TEST_PLAINTEXT_MODULUS,
                ),
            ],
        }
    }

    fn relation_input() -> BallotValidityRelationPlanInput {
        BallotValidityRelationPlanInput {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: 512,
            active_data_modulus_indices: vec![0],
            plaintext_modulus: TEST_PLAINTEXT_MODULUS,
            primitive_two_n_root: 3_400,
            slot_generator: 3,
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
        assert_eq!(variant.ordered_verifier_sources.len(), 4 + OPTION_COUNT);
        assert!(variant.ordered_public_samplers.is_empty());

        assert_eq!(
            compilation.source_plan().column_count(),
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
        let expected_source_columns = base_tree_columns.len();
        assert_eq!(
            compilation.source_plan().provided_column_count(),
            expected_source_columns
        );
        for (column_index, column) in variant.ordered_columns.iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).unwrap();
            assert_eq!(
                compilation.source_plan().recipe(column_ordinal).is_some(),
                matches!(column.origin, RelationColumnOrigin::Prover)
                    && base_tree_columns.contains(&column_ordinal),
                "column {column_ordinal} has the wrong family-source ownership"
            );
            assert_eq!(
                compilation
                    .source_plan()
                    .verifier_source(column_ordinal)
                    .is_some(),
                matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    && base_tree_columns.contains(&column_ordinal),
                "column {column_ordinal} has the wrong verifier-source ownership"
            );
        }
        assert!(
            (0..u32::try_from(variant.ordered_columns.len()).unwrap())
                .filter_map(|column_ordinal| compilation.source_plan().recipe(column_ordinal))
                .any(|recipe| matches!(
                    recipe.value_source(),
                    BallotValidityWitnessValueSource::EncryptionQuotient {
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
                RelationVerifierSource::DirectBallotPairDifferenceEncoderWeights { .. } => None,
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
            ]
        );
        let mut encoder_weight_source_options = variant
            .ordered_verifier_sources
            .iter()
            .filter_map(|source| match source {
                RelationVerifierSource::DirectBallotPairDifferenceEncoderWeights {
                    ring_degree,
                    primitive_two_n_root,
                    slot_generator,
                    option_count,
                    option_ordinal,
                } => {
                    assert_eq!(*ring_degree, TEST_RING_DEGREE);
                    assert_eq!(*primitive_two_n_root, 3_400);
                    assert_eq!(*slot_generator, 3);
                    assert_eq!(usize::from(*option_count), OPTION_COUNT);
                    Some(*option_ordinal)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        encoder_weight_source_options.sort_unstable();
        assert_eq!(
            encoder_weight_source_options,
            (0..OPTION_COUNT)
                .map(|option_ordinal| u16::try_from(option_ordinal).unwrap())
                .collect::<Vec<_>>()
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
        assert_eq!(variant.ordered_integer_lift_batches.len(), 1);
        let batch = &variant.ordered_integer_lift_batches[0];
        assert_eq!(batch.modulus_reference, SuiteModulusReference::data(0));
        assert_eq!(batch.challenge_ordinal, 0);
        assert_eq!(batch.ordered_components.len(), 2);
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
        }));

        let non_native_challenges = variant
            .derived_challenge_catalog(&context)
            .expect("challenge derivation must succeed")
            .into_iter()
            .filter(|challenge| {
                matches!(
                    challenge.role,
                    RelationChallengeRole::NonNativeTheta | RelationChallengeRole::NonNativeAlpha
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(non_native_challenges.len(), 1);
        assert_eq!(
            non_native_challenges
                .iter()
                .filter(|challenge| challenge.role == RelationChallengeRole::NonNativeTheta)
                .map(|challenge| challenge.role_coordinates.clone())
                .collect::<Vec<_>>(),
            vec![vec![0, 0]]
        );
        assert!(
            non_native_challenges
                .iter()
                .all(|challenge| challenge.role != RelationChallengeRole::NonNativeAlpha)
        );
        assert!(non_native_challenges.iter().all(|challenge| matches!(
            challenge.sampling,
            RelationChallengeSampling::ProductResidueVectorCoordinate {
                modulus_selector: RelationChallengeModulusSelector::NonNativeModulusOrdinal(0),
                coordinate_count: 1,
                maximum_candidate_draws_per_output: 128,
            }
        )));

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
        let expected_trace_mask_degree = 2_u64
            * (u64::from(context.challenge_extension_degree)
                * u64::try_from(maximum_translated_opening_count)
                    .expect("the opening count fits u64")
                + 2 * u64::from(context.unique_query_count));
        assert_eq!(expected_trace_mask_degree, 52);
        assert!(variant.ordered_masks.iter().all(|mask| {
            mask.mask_kind != RelationMaskKind::Trace
                || mask.mask_degree_bound_exclusive == expected_trace_mask_degree
        }));
        assert!(variant.ordered_columns.iter().all(|column| {
            !matches!(column.origin, RelationColumnOrigin::Prover)
                || column.source_degree_bound_exclusive
                    == TEST_RING_DEGREE + expected_trace_mask_degree
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
    fn pair_difference_encoder_weights_reconstruct_the_direct_ballot_plaintext() {
        let context = check_context();
        let compilation = compile_ballot_validity_relation(&relation_input(), &context)
            .expect("the direct ballot relation must compile");
        let source_plan = compilation.source_plan();
        let scores = [
            1_u64, 10, 2, 9, 3, 8, 4, 7, 5, 6, 10, 1, 9, 2, 8, 3, 7, 4, 6, 5,
        ];
        let packed_pair_differences = crate::bgv::direct_ballots::direct_ballot_slots(
            &scores,
            TEST_PLAINTEXT_MODULUS,
            usize::try_from(TEST_RING_DEGREE).unwrap(),
        )
        .expect("the score vector must have the canonical pair-difference packing");
        assert_eq!(source_plan.pair_slot_inverse_roots.len(), PAIR_COUNT);
        assert!(
            packed_pair_differences[PAIR_COUNT..]
                .iter()
                .all(|value| *value == 0)
        );
        assert!(
            source_plan
                .encoder_weight_sequence(u16::try_from(OPTION_COUNT).unwrap())
                .is_none()
        );
        let plaintext_coefficients = source_plan
            .plaintext_coefficients_for_scores(&scores)
            .expect("the bounded scores must encode");

        let dense_plaintext_coefficients = (0..TEST_RING_DEGREE)
            .map(|coefficient_ordinal| {
                let inverse_transform_sum = packed_pair_differences
                    .iter()
                    .take(PAIR_COUNT)
                    .copied()
                    .zip(source_plan.pair_slot_inverse_roots.iter().copied())
                    .fold(0_u64, |sum, (pair_difference, inverse_slot_root)| {
                        modular_sum(
                            sum,
                            modular_product(
                                pair_difference,
                                modular_power(
                                    inverse_slot_root,
                                    coefficient_ordinal,
                                    TEST_PLAINTEXT_MODULUS,
                                ),
                                TEST_PLAINTEXT_MODULUS,
                            ),
                            TEST_PLAINTEXT_MODULUS,
                        )
                    });
                modular_product(
                    source_plan.inverse_ring_degree,
                    inverse_transform_sum,
                    TEST_PLAINTEXT_MODULUS,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(plaintext_coefficients, dense_plaintext_coefficients);

        let encoder_reductions = source_plan
            .encoder_reductions_for_scores(&scores, &plaintext_coefficients)
            .expect("the exact integer reductions must exist");
        let weight_sequences = (0..OPTION_COUNT)
            .map(|option_ordinal| {
                source_plan
                    .encoder_weight_sequence(u16::try_from(option_ordinal).unwrap())
                    .expect("every option must have one deterministic verifier sequence")
            })
            .collect::<Vec<_>>();
        for coefficient_ordinal in 0..usize::try_from(TEST_RING_DEGREE).unwrap() {
            let weighted_score_offset =
                scores
                    .iter()
                    .zip(&weight_sequences)
                    .fold(0_u128, |sum, (score, weights)| {
                        sum + u128::from(score - MINIMUM_SCORE)
                            * u128::from(weights[coefficient_ordinal])
                    });
            assert_eq!(
                weighted_score_offset,
                u128::from(plaintext_coefficients[coefficient_ordinal])
                    + u128::from(TEST_PLAINTEXT_MODULUS)
                        * u128::from(encoder_reductions[coefficient_ordinal]),
                "coefficient {coefficient_ordinal} must satisfy the exact encoder identity"
            );
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

        let mut nonprimitive_root = relation_input();
        nonprimitive_root.primitive_two_n_root = 1;
        assert_eq!(
            compile_ballot_validity_relation_plan(&nonprimitive_root, &context),
            Err(RelationPlanError::InvalidDomain)
        );

        let mut short_slot_orbit = relation_input();
        short_slot_orbit.slot_generator = 127;
        assert_eq!(
            compile_ballot_validity_relation_plan(&short_slot_orbit, &context),
            Err(RelationPlanError::InvalidDomain)
        );

        let mut unknown_reserved_slot_rule = relation_input();
        unknown_reserved_slot_rule.reserved_slot_rule = RESERVED_SLOT_RULE + 1;
        assert_eq!(
            compile_ballot_validity_relation_plan(&unknown_reserved_slot_rule, &context),
            Err(RelationPlanError::InvalidDomain)
        );
    }

    #[test]
    fn reversed_negacyclic_transpose_recurrence_matches_dense_multiplication() {
        let public_key_coefficients = (0..TEST_RING_DEGREE)
            .map(|coefficient_ordinal| {
                (coefficient_ordinal
                    .checked_mul(73)
                    .expect("the test sequence fits u64")
                    + 19)
                    % TEST_DATA_MODULUS
            })
            .collect::<Vec<_>>();
        for theta in [0, 1, 37, TEST_DATA_MODULUS - 1] {
            let dense = dense_reversed_negacyclic_transpose(
                &public_key_coefficients,
                theta,
                TEST_DATA_MODULUS,
            );
            let recurrence = recurrent_reversed_negacyclic_transpose(
                &public_key_coefficients,
                theta,
                TEST_DATA_MODULUS,
            );
            assert_eq!(recurrence, dense, "theta={theta}");
        }
    }

    fn dense_reversed_negacyclic_transpose(
        coefficients: &[u64],
        theta: u64,
        modulus: u64,
    ) -> Vec<u64> {
        let ring_degree = coefficients.len();
        (0..ring_degree)
            .map(|row_ordinal| {
                let output_ordinal = ring_degree - 1 - row_ordinal;
                coefficients.iter().copied().enumerate().fold(
                    0_u64,
                    |sum, (coefficient_ordinal, coefficient)| {
                        let unreduced_exponent = coefficient_ordinal + output_ordinal;
                        let term = modular_product(
                            coefficient,
                            modular_power(
                                theta,
                                (unreduced_exponent % ring_degree) as u64,
                                modulus,
                            ),
                            modulus,
                        );
                        if unreduced_exponent >= ring_degree {
                            modular_difference(sum, term, modulus)
                        } else {
                            modular_addition(sum, term, modulus)
                        }
                    },
                )
            })
            .collect()
    }

    fn recurrent_reversed_negacyclic_transpose(
        coefficients: &[u64],
        theta: u64,
        modulus: u64,
    ) -> Vec<u64> {
        let mut reversed_weights = vec![0_u64; coefficients.len()];
        let theta_to_ring_degree = modular_power(theta, coefficients.len() as u64, modulus);
        reversed_weights[coefficients.len() - 1] = coefficients.iter().copied().enumerate().fold(
            0_u64,
            |sum, (coefficient_ordinal, coefficient)| {
                modular_addition(
                    sum,
                    modular_product(
                        coefficient,
                        modular_power(theta, coefficient_ordinal as u64, modulus),
                        modulus,
                    ),
                    modulus,
                )
            },
        );
        for row_ordinal in (1..coefficients.len()).rev() {
            let theta_times_current =
                modular_product(theta, reversed_weights[row_ordinal], modulus);
            let correction = modular_product(
                modular_addition(theta_to_ring_degree, 1, modulus),
                coefficients[row_ordinal],
                modulus,
            );
            reversed_weights[row_ordinal - 1] =
                modular_difference(theta_times_current, correction, modulus);
        }
        reversed_weights
    }

    fn modular_addition(left: u64, right: u64, modulus: u64) -> u64 {
        ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
    }

    fn modular_difference(left: u64, right: u64, modulus: u64) -> u64 {
        ((u128::from(left) + u128::from(modulus) - u128::from(right)) % u128::from(modulus)) as u64
    }
}
