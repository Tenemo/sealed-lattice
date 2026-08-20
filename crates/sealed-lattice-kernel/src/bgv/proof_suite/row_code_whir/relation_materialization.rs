//! Incremental relation materialization for row-code/WHIR.
//!
//! The generation owner supplies application challenges after the base-phase
//! transcript boundary and retains external-memory ownership. These cursors
//! request replayed relation material one operation at a time and yield
//! derived auxiliary or quotient polynomials for durable persistence. They
//! deliberately own neither transcript state nor storage callbacks.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

#[cfg(test)]
use crate::bgv::proof_suite::prover::CommonProofConstraintStreamQuotientCheckpoint;
use crate::bgv::proof_suite::{
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofSourcePolynomial,
    ProofChallengeExtensionElement, ProofEvaluationDomain, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanVariant,
    external_polynomial::ExternalPolynomialVector,
    prover::{
        CommonProofAuxiliaryColumnSynthesisCursor, CommonProofConstraintStreamQuotientBuilder,
        CommonProofPrivateCoinError, CommonProofQuotientComponentCursor,
        CommonProofQuotientConstraintTransformKey, CommonProofQuotientEvaluationProgress,
        CommonProofQuotientEvaluationReadRequest,
    },
};

pub(super) enum RowCodeWhirAuxiliaryRelationMaterializationAction {
    ReadColumn(u32),
    PersistColumn {
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    },
    Progressed,
    Complete,
}

/// One descriptor-local auxiliary synthesis cursor.
///
/// At most one replay input request is outstanding. The retained synthesis
/// cursor bounds live trace rows to the inputs and outputs of one checked
/// integer-lift descriptor; the caller persists each output before polling
/// again.
pub(super) struct RowCodeWhirAuxiliaryRelationMaterialization {
    synthesis_cursor: CommonProofAuxiliaryColumnSynthesisCursor,
    outstanding_input_column_ordinal: Option<u32>,
    completion_emitted: bool,
}

impl RowCodeWhirAuxiliaryRelationMaterialization {
    pub(super) fn new(
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        application_challenges: &[RelationApplicationChallengeAssignment],
    ) -> Result<Self, CommonProofProverError> {
        Ok(Self {
            synthesis_cursor: CommonProofAuxiliaryColumnSynthesisCursor::new(
                variant,
                relation_context,
                application_challenges,
            )?,
            outstanding_input_column_ordinal: None,
            completion_emitted: false,
        })
    }

    pub(super) fn next_action<Coins>(
        &mut self,
        variant: &RelationPlanVariant,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<
        RowCodeWhirAuxiliaryRelationMaterializationAction,
        CommonProofPrivateCoinError<Coins::Error>,
    >
    where
        Coins: CommonProofPrivateCoinSource,
    {
        if self.outstanding_input_column_ordinal.is_some() || self.completion_emitted {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }

        if self.synthesis_cursor.has_pending_output() {
            let (column_ordinal, polynomial) = self
                .synthesis_cursor
                .take_next_output(variant, coins, maximum_candidate_draws_per_output)?
                .ok_or(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            return Ok(
                RowCodeWhirAuxiliaryRelationMaterializationAction::PersistColumn {
                    column_ordinal,
                    polynomial,
                },
            );
        }

        if let Some(column_ordinal) = self.synthesis_cursor.next_input_column_ordinal() {
            self.outstanding_input_column_ordinal = Some(column_ordinal);
            return Ok(
                RowCodeWhirAuxiliaryRelationMaterializationAction::ReadColumn(column_ordinal),
            );
        }

        if self
            .synthesis_cursor
            .advance_ready_task()
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            return Ok(RowCodeWhirAuxiliaryRelationMaterializationAction::Progressed);
        }

        if self.synthesis_cursor.is_complete() {
            self.completion_emitted = true;
            return Ok(RowCodeWhirAuxiliaryRelationMaterializationAction::Complete);
        }

        Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ))
    }

    pub(super) fn supply_input(
        &mut self,
        column_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.outstanding_input_column_ordinal != Some(column_ordinal) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.synthesis_cursor
            .accept_input_column(column_ordinal, polynomial)?;
        self.outstanding_input_column_ordinal = None;
        Ok(())
    }
}

pub(super) enum RowCodeWhirQuotientMaterializationAction {
    TransformColumn(CommonProofQuotientConstraintTransformKey),
    ReadEvaluationRange(CommonProofQuotientEvaluationReadRequest),
    Progressed,
    ConstraintCompleted,
    PersistQuotientComponent {
        component_ordinal: u32,
        polynomial: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutstandingQuotientMaterializationAction {
    TransformColumn(CommonProofQuotientConstraintTransformKey),
    ReadEvaluationRange(CommonProofQuotientEvaluationReadRequest),
    CompleteConstraintStorageStep,
    PersistQuotientComponent(u32),
}

/// Checked quotient construction without transcript or storage ownership.
///
/// The caller performs each requested transform or external-memory read and
/// durably persists every yielded component before acknowledging it. The
/// retained quotient builder remains the sole arithmetic owner while the
/// component cursor applies the checked telescoping masks one component at a
/// time.
pub(super) struct RowCodeWhirQuotientMaterialization {
    quotient_builder: Option<CommonProofConstraintStreamQuotientBuilder>,
    quotient_component_cursor: Option<CommonProofQuotientComponentCursor>,
    next_component_ordinal: u32,
    outstanding_action: Option<OutstandingQuotientMaterializationAction>,
    completion_emitted: bool,
}

impl RowCodeWhirQuotientMaterialization {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        evaluation_domain: ProofEvaluationDomain,
        transformed_columns: BTreeMap<u32, ExternalPolynomialVector>,
        application_challenges: Vec<RelationApplicationChallengeAssignment>,
        composition_challenges: Vec<ProofChallengeExtensionElement>,
        maximum_external_read_chunk_byte_length: u32,
    ) -> Result<Self, CommonProofProverError> {
        Ok(Self {
            quotient_builder: Some(CommonProofConstraintStreamQuotientBuilder::new(
                variant,
                relation_context,
                evaluation_domain,
                transformed_columns,
                application_challenges,
                composition_challenges,
                maximum_external_read_chunk_byte_length,
            )?),
            quotient_component_cursor: None,
            next_component_ordinal: 0,
            outstanding_action: None,
            completion_emitted: false,
        })
    }

    #[cfg(test)]
    pub(super) fn completed_constraint_checkpoint_count(
        &self,
    ) -> Result<Option<usize>, CommonProofProverError> {
        if self.quotient_component_cursor.is_some()
            || self.outstanding_action.is_some()
            || self.completion_emitted
        {
            return Ok(None);
        }
        self.quotient_builder
            .as_ref()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .completed_constraint_checkpoint_count()
    }

    #[cfg(test)]
    pub(super) fn is_fresh_constraint_stream(&self) -> Result<bool, CommonProofProverError> {
        if self.quotient_component_cursor.is_some()
            || self.outstanding_action.is_some()
            || self.completion_emitted
        {
            return Ok(false);
        }
        Ok(self
            .quotient_builder
            .as_ref()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .is_fresh_constraint_stream()?
            && self.next_component_ordinal == 0)
    }

    #[cfg(test)]
    pub(super) fn canonical_constraint_checkpoint_bytes(
        &self,
    ) -> Result<Vec<u8>, CommonProofProverError> {
        if self.quotient_component_cursor.is_some()
            || self.outstanding_action.is_some()
            || self.completion_emitted
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.quotient_builder
            .as_ref()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .canonical_constraint_checkpoint_bytes()
    }

    #[cfg(test)]
    pub(super) fn decode_constraint_checkpoint(
        &self,
        canonical_checkpoint_bytes: &[u8],
    ) -> Result<CommonProofConstraintStreamQuotientCheckpoint, CommonProofProverError> {
        if self.quotient_component_cursor.is_some()
            || self.outstanding_action.is_some()
            || self.completion_emitted
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.quotient_builder
            .as_ref()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .decode_constraint_checkpoint(canonical_checkpoint_bytes)
    }

    #[cfg(test)]
    pub(super) fn restore_constraint_checkpoint(
        &mut self,
        checkpoint: CommonProofConstraintStreamQuotientCheckpoint,
    ) -> Result<(), CommonProofProverError> {
        if self.quotient_component_cursor.is_some()
            || self.outstanding_action.is_some()
            || self.completion_emitted
            || self.next_component_ordinal != 0
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.quotient_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .restore_constraint_checkpoint(checkpoint)
    }

    pub(super) fn next_action<Coins>(
        &mut self,
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        coins: &mut Coins,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<RowCodeWhirQuotientMaterializationAction, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: CommonProofPrivateCoinSource,
    {
        if self.outstanding_action
            == Some(OutstandingQuotientMaterializationAction::CompleteConstraintStorageStep)
        {
            return Ok(RowCodeWhirQuotientMaterializationAction::ConstraintCompleted);
        }
        if self.outstanding_action.is_some() || self.completion_emitted {
            return Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }

        if let Some(component_cursor) = self.quotient_component_cursor.as_mut() {
            let Some(polynomial) =
                component_cursor.next_component(coins, maximum_candidate_draws_per_output)?
            else {
                self.quotient_component_cursor = None;
                self.completion_emitted = true;
                return Ok(RowCodeWhirQuotientMaterializationAction::Complete);
            };
            let component_ordinal = self.next_component_ordinal;
            self.outstanding_action = Some(
                OutstandingQuotientMaterializationAction::PersistQuotientComponent(
                    component_ordinal,
                ),
            );
            return Ok(
                RowCodeWhirQuotientMaterializationAction::PersistQuotientComponent {
                    component_ordinal,
                    polynomial,
                },
            );
        }

        let quotient_builder =
            self.quotient_builder
                .as_mut()
                .ok_or(CommonProofPrivateCoinError::Prover(
                    CommonProofProverError::InvalidQuotient,
                ))?;
        if let Some(transform_key) = quotient_builder
            .next_transform_key()
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            self.outstanding_action = Some(
                OutstandingQuotientMaterializationAction::TransformColumn(transform_key),
            );
            return Ok(RowCodeWhirQuotientMaterializationAction::TransformColumn(
                transform_key,
            ));
        }
        if let Some(read_request) = quotient_builder
            .next_read_request()
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            self.outstanding_action =
                Some(OutstandingQuotientMaterializationAction::ReadEvaluationRange(read_request));
            return Ok(RowCodeWhirQuotientMaterializationAction::ReadEvaluationRange(read_request));
        }

        match quotient_builder
            .evaluate_ready_block(variant, relation_context)
            .map_err(CommonProofPrivateCoinError::Prover)?
        {
            CommonProofQuotientEvaluationProgress::BlockComplete => {}
            CommonProofQuotientEvaluationProgress::ConstraintComplete => {
                let all_constraints_complete = quotient_builder
                    .complete_constraint()
                    .map_err(CommonProofPrivateCoinError::Prover)?;
                if all_constraints_complete {
                    let quotient = self
                        .quotient_builder
                        .take()
                        .ok_or(CommonProofPrivateCoinError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .finish()
                        .map_err(CommonProofPrivateCoinError::Prover)?;
                    self.quotient_component_cursor = Some(
                        CommonProofQuotientComponentCursor::new(
                            variant,
                            relation_context,
                            quotient,
                        )
                        .map_err(CommonProofPrivateCoinError::Prover)?,
                    );
                }
                self.outstanding_action =
                    Some(OutstandingQuotientMaterializationAction::CompleteConstraintStorageStep);
                return Ok(RowCodeWhirQuotientMaterializationAction::ConstraintCompleted);
            }
        }
        Ok(RowCodeWhirQuotientMaterializationAction::Progressed)
    }

    pub(super) fn supply_transformed_column(
        &mut self,
        transform_key: CommonProofQuotientConstraintTransformKey,
        vector: ExternalPolynomialVector,
    ) -> Result<(), CommonProofProverError> {
        if self.outstanding_action
            != Some(OutstandingQuotientMaterializationAction::TransformColumn(
                transform_key,
            ))
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.quotient_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .accept_transformed_column(transform_key, vector)?;
        self.outstanding_action = None;
        Ok(())
    }

    pub(super) fn supply_evaluation_values(
        &mut self,
        read_request: CommonProofQuotientEvaluationReadRequest,
        values: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<(), CommonProofProverError> {
        if self.outstanding_action
            != Some(OutstandingQuotientMaterializationAction::ReadEvaluationRange(read_request))
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.quotient_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidQuotient)?
            .accept_read_values(read_request, values)?;
        self.outstanding_action = None;
        Ok(())
    }

    pub(super) fn acknowledge_persisted_component(
        &mut self,
        component_ordinal: u32,
    ) -> Result<(), CommonProofProverError> {
        if self.outstanding_action
            != Some(
                OutstandingQuotientMaterializationAction::PersistQuotientComponent(
                    component_ordinal,
                ),
            )
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.next_component_ordinal = self
            .next_component_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.outstanding_action = None;
        Ok(())
    }

    pub(super) fn acknowledge_completed_constraint_storage_step(
        &mut self,
    ) -> Result<(), CommonProofProverError> {
        if self.outstanding_action
            != Some(OutstandingQuotientMaterializationAction::CompleteConstraintStorageStep)
        {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        self.outstanding_action = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        convert::Infallible,
    };

    use super::*;
    use crate::bgv::parameters::DATA_PRIMES;
    use crate::bgv::proof_suite::{
        CollectivePublicKeyAggregatePlanInput, CommonProofPrivateCoinCoordinate,
        PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
        PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofExternalMemoryObject,
        PublicAggregateRelationGeometry, ResolvedSuiteModulus, SameSecretRelationPlanInput,
        SuiteModulusReference, compile_collective_public_key_aggregate_relation_plan,
        compile_same_secret_relation_plan,
        prover::{construct_composed_quotient_polynomial, decompose_composed_quotient},
        relation_plan::RelationColumnValueType,
    };

    const TEST_SAME_SECRET_EVALUATION_DOMAIN_SIZE: u64 = 8_192;
    const TEST_SAME_SECRET_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 1_024;

    fn modular_product(first: u64, second: u64, modulus: u64) -> u64 {
        ((u128::from(first) * u128::from(second)) % u128::from(modulus)) as u64
    }

    fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let mut result = 1_u64;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = modular_product(result, base, modulus);
            }
            exponent >>= 1;
            if exponent > 0 {
                base = modular_product(base, base, modulus);
            }
        }
        result
    }

    fn relation_context(
        evaluation_domain_size: u64,
        out_of_domain_point_count: u16,
        quotient_component_count: u32,
        quotient_component_degree_bound_exclusive: u64,
        non_native_repetition_count: u16,
        resolved_moduli: Vec<ResolvedSuiteModulus>,
    ) -> RelationPlanCheckContext {
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count,
            quotient_component_count,
            quotient_component_degree_bound_exclusive,
            phase_column_query_coordinate_count: 8,
            non_native_theta_repetition_count: non_native_repetition_count,
            non_native_alpha_repetition_count: non_native_repetition_count,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli,
        }
    }

    fn same_secret_context() -> RelationPlanCheckContext {
        relation_context(
            TEST_SAME_SECRET_EVALUATION_DOMAIN_SIZE,
            1,
            4,
            TEST_SAME_SECRET_OPENING_DEGREE_BOUND_EXCLUSIVE,
            1,
            vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), DATA_PRIMES[0]),
                ResolvedSuiteModulus::new(SuiteModulusReference::data(1), DATA_PRIMES[1]),
                ResolvedSuiteModulus::new(SuiteModulusReference::data(2), DATA_PRIMES[2]),
            ],
        )
    }

    fn same_secret_input() -> SameSecretRelationPlanInput {
        SameSecretRelationPlanInput {
            // Keep this compact geometry aligned with the relation compiler's
            // checked fixture: widening the opening schedule increases the
            // direct-view rank and is invalid without widening both the trace
            // and quotient geometry from their owning formulas.
            ring_degree: 256,
            evaluation_domain_size: TEST_SAME_SECRET_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: TEST_SAME_SECRET_OPENING_DEGREE_BOUND_EXCLUSIVE,
            material_column_degree_bound_exclusive: 10,
            public_polynomial_column_degree_bound_exclusive: 256,
            sharing_data_modulus_indices: vec![0, 1],
            commitment_data_modulus_indices: vec![0, 1, 2],
            commitment_module_rank: 1,
        }
    }

    fn same_secret_application_challenges(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Vec<RelationApplicationChallengeAssignment> {
        variant
            .common_proof_relation_prefix_schedule(context)
            .expect("the checked relation prefix schedule is available")
            .ordered_application_challenge_groups()
            .iter()
            .flat_map(|group| {
                (0..group.coordinate_count()).map(|repetition_ordinal| {
                    RelationApplicationChallengeAssignment::new(
                        group.challenge(),
                        repetition_ordinal,
                        3,
                    )
                    .expect("the deterministic application challenge is canonical")
                })
            })
            .collect()
    }

    fn public_aggregate_context() -> RelationPlanCheckContext {
        relation_context(
            128,
            2,
            2,
            64,
            2,
            vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), 97),
                ResolvedSuiteModulus::new(SuiteModulusReference::special(0), 193),
            ],
        )
    }

    fn public_aggregate_input() -> CollectivePublicKeyAggregatePlanInput {
        CollectivePublicKeyAggregatePlanInput {
            geometry: PublicAggregateRelationGeometry {
                ring_degree: 16,
                evaluation_domain_size: 128,
                opening_degree_bound_exclusive: 64,
                public_polynomial_column_degree_bound_exclusive: 8,
                participant_count: 3,
            },
            ordered_component_moduli: vec![
                SuiteModulusReference::data(0),
                SuiteModulusReference::special(0),
            ],
        }
    }

    struct DeterministicZeroCoinSource;

    impl CommonProofPrivateCoinSource for DeterministicZeroCoinSource {
        type Error = Infallible;

        fn private_randomness_attempt_identifier(
            &self,
        ) -> crate::foundation::PrivateRandomnessAttemptIdentifier {
            crate::foundation::PrivateRandomnessAttemptIdentifier::for_test([0xb4; 32])
        }

        fn sample_modulo(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn fill_raw_bytes(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            destination.fill(0);
            Ok(())
        }

        fn replay_modulo_samples(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _modulus: u64,
            _maximum_candidate_draws_per_output: u32,
            destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            destination.fill(0);
            Ok(())
        }
    }

    fn zero_base_polynomial() -> CommonProofSourcePolynomial {
        CommonProofSourcePolynomial::from_base_coefficients(vec![ProofBaseFieldElement::ZERO])
    }

    #[test]
    fn auxiliary_materialization_requires_exact_replay_inputs_and_completes_once() {
        let relation_context = same_secret_context();
        let relation_plan =
            compile_same_secret_relation_plan(&same_secret_input(), &relation_context)
                .expect("the small same-secret relation plan compiles");
        let variant = relation_plan
            .select_variant(None, None)
            .expect("the small same-secret relation has one variant");
        let application_challenges = same_secret_application_challenges(variant, &relation_context);
        let mut materialization = RowCodeWhirAuxiliaryRelationMaterialization::new(
            variant,
            &relation_context,
            &application_challenges,
        )
        .expect("the checked challenges initialize auxiliary synthesis");
        let mut coins = DeterministicZeroCoinSource;

        let first_column_ordinal = match materialization
            .next_action(
                variant,
                &mut coins,
                relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            )
            .expect("the first replay input is requested")
        {
            RowCodeWhirAuxiliaryRelationMaterializationAction::ReadColumn(column_ordinal) => {
                column_ordinal
            }
            _ => panic!("auxiliary synthesis must begin with a replay input"),
        };
        assert!(matches!(
            materialization.next_action(
                variant,
                &mut coins,
                relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            ),
            Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput
            ))
        ));
        assert_eq!(
            materialization
                .supply_input(first_column_ordinal.wrapping_add(1), zero_base_polynomial(),),
            Err(CommonProofProverError::InvalidColumn),
        );
        materialization
            .supply_input(first_column_ordinal, zero_base_polynomial())
            .expect("the exact outstanding replay input is accepted");

        let mut persisted_column_ordinals = BTreeSet::new();
        let mut progressed_step_count = 0_usize;
        let mut completed = false;
        for _ in 0..100_000 {
            match materialization
                .next_action(
                    variant,
                    &mut coins,
                    relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                )
                .expect("the checked auxiliary synthesis action succeeds")
            {
                RowCodeWhirAuxiliaryRelationMaterializationAction::ReadColumn(column_ordinal) => {
                    materialization
                        .supply_input(column_ordinal, zero_base_polynomial())
                        .expect("the requested replay input is accepted");
                }
                RowCodeWhirAuxiliaryRelationMaterializationAction::PersistColumn {
                    column_ordinal,
                    polynomial,
                } => {
                    assert!(persisted_column_ordinals.insert(column_ordinal));
                    assert_ne!(polynomial.coefficient_count(), 0);
                }
                RowCodeWhirAuxiliaryRelationMaterializationAction::Progressed => {
                    progressed_step_count += 1;
                }
                RowCodeWhirAuxiliaryRelationMaterializationAction::Complete => {
                    completed = true;
                    break;
                }
            }
        }

        assert!(completed, "the bounded auxiliary cursor must terminate");
        assert!(!persisted_column_ordinals.is_empty());
        assert_ne!(progressed_step_count, 0);
        assert!(matches!(
            materialization.next_action(
                variant,
                &mut coins,
                relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            ),
            Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput
            ))
        ));
    }

    #[test]
    fn quotient_materialization_matches_the_full_oracle_and_enforces_acknowledgements() {
        let relation_context = public_aggregate_context();
        let relation_plan = compile_collective_public_key_aggregate_relation_plan(
            &public_aggregate_input(),
            &relation_context,
        )
        .expect("the compact public aggregate relation compiles");
        let variant = relation_plan
            .select_variant(None, None)
            .expect("the public aggregate relation has one variant");
        let evaluation_domain = ProofEvaluationDomain::new(64, 7)
            .expect("the compact quotient evaluation domain is valid");
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(variant.trace_domain_size())
                .expect("the compact trace-domain size fits usize"),
        )
        .expect("the compact trace subgroup is valid");
        let source_polynomials = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .map(|(column_index, column)| {
                let column_ordinal =
                    u32::try_from(column_index).expect("the compact column ordinal fits u32");
                let tree_index = variant
                    .ordered_trees()
                    .iter()
                    .position(|tree| tree.ordered_column_ordinals().contains(&column_ordinal))
                    .expect("every compact public column belongs to one tree");
                let modulus = relation_context
                    .resolved_modulus(
                        column
                            .canonical_residue_modulus()
                            .expect("every compact public column has a residue modulus"),
                    )
                    .expect("the compact residue modulus is resolved");
                let wrapped_share_value = match tree_index {
                    0 => modulus.div_ceil(2),
                    1 => modulus / 2,
                    2 | 3 => 0,
                    _ => panic!("the compact aggregate must contain exactly four roots"),
                };
                let evaluations = (0..trace_domain.size())
                    .map(|position| {
                        ProofBaseFieldElement::from_canonical(if position.is_multiple_of(2) {
                            wrapped_share_value
                        } else {
                            0
                        })
                        .expect("the compact aggregate value is canonical")
                    })
                    .collect::<Vec<_>>();
                CommonProofSourcePolynomial::from_base_coefficients(
                    trace_domain
                        .interpolate_base_polynomial(&evaluations)
                        .expect("the valid compact aggregate trace interpolates"),
                )
            })
            .collect::<Vec<_>>();
        let application_challenges = Vec::new();
        let composition_challenges = (0..variant.constraint_count())
            .map(|constraint_ordinal| {
                ProofChallengeExtensionElement::from_base(
                    ProofBaseFieldElement::from_canonical(
                        u64::try_from(constraint_ordinal)
                            .expect("the compact constraint ordinal fits u64")
                            + 2,
                    )
                    .expect("the compact challenge is canonical"),
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            RowCodeWhirQuotientMaterialization::new(
                variant,
                &relation_context,
                ProofEvaluationDomain::new(32, 7)
                    .expect("the undersized hostile domain is structurally valid"),
                BTreeMap::new(),
                application_challenges.clone(),
                composition_challenges.clone(),
                8,
            ),
            Err(CommonProofProverError::InvalidQuotient)
        ));
        assert!(matches!(
            RowCodeWhirQuotientMaterialization::new(
                variant,
                &relation_context,
                ProofEvaluationDomain::new(64, 9)
                    .expect("the wrong-coset hostile domain is structurally valid"),
                BTreeMap::new(),
                application_challenges.clone(),
                composition_challenges.clone(),
                8,
            ),
            Err(CommonProofProverError::InvalidQuotient)
        ));
        let mut wrong_generator_context = relation_context.clone();
        wrong_generator_context.evaluation_domain_generator = wrong_generator_context
            .evaluation_domain_generator
            .wrapping_add(1);
        assert!(matches!(
            RowCodeWhirQuotientMaterialization::new(
                variant,
                &wrong_generator_context,
                evaluation_domain,
                BTreeMap::new(),
                application_challenges.clone(),
                composition_challenges.clone(),
                8,
            ),
            Err(CommonProofProverError::InvalidQuotient)
        ));
        let expected_quotient = construct_composed_quotient_polynomial(
            variant,
            &relation_context,
            evaluation_domain,
            &source_polynomials,
            &application_challenges,
            &composition_challenges,
        )
        .expect("the full quotient oracle accepts the checked relation");
        let relation_domain_quotient = construct_composed_quotient_polynomial(
            variant,
            &relation_context,
            ProofEvaluationDomain::new(128, 7)
                .expect("the complete relation evaluation domain is valid"),
            &source_polynomials,
            &application_challenges,
            &composition_challenges,
        )
        .expect("the relation-domain quotient oracle accepts the checked relation");
        assert_eq!(expected_quotient, relation_domain_quotient);
        assert!(
            expected_quotient
                .iter()
                .any(|coefficient| *coefficient != ProofChallengeExtensionElement::ZERO),
            "the parity fixture must exercise nonzero quotient arithmetic",
        );
        let expected_components = decompose_composed_quotient(
            &expected_quotient,
            relation_context.quotient_component_count,
            variant
                .quotient_decomposition_stride(&relation_context)
                .expect("the checked relation has quotient decomposition geometry"),
        )
        .expect("the full quotient oracle decomposes into checked components");

        let mut materialization = RowCodeWhirQuotientMaterialization::new(
            variant,
            &relation_context,
            evaluation_domain,
            BTreeMap::new(),
            application_challenges.clone(),
            composition_challenges.clone(),
            8,
        )
        .expect("the checked quotient cursor initializes");
        let mut coins = DeterministicZeroCoinSource;
        let mut next_external_object_ordinal = 0_u32;
        let transformed_column_evaluations = source_polynomials
            .iter()
            .map(|polynomial| match polynomial {
                CommonProofSourcePolynomial::Base(coefficients) => evaluation_domain
                    .evaluate_base_polynomial(coefficients)
                    .map(|evaluations| {
                        evaluations
                            .into_iter()
                            .map(ProofChallengeExtensionElement::from_base)
                            .collect::<Vec<_>>()
                    }),
                CommonProofSourcePolynomial::Extension(coefficients) => {
                    evaluation_domain.evaluate_extension_polynomial(coefficients)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("the compact relation columns evaluate on the quotient domain");
        let mut transformed_evaluations_by_object = BTreeMap::new();
        let mut actual_components = Vec::new();
        let mut transform_request_count = 0_usize;
        let mut evaluation_read_count = 0_usize;
        let mut progress_count = 0_usize;
        let mut completed = false;
        let mut first_constraint_checkpoint = None;
        let mut completed_constraint_checkpoint_counts = Vec::new();
        let mut completed_constraint_count = 0_usize;
        let mut mid_constraint_checkpoint_probe_count = 0_usize;

        for _ in 0..100_000 {
            match materialization
                .next_action(
                    variant,
                    &relation_context,
                    &mut coins,
                    relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                )
                .expect("the checked quotient action succeeds")
            {
                RowCodeWhirQuotientMaterializationAction::TransformColumn(transform_key) => {
                    transform_request_count += 1;
                    assert!(matches!(
                        materialization.next_action(
                            variant,
                            &relation_context,
                            &mut coins,
                            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                        ),
                        Err(CommonProofPrivateCoinError::Prover(
                            CommonProofProverError::InvalidInput
                        ))
                    ));
                    let invalid_vector = ExternalPolynomialVector::new(
                        ProofExternalMemoryObject::new(next_external_object_ordinal),
                        RelationColumnValueType::BaseField,
                        evaluation_domain.size() - 1,
                    )
                    .expect("the intentionally short vector is nonempty");
                    assert_eq!(
                        materialization.supply_transformed_column(transform_key, invalid_vector),
                        Err(CommonProofProverError::InvalidColumn),
                    );
                    let vector = ExternalPolynomialVector::new(
                        ProofExternalMemoryObject::new(next_external_object_ordinal),
                        RelationColumnValueType::BaseField,
                        evaluation_domain.size(),
                    )
                    .expect("the compact transformed vector is valid");
                    assert!(
                        transformed_evaluations_by_object
                            .insert(
                                vector.object(),
                                transformed_column_evaluations
                                    .get(
                                        usize::try_from(transform_key.column_ordinal())
                                            .expect("the compact column ordinal fits usize"),
                                    )
                                    .expect("the requested compact column exists")
                                    .clone(),
                            )
                            .is_none()
                    );
                    next_external_object_ordinal = next_external_object_ordinal
                        .checked_add(1)
                        .expect("the compact object ordinal remains bounded");
                    materialization
                        .supply_transformed_column(transform_key, vector)
                        .expect("the exact requested transform is accepted");
                    assert_eq!(
                        materialization
                            .completed_constraint_checkpoint_count()
                            .expect("valid mid-constraint transform state is not a checkpoint"),
                        None,
                    );
                    mid_constraint_checkpoint_probe_count += 1;
                }
                RowCodeWhirQuotientMaterializationAction::ReadEvaluationRange(read_request) => {
                    evaluation_read_count += 1;
                    assert_eq!(
                        materialization
                            .supply_evaluation_values(read_request, Zeroizing::new(Vec::new()),),
                        Err(CommonProofProverError::InvalidQuotient),
                    );
                    materialization
                        .supply_evaluation_values(
                            read_request,
                            Zeroizing::new(
                                transformed_evaluations_by_object
                                    .get(&read_request.vector().object())
                                    .expect("the requested compact transform exists")
                                    [read_request.element_offset()
                                        ..read_request.element_offset()
                                            + read_request.element_count()]
                                    .to_vec(),
                            ),
                        )
                        .expect("the exact transformed evaluation range is accepted");
                    assert_eq!(
                        materialization
                            .completed_constraint_checkpoint_count()
                            .expect("valid mid-constraint query state is not a checkpoint"),
                        None,
                    );
                    mid_constraint_checkpoint_probe_count += 1;
                }
                RowCodeWhirQuotientMaterializationAction::Progressed => {
                    assert_eq!(
                        materialization
                            .completed_constraint_checkpoint_count()
                            .expect("valid mid-constraint block state is not a checkpoint"),
                        None,
                    );
                    mid_constraint_checkpoint_probe_count += 1;
                    progress_count += 1;
                }
                RowCodeWhirQuotientMaterializationAction::ConstraintCompleted => {
                    completed_constraint_count += 1;
                    assert!(matches!(
                        materialization
                            .next_action(
                                variant,
                                &relation_context,
                                &mut coins,
                                relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                            )
                            .expect("an unacknowledged constraint storage step is replayable"),
                        RowCodeWhirQuotientMaterializationAction::ConstraintCompleted
                    ));
                    materialization
                        .acknowledge_completed_constraint_storage_step()
                        .expect("the completed constraint storage step is acknowledged");
                    let completed_constraint_checkpoint_count = materialization
                        .completed_constraint_checkpoint_count()
                        .expect("the completed constraint boundary is checked");
                    if let Some(completed_constraint_count) = completed_constraint_checkpoint_count
                    {
                        completed_constraint_checkpoint_counts.push(completed_constraint_count);
                    }
                    if first_constraint_checkpoint.is_none()
                        && completed_constraint_checkpoint_count == Some(1)
                    {
                        first_constraint_checkpoint = Some(
                            materialization
                                .canonical_constraint_checkpoint_bytes()
                                .expect("the first constraint boundary is canonical"),
                        );
                    }
                    assert_eq!(
                        materialization.acknowledge_completed_constraint_storage_step(),
                        Err(CommonProofProverError::InvalidQuotient),
                    );
                    progress_count += 1;
                }
                RowCodeWhirQuotientMaterializationAction::PersistQuotientComponent {
                    component_ordinal,
                    polynomial,
                } => {
                    assert_eq!(
                        component_ordinal,
                        u32::try_from(actual_components.len())
                            .expect("the compact component count fits u32"),
                    );
                    assert!(matches!(
                        materialization.next_action(
                            variant,
                            &relation_context,
                            &mut coins,
                            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                        ),
                        Err(CommonProofPrivateCoinError::Prover(
                            CommonProofProverError::InvalidInput
                        ))
                    ));
                    assert_eq!(
                        materialization.acknowledge_persisted_component(
                            component_ordinal
                                .checked_add(1)
                                .expect("the hostile component ordinal fits u32"),
                        ),
                        Err(CommonProofProverError::InvalidQuotient),
                    );
                    actual_components.push(polynomial);
                    materialization
                        .acknowledge_persisted_component(component_ordinal)
                        .expect("the exact persisted component is acknowledged");
                }
                RowCodeWhirQuotientMaterializationAction::Complete => {
                    completed = true;
                    break;
                }
            }
        }

        assert!(completed, "the bounded quotient cursor must terminate");
        assert_ne!(transform_request_count, 0);
        assert_ne!(evaluation_read_count, 0);
        assert_ne!(progress_count, 0);
        assert_ne!(mid_constraint_checkpoint_probe_count, 0);
        assert!(completed_constraint_count >= 2);
        assert_eq!(completed_constraint_checkpoint_counts.first(), Some(&1));
        assert_eq!(actual_components, expected_components);
        assert!(matches!(
            materialization.next_action(
                variant,
                &relation_context,
                &mut coins,
                relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            ),
            Err(CommonProofPrivateCoinError::Prover(
                CommonProofProverError::InvalidInput
            ))
        ));

        let first_constraint_checkpoint = first_constraint_checkpoint
            .expect("the compact relation exposes a resumable nonterminal constraint boundary");
        let mut restored_materialization = RowCodeWhirQuotientMaterialization::new(
            variant,
            &relation_context,
            evaluation_domain,
            BTreeMap::new(),
            application_challenges,
            composition_challenges,
            8,
        )
        .expect("a fresh quotient cursor initializes for restoration");
        assert!(
            restored_materialization
                .canonical_constraint_checkpoint_bytes()
                .is_err(),
            "a fresh cursor cannot emit a completed-constraint checkpoint",
        );
        let mut hostile_checkpoints = vec![
            (
                "truncated state",
                first_constraint_checkpoint[..first_constraint_checkpoint.len() - 1].to_vec(),
            ),
            ("trailing state", {
                let mut trailing = first_constraint_checkpoint.clone();
                trailing.push(0);
                trailing
            }),
            ("noncanonical field value", {
                let mut noncanonical_field_value = first_constraint_checkpoint.clone();
                let final_coordinate_start =
                    noncanonical_field_value.len() - core::mem::size_of::<u64>();
                noncanonical_field_value[final_coordinate_start..]
                    .copy_from_slice(&u64::MAX.to_le_bytes());
                noncanonical_field_value
            }),
        ];
        for (field_name, field_start) in [
            ("magic", 0),
            ("version", 8),
            ("reserved word", 10),
            ("declared byte length", 12),
            ("evaluation domain size", 20),
            ("evaluation domain generator", 28),
            ("evaluation domain coset", 36),
            ("trace domain size", 44),
            ("trace rotation stride", 52),
            ("constraint count", 60),
            ("column count", 68),
            ("completed constraint count", 76),
        ] {
            let mut changed_field = first_constraint_checkpoint.clone();
            changed_field[field_start] ^= 1;
            hostile_checkpoints.push((field_name, changed_field));
        }
        for (hostile_case, hostile_checkpoint) in hostile_checkpoints {
            assert!(
                restored_materialization
                    .decode_constraint_checkpoint(&hostile_checkpoint)
                    .is_err(),
                "the {hostile_case} checkpoint must refuse",
            );
        }
        let decoded_checkpoint = restored_materialization
            .decode_constraint_checkpoint(&first_constraint_checkpoint)
            .expect("the independent fresh cursor decodes the canonical checkpoint");
        assert_eq!(decoded_checkpoint.completed_constraint_count(), 1);
        restored_materialization
            .restore_constraint_checkpoint(decoded_checkpoint)
            .expect("the first completed constraint restores exactly once");
        assert_eq!(
            restored_materialization
                .completed_constraint_checkpoint_count()
                .expect("the restored coordinate remains checked"),
            Some(1),
        );
        assert_eq!(
            restored_materialization
                .canonical_constraint_checkpoint_bytes()
                .expect("the restored accumulator re-encodes canonically"),
            first_constraint_checkpoint,
            "the restored checkpoint state must be byte-for-byte canonical",
        );
        assert!(
            restored_materialization
                .decode_constraint_checkpoint(&first_constraint_checkpoint)
                .is_err(),
            "an advanced cursor cannot consume the same checkpoint twice",
        );

        let mut restored_components = Vec::new();
        let mut restored_transformed_evaluations_by_object = BTreeMap::new();
        let mut restored_next_external_object_ordinal = 10_000_u32;
        let mut restored_coins = DeterministicZeroCoinSource;
        let mut restored_complete = false;
        for _ in 0..100_000 {
            match restored_materialization
                .next_action(
                    variant,
                    &relation_context,
                    &mut restored_coins,
                    relation_context.maximum_fiat_shamir_candidate_draws_per_output,
                )
                .expect("the restored quotient action succeeds")
            {
                RowCodeWhirQuotientMaterializationAction::TransformColumn(transform_key) => {
                    let vector = ExternalPolynomialVector::new(
                        ProofExternalMemoryObject::new(restored_next_external_object_ordinal),
                        RelationColumnValueType::BaseField,
                        evaluation_domain.size(),
                    )
                    .expect("the restored transformed vector is valid");
                    restored_transformed_evaluations_by_object.insert(
                        vector.object(),
                        transformed_column_evaluations
                            .get(
                                usize::try_from(transform_key.column_ordinal())
                                    .expect("the restored column ordinal fits usize"),
                            )
                            .expect("the restored column exists")
                            .clone(),
                    );
                    restored_next_external_object_ordinal = restored_next_external_object_ordinal
                        .checked_add(1)
                        .expect("the restored object ordinal remains bounded");
                    restored_materialization
                        .supply_transformed_column(transform_key, vector)
                        .expect("the restored transform is accepted");
                }
                RowCodeWhirQuotientMaterializationAction::ReadEvaluationRange(read_request) => {
                    restored_materialization
                        .supply_evaluation_values(
                            read_request,
                            Zeroizing::new(
                                restored_transformed_evaluations_by_object
                                    .get(&read_request.vector().object())
                                    .expect("the restored transform exists")
                                    [read_request.element_offset()
                                        ..read_request.element_offset()
                                            + read_request.element_count()]
                                    .to_vec(),
                            ),
                        )
                        .expect("the restored evaluation range is accepted");
                }
                RowCodeWhirQuotientMaterializationAction::Progressed => {}
                RowCodeWhirQuotientMaterializationAction::ConstraintCompleted => {
                    restored_materialization
                        .acknowledge_completed_constraint_storage_step()
                        .expect("the restored constraint storage step is acknowledged");
                }
                RowCodeWhirQuotientMaterializationAction::PersistQuotientComponent {
                    component_ordinal,
                    polynomial,
                } => {
                    restored_components.push(polynomial);
                    restored_materialization
                        .acknowledge_persisted_component(component_ordinal)
                        .expect("the restored component is acknowledged");
                }
                RowCodeWhirQuotientMaterializationAction::Complete => {
                    restored_complete = true;
                    break;
                }
            }
        }
        assert!(
            restored_complete,
            "the restored quotient cursor must terminate"
        );
        assert_eq!(
            restored_components, expected_components,
            "restoration must reproduce the independent whole-operation oracle byte for byte",
        );
    }
}
