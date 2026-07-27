//! WHIR proof verification.
//!
//! Local modification: the resumable verifier state is documented in
//! `../../../UPSTREAM.md`.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::Deref;
use core::slice::from_ref;

use errors::VerifierError;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Dimensions;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::constraints::statement::{EqStatement, SelectStatement};
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{SumcheckData, verify_final_sumcheck_rounds};
use tracing::instrument;

use super::utils::get_challenge_stir_queries;
use crate::alloc::string::ToString;
use crate::parameters::{RoundConfig, WhirConfig};
use crate::pcs::proof::{QueryOpening, WhirProof};

pub mod errors;

/// Replays a WHIR opening proof against a public commitment and the
/// constraint built by the layout adapter.
///
/// # Borrowing
///
/// - Config and Merkle scheme are borrowed for the lifetime of the check.
/// - Nothing is cloned across `verify` except the bounded state retained by
///   [`WhirVerificationState`].
/// - Construction is `const`; spinning up a fresh verifier per proof is free.
///
/// # Variable order
///
/// Tag declared by the prover at commit time. Selects which way folding
/// randomness is consumed in the final identity and STIR unfold:
///
/// ```text
///     Prefix:  fold(rs)         -> final eval, query unfold
///     Suffix:  fold(rs.rev())   -> same checks, reversed binding
/// ```
#[derive(Debug)]
pub struct WhirVerifier<'a, EF, F, MT, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Derived per-protocol parameters and per-round configuration.
    pub(crate) config: &'a WhirConfig<EF, F, Challenger>,
    /// Base-field Merkle commitment scheme used to authenticate STIR queries.
    pub(crate) mmcs: &'a MT,
    /// Binding direction used to interpret folding randomness.
    pub(crate) variable_order: VariableOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationPhase {
    InitialSumcheck,
    RoundCommitment(usize),
    RoundQueries(usize),
    RoundSumcheck(usize),
    FinalPolynomial,
    FinalQueries,
    FinalSumcheck,
    Complete,
}

impl VerificationPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::InitialSumcheck => "initial sumcheck",
            Self::RoundCommitment(_) => "intermediate round commitment",
            Self::RoundQueries(_) => "intermediate round queries",
            Self::RoundSumcheck(_) => "intermediate round sumcheck",
            Self::FinalPolynomial => "final polynomial",
            Self::FinalQueries => "final queries",
            Self::FinalSumcheck => "final sumcheck",
            Self::Complete => "complete proof",
        }
    }
}

struct ActiveQuerySection<F, EF> {
    round_index: usize,
    num_variables: usize,
    query_indices: Vec<usize>,
    next_query_ordinal: usize,
    folded_domain_generator: F,
    domain_height: usize,
    row_width: usize,
    query_randomness: Point<EF>,
    folded_values: Vec<EF>,
}

/// Bounded resumable replay of one WHIR opening proof.
///
/// The state retains only transcript-derived constraints, folding challenges,
/// the roots needed by the active round, the active round's sampled query
/// indices and folded answers, and the final direct-send polynomial. Each
/// Merkle path and opened row is authenticated and folded by [`Self::verify_query`]
/// before the caller reads the next query.
///
/// Callers must invoke the methods in protocol order. A repeated, omitted, or
/// reordered transition is rejected without advancing the state.
pub struct WhirVerificationState<F, EF, MT>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    mmcs: MT,
    variable_order: VariableOrder,
    round_parameters: Vec<RoundConfig<F>>,
    folding_schedule: Vec<usize>,
    starting_folding_pow_bits: usize,
    final_round_parameters: RoundConfig<F>,
    final_sumcheck_rounds: usize,
    final_folding_pow_bits: usize,
    phase: VerificationPhase,
    constraints: Vec<Constraint<F, EF>>,
    round_folding_randomness: Vec<Point<EF>>,
    previous_commitment: MT::Commitment,
    pending_commitment: Option<MT::Commitment>,
    pending_ood_statement: Option<EqStatement<EF>>,
    claimed_evaluation: EF,
    active_queries: Option<ActiveQuerySection<F, EF>>,
    final_polynomial: Option<Poly<EF>>,
}

impl<F, EF, MT> WhirVerificationState<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F>,
{
    fn new<Challenger>(
        config: &WhirConfig<EF, F, Challenger>,
        mmcs: &MT,
        variable_order: VariableOrder,
        parsed_commitment: &MT::Commitment,
        initial_constraint: Constraint<F, EF>,
        claimed_evaluation: EF,
    ) -> Self
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self {
            mmcs: mmcs.clone(),
            variable_order,
            round_parameters: config.round_parameters.clone(),
            folding_schedule: config.folding_schedule.clone(),
            starting_folding_pow_bits: config.starting_folding_pow_bits,
            final_round_parameters: config.final_round_config(),
            final_sumcheck_rounds: config.final_sumcheck_rounds,
            final_folding_pow_bits: config.final_folding_pow_bits,
            phase: VerificationPhase::InitialSumcheck,
            constraints: vec![initial_constraint],
            round_folding_randomness: Vec::with_capacity(config.n_rounds() + 2),
            previous_commitment: parsed_commitment.clone(),
            pending_commitment: None,
            pending_ood_statement: None,
            claimed_evaluation,
            active_queries: None,
            final_polynomial: None,
        }
    }

    const fn phase(&self) -> VerificationPhase {
        self.phase
    }

    fn require_phase(&self, expected: VerificationPhase) -> Result<(), VerifierError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(VerifierError::InvalidVerificationPhase {
                expected: expected.label(),
                actual: self.phase.label(),
            })
        }
    }

    const fn number_of_intermediate_rounds(&self) -> usize {
        self.round_parameters.len()
    }

    /// Conservative live byte count for owned verifier state.
    ///
    /// This includes the state value and every protocol-sized vector payload.
    /// Commitment implementations may retain allocator metadata internally;
    /// callers that know the concrete commitment representation can add that
    /// implementation-specific payload separately.
    pub fn resident_byte_length(&self) -> usize {
        let mut byte_length = core::mem::size_of::<Self>()
            .saturating_add(
                self.round_parameters
                    .capacity()
                    .saturating_mul(core::mem::size_of::<RoundConfig<F>>()),
            )
            .saturating_add(
                self.folding_schedule
                    .capacity()
                    .saturating_mul(core::mem::size_of::<usize>()),
            )
            .saturating_add(
                self.constraints
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Constraint<F, EF>>()),
            )
            .saturating_add(
                self.round_folding_randomness
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Point<EF>>()),
            );
        for constraint in &self.constraints {
            for statement in constraint.statements() {
                byte_length = byte_length.saturating_add(
                    statement
                        .len()
                        .saturating_mul(statement.num_variables().saturating_add(1))
                        .saturating_mul(core::mem::size_of::<EF>()),
                );
            }
        }
        byte_length = byte_length.saturating_add(
            self.round_folding_randomness
                .iter()
                .map(|point| {
                    point
                        .as_slice()
                        .len()
                        .saturating_mul(core::mem::size_of::<EF>())
                })
                .fold(0_usize, usize::saturating_add),
        );
        if let Some(ood_statement) = &self.pending_ood_statement {
            byte_length = byte_length.saturating_add(
                ood_statement
                    .len()
                    .saturating_mul(ood_statement.num_variables().saturating_add(1))
                    .saturating_mul(core::mem::size_of::<EF>()),
            );
        }
        if let Some(active_queries) = &self.active_queries {
            byte_length = byte_length
                .saturating_add(
                    active_queries
                        .query_indices
                        .capacity()
                        .saturating_mul(core::mem::size_of::<usize>()),
                )
                .saturating_add(
                    active_queries
                        .folded_values
                        .capacity()
                        .saturating_mul(core::mem::size_of::<EF>()),
                )
                .saturating_add(
                    active_queries
                        .query_randomness
                        .as_slice()
                        .len()
                        .saturating_mul(core::mem::size_of::<EF>()),
                );
        }
        if let Some(final_polynomial) = &self.final_polynomial {
            byte_length = byte_length.saturating_add(
                final_polynomial
                    .as_slice()
                    .len()
                    .saturating_mul(core::mem::size_of::<EF>()),
            );
        }
        byte_length
    }

    /// Consumes the initial folding sumcheck.
    pub fn verify_initial_sumcheck<Challenger>(
        &mut self,
        sumcheck: &SumcheckData<F, EF>,
        challenger: &mut Challenger,
    ) -> Result<(), VerifierError>
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        self.require_phase(VerificationPhase::InitialSumcheck)?;
        let initial_folding_factor = self.folding_schedule.first().copied().ok_or(
            VerifierError::IncompleteVerificationState {
                details: "folding schedule has no initial phase",
            },
        )?;
        let folding_randomness = sumcheck.verify_rounds(
            challenger,
            &mut self.claimed_evaluation,
            initial_folding_factor,
            self.starting_folding_pow_bits,
        )?;
        self.round_folding_randomness.push(folding_randomness);
        self.phase = if self.round_parameters.is_empty() {
            VerificationPhase::FinalPolynomial
        } else {
            VerificationPhase::RoundCommitment(0)
        };
        Ok(())
    }

    /// Consumes an intermediate commitment, its OOD claims, and its query
    /// challenge checkpoint.
    pub fn begin_round<Challenger>(
        &mut self,
        round_index: usize,
        commitment: MT::Commitment,
        ood_answers: &[EF],
        pow_witness: F,
        challenger: &mut Challenger,
    ) -> Result<(), VerifierError>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanSampleUniformBits<F>
            + CanObserve<MT::Commitment>,
    {
        self.require_phase(VerificationPhase::RoundCommitment(round_index))?;
        let round_parameters = self
            .round_parameters
            .get(round_index)
            .cloned()
            .ok_or(VerifierError::InvalidRoundIndex { index: round_index })?;
        if ood_answers.len() != round_parameters.ood_samples {
            return Err(VerifierError::RoundOodAnswerCountMismatch {
                round: round_index,
                expected: round_parameters.ood_samples,
                actual: ood_answers.len(),
            });
        }

        challenger.observe(commitment.clone());
        let mut ood_statement = EqStatement::initialize(round_parameters.num_variables);
        for &evaluation in ood_answers {
            let point = challenger.sample_algebra_element();
            let point = Point::expand_from_univariate(point, round_parameters.num_variables);
            challenger.observe_algebra_element(evaluation);
            ood_statement.add_evaluated_constraint(point, evaluation);
        }
        if round_parameters.pow_bits > 0
            && !challenger.check_witness(round_parameters.pow_bits, pow_witness)
        {
            return Err(VerifierError::InvalidPowWitness);
        }

        challenger.sample();
        let folding_randomness = self
            .round_folding_randomness
            .last()
            .cloned()
            .ok_or(VerifierError::MissingFoldingRandomness { round: round_index })?;
        self.active_queries = Some(Self::sample_query_section(
            round_index,
            &round_parameters,
            folding_randomness,
            self.variable_order,
            challenger,
        ));
        self.pending_commitment = Some(commitment);
        self.pending_ood_statement = Some(ood_statement);
        self.phase = VerificationPhase::RoundQueries(round_index);
        Ok(())
    }

    fn sample_query_section<Challenger>(
        round_index: usize,
        round_parameters: &RoundConfig<F>,
        folding_randomness: Point<EF>,
        variable_order: VariableOrder,
        challenger: &mut Challenger,
    ) -> ActiveQuerySection<F, EF>
    where
        Challenger: FieldChallenger<F> + CanSampleUniformBits<F>,
    {
        let query_indices = get_challenge_stir_queries::<Challenger, F>(
            round_parameters.domain_size,
            round_parameters.folding_factor,
            round_parameters.num_queries,
            challenger,
        );
        let query_randomness = match variable_order {
            VariableOrder::Prefix => folding_randomness,
            VariableOrder::Suffix => folding_randomness.reversed(),
        };
        ActiveQuerySection {
            round_index,
            num_variables: round_parameters.num_variables,
            folded_values: Vec::with_capacity(query_indices.len()),
            query_indices,
            next_query_ordinal: 0,
            folded_domain_generator: round_parameters.folded_domain_gen,
            domain_height: round_parameters.domain_size >> round_parameters.folding_factor,
            row_width: 1 << round_parameters.folding_factor,
            query_randomness,
        }
    }

    /// Authenticates and folds one query opening at its exact sampled ordinal.
    pub fn verify_query(
        &mut self,
        round_index: usize,
        query_ordinal: usize,
        query: &QueryOpening<F, EF, MT::Proof>,
    ) -> Result<(), VerifierError> {
        let expected_phase = if round_index == self.number_of_intermediate_rounds() {
            VerificationPhase::FinalQueries
        } else {
            VerificationPhase::RoundQueries(round_index)
        };
        self.require_phase(expected_phase)?;

        let active_queries =
            self.active_queries
                .as_ref()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "active query section is missing",
                })?;
        if active_queries.round_index != round_index {
            return Err(VerifierError::InvalidRoundIndex { index: round_index });
        }
        if query_ordinal != active_queries.next_query_ordinal {
            return Err(VerifierError::UnexpectedQueryOrdinal {
                round_index,
                expected: active_queries.next_query_ordinal,
                actual: query_ordinal,
            });
        }
        let query_index = active_queries
            .query_indices
            .get(query_ordinal)
            .copied()
            .ok_or(VerifierError::UnexpectedQueryOrdinal {
                round_index,
                expected: active_queries.query_indices.len(),
                actual: query_ordinal,
            })?;
        let dimensions = [Dimensions {
            height: active_queries.domain_height,
            width: active_queries.row_width,
        }];
        let query_randomness = active_queries.query_randomness.clone();

        let values = match query {
            QueryOpening::Base { values, proof } => {
                self.mmcs
                    .verify_batch(
                        &self.previous_commitment,
                        &dimensions,
                        query_index,
                        BatchOpeningRef {
                            opened_values: from_ref(values),
                            opening_proof: proof,
                        },
                    )
                    .map_err(|_| VerifierError::MerkleProofInvalid {
                        position: query_index,
                        reason: "Base field Merkle proof verification failed".to_string(),
                    })?;
                values.iter().copied().map(Into::into).collect()
            }
            QueryOpening::Extension { values, proof } => {
                ExtensionMmcs::new(&self.mmcs)
                    .verify_batch(
                        &self.previous_commitment,
                        &dimensions,
                        query_index,
                        BatchOpeningRef {
                            opened_values: from_ref(values),
                            opening_proof: proof,
                        },
                    )
                    .map_err(|_| VerifierError::MerkleProofInvalid {
                        position: query_index,
                        reason: "Extension field Merkle proof verification failed".to_string(),
                    })?;
                values.clone()
            }
        };
        let folded_value = Poly::new(values).eval_ext::<F>(&query_randomness);
        let active_queries =
            self.active_queries
                .as_mut()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "active query section disappeared",
                })?;
        active_queries.folded_values.push(folded_value);
        active_queries.next_query_ordinal += 1;
        Ok(())
    }

    fn take_query_statement(
        &mut self,
        round_index: usize,
    ) -> Result<SelectStatement<F, EF>, VerifierError> {
        let active_queries =
            self.active_queries
                .as_ref()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "active query section is missing",
                })?;
        if active_queries.next_query_ordinal != active_queries.query_indices.len() {
            return Err(VerifierError::StirQueryCountMismatch {
                round_index,
                expected: active_queries.query_indices.len(),
                actual: active_queries.next_query_ordinal,
            });
        }
        let active_queries =
            self.active_queries
                .take()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "active query section disappeared",
                })?;
        let selector_values = active_queries
            .query_indices
            .into_iter()
            .map(|index| active_queries.folded_domain_generator.exp_u64(index as u64))
            .collect();
        Ok(SelectStatement::new(
            active_queries.num_variables,
            selector_values,
            active_queries.folded_values,
        ))
    }

    /// Completes an intermediate query section and batches it with the OOD
    /// statement fixed by [`Self::begin_round`].
    pub fn finish_round_queries<Challenger>(
        &mut self,
        round_index: usize,
        challenger: &mut Challenger,
    ) -> Result<(), VerifierError>
    where
        Challenger: FieldChallenger<F>,
    {
        self.require_phase(VerificationPhase::RoundQueries(round_index))?;
        let stir_statement = self.take_query_statement(round_index)?;
        let ood_statement = self.pending_ood_statement.take().ok_or(
            VerifierError::IncompleteVerificationState {
                details: "round OOD statement is missing",
            },
        )?;
        let constraint = Constraint::new(
            challenger.sample_algebra_element(),
            ood_statement.num_variables(),
            vec![
                Statements::Eq(ood_statement),
                Statements::Select(stir_statement),
            ],
        );
        constraint.combine_evals(&mut self.claimed_evaluation);
        self.constraints.push(constraint);
        self.previous_commitment =
            self.pending_commitment
                .take()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "next round commitment is missing",
                })?;
        self.phase = VerificationPhase::RoundSumcheck(round_index);
        Ok(())
    }

    /// Consumes the folding sumcheck that follows one intermediate query
    /// section.
    pub fn verify_round_sumcheck<Challenger>(
        &mut self,
        round_index: usize,
        sumcheck: &SumcheckData<F, EF>,
        challenger: &mut Challenger,
    ) -> Result<(), VerifierError>
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        self.require_phase(VerificationPhase::RoundSumcheck(round_index))?;
        let round_parameters = self
            .round_parameters
            .get(round_index)
            .ok_or(VerifierError::InvalidRoundIndex { index: round_index })?;
        let next_folding_factor = self.folding_schedule.get(round_index + 1).copied().ok_or(
            VerifierError::IncompleteVerificationState {
                details: "next folding factor is missing",
            },
        )?;
        let folding_randomness = sumcheck.verify_rounds(
            challenger,
            &mut self.claimed_evaluation,
            next_folding_factor,
            round_parameters.folding_pow_bits,
        )?;
        self.round_folding_randomness.push(folding_randomness);
        self.phase = if round_index + 1 == self.round_parameters.len() {
            VerificationPhase::FinalPolynomial
        } else {
            VerificationPhase::RoundCommitment(round_index + 1)
        };
        Ok(())
    }

    /// Consumes and binds the final direct-send polynomial, then derives the
    /// final query positions.
    pub fn begin_final_polynomial<Challenger>(
        &mut self,
        final_polynomial: Poly<EF>,
        pow_witness: F,
        challenger: &mut Challenger,
    ) -> Result<(), VerifierError>
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
    {
        self.require_phase(VerificationPhase::FinalPolynomial)?;
        let expected_length = 1usize << self.final_round_parameters.num_variables;
        let actual_length = final_polynomial.num_evals();
        if actual_length != expected_length {
            return Err(VerifierError::FinalPolyLengthMismatch {
                expected: expected_length,
                actual: actual_length,
            });
        }
        challenger.observe_algebra_slice(final_polynomial.as_slice());
        if self.final_round_parameters.pow_bits > 0
            && !challenger.check_witness(self.final_round_parameters.pow_bits, pow_witness)
        {
            return Err(VerifierError::InvalidPowWitness);
        }
        let folding_randomness = self.round_folding_randomness.last().cloned().ok_or(
            VerifierError::MissingFoldingRandomness {
                round: self.number_of_intermediate_rounds(),
            },
        )?;
        let final_round_index = self.number_of_intermediate_rounds();
        self.active_queries = Some(Self::sample_query_section(
            final_round_index,
            &self.final_round_parameters,
            folding_randomness,
            self.variable_order,
            challenger,
        ));
        self.final_polynomial = Some(final_polynomial);
        self.phase = VerificationPhase::FinalQueries;
        Ok(())
    }

    /// Completes the final query section and checks it directly against the
    /// final polynomial.
    pub fn finish_final_queries(&mut self) -> Result<(), VerifierError> {
        self.require_phase(VerificationPhase::FinalQueries)?;
        let final_round_index = self.number_of_intermediate_rounds();
        let stir_statement = self.take_query_statement(final_round_index)?;
        let final_polynomial =
            self.final_polynomial
                .as_ref()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "final polynomial is missing",
                })?;
        if !stir_statement.verify(final_polynomial) {
            return Err(VerifierError::StirChallengeFailed {
                challenge_id: 0,
                details: "STIR constraint verification failed on final polynomial".to_string(),
            });
        }
        self.phase = VerificationPhase::FinalSumcheck;
        Ok(())
    }

    /// Consumes the terminal sumcheck and checks the final WHIR identity.
    pub fn verify_final_sumcheck<Challenger>(
        &mut self,
        final_sumcheck: Option<&SumcheckData<F, EF>>,
        challenger: &mut Challenger,
    ) -> Result<Point<EF>, VerifierError>
    where
        Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        self.require_phase(VerificationPhase::FinalSumcheck)?;
        let final_sumcheck_randomness = verify_final_sumcheck_rounds(
            final_sumcheck,
            challenger,
            &mut self.claimed_evaluation,
            self.final_sumcheck_rounds,
            self.final_folding_pow_bits,
        )?;
        self.round_folding_randomness
            .push(final_sumcheck_randomness.clone());
        let folding_randomness = Point::new(
            self.round_folding_randomness
                .iter()
                .flat_map(|point| point.as_slice().iter().copied())
                .collect(),
        );
        let evaluation_of_weights = self
            .variable_order
            .eval_constraints_poly(&self.constraints, &folding_randomness);
        let final_polynomial =
            self.final_polynomial
                .as_ref()
                .ok_or(VerifierError::IncompleteVerificationState {
                    details: "final polynomial is missing",
                })?;
        let final_value = match self.variable_order {
            VariableOrder::Prefix => final_polynomial.eval_ext::<F>(&final_sumcheck_randomness),
            VariableOrder::Suffix => {
                final_polynomial.eval_ext::<F>(&final_sumcheck_randomness.reversed())
            }
        };
        let expected_evaluation = evaluation_of_weights * final_value;
        if self.claimed_evaluation != expected_evaluation {
            return Err(VerifierError::SumcheckFailed {
                round: self.final_sumcheck_rounds,
                expected: expected_evaluation.to_string(),
                actual: self.claimed_evaluation.to_string(),
            });
        }
        self.phase = VerificationPhase::Complete;
        Ok(folding_randomness)
    }

    /// Confirms that every proof section has been consumed successfully.
    pub fn finish(self) -> Result<(), VerifierError> {
        if self.phase() == VerificationPhase::Complete {
            Ok(())
        } else {
            Err(VerifierError::InvalidVerificationPhase {
                expected: VerificationPhase::Complete.label(),
                actual: self.phase().label(),
            })
        }
    }
}

impl<'a, EF, F, MT, Challenger> WhirVerifier<'a, EF, F, MT, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F> + CanSampleUniformBits<F>,
{
    /// Wraps the verifier-side dependencies into a single replay context.
    pub const fn new(
        config: &'a WhirConfig<EF, F, Challenger>,
        mmcs: &'a MT,
        variable_order: VariableOrder,
    ) -> Self {
        Self {
            config,
            mmcs,
            variable_order,
        }
    }

    /// Starts bounded replay after the layout adapter has bound the initial
    /// opening constraint and claim.
    pub fn start(
        &self,
        parsed_commitment: &MT::Commitment,
        initial_constraint: Constraint<F, EF>,
        claimed_evaluation: EF,
    ) -> WhirVerificationState<F, EF, MT> {
        WhirVerificationState::new(
            self.config,
            self.mmcs,
            self.variable_order,
            parsed_commitment,
            initial_constraint,
            claimed_evaluation,
        )
    }

    /// Verifies a complete WHIR proof by driving the same resumable state used
    /// by bounded streaming decoders.
    #[instrument(skip_all)]
    pub fn verify(
        &self,
        proof: &WhirProof<F, EF, MT>,
        challenger: &mut Challenger,
        parsed_commitment: &MT::Commitment,
        initial_constraint: Constraint<F, EF>,
        claimed_evaluation: EF,
    ) -> Result<Point<EF>, VerifierError>
    where
        Challenger: CanObserve<MT::Commitment>,
    {
        let expected_rounds = self.n_rounds();
        if proof.rounds.len() != expected_rounds {
            return Err(VerifierError::RoundCountMismatch {
                expected: expected_rounds,
                actual: proof.rounds.len(),
            });
        }

        let mut verification =
            self.start(parsed_commitment, initial_constraint, claimed_evaluation);
        verification.verify_initial_sumcheck(&proof.initial_sumcheck, challenger)?;

        for (round_index, round_proof) in proof.rounds.iter().enumerate() {
            let commitment = round_proof
                .commitment
                .clone()
                .ok_or(VerifierError::MissingRoundCommitment { round: round_index })?;
            verification.begin_round(
                round_index,
                commitment,
                &round_proof.ood_answers,
                round_proof.pow_witness,
                challenger,
            )?;
            let expected_query_count = self.round_parameters[round_index].num_queries;
            if round_proof.queries.len() != expected_query_count {
                return Err(VerifierError::StirQueryCountMismatch {
                    round_index,
                    expected: expected_query_count,
                    actual: round_proof.queries.len(),
                });
            }
            for (query_ordinal, query) in round_proof.queries.iter().enumerate() {
                verification.verify_query(round_index, query_ordinal, query)?;
            }
            verification.finish_round_queries(round_index, challenger)?;
            verification.verify_round_sumcheck(round_index, &round_proof.sumcheck, challenger)?;
        }

        let final_polynomial = proof
            .final_poly
            .clone()
            .ok_or(VerifierError::MissingFinalPoly)?;
        verification.begin_final_polynomial(
            final_polynomial,
            proof.final_pow_witness,
            challenger,
        )?;
        if proof.final_queries.len() != self.final_queries {
            return Err(VerifierError::StirQueryCountMismatch {
                round_index: expected_rounds,
                expected: self.final_queries,
                actual: proof.final_queries.len(),
            });
        }
        for (query_ordinal, query) in proof.final_queries.iter().enumerate() {
            verification.verify_query(expected_rounds, query_ordinal, query)?;
        }
        verification.finish_final_queries()?;
        verification.verify_final_sumcheck(proof.final_sumcheck.as_ref(), challenger)
    }
}

impl<EF, F, MT, Challenger> Deref for WhirVerifier<'_, EF, F, MT, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    type Target = WhirConfig<EF, F, Challenger>;

    fn deref(&self) -> &Self::Target {
        self.config
    }
}
