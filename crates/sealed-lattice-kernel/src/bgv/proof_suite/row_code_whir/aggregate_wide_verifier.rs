//! Verifier replay for the aggregate-wide hiding opening.
//!
//! The source and pad commitments are observed by the enclosing exact-proof
//! verifier before it derives the opening schedule. This module starts from
//! that committed transcript state, replays every masked sumcheck and switch,
//! and ends in the theorem-backed masked base case.

use core::slice::from_ref;

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Dimensions;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch,
    constraints::{Constraint, Statements, statement::SelectStatement},
    layout::TableShape,
    zk::ZkVerifier,
};
use p3_whir::{
    BaseCaseZkConfig, BaseCaseZkError, BaseCaseZkProof, BaseCaseZkVerifier, FoldedRsCode,
    MaskCodeShape, MaskGroupShape, QueryOpening, switch_mask_covector,
};

use super::aggregate_wide_hiding::{
    AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE, AggregateWidePadClaim, AggregateWidePadLayout,
    AggregateWideSourceConstraints,
};
use super::aggregate_wide_pcs::{AggregateWideCommitment, AggregateWidePcs};
use super::aggregate_wide_wire::CompactAggregateWideOpeningProof;
use super::hiding_whir::SelectedHidingWhirConfig;
use super::oracle_geometry::sample_distinct_query_indices;
use super::{ChallengeField, ExtensionFieldChallenger};

enum ActiveOracle<'a> {
    Initial(&'a AggregateWideCommitment),
    Folded(&'a AggregateWideCommitment),
}

impl ActiveOracle<'_> {
    fn commitment(&self) -> &AggregateWideCommitment {
        match self {
            Self::Initial(commitment) | Self::Folded(commitment) => commitment,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_compact_aggregate_wide_opening_after_observed_commitments(
    pcs: &AggregateWidePcs,
    configuration: &SelectedHidingWhirConfig,
    proof: &CompactAggregateWideOpeningProof,
    source_commitment: &AggregateWideCommitment,
    pad_commitment: &AggregateWideCommitment,
    table_width: usize,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    expected_evaluations: &[OpeningBatch<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    verify_compact_aggregate_wide_proof_after_observed_commitments(
        pcs,
        configuration,
        proof,
        source_commitment,
        pad_commitment,
        table_width,
        points,
        requested_columns_by_point,
        expected_evaluations,
        challenger,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn verify_compact_aggregate_wide_proof_after_observed_commitments(
    pcs: &AggregateWidePcs,
    configuration: &SelectedHidingWhirConfig,
    proof: &CompactAggregateWideOpeningProof,
    source_commitment: &AggregateWideCommitment,
    pad_commitment: &AggregateWideCommitment,
    table_width: usize,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    expected_evaluations: &[OpeningBatch<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    validate_statement_and_proof_shape(
        pcs,
        configuration,
        proof,
        pad_commitment,
        table_width,
        points,
        requested_columns_by_point,
        expected_evaluations,
    )?;

    let sumchecks = &proof.sumchecks;

    let pad_layout = AggregateWidePadLayout::derive(configuration)?;
    let table_shape = TableShape::new(configuration.num_variables, table_width);
    let mut layout_verifier =
        ZkVerifier::<ChallengeField, ChallengeField>::new_prefix(from_ref(&table_shape));
    for ((point, requested_columns), evaluations) in points
        .iter()
        .zip(requested_columns_by_point)
        .zip(expected_evaluations)
    {
        let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
        layout_verifier
            .add_claim_at_point(0, &request, evaluations, point.clone(), challenger)
            .map_err(|error| format!("record aggregate-wide opening claim: {error}"))?;
    }

    let initial_folding = configuration.round_folding_factor(0);
    let (initial_handoff, initial_constraint) = layout_verifier
        .into_precommitted_sumcheck_with_constraint(
            &sumchecks[0],
            configuration.zk.ell_zk,
            initial_folding,
            configuration.starting_folding_pow_bits,
            challenger,
        )
        .map_err(|error| format!("verify initial aggregate-wide sumcheck: {error}"))?;
    let mut source_constraints = AggregateWideSourceConstraints::new(initial_constraint);
    source_constraints.record_masked_sumcheck(initial_handoff.eps, &initial_handoff.randomness);
    let mut pad_claim = AggregateWidePadClaim::new(pad_layout.message_length());
    pad_claim.record_sumcheck_batch(
        pad_layout.sumcheck_batch(0)?,
        initial_handoff.eps,
        &initial_handoff.randomness,
    )?;
    let mut current_target = initial_handoff.claimed_residual;
    let mut folding_randomness = initial_handoff.randomness;
    let mut active_oracle = ActiveOracle::Initial(source_commitment);
    let mut remaining_variable_count = configuration.num_variables - initial_folding;

    for round_ordinal in 0..configuration.n_rounds() {
        let round = &proof.rounds[round_ordinal];
        let round_commitment = &round.commitment;
        let switch_mask_delta = &round.switch_mask_delta;
        let proof_of_work_witness = round.proof_of_work_witness;
        let round_configuration = &configuration.round_parameters[round_ordinal];
        let current_folding = configuration.round_folding_factor(round_ordinal);
        let next_folding = configuration.round_folding_factor(round_ordinal + 1);

        challenger.observe(round_commitment.clone());
        let switch_range = pad_layout.switch_mask_range(round_ordinal)?;
        if switch_mask_delta.len() != switch_range.len() {
            return Err(format!(
                "aggregate-wide round {round_ordinal} has {} switch-mask delta coordinates, expected {}",
                switch_mask_delta.len(),
                switch_range.len(),
            ));
        }
        challenger.observe_algebra_slice(switch_mask_delta);
        if round_configuration.pow_bits > 0
            && !challenger.check_witness(round_configuration.pow_bits, proof_of_work_witness)
        {
            return Err(format!(
                "aggregate-wide round {round_ordinal} has an invalid proof-of-work witness"
            ));
        }
        let _: ChallengeField = challenger.sample();
        let query_indices = sample_distinct_query_indices(
            round_configuration.domain_size,
            current_folding,
            round_configuration.num_queries,
            challenger,
        )?;
        let round_queries = proof.rounds[round_ordinal]
            .queries
            .materialize(&query_indices, active_oracle.commitment())?;
        if round_queries.len() != query_indices.len() {
            return Err(format!(
                "aggregate-wide round {round_ordinal} has {} queries, expected {}",
                round_queries.len(),
                query_indices.len()
            ));
        }

        let dimensions = [Dimensions {
            height: round_configuration.domain_size >> current_folding,
            width: 1 << current_folding,
        }];
        let mut public_statement = SelectStatement::initialize(remaining_variable_count);
        let mut query_points = Vec::with_capacity(query_indices.len());
        for (&query_index, opening) in query_indices.iter().zip(&round_queries) {
            let folded_value = verify_and_fold_opening(
                pcs,
                &active_oracle,
                &dimensions,
                query_index,
                opening,
                round_ordinal,
                &folding_randomness,
            )?;
            let query_point = round_configuration
                .folded_domain_gen
                .exp_u64(query_index as u64);
            public_statement.add_constraint(query_point, folded_value);
            query_points.push(query_point);
        }

        let combination: ChallengeField = challenger.sample_algebra_element();
        let public_constraint = Constraint::new(
            combination,
            remaining_variable_count,
            vec![Statements::Select(public_statement)],
        );
        public_constraint.combine_evals(&mut current_target);
        source_constraints.batch_constraint(public_constraint.clone());
        pad_claim.batch_carried_claim(public_constraint.carried_claim_multiplier());

        let query_coefficients = public_constraint
            .challenge_powers(0)
            .take(query_points.len())
            .collect::<Vec<_>>();
        let logical_mask_covector = switch_mask_covector(
            1 << remaining_variable_count,
            configuration.oracle_randomness[round_ordinal],
            0,
            &[],
            &[],
            &query_points,
            &query_coefficients,
        );
        pad_claim.record_switch_mask_delta(
            switch_range,
            &logical_mask_covector,
            switch_mask_delta,
        )?;

        let next_handoff = ZkVerifier::<ChallengeField, ChallengeField>::verify_precommitted_claim(
            &sumchecks[round_ordinal + 1],
            configuration.zk.ell_zk,
            next_folding,
            round_configuration.folding_pow_bits,
            current_target,
            challenger,
        )
        .map_err(|error| {
            format!("verify aggregate-wide sumcheck after round {round_ordinal}: {error}")
        })?;
        source_constraints.record_masked_sumcheck(next_handoff.eps, &next_handoff.randomness);
        pad_claim.record_sumcheck_batch(
            pad_layout.sumcheck_batch(round_ordinal + 1)?,
            next_handoff.eps,
            &next_handoff.randomness,
        )?;
        current_target = next_handoff.claimed_residual;
        folding_randomness = next_handoff.randomness;
        active_oracle = ActiveOracle::Folded(round_commitment);
        remaining_variable_count = remaining_variable_count
            .checked_sub(next_folding)
            .ok_or_else(|| "aggregate-wide verifier folded too many variables".to_owned())?;
    }

    let final_configuration = configuration.final_round_config();
    if remaining_variable_count != final_configuration.num_variables {
        return Err(format!(
            "aggregate-wide terminal variable count is {remaining_variable_count}, expected {}",
            final_configuration.num_variables
        ));
    }
    let source_code = FoldedRsCode::new(
        1 << final_configuration.num_variables,
        configuration.oracle_randomness[configuration.n_rounds()],
        final_configuration.domain_size >> final_configuration.folding_factor,
    );
    let pad_shape = MaskCodeShape::new(
        pad_layout.message_length(),
        configuration.mask_queries,
        AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    );
    let base_configuration = BaseCaseZkConfig {
        code: source_code,
        mask_groups: vec![MaskGroupShape {
            shape: pad_shape,
            width: 1,
        }],
        num_queries: configuration.final_queries,
        mask_queries: configuration.mask_queries,
        pow_bits: configuration.final_pow_bits,
    };
    let base_verifier = BaseCaseZkVerifier {
        config: &base_configuration,
        extension_mmcs: &pcs.extension_mmcs,
    };
    let source_covector = source_constraints.terminal_covector(remaining_variable_count)?;
    let source_dimensions = [Dimensions {
        height: final_configuration.domain_size >> final_configuration.folding_factor,
        width: 1 << final_configuration.folding_factor,
    }];
    let base_target = current_target - pad_claim.public_offset();
    let base_case = materialize_base_case(
        proof,
        configuration,
        &pad_layout,
        active_oracle.commitment(),
        pad_commitment,
        challenger,
    )?;
    base_verifier
        .verify(
            &base_case,
            &source_covector,
            from_ref(pad_claim.covector_vector()),
            from_ref(pad_commitment),
            base_target,
            |position, opening| {
                verify_and_fold_opening(
                    pcs,
                    &active_oracle,
                    &source_dimensions,
                    position,
                    opening,
                    configuration.n_rounds(),
                    &folding_randomness,
                )
                .map_err(|_| BaseCaseZkError::SourceOpeningRejected { position })
            },
            challenger,
        )
        .map_err(|error| format!("verify aggregate-wide base case: {error}"))?;
    challenger.ensure_sampling_succeeded()?;
    challenger.ensure_query_schedule_consumed()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_statement_and_proof_shape(
    pcs: &AggregateWidePcs,
    configuration: &SelectedHidingWhirConfig,
    proof: &CompactAggregateWideOpeningProof,
    _pad_commitment: &AggregateWideCommitment,
    table_width: usize,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    expected_evaluations: &[OpeningBatch<ChallengeField>],
) -> Result<(), String> {
    let proof_evaluations = &proof.evaluations;
    let round_count = proof.rounds.len();
    let sumcheck_count = proof.sumchecks.len();
    if pcs.num_variables != configuration.num_variables
        || pcs.n_rounds() != configuration.n_rounds()
    {
        return Err("aggregate-wide verifier configuration or pad commitment diverged".to_owned());
    }
    if table_width == 0
        || points.len() != requested_columns_by_point.len()
        || points.len() != expected_evaluations.len()
        || proof_evaluations != expected_evaluations
    {
        return Err(
            "aggregate-wide opening statement has the wrong shape or evaluations".to_owned(),
        );
    }
    for ((point, requested_columns), evaluations) in points
        .iter()
        .zip(requested_columns_by_point)
        .zip(expected_evaluations)
    {
        if point.num_variables() != configuration.num_variables
            || requested_columns.is_empty()
            || requested_columns
                .iter()
                .any(|column| *column >= table_width)
            || requested_columns.windows(2).any(|pair| pair[0] >= pair[1])
            || evaluations.current().len() != requested_columns.len()
            || !evaluations.next().is_empty()
        {
            return Err("aggregate-wide opening claim is not canonical".to_owned());
        }
    }
    if round_count != configuration.n_rounds() || sumcheck_count != configuration.n_rounds() + 1 {
        return Err("aggregate-wide proof has the wrong round or sumcheck count".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_base_query_schedules(
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
    fresh_main_commitment: &AggregateWideCommitment,
    fresh_pad_commitment: &AggregateWideCommitment,
    masked_claim: ChallengeField,
    blinded_message: &[ChallengeField],
    blinded_randomness: &[ChallengeField],
    blinded_pad_message: &[ChallengeField],
    blinded_pad_randomness: &[ChallengeField],
    proof_of_work_witness: ChallengeField,
    challenger: &ExtensionFieldChallenger,
) -> Result<(Vec<usize>, Vec<usize>), String> {
    let mut schedule_challenger = challenger.clone();
    schedule_challenger.observe(fresh_main_commitment.clone());
    schedule_challenger.observe(fresh_pad_commitment.clone());
    schedule_challenger.observe_algebra_element(masked_claim);
    let _: ChallengeField = schedule_challenger.sample_algebra_element();
    schedule_challenger.observe_algebra_slice(blinded_message);
    schedule_challenger.observe_algebra_slice(blinded_randomness);
    schedule_challenger.observe_algebra_slice(blinded_pad_message);
    schedule_challenger.observe_algebra_slice(blinded_pad_randomness);
    if configuration.final_pow_bits > 0
        && !schedule_challenger.check_witness(configuration.final_pow_bits, proof_of_work_witness)
    {
        return Err("aggregate-wide base case has an invalid proof-of-work witness".to_owned());
    }
    let final_configuration = configuration.final_round_config();
    let source_query_indices = sample_distinct_query_indices(
        final_configuration.domain_size,
        0,
        configuration.final_queries,
        &mut schedule_challenger,
    )?;
    let pad_domain_size = (pad_layout.message_length() + configuration.mask_queries)
        .next_power_of_two()
        << AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE;
    let pad_query_indices = sample_distinct_query_indices(
        pad_domain_size,
        0,
        configuration.mask_queries,
        &mut schedule_challenger,
    )?;
    Ok((source_query_indices, pad_query_indices))
}

fn materialize_base_case(
    proof: &CompactAggregateWideOpeningProof,
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
    active_source_commitment: &AggregateWideCommitment,
    pad_commitment: &AggregateWideCommitment,
    challenger: &ExtensionFieldChallenger,
) -> Result<BaseCaseZkProof<ChallengeField, ChallengeField, super::CommitmentScheme>, String> {
    let base = &proof.base_case;
    let (source_indices, pad_indices) = derive_base_query_schedules(
        configuration,
        pad_layout,
        &base.fresh_main_commitment,
        &base.fresh_pad_commitment,
        base.masked_claim,
        &base.blinded_message,
        &base.blinded_randomness,
        &base.blinded_pad_message,
        &base.blinded_pad_randomness,
        base.proof_of_work_witness,
        challenger,
    )?;
    base.materialize(
        active_source_commitment,
        pad_commitment,
        &source_indices,
        &pad_indices,
    )
}

fn verify_and_fold_opening(
    pcs: &AggregateWidePcs,
    active_oracle: &ActiveOracle<'_>,
    dimensions: &[Dimensions],
    position: usize,
    opening: &QueryOpening<
        ChallengeField,
        ChallengeField,
        super::coordinate_derived_hiding_mmcs::CoordinateDerivedLeafSaltProof,
    >,
    round_ordinal: usize,
    randomness: &Point<ChallengeField>,
) -> Result<ChallengeField, String> {
    let expected_width = dimensions.first().map_or(0, |shape| shape.width);
    match (active_oracle, opening) {
        (ActiveOracle::Initial(commitment), QueryOpening::Base { values, proof })
            if values.len() == expected_width =>
        {
            pcs.mmcs
                .verify_batch(
                    commitment,
                    dimensions,
                    position,
                    BatchOpeningRef {
                        opened_values: from_ref(values),
                        opening_proof: proof,
                    },
                )
                .map_err(|_| {
                    format!(
                        "aggregate-wide initial Merkle opening failed in round {round_ordinal} at position {position}"
                    )
                })?;
            Ok(Poly::new(values.clone()).eval_base(randomness))
        }
        (ActiveOracle::Folded(commitment), QueryOpening::Extension { values, proof })
            if values.len() == expected_width =>
        {
            pcs.extension_mmcs
                .verify_batch(
                    commitment,
                    dimensions,
                    position,
                    BatchOpeningRef {
                        opened_values: from_ref(values),
                        opening_proof: proof,
                    },
                )
                .map_err(|_| {
                    format!(
                        "aggregate-wide folded Merkle opening failed in round {round_ordinal} at position {position}"
                    )
                })?;
            Ok(Poly::new(values.clone()).eval_ext::<ChallengeField>(randomness))
        }
        _ => Err(format!(
            "aggregate-wide opening has the wrong variant or width in round {round_ordinal} at position {position}"
        )),
    }
}
