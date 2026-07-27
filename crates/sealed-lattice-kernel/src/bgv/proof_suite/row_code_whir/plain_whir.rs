//! Explicit-point plain WHIR adapter for the masked aggregate polynomial.
//!
//! The upstream plain adapter samples univariate opening points internally.
//! This construction instead receives points already derived by the enclosing
//! relation and column-reduction transcript. The pinned local sumcheck copy
//! exposes an explicit-point claim method that absorbs each point before its
//! evaluation, preserving commitment-before-challenge ordering.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::{point::Point, poly::Poly};
#[cfg(test)]
use p3_sumcheck::layout::{Table, Witness};
use p3_sumcheck::{
    OpeningBatch,
    layout::{Layout, PrefixProver, Verifier},
    table::{OpeningProtocol, TableShape, TableSpec},
};
use p3_whir::{
    DomainSeparator, FoldingFactor, PcsProof, ProtocolParameters, SecurityAssumption, WhirConfig,
    WhirProver, WhirVerificationState, WhirVerifier,
};
#[cfg(test)]
use p3_whir::{WhirProof, WhirProverData, WhirRoundProof};

use super::construction_plan::{
    RowCodeWhirConstructionPlan, RowCodeWhirEncodedOraclePlan, RowCodeWhirFinalRoundPlan,
    RowCodeWhirQueryEpochPlan, RowCodeWhirRoundPlan, RowCodeWhirSelectedParameters,
    RowCodeWhirSoundnessAssumption, RowCodeWhirWhirPlan,
};
use super::{
    ChallengeField, CommitmentScheme, DiscreteFourierTransform, ExtensionFieldChallenger,
    LeafHasher, NodeCompressor,
};
#[cfg(test)]
use crate::bgv::proof_suite::transcript::{
    PublicSamplerExhaustionCatalog, PublicSamplerExhaustionCatalogRow, PublicSamplerKind,
};

pub(super) type AggregateLayout = PrefixProver<ChallengeField, ChallengeField>;
pub(super) type PlainAggregatePcs = WhirProver<
    ChallengeField,
    ChallengeField,
    DiscreteFourierTransform,
    CommitmentScheme,
    ExtensionFieldChallenger,
    AggregateLayout,
>;
pub(super) type PlainAggregateCommitment =
    <PlainAggregatePcs as MultilinearPcs<ChallengeField, ExtensionFieldChallenger>>::Commitment;
pub(super) type PlainAggregateProof = PcsProof<ChallengeField, ChallengeField, CommitmentScheme>;
type PlainAggregateWhirVerificationState =
    WhirVerificationState<ChallengeField, ChallengeField, CommitmentScheme>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PlainAggregateEncodedOracleGeometry {
    pub(super) height: usize,
    pub(super) width: usize,
}

#[derive(Clone, Debug, Default)]
struct ProtocolScheduleRecorder {
    values: Vec<ChallengeField>,
}

impl CanObserve<ChallengeField> for ProtocolScheduleRecorder {
    fn observe(&mut self, value: ChallengeField) {
        self.values.push(value);
    }

    fn observe_slice(&mut self, values: &[ChallengeField]) {
        self.values.extend_from_slice(values);
    }
}

impl CanSample<ChallengeField> for ProtocolScheduleRecorder {
    fn sample(&mut self) -> ChallengeField {
        ChallengeField::ZERO
    }
}

impl CanSampleBits<usize> for ProtocolScheduleRecorder {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        0
    }
}

impl FieldChallenger<ChallengeField> for ProtocolScheduleRecorder {}

impl GrindingChallenger for ProtocolScheduleRecorder {
    type Witness = ChallengeField;

    fn grind(&mut self, _bits: usize) -> Self::Witness {
        ChallengeField::ZERO
    }
}

#[cfg(test)]
pub(super) fn plain_aggregate_pcs(variable_count: usize) -> Result<PlainAggregatePcs, String> {
    let parameters = RowCodeWhirSelectedParameters::selected();
    if variable_count != parameters.polynomial_commitment_variable_count {
        return Err(
            "plain WHIR variable count does not match the selected construction".to_owned(),
        );
    }
    plain_aggregate_pcs_from_selected_parameters(parameters)
}

pub(super) fn plain_aggregate_pcs_for_construction_plan(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<PlainAggregatePcs, String> {
    let pcs =
        plain_aggregate_pcs_from_selected_parameters(construction_plan.selected_parameters())?;
    ensure_plain_aggregate_pcs_matches_construction_plan(&pcs, construction_plan)?;
    Ok(pcs)
}

#[cfg(test)]
pub(super) fn plain_aggregate_pcs_with_parameters(
    variable_count: usize,
    starting_log_inverse_rate: usize,
    folding_factor: usize,
) -> Result<PlainAggregatePcs, String> {
    plain_aggregate_pcs_from_selected_parameters(RowCodeWhirSelectedParameters {
        polynomial_commitment_variable_count: variable_count,
        starting_log_inverse_rate,
        folding_factor,
        ..RowCodeWhirSelectedParameters::selected()
    })
}

#[cfg(test)]
fn plain_aggregate_test_pcs(variable_count: usize) -> Result<PlainAggregatePcs, String> {
    let parameters = RowCodeWhirSelectedParameters::selected();
    plain_aggregate_pcs_with_parameters(
        variable_count,
        parameters.starting_log_inverse_rate,
        parameters.folding_factor,
    )
}

fn plain_aggregate_pcs_from_selected_parameters(
    parameters: RowCodeWhirSelectedParameters,
) -> Result<PlainAggregatePcs, String> {
    let soundness_type = plain_whir_security_assumption(parameters.soundness_assumption);
    let configuration =
        WhirConfig::<ChallengeField, ChallengeField, ExtensionFieldChallenger>::new(
            parameters.polynomial_commitment_variable_count,
            ProtocolParameters {
                starting_log_inv_rate: parameters.starting_log_inverse_rate,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::Constant(parameters.folding_factor),
                soundness_type,
                security_level: parameters.security_level,
                pow_bits: parameters.proof_of_work_bits,
            },
        )
        .map_err(|error| format!("construct plain WHIR configuration: {error}"))?;
    let commitment_scheme = CommitmentScheme::new(
        LeafHasher::new(super::DomainSeparatedShake256 {
            domain: super::ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
        }),
        NodeCompressor::new(super::DomainSeparatedShake256 {
            domain: super::ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
        }),
        0,
    );
    Ok(WhirProver::new(
        configuration,
        DiscreteFourierTransform::default(),
        commitment_scheme,
    ))
}

const fn plain_whir_security_assumption(
    soundness_assumption: RowCodeWhirSoundnessAssumption,
) -> SecurityAssumption {
    match soundness_assumption {
        RowCodeWhirSoundnessAssumption::UniqueDecoding => SecurityAssumption::UniqueDecoding,
    }
}

fn ensure_plain_aggregate_pcs_matches_construction_plan(
    pcs: &PlainAggregatePcs,
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<(), String> {
    let parameters = construction_plan.selected_parameters();
    let folding_factor_matches = matches!(
        &pcs.params.folding_factor,
        FoldingFactor::Constant(folding_factor) if *folding_factor == parameters.folding_factor
    );
    if pcs.num_variables != parameters.polynomial_commitment_variable_count
        || pcs.params.starting_log_inv_rate != parameters.starting_log_inverse_rate
        || !pcs.params.round_log_inv_rates.is_empty()
        || !folding_factor_matches
        || pcs.params.soundness_type
            != plain_whir_security_assumption(parameters.soundness_assumption)
        || pcs.params.security_level != parameters.security_level
        || pcs.params.pow_bits != parameters.proof_of_work_bits
    {
        return Err(
            "plain WHIR protocol parameters do not match the checked construction plan".to_owned(),
        );
    }
    let (derived_whir_plan, _) = derive_plain_aggregate_whir_plan_from_pcs(pcs)?;
    if &derived_whir_plan != construction_plan.whir_plan() {
        return Err(
            "plain WHIR configuration does not match the checked construction plan".to_owned(),
        );
    }
    Ok(())
}

pub(super) fn plain_aggregate_challenger_from_transcript(
    pcs: &PlainAggregatePcs,
    expected_whir_plan: &RowCodeWhirWhirPlan,
    transcript: super::RowCodeWhirTranscript,
) -> Result<ExtensionFieldChallenger, String> {
    let (derived_whir_plan, _) = derive_plain_aggregate_whir_plan_from_pcs(pcs)?;
    if &derived_whir_plan != expected_whir_plan {
        return Err(
            "plain WHIR challenger geometry does not match the checked construction plan"
                .to_owned(),
        );
    }
    let mut query_schedule = expected_whir_plan
        .rounds
        .iter()
        .map(|round| super::WhirQueryEpoch {
            bit_length: round.query_epoch.bit_length,
            query_count: round.query_epoch.query_count,
        })
        .collect::<Vec<_>>();
    query_schedule.push(super::WhirQueryEpoch {
        bit_length: expected_whir_plan.final_round.query_epoch.bit_length,
        query_count: expected_whir_plan.final_round.query_epoch.query_count,
    });
    let mut challenger = ExtensionFieldChallenger::new(transcript, query_schedule);
    let mut separator = DomainSeparator::<ChallengeField, ChallengeField>::new(Vec::new());
    pcs.add_domain_separator::<{ super::MERKLE_DIGEST_WORD_LENGTH }>(&mut separator);
    separator.observe_domain_separator(&mut challenger);
    challenger.ensure_sampling_succeeded()?;
    Ok(challenger)
}

pub(super) fn plain_aggregate_encoded_oracle_geometries(
    pcs: &PlainAggregatePcs,
) -> Result<Vec<PlainAggregateEncodedOracleGeometry>, String> {
    let encoded_oracle_count = pcs
        .n_rounds()
        .checked_add(1)
        .ok_or_else(|| "plain WHIR encoded-oracle count overflowed".to_owned())?;
    let mut geometries = Vec::with_capacity(encoded_oracle_count);
    for encoded_oracle_index in 0..encoded_oracle_count {
        let domain_size = if encoded_oracle_index < pcs.n_rounds() {
            pcs.round_parameters[encoded_oracle_index].domain_size
        } else {
            pcs.final_round_config().domain_size
        };
        let folding_factor = pcs.round_folding_factor(encoded_oracle_index);
        let height = domain_size
            .checked_shr(
                u32::try_from(folding_factor)
                    .map_err(|_| "WHIR folding factor exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "WHIR encoded-oracle height overflowed".to_owned())?;
        let width = 1_usize
            .checked_shl(
                u32::try_from(folding_factor)
                    .map_err(|_| "WHIR folding factor exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "WHIR encoded-oracle width overflowed".to_owned())?;
        if height == 0
            || !height.is_power_of_two()
            || width == 0
            || !width.is_power_of_two()
            || height.checked_mul(width) != Some(domain_size)
        {
            return Err("WHIR encoded-oracle geometry is invalid".to_owned());
        }
        geometries.push(PlainAggregateEncodedOracleGeometry { height, width });
    }
    Ok(geometries)
}

pub(super) fn derive_plain_aggregate_whir_plan(
    parameters: RowCodeWhirSelectedParameters,
) -> Result<
    (
        RowCodeWhirWhirPlan,
        Vec<super::super::ProofChallengeExtensionElement>,
    ),
    String,
> {
    let pcs = plain_aggregate_pcs_from_selected_parameters(parameters)?;
    derive_plain_aggregate_whir_plan_from_pcs(&pcs)
}

fn derive_plain_aggregate_whir_plan_from_pcs(
    pcs: &PlainAggregatePcs,
) -> Result<
    (
        RowCodeWhirWhirPlan,
        Vec<super::super::ProofChallengeExtensionElement>,
    ),
    String,
> {
    let geometries = plain_aggregate_encoded_oracle_geometries(pcs)?;
    if geometries.len() != pcs.n_rounds() + 1 {
        return Err("plain WHIR encoded-oracle geometry is incomplete".to_owned());
    }

    let query_epoch = |epoch_ordinal: usize,
                       geometry: PlainAggregateEncodedOracleGeometry,
                       query_count: usize|
     -> Result<RowCodeWhirQueryEpochPlan, String> {
        let query_count = query_count.min(geometry.height);
        if geometry.height == 0 || !geometry.height.is_power_of_two() || query_count == 0 {
            return Err("plain WHIR query epoch has invalid geometry".to_owned());
        }
        Ok(RowCodeWhirQueryEpochPlan {
            epoch_ordinal: u32::try_from(epoch_ordinal)
                .map_err(|_| "plain WHIR query epoch ordinal exceeds u32".to_owned())?,
            bit_length: usize::try_from(geometry.height.ilog2())
                .map_err(|_| "plain WHIR query bit length exceeds usize".to_owned())?,
            domain_size: geometry.height,
            query_count,
        })
    };
    let encoded_oracle = |geometry: PlainAggregateEncodedOracleGeometry|
     -> Result<RowCodeWhirEncodedOraclePlan, String> {
        Ok(RowCodeWhirEncodedOraclePlan {
            evaluation_count: geometry
                .height
                .checked_mul(geometry.width)
                .ok_or_else(|| "plain WHIR encoded-oracle size overflowed".to_owned())?,
            leaf_count: geometry.height,
            leaf_width: geometry.width,
        })
    };

    let mut rounds = Vec::with_capacity(pcs.n_rounds());
    for (round_index, round_parameters) in pcs.round_parameters.iter().enumerate() {
        rounds.push(RowCodeWhirRoundPlan {
            round_ordinal: u32::try_from(round_index)
                .map_err(|_| "plain WHIR round ordinal exceeds u32".to_owned())?,
            encoded_oracle: encoded_oracle(geometries[round_index])?,
            out_of_domain_sample_count: round_parameters.ood_samples,
            query_epoch: query_epoch(
                round_index,
                geometries[round_index],
                round_parameters.num_queries,
            )?,
            following_sumcheck_round_count: pcs.round_folding_factor(round_index + 1),
            commitment_proof_of_work_bits: round_parameters.pow_bits,
            folding_proof_of_work_bits: round_parameters.folding_pow_bits,
        });
    }
    let final_geometry = *geometries
        .last()
        .ok_or_else(|| "plain WHIR final encoded-oracle geometry is absent".to_owned())?;
    let final_round_configuration = pcs.final_round_config();
    let revealed_coefficient_count = 1_usize
        .checked_shl(
            u32::try_from(final_round_configuration.num_variables)
                .map_err(|_| "plain WHIR final variable count exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR final polynomial size overflowed".to_owned())?;
    let whir_plan = RowCodeWhirWhirPlan {
        initial_out_of_domain_sample_count: pcs.commitment_ood_samples,
        initial_sumcheck_round_count: pcs.round_folding_factor(0),
        rounds,
        final_round: RowCodeWhirFinalRoundPlan {
            encoded_oracle: encoded_oracle(final_geometry)?,
            query_epoch: query_epoch(pcs.n_rounds(), final_geometry, pcs.final_queries)?,
            revealed_coefficient_count,
            sumcheck_round_count: pcs.final_sumcheck_rounds,
            proof_of_work_bits: pcs.final_pow_bits,
        },
    };

    let mut separator = DomainSeparator::<ChallengeField, ChallengeField>::new(Vec::new());
    pcs.add_domain_separator::<{ super::MERKLE_DIGEST_WORD_LENGTH }>(&mut separator);
    let mut recorder = ProtocolScheduleRecorder::default();
    separator.observe_domain_separator(&mut recorder);
    let canonical_schedule = recorder
        .values
        .into_iter()
        .map(|value| {
            super::challenge_to_production(value)
                .map_err(|_| "plain WHIR protocol schedule is not canonical".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if canonical_schedule.is_empty() {
        return Err("plain WHIR protocol schedule is empty".to_owned());
    }
    Ok((whir_plan, canonical_schedule))
}

#[cfg(test)]
fn plain_aggregate_query_schedule(
    pcs: &PlainAggregatePcs,
) -> Result<Vec<super::WhirQueryEpoch>, String> {
    let geometries = plain_aggregate_encoded_oracle_geometries(pcs)?;
    let mut query_schedule = Vec::with_capacity(geometries.len());
    for (encoded_oracle_index, geometry) in geometries.into_iter().enumerate() {
        let configured_query_count = if encoded_oracle_index < pcs.n_rounds() {
            pcs.round_parameters[encoded_oracle_index].num_queries
        } else {
            pcs.final_queries
        };
        query_schedule.push(super::WhirQueryEpoch {
            bit_length: geometry.height.ilog2() as usize,
            query_count: configured_query_count.min(geometry.height),
        });
    }
    Ok(query_schedule)
}

#[cfg(test)]
fn plain_aggregate_has_nonzero_pow(pcs: &PlainAggregatePcs) -> bool {
    pcs.starting_folding_pow_bits != 0
        || pcs.final_pow_bits != 0
        || pcs.final_folding_pow_bits != 0
        || pcs
            .round_parameters
            .iter()
            .any(|round| round.pow_bits != 0 || round.folding_pow_bits != 0)
}

#[cfg(test)]
fn push_plain_aggregate_extension_sampler(
    catalog: &mut PublicSamplerExhaustionCatalog,
    challenge_ordinal: &mut u32,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), String> {
    let row = PublicSamplerExhaustionCatalogRow::extension(
        format!("row-code-whir/whir-challenge/{:08x}", *challenge_ordinal),
        PublicSamplerKind::Extension,
        maximum_candidate_draws_per_output,
        None,
    )
    .map_err(|error| format!("derive plain WHIR extension sampler: {error:?}"))?;
    catalog
        .push_row(row)
        .map_err(|error| format!("catalog plain WHIR extension sampler: {error:?}"))?;
    *challenge_ordinal = (*challenge_ordinal)
        .checked_add(1)
        .ok_or_else(|| "plain WHIR challenge ordinal overflowed".to_owned())?;
    Ok(())
}

#[cfg(test)]
fn push_plain_aggregate_distinct_sampler(
    catalog: &mut PublicSamplerExhaustionCatalog,
    epoch_ordinal: u32,
    epoch: super::WhirQueryEpoch,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), String> {
    let output_count = u64::try_from(epoch.query_count)
        .map_err(|_| "plain WHIR query count exceeds u64".to_owned())?;
    let row = PublicSamplerExhaustionCatalogRow::distinct(
        format!(
            "row-code-whir/whir-query-vector/{epoch_ordinal:08x}/{:04x}/{output_count:016x}",
            epoch.bit_length
        ),
        1_usize
            .checked_shl(
                u32::try_from(epoch.bit_length)
                    .map_err(|_| "plain WHIR query bit length exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "plain WHIR query domain overflowed".to_owned())?,
        epoch.query_count,
        maximum_candidate_draws_per_output,
    )
    .map_err(|error| format!("derive plain WHIR distinct sampler: {error:?}"))?;
    catalog
        .push_row(row)
        .map_err(|error| format!("catalog plain WHIR distinct sampler: {error:?}"))
}

/// Extends the public sampler ledger from the same checked WHIR configuration
/// and query epochs installed in the live challenger.
#[cfg(test)]
pub(super) fn extend_plain_aggregate_public_sampler_exhaustion_catalog(
    catalog: &mut PublicSamplerExhaustionCatalog,
    pcs: &PlainAggregatePcs,
    maximum_candidate_draws_per_output: u32,
) -> Result<(), String> {
    if plain_aggregate_has_nonzero_pow(pcs) {
        return Err("plain WHIR public sampler catalog requires the zero-PoW profile".to_owned());
    }

    let mut extension_challenge_ordinal = 0_u32;
    let mut query_schedule = plain_aggregate_query_schedule(pcs)?.into_iter();
    for _ in 0..pcs.commitment_ood_samples {
        push_plain_aggregate_extension_sampler(
            catalog,
            &mut extension_challenge_ordinal,
            maximum_candidate_draws_per_output,
        )?;
    }

    // The explicit-point layout samples one claim-batching weight before the
    // initial sumcheck coordinates.
    push_plain_aggregate_extension_sampler(
        catalog,
        &mut extension_challenge_ordinal,
        maximum_candidate_draws_per_output,
    )?;
    for _ in 0..pcs.round_folding_factor(0) {
        push_plain_aggregate_extension_sampler(
            catalog,
            &mut extension_challenge_ordinal,
            maximum_candidate_draws_per_output,
        )?;
    }

    for round_index in 0..pcs.n_rounds() {
        let round = &pcs.round_parameters[round_index];
        for _ in 0..round.ood_samples {
            push_plain_aggregate_extension_sampler(
                catalog,
                &mut extension_challenge_ordinal,
                maximum_candidate_draws_per_output,
            )?;
        }
        // The typed checkpoint precedes this round's distinct query vector;
        // the constraint-combination challenge follows it.
        push_plain_aggregate_extension_sampler(
            catalog,
            &mut extension_challenge_ordinal,
            maximum_candidate_draws_per_output,
        )?;
        let epoch = query_schedule
            .next()
            .ok_or_else(|| "plain WHIR query schedule ended before its rounds".to_owned())?;
        push_plain_aggregate_distinct_sampler(
            catalog,
            u32::try_from(round_index)
                .map_err(|_| "plain WHIR query epoch exceeds u32".to_owned())?,
            epoch,
            maximum_candidate_draws_per_output,
        )?;
        push_plain_aggregate_extension_sampler(
            catalog,
            &mut extension_challenge_ordinal,
            maximum_candidate_draws_per_output,
        )?;
        for _ in 0..pcs.round_folding_factor(round_index + 1) {
            push_plain_aggregate_extension_sampler(
                catalog,
                &mut extension_challenge_ordinal,
                maximum_candidate_draws_per_output,
            )?;
        }
    }

    let final_epoch = query_schedule
        .next()
        .ok_or_else(|| "plain WHIR query schedule omitted its final epoch".to_owned())?;
    push_plain_aggregate_distinct_sampler(
        catalog,
        u32::try_from(pcs.n_rounds())
            .map_err(|_| "plain WHIR final query epoch exceeds u32".to_owned())?,
        final_epoch,
        maximum_candidate_draws_per_output,
    )?;
    if query_schedule.next().is_some() {
        return Err("plain WHIR query schedule has trailing epochs".to_owned());
    }
    for _ in 0..pcs.final_sumcheck_rounds {
        push_plain_aggregate_extension_sampler(
            catalog,
            &mut extension_challenge_ordinal,
            maximum_candidate_draws_per_output,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn plain_aggregate_challenger(
    pcs: &PlainAggregatePcs,
    statement: &[u8],
) -> ExtensionFieldChallenger {
    let transcript = super::RowCodeWhirTranscript::new_for_test(statement)
        .expect("construct canonical row-code WHIR test transcript");
    let (whir_plan, _) = derive_plain_aggregate_whir_plan_from_pcs(pcs)
        .expect("derive the checked plain WHIR test plan");
    plain_aggregate_challenger_from_transcript(pcs, &whir_plan, transcript)
        .expect("bind the plain WHIR protocol schedule")
}

fn plain_aggregate_opening_protocol_for_requests(
    variable_count: usize,
    table_width: usize,
    requested_columns_by_point: &[Vec<usize>],
) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(variable_count, table_width),
        requested_columns_by_point
            .iter()
            .cloned()
            .map(|requested_columns| OpeningBatch::new(requested_columns, Vec::new()))
            .collect(),
    )])
}

#[cfg(test)]
pub(super) fn commit_plain_aggregate(
    pcs: &PlainAggregatePcs,
    message: Poly<ChallengeField>,
    challenger: &mut ExtensionFieldChallenger,
) -> (
    PlainAggregateCommitment,
    WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
) {
    commit_plain_aggregate_batch(pcs, vec![message], challenger)
}

#[cfg(test)]
pub(super) fn commit_plain_aggregate_batch(
    pcs: &PlainAggregatePcs,
    messages: Vec<Poly<ChallengeField>>,
    challenger: &mut ExtensionFieldChallenger,
) -> (
    PlainAggregateCommitment,
    WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
) {
    let witness: Witness<ChallengeField> =
        AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
    pcs.commit(witness, challenger)
}

#[cfg(test)]
pub(super) fn open_plain_aggregate_at_points(
    pcs: &PlainAggregatePcs,
    prover_data: WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
    points: &[Point<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> PlainAggregateProof {
    let requested_columns_by_point = vec![vec![0]; points.len()];
    open_plain_aggregate_batches_at_points(
        pcs,
        prover_data,
        points,
        &requested_columns_by_point,
        challenger,
    )
}

#[cfg(test)]
pub(super) fn open_plain_aggregate_batches_at_points(
    pcs: &PlainAggregatePcs,
    mut prover_data: WhirProverData<
        ChallengeField,
        ChallengeField,
        CommitmentScheme,
        AggregateLayout,
    >,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
) -> PlainAggregateProof {
    assert_eq!(points.len(), requested_columns_by_point.len());
    let mut whir = empty_plain_whir_proof(pcs);
    whir.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| prover_data.layout.add_virtual_eval(challenger))
        .collect();
    let evaluations = points
        .iter()
        .cloned()
        .zip(requested_columns_by_point)
        .map(|(point, requested_columns)| {
            let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
            prover_data
                .layout
                .eval_at_point(0, &request, point, challenger)
        })
        .collect();
    pcs.prove(
        &mut whir,
        challenger,
        prover_data.layout,
        prover_data.merkle_data,
    );
    PcsProof {
        whir,
        evals: evaluations,
    }
}

#[cfg(test)]
pub(super) fn verify_plain_aggregate_at_points(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    let requested_columns_by_point = vec![vec![0]; points.len()];
    verify_plain_aggregate_batches_at_points(
        pcs,
        commitment,
        proof,
        points,
        pcs.num_variables,
        1,
        &requested_columns_by_point,
        challenger,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn verify_plain_aggregate_batches_at_points(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    table_variable_count: usize,
    table_width: usize,
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    challenger.observe(commitment.clone());
    verify_plain_aggregate_batches_with_requests_after_commitment(
        pcs,
        commitment,
        proof,
        points,
        table_variable_count,
        table_width,
        requested_columns_by_point,
        challenger,
    )
}

#[cfg(test)]
pub(super) fn verify_plain_aggregate_batches_at_points_after_commitment(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    construction_plan: &RowCodeWhirConstructionPlan,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    let opening_schedule =
        checked_plain_aggregate_opening_schedule(pcs, points, construction_plan)?;
    verify_plain_aggregate_batches_with_requests_after_commitment(
        pcs,
        commitment,
        proof,
        points,
        opening_schedule.table_variable_count,
        opening_schedule.table_width,
        &opening_schedule.requested_columns_by_point,
        challenger,
    )
}

struct PlainAggregateOpeningSchedule {
    table_variable_count: usize,
    table_width: usize,
    requested_columns_by_point: Vec<Vec<usize>>,
}

fn checked_plain_aggregate_opening_schedule(
    pcs: &PlainAggregatePcs,
    points: &[Point<ChallengeField>],
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<PlainAggregateOpeningSchedule, String> {
    ensure_plain_aggregate_pcs_matches_construction_plan(pcs, construction_plan)?;
    let parameters = construction_plan.selected_parameters();
    let table_width = construction_plan.aggregate_table_width();
    if table_width == 0 {
        return Err("checked plain WHIR aggregate table has no columns".to_owned());
    }
    let padded_table_width = table_width
        .checked_next_power_of_two()
        .ok_or_else(|| "checked plain WHIR aggregate table width overflowed".to_owned())?;
    let selector_variable_count = usize::try_from(padded_table_width.ilog2())
        .map_err(|_| "plain WHIR aggregate selector width exceeds usize".to_owned())?;
    if parameters
        .table_variable_count
        .checked_add(selector_variable_count)
        != Some(parameters.polynomial_commitment_variable_count)
    {
        return Err(
            "checked plain WHIR table dimensions do not match the polynomial commitment".to_owned(),
        );
    }
    let opening_batches = construction_plan.opening_batches();
    if points.len() != opening_batches.len() {
        return Err(format!(
            "plain WHIR verifier received {} points for {} checked opening batches",
            points.len(),
            opening_batches.len()
        ));
    }
    let mut requested_columns_by_point = Vec::with_capacity(opening_batches.len());
    for (point_index, (point, opening_batch)) in points.iter().zip(opening_batches).enumerate() {
        if usize::try_from(opening_batch.point_ordinal).ok() != Some(point_index) {
            return Err("checked plain WHIR opening-point order is not canonical".to_owned());
        }
        if point.num_variables() != parameters.table_variable_count {
            return Err(format!(
                "plain WHIR opening point {point_index} has {} variables, expected {}",
                point.num_variables(),
                parameters.table_variable_count
            ));
        }
        let requested_columns = opening_batch
            .requested_aggregate_column_ordinals
            .iter()
            .copied()
            .map(|column_ordinal| {
                usize::try_from(column_ordinal)
                    .map_err(|_| "plain WHIR aggregate column ordinal exceeds usize".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if requested_columns.is_empty()
            || requested_columns
                .iter()
                .any(|column_index| *column_index >= table_width)
        {
            return Err(
                "checked plain WHIR opening request is outside the aggregate table".to_owned(),
            );
        }
        requested_columns_by_point.push(requested_columns);
    }
    Ok(PlainAggregateOpeningSchedule {
        table_variable_count: parameters.table_variable_count,
        table_width,
        requested_columns_by_point,
    })
}

/// Verifier-owned inputs retained until the canonical wire supplies the
/// opening evaluations and initial OOD answers that precede the first
/// sumcheck.
pub(super) struct PlainAggregateIncrementalVerificationPreparation {
    configuration: WhirConfig<ChallengeField, ChallengeField, ExtensionFieldChallenger>,
    commitment_scheme: CommitmentScheme,
    commitment: PlainAggregateCommitment,
    points: Vec<Point<ChallengeField>>,
    opening_schedule: PlainAggregateOpeningSchedule,
    expected_opening_evaluations: Vec<Vec<ChallengeField>>,
    challenger: ExtensionFieldChallenger,
}

impl PlainAggregateIncrementalVerificationPreparation {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        pcs: &PlainAggregatePcs,
        commitment: PlainAggregateCommitment,
        points: Vec<Point<ChallengeField>>,
        construction_plan: &RowCodeWhirConstructionPlan,
        expected_opening_evaluations: Vec<Vec<ChallengeField>>,
        challenger: ExtensionFieldChallenger,
    ) -> Result<Self, String> {
        let opening_schedule =
            checked_plain_aggregate_opening_schedule(pcs, &points, construction_plan)?;
        Self::new_with_schedule(
            pcs,
            commitment,
            points,
            opening_schedule,
            expected_opening_evaluations,
            challenger,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_for_requests(
        pcs: &PlainAggregatePcs,
        commitment: PlainAggregateCommitment,
        points: Vec<Point<ChallengeField>>,
        table_variable_count: usize,
        table_width: usize,
        requested_columns_by_point: Vec<Vec<usize>>,
        expected_opening_evaluations: Vec<Vec<ChallengeField>>,
        challenger: ExtensionFieldChallenger,
    ) -> Result<Self, String> {
        if table_variable_count != pcs.num_variables
            || table_width == 0
            || points
                .iter()
                .any(|point| point.num_variables() != table_variable_count)
            || requested_columns_by_point.len() != points.len()
            || requested_columns_by_point.iter().any(|columns| {
                columns.is_empty() || columns.iter().any(|column| *column >= table_width)
            })
        {
            return Err("test plain WHIR opening schedule is invalid".to_owned());
        }
        Self::new_with_schedule(
            pcs,
            commitment,
            points,
            PlainAggregateOpeningSchedule {
                table_variable_count,
                table_width,
                requested_columns_by_point,
            },
            expected_opening_evaluations,
            challenger,
        )
    }

    fn new_with_schedule(
        pcs: &PlainAggregatePcs,
        commitment: PlainAggregateCommitment,
        points: Vec<Point<ChallengeField>>,
        opening_schedule: PlainAggregateOpeningSchedule,
        expected_opening_evaluations: Vec<Vec<ChallengeField>>,
        challenger: ExtensionFieldChallenger,
    ) -> Result<Self, String> {
        if expected_opening_evaluations.len() != points.len() {
            return Err(format!(
                "plain WHIR expected {} opening batches, got {}",
                points.len(),
                expected_opening_evaluations.len()
            ));
        }
        for (opening_index, (expected, requested_columns)) in expected_opening_evaluations
            .iter()
            .zip(&opening_schedule.requested_columns_by_point)
            .enumerate()
        {
            if expected.len() != requested_columns.len() {
                return Err(format!(
                    "plain WHIR expected opening {opening_index} has {} evaluations for {} requested columns",
                    expected.len(),
                    requested_columns.len()
                ));
            }
        }
        Ok(Self {
            configuration: pcs.config.clone(),
            commitment_scheme: pcs.mmcs.clone(),
            commitment,
            points,
            opening_schedule,
            expected_opening_evaluations,
            challenger,
        })
    }

    pub(super) fn start(
        mut self,
        initial_ood_answers: Vec<ChallengeField>,
        opening_evaluations: Vec<OpeningBatch<ChallengeField>>,
    ) -> Result<PlainAggregateIncrementalVerification, String> {
        if initial_ood_answers.len() != self.configuration.commitment_ood_samples {
            return Err(format!(
                "plain WHIR proof has {} initial OOD answers, expected {}",
                initial_ood_answers.len(),
                self.configuration.commitment_ood_samples
            ));
        }
        if opening_evaluations.len() != self.expected_opening_evaluations.len() {
            return Err(format!(
                "plain WHIR proof has {} opening batches, expected {}",
                opening_evaluations.len(),
                self.expected_opening_evaluations.len()
            ));
        }
        for (opening_index, (actual, expected)) in opening_evaluations
            .iter()
            .zip(&self.expected_opening_evaluations)
            .enumerate()
        {
            if actual.current() != expected.as_slice() || !actual.next().is_empty() {
                return Err(format!(
                    "plain WHIR opening {opening_index} does not match verifier-recomputed values"
                ));
            }
        }

        let protocol = plain_aggregate_opening_protocol_for_requests(
            self.opening_schedule.table_variable_count,
            self.opening_schedule.table_width,
            &self.opening_schedule.requested_columns_by_point,
        );
        let mut layout_verifier = Verifier::<ChallengeField, ChallengeField>::new(
            &protocol.table_shapes(),
            AggregateLayout::strategy(),
        );
        for evaluation in initial_ood_answers {
            layout_verifier.add_virtual_eval(evaluation, &mut self.challenger);
        }
        for (((point, evaluations), requested_columns), expected) in self
            .points
            .into_iter()
            .zip(opening_evaluations)
            .zip(&self.opening_schedule.requested_columns_by_point)
            .zip(&self.expected_opening_evaluations)
        {
            debug_assert_eq!(evaluations.current(), expected.as_slice());
            let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
            layout_verifier
                .add_claim_at_point(0, &request, &evaluations, point, &mut self.challenger)
                .map_err(|error| format!("register explicit plain WHIR claim: {error}"))?;
        }
        let batching_challenge = self.challenger.sample_algebra_element();
        let constraint = layout_verifier.constraint(batching_challenge);
        let mut claimed_evaluation = ChallengeField::ZERO;
        constraint.combine_evals(&mut claimed_evaluation);
        self.challenger.ensure_sampling_succeeded()?;
        let verification = WhirVerifier::new(
            &self.configuration,
            &self.commitment_scheme,
            AggregateLayout::variable_order(),
        )
        .start(&self.commitment, constraint, claimed_evaluation);
        Ok(PlainAggregateIncrementalVerification {
            verification,
            challenger: self.challenger,
            intermediate_round_count: self.configuration.n_rounds(),
        })
    }
}

/// Explicit-point WHIR verification driven by canonical wire sections.
pub(super) struct PlainAggregateIncrementalVerification {
    verification: PlainAggregateWhirVerificationState,
    challenger: ExtensionFieldChallenger,
    intermediate_round_count: usize,
}

impl PlainAggregateIncrementalVerification {
    pub(super) fn resident_payload_byte_length(&self) -> usize {
        self.verification.resident_byte_length()
    }

    pub(super) fn verify_initial_sumcheck(
        &mut self,
        sumcheck: &p3_sumcheck::SumcheckData<ChallengeField, ChallengeField>,
    ) -> Result<(), String> {
        self.verification
            .verify_initial_sumcheck(sumcheck, &mut self.challenger)
            .map_err(|error| format!("verify initial plain WHIR sumcheck: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn begin_round(
        &mut self,
        round_index: usize,
        commitment: PlainAggregateCommitment,
        ood_answers: &[ChallengeField],
    ) -> Result<(), String> {
        self.verification
            .begin_round(
                round_index,
                commitment,
                ood_answers,
                ChallengeField::ZERO,
                &mut self.challenger,
            )
            .map_err(|error| format!("begin plain WHIR round {round_index}: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn verify_query(
        &mut self,
        round_index: usize,
        query_ordinal: usize,
        query: &p3_whir::QueryOpening<
            ChallengeField,
            ChallengeField,
            <CommitmentScheme as p3_commit::Mmcs<ChallengeField>>::Proof,
        >,
    ) -> Result<(), String> {
        self.verification
            .verify_query(round_index, query_ordinal, query)
            .map_err(|error| {
                format!("verify plain WHIR round {round_index} query {query_ordinal}: {error}")
            })
    }

    pub(super) fn finish_round_queries(&mut self, round_index: usize) -> Result<(), String> {
        self.verification
            .finish_round_queries(round_index, &mut self.challenger)
            .map_err(|error| format!("finish plain WHIR round {round_index} queries: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn verify_round_sumcheck(
        &mut self,
        round_index: usize,
        sumcheck: &p3_sumcheck::SumcheckData<ChallengeField, ChallengeField>,
    ) -> Result<(), String> {
        self.verification
            .verify_round_sumcheck(round_index, sumcheck, &mut self.challenger)
            .map_err(|error| format!("verify plain WHIR round {round_index} sumcheck: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn begin_final_polynomial(
        &mut self,
        final_polynomial: Poly<ChallengeField>,
    ) -> Result<(), String> {
        self.verification
            .begin_final_polynomial(final_polynomial, ChallengeField::ZERO, &mut self.challenger)
            .map_err(|error| format!("begin final plain WHIR polynomial: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn verify_final_query(
        &mut self,
        query_ordinal: usize,
        query: &p3_whir::QueryOpening<
            ChallengeField,
            ChallengeField,
            <CommitmentScheme as p3_commit::Mmcs<ChallengeField>>::Proof,
        >,
    ) -> Result<(), String> {
        self.verify_query(self.intermediate_round_count, query_ordinal, query)
    }

    pub(super) fn finish_final_queries(&mut self) -> Result<(), String> {
        self.verification
            .finish_final_queries()
            .map_err(|error| format!("finish final plain WHIR queries: {error}"))
    }

    pub(super) fn verify_final_sumcheck(
        &mut self,
        final_sumcheck: Option<&p3_sumcheck::SumcheckData<ChallengeField, ChallengeField>>,
    ) -> Result<(), String> {
        self.verification
            .verify_final_sumcheck(final_sumcheck, &mut self.challenger)
            .map_err(|error| format!("verify final plain WHIR sumcheck: {error}"))?;
        self.challenger.ensure_sampling_succeeded()
    }

    pub(super) fn finish(self) -> Result<ExtensionFieldChallenger, String> {
        self.verification
            .finish()
            .map_err(|error| format!("finish incremental plain WHIR verification: {error}"))?;
        Ok(self.challenger)
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_plain_aggregate_batches_with_requests_after_commitment(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    table_variable_count: usize,
    table_width: usize,
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    if proof.evals.len() != points.len() {
        return Err(format!(
            "plain WHIR proof has {} opening batches for {} explicit points",
            proof.evals.len(),
            points.len()
        ));
    }
    if points
        .iter()
        .any(|point| point.num_variables() != table_variable_count)
        || requested_columns_by_point.len() != points.len()
        || requested_columns_by_point.iter().any(|columns| {
            columns.is_empty() || columns.iter().any(|column| *column >= table_width)
        })
    {
        return Err("plain WHIR opening requests do not match the committed table".to_owned());
    }
    let protocol = plain_aggregate_opening_protocol_for_requests(
        table_variable_count,
        table_width,
        requested_columns_by_point,
    );
    let mut layout_verifier = Verifier::<ChallengeField, ChallengeField>::new(
        &protocol.table_shapes(),
        AggregateLayout::strategy(),
    );
    if proof.whir.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(format!(
            "plain WHIR proof has {} initial OOD answers, expected {}",
            proof.whir.initial_ood_answers.len(),
            pcs.commitment_ood_samples
        ));
    }
    for evaluation in &proof.whir.initial_ood_answers {
        layout_verifier.add_virtual_eval(*evaluation, challenger);
    }
    for ((point, evaluations), requested_columns) in points
        .iter()
        .cloned()
        .zip(&proof.evals)
        .zip(requested_columns_by_point)
    {
        let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
        layout_verifier
            .add_claim_at_point(0, &request, evaluations, point, challenger)
            .map_err(|error| format!("register explicit plain WHIR claim: {error}"))?;
    }
    let batching_challenge = challenger.sample_algebra_element();
    let constraint = layout_verifier.constraint(batching_challenge);
    let mut claimed_evaluation = ChallengeField::ZERO;
    constraint.combine_evals(&mut claimed_evaluation);
    let verification = WhirVerifier::new(&pcs.config, &pcs.mmcs, AggregateLayout::variable_order())
        .verify(
            &proof.whir,
            challenger,
            commitment,
            constraint,
            claimed_evaluation,
        );
    challenger.ensure_sampling_succeeded()?;
    verification
        .map(|_| ())
        .map_err(|error| format!("verify explicit-point plain WHIR proof: {error}"))
}

#[cfg(test)]
fn empty_plain_whir_proof(
    pcs: &PlainAggregatePcs,
) -> WhirProof<ChallengeField, ChallengeField, CommitmentScheme> {
    WhirProof {
        initial_ood_answers: Vec::with_capacity(pcs.commitment_ood_samples),
        initial_sumcheck: Default::default(),
        rounds: (0..pcs.n_rounds())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: ChallengeField::ZERO,
        final_queries: Vec::with_capacity(pcs.final_queries),
        final_sumcheck: None,
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::ChallengeField;

    #[test]
    fn selected_plain_aggregate_entry_refuses_nonselected_variable_counts() {
        let selected_variable_count =
            RowCodeWhirSelectedParameters::selected().polynomial_commitment_variable_count;
        for nonselected_variable_count in [
            0,
            selected_variable_count - 1,
            selected_variable_count + 1,
            usize::MAX,
        ] {
            assert_eq!(
                plain_aggregate_pcs(nonselected_variable_count)
                    .err()
                    .as_deref(),
                Some("plain WHIR variable count does not match the selected construction")
            );
        }
        assert_eq!(
            plain_aggregate_pcs(selected_variable_count)
                .expect("the selected variable count constructs the production PCS")
                .num_variables,
            selected_variable_count
        );
    }

    #[test]
    fn target_plain_aggregate_configuration_uses_selected_parameters() {
        let parameters = RowCodeWhirSelectedParameters::selected();
        let pcs = plain_aggregate_pcs_from_selected_parameters(parameters)
            .expect("plain WHIR configuration");
        assert_eq!(
            pcs.num_variables,
            parameters.polynomial_commitment_variable_count
        );
        assert_eq!(
            pcs.params.starting_log_inv_rate,
            parameters.starting_log_inverse_rate
        );
        assert_eq!(pcs.params.security_level, parameters.security_level);
        assert_eq!(
            pcs.params.soundness_type,
            plain_whir_security_assumption(parameters.soundness_assumption)
        );
        assert_eq!(pcs.params.pow_bits, parameters.proof_of_work_bits);
        assert_eq!(pcs.folding_schedule, [3, 3, 3, 3, 3]);
        assert_eq!(
            pcs.round_parameters
                .iter()
                .map(|round| (
                    round.num_variables,
                    round.log_inv_rate,
                    round.num_queries,
                    round.pow_bits,
                    round.folding_pow_bits,
                    round.ood_samples,
                ))
                .collect::<Vec<_>>(),
            [
                (18, 4, 387, 0, 0, 0),
                (15, 6, 288, 0, 0, 0),
                (12, 8, 268, 0, 0, 0),
                (9, 10, 264, 0, 0, 0),
            ]
        );
        assert_eq!(pcs.starting_folding_pow_bits, 0);
        assert_eq!(pcs.final_queries, 263);
        assert_eq!(pcs.final_pow_bits, 0);
        assert_eq!(pcs.final_folding_pow_bits, 0);
        assert_eq!(pcs.final_round_config().num_variables, 6);
        assert_eq!(pcs.final_round_config().log_inv_rate, 10);
        assert!(pcs.check_pow_bits());
    }

    #[test]
    fn target_plain_aggregate_public_sampler_catalog_is_configuration_derived() {
        let pcs = plain_aggregate_pcs(21).expect("exact plain WHIR configuration");
        let mut catalog = PublicSamplerExhaustionCatalog::default();
        extend_plain_aggregate_public_sampler_exhaustion_catalog(
            &mut catalog,
            &pcs,
            super::super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        )
        .expect("derive public samplers from the exact plain WHIR configuration");

        assert_eq!(
            catalog.sampler_kind_row_count(PublicSamplerKind::Extension),
            30
        );
        assert_eq!(
            catalog.sampler_kind_row_count(PublicSamplerKind::Distinct),
            5
        );
        assert_eq!(catalog.logical_verifier_message_count(), 35);
        assert_eq!(catalog.bit_output_count(), 0);
        assert_eq!(catalog.grinding_output_count(), 0);

        let distinct_rows = catalog
            .rows()
            .iter()
            .filter(|row| row.sampler_kind() == PublicSamplerKind::Distinct)
            .collect::<Vec<_>>();
        assert_eq!(
            distinct_rows
                .iter()
                .map(|row| row.scalar_output_count())
                .collect::<Vec<_>>(),
            [387, 288, 268, 264, 263]
        );
        assert_eq!(
            distinct_rows
                .iter()
                .map(|row| row.target_cardinality().clone())
                .collect::<Vec<_>>(),
            [
                BigUint::from(1_u8) << 20_usize,
                BigUint::from(1_u8) << 19_usize,
                BigUint::from(1_u8) << 18_usize,
                BigUint::from(1_u8) << 17_usize,
                BigUint::from(1_u8) << 16_usize,
            ]
        );
        assert!(distinct_rows.iter().all(|row| {
            row.transcript_handle_domain()
                == crate::bgv::proof_suite::transcript::PUBLIC_SAMPLER_HANDLE_DOMAIN
                && row.candidate_bit_length() == 64
                && row.maximum_candidate_draws_per_output()
                    == super::super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
        }));
    }

    #[test]
    fn public_sampler_catalog_rejects_nonzero_pow_before_recording_rows() {
        let mut pcs = plain_aggregate_pcs(21).expect("exact plain WHIR configuration");
        pcs.config.final_pow_bits = 1;
        let mut catalog = PublicSamplerExhaustionCatalog::default();
        assert_eq!(
            extend_plain_aggregate_public_sampler_exhaustion_catalog(
                &mut catalog,
                &pcs,
                super::super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            ),
            Err("plain WHIR public sampler catalog requires the zero-PoW profile".to_owned())
        );
        assert_eq!(catalog.logical_verifier_message_count(), 0);
        assert_eq!(catalog.bit_output_count(), 0);
        assert_eq!(catalog.grinding_output_count(), 0);
    }

    #[test]
    fn explicit_points_are_bound_and_verified() {
        let variable_count = 12;
        let pcs = plain_aggregate_test_pcs(variable_count).expect("plain WHIR configuration");
        let mut prover_challenger = plain_aggregate_challenger(&pcs, b"plain explicit-point test");
        let message = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 19 + 7))
                .collect(),
        );
        let points = vec![
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 + 2))
                    .collect(),
            ),
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 3 + 11))
                    .collect(),
            ),
        ];
        let (commitment, prover_data) =
            commit_plain_aggregate(&pcs, message, &mut prover_challenger);
        let proof =
            open_plain_aggregate_at_points(&pcs, prover_data, &points, &mut prover_challenger);

        let verifier_pcs =
            plain_aggregate_test_pcs(variable_count).expect("verifier configuration");
        let mut verifier_challenger =
            plain_aggregate_challenger(&verifier_pcs, b"plain explicit-point test");
        verify_plain_aggregate_at_points(
            &verifier_pcs,
            &commitment,
            &proof,
            &points,
            &mut verifier_challenger,
        )
        .expect("verify explicit points");

        let mut changed_coordinates = points[0].as_slice().to_vec();
        changed_coordinates[0] += ChallengeField::ONE;
        let mut changed_points = points;
        changed_points[0] = Point::new(changed_coordinates);
        let mut changed_verifier_challenger =
            plain_aggregate_challenger(&verifier_pcs, b"plain explicit-point test");
        assert!(
            verify_plain_aggregate_at_points(
                &verifier_pcs,
                &commitment,
                &proof,
                &changed_points,
                &mut changed_verifier_challenger,
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_point_whir_rejects_a_false_evaluation_that_the_weak_proof_does_not_bind() {
        let variable_count = 12;
        let statement = b"plain explicit-point forgery regression";
        let pcs = plain_aggregate_test_pcs(variable_count).expect("plain WHIR configuration");
        let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
        let zero_message = Poly::new(vec![ChallengeField::ZERO; 1_usize << variable_count]);
        let (commitment, prover_data) =
            commit_plain_aggregate(&pcs, zero_message, &mut prover_challenger);
        let sampled_point = Point::<ChallengeField>::new(
            (0..variable_count)
                .map(|_| prover_challenger.sample_algebra_element())
                .collect(),
        );
        assert!(
            sampled_point.as_slice().iter().any(|coordinate| {
                *coordinate != ChallengeField::ZERO && *coordinate != ChallengeField::ONE
            }),
            "the explicit-point forgery regression requires a non-Boolean sampled point",
        );
        let weak_proof = open_plain_aggregate_batches_at_points(
            &pcs,
            prover_data,
            &[],
            &[],
            &mut prover_challenger,
        );
        assert!(weak_proof.evals.is_empty());

        let verifier_pcs =
            plain_aggregate_test_pcs(variable_count).expect("verifier configuration");
        let mut weak_verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
        weak_verifier_challenger.observe(commitment.clone());
        let weak_verifier_point = Point::<ChallengeField>::new(
            (0..variable_count)
                .map(|_| weak_verifier_challenger.sample_algebra_element())
                .collect(),
        );
        assert_eq!(weak_verifier_point.as_slice(), sampled_point.as_slice());
        verify_plain_aggregate_batches_with_requests_after_commitment(
            &verifier_pcs,
            &commitment,
            &weak_proof,
            &[],
            variable_count,
            1,
            &[],
            &mut weak_verifier_challenger,
        )
        .expect("the weak Merkle-plus-sumcheck proof verifies without an explicit-point claim");

        let mut forged_proof = weak_proof;
        forged_proof
            .evals
            .push(OpeningBatch::new(vec![ChallengeField::ONE], Vec::new()));
        let mut production_verifier_challenger =
            plain_aggregate_challenger(&verifier_pcs, statement);
        production_verifier_challenger.observe(commitment.clone());
        let production_verifier_point = Point::<ChallengeField>::new(
            (0..variable_count)
                .map(|_| production_verifier_challenger.sample_algebra_element())
                .collect(),
        );
        assert_eq!(
            production_verifier_point.as_slice(),
            sampled_point.as_slice()
        );
        let production_error = verify_plain_aggregate_batches_with_requests_after_commitment(
            &verifier_pcs,
            &commitment,
            &forged_proof,
            &[production_verifier_point],
            variable_count,
            1,
            &[vec![0]],
            &mut production_verifier_challenger,
        )
        .expect_err("the production explicit-point verifier accepted a false evaluation");
        assert!(
            production_error.contains("verify explicit-point plain WHIR proof"),
            "the false evaluation reached an unexpected refusal: {production_error}",
        );
    }

    #[test]
    #[ignore = "manual target-size evidence"]
    fn heavy_rust_kernel_target_plain_whir_aggregate_proof_size() {
        use std::collections::BTreeSet;

        let variable_count = 20;
        let opening_count = 480;
        let pcs = plain_aggregate_test_pcs(variable_count).expect("plain WHIR configuration");
        let statement = b"plain aggregate target-size evidence";
        let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
        let message = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 1_000_003 + 41))
                .collect(),
        );
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let (commitment, prover_data) =
            commit_plain_aggregate(&pcs, message, &mut prover_challenger);
        let proof =
            open_plain_aggregate_at_points(&pcs, prover_data, &points, &mut prover_challenger);
        let canonical =
            super::super::plain_whir_wire::encode_plain_whir_proof(&pcs, &proof, opening_count)
                .expect("encode bounded canonical plain WHIR proof");
        let breakdown =
            super::super::plain_whir_wire::plain_whir_wire_breakdown(&pcs, &proof, opening_count)
                .expect("measure canonical plain WHIR proof");
        println!(
            "canonical plain aggregate proof bytes: {}, query values: {}, dictionary: {}, references: {}",
            canonical.len(),
            breakdown.query_value_byte_length,
            breakdown.merkle_dictionary_byte_length,
            breakdown.merkle_reference_byte_length,
        );
        println!(
            "plain WHIR rounds: {}, initial fold: {}, final queries: {}, final variables: {}",
            pcs.n_rounds(),
            pcs.round_folding_factor(0),
            pcs.final_queries,
            pcs.final_round_config().num_variables,
        );
        for (round_index, round) in proof.whir.rounds.iter().enumerate() {
            let first_query = round.queries.first().expect("round query");
            let (value_count, path_count) = match first_query {
                p3_whir::QueryOpening::Base { values, proof }
                | p3_whir::QueryOpening::Extension { values, proof } => (values.len(), proof.len()),
            };
            println!(
                "round {round_index}: queries {}, values {}, path {}, OOD {}, sumcheck {}",
                round.queries.len(),
                value_count,
                path_count,
                round.ood_answers.len(),
                round.sumcheck.num_rounds(),
            );
        }
        let first_final_query = proof.whir.final_queries.first().expect("final query");
        let (final_value_count, final_path_count) = match first_final_query {
            p3_whir::QueryOpening::Base { values, proof }
            | p3_whir::QueryOpening::Extension { values, proof } => (values.len(), proof.len()),
        };
        println!(
            "final: queries {}, values {}, path {}, sumcheck {}",
            proof.whir.final_queries.len(),
            final_value_count,
            final_path_count,
            proof
                .whir
                .final_sumcheck
                .as_ref()
                .map_or(0, p3_sumcheck::SumcheckData::num_rounds),
        );
        let mut unique_merkle_nodes = BTreeSet::new();
        let mut merkle_references = 0_usize;
        for query in proof
            .whir
            .rounds
            .iter()
            .flat_map(|round| round.queries.iter())
            .chain(proof.whir.final_queries.iter())
        {
            let path = match query {
                p3_whir::QueryOpening::Base { proof, .. }
                | p3_whir::QueryOpening::Extension { proof, .. } => proof,
            };
            merkle_references += path.len();
            unique_merkle_nodes.extend(path.iter().copied());
        }
        println!(
            "Merkle dictionary: {} unique nodes, {} references, {} fixed bytes",
            unique_merkle_nodes.len(),
            merkle_references,
            unique_merkle_nodes.len() * super::super::MERKLE_DIGEST_WORD_LENGTH * 8
                + merkle_references * 4,
        );

        let verifier_pcs =
            plain_aggregate_test_pcs(variable_count).expect("verifier configuration");
        let decoded = super::super::plain_whir_wire::decode_plain_whir_proof(
            &verifier_pcs,
            &canonical,
            opening_count,
        )
        .expect("decode bounded canonical plain WHIR proof");
        let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
        verify_plain_aggregate_at_points(
            &verifier_pcs,
            &commitment,
            &decoded,
            &points,
            &mut verifier_challenger,
        )
        .expect("verify target plain WHIR proof");
    }

    #[test]
    #[ignore = "manual parameter-size evidence"]
    fn heavy_rust_kernel_plain_whir_parameter_size_sweep() {
        let variable_count = 20;
        let opening_count = 480;
        let statement = b"plain aggregate parameter-size sweep";
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        for starting_log_inverse_rate in 2..=4 {
            for folding_factor in 4..=8 {
                let Ok(pcs) = plain_aggregate_pcs_with_parameters(
                    variable_count,
                    starting_log_inverse_rate,
                    folding_factor,
                ) else {
                    println!(
                        "configuration start={starting_log_inverse_rate} fold={folding_factor}: invalid"
                    );
                    continue;
                };
                let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
                let message = Poly::new(
                    (0..1_usize << variable_count)
                        .map(|index| ChallengeField::from_u64(index as u64 * 1_000_003 + 41))
                        .collect(),
                );
                let (commitment, prover_data) =
                    commit_plain_aggregate(&pcs, message, &mut prover_challenger);
                let proof = open_plain_aggregate_at_points(
                    &pcs,
                    prover_data,
                    &points,
                    &mut prover_challenger,
                );
                let Ok(canonical) = super::super::plain_whir_wire::encode_plain_whir_proof(
                    &pcs,
                    &proof,
                    opening_count,
                ) else {
                    println!(
                        "configuration start={starting_log_inverse_rate} fold={folding_factor}: exceeds canonical wire cap"
                    );
                    continue;
                };
                let breakdown = super::super::plain_whir_wire::plain_whir_wire_breakdown(
                    &pcs,
                    &proof,
                    opening_count,
                )
                .expect("measure parameter-sweep proof");
                let verifier_pcs = plain_aggregate_pcs_with_parameters(
                    variable_count,
                    starting_log_inverse_rate,
                    folding_factor,
                )
                .expect("reconstruct verifier configuration");
                let decoded = super::super::plain_whir_wire::decode_plain_whir_proof(
                    &verifier_pcs,
                    &canonical,
                    opening_count,
                )
                .expect("decode parameter-sweep proof");
                let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
                verify_plain_aggregate_at_points(
                    &verifier_pcs,
                    &commitment,
                    &decoded,
                    &points,
                    &mut verifier_challenger,
                )
                .expect("verify parameter-sweep proof");
                println!(
                    "configuration start={starting_log_inverse_rate} fold={folding_factor}: bytes={}, values={}, dictionary={}, references={}, rounds={}, final_queries={}, final_variables={}",
                    canonical.len(),
                    breakdown.query_value_byte_length,
                    breakdown.merkle_dictionary_byte_length,
                    breakdown.merkle_reference_byte_length,
                    pcs.n_rounds(),
                    pcs.final_queries,
                    pcs.final_round_config().num_variables,
                );
            }
        }
    }

    #[test]
    #[ignore = "manual exact-layout size evidence"]
    fn heavy_rust_kernel_exact_layout_plain_whir_size() {
        let table_variable_count = 19;
        let table_width = 4_usize;
        let mut requested_columns_by_point = vec![vec![0], vec![1], vec![2]];
        requested_columns_by_point.extend((0..387).map(|_| vec![0, 1, 2]));
        requested_columns_by_point.extend((0..80 + 532 + 8).map(|_| vec![3]));
        let opening_count = requested_columns_by_point.len();
        let selector_variable_count = table_width.next_power_of_two().ilog2() as usize;
        let pcs_variable_count = table_variable_count + selector_variable_count;
        let statement = b"plain aggregate exact production-layout size";
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..table_variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let expected_opening_widths = requested_columns_by_point
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>();
        let selected_parameters = RowCodeWhirSelectedParameters::selected();
        let starting_log_inverse_rate = selected_parameters.starting_log_inverse_rate;
        let folding_factor = selected_parameters.folding_factor;
        let pcs = plain_aggregate_pcs_with_parameters(
            pcs_variable_count,
            starting_log_inverse_rate,
            folding_factor,
        )
        .expect("exact-layout configuration");
        let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
        let messages = (0..table_width)
            .map(|table_column| {
                Poly::new(
                    (0..1_usize << table_variable_count)
                        .map(|index| {
                            ChallengeField::from_u64(
                                index as u64 * 1_000_003 + table_column as u64 * 65_537 + 41,
                            )
                        })
                        .collect(),
                )
            })
            .collect();
        let (commitment, prover_data) =
            commit_plain_aggregate_batch(&pcs, messages, &mut prover_challenger);
        let proof = open_plain_aggregate_batches_at_points(
            &pcs,
            prover_data,
            &points,
            &requested_columns_by_point,
            &mut prover_challenger,
        );
        let canonical = super::super::plain_whir_wire::encode_plain_whir_batch_proof(
            &pcs,
            &proof,
            &expected_opening_widths,
            table_width,
        )
        .expect("encode exact-layout proof");
        let breakdown = super::super::plain_whir_wire::plain_whir_batch_wire_breakdown(
            &pcs,
            &proof,
            &expected_opening_widths,
            table_width,
        )
        .expect("measure exact-layout proof");
        let verifier_pcs = plain_aggregate_pcs_with_parameters(
            pcs_variable_count,
            starting_log_inverse_rate,
            folding_factor,
        )
        .expect("verifier configuration");
        let decoded = super::super::plain_whir_wire::decode_plain_whir_batch_proof(
            &verifier_pcs,
            &canonical,
            &expected_opening_widths,
            table_width,
        )
        .expect("decode exact-layout proof");
        let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
        verify_plain_aggregate_batches_at_points(
            &verifier_pcs,
            &commitment,
            &decoded,
            &points,
            table_variable_count,
            table_width,
            &requested_columns_by_point,
            &mut verifier_challenger,
        )
        .expect("verify exact-layout proof");
        println!(
            "exact layout start={starting_log_inverse_rate}, fold={folding_factor}: bytes={}, values={}, dictionary={}, references={}, rounds={}, final_queries={}, final_variables={}",
            canonical.len(),
            breakdown.query_value_byte_length,
            breakdown.merkle_dictionary_byte_length,
            breakdown.merkle_reference_byte_length,
            pcs.n_rounds(),
            pcs.final_queries,
            pcs.final_round_config().num_variables,
        );
    }
}
