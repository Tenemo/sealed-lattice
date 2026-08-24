//! Checked WHIR configuration and commitments for the aggregate-wide proof.
//!
//! The selected prover supplies the explicit points and implements the masked
//! sumcheck and compact opening protocol directly. This module retains only
//! the upstream configuration, commitment type, oracle geometry, and domain
//! separator needed by that construction.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::layout::PrefixProver;
use p3_whir::{DomainSeparator, FoldingFactor, WhirProver};

use super::construction_plan::{
    RowCodeWhirConstructionPlan, RowCodeWhirEncodedOraclePlan, RowCodeWhirFinalRoundPlan,
    RowCodeWhirQueryEpochPlan, RowCodeWhirRoundPlan, RowCodeWhirSelectedParameters,
    RowCodeWhirSoundnessAssumption, RowCodeWhirWhirPlan,
};
use super::{ChallengeField, CommitmentScheme, DiscreteFourierTransform, ExtensionFieldChallenger};

pub(super) type AggregateLayout = PrefixProver<ChallengeField, ChallengeField>;
pub(super) type AggregateWidePcs = WhirProver<
    ChallengeField,
    ChallengeField,
    DiscreteFourierTransform,
    CommitmentScheme,
    ExtensionFieldChallenger,
    AggregateLayout,
>;
pub(super) type AggregateWideCommitment =
    <AggregateWidePcs as MultilinearPcs<ChallengeField, ExtensionFieldChallenger>>::Commitment;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideEncodedOracleGeometry {
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

pub(super) fn aggregate_wide_pcs_for_construction_plan(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<AggregateWidePcs, String> {
    let pcs = aggregate_wide_pcs_from_selected_parameters(
        construction_plan.selected_parameters(),
        construction_plan.proof_privacy_mode,
    )?;
    ensure_aggregate_wide_pcs_matches_construction_plan(&pcs, construction_plan)?;
    Ok(pcs)
}

fn aggregate_wide_pcs_from_selected_parameters(
    parameters: RowCodeWhirSelectedParameters,
    privacy_mode: crate::bgv::proof_suite::relation_plan::ProofPrivacyMode,
) -> Result<AggregateWidePcs, String> {
    let configuration = super::hiding_whir::selected_hiding_whir_config(parameters)
        .map_err(|error| format!("construct aggregate-wide WHIR configuration: {error}"))?
        .inner;
    let commitment_scheme = CommitmentScheme::verifier(privacy_mode);
    Ok(WhirProver::new(
        configuration,
        DiscreteFourierTransform::default(),
        commitment_scheme,
    ))
}

fn ensure_aggregate_wide_pcs_matches_construction_plan(
    pcs: &AggregateWidePcs,
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
        || !matches!(
            (pcs.params.soundness_type, parameters.soundness_assumption),
            (
                p3_whir::SecurityAssumption::UniqueDecoding,
                RowCodeWhirSoundnessAssumption::UniqueDecoding
            )
        )
        || pcs.params.security_level != parameters.security_level
        || pcs.params.pow_bits != parameters.proof_of_work_bits
    {
        return Err(
            "aggregate-wide WHIR parameters do not match the checked construction plan".to_owned(),
        );
    }
    let (derived_whir_plan, _) = derive_aggregate_wide_whir_plan_from_pcs(pcs)?;
    if &derived_whir_plan != construction_plan.whir_plan() {
        return Err(
            "aggregate-wide WHIR configuration does not match the checked construction plan"
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn aggregate_wide_challenger_from_transcript(
    pcs: &AggregateWidePcs,
    construction_plan: &RowCodeWhirConstructionPlan,
    transcript: super::RowCodeWhirTranscript,
) -> Result<ExtensionFieldChallenger, String> {
    let expected_whir_plan = construction_plan.whir_plan();
    let (derived_whir_plan, _) = derive_aggregate_wide_whir_plan_from_pcs(pcs)?;
    if &derived_whir_plan != expected_whir_plan {
        return Err(
            "aggregate-wide challenger geometry does not match the checked construction plan"
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
    let hiding_configuration =
        super::hiding_whir::selected_hiding_whir_config(construction_plan.selected_parameters())
            .map_err(|error| format!("derive aggregate-wide challenger geometry: {error}"))?;
    let pad_layout =
        super::aggregate_wide_hiding::AggregateWidePadLayout::derive(&hiding_configuration)?;
    let pad_shape = p3_whir::MaskCodeShape::new(
        pad_layout.message_length(),
        hiding_configuration.sumcheck_mask.randomness_len,
        super::aggregate_wide_hiding::AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    );
    query_schedule.push(super::WhirQueryEpoch {
        bit_length: pad_shape.domain_size.ilog2() as usize,
        query_count: hiding_configuration.mask_queries,
    });
    let mut challenger = ExtensionFieldChallenger::new(transcript, query_schedule);
    let mut separator = DomainSeparator::<ChallengeField, ChallengeField>::new(Vec::new());
    pcs.add_domain_separator::<{ super::MERKLE_DIGEST_WORD_LENGTH }>(&mut separator);
    separator.observe_domain_separator(&mut challenger);
    challenger.ensure_sampling_succeeded()?;
    Ok(challenger)
}

pub(super) fn aggregate_wide_encoded_oracle_geometries(
    pcs: &AggregateWidePcs,
) -> Result<Vec<AggregateWideEncodedOracleGeometry>, String> {
    let encoded_oracle_count = pcs
        .n_rounds()
        .checked_add(1)
        .ok_or_else(|| "aggregate-wide encoded-oracle count overflowed".to_owned())?;
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
            .ok_or_else(|| "aggregate-wide encoded-oracle height overflowed".to_owned())?;
        let width = 1_usize
            .checked_shl(
                u32::try_from(folding_factor)
                    .map_err(|_| "WHIR folding factor exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "aggregate-wide encoded-oracle width overflowed".to_owned())?;
        if height == 0
            || !height.is_power_of_two()
            || width == 0
            || !width.is_power_of_two()
            || height.checked_mul(width) != Some(domain_size)
        {
            return Err("aggregate-wide encoded-oracle geometry is invalid".to_owned());
        }
        geometries.push(AggregateWideEncodedOracleGeometry { height, width });
    }
    Ok(geometries)
}

pub(super) fn derive_aggregate_wide_whir_plan(
    parameters: RowCodeWhirSelectedParameters,
    privacy_mode: crate::bgv::proof_suite::relation_plan::ProofPrivacyMode,
) -> Result<
    (
        RowCodeWhirWhirPlan,
        Vec<super::super::ProofChallengeExtensionElement>,
    ),
    String,
> {
    let pcs = aggregate_wide_pcs_from_selected_parameters(parameters, privacy_mode)?;
    derive_aggregate_wide_whir_plan_from_pcs(&pcs)
}

fn derive_aggregate_wide_whir_plan_from_pcs(
    pcs: &AggregateWidePcs,
) -> Result<
    (
        RowCodeWhirWhirPlan,
        Vec<super::super::ProofChallengeExtensionElement>,
    ),
    String,
> {
    let geometries = aggregate_wide_encoded_oracle_geometries(pcs)?;
    if geometries.len() != pcs.n_rounds() + 1 {
        return Err("aggregate-wide encoded-oracle geometry is incomplete".to_owned());
    }

    let query_epoch = |epoch_ordinal: usize,
                       geometry: AggregateWideEncodedOracleGeometry,
                       query_count: usize|
     -> Result<RowCodeWhirQueryEpochPlan, String> {
        let query_count = query_count.min(geometry.height);
        if geometry.height == 0 || !geometry.height.is_power_of_two() || query_count == 0 {
            return Err("aggregate-wide query epoch has invalid geometry".to_owned());
        }
        Ok(RowCodeWhirQueryEpochPlan {
            epoch_ordinal: u32::try_from(epoch_ordinal)
                .map_err(|_| "aggregate-wide query epoch ordinal exceeds u32".to_owned())?,
            bit_length: usize::try_from(geometry.height.ilog2())
                .map_err(|_| "aggregate-wide query bit length exceeds usize".to_owned())?,
            domain_size: geometry.height,
            query_count,
        })
    };
    let encoded_oracle = |geometry: AggregateWideEncodedOracleGeometry|
     -> Result<RowCodeWhirEncodedOraclePlan, String> {
        Ok(RowCodeWhirEncodedOraclePlan {
            evaluation_count: geometry
                .height
                .checked_mul(geometry.width)
                .ok_or_else(|| "aggregate-wide encoded-oracle size overflowed".to_owned())?,
            leaf_count: geometry.height,
            leaf_width: geometry.width,
        })
    };

    let mut rounds = Vec::with_capacity(pcs.n_rounds());
    for (round_index, round_parameters) in pcs.round_parameters.iter().enumerate() {
        rounds.push(RowCodeWhirRoundPlan {
            round_ordinal: u32::try_from(round_index)
                .map_err(|_| "aggregate-wide round ordinal exceeds u32".to_owned())?,
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
        .ok_or_else(|| "aggregate-wide final encoded-oracle geometry is absent".to_owned())?;
    let final_round_configuration = pcs.final_round_config();
    let revealed_coefficient_count = 1_usize
        .checked_shl(
            u32::try_from(final_round_configuration.num_variables)
                .map_err(|_| "aggregate-wide final variable count exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "aggregate-wide final polynomial size overflowed".to_owned())?;
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
                .map_err(|_| "aggregate-wide protocol schedule is not canonical".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if canonical_schedule.is_empty() {
        return Err("aggregate-wide protocol schedule is empty".to_owned());
    }
    Ok((whir_plan, canonical_schedule))
}
