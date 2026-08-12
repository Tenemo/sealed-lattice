//! Verifier-owned WHIR geometry for the selected compact proof contract.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters, ZkWhirConfig};

use super::compact_cfw_geometry::CompactCfwVerifierConfiguration;

pub(crate) const COMPACT_WHIR_EPOCH_COUNT: usize = 2;
pub(crate) const COMPACT_WHIR_FOLD_COUNT: usize = 4;
const COMPACT_WHIR_ROUND_COUNT: usize = COMPACT_WHIR_FOLD_COUNT - 1;
const COMPACT_WHIR_FINAL_VARIABLE_COUNT: u32 = 3;
const COMPACT_WHIR_REPEATED_FOLDING_FACTOR: u32 = 4;
const COMPACT_WHIR_STARTING_LOG_INVERSE_RATE: usize = 2;
const COMPACT_WHIR_ROUND_LOG_INVERSE_RATES: [u32; COMPACT_WHIR_ROUND_COUNT] = [2, 4, 8];
const COMPACT_WHIR_PROTOCOL_SECURITY_LEVEL: usize = 267;
const COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;
const COMPACT_WHIR_MASK_LOG_INVERSE_RATE: usize = 2;

type CompactWhirChallengeField = BinomialExtensionField<Goldilocks, 5>;

#[derive(Clone, Copy, Debug)]
struct ConfigurationOnlyChallenger<Field>(core::marker::PhantomData<Field>);

impl<Field> CanObserve<Field> for ConfigurationOnlyChallenger<Field> {
    fn observe(&mut self, _value: Field) {}
}

impl<Field: p3_field::Field> CanSample<Field> for ConfigurationOnlyChallenger<Field> {
    fn sample(&mut self) -> Field {
        Field::ZERO
    }
}

impl<Field> CanSampleBits<usize> for ConfigurationOnlyChallenger<Field> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        0
    }
}

impl<Field: p3_field::Field> FieldChallenger<Field> for ConfigurationOnlyChallenger<Field> {}

impl<Field: p3_field::Field> GrindingChallenger for ConfigurationOnlyChallenger<Field> {
    type Witness = Field;

    fn grind(&mut self, _bits: usize) -> Self::Witness {
        Field::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirVerifierEpochGeometry {
    polynomial_variable_count: u32,
    folding_schedule: [u32; COMPACT_WHIR_FOLD_COUNT],
    final_variable_count: u32,
    round_log_inverse_rates: [u32; COMPACT_WHIR_ROUND_COUNT],
    query_counts: [u64; COMPACT_WHIR_FOLD_COUNT],
    mask_query_count: u64,
}

impl CompactWhirVerifierEpochGeometry {
    pub(crate) const fn polynomial_variable_count(self) -> u32 {
        self.polynomial_variable_count
    }

    pub(crate) const fn folding_schedule(self) -> [u32; COMPACT_WHIR_FOLD_COUNT] {
        self.folding_schedule
    }

    pub(crate) const fn final_variable_count(self) -> u32 {
        self.final_variable_count
    }

    pub(crate) const fn round_log_inverse_rates(self) -> [u32; COMPACT_WHIR_ROUND_COUNT] {
        self.round_log_inverse_rates
    }

    pub(crate) const fn query_counts(self) -> [u64; COMPACT_WHIR_FOLD_COUNT] {
        self.query_counts
    }

    pub(crate) const fn mask_query_count(self) -> u64 {
        self.mask_query_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirVerifierGeometry {
    epochs: [CompactWhirVerifierEpochGeometry; COMPACT_WHIR_EPOCH_COUNT],
    cross_epoch_mask_width: u64,
    cross_epoch_mask_message_length: u64,
}

impl CompactWhirVerifierGeometry {
    pub(crate) fn derive(
        cfw_configuration: CompactCfwVerifierConfiguration,
    ) -> Result<Self, CompactWhirGeometryError> {
        let cross_epoch = cfw_configuration.cross_epoch();
        let polynomial_variable_counts = [
            exact_log2(cross_epoch.pre_challenge_message_element_count)?,
            exact_log2(cross_epoch.main_message_element_count)?,
        ];
        let epochs = [
            derive_epoch(polynomial_variable_counts[0])?,
            derive_epoch(polynomial_variable_counts[1])?,
        ];
        let cross_epoch_mask_width = cfw_configuration.cross_epoch_mask_message_count();
        let preceding_claim_count = cfw_configuration.cross_epoch_preceding_claim_count();
        if cross_epoch_mask_width == 0
            || preceding_claim_count == 0
            || !preceding_claim_count.is_multiple_of(cross_epoch_mask_width)
        {
            return Err(CompactWhirGeometryError::InvalidGeometry);
        }
        let cross_epoch_mask_message_length = preceding_claim_count / cross_epoch_mask_width;
        if cross_epoch_mask_message_length == 0 {
            return Err(CompactWhirGeometryError::InvalidGeometry);
        }
        Ok(Self {
            epochs,
            cross_epoch_mask_width,
            cross_epoch_mask_message_length,
        })
    }

    pub(crate) const fn epochs(
        self,
    ) -> [CompactWhirVerifierEpochGeometry; COMPACT_WHIR_EPOCH_COUNT] {
        self.epochs
    }

    pub(crate) const fn cross_epoch_mask_width(self) -> u64 {
        self.cross_epoch_mask_width
    }

    pub(crate) const fn cross_epoch_mask_message_length(self) -> u64 {
        self.cross_epoch_mask_message_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactWhirGeometryError {
    InvalidGeometry,
    CountOverflow,
}

fn derive_epoch(
    polynomial_variable_count: u32,
) -> Result<CompactWhirVerifierEpochGeometry, CompactWhirGeometryError> {
    let repeated_fold_count = u32::try_from(COMPACT_WHIR_ROUND_COUNT)
        .map_err(|_| CompactWhirGeometryError::CountOverflow)?;
    let first_folding_factor = polynomial_variable_count
        .checked_sub(
            COMPACT_WHIR_REPEATED_FOLDING_FACTOR
                .checked_mul(repeated_fold_count)
                .and_then(|count| count.checked_add(COMPACT_WHIR_FINAL_VARIABLE_COUNT))
                .ok_or(CompactWhirGeometryError::CountOverflow)?,
        )
        .ok_or(CompactWhirGeometryError::InvalidGeometry)?;
    if first_folding_factor == 0 {
        return Err(CompactWhirGeometryError::InvalidGeometry);
    }
    let folding_schedule = [
        first_folding_factor,
        COMPACT_WHIR_REPEATED_FOLDING_FACTOR,
        COMPACT_WHIR_REPEATED_FOLDING_FACTOR,
        COMPACT_WHIR_REPEATED_FOLDING_FACTOR,
    ];
    let configuration = ZkWhirConfig::<
        CompactWhirChallengeField,
        Goldilocks,
        ConfigurationOnlyChallenger<Goldilocks>,
    >::new(
        usize::try_from(polynomial_variable_count)
            .map_err(|_| CompactWhirGeometryError::CountOverflow)?,
        ProtocolParameters {
            starting_log_inv_rate: COMPACT_WHIR_STARTING_LOG_INVERSE_RATE,
            round_log_inv_rates: COMPACT_WHIR_ROUND_LOG_INVERSE_RATES
                .into_iter()
                .map(|rate| {
                    usize::try_from(rate).map_err(|_| CompactWhirGeometryError::CountOverflow)
                })
                .collect::<Result<Vec<_>, _>>()?,
            folding_factor: FoldingFactor::PerRound(
                folding_schedule
                    .into_iter()
                    .map(|factor| {
                        usize::try_from(factor).map_err(|_| CompactWhirGeometryError::CountOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            soundness_type: SecurityAssumption::UniqueDecoding,
            security_level: COMPACT_WHIR_PROTOCOL_SECURITY_LEVEL,
            pow_bits: 0,
        },
        ZkParameters {
            ell_zk: COMPACT_WHIR_SUMCHECK_MASK_MESSAGE_LENGTH,
            mask_log_inv_rate: COMPACT_WHIR_MASK_LOG_INVERSE_RATE,
        },
    )
    .map_err(|_| CompactWhirGeometryError::InvalidGeometry)?;

    let query_counts = configuration
        .round_parameters
        .iter()
        .map(|round| u64::try_from(round.num_queries))
        .chain(core::iter::once(u64::try_from(configuration.final_queries)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompactWhirGeometryError::CountOverflow)?
        .try_into()
        .map_err(|_| CompactWhirGeometryError::InvalidGeometry)?;
    let derived_folding_schedule: [u32; COMPACT_WHIR_FOLD_COUNT] = configuration
        .folding_schedule
        .iter()
        .copied()
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompactWhirGeometryError::CountOverflow)?
        .try_into()
        .map_err(|_| CompactWhirGeometryError::InvalidGeometry)?;
    let final_variable_count = u32::try_from(configuration.final_sumcheck_rounds)
        .map_err(|_| CompactWhirGeometryError::CountOverflow)?;
    if derived_folding_schedule != folding_schedule
        || final_variable_count != COMPACT_WHIR_FINAL_VARIABLE_COUNT
        || configuration.params.round_log_inv_rates
            != COMPACT_WHIR_ROUND_LOG_INVERSE_RATES
                .into_iter()
                .map(|rate| usize::try_from(rate).expect("u32 rate fits usize"))
                .collect::<Vec<_>>()
    {
        return Err(CompactWhirGeometryError::InvalidGeometry);
    }
    Ok(CompactWhirVerifierEpochGeometry {
        polynomial_variable_count,
        folding_schedule,
        final_variable_count,
        round_log_inverse_rates: COMPACT_WHIR_ROUND_LOG_INVERSE_RATES,
        query_counts,
        mask_query_count: u64::try_from(configuration.mask_queries)
            .map_err(|_| CompactWhirGeometryError::CountOverflow)?,
    })
}

fn exact_log2(value: u64) -> Result<u32, CompactWhirGeometryError> {
    if value == 0 || !value.is_power_of_two() {
        return Err(CompactWhirGeometryError::InvalidGeometry);
    }
    Ok(value.ilog2())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_cfw_geometry::CompactCfwCrossEpochVerifierGeometry;

    #[test]
    fn selected_geometry_is_derived_from_the_verifier_configuration() {
        let configuration = CompactCfwVerifierConfiguration::derive(
            4_194_304,
            CompactCfwCrossEpochVerifierGeometry {
                copied_ring_vector_count: 33,
                copied_element_count: 1_081_344,
                pre_challenge_message_element_count: 2_097_152,
                main_message_element_count: 4_194_304,
                point_coordinate_count: 21,
            },
        )
        .expect("selected CFW geometry derives");
        let geometry = CompactWhirVerifierGeometry::derive(configuration)
            .expect("selected WHIR geometry derives");
        let [pre_challenge, main] = geometry.epochs();
        assert_eq!(pre_challenge.polynomial_variable_count(), 21);
        assert_eq!(main.polynomial_variable_count(), 22);
        assert_eq!(pre_challenge.folding_schedule(), [6, 4, 4, 4]);
        assert_eq!(main.folding_schedule(), [7, 4, 4, 4]);
        assert_eq!(pre_challenge.query_counts(), [396, 432, 400, 348]);
        assert_eq!(main.query_counts(), [396, 432, 400, 348]);
        assert_eq!(pre_challenge.mask_query_count(), 399);
        assert_eq!(main.mask_query_count(), 399);
        assert_eq!(geometry.cross_epoch_mask_width(), 2);
        assert_eq!(geometry.cross_epoch_mask_message_length(), 1);
    }
}
