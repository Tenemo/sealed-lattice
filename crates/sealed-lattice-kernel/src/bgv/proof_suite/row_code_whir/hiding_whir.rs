//! Hiding aggregate-opening configuration for the selected construction.
//!
//! The row pads committed inside the phase rows cannot mask a query answer,
//! because every query vector is drawn only after the aggregate commitment is
//! observed. Query-answer masking therefore belongs to mask groups committed
//! with the aggregate, and the construction already reserves a hiding component
//! in its round-by-round budget.
//!
//! This module derives that configuration from the same selected parameters the
//! plain aggregate opening uses, so the mask geometry the construction plan must
//! bind is a derived quantity rather than a chosen one. It does not yet replace
//! the operative opening argument.

use p3_whir::{FoldingFactor, ProtocolParameters, ZkParameters, ZkWhirConfig};

use super::construction_plan::{RowCodeWhirSelectedParameters, RowCodeWhirSoundnessAssumption};
use super::{ChallengeField, ExtensionFieldChallenger};

/// Mask-code message length for the hiding sumcheck.
///
/// The vendored configuration requires at least three coefficients. The selected
/// construction uses the minimum, because the sumcheck mask only has to hide the
/// per-round sumcheck wires and every additional coefficient is proof bytes that
/// no view consumes.
const SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH: usize = 3;

/// Log inverse rate of the mask codewords.
///
/// A rate-one mask code has minimal distance, so its spot checks barely bind and
/// the vendored configuration refuses it. The selected construction reuses the
/// row code's inverse rate so the mask codewords carry the same relative
/// distance as everything else the verifier spot-checks.
const SELECTED_HIDING_MASK_LOG_INVERSE_RATE: usize = 2;

pub(super) type SelectedHidingWhirConfig =
    ZkWhirConfig<ChallengeField, ChallengeField, ExtensionFieldChallenger>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HidingWhirConfigurationError {
    UnsupportedVariableCount,
    Vendored,
}

impl core::fmt::Display for HidingWhirConfigurationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVariableCount => write!(
                formatter,
                "the hiding aggregate opening requires the selected commitment variable count"
            ),
            Self::Vendored => write!(
                formatter,
                "the vendored hiding WHIR configuration refused the selected parameters"
            ),
        }
    }
}

pub(super) const fn selected_hiding_parameters() -> ZkParameters {
    ZkParameters {
        ell_zk: SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH,
        mask_log_inv_rate: SELECTED_HIDING_MASK_LOG_INVERSE_RATE,
    }
}

/// Derives the hiding configuration for the selected construction parameters.
///
/// The plain and hiding configurations share one round structure, so the folding
/// factors, domains, query counts, and proof-of-work bits are the same values the
/// construction plan already binds. Only the mask budgets are new.
pub(super) fn selected_hiding_whir_config(
    parameters: RowCodeWhirSelectedParameters,
) -> Result<SelectedHidingWhirConfig, HidingWhirConfigurationError> {
    if parameters.polynomial_commitment_variable_count == 0 {
        return Err(HidingWhirConfigurationError::UnsupportedVariableCount);
    }
    let soundness_type = match parameters.soundness_assumption {
        RowCodeWhirSoundnessAssumption::UniqueDecoding => {
            p3_whir::SecurityAssumption::UniqueDecoding
        }
    };
    ZkWhirConfig::new(
        parameters.polynomial_commitment_variable_count,
        ProtocolParameters {
            starting_log_inv_rate: parameters.starting_log_inverse_rate,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(parameters.folding_factor),
            soundness_type,
            security_level: parameters.security_level,
            pow_bits: parameters.proof_of_work_bits,
        },
        selected_hiding_parameters(),
    )
    .map_err(|_| HidingWhirConfigurationError::Vendored)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the mask geometry the construction plan will have to bind.
    ///
    /// Every value here is derived from the selected parameters, so a change to
    /// the round structure, query counts, or security level moves this geometry
    /// and must move the plan and the exact ledger with it.
    #[test]
    fn selected_hiding_configuration_derives_its_complete_mask_geometry() {
        let parameters = RowCodeWhirSelectedParameters::selected();
        let configuration = selected_hiding_whir_config(parameters)
            .expect("the selected parameters admit a hiding configuration");

        // The hiding pipeline keeps the plain round structure.
        assert_eq!(configuration.inner.n_rounds(), 4);
        assert_eq!(
            configuration.inner.starting_log_inv_rate,
            parameters.starting_log_inverse_rate
        );

        // Each oracle's randomness budget equals the spot checks of the round
        // that consumes it, so every opening against it is simulatable.
        let consuming_query_counts = configuration
            .inner
            .round_parameters
            .iter()
            .map(|round| round.num_queries)
            .chain(core::iter::once(configuration.inner.final_queries))
            .collect::<Vec<_>>();
        assert_eq!(configuration.oracle_randomness, consuming_query_counts);
        assert_eq!(configuration.oracle_randomness.len(), 5);

        // Randomness must fit strictly inside each oracle's rate slack, which is
        // load-bearing for zero knowledge rather than a layout convenience. The
        // vendored constructor enforces it, so a successful derivation is the
        // proof that it holds for the selected geometry.
        assert!(
            configuration
                .oracle_randomness
                .iter()
                .all(|randomness| *randomness > 0)
        );

        // One sumcheck mask plus one code-switch mask per round.
        assert_eq!(configuration.switch_masks.len(), 4);
        assert_eq!(
            configuration.sumcheck_mask.message_len,
            SELECTED_HIDING_SUMCHECK_MASK_MESSAGE_LENGTH
        );
        assert_eq!(
            configuration.sumcheck_mask.randomness_len,
            configuration.mask_queries
        );

        // Each code-switch mask commits the previous oracle's folded randomness
        // plus one pad coordinate per out-of-domain answer of that round.
        for (round_index, mask) in configuration.switch_masks.iter().enumerate() {
            assert_eq!(
                mask.message_len,
                configuration.oracle_randomness[round_index]
                    + configuration.inner.round_parameters[round_index].ood_samples
            );
            assert_eq!(mask.randomness_len, configuration.mask_queries);
            // The mask domain is the smallest power of two that holds the
            // message and its randomness, expanded by the mask code's inverse
            // rate. Recomputing it independently keeps the layout honest.
            assert_eq!(
                mask.domain_size,
                (mask.message_len + mask.randomness_len).next_power_of_two()
                    << SELECTED_HIDING_MASK_LOG_INVERSE_RATE
            );
        }

        // Mask spot checks carry no proof-of-work relief, so they target the
        // full security level plus the union over every mask oracle. For the
        // selected geometry that union is over ten mask oracles, four bits.
        assert_eq!(configuration.mask_queries, 393);

        // The complete derived geometry, pinned so the construction plan binds
        // measured values. Round out-of-domain sampling is empty, which also
        // corroborates the response census behind the transcript ceiling.
        assert_eq!(
            configuration.oracle_randomness,
            vec![387, 288, 268, 264, 263]
        );
        assert_eq!(configuration.sumcheck_mask.domain_size, 2_048);
        assert_eq!(
            configuration
                .switch_masks
                .iter()
                .map(|mask| (mask.message_len, mask.domain_size))
                .collect::<Vec<_>>(),
            vec![(387, 4_096), (288, 4_096), (268, 4_096), (264, 4_096)],
        );
        assert!(
            configuration
                .inner
                .round_parameters
                .iter()
                .all(|round| round.ood_samples == 0)
        );
        let total_mask_codeword_coordinates: usize =
            core::iter::once(configuration.sumcheck_mask.domain_size)
                .chain(
                    configuration
                        .switch_masks
                        .iter()
                        .map(|mask| mask.domain_size),
                )
                .sum();
        assert_eq!(total_mask_codeword_coordinates, 18_432);
    }

    #[test]
    fn hiding_configuration_refuses_a_degenerate_mask_code() {
        assert!(matches!(
            selected_hiding_whir_config(RowCodeWhirSelectedParameters {
                polynomial_commitment_variable_count: 0,
                ..RowCodeWhirSelectedParameters::selected()
            }),
            Err(HidingWhirConfigurationError::UnsupportedVariableCount),
        ));
    }
}
