//! Derived configuration for the HVZK-WHIR pipeline.

use alloc::vec::Vec;
use core::iter::once;
use core::ops::Deref;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_util::log2_ceil_usize;
use thiserror::Error;

use super::mask::{MaskCodeShape, MaskGroupShape};
use crate::parameters::{ProtocolParameters, SecurityAssumption, WhirConfig, WhirConfigError};

/// Reasons ZK parameters cannot extend a WHIR configuration.
#[derive(Debug, Error)]
pub enum ZkConfigError {
    /// The underlying WHIR configuration is invalid.
    #[error(transparent)]
    Whir(#[from] WhirConfigError),

    /// The mask code message length is below the HVZK sumcheck minimum.
    #[error("sumcheck mask length {ell_zk} is below the minimum of 3")]
    MaskLengthTooSmall { ell_zk: usize },

    /// The mask code has no rate expansion, so its distance is too small
    /// for the spot checks to bind.
    #[error("mask_log_inv_rate must be at least 1")]
    MaskRateTooHigh,

    /// An oracle's randomness rows do not fit inside its codeword slack.
    #[error("round {round}: {randomness} randomness rows exceed the {slack} spare codeword rows")]
    RandomnessExceedsSlack {
        round: usize,
        randomness: usize,
        slack: usize,
    },

    /// A mask code domain exceeds the extension field two-adicity.
    ///
    /// - Mask codewords are evaluated over an extension-field two-adic subgroup.
    /// - A domain past the two-adicity has no generator.
    /// - Rejecting here surfaces the failure before any encoding runs.
    #[error("mask domain 2^{log_domain_size} exceeds extension-field two-adicity 2^{two_adicity}")]
    MaskDomainExceedsTwoAdicity {
        log_domain_size: usize,
        two_adicity: usize,
    },

    /// A source oracle cannot reach the requested unique-decoding query
    /// security once its hiding coefficients are included in the RS degree.
    #[error(
        "source oracle {oracle}: no query count reaches {security_level}-bit unique-decoding security with message length {message_len} and domain size {domain_size}"
    )]
    SourceUniqueDecodingQueriesInfeasible {
        oracle: usize,
        security_level: usize,
        message_len: usize,
        domain_size: usize,
    },
}

/// The exact Reed-Solomon code committed by one hiding WHIR source oracle.
///
/// Its dimension is `message_len + randomness_len`; the hiding coefficients
/// are not zero padding and therefore participate in distance and query
/// calculations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCodeShape {
    /// Multilinear message coefficients remaining after the current fold.
    pub message_len: usize,
    /// Per-limb hiding coefficients, equal to the oracle's query budget.
    pub randomness_len: usize,
    /// Number of evaluation points in the committed source codeword.
    pub domain_size: usize,
}

impl SourceCodeShape {
    /// Full RS dimension, including the hiding coefficients.
    #[must_use]
    pub const fn dimension(self) -> usize {
        self.message_len + self.randomness_len
    }

    /// Numerator of the relative minimum distance over `domain_size`.
    #[must_use]
    pub const fn minimum_distance_numerator(self) -> usize {
        self.domain_size - self.dimension() + 1
    }

    /// Numerator of the selected unique-decoding radius over `domain_size`.
    ///
    /// The integer radius is strictly below `(N - K) / (2N)`, as required by
    /// the proved mutual-correlated-agreement regime.
    #[must_use]
    pub const fn unique_decoding_radius_numerator(self) -> usize {
        (self.domain_size - self.dimension() - 1) / 2
    }

    /// Denominator of the selected integer unique-decoding radius.
    #[must_use]
    pub const fn unique_decoding_radius_denominator(self) -> usize {
        self.domain_size
    }

    /// Minimum number of positions that can agree with the uniquely decoded
    /// codeword at the selected integer radius.
    #[must_use]
    pub const fn minimum_agreement_count(self) -> usize {
        self.domain_size - self.unique_decoding_radius_numerator()
    }

    /// Query-failure security in bits for this exact code shape.
    #[must_use]
    pub fn query_security_bits(self) -> f64 {
        -(self.randomness_len as f64)
            * libm::log2(self.minimum_agreement_count() as f64 / self.domain_size as f64)
    }
}

/// User-facing ZK extension of [`ProtocolParameters`].
///
/// - The mask spot-check count `t_zk` is not a knob.
/// - [`ZkWhirConfig::new`] derives it from `security_level` and
///   `mask_log_inv_rate`.
/// - The mask code then always reaches the configured security on its
///   spot-check branch.
#[derive(Debug, Clone)]
pub struct ZkParameters {
    /// Mask code message length `ell_zk` for the HVZK sumcheck (at least 3).
    pub ell_zk: usize,
    /// Log inverse rate of the mask codewords; sets the mask code distance.
    pub mask_log_inv_rate: usize,
}

/// Fully derived HVZK-WHIR configuration.
///
/// Wraps the plain [`WhirConfig`] round structure and adds the ZK budgets:
/// per-oracle encoding randomness, mask code shapes, and spot-check counts.
#[derive(Debug, Clone)]
pub struct ZkWhirConfig<EF, F, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Plain WHIR round structure (folding factors, domains, queries, PoW).
    pub inner: WhirConfig<EF, F, Challenger>,
    /// ZK extension parameters.
    pub zk: ZkParameters,
    /// ZK randomness coefficients per limb of each committed oracle
    /// `u_0, ..., u_{n_rounds}`.
    ///
    /// Budget rule: at least the spot checks ever opened against the oracle.
    /// Every opening is then simulatable.
    pub oracle_randomness: Vec<usize>,
    /// Full source-code shapes in commitment order.
    ///
    /// Every shape includes its hiding coefficients in the RS dimension.
    pub source_code_shapes: Vec<SourceCodeShape>,
    /// Mask code for the HVZK sumcheck rounds.
    pub sumcheck_mask: MaskCodeShape,
    /// Mask code per code-switching round.
    /// It commits the previous oracle's folded randomness plus the OOD pad.
    pub switch_masks: Vec<MaskCodeShape>,
    /// Base-case spot checks per mask group, derived from `security_level`.
    pub mask_queries: usize,
}

impl<EF, F, Challenger> Deref for ZkWhirConfig<EF, F, Challenger>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Target = WhirConfig<EF, F, Challenger>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<EF, F, Challenger> ZkWhirConfig<EF, F, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    /// Derives a full HVZK configuration.
    ///
    /// # Errors
    ///
    /// - The plain WHIR configuration is invalid.
    /// - The sumcheck mask is shorter than 3 coefficients.
    /// - An oracle's randomness rows do not fit in its codeword slack.
    pub fn new(
        num_variables: usize,
        params: ProtocolParameters,
        zk: ZkParameters,
    ) -> Result<Self, ZkConfigError> {
        if zk.ell_zk < 3 {
            return Err(ZkConfigError::MaskLengthTooSmall { ell_zk: zk.ell_zk });
        }
        // A rate-one mask code has minimal distance, so its spot checks
        // barely bind; require at least a 2x domain expansion.
        if zk.mask_log_inv_rate == 0 {
            return Err(ZkConfigError::MaskRateTooHigh);
        }

        let security_level = params.security_level;
        let soundness_type = params.soundness_type;

        let mut inner = WhirConfig::<EF, F, Challenger>::new(num_variables, params)?;
        let n_rounds = inner.n_rounds();

        // The plain WHIR configuration derives query counts from the message
        // rate. A hiding source oracle instead commits
        //
        //     message || query-private randomness || zero padding,
        //
        // so its RS dimension is `message + queries`. In unique-decoding
        // mode the query count is therefore a fixed point: it is both part of
        // the distance and the number of spot checks. Derive that count from
        // every physical source domain before allocating oracle randomness.
        let source_message_and_domain = source_message_and_domain_shapes(&inner);
        if matches!(soundness_type, SecurityAssumption::UniqueDecoding) {
            let protocol_security_level = security_level.saturating_sub(inner.params.pow_bits);
            let mut source_query_counts = Vec::with_capacity(source_message_and_domain.len());
            for (oracle, &(message_len, domain_size)) in
                source_message_and_domain.iter().enumerate()
            {
                let query_count = unique_decoding_source_query_count(
                    message_len,
                    domain_size,
                    protocol_security_level,
                )
                .ok_or(ZkConfigError::SourceUniqueDecodingQueriesInfeasible {
                    oracle,
                    security_level: protocol_security_level,
                    message_len,
                    domain_size,
                })?;
                source_query_counts.push(query_count);
            }

            for (round, &query_count) in source_query_counts.iter().take(n_rounds).enumerate() {
                inner.round_parameters[round].num_queries = query_count;
            }
            inner.final_queries = source_query_counts[n_rounds];

            // Recompute the query-phase grinding gaps from the full source
            // dimensions. The combination branch remains the plain WHIR
            // expression; under unique decoding its list size is one.
            let field_size_bits = EF::bits();
            for round in 0..n_rounds {
                let (message_len, domain_size) = source_message_and_domain[round];
                let shape = SourceCodeShape {
                    message_len,
                    randomness_len: source_query_counts[round],
                    domain_size,
                };
                let round_config = &mut inner.round_parameters[round];
                let combination_security = soundness_type.queries_combination_error(
                    field_size_bits,
                    round_config.num_variables,
                    round_config.log_inv_rate,
                    round_config.ood_samples,
                    round_config.num_queries,
                );
                round_config.pow_bits = ceil_nonnegative_gap(
                    security_level as f64 - shape.query_security_bits().min(combination_security),
                );
            }
            let (message_len, domain_size) = source_message_and_domain[n_rounds];
            let final_shape = SourceCodeShape {
                message_len,
                randomness_len: source_query_counts[n_rounds],
                domain_size,
            };
            inner.final_pow_bits =
                ceil_nonnegative_gap(security_level as f64 - final_shape.query_security_bits());
        }

        // Per-oracle ZK budget.
        //
        //     oracle u_i, i < n_rounds  ->  opened by code-switch round i
        //     oracle u_{n_rounds}       ->  opened by the base case
        //
        // Each budget equals the spot checks of the round that consumes it.
        let oracle_randomness: Vec<usize> = (0..=n_rounds)
            .map(|i| {
                if i < n_rounds {
                    inner.round_parameters[i].num_queries
                } else {
                    inner.final_queries
                }
            })
            .collect();
        let source_code_shapes = source_message_and_domain
            .iter()
            .copied()
            .zip(oracle_randomness.iter().copied())
            .map(
                |((message_len, domain_size), randomness_len)| SourceCodeShape {
                    message_len,
                    randomness_len,
                    domain_size,
                },
            )
            .collect::<Vec<_>>();

        // Derive the mask spot-check count t_zk. The independently interpreted
        // static catalog checks this conservative nominal-rate count against
        // every full mask-code dimension and the complete grouped move.
        let union = log2_ceil_usize(2 * n_rounds + 2);
        let mask_queries = soundness_type.queries(security_level + union, zk.mask_log_inv_rate);

        // Randomness rows must fit inside each oracle's rate slack:
        //
        //     height - message_rows = (2^rate - 1) * message_rows >= t_i
        //
        // This is load-bearing for zero knowledge, not just a layout fit.
        // The base case opens at most `randomness` distinct positions per
        // oracle (the query budget equals the randomness budget), so the
        // bound keeps the opened set strictly inside the codeword: it never
        // saturates the domain, which would reveal a limb polynomial outright.
        for (round, &randomness) in oracle_randomness.iter().enumerate() {
            let (message_rows, height) = if round == 0 {
                let rows = 1 << (num_variables - inner.round_folding_factor(0));
                (rows, rows << inner.starting_log_inv_rate)
            } else {
                let prev = &inner.round_parameters[round - 1];
                let rows = 1 << (prev.num_variables - inner.round_folding_factor(round));
                (rows, rows * inner.inv_rate(round - 1))
            };
            let slack = height - message_rows;
            if randomness > slack {
                return Err(ZkConfigError::RandomnessExceedsSlack {
                    round,
                    randomness,
                    slack,
                });
            }
        }

        // Reject mask domains the extension field cannot host.
        //
        // The check is in log space, before the shift in `MaskCodeShape::new`,
        // so an oversized rate yields the typed error instead of overflowing.
        let mask_message_lens = once(zk.ell_zk).chain(
            (0..n_rounds).map(|j| oracle_randomness[j] + inner.round_parameters[j].ood_samples),
        );
        for message_len in mask_message_lens {
            let log_domain_size =
                log2_ceil_usize(message_len + mask_queries) + zk.mask_log_inv_rate;
            if log_domain_size > EF::TWO_ADICITY {
                return Err(ZkConfigError::MaskDomainExceedsTwoAdicity {
                    log_domain_size,
                    two_adicity: EF::TWO_ADICITY,
                });
            }
        }

        let sumcheck_mask = MaskCodeShape::new(zk.ell_zk, mask_queries, zk.mask_log_inv_rate);
        let switch_masks: Vec<MaskCodeShape> = (0..n_rounds)
            .map(|j| {
                MaskCodeShape::new(
                    oracle_randomness[j] + inner.round_parameters[j].ood_samples,
                    mask_queries,
                    zk.mask_log_inv_rate,
                )
            })
            .collect();

        Ok(Self {
            inner,
            zk,
            oracle_randomness,
            source_code_shapes,
            sumcheck_mask,
            switch_masks,
            mask_queries,
        })
    }

    /// Mask oracle groups in chronological commit order.
    ///
    /// One `k`-wide group per fold batch, one width-one group per round.
    #[must_use]
    pub fn mask_groups(&self) -> Vec<MaskGroupShape> {
        let mut groups = Vec::with_capacity(2 * self.n_rounds() + 1);
        groups.push(MaskGroupShape {
            shape: self.sumcheck_mask,
            width: self.round_folding_factor(0),
        });
        for round in 0..self.n_rounds() {
            groups.push(MaskGroupShape {
                shape: self.switch_masks[round],
                width: 1,
            });
            groups.push(MaskGroupShape {
                shape: self.sumcheck_mask,
                width: self.round_folding_factor(round + 1),
            });
        }
        groups
    }
}

fn source_message_and_domain_shapes<EF, F, Challenger>(
    inner: &WhirConfig<EF, F, Challenger>,
) -> Vec<(usize, usize)>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let mut shapes = inner
        .round_parameters
        .iter()
        .map(|round| {
            (
                1 << round.num_variables,
                round.domain_size >> round.folding_factor,
            )
        })
        .collect::<Vec<_>>();
    let final_round = inner.final_round_config();
    shapes.push((
        1 << final_round.num_variables,
        final_round.domain_size >> final_round.folding_factor,
    ));
    shapes
}

fn unique_decoding_source_query_count(
    message_len: usize,
    domain_size: usize,
    protocol_security_level: usize,
) -> Option<usize> {
    let slack = domain_size.checked_sub(message_len)?;
    (1..slack).find(|&query_count| {
        SourceCodeShape {
            message_len,
            randomness_len: query_count,
            domain_size,
        }
        .query_security_bits()
            >= protocol_security_level as f64
    })
}

fn ceil_nonnegative_gap(gap: f64) -> usize {
    libm::ceil(0_f64.max(gap)) as usize
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::extension::BinomialExtensionField;

    use super::*;
    use crate::parameters::{FoldingFactor, SecurityAssumption};

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    /// Small ZK parameters: short masks, few spot checks.
    fn zk_params() -> ZkParameters {
        ZkParameters {
            ell_zk: 4,
            mask_log_inv_rate: 1,
        }
    }

    fn params() -> ProtocolParameters {
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        }
    }

    #[test]
    fn config_derives_budgets_and_mask_shapes() {
        let config = ZkWhirConfig::<EF, F, MyChallenger>::new(16, params(), zk_params()).unwrap();

        // One budget per committed oracle.
        assert_eq!(config.oracle_randomness.len(), config.n_rounds() + 1);
        // The last oracle absorbs the final spot checks.
        assert_eq!(
            config.oracle_randomness[config.n_rounds()],
            config.final_queries
        );
        // One code-switch mask per intermediate round.
        assert_eq!(config.switch_masks.len(), config.n_rounds());
        for (j, mask) in config.switch_masks.iter().enumerate() {
            assert_eq!(
                mask.message_len,
                config.oracle_randomness[j] + config.round_parameters[j].ood_samples
            );
        }
        // Mask oracle count: sumcheck masks plus code-switch masks.
        // Expected flat mask count: one per sumcheck round, one per
        // code-switching round.
        let expected_sumcheck_masks: usize = (0..=config.n_rounds())
            .map(|i| config.round_folding_factor(i))
            .sum();
        // Groups tile the flat mask list exactly.
        let group_total: usize = config.mask_groups().iter().map(|g| g.width).sum();
        assert_eq!(group_total, expected_sumcheck_masks + config.n_rounds());
    }

    #[test]
    fn config_rejects_short_sumcheck_mask() {
        let zk = ZkParameters {
            ell_zk: 2,
            ..zk_params()
        };
        let err = ZkWhirConfig::<EF, F, MyChallenger>::new(16, params(), zk).unwrap_err();
        assert!(matches!(
            err,
            ZkConfigError::MaskLengthTooSmall { ell_zk: 2 }
        ));
    }

    #[test]
    fn config_rejects_rate_one_mask_code() {
        // A rate-one mask code lacks the distance its spot checks rely on,
        // so the configuration is rejected.
        let zk = ZkParameters {
            mask_log_inv_rate: 0,
            ..zk_params()
        };
        let err = ZkWhirConfig::<EF, F, MyChallenger>::new(16, params(), zk).unwrap_err();
        assert!(matches!(err, ZkConfigError::MaskRateTooHigh));
    }

    #[test]
    fn config_rejects_mask_domain_past_two_adicity() {
        // BabyBear's quartic extension has two-adicity 29 (27 + 2).
        //
        // A large mask_log_inv_rate pushes the mask code domain past that
        // subgroup, so the configuration is rejected.
        let zk = ZkParameters {
            mask_log_inv_rate: 26,
            ..zk_params()
        };
        let err = ZkWhirConfig::<EF, F, MyChallenger>::new(16, params(), zk).unwrap_err();
        let ZkConfigError::MaskDomainExceedsTwoAdicity {
            log_domain_size,
            two_adicity,
        } = err
        else {
            panic!("expected MaskDomainExceedsTwoAdicity, got {err:?}");
        };
        assert_eq!((log_domain_size, two_adicity), (32, 29));
    }

    #[test]
    fn mask_code_shape_rounds_domain_to_power_of_two() {
        let shape = MaskCodeShape::new(5, 3, 1);
        // (5 + 3).next_power_of_two() << 1 = 16.
        assert_eq!(shape.domain_size, 16);
    }
}
