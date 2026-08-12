//! Construction-level masking and leakage correspondence for compact CFW/WHIR.
//!
//! This owner follows the masks that production actually samples. It separates
//! message masks, randomized encodings, fresh base-case mirrors, and derived
//! linear images; proves the conditional rank of every affine verifier view;
//! and reconciles the commitment and opening topology with the checked
//! transcript chronology. The construction theorem is interactive. Canonical
//! emitted multiproof regions are mapped by the separate byte-correspondence
//! owner, while root/frontier programming and every compiled or QROM
//! zero-knowledge claim remain typed refusals rather than being inferred here.

use num_bigint::BigUint;
use num_traits::One;
use p3_field::PrimeCharacteristicRing;

use super::cfw_reduction::CfwReductionCatalog;
use super::lifecycle::PackingQuerySamplingLifecycle;
use super::transcript_chronology::{
    PackingTranscriptChronology, TranscriptEpoch, VerifierMove, VerifierMoveRole,
};
use super::{
    CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS, MaskCommittedEncodingSource,
    MaskGroupRole, MaskGroupStaticLedger, PRIVATE_LEAF_SALT_BYTE_LENGTH, QUINTIC_EXTENSION_DEGREE,
    SUMCHECK_MASK_MESSAGE_LENGTH, WHIR_FOLD_BATCH_COUNT, WHIR_ROUND_COUNT, WhirStaticLedger,
    checked_add, checked_product,
};
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactChallengeField,
};
use crate::bgv::proof_suite::zero_knowledge::construction_masking_matrix_rank;
use crate::foundation::{
    DECLARED_ADVERSARIAL_QUERY_BUDGET, MaskGeneratorHonestAbortEvent,
    MaskGeneratorHybridAssumption, MaskGeneratorHybridHop, MaskGeneratorHybridLoss,
    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT, action_root_expansion_summary,
    deployed_mask_generator_hybrid, deployed_private_stream_hybrid, quantum_mask_generator_hybrid,
    quantum_private_stream_hybrid,
};

const PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH: u32 = 8;
const ACTION_ROOT_BIT_LENGTH: u32 = 512;
const PRIVATE_LEAF_SALT_BIT_LENGTH: u64 = PRIVATE_LEAF_SALT_BYTE_LENGTH * 8;
const CFW_TERMINAL_VALUE_COUNT: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequiredViewFamily {
    Source,
    CarriedMask,
    Mirror,
    CodeSwitch,
    Fold,
    Quotient,
    Sumcheck,
    ExplicitPoint,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewCoverageMechanism {
    RandomizedSourceEncoding,
    RandomizedCarriedMaskEncoding,
    FreshCoordinateOneTimePad,
    DerivedFromFoldedSourceRandomness,
    DeterministicLinearImageOfCheckedSource,
    PreChallengeSourceWithMaskedCrossEpochOpening,
    ChallengeIndependentConstantMinor,
    TwoMaskCorrectionRelation,
    CfwTerminalAndWhirBaseCase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RequiredViewCoverageRow {
    family: RequiredViewFamily,
    mechanism: ViewCoverageMechanism,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionalAffineViewKind {
    CrossEpochDisclosures,
    CfwOuterTranscript,
    CfwTerminalValues,
    WhirSumcheckTranscript {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    SourceQueries {
        epoch: TranscriptEpoch,
        source_epoch_ordinal: u8,
    },
    CarriedMaskQueries {
        epoch: TranscriptEpoch,
        role: MaskGroupRole,
    },
    FreshSourceReveal {
        epoch: TranscriptEpoch,
    },
    FreshMaskReveal {
        epoch: TranscriptEpoch,
        role: MaskGroupRole,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionalAffineRank {
    Exact {
        rank: u64,
        residual_entropy_dimension: u64,
    },
    SharedCrossEpochQueryUnion {
        lane_count: u64,
        encoding_randomness_per_lane: u64,
        preceding_query_count: u64,
        current_query_count: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AffineRankVerification {
    ExactMatrixRank,
    CfwOuterAffineChain {
        round_count: u32,
        coefficients_per_round: u64,
        transmitted_auxiliary_coordinate_count: u64,
        transmitted_outer_evaluation_count: u64,
    },
    CfwTerminalSuffixMinor {
        matrix_count: u64,
        independent_coefficients_per_final_mask: u64,
        excluded_challenge_count: u64,
    },
    SumcheckConstantMinor {
        mask_count: u64,
        coefficients_per_mask: u64,
        selected_minor_size: u64,
        determinant_sign_is_negative: bool,
        determinant_power_of_two_exponent: u32,
    },
    DistinctNonzeroGeneralizedVandermonde {
        lane_count: u64,
        message_length: u64,
        randomness_length: u64,
        domain_size: u64,
        query_count: u64,
    },
    SharedRootGeneralizedVandermondeUnion {
        lane_count: u64,
        message_length: u64,
        randomness_length: u64,
        domain_size: u64,
        preceding_query_count: u64,
        current_query_count: u64,
    },
    CoordinateIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConditionalAffineViewRow {
    kind: ConditionalAffineViewKind,
    private_coordinate_count: u64,
    conditional_rank: ConditionalAffineRank,
    verification: AffineRankVerification,
}

/// Exact outer-mask coefficient map for the production CFW transcript.
///
/// Rows are the auxiliary target followed by every round-polynomial
/// coefficient in chronological order. Columns are every independent outer
/// mask coefficient in mask-major order. The map is derived without calling
/// the production accumulator; the differential test below compares every
/// column with [`crate::bgv::proof_suite::compact_cfw::CompactCfwScalarProverState`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct CfwOuterCoefficientToViewMatrix {
    round_challenges: Vec<CompactChallengeField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CfwOuterViewCoordinate {
    AuxiliaryTarget,
    RoundPolynomialCoefficient {
        round_ordinal: usize,
        coefficient_ordinal: usize,
    },
    OuterEvaluation {
        mask_round_ordinal: usize,
    },
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CfwOuterVerifierView {
    auxiliary_target: CompactChallengeField,
    round_polynomials: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    outer_evaluations: Vec<CompactChallengeField>,
}

impl CfwOuterCoefficientToViewMatrix {
    fn derive(
        round_challenges: Vec<CompactChallengeField>,
    ) -> Result<Self, CompactStaticCatalogError> {
        if round_challenges.is_empty() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(Self { round_challenges })
    }

    fn round_count(&self) -> usize {
        self.round_challenges.len()
    }

    fn row_count(&self) -> Result<usize, CompactStaticCatalogError> {
        self.round_count()
            .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .and_then(|count| count.checked_add(self.round_count()))
            .and_then(|count| count.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
    }

    fn column_count(&self) -> Result<usize, CompactStaticCatalogError> {
        self.round_count()
            .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
    }

    fn coefficient(
        &self,
        view_coordinate: CfwOuterViewCoordinate,
        mask_round_ordinal: usize,
        mask_coefficient_ordinal: usize,
    ) -> Result<CompactChallengeField, CompactStaticCatalogError> {
        if mask_round_ordinal >= self.round_count()
            || mask_coefficient_ordinal >= COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let endpoint_coefficient = if mask_coefficient_ordinal == 0 {
            CompactChallengeField::TWO
        } else {
            CompactChallengeField::ONE
        };
        match view_coordinate {
            CfwOuterViewCoordinate::AuxiliaryTarget => {
                let endpoint_multiplicity = CompactChallengeField::TWO.exp_u64(
                    u64::try_from(self.round_count() - 1)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                );
                Ok(endpoint_multiplicity * endpoint_coefficient)
            }
            CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                round_ordinal,
                coefficient_ordinal,
            } => {
                if round_ordinal >= self.round_count()
                    || coefficient_ordinal >= COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                let suffix_scale = CompactChallengeField::TWO.exp_u64(
                    u64::try_from(self.round_count() - round_ordinal - 1)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                );
                if mask_round_ordinal < round_ordinal {
                    if coefficient_ordinal != 0 {
                        return Ok(CompactChallengeField::ZERO);
                    }
                    return Ok(suffix_scale
                        * self.round_challenges[mask_round_ordinal].exp_u64(
                            u64::try_from(mask_coefficient_ordinal)
                                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                        ));
                }
                if mask_round_ordinal == round_ordinal {
                    return Ok(if mask_coefficient_ordinal == coefficient_ordinal {
                        suffix_scale
                    } else {
                        CompactChallengeField::ZERO
                    });
                }
                if coefficient_ordinal != 0 {
                    return Ok(CompactChallengeField::ZERO);
                }
                let future_scale = CompactChallengeField::TWO.exp_u64(
                    u64::try_from(self.round_count() - round_ordinal - 2)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                );
                Ok(future_scale * endpoint_coefficient)
            }
            CfwOuterViewCoordinate::OuterEvaluation {
                mask_round_ordinal: evaluation_mask_round_ordinal,
            } => {
                if evaluation_mask_round_ordinal >= self.round_count() {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                Ok(if mask_round_ordinal == evaluation_mask_round_ordinal {
                    self.round_challenges[evaluation_mask_round_ordinal].exp_u64(
                        u64::try_from(mask_coefficient_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    )
                } else {
                    CompactChallengeField::ZERO
                })
            }
        }
    }

    #[cfg(test)]
    fn apply(
        &self,
        outer_masks: &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]],
    ) -> Result<CfwOuterVerifierView, CompactStaticCatalogError> {
        if outer_masks.len() != self.round_count() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let evaluate_row = |view_coordinate| -> Result<CompactChallengeField, _> {
            let mut value = CompactChallengeField::ZERO;
            for (mask_round_ordinal, mask) in outer_masks.iter().enumerate() {
                for (mask_coefficient_ordinal, mask_coefficient) in mask.iter().copied().enumerate()
                {
                    value += self.coefficient(
                        view_coordinate,
                        mask_round_ordinal,
                        mask_coefficient_ordinal,
                    )? * mask_coefficient;
                }
            }
            Ok(value)
        };
        let auxiliary_target = evaluate_row(CfwOuterViewCoordinate::AuxiliaryTarget)?;
        let mut round_polynomials = Vec::new();
        round_polynomials
            .try_reserve_exact(self.round_count())
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        for round_ordinal in 0..self.round_count() {
            let mut polynomial =
                [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
            for (coefficient_ordinal, coefficient) in polynomial.iter_mut().enumerate() {
                *coefficient = evaluate_row(CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                    round_ordinal,
                    coefficient_ordinal,
                })?;
            }
            round_polynomials.push(polynomial);
        }
        let mut outer_evaluations = Vec::new();
        outer_evaluations
            .try_reserve_exact(self.round_count())
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        for mask_round_ordinal in 0..self.round_count() {
            outer_evaluations.push(evaluate_row(CfwOuterViewCoordinate::OuterEvaluation {
                mask_round_ordinal,
            })?);
        }
        Ok(CfwOuterVerifierView {
            auxiliary_target,
            round_polynomials,
            outer_evaluations,
        })
    }

    /// Checks the exact rank proof for every challenge vector.
    ///
    /// The seven nonconstant rows of each round expose seven disjoint pivots.
    /// After eliminating those columns, each outer-evaluation row has a unit
    /// pivot on its own mask's constant coordinate. Those `8 * round_count`
    /// pivots cover every column. The auxiliary row is the endpoint sum of
    /// round zero, so it adds no rank.
    fn check_exact_rank_certificate(&self) -> Result<(u64, u64), CompactStaticCatalogError> {
        let expected_row_count = self.row_count()?;
        let expected_column_count = self.column_count()?;
        if expected_row_count
            != expected_column_count
                .checked_add(self.round_count())
                .and_then(|count| count.checked_add(1))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for round_ordinal in 0..self.round_count() {
            let suffix_scale = CompactChallengeField::TWO.exp_u64(
                u64::try_from(self.round_count() - round_ordinal - 1)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            );
            if suffix_scale == CompactChallengeField::ZERO {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            for output_coefficient_ordinal in 1..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                let output = CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                    round_ordinal,
                    coefficient_ordinal: output_coefficient_ordinal,
                };
                for mask_round_ordinal in 0..self.round_count() {
                    for mask_coefficient_ordinal in 0..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                        let expected = if mask_round_ordinal == round_ordinal
                            && mask_coefficient_ordinal == output_coefficient_ordinal
                        {
                            suffix_scale
                        } else {
                            CompactChallengeField::ZERO
                        };
                        if self.coefficient(output, mask_round_ordinal, mask_coefficient_ordinal)?
                            != expected
                        {
                            return Err(CompactStaticCatalogError::InvalidGeometry);
                        }
                    }
                }
            }
            let constant_output = CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                round_ordinal,
                coefficient_ordinal: 0,
            };
            for mask_round_ordinal in 0..self.round_count() {
                if self.coefficient(constant_output, mask_round_ordinal, 0)? != suffix_scale {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
        }
        for evaluation_mask_round_ordinal in 0..self.round_count() {
            let evaluation = CfwOuterViewCoordinate::OuterEvaluation {
                mask_round_ordinal: evaluation_mask_round_ordinal,
            };
            for mask_round_ordinal in 0..self.round_count() {
                let expected_constant_coefficient =
                    if mask_round_ordinal == evaluation_mask_round_ordinal {
                        CompactChallengeField::ONE
                    } else {
                        CompactChallengeField::ZERO
                    };
                if self.coefficient(evaluation, mask_round_ordinal, 0)?
                    != expected_constant_coefficient
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
        }
        for mask_round_ordinal in 0..self.round_count() {
            for mask_coefficient_ordinal in 0..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                let mut endpoint_sum_coefficient = self.coefficient(
                    CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                        round_ordinal: 0,
                        coefficient_ordinal: 0,
                    },
                    mask_round_ordinal,
                    mask_coefficient_ordinal,
                )? * CompactChallengeField::TWO;
                for coefficient_ordinal in 1..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                    endpoint_sum_coefficient += self.coefficient(
                        CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                            round_ordinal: 0,
                            coefficient_ordinal,
                        },
                        mask_round_ordinal,
                        mask_coefficient_ordinal,
                    )?;
                }
                if self.coefficient(
                    CfwOuterViewCoordinate::AuxiliaryTarget,
                    mask_round_ordinal,
                    mask_coefficient_ordinal,
                )? != endpoint_sum_coefficient
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
        }
        let round_count = u64::try_from(self.round_count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let coefficients_per_round = u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        Ok((checked_product(&[round_count, coefficients_per_round])?, 0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DerivedAffineIdentity {
    SumcheckLinearCoefficient {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    FoldedSourceRandomness {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    FoldedSourceValues {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    CodeSwitchMessage {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    FreshSourceQueries {
        epoch: TranscriptEpoch,
    },
    FreshMaskQueries {
        epoch: TranscriptEpoch,
        role: MaskGroupRole,
    },
    CrossEpochCorrection,
    PreChallengeQuotientSource,
    ExplicitPointOpening,
    TerminalSourceCovector {
        epoch: TranscriptEpoch,
    },
    TerminalMaskCovectors {
        epoch: TranscriptEpoch,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OriginalRootIdentity {
    CrossEpochShared,
    EpochMask {
        epoch: TranscriptEpoch,
        group_ordinal: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryDependency {
    AdaptiveRoundQuery,
    FinalQueryAfterFreshCommitmentsAndReveals,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreshSourceCounterpart {
    AbsentForIntermediateSource,
    PresentAtBaseCase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceOpeningTopologyRow {
    epoch: TranscriptEpoch,
    source_epoch_ordinal: u8,
    oracle_width: u64,
    domain_size: u64,
    query_count: u64,
    original_root_count: u64,
    original_opening_batch_count: u64,
    fresh_source_counterpart: FreshSourceCounterpart,
    dependency: QueryDependency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaskOpeningTopologyRow {
    epoch: TranscriptEpoch,
    group_ordinal: u8,
    role: MaskGroupRole,
    original_root: OriginalRootIdentity,
    root_ownership: MaskCommittedEncodingSource,
    width: u64,
    domain_size: u64,
    query_count: u64,
    original_opening_batch_count: u64,
    fresh_mirror_root_count: u64,
    fresh_mirror_opening_batch_count: u64,
    dependency: QueryDependency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedCrossEpochRootTopology {
    original_root_count: u64,
    original_opening_batch_count: u64,
    fresh_mirror_root_count: u64,
    fresh_mirror_opening_batch_count: u64,
    width: u64,
    message_length: u64,
    encoding_randomness_length: u64,
    domain_size: u64,
    pre_challenge_query_count: u64,
    main_query_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootClass {
    Source,
    CarriedMask,
    FreshSource,
    FreshMaskMirror,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionRootDisposition {
    VerifierRecomputesCanonicalRootFromValuesSaltsAndFrontier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InteractiveSimulatorRootDisposition {
    AbstractOracleWithoutConcreteRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompiledSimulatorRootDisposition {
    ProgrammingUnproved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootDispositionRow {
    class: RootClass,
    distinct_root_count: u64,
    verifier_opening_batch_count: u64,
    production: ProductionRootDisposition,
    interactive_simulator: InteractiveSimulatorRootDisposition,
    compiled_simulator: CompiledSimulatorRootDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitmentAndOpeningTopology {
    source_root_count: u64,
    distinct_carried_mask_root_count: u64,
    fresh_source_root_count: u64,
    fresh_mask_mirror_root_count: u64,
    total_commitment_count: u64,
    original_query_group_count: u64,
    fresh_counterpart_opening_batch_count: u64,
    total_verifier_opening_batch_count: u64,
    shared_cross_epoch: SharedCrossEpochRootTopology,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DependencyBarrierKind {
    CrossEpochRootBeforeExplicitPoint,
    CfwMaskRootsBeforeInitialRandomness,
    WhirSumcheckRootBeforeCombination {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirCodeSwitchRootBeforeRoundQuery {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    FreshBaseRootsAndClaimBeforeCombination {
        epoch: TranscriptEpoch,
    },
    RevealsBeforeFinalQueries {
        epoch: TranscriptEpoch,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DependencyBarrierRow {
    kind: DependencyBarrierKind,
    verifier_move_ordinal: u32,
    preceding_prover_response_ordinal: u32,
    preceding_commitment_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimulatorInputKind {
    CrossEpochPublicDifference,
    CfwPublicRelationAndVerifierChallenges,
    WhirPublicClaimsAndAbstractOracleQueries { epoch: TranscriptEpoch },
    WhirBaseCaseTargetAndCovectors { epoch: TranscriptEpoch },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SimulatorInputRow {
    kind: SimulatorInputKind,
    public_claim_count: u64,
    query_group_count: u64,
    mask_group_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateRandomnessHybridLedger {
    deployed_mask_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5],
    quantum_mask_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5],
    deployed_raw_stream_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4],
    quantum_raw_stream_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4],
    action_root_expansion: (usize, usize, usize),
    private_extension_element_count: u64,
    private_base_field_output_count: u64,
    committed_leaf_salt_count: u64,
    committed_leaf_salt_byte_count: u64,
    maximum_candidate_draws_per_output: u32,
    action_root_guessing_loss: super::lifecycle::ExactProbability,
    private_sampler_exhaustion_loss: super::lifecycle::ExactProbability,
    private_leaf_salt_collision_loss: super::lifecycle::ExactProbability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaskingPrivacyRefusal {
    MaliciousVerifierZeroKnowledge,
    ResettableVerifierZeroKnowledge,
    FullProofFamilySimulation,
    CompleteCeremonySimulation,
    QromZeroKnowledge,
    FixedShake256RandomOracleJustification,
    EmittedMerkleRootAndFrontierProgramming,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingMaskingLeakageCorrespondence {
    required_view_coverage: Vec<RequiredViewCoverageRow>,
    affine_views: Vec<ConditionalAffineViewRow>,
    derived_affine_identities: Vec<DerivedAffineIdentity>,
    source_opening_rows: Vec<SourceOpeningTopologyRow>,
    mask_opening_rows: Vec<MaskOpeningTopologyRow>,
    commitment_and_opening_topology: CommitmentAndOpeningTopology,
    dependency_barriers: Vec<DependencyBarrierRow>,
    simulator_inputs: Vec<SimulatorInputRow>,
    root_dispositions: Vec<RootDispositionRow>,
    private_randomness_hybrid: PrivateRandomnessHybridLedger,
    privacy_refusals: Vec<MaskingPrivacyRefusal>,
}

impl PackingMaskingLeakageCorrespondence {
    pub(super) fn derive(
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        chronology: &PackingTranscriptChronology,
        query_sampling: &PackingQuerySamplingLifecycle,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let required_view_coverage = required_view_coverage();
        let affine_views = derive_affine_views(pre_challenge_whir, main_whir, cfw_reduction)?;
        let derived_affine_identities = derive_affine_identities(pre_challenge_whir, main_whir)?;
        let source_opening_rows = derive_source_opening_rows(pre_challenge_whir, main_whir)?;
        let mask_opening_rows = derive_mask_opening_rows(pre_challenge_whir, main_whir)?;
        let commitment_and_opening_topology = derive_commitment_and_opening_topology(
            pre_challenge_whir,
            main_whir,
            chronology,
            query_sampling,
            &source_opening_rows,
            &mask_opening_rows,
        )?;
        let dependency_barriers = derive_dependency_barriers(chronology)?;
        let simulator_inputs = derive_simulator_inputs(pre_challenge_whir, main_whir)?;
        let root_dispositions = derive_root_dispositions(commitment_and_opening_topology);
        let private_randomness_hybrid =
            PrivateRandomnessHybridLedger::derive(pre_challenge_whir, main_whir)?;
        let privacy_refusals = privacy_refusals();

        let correspondence = Self {
            required_view_coverage,
            affine_views,
            derived_affine_identities,
            source_opening_rows,
            mask_opening_rows,
            commitment_and_opening_topology,
            dependency_barriers,
            simulator_inputs,
            root_dispositions,
            private_randomness_hybrid,
            privacy_refusals,
        };
        correspondence.check(
            pre_challenge_whir,
            main_whir,
            chronology,
            query_sampling,
            cfw_reduction,
        )?;
        Ok(correspondence)
    }

    fn check(
        &self,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        chronology: &PackingTranscriptChronology,
        query_sampling: &PackingQuerySamplingLifecycle,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        check_cross_epoch_disclosure_rank()?;
        check_cfw_rank_geometry(cfw_reduction)?;
        check_every_sumcheck_constant_minor(pre_challenge_whir, main_whir)?;
        check_randomness_partition(pre_challenge_whir, main_whir, cfw_reduction)?;

        let expected_source_opening_rows =
            derive_source_opening_rows(pre_challenge_whir, main_whir)?;
        let expected_mask_opening_rows = derive_mask_opening_rows(pre_challenge_whir, main_whir)?;
        let expected_topology = derive_commitment_and_opening_topology(
            pre_challenge_whir,
            main_whir,
            chronology,
            query_sampling,
            &expected_source_opening_rows,
            &expected_mask_opening_rows,
        )?;
        let expected_root_dispositions = derive_root_dispositions(expected_topology);
        if self.required_view_coverage != required_view_coverage()
            || self.affine_views
                != derive_affine_views(pre_challenge_whir, main_whir, cfw_reduction)?
            || self.derived_affine_identities
                != derive_affine_identities(pre_challenge_whir, main_whir)?
            || self.source_opening_rows != expected_source_opening_rows
            || self.mask_opening_rows != expected_mask_opening_rows
            || self.commitment_and_opening_topology != expected_topology
            || self.dependency_barriers != derive_dependency_barriers(chronology)?
            || self.simulator_inputs != derive_simulator_inputs(pre_challenge_whir, main_whir)?
            || self.root_dispositions != expected_root_dispositions
            || self.private_randomness_hybrid
                != PrivateRandomnessHybridLedger::derive(pre_challenge_whir, main_whir)?
            || self.privacy_refusals != privacy_refusals()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        self.private_randomness_hybrid.check()?;
        Ok(())
    }
}

fn required_view_coverage() -> Vec<RequiredViewCoverageRow> {
    vec![
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Source,
            mechanism: ViewCoverageMechanism::RandomizedSourceEncoding,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::CarriedMask,
            mechanism: ViewCoverageMechanism::RandomizedCarriedMaskEncoding,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Mirror,
            mechanism: ViewCoverageMechanism::FreshCoordinateOneTimePad,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::CodeSwitch,
            mechanism: ViewCoverageMechanism::DerivedFromFoldedSourceRandomness,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Fold,
            mechanism: ViewCoverageMechanism::DeterministicLinearImageOfCheckedSource,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Quotient,
            mechanism: ViewCoverageMechanism::PreChallengeSourceWithMaskedCrossEpochOpening,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Sumcheck,
            mechanism: ViewCoverageMechanism::ChallengeIndependentConstantMinor,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::ExplicitPoint,
            mechanism: ViewCoverageMechanism::TwoMaskCorrectionRelation,
        },
        RequiredViewCoverageRow {
            family: RequiredViewFamily::Terminal,
            mechanism: ViewCoverageMechanism::CfwTerminalAndWhirBaseCase,
        },
    ]
}

fn derive_affine_views(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<Vec<ConditionalAffineViewRow>, CompactStaticCatalogError> {
    let cfw_inner_private_coordinate_count = checked_product(&[
        cfw_reduction.inner_mask_count(),
        cfw_reduction
            .inner_mask_message_length()
            .checked_sub(2)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
    ])?;
    let cfw_outer_private_coordinate_count = checked_product(&[
        cfw_reduction.outer_mask_count(),
        cfw_reduction.outer_mask_message_length(),
    ])?;
    let mut rows = vec![
        ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::CrossEpochDisclosures,
            private_coordinate_count: 2,
            conditional_rank: ConditionalAffineRank::Exact {
                rank: 2,
                residual_entropy_dimension: 0,
            },
            verification: AffineRankVerification::ExactMatrixRank,
        },
        ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::CfwOuterTranscript,
            private_coordinate_count: cfw_outer_private_coordinate_count,
            conditional_rank: ConditionalAffineRank::Exact {
                rank: cfw_outer_private_coordinate_count,
                residual_entropy_dimension: 0,
            },
            verification: AffineRankVerification::CfwOuterAffineChain {
                round_count: cfw_reduction.sumcheck_round_count(),
                coefficients_per_round: cfw_reduction.outer_mask_message_length(),
                transmitted_auxiliary_coordinate_count: 1,
                transmitted_outer_evaluation_count: cfw_reduction.outer_mask_count(),
            },
        },
        ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::CfwTerminalValues,
            private_coordinate_count: cfw_inner_private_coordinate_count,
            conditional_rank: ConditionalAffineRank::Exact {
                rank: CFW_TERMINAL_VALUE_COUNT,
                residual_entropy_dimension: cfw_inner_private_coordinate_count
                    .checked_sub(CFW_TERMINAL_VALUE_COUNT)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            },
            verification: AffineRankVerification::CfwTerminalSuffixMinor {
                matrix_count: CFW_TERMINAL_VALUE_COUNT,
                independent_coefficients_per_final_mask: 2,
                excluded_challenge_count: cfw_reduction.last_round_excluded_element_count(),
            },
        },
    ];
    for (epoch, whir) in [
        (TranscriptEpoch::PreChallenge, pre_challenge_whir),
        (TranscriptEpoch::Main, main_whir),
    ] {
        append_whir_affine_views(&mut rows, epoch, whir)?;
    }
    Ok(rows)
}

fn append_whir_affine_views(
    rows: &mut Vec<ConditionalAffineViewRow>,
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    for group in &whir.internal_mask_groups {
        let MaskGroupRole::WhirSumcheck { batch_ordinal } = group.role else {
            continue;
        };
        let private_coordinate_count = checked_product(&[group.width, group.message_length])?;
        let rank = group
            .width
            .checked_mul(2)
            .and_then(|rank| rank.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let determinant_power_of_two_exponent = u32::try_from(
            group
                .width
                .checked_mul(group.width.saturating_sub(1))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
        )
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        rows.push(ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::WhirSumcheckTranscript {
                epoch,
                batch_ordinal,
            },
            private_coordinate_count,
            conditional_rank: ConditionalAffineRank::Exact {
                rank,
                residual_entropy_dimension: private_coordinate_count
                    .checked_sub(rank)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            },
            verification: AffineRankVerification::SumcheckConstantMinor {
                mask_count: group.width,
                coefficients_per_mask: group.message_length,
                selected_minor_size: rank,
                determinant_sign_is_negative: group.width % 2 == 1,
                determinant_power_of_two_exponent,
            },
        });
    }

    for source_epoch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
        let lane_count = whir.oracle_widths[source_epoch_ordinal];
        let query_count = whir.query_counts[source_epoch_ordinal];
        let private_coordinate_count = checked_product(&[lane_count, query_count])?;
        rows.push(ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::SourceQueries {
                epoch,
                source_epoch_ordinal: u8::try_from(source_epoch_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            private_coordinate_count,
            conditional_rank: ConditionalAffineRank::Exact {
                rank: private_coordinate_count,
                residual_entropy_dimension: 0,
            },
            verification: AffineRankVerification::DistinctNonzeroGeneralizedVandermonde {
                lane_count,
                message_length: whir.source_message_lengths[source_epoch_ordinal],
                randomness_length: query_count,
                domain_size: whir.oracle_heights[source_epoch_ordinal],
                query_count,
            },
        });
    }

    for group in whir.mask_groups_in_commitment_order() {
        let private_coordinate_count = checked_product(&[group.width, group.randomness_length])?;
        let (conditional_rank, verification) = if group.role == MaskGroupRole::CrossEpochOpening {
            match epoch {
                TranscriptEpoch::PreChallenge => {
                    let rank = checked_product(&[group.width, whir.mask_query_count])?;
                    (
                        ConditionalAffineRank::Exact {
                            rank,
                            residual_entropy_dimension: private_coordinate_count
                                .checked_sub(rank)
                                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                        },
                        AffineRankVerification::DistinctNonzeroGeneralizedVandermonde {
                            lane_count: group.width,
                            message_length: group.message_length,
                            randomness_length: group.randomness_length,
                            domain_size: group.domain_size,
                            query_count: whir.mask_query_count,
                        },
                    )
                }
                TranscriptEpoch::Main => (
                    ConditionalAffineRank::SharedCrossEpochQueryUnion {
                        lane_count: group.width,
                        encoding_randomness_per_lane: group.randomness_length,
                        preceding_query_count: group
                            .randomness_length
                            .checked_sub(whir.mask_query_count)
                            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                        current_query_count: whir.mask_query_count,
                    },
                    AffineRankVerification::SharedRootGeneralizedVandermondeUnion {
                        lane_count: group.width,
                        message_length: group.message_length,
                        randomness_length: group.randomness_length,
                        domain_size: group.domain_size,
                        preceding_query_count: group
                            .randomness_length
                            .checked_sub(whir.mask_query_count)
                            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                        current_query_count: whir.mask_query_count,
                    },
                ),
            }
        } else {
            let rank = checked_product(&[group.width, whir.mask_query_count])?;
            (
                ConditionalAffineRank::Exact {
                    rank,
                    residual_entropy_dimension: private_coordinate_count
                        .checked_sub(rank)
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                },
                AffineRankVerification::DistinctNonzeroGeneralizedVandermonde {
                    lane_count: group.width,
                    message_length: group.message_length,
                    randomness_length: group.randomness_length,
                    domain_size: group.domain_size,
                    query_count: whir.mask_query_count,
                },
            )
        };
        rows.push(ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::CarriedMaskQueries {
                epoch,
                role: group.role,
            },
            private_coordinate_count,
            conditional_rank,
            verification,
        });
    }

    let fresh_source_private_coordinate_count = checked_add(
        whir.fresh_source_message_randomness_element_count,
        whir.fresh_source_encoding_randomness_element_count,
    )?;
    rows.push(ConditionalAffineViewRow {
        kind: ConditionalAffineViewKind::FreshSourceReveal { epoch },
        private_coordinate_count: fresh_source_private_coordinate_count,
        conditional_rank: ConditionalAffineRank::Exact {
            rank: fresh_source_private_coordinate_count,
            residual_entropy_dimension: 0,
        },
        verification: AffineRankVerification::CoordinateIdentity,
    });
    for group in whir.mask_groups_in_commitment_order() {
        let fresh_private_coordinate_count = checked_product(&[
            group.width,
            checked_add(group.message_length, group.randomness_length)?,
        ])?;
        rows.push(ConditionalAffineViewRow {
            kind: ConditionalAffineViewKind::FreshMaskReveal {
                epoch,
                role: group.role,
            },
            private_coordinate_count: fresh_private_coordinate_count,
            conditional_rank: ConditionalAffineRank::Exact {
                rank: fresh_private_coordinate_count,
                residual_entropy_dimension: 0,
            },
            verification: AffineRankVerification::CoordinateIdentity,
        });
    }
    Ok(())
}

fn derive_affine_identities(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<DerivedAffineIdentity>, CompactStaticCatalogError> {
    let mut identities = vec![
        DerivedAffineIdentity::CrossEpochCorrection,
        DerivedAffineIdentity::PreChallengeQuotientSource,
        DerivedAffineIdentity::ExplicitPointOpening,
    ];
    for (epoch, whir) in [
        (TranscriptEpoch::PreChallenge, pre_challenge_whir),
        (TranscriptEpoch::Main, main_whir),
    ] {
        for batch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
            identities.push(DerivedAffineIdentity::SumcheckLinearCoefficient {
                epoch,
                batch_ordinal: u8::try_from(batch_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            });
        }
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            let round_ordinal = u8::try_from(round_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            identities.push(DerivedAffineIdentity::FoldedSourceRandomness {
                epoch,
                round_ordinal,
            });
            identities.push(DerivedAffineIdentity::FoldedSourceValues {
                epoch,
                round_ordinal,
            });
            identities.push(DerivedAffineIdentity::CodeSwitchMessage {
                epoch,
                round_ordinal,
            });
        }
        identities.push(DerivedAffineIdentity::FreshSourceQueries { epoch });
        for group in whir.mask_groups_in_commitment_order() {
            identities.push(DerivedAffineIdentity::FreshMaskQueries {
                epoch,
                role: group.role,
            });
        }
        identities.push(DerivedAffineIdentity::TerminalSourceCovector { epoch });
        identities.push(DerivedAffineIdentity::TerminalMaskCovectors { epoch });
    }
    Ok(identities)
}

fn derive_source_opening_rows(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<SourceOpeningTopologyRow>, CompactStaticCatalogError> {
    let mut rows = Vec::new();
    for (epoch, whir) in [
        (TranscriptEpoch::PreChallenge, pre_challenge_whir),
        (TranscriptEpoch::Main, main_whir),
    ] {
        for source_epoch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
            let is_terminal = source_epoch_ordinal == WHIR_ROUND_COUNT;
            rows.push(SourceOpeningTopologyRow {
                epoch,
                source_epoch_ordinal: u8::try_from(source_epoch_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                oracle_width: whir.oracle_widths[source_epoch_ordinal],
                domain_size: whir.oracle_heights[source_epoch_ordinal],
                query_count: whir.query_counts[source_epoch_ordinal],
                original_root_count: 1,
                original_opening_batch_count: 1,
                fresh_source_counterpart: if is_terminal {
                    FreshSourceCounterpart::PresentAtBaseCase
                } else {
                    FreshSourceCounterpart::AbsentForIntermediateSource
                },
                dependency: if is_terminal {
                    QueryDependency::FinalQueryAfterFreshCommitmentsAndReveals
                } else {
                    QueryDependency::AdaptiveRoundQuery
                },
            });
        }
    }
    Ok(rows)
}

fn derive_mask_opening_rows(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<MaskOpeningTopologyRow>, CompactStaticCatalogError> {
    let mut rows = Vec::new();
    for (epoch, whir) in [
        (TranscriptEpoch::PreChallenge, pre_challenge_whir),
        (TranscriptEpoch::Main, main_whir),
    ] {
        for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
            let group_ordinal = u8::try_from(group_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            rows.push(MaskOpeningTopologyRow {
                epoch,
                group_ordinal,
                role: group.role,
                original_root: if group.role == MaskGroupRole::CrossEpochOpening {
                    OriginalRootIdentity::CrossEpochShared
                } else {
                    OriginalRootIdentity::EpochMask {
                        epoch,
                        group_ordinal,
                    }
                },
                root_ownership: group.committed_encoding_source,
                width: group.width,
                domain_size: group.domain_size,
                query_count: whir.mask_query_count,
                original_opening_batch_count: 1,
                fresh_mirror_root_count: 1,
                fresh_mirror_opening_batch_count: 1,
                dependency: QueryDependency::FinalQueryAfterFreshCommitmentsAndReveals,
            });
        }
    }
    Ok(rows)
}

fn derive_commitment_and_opening_topology(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
    chronology: &PackingTranscriptChronology,
    query_sampling: &PackingQuerySamplingLifecycle,
    source_opening_rows: &[SourceOpeningTopologyRow],
    mask_opening_rows: &[MaskOpeningTopologyRow],
) -> Result<CommitmentAndOpeningTopology, CompactStaticCatalogError> {
    let source_root_count = source_opening_rows.iter().try_fold(0_u64, |count, row| {
        checked_add(count, row.original_root_count)
    })?;
    let distinct_carried_mask_root_count = u64::try_from(
        mask_opening_rows
            .iter()
            .filter(|row| row.root_ownership.is_owned_by_this_epoch())
            .count(),
    )
    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let fresh_source_root_count = u64::try_from(
        source_opening_rows
            .iter()
            .filter(|row| row.fresh_source_counterpart == FreshSourceCounterpart::PresentAtBaseCase)
            .count(),
    )
    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let fresh_mask_mirror_root_count = u64::try_from(mask_opening_rows.len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let total_commitment_count = [
        source_root_count,
        distinct_carried_mask_root_count,
        fresh_source_root_count,
        fresh_mask_mirror_root_count,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;
    let source_opening_batch_count = source_opening_rows.iter().try_fold(0_u64, |count, row| {
        checked_add(count, row.original_opening_batch_count)
    })?;
    let original_query_group_count = checked_add(
        source_opening_batch_count,
        u64::try_from(mask_opening_rows.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )?;
    let fresh_counterpart_opening_batch_count =
        checked_add(fresh_source_root_count, fresh_mask_mirror_root_count)?;
    let total_verifier_opening_batch_count = checked_add(
        original_query_group_count,
        fresh_counterpart_opening_batch_count,
    )?;

    let pre_cross = unique_mask_group(pre_challenge_whir, MaskGroupRole::CrossEpochOpening)?;
    let main_cross = unique_mask_group(main_whir, MaskGroupRole::CrossEpochOpening)?;
    let shared_cross_epoch = SharedCrossEpochRootTopology {
        original_root_count: 1,
        original_opening_batch_count: 2,
        fresh_mirror_root_count: 2,
        fresh_mirror_opening_batch_count: 2,
        width: pre_cross.width,
        message_length: pre_cross.message_length,
        encoding_randomness_length: pre_cross.randomness_length,
        domain_size: pre_cross.domain_size,
        pre_challenge_query_count: pre_challenge_whir.mask_query_count,
        main_query_count: main_whir.mask_query_count,
    };
    if pre_cross.committed_encoding_source != MaskCommittedEncodingSource::OwnedByThisEpoch
        || main_cross.committed_encoding_source
            != MaskCommittedEncodingSource::ReusedFromPreChallenge
        || (
            pre_cross.width,
            pre_cross.message_length,
            pre_cross.randomness_length,
            pre_cross.domain_size,
        ) != (
            main_cross.width,
            main_cross.message_length,
            main_cross.randomness_length,
            main_cross.domain_size,
        )
        || shared_cross_epoch.encoding_randomness_length
            != checked_add(
                shared_cross_epoch.pre_challenge_query_count,
                shared_cross_epoch.main_query_count,
            )?
        || total_commitment_count != chronology.commitment_count()
        || original_query_group_count != query_sampling.query_group_count
        || source_opening_rows.len() != 8
        || source_opening_rows.iter().any(|row| {
            row.oracle_width == 0
                || row.domain_size == 0
                || !row.domain_size.is_power_of_two()
                || row.query_count == 0
                || row.query_count >= row.domain_size
        })
        || source_root_count != 8
        || distinct_carried_mask_root_count != 17
        || fresh_source_root_count != 2
        || fresh_mask_mirror_root_count != 18
        || total_commitment_count != 45
        || original_query_group_count != 26
        || fresh_counterpart_opening_batch_count != 20
        || total_verifier_opening_batch_count != 46
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    Ok(CommitmentAndOpeningTopology {
        source_root_count,
        distinct_carried_mask_root_count,
        fresh_source_root_count,
        fresh_mask_mirror_root_count,
        total_commitment_count,
        original_query_group_count,
        fresh_counterpart_opening_batch_count,
        total_verifier_opening_batch_count,
        shared_cross_epoch,
    })
}

fn derive_dependency_barriers(
    chronology: &PackingTranscriptChronology,
) -> Result<Vec<DependencyBarrierRow>, CompactStaticCatalogError> {
    let mut rows = Vec::new();
    rows.push(dependency_barrier(
        chronology,
        DependencyBarrierKind::CrossEpochRootBeforeExplicitPoint,
        |role| matches!(role, VerifierMoveRole::CrossEpochPoint),
    )?);
    rows.push(dependency_barrier(
        chronology,
        DependencyBarrierKind::CfwMaskRootsBeforeInitialRandomness,
        |role| matches!(role, VerifierMoveRole::CfwInitialRandomness),
    )?);
    for epoch in [TranscriptEpoch::PreChallenge, TranscriptEpoch::Main] {
        rows.push(sumcheck_dependency_barrier(chronology, epoch, 0)?);
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            let round_ordinal = u8::try_from(round_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            rows.push(dependency_barrier(
                chronology,
                DependencyBarrierKind::WhirCodeSwitchRootBeforeRoundQuery {
                    epoch,
                    round_ordinal,
                },
                |role| {
                    matches!(
                        role,
                        VerifierMoveRole::WhirRoundQueryAndCombination {
                            epoch: role_epoch,
                            round_ordinal: role_round,
                        } if *role_epoch == epoch && *role_round == round_ordinal
                    )
                },
            )?);
            rows.push(sumcheck_dependency_barrier(
                chronology,
                epoch,
                round_ordinal
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )?);
        }
        rows.push(dependency_barrier(
            chronology,
            DependencyBarrierKind::FreshBaseRootsAndClaimBeforeCombination { epoch },
            |role| {
                matches!(
                    role,
                    VerifierMoveRole::WhirBaseCombination { epoch: role_epoch }
                        if *role_epoch == epoch
                )
            },
        )?);
        rows.push(dependency_barrier(
            chronology,
            DependencyBarrierKind::RevealsBeforeFinalQueries { epoch },
            |role| {
                matches!(
                    role,
                    VerifierMoveRole::WhirFinalQueries { epoch: role_epoch }
                        if *role_epoch == epoch
                )
            },
        )?);
    }
    let cross_barrier = rows
        .first()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let final_barrier = rows
        .last()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if cross_barrier.preceding_commitment_count != 5
        || final_barrier.preceding_commitment_count != chronology.commitment_count()
        || rows
            .windows(2)
            .any(|pair| pair[0].verifier_move_ordinal > pair[1].verifier_move_ordinal)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(rows)
}

fn sumcheck_dependency_barrier(
    chronology: &PackingTranscriptChronology,
    epoch: TranscriptEpoch,
    batch_ordinal: u8,
) -> Result<DependencyBarrierRow, CompactStaticCatalogError> {
    dependency_barrier(
        chronology,
        DependencyBarrierKind::WhirSumcheckRootBeforeCombination {
            epoch,
            batch_ordinal,
        },
        |role| {
            matches!(
                role,
                VerifierMoveRole::WhirMaskedSumcheckCombination {
                    epoch: role_epoch,
                    batch_ordinal: role_batch,
                } if *role_epoch == epoch && *role_batch == batch_ordinal
            )
        },
    )
}

fn dependency_barrier(
    chronology: &PackingTranscriptChronology,
    kind: DependencyBarrierKind,
    role_matches: impl Fn(&VerifierMoveRole) -> bool,
) -> Result<DependencyBarrierRow, CompactStaticCatalogError> {
    let verifier_move = unique_verifier_move(chronology, role_matches)?;
    Ok(DependencyBarrierRow {
        kind,
        verifier_move_ordinal: verifier_move.ordinal(),
        preceding_prover_response_ordinal: verifier_move.preceding_prover_response_ordinal(),
        preceding_commitment_count: verifier_move.preceding_commitment_count(),
    })
}

fn unique_verifier_move(
    chronology: &PackingTranscriptChronology,
    role_matches: impl Fn(&VerifierMoveRole) -> bool,
) -> Result<&VerifierMove, CompactStaticCatalogError> {
    let mut matches = chronology
        .verifier_moves()
        .iter()
        .filter(|move_record| move_record.roles().iter().any(&role_matches));
    let verifier_move = matches
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if matches.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(verifier_move)
}

fn derive_simulator_inputs(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<SimulatorInputRow>, CompactStaticCatalogError> {
    Ok(vec![
        SimulatorInputRow {
            kind: SimulatorInputKind::CrossEpochPublicDifference,
            public_claim_count: 1,
            query_group_count: 0,
            mask_group_count: 1,
        },
        SimulatorInputRow {
            kind: SimulatorInputKind::CfwPublicRelationAndVerifierChallenges,
            public_claim_count: main_whir.external_generalized_relation_claim_count,
            query_group_count: 0,
            mask_group_count: 2,
        },
        whir_simulator_input(TranscriptEpoch::PreChallenge, pre_challenge_whir)?,
        SimulatorInputRow {
            kind: SimulatorInputKind::WhirBaseCaseTargetAndCovectors {
                epoch: TranscriptEpoch::PreChallenge,
            },
            public_claim_count: pre_challenge_whir.opening_batching_claim_count,
            query_group_count: pre_challenge_whir.mask_query_union_branch_count,
            mask_group_count: u64::try_from(
                pre_challenge_whir.mask_groups_in_commitment_order().count(),
            )
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
        whir_simulator_input(TranscriptEpoch::Main, main_whir)?,
        SimulatorInputRow {
            kind: SimulatorInputKind::WhirBaseCaseTargetAndCovectors {
                epoch: TranscriptEpoch::Main,
            },
            public_claim_count: main_whir.opening_batching_claim_count,
            query_group_count: main_whir.mask_query_union_branch_count,
            mask_group_count: u64::try_from(main_whir.mask_groups_in_commitment_order().count())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
    ])
}

fn whir_simulator_input(
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<SimulatorInputRow, CompactStaticCatalogError> {
    Ok(SimulatorInputRow {
        kind: SimulatorInputKind::WhirPublicClaimsAndAbstractOracleQueries { epoch },
        public_claim_count: whir.opening_batching_claim_count,
        query_group_count: u64::try_from(WHIR_FOLD_BATCH_COUNT)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        mask_group_count: u64::try_from(whir.mask_groups_in_commitment_order().count())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    })
}

fn derive_root_dispositions(topology: CommitmentAndOpeningTopology) -> Vec<RootDispositionRow> {
    let row = |class, distinct_root_count, verifier_opening_batch_count| RootDispositionRow {
        class,
        distinct_root_count,
        verifier_opening_batch_count,
        production:
            ProductionRootDisposition::VerifierRecomputesCanonicalRootFromValuesSaltsAndFrontier,
        interactive_simulator:
            InteractiveSimulatorRootDisposition::AbstractOracleWithoutConcreteRoot,
        compiled_simulator: CompiledSimulatorRootDisposition::ProgrammingUnproved,
    };
    vec![
        row(
            RootClass::Source,
            topology.source_root_count,
            topology.source_root_count,
        ),
        row(
            RootClass::CarriedMask,
            topology.distinct_carried_mask_root_count,
            topology.fresh_mask_mirror_root_count,
        ),
        row(
            RootClass::FreshSource,
            topology.fresh_source_root_count,
            topology.fresh_source_root_count,
        ),
        row(
            RootClass::FreshMaskMirror,
            topology.fresh_mask_mirror_root_count,
            topology.fresh_mask_mirror_root_count,
        ),
    ]
}

impl PrivateRandomnessHybridLedger {
    fn derive(
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
    ) -> Result<Self, CompactStaticCatalogError> {
        let private_extension_element_count = checked_add(
            pre_challenge_whir.private_extension_randomness_element_count,
            main_whir.private_extension_randomness_element_count,
        )?;
        let private_base_field_output_count =
            checked_product(&[private_extension_element_count, QUINTIC_EXTENSION_DEGREE])?;
        let committed_leaf_salt_count = checked_add(
            pre_challenge_whir.committed_leaf_count,
            main_whir.committed_leaf_count,
        )?;
        let committed_leaf_salt_byte_count =
            checked_product(&[committed_leaf_salt_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?;
        let action_root_guessing_loss = super::lifecycle::ExactProbability::new(
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            BigUint::one() << ACTION_ROOT_BIT_LENGTH,
        )?;
        let candidate_space = BigUint::one()
            << usize::try_from(PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH * 8)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let rejected_candidate_count = &candidate_space % GOLDILOCKS_BASE_FIELD_MODULUS;
        let private_sampler_exhaustion_loss = super::lifecycle::ExactProbability::new(
            BigUint::from(private_base_field_output_count)
                * rejected_candidate_count
                    .pow(SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT),
            candidate_space.pow(SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT),
        )?;
        let collision_pair_count = BigUint::from(committed_leaf_salt_count)
            * BigUint::from(committed_leaf_salt_count.saturating_sub(1))
            / BigUint::from(2_u8);
        let private_leaf_salt_collision_loss = super::lifecycle::ExactProbability::new(
            collision_pair_count,
            BigUint::one()
                << usize::try_from(PRIVATE_LEAF_SALT_BIT_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )?;
        Ok(Self {
            deployed_mask_hybrid: deployed_mask_generator_hybrid(),
            quantum_mask_hybrid: quantum_mask_generator_hybrid(),
            deployed_raw_stream_hybrid: deployed_private_stream_hybrid(),
            quantum_raw_stream_hybrid: quantum_private_stream_hybrid(),
            action_root_expansion: action_root_expansion_summary(),
            private_extension_element_count,
            private_base_field_output_count,
            committed_leaf_salt_count,
            committed_leaf_salt_byte_count,
            maximum_candidate_draws_per_output:
                SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            action_root_guessing_loss,
            private_sampler_exhaustion_loss,
            private_leaf_salt_collision_loss,
        })
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        let expected_hops = [
            MaskGeneratorHybridHop::ActionRootEntropy,
            MaskGeneratorHybridHop::ActionKeyHierarchyReplacement,
            MaskGeneratorHybridHop::BlockStreamReplacement,
            MaskGeneratorHybridHop::FramedInputInjectivity,
            MaskGeneratorHybridHop::RejectionSamplerUniformity,
        ];
        let classical_reductions_match = [
            self.deployed_mask_hybrid[1].1,
            self.deployed_mask_hybrid[2].1,
        ]
        .into_iter()
        .all(|loss| {
            matches!(
                loss,
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
        });
        let quantum_reductions_match =
            [self.quantum_mask_hybrid[1].1, self.quantum_mask_hybrid[2].1]
                .into_iter()
                .all(|loss| {
                    matches!(
                        loss,
                        MaskGeneratorHybridLoss::ComputationalReduction {
                            assumption:
                                MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                            key_bit_length: 512,
                            classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                        }
                    )
                });
        if self.deployed_mask_hybrid != deployed_mask_generator_hybrid()
            || self.quantum_mask_hybrid != quantum_mask_generator_hybrid()
            || self.deployed_raw_stream_hybrid != deployed_private_stream_hybrid()
            || self.quantum_raw_stream_hybrid != quantum_private_stream_hybrid()
            || self.deployed_mask_hybrid.map(|(hop, _)| hop) != expected_hops
            || self.quantum_mask_hybrid.map(|(hop, _)| hop) != expected_hops
            || !matches!(
                self.deployed_mask_hybrid[0].1,
                MaskGeneratorHybridLoss::SecretGuessing {
                    secret_bit_length: ACTION_ROOT_BIT_LENGTH,
                    query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            || !matches!(
                self.quantum_mask_hybrid[0].1,
                MaskGeneratorHybridLoss::QuantumSecretSearch {
                    secret_bit_length: ACTION_ROOT_BIT_LENGTH,
                    query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            || !classical_reductions_match
            || !quantum_reductions_match
            || self.deployed_mask_hybrid[3].1 != MaskGeneratorHybridLoss::Exact
            || self.deployed_mask_hybrid[4].1
                != (MaskGeneratorHybridLoss::ExactGivenHonestAbort {
                    abort_event: MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion,
                })
            || self.action_root_expansion != (64, 192, 64)
            || self.private_extension_element_count == 0
            || self.private_base_field_output_count
                != self.private_extension_element_count * QUINTIC_EXTENSION_DEGREE
            || self.committed_leaf_salt_count == 0
            || self.committed_leaf_salt_byte_count
                != self.committed_leaf_salt_count * PRIVATE_LEAF_SALT_BYTE_LENGTH
            || self.maximum_candidate_draws_per_output != 64
            || !self
                .action_root_guessing_loss
                .is_at_most_inverse_power_of_two(431)
            || !self
                .private_sampler_exhaustion_loss
                .is_at_most_inverse_power_of_two(2_000)
            || !self
                .private_leaf_salt_collision_loss
                .is_at_most_inverse_power_of_two(960)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

fn privacy_refusals() -> Vec<MaskingPrivacyRefusal> {
    vec![
        MaskingPrivacyRefusal::MaliciousVerifierZeroKnowledge,
        MaskingPrivacyRefusal::ResettableVerifierZeroKnowledge,
        MaskingPrivacyRefusal::FullProofFamilySimulation,
        MaskingPrivacyRefusal::CompleteCeremonySimulation,
        MaskingPrivacyRefusal::QromZeroKnowledge,
        MaskingPrivacyRefusal::FixedShake256RandomOracleJustification,
        MaskingPrivacyRefusal::EmittedMerkleRootAndFrontierProgramming,
    ]
}

fn check_cross_epoch_disclosure_rank() -> Result<(), CompactStaticCatalogError> {
    let modulus_minus_one = GOLDILOCKS_BASE_FIELD_MODULUS - 1;
    let matrix = vec![vec![1, 0], vec![0, 1], vec![1, modulus_minus_one]];
    let rank = construction_masking_matrix_rank(&matrix, GOLDILOCKS_BASE_FIELD_MODULUS)
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    if rank != 2 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn check_cfw_rank_geometry(
    cfw_reduction: &CfwReductionCatalog,
) -> Result<(), CompactStaticCatalogError> {
    let round_count = usize::try_from(cfw_reduction.sumcheck_round_count())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let matrix = CfwOuterCoefficientToViewMatrix::derive(
        (0..round_count)
            .map(|round_ordinal| {
                let challenge = u64::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
                    .checked_add(2)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
                Ok(CompactChallengeField::from_u64(challenge))
            })
            .collect::<Result<Vec<_>, CompactStaticCatalogError>>()?,
    )?;
    let (outer_rank, outer_residual_entropy_dimension) = matrix.check_exact_rank_certificate()?;
    let expected_outer_rank = checked_product(&[
        cfw_reduction.outer_mask_count(),
        cfw_reduction.outer_mask_message_length(),
    ])?;
    let expected_outer_residual_entropy_dimension = 0;
    let final_challenge = 2_u64;
    let first_terminal_coefficient = modular_product(
        2,
        modular_difference(
            final_challenge,
            modular_power(final_challenge, 3, GOLDILOCKS_BASE_FIELD_MODULUS),
            GOLDILOCKS_BASE_FIELD_MODULUS,
        ),
        GOLDILOCKS_BASE_FIELD_MODULUS,
    );
    let second_terminal_coefficient = modular_product(
        2,
        modular_difference(
            modular_power(final_challenge, 2, GOLDILOCKS_BASE_FIELD_MODULUS),
            modular_power(final_challenge, 3, GOLDILOCKS_BASE_FIELD_MODULUS),
            GOLDILOCKS_BASE_FIELD_MODULUS,
        ),
        GOLDILOCKS_BASE_FIELD_MODULUS,
    );
    let terminal_matrix = (0..CFW_TERMINAL_VALUE_COUNT)
        .map(|matrix_ordinal| {
            let mut row = vec![
                0_u64;
                usize::try_from(CFW_TERMINAL_VALUE_COUNT * 2)
                    .expect("the fixed terminal matrix width fits usize")
            ];
            let offset = usize::try_from(matrix_ordinal * 2)
                .expect("the fixed terminal matrix offset fits usize");
            row[offset] = first_terminal_coefficient;
            row[offset + 1] = second_terminal_coefficient;
            row
        })
        .collect::<Vec<_>>();
    let terminal_rank =
        construction_masking_matrix_rank(&terminal_matrix, GOLDILOCKS_BASE_FIELD_MODULUS)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    if cfw_reduction.sumcheck_round_count() != 23
        || cfw_reduction.inner_mask_count() != 69
        || cfw_reduction.outer_mask_count() != 23
        || cfw_reduction.inner_mask_message_length() != 4
        || cfw_reduction.outer_mask_message_length() != 8
        || cfw_reduction.last_round_excluded_element_count() != 2
        || outer_rank != expected_outer_rank
        || outer_residual_entropy_dimension != expected_outer_residual_entropy_dimension
        || terminal_rank
            != usize::try_from(CFW_TERMINAL_VALUE_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn check_every_sumcheck_constant_minor(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    for whir in [pre_challenge_whir, main_whir] {
        for group in &whir.internal_mask_groups {
            if !matches!(group.role, MaskGroupRole::WhirSumcheck { .. }) {
                continue;
            }
            if group.message_length != SUMCHECK_MASK_MESSAGE_LENGTH {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            check_sumcheck_constant_minor(group.width)?;
        }
    }
    Ok(())
}

fn check_sumcheck_constant_minor(mask_count: u64) -> Result<(), CompactStaticCatalogError> {
    let mask_count_usize =
        usize::try_from(mask_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    if mask_count_usize == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let challenge_vectors = [
        vec![0_u64; mask_count_usize],
        (0..mask_count)
            .map(|ordinal| ordinal + 1)
            .collect::<Vec<_>>(),
        (0..mask_count)
            .map(|ordinal| 17 + 240 * ordinal)
            .collect::<Vec<_>>(),
    ];
    let expected_rank = usize::try_from(
        mask_count
            .checked_mul(2)
            .and_then(|rank| rank.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let determinant_exponent = mask_count
        .checked_mul(mask_count.saturating_sub(1))
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let determinant_magnitude =
        modular_power(2, determinant_exponent, GOLDILOCKS_BASE_FIELD_MODULUS);
    let expected_determinant = if mask_count % 2 == 1 {
        modular_difference(0, determinant_magnitude, GOLDILOCKS_BASE_FIELD_MODULUS)
    } else {
        determinant_magnitude
    };
    for challenges in challenge_vectors {
        let matrix = sumcheck_masking_matrix(mask_count_usize, &challenges)?;
        let rank = construction_masking_matrix_rank(&matrix, GOLDILOCKS_BASE_FIELD_MODULUS)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let minor = sumcheck_constant_minor(&matrix, mask_count_usize)?;
        if rank != expected_rank
            || modular_determinant(&minor, GOLDILOCKS_BASE_FIELD_MODULUS)? != expected_determinant
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }
    Ok(())
}

fn sumcheck_masking_matrix(
    mask_count: usize,
    challenges: &[u64],
) -> Result<Vec<Vec<u64>>, CompactStaticCatalogError> {
    if mask_count == 0
        || challenges.len() != mask_count
        || challenges
            .iter()
            .any(|challenge| *challenge >= GOLDILOCKS_BASE_FIELD_MODULUS)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let row_count = mask_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let column_count = mask_count
        .checked_mul(3)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let mut matrix = vec![vec![0_u64; column_count]; row_count];
    let auxiliary_scale = modular_power(
        2,
        u64::try_from(mask_count - 1).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        GOLDILOCKS_BASE_FIELD_MODULUS,
    );
    for mask_ordinal in 0..mask_count {
        let column = mask_ordinal * 3;
        matrix[0][column] = modular_product(2, auxiliary_scale, GOLDILOCKS_BASE_FIELD_MODULUS);
        matrix[0][column + 1] = auxiliary_scale;
        matrix[0][column + 2] = auxiliary_scale;
    }
    for round_ordinal in 0..mask_count {
        let live_scale = modular_power(
            2,
            u64::try_from(mask_count - round_ordinal - 1)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            GOLDILOCKS_BASE_FIELD_MODULUS,
        );
        let constant_row = 1 + 2 * round_ordinal;
        let leading_row = constant_row + 1;
        for (mask_ordinal, challenge) in challenges.iter().copied().enumerate() {
            let column = mask_ordinal * 3;
            if mask_ordinal < round_ordinal {
                matrix[constant_row][column] = live_scale;
                matrix[constant_row][column + 1] =
                    modular_product(live_scale, challenge, GOLDILOCKS_BASE_FIELD_MODULUS);
                matrix[constant_row][column + 2] = modular_product(
                    live_scale,
                    modular_power(challenge, 2, GOLDILOCKS_BASE_FIELD_MODULUS),
                    GOLDILOCKS_BASE_FIELD_MODULUS,
                );
            } else if mask_ordinal == round_ordinal {
                matrix[constant_row][column] = live_scale;
                matrix[leading_row][column + 2] = live_scale;
            } else {
                let future_scale = live_scale
                    .checked_div(2)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                matrix[constant_row][column] =
                    modular_product(2, future_scale, GOLDILOCKS_BASE_FIELD_MODULUS);
                matrix[constant_row][column + 1] = future_scale;
                matrix[constant_row][column + 2] = future_scale;
            }
        }
    }
    Ok(matrix)
}

fn sumcheck_constant_minor(
    matrix: &[Vec<u64>],
    mask_count: usize,
) -> Result<Vec<Vec<u64>>, CompactStaticCatalogError> {
    let mut selected_columns = vec![0, 1, 2];
    for mask_ordinal in 1..mask_count {
        selected_columns.push(mask_ordinal * 3 + 1);
        selected_columns.push(mask_ordinal * 3 + 2);
    }
    if matrix.len() != selected_columns.len()
        || matrix
            .iter()
            .any(|row| row.len() != mask_count.saturating_mul(3))
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(matrix
        .iter()
        .map(|row| selected_columns.iter().map(|column| row[*column]).collect())
        .collect())
}

fn modular_determinant(
    matrix: &[Vec<u64>],
    modulus: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if matrix.is_empty() || matrix.iter().any(|row| row.len() != matrix.len()) {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut reduced = matrix.to_vec();
    let mut determinant = 1_u64;
    for column_ordinal in 0..reduced.len() {
        let pivot_offset = reduced[column_ordinal..]
            .iter()
            .position(|row| row[column_ordinal] != 0)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let pivot_ordinal = column_ordinal + pivot_offset;
        if pivot_ordinal != column_ordinal {
            reduced.swap(column_ordinal, pivot_ordinal);
            determinant = modular_difference(0, determinant, modulus);
        }
        let pivot = reduced[column_ordinal][column_ordinal];
        determinant = modular_product(determinant, pivot, modulus);
        let inverse = modular_power(pivot, modulus - 2, modulus);
        for value in &mut reduced[column_ordinal][column_ordinal..] {
            *value = modular_product(*value, inverse, modulus);
        }
        let normalized_pivot = reduced[column_ordinal][column_ordinal..].to_vec();
        for row in &mut reduced[column_ordinal + 1..] {
            let scale = row[column_ordinal];
            for (value, pivot_value) in row[column_ordinal..].iter_mut().zip(&normalized_pivot) {
                *value = modular_difference(
                    *value,
                    modular_product(scale, *pivot_value, modulus),
                    modulus,
                );
            }
        }
    }
    Ok(determinant)
}

fn check_randomness_partition(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<(), CompactStaticCatalogError> {
    let pre_cross = unique_mask_group(pre_challenge_whir, MaskGroupRole::CrossEpochOpening)?;
    let main_cross = unique_mask_group(main_whir, MaskGroupRole::CrossEpochOpening)?;
    let cfw_inner = unique_mask_group(main_whir, MaskGroupRole::CfwInner)?;
    let cfw_outer = unique_mask_group(main_whir, MaskGroupRole::CfwOuter)?;
    let cfw_message_randomness = checked_add(
        checked_product(&[
            cfw_reduction.inner_mask_count(),
            cfw_reduction
                .inner_mask_message_length()
                .checked_sub(2)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
        ])?,
        checked_product(&[
            cfw_reduction.outer_mask_count(),
            cfw_reduction.outer_mask_message_length(),
        ])?,
    )?;
    let pre_sumcheck_message_randomness = sumcheck_message_randomness(pre_challenge_whir)?;
    let main_sumcheck_message_randomness = sumcheck_message_randomness(main_whir)?;
    let pre_expected_carried_message_randomness = checked_add(
        checked_product(&[pre_cross.width, pre_cross.message_length])?,
        pre_sumcheck_message_randomness,
    )?;
    let main_expected_carried_message_randomness =
        checked_add(cfw_message_randomness, main_sumcheck_message_randomness)?;
    if pre_cross.committed_encoding_source != MaskCommittedEncodingSource::OwnedByThisEpoch
        || main_cross.committed_encoding_source
            != MaskCommittedEncodingSource::ReusedFromPreChallenge
        || cfw_inner.width != cfw_reduction.inner_mask_count()
        || cfw_outer.width != cfw_reduction.outer_mask_count()
        || pre_challenge_whir.carried_mask_message_randomness_element_count
            != pre_expected_carried_message_randomness
        || main_whir.carried_mask_message_randomness_element_count
            != main_expected_carried_message_randomness
        || pre_challenge_whir.external_carried_mask_message_randomness_element_count != 2
        || main_whir.external_carried_mask_message_randomness_element_count
            != cfw_message_randomness
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn sumcheck_message_randomness(whir: &WhirStaticLedger) -> Result<u64, CompactStaticCatalogError> {
    whir.internal_mask_groups
        .iter()
        .try_fold(0_u64, |count, group| match group.role {
            MaskGroupRole::WhirSumcheck { .. } => checked_add(
                count,
                checked_product(&[group.width, group.message_length])?,
            ),
            MaskGroupRole::WhirCodeSwitch { .. } => Ok(count),
            _ => Err(CompactStaticCatalogError::InvalidGeometry),
        })
}

fn unique_mask_group(
    whir: &WhirStaticLedger,
    role: MaskGroupRole,
) -> Result<&MaskGroupStaticLedger, CompactStaticCatalogError> {
    let mut matches = whir
        .mask_groups_in_commitment_order()
        .filter(|group| group.role == role);
    let group = matches
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if matches.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(group)
}

fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("a product reduced modulo a u64 modulus fits u64")
}

fn modular_difference(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        base = modular_product(base, base, modulus);
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
fn shared_cross_epoch_query_rank(
    domain_size: u64,
    encoding_randomness_length: u64,
    lane_count: u64,
    pre_challenge_positions: &[u64],
    main_positions: &[u64],
) -> Result<(u64, u64, u64, u64), CompactStaticCatalogError> {
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || lane_count == 0
        || pre_challenge_positions.is_empty()
        || main_positions.is_empty()
        || pre_challenge_positions
            .iter()
            .chain(main_positions)
            .any(|position| *position >= domain_size)
        || has_duplicate(pre_challenge_positions)
        || has_duplicate(main_positions)
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut union = pre_challenge_positions.to_vec();
    union.extend_from_slice(main_positions);
    union.sort_unstable();
    union.dedup();
    let union_count =
        u64::try_from(union.len()).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    if union_count > encoding_randomness_length {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let pre_rank = checked_product(&[
        lane_count,
        u64::try_from(pre_challenge_positions.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    ])?;
    let total_rank = checked_product(&[lane_count, union_count])?;
    let current_incremental_rank = total_rank
        .checked_sub(pre_rank)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let residual_after_pre = checked_product(&[
        lane_count,
        encoding_randomness_length
            .checked_sub(
                u64::try_from(pre_challenge_positions.len())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
    ])?;
    let residual_after_both = checked_product(&[
        lane_count,
        encoding_randomness_length
            .checked_sub(union_count)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
    ])?;
    Ok((
        pre_rank,
        current_incremental_rank,
        residual_after_pre,
        residual_after_both,
    ))
}

#[cfg(test)]
fn has_duplicate(values: &[u64]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_cfw::{
        COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT, CompactCfwError,
        CompactCfwGeometry, CompactCfwMaskMaterial, CompactCfwScalarProverState,
    };
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    fn production_cfw_outer_view(
        outer_masks: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        round_challenges: &[CompactChallengeField],
    ) -> Result<CfwOuterVerifierView, CompactCfwError> {
        let geometry = CompactCfwGeometry::derive(4)?;
        if round_challenges.len() != geometry.sumcheck_round_count() {
            return Err(CompactCfwError::InvalidGeometry);
        }
        let inner_masks = vec![
            [CompactChallengeField::ZERO; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH];
            geometry.inner_mask_count()
        ];
        let mask_material =
            CompactCfwMaskMaterial::from_canonical_messages(geometry, inner_masks, outer_masks)?;
        let equality_point = vec![
            CompactChallengeField::from_u64(17),
            CompactChallengeField::from_u64(19),
            CompactChallengeField::from_u64(23),
        ];
        let mut state = CompactCfwScalarProverState::begin(
            geometry,
            mask_material,
            CompactChallengeField::from_u64(29),
            equality_point,
        )?;
        let auxiliary_target = state.auxiliary_target();
        let mut round_polynomials = Vec::with_capacity(geometry.sumcheck_round_count());
        for (round_ordinal, &round_challenge) in round_challenges.iter().enumerate() {
            let mut accumulator = state.round_accumulator()?;
            let suffix_count = 1_usize << (geometry.sumcheck_round_count() - round_ordinal - 1);
            for _ in 0..suffix_count {
                accumulator.absorb_next_row_pair(
                    [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT],
                    [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT],
                )?;
            }
            let round_polynomial = accumulator.finish()?;
            state.accept_round_polynomial(round_polynomial)?;
            state.bind_round_challenge(round_challenge)?;
            round_polynomials.push(round_polynomial);
        }
        let finish = state.finish([CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT])?;
        Ok(CfwOuterVerifierView {
            auxiliary_target,
            round_polynomials,
            outer_evaluations: finish.outer_evaluations().to_vec(),
        })
    }

    #[test]
    fn factor_one_reconciles_the_current_masking_catalog_without_closing_the_gate() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let masking = &selected.masking_leakage;
        masking
            .check(
                &selected.pre_challenge_whir,
                &selected.main_whir,
                &selected.transcript_chronology,
                &selected.query_sampling_lifecycle,
                &catalog.cfw_reduction,
            )
            .expect("factor-one construction masking correspondence");
        assert_eq!(masking.required_view_coverage.len(), 9);
        assert_eq!(masking.mask_opening_rows.len(), 18);
        assert_eq!(
            masking
                .commitment_and_opening_topology
                .total_commitment_count,
            45
        );
        assert_eq!(
            masking
                .commitment_and_opening_topology
                .total_verifier_opening_batch_count,
            46
        );
        assert_eq!(masking.privacy_refusals, privacy_refusals());
    }

    #[test]
    fn cfw_outer_matrix_matches_every_production_coordinate_and_chronology_barrier() {
        let round_challenges = vec![
            CompactChallengeField::from_u64(3),
            CompactChallengeField::from_u64(5),
            CompactChallengeField::from_u64(7),
        ];
        let matrix = CfwOuterCoefficientToViewMatrix::derive(round_challenges.clone())
            .expect("three-round CFW outer-mask matrix");
        assert_eq!(matrix.check_exact_rank_certificate(), Ok((24, 0)));

        let round_count = round_challenges.len();
        let zero_masks = || {
            vec![[CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]; round_count]
        };
        for column_ordinal in 0..matrix.column_count().expect("matrix column count") {
            let mut basis_masks = zero_masks();
            basis_masks[column_ordinal / COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]
                [column_ordinal % COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH] =
                CompactChallengeField::ONE;
            let expected = matrix
                .apply(&basis_masks)
                .expect("independent matrix application");
            let actual = production_cfw_outer_view(basis_masks, &round_challenges)
                .expect("production CFW outer-mask execution");
            assert_eq!(actual, expected, "outer-mask basis column {column_ordinal}");
        }

        let dense_masks = (0..round_count)
            .map(|mask_round_ordinal| {
                core::array::from_fn(|mask_coefficient_ordinal| {
                    CompactChallengeField::from_u64(
                        31 + u64::try_from(
                            mask_round_ordinal * COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH
                                + mask_coefficient_ordinal,
                        )
                        .expect("the small dense fixture index fits u64"),
                    )
                })
            })
            .collect::<Vec<_>>();
        let expected_dense = matrix
            .apply(&dense_masks)
            .expect("independent dense matrix application");
        let actual_dense = production_cfw_outer_view(dense_masks.clone(), &round_challenges)
            .expect("production dense outer-mask execution");
        assert_eq!(actual_dense, expected_dense);

        for round_ordinal in 0..round_count {
            let mut future_mutated_challenges = round_challenges.clone();
            for challenge in &mut future_mutated_challenges[round_ordinal..] {
                *challenge += CompactChallengeField::from_u64(101);
            }
            let future_mutated_matrix =
                CfwOuterCoefficientToViewMatrix::derive(future_mutated_challenges)
                    .expect("future-mutated CFW matrix");
            for coefficient_ordinal in 0..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                let view_coordinate = CfwOuterViewCoordinate::RoundPolynomialCoefficient {
                    round_ordinal,
                    coefficient_ordinal,
                };
                for mask_round_ordinal in 0..round_count {
                    for mask_coefficient_ordinal in 0..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                        assert_eq!(
                            matrix
                                .coefficient(
                                    view_coordinate,
                                    mask_round_ordinal,
                                    mask_coefficient_ordinal,
                                )
                                .expect("original matrix coefficient"),
                            future_mutated_matrix
                                .coefficient(
                                    view_coordinate,
                                    mask_round_ordinal,
                                    mask_coefficient_ordinal,
                                )
                                .expect("future-mutated matrix coefficient"),
                            "round {round_ordinal} depended on an unavailable challenge",
                        );
                    }
                }
            }
        }

        let reordered_matrix = CfwOuterCoefficientToViewMatrix::derive(vec![
            round_challenges[1],
            round_challenges[0],
            round_challenges[2],
        ])
        .expect("reordered-challenge CFW matrix");
        assert_ne!(
            reordered_matrix
                .apply(&dense_masks)
                .expect("reordered matrix application")
                .round_polynomials,
            actual_dense.round_polynomials,
        );
    }

    #[test]
    fn sumcheck_constant_minor_covers_every_production_folding_width() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let mut widths = [&selected.pre_challenge_whir, &selected.main_whir]
            .into_iter()
            .flat_map(|whir| {
                whir.internal_mask_groups.iter().filter_map(|group| {
                    matches!(group.role, MaskGroupRole::WhirSumcheck { .. }).then_some(group.width)
                })
            })
            .collect::<Vec<_>>();
        widths.sort_unstable();
        widths.dedup();
        assert_eq!(widths, vec![4, 6, 7]);
        for width in widths {
            check_sumcheck_constant_minor(width)
                .expect("the exact sumcheck map has its constant minor");
        }
    }

    #[test]
    fn cross_epoch_query_rank_is_exact_for_disjoint_and_overlapping_schedules() {
        assert_eq!(
            shared_cross_epoch_query_rank(4_096, 6, 2, &[1, 7, 13], &[2, 8, 14]),
            Ok((6, 6, 6, 0))
        );
        assert_eq!(
            shared_cross_epoch_query_rank(4_096, 6, 2, &[1, 7, 13], &[7, 13, 19]),
            Ok((6, 2, 6, 4))
        );
        assert_eq!(
            shared_cross_epoch_query_rank(4_096, 6, 2, &[1, 7, 13], &[1, 7, 13]),
            Ok((6, 0, 6, 6))
        );
        assert_eq!(
            shared_cross_epoch_query_rank(4_096, 6, 2, &[1, 1, 13], &[2, 8, 14]),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn hostile_rank_and_shared_root_mutations_refuse() {
        let rank_one_cross_epoch_matrix = vec![vec![1, 0], vec![2, 0], vec![3, 0]];
        assert_eq!(
            construction_masking_matrix_rank(
                &rank_one_cross_epoch_matrix,
                GOLDILOCKS_BASE_FIELD_MODULUS,
            ),
            Ok(1)
        );

        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let mut mutated = selected.masking_leakage.clone();
        mutated
            .commitment_and_opening_topology
            .shared_cross_epoch
            .original_root_count = 2;
        assert_eq!(
            mutated.check(
                &selected.pre_challenge_whir,
                &selected.main_whir,
                &selected.transcript_chronology,
                &selected.query_sampling_lifecycle,
                &catalog.cfw_reduction,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
