//! Relaxed round-by-round knowledge theorem for the compact public-key path.
//!
//! This owner instantiates the prefix state and straight-line extractor for
//! the actual interleaved CFW and two-epoch hiding-WHIR chronology. It derives
//! every code distance from `message || hiding randomness`, assigns an
//! extractor algorithm to every verifier move, and compares the exact relaxed
//! relation on both sides of every sequential-composition boundary. The
//! numerical event ledger is an input only after these hypotheses have been
//! reconstructed; it cannot authorize this theorem by itself.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One};

use super::cfw_reduction::CfwReductionCatalog;
use super::cfw_to_whir_handoff::CfwToWhirHandoffCatalog;
use super::lifecycle::ExactProbability;
use super::soundness::PackingInteractiveSoundness;
use super::transcript_chronology::{
    ExactChallengeSpace, PackingTranscriptChronology, TranscriptEpoch, VerifierMoveRole,
};
use super::{
    CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS,
    INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL, MAIN_CODE_LOG_INVERSE_RATE, MaskGroupRole,
    MaskGroupStaticLedger, QUINTIC_EXTENSION_DEGREE, SUMCHECK_MASK_MESSAGE_LENGTH,
    WHIR_FOLD_BATCH_COUNT, WHIR_PROTOCOL_SECURITY_LEVEL, WHIR_ROUND_COUNT, WhirStaticLedger,
    checked_add, checked_product,
};
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT,
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, COMPACT_CFW_ZERO_EVADER_EXPONENTS,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeRole {
    CfwMain,
    CfwInnerMasks,
    CfwOuterMasks,
    WhirSource {
        epoch: TranscriptEpoch,
        batch_ordinal: u8,
    },
    WhirMask {
        epoch: TranscriptEpoch,
        group_ordinal: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeterministicCorrectionAlgorithm {
    CanonicalBerlekampWelch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UniqueDecodingCode {
    role: CodeRole,
    message_length: u64,
    hiding_randomness_length: u64,
    dimension: u64,
    block_length: u64,
    interleaving_width: u64,
    minimum_distance_numerator: u64,
    minimum_distance_denominator: u64,
    decoding_radius_numerator: u64,
    decoding_radius_denominator: u64,
    selected_decoding_error_count: u64,
    minimum_agreement_count: u64,
    list_size_bound: u64,
    correction_algorithm: DeterministicCorrectionAlgorithm,
    correction_field_operation_bound: u128,
}

impl UniqueDecodingCode {
    fn derive(
        role: CodeRole,
        message_length: u64,
        hiding_randomness_length: u64,
        block_length: u64,
        interleaving_width: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        let dimension = message_length
            .checked_add(hiding_randomness_length)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if message_length == 0
            || hiding_randomness_length == 0
            || interleaving_width == 0
            || dimension >= block_length
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let minimum_distance_numerator = block_length
            .checked_sub(dimension)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let distance_without_endpoint = block_length
            .checked_sub(dimension)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let selected_decoding_error_count = distance_without_endpoint
            .checked_sub(1)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?
            / 2;
        let minimum_agreement_count = block_length
            .checked_sub(selected_decoding_error_count)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;

        // Deterministic error correction uses the canonical Berlekamp-Welch
        // decoder over all evaluation points:
        // 1. build the monic-error-locator linear system for the maximum
        //    correctable error count;
        // 2. row-reduce with left-to-right pivots and set every free variable
        //    to zero, rejecting only an inconsistent system; fewer than the
        //    maximum errors can leave irrelevant locator factors free, so
        //    non-uniqueness of the locator is not a decoding failure;
        // 3. divide the recovered numerator by the error locator, rejecting a
        //    remainder or a message polynomial outside the dimension;
        // 4. re-encode over the canonical domain and reject unless the Hamming
        //    distance is at most the selected integer radius.
        //
        // The following is an explicit field-operation ceiling for that fixed
        // algorithm: system construction, dense canonical elimination,
        // polynomial division, Horner re-encoding, and final comparison. Each
        // interleaved component is decoded separately.
        let dimension_128 = u128::from(dimension);
        let block_length_128 = u128::from(block_length);
        let maximum_errors_128 = u128::from(selected_decoding_error_count);
        let system_width = dimension_128
            .checked_add(
                maximum_errors_128
                    .checked_mul(2)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let system_construction_bound = block_length_128
            .checked_mul(system_width)
            .and_then(|count| count.checked_mul(3))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let elimination_bound = system_width
            .checked_mul(
                system_width
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_mul(block_length_128.checked_mul(2)?.checked_add(1)?))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let division_bound = dimension_128
            .checked_add(maximum_errors_128)
            .and_then(|count| count.checked_mul(maximum_errors_128.checked_add(1)?))
            .and_then(|count| count.checked_mul(2))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let reencoding_bound = block_length_128
            .checked_mul(dimension_128)
            .and_then(|count| count.checked_mul(2))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let per_component_correction_bound = system_construction_bound
            .checked_add(elimination_bound)
            .and_then(|count| count.checked_add(division_bound))
            .and_then(|count| count.checked_add(reencoding_bound))
            .and_then(|count| count.checked_add(block_length_128))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let correction_field_operation_bound = per_component_correction_bound
            .checked_mul(u128::from(interleaving_width))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;

        let code = Self {
            role,
            message_length,
            hiding_randomness_length,
            dimension,
            block_length,
            interleaving_width,
            minimum_distance_numerator,
            minimum_distance_denominator: block_length,
            decoding_radius_numerator: selected_decoding_error_count,
            decoding_radius_denominator: block_length,
            selected_decoding_error_count,
            minimum_agreement_count,
            list_size_bound: 1,
            correction_algorithm: DeterministicCorrectionAlgorithm::CanonicalBerlekampWelch,
            correction_field_operation_bound,
        };
        code.check()?;
        Ok(code)
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        let expected_dimension = checked_add(self.message_length, self.hiding_randomness_length)?;
        if self.dimension != expected_dimension
            || self.dimension >= self.block_length
            || self.minimum_distance_numerator != self.block_length - self.dimension + 1
            || self.minimum_distance_denominator != self.block_length
            || self.selected_decoding_error_count != (self.block_length - self.dimension - 1) / 2
            || self.decoding_radius_numerator != self.selected_decoding_error_count
            || self.decoding_radius_denominator != self.block_length
            || 2 * self.selected_decoding_error_count >= self.block_length - self.dimension
            || self.minimum_agreement_count
                != self.block_length - self.selected_decoding_error_count
            || self.minimum_agreement_count < self.dimension
            || self.list_size_bound != 1
            || self.correction_algorithm
                != DeterministicCorrectionAlgorithm::CanonicalBerlekampWelch
            || self.correction_field_operation_bound == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    fn exact_query_failure(&self) -> Result<ExactProbability, CompactStaticCatalogError> {
        ExactProbability::new(
            BigUint::from(self.minimum_agreement_count).pow(
                u32::try_from(self.hiding_randomness_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
            BigUint::from(self.block_length).pow(
                u32::try_from(self.hiding_randomness_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedCodeRelation {
    message_length: u64,
    hiding_randomness_length: u64,
    block_length: u64,
    interleaving_width: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedMaskCodeRelation {
    role: MaskGroupRole,
    code: CommittedCodeRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GeneralizedCommittedRelation {
    source_code: CommittedCodeRelation,
    mask_codes: Vec<CommittedMaskCodeRelation>,
    source_message_element_count: u64,
    source_hiding_element_count: u64,
    mask_message_element_count: u64,
    covector_extension_element_count: u64,
    opening_evaluation_claim_count: u64,
    carried_reduction_claim_count: u64,
    claim_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OuterRelaxedRelation {
    Unbound,
    LookupIdentityBound,
    CrossEpochEqualityBound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CfwRelaxedRelation {
    InputR1cs {
        relation_plan_hash: [u8; 64],
        witness_element_count: u64,
        operative_constraint_count: u64,
    },
    InitialMaskedClaim,
    FoldedClaim {
        completed_round_count: u32,
    },
    OutputGeneralizedCode(GeneralizedCommittedRelation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WhirRelaxedRelation {
    InputGeneralizedCode(GeneralizedCommittedRelation),
    OpeningBatched,
    MaskedSumcheck {
        batch_ordinal: u8,
    },
    Folded {
        batch_ordinal: u8,
        completed_round_count: u8,
    },
    CodeSwitched {
        completed_round_ordinal: u8,
    },
    BaseCombined,
    OutputTrivial,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrefixKnowledgeState {
    outer: OuterRelaxedRelation,
    cfw: CfwRelaxedRelation,
    pre_challenge_whir: WhirRelaxedRelation,
    main_whir: WhirRelaxedRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExtractorStep {
    /// Preserve the already extracted witness while only the public relaxed
    /// relation changes.
    CarryWitness,
    /// Return the failure symbol on the theorem's explicitly charged bad
    /// challenge set and preserve the extracted witness otherwise.
    ReturnBottomUnderErrorBound,
    /// Decode each named physical code with its canonical Berlekamp-Welch
    /// correction algorithm and strict integer radius.
    CorrectCodes(Vec<CodeRole>),
    /// Re-encode the uniquely decoded folded message in the next canonical
    /// two-adic Reed-Solomon domain.
    ReencodeCodeSwitch {
        epoch: TranscriptEpoch,
        next_batch_ordinal: u8,
    },
    /// Return the failure symbol when a terminal query check fails and the
    /// final decoded witness otherwise.
    EmitDecodedWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KnowledgeTransition {
    verifier_move_ordinal: u32,
    roles: Vec<VerifierMoveRole>,
    preceding_prover_response_ordinal: u32,
    preceding_commitment_count: u64,
    challenge_space: ExactChallengeSpace,
    input_relation: PrefixKnowledgeState,
    output_relation: PrefixKnowledgeState,
    extractor_steps: Vec<ExtractorStep>,
    extraction_field_operation_bound: u128,
    extraction_error: ExactProbability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompositionBoundaryRole {
    CfwToMainWhir,
    MaskedSumcheckToCodeSwitch {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    CodeSwitchToNextMaskedSumcheck {
        epoch: TranscriptEpoch,
        round_ordinal: u8,
    },
    FinalMaskedSumcheckToBase {
        epoch: TranscriptEpoch,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SequentialCompositionBoundary {
    role: CompositionBoundaryRole,
    left_output_relation: GeneralizedCommittedRelation,
    right_input_relation: GeneralizedCommittedRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CfwTheoremInstantiation {
    relation_length: u64,
    r1cs_public_input_length: u64,
    base_field_characteristic: u64,
    extension_degree: u64,
    main_code: CodeRole,
    inner_mask_code: CodeRole,
    outer_mask_code: CodeRole,
    inner_mask_message_length: u64,
    outer_mask_message_length: u64,
    sumcheck_round_count: u32,
    query_count: u64,
    zero_evader_exponents: [u32; COMPACT_CFW_MATRIX_COUNT],
    initial_consistency_error: ExactProbability,
    sumcheck_round_errors: Vec<ExactProbability>,
    joint_zero_evader_error: ExactProbability,
    main_list_size_bound: u64,
    interleaved_inner_list_size_bound: u64,
    interleaved_outer_list_size_bound: u64,
    total_extraction_field_operation_bound: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirMcaTransitionBound {
    epoch: TranscriptEpoch,
    batch_ordinal: u8,
    round_ordinal: u8,
    correlated_function_count: u64,
    target_domain_size: u64,
    exact_mca_error: ExactProbability,
    exact_masked_sumcheck_error: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelaxedRoundByRoundCatalog {
    cfw: CfwTheoremInstantiation,
    codes: Vec<UniqueDecodingCode>,
    whir_mca_bounds: Vec<WhirMcaTransitionBound>,
    transitions: Vec<KnowledgeTransition>,
    composition_boundaries: Vec<SequentialCompositionBoundary>,
    maximum_per_move_extraction_error: ExactProbability,
    total_extraction_field_operation_bound: u128,
}

impl RelaxedRoundByRoundCatalog {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
        cfw_to_whir_handoff: &CfwToWhirHandoffCatalog,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        chronology: &PackingTranscriptChronology,
        interactive_soundness: &PackingInteractiveSoundness,
    ) -> Result<Self, CompactStaticCatalogError> {
        let extension_field_order = extension_field_order();
        let mut codes = Vec::new();
        append_whir_codes(
            &mut codes,
            TranscriptEpoch::PreChallenge,
            pre_challenge_whir,
        )?;
        append_whir_codes(&mut codes, TranscriptEpoch::Main, main_whir)?;
        let whir_mca_bounds = derive_whir_mca_bounds(pre_challenge_whir, main_whir)?;

        let main_code = code_by_role(
            &codes,
            CodeRole::WhirSource {
                epoch: TranscriptEpoch::Main,
                batch_ordinal: 0,
            },
        )?
        .clone();
        codes.push(UniqueDecodingCode {
            role: CodeRole::CfwMain,
            ..main_code
        });

        let inner_group = main_whir
            .external_mask_groups
            .iter()
            .find(|group| group.role == MaskGroupRole::CfwInner)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let outer_group = main_whir
            .external_mask_groups
            .iter()
            .find(|group| group.role == MaskGroupRole::CfwOuter)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        codes.push(code_from_mask_group(CodeRole::CfwInnerMasks, inner_group)?);
        codes.push(code_from_mask_group(CodeRole::CfwOuterMasks, outer_group)?);

        let cfw_main_code = code_by_role(&codes, CodeRole::CfwMain)?;
        let cfw_inner_code = code_by_role(&codes, CodeRole::CfwInnerMasks)?;
        let cfw_outer_code = code_by_role(&codes, CodeRole::CfwOuterMasks)?;
        let cfw_mask_correction_field_operation_bound = cfw_inner_code
            .correction_field_operation_bound
            .checked_add(cfw_outer_code.correction_field_operation_bound)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let cfw_total_extraction_field_operation_bound = cfw_main_code
            .correction_field_operation_bound
            .checked_add(cfw_mask_correction_field_operation_bound)
            .and_then(|bound| {
                bound.checked_add(
                    u128::from(cfw_reduction.sumcheck_round_count())
                        .checked_mul(cfw_mask_correction_field_operation_bound)?,
                )
            })
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let initial_consistency_error = ExactProbability::new(
            BigUint::from(cfw_reduction.initial_consistency_soundness_numerator()),
            extension_field_order.clone(),
        )?;
        let sumcheck_round_errors = (0..cfw_reduction.sumcheck_round_count())
            .map(|round_ordinal| {
                let denominator = if round_ordinal + 1 == cfw_reduction.sumcheck_round_count() {
                    extension_field_order
                        .checked_sub(&BigUint::from(
                            cfw_reduction.last_round_excluded_element_count(),
                        ))
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
                } else {
                    extension_field_order.clone()
                };
                ExactProbability::new(
                    BigUint::from(cfw_reduction.per_round_soundness_numerator()),
                    denominator,
                )
            })
            .collect::<Result<Vec<_>, CompactStaticCatalogError>>()?;
        let joint_zero_evader_error = ExactProbability::new(
            BigUint::from(cfw_reduction.joint_constraint_soundness_numerator()),
            extension_field_order.clone(),
        )?;
        let cfw = CfwTheoremInstantiation {
            relation_length: relation.padded_witness_element_count(),
            r1cs_public_input_length: relation.padded_witness_element_count(),
            base_field_characteristic: GOLDILOCKS_BASE_FIELD_MODULUS,
            extension_degree: QUINTIC_EXTENSION_DEGREE,
            main_code: cfw_main_code.role,
            inner_mask_code: cfw_inner_code.role,
            outer_mask_code: cfw_outer_code.role,
            inner_mask_message_length: cfw_reduction.inner_mask_message_length(),
            outer_mask_message_length: cfw_reduction.outer_mask_message_length(),
            sumcheck_round_count: cfw_reduction.sumcheck_round_count(),
            query_count: 0,
            zero_evader_exponents: COMPACT_CFW_ZERO_EVADER_EXPONENTS,
            initial_consistency_error,
            sumcheck_round_errors,
            joint_zero_evader_error,
            main_list_size_bound: cfw_main_code.list_size_bound,
            interleaved_inner_list_size_bound: cfw_inner_code.list_size_bound,
            interleaved_outer_list_size_bound: cfw_outer_code.list_size_bound,
            total_extraction_field_operation_bound: cfw_total_extraction_field_operation_bound,
        };

        let cfw_output_relation = cfw_output_relation(cfw_to_whir_handoff, main_whir)?;
        let main_whir_input_relation = whir_input_relation(main_whir)?;
        let composition_boundaries = derive_composition_boundaries(
            &codes,
            cfw_to_whir_handoff,
            pre_challenge_whir,
            main_whir,
        )?;

        let mut current_state =
            initial_prefix_knowledge_state(relation, pre_challenge_whir, main_whir_input_relation)?;
        let move_failures = interactive_soundness.verifier_move_failures();
        if chronology.verifier_moves().len() != move_failures.len() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let mut transitions = Vec::with_capacity(chronology.verifier_moves().len());
        let mut total_extraction_field_operation_bound = 0_u128;
        for (verifier_move, move_failure) in
            chronology.verifier_moves().iter().zip(move_failures.iter())
        {
            if verifier_move.ordinal() != move_failure.ordinal()
                || verifier_move.roles() != move_failure.roles()
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            let input_relation = current_state.clone();
            let mut extractor_steps = Vec::new();
            for role in verifier_move.roles() {
                apply_role(
                    &mut current_state,
                    &mut extractor_steps,
                    *role,
                    cfw_reduction,
                    &cfw_output_relation,
                    pre_challenge_whir,
                    main_whir,
                )?;
            }
            if extractor_steps.is_empty() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            let extraction_field_operation_bound =
                extractor_steps.iter().try_fold(0_u128, |bound, step| {
                    bound
                        .checked_add(extractor_step_bound(step, &codes)?)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
                })?;
            total_extraction_field_operation_bound = total_extraction_field_operation_bound
                .checked_add(extraction_field_operation_bound)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            transitions.push(KnowledgeTransition {
                verifier_move_ordinal: verifier_move.ordinal(),
                roles: verifier_move.roles().to_vec(),
                preceding_prover_response_ordinal: verifier_move
                    .preceding_prover_response_ordinal(),
                preceding_commitment_count: verifier_move.preceding_commitment_count(),
                challenge_space: verifier_move.challenge_space().clone(),
                input_relation,
                output_relation: current_state.clone(),
                extractor_steps,
                extraction_field_operation_bound,
                extraction_error: move_failure.probability().clone(),
            });
        }

        let catalog = Self {
            cfw,
            codes,
            whir_mca_bounds,
            transitions,
            composition_boundaries,
            maximum_per_move_extraction_error: interactive_soundness
                .maximum_verifier_move_failure()
                .clone(),
            total_extraction_field_operation_bound,
        };
        catalog.check(
            relation,
            cfw_reduction,
            cfw_to_whir_handoff,
            pre_challenge_whir,
            main_whir,
            chronology,
            interactive_soundness,
        )?;
        Ok(catalog)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
        cfw_to_whir_handoff: &CfwToWhirHandoffCatalog,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
        chronology: &PackingTranscriptChronology,
        interactive_soundness: &PackingInteractiveSoundness,
    ) -> Result<(), CompactStaticCatalogError> {
        cfw_reduction.check(relation)?;
        if self.cfw.relation_length != relation.padded_witness_element_count()
            || self.cfw.r1cs_public_input_length != relation.padded_witness_element_count()
            || !self.cfw.relation_length.is_power_of_two()
            || self.cfw.relation_length != self.cfw.r1cs_public_input_length
            || self.cfw.base_field_characteristic != GOLDILOCKS_BASE_FIELD_MODULUS
            || self.cfw.base_field_characteristic % 2 != 1
            || self.cfw.extension_degree != QUINTIC_EXTENSION_DEGREE
            || self.cfw.inner_mask_message_length
                != u64::try_from(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.outer_mask_message_length
                != u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.outer_mask_message_length < 2 * self.cfw.inner_mask_message_length
            || self.cfw.inner_mask_message_length < 4
            || self.cfw.sumcheck_round_count != relation.padded_witness_element_count().ilog2() + 1
            || self.cfw.query_count != 0
            || self.cfw.zero_evader_exponents != [0, 1, 2]
            || self.cfw.initial_consistency_error
                != ExactProbability::new(
                    BigUint::from(cfw_reduction.initial_consistency_soundness_numerator()),
                    extension_field_order(),
                )?
            || self.cfw.sumcheck_round_errors.len()
                != usize::try_from(cfw_reduction.sumcheck_round_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.joint_zero_evader_error
                != ExactProbability::new(
                    BigUint::from(cfw_reduction.joint_constraint_soundness_numerator()),
                    extension_field_order(),
                )?
            || self.cfw.main_list_size_bound != 1
            || self.cfw.interleaved_inner_list_size_bound != 1
            || self.cfw.interleaved_outer_list_size_bound != 1
            || self.cfw.total_extraction_field_operation_bound == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for (round_ordinal, error) in self.cfw.sumcheck_round_errors.iter().enumerate() {
            let round_ordinal = u32::try_from(round_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            let denominator = if round_ordinal + 1 == cfw_reduction.sumcheck_round_count() {
                extension_field_order()
                    .checked_sub(&BigUint::from(
                        cfw_reduction.last_round_excluded_element_count(),
                    ))
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?
            } else {
                extension_field_order()
            };
            if error
                != &ExactProbability::new(
                    BigUint::from(cfw_reduction.per_round_soundness_numerator()),
                    denominator,
                )?
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        for code in &self.codes {
            code.check()?;
            let required_query_security = match code.role {
                CodeRole::WhirSource { .. } | CodeRole::CfwMain => WHIR_PROTOCOL_SECURITY_LEVEL,
                CodeRole::WhirMask { .. } | CodeRole::CfwInnerMasks | CodeRole::CfwOuterMasks => {
                    INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL
                }
            };
            if !code
                .exact_query_failure()?
                .is_at_most_inverse_power_of_two(required_query_security as usize)
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        let expected_mca_bounds = derive_whir_mca_bounds(pre_challenge_whir, main_whir)?;
        if self.whir_mca_bounds != expected_mca_bounds {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let expected_composition_boundaries = derive_composition_boundaries(
            &self.codes,
            cfw_to_whir_handoff,
            pre_challenge_whir,
            main_whir,
        )?;
        if self.composition_boundaries != expected_composition_boundaries
            || self.composition_boundaries.len() != 15
            || self
                .composition_boundaries
                .iter()
                .any(|boundary| boundary.left_output_relation != boundary.right_input_relation)
            || self.composition_boundaries[0].left_output_relation
                != cfw_output_relation(cfw_to_whir_handoff, main_whir)?
            || self.composition_boundaries[0].right_input_relation
                != whir_input_relation(main_whir)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        if self.transitions.len() != chronology.verifier_moves().len()
            || self.transitions.len() != interactive_soundness.verifier_move_failures().len()
            || self.transitions.is_empty()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let mut interpreted_state = initial_prefix_knowledge_state(
            relation,
            pre_challenge_whir,
            whir_input_relation(main_whir)?,
        )?;
        let mut interpreted_total_extraction_field_operation_bound = 0_u128;
        let mut interpreted_cfw_extraction_field_operation_bound = 0_u128;
        let mut interpreted_maximum_error = ExactProbability::zero();
        for (transition_ordinal, transition) in self.transitions.iter().enumerate() {
            let verifier_move = &chronology.verifier_moves()[transition_ordinal];
            let move_failure = &interactive_soundness.verifier_move_failures()[transition_ordinal];
            let mut interpreted_extractor_steps = Vec::new();
            let interpreted_input_relation = interpreted_state.clone();
            for role in verifier_move.roles() {
                apply_role(
                    &mut interpreted_state,
                    &mut interpreted_extractor_steps,
                    *role,
                    cfw_reduction,
                    &cfw_output_relation(cfw_to_whir_handoff, main_whir)?,
                    pre_challenge_whir,
                    main_whir,
                )?;
            }
            let interpreted_extraction_field_operation_bound =
                interpreted_extractor_steps
                    .iter()
                    .try_fold(0_u128, |bound, step| {
                        bound
                            .checked_add(extractor_step_bound(step, &self.codes)?)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
                    })?;
            if transition.verifier_move_ordinal
                != u32::try_from(transition_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
                || transition.verifier_move_ordinal != verifier_move.ordinal()
                || transition.roles != verifier_move.roles()
                || transition.challenge_space != *verifier_move.challenge_space()
                || transition.preceding_prover_response_ordinal
                    != verifier_move.preceding_prover_response_ordinal()
                || transition.preceding_commitment_count
                    != verifier_move.preceding_commitment_count()
                || transition.preceding_commitment_count == 0
                || transition.challenge_space.cardinality()? <= BigUint::one()
                || transition.input_relation != interpreted_input_relation
                || transition.output_relation != interpreted_state
                || transition.extractor_steps != interpreted_extractor_steps
                || transition.extraction_field_operation_bound
                    != interpreted_extraction_field_operation_bound
                || transition.extraction_error != *move_failure.probability()
                || (transition.extraction_error != ExactProbability::zero()
                    && !transition
                        .extractor_steps
                        .iter()
                        .any(extractor_step_charges_failure))
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            check_cfw_transition_error(transition, &self.cfw)?;
            check_whir_mca_transition_error(transition, &self.whir_mca_bounds)?;
            interpreted_total_extraction_field_operation_bound =
                interpreted_total_extraction_field_operation_bound
                    .checked_add(interpreted_extraction_field_operation_bound)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            if transition.roles.iter().any(is_cfw_role) {
                interpreted_cfw_extraction_field_operation_bound =
                    interpreted_cfw_extraction_field_operation_bound
                        .checked_add(interpreted_extraction_field_operation_bound)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            }
            if transition
                .extraction_error
                .is_greater_than(&interpreted_maximum_error)
            {
                interpreted_maximum_error = transition.extraction_error.clone();
            }
        }
        if interpreted_state.outer != OuterRelaxedRelation::CrossEpochEqualityBound
            || !matches!(
                interpreted_state.cfw,
                CfwRelaxedRelation::OutputGeneralizedCode(_)
            )
            || interpreted_state.pre_challenge_whir != WhirRelaxedRelation::OutputTrivial
            || interpreted_state.main_whir != WhirRelaxedRelation::OutputTrivial
            || self.maximum_per_move_extraction_error
                != *interactive_soundness.maximum_verifier_move_failure()
            || self.maximum_per_move_extraction_error != interpreted_maximum_error
            || !self
                .maximum_per_move_extraction_error
                .is_at_most_inverse_power_of_two(INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL as usize)
            || self.cfw.total_extraction_field_operation_bound
                != interpreted_cfw_extraction_field_operation_bound
            || self.total_extraction_field_operation_bound
                != interpreted_total_extraction_field_operation_bound
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        // Both epochs must use the production full-dimension code shapes.
        check_whir_source_correspondence(
            &self.codes,
            TranscriptEpoch::PreChallenge,
            pre_challenge_whir,
        )?;
        check_whir_source_correspondence(&self.codes, TranscriptEpoch::Main, main_whir)?;
        Ok(())
    }

    pub(super) fn maximum_per_move_extraction_error(&self) -> &ExactProbability {
        &self.maximum_per_move_extraction_error
    }

    pub(super) const fn total_extraction_field_operation_bound(&self) -> u128 {
        self.total_extraction_field_operation_bound
    }
}

fn is_cfw_role(role: &VerifierMoveRole) -> bool {
    matches!(
        role,
        VerifierMoveRole::CfwInitialRandomness
            | VerifierMoveRole::CfwSumcheckRound { .. }
            | VerifierMoveRole::CfwJointConstraint
    )
}

fn extractor_step_charges_failure(step: &ExtractorStep) -> bool {
    matches!(
        step,
        ExtractorStep::ReturnBottomUnderErrorBound
            | ExtractorStep::CorrectCodes(_)
            | ExtractorStep::EmitDecodedWitness
    )
}

fn check_cfw_transition_error(
    transition: &KnowledgeTransition,
    cfw: &CfwTheoremInstantiation,
) -> Result<(), CompactStaticCatalogError> {
    for role in &transition.roles {
        match role {
            VerifierMoveRole::CfwInitialRandomness => {
                if transition.extraction_error != cfw.initial_consistency_error {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
            VerifierMoveRole::CfwSumcheckRound { round_ordinal } => {
                let round_error = cfw
                    .sumcheck_round_errors
                    .get(
                        usize::try_from(*round_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    )
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                if &transition.extraction_error != round_error {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
            VerifierMoveRole::CfwJointConstraint => {
                // This verifier move also owns pre-challenge WHIR opening
                // batching. The move error is their exact union, so the CFW
                // zero-evader component must be present but need not equal the
                // complete grouped move.
                if cfw
                    .joint_zero_evader_error
                    .is_greater_than(&transition.extraction_error)
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_whir_mca_transition_error(
    transition: &KnowledgeTransition,
    bounds: &[WhirMcaTransitionBound],
) -> Result<(), CompactStaticCatalogError> {
    for role in &transition.roles {
        let VerifierMoveRole::WhirFolding {
            epoch,
            batch_ordinal,
            round_ordinal,
        } = role
        else {
            continue;
        };
        let mut matching_bounds = bounds.iter().filter(|bound| {
            bound.epoch == *epoch
                && bound.batch_ordinal == *batch_ordinal
                && bound.round_ordinal == *round_ordinal
        });
        let bound = matching_bounds
            .next()
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if matching_bounds.next().is_some()
            || bound.correlated_function_count != 2
            || transition.extraction_error
                != bound
                    .exact_mca_error
                    .add(&bound.exact_masked_sumcheck_error)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }
    Ok(())
}

fn derive_whir_mca_bounds(
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<WhirMcaTransitionBound>, CompactStaticCatalogError> {
    let extension_field_order = extension_field_order();
    let mut bounds = Vec::new();
    for (epoch, whir) in [
        (TranscriptEpoch::PreChallenge, pre_challenge_whir),
        (TranscriptEpoch::Main, main_whir),
    ] {
        let source_rates = [
            MAIN_CODE_LOG_INVERSE_RATE,
            whir.round_log_inverse_rates[0],
            whir.round_log_inverse_rates[1],
            whir.round_log_inverse_rates[2],
        ];
        let mut source_variable_count = whir.polynomial_variable_count;
        for (batch_ordinal, source_rate) in source_rates.into_iter().enumerate() {
            let source_domain_exponent = source_variable_count
                .checked_add(source_rate)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let source_domain_size = 1_u64
                .checked_shl(source_domain_exponent)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            for round_ordinal in 0..whir.folding_schedule[batch_ordinal] {
                let target_domain_size = source_domain_size
                    .checked_shr(round_ordinal + 1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
                // A binary fold invokes Corollary 4.11 with two correlated
                // functions. In the strict unique-decoding regime its MCA
                // term is `(2 - 1) * target_domain_size / |F|`; the masked
                // sumcheck contributes its separate degree-eight term.
                bounds.push(WhirMcaTransitionBound {
                    epoch,
                    batch_ordinal: u8::try_from(batch_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    round_ordinal: u8::try_from(round_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    correlated_function_count: 2,
                    target_domain_size,
                    exact_mca_error: ExactProbability::new(
                        BigUint::from(target_domain_size),
                        extension_field_order.clone(),
                    )?,
                    exact_masked_sumcheck_error: ExactProbability::new(
                        BigUint::from(SUMCHECK_MASK_MESSAGE_LENGTH),
                        extension_field_order.clone(),
                    )?,
                });
            }
            source_variable_count = source_variable_count
                .checked_sub(whir.folding_schedule[batch_ordinal])
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        }
        if source_variable_count != whir.final_variable_count {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }
    Ok(bounds)
}

fn append_whir_codes(
    codes: &mut Vec<UniqueDecodingCode>,
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    for batch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
        codes.push(UniqueDecodingCode::derive(
            CodeRole::WhirSource {
                epoch,
                batch_ordinal: u8::try_from(batch_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            whir.source_message_lengths[batch_ordinal],
            whir.query_counts[batch_ordinal],
            whir.oracle_heights[batch_ordinal],
            whir.oracle_widths[batch_ordinal],
        )?);
    }
    for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
        codes.push(code_from_mask_group(
            CodeRole::WhirMask {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            group,
        )?);
    }
    Ok(())
}

fn code_from_mask_group(
    role: CodeRole,
    group: &MaskGroupStaticLedger,
) -> Result<UniqueDecodingCode, CompactStaticCatalogError> {
    UniqueDecodingCode::derive(
        role,
        group.message_length,
        group.randomness_length,
        group.domain_size,
        group.width,
    )
}

fn code_by_role(
    codes: &[UniqueDecodingCode],
    role: CodeRole,
) -> Result<&UniqueDecodingCode, CompactStaticCatalogError> {
    let mut matches = codes.iter().filter(|code| code.role == role);
    let code = matches
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if matches.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(code)
}

const fn committed_code_relation(
    message_length: u64,
    hiding_randomness_length: u64,
    block_length: u64,
    interleaving_width: u64,
) -> CommittedCodeRelation {
    CommittedCodeRelation {
        message_length,
        hiding_randomness_length,
        block_length,
        interleaving_width,
    }
}

fn committed_mask_code_relation(group: &MaskGroupStaticLedger) -> CommittedMaskCodeRelation {
    CommittedMaskCodeRelation {
        role: group.role,
        code: committed_code_relation(
            group.message_length,
            group.randomness_length,
            group.domain_size,
            group.width,
        ),
    }
}

fn whir_input_relation(
    whir: &WhirStaticLedger,
) -> Result<GeneralizedCommittedRelation, CompactStaticCatalogError> {
    let source_message_element_count =
        checked_product(&[whir.oracle_widths[0], whir.source_message_lengths[0]])?;
    let source_hiding_element_count =
        checked_product(&[whir.oracle_widths[0], whir.query_counts[0]])?;
    // Only carried masks are part of the input relation. WHIR sumcheck and
    // code-switch masks are prover messages introduced by later reductions.
    let mask_message_element_count =
        whir.external_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.message_length])?,
                )
            })?;
    let opening_evaluation_claim_count = whir.opening_evaluation_count;
    let carried_reduction_claim_count = whir.external_generalized_relation_claim_count;
    let claim_count = checked_add(
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
    )?;
    if claim_count != whir.opening_batching_claim_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(GeneralizedCommittedRelation {
        source_code: committed_code_relation(
            whir.source_message_lengths[0],
            whir.query_counts[0],
            whir.oracle_heights[0],
            whir.oracle_widths[0],
        ),
        mask_codes: whir
            .external_mask_groups
            .iter()
            .map(committed_mask_code_relation)
            .collect(),
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: [
            source_message_element_count,
            1,
            mask_message_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?,
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
        claim_count,
    })
}

fn cfw_output_relation(
    handoff: &CfwToWhirHandoffCatalog,
    main_whir: &WhirStaticLedger,
) -> Result<GeneralizedCommittedRelation, CompactStaticCatalogError> {
    let source_message_element_count = handoff.source_covector_extension_element_count();
    let source_interleaving_width = main_whir.oracle_widths[0];
    let source_message_length = source_message_element_count
        .checked_div(source_interleaving_width)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if checked_product(&[source_interleaving_width, source_message_length])?
        != source_message_element_count
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let source_hiding_element_count =
        checked_product(&[main_whir.oracle_widths[0], main_whir.query_counts[0]])?;
    let mask_message_element_count =
        main_whir
            .external_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.message_length])?,
                )
            })?;
    let opening_evaluation_claim_count = handoff.preceding_opening_claim_count();
    let carried_reduction_claim_count = handoff
        .combined_relation_claim_count()
        .checked_sub(opening_evaluation_claim_count)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(GeneralizedCommittedRelation {
        source_code: committed_code_relation(
            source_message_length,
            main_whir.query_counts[0],
            main_whir.oracle_heights[0],
            source_interleaving_width,
        ),
        mask_codes: main_whir
            .external_mask_groups
            .iter()
            .map(committed_mask_code_relation)
            .collect(),
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: handoff.combined_relation_extension_element_count(),
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
        claim_count: handoff.combined_relation_claim_count(),
    })
}

fn initial_prefix_knowledge_state(
    relation: &CompactPublicKeyRelationCatalog,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir_input_relation: GeneralizedCommittedRelation,
) -> Result<PrefixKnowledgeState, CompactStaticCatalogError> {
    Ok(PrefixKnowledgeState {
        outer: OuterRelaxedRelation::Unbound,
        cfw: CfwRelaxedRelation::InputR1cs {
            relation_plan_hash: relation.relation_plan_hash(),
            witness_element_count: relation.padded_witness_element_count(),
            operative_constraint_count: relation.operative_constraint_count(),
        },
        pre_challenge_whir: WhirRelaxedRelation::InputGeneralizedCode(whir_input_relation(
            pre_challenge_whir,
        )?),
        main_whir: WhirRelaxedRelation::InputGeneralizedCode(main_whir_input_relation),
    })
}

fn whir_stage_relation(
    whir: &WhirStaticLedger,
    batch_ordinal: usize,
) -> Result<GeneralizedCommittedRelation, CompactStaticCatalogError> {
    let source_message_element_count = checked_product(&[
        whir.oracle_widths[batch_ordinal],
        whir.source_message_lengths[batch_ordinal],
    ])?;
    let source_hiding_element_count = checked_product(&[
        whir.oracle_widths[batch_ordinal],
        whir.query_counts[batch_ordinal],
    ])?;
    let mask_message_element_count =
        whir.mask_groups_in_commitment_order()
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.message_length])?,
                )
            })?;
    let opening_evaluation_claim_count = whir.opening_evaluation_count;
    let carried_reduction_claim_count = whir.external_generalized_relation_claim_count;
    let claim_count = checked_add(
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
    )?;
    if claim_count != whir.opening_batching_claim_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(GeneralizedCommittedRelation {
        source_code: committed_code_relation(
            whir.source_message_lengths[batch_ordinal],
            whir.query_counts[batch_ordinal],
            whir.oracle_heights[batch_ordinal],
            whir.oracle_widths[batch_ordinal],
        ),
        mask_codes: whir
            .mask_groups_in_commitment_order()
            .map(committed_mask_code_relation)
            .collect(),
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: [
            source_message_element_count,
            1,
            mask_message_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?,
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
        claim_count,
    })
}

fn derive_composition_boundaries(
    codes: &[UniqueDecodingCode],
    handoff: &CfwToWhirHandoffCatalog,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<Vec<SequentialCompositionBoundary>, CompactStaticCatalogError> {
    let mut boundaries = vec![SequentialCompositionBoundary {
        role: CompositionBoundaryRole::CfwToMainWhir,
        left_output_relation: cfw_output_relation(handoff, main_whir)?,
        right_input_relation: whir_relation_from_codes(
            codes,
            TranscriptEpoch::Main,
            main_whir,
            0,
            true,
        )?,
    }];
    append_whir_composition_boundaries(
        &mut boundaries,
        codes,
        TranscriptEpoch::PreChallenge,
        pre_challenge_whir,
    )?;
    append_whir_composition_boundaries(&mut boundaries, codes, TranscriptEpoch::Main, main_whir)?;
    Ok(boundaries)
}

fn append_whir_composition_boundaries(
    boundaries: &mut Vec<SequentialCompositionBoundary>,
    codes: &[UniqueDecodingCode],
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    for round_ordinal in 0..WHIR_ROUND_COUNT {
        boundaries.push(SequentialCompositionBoundary {
            role: CompositionBoundaryRole::MaskedSumcheckToCodeSwitch {
                epoch,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            left_output_relation: whir_stage_relation(whir, round_ordinal)?,
            right_input_relation: whir_relation_from_codes(
                codes,
                epoch,
                whir,
                round_ordinal,
                false,
            )?,
        });
        boundaries.push(SequentialCompositionBoundary {
            role: CompositionBoundaryRole::CodeSwitchToNextMaskedSumcheck {
                epoch,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            left_output_relation: whir_relation_from_codes(
                codes,
                epoch,
                whir,
                round_ordinal + 1,
                false,
            )?,
            right_input_relation: whir_stage_relation(whir, round_ordinal + 1)?,
        });
    }
    boundaries.push(SequentialCompositionBoundary {
        role: CompositionBoundaryRole::FinalMaskedSumcheckToBase { epoch },
        left_output_relation: whir_stage_relation(whir, WHIR_ROUND_COUNT)?,
        right_input_relation: whir_relation_from_codes(
            codes,
            epoch,
            whir,
            WHIR_ROUND_COUNT,
            false,
        )?,
    });
    Ok(())
}

fn whir_relation_from_codes(
    codes: &[UniqueDecodingCode],
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
    batch_ordinal: usize,
    external_masks_only: bool,
) -> Result<GeneralizedCommittedRelation, CompactStaticCatalogError> {
    let source_code = code_by_role(
        codes,
        CodeRole::WhirSource {
            epoch,
            batch_ordinal: u8::try_from(batch_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
    )?;
    let source_message_element_count =
        checked_product(&[source_code.interleaving_width, source_code.message_length])?;
    let source_hiding_element_count = checked_product(&[
        source_code.interleaving_width,
        source_code.hiding_randomness_length,
    ])?;
    let last_mask_ordinal = if external_masks_only {
        whir.external_mask_groups.len()
    } else {
        whir.internal_mask_groups.len() + whir.external_mask_groups.len()
    };
    let mask_groups = whir.mask_groups_in_commitment_order().collect::<Vec<_>>();
    let mut mask_code_count = 0_usize;
    let mut mask_message_element_count = 0_u64;
    let mut mask_codes = Vec::with_capacity(last_mask_ordinal);
    for group_ordinal in 0..last_mask_ordinal {
        let mask_code = code_by_role(
            codes,
            CodeRole::WhirMask {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
        )?;
        mask_message_element_count = checked_add(
            mask_message_element_count,
            checked_product(&[mask_code.interleaving_width, mask_code.message_length])?,
        )?;
        mask_code_count = mask_code_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let mask_group = mask_groups
            .get(group_ordinal)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        mask_codes.push(CommittedMaskCodeRelation {
            role: mask_group.role,
            code: committed_code_relation(
                mask_code.message_length,
                mask_code.hiding_randomness_length,
                mask_code.block_length,
                mask_code.interleaving_width,
            ),
        });
    }
    if mask_code_count != last_mask_ordinal {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let opening_evaluation_claim_count = whir.opening_evaluation_count;
    let carried_reduction_claim_count = whir.external_generalized_relation_claim_count;
    let claim_count = checked_add(
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
    )?;
    if claim_count != whir.opening_batching_claim_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(GeneralizedCommittedRelation {
        source_code: committed_code_relation(
            source_code.message_length,
            source_code.hiding_randomness_length,
            source_code.block_length,
            source_code.interleaving_width,
        ),
        mask_codes,
        source_message_element_count,
        source_hiding_element_count,
        mask_message_element_count,
        covector_extension_element_count: [
            source_message_element_count,
            1,
            mask_message_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?,
        opening_evaluation_claim_count,
        carried_reduction_claim_count,
        claim_count,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_role(
    state: &mut PrefixKnowledgeState,
    extractor_steps: &mut Vec<ExtractorStep>,
    role: VerifierMoveRole,
    cfw_reduction: &CfwReductionCatalog,
    cfw_output_relation: &GeneralizedCommittedRelation,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    match role {
        VerifierMoveRole::LookupChallenge => {
            if state.outer != OuterRelaxedRelation::Unbound {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.outer = OuterRelaxedRelation::LookupIdentityBound;
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
            extractor_steps.push(ExtractorStep::CarryWitness);
        }
        VerifierMoveRole::CrossEpochPoint => {
            if state.outer != OuterRelaxedRelation::LookupIdentityBound {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.outer = OuterRelaxedRelation::CrossEpochEqualityBound;
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
            extractor_steps.push(ExtractorStep::CarryWitness);
        }
        VerifierMoveRole::CfwInitialRandomness => {
            if !matches!(state.cfw, CfwRelaxedRelation::InputR1cs { .. }) {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.cfw = CfwRelaxedRelation::InitialMaskedClaim;
            extractor_steps.push(ExtractorStep::CorrectCodes(vec![
                CodeRole::CfwMain,
                CodeRole::CfwInnerMasks,
                CodeRole::CfwOuterMasks,
            ]));
        }
        VerifierMoveRole::CfwSumcheckRound { round_ordinal } => {
            let expected_previous = if round_ordinal == 0 {
                matches!(state.cfw, CfwRelaxedRelation::InitialMaskedClaim)
            } else {
                state.cfw
                    == CfwRelaxedRelation::FoldedClaim {
                        completed_round_count: round_ordinal,
                    }
            };
            if !expected_previous || round_ordinal >= cfw_reduction.sumcheck_round_count() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.cfw = CfwRelaxedRelation::FoldedClaim {
                completed_round_count: round_ordinal + 1,
            };
            extractor_steps.push(ExtractorStep::CorrectCodes(vec![
                CodeRole::CfwInnerMasks,
                CodeRole::CfwOuterMasks,
            ]));
        }
        VerifierMoveRole::CfwJointConstraint => {
            if state.cfw
                != (CfwRelaxedRelation::FoldedClaim {
                    completed_round_count: cfw_reduction.sumcheck_round_count(),
                })
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.cfw = CfwRelaxedRelation::OutputGeneralizedCode(cfw_output_relation.clone());
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
        }
        VerifierMoveRole::WhirOpeningBatching { epoch } => {
            if epoch == TranscriptEpoch::Main
                && state.cfw
                    != CfwRelaxedRelation::OutputGeneralizedCode(cfw_output_relation.clone())
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            let whir_state = whir_state_mut(state, epoch);
            if !matches!(whir_state, WhirRelaxedRelation::InputGeneralizedCode(_)) {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::OpeningBatched;
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
        }
        VerifierMoveRole::WhirMaskedSumcheckCombination {
            epoch,
            batch_ordinal,
        } => {
            let whir_state = whir_state_mut(state, epoch);
            let valid_previous = if batch_ordinal == 0 {
                *whir_state == WhirRelaxedRelation::OpeningBatched
            } else {
                *whir_state
                    == WhirRelaxedRelation::CodeSwitched {
                        completed_round_ordinal: batch_ordinal,
                    }
            };
            if !valid_previous {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::MaskedSumcheck { batch_ordinal };
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
            extractor_steps.push(ExtractorStep::CarryWitness);
        }
        VerifierMoveRole::WhirFolding {
            epoch,
            batch_ordinal,
            round_ordinal,
        } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let whir_state = whir_state_mut(state, epoch);
            let valid_previous = if round_ordinal == 0 {
                *whir_state == WhirRelaxedRelation::MaskedSumcheck { batch_ordinal }
            } else {
                *whir_state
                    == WhirRelaxedRelation::Folded {
                        batch_ordinal,
                        completed_round_count: round_ordinal,
                    }
            };
            if !valid_previous
                || u32::from(round_ordinal) >= whir.folding_schedule[usize::from(batch_ordinal)]
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::Folded {
                batch_ordinal,
                completed_round_count: round_ordinal + 1,
            };
            extractor_steps.push(ExtractorStep::CorrectCodes(vec![CodeRole::WhirSource {
                epoch,
                batch_ordinal,
            }]));
        }
        VerifierMoveRole::WhirRoundQueryAndCombination {
            epoch,
            round_ordinal,
        } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let whir_state = whir_state_mut(state, epoch);
            if *whir_state
                != (WhirRelaxedRelation::Folded {
                    batch_ordinal: round_ordinal,
                    completed_round_count: u8::try_from(
                        whir.folding_schedule[usize::from(round_ordinal)],
                    )
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                })
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::CodeSwitched {
                completed_round_ordinal: round_ordinal + 1,
            };
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
            extractor_steps.push(ExtractorStep::ReencodeCodeSwitch {
                epoch,
                next_batch_ordinal: round_ordinal + 1,
            });
        }
        VerifierMoveRole::WhirBaseCombination { epoch } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let whir_state = whir_state_mut(state, epoch);
            if *whir_state
                != (WhirRelaxedRelation::Folded {
                    batch_ordinal: u8::try_from(WHIR_ROUND_COUNT)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    completed_round_count: u8::try_from(whir.folding_schedule[WHIR_ROUND_COUNT])
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                })
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::BaseCombined;
            let mut roles = vec![CodeRole::WhirSource {
                epoch,
                batch_ordinal: u8::try_from(WHIR_ROUND_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            }];
            for group_ordinal in 0..whir.mask_groups_in_commitment_order().count() {
                roles.push(CodeRole::WhirMask {
                    epoch,
                    group_ordinal: u8::try_from(group_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                });
            }
            extractor_steps.push(ExtractorStep::CorrectCodes(roles));
        }
        VerifierMoveRole::WhirFinalQueries { epoch } => {
            let whir_state = whir_state_mut(state, epoch);
            if *whir_state != WhirRelaxedRelation::BaseCombined {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::OutputTrivial;
            extractor_steps.push(ExtractorStep::EmitDecodedWitness);
        }
    }
    Ok(())
}

fn whir_state_mut(
    state: &mut PrefixKnowledgeState,
    epoch: TranscriptEpoch,
) -> &mut WhirRelaxedRelation {
    match epoch {
        TranscriptEpoch::PreChallenge => &mut state.pre_challenge_whir,
        TranscriptEpoch::Main => &mut state.main_whir,
    }
}

fn whir_for_epoch<'a>(
    epoch: TranscriptEpoch,
    pre_challenge_whir: &'a WhirStaticLedger,
    main_whir: &'a WhirStaticLedger,
) -> &'a WhirStaticLedger {
    match epoch {
        TranscriptEpoch::PreChallenge => pre_challenge_whir,
        TranscriptEpoch::Main => main_whir,
    }
}

fn extractor_step_bound(
    step: &ExtractorStep,
    codes: &[UniqueDecodingCode],
) -> Result<u128, CompactStaticCatalogError> {
    match step {
        ExtractorStep::CarryWitness
        | ExtractorStep::ReturnBottomUnderErrorBound
        | ExtractorStep::EmitDecodedWitness => Ok(0),
        ExtractorStep::CorrectCodes(roles) => roles.iter().try_fold(0_u128, |sum, role| {
            sum.checked_add(code_by_role(codes, *role)?.correction_field_operation_bound)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
        }),
        ExtractorStep::ReencodeCodeSwitch {
            epoch,
            next_batch_ordinal,
        } => {
            let code = code_by_role(
                codes,
                CodeRole::WhirSource {
                    epoch: *epoch,
                    batch_ordinal: *next_batch_ordinal,
                },
            )?;
            u128::from(code.interleaving_width)
                .checked_mul(u128::from(code.block_length))
                .and_then(|count| count.checked_mul(u128::from(code.dimension)))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
        }
    }
}

fn check_whir_source_correspondence(
    codes: &[UniqueDecodingCode],
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    for batch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
        let code = code_by_role(
            codes,
            CodeRole::WhirSource {
                epoch,
                batch_ordinal: u8::try_from(batch_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
        )?;
        if code.message_length != whir.source_message_lengths[batch_ordinal]
            || code.hiding_randomness_length != whir.query_counts[batch_ordinal]
            || code.block_length != whir.oracle_heights[batch_ordinal]
            || code.interleaving_width != whir.oracle_widths[batch_ordinal]
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }
    Ok(())
}

fn extension_field_order() -> BigUint {
    BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(QUINTIC_EXTENSION_DEGREE as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn factor_one_instantiates_every_relaxed_transition_and_extractor() {
        let catalog =
            CompactPublicKeyStaticCatalog::derive().expect("compact public-key static catalog");
        let factor_one = &catalog.factor_catalogs[0];
        let theorem = &factor_one.relaxed_round_by_round;

        assert_eq!(theorem.transitions.len(), 82);
        assert_eq!(theorem.composition_boundaries.len(), 15);
        assert_eq!(theorem.cfw.relation_length, 4_194_304);
        assert_eq!(theorem.cfw.r1cs_public_input_length, 4_194_304);
        assert_eq!(theorem.cfw.sumcheck_round_count, 23);
        assert_eq!(theorem.cfw.inner_mask_message_length, 4);
        assert_eq!(theorem.cfw.outer_mask_message_length, 8);
        assert_eq!(theorem.cfw.zero_evader_exponents, [0, 1, 2]);
        let field_order = extension_field_order();
        assert_eq!(
            theorem.cfw.initial_consistency_error,
            ExactProbability::new(BigUint::from(9_u8), field_order.clone())
                .expect("initial CFW error")
        );
        assert_eq!(theorem.cfw.sumcheck_round_errors.len(), 23);
        assert!(theorem.cfw.sumcheck_round_errors[..22].iter().all(|error| {
            error
                == &ExactProbability::new(BigUint::from(8_u8), field_order.clone())
                    .expect("ordinary CFW round error")
        }));
        assert_eq!(
            theorem.cfw.sumcheck_round_errors[22],
            ExactProbability::new(
                BigUint::from(8_u8),
                field_order
                    .checked_sub(&BigUint::from(2_u8))
                    .expect("two excluded field elements"),
            )
            .expect("final CFW round error")
        );
        assert_eq!(
            theorem.cfw.joint_zero_evader_error,
            ExactProbability::new(BigUint::from(2_u8), field_order.clone())
                .expect("quadratic zero-evader error")
        );
        assert_eq!(theorem.cfw.main_list_size_bound, 1);
        assert_eq!(theorem.cfw.interleaved_inner_list_size_bound, 1);
        assert_eq!(theorem.cfw.interleaved_outer_list_size_bound, 1);
        assert_eq!(theorem.whir_mca_bounds.len(), 37);
        assert!(theorem.whir_mca_bounds.iter().all(|bound| {
            bound.correlated_function_count == 2
                && bound.exact_mca_error
                    == ExactProbability::new(
                        BigUint::from(bound.target_domain_size),
                        field_order.clone(),
                    )
                    .expect("binary-fold MCA error")
                && bound.exact_masked_sumcheck_error
                    == ExactProbability::new(
                        BigUint::from(SUMCHECK_MASK_MESSAGE_LENGTH),
                        field_order.clone(),
                    )
                    .expect("masked-sumcheck error")
        }));
        assert!(
            theorem
                .maximum_per_move_extraction_error()
                .is_at_most_inverse_power_of_two(266)
        );
        assert!(theorem.total_extraction_field_operation_bound > 0);
        assert!(theorem.transitions.iter().all(|transition| {
            !transition.extractor_steps.is_empty()
                && transition.preceding_commitment_count > 0
                && transition
                    .challenge_space
                    .cardinality()
                    .is_ok_and(|cardinality| cardinality > BigUint::one())
        }));
        assert!(theorem.transitions.iter().all(|transition| {
            transition.extraction_error == ExactProbability::zero()
                || transition
                    .extractor_steps
                    .iter()
                    .any(extractor_step_charges_failure)
        }));
        assert!(theorem.transitions.windows(2).all(|adjacent| {
            adjacent[0].verifier_move_ordinal + 1 == adjacent[1].verifier_move_ordinal
                && adjacent[0].preceding_prover_response_ordinal
                    < adjacent[1].preceding_prover_response_ordinal
        }));
        assert!(
            theorem
                .composition_boundaries
                .iter()
                .all(|boundary| { boundary.left_output_relation == boundary.right_input_relation })
        );
        let cfw_to_whir_boundary = &theorem.composition_boundaries[0];
        assert_eq!(
            cfw_to_whir_boundary.left_output_relation.source_code,
            CommittedCodeRelation {
                message_length: 32_768,
                hiding_randomness_length: 396,
                block_length: 131_072,
                interleaving_width: 128,
            }
        );
        assert_eq!(
            cfw_to_whir_boundary.left_output_relation.mask_codes,
            vec![
                CommittedMaskCodeRelation {
                    role: MaskGroupRole::CfwInner,
                    code: CommittedCodeRelation {
                        message_length: 4,
                        hiding_randomness_length: 399,
                        block_length: 2_048,
                        interleaving_width: 69,
                    },
                },
                CommittedMaskCodeRelation {
                    role: MaskGroupRole::CfwOuter,
                    code: CommittedCodeRelation {
                        message_length: 8,
                        hiding_randomness_length: 399,
                        block_length: 2_048,
                        interleaving_width: 23,
                    },
                },
                CommittedMaskCodeRelation {
                    role: MaskGroupRole::CrossEpochOpening,
                    code: CommittedCodeRelation {
                        message_length: 1,
                        hiding_randomness_length: 798,
                        block_length: 4_096,
                        interleaving_width: 2,
                    },
                },
            ]
        );
        assert_eq!(
            cfw_to_whir_boundary
                .left_output_relation
                .opening_evaluation_claim_count,
            2
        );
        assert_eq!(
            cfw_to_whir_boundary
                .left_output_relation
                .carried_reduction_claim_count,
            162
        );
        assert_eq!(cfw_to_whir_boundary.left_output_relation.claim_count, 164);
    }

    #[test]
    fn factor_one_source_codes_include_hiding_rows_in_distance_and_queries() {
        let catalog =
            CompactPublicKeyStaticCatalog::derive().expect("compact public-key static catalog");
        let theorem = &catalog.factor_catalogs[0].relaxed_round_by_round;
        let source_codes = theorem
            .codes
            .iter()
            .filter(|code| {
                matches!(
                    code.role,
                    CodeRole::WhirSource {
                        epoch: TranscriptEpoch::Main,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(source_codes.len(), 4);
        assert_eq!(
            source_codes
                .iter()
                .map(|code| (
                    code.message_length,
                    code.hiding_randomness_length,
                    code.block_length,
                    code.dimension,
                ))
                .collect::<Vec<_>>(),
            vec![
                (32_768, 396, 131_072, 33_164),
                (2_048, 432, 8_192, 2_480),
                (128, 400, 2_048, 528),
                (8, 348, 2_048, 356),
            ]
        );
        for code in source_codes {
            assert!(
                code.exact_query_failure()
                    .expect("exact source query failure")
                    .is_at_most_inverse_power_of_two(267)
            );
            let previous = UniqueDecodingCode::derive(
                code.role,
                code.message_length,
                code.hiding_randomness_length - 1,
                code.block_length,
                code.interleaving_width,
            )
            .expect("previous source code shape");
            assert!(
                !previous
                    .exact_query_failure()
                    .expect("exact previous query failure")
                    .is_at_most_inverse_power_of_two(267)
            );
        }
    }

    #[test]
    fn theorem_checker_rejects_changed_relations_extractors_barriers_and_code_dimensions() {
        let relation =
            crate::bgv::proof_suite::relation_plan::selected_compact_public_key_relation_catalog()
                .expect("selected compact public-key relation");
        let catalog =
            CompactPublicKeyStaticCatalog::derive().expect("compact public-key static catalog");
        let factor_one = &catalog.factor_catalogs[0];

        let mut changed_boundary = factor_one.relaxed_round_by_round.clone();
        changed_boundary.composition_boundaries[0]
            .right_input_relation
            .claim_count += 1;
        assert_eq!(
            changed_boundary.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut coordinated_boundary_change = factor_one.relaxed_round_by_round.clone();
        coordinated_boundary_change.composition_boundaries[0]
            .left_output_relation
            .claim_count += 1;
        coordinated_boundary_change.composition_boundaries[0]
            .right_input_relation
            .claim_count += 1;
        assert_eq!(
            coordinated_boundary_change.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut coordinated_code_shape_change = factor_one.relaxed_round_by_round.clone();
        coordinated_code_shape_change.composition_boundaries[0]
            .left_output_relation
            .source_code
            .message_length += 1;
        coordinated_code_shape_change.composition_boundaries[0]
            .right_input_relation
            .source_code
            .message_length += 1;
        assert_eq!(
            coordinated_code_shape_change.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_extractor = factor_one.relaxed_round_by_round.clone();
        changed_extractor.transitions[2].extractor_steps = vec![ExtractorStep::CarryWitness];
        assert_eq!(
            changed_extractor.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_barrier = factor_one.relaxed_round_by_round.clone();
        changed_barrier.transitions[2].preceding_commitment_count += 1;
        assert_eq!(
            changed_barrier.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut changed_dimension = factor_one.relaxed_round_by_round.clone();
        changed_dimension.codes[0].hiding_randomness_length += 1;
        assert_eq!(
            changed_dimension.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &factor_one.transcript_chronology,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
