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

use super::canonical_reed_solomon::{
    CanonicalReedSolomonDecodedWitness, CanonicalReedSolomonError, CanonicalReedSolomonGeometry,
    decode_canonical_interleaved_reed_solomon,
};
use super::cfw_reduction::CfwReductionCatalog;
use super::cfw_to_whir_handoff::CfwToWhirHandoffCatalog;
use super::lifecycle::ExactProbability;
use super::soundness::PackingInteractiveSoundness;
use super::transcript_chronology::{
    ExactChallengeSpace, PackingTranscriptChronology, TranscriptEpoch, VerifierMoveRole,
};
use super::{
    CROSS_EPOCH_POINT_COORDINATE_COUNT, CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS,
    INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL, MaskGroupRole, MaskGroupStaticLedger,
    QUINTIC_EXTENSION_DEGREE, SUMCHECK_MASK_MESSAGE_LENGTH, WHIR_FOLD_BATCH_COUNT,
    WHIR_PROTOCOL_SECURITY_LEVEL, WHIR_ROUND_COUNT, WhirStaticLedger, checked_add, checked_product,
};
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_LAST_ROUND_EXCLUDED_ELEMENT_COUNT,
    COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
    COMPACT_CFW_ZERO_EVADER_EXPONENTS,
};
use crate::bgv::proof_suite::relation_plan::CompactPublicKeyRelationCatalog;

mod semantic_relations;

/// Maximum canonical code operations applied to one committed oracle by one
/// executable `ERRBR` call. WHIR base reconstruction attains this bound with
/// two encodings followed by two erasure corrections.
const MAXIMUM_CODE_OPERATIONS_PER_ORACLE: usize = 4;

/// Source-level non-arithmetic passes inside one canonical code operation.
const MAXIMUM_CODE_ELEMENT_PASSES_PER_OPERATION: u128 = 10;

/// Source-level semantic algebra, shape-validation, and witness-projection
/// passes outside the canonical code implementation.
const MAXIMUM_SEMANTIC_ELEMENT_PASSES: u128 = 12;

/// Construction-wide local projection and predecessor-reassembly passes. The
/// history-independent extractor does not replay completed histories.
const MAXIMUM_CONSTRUCTION_ELEMENT_PASSES: u128 = 8;

/// Fixed-width word operations charged to one visited extension element in
/// the declared unit-cost field/word-RAM model.
const MAXIMUM_WORD_OPERATIONS_PER_ELEMENT_PASS: u128 = 16;

/// The source audit gives every counted field operation a separate, deliberately
/// loose word-bookkeeping allowance. This covers loop progress, indexing,
/// checked-counter updates, result placement, and error propagation around the
/// arithmetic primitive; the field operation itself is counted independently.
const MAXIMUM_WORD_BOOKKEEPING_PER_FIELD_OPERATION: u128 = 1_024;

/// Fixed straight-line validation and branch work in one local extractor.
const MAXIMUM_STRAIGHT_LINE_WORD_OPERATIONS: u128 = 1_024;

/// One footprint element receives a full 1024-word allowance. The independently
/// enumerated executable paths require at most sixty passes and sixteen word
/// operations per pass, so this retains 64 words of slack per element while
/// keeping the previous conservative arithmetic unchanged.
const MAXIMUM_WORD_OPERATIONS_PER_SEMANTIC_ELEMENT: u128 = 1_024;

const MAXIMUM_AUDITED_ELEMENT_PASSES: u128 = (MAXIMUM_CODE_OPERATIONS_PER_ORACLE as u128)
    * MAXIMUM_CODE_ELEMENT_PASSES_PER_OPERATION
    + MAXIMUM_SEMANTIC_ELEMENT_PASSES
    + MAXIMUM_CONSTRUCTION_ELEMENT_PASSES;

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
    query_count: u64,
    minimum_distance_numerator: u64,
    minimum_distance_denominator: u64,
    decoding_radius_numerator: u64,
    decoding_radius_denominator: u64,
    selected_decoding_error_count: u64,
    maximum_bad_agreement_count: u64,
    list_size_bound: u64,
    correction_algorithm: DeterministicCorrectionAlgorithm,
    correction_field_operation_bound: u128,
}

impl UniqueDecodingCode {
    fn derive(
        role: CodeRole,
        message_length: u64,
        hiding_randomness_length: u64,
        query_count: u64,
        block_length: u64,
        interleaving_width: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        let dimension = message_length
            .checked_add(hiding_randomness_length)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if message_length == 0
            || hiding_randomness_length == 0
            || query_count == 0
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
        let maximum_bad_agreement_count = block_length
            .checked_sub(selected_decoding_error_count)
            .and_then(|count| count.checked_sub(1))
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
        // The canonical implementation owns the operation formula. It counts
        // evaluation-point generation, system construction, the exact
        // triangular suffix ceiling for deterministic elimination, monic
        // division, and both executable re-encodings.
        let decoder_geometry = CanonicalReedSolomonGeometry::new(
            usize::try_from(message_length)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            usize::try_from(hiding_randomness_length)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            usize::try_from(block_length)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            usize::try_from(interleaving_width)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let correction_field_operation_bound = decoder_geometry
            .decoding_field_operation_bound()
            .map_err(|error| match error {
                CanonicalReedSolomonError::ArithmeticOverflow => {
                    CompactStaticCatalogError::ArithmeticOverflow
                }
                _ => CompactStaticCatalogError::InvalidGeometry,
            })?;

        let code = Self {
            role,
            message_length,
            hiding_randomness_length,
            dimension,
            block_length,
            interleaving_width,
            query_count,
            minimum_distance_numerator,
            minimum_distance_denominator: block_length,
            decoding_radius_numerator: selected_decoding_error_count,
            decoding_radius_denominator: block_length,
            selected_decoding_error_count,
            maximum_bad_agreement_count,
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
            || self.maximum_bad_agreement_count
                != self.block_length - self.selected_decoding_error_count - 1
            || self.maximum_bad_agreement_count < self.dimension
            || self.query_count == 0
            || self.query_count > self.maximum_bad_agreement_count
            || self.list_size_bound != 1
            || self.correction_algorithm
                != DeterministicCorrectionAlgorithm::CanonicalBerlekampWelch
            || self.correction_field_operation_bound == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        self.decoder_geometry()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        Ok(())
    }

    fn decoder_geometry(&self) -> Result<CanonicalReedSolomonGeometry, CanonicalReedSolomonError> {
        CanonicalReedSolomonGeometry::new(
            usize::try_from(self.message_length)
                .map_err(|_| CanonicalReedSolomonError::InvalidGeometry)?,
            usize::try_from(self.hiding_randomness_length)
                .map_err(|_| CanonicalReedSolomonError::InvalidGeometry)?,
            usize::try_from(self.block_length)
                .map_err(|_| CanonicalReedSolomonError::InvalidGeometry)?,
            usize::try_from(self.interleaving_width)
                .map_err(|_| CanonicalReedSolomonError::InvalidGeometry)?,
        )
    }

    fn decode_received_rows(
        &self,
        received_rows: &[Vec<crate::bgv::proof_suite::ProofChallengeExtensionElement>],
    ) -> Result<CanonicalReedSolomonDecodedWitness, CanonicalReedSolomonError> {
        decode_canonical_interleaved_reed_solomon(self.decoder_geometry()?, received_rows)
    }

    fn exact_query_failure(&self) -> Result<ExactProbability, CompactStaticCatalogError> {
        ExactProbability::new(
            falling_factorial(self.maximum_bad_agreement_count, self.query_count)?,
            falling_factorial(self.block_length, self.query_count)?,
        )
    }
}

fn falling_factorial(
    population_size: u64,
    selection_count: u64,
) -> Result<BigUint, CompactStaticCatalogError> {
    if selection_count == 0 || selection_count > population_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    (0..selection_count).try_fold(BigUint::one(), |product, selected_count| {
        Ok(product * (population_size - selected_count))
    })
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
    /// Return the failure symbol on the theorem's explicitly charged bad
    /// challenge set and preserve the extracted witness otherwise.
    ReturnBottomUnderErrorBound,
    /// Execute one canonical code operation at the exact interleaving width
    /// used by the semantic extractor. A folded WHIR relation retains its
    /// physical message length and domain while its logical width decreases,
    /// so the width is part of the operation rather than inferred from the
    /// commitment's initial catalog row.
    CodeOperation(ExtractorCodeOperation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExtractorCodeOperationKind {
    Decode,
    Encode,
    /// Run the selected deterministic erasure corrector on the largest
    /// possible agreement set. The semantic extractor may use a smaller
    /// challenge-selected set; the full-domain count is its exact uniform
    /// ceiling and is attained when every combined row agrees.
    ErasureCorrect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExtractorCodeOperation {
    kind: ExtractorCodeOperationKind,
    role: CodeRole,
    interleaving_width: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExtractorDeterministicWorkBound {
    field_operation_bound: u128,
    field_bookkeeping_word_operation_bound: u128,
    semantic_element_word_operation_bound: u128,
    straight_line_word_operation_bound: u128,
    non_field_operation_bound: u128,
    total_operation_bound: u128,
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
    extraction_non_field_operation_bound: u128,
    extraction_operation_bound: u128,
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
struct CfwCodeCorrectionInstantiation {
    role: CodeRole,
    message_length: u64,
    encoding_randomness_length: u64,
    dimension: u64,
    block_length: u64,
    base_alphabet_extension_width: u64,
    repeated_encoding_count: u64,
    interleaved_width: u64,
    selected_decoding_error_count: u64,
    maximum_bad_agreement_count: u64,
    list_size_bound: u64,
    correction_algorithm: DeterministicCorrectionAlgorithm,
    correction_field_operation_bound: u128,
}

impl CfwCodeCorrectionInstantiation {
    fn from_selected_code(
        code: &UniqueDecodingCode,
        base_alphabet_extension_width: u64,
        repeated_encoding_count: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        if base_alphabet_extension_width == 0
            || repeated_encoding_count == 0
            || code.interleaving_width
                != checked_product(&[base_alphabet_extension_width, repeated_encoding_count])?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(Self {
            role: code.role,
            message_length: code.message_length,
            encoding_randomness_length: code.hiding_randomness_length,
            dimension: code.dimension,
            block_length: code.block_length,
            base_alphabet_extension_width,
            repeated_encoding_count,
            interleaved_width: code.interleaving_width,
            selected_decoding_error_count: code.selected_decoding_error_count,
            maximum_bad_agreement_count: code.maximum_bad_agreement_count,
            list_size_bound: code.list_size_bound,
            correction_algorithm: code.correction_algorithm,
            correction_field_operation_bound: code.correction_field_operation_bound,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CfwRoundByRoundInstantiation {
    relation_length: u64,
    r1cs_public_input_length: u64,
    base_field_characteristic: u64,
    extension_degree: u64,
    main_code: CfwCodeCorrectionInstantiation,
    inner_mask_code: CfwCodeCorrectionInstantiation,
    outer_mask_code: CfwCodeCorrectionInstantiation,
    initial_randomness_element_count: u32,
    per_round_randomness_element_count: u32,
    sumcheck_round_count: u32,
    joint_constraint_randomness_element_count: u32,
    last_round_excluded_element_count: u64,
    query_count: u64,
    zero_evader_exponents: [u32; COMPACT_CFW_MATRIX_COUNT],
    zero_evader_output_coordinate_count: u64,
    zero_evader_maximum_root_count: u64,
    theorem_list_size_multiplier: u64,
    /// The first coordinate printed by CFW Theorem 11.3.
    ///
    /// For the production outer-mask message length this is `9 / |F|`. It is
    /// retained as paper correspondence only and is not used by the executable
    /// relaxation because it does not cover the complete equality-point
    /// challenge below.
    theorem_initial_consistency_error: ExactProbability,
    /// Uniform bound derived from the executable CDHZ bad-transition
    /// certificate: one combining-scalar root plus the 23-coordinate
    /// multilinear constraint identity, namely `24 / |F|`.
    semantic_initial_consistency_error: ExactProbability,
    sumcheck_round_errors: Vec<ExactProbability>,
    joint_zero_evader_error: ExactProbability,
    initial_extraction_field_operation_bound: u128,
    per_sumcheck_extraction_field_operation_bound: u128,
    joint_extraction_field_operation_bound: u128,
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
    cfw: CfwRoundByRoundInstantiation,
    codes: Vec<UniqueDecodingCode>,
    whir_mca_bounds: Vec<WhirMcaTransitionBound>,
    transitions: Vec<KnowledgeTransition>,
    composition_boundaries: Vec<SequentialCompositionBoundary>,
    /// The composed IOR starts from the explicit RR1CS statement. Every code
    /// oracle is a prover message, not an input implicit-instance string.
    input_implicit_instance_tuple_size: u64,
    /// Both WHIR base components end in the trivial relation, so no internal
    /// code oracle is selected as an output implicit-instance string.
    output_implicit_instance_tuple_size: u64,
    maximum_per_move_extraction_error: ExactProbability,
    /// Uniform `etRRBR` field-operation ceiling for one invocation of
    /// `ERRBR`, as required by CDHZ Definition 3.6.
    maximum_extraction_field_operation_bound: u128,
    /// Maximum non-field word-RAM work in one history-independent `ERRBR`
    /// call, including canonical code bookkeeping, semantic algebra, shape
    /// validation, witness projection, and predecessor reassembly.
    maximum_extraction_non_field_operation_bound: u128,
    /// Complete uniform `etRRBR` ceiling in the source-audited deterministic
    /// word-RAM model.
    maximum_extraction_operation_bound: u128,
    /// Aggregate diagnostic work across one backward pass over all verifier
    /// moves. This is not substituted for `etRRBR`.
    total_extraction_field_operation_bound: u128,
    total_extraction_non_field_operation_bound: u128,
    total_extraction_operation_bound: u128,
    /// Maximum number of extension elements reachable by one local extractor
    /// before applying the audited pass multiplier. Derived only from the
    /// canonical code geometries, never supplied by the prover.
    extraction_semantic_element_capacity: u128,
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
        codes.push(code_from_mask_group(
            CodeRole::CfwInnerMasks,
            inner_group,
            main_whir.mask_query_count,
        )?);
        codes.push(code_from_mask_group(
            CodeRole::CfwOuterMasks,
            outer_group,
            main_whir.mask_query_count,
        )?);

        let cfw_main_code = code_by_role(&codes, CodeRole::CfwMain)?;
        let cfw_inner_code = code_by_role(&codes, CodeRole::CfwInnerMasks)?;
        let cfw_outer_code = code_by_role(&codes, CodeRole::CfwOuterMasks)?;
        let cfw_main_code_instantiation = CfwCodeCorrectionInstantiation::from_selected_code(
            cfw_main_code,
            cfw_main_code.interleaving_width,
            1,
        )?;
        let cfw_inner_code_instantiation = CfwCodeCorrectionInstantiation::from_selected_code(
            cfw_inner_code,
            1,
            cfw_reduction.inner_mask_count(),
        )?;
        let cfw_outer_code_instantiation = CfwCodeCorrectionInstantiation::from_selected_code(
            cfw_outer_code,
            1,
            cfw_reduction.outer_mask_count(),
        )?;
        let cfw_theorem_list_size_multiplier = checked_product(&[
            cfw_main_code_instantiation.list_size_bound,
            cfw_inner_code_instantiation.list_size_bound,
            cfw_outer_code_instantiation.list_size_bound,
        ])?;
        let cfw_mask_correction_field_operation_bound = cfw_inner_code
            .correction_field_operation_bound
            .checked_add(cfw_outer_code.correction_field_operation_bound)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let cfw_initial_extraction_field_operation_bound = cfw_main_code
            .correction_field_operation_bound
            .checked_add(cfw_mask_correction_field_operation_bound)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let cfw_total_extraction_field_operation_bound =
            cfw_initial_extraction_field_operation_bound
                .checked_add(
                    u128::from(cfw_reduction.sumcheck_round_count())
                        .checked_mul(cfw_mask_correction_field_operation_bound)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                )
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let theorem_initial_consistency_error = ExactProbability::new(
            BigUint::from(
                cfw_outer_code_instantiation
                    .message_length
                    .checked_add(1)
                    .and_then(|numerator| numerator.checked_mul(cfw_theorem_list_size_multiplier))
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
            extension_field_order.clone(),
        )?;
        let semantic_initial_consistency_error = ExactProbability::new(
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
                    BigUint::from(
                        cfw_reduction
                            .per_round_soundness_numerator()
                            .checked_mul(cfw_theorem_list_size_multiplier)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                    ),
                    denominator,
                )
            })
            .collect::<Result<Vec<_>, CompactStaticCatalogError>>()?;
        let joint_zero_evader_error = ExactProbability::new(
            BigUint::from(
                cfw_reduction
                    .joint_constraint_soundness_numerator()
                    .checked_mul(cfw_theorem_list_size_multiplier)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
            extension_field_order.clone(),
        )?;
        let cfw = CfwRoundByRoundInstantiation {
            relation_length: relation.padded_witness_element_count(),
            r1cs_public_input_length: relation.padded_witness_element_count(),
            base_field_characteristic: GOLDILOCKS_BASE_FIELD_MODULUS,
            extension_degree: QUINTIC_EXTENSION_DEGREE,
            main_code: cfw_main_code_instantiation,
            inner_mask_code: cfw_inner_code_instantiation,
            outer_mask_code: cfw_outer_code_instantiation,
            initial_randomness_element_count: cfw_reduction.initial_randomness_element_count(),
            per_round_randomness_element_count: cfw_reduction.per_round_randomness_element_count(),
            sumcheck_round_count: cfw_reduction.sumcheck_round_count(),
            joint_constraint_randomness_element_count: cfw_reduction
                .joint_constraint_randomness_element_count(),
            last_round_excluded_element_count: cfw_reduction.last_round_excluded_element_count(),
            query_count: 0,
            zero_evader_exponents: COMPACT_CFW_ZERO_EVADER_EXPONENTS,
            zero_evader_output_coordinate_count: u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            zero_evader_maximum_root_count: u64::from(
                COMPACT_CFW_ZERO_EVADER_EXPONENTS
                    .into_iter()
                    .max()
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
            ),
            theorem_list_size_multiplier: cfw_theorem_list_size_multiplier,
            theorem_initial_consistency_error,
            semantic_initial_consistency_error,
            sumcheck_round_errors,
            joint_zero_evader_error,
            initial_extraction_field_operation_bound: cfw_initial_extraction_field_operation_bound,
            per_sumcheck_extraction_field_operation_bound:
                cfw_mask_correction_field_operation_bound,
            joint_extraction_field_operation_bound: 0,
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
        let extraction_semantic_element_capacity = extractor_semantic_element_capacity(&codes)?;
        let mut transitions = Vec::with_capacity(chronology.verifier_moves().len());
        let mut maximum_extraction_field_operation_bound = 0_u128;
        let mut maximum_extraction_non_field_operation_bound = 0_u128;
        let mut maximum_extraction_operation_bound = 0_u128;
        let mut total_extraction_field_operation_bound = 0_u128;
        let mut total_extraction_non_field_operation_bound = 0_u128;
        let mut total_extraction_operation_bound = 0_u128;
        let mut maximum_per_move_extraction_error = ExactProbability::zero();
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
            if !extractor_steps_fit_source_audit(&extractor_steps) {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            let extraction_field_operation_bound =
                extractor_steps.iter().try_fold(0_u128, |bound, step| {
                    bound
                        .checked_add(extractor_step_bound(step, &codes)?)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
                })?;
            let extraction_work_bound = extractor_deterministic_work_bound(
                extraction_field_operation_bound,
                extraction_semantic_element_capacity,
            )?;
            total_extraction_field_operation_bound = total_extraction_field_operation_bound
                .checked_add(extraction_field_operation_bound)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            total_extraction_non_field_operation_bound = total_extraction_non_field_operation_bound
                .checked_add(extraction_work_bound.non_field_operation_bound)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            total_extraction_operation_bound = total_extraction_operation_bound
                .checked_add(extraction_work_bound.total_operation_bound)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            maximum_extraction_field_operation_bound =
                maximum_extraction_field_operation_bound.max(extraction_field_operation_bound);
            maximum_extraction_non_field_operation_bound =
                maximum_extraction_non_field_operation_bound
                    .max(extraction_work_bound.non_field_operation_bound);
            maximum_extraction_operation_bound =
                maximum_extraction_operation_bound.max(extraction_work_bound.total_operation_bound);
            let extraction_error = derive_independent_transition_error(
                verifier_move.roles(),
                relation,
                cfw_reduction,
                &codes,
                &whir_mca_bounds,
                pre_challenge_whir,
                main_whir,
            )?;
            if extraction_error.is_greater_than(&maximum_per_move_extraction_error) {
                maximum_per_move_extraction_error = extraction_error.clone();
            }
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
                extraction_non_field_operation_bound: extraction_work_bound
                    .non_field_operation_bound,
                extraction_operation_bound: extraction_work_bound.total_operation_bound,
                extraction_error,
            });
        }

        let catalog = Self {
            cfw,
            codes,
            whir_mca_bounds,
            transitions,
            composition_boundaries,
            input_implicit_instance_tuple_size: 0,
            output_implicit_instance_tuple_size: 0,
            maximum_per_move_extraction_error,
            maximum_extraction_field_operation_bound,
            maximum_extraction_non_field_operation_bound,
            maximum_extraction_operation_bound,
            total_extraction_field_operation_bound,
            total_extraction_non_field_operation_bound,
            total_extraction_operation_bound,
            extraction_semantic_element_capacity,
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
        let expected_main_code = code_by_role(&self.codes, CodeRole::CfwMain)?;
        let expected_inner_mask_code = code_by_role(&self.codes, CodeRole::CfwInnerMasks)?;
        let expected_outer_mask_code = code_by_role(&self.codes, CodeRole::CfwOuterMasks)?;
        let expected_main_code_instantiation = CfwCodeCorrectionInstantiation::from_selected_code(
            expected_main_code,
            expected_main_code.interleaving_width,
            1,
        )?;
        let expected_inner_mask_code_instantiation =
            CfwCodeCorrectionInstantiation::from_selected_code(
                expected_inner_mask_code,
                1,
                checked_product(&[
                    u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    u64::from(cfw_reduction.sumcheck_round_count()),
                ])?,
            )?;
        let expected_outer_mask_code_instantiation =
            CfwCodeCorrectionInstantiation::from_selected_code(
                expected_outer_mask_code,
                1,
                u64::from(cfw_reduction.sumcheck_round_count()),
            )?;
        let expected_theorem_list_size_multiplier = checked_product(&[
            expected_main_code_instantiation.list_size_bound,
            expected_inner_mask_code_instantiation.list_size_bound,
            expected_outer_mask_code_instantiation.list_size_bound,
        ])?;
        let expected_mask_correction_field_operation_bound = expected_inner_mask_code
            .correction_field_operation_bound
            .checked_add(expected_outer_mask_code.correction_field_operation_bound)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let expected_initial_extraction_field_operation_bound = expected_main_code
            .correction_field_operation_bound
            .checked_add(expected_mask_correction_field_operation_bound)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let expected_total_extraction_field_operation_bound =
            expected_initial_extraction_field_operation_bound
                .checked_add(
                    u128::from(cfw_reduction.sumcheck_round_count())
                        .checked_mul(expected_mask_correction_field_operation_bound)
                        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                )
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let expected_theorem_initial_consistency_error = ExactProbability::new(
            BigUint::from(
                expected_outer_mask_code_instantiation
                    .message_length
                    .checked_add(1)
                    .and_then(|numerator| {
                        numerator.checked_mul(expected_theorem_list_size_multiplier)
                    })
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
            extension_field_order(),
        )?;
        let expected_semantic_initial_consistency_error = ExactProbability::new(
            BigUint::from(cfw_reduction.initial_consistency_soundness_numerator()),
            extension_field_order(),
        )?;
        if self.cfw.relation_length != relation.padded_witness_element_count()
            || self.cfw.r1cs_public_input_length != relation.padded_witness_element_count()
            || !self.cfw.relation_length.is_power_of_two()
            || self.cfw.relation_length != self.cfw.r1cs_public_input_length
            || self.cfw.base_field_characteristic != GOLDILOCKS_BASE_FIELD_MODULUS
            || self.cfw.base_field_characteristic % 2 != 1
            || self.cfw.extension_degree != QUINTIC_EXTENSION_DEGREE
            || self.cfw.main_code != expected_main_code_instantiation
            || self.cfw.inner_mask_code != expected_inner_mask_code_instantiation
            || self.cfw.outer_mask_code != expected_outer_mask_code_instantiation
            || self.cfw.inner_mask_code.message_length
                != u64::try_from(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.outer_mask_code.message_length
                != u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.outer_mask_code.message_length < 2 * self.cfw.inner_mask_code.message_length
            || self.cfw.inner_mask_code.message_length < 4
            || self.cfw.main_code.encoding_randomness_length == 0
            || self.cfw.inner_mask_code.encoding_randomness_length == 0
            || self.cfw.outer_mask_code.encoding_randomness_length == 0
            || self.cfw.initial_randomness_element_count
                != cfw_reduction.initial_randomness_element_count()
            || self.cfw.per_round_randomness_element_count
                != cfw_reduction.per_round_randomness_element_count()
            || self.cfw.sumcheck_round_count != relation.padded_witness_element_count().ilog2() + 1
            || self.cfw.joint_constraint_randomness_element_count
                != cfw_reduction.joint_constraint_randomness_element_count()
            || self.cfw.last_round_excluded_element_count
                != cfw_reduction.last_round_excluded_element_count()
            || self.cfw.last_round_excluded_element_count
                != COMPACT_CFW_LAST_ROUND_EXCLUDED_ELEMENT_COUNT
            || self.cfw.query_count != 0
            || self.cfw.zero_evader_exponents != [0, 1, 2]
            || self.cfw.zero_evader_output_coordinate_count
                != u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.zero_evader_maximum_root_count
                != u64::from(
                    COMPACT_CFW_ZERO_EVADER_EXPONENTS
                        .into_iter()
                        .max()
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                )
            || self.cfw.theorem_list_size_multiplier != expected_theorem_list_size_multiplier
            || self.cfw.theorem_initial_consistency_error
                != expected_theorem_initial_consistency_error
            || self.cfw.semantic_initial_consistency_error
                != expected_semantic_initial_consistency_error
            || self.cfw.sumcheck_round_errors.len()
                != usize::try_from(cfw_reduction.sumcheck_round_count())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.cfw.joint_zero_evader_error
                != ExactProbability::new(
                    BigUint::from(
                        cfw_reduction
                            .joint_constraint_soundness_numerator()
                            .checked_mul(expected_theorem_list_size_multiplier)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                    ),
                    extension_field_order(),
                )?
            || self.cfw.main_code.list_size_bound != 1
            || self.cfw.inner_mask_code.list_size_bound != 1
            || self.cfw.outer_mask_code.list_size_bound != 1
            || self.cfw.initial_extraction_field_operation_bound
                != expected_initial_extraction_field_operation_bound
            || self.cfw.per_sumcheck_extraction_field_operation_bound
                != expected_mask_correction_field_operation_bound
            || self.cfw.joint_extraction_field_operation_bound != 0
            || self.cfw.total_extraction_field_operation_bound
                != expected_total_extraction_field_operation_bound
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
                    BigUint::from(
                        cfw_reduction
                            .per_round_soundness_numerator()
                            .checked_mul(expected_theorem_list_size_multiplier)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                    ),
                    denominator,
                )?
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        check_cfw_challenge_chronology(&self.cfw, chronology)?;
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
        let interpreted_extraction_semantic_element_capacity =
            extractor_semantic_element_capacity(&self.codes)?;
        let mut interpreted_total_extraction_field_operation_bound = 0_u128;
        let mut interpreted_total_extraction_non_field_operation_bound = 0_u128;
        let mut interpreted_total_extraction_operation_bound = 0_u128;
        let mut interpreted_maximum_extraction_field_operation_bound = 0_u128;
        let mut interpreted_maximum_extraction_non_field_operation_bound = 0_u128;
        let mut interpreted_maximum_extraction_operation_bound = 0_u128;
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
            let interpreted_extraction_work_bound = extractor_deterministic_work_bound(
                interpreted_extraction_field_operation_bound,
                interpreted_extraction_semantic_element_capacity,
            )?;
            let independently_derived_extraction_error = derive_independent_transition_error(
                verifier_move.roles(),
                relation,
                cfw_reduction,
                &self.codes,
                &self.whir_mca_bounds,
                pre_challenge_whir,
                main_whir,
            )?;
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
                || !extractor_steps_fit_source_audit(&transition.extractor_steps)
                || transition.extraction_field_operation_bound
                    != interpreted_extraction_field_operation_bound
                || transition.extraction_non_field_operation_bound
                    != interpreted_extraction_work_bound.non_field_operation_bound
                || transition.extraction_operation_bound
                    != interpreted_extraction_work_bound.total_operation_bound
                || transition.extraction_error != independently_derived_extraction_error
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
            interpreted_total_extraction_non_field_operation_bound =
                interpreted_total_extraction_non_field_operation_bound
                    .checked_add(interpreted_extraction_work_bound.non_field_operation_bound)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            interpreted_total_extraction_operation_bound =
                interpreted_total_extraction_operation_bound
                    .checked_add(interpreted_extraction_work_bound.total_operation_bound)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            interpreted_maximum_extraction_field_operation_bound =
                interpreted_maximum_extraction_field_operation_bound
                    .max(interpreted_extraction_field_operation_bound);
            interpreted_maximum_extraction_non_field_operation_bound =
                interpreted_maximum_extraction_non_field_operation_bound
                    .max(interpreted_extraction_work_bound.non_field_operation_bound);
            interpreted_maximum_extraction_operation_bound =
                interpreted_maximum_extraction_operation_bound
                    .max(interpreted_extraction_work_bound.total_operation_bound);
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
            || self.input_implicit_instance_tuple_size != 0
            || self.output_implicit_instance_tuple_size != 0
            || self.maximum_per_move_extraction_error
                != *interactive_soundness.maximum_verifier_move_failure()
            || self.maximum_per_move_extraction_error != interpreted_maximum_error
            || !self
                .maximum_per_move_extraction_error
                .is_at_most_inverse_power_of_two(INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL as usize)
            || self.cfw.total_extraction_field_operation_bound
                != interpreted_cfw_extraction_field_operation_bound
            || self.maximum_extraction_field_operation_bound
                != interpreted_maximum_extraction_field_operation_bound
            || self.maximum_extraction_field_operation_bound == 0
            || self.maximum_extraction_non_field_operation_bound
                != interpreted_maximum_extraction_non_field_operation_bound
            || self.maximum_extraction_operation_bound
                != interpreted_maximum_extraction_operation_bound
            || self.total_extraction_field_operation_bound
                != interpreted_total_extraction_field_operation_bound
            || self.total_extraction_non_field_operation_bound
                != interpreted_total_extraction_non_field_operation_bound
            || self.total_extraction_operation_bound != interpreted_total_extraction_operation_bound
            || self.extraction_semantic_element_capacity
                != interpreted_extraction_semantic_element_capacity
            || self.extraction_semantic_element_capacity == 0
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

    pub(super) const fn maximum_extraction_field_operation_bound(&self) -> u128 {
        self.maximum_extraction_field_operation_bound
    }

    pub(super) const fn maximum_extraction_operation_bound(&self) -> u128 {
        self.maximum_extraction_operation_bound
    }

    pub(super) fn check_factor_one_semantic_error_theorem(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &CfwReductionCatalog,
        pre_challenge_whir: &WhirStaticLedger,
        main_whir: &WhirStaticLedger,
    ) -> Result<(), CompactStaticCatalogError> {
        let theorem = semantic_relations::derive_factor_one_semantic_error_theorem(
            self,
            relation,
            cfw_reduction,
            pre_challenge_whir,
            main_whir,
        )?;
        if theorem.moves.len() != self.transitions.len()
            || theorem
                .moves
                .iter()
                .zip(&self.transitions)
                .any(|(semantic_move, transition)| {
                    semantic_move.verifier_move_ordinal != transition.verifier_move_ordinal
                        || semantic_move.total_probability != transition.extraction_error
                })
            || theorem.maximum_per_move_error != self.maximum_per_move_extraction_error
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

// Recompute each magnitude from operative code, challenge, and relation
// parameters without consulting the numerical event ledger. Equality with the
// ledger is a consistency check only; executable bad-transition certificates
// and their owning move bounds are checked separately by `semantic_relations`.
#[allow(clippy::too_many_arguments)]
fn derive_independent_transition_error(
    roles: &[VerifierMoveRole],
    relation: &CompactPublicKeyRelationCatalog,
    cfw_reduction: &CfwReductionCatalog,
    codes: &[UniqueDecodingCode],
    whir_mca_bounds: &[WhirMcaTransitionBound],
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<ExactProbability, CompactStaticCatalogError> {
    roles
        .iter()
        .try_fold(ExactProbability::zero(), |sum, role| {
            sum.add(&derive_independent_role_error(
                *role,
                relation,
                cfw_reduction,
                codes,
                whir_mca_bounds,
                pre_challenge_whir,
                main_whir,
            )?)
        })
}

#[allow(clippy::too_many_arguments)]
fn derive_independent_role_error(
    role: VerifierMoveRole,
    relation: &CompactPublicKeyRelationCatalog,
    cfw_reduction: &CfwReductionCatalog,
    codes: &[UniqueDecodingCode],
    whir_mca_bounds: &[WhirMcaTransitionBound],
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<ExactProbability, CompactStaticCatalogError> {
    let extension_field_order = extension_field_order();
    match role {
        VerifierMoveRole::LookupChallenge => ExactProbability::new(
            BigUint::from(relation.lookup_soundness_numerator()),
            extension_field_order
                .checked_sub(&BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS))
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
        ),
        VerifierMoveRole::CrossEpochPoint => ExactProbability::new(
            BigUint::from(CROSS_EPOCH_POINT_COORDINATE_COUNT),
            extension_field_order,
        ),
        VerifierMoveRole::CfwInitialRandomness => ExactProbability::new(
            BigUint::from(cfw_reduction.initial_consistency_soundness_numerator()),
            extension_field_order,
        ),
        VerifierMoveRole::CfwSumcheckRound { round_ordinal } => {
            if round_ordinal >= cfw_reduction.sumcheck_round_count() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            let denominator = if round_ordinal + 1 == cfw_reduction.sumcheck_round_count() {
                extension_field_order
                    .checked_sub(&BigUint::from(
                        cfw_reduction.last_round_excluded_element_count(),
                    ))
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?
            } else {
                extension_field_order
            };
            ExactProbability::new(
                BigUint::from(cfw_reduction.per_round_soundness_numerator()),
                denominator,
            )
        }
        VerifierMoveRole::CfwJointConstraint => ExactProbability::new(
            BigUint::from(cfw_reduction.joint_constraint_soundness_numerator()),
            extension_field_order,
        ),
        VerifierMoveRole::WhirOpeningBatching { epoch } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            ExactProbability::new(
                BigUint::from(
                    whir.opening_batching_claim_count
                        .checked_sub(1)
                        .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                ),
                extension_field_order,
            )
        }
        VerifierMoveRole::WhirMaskedSumcheckCombination { .. } => {
            ExactProbability::new(BigUint::one(), extension_field_order)
        }
        VerifierMoveRole::WhirFolding {
            epoch,
            batch_ordinal,
            round_ordinal,
        } => {
            let mut matches = whir_mca_bounds.iter().filter(|bound| {
                bound.epoch == epoch
                    && bound.batch_ordinal == batch_ordinal
                    && bound.round_ordinal == round_ordinal
            });
            let bound = matches
                .next()
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            if matches.next().is_some() {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            bound
                .exact_mca_error
                .add(&bound.exact_masked_sumcheck_error)
        }
        VerifierMoveRole::WhirRoundQueryAndCombination {
            epoch,
            round_ordinal,
        } => {
            let source_code = code_by_role(
                codes,
                CodeRole::WhirSource {
                    epoch,
                    batch_ordinal: round_ordinal,
                },
            )?;
            source_code
                .exact_query_failure()?
                .add(&ExactProbability::new(
                    BigUint::from(
                        source_code
                            .hiding_randomness_length
                            .checked_add(1)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                    ),
                    extension_field_order,
                )?)
        }
        VerifierMoveRole::WhirBaseCombination { epoch } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let mask_domain_size_sum =
                whir.mask_groups_in_commitment_order()
                    .try_fold(0_u64, |sum, group| {
                        sum.checked_add(group.domain_size)
                            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
                    })?;
            let numerator = whir.oracle_heights[WHIR_ROUND_COUNT]
                .checked_add(mask_domain_size_sum)
                .and_then(|value| value.checked_add(1))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            ExactProbability::new(BigUint::from(numerator), extension_field_order)
        }
        VerifierMoveRole::WhirFinalQueries { epoch } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let source_code = code_by_role(
                codes,
                CodeRole::WhirSource {
                    epoch,
                    batch_ordinal: u8::try_from(WHIR_ROUND_COUNT)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
            )?;
            let mut error = source_code.exact_query_failure()?;
            for group_ordinal in 0..whir.mask_groups_in_commitment_order().count() {
                error = error.add(
                    &code_by_role(
                        codes,
                        CodeRole::WhirMask {
                            epoch,
                            group_ordinal: u8::try_from(group_ordinal)
                                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                        },
                    )?
                    .exact_query_failure()?,
                )?;
            }
            Ok(error)
        }
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

fn check_cfw_challenge_chronology(
    cfw: &CfwRoundByRoundInstantiation,
    chronology: &PackingTranscriptChronology,
) -> Result<(), CompactStaticCatalogError> {
    let cfw_moves = chronology
        .verifier_moves()
        .iter()
        .filter(|verifier_move| verifier_move.roles().iter().any(is_cfw_role))
        .collect::<Vec<_>>();
    let expected_move_count = usize::try_from(cfw.sumcheck_round_count)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        .checked_add(2)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    if cfw_moves.len() != expected_move_count {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    let initial_move = cfw_moves
        .first()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if initial_move.roles() != [VerifierMoveRole::CfwInitialRandomness]
        || initial_move.challenge_space()
            != &(ExactChallengeSpace::ExtensionVector {
                element_count: cfw.initial_randomness_element_count,
                excluded_element_count: 0,
            })
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    for round_ordinal in 0..cfw.sumcheck_round_count {
        let move_index = usize::try_from(round_ordinal)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let round_move = cfw_moves
            .get(move_index)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let excluded_element_count = if round_ordinal + 1 == cfw.sumcheck_round_count {
            cfw.last_round_excluded_element_count
        } else {
            0
        };
        if round_move.roles() != [VerifierMoveRole::CfwSumcheckRound { round_ordinal }]
            || round_move.challenge_space()
                != &(ExactChallengeSpace::ExtensionVector {
                    element_count: cfw.per_round_randomness_element_count,
                    excluded_element_count,
                })
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
    }

    let joint_move = cfw_moves
        .last()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if joint_move.roles()
        != [
            VerifierMoveRole::CfwJointConstraint,
            VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::PreChallenge,
            },
        ]
        || joint_move.challenge_space()
            != &(ExactChallengeSpace::ExtensionVector {
                element_count: cfw
                    .joint_constraint_randomness_element_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
                excluded_element_count: 0,
            })
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn extractor_step_charges_failure(step: &ExtractorStep) -> bool {
    matches!(
        step,
        ExtractorStep::ReturnBottomUnderErrorBound | ExtractorStep::CodeOperation(_)
    )
}

fn check_cfw_transition_error(
    transition: &KnowledgeTransition,
    cfw: &CfwRoundByRoundInstantiation,
) -> Result<(), CompactStaticCatalogError> {
    for role in &transition.roles {
        match role {
            VerifierMoveRole::CfwInitialRandomness => {
                if transition.extraction_error != cfw.semantic_initial_consistency_error {
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
        for batch_ordinal in 0..WHIR_FOLD_BATCH_COUNT {
            let target_domain_size = whir.oracle_heights[batch_ordinal];
            if target_domain_size == 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            for round_ordinal in 0..whir.folding_schedule[batch_ordinal] {
                // The production batch stores the intermediate functions as
                // correlated columns over its final committed row domain.
                // A binary fold therefore invokes Corollary 4.11 on that
                // same code at every internal challenge. With two correlated
                // functions the MCA term is `(2 - 1) * |L| / |F|`; the
                // masked sumcheck contributes its separate degree term.
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
            whir.mask_query_count,
        )?);
    }
    Ok(())
}

fn code_from_mask_group(
    role: CodeRole,
    group: &MaskGroupStaticLedger,
    query_count: u64,
) -> Result<UniqueDecodingCode, CompactStaticCatalogError> {
    UniqueDecodingCode::derive(
        role,
        group.message_length,
        group.randomness_length,
        query_count,
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
            main_whir.oracle_widths[0],
            0,
            WhirClaimShape::UnbatchedInput,
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
        let sumcheck_mask_count = round_ordinal
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let code_switch_mask_count = sumcheck_mask_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        boundaries.push(SequentialCompositionBoundary {
            role: CompositionBoundaryRole::MaskedSumcheckToCodeSwitch {
                epoch,
                round_ordinal: u8::try_from(round_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            left_output_relation: whir_relation_from_codes(
                codes,
                epoch,
                whir,
                round_ordinal,
                1,
                sumcheck_mask_count,
                WhirClaimShape::Batched,
            )?,
            right_input_relation: whir_relation_from_codes(
                codes,
                epoch,
                whir,
                round_ordinal,
                1,
                sumcheck_mask_count,
                WhirClaimShape::Batched,
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
                whir.oracle_widths[round_ordinal + 1],
                code_switch_mask_count,
                WhirClaimShape::Batched,
            )?,
            right_input_relation: whir_relation_from_codes(
                codes,
                epoch,
                whir,
                round_ordinal + 1,
                whir.oracle_widths[round_ordinal + 1],
                code_switch_mask_count,
                WhirClaimShape::Batched,
            )?,
        });
    }
    let final_internal_mask_count = whir.internal_mask_groups.len();
    boundaries.push(SequentialCompositionBoundary {
        role: CompositionBoundaryRole::FinalMaskedSumcheckToBase { epoch },
        left_output_relation: whir_relation_from_codes(
            codes,
            epoch,
            whir,
            WHIR_ROUND_COUNT,
            1,
            final_internal_mask_count,
            WhirClaimShape::Batched,
        )?,
        right_input_relation: whir_relation_from_codes(
            codes,
            epoch,
            whir,
            WHIR_ROUND_COUNT,
            1,
            final_internal_mask_count,
            WhirClaimShape::Batched,
        )?,
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WhirClaimShape {
    UnbatchedInput,
    Batched,
}

fn whir_relation_from_codes(
    codes: &[UniqueDecodingCode],
    epoch: TranscriptEpoch,
    whir: &WhirStaticLedger,
    batch_ordinal: usize,
    source_interleaving_width: u64,
    included_internal_mask_group_count: usize,
    claim_shape: WhirClaimShape,
) -> Result<GeneralizedCommittedRelation, CompactStaticCatalogError> {
    let source_code = code_by_role(
        codes,
        CodeRole::WhirSource {
            epoch,
            batch_ordinal: u8::try_from(batch_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        },
    )?;
    if (source_interleaving_width != 1
        && source_interleaving_width != source_code.interleaving_width)
        || included_internal_mask_group_count > whir.internal_mask_groups.len()
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let source_message_element_count =
        checked_product(&[source_interleaving_width, source_code.message_length])?;
    let source_hiding_element_count = checked_product(&[
        source_interleaving_width,
        source_code.hiding_randomness_length,
    ])?;
    let last_mask_ordinal = whir
        .external_mask_groups
        .len()
        .checked_add(included_internal_mask_group_count)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
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
    let (opening_evaluation_claim_count, carried_reduction_claim_count, claim_count) =
        match claim_shape {
            WhirClaimShape::UnbatchedInput => {
                let claim_count = checked_add(
                    whir.opening_evaluation_count,
                    whir.external_generalized_relation_claim_count,
                )?;
                if included_internal_mask_group_count != 0
                    || source_interleaving_width != source_code.interleaving_width
                    || claim_count != whir.opening_batching_claim_count
                {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
                (
                    whir.opening_evaluation_count,
                    whir.external_generalized_relation_claim_count,
                    claim_count,
                )
            }
            // Once the opening claims have been alpha-batched, every WHIR
            // component carries one committed linear relation. Sumcheck and
            // code switching change its source and mask witnesses, but they
            // do not resurrect the pre-batching claim vector.
            WhirClaimShape::Batched => (0, 1, 1),
        };
    Ok(GeneralizedCommittedRelation {
        source_code: committed_code_relation(
            source_code.message_length,
            source_code.hiding_randomness_length,
            source_code.block_length,
            source_interleaving_width,
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
            append_code_operation(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                CodeRole::WhirSource {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                },
                pre_challenge_whir.oracle_widths[0],
            );
        }
        VerifierMoveRole::CrossEpochPoint => {
            if state.outer != OuterRelaxedRelation::LookupIdentityBound {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.outer = OuterRelaxedRelation::CrossEpochEqualityBound;
            extractor_steps.push(ExtractorStep::ReturnBottomUnderErrorBound);
            append_code_operation(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                CodeRole::WhirSource {
                    epoch: TranscriptEpoch::PreChallenge,
                    batch_ordinal: 0,
                },
                pre_challenge_whir.oracle_widths[0],
            );
            append_code_operation(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                CodeRole::CfwMain,
                main_whir.oracle_widths[0],
            );
            let shared_mask_group_ordinal =
                mask_group_ordinal(pre_challenge_whir, MaskGroupRole::CrossEpochOpening)?;
            let shared_mask_group = pre_challenge_whir
                .mask_groups_in_commitment_order()
                .nth(shared_mask_group_ordinal)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            append_code_operation(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                CodeRole::WhirMask {
                    epoch: TranscriptEpoch::PreChallenge,
                    group_ordinal: u8::try_from(shared_mask_group_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
                shared_mask_group.width,
            );
        }
        VerifierMoveRole::CfwInitialRandomness => {
            if !matches!(state.cfw, CfwRelaxedRelation::InputR1cs { .. }) {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            state.cfw = CfwRelaxedRelation::InitialMaskedClaim;
            for role in [
                CodeRole::CfwMain,
                CodeRole::CfwInnerMasks,
                CodeRole::CfwOuterMasks,
            ] {
                append_code_operation(
                    extractor_steps,
                    ExtractorCodeOperationKind::Decode,
                    role,
                    code_interleaving_width_for_role(role, pre_challenge_whir, main_whir)?,
                );
            }
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
            for role in [CodeRole::CfwInnerMasks, CodeRole::CfwOuterMasks] {
                append_code_operation(
                    extractor_steps,
                    ExtractorCodeOperationKind::Decode,
                    role,
                    code_interleaving_width_for_role(role, pre_challenge_whir, main_whir)?,
                );
            }
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
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
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
            append_whir_generalized_code_operations(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                epoch,
                batch_ordinal,
                whir.oracle_widths[usize::from(batch_ordinal)],
                whir.external_mask_groups.len() + 2 * usize::from(batch_ordinal),
                whir,
            )?;
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
            let preceding_source_width = whir.oracle_widths[usize::from(batch_ordinal)]
                .checked_shr(u32::from(round_ordinal))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            append_whir_generalized_code_operations(
                extractor_steps,
                ExtractorCodeOperationKind::Decode,
                epoch,
                batch_ordinal,
                preceding_source_width,
                whir.external_mask_groups.len() + 2 * usize::from(batch_ordinal) + 1,
                whir,
            )?;
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
            append_code_operation(
                extractor_steps,
                ExtractorCodeOperationKind::Encode,
                CodeRole::WhirSource {
                    epoch,
                    batch_ordinal: round_ordinal,
                },
                1,
            );
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
            let final_batch_ordinal = u8::try_from(WHIR_ROUND_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            let mut roles_and_widths = vec![(
                CodeRole::WhirSource {
                    epoch,
                    batch_ordinal: final_batch_ordinal,
                },
                1,
            )];
            for (group_ordinal, group) in whir.mask_groups_in_commitment_order().enumerate() {
                roles_and_widths.push((
                    CodeRole::WhirMask {
                        epoch,
                        group_ordinal: u8::try_from(group_ordinal)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    },
                    group.width,
                ));
            }
            // The executable base extractor first re-encodes every blinded
            // oracle. Its pair reconstruction then re-encodes the same
            // canonical post word and erasure-corrects both committed sides.
            for (role, width) in roles_and_widths {
                for kind in [
                    ExtractorCodeOperationKind::Encode,
                    ExtractorCodeOperationKind::Encode,
                    ExtractorCodeOperationKind::ErasureCorrect,
                    ExtractorCodeOperationKind::ErasureCorrect,
                ] {
                    append_code_operation(extractor_steps, kind, role, width);
                }
            }
        }
        VerifierMoveRole::WhirFinalQueries { epoch } => {
            let whir = whir_for_epoch(epoch, pre_challenge_whir, main_whir);
            let whir_state = whir_state_mut(state, epoch);
            if *whir_state != WhirRelaxedRelation::BaseCombined {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            *whir_state = WhirRelaxedRelation::OutputTrivial;
            append_whir_generalized_code_operations(
                extractor_steps,
                ExtractorCodeOperationKind::Encode,
                epoch,
                u8::try_from(WHIR_ROUND_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                1,
                whir.mask_groups_in_commitment_order().count(),
                whir,
            )?;
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

fn append_code_operation(
    extractor_steps: &mut Vec<ExtractorStep>,
    kind: ExtractorCodeOperationKind,
    role: CodeRole,
    interleaving_width: u64,
) {
    extractor_steps.push(ExtractorStep::CodeOperation(ExtractorCodeOperation {
        kind,
        role,
        interleaving_width,
    }));
}

fn append_whir_generalized_code_operations(
    extractor_steps: &mut Vec<ExtractorStep>,
    kind: ExtractorCodeOperationKind,
    epoch: TranscriptEpoch,
    batch_ordinal: u8,
    source_interleaving_width: u64,
    included_mask_group_count: usize,
    whir: &WhirStaticLedger,
) -> Result<(), CompactStaticCatalogError> {
    if usize::from(batch_ordinal) >= WHIR_FOLD_BATCH_COUNT
        || source_interleaving_width == 0
        || included_mask_group_count > whir.mask_groups_in_commitment_order().count()
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    append_code_operation(
        extractor_steps,
        kind,
        CodeRole::WhirSource {
            epoch,
            batch_ordinal,
        },
        source_interleaving_width,
    );
    for (group_ordinal, group) in whir
        .mask_groups_in_commitment_order()
        .take(included_mask_group_count)
        .enumerate()
    {
        append_code_operation(
            extractor_steps,
            kind,
            CodeRole::WhirMask {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            group.width,
        );
    }
    Ok(())
}

fn mask_group_ordinal(
    whir: &WhirStaticLedger,
    role: MaskGroupRole,
) -> Result<usize, CompactStaticCatalogError> {
    let mut matches = whir
        .mask_groups_in_commitment_order()
        .enumerate()
        .filter_map(|(ordinal, group)| (group.role == role).then_some(ordinal));
    let ordinal = matches
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if matches.next().is_some() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(ordinal)
}

fn code_interleaving_width_for_role(
    role: CodeRole,
    pre_challenge_whir: &WhirStaticLedger,
    main_whir: &WhirStaticLedger,
) -> Result<u64, CompactStaticCatalogError> {
    match role {
        CodeRole::CfwMain => Ok(main_whir.oracle_widths[0]),
        CodeRole::CfwInnerMasks => main_whir
            .mask_groups_in_commitment_order()
            .find(|group| group.role == MaskGroupRole::CfwInner)
            .map(|group| group.width)
            .ok_or(CompactStaticCatalogError::InvalidGeometry),
        CodeRole::CfwOuterMasks => main_whir
            .mask_groups_in_commitment_order()
            .find(|group| group.role == MaskGroupRole::CfwOuter)
            .map(|group| group.width)
            .ok_or(CompactStaticCatalogError::InvalidGeometry),
        CodeRole::WhirSource {
            epoch,
            batch_ordinal,
        } => whir_for_epoch(epoch, pre_challenge_whir, main_whir)
            .oracle_widths
            .get(usize::from(batch_ordinal))
            .copied()
            .ok_or(CompactStaticCatalogError::InvalidGeometry),
        CodeRole::WhirMask {
            epoch,
            group_ordinal,
        } => whir_for_epoch(epoch, pre_challenge_whir, main_whir)
            .mask_groups_in_commitment_order()
            .nth(usize::from(group_ordinal))
            .map(|group| group.width)
            .ok_or(CompactStaticCatalogError::InvalidGeometry),
    }
}

fn extractor_step_bound(
    step: &ExtractorStep,
    codes: &[UniqueDecodingCode],
) -> Result<u128, CompactStaticCatalogError> {
    match step {
        ExtractorStep::ReturnBottomUnderErrorBound => Ok(0),
        ExtractorStep::CodeOperation(operation) => {
            let code = code_by_role(codes, operation.role)?;
            let geometry = CanonicalReedSolomonGeometry::new(
                usize::try_from(code.message_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                usize::try_from(code.hiding_randomness_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                usize::try_from(code.block_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                usize::try_from(operation.interleaving_width)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
            match operation.kind {
                ExtractorCodeOperationKind::Decode => geometry
                    .decoding_field_operation_bound()
                    .map_err(map_canonical_code_error),
                ExtractorCodeOperationKind::Encode => geometry
                    .encoding_field_operation_count()
                    .map_err(map_canonical_code_error),
                ExtractorCodeOperationKind::ErasureCorrect => geometry
                    .erasure_correction_field_operation_bound(geometry.block_length())
                    .map_err(map_canonical_code_error),
            }
        }
    }
}

fn extractor_semantic_element_capacity(
    codes: &[UniqueDecodingCode],
) -> Result<u128, CompactStaticCatalogError> {
    let canonical_code_element_capacity = codes.iter().try_fold(
        0_u128,
        |capacity, code| -> Result<_, CompactStaticCatalogError> {
            let interleaving_width = u128::from(code.interleaving_width);
            let committed_instance_element_count = u128::from(code.block_length)
                .checked_mul(interleaving_width)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let witness_element_count = u128::from(code.dimension)
                .checked_mul(interleaving_width)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            capacity
                .checked_add(committed_instance_element_count)
                .and_then(|count| count.checked_add(witness_element_count))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
        },
    )?;
    if canonical_code_element_capacity == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    // At most four simultaneous representations are reachable on a local
    // path: the borrowed statement/prefix, the post witness, canonical code
    // workspace/output, and the predecessor witness. Completed histories are
    // not replayed or copied by `ERRBR`.
    canonical_code_element_capacity
        .checked_mul(4)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

fn extractor_deterministic_work_bound(
    field_operation_bound: u128,
    semantic_element_capacity: u128,
) -> Result<ExtractorDeterministicWorkBound, CompactStaticCatalogError> {
    if semantic_element_capacity == 0
        || MAXIMUM_AUDITED_ELEMENT_PASSES
            .checked_mul(MAXIMUM_WORD_OPERATIONS_PER_ELEMENT_PASS)
            .is_none_or(|audited_word_operations| {
                audited_word_operations > MAXIMUM_WORD_OPERATIONS_PER_SEMANTIC_ELEMENT
            })
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let field_bookkeeping_word_operation_bound = field_operation_bound
        .checked_mul(MAXIMUM_WORD_BOOKKEEPING_PER_FIELD_OPERATION)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let semantic_element_word_operation_bound = semantic_element_capacity
        .checked_mul(MAXIMUM_WORD_OPERATIONS_PER_SEMANTIC_ELEMENT)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let straight_line_word_operation_bound = MAXIMUM_STRAIGHT_LINE_WORD_OPERATIONS;
    let non_field_operation_bound = field_bookkeeping_word_operation_bound
        .checked_add(semantic_element_word_operation_bound)
        .and_then(|bound| bound.checked_add(straight_line_word_operation_bound))
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    let total_operation_bound = field_operation_bound
        .checked_add(non_field_operation_bound)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    Ok(ExtractorDeterministicWorkBound {
        field_operation_bound,
        field_bookkeeping_word_operation_bound,
        semantic_element_word_operation_bound,
        straight_line_word_operation_bound,
        non_field_operation_bound,
        total_operation_bound,
    })
}

fn extractor_steps_fit_source_audit(steps: &[ExtractorStep]) -> bool {
    let mut operation_counts_by_role = Vec::<(CodeRole, usize)>::new();
    for operation in steps.iter().filter_map(|step| match step {
        ExtractorStep::CodeOperation(operation) => Some(operation),
        ExtractorStep::ReturnBottomUnderErrorBound => None,
    }) {
        if let Some((_, count)) = operation_counts_by_role
            .iter_mut()
            .find(|(role, _)| *role == operation.role)
        {
            *count += 1;
            if *count > MAXIMUM_CODE_OPERATIONS_PER_ORACLE {
                return false;
            }
        } else {
            operation_counts_by_role.push((operation.role, 1));
        }
    }
    true
}

fn map_canonical_code_error(error: CanonicalReedSolomonError) -> CompactStaticCatalogError {
    match error {
        CanonicalReedSolomonError::ArithmeticOverflow => {
            CompactStaticCatalogError::ArithmeticOverflow
        }
        _ => CompactStaticCatalogError::InvalidGeometry,
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
    use crate::bgv::proof_suite::compact_public_key_static_catalog::canonical_reed_solomon::encode_canonical_interleaved_reed_solomon;
    use crate::bgv::proof_suite::{ProofBaseFieldElement, ProofChallengeExtensionElement};

    fn small_semantic_field_element(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value)
                .expect("small semantic field element is canonical"),
        )
    }

    #[test]
    fn deterministic_extractor_executes_canonical_correction_within_its_field_operation_bound() {
        let code = UniqueDecodingCode::derive(CodeRole::CfwMain, 2, 1, 1, 8, 3)
            .expect("small semantic code derives");
        let coefficient_columns = vec![
            vec![
                small_semantic_field_element(3),
                small_semantic_field_element(5),
                small_semantic_field_element(7),
            ],
            vec![
                small_semantic_field_element(11),
                small_semantic_field_element(13),
                small_semantic_field_element(17),
            ],
            vec![
                small_semantic_field_element(19),
                small_semantic_field_element(23),
                small_semantic_field_element(29),
            ],
        ];
        let mut received_rows = encode_canonical_interleaved_reed_solomon(
            code.decoder_geometry()
                .expect("small decoder geometry derives"),
            &coefficient_columns,
        )
        .expect("small semantic codeword encodes");
        received_rows[1][0] = received_rows[1][0].add(small_semantic_field_element(31));
        received_rows[6][2] = received_rows[6][2].add(small_semantic_field_element(37));

        let decoded = code
            .decode_received_rows(&received_rows)
            .expect("the deterministic extractor corrects the maximum two shared row errors");
        assert_eq!(
            decoded.message_columns(),
            coefficient_columns
                .iter()
                .map(|column| column[..2].to_vec())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.hiding_randomness_columns(),
            coefficient_columns
                .iter()
                .map(|column| column[2..].to_vec())
                .collect::<Vec<_>>()
        );
        assert!(
            decoded.field_operation_count() <= code.correction_field_operation_bound,
            "the executed correction exceeded the theorem's explicit field-operation ceiling"
        );
    }

    #[test]
    fn semantic_query_escape_uses_the_exact_distinct_query_distribution() {
        let code = UniqueDecodingCode::derive(CodeRole::CfwMain, 3, 2, 2, 8, 1)
            .expect("small semantic code derives");
        let exact_without_replacement =
            ExactProbability::new(BigUint::from(6_u8 * 5), BigUint::from(8_u8 * 7))
                .expect("exact distinct-query probability derives");
        let independent_with_replacement =
            ExactProbability::new(BigUint::from(7_u8).pow(2), BigUint::from(8_u8).pow(2))
                .expect("comparison probability derives");

        assert_eq!(
            code.exact_query_failure().unwrap(),
            exact_without_replacement
        );
        assert_ne!(exact_without_replacement, independent_with_replacement);
    }

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
        assert_eq!(theorem.cfw.main_code.role, CodeRole::CfwMain);
        assert_eq!(theorem.cfw.main_code.repeated_encoding_count, 1);
        assert_eq!(theorem.cfw.inner_mask_code.message_length, 4);
        assert_eq!(theorem.cfw.inner_mask_code.repeated_encoding_count, 69);
        assert_eq!(theorem.cfw.inner_mask_code.base_alphabet_extension_width, 1);
        assert_eq!(theorem.cfw.outer_mask_code.message_length, 8);
        assert_eq!(theorem.cfw.outer_mask_code.repeated_encoding_count, 23);
        assert_eq!(theorem.cfw.outer_mask_code.base_alphabet_extension_width, 1);
        for code in [
            &theorem.cfw.main_code,
            &theorem.cfw.inner_mask_code,
            &theorem.cfw.outer_mask_code,
        ] {
            assert_eq!(
                code.dimension,
                code.message_length + code.encoding_randomness_length
            );
            assert_eq!(
                code.interleaved_width,
                code.base_alphabet_extension_width * code.repeated_encoding_count
            );
            assert_eq!(
                code.selected_decoding_error_count,
                (code.block_length - code.dimension - 1) / 2
            );
            assert_eq!(
                code.maximum_bad_agreement_count,
                code.block_length - code.selected_decoding_error_count - 1
            );
            assert_eq!(
                code.correction_algorithm,
                DeterministicCorrectionAlgorithm::CanonicalBerlekampWelch
            );
            assert!(code.correction_field_operation_bound > 0);
        }
        assert_eq!(theorem.cfw.zero_evader_exponents, [0, 1, 2]);
        assert_eq!(theorem.cfw.zero_evader_output_coordinate_count, 3);
        assert_eq!(theorem.cfw.zero_evader_maximum_root_count, 2);
        assert_eq!(theorem.cfw.theorem_list_size_multiplier, 1);
        let field_order = extension_field_order();
        assert_eq!(
            theorem.cfw.theorem_initial_consistency_error,
            ExactProbability::new(BigUint::from(9_u8), field_order.clone())
                .expect("stated CFW theorem initial error")
        );
        assert_eq!(
            theorem.cfw.semantic_initial_consistency_error,
            ExactProbability::new(BigUint::from(24_u8), field_order.clone())
                .expect("semantic initial CFW error")
        );
        assert_ne!(
            theorem.cfw.theorem_initial_consistency_error,
            theorem.cfw.semantic_initial_consistency_error,
            "the tighter published coordinate cannot replace the executable semantic bound"
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
        assert_eq!(theorem.cfw.main_code.list_size_bound, 1);
        assert_eq!(theorem.cfw.inner_mask_code.list_size_bound, 1);
        assert_eq!(theorem.cfw.outer_mask_code.list_size_bound, 1);
        assert_eq!(theorem.cfw.joint_extraction_field_operation_bound, 0);
        assert_eq!(
            theorem.cfw.total_extraction_field_operation_bound,
            theorem.cfw.initial_extraction_field_operation_bound
                + u128::from(theorem.cfw.sumcheck_round_count)
                    * theorem.cfw.per_sumcheck_extraction_field_operation_bound
        );
        assert_eq!(theorem.input_implicit_instance_tuple_size, 0);
        assert_eq!(theorem.output_implicit_instance_tuple_size, 0);
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
        assert_eq!(
            theorem.total_extraction_field_operation_bound,
            2_152_842_506_562_617_882
        );
        assert_eq!(
            theorem.maximum_extraction_field_operation_bound,
            432_349_246_225_014_321
        );
        assert_eq!(theorem.extraction_semantic_element_capacity, 214_588_832);
        assert_eq!(
            theorem.maximum_extraction_non_field_operation_bound,
            442_725_628_354_153_629_696
        );
        assert_eq!(
            theorem.maximum_extraction_operation_bound,
            443_157_977_600_378_644_017
        );
        assert_eq!(
            theorem.total_extraction_non_field_operation_bound,
            2_204_510_744_738_715_840_512
        );
        assert_eq!(
            theorem.total_extraction_operation_bound,
            2_206_663_587_245_278_458_394
        );
        assert_eq!(
            theorem.maximum_extraction_operation_bound,
            theorem.maximum_extraction_field_operation_bound
                + theorem.maximum_extraction_non_field_operation_bound
        );
        assert_eq!(
            theorem.total_extraction_operation_bound,
            theorem.total_extraction_field_operation_bound
                + theorem.total_extraction_non_field_operation_bound
        );
        assert!(
            theorem.maximum_extraction_non_field_operation_bound
                > theorem.maximum_extraction_field_operation_bound
        );
        assert_eq!(MAXIMUM_AUDITED_ELEMENT_PASSES, 60);
        assert_eq!(
            MAXIMUM_AUDITED_ELEMENT_PASSES * MAXIMUM_WORD_OPERATIONS_PER_ELEMENT_PASS,
            960
        );
        assert!(
            MAXIMUM_AUDITED_ELEMENT_PASSES * MAXIMUM_WORD_OPERATIONS_PER_ELEMENT_PASS
                <= MAXIMUM_WORD_OPERATIONS_PER_SEMANTIC_ELEMENT
        );
        assert!(theorem.transitions.iter().all(|transition| {
            extractor_deterministic_work_bound(
                transition.extraction_field_operation_bound,
                theorem.extraction_semantic_element_capacity,
            )
            .is_ok_and(|bound| {
                bound.field_operation_bound == transition.extraction_field_operation_bound
                    && bound.field_bookkeeping_word_operation_bound
                        == transition.extraction_field_operation_bound
                            * MAXIMUM_WORD_BOOKKEEPING_PER_FIELD_OPERATION
                    && bound.semantic_element_word_operation_bound
                        == theorem.extraction_semantic_element_capacity
                            * MAXIMUM_WORD_OPERATIONS_PER_SEMANTIC_ELEMENT
                    && bound.straight_line_word_operation_bound
                        == MAXIMUM_STRAIGHT_LINE_WORD_OPERATIONS
                    && transition.extraction_non_field_operation_bound
                        == bound.non_field_operation_bound
                    && transition.extraction_operation_bound == bound.total_operation_bound
            })
        }));
        let code_operations = |transition: &KnowledgeTransition| {
            transition
                .extractor_steps
                .iter()
                .filter_map(|step| match step {
                    ExtractorStep::CodeOperation(operation) => Some(*operation),
                    ExtractorStep::ReturnBottomUnderErrorBound => None,
                })
                .collect::<Vec<_>>()
        };
        let lookup_operations = code_operations(&theorem.transitions[0]);
        assert_eq!(lookup_operations.len(), 1);
        assert_eq!(
            lookup_operations[0].kind,
            ExtractorCodeOperationKind::Decode
        );
        assert_eq!(
            lookup_operations[0].role,
            CodeRole::WhirSource {
                epoch: TranscriptEpoch::PreChallenge,
                batch_ordinal: 0,
            }
        );
        let unaudited_lookup_path = (0..=MAXIMUM_CODE_OPERATIONS_PER_ORACLE)
            .map(|_| ExtractorStep::CodeOperation(lookup_operations[0]))
            .collect::<Vec<_>>();
        assert!(!extractor_steps_fit_source_audit(&unaudited_lookup_path));
        let cross_epoch_operations = code_operations(&theorem.transitions[1]);
        assert_eq!(cross_epoch_operations.len(), 3);
        assert!(
            cross_epoch_operations
                .iter()
                .all(|operation| operation.kind == ExtractorCodeOperationKind::Decode)
        );
        for transition in &theorem.transitions {
            match transition.roles.as_slice() {
                [
                    VerifierMoveRole::WhirMaskedSumcheckCombination {
                        epoch,
                        batch_ordinal,
                    },
                ] => {
                    let whir = whir_for_epoch(
                        *epoch,
                        &factor_one.pre_challenge_whir,
                        &factor_one.main_whir,
                    );
                    let operations = code_operations(transition);
                    assert_eq!(
                        operations.len(),
                        1 + whir.external_mask_groups.len() + 2 * usize::from(*batch_ordinal)
                    );
                    assert!(
                        operations
                            .iter()
                            .all(|operation| operation.kind == ExtractorCodeOperationKind::Decode)
                    );
                }
                [
                    VerifierMoveRole::WhirFolding {
                        epoch,
                        batch_ordinal,
                        round_ordinal,
                    },
                ] => {
                    let whir = whir_for_epoch(
                        *epoch,
                        &factor_one.pre_challenge_whir,
                        &factor_one.main_whir,
                    );
                    let operations = code_operations(transition);
                    assert_eq!(
                        operations.len(),
                        2 + whir.external_mask_groups.len() + 2 * usize::from(*batch_ordinal)
                    );
                    assert_eq!(
                        operations[0].interleaving_width,
                        whir.oracle_widths[usize::from(*batch_ordinal)]
                            >> u32::from(*round_ordinal)
                    );
                    assert!(
                        operations
                            .iter()
                            .all(|operation| operation.kind == ExtractorCodeOperationKind::Decode)
                    );
                }
                [
                    VerifierMoveRole::WhirRoundQueryAndCombination {
                        epoch,
                        round_ordinal,
                    },
                ] => {
                    assert_eq!(
                        code_operations(transition),
                        vec![ExtractorCodeOperation {
                            kind: ExtractorCodeOperationKind::Encode,
                            role: CodeRole::WhirSource {
                                epoch: *epoch,
                                batch_ordinal: *round_ordinal,
                            },
                            interleaving_width: 1,
                        }]
                    );
                }
                [VerifierMoveRole::WhirBaseCombination { epoch }] => {
                    let whir = whir_for_epoch(
                        *epoch,
                        &factor_one.pre_challenge_whir,
                        &factor_one.main_whir,
                    );
                    let operations = code_operations(transition);
                    assert_eq!(
                        operations.len(),
                        4 * (1 + whir.mask_groups_in_commitment_order().count())
                    );
                    assert!(operations.chunks_exact(4).all(|operations| {
                        operations[0].kind == ExtractorCodeOperationKind::Encode
                            && operations[1].kind == ExtractorCodeOperationKind::Encode
                            && operations[2].kind == ExtractorCodeOperationKind::ErasureCorrect
                            && operations[3].kind == ExtractorCodeOperationKind::ErasureCorrect
                    }));
                }
                [VerifierMoveRole::WhirFinalQueries { epoch }] => {
                    let whir = whir_for_epoch(
                        *epoch,
                        &factor_one.pre_challenge_whir,
                        &factor_one.main_whir,
                    );
                    let operations = code_operations(transition);
                    assert_eq!(
                        operations.len(),
                        1 + whir.mask_groups_in_commitment_order().count()
                    );
                    assert!(
                        operations
                            .iter()
                            .all(|operation| operation.kind == ExtractorCodeOperationKind::Encode)
                    );
                }
                [
                    VerifierMoveRole::WhirFinalQueries {
                        epoch: TranscriptEpoch::PreChallenge,
                    },
                    VerifierMoveRole::WhirOpeningBatching {
                        epoch: TranscriptEpoch::Main,
                    },
                ] => {
                    let whir = &factor_one.pre_challenge_whir;
                    let operations = code_operations(transition);
                    assert_eq!(
                        operations.len(),
                        1 + whir.mask_groups_in_commitment_order().count()
                    );
                    assert!(
                        operations
                            .iter()
                            .all(|operation| operation.kind == ExtractorCodeOperationKind::Encode)
                    );
                }
                _ => {}
            }
        }
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

        for (epoch, whir) in [
            (
                TranscriptEpoch::PreChallenge,
                &factor_one.pre_challenge_whir,
            ),
            (TranscriptEpoch::Main, &factor_one.main_whir),
        ] {
            for round_ordinal in 0..WHIR_ROUND_COUNT {
                let sumcheck_boundary = theorem
                    .composition_boundaries
                    .iter()
                    .find(|boundary| {
                        boundary.role
                            == CompositionBoundaryRole::MaskedSumcheckToCodeSwitch {
                                epoch,
                                round_ordinal: u8::try_from(round_ordinal)
                                    .expect("WHIR round ordinal fits in u8"),
                            }
                    })
                    .expect("masked-sumcheck composition boundary");
                assert_eq!(
                    sumcheck_boundary
                        .left_output_relation
                        .source_code
                        .interleaving_width,
                    1
                );
                assert_eq!(
                    sumcheck_boundary.left_output_relation.mask_codes.len(),
                    whir.external_mask_groups.len() + round_ordinal * 2 + 1
                );
                assert_eq!(
                    (
                        sumcheck_boundary
                            .left_output_relation
                            .opening_evaluation_claim_count,
                        sumcheck_boundary
                            .left_output_relation
                            .carried_reduction_claim_count,
                        sumcheck_boundary.left_output_relation.claim_count,
                    ),
                    (0, 1, 1)
                );

                let code_switch_boundary = theorem
                    .composition_boundaries
                    .iter()
                    .find(|boundary| {
                        boundary.role
                            == CompositionBoundaryRole::CodeSwitchToNextMaskedSumcheck {
                                epoch,
                                round_ordinal: u8::try_from(round_ordinal)
                                    .expect("WHIR round ordinal fits in u8"),
                            }
                    })
                    .expect("code-switch composition boundary");
                assert_eq!(
                    code_switch_boundary
                        .left_output_relation
                        .source_code
                        .interleaving_width,
                    whir.oracle_widths[round_ordinal + 1]
                );
                assert_eq!(
                    code_switch_boundary.left_output_relation.mask_codes.len(),
                    whir.external_mask_groups.len() + round_ordinal * 2 + 2
                );
                assert_eq!(
                    (
                        code_switch_boundary
                            .left_output_relation
                            .opening_evaluation_claim_count,
                        code_switch_boundary
                            .left_output_relation
                            .carried_reduction_claim_count,
                        code_switch_boundary.left_output_relation.claim_count,
                    ),
                    (0, 1, 1)
                );
            }

            let final_boundary = theorem
                .composition_boundaries
                .iter()
                .find(|boundary| {
                    boundary.role == CompositionBoundaryRole::FinalMaskedSumcheckToBase { epoch }
                })
                .expect("final masked-sumcheck composition boundary");
            assert_eq!(
                final_boundary
                    .left_output_relation
                    .source_code
                    .interleaving_width,
                1
            );
            assert_eq!(
                final_boundary.left_output_relation.mask_codes.len(),
                whir.external_mask_groups.len() + whir.internal_mask_groups.len()
            );
            assert_eq!(
                (
                    final_boundary
                        .left_output_relation
                        .opening_evaluation_claim_count,
                    final_boundary
                        .left_output_relation
                        .carried_reduction_claim_count,
                    final_boundary.left_output_relation.claim_count,
                ),
                (0, 1, 1)
            );
        }
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
                    code.query_count,
                    code.block_length,
                    code.dimension,
                ))
                .collect::<Vec<_>>(),
            vec![
                (32_768, 396, 396, 131_072, 33_164),
                (2_048, 432, 432, 8_192, 2_480),
                (128, 400, 400, 2_048, 528),
                (8, 348, 348, 2_048, 356),
            ]
        );
        for code in source_codes {
            assert!(
                code.exact_query_failure()
                    .expect("exact source query failure")
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
        changed_extractor.transitions[2].extractor_steps =
            vec![ExtractorStep::ReturnBottomUnderErrorBound];
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

        let mut changed_extraction_work = factor_one.relaxed_round_by_round.clone();
        changed_extraction_work.transitions[0].extraction_operation_bound += 1;
        assert_eq!(
            changed_extraction_work.check(
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

        let mut changed_query_count = factor_one.relaxed_round_by_round.clone();
        changed_query_count.codes[0].query_count += 1;
        assert_eq!(
            changed_query_count.check(
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

        let mut changed_cfw_repetition = factor_one.relaxed_round_by_round.clone();
        changed_cfw_repetition
            .cfw
            .inner_mask_code
            .repeated_encoding_count -= 1;
        assert_eq!(
            changed_cfw_repetition.check(
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

        let mut substituted_theorem_error = factor_one.relaxed_round_by_round.clone();
        substituted_theorem_error
            .cfw
            .theorem_initial_consistency_error = substituted_theorem_error
            .cfw
            .semantic_initial_consistency_error
            .clone();
        assert_eq!(
            substituted_theorem_error.check(
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

        let mut changed_cfw_challenge_space = factor_one.transcript_chronology.clone();
        let cfw_initial_move = changed_cfw_challenge_space
            .verifier_moves
            .iter_mut()
            .find(|verifier_move| verifier_move.roles() == [VerifierMoveRole::CfwInitialRandomness])
            .expect("CFW initial verifier move");
        cfw_initial_move.challenge_space = ExactChallengeSpace::ExtensionVector {
            element_count: catalog.cfw_reduction.initial_randomness_element_count() - 1,
            excluded_element_count: 0,
        };
        assert_eq!(
            factor_one.relaxed_round_by_round.check(
                &relation,
                &catalog.cfw_reduction,
                &catalog.cfw_to_whir_handoff,
                &factor_one.pre_challenge_whir,
                &factor_one.main_whir,
                &changed_cfw_challenge_space,
                &factor_one.interactive_soundness,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
