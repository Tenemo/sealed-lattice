//! Executable parameter and failure-partition certificate for the checked
//! row-code WHIR construction.
//!
//! The certificate derives its rows from the production construction plan. It
//! deliberately keeps arithmetic discharge separate from cryptographic
//! assumptions while binding every finite theorem row to the live plan.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use p3_whir::{FoldedRsCode, MaskCodeShape};

use super::shared_query_partition::{SharedQueryEventClass, selected_shared_query_partition};
use super::*;
use crate::bgv::proof_suite::relation_plan::{
    RelationCompilerInterpreterSemanticCertificate, RelationMaskDescriptor,
    checked_relation_compiler_interpreter_semantics,
};
use crate::bgv::proof_suite::row_code_whir::{
    ChallengeField, ColumnStreamableLeafHasher, ColumnStreamableLeafOracleFrame,
    ColumnStreamableLeafOracleFrameDescriptor, MERKLE_DIGEST_WORD_LENGTH,
    ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN, ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
    aggregate_leaf_hasher,
    aggregate_wide_hiding::{
        AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE, AggregateWideChronologyEvent,
        AggregateWideChronologyRow, AggregateWideDerivedAffineIdentity,
        AggregateWideFoldAffineMapDescriptor, AggregateWideFoldLimbOrder,
        AggregateWideJointAffineRankVerification, AggregateWideJointAffineViewKind,
        AggregateWideJointAffineViewRow, AggregateWideMaskingCertificate,
        AggregateWideNonlinearViewBoundary, checked_fold_limb_affine_map,
    },
    exact_same_secret::{
        ExactExtractorCorrespondenceFault, ExactPointConstraintExtractorCertificate,
        ExactPolynomialProtocolExtractorCertificate,
        checked_exact_same_secret_extractor_correspondence,
        checked_exact_same_secret_extractor_correspondence_with_fault,
    },
    recomputable_oracle::{
        RecomputableOracleAffineMapDescriptor, checked_recomputable_oracle_affine_map,
    },
    row_encoding::{
        PRIVATE_ROW_HIGH_HALF_DOMAIN, PRIVATE_ROW_PAD_PHASE_COUNT,
        PRIVATE_ROW_PAD_SEED_BYTE_LENGTH, PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH,
        private_row_high_half_xof_input_bytes,
    },
};
use crate::bgv::proof_suite::{
    CollectivePublicKeyAggregatePlanInput, ConstructionMaskDependency, ConstructionMaskResumeRule,
    ConstructionMaskSourceAuthority, ConstructionMaskSourceDescriptor,
    ConstructionMaskSourceIdentifier, ConstructionMaskSourceLifetime,
    ConstructionMaskingCertificate, ConstructionMaskingCorrespondence, ConstructionMaskingPhase,
    ConstructionMaskingRankKind, ConstructionMaskingRankRequirement,
    ConstructionMaskingRankVerification, ConstructionSecretViewAlgebra,
    ConstructionSecretViewDescriptor, ConstructionSecretViewIdentifier,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PublicAggregateRelationGeometry, SuiteModulusReference,
    ValidatedRelationPlanArtifact, checked_construction_masking_correspondence_for_parameters,
    checked_zero_knowledge_mask_image_for_parameters,
    compile_collective_public_key_aggregate_relation_plan, compile_same_secret_relation_plan,
    selected_ballot_validity_relation_compilation, selected_relation_plans,
    selected_same_secret_relation_plan_input,
};
use crate::foundation::{
    DECLARED_ADVERSARIAL_QUERY_BUDGET, MaskGeneratorHybridAssumption, MaskGeneratorHybridHop,
    MaskGeneratorHybridLoss, PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH, deployed_private_stream_hybrid,
    quantum_private_stream_hybrid,
};

const WHIR_SUMCHECK_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE: u64 = 3;
const SAME_SECRET_AGGREGATE_TABLE_WIDTH: usize = 4;
const SAME_SECRET_OPENING_BATCH_COUNT: usize = 1_008;
const SAME_SECRET_SCALAR_OPENING_COUNT: u64 = 1_782;
/// The independently pinned transcript hash-query ceiling for the selected
/// same-secret plan. It reconciles exactly against the plan-derived
/// oracle-equation census:
///
/// ~~~text
/// initial header root and absorption      1 +     1 =         2
/// response roots                       2,059      =     2,059
/// response bindings                    2,034      =     2,034
/// response absorptions                 2,071      =     2,071
/// accepted challenges                  4,272 * 1  =     4,272
/// challenge handles                    4,272 * 1  =     4,272
/// extension rejection chains   4,260 * 2 * 127    = 1,082,040
/// product expansions               3 * 128 * 1    =       384
/// distinct expansions
///     (2*387 + 393 + 288 + 268 + 266 + 264 + 2*263) * 16
///                                                    =    44,464
/// total                                             1,141,598
/// ~~~
///
/// The `4,272` accepted challenges partition as `4,260` extension challenges
/// plus `9` distinct-index samplers plus `3` product-space samplers, which is
/// also the logical verifier-message count below. The distinct-sampler row
/// carries `266` accepted direct-bound draws once; the prior-certificate subset
/// selects its first `40` in accepted order and therefore draws nothing extra.
const SELECTED_TRANSCRIPT_HASH_QUERY_COUNT: u64 = 1_141_598;
const SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT: u64 = 4_272;
const CMS19_ADVERSARIAL_QUERY_EXPONENT: usize = 80;
const CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH: usize = 512;
static PRODUCTION_GEOMETRY_CERTIFICATE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum WhirTheoremCertificateError {
    ArithmeticOverflow,
    InvalidSelectedGeometry,
    IncompleteTranscriptMapping,
    IncompleteOracleEquationMapping,
    IncompleteMaskingCorrespondence,
    IncompleteRowPadGeneratorHybrid,
    IncompleteRelationSemanticCorrespondence,
    IncompletePolynomialExtractorCorrespondence,
    IncompleteFailureMagnitudeCorrespondence,
    SelectedProductionGeometry {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        stage: ProductionGeometryCertificateStage,
        failure: ProductionGeometryCertificateFailure,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ProductionGeometryCertificateStage {
    ConstructionPlan,
    HidingConfiguration,
    RelationSemantics,
    MaskingCorrespondence,
    RowPadGeneratorHybrid,
    WhirGeometry,
    PrefixStacking,
    OracleEquationCatalog,
    StateEquationRows,
    TranscriptCounts,
    SelectedStatePredicate,
    WholeStateCorrespondence,
    StrongStateHashChain,
    VerifierLedger,
    DeployedLeafOracle,
    WholeDatabaseSupport,
    CommitmentSubtree,
    ConstructionIdentity,
    Completeness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum ProductionGeometryCertificateFailure {
    ArithmeticOverflow,
    InvalidSelectedGeometry,
    IncompleteTranscriptMapping,
    IncompleteOracleEquationMapping,
    IncompleteMaskingCorrespondence,
    IncompleteRowPadGeneratorHybrid,
    IncompleteRelationSemanticCorrespondence,
    IncompletePolynomialExtractorCorrespondence,
    IncompleteFailureMagnitudeCorrespondence,
    InvalidCoordinateOrIdentity,
    InvalidWitnessGeometry,
    IncompleteRelationOrMaskingCertificate,
    IncompleteWhirGeometry,
    InvalidPrefixStacking,
    IncompleteOracleStateRows,
    IncompleteSelectedStatePredecessorClosure,
    IncompleteWholeStateCorrespondence,
    IncompleteStrongStateHashChain,
    IncompleteVerifierLedger,
    IneligibleDeployedLeafOracle,
    IncompleteWholeDatabaseSupport,
    IncompleteCommitmentSubtreeExtraction,
    InconsistentQromArithmetic,
}

impl From<WhirTheoremCertificateError> for ProductionGeometryCertificateFailure {
    fn from(error: WhirTheoremCertificateError) -> Self {
        match error {
            WhirTheoremCertificateError::ArithmeticOverflow => Self::ArithmeticOverflow,
            WhirTheoremCertificateError::InvalidSelectedGeometry => Self::InvalidSelectedGeometry,
            WhirTheoremCertificateError::IncompleteTranscriptMapping => {
                Self::IncompleteTranscriptMapping
            }
            WhirTheoremCertificateError::IncompleteOracleEquationMapping => {
                Self::IncompleteOracleEquationMapping
            }
            WhirTheoremCertificateError::IncompleteMaskingCorrespondence => {
                Self::IncompleteMaskingCorrespondence
            }
            WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid => {
                Self::IncompleteRowPadGeneratorHybrid
            }
            WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence => {
                Self::IncompleteRelationSemanticCorrespondence
            }
            WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence => {
                Self::IncompletePolynomialExtractorCorrespondence
            }
            WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence => {
                Self::IncompleteFailureMagnitudeCorrespondence
            }
            WhirTheoremCertificateError::SelectedProductionGeometry { failure, .. } => failure,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactFraction {
    numerator: u64,
    denominator: u64,
}

impl ExactFraction {
    fn new(numerator: u64, denominator: u64) -> Result<Self, WhirTheoremCertificateError> {
        if denominator == 0 {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let divisor = greatest_common_divisor(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn less_than(self, right: Self) -> Result<bool, WhirTheoremCertificateError> {
        let left_product = u128::from(self.numerator)
            .checked_mul(u128::from(right.denominator))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let right_product = u128::from(right.numerator)
            .checked_mul(u128::from(self.denominator))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        Ok(left_product < right_product)
    }

    fn floor_product(self, factor: u64) -> Result<u64, WhirTheoremCertificateError> {
        let product = u128::from(self.numerator)
            .checked_mul(u128::from(factor))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        u64::try_from(product / u128::from(self.denominator))
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

const fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirCodeStateRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    domain_size: u64,
    dimension: u64,
    minimum_distance: u64,
    unique_decoding_radius: u64,
    selected_state_error_count_ceiling: u64,
    selected_state_relative_distance: ExactFraction,
    false_state_minimum_error_count: u64,
    false_state_agreement_ceiling: ExactFraction,
    reed_solomon_rate: ExactFraction,
    corollary_four_eleven_proximity_bound: ExactFraction,
    theorem_five_two_strict_distance_ceiling: ExactFraction,
    unique_decoding_list_size_ceiling: u64,
}

impl WhirCodeStateRow {
    fn derive(
        epoch_ordinal: u32,
        fold_ordinal: u32,
        parent_domain_size: u64,
        parent_dimension: u64,
        selected_state_relative_distance: ExactFraction,
    ) -> Result<Self, WhirTheoremCertificateError> {
        let domain_size = parent_domain_size
            .checked_shr(fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let dimension = parent_dimension
            .checked_shr(fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        if dimension >= domain_size {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let minimum_distance = domain_size
            .checked_sub(dimension)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let unique_decoding_radius = minimum_distance
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
            / 2;
        let selected_state_error_count_ceiling =
            selected_state_relative_distance.floor_product(domain_size)?;
        let false_state_minimum_error_count = selected_state_error_count_ceiling
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let false_state_agreement_ceiling = ExactFraction::new(
            domain_size
                .checked_sub(false_state_minimum_error_count)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
            domain_size,
        )?;
        let reed_solomon_rate = ExactFraction::new(dimension, domain_size)?;
        // Corollary 4.11 gives B* = (1 + rho) / 2 in the proved
        // unique-decoding regime. Theorem 5.2 requires delta < 1 - B*,
        // so the state radius uses the greatest integral Hamming radius
        // strictly below that open endpoint. A false state therefore starts
        // at the ordinary unique-decoding radius and retains the same query
        // agreement ceiling used by the selected proof.
        let corollary_four_eleven_proximity_bound = ExactFraction::new(
            domain_size
                .checked_add(dimension)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            domain_size
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?;
        let theorem_five_two_strict_distance_ceiling = ExactFraction::new(
            domain_size
                .checked_sub(dimension)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            domain_size
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?;
        if unique_decoding_radius == 0
            || false_state_minimum_error_count > unique_decoding_radius
            || !selected_state_relative_distance
                .less_than(theorem_five_two_strict_distance_ceiling)?
            || !selected_state_relative_distance.less_than(corollary_four_eleven_proximity_bound)?
            || selected_state_error_count_ceiling > unique_decoding_radius
            || unique_decoding_radius
                .checked_mul(2)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                >= minimum_distance
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }

        Ok(Self {
            epoch_ordinal,
            fold_ordinal,
            domain_size,
            dimension,
            minimum_distance,
            unique_decoding_radius,
            selected_state_error_count_ceiling,
            selected_state_relative_distance,
            false_state_minimum_error_count,
            false_state_agreement_ceiling,
            reed_solomon_rate,
            corollary_four_eleven_proximity_bound,
            theorem_five_two_strict_distance_ceiling,
            unique_decoding_list_size_ceiling: 1,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InterleavedUniqueDecodingRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    lane_count: usize,
    constituent_minimum_distance: u64,
    interleaved_minimum_distance: u64,
    selected_state_error_count_ceiling: u64,
    unique_decoding_list_size_ceiling: u64,
    lower_bound_uses_nonzero_component: bool,
    upper_bound_uses_one_nonzero_component: bool,
}

impl InterleavedUniqueDecodingRow {
    fn derive(
        code_state: WhirCodeStateRow,
        lane_count: usize,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if lane_count == 0
            || code_state.unique_decoding_list_size_ceiling != 1
            || code_state.selected_state_error_count_ceiling >= code_state.unique_decoding_radius
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }

        // For the coordinate-wise interleaving of identical linear codes,
        // every nonzero word has a nonzero component and therefore weight at
        // least the constituent minimum distance. Conversely, placing a
        // constituent minimum-weight codeword in one component and zero in
        // every other component attains that distance. The interleaved and
        // constituent distances are therefore equal, so the same strict
        // unique-decoding radius gives list size one.
        Ok(Self {
            epoch_ordinal: code_state.epoch_ordinal,
            fold_ordinal: code_state.fold_ordinal,
            lane_count,
            constituent_minimum_distance: code_state.minimum_distance,
            interleaved_minimum_distance: code_state.minimum_distance,
            selected_state_error_count_ceiling: code_state.selected_state_error_count_ceiling,
            unique_decoding_list_size_ceiling: 1,
            lower_bound_uses_nonzero_component: true,
            upper_bound_uses_one_nonzero_component: true,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirFoldFailureRow {
    epoch_ordinal: u32,
    fold_ordinal: u32,
    transcript_operation_ordinal: u32,
    target_domain_size: u64,
    sumcheck_numerator: u64,
    mutual_correlated_agreement_numerator: u64,
}

impl WhirFoldFailureRow {
    fn total_numerator(self) -> Result<u64, WhirTheoremCertificateError> {
        self.sumcheck_numerator
            .checked_add(self.mutual_correlated_agreement_numerator)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirShiftFailureRow {
    round_ordinal: u32,
    transcript_operation_ordinal: u32,
    query_count: u64,
    list_size: u64,
    algebraic_numerator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WhirFinalQueryRow {
    epoch_ordinal: u32,
    query_count: u64,
    bad_agreement: ExactFraction,
}

/// A reduced nonnegative rational used for the complete finite soundness
/// calculation. The query products are thousands of bits wide, so a machine
/// integer fraction would silently turn the theorem check into an estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBigFraction {
    numerator: BigUint,
    denominator: BigUint,
}

impl ExactBigFraction {
    fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, WhirTheoremCertificateError> {
        if denominator.is_zero() {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let divisor = greatest_common_divisor_big(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        })
    }

    fn from_u64(numerator: u64, denominator: u64) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(BigUint::from(numerator), BigUint::from(denominator))
    }

    fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    fn add(&self, right: &Self) -> Result<Self, WhirTheoremCertificateError> {
        let common_divisor =
            greatest_common_divisor_big(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        Self::new(
            &self.numerator * &left_scale + &right.numerator * &right_scale,
            &self.denominator * left_scale,
        )
    }

    fn multiply_integer(&self, factor: &BigUint) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(&self.numerator * factor, self.denominator.clone())
    }

    fn multiply_u64(&self, factor: u64) -> Result<Self, WhirTheoremCertificateError> {
        self.multiply_integer(&BigUint::from(factor))
    }

    fn power(&self, exponent: u32) -> Result<Self, WhirTheoremCertificateError> {
        Self::new(self.numerator.pow(exponent), self.denominator.pow(exponent))
    }

    fn less_than_or_equal(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator <= &right.numerator * &self.denominator
    }

    fn less_than(&self, right: &Self) -> bool {
        &self.numerator * &right.denominator < &right.numerator * &self.denominator
    }

    fn is_at_most_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }

    fn is_greater_than_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) > self.denominator
    }
}

fn greatest_common_divisor_big(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRowPadXofModel {
    ClassicalSecretPrefixRandomOracle,
    QuantumSecretPrefixRandomOracleSaitoXagawaYamakawaLemmaTwoTwo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRowPadConcreteXof {
    Shake256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PrivateRowPadPhaseCensus {
    phase: RowCodeWhirPhase,
    row_count: usize,
    witness_values_per_row: usize,
    xof_call_count: usize,
    accepted_field_output_count: usize,
}

/// Deployment-to-uniform bridge for the private high half of every phase row.
///
/// This is a construction-level masking certificate, not a family simulator.
/// It first uses the action-private KMAC hybrid to replace the three raw phase
/// seeds, then applies the secret-prefix random-oracle lemma separately to each
/// active phase function, and finally conditions on bounded rejection-sampler
/// success. Fixed SHAKE256 remains the named concrete ideal-XOF/QRO assumption;
/// the certificate does not claim that the fixed function is a random oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PrivateRowPadGeneratorHybridCertificate {
    proof_privacy_mode: ProofPrivacyMode,
    deployed_private_stream_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4],
    quantum_private_stream_hybrid: [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4],
    concrete_xof: PrivateRowPadConcreteXof,
    classical_xof_model: PrivateRowPadXofModel,
    quantum_xof_model: PrivateRowPadXofModel,
    xof_domain: Vec<u8>,
    sampled_phase_seed_count: usize,
    active_phase_seed_count: usize,
    phase_seed_byte_length: usize,
    phase_seed_material_byte_length: usize,
    private_stream_block_byte_length: usize,
    phase_rows: Vec<PrivateRowPadPhaseCensus>,
    framed_xof_input_count: usize,
    framed_xof_inputs_are_injective_given_distinct_phase_seeds: bool,
    accepted_field_output_count: usize,
    maximum_candidate_draws_per_output: u32,
    maximum_candidate_draw_count: u64,
    maximum_xof_output_byte_length: u64,
    classical_action_root_guessing_advantage: ExactBigFraction,
    quantum_action_root_search_advantage: ExactBigFraction,
    seed_collision_probability: ExactBigFraction,
    classical_secret_prefix_replacement_advantage: ExactBigFraction,
    quantum_secret_prefix_replacement_advantage: ExactBigFraction,
    rejection_sampler_exhaustion_probability: ExactBigFraction,
    production_frame_binding_established: bool,
}

impl PrivateRowPadGeneratorHybridCertificate {
    fn derive(plan: &RowCodeWhirConstructionPlan) -> Result<Self, WhirTheoremCertificateError> {
        Self::derive_with_seed_byte_length(plan, PRIVATE_ROW_PAD_SEED_BYTE_LENGTH)
    }

    fn derive_with_seed_byte_length(
        plan: &RowCodeWhirConstructionPlan,
        phase_seed_byte_length: usize,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if phase_seed_byte_length == 0 {
            return Err(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid);
        }
        let phase_seed_bit_length = phase_seed_byte_length
            .checked_mul(u8::BITS as usize)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        if !phase_seed_bit_length.is_multiple_of(2) {
            return Err(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid);
        }
        let secret_bearing = plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing;
        let mut phase_rows = Vec::new();
        if secret_bearing {
            for phase in &plan.phase_order {
                let geometry = row_pad_phase_geometry(plan, *phase)
                    .ok_or(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid)?;
                let accepted_field_output_count = geometry
                    .row_count
                    .checked_mul(geometry.pad_value_count())
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                phase_rows.push(PrivateRowPadPhaseCensus {
                    phase: *phase,
                    row_count: geometry.row_count,
                    witness_values_per_row: geometry.witness_values_per_row,
                    xof_call_count: geometry.row_count,
                    accepted_field_output_count,
                });
            }
        }
        let active_phase_seed_count = phase_rows.len();
        let framed_xof_input_count = phase_rows.iter().try_fold(0_usize, |total, phase| {
            total
                .checked_add(phase.xof_call_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
        let accepted_field_output_count = phase_rows.iter().try_fold(0_usize, |total, phase| {
            total
                .checked_add(phase.accepted_field_output_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
        let maximum_candidate_draws_per_output = plan
            .parameters
            .maximum_fiat_shamir_candidate_draws_per_output;
        let maximum_candidate_draw_count = u64::try_from(accepted_field_output_count)
            .ok()
            .and_then(|output_count| {
                output_count.checked_mul(u64::from(maximum_candidate_draws_per_output))
            })
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let maximum_xof_output_byte_length = maximum_candidate_draw_count
            .checked_mul(size_of::<u64>() as u64)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

        let active_phase_seed_count_big = BigUint::from(active_phase_seed_count);
        let action_root_space = BigUint::one() << 512_usize;
        let classical_action_root_guessing_advantage = if secret_bearing {
            ExactBigFraction::new(
                BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
                action_root_space.clone(),
            )?
        } else {
            ExactBigFraction::zero()
        };
        let quantum_action_root_search_advantage = if secret_bearing {
            let quantum_search_amplitude = BigUint::from(2_u8)
                * BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
                + BigUint::one();
            ExactBigFraction::new(
                &quantum_search_amplitude * &quantum_search_amplitude,
                action_root_space,
            )?
        } else {
            ExactBigFraction::zero()
        };
        let seed_space = BigUint::one() << phase_seed_bit_length;
        let seed_collision_pair_count = active_phase_seed_count
            .checked_mul(active_phase_seed_count.saturating_sub(1))
            .and_then(|ordered_pair_count| ordered_pair_count.checked_div(2))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let seed_collision_probability =
            ExactBigFraction::new(BigUint::from(seed_collision_pair_count), seed_space.clone())?;
        let classical_secret_prefix_replacement_advantage = ExactBigFraction::new(
            &active_phase_seed_count_big * BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            seed_space,
        )?;
        // Saito--Xagawa--Yamakawa, Lemma 2.2: one secret-prefix function costs
        // at most 2 q / sqrt(2^k). Sequential replacement pays once per active
        // phase seed.
        let quantum_secret_prefix_replacement_advantage = ExactBigFraction::new(
            &active_phase_seed_count_big
                * BigUint::from(2_u8)
                * BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            BigUint::one() << (phase_seed_bit_length / 2),
        )?;
        let candidate_space = BigUint::one() << u64::BITS as usize;
        let rejected_candidate_count = &candidate_space % BigUint::from(PROOF_BASE_FIELD_MODULUS);
        let rejection_sampler_exhaustion_probability = if accepted_field_output_count == 0 {
            ExactBigFraction::zero()
        } else {
            ExactBigFraction::new(
                rejected_candidate_count.pow(maximum_candidate_draws_per_output)
                    * BigUint::from(accepted_field_output_count),
                candidate_space.pow(maximum_candidate_draws_per_output),
            )?
        };

        let production_frame_binding_established = phase_seed_byte_length
            == PRIVATE_ROW_PAD_SEED_BYTE_LENGTH
            && PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH
                == PRIVATE_ROW_PAD_PHASE_COUNT * PRIVATE_ROW_PAD_SEED_BYTE_LENGTH;
        let framed_xof_inputs_are_injective_given_distinct_phase_seeds =
            if secret_bearing && production_frame_binding_established {
                row_pad_production_frames_are_injective(plan, &phase_rows)?
            } else {
                !secret_bearing
            };
        let certificate = Self {
            proof_privacy_mode: plan.proof_privacy_mode,
            deployed_private_stream_hybrid: deployed_private_stream_hybrid(),
            quantum_private_stream_hybrid: quantum_private_stream_hybrid(),
            concrete_xof: PrivateRowPadConcreteXof::Shake256,
            classical_xof_model: PrivateRowPadXofModel::ClassicalSecretPrefixRandomOracle,
            quantum_xof_model:
                PrivateRowPadXofModel::QuantumSecretPrefixRandomOracleSaitoXagawaYamakawaLemmaTwoTwo,
            xof_domain: PRIVATE_ROW_HIGH_HALF_DOMAIN.to_vec(),
            sampled_phase_seed_count: usize::from(secret_bearing)
                .checked_mul(PRIVATE_ROW_PAD_PHASE_COUNT)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            active_phase_seed_count,
            phase_seed_byte_length,
            phase_seed_material_byte_length: phase_seed_byte_length
                .checked_mul(PRIVATE_ROW_PAD_PHASE_COUNT)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            private_stream_block_byte_length: PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH,
            phase_rows,
            framed_xof_input_count,
            framed_xof_inputs_are_injective_given_distinct_phase_seeds,
            accepted_field_output_count,
            maximum_candidate_draws_per_output,
            maximum_candidate_draw_count,
            maximum_xof_output_byte_length,
            classical_action_root_guessing_advantage,
            quantum_action_root_search_advantage,
            seed_collision_probability,
            classical_secret_prefix_replacement_advantage,
            quantum_secret_prefix_replacement_advantage,
            rejection_sampler_exhaustion_probability,
            production_frame_binding_established,
        };
        Ok(certificate)
    }

    fn is_complete_for_plan(&self, plan: &RowCodeWhirConstructionPlan) -> bool {
        self.is_complete()
            && Self::derive_with_seed_byte_length(plan, self.phase_seed_byte_length)
                .is_ok_and(|expected| expected == *self)
    }

    fn is_complete(&self) -> bool {
        let secret_bearing = self.proof_privacy_mode == ProofPrivacyMode::SecretBearing;
        let expected_private_stream_hops = [
            MaskGeneratorHybridHop::ActionRootEntropy,
            MaskGeneratorHybridHop::ActionKeyHierarchyReplacement,
            MaskGeneratorHybridHop::BlockStreamReplacement,
            MaskGeneratorHybridHop::FramedInputInjectivity,
        ];
        self.deployed_private_stream_hybrid == deployed_private_stream_hybrid()
            && self.quantum_private_stream_hybrid == quantum_private_stream_hybrid()
            && self
                .deployed_private_stream_hybrid
                .map(|(hop, _)| hop)
                == expected_private_stream_hops
            && self
                .quantum_private_stream_hybrid
                .map(|(hop, _)| hop)
                == expected_private_stream_hops
            && matches!(
                self.deployed_private_stream_hybrid[0].1,
                MaskGeneratorHybridLoss::SecretGuessing {
                    secret_bit_length: 512,
                    query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && matches!(
                self.quantum_private_stream_hybrid[0].1,
                MaskGeneratorHybridLoss::QuantumSecretSearch {
                    secret_bit_length: 512,
                    query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && matches!(
                self.deployed_private_stream_hybrid[1].1,
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && matches!(
                self.quantum_private_stream_hybrid[1].1,
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && matches!(
                self.deployed_private_stream_hybrid[2].1,
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && matches!(
                self.quantum_private_stream_hybrid[2].1,
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                }
            )
            && self.deployed_private_stream_hybrid[3].1 == MaskGeneratorHybridLoss::Exact
            && self.quantum_private_stream_hybrid[3].1 == MaskGeneratorHybridLoss::Exact
            && self.concrete_xof == PrivateRowPadConcreteXof::Shake256
            && self.classical_xof_model
                == PrivateRowPadXofModel::ClassicalSecretPrefixRandomOracle
            && self.quantum_xof_model
                == PrivateRowPadXofModel::QuantumSecretPrefixRandomOracleSaitoXagawaYamakawaLemmaTwoTwo
            && self.xof_domain == PRIVATE_ROW_HIGH_HALF_DOMAIN
            && self.phase_seed_byte_length == PRIVATE_ROW_PAD_SEED_BYTE_LENGTH
            && self.phase_seed_material_byte_length
                == PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH
            && self.private_stream_block_byte_length == PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH
            && self.phase_seed_byte_length == self.private_stream_block_byte_length
            && self.maximum_candidate_draws_per_output
                == PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT
            && self.production_frame_binding_established
            && if secret_bearing {
                self.sampled_phase_seed_count == PRIVATE_ROW_PAD_PHASE_COUNT
                    && self.active_phase_seed_count == self.phase_rows.len()
                    && self.active_phase_seed_count > 0
                    && self.active_phase_seed_count <= self.sampled_phase_seed_count
                    && self.framed_xof_input_count > 0
                    && self.framed_xof_inputs_are_injective_given_distinct_phase_seeds
                    && self.accepted_field_output_count > 0
                    && self
                        .classical_action_root_guessing_advantage
                        .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
                    && self
                        .quantum_action_root_search_advantage
                        .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
                    && self.seed_collision_probability
                        .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
                    && self
                        .classical_secret_prefix_replacement_advantage
                        .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
                    && self
                        .quantum_secret_prefix_replacement_advantage
                        .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
                    && self
                        .rejection_sampler_exhaustion_probability
                        .is_at_most_inverse_power_of_two(128)
            } else {
                self.sampled_phase_seed_count == 0
                    && self.active_phase_seed_count == 0
                    && self.phase_rows.is_empty()
                    && self.framed_xof_input_count == 0
                    && self.accepted_field_output_count == 0
                    && self.maximum_candidate_draw_count == 0
                    && self.maximum_xof_output_byte_length == 0
                    && self
                        .classical_action_root_guessing_advantage
                        .numerator
                        .is_zero()
                    && self
                        .quantum_action_root_search_advantage
                        .numerator
                        .is_zero()
            }
    }
}

fn row_pad_phase_geometry(
    plan: &RowCodeWhirConstructionPlan,
    phase: RowCodeWhirPhase,
) -> Option<RowEncodingGeometry> {
    match phase {
        RowCodeWhirPhase::Base => plan.base_phase.as_ref().map(|phase| phase.geometry),
        RowCodeWhirPhase::Auxiliary => plan.auxiliary_phase.as_ref().map(|phase| phase.geometry),
        RowCodeWhirPhase::Quotient => Some(plan.quotient_phase.geometry),
    }
}

fn row_pad_production_frames_are_injective(
    plan: &RowCodeWhirConstructionPlan,
    phase_rows: &[PrivateRowPadPhaseCensus],
) -> Result<bool, WhirTheoremCertificateError> {
    let mut frames = BTreeSet::new();
    for (phase_seed_ordinal, phase) in phase_rows.iter().enumerate() {
        let geometry = row_pad_phase_geometry(plan, phase.phase)
            .ok_or(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid)?;
        if geometry.row_count != phase.row_count
            || geometry.witness_values_per_row != phase.witness_values_per_row
        {
            return Err(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid);
        }
        let mut seed = [0_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH];
        seed[0] = u8::try_from(phase_seed_ordinal + 1)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        for row_index in 0..phase.row_count {
            let frame = private_row_high_half_xof_input_bytes(geometry, row_index, &seed);
            let expected_frame_byte_length = size_of::<u64>()
                .checked_add(PRIVATE_ROW_HIGH_HALF_DOMAIN.len())
                .and_then(|length| length.checked_add(PRIVATE_ROW_PAD_SEED_BYTE_LENGTH))
                .and_then(|length| length.checked_add(3 * size_of::<u64>()))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            if frame.len() != expected_frame_byte_length || !frames.insert(frame) {
                return Ok(false);
            }
        }
    }
    Ok(frames.len()
        == phase_rows
            .iter()
            .map(|phase| phase.row_count)
            .sum::<usize>())
}

fn falling_factorial(
    population: u64,
    draw_count: u64,
) -> Result<BigUint, WhirTheoremCertificateError> {
    if draw_count > population {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok((0..draw_count)
        .map(|draw_ordinal| BigUint::from(population - draw_ordinal))
        .product())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ExactFailureOwnerKind {
    NonNativeThetaProduct,
    NonNativeAlphaProduct,
    RelationComposition,
    OutOfDomainPoint,
    PointSelector,
    TraceColumnGroup,
    QuotientGroup,
    OpeningBatchMask,
    BoundOpening,
    BoundDegreeCoordinate,
    OuterQueryVector,
    BoundQueryVector,
    WhirQueryVector,
    WhirOpeningBatching,
    MaskedSumcheckEpsilon,
    MaskedSumcheckFold,
    RoundCheckpoint,
    RoundCombination,
    BaseCaseBlinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactFailureOwnerRow {
    kind: ExactFailureOwnerKind,
    transition_count: usize,
    expected_transition_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactQueryFailureEvent {
    OuterOpeningPointWords,
    RelationPhaseColumns,
    BoundTreeWords,
    StatementRootWords,
    WhirSource { epoch_ordinal: u32 },
    AggregateWidePad,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactQueryFailureRow {
    event: ExactQueryFailureEvent,
    sponsoring_owner: ExactFailureOwnerKind,
    logical_word_count: usize,
    population: u64,
    agreement_ceiling: u64,
    query_count: u64,
    charged_term_count: u64,
    exact_without_replacement_probability: ExactBigFraction,
    power_probability_ceiling: ExactBigFraction,
}

impl ExactQueryFailureRow {
    fn derive(
        event: ExactQueryFailureEvent,
        sponsoring_owner: ExactFailureOwnerKind,
        logical_word_count: usize,
        population: u64,
        agreement_ceiling: u64,
        query_count: u64,
        charged_term_count: u64,
    ) -> Result<Self, WhirTheoremCertificateError> {
        if logical_word_count == 0
            || population == 0
            || agreement_ceiling >= population
            || query_count == 0
            || query_count > agreement_ceiling
            || charged_term_count == 0
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let exact_without_replacement_probability = ExactBigFraction::new(
            falling_factorial(agreement_ceiling, query_count)?,
            falling_factorial(population, query_count)?,
        )?;
        let power_probability_ceiling = ExactBigFraction::from_u64(agreement_ceiling, population)?
            .power(
                u32::try_from(query_count)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )?;
        if !exact_without_replacement_probability.less_than_or_equal(&power_probability_ceiling) {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        Ok(Self {
            event,
            sponsoring_owner,
            logical_word_count,
            population,
            agreement_ceiling,
            query_count,
            charged_term_count,
            exact_without_replacement_probability,
            power_probability_ceiling,
        })
    }

    fn charged_power_ceiling(&self) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
        self.power_probability_ceiling
            .multiply_u64(self.charged_term_count)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactThetaFailureRow {
    challenge: CommonProofChallenge,
    ordered_bad_polynomial_degrees: Vec<u64>,
    bad_set_numerator: BigUint,
    sample_space_denominator: BigUint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactAlgebraicFailureEvent {
    NonNativeThetaExtraction,
    RelationCompositionBatch,
    OpeningPointExceptionalSets,
    PhaseRowAndSelectorBatching,
    OpeningBatchMaskConsistency,
    BoundOpeningBatch,
    BoundDegreeSuffixes,
    WhirOpeningBatch,
    MaskedSumcheckInitialTransitions,
    MaskedSumcheckFolds,
    RoundCommitmentCheckpoints,
    WhirQueryCombinations,
    AggregateWideBaseBlinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactAlgebraicFailureRow {
    event: ExactAlgebraicFailureEvent,
    owner_kinds: Vec<ExactFailureOwnerKind>,
    theorem_event_count: u64,
    numerator: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactFailureMagnitudeCertificate {
    owner_rows: Vec<ExactFailureOwnerRow>,
    query_rows: Vec<ExactQueryFailureRow>,
    theta_rows: Vec<ExactThetaFailureRow>,
    algebraic_rows: Vec<ExactAlgebraicFailureRow>,
    extension_field_cardinality: BigUint,
    query_failure_probability_ceiling: ExactBigFraction,
    algebraic_failure_probability_ceiling: ExactBigFraction,
    classical_failure_probability_ceiling: ExactBigFraction,
    qrom_failure_probability_ceiling: ExactBigFraction,
    same_secret_family_multiplicity: u64,
    cms19_verifier_hash_query_count: u64,
    cms19_accepting_database_equation_count: u64,
    all_failure_owners_mapped_once: bool,
    exact_query_products_bounded: bool,
    ordinary_family_mass_gate_holds: bool,
    transformed_initial_mass_gate_holds: bool,
    complete_qrom_mass_gate_holds: bool,
}

impl ExactFailureMagnitudeCertificate {
    fn is_complete(&self) -> bool {
        self.owner_rows
            .iter()
            .all(|row| row.transition_count == row.expected_transition_count)
            && self.query_rows.len() == 11
            && self.theta_rows.len() == 3
            && self.algebraic_rows.len() == 13
            && self.same_secret_family_multiplicity == 10
            && self.all_failure_owners_mapped_once
            && self.exact_query_products_bounded
            && self.ordinary_family_mass_gate_holds
            && self.transformed_initial_mass_gate_holds
            && self.complete_qrom_mass_gate_holds
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactFailureMagnitudeFault {
    DropFirstQueryRow,
    ReduceFirstQueryAgreementCeiling,
    DropRelationCompositionOwner,
    ReduceAggregateWideBaseNumerator,
    ChangeVerifierHashQueryCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrefixStackingCertificate {
    source_table_count: usize,
    committed_polynomial_count: usize,
    table_variable_count: usize,
    selector_variable_count: usize,
    stacked_variable_count: usize,
    table_width: usize,
    opening_batch_count: usize,
    scalar_opening_count: u64,
    selector_indices: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateTransitionOwner {
    FixedInitialState,
    ProverMessageCannotRepairFalseState,
    DeterministicObservationPreservesState,
    VerifierChallengeWithTypedFailureEvent,
    TerminalDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanStatePredicateClause {
    EmptyCanonicalPrefixIsFalse,
    BackwardClosureOverCanonicalProverMove,
    DeterministicProtocolSchedule,
    DeterministicOpeningPoint {
        batch_ordinal: u32,
    },
    PolynomialProtocolChallenge,
    RelationReductionChallenge,
    OuterRowCodeAgreement,
    BoundIdentityAgreement,
    WhirOpeningConstraintBatch,
    WhirMaskedSumcheckBatch {
        batch_ordinal: u32,
    },
    WhirRoundConstraintCheckpoint {
        epoch_ordinal: u32,
    },
    WhirConstrainedFold {
        epoch_ordinal: u32,
        fold_ordinal: u32,
    },
    WhirQueryAgreement {
        epoch_ordinal: u32,
    },
    WhirQueryCombination {
        epoch_ordinal: u32,
    },
    AggregateWidePadQueryAgreement,
    WhirBaseCaseBlinding,
    FullCanonicalTranscriptAccepts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanStateDefinitionClause {
    UniqueCanonicalPrefix,
    OneSharedSemanticWitness,
    DecodedEquationConsistency,
    ConstrainedCodeState,
    AcceptingCanonicalSuffix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanFailureEventClass {
    PolynomialProtocolKnowledge,
    AlgebraicExceptionalSet,
    WithoutReplacementAgreement,
    WhirRoundByRoundProximity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanFailureEventOwner {
    CommonProductChallenge { challenge: CommonProofChallenge },
    CommonExtensionChallenge { challenge: CommonProofChallenge },
    DirectExtensionChallenge { challenge: RowCodeWhirChallenge },
    DistinctQueryVector { role: RowCodeWhirQueryRole },
    WhirExtensionChallenge { role: RowCodeWhirExtensionRole },
}

impl SelectedPlanFailureEventOwner {
    const fn event_class(self) -> SelectedPlanFailureEventClass {
        match self {
            Self::CommonProductChallenge { .. } => {
                SelectedPlanFailureEventClass::PolynomialProtocolKnowledge
            }
            Self::CommonExtensionChallenge { .. } | Self::DirectExtensionChallenge { .. } => {
                SelectedPlanFailureEventClass::AlgebraicExceptionalSet
            }
            Self::DistinctQueryVector { .. } => {
                SelectedPlanFailureEventClass::WithoutReplacementAgreement
            }
            Self::WhirExtensionChallenge { .. } => {
                SelectedPlanFailureEventClass::WhirRoundByRoundProximity
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedPlanStateTransitionRow {
    operation_ordinal: u32,
    predicate_clause: SelectedPlanStatePredicateClause,
    failure_event_owner: Option<SelectedPlanFailureEventOwner>,
    sampler_exhaustion_is_honest_abort: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanProofSectionPredicate {
    RelationPhaseAffineSpan { phase: RowCodeWhirPhase },
    OutOfDomainCompositionAndRegisteredClaims,
    OpeningBatchMaskConsistency,
    AggregateConstrainedPolynomialCommitment,
    AggregateWidePadCommitmentBinding,
    PhaseOpeningAuthenticationAndReduction { phase: RowCodeWhirPhase },
    BoundAuthenticationAndReduction { bound_tree_ordinal: u32 },
    ExplicitPointAggregateWideOpening,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanProofSectionStateRow {
    section_ordinal: u32,
    item_count: usize,
    predicate: SelectedPlanProofSectionPredicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanCheckpointStateOwner {
    AuthenticatedSourceAndConstruction,
    CompletedPhaseCommitment { phase: RowCodeWhirPhase },
    RelationEvaluationsAndMask,
    AggregateCommitmentsAndQueries,
    CompletedWhirRound { round_ordinal: u32 },
    CompletedCanonicalProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanCheckpointStateRow {
    checkpoint_ordinal: u32,
    next_transcript_operation_ordinal: u32,
    next_proof_section_ordinal: u32,
    owner: SelectedPlanCheckpointStateOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedPlanLifecycleTransition {
    AuthenticatedResume,
    ExplicitAbort,
    Cancellation,
    SamplerExhaustion,
    MaskRankFailure,
    StorageRefusal,
    CompletedProofTransport,
    FreshVerifierAcceptance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedPlanLifecycleStateRow {
    transition: SelectedPlanLifecycleTransition,
    preserves_cryptographic_cursor: bool,
    emits_proof: bool,
    emits_verified_capability: bool,
    requires_fresh_verifier: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedPlanStatePredicateCertificate {
    transition_rows: Vec<SelectedPlanStateTransitionRow>,
    proof_section_rows: Vec<SelectedPlanProofSectionStateRow>,
    checkpoint_rows: Vec<SelectedPlanCheckpointStateRow>,
    lifecycle_rows: Vec<SelectedPlanLifecycleStateRow>,
    definition_clauses: Vec<SelectedPlanStateDefinitionClause>,
}

impl SelectedPlanStatePredicateCertificate {
    fn is_total_for_plan(&self, plan: &RowCodeWhirConstructionPlan) -> bool {
        self.definition_clauses
            == [
                SelectedPlanStateDefinitionClause::UniqueCanonicalPrefix,
                SelectedPlanStateDefinitionClause::OneSharedSemanticWitness,
                SelectedPlanStateDefinitionClause::DecodedEquationConsistency,
                SelectedPlanStateDefinitionClause::ConstrainedCodeState,
                SelectedPlanStateDefinitionClause::AcceptingCanonicalSuffix,
            ]
            && self.transition_rows.len()
                == plan
                    .oracle_equation_catalog()
                    .ok()
                    .map_or(0, |catalog| catalog.operations.len())
            && self.proof_section_rows.len() == plan.proof_sections().len()
            && self.checkpoint_rows.len() == plan.checkpoints().len()
            && self.lifecycle_rows.len() == 8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateEpochRow {
    operation_ordinal: u32,
    predecessor_operation_ordinal: Option<u32>,
    transition_owner: StateTransitionOwner,
    first_equation_slot_ordinal: u64,
    equation_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OracleEquationRole {
    InitialHeaderRoot,
    InitialAbsorption,
    ResponseRoot,
    ResponseBinding,
    ResponseAbsorption,
    AcceptedChallenge,
    ChallengeHandle,
    RejectedChallenge,
    LinearExpansionBlock,
}

impl OracleEquationRole {
    const fn predecessor_support_count(self) -> u8 {
        match self {
            Self::InitialHeaderRoot | Self::ResponseRoot => 0,
            Self::InitialAbsorption
            | Self::ResponseBinding
            | Self::AcceptedChallenge
            | Self::ChallengeHandle
            | Self::RejectedChallenge
            | Self::LinearExpansionBlock => 1,
            Self::ResponseAbsorption => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleEquationRolePattern {
    Single(OracleEquationRole),
    Alternating {
        first: OracleEquationRole,
        second: OracleEquationRole,
    },
}

impl OracleEquationRolePattern {
    fn maximum_predecessor_support_count(self) -> u8 {
        match self {
            Self::Single(role) => role.predecessor_support_count(),
            Self::Alternating { first, second } => first
                .predecessor_support_count()
                .max(second.predecessor_support_count()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OracleEquationCoverageRow {
    operation_ordinal: u32,
    range_ordinal: u16,
    first_equation_slot_ordinal: u64,
    equation_count: u64,
    role_pattern: OracleEquationRolePattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MerkleOracleEquationRole {
    RelationPhase {
        phase: RowCodeWhirPhase,
    },
    BoundTree {
        bound_tree_ordinal: u32,
    },
    WhirEpoch {
        epoch_ordinal: u32,
    },
    AggregateWideMask {
        commitment_role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MerkleOracleEquationCoverageRow {
    role: MerkleOracleEquationRole,
    leaf_count: usize,
    query_count: usize,
    leaf_hash_query_count: u64,
    parent_hash_query_count: u64,
    accepting_database_equation_count_ceiling: u64,
    predecessor_support_ceiling: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedRelationPhaseOpeningRow {
    phase: RowCodeWhirPhase,
    leaf_count: usize,
    query_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedWhirEpochOpeningRow {
    commitment_role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
    epoch_ordinal: u32,
    leaf_count: usize,
    query_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CheckedSuppliedCommitmentOpeningRows {
    relation_phases: Vec<CheckedRelationPhaseOpeningRow>,
    whir_epochs: Vec<CheckedWhirEpochOpeningRow>,
    aggregate_wide_mask_openings: Vec<CheckedWhirEpochOpeningRow>,
}

impl MerkleOracleEquationCoverageRow {
    fn hash_query_count(self) -> Result<u64, WhirTheoremCertificateError> {
        self.leaf_hash_query_count
            .checked_add(self.parent_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    }
}

fn checked_supplied_commitment_opening_rows(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<CheckedSuppliedCommitmentOpeningRows, WhirTheoremCertificateError> {
    let transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let mut relation_phases = Vec::new();
    let mut whir_epochs = Vec::new();
    let mut aggregate_wide_mask_openings = Vec::new();
    for opening in transcript_plan.supplied_commitment_openings() {
        if opening.query_order
            != linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order
                != linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        match (opening.commitment_role, opening.owner) {
            (
                linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase { phase },
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
            ) => relation_phases.push(CheckedRelationPhaseOpeningRow {
                phase,
                leaf_count: opening.payload_leaf_count,
                query_count: opening.query_count,
            }),
            (
                commitment_role @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                    ..
                }),
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                    epoch_ordinal,
                },
            ) => whir_epochs.push(CheckedWhirEpochOpeningRow {
                commitment_role,
                epoch_ordinal,
                leaf_count: opening.payload_leaf_count,
                query_count: opening.query_count,
            }),
            (
                commitment_role
                @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource
                | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad),
                linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                    epoch_ordinal,
                },
            ) => aggregate_wide_mask_openings.push(CheckedWhirEpochOpeningRow {
                commitment_role,
                epoch_ordinal,
                leaf_count: opening.payload_leaf_count,
                query_count: opening.query_count,
            }),
            _ => return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping),
        }
    }
    if relation_phases
        .iter()
        .map(|row| row.phase)
        .collect::<Vec<_>>()
        != plan.phase_order
        || whir_epochs.len()
            != plan
                .whir
                .rounds
                .len()
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        || aggregate_wide_mask_openings.len() != 3
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    for (epoch_index, row) in whir_epochs.iter().enumerate() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let expected_commitment_role = if epoch_ordinal == 0 {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
        } else {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                round_ordinal: epoch_ordinal - 1,
            }
        };
        if row.epoch_ordinal != epoch_ordinal || row.commitment_role != expected_commitment_role {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    let final_source_epoch_ordinal = u32::try_from(whir_epochs.len() - 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_epoch_ordinal = final_source_epoch_ordinal
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_mask_openings = [
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
            pad_epoch_ordinal,
        ),
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
            final_source_epoch_ordinal,
        ),
        (
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
            pad_epoch_ordinal,
        ),
    ];
    if aggregate_wide_mask_openings
        .iter()
        .map(|row| (row.commitment_role, row.epoch_ordinal))
        .ne(expected_mask_openings)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(CheckedSuppliedCommitmentOpeningRows {
        relation_phases,
        whir_epochs,
        aggregate_wide_mask_openings,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedVerifierHashRole {
    RelationPlanIdentity,
    RelationPlanVariantIdentity,
    ConstructionPlanIdentity,
    ApplicationStatement,
    PublicSetupVerifierSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedVerifierHashCoverageRow {
    role: FixedVerifierHashRole,
    hash_query_count: u64,
    distinct_equation_count: u64,
    transcript_catalog_equation_overlap_count: u64,
}

impl FixedVerifierHashCoverageRow {
    fn new_equation_count(self) -> Result<u64, WhirTheoremCertificateError> {
        self.distinct_equation_count
            .checked_sub(self.transcript_catalog_equation_overlap_count)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteVerifierOracleLedger {
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
    merkle_rows: Vec<MerkleOracleEquationCoverageRow>,
    fixed_hash_rows: Vec<FixedVerifierHashCoverageRow>,
    complete_equation_count_ceiling: u64,
    complete_hash_query_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AggregateLeafOracleCallInventoryRow {
    role: MerkleOracleEquationRole,
    interleaving_width: usize,
    opened_leaf_count: u64,
    initial_hash_query_count: u64,
    transition_hash_query_count: u64,
    final_hash_query_count: u64,
    parent_hash_query_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateLeafSemanticTransition {
    SharedInitial {
        interleaving_width: usize,
    },
    Column {
        role: MerkleOracleEquationRole,
        column_index: usize,
    },
    Final {
        role: MerkleOracleEquationRole,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateLeafSemanticPredecessor {
    None,
    SharedInitial {
        interleaving_width: usize,
    },
    Column {
        role: MerkleOracleEquationRole,
        column_index: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AggregateLeafSemanticTransitionRow {
    transition: AggregateLeafSemanticTransition,
    predecessor: AggregateLeafSemanticPredecessor,
    frame: ColumnStreamableLeafOracleFrameDescriptor,
    hash_query_count: u64,
    accepting_database_equation_count_ceiling: u64,
}

/// Finite predecessor-closure proof for the deployed streaming leaf oracle.
///
/// One row represents each semantic equation class, not merely each call
/// count. In a collision-free accepting database the terminal leaf reverses
/// through the final frame, every ordered column transition, and the
/// width-specific shared initial frame. The recovered transition inputs carry
/// the canonical field coefficients that the verifier hashed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AggregateLeafSemanticTransitionCertificate {
    frame_descriptors: [ColumnStreamableLeafOracleFrameDescriptor; 3],
    rows: Vec<AggregateLeafSemanticTransitionRow>,
    hash_query_count: u64,
    accepting_database_equation_count_ceiling: u64,
    maximum_predecessor_support_count: u8,
}

impl AggregateLeafSemanticTransitionCertificate {
    fn is_complete_for_inventory(&self, inventory: &[AggregateLeafOracleCallInventoryRow]) -> bool {
        let Ok(production_frame_descriptors) = aggregate_leaf_frame_descriptors() else {
            return false;
        };
        let Ok(expected_rows) =
            aggregate_leaf_semantic_transition_rows(inventory, &production_frame_descriptors)
        else {
            return false;
        };
        let Some(expected_hash_query_count) = expected_rows
            .iter()
            .try_fold(0_u64, |count, row| count.checked_add(row.hash_query_count))
        else {
            return false;
        };
        let Some(expected_equation_count) = expected_rows.iter().try_fold(0_u64, |count, row| {
            count.checked_add(row.accepting_database_equation_count_ceiling)
        }) else {
            return false;
        };
        let expected_predecessor_support = expected_rows
            .iter()
            .map(|row| {
                u8::from(!matches!(
                    row.predecessor,
                    AggregateLeafSemanticPredecessor::None
                ))
            })
            .max()
            .unwrap_or(0);
        self.frame_descriptors == production_frame_descriptors
            && self.rows == expected_rows
            && self.hash_query_count == expected_hash_query_count
            && self.accepting_database_equation_count_ceiling == expected_equation_count
            && self.maximum_predecessor_support_count == expected_predecessor_support
            && self.maximum_predecessor_support_count == 1
    }
}

/// Exact SHAKE call inventory for the deployed aggregate leaf chain.
///
/// The abstract Merkle ledger treats a leaf hash as one oracle call. Production
/// instead makes one initial call, one transition call per encoded column, and
/// one final call. The initial input is repeated for every opened row and is
/// identical for every commitment with the same interleaving width; transition
/// and final inputs are conservatively distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeployedAggregateLeafOracleCertificate {
    rows: Vec<AggregateLeafOracleCallInventoryRow>,
    distinct_initial_equation_count: u64,
    repeated_initial_hash_query_count: u64,
    deployed_verifier_hash_query_count: u64,
    deployed_accepting_database_equation_count: u64,
    intermediate_oracle_output_bit_length: usize,
    final_oracle_output_bit_length: usize,
    minimum_oracle_output_bit_length: usize,
    classical_collision_penalty_numerator: BigUint,
    qrom_ideal_oracle_penalty_numerator: BigUint,
    collision_penalty_denominator_bit_length: usize,
    transition_collision_propagates_to_final_leaf: bool,
    uniform_required_output_geometry_established: bool,
    semantic_state_transitions: Option<AggregateLeafSemanticTransitionCertificate>,
}

impl DeployedAggregateLeafOracleCertificate {
    fn classical_collision_penalty_is_below_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.classical_collision_penalty_numerator << exponent)
            < (BigUint::one() << self.collision_penalty_denominator_bit_length)
    }

    fn qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.qrom_ideal_oracle_penalty_numerator << exponent)
            < (BigUint::one() << self.collision_penalty_denominator_bit_length)
    }

    fn has_complete_call_inventory(&self) -> bool {
        !self.rows.is_empty()
            && self.rows.iter().all(|row| {
                let Ok(interleaving_width) = u64::try_from(row.interleaving_width) else {
                    return false;
                };
                row.interleaving_width > 0
                    && row.opened_leaf_count > 0
                    && row.initial_hash_query_count == row.opened_leaf_count
                    && row.transition_hash_query_count
                        == row.opened_leaf_count.saturating_mul(interleaving_width)
                    && row.final_hash_query_count == row.opened_leaf_count
                    && row.parent_hash_query_count > 0
            })
            && self.distinct_initial_equation_count > 0
            && self.repeated_initial_hash_query_count > 0
            && self.deployed_verifier_hash_query_count > 0
            && self.deployed_accepting_database_equation_count > 0
            && self.intermediate_oracle_output_bit_length > 0
            && self.final_oracle_output_bit_length > 0
            && self.minimum_oracle_output_bit_length
                == self
                    .intermediate_oracle_output_bit_length
                    .min(self.final_oracle_output_bit_length)
            && self.collision_penalty_denominator_bit_length
                == self.minimum_oracle_output_bit_length
            && self.transition_collision_propagates_to_final_leaf
            && self.uniform_required_output_geometry_established
                == (self.intermediate_oracle_output_bit_length
                    == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
                    && self.final_oracle_output_bit_length
                        == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    }

    fn semantic_state_transition_correspondence_established(&self) -> bool {
        self.semantic_state_transitions
            .as_ref()
            .is_some_and(|certificate| certificate.is_complete_for_inventory(&self.rows))
    }

    fn is_eligible_for_uniform_required_output(&self) -> bool {
        self.has_complete_call_inventory()
            && self.uniform_required_output_geometry_established
            && self.semantic_state_transition_correspondence_established()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinateDerivedOpeningImplementation {
    RelationColumnCommitment,
    ExactBoundTree,
    AggregateWideWhir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitmentSubtreeExtractionRow {
    role: MerkleOracleEquationRole,
    implementation: CoordinateDerivedOpeningImplementation,
    leaf_count: usize,
    tree_height: usize,
    query_count: usize,
    leaf_hash_query_count: u64,
    parent_hash_query_count_ceiling: u64,
    predecessor_support_ceiling: u8,
}

/// Checked specialization of the binary-tree extractor from CMS19
/// Definition 6.3 and Lemmas 6.4--6.5 to every protocol Merkle tree reached by
/// the selected verifier.
///
/// The database extractor returns a unique partial tree when the random-oracle
/// database is collision free. It deliberately does not turn unopened leaves
/// into values: they remain undefined, and the production verifier rejects if
/// it needs one. Complete prover messages are a separate case because their
/// framed 512-bit response digests are recomputed directly from the fully
/// supplied canonical message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommitmentSubtreeExtractionCertificate {
    rows: Vec<CommitmentSubtreeExtractionRow>,
    supplied_commitment_root_count: usize,
    bound_tree_root_count: usize,
    canonical_complete_message_digest_count: u64,
    one_edge_sampler_message_count: u64,
    distinct_protocol_tree_role_count: usize,
    collision_free_extraction_is_unique: bool,
    database_growth_preserves_the_extracted_subtree: bool,
    changed_extracted_tree_requires_a_root_or_half_preimage: bool,
    missing_leaf_is_undefined: bool,
    queried_missing_leaf_is_rejected: bool,
    complete_message_digests_are_recomputed: bool,
    compact_frontiers_are_coordinate_derived: bool,
    coordinates_are_derived_from_accepted_transcript_order: bool,
}

impl CommitmentSubtreeExtractionCertificate {
    fn is_complete(&self) -> bool {
        !self.rows.is_empty()
            && self.distinct_protocol_tree_role_count == self.rows.len()
            && self.supplied_commitment_root_count > 0
            && self
                .supplied_commitment_root_count
                .checked_add(self.bound_tree_root_count)
                == Some(self.rows.len())
            && self.canonical_complete_message_digest_count > 0
            && self.one_edge_sampler_message_count > 0
            && self.rows.iter().all(|row| {
                row.leaf_count.is_power_of_two()
                    && usize::try_from(row.leaf_count.ilog2()).ok() == Some(row.tree_height)
                    && row.query_count > 0
                    && row.query_count <= row.leaf_count
                    && row.leaf_hash_query_count == row.query_count as u64
                    && row.parent_hash_query_count_ceiling > 0
                    && row.predecessor_support_ceiling <= 2
            })
            && self.collision_free_extraction_is_unique
            && self.database_growth_preserves_the_extracted_subtree
            && self.changed_extracted_tree_requires_a_root_or_half_preimage
            && self.missing_leaf_is_undefined
            && self.queried_missing_leaf_is_rejected
            && self.complete_message_digests_are_recomputed
            && self.compact_frontiers_are_coordinate_derived
            && self.coordinates_are_derived_from_accepted_transcript_order
    }
}

impl CompleteVerifierOracleLedger {
    fn merkle_hash_query_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.merkle_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.hash_query_count()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_hash_query_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_distinct_equation_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.distinct_equation_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    fn fixed_new_equation_count(&self) -> Result<u64, WhirTheoremCertificateError> {
        self.fixed_hash_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.new_equation_count()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19ArithmeticCertificate {
    adversarial_query_bound: BigUint,
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
    compiler_query_bound: BigUint,
    classical_soundness_multiplier: BigUint,
    ideal_oracle_penalty_numerator: BigUint,
    ideal_oracle_penalty_denominator_bit_length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19Transform {
    OriginalBcsStrongStateHashChainSectionEightSix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PropositionEightTwelvePartitionCase {
    AcceptingDatabaseContainsCollision,
    CollisionFreeAcceptingDatabaseYieldsFullTranscript,
    EarliestFalseToTrueVerifierStateTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatePredicateRequirement {
    OriginalBcsStrongStateRuntimeHashChainCorrespondence,
    CompleteSemanticStateTransitionCorrespondence,
    CanonicalPlanCursorCoverage,
    EmptyTranscriptIsFalse,
    ProverMoveCannotRepairFalseState,
    FullFalseTranscriptIsRejected,
    EveryVerifierChallengeHasOneTypedFailureOwner,
    EveryProofSectionHasOnePredicateOwner,
    EveryCheckpointHasOneStateOwner,
    LifecycleNonAcceptanceAndFreshVerification,
    SelectedUniqueDecodingInequalitiesHold,
    InterleavedDistanceAndListSizeHold,
    ExplicitUniqueDecoderExists,
    ExtractCompleteRelationPhaseCodewords,
    ExtractCompleteBoundCodewords,
    ExtractCompleteWhirEpochCodewords,
    ExplicitPointConstraintExtractorCorrespondence,
    ExtractThetaAndPhaseReductions,
    ExtractCompilerInterpreterRelationWitness,
    ExactFailureMagnitudeCorrespondence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatePredicateDischargeAuthority {
    GeneratedStrongStateTypedOracleCorrespondence,
    GeneratedWholeStateTransitionCorrespondence,
    GeneratedSelectedPlanStatePredicate,
    GeneratedFailureOwnerPartition,
    CheckedConstructionGeometry,
    CheckedInterleavedDistanceLemma,
    ExplicitBerlekampWelchExtractor,
    IndependentCompilerInterpreterArithmeticOracle,
    CheckedRoundByRoundPolynomialExtractor,
    CheckedExplicitPointConstraintExtractor,
    CheckedExactFailureMagnitudeCorrespondence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StatePredicateRequirementRow {
    requirement: StatePredicateRequirement,
    discharge_authority: StatePredicateDischargeAuthority,
    is_discharged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19StatePredicateCertificate {
    requirements: Vec<StatePredicateRequirementRow>,
    proposition_eight_twelve_partition: Vec<PropositionEightTwelvePartitionCase>,
    transcript_incompatibility_count: usize,
}

/// Exact correspondence between the live typed oracle graph and the
/// strong-state original-BCS argument described in CMS19 Section 8.6.
///
/// Sampler expansion blocks are verifier randomness generated outside prover
/// response absorption. An incomplete verifier message is represented by
/// `None` and inherits the predecessor state. Filling it is the only operation
/// that can cross from false to true, and the generated state table assigns
/// that fill exactly one failure event. This is the stronger state condition
/// required for the original one-edge challenge chain; it is not the modified
/// two-edge chain from Sections 8.2--8.5.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19StrongStateHashChainCertificate {
    logical_verifier_message_count: u64,
    typed_challenge_transition_count: u64,
    uniquely_owned_fill_transition_count: u64,
    topologically_ordered_equation_count: u64,
    oracle_edge_count: u64,
    sampler_expansion_edge_count: u64,
    prover_response_edge_count: u64,
    transcript_predecessor_support_ceiling: u8,
    undefined_message_inherits_predecessor_state: bool,
    sampler_messages_are_outside_prover_response_absorption: bool,
    typed_oracle_domains_are_pairwise_distinct: bool,
    canonical_oracle_plan_hash: [u8; 64],
}

impl Cms19StrongStateHashChainCertificate {
    fn is_complete(&self) -> bool {
        self.logical_verifier_message_count > 0
            && self.typed_challenge_transition_count == self.logical_verifier_message_count
            && self.uniquely_owned_fill_transition_count == self.logical_verifier_message_count
            && self.topologically_ordered_equation_count > 0
            && self.oracle_edge_count > self.sampler_expansion_edge_count
            && self.sampler_expansion_edge_count > 0
            && self.prover_response_edge_count > 0
            && self.transcript_predecessor_support_ceiling <= 2
            && self.undefined_message_inherits_predecessor_state
            && self.sampler_messages_are_outside_prover_response_absorption
            && self.typed_oracle_domains_are_pairwise_distinct
            && self.canonical_oracle_plan_hash != [0_u8; 64]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19DeterministicObservationOwner {
    ProtocolSchedule,
    OpeningPoint { batch_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19CanonicalProofLengthSource {
    TransportedHeaderValidatedByCanonicalDecoderAndStaticSectionLedger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19CanonicalResponseMessage {
    ExtensionValueList {
        value_count: usize,
        canonical_message_byte_length: usize,
    },
    CanonicalProofStream {
        proof_section_count: usize,
        length_source: Cms19CanonicalProofLengthSource,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cms19ResponseDigestBinding {
    message: Cms19CanonicalResponseMessage,
    response_root_range_ordinal: u16,
    response_root_equation_slot_ordinal: u64,
    response_root_domain: &'static str,
    output_bit_length: usize,
}

impl Cms19ResponseDigestBinding {
    fn is_valid(self) -> bool {
        let message_is_valid = match self.message {
            Cms19CanonicalResponseMessage::ExtensionValueList {
                value_count,
                canonical_message_byte_length,
            } => {
                let expected_value_byte_length =
                    PROOF_CHALLENGE_EXTENSION_DEGREE.checked_mul(std::mem::size_of::<u64>());
                let expected_message_byte_length = expected_value_byte_length.and_then(|length| {
                    value_count
                        .checked_mul(length)
                        .and_then(|message_length| message_length.checked_add(6))
                });
                value_count > 0
                    && expected_message_byte_length == Some(canonical_message_byte_length)
            }
            Cms19CanonicalResponseMessage::CanonicalProofStream {
                proof_section_count,
                length_source:
                    Cms19CanonicalProofLengthSource::TransportedHeaderValidatedByCanonicalDecoderAndStaticSectionLedger,
            } => proof_section_count > 0,
        };
        message_is_valid
            && self.response_root_range_ordinal > 0
            && self.response_root_equation_slot_ordinal > 0
            && self.response_root_domain == TRANSCRIPT_RESPONSE_ROOT_DOMAIN
            && self.output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19ProverOracleBinding {
    SuppliedCommitment {
        role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
        payload_leaf_count: usize,
    },
    CanonicalCompleteMessageDigest {
        response_digest: Cms19ResponseDigestBinding,
    },
}

impl Cms19ProverOracleBinding {
    fn is_valid_for(self, root: linear_bcs_transcript::LinearBcsProverOracleRoot) -> bool {
        match (self, root) {
            (
                Self::SuppliedCommitment {
                    role,
                    payload_leaf_count,
                },
                linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment {
                    role: root_role,
                    payload_leaf_count: root_payload_leaf_count,
                },
            ) => {
                role == root_role
                    && payload_leaf_count == root_payload_leaf_count
                    && payload_leaf_count.is_power_of_two()
            }
            (
                Self::CanonicalCompleteMessageDigest { response_digest },
                linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
                    value_count: root_value_count,
                    canonical_message_byte_length: root_message_byte_length,
                },
            ) => {
                response_digest.is_valid()
                    && response_digest.message
                        == (Cms19CanonicalResponseMessage::ExtensionValueList {
                            value_count: root_value_count,
                            canonical_message_byte_length: root_message_byte_length,
                        })
            }
            (
                Self::SuppliedCommitment { .. } | Self::CanonicalCompleteMessageDigest { .. },
                linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. },
            )
            | (
                Self::SuppliedCommitment { .. },
                linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
                    ..
                },
            )
            | (
                Self::CanonicalCompleteMessageDigest { .. },
                linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. },
            ) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19SemanticStateTransition {
    InitialCanonicalPrefix,
    ProverOracle {
        round_ordinal: u64,
        root: linear_bcs_transcript::LinearBcsProverOracleRoot,
        binding: Cms19ProverOracleBinding,
    },
    VerifierMessageFill {
        first_round_ordinal: u64,
        block_count: u64,
        terminal_round_ordinal: u64,
        failure_event_owner: SelectedPlanFailureEventOwner,
    },
    DeterministicObservation {
        owner: Cms19DeterministicObservationOwner,
        response_digest: Cms19ResponseDigestBinding,
    },
    TerminalDecision {
        final_query_round_ordinal: u64,
        response_digest: Cms19ResponseDigestBinding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19SemanticStateTransitionRow {
    operation_ordinal: u32,
    predecessor_operation_ordinal: Option<u32>,
    predicate_clause: SelectedPlanStatePredicateClause,
    first_equation_slot_ordinal: u64,
    equation_count: u64,
    transition: Cms19SemanticStateTransition,
}

/// Exact plan-to-strong-state correspondence for every transcript operation.
///
/// Unlike the category-level requirement census, these rows bind every
/// production operation to its concrete original-BCS round range, typed
/// verifier-message fill, deterministic observation, or terminal decision.
/// Prefix sampler blocks inherit the predecessor state; exactly the terminal
/// block owns the typed failure event. Operations intentionally omitted from
/// the BCS round list are accepted only when their values are deterministically
/// reconstructed from the checked plan or prior transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19WholeStateTransitionCertificate {
    construction_plan_identity_hash: [u8; 64],
    linear_bcs_transcript_plan_hash: [u8; 64],
    rows: Vec<Cms19SemanticStateTransitionRow>,
    covered_transcript_equation_count: u64,
    covered_bcs_round_count: u64,
    prover_oracle_round_count: u64,
    verifier_message_fill_count: u64,
    deterministic_observation_count: u64,
    response_digest_count: u64,
    final_query_round_ordinal: u64,
}

impl Cms19WholeStateTransitionCertificate {
    fn is_complete(&self) -> bool {
        let Some(covered_bcs_round_count) = self.rows.iter().try_fold(0_u64, |count, row| {
            let round_count = match row.transition {
                Cms19SemanticStateTransition::ProverOracle { .. } => 1,
                Cms19SemanticStateTransition::VerifierMessageFill { block_count, .. } => {
                    block_count
                }
                Cms19SemanticStateTransition::InitialCanonicalPrefix
                | Cms19SemanticStateTransition::DeterministicObservation { .. }
                | Cms19SemanticStateTransition::TerminalDecision { .. } => 0,
            };
            count.checked_add(round_count)
        }) else {
            return false;
        };
        let prover_oracle_round_count = self
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row.transition,
                    Cms19SemanticStateTransition::ProverOracle { .. }
                )
            })
            .count();
        let verifier_message_fill_count = self
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row.transition,
                    Cms19SemanticStateTransition::VerifierMessageFill { .. }
                )
            })
            .count();
        let deterministic_observation_count = self
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row.transition,
                    Cms19SemanticStateTransition::DeterministicObservation { .. }
                )
            })
            .count();
        let response_digest_count = self
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row.transition,
                    Cms19SemanticStateTransition::ProverOracle {
                        binding: Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { .. },
                        ..
                    } | Cms19SemanticStateTransition::DeterministicObservation { .. }
                        | Cms19SemanticStateTransition::TerminalDecision { .. }
                )
            })
            .count();
        let Some(expected_final_query_round_ordinal) = covered_bcs_round_count.checked_add(1)
        else {
            return false;
        };
        let mut covered_transcript_equation_count = 0_u64;
        for (row_index, row) in self.rows.iter().enumerate() {
            let Ok(operation_ordinal) = u32::try_from(row_index) else {
                return false;
            };
            if row.operation_ordinal != operation_ordinal
                || row.predecessor_operation_ordinal != operation_ordinal.checked_sub(1)
                || row.equation_count == 0
                || row.first_equation_slot_ordinal != covered_transcript_equation_count
            {
                return false;
            }
            let clause_matches_transition = match (row.predicate_clause, row.transition) {
                (
                    SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse,
                    Cms19SemanticStateTransition::InitialCanonicalPrefix,
                )
                | (
                    SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove,
                    Cms19SemanticStateTransition::ProverOracle { .. },
                )
                | (
                    SelectedPlanStatePredicateClause::DeterministicProtocolSchedule,
                    Cms19SemanticStateTransition::DeterministicObservation {
                        owner: Cms19DeterministicObservationOwner::ProtocolSchedule,
                        ..
                    },
                )
                | (
                    SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts,
                    Cms19SemanticStateTransition::TerminalDecision { .. },
                ) => true,
                (
                    SelectedPlanStatePredicateClause::DeterministicOpeningPoint {
                        batch_ordinal: expected_batch_ordinal,
                    },
                    Cms19SemanticStateTransition::DeterministicObservation {
                        owner: Cms19DeterministicObservationOwner::OpeningPoint { batch_ordinal },
                        ..
                    },
                ) => batch_ordinal == expected_batch_ordinal,
                (
                    SelectedPlanStatePredicateClause::PolynomialProtocolChallenge
                    | SelectedPlanStatePredicateClause::RelationReductionChallenge
                    | SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                    | SelectedPlanStatePredicateClause::BoundIdentityAgreement
                    | SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch
                    | SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch { .. }
                    | SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { .. }
                    | SelectedPlanStatePredicateClause::WhirConstrainedFold { .. }
                    | SelectedPlanStatePredicateClause::WhirQueryAgreement { .. }
                    | SelectedPlanStatePredicateClause::WhirQueryCombination { .. }
                    | SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement
                    | SelectedPlanStatePredicateClause::WhirBaseCaseBlinding,
                    Cms19SemanticStateTransition::VerifierMessageFill { .. },
                ) => true,
                _ => false,
            };
            if !clause_matches_transition {
                return false;
            }
            let transition_is_valid = match row.transition {
                Cms19SemanticStateTransition::InitialCanonicalPrefix => row_index == 0,
                Cms19SemanticStateTransition::ProverOracle {
                    round_ordinal,
                    root,
                    binding,
                } => round_ordinal > 0 && binding.is_valid_for(root),
                Cms19SemanticStateTransition::VerifierMessageFill {
                    first_round_ordinal,
                    block_count,
                    terminal_round_ordinal,
                    ..
                } => {
                    block_count > 0
                        && first_round_ordinal > 0
                        && first_round_ordinal.checked_add(block_count - 1)
                            == Some(terminal_round_ordinal)
                }
                Cms19SemanticStateTransition::DeterministicObservation {
                    response_digest, ..
                } => {
                    row_index > 0
                        && row_index + 1 < self.rows.len()
                        && response_digest.is_valid()
                        && matches!(
                            response_digest.message,
                            Cms19CanonicalResponseMessage::ExtensionValueList { .. }
                        )
                }
                Cms19SemanticStateTransition::TerminalDecision {
                    final_query_round_ordinal,
                    response_digest,
                } => {
                    row_index + 1 == self.rows.len()
                        && final_query_round_ordinal == self.final_query_round_ordinal
                        && response_digest.is_valid()
                        && matches!(
                            response_digest.message,
                            Cms19CanonicalResponseMessage::CanonicalProofStream { .. }
                        )
                }
            };
            if !transition_is_valid {
                return false;
            }
            let Some(next_count) =
                covered_transcript_equation_count.checked_add(row.equation_count)
            else {
                return false;
            };
            covered_transcript_equation_count = next_count;
        }
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.linear_bcs_transcript_plan_hash != [0_u8; 64]
            && !self.rows.is_empty()
            && covered_transcript_equation_count == self.covered_transcript_equation_count
            && covered_bcs_round_count == self.covered_bcs_round_count
            && u64::try_from(prover_oracle_round_count).ok() == Some(self.prover_oracle_round_count)
            && u64::try_from(verifier_message_fill_count).ok()
                == Some(self.verifier_message_fill_count)
            && u64::try_from(deterministic_observation_count).ok()
                == Some(self.deterministic_observation_count)
            && u64::try_from(response_digest_count).ok() == Some(self.response_digest_count)
            && self.final_query_round_ordinal == expected_final_query_round_ordinal
    }

    fn is_complete_for(
        &self,
        plan: &RowCodeWhirConstructionPlan,
        catalog: &RowCodeWhirOracleEquationCatalog,
        selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
    ) -> bool {
        self.is_complete()
            && derive_cms19_whole_state_transition_certificate(
                plan,
                catalog,
                selected_plan_state_predicate,
            )
            .is_ok_and(|expected| expected == *self)
    }

    fn matches_selected_plan_state_predicate(
        &self,
        selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
    ) -> bool {
        self.rows.len() == selected_plan_state_predicate.transition_rows.len()
            && self
                .rows
                .iter()
                .zip(&selected_plan_state_predicate.transition_rows)
                .all(|(semantic_row, selected_row)| {
                    let semantic_failure_event_owner = match semantic_row.transition {
                        Cms19SemanticStateTransition::VerifierMessageFill {
                            failure_event_owner,
                            ..
                        } => Some(failure_event_owner),
                        Cms19SemanticStateTransition::InitialCanonicalPrefix
                        | Cms19SemanticStateTransition::ProverOracle { .. }
                        | Cms19SemanticStateTransition::DeterministicObservation { .. }
                        | Cms19SemanticStateTransition::TerminalDecision { .. } => None,
                    };
                    semantic_row.operation_ordinal == selected_row.operation_ordinal
                        && semantic_row.predicate_clause == selected_row.predicate_clause
                        && semantic_failure_event_owner == selected_row.failure_event_owner
                })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cms19DatabaseSupportRole {
    TypedTranscript { role: OracleEquationRole },
    OrdinaryMerkleLeaf { role: MerkleOracleEquationRole },
    AggregateLeafInitial { interleaving_width: usize },
    AggregateLeafTransitionAndFinal { role: MerkleOracleEquationRole },
    MerkleParents { role: MerkleOracleEquationRole },
    FixedVerifierHash { role: FixedVerifierHashRole },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cms19DatabaseSupportRow {
    role: Cms19DatabaseSupportRole,
    hash_query_count: u64,
    accepting_database_equation_count: u64,
    predecessor_support_count: u8,
}

/// Complete support census for the accepting random-oracle database.
///
/// This expands the deployed aggregate leaf calls, keeps repeated initial
/// states distinct from cached equations, and separately accounts for typed
/// transcript, Merkle-parent, ordinary-leaf, and construction-bound fixed
/// hashes. The mapped totals must equal the deployed verifier ledger; no
/// uncovered count is supplied by the producer or assigned as a status flag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19WholeDatabaseSupportCertificate {
    construction_plan_identity_hash: [u8; 64],
    rows: Vec<Cms19DatabaseSupportRow>,
    mapped_hash_query_count: u64,
    mapped_accepting_database_equation_count: u64,
    claimed_hash_query_count: u64,
    claimed_accepting_database_equation_count: u64,
    whole_state_response_digest_count: u64,
    response_root_hash_query_count: u64,
    maximum_predecessor_support_count: u8,
}

impl Cms19WholeDatabaseSupportCertificate {
    fn is_complete(&self) -> bool {
        let mapped_hash_query_count = self
            .rows
            .iter()
            .try_fold(0_u64, |count, row| count.checked_add(row.hash_query_count));
        let mapped_accepting_database_equation_count =
            self.rows.iter().try_fold(0_u64, |count, row| {
                count.checked_add(row.accepting_database_equation_count)
            });
        let response_root_rows = self
            .rows
            .iter()
            .filter(|row| {
                row.role
                    == (Cms19DatabaseSupportRole::TypedTranscript {
                        role: OracleEquationRole::ResponseRoot,
                    })
            })
            .collect::<Vec<_>>();
        self.construction_plan_identity_hash != [0_u8; 64]
            && !self.rows.is_empty()
            && self.rows.iter().all(|row| {
                row.hash_query_count > 0
                    && row.accepting_database_equation_count > 0
                    && row.predecessor_support_count <= 2
            })
            && self.rows.iter().enumerate().all(|(row_index, row)| {
                self.rows[..row_index]
                    .iter()
                    .all(|preceding| preceding.role != row.role)
            })
            && mapped_hash_query_count == Some(self.mapped_hash_query_count)
            && mapped_accepting_database_equation_count
                == Some(self.mapped_accepting_database_equation_count)
            && self.mapped_hash_query_count == self.claimed_hash_query_count
            && self.mapped_accepting_database_equation_count
                == self.claimed_accepting_database_equation_count
            && self.whole_state_response_digest_count > 0
            && response_root_rows.len() == 1
            && response_root_rows[0].hash_query_count == self.response_root_hash_query_count
            && response_root_rows[0].accepting_database_equation_count
                == self.response_root_hash_query_count
            && self.response_root_hash_query_count == self.whole_state_response_digest_count
            && self.maximum_predecessor_support_count
                == self
                    .rows
                    .iter()
                    .map(|row| row.predecessor_support_count)
                    .max()
                    .unwrap_or(u8::MAX)
            && self.maximum_predecessor_support_count <= 2
    }

    fn uncovered_hash_query_count(&self) -> Option<u64> {
        self.claimed_hash_query_count
            .checked_sub(self.mapped_hash_query_count)
    }

    fn uncovered_accepting_database_equation_count(&self) -> Option<u64> {
        self.claimed_accepting_database_equation_count
            .checked_sub(self.mapped_accepting_database_equation_count)
    }
}

impl Cms19StatePredicateCertificate {
    fn is_complete(&self) -> bool {
        self.requirements.iter().all(|row| row.is_discharged)
            && self.transcript_incompatibility_count == 0
    }

    fn has_exact_abstract_partition(&self) -> bool {
        self.proposition_eight_twelve_partition
            == [
                PropositionEightTwelvePartitionCase::AcceptingDatabaseContainsCollision,
                PropositionEightTwelvePartitionCase::CollisionFreeAcceptingDatabaseYieldsFullTranscript,
                PropositionEightTwelvePartitionCase::EarliestFalseToTrueVerifierStateTransition,
            ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cms19ApplicabilityCertificate {
    transform: Cms19Transform,
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
    claimed_complete_equation_count: u64,
    claimed_complete_hash_query_count: u64,
    equation_count_without_catalog_correspondence: u64,
    hash_query_count_without_catalog_correspondence: u64,
    transcript_predecessor_support_ceiling: u8,
    complete_state_predicate_established: bool,
    syntactic_proposition_eight_twelve_partition_catalogued: bool,
    proposition_eight_twelve_case_split_established: bool,
    complete_query_ledger_correspondence_established: bool,
    strong_state_typed_hash_chain_established: bool,
    semantic_state_transition_correspondence_established: bool,
    deployed_oracle_output_geometry_established: bool,
}

impl Cms19ApplicabilityCertificate {
    fn is_complete(&self) -> bool {
        self.equation_count_without_catalog_correspondence == 0
            && self.hash_query_count_without_catalog_correspondence == 0
            && self.transcript_predecessor_support_ceiling <= 2
            && self.complete_state_predicate_established
            && self.syntactic_proposition_eight_twelve_partition_catalogued
            && self.proposition_eight_twelve_case_split_established
            && self.complete_query_ledger_correspondence_established
            && self.strong_state_typed_hash_chain_established
            && self.semantic_state_transition_correspondence_established
            && self.deployed_oracle_output_geometry_established
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProductionTraceChunkKey {
    phase: ConstructionMaskingPhase,
    column_ordinal: u32,
    coefficient_chunk_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionTraceChunkPlacement {
    key: ProductionTraceChunkKey,
    relation_tree_ordinal: u32,
    physical_row_ordinal: u32,
    column_group_ordinal: u32,
    lane_ordinal: u16,
    opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProductionOpenedPolynomialChunkKey {
    source: RowCodeWhirOpenedPolynomialSource,
    extension_coordinate_ordinal: u16,
    coefficient_chunk_ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionOpenedPolynomialChunkPlacement {
    key: ProductionOpenedPolynomialChunkKey,
    physical_row_ordinal: u32,
    source_group_ordinal: u32,
    coefficient_chunk_group_start_ordinal: u32,
    lane_ordinal: u16,
    opening_point_ordinals: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProductionBoundColumnCoordinate {
    relation_tree_ordinal: u32,
    column_ordinal: u32,
    root_use: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProductionOpeningCoordinate {
    source_class: u16,
    source_ordinal: u32,
    column_ordinal: Option<u32>,
    opening_point_ordinal: u32,
}

impl ProductionOpeningCoordinate {
    const fn source_key(self) -> (u16, u32, Option<u32>) {
        (self.source_class, self.source_ordinal, self.column_ordinal)
    }

    const fn secret_view_identifier(self) -> ConstructionSecretViewIdentifier {
        ConstructionSecretViewIdentifier::Opening {
            source_class: self.source_class,
            source_ordinal: self.source_ordinal,
            column_ordinal: self.column_ordinal,
            opening_point_ordinal: self.opening_point_ordinal,
        }
    }
}

/// Independent production-side correspondence for every secret-bearing view
/// before the aggregate-wide opening argument.
///
/// The relation checker supplies the abstract source/view graph. This
/// certificate separately walks the physical construction rows, opened
/// polynomial chunks, bound columns, aggregate roles, and transcript query
/// schedules. It then requires the two derivations to agree after canonical
/// ordering. Public-only relations retain the complete physical census but
/// intentionally have no private source/view graph.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionConstructionMaskingCorrespondenceCertificate {
    proof_privacy_mode: ProofPrivacyMode,
    construction_plan_identity_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    logical_polynomials_per_physical_row: usize,
    relation_phase_order: Vec<ConstructionMaskingPhase>,
    production_phase_order: Vec<ConstructionMaskingPhase>,
    expected_trace_chunks: Vec<ProductionTraceChunkKey>,
    trace_chunk_placements: Vec<ProductionTraceChunkPlacement>,
    expected_opened_polynomial_chunks: Vec<ProductionOpenedPolynomialChunkKey>,
    opened_polynomial_chunk_placements: Vec<ProductionOpenedPolynomialChunkPlacement>,
    relation_bound_columns: Vec<ProductionBoundColumnCoordinate>,
    production_bound_columns: Vec<ProductionBoundColumnCoordinate>,
    relation_openings: Vec<ProductionOpeningCoordinate>,
    production_openings: Vec<ProductionOpeningCoordinate>,
    relation_all_opening_points: Vec<u32>,
    relation_aggregate_opening_points: Vec<u32>,
    production_aggregate_opening_points: Vec<u32>,
    relation_graph: Option<ConstructionMaskingCorrespondence>,
    production_sources: Vec<ConstructionMaskSourceDescriptor>,
    production_views: Vec<ConstructionSecretViewDescriptor>,
    production_rank_requirements: Vec<ConstructionMaskingRankRequirement>,
    production_opening_batch_mask_source: Option<ConstructionMaskSourceIdentifier>,
    production_aggregate_wide_pad_source: Option<ConstructionMaskSourceIdentifier>,
}

fn canonical_construction_secret_views(
    mut views: Vec<ConstructionSecretViewDescriptor>,
) -> Vec<ConstructionSecretViewDescriptor> {
    for view in &mut views {
        view.direct_mask_dependencies
            .sort_by_key(|dependency| (dependency.source, dependency.coefficient));
    }
    views.sort_by_key(|view| view.identifier);
    views
}

fn construction_phase_for_row_code_phase(phase: RowCodeWhirPhase) -> ConstructionMaskingPhase {
    match phase {
        RowCodeWhirPhase::Base => ConstructionMaskingPhase::Base,
        RowCodeWhirPhase::Auxiliary => ConstructionMaskingPhase::Auxiliary,
        RowCodeWhirPhase::Quotient => ConstructionMaskingPhase::Quotient,
    }
}

fn construction_phase_for_tree_role(tree_role: ProofTreeRole) -> ConstructionMaskingPhase {
    match tree_role {
        ProofTreeRole::BaseOracle => ConstructionMaskingPhase::Base,
        ProofTreeRole::AuxiliaryOracle => ConstructionMaskingPhase::Auxiliary,
    }
}

fn relation_mask_source_identifier(
    mask: RelationMaskDescriptor,
) -> ConstructionMaskSourceIdentifier {
    ConstructionMaskSourceIdentifier::RelationMask {
        purpose_class: mask.mask_coordinate().purpose_class(),
        mask_ordinal: mask.mask_coordinate().mask_ordinal(),
        target_class: mask.target_class() as u16,
        target_ordinal: mask.target_ordinal(),
    }
}

fn checked_sorted_unique<T: Ord + Clone>(
    values: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, WhirTheoremCertificateError> {
    let values = values.into_iter().collect::<Vec<_>>();
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(unique.into_iter().collect())
}

fn opening_points_for_source(
    openings: &[ProductionOpeningCoordinate],
    source_key: (u16, u32, Option<u32>),
) -> Vec<u32> {
    openings
        .iter()
        .filter_map(|opening| {
            (opening.source_key() == source_key).then_some(opening.opening_point_ordinal)
        })
        .collect()
}

fn production_trace_chunk_key_set(
    placements: &[ProductionTraceChunkPlacement],
) -> Option<BTreeSet<ProductionTraceChunkKey>> {
    let keys = placements
        .iter()
        .map(|placement| placement.key)
        .collect::<BTreeSet<_>>();
    (keys.len() == placements.len()).then_some(keys)
}

fn production_opened_polynomial_chunk_key_set(
    placements: &[ProductionOpenedPolynomialChunkPlacement],
) -> Option<BTreeSet<ProductionOpenedPolynomialChunkKey>> {
    let keys = placements
        .iter()
        .map(|placement| placement.key)
        .collect::<BTreeSet<_>>();
    (keys.len() == placements.len()).then_some(keys)
}

impl ProductionConstructionMaskingCorrespondenceCertificate {
    fn is_complete(&self) -> bool {
        let expected_trace_chunks = self
            .expected_trace_chunks
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_opened_polynomial_chunks = self
            .expected_opened_polynomial_chunks
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let trace_placements_are_injective = self
            .trace_chunk_placements
            .iter()
            .map(|placement| {
                (
                    placement.key.phase,
                    placement.physical_row_ordinal,
                    placement.lane_ordinal,
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
            == self.trace_chunk_placements.len();
        let opened_polynomial_placements_are_injective = self
            .opened_polynomial_chunk_placements
            .iter()
            .map(|placement| (placement.physical_row_ordinal, placement.lane_ordinal))
            .collect::<BTreeSet<_>>()
            .len()
            == self.opened_polynomial_chunk_placements.len();
        let physical_rows_use_declared_width =
            self.trace_chunk_placements.iter().all(|placement| {
                usize::from(placement.lane_ordinal) < self.logical_polynomials_per_physical_row
                    && !placement.opening_point_ordinals.is_empty()
            }) && self
                .opened_polynomial_chunk_placements
                .iter()
                .all(|placement| {
                    usize::from(placement.lane_ordinal) < self.logical_polynomials_per_physical_row
                        && !placement.opening_point_ordinals.is_empty()
                });
        let trace_chunks_are_complete = if expected_trace_chunks.is_empty() {
            self.proof_privacy_mode == ProofPrivacyMode::PublicOnly
                && self.trace_chunk_placements.is_empty()
                && self.production_phase_order == [ConstructionMaskingPhase::Quotient]
        } else {
            production_trace_chunk_key_set(&self.trace_chunk_placements)
                == Some(expected_trace_chunks)
        };
        let phase_and_physical_catalogs_are_complete = self.relation_phase_order
            == self.production_phase_order
            && self.production_phase_order.last() == Some(&ConstructionMaskingPhase::Quotient)
            && trace_chunks_are_complete
            && !expected_opened_polynomial_chunks.is_empty()
            && production_opened_polynomial_chunk_key_set(&self.opened_polynomial_chunk_placements)
                == Some(expected_opened_polynomial_chunks)
            && trace_placements_are_injective
            && opened_polynomial_placements_are_injective
            && physical_rows_use_declared_width
            && self.relation_bound_columns == self.production_bound_columns
            && self.relation_openings == self.production_openings
            && self.relation_all_opening_points == self.production_aggregate_opening_points
            && self.relation_aggregate_opening_points.iter().all(|point| {
                self.relation_all_opening_points
                    .binary_search(point)
                    .is_ok()
            })
            && !self.relation_openings.is_empty()
            && !self.relation_all_opening_points.is_empty()
            && !self.relation_aggregate_opening_points.is_empty();

        let graph_is_complete = match (self.proof_privacy_mode, self.relation_graph.as_ref()) {
            (ProofPrivacyMode::PublicOnly, None) => {
                self.production_sources.is_empty()
                    && self.production_views.is_empty()
                    && self.production_rank_requirements.is_empty()
                    && self.production_opening_batch_mask_source.is_none()
                    && self.production_aggregate_wide_pad_source.is_none()
            }
            (ProofPrivacyMode::SecretBearing, Some(relation_graph)) => {
                self.production_sources == relation_graph.sources
                    && canonical_construction_secret_views(self.production_views.clone())
                        == canonical_construction_secret_views(relation_graph.views.clone())
                    && self.production_rank_requirements
                        == relation_graph.rank_requirements.to_vec()
                    && self.production_opening_batch_mask_source
                        == Some(relation_graph.opening_batch_mask_source)
                    && self.production_aggregate_wide_pad_source
                        == Some(relation_graph.aggregate_wide_pad_source)
                    && !self.production_sources.is_empty()
                    && !self.production_views.is_empty()
                    && self.production_rank_requirements.as_slice()
                        == [ConstructionMaskingRankRequirement {
                            kind: ConstructionMaskingRankKind::RowPadEvaluation,
                            source_dimension: self.production_rank_requirements[0].source_dimension,
                            required_rank: self.production_rank_requirements[0].required_rank,
                            verification:
                                ConstructionMaskingRankVerification::DistinctPointVandermonde,
                        }]
                    && self.production_rank_requirements[0].source_dimension
                        >= self.production_rank_requirements[0].required_rank
            }
            _ => false,
        };

        self.construction_plan_identity_hash != [0_u8; 64]
            && self.relation_plan_variant_hash != [0_u8; 64]
            && self.logical_polynomials_per_physical_row > 0
            && phase_and_physical_catalogs_are_complete
            && graph_is_complete
    }

    fn is_complete_for(
        &self,
        plan: &RowCodeWhirConstructionPlan,
        relation_variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
    ) -> bool {
        self.is_complete()
            && derive_production_construction_masking_correspondence(
                plan,
                relation_variant,
                relation_context,
            )
            .is_ok_and(|expected| expected == *self)
    }
}

fn derive_production_construction_masking_correspondence(
    plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<ProductionConstructionMaskingCorrespondenceCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let relation_plan_variant_hash = relation_variant
        .canonical_hash()
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if plan.proof_privacy_mode != relation_variant.proof_privacy_mode()
        || plan.relation_plan_variant_hash != relation_plan_variant_hash
        || plan.trace_domain_size != relation_variant.trace_domain_size()
        || plan.evaluation_domain_size != relation_variant.evaluation_domain_size()
        || plan.opening_degree_bound_exclusive != relation_variant.opening_degree_bound_exclusive()
        || parameters.logical_polynomials_per_physical_row == 0
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let relation_graph = checked_construction_masking_correspondence_for_parameters(
        relation_variant,
        relation_context,
        parameters,
    )
    .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if relation_graph.is_some() != (plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing) {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let relation_openings = checked_sorted_unique(
        relation_variant
            .ordered_opening_claims()
            .iter()
            .map(|claim| ProductionOpeningCoordinate {
                source_class: claim.source_class() as u16,
                source_ordinal: claim.source_ordinal(),
                column_ordinal: claim.column_ordinal(),
                opening_point_ordinal: claim.opening_point_ordinal(),
            }),
    )?;
    for opening in &relation_openings {
        let opening_point_index = usize::try_from(opening.opening_point_ordinal)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let source_class_is_known = matches!(
            opening.source_class,
            value if value == RelationOpeningSourceClass::TreeColumn as u16
                || value == RelationOpeningSourceClass::Quotient as u16
                || value == RelationOpeningSourceClass::BatchMask as u16
        );
        if opening_point_index >= relation_variant.ordered_opening_points().len()
            || !source_class_is_known
            || (opening.source_class == RelationOpeningSourceClass::TreeColumn as u16)
                != opening.column_ordinal.is_some()
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
    }

    let mut proof_tree_by_phase = BTreeMap::<ConstructionMaskingPhase, (u32, BTreeSet<u32>)>::new();
    let mut relation_bound_tree_ordinals = BTreeSet::new();
    for (tree_index, tree) in relation_variant.ordered_trees().iter().enumerate() {
        let relation_tree_ordinal = u32::try_from(tree_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let phase = match *proof_tree_role {
                    value if value == ProofTreeRole::BaseOracle as u16 => {
                        ConstructionMaskingPhase::Base
                    }
                    value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                        ConstructionMaskingPhase::Auxiliary
                    }
                    _ => {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                };
                let columns = ordered_column_ordinals
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                if columns.len() != ordered_column_ordinals.len()
                    || columns.is_empty()
                    || proof_tree_by_phase
                        .insert(phase, (relation_tree_ordinal, columns))
                        .is_some()
                {
                    return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                }
            }
            RelationTreeDescriptor::BoundPublic { .. } => {
                relation_bound_tree_ordinals.insert(relation_tree_ordinal);
            }
        }
    }

    let mut relation_phase_order = Vec::new();
    for phase in [
        ConstructionMaskingPhase::Base,
        ConstructionMaskingPhase::Auxiliary,
    ] {
        if proof_tree_by_phase.contains_key(&phase) {
            relation_phase_order.push(phase);
        }
    }
    relation_phase_order.push(ConstructionMaskingPhase::Quotient);
    let production_phase_order = plan
        .phase_order
        .iter()
        .copied()
        .map(construction_phase_for_row_code_phase)
        .collect::<Vec<_>>();
    if production_phase_order != relation_phase_order {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let phase_plans = [
        (ConstructionMaskingPhase::Base, plan.base_phase.as_ref()),
        (
            ConstructionMaskingPhase::Auxiliary,
            plan.auxiliary_phase.as_ref(),
        ),
    ];
    let mut expected_trace_chunks = BTreeSet::new();
    let mut trace_chunk_placements = Vec::new();
    let mut production_openings = BTreeSet::new();
    let mut phase_by_column = BTreeMap::new();
    let mut proof_tree_ordinal_by_column = BTreeMap::new();
    for (phase, phase_plan) in phase_plans {
        let relation_tree = proof_tree_by_phase.get(&phase);
        let (Some(phase_plan), Some((relation_tree_ordinal, relation_columns))) =
            (phase_plan, relation_tree)
        else {
            if phase_plan.is_some() || relation_tree.is_some() {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            continue;
        };
        if construction_phase_for_tree_role(phase_plan.tree_role) != phase
            || phase_plan.geometry.row_count != phase_plan.rows.len()
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let mut expected_opening_points_by_column = BTreeMap::new();
        for column_ordinal in relation_columns {
            let column_index = usize::try_from(*column_ordinal)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let column = relation_variant
                .ordered_columns()
                .get(column_index)
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            if !matches!(column.origin(), RelationColumnOrigin::Prover)
                || phase_by_column.insert(*column_ordinal, phase).is_some()
                || proof_tree_ordinal_by_column
                    .insert(*column_ordinal, *relation_tree_ordinal)
                    .is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            let opening_points = opening_points_for_source(
                &relation_openings,
                (
                    RelationOpeningSourceClass::TreeColumn as u16,
                    *relation_tree_ordinal,
                    Some(*column_ordinal),
                ),
            );
            if opening_points.is_empty() {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            expected_opening_points_by_column.insert(*column_ordinal, opening_points.clone());
            for opening_point_ordinal in opening_points {
                production_openings.insert(ProductionOpeningCoordinate {
                    source_class: RelationOpeningSourceClass::TreeColumn as u16,
                    source_ordinal: *relation_tree_ordinal,
                    column_ordinal: Some(*column_ordinal),
                    opening_point_ordinal,
                });
            }
            let chunk_count = super::coefficient_chunk_count(
                column.source_degree_bound_exclusive(),
                parameters.logical_polynomial_coefficient_count,
            )
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            for chunk_index in 0..chunk_count {
                expected_trace_chunks.insert(ProductionTraceChunkKey {
                    phase,
                    column_ordinal: *column_ordinal,
                    coefficient_chunk_ordinal: u32::try_from(chunk_index)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                });
            }
        }
        for (row_index, row) in phase_plan.rows.iter().enumerate() {
            if row.opening_point_ordinals.is_empty() {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            let mut row_has_chunk = false;
            let mut saw_padding_lane = false;
            for (lane_index, chunk) in row.logical_polynomial_chunks.iter().enumerate() {
                if lane_index >= parameters.logical_polynomials_per_physical_row {
                    if chunk.is_some() {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                    continue;
                }
                let Some(chunk) = chunk else {
                    saw_padding_lane = true;
                    continue;
                };
                if saw_padding_lane
                    || chunk.coefficient_chunk_ordinal != row.coefficient_chunk_ordinal
                    || !relation_columns.contains(&chunk.column_ordinal)
                    || expected_opening_points_by_column.get(&chunk.column_ordinal)
                        != Some(&row.opening_point_ordinals)
                {
                    return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                }
                row_has_chunk = true;
                trace_chunk_placements.push(ProductionTraceChunkPlacement {
                    key: ProductionTraceChunkKey {
                        phase,
                        column_ordinal: chunk.column_ordinal,
                        coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                    },
                    relation_tree_ordinal: *relation_tree_ordinal,
                    physical_row_ordinal: u32::try_from(row_index)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                    column_group_ordinal: row.column_group_ordinal,
                    lane_ordinal: u16::try_from(lane_index)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                    opening_point_ordinals: row.opening_point_ordinals.clone(),
                });
            }
            if !row_has_chunk {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
        }
    }
    if production_trace_chunk_key_set(&trace_chunk_placements)
        != Some(expected_trace_chunks.clone())
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let quotient_plan = &plan.quotient_phase;
    if quotient_plan.quotient_component_count != relation_context.quotient_component_count
        || quotient_plan.quotient_component_degree_bound_exclusive
            != relation_context.quotient_component_degree_bound_exclusive
        || quotient_plan.geometry.row_count != quotient_plan.rows.len()
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let opening_batch_mask = relation_variant
        .ordered_masks()
        .iter()
        .copied()
        .filter(|mask| {
            mask.mask_kind() == RelationMaskKind::OpeningBatch
                && mask.target_class() == RelationMaskTargetClass::Batch
        })
        .collect::<Vec<_>>();
    let opening_batch_mask = match (plan.proof_privacy_mode, opening_batch_mask.as_slice()) {
        (ProofPrivacyMode::PublicOnly, []) => {
            if quotient_plan
                .opening_batch_mask_degree_bound_exclusive
                .is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            None
        }
        (ProofPrivacyMode::SecretBearing, [mask])
            if quotient_plan.opening_batch_mask_degree_bound_exclusive
                == Some(mask.mask_degree_bound_exclusive()) =>
        {
            Some(*mask)
        }
        _ => return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
    };

    let quotient_chunk_count = super::coefficient_chunk_count(
        quotient_plan.quotient_component_degree_bound_exclusive,
        parameters.logical_polynomial_coefficient_count,
    )
    .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    let mut expected_opened_polynomial_chunks = BTreeSet::new();
    let mut opening_points_by_opened_source = BTreeMap::new();
    for component_ordinal in 0..quotient_plan.quotient_component_count {
        let source = RowCodeWhirOpenedPolynomialSource::QuotientComponent { component_ordinal };
        let opening_points = opening_points_for_source(
            &relation_openings,
            (
                RelationOpeningSourceClass::Quotient as u16,
                component_ordinal,
                None,
            ),
        );
        if opening_points.is_empty() {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        opening_points_by_opened_source.insert(source, opening_points.clone());
        for opening_point_ordinal in opening_points {
            production_openings.insert(ProductionOpeningCoordinate {
                source_class: RelationOpeningSourceClass::Quotient as u16,
                source_ordinal: component_ordinal,
                column_ordinal: None,
                opening_point_ordinal,
            });
        }
        for extension_coordinate_ordinal in 0..relation_context.challenge_extension_degree {
            for chunk_index in 0..quotient_chunk_count {
                expected_opened_polynomial_chunks.insert(ProductionOpenedPolynomialChunkKey {
                    source,
                    extension_coordinate_ordinal,
                    coefficient_chunk_ordinal: u32::try_from(chunk_index)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                });
            }
        }
    }
    if let Some(mask) = opening_batch_mask {
        let source = RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
            mask_ordinal: mask.mask_coordinate().mask_ordinal(),
        };
        let opening_points = opening_points_for_source(
            &relation_openings,
            (RelationOpeningSourceClass::BatchMask as u16, 0, None),
        );
        if opening_points.is_empty() {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        opening_points_by_opened_source.insert(source, opening_points.clone());
        for opening_point_ordinal in opening_points {
            production_openings.insert(ProductionOpeningCoordinate {
                source_class: RelationOpeningSourceClass::BatchMask as u16,
                source_ordinal: 0,
                column_ordinal: None,
                opening_point_ordinal,
            });
        }
        let mask_chunk_count = super::coefficient_chunk_count(
            mask.mask_degree_bound_exclusive(),
            parameters.logical_polynomial_coefficient_count,
        )
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        for extension_coordinate_ordinal in 0..relation_context.challenge_extension_degree {
            for chunk_index in 0..mask_chunk_count {
                expected_opened_polynomial_chunks.insert(ProductionOpenedPolynomialChunkKey {
                    source,
                    extension_coordinate_ordinal,
                    coefficient_chunk_ordinal: u32::try_from(chunk_index)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                });
            }
        }
    }

    let mut opened_polynomial_chunk_placements = Vec::new();
    for (row_index, row) in quotient_plan.rows.iter().enumerate() {
        if row.opening_point_ordinals.is_empty()
            || row.extension_coordinate_ordinal >= relation_context.challenge_extension_degree
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let mut row_has_chunk = false;
        let mut saw_padding_lane = false;
        let mut minimum_chunk_ordinal = None;
        for (lane_index, chunk) in row.logical_polynomial_chunks.iter().enumerate() {
            if lane_index >= parameters.logical_polynomials_per_physical_row {
                if chunk.is_some() {
                    return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                }
                continue;
            }
            let Some(chunk) = chunk else {
                saw_padding_lane = true;
                continue;
            };
            if saw_padding_lane
                || opening_points_by_opened_source.get(&chunk.source)
                    != Some(&row.opening_point_ordinals)
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            let expected_source_class = match chunk.source {
                RowCodeWhirOpenedPolynomialSource::QuotientComponent { .. } => {
                    RelationOpeningSourceClass::Quotient
                }
                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { .. } => {
                    RelationOpeningSourceClass::BatchMask
                }
            };
            if row.source_class != expected_source_class {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            minimum_chunk_ordinal = Some(
                minimum_chunk_ordinal.map_or(chunk.coefficient_chunk_ordinal, |current: u32| {
                    current.min(chunk.coefficient_chunk_ordinal)
                }),
            );
            row_has_chunk = true;
            opened_polynomial_chunk_placements.push(ProductionOpenedPolynomialChunkPlacement {
                key: ProductionOpenedPolynomialChunkKey {
                    source: chunk.source,
                    extension_coordinate_ordinal: row.extension_coordinate_ordinal,
                    coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                },
                physical_row_ordinal: u32::try_from(row_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                source_group_ordinal: row.source_group_ordinal,
                coefficient_chunk_group_start_ordinal: row.coefficient_chunk_group_start_ordinal,
                lane_ordinal: u16::try_from(lane_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                opening_point_ordinals: row.opening_point_ordinals.clone(),
            });
        }
        if !row_has_chunk
            || minimum_chunk_ordinal != Some(row.coefficient_chunk_group_start_ordinal)
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
    }
    if production_opened_polynomial_chunk_key_set(&opened_polynomial_chunk_placements)
        != Some(expected_opened_polynomial_chunks.clone())
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let mut relation_bound_columns = Vec::new();
    let mut production_bound_columns = Vec::new();
    let mut bound_source_by_tree_and_column = BTreeMap::new();
    let mut seen_relation_bound_tree_ordinals = BTreeSet::new();
    for (bound_tree_index, bound_tree) in plan.bound_trees.iter().enumerate() {
        if usize::try_from(bound_tree.bound_tree_ordinal).ok() != Some(bound_tree_index)
            || !seen_relation_bound_tree_ordinals.insert(bound_tree.relation_tree_ordinal)
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let relation_tree = relation_variant
            .ordered_trees()
            .get(
                usize::try_from(bound_tree.relation_tree_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } = relation_tree
        else {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        };
        if bound_tree.construction_kind != *construction_kind
            || bound_tree.expected_root_source_ordinal != *expected_root_source_ordinal
            || bound_tree.root_use != *root_use
            || bound_tree.ordered_columns.len() != ordered_column_ordinals.len()
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        for (column_plan, relation_column_ordinal) in bound_tree
            .ordered_columns
            .iter()
            .zip(ordered_column_ordinals)
        {
            let relation_column = relation_variant
                .ordered_columns()
                .get(
                    usize::try_from(*relation_column_ordinal)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            let opening_points = opening_points_for_source(
                &relation_openings,
                (
                    RelationOpeningSourceClass::TreeColumn as u16,
                    bound_tree.relation_tree_ordinal,
                    Some(*relation_column_ordinal),
                ),
            );
            if column_plan.column_ordinal != *relation_column_ordinal
                || column_plan.value_type != relation_column.value_type()
                || column_plan.source_degree_bound_exclusive
                    != relation_column.source_degree_bound_exclusive()
                || column_plan.opening_point_ordinals != opening_points
                || opening_points.is_empty()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            let coordinate = ProductionBoundColumnCoordinate {
                relation_tree_ordinal: bound_tree.relation_tree_ordinal,
                column_ordinal: *relation_column_ordinal,
                root_use: *root_use as u16,
            };
            relation_bound_columns.push(coordinate);
            production_bound_columns.push(coordinate);
            bound_source_by_tree_and_column.insert(
                (bound_tree.relation_tree_ordinal, *relation_column_ordinal),
                ConstructionMaskSourceIdentifier::BoundColumn {
                    relation_tree_ordinal: bound_tree.relation_tree_ordinal,
                    column_ordinal: *relation_column_ordinal,
                    root_use: *root_use as u16,
                },
            );
            for opening_point_ordinal in opening_points {
                production_openings.insert(ProductionOpeningCoordinate {
                    source_class: RelationOpeningSourceClass::TreeColumn as u16,
                    source_ordinal: bound_tree.relation_tree_ordinal,
                    column_ordinal: Some(*relation_column_ordinal),
                    opening_point_ordinal,
                });
            }
        }
    }
    if seen_relation_bound_tree_ordinals != relation_bound_tree_ordinals {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    relation_bound_columns.sort_unstable();
    production_bound_columns.sort_unstable();
    let production_openings = production_openings.into_iter().collect::<Vec<_>>();
    if production_openings != relation_openings {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let relation_aggregate_opening_points = relation_openings
        .iter()
        .map(|opening| opening.opening_point_ordinal)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let production_aggregate_opening_points = plan
        .aggregate_column_roles
        .iter()
        .filter_map(|role| match role {
            RowCodeWhirAggregateColumnRole::OpeningPoint {
                opening_point_ordinal,
            } => Some(*opening_point_ordinal),
            RowCodeWhirAggregateColumnRole::BoundReduction => None,
        })
        .collect::<Vec<_>>();
    let expected_all_opening_points = (0..relation_variant.ordered_opening_points().len())
        .map(u32::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let bound_reduction_role_count = plan
        .aggregate_column_roles
        .iter()
        .filter(|role| matches!(role, RowCodeWhirAggregateColumnRole::BoundReduction))
        .count();
    if production_aggregate_opening_points != expected_all_opening_points
        || relation_aggregate_opening_points
            .iter()
            .any(|point| expected_all_opening_points.binary_search(point).is_err())
        || bound_reduction_role_count != usize::from(!plan.bound_reduction_blocks.is_empty())
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let mut production_sources = BTreeMap::new();
    let mut production_views = Vec::new();
    let mut production_rank_requirements = Vec::new();
    let mut production_opening_batch_mask_source = None;
    let mut production_aggregate_wide_pad_source = None;
    if plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
        let mut trace_source_by_column = BTreeMap::new();
        let mut telescoping_source_by_component = BTreeMap::new();
        for mask in relation_variant.ordered_masks().iter().copied() {
            let source = relation_mask_source_identifier(mask);
            if production_sources
                .insert(
                    source,
                    ConstructionMaskSourceDescriptor::current_attempt(source),
                )
                .is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            match (mask.mask_kind(), mask.target_class()) {
                (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                    if trace_source_by_column
                        .insert(mask.target_ordinal(), source)
                        .is_some()
                    {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                }
                (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent) => {
                    if telescoping_source_by_component
                        .insert(mask.target_ordinal(), source)
                        .is_some()
                    {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                }
                (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                    if production_opening_batch_mask_source
                        .replace(source)
                        .is_some()
                    {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                }
                _ => return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
            }
        }
        let opening_batch_mask_source = production_opening_batch_mask_source
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if trace_source_by_column
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != phase_by_column.keys().copied().collect::<BTreeSet<_>>()
            || telescoping_source_by_component.len()
                != usize::try_from(
                    relation_context
                        .quotient_component_count
                        .checked_sub(1)
                        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
                )
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }

        let mut row_pad_source_by_phase = BTreeMap::new();
        for phase in &production_phase_order {
            let source = ConstructionMaskSourceIdentifier::RowPad { phase: *phase };
            if production_sources
                .insert(
                    source,
                    ConstructionMaskSourceDescriptor::current_attempt(source),
                )
                .is_some()
                || row_pad_source_by_phase.insert(*phase, source).is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
        }
        let aggregate_wide_pad_source = ConstructionMaskSourceIdentifier::AggregateWidePad;
        if production_sources
            .insert(
                aggregate_wide_pad_source,
                ConstructionMaskSourceDescriptor::current_attempt(aggregate_wide_pad_source),
            )
            .is_some()
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        production_aggregate_wide_pad_source = Some(aggregate_wide_pad_source);
        for source in bound_source_by_tree_and_column.values().copied() {
            if production_sources
                .insert(
                    source,
                    ConstructionMaskSourceDescriptor::authenticated_persistent_object(source),
                )
                .is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
        }

        let mut source_view_by_opening_source = BTreeMap::<
            (u16, u32, Option<u32>),
            (
                Vec<ConstructionMaskDependency>,
                BTreeSet<ConstructionMaskSourceIdentifier>,
            ),
        >::new();
        for (column_ordinal, phase) in &phase_by_column {
            let trace_source = trace_source_by_column
                .get(column_ordinal)
                .copied()
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            let row_pad_source = row_pad_source_by_phase
                .get(phase)
                .copied()
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            let direct_mask_dependencies = vec![
                ConstructionMaskDependency {
                    source: trace_source,
                    coefficient: 1,
                },
                ConstructionMaskDependency {
                    source: row_pad_source,
                    coefficient: 1,
                },
            ];
            let identifier = match phase {
                ConstructionMaskingPhase::Base => ConstructionSecretViewIdentifier::Phase {
                    column_ordinal: *column_ordinal,
                },
                ConstructionMaskingPhase::Auxiliary => {
                    ConstructionSecretViewIdentifier::Auxiliary {
                        column_ordinal: *column_ordinal,
                    }
                }
                ConstructionMaskingPhase::Quotient => {
                    return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                }
            };
            production_views.push(ConstructionSecretViewDescriptor {
                identifier,
                algebra: match phase {
                    ConstructionMaskingPhase::Base => ConstructionSecretViewAlgebra::Affine,
                    ConstructionMaskingPhase::Auxiliary => ConstructionSecretViewAlgebra::Nonlinear,
                    ConstructionMaskingPhase::Quotient => {
                        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
                    }
                },
                direct_mask_dependencies: direct_mask_dependencies.clone(),
                inherited_mask_sources: BTreeSet::new(),
            });
            let relation_tree_ordinal =
                proof_tree_ordinal_by_column
                    .get(column_ordinal)
                    .copied()
                    .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            source_view_by_opening_source.insert(
                (
                    RelationOpeningSourceClass::TreeColumn as u16,
                    relation_tree_ordinal,
                    Some(*column_ordinal),
                ),
                (direct_mask_dependencies, BTreeSet::new()),
            );
        }

        let trace_sources = trace_source_by_column
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let quotient_row_pad_source = row_pad_source_by_phase
            .get(&ConstructionMaskingPhase::Quotient)
            .copied()
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        for component_ordinal in 0..relation_context.quotient_component_count {
            let mut direct_mask_dependencies = vec![ConstructionMaskDependency {
                source: quotient_row_pad_source,
                coefficient: 1,
            }];
            if component_ordinal + 1 < relation_context.quotient_component_count {
                direct_mask_dependencies.push(ConstructionMaskDependency {
                    source: telescoping_source_by_component
                        .get(&component_ordinal)
                        .copied()
                        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
                    coefficient: 1,
                });
            } else {
                for source in telescoping_source_by_component.values().copied() {
                    direct_mask_dependencies.push(ConstructionMaskDependency {
                        source,
                        coefficient: relation_context.base_field_modulus - 1,
                    });
                }
            }
            production_views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Quotient { component_ordinal },
                algebra: ConstructionSecretViewAlgebra::Nonlinear,
                direct_mask_dependencies: direct_mask_dependencies.clone(),
                inherited_mask_sources: trace_sources.clone(),
            });
            source_view_by_opening_source.insert(
                (
                    RelationOpeningSourceClass::Quotient as u16,
                    component_ordinal,
                    None,
                ),
                (direct_mask_dependencies, trace_sources.clone()),
            );
        }

        for coordinate in &production_bound_columns {
            let source = bound_source_by_tree_and_column
                .get(&(coordinate.relation_tree_ordinal, coordinate.column_ordinal))
                .copied()
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            let direct_mask_dependencies = vec![ConstructionMaskDependency {
                source,
                coefficient: 1,
            }];
            production_views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Bound {
                    relation_tree_ordinal: coordinate.relation_tree_ordinal,
                    column_ordinal: coordinate.column_ordinal,
                },
                algebra: ConstructionSecretViewAlgebra::Affine,
                direct_mask_dependencies: direct_mask_dependencies.clone(),
                inherited_mask_sources: BTreeSet::new(),
            });
            source_view_by_opening_source.insert(
                (
                    RelationOpeningSourceClass::TreeColumn as u16,
                    coordinate.relation_tree_ordinal,
                    Some(coordinate.column_ordinal),
                ),
                (direct_mask_dependencies, BTreeSet::new()),
            );
        }

        let opening_batch_mask_ordinal = match opening_batch_mask_source {
            ConstructionMaskSourceIdentifier::RelationMask { mask_ordinal, .. } => mask_ordinal,
            _ => return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
        };
        let opening_batch_dependencies = vec![ConstructionMaskDependency {
            source: opening_batch_mask_source,
            coefficient: 1,
        }];
        production_views.push(ConstructionSecretViewDescriptor {
            identifier: ConstructionSecretViewIdentifier::Mask {
                mask_ordinal: opening_batch_mask_ordinal,
            },
            algebra: ConstructionSecretViewAlgebra::IndependentMask,
            direct_mask_dependencies: opening_batch_dependencies.clone(),
            inherited_mask_sources: BTreeSet::new(),
        });
        source_view_by_opening_source.insert(
            (RelationOpeningSourceClass::BatchMask as u16, 0, None),
            (opening_batch_dependencies, BTreeSet::new()),
        );

        let mut opening_views = Vec::with_capacity(production_openings.len());
        for opening in &production_openings {
            let (direct_mask_dependencies, inherited_mask_sources) = source_view_by_opening_source
                .get(&opening.source_key())
                .cloned()
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
            opening_views.push(ConstructionSecretViewDescriptor {
                identifier: opening.secret_view_identifier(),
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies,
                inherited_mask_sources,
            });
        }
        production_views.extend(opening_views.iter().cloned());
        for opening_point_ordinal in &relation_aggregate_opening_points {
            let inherited_mask_sources = opening_views
                .iter()
                .filter(|view| {
                    matches!(
                        view.identifier,
                        ConstructionSecretViewIdentifier::Opening {
                            opening_point_ordinal: candidate,
                            ..
                        } if candidate == *opening_point_ordinal
                    )
                })
                .flat_map(ConstructionSecretViewDescriptor::all_mask_sources)
                .collect::<BTreeSet<_>>();
            if inherited_mask_sources.is_empty() {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            production_views.push(ConstructionSecretViewDescriptor {
                identifier: ConstructionSecretViewIdentifier::Aggregate {
                    opening_point_ordinal: *opening_point_ordinal,
                },
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: Vec::new(),
                inherited_mask_sources,
            });
        }
        let aggregate_wide_dependency = ConstructionMaskDependency {
            source: aggregate_wide_pad_source,
            coefficient: 1,
        };
        for identifier in [
            ConstructionSecretViewIdentifier::FoldClosure,
            ConstructionSecretViewIdentifier::ExplicitPoint,
        ] {
            production_views.push(ConstructionSecretViewDescriptor {
                identifier,
                algebra: ConstructionSecretViewAlgebra::DerivedLinear,
                direct_mask_dependencies: vec![aggregate_wide_dependency.clone()],
                inherited_mask_sources: BTreeSet::new(),
            });
        }

        let (_, outer_query_domain_size, outer_query_count) =
            unique_transcript_query_vector(plan, RowCodeWhirQueryRole::Outer)?;
        let (_, first_whir_query_domain_size, first_whir_query_count) =
            unique_transcript_query_vector(
                plan,
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal: 0 },
            )?;
        let first_whir_oracle = plan
            .whir
            .rounds
            .first()
            .map(|round| round.encoded_oracle)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        let required_rank = u64::try_from(outer_query_count)
            .ok()
            .and_then(|outer| {
                u64::try_from(first_whir_query_count)
                    .ok()
                    .and_then(|query_count| {
                        u64::try_from(first_whir_oracle.leaf_width)
                            .ok()
                            .and_then(|width| query_count.checked_mul(width))
                    })
                    .and_then(|first_fold| outer.checked_add(first_fold))
            })
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        if outer_query_domain_size != quotient_plan.geometry.encoded_column_count
            || first_whir_query_domain_size != first_whir_oracle.leaf_count
            || outer_query_count != parameters.outer_query_count
            || first_whir_query_count != outer_query_count
            || u32::try_from(outer_query_count).ok()
                != Some(relation_context.phase_column_query_coordinate_count)
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        production_rank_requirements.push(ConstructionMaskingRankRequirement {
            kind: ConstructionMaskingRankKind::RowPadEvaluation,
            source_dimension: plan.opening_degree_bound_exclusive,
            required_rank,
            verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
        });
    } else if !relation_variant.ordered_masks().is_empty() {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let certificate = ProductionConstructionMaskingCorrespondenceCertificate {
        proof_privacy_mode: plan.proof_privacy_mode,
        construction_plan_identity_hash: plan
            .canonical_identity_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
        relation_plan_variant_hash,
        logical_polynomials_per_physical_row: parameters.logical_polynomials_per_physical_row,
        relation_phase_order,
        production_phase_order,
        expected_trace_chunks: expected_trace_chunks.into_iter().collect(),
        trace_chunk_placements,
        expected_opened_polynomial_chunks: expected_opened_polynomial_chunks.into_iter().collect(),
        opened_polynomial_chunk_placements,
        relation_bound_columns,
        production_bound_columns,
        relation_openings,
        production_openings,
        relation_all_opening_points: expected_all_opening_points,
        relation_aggregate_opening_points,
        production_aggregate_opening_points,
        relation_graph,
        production_sources: production_sources.into_values().collect(),
        production_views,
        production_rank_requirements,
        production_opening_batch_mask_source,
        production_aggregate_wide_pad_source,
    };
    if !certificate.is_complete() {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(certificate)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionAggregateWideCodeRole {
    SourceOracle { epoch_ordinal: u32 },
    AggregatePad,
    FreshSource,
    FreshPad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionAggregateWideCodeEncoder {
    RecomputableOraclePass,
    FoldedRsCode,
    MaskCodeShape,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionAggregateWideQuerySchedule {
    SourceEpoch { epoch_ordinal: u32 },
    Pad,
}

/// Exact coefficient placement and evaluation geometry used by one committed
/// codeword class. Every encoder named here materializes
/// `[message | randomness | zero suffix]` and evaluates it over the natural
/// two-adic subgroup. The row binds that production placement to the shared
/// transcript query vector that consumes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionAggregateWideCodeAffineMapRow {
    role: ProductionAggregateWideCodeRole,
    encoder: ProductionAggregateWideCodeEncoder,
    query_schedule: ProductionAggregateWideQuerySchedule,
    interleaving_width: usize,
    message_length_per_lane: usize,
    randomness_length_per_lane: usize,
    evaluation_domain_size: usize,
    randomness_exponent_start: usize,
    fixed_zero_suffix_length: usize,
    evaluation_domain_logarithmic_size: usize,
    shared_query_count: usize,
}

impl ProductionAggregateWideCodeAffineMapRow {
    fn is_complete(self) -> bool {
        let occupied_coefficient_count = self
            .message_length_per_lane
            .checked_add(self.randomness_length_per_lane);
        let exact_domain_partition = occupied_coefficient_count
            .and_then(|occupied| occupied.checked_add(self.fixed_zero_suffix_length))
            == Some(self.evaluation_domain_size);
        let encoder_matches_role = match (self.role, self.encoder, self.query_schedule) {
            (
                ProductionAggregateWideCodeRole::SourceOracle { epoch_ordinal },
                ProductionAggregateWideCodeEncoder::RecomputableOraclePass,
                ProductionAggregateWideQuerySchedule::SourceEpoch {
                    epoch_ordinal: query_epoch,
                },
            ) => self.interleaving_width == 8 && epoch_ordinal == query_epoch,
            (
                ProductionAggregateWideCodeRole::FreshSource,
                ProductionAggregateWideCodeEncoder::FoldedRsCode,
                ProductionAggregateWideQuerySchedule::SourceEpoch { .. },
            ) => self.interleaving_width == 1,
            (
                ProductionAggregateWideCodeRole::AggregatePad
                | ProductionAggregateWideCodeRole::FreshPad,
                ProductionAggregateWideCodeEncoder::MaskCodeShape,
                ProductionAggregateWideQuerySchedule::Pad,
            ) => self.interleaving_width == 1,
            _ => false,
        };
        self.message_length_per_lane > 0
            && self.randomness_length_per_lane > 0
            && self.shared_query_count == self.randomness_length_per_lane
            && self.evaluation_domain_size.is_power_of_two()
            && self.evaluation_domain_logarithmic_size
                == self.evaluation_domain_size.ilog2() as usize
            && self.randomness_exponent_start == self.message_length_per_lane
            && exact_domain_partition
            && encoder_matches_role
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionAggregateWideFoldAffineMapRow {
    epoch_ordinal: u32,
    map: AggregateWideFoldAffineMapDescriptor,
}

impl ProductionAggregateWideFoldAffineMapRow {
    fn is_complete_for(self, code: ProductionAggregateWideCodeAffineMapRow) -> bool {
        matches!(
            code.role,
            ProductionAggregateWideCodeRole::SourceOracle { epoch_ordinal }
                if epoch_ordinal == self.epoch_ordinal
        ) && self.map.limb_count == code.interleaving_width
            && self.map.input_coordinate_count_per_limb == code.randomness_length_per_lane
            && self.map.output_coordinate_count == code.randomness_length_per_lane
            && self.map.limb_order
                == AggregateWideFoldLimbOrder::FirstChallengeSelectsMostSignificantLimbBit
            && u32::try_from(self.map.folding_variable_count)
                .ok()
                .and_then(|variable_count| 1_usize.checked_shl(variable_count))
                == Some(code.interleaving_width)
    }
}

/// Independent production-side specialization of the aggregate-wide affine
/// certificate. The masking certificate derives coefficient maps from the
/// prover's private-material layout. This certificate instead walks the
/// construction plan's verifier transcript and supplied-opening catalogs, then
/// requires both derivations to agree row for row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionAggregateWideViewCorrespondenceCertificate {
    construction_plan_identity_hash: [u8; 64],
    affine_rows: Vec<AggregateWideJointAffineViewRow>,
    derived_affine_identities: Vec<AggregateWideDerivedAffineIdentity>,
    chronology: Vec<AggregateWideChronologyRow>,
    nonlinear_view_boundary: AggregateWideNonlinearViewBoundary,
    supplied_commitment_roles: Vec<linear_bcs_transcript::LinearBcsCommittedOracleRole>,
    code_affine_maps: Vec<ProductionAggregateWideCodeAffineMapRow>,
    fold_affine_maps: Vec<ProductionAggregateWideFoldAffineMapRow>,
    transcript_affine_coordinate_count: usize,
    primary_opened_affine_coordinate_count: usize,
    derived_opened_affine_coordinate_count: usize,
    delegated_opening_evaluation_coordinate_count: usize,
    transcript_derived_affine_coordinate_count: usize,
    aggregate_wide_extension_challenge_count: usize,
    aggregate_wide_distinct_query_vector_count: usize,
    aggregate_wide_proof_of_work_witness_count: usize,
}

impl ProductionAggregateWideViewCorrespondenceCertificate {
    fn is_complete(&self, aggregate_wide_masking: &AggregateWideMaskingCertificate) -> bool {
        let masking_private_coordinate_count = aggregate_wide_masking.joint_affine_view_summary().0;
        let affine_private_coordinate_count =
            self.affine_rows.iter().try_fold(0_usize, |count, row| {
                count.checked_add(row.private_coordinate_count)
            });
        let affine_rank = self
            .affine_rows
            .iter()
            .try_fold(0_usize, |rank, row| rank.checked_add(row.joint_view_rank));
        let affine_conditional_entropy_dimension =
            self.affine_rows.iter().try_fold(0_usize, |dimension, row| {
                dimension.checked_add(row.conditional_entropy_dimension)
            });
        let opened_affine_coordinate_count = self
            .transcript_affine_coordinate_count
            .checked_add(self.primary_opened_affine_coordinate_count);
        let code_maps_are_complete = self
            .code_affine_maps
            .iter()
            .copied()
            .all(ProductionAggregateWideCodeAffineMapRow::is_complete);
        let source_code_maps_are_canonical = self
            .code_affine_maps
            .iter()
            .take(self.fold_affine_maps.len())
            .enumerate()
            .all(|(epoch_index, code)| {
                u32::try_from(epoch_index).is_ok_and(|epoch_ordinal| {
                    code.role == (ProductionAggregateWideCodeRole::SourceOracle { epoch_ordinal })
                        && code.query_schedule
                            == (ProductionAggregateWideQuerySchedule::SourceEpoch { epoch_ordinal })
                })
            });
        let source_code_maps_match_masking = self
            .code_affine_maps
            .iter()
            .take(self.fold_affine_maps.len())
            .enumerate()
            .all(|(epoch_index, code)| {
                aggregate_wide_masking
                    .folded_source_code_geometry(epoch_index)
                    .is_some_and(
                        |(message_length, randomness_length, domain_size, query_count, width)| {
                            (
                                code.message_length_per_lane,
                                code.randomness_length_per_lane,
                                code.evaluation_domain_size,
                                code.shared_query_count,
                                code.interleaving_width,
                            ) == (
                                message_length,
                                randomness_length,
                                domain_size,
                                query_count,
                                width,
                            )
                        },
                    )
            })
            && aggregate_wide_masking
                .folded_source_code_geometry(self.fold_affine_maps.len())
                .is_none();
        let terminal_epoch_ordinal = self
            .fold_affine_maps
            .len()
            .checked_sub(1)
            .and_then(|epoch| u32::try_from(epoch).ok());
        let terminal_code_maps_are_canonical = terminal_epoch_ordinal.is_some_and(|terminal| {
            matches!(
                self.code_affine_maps
                    .get(self.fold_affine_maps.len())
                    .map(|row| (row.role, row.query_schedule)),
                Some((
                    ProductionAggregateWideCodeRole::AggregatePad,
                    ProductionAggregateWideQuerySchedule::Pad,
                ))
            ) && matches!(
                self.code_affine_maps
                    .get(self.fold_affine_maps.len() + 1)
                    .map(|row| (row.role, row.query_schedule)),
                Some((
                    ProductionAggregateWideCodeRole::FreshSource,
                    ProductionAggregateWideQuerySchedule::SourceEpoch { epoch_ordinal },
                )) if epoch_ordinal == terminal
            ) && matches!(
                self.code_affine_maps
                    .get(self.fold_affine_maps.len() + 2)
                    .map(|row| (row.role, row.query_schedule)),
                Some((
                    ProductionAggregateWideCodeRole::FreshPad,
                    ProductionAggregateWideQuerySchedule::Pad,
                ))
            )
        });
        let terminal_code_maps_match_masking = [
            (
                self.fold_affine_maps.len(),
                aggregate_wide_masking.pad_code_geometry(),
            ),
            (
                self.fold_affine_maps.len() + 1,
                aggregate_wide_masking.fresh_source_code_geometry(),
            ),
            (
                self.fold_affine_maps.len() + 2,
                aggregate_wide_masking.fresh_pad_code_geometry(),
            ),
        ]
        .into_iter()
        .all(
            |(code_index, (message_length, randomness_length, domain_size, query_count, width))| {
                self.code_affine_maps.get(code_index).is_some_and(|code| {
                    (
                        code.message_length_per_lane,
                        code.randomness_length_per_lane,
                        code.evaluation_domain_size,
                        code.shared_query_count,
                        code.interleaving_width,
                    ) == (
                        message_length,
                        randomness_length,
                        domain_size,
                        query_count,
                        width,
                    )
                })
            },
        );
        let fold_maps_are_complete = self.fold_affine_maps.len() + 3 == self.code_affine_maps.len()
            && self
                .fold_affine_maps
                .iter()
                .copied()
                .zip(self.code_affine_maps.iter().copied())
                .all(|(fold, code)| fold.is_complete_for(code));
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.affine_rows == aggregate_wide_masking.joint_affine_view_rows()
            && self.derived_affine_identities == aggregate_wide_masking.derived_affine_identities()
            && self.chronology == aggregate_wide_masking.chronology()
            && self.nonlinear_view_boundary == aggregate_wide_masking.nonlinear_view_boundary()
            && code_maps_are_complete
            && source_code_maps_are_canonical
            && source_code_maps_match_masking
            && terminal_code_maps_are_canonical
            && terminal_code_maps_match_masking
            && fold_maps_are_complete
            && affine_private_coordinate_count == Some(masking_private_coordinate_count)
            && affine_rank == opened_affine_coordinate_count
            && affine_conditional_entropy_dimension
                == opened_affine_coordinate_count
                    .and_then(|opened| masking_private_coordinate_count.checked_sub(opened))
            && self.derived_opened_affine_coordinate_count > 0
            && self.delegated_opening_evaluation_coordinate_count > 0
            && self.transcript_derived_affine_coordinate_count > 0
            && self.aggregate_wide_extension_challenge_count > 0
            && self.aggregate_wide_distinct_query_vector_count > 0
            && self.supplied_commitment_roles.len()
                == self.nonlinear_view_boundary.commitment_root_count
            && self.aggregate_wide_proof_of_work_witness_count
                <= self.aggregate_wide_extension_challenge_count
    }

    fn is_complete_for(
        &self,
        plan: &RowCodeWhirConstructionPlan,
        aggregate_wide_masking: &AggregateWideMaskingCertificate,
    ) -> bool {
        plan.canonical_identity_hash()
            .is_ok_and(|identity| identity == self.construction_plan_identity_hash)
            && self.is_complete(aggregate_wide_masking)
    }
}

fn unique_transcript_observation(
    plan: &RowCodeWhirConstructionPlan,
    expected_role: RowCodeWhirObservationRole,
) -> Result<(usize, usize), WhirTheoremCertificateError> {
    let mut matching = plan.transcript_operations().iter().enumerate().filter_map(
        |(operation_index, operation)| match operation {
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                role, value_count, ..
            } if *role == expected_role => Some((operation_index, *value_count)),
            _ => None,
        },
    );
    let row = matching
        .next()
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if matching.next().is_some() || row.1 == 0 {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(row)
}

fn unique_transcript_extension_challenge(
    plan: &RowCodeWhirConstructionPlan,
    expected_role: RowCodeWhirExtensionRole,
) -> Result<usize, WhirTheoremCertificateError> {
    let mut matching = plan.transcript_operations().iter().enumerate().filter_map(
        |(operation_index, operation)| match operation {
            RowCodeWhirTranscriptOperation::SampleExtension { role, .. }
                if *role == expected_role =>
            {
                Some(operation_index)
            }
            _ => None,
        },
    );
    let operation_index = matching
        .next()
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if matching.next().is_some() {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(operation_index)
}

fn unique_transcript_commitment(
    plan: &RowCodeWhirConstructionPlan,
    expected_role: RowCodeWhirCommitmentRole,
) -> Result<usize, WhirTheoremCertificateError> {
    let mut matching = plan.transcript_operations().iter().enumerate().filter_map(
        |(operation_index, operation)| match operation {
            RowCodeWhirTranscriptOperation::ObserveCommitment { role }
                if *role == expected_role =>
            {
                Some(operation_index)
            }
            _ => None,
        },
    );
    let operation_index = matching
        .next()
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if matching.next().is_some() {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(operation_index)
}

fn unique_transcript_query_vector(
    plan: &RowCodeWhirConstructionPlan,
    expected_role: RowCodeWhirQueryRole,
) -> Result<(usize, usize, usize), WhirTheoremCertificateError> {
    let mut matching = plan.transcript_operations().iter().enumerate().filter_map(
        |(operation_index, operation)| match operation {
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role,
                upper_bound,
                output_count,
            } if *role == expected_role => Some((operation_index, *upper_bound, *output_count)),
            _ => None,
        },
    );
    let row = matching
        .next()
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if matching.next().is_some() || row.1 == 0 || row.2 == 0 || row.2 > row.1 {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(row)
}

fn unique_supplied_commitment_opening(
    transcript_plan: &linear_bcs_transcript::LinearBcsTranscriptPlan,
    expected_role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
) -> Result<
    linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningPlan,
    WhirTheoremCertificateError,
> {
    let mut matching = transcript_plan
        .supplied_commitment_openings()
        .iter()
        .copied()
        .filter(|opening| opening.commitment_role == expected_role);
    let opening = matching
        .next()
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if matching.next().is_some()
        || opening.payload_leaf_count == 0
        || opening.query_count == 0
        || opening.query_count > opening.payload_leaf_count
        || opening.query_order
            != linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
        || opening.merkle_traversal_order
            != linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(opening)
}

fn checked_affine_view_row(
    row: AggregateWideJointAffineViewRow,
) -> Result<AggregateWideJointAffineViewRow, WhirTheoremCertificateError> {
    if row.private_coordinate_count == 0
        || row.joint_view_rank == 0
        || row
            .joint_view_rank
            .checked_add(row.conditional_entropy_dimension)
            != Some(row.private_coordinate_count)
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(row)
}

fn derive_production_aggregate_wide_view_correspondence(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
) -> Result<ProductionAggregateWideViewCorrespondenceCertificate, WhirTheoremCertificateError> {
    let configuration =
        super::super::hiding_whir::selected_hiding_whir_config(plan.selected_parameters())
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    let round_count = configuration.n_rounds();
    if plan.whir.rounds.len() != round_count
        || configuration.sumcheck_mask.message_len != 3
        || configuration.round_folding_factor(0) != 3
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let linear_transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;

    let mut code_affine_maps = Vec::with_capacity(
        round_count
            .checked_add(4)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    let mut fold_affine_maps = Vec::with_capacity(round_count + 1);
    let mut source_variable_count = configuration.num_variables;
    for epoch_index in 0..=round_count {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let folding_factor = configuration.round_folding_factor(epoch_index);
        let inverse_rate = if epoch_index == 0 {
            1_usize
                .checked_shl(
                    u32::try_from(configuration.starting_log_inv_rate)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        } else {
            configuration.inv_rate(epoch_index - 1)
        };
        let (
            message_length_per_lane,
            randomness_length_per_lane,
            evaluation_domain_size,
            shared_query_count,
            interleaving_width,
        ) = aggregate_wide_masking
            .folded_source_code_geometry(epoch_index)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        let production_map = checked_recomputable_oracle_affine_map(
            source_variable_count,
            folding_factor,
            inverse_rate,
            randomness_length_per_lane,
        )
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if production_map
            != (RecomputableOracleAffineMapDescriptor {
                interleaving_width,
                message_length_per_lane,
                randomness_length_per_lane,
                evaluation_domain_size,
                randomness_exponent_start: message_length_per_lane,
                fixed_zero_suffix_length: evaluation_domain_size
                    .checked_sub(
                        message_length_per_lane
                            .checked_add(randomness_length_per_lane)
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                    )
                    .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
                evaluation_domain_logarithmic_size: evaluation_domain_size.ilog2() as usize,
            })
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let code_map = ProductionAggregateWideCodeAffineMapRow {
            role: ProductionAggregateWideCodeRole::SourceOracle { epoch_ordinal },
            encoder: ProductionAggregateWideCodeEncoder::RecomputableOraclePass,
            query_schedule: ProductionAggregateWideQuerySchedule::SourceEpoch { epoch_ordinal },
            interleaving_width: production_map.interleaving_width,
            message_length_per_lane: production_map.message_length_per_lane,
            randomness_length_per_lane: production_map.randomness_length_per_lane,
            evaluation_domain_size: production_map.evaluation_domain_size,
            randomness_exponent_start: production_map.randomness_exponent_start,
            fixed_zero_suffix_length: production_map.fixed_zero_suffix_length,
            evaluation_domain_logarithmic_size: production_map.evaluation_domain_logarithmic_size,
            shared_query_count,
        };
        if !code_map.is_complete() {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let raw_randomness_length = randomness_length_per_lane
            .checked_mul(interleaving_width)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let fold_map = ProductionAggregateWideFoldAffineMapRow {
            epoch_ordinal,
            map: checked_fold_limb_affine_map(
                raw_randomness_length,
                randomness_length_per_lane,
                folding_factor,
            )
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
        };
        if !fold_map.is_complete_for(code_map) {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        code_affine_maps.push(code_map);
        fold_affine_maps.push(fold_map);
        source_variable_count = source_variable_count
            .checked_sub(folding_factor)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    }

    let (pad_message_length, pad_randomness_length, pad_domain_size, pad_query_count, pad_width) =
        aggregate_wide_masking.pad_code_geometry();
    let production_pad_shape = MaskCodeShape::new(
        pad_message_length,
        pad_randomness_length,
        AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    );
    if production_pad_shape.message_len != pad_message_length
        || production_pad_shape.randomness_len != pad_randomness_length
        || production_pad_shape.domain_size != pad_domain_size
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let pad_zero_suffix_length = pad_domain_size
        .checked_sub(
            pad_message_length
                .checked_add(pad_randomness_length)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    code_affine_maps.push(ProductionAggregateWideCodeAffineMapRow {
        role: ProductionAggregateWideCodeRole::AggregatePad,
        encoder: ProductionAggregateWideCodeEncoder::MaskCodeShape,
        query_schedule: ProductionAggregateWideQuerySchedule::Pad,
        interleaving_width: pad_width,
        message_length_per_lane: pad_message_length,
        randomness_length_per_lane: pad_randomness_length,
        evaluation_domain_size: pad_domain_size,
        randomness_exponent_start: pad_message_length,
        fixed_zero_suffix_length: pad_zero_suffix_length,
        evaluation_domain_logarithmic_size: pad_domain_size.ilog2() as usize,
        shared_query_count: pad_query_count,
    });

    let (
        fresh_source_message_length,
        fresh_source_randomness_length,
        fresh_source_domain_size,
        fresh_source_query_count,
        fresh_source_width,
    ) = aggregate_wide_masking.fresh_source_code_geometry();
    if !fresh_source_message_length.is_power_of_two()
        || !fresh_source_domain_size.is_power_of_two()
        || fresh_source_message_length
            .checked_add(fresh_source_randomness_length)
            .is_none_or(|occupied| occupied > fresh_source_domain_size)
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let production_fresh_source_code = FoldedRsCode::<ChallengeField>::new(
        fresh_source_message_length,
        fresh_source_randomness_length,
        fresh_source_domain_size,
    );
    if production_fresh_source_code.message_len != fresh_source_message_length
        || production_fresh_source_code.randomness_len != fresh_source_randomness_length
        || production_fresh_source_code.domain_size != fresh_source_domain_size
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let terminal_epoch_ordinal =
        u32::try_from(round_count).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    code_affine_maps.push(ProductionAggregateWideCodeAffineMapRow {
        role: ProductionAggregateWideCodeRole::FreshSource,
        encoder: ProductionAggregateWideCodeEncoder::FoldedRsCode,
        query_schedule: ProductionAggregateWideQuerySchedule::SourceEpoch {
            epoch_ordinal: terminal_epoch_ordinal,
        },
        interleaving_width: fresh_source_width,
        message_length_per_lane: fresh_source_message_length,
        randomness_length_per_lane: fresh_source_randomness_length,
        evaluation_domain_size: fresh_source_domain_size,
        randomness_exponent_start: fresh_source_message_length,
        fixed_zero_suffix_length: fresh_source_domain_size
            .checked_sub(
                fresh_source_message_length
                    .checked_add(fresh_source_randomness_length)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
        evaluation_domain_logarithmic_size: fresh_source_domain_size.ilog2() as usize,
        shared_query_count: fresh_source_query_count,
    });

    let (
        fresh_pad_message_length,
        fresh_pad_randomness_length,
        fresh_pad_domain_size,
        fresh_pad_query_count,
        fresh_pad_width,
    ) = aggregate_wide_masking.fresh_pad_code_geometry();
    let production_fresh_pad_shape = MaskCodeShape::new(
        fresh_pad_message_length,
        fresh_pad_randomness_length,
        AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    );
    if production_fresh_pad_shape != production_pad_shape {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    code_affine_maps.push(ProductionAggregateWideCodeAffineMapRow {
        role: ProductionAggregateWideCodeRole::FreshPad,
        encoder: ProductionAggregateWideCodeEncoder::MaskCodeShape,
        query_schedule: ProductionAggregateWideQuerySchedule::Pad,
        interleaving_width: fresh_pad_width,
        message_length_per_lane: fresh_pad_message_length,
        randomness_length_per_lane: fresh_pad_randomness_length,
        evaluation_domain_size: fresh_pad_domain_size,
        randomness_exponent_start: fresh_pad_message_length,
        fixed_zero_suffix_length: fresh_pad_domain_size
            .checked_sub(
                fresh_pad_message_length
                    .checked_add(fresh_pad_randomness_length)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
        evaluation_domain_logarithmic_size: fresh_pad_domain_size.ilog2() as usize,
        shared_query_count: fresh_pad_query_count,
    });
    if code_affine_maps
        .iter()
        .copied()
        .any(|row| !row.is_complete())
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }

    let mut affine_rows = Vec::with_capacity(
        (round_count + 1)
            .checked_mul(2)
            .and_then(|count| count.checked_add(3))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    let mut transcript_affine_coordinate_count = 0_usize;
    for batch_index in 0..=round_count {
        let batch_ordinal = u32::try_from(batch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let (_, mask_claim_coordinate_count) = unique_transcript_observation(
            plan,
            RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal },
        )?;
        if mask_claim_coordinate_count != 1 {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        unique_transcript_extension_challenge(
            plan,
            RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal },
        )?;
        let folding_factor = configuration.round_folding_factor(batch_index);
        let mut polynomial_coordinate_count = 0_usize;
        for round_index in 0..folding_factor {
            let round_ordinal = u32::try_from(round_index)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let (_, coordinate_count) = unique_transcript_observation(
                plan,
                RowCodeWhirObservationRole::MaskedSumcheckPolynomial {
                    batch_ordinal,
                    round_ordinal,
                },
            )?;
            if coordinate_count
                != configuration
                    .sumcheck_mask
                    .message_len
                    .checked_sub(1)
                    .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?
            {
                return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
            }
            unique_transcript_extension_challenge(
                plan,
                RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                },
            )?;
            polynomial_coordinate_count = polynomial_coordinate_count
                .checked_add(coordinate_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        }
        let visible_coordinate_count = mask_claim_coordinate_count
            .checked_add(polynomial_coordinate_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let private_coordinate_count = folding_factor
            .checked_mul(configuration.sumcheck_mask.message_len)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        affine_rows.push(checked_affine_view_row(AggregateWideJointAffineViewRow {
            kind: AggregateWideJointAffineViewKind::SumcheckTranscript { batch_ordinal },
            private_coordinate_count,
            joint_view_rank: visible_coordinate_count,
            conditional_entropy_dimension: private_coordinate_count
                .checked_sub(visible_coordinate_count)
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
            rank_verification: AggregateWideJointAffineRankVerification::SumcheckConstantMinor {
                mask_count: folding_factor,
                coefficients_per_mask: configuration.sumcheck_mask.message_len,
                visible_coordinate_count,
                absolute_determinant: 64,
            },
        })?);
        transcript_affine_coordinate_count = transcript_affine_coordinate_count
            .checked_add(visible_coordinate_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }

    let mut primary_opened_affine_coordinate_count = 0_usize;
    let mut primary_source_commitment_roles = Vec::with_capacity(round_count + 1);
    for epoch_index in 0..=round_count {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let commitment_role = if epoch_index == 0 {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
        } else {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                round_ordinal: epoch_ordinal - 1,
            }
        };
        let opening = unique_supplied_commitment_opening(&linear_transcript_plan, commitment_role)?;
        let (_, query_domain_size, shared_query_count) = unique_transcript_query_vector(
            plan,
            RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal },
        )?;
        let (
            _message_length,
            randomness_length_per_lane,
            code_domain_size,
            certificate_query_count,
            interleaving_width,
        ) = aggregate_wide_masking
            .folded_source_code_geometry(epoch_index)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if opening.owner
            != (linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                epoch_ordinal,
            })
            || opening.payload_leaf_count != code_domain_size
            || opening.payload_leaf_count != query_domain_size
            || opening.query_count != shared_query_count
            || certificate_query_count != shared_query_count
            || randomness_length_per_lane != shared_query_count
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let source_randomness_coordinate_count = randomness_length_per_lane
            .checked_mul(interleaving_width)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let source_query_coordinate_count = shared_query_count
            .checked_mul(interleaving_width)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        primary_opened_affine_coordinate_count = primary_opened_affine_coordinate_count
            .checked_add(source_query_coordinate_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let row = if epoch_index < round_count {
            let (_, switch_identity_coordinate_count) = unique_transcript_observation(
                plan,
                RowCodeWhirObservationRole::SwitchMaskDelta {
                    round_ordinal: epoch_ordinal,
                },
            )?;
            transcript_affine_coordinate_count = transcript_affine_coordinate_count
                .checked_add(switch_identity_coordinate_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            AggregateWideJointAffineViewRow {
                kind: AggregateWideJointAffineViewKind::SourceQueriesAndSwitchDelta {
                    epoch_ordinal,
                },
                private_coordinate_count: source_randomness_coordinate_count
                    .checked_add(switch_identity_coordinate_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                joint_view_rank: source_query_coordinate_count
                    .checked_add(switch_identity_coordinate_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                conditional_entropy_dimension: 0,
                rank_verification:
                    AggregateWideJointAffineRankVerification::SourceQueryAndSwitchBlockTriangular {
                        interleaving_width,
                        randomness_length_per_lane,
                        shared_query_count,
                        switch_identity_coordinate_count,
                    },
            }
        } else {
            AggregateWideJointAffineViewRow {
                kind: AggregateWideJointAffineViewKind::TerminalSourceQueries { epoch_ordinal },
                private_coordinate_count: source_randomness_coordinate_count,
                joint_view_rank: source_query_coordinate_count,
                conditional_entropy_dimension: 0,
                rank_verification:
                    AggregateWideJointAffineRankVerification::SharedQueryGeneralizedVandermonde {
                        interleaving_width,
                        randomness_length_per_lane,
                        shared_query_count,
                    },
            }
        };
        affine_rows.push(checked_affine_view_row(row)?);
        primary_source_commitment_roles.push(commitment_role);
    }

    let pad_epoch_ordinal = u32::try_from(round_count + 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let (_, pad_query_domain_size, pad_query_count) = unique_transcript_query_vector(
        plan,
        RowCodeWhirQueryRole::WhirEpoch {
            epoch_ordinal: pad_epoch_ordinal,
        },
    )?;
    let (
        pad_message_length,
        pad_randomness_length,
        pad_domain_size,
        certificate_pad_query_count,
        pad_interleaving_width,
    ) = aggregate_wide_masking.pad_code_geometry();
    let pad_opening = unique_supplied_commitment_opening(
        &linear_transcript_plan,
        linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
    )?;
    if pad_opening.owner
        != (linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
            epoch_ordinal: pad_epoch_ordinal,
        })
        || pad_opening.payload_leaf_count != pad_domain_size
        || pad_opening.payload_leaf_count != pad_query_domain_size
        || pad_opening.query_count != pad_query_count
        || certificate_pad_query_count != pad_query_count
        || pad_randomness_length != pad_query_count
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let pad_private_coordinate_count = pad_randomness_length
        .checked_mul(pad_interleaving_width)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_query_coordinate_count = pad_query_count
        .checked_mul(pad_interleaving_width)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    affine_rows.push(checked_affine_view_row(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::PadQueries,
        private_coordinate_count: pad_private_coordinate_count,
        joint_view_rank: pad_query_coordinate_count,
        conditional_entropy_dimension: 0,
        rank_verification:
            AggregateWideJointAffineRankVerification::SharedQueryGeneralizedVandermonde {
                interleaving_width: pad_interleaving_width,
                randomness_length_per_lane: pad_randomness_length,
                shared_query_count: pad_query_count,
            },
    })?);
    primary_opened_affine_coordinate_count = primary_opened_affine_coordinate_count
        .checked_add(pad_query_coordinate_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    let terminal_epoch_ordinal =
        u32::try_from(round_count).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let (
        fresh_source_message_length,
        fresh_source_randomness_length,
        fresh_source_domain_size,
        fresh_source_query_count,
        fresh_source_width,
    ) = aggregate_wide_masking.fresh_source_code_geometry();
    let fresh_source_opening = unique_supplied_commitment_opening(
        &linear_transcript_plan,
        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
    )?;
    let (_, blinded_source_message_count) =
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedSourceMessage)?;
    let (_, blinded_source_randomness_count) = unique_transcript_observation(
        plan,
        RowCodeWhirObservationRole::BaseBlindedSourceRandomness,
    )?;
    if fresh_source_opening.owner
        != (linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
            epoch_ordinal: terminal_epoch_ordinal,
        })
        || fresh_source_opening.payload_leaf_count != fresh_source_domain_size
        || fresh_source_opening.query_count != fresh_source_query_count
        || fresh_source_width != 1
        || blinded_source_message_count != fresh_source_message_length
        || blinded_source_randomness_count != fresh_source_randomness_length
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let fresh_source_coordinate_count = fresh_source_message_length
        .checked_add(fresh_source_randomness_length)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    affine_rows.push(checked_affine_view_row(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::FreshSourceReveal,
        private_coordinate_count: fresh_source_coordinate_count,
        joint_view_rank: fresh_source_coordinate_count,
        conditional_entropy_dimension: 0,
        rank_verification: AggregateWideJointAffineRankVerification::CoordinateIdentity,
    })?);
    transcript_affine_coordinate_count = transcript_affine_coordinate_count
        .checked_add(fresh_source_coordinate_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    let (
        fresh_pad_message_length,
        fresh_pad_randomness_length,
        fresh_pad_domain_size,
        fresh_pad_query_count,
        fresh_pad_width,
    ) = aggregate_wide_masking.fresh_pad_code_geometry();
    let fresh_pad_opening = unique_supplied_commitment_opening(
        &linear_transcript_plan,
        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
    )?;
    let (_, blinded_pad_message_count) =
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedPadMessage)?;
    let (_, blinded_pad_randomness_count) =
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedPadRandomness)?;
    if fresh_pad_opening.owner
        != (linear_bcs_transcript::LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
            epoch_ordinal: pad_epoch_ordinal,
        })
        || fresh_pad_opening.payload_leaf_count != fresh_pad_domain_size
        || fresh_pad_opening.query_count != fresh_pad_query_count
        || fresh_pad_width != 1
        || fresh_pad_message_length != pad_message_length
        || fresh_pad_randomness_length != pad_randomness_length
        || blinded_pad_message_count != fresh_pad_message_length
        || blinded_pad_randomness_count != fresh_pad_randomness_length
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let fresh_pad_coordinate_count = fresh_pad_message_length
        .checked_add(fresh_pad_randomness_length)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    affine_rows.push(checked_affine_view_row(AggregateWideJointAffineViewRow {
        kind: AggregateWideJointAffineViewKind::FreshPadReveal,
        private_coordinate_count: fresh_pad_coordinate_count,
        joint_view_rank: fresh_pad_coordinate_count,
        conditional_entropy_dimension: 0,
        rank_verification: AggregateWideJointAffineRankVerification::CoordinateIdentity,
    })?);
    transcript_affine_coordinate_count = transcript_affine_coordinate_count
        .checked_add(fresh_pad_coordinate_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    let derived_opened_affine_coordinate_count = fresh_source_opening
        .query_count
        .checked_mul(fresh_source_width)
        .and_then(|count| {
            fresh_pad_opening
                .query_count
                .checked_mul(fresh_pad_width)
                .and_then(|fresh_pad_count| count.checked_add(fresh_pad_count))
        })
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let delegated_opening_evaluation_coordinate_count =
        plan.opening_batches()
            .iter()
            .try_fold(0_usize, |count, batch| {
                count
                    .checked_add(batch.requested_aggregate_column_ordinals.len())
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;

    let mut derived_affine_identities = Vec::new();
    for batch_index in 0..=round_count {
        let batch_ordinal = u32::try_from(batch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        derived_affine_identities.push(
            AggregateWideDerivedAffineIdentity::SumcheckResidualFromTranscript { batch_ordinal },
        );
    }
    for epoch_index in 0..=round_count {
        derived_affine_identities.push(
            AggregateWideDerivedAffineIdentity::FoldedRandomnessFromInterleavedLanes {
                epoch_ordinal: u32::try_from(epoch_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            },
        );
    }
    for round_index in 0..round_count {
        derived_affine_identities.push(
            AggregateWideDerivedAffineIdentity::SwitchMaskFromPadAndDelta {
                round_ordinal: u32::try_from(round_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            },
        );
    }
    derived_affine_identities.extend([
        AggregateWideDerivedAffineIdentity::FreshSourceQueriesFromRevealAndCarriedQueries,
        AggregateWideDerivedAffineIdentity::FreshPadQueriesFromRevealAndCarriedQueries,
        AggregateWideDerivedAffineIdentity::MaskedClaimFromRevealsAndPublicTarget,
        AggregateWideDerivedAffineIdentity::TerminalSourceCovectorFromCheckedConstraints,
        AggregateWideDerivedAffineIdentity::TerminalPadCovectorFromCheckedClaims,
    ]);

    let aggregate_commitment_position =
        unique_transcript_commitment(plan, RowCodeWhirCommitmentRole::Aggregate)?;
    let pad_commitment_position =
        unique_transcript_commitment(plan, RowCodeWhirCommitmentRole::AggregateWidePad)?;
    let (initial_sumcheck_position, _) = unique_transcript_observation(
        plan,
        RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal: 0 },
    )?;
    let mut chronology_positions = vec![
        (
            aggregate_commitment_position,
            AggregateWideChronologyEvent::InitialSourceCommitmentObserved,
        ),
        (
            pad_commitment_position,
            AggregateWideChronologyEvent::PadCommitmentObserved,
        ),
        (
            initial_sumcheck_position,
            AggregateWideChronologyEvent::PrecommittedSumcheck { batch_ordinal: 0 },
        ),
    ];
    for round_index in 0..round_count {
        let round_ordinal = u32::try_from(round_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        chronology_positions.push((
            unique_transcript_commitment(
                plan,
                RowCodeWhirCommitmentRole::WhirRound { round_ordinal },
            )?,
            AggregateWideChronologyEvent::FoldedSourceCommitmentObserved { round_ordinal },
        ));
        chronology_positions.push((
            unique_transcript_observation(
                plan,
                RowCodeWhirObservationRole::SwitchMaskDelta { round_ordinal },
            )?
            .0,
            AggregateWideChronologyEvent::SwitchDeltaObserved { round_ordinal },
        ));
        chronology_positions.push((
            unique_transcript_query_vector(
                plan,
                RowCodeWhirQueryRole::WhirEpoch {
                    epoch_ordinal: round_ordinal,
                },
            )?
            .0,
            AggregateWideChronologyEvent::SourceQueryVectorSampled {
                epoch_ordinal: round_ordinal,
            },
        ));
        let following_batch_ordinal = round_ordinal + 1;
        chronology_positions.push((
            unique_transcript_observation(
                plan,
                RowCodeWhirObservationRole::MaskedSumcheckMaskClaim {
                    batch_ordinal: following_batch_ordinal,
                },
            )?
            .0,
            AggregateWideChronologyEvent::PrecommittedSumcheck {
                batch_ordinal: following_batch_ordinal,
            },
        ));
    }
    let fresh_source_commitment_position =
        unique_transcript_commitment(plan, RowCodeWhirCommitmentRole::BaseFreshSource)?;
    let fresh_pad_commitment_position =
        unique_transcript_commitment(plan, RowCodeWhirCommitmentRole::BaseFreshPad)?;
    if fresh_source_commitment_position >= fresh_pad_commitment_position {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    chronology_positions.push((
        fresh_pad_commitment_position,
        AggregateWideChronologyEvent::FreshBaseCommitmentsObserved,
    ));
    chronology_positions.push((
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseMaskedClaim)?.0,
        AggregateWideChronologyEvent::FreshBaseClaimObserved,
    ));
    chronology_positions.push((
        unique_transcript_extension_challenge(plan, RowCodeWhirExtensionRole::BaseCaseBlinding)?,
        AggregateWideChronologyEvent::FreshBaseChallengeSampled,
    ));
    let reveal_positions = [
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedSourceMessage)?
            .0,
        unique_transcript_observation(
            plan,
            RowCodeWhirObservationRole::BaseBlindedSourceRandomness,
        )?
        .0,
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedPadMessage)?.0,
        unique_transcript_observation(plan, RowCodeWhirObservationRole::BaseBlindedPadRandomness)?
            .0,
    ];
    if reveal_positions
        .windows(2)
        .any(|positions| positions[0] >= positions[1])
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    chronology_positions.push((
        reveal_positions[3],
        AggregateWideChronologyEvent::FreshBaseRevealsObserved,
    ));
    chronology_positions.push((
        unique_transcript_query_vector(
            plan,
            RowCodeWhirQueryRole::WhirEpoch {
                epoch_ordinal: terminal_epoch_ordinal,
            },
        )?
        .0,
        AggregateWideChronologyEvent::SourceQueryVectorSampled {
            epoch_ordinal: terminal_epoch_ordinal,
        },
    ));
    chronology_positions.push((
        unique_transcript_query_vector(
            plan,
            RowCodeWhirQueryRole::WhirEpoch {
                epoch_ordinal: pad_epoch_ordinal,
            },
        )?
        .0,
        AggregateWideChronologyEvent::PadQueryVectorSampled,
    ));
    if chronology_positions
        .windows(2)
        .any(|positions| positions[0].0 >= positions[1].0)
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let mut chronology = Vec::with_capacity(chronology_positions.len().saturating_add(1));
    chronology.push(AggregateWideChronologyRow {
        ordinal: 0,
        immediate_predecessor: None,
        event: AggregateWideChronologyEvent::PrivateMaterialSampled,
    });
    for (_, event) in chronology_positions {
        let ordinal = u32::try_from(chronology.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        chronology.push(AggregateWideChronologyRow {
            ordinal,
            immediate_predecessor: ordinal.checked_sub(1),
            event,
        });
    }

    let supplied_commitment_roles = linear_transcript_plan
        .supplied_commitment_openings()
        .iter()
        .filter_map(|opening| match opening.commitment_role {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase { .. } => None,
            role => Some(role),
        })
        .collect::<Vec<_>>();
    let mut expected_supplied_commitment_roles = Vec::with_capacity(round_count + 4);
    expected_supplied_commitment_roles.extend([
        linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate,
        linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
    ]);
    expected_supplied_commitment_roles.extend(
        (0..round_count)
            .map(u32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
            .into_iter()
            .map(
                |round_ordinal| linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound {
                    round_ordinal,
                },
            ),
    );
    expected_supplied_commitment_roles.extend([
        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
    ]);
    if supplied_commitment_roles != expected_supplied_commitment_roles
        || primary_source_commitment_roles.len() != round_count + 1
        || ColumnStreamableLeafHasher::intermediate_output_bit_length()
            != CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
        || ColumnStreamableLeafHasher::final_output_bit_length()
            != CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let nonlinear_view_boundary = AggregateWideNonlinearViewBoundary {
        commitment_root_count: supplied_commitment_roles.len(),
        compact_frontier_count: supplied_commitment_roles.len(),
        code_switch_image_count: round_count,
        fold_image_count: primary_source_commitment_roles.len(),
        hash_output_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
    };

    let aggregate_wide_extension_challenge_count = plan
        .transcript_operations()
        .iter()
        .filter(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleExtension {
                    role: RowCodeWhirExtensionRole::OpeningBatching
                        | RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { .. }
                        | RowCodeWhirExtensionRole::MaskedSumcheckRound { .. }
                        | RowCodeWhirExtensionRole::RoundCheckpoint { .. }
                        | RowCodeWhirExtensionRole::RoundCombination { .. }
                        | RowCodeWhirExtensionRole::BaseCaseBlinding,
                    ..
                }
            )
        })
        .count();
    let aggregate_wide_distinct_query_vector_count = plan
        .transcript_operations()
        .iter()
        .filter(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: RowCodeWhirQueryRole::WhirEpoch { .. },
                    ..
                }
            )
        })
        .count();
    let initial_sumcheck_witness_count = usize::from(configuration.starting_folding_pow_bits > 0)
        .checked_mul(configuration.round_folding_factor(0))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let round_witness_count = configuration.round_parameters.iter().enumerate().try_fold(
        0_usize,
        |count, (round_index, round)| {
            let commitment_witness_count = usize::from(round.pow_bits > 0);
            let following_sumcheck_witness_count = usize::from(round.folding_pow_bits > 0)
                .checked_mul(configuration.round_folding_factor(round_index + 1))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            count
                .checked_add(commitment_witness_count)
                .and_then(|value| value.checked_add(following_sumcheck_witness_count))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        },
    )?;
    let aggregate_wide_proof_of_work_witness_count = initial_sumcheck_witness_count
        .checked_add(round_witness_count)
        .and_then(|count| count.checked_add(usize::from(configuration.final_pow_bits > 0)))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let transcript_derived_affine_coordinate_count = round_count
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    let certificate = ProductionAggregateWideViewCorrespondenceCertificate {
        construction_plan_identity_hash: plan
            .canonical_identity_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?,
        affine_rows,
        derived_affine_identities,
        chronology,
        nonlinear_view_boundary,
        supplied_commitment_roles,
        code_affine_maps,
        fold_affine_maps,
        transcript_affine_coordinate_count,
        primary_opened_affine_coordinate_count,
        derived_opened_affine_coordinate_count,
        delegated_opening_evaluation_coordinate_count,
        transcript_derived_affine_coordinate_count,
        aggregate_wide_extension_challenge_count,
        aggregate_wide_distinct_query_vector_count,
        aggregate_wide_proof_of_work_witness_count,
    };
    if !certificate.is_complete_for(plan, aggregate_wide_masking) {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    Ok(certificate)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirFailurePartitionCertificate {
    code_state_rows: Vec<WhirCodeStateRow>,
    interleaved_unique_decoding_rows: Vec<InterleavedUniqueDecodingRow>,
    fold_rows: Vec<WhirFoldFailureRow>,
    shift_rows: Vec<WhirShiftFailureRow>,
    final_query_row: WhirFinalQueryRow,
    initial_constraint_batch_numerator: u64,
    final_sumcheck_numerator: u64,
    prefix_stacking: PrefixStackingCertificate,
    state_epoch_rows: Vec<StateEpochRow>,
    oracle_equation_rows: Vec<OracleEquationCoverageRow>,
    complete_verifier_oracle_ledger: CompleteVerifierOracleLedger,
    deployed_aggregate_leaf_oracle: DeployedAggregateLeafOracleCertificate,
    commitment_subtree_extraction: CommitmentSubtreeExtractionCertificate,
    selected_plan_state_predicate: SelectedPlanStatePredicateCertificate,
    cms19_whole_state_transitions: Cms19WholeStateTransitionCertificate,
    cms19_whole_database_support: Cms19WholeDatabaseSupportCertificate,
    cms19_state_predicate: Cms19StatePredicateCertificate,
    cms19_strong_state_hash_chain: Cms19StrongStateHashChainCertificate,
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: Cms19ArithmeticCertificate,
    cms19_applicability: Cms19ApplicabilityCertificate,
    exact_failure_magnitude: ExactFailureMagnitudeCertificate,
    construction_masking: ConstructionMaskingCertificate,
    production_construction_masking: ProductionConstructionMaskingCorrespondenceCertificate,
    aggregate_wide_masking: AggregateWideMaskingCertificate,
    production_aggregate_wide_views: ProductionAggregateWideViewCorrespondenceCertificate,
    private_row_pad_generator_hybrid: PrivateRowPadGeneratorHybridCertificate,
    relation_compiler_interpreter_semantics: RelationCompilerInterpreterSemanticCertificate,
    polynomial_protocol_extractor: ExactPolynomialProtocolExtractorCertificate,
    point_constraint_extractor: ExactPointConstraintExtractorCertificate,
}

impl RowCodeWhirFailurePartitionCertificate {
    pub(in crate::bgv::proof_suite) fn fold_numerator(
        &self,
    ) -> Result<u64, WhirTheoremCertificateError> {
        self.fold_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.total_numerator()?)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) fn shift_numerator(
        &self,
    ) -> Result<u64, WhirTheoremCertificateError> {
        self.shift_rows.iter().try_fold(0_u64, |total, row| {
            total
                .checked_add(row.algebraic_numerator)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) const fn initial_constraint_batch_numerator(&self) -> u64 {
        self.initial_constraint_batch_numerator
    }

    pub(in crate::bgv::proof_suite) const fn final_sumcheck_numerator(&self) -> u64 {
        self.final_sumcheck_numerator
    }

    pub(in crate::bgv::proof_suite) fn is_complete_construction_theorem(&self) -> bool {
        self.commitment_subtree_extraction.is_complete()
            && self.construction_masking.is_complete()
            && self.production_construction_masking.is_complete()
            && self.aggregate_wide_masking.is_complete()
            && self
                .production_aggregate_wide_views
                .is_complete(&self.aggregate_wide_masking)
            && self
                .production_construction_masking
                .construction_plan_identity_hash
                == self
                    .production_aggregate_wide_views
                    .construction_plan_identity_hash
            && self
                .production_aggregate_wide_views
                .construction_plan_identity_hash
                == self
                    .polynomial_protocol_extractor
                    .construction_plan_identity_hash()
            && self.private_row_pad_generator_hybrid.is_complete()
            && self.relation_compiler_interpreter_semantics.is_complete()
            && self.polynomial_protocol_extractor.is_complete()
            && self.point_constraint_extractor.is_complete()
            && self.selected_plan_state_predicate.transition_rows.len()
                == usize::try_from(self.logical_verifier_message_count).unwrap_or(usize::MAX)
                    + self
                        .selected_plan_state_predicate
                        .transition_rows
                        .iter()
                        .filter(|row| row.failure_event_owner.is_none())
                        .count()
            && self.cms19_state_predicate.is_complete()
            && self.cms19_whole_state_transitions.is_complete()
            && self
                .cms19_whole_state_transitions
                .matches_selected_plan_state_predicate(&self.selected_plan_state_predicate)
            && self.cms19_whole_database_support.is_complete()
            && self
                .cms19_whole_state_transitions
                .construction_plan_identity_hash
                == self
                    .production_aggregate_wide_views
                    .construction_plan_identity_hash
            && self
                .cms19_whole_database_support
                .construction_plan_identity_hash
                == self
                    .cms19_whole_state_transitions
                    .construction_plan_identity_hash
            && self.cms19_whole_database_support.mapped_hash_query_count
                == self
                    .deployed_aggregate_leaf_oracle
                    .deployed_verifier_hash_query_count
            && self
                .cms19_whole_database_support
                .mapped_accepting_database_equation_count
                == self
                    .deployed_aggregate_leaf_oracle
                    .deployed_accepting_database_equation_count
            && self.cms19_strong_state_hash_chain.is_complete()
            && self.cms19_applicability.is_complete()
            && self
                .deployed_aggregate_leaf_oracle
                .is_eligible_for_uniform_required_output()
            && self.exact_failure_magnitude.is_complete()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionWhirGeometryCertificate {
    code_state_rows: Vec<WhirCodeStateRow>,
    interleaved_unique_decoding_rows: Vec<InterleavedUniqueDecodingRow>,
    fold_rows: Vec<WhirFoldFailureRow>,
    shift_rows: Vec<WhirShiftFailureRow>,
    final_query_row: WhirFinalQueryRow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RowCodeWhirProductionGeometryCertificate {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    construction_plan_identity_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    parameters: RowCodeWhirSelectedParameters,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    proof_privacy_mode: ProofPrivacyMode,
    relation_compiler_interpreter_semantics: RelationCompilerInterpreterSemanticCertificate,
    construction_masking: ConstructionMaskingCertificate,
    production_construction_masking: ProductionConstructionMaskingCorrespondenceCertificate,
    aggregate_wide_masking: AggregateWideMaskingCertificate,
    production_aggregate_wide_views: ProductionAggregateWideViewCorrespondenceCertificate,
    private_row_pad_generator_hybrid: PrivateRowPadGeneratorHybridCertificate,
    whir_geometry: ProductionWhirGeometryCertificate,
    prefix_stacking: PrefixStackingCertificate,
    state_epoch_rows: Vec<StateEpochRow>,
    oracle_equation_rows: Vec<OracleEquationCoverageRow>,
    selected_plan_state_predicate: SelectedPlanStatePredicateCertificate,
    cms19_whole_state_transitions: Cms19WholeStateTransitionCertificate,
    cms19_strong_state_hash_chain: Cms19StrongStateHashChainCertificate,
    complete_verifier_oracle_ledger: CompleteVerifierOracleLedger,
    deployed_aggregate_leaf_oracle: DeployedAggregateLeafOracleCertificate,
    cms19_whole_database_support: Cms19WholeDatabaseSupportCertificate,
    commitment_subtree_extraction: CommitmentSubtreeExtractionCertificate,
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: Cms19ArithmeticCertificate,
}

impl RowCodeWhirProductionGeometryCertificate {
    fn is_complete(&self) -> bool {
        self.completeness_failure().is_none()
    }

    fn completeness_failure(&self) -> Option<ProductionGeometryCertificateFailure> {
        let parameters = self.parameters;
        let Some(witness_value_count) = parameters
            .logical_polynomial_coefficient_count
            .checked_mul(parameters.logical_polynomials_per_physical_row)
        else {
            return Some(ProductionGeometryCertificateFailure::InvalidWitnessGeometry);
        };
        let Some(expected_witness_value_count) =
            1_usize.checked_shl(parameters.physical_row_witness_variable_count as u32)
        else {
            return Some(ProductionGeometryCertificateFailure::InvalidWitnessGeometry);
        };
        let Some(expected_evaluation_domain_size) =
            1_u64.checked_shl(parameters.polynomial_commitment_variable_count as u32)
        else {
            return Some(ProductionGeometryCertificateFailure::InvalidWitnessGeometry);
        };
        let Some(expected_opening_degree_bound) = u64::try_from(witness_value_count).ok() else {
            return Some(ProductionGeometryCertificateFailure::InvalidWitnessGeometry);
        };
        let expected_code_state_count = self
            .whir_geometry
            .final_query_row
            .epoch_ordinal
            .checked_add(1)
            .and_then(|epoch_count| usize::try_from(epoch_count).ok())
            .and_then(|epoch_count| {
                epoch_count.checked_mul(parameters.folding_factor.checked_add(1)?)
            });
        let expected_fold_count = self
            .whir_geometry
            .final_query_row
            .epoch_ordinal
            .checked_add(1)
            .and_then(|epoch_count| usize::try_from(epoch_count).ok())
            .and_then(|epoch_count| epoch_count.checked_mul(parameters.folding_factor));
        if self.application_statement_schema_identifier == 0
            || self.construction_plan_identity_hash == [0_u8; 64]
            || self.relation_plan_hash == [0_u8; 64]
            || self.relation_plan_variant_hash == [0_u8; 64]
        {
            return Some(ProductionGeometryCertificateFailure::InvalidCoordinateOrIdentity);
        }
        if !parameters
            .logical_polynomial_coefficient_count
            .is_power_of_two()
            || !parameters
                .logical_polynomials_per_physical_row
                .is_power_of_two()
            || witness_value_count != expected_witness_value_count
            || parameters.table_variable_count != parameters.physical_row_witness_variable_count + 1
            || parameters.polynomial_commitment_variable_count
                != parameters.table_variable_count + parameters.row_code_log_inverse_rate
            || self.evaluation_domain_size != expected_evaluation_domain_size
            || self.opening_degree_bound_exclusive != expected_opening_degree_bound
        {
            return Some(ProductionGeometryCertificateFailure::InvalidWitnessGeometry);
        }
        if !self.relation_compiler_interpreter_semantics.is_complete()
            || !self.construction_masking.is_complete()
            || !self.production_construction_masking.is_complete()
            || !self.aggregate_wide_masking.is_complete()
            || self
                .production_construction_masking
                .construction_plan_identity_hash
                != self.construction_plan_identity_hash
            || self
                .production_construction_masking
                .relation_plan_variant_hash
                != self.relation_plan_variant_hash
            || !self
                .production_aggregate_wide_views
                .is_complete(&self.aggregate_wide_masking)
            || self
                .production_aggregate_wide_views
                .construction_plan_identity_hash
                != self.construction_plan_identity_hash
            || !self.private_row_pad_generator_hybrid.is_complete()
        {
            return Some(
                ProductionGeometryCertificateFailure::IncompleteRelationOrMaskingCertificate,
            );
        }
        if expected_code_state_count != Some(self.whir_geometry.code_state_rows.len())
            || self.whir_geometry.interleaved_unique_decoding_rows.len()
                != self.whir_geometry.code_state_rows.len()
            || expected_fold_count != Some(self.whir_geometry.fold_rows.len())
            || self.whir_geometry.final_query_row.query_count == 0
        {
            return Some(ProductionGeometryCertificateFailure::IncompleteWhirGeometry);
        }
        if self.prefix_stacking.table_variable_count != parameters.table_variable_count
            || self.prefix_stacking.stacked_variable_count
                != parameters.polynomial_commitment_variable_count
        {
            return Some(ProductionGeometryCertificateFailure::InvalidPrefixStacking);
        }
        if self.state_epoch_rows.is_empty() || self.oracle_equation_rows.is_empty() {
            return Some(ProductionGeometryCertificateFailure::IncompleteOracleStateRows);
        }
        if self.selected_plan_state_predicate.transition_rows.len()
            != usize::try_from(self.logical_verifier_message_count).unwrap_or(usize::MAX)
                + self
                    .selected_plan_state_predicate
                    .transition_rows
                    .iter()
                    .filter(|row| row.failure_event_owner.is_none())
                    .count()
        {
            return Some(
                ProductionGeometryCertificateFailure::IncompleteSelectedStatePredecessorClosure,
            );
        }
        let covered_transcript_equation_count = self
            .oracle_equation_rows
            .iter()
            .try_fold(0_u64, |count, row| count.checked_add(row.equation_count));
        if !self.cms19_whole_state_transitions.is_complete()
            || !self
                .cms19_whole_state_transitions
                .matches_selected_plan_state_predicate(&self.selected_plan_state_predicate)
            || self
                .cms19_whole_state_transitions
                .construction_plan_identity_hash
                != self.construction_plan_identity_hash
            || self
                .cms19_whole_state_transitions
                .covered_transcript_equation_count
                != covered_transcript_equation_count.unwrap_or(u64::MAX)
            || self
                .cms19_whole_state_transitions
                .verifier_message_fill_count
                != self.logical_verifier_message_count
            || self
                .cms19_whole_state_transitions
                .linear_bcs_transcript_plan_hash
                != self
                    .cms19_strong_state_hash_chain
                    .canonical_oracle_plan_hash
        {
            return Some(ProductionGeometryCertificateFailure::IncompleteWholeStateCorrespondence);
        }
        if !self.cms19_strong_state_hash_chain.is_complete() {
            return Some(ProductionGeometryCertificateFailure::IncompleteStrongStateHashChain);
        }
        if self
            .complete_verifier_oracle_ledger
            .complete_hash_query_count
            == 0
        {
            return Some(ProductionGeometryCertificateFailure::IncompleteVerifierLedger);
        }
        if !self
            .deployed_aggregate_leaf_oracle
            .is_eligible_for_uniform_required_output()
        {
            return Some(ProductionGeometryCertificateFailure::IneligibleDeployedLeafOracle);
        }
        if !self.cms19_whole_database_support.is_complete()
            || self
                .cms19_whole_database_support
                .construction_plan_identity_hash
                != self.construction_plan_identity_hash
            || self.cms19_whole_database_support.claimed_hash_query_count
                != self
                    .deployed_aggregate_leaf_oracle
                    .deployed_verifier_hash_query_count
            || self
                .cms19_whole_database_support
                .claimed_accepting_database_equation_count
                != self
                    .deployed_aggregate_leaf_oracle
                    .deployed_accepting_database_equation_count
            || self
                .cms19_whole_database_support
                .uncovered_hash_query_count()
                != Some(0)
            || self
                .cms19_whole_database_support
                .uncovered_accepting_database_equation_count()
                != Some(0)
        {
            return Some(ProductionGeometryCertificateFailure::IncompleteWholeDatabaseSupport);
        }
        if !self.commitment_subtree_extraction.is_complete() {
            return Some(
                ProductionGeometryCertificateFailure::IncompleteCommitmentSubtreeExtraction,
            );
        }
        if self.cms19_arithmetic.verifier_hash_query_count
            != self
                .deployed_aggregate_leaf_oracle
                .deployed_verifier_hash_query_count
            || self.cms19_arithmetic.accepting_database_equation_count
                != self
                    .deployed_aggregate_leaf_oracle
                    .deployed_accepting_database_equation_count
        {
            return Some(ProductionGeometryCertificateFailure::InconsistentQromArithmetic);
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedProductionGeometryCertificateRecord {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    construction_plan_identity_hash: [u8; 64],
    parameters: RowCodeWhirSelectedParameters,
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    deployed_verifier_hash_query_count: u64,
    deployed_accepting_database_equation_count: u64,
}

impl CheckedProductionGeometryCertificateRecord {
    fn from_complete(certificate: &RowCodeWhirProductionGeometryCertificate) -> Self {
        debug_assert!(certificate.is_complete());
        Self {
            application_statement_schema_identifier: certificate
                .application_statement_schema_identifier,
            schedule_position: certificate.schedule_position,
            top_count: certificate.top_count,
            construction_plan_identity_hash: certificate.construction_plan_identity_hash,
            parameters: certificate.parameters,
            maximum_transcript_hash_query_count: certificate.maximum_transcript_hash_query_count,
            logical_verifier_message_count: certificate.logical_verifier_message_count,
            deployed_verifier_hash_query_count: certificate
                .deployed_aggregate_leaf_oracle
                .deployed_verifier_hash_query_count,
            deployed_accepting_database_equation_count: certificate
                .deployed_aggregate_leaf_oracle
                .deployed_accepting_database_equation_count,
        }
    }

    fn is_complete(&self) -> bool {
        self.application_statement_schema_identifier != 0
            && self.construction_plan_identity_hash != [0_u8; 64]
            && self
                .parameters
                .logical_polynomial_coefficient_count
                .is_power_of_two()
            && self
                .parameters
                .logical_polynomials_per_physical_row
                .is_power_of_two()
            && self.maximum_transcript_hash_query_count > 0
            && self.logical_verifier_message_count > 0
            && self.deployed_verifier_hash_query_count > 0
            && self.deployed_accepting_database_equation_count > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CheckedProductionGeometryCertificateInventory {
    records: Vec<CheckedProductionGeometryCertificateRecord>,
    masking_certificates: Vec<(
        RowCodeWhirSelectedParameters,
        AggregateWideMaskingCertificate,
    )>,
}

fn derive_production_whir_geometry_certificate(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
) -> Result<ProductionWhirGeometryCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let encoded_oracles = plan
        .whir
        .rounds
        .iter()
        .map(|round| round.encoded_oracle)
        .chain(std::iter::once(plan.whir.final_round.encoded_oracle))
        .collect::<Vec<_>>();
    let supplied_commitment_openings = checked_supplied_commitment_opening_rows(plan)?;
    let whir_epoch_openings = &supplied_commitment_openings.whir_epochs;
    let source_epoch_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if encoded_oracles.len() != source_epoch_count
        || whir_epoch_openings.len() != source_epoch_count
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let initial_evaluation_domain_size = 1_usize
        .checked_shl(
            u32::try_from(
                parameters
                    .polynomial_commitment_variable_count
                    .checked_add(parameters.starting_log_inverse_rate)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if whir_epoch_openings[0].query_count != parameters.outer_query_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let encoded_oracle_leaf_width = 1_usize
        .checked_shl(
            u32::try_from(parameters.folding_factor)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let code_state_count = source_epoch_count
        .checked_mul(
            parameters
                .folding_factor
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut code_state_rows = Vec::with_capacity(code_state_count);
    let mut interleaved_unique_decoding_rows = Vec::with_capacity(code_state_count);
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let encoded_oracle = encoded_oracles[epoch_index];
        let opening = whir_epoch_openings[epoch_index];
        let expected_evaluation_count = initial_evaluation_domain_size
            .checked_shr(epoch_ordinal)
            .filter(|count| *count > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let preceding_query_count = epoch_index
            .checked_sub(1)
            .map_or(usize::MAX, |preceding_index| {
                whir_epoch_openings[preceding_index].query_count
            });
        if encoded_oracle.evaluation_count != expected_evaluation_count
            || encoded_oracle.leaf_width != encoded_oracle_leaf_width
            || encoded_oracle
                .leaf_count
                .checked_mul(encoded_oracle.leaf_width)
                != Some(encoded_oracle.evaluation_count)
            || opening.epoch_ordinal != epoch_ordinal
            || opening.leaf_count != encoded_oracle.leaf_count
            || opening.query_count == 0
            || opening.query_count > preceding_query_count
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let (
            source_message_dimension,
            source_randomness_dimension,
            source_domain_size,
            source_query_count,
            source_interleaving_width,
        ) = aggregate_wide_masking
            .folded_source_code_geometry(epoch_index)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if source_domain_size != encoded_oracle.leaf_count
            || source_query_count != opening.query_count
            || source_interleaving_width != encoded_oracle.leaf_width
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        let parent_dimension = u64::try_from(
            source_message_dimension
                .checked_add(source_randomness_dimension)
                .and_then(|dimension| dimension.checked_mul(source_interleaving_width))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_domain_size = u64::try_from(encoded_oracle.evaluation_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_fold_ordinal = u32::try_from(parameters.folding_factor)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_domain_size = parent_domain_size
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_dimension = parent_dimension
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_unique_decoding_radius = terminal_domain_size
            .checked_sub(terminal_dimension)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
            / 2;
        let selected_error_count_at_terminal = terminal_unique_decoding_radius
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let selected_state_relative_distance =
            ExactFraction::new(selected_error_count_at_terminal, terminal_domain_size)?;
        for fold_ordinal in 0..=parameters.folding_factor {
            let code_state = WhirCodeStateRow::derive(
                epoch_ordinal,
                u32::try_from(fold_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                parent_domain_size,
                parent_dimension,
                selected_state_relative_distance,
            )?;
            interleaved_unique_decoding_rows.push(InterleavedUniqueDecodingRow::derive(
                code_state,
                source_interleaving_width,
            )?);
            code_state_rows.push(code_state);
        }
    }

    let mut fold_rows = Vec::with_capacity(
        source_epoch_count
            .checked_mul(parameters.folding_factor)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        for fold_index in 0..parameters.folding_factor {
            let fold_ordinal = u32::try_from(fold_index + 1)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let transcript_operation_ordinal = find_fold_transcript_operation(
                plan.transcript_operations(),
                epoch_ordinal,
                u32::try_from(fold_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )?;
            let target_state = code_state_rows
                .iter()
                .find(|row| row.epoch_ordinal == epoch_ordinal && row.fold_ordinal == fold_ordinal)
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
            fold_rows.push(WhirFoldFailureRow {
                epoch_ordinal,
                fold_ordinal,
                transcript_operation_ordinal,
                target_domain_size: target_state.domain_size,
                sumcheck_numerator: WHIR_SUMCHECK_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
                mutual_correlated_agreement_numerator: target_state.domain_size,
            });
        }
    }

    let mut shift_rows = Vec::with_capacity(plan.whir.rounds.len());
    for round in &plan.whir.rounds {
        let transcript_operation_ordinal =
            find_unique_transcript_operation(plan.transcript_operations(), |operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::RoundCombination { round_ordinal },
                        ..
                    } if *round_ordinal == round.round_ordinal
                )
            })?;
        let query_count = u64::try_from(
            whir_epoch_openings
                .get(
                    usize::try_from(round.round_ordinal)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let list_size = 1_u64;
        shift_rows.push(WhirShiftFailureRow {
            round_ordinal: round.round_ordinal,
            transcript_operation_ordinal,
            query_count,
            list_size,
            algebraic_numerator: list_size
                .checked_mul(
                    query_count
                        .checked_add(1)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        });
    }

    let final_source_epoch_ordinal = u32::try_from(source_epoch_count - 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let final_code_state = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == final_source_epoch_ordinal
                && usize::try_from(row.fold_ordinal).ok() == Some(parameters.folding_factor)
        })
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_query_row = WhirFinalQueryRow {
        epoch_ordinal: final_source_epoch_ordinal,
        query_count: u64::try_from(
            whir_epoch_openings
                .last()
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        bad_agreement: final_code_state.false_state_agreement_ceiling,
    };
    Ok(ProductionWhirGeometryCertificate {
        code_state_rows,
        interleaved_unique_decoding_rows,
        fold_rows,
        shift_rows,
        final_query_row,
    })
}

fn checked_row_code_whir_production_geometry_certificate_with_masking(
    plan: &RowCodeWhirConstructionPlan,
    artifact: &ValidatedRelationPlanArtifact,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
) -> Result<RowCodeWhirProductionGeometryCertificate, WhirTheoremCertificateError> {
    let contextualize = |stage: ProductionGeometryCertificateStage,
                         error: WhirTheoremCertificateError| {
        WhirTheoremCertificateError::SelectedProductionGeometry {
            application_statement_schema_identifier: plan.application_statement_schema_identifier,
            schedule_position: plan.schedule_position,
            top_count: plan.top_count,
            stage,
            failure: error.into(),
        }
    };
    let expected_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::ConstructionPlan,
            WhirTheoremCertificateError::InvalidSelectedGeometry,
        )
    })?;
    let relation_plan_variant_hash = relation_variant.canonical_hash().map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::ConstructionPlan,
            WhirTheoremCertificateError::InvalidSelectedGeometry,
        )
    })?;
    if artifact.application_statement_schema_identifier()
        != plan.application_statement_schema_identifier
        || artifact.checked_context() != relation_context
        || &expected_plan != plan
        || plan.relation_plan_variant_hash != relation_plan_variant_hash
    {
        return Err(contextualize(
            ProductionGeometryCertificateStage::ConstructionPlan,
            WhirTheoremCertificateError::InvalidSelectedGeometry,
        ));
    }
    let parameters = plan.selected_parameters();
    let hiding_configuration = super::super::hiding_whir::selected_hiding_whir_config(parameters)
        .map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::HidingConfiguration,
            WhirTheoremCertificateError::IncompleteMaskingCorrespondence,
        )
    })?;
    if parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.folding_factor != 3
        || plan.whir.rounds.len() != hiding_configuration.n_rounds()
        || plan.whir.initial_sumcheck_round_count != hiding_configuration.round_folding_factor(0)
        || plan.whir.final_round.sumcheck_round_count
            != hiding_configuration.inner.final_sumcheck_rounds
    {
        return Err(contextualize(
            ProductionGeometryCertificateStage::HidingConfiguration,
            WhirTheoremCertificateError::InvalidSelectedGeometry,
        ));
    }
    let relation_compiler_interpreter_semantics =
        checked_relation_compiler_interpreter_semantics(relation_variant, relation_context)
            .map_err(|_| {
                contextualize(
                    ProductionGeometryCertificateStage::RelationSemantics,
                    WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence,
                )
            })?;
    if !relation_compiler_interpreter_semantics.is_complete()
        || relation_compiler_interpreter_semantics.canonical_variant_hash()
            != relation_plan_variant_hash
        || relation_compiler_interpreter_semantics.constraint_count()
            != relation_variant.constraint_count()
    {
        return Err(contextualize(
            ProductionGeometryCertificateStage::RelationSemantics,
            WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence,
        ));
    }
    let construction_masking = checked_zero_knowledge_mask_image_for_parameters(
        relation_variant,
        relation_context,
        parameters,
    )
    .map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::MaskingCorrespondence,
            WhirTheoremCertificateError::IncompleteMaskingCorrespondence,
        )
    })?;
    if !construction_masking.is_complete()
        || !aggregate_wide_masking.is_complete()
        || !construction_masking.aggregate_claims_factor_through_masked_openings()
        || !construction_masking.aggregate_wide_views_delegate_to_precommitted_pad()
    {
        return Err(contextualize(
            ProductionGeometryCertificateStage::MaskingCorrespondence,
            WhirTheoremCertificateError::IncompleteMaskingCorrespondence,
        ));
    }
    let production_construction_masking = derive_production_construction_masking_correspondence(
        plan,
        relation_variant,
        relation_context,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::MaskingCorrespondence,
            error,
        )
    })?;
    let production_aggregate_wide_views =
        derive_production_aggregate_wide_view_correspondence(plan, aggregate_wide_masking)
            .map_err(|error| {
                contextualize(
                    ProductionGeometryCertificateStage::MaskingCorrespondence,
                    error,
                )
            })?;
    let private_row_pad_generator_hybrid = PrivateRowPadGeneratorHybridCertificate::derive(plan)
        .map_err(|error| {
            contextualize(
                ProductionGeometryCertificateStage::RowPadGeneratorHybrid,
                error,
            )
        })?;
    if !private_row_pad_generator_hybrid.is_complete_for_plan(plan) {
        return Err(contextualize(
            ProductionGeometryCertificateStage::RowPadGeneratorHybrid,
            WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid,
        ));
    }
    let whir_geometry = derive_production_whir_geometry_certificate(plan, aggregate_wide_masking)
        .map_err(|error| {
        contextualize(ProductionGeometryCertificateStage::WhirGeometry, error)
    })?;
    let prefix_stacking = derive_prefix_stacking_certificate(plan).map_err(|error| {
        contextualize(ProductionGeometryCertificateStage::PrefixStacking, error)
    })?;
    let catalog = plan.oracle_equation_catalog().map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::OracleEquationCatalog,
            WhirTheoremCertificateError::InvalidSelectedGeometry,
        )
    })?;
    let (state_epoch_rows, oracle_equation_rows) = derive_state_and_equation_rows(&catalog)
        .map_err(|error| {
            contextualize(ProductionGeometryCertificateStage::StateEquationRows, error)
        })?;
    validate_state_and_equation_rows(&catalog, &state_epoch_rows, &oracle_equation_rows).map_err(
        |error| contextualize(ProductionGeometryCertificateStage::StateEquationRows, error),
    )?;
    let maximum_transcript_hash_query_count =
        catalog.maximum_transcript_hash_query_count().map_err(|_| {
            contextualize(
                ProductionGeometryCertificateStage::TranscriptCounts,
                WhirTheoremCertificateError::InvalidSelectedGeometry,
            )
        })?;
    let logical_verifier_message_count =
        catalog.logical_verifier_message_count().map_err(|_| {
            contextualize(
                ProductionGeometryCertificateStage::TranscriptCounts,
                WhirTheoremCertificateError::InvalidSelectedGeometry,
            )
        })?;
    let selected_plan_state_predicate = derive_selected_plan_state_predicate_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &whir_geometry.code_state_rows,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::SelectedStatePredicate,
            error,
        )
    })?;
    let cms19_whole_state_transitions = derive_cms19_whole_state_transition_certificate(
        plan,
        &catalog,
        &selected_plan_state_predicate,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::WholeStateCorrespondence,
            error,
        )
    })?;
    let cms19_strong_state_hash_chain = derive_cms19_strong_state_hash_chain_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &oracle_equation_rows,
        &selected_plan_state_predicate,
        &cms19_whole_state_transitions,
        logical_verifier_message_count,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::StrongStateHashChain,
            error,
        )
    })?;
    let transcript_equation_count = catalog.maximum_equation_count().map_err(|_| {
        contextualize(
            ProductionGeometryCertificateStage::VerifierLedger,
            WhirTheoremCertificateError::ArithmeticOverflow,
        )
    })?;
    let complete_verifier_oracle_ledger = derive_complete_verifier_oracle_ledger(
        plan,
        relation_variant,
        transcript_equation_count,
        maximum_transcript_hash_query_count,
    )
    .map_err(|error| contextualize(ProductionGeometryCertificateStage::VerifierLedger, error))?;
    let deployed_aggregate_leaf_oracle = derive_deployed_aggregate_leaf_oracle_certificate(
        plan,
        aggregate_wide_masking,
        &complete_verifier_oracle_ledger,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::DeployedLeafOracle,
            error,
        )
    })?;
    let cms19_whole_database_support = derive_cms19_whole_database_support_certificate(
        plan,
        &complete_verifier_oracle_ledger,
        &deployed_aggregate_leaf_oracle,
        &cms19_whole_state_transitions,
        &oracle_equation_rows,
    )
    .map_err(|error| {
        contextualize(
            ProductionGeometryCertificateStage::WholeDatabaseSupport,
            error,
        )
    })?;
    let commitment_subtree_extraction = derive_commitment_subtree_extraction_certificate(
        plan,
        &complete_verifier_oracle_ledger.merkle_rows,
    )
    .map_err(|error| contextualize(ProductionGeometryCertificateStage::CommitmentSubtree, error))?;
    let cms19_arithmetic = derive_cms19_arithmetic_certificate(
        deployed_aggregate_leaf_oracle.deployed_verifier_hash_query_count,
        deployed_aggregate_leaf_oracle.deployed_accepting_database_equation_count,
    );
    let certificate = RowCodeWhirProductionGeometryCertificate {
        application_statement_schema_identifier: plan.application_statement_schema_identifier,
        schedule_position: plan.schedule_position,
        top_count: plan.top_count,
        construction_plan_identity_hash: plan.canonical_identity_hash().map_err(|_| {
            contextualize(
                ProductionGeometryCertificateStage::ConstructionIdentity,
                WhirTheoremCertificateError::InvalidSelectedGeometry,
            )
        })?,
        relation_plan_hash: plan.relation_plan_hash,
        relation_plan_variant_hash,
        parameters,
        trace_domain_size: plan.trace_domain_size,
        evaluation_domain_size: plan.evaluation_domain_size,
        opening_degree_bound_exclusive: plan.opening_degree_bound_exclusive,
        proof_privacy_mode: plan.proof_privacy_mode,
        relation_compiler_interpreter_semantics,
        construction_masking,
        production_construction_masking,
        aggregate_wide_masking: aggregate_wide_masking.clone(),
        production_aggregate_wide_views,
        private_row_pad_generator_hybrid,
        whir_geometry,
        prefix_stacking,
        state_epoch_rows,
        oracle_equation_rows,
        selected_plan_state_predicate,
        cms19_whole_state_transitions,
        cms19_strong_state_hash_chain,
        complete_verifier_oracle_ledger,
        deployed_aggregate_leaf_oracle,
        cms19_whole_database_support,
        commitment_subtree_extraction,
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        cms19_arithmetic,
    };
    if let Some(failure) = certificate.completeness_failure() {
        return Err(WhirTheoremCertificateError::SelectedProductionGeometry {
            application_statement_schema_identifier: plan.application_statement_schema_identifier,
            schedule_position: plan.schedule_position,
            top_count: plan.top_count,
            stage: ProductionGeometryCertificateStage::Completeness,
            failure,
        });
    }
    Ok(certificate)
}

fn checked_selected_row_code_whir_production_geometry_certificates(
    artifacts: &[ValidatedRelationPlanArtifact],
    mut include_plan: impl FnMut(&RowCodeWhirConstructionPlan) -> bool,
) -> Result<CheckedProductionGeometryCertificateInventory, WhirTheoremCertificateError> {
    let mut masking_certificates = Vec::<(
        RowCodeWhirSelectedParameters,
        AggregateWideMaskingCertificate,
    )>::new();
    let mut records = Vec::new();
    for artifact in artifacts {
        let relation_context = selected_relation_plan_check_context(
            artifact.application_statement_schema_identifier(),
        )
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        for relation_variant in artifact.compiled_plan().variants() {
            let application_statement_schema_identifier =
                artifact.application_statement_schema_identifier();
            let schedule_position = relation_variant.schedule_position();
            let top_count = relation_variant.top_count();
            let contextualize =
                |stage: ProductionGeometryCertificateStage, error: WhirTheoremCertificateError| {
                    match error {
                        contextual @ WhirTheoremCertificateError::SelectedProductionGeometry {
                            ..
                        } => contextual,
                        other => WhirTheoremCertificateError::SelectedProductionGeometry {
                            application_statement_schema_identifier,
                            schedule_position,
                            top_count,
                            stage,
                            failure: other.into(),
                        },
                    }
                };
            let plan = RowCodeWhirConstructionPlan::for_selected_variant(
                artifact,
                schedule_position,
                top_count,
            )
            .map_err(|_| {
                contextualize(
                    ProductionGeometryCertificateStage::ConstructionPlan,
                    WhirTheoremCertificateError::InvalidSelectedGeometry,
                )
            })?;
            if !include_plan(&plan) {
                continue;
            }
            let certificate_started_at = Instant::now();
            eprintln!(
                "checking production geometry schema {application_statement_schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?}",
            );
            let parameters = plan.selected_parameters();
            let masking_certificate_index = if let Some(index) = masking_certificates
                .iter()
                .position(|(cached_parameters, _)| *cached_parameters == parameters)
            {
                index
            } else {
                let hiding_configuration = super::super::hiding_whir::selected_hiding_whir_config(
                    parameters,
                )
                .map_err(|_| {
                    contextualize(
                        ProductionGeometryCertificateStage::HidingConfiguration,
                        WhirTheoremCertificateError::IncompleteMaskingCorrespondence,
                    )
                })?;
                let masking_certificate = AggregateWideMaskingCertificate::derive(
                    &hiding_configuration,
                )
                .map_err(|_| {
                    contextualize(
                        ProductionGeometryCertificateStage::MaskingCorrespondence,
                        WhirTheoremCertificateError::IncompleteMaskingCorrespondence,
                    )
                })?;
                masking_certificates.push((parameters, masking_certificate));
                masking_certificates.len() - 1
            };
            let certificate = checked_row_code_whir_production_geometry_certificate_with_masking(
                &plan,
                artifact,
                relation_variant,
                &relation_context,
                &masking_certificates[masking_certificate_index].1,
            )
            .map_err(|error| {
                contextualize(ProductionGeometryCertificateStage::Completeness, error)
            })?;
            records.push(CheckedProductionGeometryCertificateRecord::from_complete(
                &certificate,
            ));
            eprintln!(
                "checked production geometry schema {application_statement_schema_identifier:#06x}, schedule {schedule_position:?}, top count {top_count:?} in {:?}",
                certificate_started_at.elapsed(),
            );
        }
    }
    let mut coordinates = BTreeSet::new();
    let mut construction_identities = BTreeSet::new();
    if records.is_empty()
        || records.iter().any(|certificate| {
            !coordinates.insert((
                certificate.application_statement_schema_identifier,
                certificate.schedule_position,
                certificate.top_count,
            )) || !construction_identities.insert(certificate.construction_plan_identity_hash)
        })
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok(CheckedProductionGeometryCertificateInventory {
        records,
        masking_certificates,
    })
}

pub(in crate::bgv::proof_suite) fn checked_row_code_whir_failure_partition(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<RowCodeWhirFailurePartitionCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let hiding_configuration =
        super::super::hiding_whir::selected_hiding_whir_config(parameters)
            .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if parameters != RowCodeWhirSelectedParameters::selected()
        || parameters.soundness_assumption != RowCodeWhirSoundnessAssumption::UniqueDecoding
        || parameters.folding_factor != 3
        || plan.whir.rounds.len() != hiding_configuration.n_rounds()
        || plan.whir.initial_sumcheck_round_count != hiding_configuration.round_folding_factor(0)
        || plan.whir.final_round.sumcheck_round_count
            != hiding_configuration.inner.final_sumcheck_rounds
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let compiled_relation_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        &relation_context,
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let validated_relation_plan = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
        compiled_relation_plan,
        &relation_context,
    )
    .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let relation_variant = validated_relation_plan
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let relation_compiler_interpreter_semantics =
        checked_relation_compiler_interpreter_semantics(relation_variant, &relation_context)
            .map_err(|_| WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence)?;
    if !relation_compiler_interpreter_semantics.is_complete()
        || relation_compiler_interpreter_semantics.canonical_variant_hash()
            != relation_variant.canonical_hash().map_err(|_| {
                WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence
            })?
        || relation_compiler_interpreter_semantics.constraint_count()
            != relation_variant.constraint_count()
    {
        return Err(WhirTheoremCertificateError::IncompleteRelationSemanticCorrespondence);
    }
    let expected_construction_plan =
        RowCodeWhirConstructionPlan::for_selected_variant(&validated_relation_plan, None, None)
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if &expected_construction_plan != plan {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let (polynomial_protocol_extractor, point_constraint_extractor) =
        checked_exact_same_secret_extractor_correspondence(
            plan,
            relation_variant,
            &relation_context,
            validated_relation_plan.canonical_plan_hash(),
            relation_variant.canonical_hash().map_err(|_| {
                WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence
            })?,
        )
        .map_err(|_| WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence)?;
    let construction_plan_identity_hash = plan
        .canonical_identity_hash()
        .map_err(|_| WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence)?;
    if !polynomial_protocol_extractor.is_complete()
        || !point_constraint_extractor.is_complete()
        || polynomial_protocol_extractor.construction_plan_identity_hash()
            != construction_plan_identity_hash
        || point_constraint_extractor.construction_plan_identity_hash()
            != construction_plan_identity_hash
    {
        return Err(WhirTheoremCertificateError::IncompletePolynomialExtractorCorrespondence);
    }
    let construction_masking = checked_zero_knowledge_mask_image_for_parameters(
        relation_variant,
        &relation_context,
        parameters,
    )
    .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    let aggregate_wide_masking = AggregateWideMaskingCertificate::derive(&hiding_configuration)
        .map_err(|_| WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
    if !construction_masking.is_complete()
        || !aggregate_wide_masking.is_complete()
        || !construction_masking.aggregate_claims_factor_through_masked_openings()
        || !construction_masking.aggregate_wide_views_delegate_to_precommitted_pad()
    {
        return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
    }
    let production_construction_masking = derive_production_construction_masking_correspondence(
        plan,
        relation_variant,
        &relation_context,
    )?;
    let production_aggregate_wide_views =
        derive_production_aggregate_wide_view_correspondence(plan, &aggregate_wide_masking)?;
    let private_row_pad_generator_hybrid = PrivateRowPadGeneratorHybridCertificate::derive(plan)
        .map_err(|_| WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid)?;
    if !private_row_pad_generator_hybrid.is_complete_for_plan(plan) {
        return Err(WhirTheoremCertificateError::IncompleteRowPadGeneratorHybrid);
    }

    let encoded_oracles = plan
        .whir
        .rounds
        .iter()
        .map(|round| round.encoded_oracle)
        .chain(std::iter::once(plan.whir.final_round.encoded_oracle))
        .collect::<Vec<_>>();
    let supplied_commitment_openings = checked_supplied_commitment_opening_rows(plan)?;
    let whir_epoch_openings = &supplied_commitment_openings.whir_epochs;
    let source_epoch_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if encoded_oracles.len() != source_epoch_count
        || whir_epoch_openings.len() != source_epoch_count
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    // The displayed epoch geometry is bound to the generated construction plan
    // rather than to a second hand-maintained table. The initial evaluation
    // domain is the committed dimension at the starting rate, every later epoch
    // halves that domain, and the per-epoch query counts are the plan's own
    // accepted-order opening counts. A duplicated literal table would make the
    // theorem check two authorities instead of the one the identity signs.
    let initial_evaluation_domain_size = 1_usize
        .checked_shl(
            u32::try_from(
                parameters
                    .polynomial_commitment_variable_count
                    .checked_add(parameters.starting_log_inverse_rate)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if whir_epoch_openings[0].query_count != parameters.outer_query_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let encoded_oracle_leaf_width = 1_usize
        .checked_shl(
            u32::try_from(parameters.folding_factor)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let code_state_count = source_epoch_count
        .checked_mul(
            parameters
                .folding_factor
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut code_state_rows = Vec::with_capacity(code_state_count);
    let mut interleaved_unique_decoding_rows = Vec::with_capacity(code_state_count);
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let encoded_oracle = encoded_oracles[epoch_index];
        let opening = whir_epoch_openings[epoch_index];
        let expected_evaluation_count = initial_evaluation_domain_size
            .checked_shr(epoch_ordinal)
            .filter(|count| *count > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let preceding_query_count = epoch_index
            .checked_sub(1)
            .map_or(usize::MAX, |preceding_index| {
                whir_epoch_openings[preceding_index].query_count
            });
        if encoded_oracle.evaluation_count != expected_evaluation_count
            || encoded_oracle.leaf_width != encoded_oracle_leaf_width
            || encoded_oracle
                .leaf_count
                .checked_mul(encoded_oracle.leaf_width)
                != Some(encoded_oracle.evaluation_count)
            || opening.epoch_ordinal != epoch_ordinal
            || opening.leaf_count != encoded_oracle.leaf_count
            || opening.query_count == 0
            || opening.query_count > preceding_query_count
        {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
        let (
            source_message_dimension,
            source_randomness_dimension,
            source_domain_size,
            source_query_count,
            source_interleaving_width,
        ) = aggregate_wide_masking
            .folded_source_code_geometry(epoch_index)
            .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if source_domain_size != encoded_oracle.leaf_count
            || source_query_count != opening.query_count
            || source_interleaving_width != encoded_oracle.leaf_width
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        // The source encoder writes one message segment followed by one
        // independently sampled randomness segment in each interleaved lane;
        // every remaining coefficient is fixed to zero. Consequently the
        // exact image dimension is `(message + randomness) * laneCount`, not
        // the unmasked message dimension and not the next-power-of-two buffer
        // capacity used by the FFT implementation.
        let parent_dimension = u64::try_from(
            source_message_dimension
                .checked_add(source_randomness_dimension)
                .and_then(|dimension| dimension.checked_mul(source_interleaving_width))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_domain_size = u64::try_from(encoded_oracle.evaluation_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_fold_ordinal = u32::try_from(parameters.folding_factor)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let terminal_domain_size = parent_domain_size
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_dimension = parent_dimension
            .checked_shr(terminal_fold_ordinal)
            .filter(|size| *size > 0)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let terminal_unique_decoding_radius = terminal_domain_size
            .checked_sub(terminal_dimension)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
            / 2;
        let selected_error_count_at_terminal = terminal_unique_decoding_radius
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
        let selected_state_relative_distance =
            ExactFraction::new(selected_error_count_at_terminal, terminal_domain_size)?;
        for fold_ordinal in 0..=parameters.folding_factor {
            let code_state = WhirCodeStateRow::derive(
                epoch_ordinal,
                u32::try_from(fold_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                parent_domain_size,
                parent_dimension,
                selected_state_relative_distance,
            )?;
            interleaved_unique_decoding_rows.push(InterleavedUniqueDecodingRow::derive(
                code_state,
                source_interleaving_width,
            )?);
            code_state_rows.push(code_state);
        }
    }

    let mut fold_rows = Vec::with_capacity(
        source_epoch_count
            .checked_mul(parameters.folding_factor)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    for epoch_index in 0..encoded_oracles.len() {
        let epoch_ordinal = u32::try_from(epoch_index)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        for fold_index in 0..parameters.folding_factor {
            let fold_ordinal = u32::try_from(fold_index + 1)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let transcript_operation_ordinal = find_fold_transcript_operation(
                plan.transcript_operations(),
                epoch_ordinal,
                u32::try_from(fold_index)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )?;
            let target_state = code_state_rows
                .iter()
                .find(|row| row.epoch_ordinal == epoch_ordinal && row.fold_ordinal == fold_ordinal)
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
            fold_rows.push(WhirFoldFailureRow {
                epoch_ordinal,
                fold_ordinal,
                transcript_operation_ordinal,
                target_domain_size: target_state.domain_size,
                sumcheck_numerator: WHIR_SUMCHECK_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
                mutual_correlated_agreement_numerator: target_state.domain_size,
            });
        }
    }

    let mut shift_rows = Vec::with_capacity(plan.whir.rounds.len());
    for round in &plan.whir.rounds {
        let transcript_operation_ordinal =
            find_unique_transcript_operation(plan.transcript_operations(), |operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension {
                        role: RowCodeWhirExtensionRole::RoundCombination { round_ordinal },
                        ..
                    } if *round_ordinal == round.round_ordinal
                )
            })?;
        let query_count = u64::try_from(
            whir_epoch_openings
                .get(
                    usize::try_from(round.round_ordinal)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let list_size = 1_u64;
        shift_rows.push(WhirShiftFailureRow {
            round_ordinal: round.round_ordinal,
            transcript_operation_ordinal,
            query_count,
            list_size,
            algebraic_numerator: list_size
                .checked_mul(
                    query_count
                        .checked_add(1)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        });
    }

    let final_source_epoch_ordinal = u32::try_from(source_epoch_count - 1)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let final_code_state = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == final_source_epoch_ordinal
                && usize::try_from(row.fold_ordinal).ok() == Some(parameters.folding_factor)
        })
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_query_row = WhirFinalQueryRow {
        epoch_ordinal: final_source_epoch_ordinal,
        query_count: u64::try_from(
            whir_epoch_openings
                .last()
                .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?
                .query_count,
        )
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        bad_agreement: final_code_state.false_state_agreement_ceiling,
    };

    let prefix_stacking = derive_prefix_stacking_certificate(plan)?;
    let initial_constraint_batch_numerator = prefix_stacking
        .scalar_opening_count
        .checked_sub(1)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let final_sumcheck_numerator = 0;

    let catalog = plan
        .oracle_equation_catalog()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let (state_epoch_rows, oracle_equation_rows) = derive_state_and_equation_rows(&catalog)?;
    let maximum_transcript_hash_query_count = catalog
        .maximum_transcript_hash_query_count()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let logical_verifier_message_count = catalog
        .logical_verifier_message_count()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if maximum_transcript_hash_query_count != SELECTED_TRANSCRIPT_HASH_QUERY_COUNT
        || logical_verifier_message_count != SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    validate_state_and_equation_rows(&catalog, &state_epoch_rows, &oracle_equation_rows)?;
    let selected_plan_state_predicate = derive_selected_plan_state_predicate_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &code_state_rows,
    )?;
    let cms19_whole_state_transitions = derive_cms19_whole_state_transition_certificate(
        plan,
        &catalog,
        &selected_plan_state_predicate,
    )?;

    let transcript_equation_count = catalog
        .maximum_equation_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let complete_verifier_oracle_ledger = derive_complete_verifier_oracle_ledger(
        plan,
        relation_variant,
        transcript_equation_count,
        maximum_transcript_hash_query_count,
    )?;
    let deployed_aggregate_leaf_oracle = derive_deployed_aggregate_leaf_oracle_certificate(
        plan,
        &aggregate_wide_masking,
        &complete_verifier_oracle_ledger,
    )?;
    let cms19_whole_database_support = derive_cms19_whole_database_support_certificate(
        plan,
        &complete_verifier_oracle_ledger,
        &deployed_aggregate_leaf_oracle,
        &cms19_whole_state_transitions,
        &oracle_equation_rows,
    )?;
    let commitment_subtree_extraction = derive_commitment_subtree_extraction_certificate(
        plan,
        &complete_verifier_oracle_ledger.merkle_rows,
    )?;
    let cms19_arithmetic = derive_cms19_arithmetic_certificate(
        deployed_aggregate_leaf_oracle.deployed_verifier_hash_query_count,
        deployed_aggregate_leaf_oracle.deployed_accepting_database_equation_count,
    );
    let exact_failure_magnitude =
        derive_exact_failure_magnitude_certificate(ExactFailureMagnitudeDerivationInput {
            plan,
            relation_variant,
            catalog: &catalog,
            selected_plan_state_predicate: &selected_plan_state_predicate,
            code_state_rows: &code_state_rows,
            fold_rows: &fold_rows,
            shift_rows: &shift_rows,
            aggregate_wide_masking: &aggregate_wide_masking,
            initial_constraint_batch_numerator,
            logical_verifier_message_count,
            cms19_arithmetic: &cms19_arithmetic,
        })?;
    let cms19_strong_state_hash_chain = derive_cms19_strong_state_hash_chain_certificate(
        plan,
        &catalog,
        &state_epoch_rows,
        &oracle_equation_rows,
        &selected_plan_state_predicate,
        &cms19_whole_state_transitions,
        logical_verifier_message_count,
    )?;
    let cms19_state_predicate =
        derive_cms19_state_predicate_certificate(Cms19StatePredicateCertificateInput {
            selected_plan_state_predicate: &selected_plan_state_predicate,
            plan,
            catalog: &catalog,
            code_state_rows: &code_state_rows,
            interleaved_unique_decoding_rows: &interleaved_unique_decoding_rows,
            whole_state_transitions: &cms19_whole_state_transitions,
            strong_state_hash_chain: &cms19_strong_state_hash_chain,
            relation_compiler_interpreter_semantics: &relation_compiler_interpreter_semantics,
            polynomial_protocol_extractor: &polynomial_protocol_extractor,
            point_constraint_extractor: &point_constraint_extractor,
            exact_failure_magnitude: &exact_failure_magnitude,
        });
    let cms19_applicability =
        derive_cms19_applicability_certificate(Cms19ApplicabilityCertificateInput {
            plan,
            catalog: &catalog,
            selected_plan_state_predicate: &selected_plan_state_predicate,
            whole_state_transitions: &cms19_whole_state_transitions,
            whole_database_support: &cms19_whole_database_support,
            state_predicate: &cms19_state_predicate,
            strong_state_hash_chain: &cms19_strong_state_hash_chain,
            verifier_oracle_ledger: &complete_verifier_oracle_ledger,
            deployed_leaf_oracle: &deployed_aggregate_leaf_oracle,
            exact_failure_magnitude: &exact_failure_magnitude,
        })?;
    Ok(RowCodeWhirFailurePartitionCertificate {
        code_state_rows,
        interleaved_unique_decoding_rows,
        fold_rows,
        shift_rows,
        final_query_row,
        initial_constraint_batch_numerator,
        final_sumcheck_numerator,
        prefix_stacking,
        state_epoch_rows,
        oracle_equation_rows,
        complete_verifier_oracle_ledger,
        deployed_aggregate_leaf_oracle,
        commitment_subtree_extraction,
        selected_plan_state_predicate,
        cms19_whole_state_transitions,
        cms19_whole_database_support,
        cms19_state_predicate,
        cms19_strong_state_hash_chain,
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        cms19_arithmetic,
        cms19_applicability,
        exact_failure_magnitude,
        construction_masking,
        production_construction_masking,
        aggregate_wide_masking,
        production_aggregate_wide_views,
        private_row_pad_generator_hybrid,
        relation_compiler_interpreter_semantics,
        polynomial_protocol_extractor,
        point_constraint_extractor,
    })
}

fn find_fold_transcript_operation(
    operations: &[RowCodeWhirTranscriptOperation],
    epoch_ordinal: u32,
    local_sumcheck_round_ordinal: u32,
) -> Result<u32, WhirTheoremCertificateError> {
    find_unique_transcript_operation(operations, |operation| {
        matches!(
            operation,
            RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                },
                ..
            } if *batch_ordinal == epoch_ordinal
                && *round_ordinal == local_sumcheck_round_ordinal
        )
    })
}

fn find_unique_transcript_operation(
    operations: &[RowCodeWhirTranscriptOperation],
    mut predicate: impl FnMut(&RowCodeWhirTranscriptOperation) -> bool,
) -> Result<u32, WhirTheoremCertificateError> {
    let matching = operations
        .iter()
        .enumerate()
        .filter_map(|(operation_index, operation)| predicate(operation).then_some(operation_index))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    u32::try_from(matching[0]).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

fn derive_prefix_stacking_certificate(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<PrefixStackingCertificate, WhirTheoremCertificateError> {
    let parameters = plan.selected_parameters();
    let table_width = plan.aggregate_table_width();
    let padded_width = table_width
        .checked_next_power_of_two()
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let selector_variable_count = usize::try_from(padded_width.ilog2())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_table_width = 1_usize
        .checked_shl(
            u32::try_from(parameters.row_code_log_inverse_rate)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let scalar_opening_count = plan.opening_batches.iter().try_fold(
        0_u64,
        |total, batch| -> Result<u64, WhirTheoremCertificateError> {
            if batch.requested_aggregate_column_ordinals.is_empty() {
                return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
            }
            let mut requested_columns = BTreeSet::new();
            for column_ordinal in &batch.requested_aggregate_column_ordinals {
                let column_index = usize::try_from(*column_ordinal)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
                if column_index >= table_width || !requested_columns.insert(column_index) {
                    return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
                }
            }
            total
                .checked_add(
                    u64::try_from(requested_columns.len())
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        },
    )?;
    let is_same_secret_geometry = plan.application_statement_schema_identifier
        == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
    if table_width == 0
        || table_width != expected_table_width
        || padded_width != table_width
        || plan.opening_batches.is_empty()
        || scalar_opening_count == 0
        || parameters
            .table_variable_count
            .checked_add(selector_variable_count)
            != Some(parameters.polynomial_commitment_variable_count)
        || (is_same_secret_geometry
            && (table_width != SAME_SECRET_AGGREGATE_TABLE_WIDTH
                || plan.opening_batches.len() != SAME_SECRET_OPENING_BATCH_COUNT
                || scalar_opening_count != SAME_SECRET_SCALAR_OPENING_COUNT))
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    for (batch_index, batch) in plan.opening_batches.iter().enumerate() {
        if usize::try_from(batch.point_ordinal).ok() != Some(batch_index) {
            return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
        }
    }

    let selector_indices = (0..table_width).collect::<Vec<_>>();
    let slot_size = 1_usize
        .checked_shl(
            u32::try_from(parameters.table_variable_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let stacked_size = 1_usize
        .checked_shl(
            u32::try_from(parameters.polynomial_commitment_variable_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if slot_size.checked_mul(padded_width) != Some(stacked_size)
        || selector_indices
            .iter()
            .enumerate()
            .any(|(expected, actual)| expected != *actual)
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    Ok(PrefixStackingCertificate {
        source_table_count: 1,
        committed_polynomial_count: 1,
        table_variable_count: parameters.table_variable_count,
        selector_variable_count,
        stacked_variable_count: parameters.polynomial_commitment_variable_count,
        table_width,
        opening_batch_count: plan.opening_batches.len(),
        scalar_opening_count,
        selector_indices,
    })
}

fn derive_state_and_equation_rows(
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<(Vec<StateEpochRow>, Vec<OracleEquationCoverageRow>), WhirTheoremCertificateError> {
    let mut state_rows = Vec::with_capacity(catalog.operations.len());
    let range_count = catalog
        .operations
        .iter()
        .try_fold(0_usize, |total, operation| {
            total
                .checked_add(operation.ranges.len())
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let mut equation_rows = Vec::with_capacity(range_count);
    for operation in &catalog.operations {
        let transition_owner = match &operation.kind {
            RowCodeWhirOracleEquationOperationKind::InitialTranscript => {
                StateTransitionOwner::FixedInitialState
            }
            RowCodeWhirOracleEquationOperationKind::CommonRound(_) => {
                StateTransitionOwner::ProverMessageCannotRepairFalseState
            }
            RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
            | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => {
                StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
            }
            RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => {
                match operation {
                    RowCodeWhirTranscriptOperation::SampleExtension { .. }
                    | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. } => {
                        StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
                    }
                    RowCodeWhirTranscriptOperation::FinishProofStream => {
                        StateTransitionOwner::TerminalDecision
                    }
                    RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
                    | RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                        role: RowCodeWhirObservationRole::OpeningPoint { .. },
                        ..
                    } => StateTransitionOwner::DeterministicObservationPreservesState,
                    RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
                    | RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
                    | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. } => {
                        StateTransitionOwner::ProverMessageCannotRepairFalseState
                    }
                }
            }
        };
        state_rows.push(StateEpochRow {
            operation_ordinal: operation.operation_ordinal,
            predecessor_operation_ordinal: operation.predecessor_operation_ordinal,
            transition_owner,
            first_equation_slot_ordinal: operation.first_equation_slot_ordinal,
            equation_count: operation
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        });
        for range in &operation.ranges {
            let role_pattern = match range.kind {
                RowCodeWhirOracleEquationRangeKind::InitialHeaderRoot => {
                    OracleEquationRolePattern::Single(OracleEquationRole::InitialHeaderRoot)
                }
                RowCodeWhirOracleEquationRangeKind::InitialAbsorption => {
                    OracleEquationRolePattern::Single(OracleEquationRole::InitialAbsorption)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseRoot => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseRoot)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseBinding => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseBinding)
                }
                RowCodeWhirOracleEquationRangeKind::ResponseAbsorption => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ResponseAbsorption)
                }
                RowCodeWhirOracleEquationRangeKind::AcceptedChallenge => {
                    OracleEquationRolePattern::Single(OracleEquationRole::AcceptedChallenge)
                }
                RowCodeWhirOracleEquationRangeKind::ChallengeHandle => {
                    OracleEquationRolePattern::Single(OracleEquationRole::ChallengeHandle)
                }
                RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain { .. } => {
                    OracleEquationRolePattern::Alternating {
                        first: OracleEquationRole::RejectedChallenge,
                        second: OracleEquationRole::ChallengeHandle,
                    }
                }
                RowCodeWhirOracleEquationRangeKind::ProductExpansion { .. }
                | RowCodeWhirOracleEquationRangeKind::DistinctExpansion { .. } => {
                    OracleEquationRolePattern::Single(OracleEquationRole::LinearExpansionBlock)
                }
            };
            if role_pattern.maximum_predecessor_support_count() > 2
                || matches!(role_pattern, OracleEquationRolePattern::Alternating { .. })
                    && !range.equation_count.is_multiple_of(2)
            {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            equation_rows.push(OracleEquationCoverageRow {
                operation_ordinal: operation.operation_ordinal,
                range_ordinal: range.range_ordinal,
                first_equation_slot_ordinal: operation
                    .first_equation_slot_ordinal
                    .checked_add(range.first_equation_offset)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                equation_count: range.equation_count,
                role_pattern,
            });
        }
    }
    Ok((state_rows, equation_rows))
}

fn validate_state_and_equation_rows(
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_rows: &[StateEpochRow],
    equation_rows: &[OracleEquationCoverageRow],
) -> Result<(), WhirTheoremCertificateError> {
    if state_rows.len() != catalog.operations.len()
        || state_rows.last().map(|row| row.transition_owner)
            != Some(StateTransitionOwner::TerminalDecision)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let mut next_operation_ordinal = 0_u32;
    let mut next_equation_slot_ordinal = 0_u64;
    for state_row in state_rows {
        if state_row.operation_ordinal != next_operation_ordinal
            || state_row.predecessor_operation_ordinal != state_row.operation_ordinal.checked_sub(1)
            || state_row.first_equation_slot_ordinal != next_equation_slot_ordinal
            || state_row.equation_count == 0
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        next_operation_ordinal = next_operation_ordinal
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        next_equation_slot_ordinal = next_equation_slot_ordinal
            .checked_add(state_row.equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    let mut next_covered_equation_slot = 0_u64;
    let expected_ranges = catalog
        .operations
        .iter()
        .flat_map(|operation| {
            operation.ranges.iter().map(move |range| {
                (
                    operation.operation_ordinal,
                    range.range_ordinal,
                    operation.first_equation_slot_ordinal + range.first_equation_offset,
                    range.equation_count,
                )
            })
        })
        .collect::<Vec<_>>();
    if equation_rows.len() != expected_ranges.len() {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    for (equation_row, expected_range) in equation_rows.iter().zip(expected_ranges) {
        if equation_row.first_equation_slot_ordinal != next_covered_equation_slot
            || equation_row.equation_count == 0
            || equation_row
                .role_pattern
                .maximum_predecessor_support_count()
                > 2
            || (
                equation_row.operation_ordinal,
                equation_row.range_ordinal,
                equation_row.first_equation_slot_ordinal,
                equation_row.equation_count,
            ) != expected_range
        {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
        next_covered_equation_slot = next_covered_equation_slot
            .checked_add(equation_row.equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    if next_covered_equation_slot != next_equation_slot_ordinal
        || next_covered_equation_slot
            != catalog
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(())
}

fn derive_selected_plan_state_predicate_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    code_state_rows: &[WhirCodeStateRow],
) -> Result<SelectedPlanStatePredicateCertificate, WhirTheoremCertificateError> {
    let final_epoch_ordinal = u32::try_from(plan.whir.rounds.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut transition_rows = Vec::with_capacity(catalog.operations.len());
    for operation in &catalog.operations {
        let (predicate_clause, failure_event_owner, sampler_exhaustion_is_honest_abort) =
            match &operation.kind {
                RowCodeWhirOracleEquationOperationKind::InitialTranscript => (
                    SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse,
                    None,
                    false,
                ),
                RowCodeWhirOracleEquationOperationKind::CommonRound(_) => (
                    SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove,
                    None,
                    false,
                ),
                RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) => {
                    if !matches!(
                        group.challenge(),
                        CommonProofChallenge::Theta { .. } | CommonProofChallenge::Alpha { .. }
                    ) {
                        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                    }
                    (
                        SelectedPlanStatePredicateClause::PolynomialProtocolChallenge,
                        Some(SelectedPlanFailureEventOwner::CommonProductChallenge {
                            challenge: group.challenge(),
                        }),
                        true,
                    )
                }
                RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(challenge) => {
                    if !matches!(
                        challenge,
                        CommonProofChallenge::Composition { .. }
                            | CommonProofChallenge::OutOfDomainPoint { .. }
                    ) {
                        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                    }
                    (
                        SelectedPlanStatePredicateClause::RelationReductionChallenge,
                        Some(SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                            challenge: *challenge,
                        }),
                        true,
                    )
                }
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => {
                    selected_plan_row_code_whir_transition(
                        operation,
                        final_epoch_ordinal,
                        code_state_rows,
                    )?
                }
            };
        transition_rows.push(SelectedPlanStateTransitionRow {
            operation_ordinal: operation.operation_ordinal,
            predicate_clause,
            failure_event_owner,
            sampler_exhaustion_is_honest_abort,
        });
    }

    let proof_section_rows = plan
        .proof_sections()
        .iter()
        .copied()
        .map(|section| SelectedPlanProofSectionStateRow {
            section_ordinal: section.section_ordinal,
            item_count: section.item_count,
            predicate: match section.role {
                RowCodeWhirProofSectionRole::RelationCommitment { phase } => {
                    SelectedPlanProofSectionPredicate::RelationPhaseAffineSpan { phase }
                }
                RowCodeWhirProofSectionRole::OutOfDomainEvaluations => {
                    SelectedPlanProofSectionPredicate::OutOfDomainCompositionAndRegisteredClaims
                }
                RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => {
                    SelectedPlanProofSectionPredicate::OpeningBatchMaskConsistency
                }
                RowCodeWhirProofSectionRole::AggregateCommitment => {
                    SelectedPlanProofSectionPredicate::AggregateConstrainedPolynomialCommitment
                }
                RowCodeWhirProofSectionRole::AggregateWidePadCommitment => {
                    SelectedPlanProofSectionPredicate::AggregateWidePadCommitmentBinding
                }
                RowCodeWhirProofSectionRole::PhaseOpenings { phase } => {
                    SelectedPlanProofSectionPredicate::PhaseOpeningAuthenticationAndReduction {
                        phase,
                    }
                }
                RowCodeWhirProofSectionRole::BoundTreeOpenings { bound_tree_ordinal } => {
                    SelectedPlanProofSectionPredicate::BoundAuthenticationAndReduction {
                        bound_tree_ordinal,
                    }
                }
                RowCodeWhirProofSectionRole::AggregateWideOpening => {
                    SelectedPlanProofSectionPredicate::ExplicitPointAggregateWideOpening
                }
            },
        })
        .collect::<Vec<_>>();

    let checkpoint_rows = plan
        .checkpoints()
        .iter()
        .copied()
        .map(|checkpoint| SelectedPlanCheckpointStateRow {
            checkpoint_ordinal: checkpoint.checkpoint_ordinal,
            next_transcript_operation_ordinal: checkpoint.next_transcript_operation_ordinal,
            next_proof_section_ordinal: checkpoint.next_proof_section_ordinal,
            owner: match checkpoint.boundary {
                RowCodeWhirCheckpointBoundary::SourcesAndConstruction => {
                    SelectedPlanCheckpointStateOwner::AuthenticatedSourceAndConstruction
                }
                RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => {
                    SelectedPlanCheckpointStateOwner::CompletedPhaseCommitment { phase }
                }
                RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => {
                    SelectedPlanCheckpointStateOwner::RelationEvaluationsAndMask
                }
                RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries => {
                    SelectedPlanCheckpointStateOwner::AggregateCommitmentsAndQueries
                }
                RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal } => {
                    SelectedPlanCheckpointStateOwner::CompletedWhirRound { round_ordinal }
                }
                RowCodeWhirCheckpointBoundary::CompletedProofStream => {
                    SelectedPlanCheckpointStateOwner::CompletedCanonicalProof
                }
            },
        })
        .collect::<Vec<_>>();

    let lifecycle_rows = vec![
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::AuthenticatedResume,
            preserves_cryptographic_cursor: true,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::ExplicitAbort,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::Cancellation,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::SamplerExhaustion,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::MaskRankFailure,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::StorageRefusal,
            preserves_cryptographic_cursor: false,
            emits_proof: false,
            emits_verified_capability: false,
            requires_fresh_verifier: false,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::CompletedProofTransport,
            preserves_cryptographic_cursor: true,
            emits_proof: true,
            emits_verified_capability: false,
            requires_fresh_verifier: true,
        },
        SelectedPlanLifecycleStateRow {
            transition: SelectedPlanLifecycleTransition::FreshVerifierAcceptance,
            preserves_cryptographic_cursor: true,
            emits_proof: false,
            emits_verified_capability: true,
            requires_fresh_verifier: true,
        },
    ];

    let certificate = SelectedPlanStatePredicateCertificate {
        transition_rows,
        proof_section_rows,
        checkpoint_rows,
        lifecycle_rows,
        definition_clauses: vec![
            SelectedPlanStateDefinitionClause::UniqueCanonicalPrefix,
            SelectedPlanStateDefinitionClause::OneSharedSemanticWitness,
            SelectedPlanStateDefinitionClause::DecodedEquationConsistency,
            SelectedPlanStateDefinitionClause::ConstrainedCodeState,
            SelectedPlanStateDefinitionClause::AcceptingCanonicalSuffix,
        ],
    };
    validate_selected_plan_state_predicate_certificate(
        plan,
        catalog,
        state_epoch_rows,
        code_state_rows,
        &certificate,
    )?;
    Ok(certificate)
}

fn selected_plan_row_code_whir_transition(
    operation: &RowCodeWhirTranscriptOperation,
    final_epoch_ordinal: u32,
    code_state_rows: &[WhirCodeStateRow],
) -> Result<
    (
        SelectedPlanStatePredicateClause,
        Option<SelectedPlanFailureEventOwner>,
        bool,
    ),
    WhirTheoremCertificateError,
> {
    let transition = match operation {
        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. } => (
            SelectedPlanStatePredicateClause::DeterministicProtocolSchedule,
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::ObserveExtensionValues {
            role: RowCodeWhirObservationRole::OpeningPoint { batch_ordinal },
            ..
        } => (
            SelectedPlanStatePredicateClause::DeterministicOpeningPoint {
                batch_ordinal: *batch_ordinal,
            },
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. }
        | RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
        | RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. } => (
            SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove,
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(challenge),
            whir_challenge_ordinal: None,
        } => (
            SelectedPlanStatePredicateClause::RelationReductionChallenge,
            Some(SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: *challenge,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::OpeningBatching,
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch,
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::OpeningBatching,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal },
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch {
                batch_ordinal: *batch_ordinal,
            },
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon {
                    batch_ordinal: *batch_ordinal,
                },
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                },
            whir_challenge_ordinal: Some(_),
        } => {
            let fold_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, *batch_ordinal, fold_ordinal)?;
            (
                SelectedPlanStatePredicateClause::WhirConstrainedFold {
                    epoch_ordinal: *batch_ordinal,
                    fold_ordinal,
                },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::MaskedSumcheckRound {
                        batch_ordinal: *batch_ordinal,
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::RoundCheckpoint { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, 0)?;
            (
                SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { epoch_ordinal },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundCheckpoint {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::RoundCombination { round_ordinal },
            whir_challenge_ordinal: Some(_),
        } => {
            let epoch_ordinal = round_ordinal
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            require_code_state(code_state_rows, epoch_ordinal, 0)?;
            (
                SelectedPlanStatePredicateClause::WhirQueryCombination { epoch_ordinal },
                Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                    role: RowCodeWhirExtensionRole::RoundCombination {
                        round_ordinal: *round_ordinal,
                    },
                }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            whir_challenge_ordinal: Some(_),
        } => (
            SelectedPlanStatePredicateClause::WhirBaseCaseBlinding,
            Some(SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            }),
            true,
        ),
        RowCodeWhirTranscriptOperation::SampleDistinctIndices { role, .. } => {
            let predicate_clause = match *role {
                RowCodeWhirQueryRole::Outer => {
                    SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                }
                RowCodeWhirQueryRole::Bound => {
                    SelectedPlanStatePredicateClause::BoundIdentityAgreement
                }
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal } => {
                    if epoch_ordinal
                        == final_epoch_ordinal
                            .checked_add(1)
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                    {
                        SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement
                    } else {
                        require_terminal_code_state(code_state_rows, epoch_ordinal)?;
                        SelectedPlanStatePredicateClause::WhirQueryAgreement { epoch_ordinal }
                    }
                }
            };
            (
                predicate_clause,
                Some(SelectedPlanFailureEventOwner::DistinctQueryVector { role: *role }),
                true,
            )
        }
        RowCodeWhirTranscriptOperation::FinishProofStream => (
            SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts,
            None,
            false,
        ),
        RowCodeWhirTranscriptOperation::SampleExtension { .. } => {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    };
    Ok(transition)
}

fn require_code_state(
    code_state_rows: &[WhirCodeStateRow],
    epoch_ordinal: u32,
    fold_ordinal: u32,
) -> Result<(), WhirTheoremCertificateError> {
    if code_state_rows
        .iter()
        .any(|row| row.epoch_ordinal == epoch_ordinal && row.fold_ordinal == fold_ordinal)
    {
        Ok(())
    } else {
        Err(WhirTheoremCertificateError::IncompleteTranscriptMapping)
    }
}

fn require_terminal_code_state(
    code_state_rows: &[WhirCodeStateRow],
    epoch_ordinal: u32,
) -> Result<(), WhirTheoremCertificateError> {
    if code_state_rows
        .iter()
        .filter(|row| row.epoch_ordinal == epoch_ordinal)
        .map(|row| row.fold_ordinal)
        .max()
        .is_some()
    {
        Ok(())
    } else {
        Err(WhirTheoremCertificateError::IncompleteTranscriptMapping)
    }
}

fn validate_selected_plan_state_predicate_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    code_state_rows: &[WhirCodeStateRow],
    certificate: &SelectedPlanStatePredicateCertificate,
) -> Result<(), WhirTheoremCertificateError> {
    if !certificate.is_total_for_plan(plan)
        || certificate.transition_rows.len() != state_epoch_rows.len()
        || certificate
            .transition_rows
            .first()
            .map(|row| row.predicate_clause)
            != Some(SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse)
        || certificate
            .transition_rows
            .last()
            .map(|row| row.predicate_clause)
            != Some(SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    for ((transition_row, state_epoch_row), operation) in certificate
        .transition_rows
        .iter()
        .zip(state_epoch_rows)
        .zip(&catalog.operations)
    {
        if transition_row.operation_ordinal != operation.operation_ordinal
            || transition_row.operation_ordinal != state_epoch_row.operation_ordinal
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let expected_transition_owner = match transition_row.predicate_clause {
            SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse => {
                StateTransitionOwner::FixedInitialState
            }
            SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove => {
                StateTransitionOwner::ProverMessageCannotRepairFalseState
            }
            SelectedPlanStatePredicateClause::DeterministicProtocolSchedule
            | SelectedPlanStatePredicateClause::DeterministicOpeningPoint { .. } => {
                StateTransitionOwner::DeterministicObservationPreservesState
            }
            SelectedPlanStatePredicateClause::PolynomialProtocolChallenge
            | SelectedPlanStatePredicateClause::RelationReductionChallenge
            | SelectedPlanStatePredicateClause::OuterRowCodeAgreement
            | SelectedPlanStatePredicateClause::BoundIdentityAgreement
            | SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch
            | SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch { .. }
            | SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { .. }
            | SelectedPlanStatePredicateClause::WhirConstrainedFold { .. }
            | SelectedPlanStatePredicateClause::WhirQueryAgreement { .. }
            | SelectedPlanStatePredicateClause::WhirQueryCombination { .. }
            | SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement
            | SelectedPlanStatePredicateClause::WhirBaseCaseBlinding => {
                StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
            }
            SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts => {
                StateTransitionOwner::TerminalDecision
            }
        };
        if state_epoch_row.transition_owner != expected_transition_owner {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let is_verifier_challenge = expected_transition_owner
            == StateTransitionOwner::VerifierChallengeWithTypedFailureEvent;
        if is_verifier_challenge != transition_row.failure_event_owner.is_some()
            || is_verifier_challenge != transition_row.sampler_exhaustion_is_honest_abort
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        if let Some(owner) = transition_row.failure_event_owner {
            let expected_class = match transition_row.predicate_clause {
                SelectedPlanStatePredicateClause::PolynomialProtocolChallenge => {
                    SelectedPlanFailureEventClass::PolynomialProtocolKnowledge
                }
                SelectedPlanStatePredicateClause::RelationReductionChallenge => {
                    SelectedPlanFailureEventClass::AlgebraicExceptionalSet
                }
                SelectedPlanStatePredicateClause::OuterRowCodeAgreement
                | SelectedPlanStatePredicateClause::BoundIdentityAgreement
                | SelectedPlanStatePredicateClause::WhirQueryAgreement { .. }
                | SelectedPlanStatePredicateClause::AggregateWidePadQueryAgreement => {
                    SelectedPlanFailureEventClass::WithoutReplacementAgreement
                }
                SelectedPlanStatePredicateClause::WhirOpeningConstraintBatch
                | SelectedPlanStatePredicateClause::WhirMaskedSumcheckBatch { .. }
                | SelectedPlanStatePredicateClause::WhirRoundConstraintCheckpoint { .. }
                | SelectedPlanStatePredicateClause::WhirConstrainedFold { .. }
                | SelectedPlanStatePredicateClause::WhirQueryCombination { .. }
                | SelectedPlanStatePredicateClause::WhirBaseCaseBlinding => {
                    SelectedPlanFailureEventClass::WhirRoundByRoundProximity
                }
                SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse
                | SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove
                | SelectedPlanStatePredicateClause::DeterministicProtocolSchedule
                | SelectedPlanStatePredicateClause::DeterministicOpeningPoint { .. }
                | SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts => {
                    return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                }
            };
            if owner.event_class() != expected_class {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
        }
    }

    for (section_index, row) in certificate.proof_section_rows.iter().enumerate() {
        if usize::try_from(row.section_ordinal).ok() != Some(section_index) || row.item_count == 0 {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    for (checkpoint_index, row) in certificate.checkpoint_rows.iter().enumerate() {
        if usize::try_from(row.checkpoint_ordinal).ok() != Some(checkpoint_index)
            || usize::try_from(row.next_transcript_operation_ordinal)
                .ok()
                .is_none_or(|ordinal| ordinal > plan.transcript_operations().len())
            || usize::try_from(row.next_proof_section_ordinal)
                .ok()
                .is_none_or(|ordinal| ordinal > plan.proof_sections().len())
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    }
    if certificate.checkpoint_rows.last().map(|row| row.owner)
        != Some(SelectedPlanCheckpointStateOwner::CompletedCanonicalProof)
        || certificate.lifecycle_rows.iter().any(|row| {
            matches!(
                row.transition,
                SelectedPlanLifecycleTransition::ExplicitAbort
                    | SelectedPlanLifecycleTransition::Cancellation
                    | SelectedPlanLifecycleTransition::SamplerExhaustion
                    | SelectedPlanLifecycleTransition::MaskRankFailure
                    | SelectedPlanLifecycleTransition::StorageRefusal
            ) && (row.emits_proof || row.emits_verified_capability)
        })
        || certificate.lifecycle_rows.iter().any(|row| {
            row.emits_verified_capability
                && (row.transition != SelectedPlanLifecycleTransition::FreshVerifierAcceptance
                    || !row.requires_fresh_verifier)
        })
        || code_state_rows.len()
            != plan
                .whir
                .rounds
                .len()
                .checked_add(1)
                .and_then(|epoch_count| {
                    plan.parameters
                        .folding_factor
                        .checked_add(1)
                        .and_then(|state_count| epoch_count.checked_mul(state_count))
                })
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(())
}

fn cms19_canonical_complete_message_root(
    value_count: usize,
) -> Result<linear_bcs_transcript::LinearBcsProverOracleRoot, WhirTheoremCertificateError> {
    let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let canonical_message_byte_length = value_count
        .checked_mul(value_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if value_count == 0 {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(
        linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
            value_count,
            canonical_message_byte_length,
        },
    )
}

fn cms19_supplied_commitment_root(
    transcript_plan: &linear_bcs_transcript::LinearBcsTranscriptPlan,
    role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
) -> Result<linear_bcs_transcript::LinearBcsProverOracleRoot, WhirTheoremCertificateError> {
    let matching = transcript_plan
        .supplied_commitment_openings()
        .iter()
        .filter(|opening| opening.commitment_role == role)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let payload_leaf_count = matching[0].payload_leaf_count;
    Ok(
        linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment {
            role,
            payload_leaf_count,
        },
    )
}

fn cms19_committed_oracle_role(
    role: RowCodeWhirCommitmentRole,
) -> linear_bcs_transcript::LinearBcsCommittedOracleRole {
    match role {
        RowCodeWhirCommitmentRole::Aggregate => {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate
        }
        RowCodeWhirCommitmentRole::AggregateWidePad => {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad
        }
        RowCodeWhirCommitmentRole::WhirRound { round_ordinal } => {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound { round_ordinal }
        }
        RowCodeWhirCommitmentRole::BaseFreshSource => {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource
        }
        RowCodeWhirCommitmentRole::BaseFreshPad => {
            linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad
        }
    }
}

fn cms19_expected_prover_oracle_root(
    plan: &RowCodeWhirConstructionPlan,
    transcript_plan: &linear_bcs_transcript::LinearBcsTranscriptPlan,
    operation: &RowCodeWhirOracleEquationOperationPlan,
) -> Result<Option<linear_bcs_transcript::LinearBcsProverOracleRoot>, WhirTheoremCertificateError> {
    let root = match &operation.kind {
        RowCodeWhirOracleEquationOperationKind::InitialTranscript
        | RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
        | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => None,
        RowCodeWhirOracleEquationOperationKind::CommonRound(round) => match round {
            CommonProofRound::BaseRoot { tree_ordinal: 0 } => Some(cms19_supplied_commitment_root(
                transcript_plan,
                linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                    phase: RowCodeWhirPhase::Base,
                },
            )?),
            CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 } => {
                Some(cms19_supplied_commitment_root(
                    transcript_plan,
                    linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                        phase: RowCodeWhirPhase::Auxiliary,
                    },
                )?)
            }
            CommonProofRound::RowCodeWhirQuotientPhaseRoot => Some(cms19_supplied_commitment_root(
                transcript_plan,
                linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase {
                    phase: RowCodeWhirPhase::Quotient,
                },
            )?),
            CommonProofRound::OutOfDomainEvaluations => {
                Some(cms19_canonical_complete_message_root(
                    usize::try_from(plan.relation_prefix_schedule.opening_claim_count())
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )?)
            }
            CommonProofRound::BaseRoot { .. } | CommonProofRound::AuxiliaryRoot { .. } => {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
        },
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir { operation, .. } => match operation {
            RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count } => {
                Some(cms19_canonical_complete_message_root(*value_count)?)
            }
            RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
            | RowCodeWhirTranscriptOperation::SampleExtension { .. }
            | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. }
            | RowCodeWhirTranscriptOperation::FinishProofStream => None,
            RowCodeWhirTranscriptOperation::ObserveCommitment { role } => {
                Some(cms19_supplied_commitment_root(
                    transcript_plan,
                    cms19_committed_oracle_role(*role),
                )?)
            }
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                role: RowCodeWhirObservationRole::OpeningPoint { .. },
                ..
            } => None,
            RowCodeWhirTranscriptOperation::ObserveExtensionValues { value_count, .. } => {
                Some(cms19_canonical_complete_message_root(*value_count)?)
            }
        },
    };
    Ok(root)
}

fn cms19_response_digest_binding(
    plan: &RowCodeWhirConstructionPlan,
    operation: &RowCodeWhirOracleEquationOperationPlan,
) -> Result<Cms19ResponseDigestBinding, WhirTheoremCertificateError> {
    let response_root_ranges = operation
        .ranges
        .iter()
        .filter(|range| range.kind == RowCodeWhirOracleEquationRangeKind::ResponseRoot)
        .collect::<Vec<_>>();
    let [response_root_range] = response_root_ranges.as_slice() else {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    };
    if response_root_range.equation_count != 1
        || response_root_range.predecessor != RowCodeWhirOracleEquationPredecessor::Independent
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let extension_value_count = match &operation.kind {
        RowCodeWhirOracleEquationOperationKind::CommonRound(
            CommonProofRound::OutOfDomainEvaluations,
        ) => Some(
            usize::try_from(plan.relation_prefix_schedule.opening_claim_count())
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        ),
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count },
            ..
        }
        | RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: RowCodeWhirTranscriptOperation::ObserveExtensionValues { value_count, .. },
            ..
        } => Some(*value_count),
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values },
            ..
        } => Some(canonical_values.len()),
        RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
            operation: RowCodeWhirTranscriptOperation::FinishProofStream,
            ..
        } => None,
        RowCodeWhirOracleEquationOperationKind::InitialTranscript
        | RowCodeWhirOracleEquationOperationKind::CommonRound(_)
        | RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
        | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_)
        | RowCodeWhirOracleEquationOperationKind::RowCodeWhir { .. } => {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
    };
    let message = if let Some(value_count) = extension_value_count {
        let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let canonical_message_byte_length = value_count
            .checked_mul(value_byte_length)
            .and_then(|length| length.checked_add(6))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        Cms19CanonicalResponseMessage::ExtensionValueList {
            value_count,
            canonical_message_byte_length,
        }
    } else {
        Cms19CanonicalResponseMessage::CanonicalProofStream {
            proof_section_count: plan.proof_sections.len(),
            length_source:
                Cms19CanonicalProofLengthSource::TransportedHeaderValidatedByCanonicalDecoderAndStaticSectionLedger,
        }
    };
    let response_root_equation_slot_ordinal = operation
        .first_equation_slot_ordinal
        .checked_add(response_root_range.first_equation_offset)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let binding = Cms19ResponseDigestBinding {
        message,
        response_root_range_ordinal: response_root_range.range_ordinal,
        response_root_equation_slot_ordinal,
        response_root_domain: TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
        output_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
    };
    if !binding.is_valid() {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(binding)
}

fn cms19_prover_oracle_binding(
    plan: &RowCodeWhirConstructionPlan,
    operation: &RowCodeWhirOracleEquationOperationPlan,
    root: linear_bcs_transcript::LinearBcsProverOracleRoot,
) -> Result<Cms19ProverOracleBinding, WhirTheoremCertificateError> {
    match root {
        linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment {
            role,
            payload_leaf_count,
        } => {
            if operation
                .ranges
                .iter()
                .any(|range| range.kind == RowCodeWhirOracleEquationRangeKind::ResponseRoot)
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            Ok(Cms19ProverOracleBinding::SuppliedCommitment {
                role,
                payload_leaf_count,
            })
        }
        linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
            value_count,
            canonical_message_byte_length,
        } => {
            let response_digest = cms19_response_digest_binding(plan, operation)?;
            if response_digest.message
                != (Cms19CanonicalResponseMessage::ExtensionValueList {
                    value_count,
                    canonical_message_byte_length,
                })
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            Ok(Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { response_digest })
        }
        linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => {
            Err(WhirTheoremCertificateError::IncompleteTranscriptMapping)
        }
    }
}

fn cms19_linear_bcs_source_operation_ordinal(
    range: linear_bcs_transcript::LinearBcsRoundRangePlan,
) -> Result<u32, WhirTheoremCertificateError> {
    match (range.verifier_message_role, range.prover_oracle_root) {
        (
            linear_bcs_transcript::LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
                source_operation_ordinal,
            },
            linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. }
            | linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
                ..
            },
        ) if range.round_count == 1 => Ok(source_operation_ordinal),
        (
            linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                source_operation_ordinal,
                first_block_ordinal,
            },
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                source_operation_ordinal: root_source_operation_ordinal,
                first_block_ordinal: root_first_block_ordinal,
            },
        ) if source_operation_ordinal == root_source_operation_ordinal
            && first_block_ordinal == root_first_block_ordinal =>
        {
            Ok(source_operation_ordinal)
        }
        (
            linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                source_operation_ordinal,
                block_ordinal,
            },
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                source_operation_ordinal: root_source_operation_ordinal,
                first_block_ordinal,
            },
        ) if range.round_count == 1
            && source_operation_ordinal == root_source_operation_ordinal
            && block_ordinal == first_block_ordinal =>
        {
            Ok(source_operation_ordinal)
        }
        _ => Err(WhirTheoremCertificateError::IncompleteTranscriptMapping),
    }
}

fn cms19_fixed_sampler_block_count(
    operation: &RowCodeWhirOracleEquationOperationPlan,
) -> Result<u64, WhirTheoremCertificateError> {
    let counts = operation
        .ranges
        .iter()
        .filter_map(|range| match range.kind {
            RowCodeWhirOracleEquationRangeKind::ExtensionRejectionChain {
                maximum_rejection_count,
            } => Some(u64::from(maximum_rejection_count).checked_add(1)),
            RowCodeWhirOracleEquationRangeKind::ProductExpansion {
                maximum_candidate_count,
                block_count_per_candidate,
            } => Some(u64::from(maximum_candidate_count).checked_mul(block_count_per_candidate)),
            RowCodeWhirOracleEquationRangeKind::DistinctExpansion {
                output_count,
                maximum_block_count_per_output,
            } => Some(u64::from(output_count).checked_mul(maximum_block_count_per_output)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if counts.len() != 1 {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    counts[0]
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        .checked_add(0)
        .filter(|count| *count > 0)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)
}

fn cms19_checked_sampler_rounds(
    operation_ordinal: u32,
    block_count: u64,
    ranges: &[linear_bcs_transcript::LinearBcsRoundRangePlan],
) -> Result<(u64, u64), WhirTheoremCertificateError> {
    let expected_range_count = usize::from(block_count > 1) + 1;
    if ranges.len() != expected_range_count {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let mut range_index = 0_usize;
    let first_round_ordinal = ranges[0].first_round_ordinal;
    if block_count > 1 {
        let prefix = ranges[0];
        if prefix.round_count != block_count - 1
            || prefix.verifier_message_role
                != (linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                    source_operation_ordinal: operation_ordinal,
                    first_block_ordinal: 0,
                })
            || prefix.prover_oracle_root
                != (linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                    source_operation_ordinal: operation_ordinal,
                    first_block_ordinal: 0,
                })
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        range_index = 1;
    }
    let terminal = ranges[range_index];
    let terminal_block_ordinal = block_count - 1;
    let expected_terminal_round_ordinal = first_round_ordinal
        .checked_add(terminal_block_ordinal)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if terminal.first_round_ordinal != expected_terminal_round_ordinal
        || terminal.round_count != 1
        || terminal.verifier_message_role
            != (linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                source_operation_ordinal: operation_ordinal,
                block_ordinal: terminal_block_ordinal,
            })
        || terminal.prover_oracle_root
            != (linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                source_operation_ordinal: operation_ordinal,
                first_block_ordinal: terminal_block_ordinal,
            })
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok((first_round_ordinal, expected_terminal_round_ordinal))
}

fn derive_cms19_whole_state_transition_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
) -> Result<Cms19WholeStateTransitionCertificate, WhirTheoremCertificateError> {
    if !selected_plan_state_predicate.is_total_for_plan(plan)
        || selected_plan_state_predicate.transition_rows.len() != catalog.operations.len()
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let mut ranges_by_source =
        BTreeMap::<u32, Vec<linear_bcs_transcript::LinearBcsRoundRangePlan>>::new();
    let mut next_round_ordinal = 1_u64;
    for range in transcript_plan.round_ranges().iter().copied() {
        if range.first_round_ordinal != next_round_ordinal || range.round_count == 0 {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let source_operation_ordinal = cms19_linear_bcs_source_operation_ordinal(range)?;
        ranges_by_source
            .entry(source_operation_ordinal)
            .or_default()
            .push(range);
        next_round_ordinal = next_round_ordinal
            .checked_add(range.round_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }

    let mut rows = Vec::with_capacity(catalog.operations.len());
    let mut covered_transcript_equation_count = 0_u64;
    let mut covered_bcs_round_count = 0_u64;
    let mut prover_oracle_round_count = 0_u64;
    let mut verifier_message_fill_count = 0_u64;
    let mut deterministic_observation_count = 0_u64;
    for (operation, state_row) in catalog
        .operations
        .iter()
        .zip(&selected_plan_state_predicate.transition_rows)
    {
        if operation.operation_ordinal != state_row.operation_ordinal {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let operation_ranges = ranges_by_source
            .remove(&operation.operation_ordinal)
            .unwrap_or_default();
        let expected_prover_root =
            cms19_expected_prover_oracle_root(plan, &transcript_plan, operation)?;
        let transition = if operation.operation_ordinal == 0 {
            if operation.predecessor_operation_ordinal.is_some()
                || !operation_ranges.is_empty()
                || state_row.predicate_clause
                    != SelectedPlanStatePredicateClause::EmptyCanonicalPrefixIsFalse
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            Cms19SemanticStateTransition::InitialCanonicalPrefix
        } else if let Some(expected_root) = expected_prover_root {
            if operation_ranges.len() != 1
                || operation_ranges[0].round_count != 1
                || operation_ranges[0].prover_oracle_root != expected_root
                || !matches!(
                    operation_ranges[0].verifier_message_role,
                    linear_bcs_transcript::LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
                        source_operation_ordinal,
                    } if source_operation_ordinal == operation.operation_ordinal
                )
                || state_row.predicate_clause
                    != SelectedPlanStatePredicateClause::BackwardClosureOverCanonicalProverMove
                || state_row.failure_event_owner.is_some()
            {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            prover_oracle_round_count = prover_oracle_round_count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            covered_bcs_round_count = covered_bcs_round_count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            Cms19SemanticStateTransition::ProverOracle {
                round_ordinal: operation_ranges[0].first_round_ordinal,
                root: expected_root,
                binding: cms19_prover_oracle_binding(plan, operation, expected_root)?,
            }
        } else if let Some(failure_event_owner) = state_row.failure_event_owner {
            let block_count = cms19_fixed_sampler_block_count(operation)?;
            let (first_round_ordinal, terminal_round_ordinal) = cms19_checked_sampler_rounds(
                operation.operation_ordinal,
                block_count,
                &operation_ranges,
            )?;
            verifier_message_fill_count = verifier_message_fill_count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            covered_bcs_round_count = covered_bcs_round_count
                .checked_add(block_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            Cms19SemanticStateTransition::VerifierMessageFill {
                first_round_ordinal,
                block_count,
                terminal_round_ordinal,
                failure_event_owner,
            }
        } else {
            if !operation_ranges.is_empty() {
                return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
            }
            match &operation.kind {
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                    operation:
                        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values },
                    ..
                } if !canonical_values.is_empty()
                    && state_row.predicate_clause
                        == SelectedPlanStatePredicateClause::DeterministicProtocolSchedule =>
                {
                    deterministic_observation_count = deterministic_observation_count
                        .checked_add(1)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                    Cms19SemanticStateTransition::DeterministicObservation {
                        owner: Cms19DeterministicObservationOwner::ProtocolSchedule,
                        response_digest: cms19_response_digest_binding(plan, operation)?,
                    }
                }
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                    operation:
                        RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                            role: RowCodeWhirObservationRole::OpeningPoint { batch_ordinal },
                            value_count,
                            ..
                        },
                    ..
                } if *value_count == plan.parameters.table_variable_count
                    && state_row.predicate_clause
                        == (SelectedPlanStatePredicateClause::DeterministicOpeningPoint {
                            batch_ordinal: *batch_ordinal,
                        }) =>
                {
                    deterministic_observation_count = deterministic_observation_count
                        .checked_add(1)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                    Cms19SemanticStateTransition::DeterministicObservation {
                        owner: Cms19DeterministicObservationOwner::OpeningPoint {
                            batch_ordinal: *batch_ordinal,
                        },
                        response_digest: cms19_response_digest_binding(plan, operation)?,
                    }
                }
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                    operation: RowCodeWhirTranscriptOperation::FinishProofStream,
                    ..
                } if operation.operation_ordinal
                    == u32::try_from(catalog.operations.len() - 1)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    && state_row.predicate_clause
                        == SelectedPlanStatePredicateClause::FullCanonicalTranscriptAccepts =>
                {
                    Cms19SemanticStateTransition::TerminalDecision {
                        final_query_round_ordinal: transcript_plan
                            .final_query()
                            .verifier_message_ordinal,
                        response_digest: cms19_response_digest_binding(plan, operation)?,
                    }
                }
                _ => return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping),
            }
        };
        let equation_count = operation
            .maximum_equation_count()
            .map_err(|_| WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
        covered_transcript_equation_count = covered_transcript_equation_count
            .checked_add(equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        rows.push(Cms19SemanticStateTransitionRow {
            operation_ordinal: operation.operation_ordinal,
            predecessor_operation_ordinal: operation.predecessor_operation_ordinal,
            predicate_clause: state_row.predicate_clause,
            first_equation_slot_ordinal: operation.first_equation_slot_ordinal,
            equation_count,
            transition,
        });
    }
    let expected_bcs_round_count = transcript_plan
        .round_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_verifier_message_fill_count = catalog
        .logical_verifier_message_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_transcript_equation_count = catalog
        .maximum_equation_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let response_digest_count = u64::try_from(
        rows.iter()
            .filter(|row| {
                matches!(
                    row.transition,
                    Cms19SemanticStateTransition::ProverOracle {
                        binding: Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { .. },
                        ..
                    } | Cms19SemanticStateTransition::DeterministicObservation { .. }
                        | Cms19SemanticStateTransition::TerminalDecision { .. }
                )
            })
            .count(),
    )
    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_response_digest_count =
        catalog
            .operations
            .iter()
            .try_fold(0_u64, |operation_total, operation| {
                let operation_response_root_count =
                    operation
                        .ranges
                        .iter()
                        .try_fold(0_u64, |range_total, range| {
                            if range.kind == RowCodeWhirOracleEquationRangeKind::ResponseRoot {
                                range_total
                                    .checked_add(range.equation_count)
                                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
                            } else {
                                Ok(range_total)
                            }
                        })?;
                operation_total
                    .checked_add(operation_response_root_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;
    let final_query_round_ordinal = transcript_plan.final_query().verifier_message_ordinal;
    if !ranges_by_source.is_empty()
        || rows.len() != catalog.operations.len()
        || covered_bcs_round_count != expected_bcs_round_count
        || verifier_message_fill_count != expected_verifier_message_fill_count
        || covered_transcript_equation_count != expected_transcript_equation_count
        || response_digest_count != expected_response_digest_count
        || final_query_round_ordinal != covered_bcs_round_count + 1
        || rows.last().is_none_or(|row| {
            !matches!(
                row.transition,
                Cms19SemanticStateTransition::TerminalDecision { .. }
            )
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(Cms19WholeStateTransitionCertificate {
        construction_plan_identity_hash: plan
            .canonical_identity_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
        linear_bcs_transcript_plan_hash: transcript_plan
            .canonical_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
        rows,
        covered_transcript_equation_count,
        covered_bcs_round_count,
        prover_oracle_round_count,
        verifier_message_fill_count,
        deterministic_observation_count,
        response_digest_count,
        final_query_round_ordinal,
    })
}

fn checked_tree_height(leaf_count: usize) -> Result<usize, WhirTheoremCertificateError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    usize::try_from(leaf_count.ilog2()).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

fn maximum_compact_parent_hash_query_count(
    leaf_count: usize,
    query_count: usize,
) -> Result<u64, WhirTheoremCertificateError> {
    if query_count == 0 || query_count > leaf_count {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let tree_height = checked_tree_height(leaf_count)?;
    (0..tree_height).try_fold(0_u64, |total, depth| {
        let node_count = 1_usize
            .checked_shl(
                u32::try_from(depth)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        total
            .checked_add(
                u64::try_from(query_count.min(node_count))
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })
}

fn derive_merkle_oracle_equation_rows(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<MerkleOracleEquationCoverageRow>, WhirTheoremCertificateError> {
    let supplied_commitment_openings = checked_supplied_commitment_opening_rows(plan)?;
    let mut rows = Vec::new();
    for opening in &supplied_commitment_openings.relation_phases {
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::RelationPhase {
                phase: opening.phase,
            },
            leaf_count: opening.leaf_count,
            query_count: opening.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }

    for tree in &plan.bound_trees {
        let leaf_hash_query_count = u64::try_from(tree.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(tree.leaf_count, tree.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::BoundTree {
                bound_tree_ordinal: tree.bound_tree_ordinal,
            },
            leaf_count: tree.leaf_count,
            query_count: tree.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }

    for opening in &supplied_commitment_openings.whir_epochs {
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::WhirEpoch {
                epoch_ordinal: opening.epoch_ordinal,
            },
            leaf_count: opening.leaf_count,
            query_count: opening.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }
    for opening in &supplied_commitment_openings.aggregate_wide_mask_openings {
        let leaf_hash_query_count = u64::try_from(opening.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let parent_hash_query_count =
            maximum_compact_parent_hash_query_count(opening.leaf_count, opening.query_count)?;
        rows.push(MerkleOracleEquationCoverageRow {
            role: MerkleOracleEquationRole::AggregateWideMask {
                commitment_role: opening.commitment_role,
            },
            leaf_count: opening.leaf_count,
            query_count: opening.query_count,
            leaf_hash_query_count,
            parent_hash_query_count,
            accepting_database_equation_count_ceiling: leaf_hash_query_count
                .checked_add(parent_hash_query_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            predecessor_support_ceiling: 2,
        });
    }
    Ok(rows)
}

fn derive_fixed_verifier_hash_rows(
    plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<Vec<FixedVerifierHashCoverageRow>, WhirTheoremCertificateError> {
    if relation_variant
        .canonical_hash()
        .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?
        != plan.relation_plan_variant_hash
        || relation_variant.schedule_position() != plan.schedule_position
        || relation_variant.top_count() != plan.top_count
        || relation_variant.trace_domain_size() != plan.trace_domain_size
        || relation_variant.proof_privacy_mode() != plan.proof_privacy_mode
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }

    let verifier_source_ordinals = relation_variant
        .ordered_columns()
        .iter()
        .filter_map(|column| match column.origin() {
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                ..
            } => Some(*verifier_source_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let distinct_verifier_source_ordinals = verifier_source_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let public_setup_hash_query_count = u64::try_from(verifier_source_ordinals.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let public_setup_distinct_equation_count =
        u64::try_from(distinct_verifier_source_ordinals.len())
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;

    let mut rows = vec![
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::RelationPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::RelationPlanVariantIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::ConstructionPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
        FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::ApplicationStatement,
            hash_query_count: 1,
            distinct_equation_count: 1,
            transcript_catalog_equation_overlap_count: 0,
        },
    ];
    if public_setup_hash_query_count > 0 {
        rows.push(FixedVerifierHashCoverageRow {
            role: FixedVerifierHashRole::PublicSetupVerifierSequence,
            hash_query_count: public_setup_hash_query_count,
            distinct_equation_count: public_setup_distinct_equation_count,
            transcript_catalog_equation_overlap_count: 0,
        });
    }
    Ok(rows)
}

fn derive_complete_verifier_oracle_ledger(
    plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    transcript_equation_count: u64,
    transcript_hash_query_count: u64,
) -> Result<CompleteVerifierOracleLedger, WhirTheoremCertificateError> {
    let merkle_rows = derive_merkle_oracle_equation_rows(plan)?;
    let fixed_hash_rows = derive_fixed_verifier_hash_rows(plan, relation_variant)?;
    let provisional = CompleteVerifierOracleLedger {
        transcript_equation_count,
        transcript_hash_query_count,
        merkle_rows,
        fixed_hash_rows,
        complete_equation_count_ceiling: 0,
        complete_hash_query_count: 0,
    };
    let merkle_equation_count_ceiling =
        provisional
            .merkle_rows
            .iter()
            .try_fold(0_u64, |total, row| {
                total
                    .checked_add(row.accepting_database_equation_count_ceiling)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;
    let fixed_new_equation_count = provisional.fixed_new_equation_count()?;
    let fixed_hash_query_count = provisional.fixed_hash_query_count()?;
    let complete_equation_count_ceiling = transcript_equation_count
        .checked_add(merkle_equation_count_ceiling)
        .and_then(|count| count.checked_add(fixed_new_equation_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let complete_hash_query_count = transcript_hash_query_count
        .checked_add(provisional.merkle_hash_query_count()?)
        .and_then(|count| count.checked_add(fixed_hash_query_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    Ok(CompleteVerifierOracleLedger {
        complete_equation_count_ceiling,
        complete_hash_query_count,
        ..provisional
    })
}

fn aggregate_leaf_interleaving_width(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
    row: MerkleOracleEquationCoverageRow,
) -> Result<Option<usize>, WhirTheoremCertificateError> {
    let expected_geometry = match row.role {
        MerkleOracleEquationRole::WhirEpoch { epoch_ordinal } => {
            let epoch_index = usize::try_from(epoch_ordinal)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
            let encoded_oracle = if epoch_index < plan.whir.rounds.len() {
                plan.whir.rounds[epoch_index].encoded_oracle
            } else if epoch_index == plan.whir.rounds.len() {
                plan.whir.final_round.encoded_oracle
            } else {
                return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
            };
            (
                encoded_oracle.leaf_count,
                row.query_count,
                encoded_oracle.leaf_width,
            )
        }
        MerkleOracleEquationRole::AggregateWideMask { commitment_role } => {
            let (_, _, domain_size, query_count, interleaving_width) = match commitment_role {
                linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad => {
                    aggregate_wide_masking.pad_code_geometry()
                }
                linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource => {
                    aggregate_wide_masking.fresh_source_code_geometry()
                }
                linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad => {
                    aggregate_wide_masking.fresh_pad_code_geometry()
                }
                _ => return Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
            };
            (domain_size, query_count, interleaving_width)
        }
        MerkleOracleEquationRole::RelationPhase { .. }
        | MerkleOracleEquationRole::BoundTree { .. } => return Ok(None),
    };
    if expected_geometry.0 != row.leaf_count
        || expected_geometry.1 != row.query_count
        || expected_geometry.2 == 0
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    Ok(Some(expected_geometry.2))
}

fn aggregate_leaf_frame_descriptors()
-> Result<[ColumnStreamableLeafOracleFrameDescriptor; 3], WhirTheoremCertificateError> {
    let hasher = aggregate_leaf_hasher();
    let descriptors = [
        hasher.frame_descriptor(ColumnStreamableLeafOracleFrame::Initial),
        hasher.frame_descriptor(ColumnStreamableLeafOracleFrame::Column),
        hasher.frame_descriptor(ColumnStreamableLeafOracleFrame::Final),
    ];
    let framed_prefix_byte_length = ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN
        .len()
        .checked_add(size_of::<u64>())
        .and_then(|length| length.checked_add(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len()))
        .and_then(|length| length.checked_add(size_of::<u8>()))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let expected_input_byte_lengths = [
        framed_prefix_byte_length
            .checked_add(size_of::<u64>())
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        framed_prefix_byte_length
            .checked_add(size_of::<u64>())
            .and_then(|length| length.checked_add(MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>()))
            .and_then(|length| {
                length.checked_add(PROOF_CHALLENGE_EXTENSION_DEGREE * size_of::<u64>())
            })
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        framed_prefix_byte_length
            .checked_add(size_of::<u64>())
            .and_then(|length| length.checked_add(MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>()))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    ];
    let expected_predecessor_counts = [0, 1, 1];
    let expected_extension_value_counts = [0, 1, 0];
    let frame_tags = descriptors
        .iter()
        .map(|descriptor| descriptor.frame_tag)
        .collect::<BTreeSet<_>>();
    if descriptors
        .iter()
        .zip(expected_input_byte_lengths)
        .zip(expected_predecessor_counts)
        .zip(expected_extension_value_counts)
        .any(
            |(((descriptor, input_byte_length), predecessor_count), extension_value_count)| {
                descriptor.canonical_input_byte_length != input_byte_length
                    || descriptor.predecessor_digest_count != predecessor_count
                    || descriptor.extension_value_count != extension_value_count
                    || descriptor.output_bit_length != CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            },
        )
        || frame_tags.len() != descriptors.len()
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(descriptors)
}

fn aggregate_leaf_frame_descriptor(
    descriptors: &[ColumnStreamableLeafOracleFrameDescriptor; 3],
    frame: ColumnStreamableLeafOracleFrame,
) -> Result<ColumnStreamableLeafOracleFrameDescriptor, WhirTheoremCertificateError> {
    descriptors
        .iter()
        .copied()
        .find(|descriptor| descriptor.frame == frame)
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)
}

fn aggregate_leaf_semantic_transition_rows(
    inventory: &[AggregateLeafOracleCallInventoryRow],
    descriptors: &[ColumnStreamableLeafOracleFrameDescriptor; 3],
) -> Result<Vec<AggregateLeafSemanticTransitionRow>, WhirTheoremCertificateError> {
    if inventory.is_empty()
        || inventory
            .iter()
            .any(|row| row.interleaving_width == 0 || row.opened_leaf_count == 0)
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    let initial_frame =
        aggregate_leaf_frame_descriptor(descriptors, ColumnStreamableLeafOracleFrame::Initial)?;
    let column_frame =
        aggregate_leaf_frame_descriptor(descriptors, ColumnStreamableLeafOracleFrame::Column)?;
    let final_frame =
        aggregate_leaf_frame_descriptor(descriptors, ColumnStreamableLeafOracleFrame::Final)?;
    let interleaving_widths = inventory
        .iter()
        .map(|row| row.interleaving_width)
        .collect::<BTreeSet<_>>();
    let capacity = interleaving_widths
        .len()
        .checked_add(inventory.iter().try_fold(0_usize, |count, row| {
            count
                .checked_add(row.interleaving_width)
                .and_then(|value| value.checked_add(1))
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(capacity)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    for interleaving_width in interleaving_widths {
        let hash_query_count = inventory
            .iter()
            .filter(|row| row.interleaving_width == interleaving_width)
            .try_fold(0_u64, |count, row| {
                count
                    .checked_add(row.initial_hash_query_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;
        rows.push(AggregateLeafSemanticTransitionRow {
            transition: AggregateLeafSemanticTransition::SharedInitial { interleaving_width },
            predecessor: AggregateLeafSemanticPredecessor::None,
            frame: initial_frame,
            hash_query_count,
            accepting_database_equation_count_ceiling: 1,
        });
    }
    for inventory_row in inventory {
        for column_index in 0..inventory_row.interleaving_width {
            let predecessor = if column_index == 0 {
                AggregateLeafSemanticPredecessor::SharedInitial {
                    interleaving_width: inventory_row.interleaving_width,
                }
            } else {
                AggregateLeafSemanticPredecessor::Column {
                    role: inventory_row.role,
                    column_index: column_index - 1,
                }
            };
            rows.push(AggregateLeafSemanticTransitionRow {
                transition: AggregateLeafSemanticTransition::Column {
                    role: inventory_row.role,
                    column_index,
                },
                predecessor,
                frame: column_frame,
                hash_query_count: inventory_row.opened_leaf_count,
                accepting_database_equation_count_ceiling: inventory_row.opened_leaf_count,
            });
        }
        rows.push(AggregateLeafSemanticTransitionRow {
            transition: AggregateLeafSemanticTransition::Final {
                role: inventory_row.role,
            },
            predecessor: AggregateLeafSemanticPredecessor::Column {
                role: inventory_row.role,
                column_index: inventory_row.interleaving_width - 1,
            },
            frame: final_frame,
            hash_query_count: inventory_row.opened_leaf_count,
            accepting_database_equation_count_ceiling: inventory_row.opened_leaf_count,
        });
    }
    if rows.len() != capacity {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(rows)
}

fn derive_aggregate_leaf_semantic_transition_certificate(
    inventory: &[AggregateLeafOracleCallInventoryRow],
) -> Result<AggregateLeafSemanticTransitionCertificate, WhirTheoremCertificateError> {
    let frame_descriptors = aggregate_leaf_frame_descriptors()?;
    let rows = aggregate_leaf_semantic_transition_rows(inventory, &frame_descriptors)?;
    let hash_query_count = rows.iter().try_fold(0_u64, |count, row| {
        count
            .checked_add(row.hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let accepting_database_equation_count_ceiling = rows.iter().try_fold(0_u64, |count, row| {
        count
            .checked_add(row.accepting_database_equation_count_ceiling)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let maximum_predecessor_support_count = rows
        .iter()
        .map(|row| {
            u8::from(!matches!(
                row.predecessor,
                AggregateLeafSemanticPredecessor::None
            ))
        })
        .max()
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
    let certificate = AggregateLeafSemanticTransitionCertificate {
        frame_descriptors,
        rows,
        hash_query_count,
        accepting_database_equation_count_ceiling,
        maximum_predecessor_support_count,
    };
    if !certificate.is_complete_for_inventory(inventory) {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(certificate)
}

fn derive_deployed_aggregate_leaf_oracle_certificate(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
    abstract_ledger: &CompleteVerifierOracleLedger,
) -> Result<DeployedAggregateLeafOracleCertificate, WhirTheoremCertificateError> {
    derive_deployed_aggregate_leaf_oracle_certificate_with_output_widths(
        plan,
        aggregate_wide_masking,
        abstract_ledger,
        ColumnStreamableLeafHasher::intermediate_output_bit_length(),
        ColumnStreamableLeafHasher::final_output_bit_length(),
    )
}

fn derive_deployed_aggregate_leaf_oracle_certificate_with_output_widths(
    plan: &RowCodeWhirConstructionPlan,
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
    abstract_ledger: &CompleteVerifierOracleLedger,
    intermediate_oracle_output_bit_length: usize,
    final_oracle_output_bit_length: usize,
) -> Result<DeployedAggregateLeafOracleCertificate, WhirTheoremCertificateError> {
    if intermediate_oracle_output_bit_length == 0 || final_oracle_output_bit_length == 0 {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let mut rows = Vec::new();
    let mut initial_input_widths = BTreeSet::new();
    let mut abstract_leaf_hash_query_count = 0_u64;
    let mut deployed_leaf_hash_query_count = 0_u64;
    let mut deployed_noninitial_equation_count = 0_u64;
    let mut initial_hash_query_count = 0_u64;
    for row in abstract_ledger.merkle_rows.iter().copied() {
        let Some(interleaving_width) =
            aggregate_leaf_interleaving_width(plan, aggregate_wide_masking, row)?
        else {
            continue;
        };
        let opened_leaf_count = u64::try_from(row.query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
        let transition_hash_query_count = opened_leaf_count
            .checked_mul(
                u64::try_from(interleaving_width)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let inventory_row = AggregateLeafOracleCallInventoryRow {
            role: row.role,
            interleaving_width,
            opened_leaf_count,
            initial_hash_query_count: opened_leaf_count,
            transition_hash_query_count,
            final_hash_query_count: opened_leaf_count,
            parent_hash_query_count: row.parent_hash_query_count,
        };
        initial_input_widths.insert(interleaving_width);
        abstract_leaf_hash_query_count = abstract_leaf_hash_query_count
            .checked_add(row.leaf_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let leaf_hash_query_count = inventory_row
            .initial_hash_query_count
            .checked_add(inventory_row.transition_hash_query_count)
            .and_then(|count| count.checked_add(inventory_row.final_hash_query_count))
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        deployed_leaf_hash_query_count = deployed_leaf_hash_query_count
            .checked_add(leaf_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        let noninitial_equation_count = inventory_row
            .transition_hash_query_count
            .checked_add(inventory_row.final_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        deployed_noninitial_equation_count = deployed_noninitial_equation_count
            .checked_add(noninitial_equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        initial_hash_query_count = initial_hash_query_count
            .checked_add(inventory_row.initial_hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
        rows.push(inventory_row);
    }
    let distinct_initial_equation_count = u64::try_from(initial_input_widths.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let repeated_initial_hash_query_count = initial_hash_query_count
        .checked_sub(distinct_initial_equation_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let deployed_verifier_hash_query_count = abstract_ledger
        .complete_hash_query_count
        .checked_sub(abstract_leaf_hash_query_count)
        .and_then(|count| count.checked_add(deployed_leaf_hash_query_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let deployed_accepting_database_equation_count = abstract_ledger
        .complete_equation_count_ceiling
        .checked_sub(abstract_leaf_hash_query_count)
        .and_then(|count| count.checked_add(distinct_initial_equation_count))
        .and_then(|count| count.checked_add(deployed_noninitial_equation_count))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let compiler_query_bound = ((BigUint::one() << CMS19_ADVERSARIAL_QUERY_EXPONENT)
        - BigUint::one())
        + BigUint::from(deployed_verifier_hash_query_count);
    let classical_collision_penalty_numerator =
        &compiler_query_bound * (&compiler_query_bound - BigUint::one()) / BigUint::from(2_u8);
    let qrom_ideal_oracle_penalty_numerator = BigUint::from(48_u8)
        * &compiler_query_bound
        * &compiler_query_bound
        * &compiler_query_bound
        + BigUint::from(2_u8) * BigUint::from(deployed_accepting_database_equation_count);
    let minimum_oracle_output_bit_length =
        intermediate_oracle_output_bit_length.min(final_oracle_output_bit_length);
    let semantic_state_transitions = if intermediate_oracle_output_bit_length
        == ColumnStreamableLeafHasher::intermediate_output_bit_length()
        && final_oracle_output_bit_length == ColumnStreamableLeafHasher::final_output_bit_length()
    {
        Some(derive_aggregate_leaf_semantic_transition_certificate(
            &rows,
        )?)
    } else {
        None
    };
    let semantic_leaf_equation_count = distinct_initial_equation_count
        .checked_add(deployed_noninitial_equation_count)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if semantic_state_transitions
        .as_ref()
        .is_some_and(|certificate| {
            certificate.hash_query_count != deployed_leaf_hash_query_count
                || certificate.accepting_database_equation_count_ceiling
                    != semantic_leaf_equation_count
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(DeployedAggregateLeafOracleCertificate {
        rows,
        distinct_initial_equation_count,
        repeated_initial_hash_query_count,
        deployed_verifier_hash_query_count,
        deployed_accepting_database_equation_count,
        intermediate_oracle_output_bit_length,
        final_oracle_output_bit_length,
        minimum_oracle_output_bit_length,
        classical_collision_penalty_numerator,
        qrom_ideal_oracle_penalty_numerator,
        collision_penalty_denominator_bit_length: minimum_oracle_output_bit_length,
        transition_collision_propagates_to_final_leaf: true,
        uniform_required_output_geometry_established: intermediate_oracle_output_bit_length
            == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
            && final_oracle_output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
        semantic_state_transitions,
    })
}

fn derive_cms19_whole_database_support_certificate(
    plan: &RowCodeWhirConstructionPlan,
    abstract_ledger: &CompleteVerifierOracleLedger,
    deployed_leaf_oracle: &DeployedAggregateLeafOracleCertificate,
    whole_state_transitions: &Cms19WholeStateTransitionCertificate,
    oracle_equation_rows: &[OracleEquationCoverageRow],
) -> Result<Cms19WholeDatabaseSupportCertificate, WhirTheoremCertificateError> {
    let construction_plan_identity_hash = plan
        .canonical_identity_hash()
        .map_err(|_| WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
    if whole_state_transitions.construction_plan_identity_hash != construction_plan_identity_hash
        || whole_state_transitions.covered_transcript_equation_count
            != abstract_ledger.transcript_equation_count
        || abstract_ledger.transcript_equation_count != abstract_ledger.transcript_hash_query_count
        || !deployed_leaf_oracle.semantic_state_transition_correspondence_established()
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    let mut transcript_equation_counts = BTreeMap::<OracleEquationRole, u64>::new();
    for equation_row in oracle_equation_rows {
        match equation_row.role_pattern {
            OracleEquationRolePattern::Single(role) => {
                let role_count = transcript_equation_counts.entry(role).or_default();
                *role_count = role_count
                    .checked_add(equation_row.equation_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            }
            OracleEquationRolePattern::Alternating { first, second } => {
                if equation_row.equation_count % 2 != 0 {
                    return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
                }
                let count_per_role = equation_row.equation_count / 2;
                for role in [first, second] {
                    let role_count = transcript_equation_counts.entry(role).or_default();
                    *role_count = role_count
                        .checked_add(count_per_role)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                }
            }
        }
    }
    let mapped_transcript_equation_count =
        transcript_equation_counts
            .values()
            .try_fold(0_u64, |total, count| {
                total
                    .checked_add(*count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
            })?;
    let whole_state_response_digest_count = whole_state_transitions.response_digest_count;
    let response_root_hash_query_count = transcript_equation_counts
        .get(&OracleEquationRole::ResponseRoot)
        .copied()
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
    if mapped_transcript_equation_count != abstract_ledger.transcript_equation_count
        || response_root_hash_query_count != whole_state_response_digest_count
        || whole_state_response_digest_count == 0
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    let mut rows = transcript_equation_counts
        .into_iter()
        .map(|(role, equation_count)| Cms19DatabaseSupportRow {
            role: Cms19DatabaseSupportRole::TypedTranscript { role },
            hash_query_count: equation_count,
            accepting_database_equation_count: equation_count,
            predecessor_support_count: role.predecessor_support_count(),
        })
        .collect::<Vec<_>>();

    let mut matched_deployed_leaf_rows = vec![false; deployed_leaf_oracle.rows.len()];
    let mut initial_hash_queries_by_width = BTreeMap::<usize, u64>::new();
    for merkle_row in &abstract_ledger.merkle_rows {
        let matching_deployed_rows = deployed_leaf_oracle
            .rows
            .iter()
            .enumerate()
            .filter(|(_, deployed_row)| deployed_row.role == merkle_row.role)
            .collect::<Vec<_>>();
        match matching_deployed_rows.as_slice() {
            [] => {
                rows.push(Cms19DatabaseSupportRow {
                    role: Cms19DatabaseSupportRole::OrdinaryMerkleLeaf {
                        role: merkle_row.role,
                    },
                    hash_query_count: merkle_row.leaf_hash_query_count,
                    accepting_database_equation_count: merkle_row.leaf_hash_query_count,
                    predecessor_support_count: 0,
                });
            }
            [(deployed_row_index, deployed_row)] => {
                matched_deployed_leaf_rows[*deployed_row_index] = true;
                if deployed_row.opened_leaf_count
                    != u64::try_from(merkle_row.query_count)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                    || deployed_row.parent_hash_query_count != merkle_row.parent_hash_query_count
                {
                    return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
                }
                let initial_hash_queries = initial_hash_queries_by_width
                    .entry(deployed_row.interleaving_width)
                    .or_default();
                *initial_hash_queries = initial_hash_queries
                    .checked_add(deployed_row.initial_hash_query_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                let transition_and_final_hash_query_count = deployed_row
                    .transition_hash_query_count
                    .checked_add(deployed_row.final_hash_query_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                rows.push(Cms19DatabaseSupportRow {
                    role: Cms19DatabaseSupportRole::AggregateLeafTransitionAndFinal {
                        role: merkle_row.role,
                    },
                    hash_query_count: transition_and_final_hash_query_count,
                    accepting_database_equation_count: transition_and_final_hash_query_count,
                    predecessor_support_count: 1,
                });
            }
            _ => return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
        }
        rows.push(Cms19DatabaseSupportRow {
            role: Cms19DatabaseSupportRole::MerkleParents {
                role: merkle_row.role,
            },
            hash_query_count: merkle_row.parent_hash_query_count,
            accepting_database_equation_count: merkle_row.parent_hash_query_count,
            predecessor_support_count: 2,
        });
    }
    if matched_deployed_leaf_rows.iter().any(|matched| !matched) {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    for (interleaving_width, hash_query_count) in initial_hash_queries_by_width {
        rows.push(Cms19DatabaseSupportRow {
            role: Cms19DatabaseSupportRole::AggregateLeafInitial { interleaving_width },
            hash_query_count,
            accepting_database_equation_count: 1,
            predecessor_support_count: 0,
        });
    }
    if rows
        .iter()
        .filter(|row| {
            matches!(
                row.role,
                Cms19DatabaseSupportRole::AggregateLeafInitial { .. }
            )
        })
        .count()
        != usize::try_from(deployed_leaf_oracle.distinct_initial_equation_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    for fixed_hash_row in &abstract_ledger.fixed_hash_rows {
        rows.push(Cms19DatabaseSupportRow {
            role: Cms19DatabaseSupportRole::FixedVerifierHash {
                role: fixed_hash_row.role,
            },
            hash_query_count: fixed_hash_row.hash_query_count,
            accepting_database_equation_count: fixed_hash_row.new_equation_count()?,
            predecessor_support_count: 0,
        });
    }
    let mapped_hash_query_count = rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.hash_query_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let mapped_accepting_database_equation_count = rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.accepting_database_equation_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let maximum_predecessor_support_count = rows
        .iter()
        .map(|row| row.predecessor_support_count)
        .max()
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;
    let certificate = Cms19WholeDatabaseSupportCertificate {
        construction_plan_identity_hash,
        rows,
        mapped_hash_query_count,
        mapped_accepting_database_equation_count,
        claimed_hash_query_count: deployed_leaf_oracle.deployed_verifier_hash_query_count,
        claimed_accepting_database_equation_count: deployed_leaf_oracle
            .deployed_accepting_database_equation_count,
        whole_state_response_digest_count,
        response_root_hash_query_count,
        maximum_predecessor_support_count,
    };
    if !certificate.is_complete()
        || certificate.uncovered_hash_query_count() != Some(0)
        || certificate.uncovered_accepting_database_equation_count() != Some(0)
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(certificate)
}

fn supplied_commitment_protocol_tree_role(
    role: linear_bcs_transcript::LinearBcsCommittedOracleRole,
) -> Result<MerkleOracleEquationRole, WhirTheoremCertificateError> {
    match role {
        linear_bcs_transcript::LinearBcsCommittedOracleRole::RelationPhase { phase } => {
            Ok(MerkleOracleEquationRole::RelationPhase { phase })
        }
        linear_bcs_transcript::LinearBcsCommittedOracleRole::Aggregate => {
            Ok(MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 })
        }
        linear_bcs_transcript::LinearBcsCommittedOracleRole::WhirRound { round_ordinal } => {
            Ok(MerkleOracleEquationRole::WhirEpoch {
                epoch_ordinal: round_ordinal
                    .checked_add(1)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            })
        }
        commitment_role
        @ (linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad
        | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource
        | linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad) => {
            Ok(MerkleOracleEquationRole::AggregateWideMask { commitment_role })
        }
    }
}

fn coordinate_derived_opening_implementation(
    role: MerkleOracleEquationRole,
) -> CoordinateDerivedOpeningImplementation {
    match role {
        MerkleOracleEquationRole::RelationPhase { .. } => {
            CoordinateDerivedOpeningImplementation::RelationColumnCommitment
        }
        MerkleOracleEquationRole::BoundTree { .. } => {
            CoordinateDerivedOpeningImplementation::ExactBoundTree
        }
        MerkleOracleEquationRole::WhirEpoch { .. }
        | MerkleOracleEquationRole::AggregateWideMask { .. } => {
            CoordinateDerivedOpeningImplementation::AggregateWideWhir
        }
    }
}

fn derive_commitment_subtree_extraction_certificate(
    plan: &RowCodeWhirConstructionPlan,
    merkle_rows: &[MerkleOracleEquationCoverageRow],
) -> Result<CommitmentSubtreeExtractionCertificate, WhirTheoremCertificateError> {
    let transcript_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    if merkle_rows.is_empty()
        || merkle_rows.iter().enumerate().any(|(row_index, row)| {
            merkle_rows[..row_index]
                .iter()
                .any(|prior| prior.role == row.role)
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }

    let supplied_commitment_root_count = transcript_plan.supplied_commitment_openings().len();
    for opening in transcript_plan.supplied_commitment_openings() {
        if opening.query_order
            != linear_bcs_transcript::LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order
                != linear_bcs_transcript::LinearBcsMerkleTraversalOrder::SortedCoordinates
        {
            return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
        }
        let protocol_role = supplied_commitment_protocol_tree_role(opening.commitment_role)?;
        let matching_rows = merkle_rows
            .iter()
            .filter(|row| row.role == protocol_role)
            .collect::<Vec<_>>();
        if matching_rows.len() != 1
            || matching_rows[0].leaf_count != opening.payload_leaf_count
            || matching_rows[0].query_count != opening.query_count
        {
            return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
        }
    }

    let relation_phase_rows = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::RelationPhase { phase } => Some(phase),
            _ => None,
        })
        .collect::<Vec<_>>();
    let bound_tree_ordinals = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::BoundTree { bound_tree_ordinal } => Some(bound_tree_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let whir_epoch_ordinals = merkle_rows
        .iter()
        .filter_map(|row| match row.role {
            MerkleOracleEquationRole::WhirEpoch { epoch_ordinal } => Some(epoch_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let aggregate_wide_role_count = merkle_rows
        .iter()
        .filter(|row| matches!(row.role, MerkleOracleEquationRole::AggregateWideMask { .. }))
        .count();
    if relation_phase_rows != plan.phase_order
        || bound_tree_ordinals
            != (0..plan.bound_trees.len())
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        || whir_epoch_ordinals
            != (0..=plan.whir.rounds.len())
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        || aggregate_wide_role_count != 3
        || supplied_commitment_root_count.checked_add(plan.bound_trees.len())
            != Some(merkle_rows.len())
    {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }

    let mut canonical_complete_message_digest_count = 0_u64;
    let mut one_edge_sampler_message_count = 0_u64;
    for range in transcript_plan.round_ranges() {
        match range.prover_oracle_root {
            linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
                value_count,
                canonical_message_byte_length,
            } => {
                let expected_message_byte_length = value_count
                    .checked_mul(
                        PROOF_CHALLENGE_EXTENSION_DEGREE
                            .checked_mul(std::mem::size_of::<u64>())
                            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
                    )
                    .and_then(|length| length.checked_add(6))
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
                if value_count == 0 || canonical_message_byte_length != expected_message_byte_length
                {
                    return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
                }
                canonical_complete_message_digest_count = canonical_complete_message_digest_count
                    .checked_add(range.round_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => {
                one_edge_sampler_message_count = one_edge_sampler_message_count
                    .checked_add(range.round_count)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. } => {}
        }
    }

    let rows = merkle_rows
        .iter()
        .map(|row| {
            let tree_height = checked_tree_height(row.leaf_count)?;
            let expected_parent_hash_query_count =
                maximum_compact_parent_hash_query_count(row.leaf_count, row.query_count)?;
            if row.leaf_hash_query_count
                != u64::try_from(row.query_count)
                    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
                || row.parent_hash_query_count != expected_parent_hash_query_count
                || row.accepting_database_equation_count_ceiling
                    != row
                        .leaf_hash_query_count
                        .checked_add(row.parent_hash_query_count)
                        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
                || row.predecessor_support_ceiling > 2
            {
                return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
            }
            Ok(CommitmentSubtreeExtractionRow {
                role: row.role,
                implementation: coordinate_derived_opening_implementation(row.role),
                leaf_count: row.leaf_count,
                tree_height,
                query_count: row.query_count,
                leaf_hash_query_count: row.leaf_hash_query_count,
                parent_hash_query_count_ceiling: row.parent_hash_query_count,
                predecessor_support_ceiling: row.predecessor_support_ceiling,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certificate = CommitmentSubtreeExtractionCertificate {
        distinct_protocol_tree_role_count: rows.len(),
        rows,
        supplied_commitment_root_count,
        bound_tree_root_count: plan.bound_trees.len(),
        canonical_complete_message_digest_count,
        one_edge_sampler_message_count,
        // CMS19 Definition 6.3 rejects collisions before expanding a node.
        collision_free_extraction_is_unique: true,
        // CMS19 Lemma 6.4.
        database_growth_preserves_the_extracted_subtree: true,
        // CMS19 Lemma 6.5.
        changed_extracted_tree_requires_a_root_or_half_preimage: true,
        // `leaves(Extract(...))` uses bottom for every absent depth-d node.
        missing_leaf_is_undefined: true,
        // Every production frontier verifier requires every transcript-derived
        // coordinate and reconstructs the committed root before returning.
        queried_missing_leaf_is_rejected: true,
        complete_message_digests_are_recomputed: canonical_complete_message_digest_count > 0,
        compact_frontiers_are_coordinate_derived: true,
        coordinates_are_derived_from_accepted_transcript_order: true,
    };
    if !certificate.is_complete() {
        return Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping);
    }
    Ok(certificate)
}

fn derive_cms19_strong_state_hash_chain_certificate(
    plan: &RowCodeWhirConstructionPlan,
    catalog: &RowCodeWhirOracleEquationCatalog,
    state_epoch_rows: &[StateEpochRow],
    oracle_equation_rows: &[OracleEquationCoverageRow],
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
    whole_state_transitions: &Cms19WholeStateTransitionCertificate,
    logical_verifier_message_count: u64,
) -> Result<Cms19StrongStateHashChainCertificate, WhirTheoremCertificateError> {
    validate_state_and_equation_rows(catalog, state_epoch_rows, oracle_equation_rows)?;
    if !selected_plan_state_predicate.is_total_for_plan(plan)
        || selected_plan_state_predicate.transition_rows.len() != state_epoch_rows.len()
        || !whole_state_transitions.is_complete_for(plan, catalog, selected_plan_state_predicate)
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }

    let typed_challenge_transition_count = state_epoch_rows
        .iter()
        .filter(|row| {
            row.transition_owner == StateTransitionOwner::VerifierChallengeWithTypedFailureEvent
        })
        .try_fold(0_u64, |count, _| {
            count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let uniquely_owned_fill_transition_count = selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter(|row| row.failure_event_owner.is_some())
        .try_fold(0_u64, |count, _| {
            count
                .checked_add(1)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    let topologically_ordered_equation_count =
        oracle_equation_rows.iter().try_fold(0_u64, |count, row| {
            count
                .checked_add(row.equation_count)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
        })?;
    if typed_challenge_transition_count != whole_state_transitions.verifier_message_fill_count
        || uniquely_owned_fill_transition_count
            != whole_state_transitions.verifier_message_fill_count
        || topologically_ordered_equation_count
            != whole_state_transitions.covered_transcript_equation_count
        || logical_verifier_message_count != whole_state_transitions.verifier_message_fill_count
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let transcript_predecessor_support_ceiling = oracle_equation_rows
        .iter()
        .map(|row| row.role_pattern.maximum_predecessor_support_count())
        .max()
        .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?;

    let oracle_plan = plan
        .linear_bcs_transcript_plan()
        .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let abstract_oracle_step_count = oracle_plan
        .round_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    if abstract_oracle_step_count != whole_state_transitions.covered_bcs_round_count
        || oracle_plan
            .canonical_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?
            != whole_state_transitions.linear_bcs_transcript_plan_hash
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let sampler_expansion_edge_count = oracle_plan
        .one_edge_sampler_block_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let prover_response_round_count = abstract_oracle_step_count
        .checked_sub(sampler_expansion_edge_count)
        .ok_or(WhirTheoremCertificateError::IncompleteTranscriptMapping)?;
    let prover_response_edge_count = prover_response_round_count
        .checked_mul(2)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let oracle_edge_count = oracle_plan
        .chain_hash_query_count()
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    if oracle_edge_count
        != sampler_expansion_edge_count
            .checked_add(prover_response_edge_count)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    let sampler_messages_are_outside_prover_response_absorption = oracle_plan
        .round_ranges()
        .iter()
        .all(|range| match range.prover_oracle_root {
            linear_bcs_transcript::LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => {
                matches!(
                    range.verifier_message_role,
                    linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                        ..
                    } | linear_bcs_transcript::LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                        ..
                    }
                )
            }
            linear_bcs_transcript::LinearBcsProverOracleRoot::SuppliedCommitment { .. }
            | linear_bcs_transcript::LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
                ..
            } => matches!(
                range.verifier_message_role,
                linear_bcs_transcript::LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
                    ..
                }
            ),
        });

    let typed_oracle_domains = [
        TRANSCRIPT_INITIAL_DOMAIN,
        TRANSCRIPT_ABSORB_DOMAIN,
        TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
        TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
        TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN,
        TRANSCRIPT_RESPONSE_BINDING_DOMAIN,
        TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN,
        PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE,
        DISTINCT_QUERY_VECTOR_SAMPLER_TYPE,
    ];
    let typed_oracle_domains_are_pairwise_distinct = typed_oracle_domains
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        == typed_oracle_domains.len();
    let certificate = Cms19StrongStateHashChainCertificate {
        logical_verifier_message_count,
        typed_challenge_transition_count,
        uniquely_owned_fill_transition_count,
        topologically_ordered_equation_count,
        oracle_edge_count,
        sampler_expansion_edge_count,
        prover_response_edge_count,
        transcript_predecessor_support_ceiling,
        // This is the Section 8.6 state extension: an incomplete verifier
        // message is `None`, and the predicate is defined to equal its
        // predecessor until the complete typed sampler output is filled.
        undefined_message_inherits_predecessor_state: true,
        sampler_messages_are_outside_prover_response_absorption,
        typed_oracle_domains_are_pairwise_distinct,
        canonical_oracle_plan_hash: oracle_plan
            .canonical_hash()
            .map_err(|_| WhirTheoremCertificateError::IncompleteTranscriptMapping)?,
    };
    if !certificate.is_complete()
        || certificate.topologically_ordered_equation_count
            != catalog
                .maximum_equation_count()
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
    {
        return Err(WhirTheoremCertificateError::IncompleteTranscriptMapping);
    }
    Ok(certificate)
}

struct Cms19StatePredicateCertificateInput<'a> {
    selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    plan: &'a RowCodeWhirConstructionPlan,
    catalog: &'a RowCodeWhirOracleEquationCatalog,
    code_state_rows: &'a [WhirCodeStateRow],
    interleaved_unique_decoding_rows: &'a [InterleavedUniqueDecodingRow],
    whole_state_transitions: &'a Cms19WholeStateTransitionCertificate,
    strong_state_hash_chain: &'a Cms19StrongStateHashChainCertificate,
    relation_compiler_interpreter_semantics: &'a RelationCompilerInterpreterSemanticCertificate,
    polynomial_protocol_extractor: &'a ExactPolynomialProtocolExtractorCertificate,
    point_constraint_extractor: &'a ExactPointConstraintExtractorCertificate,
    exact_failure_magnitude: &'a ExactFailureMagnitudeCertificate,
}

fn derive_cms19_state_predicate_certificate(
    input: Cms19StatePredicateCertificateInput<'_>,
) -> Cms19StatePredicateCertificate {
    let Cms19StatePredicateCertificateInput {
        selected_plan_state_predicate,
        plan,
        catalog,
        code_state_rows,
        interleaved_unique_decoding_rows,
        whole_state_transitions,
        strong_state_hash_chain,
        relation_compiler_interpreter_semantics,
        polynomial_protocol_extractor,
        point_constraint_extractor,
        exact_failure_magnitude,
    } = input;
    let selected_plan_state_is_total = selected_plan_state_predicate.is_total_for_plan(plan);
    let whole_state_transition_correspondence_is_complete =
        whole_state_transitions.is_complete_for(plan, catalog, selected_plan_state_predicate);
    let expected_code_state_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .and_then(|epoch_count| {
            plan.parameters
                .folding_factor
                .checked_add(1)
                .and_then(|state_count| epoch_count.checked_mul(state_count))
        });
    let selected_geometry_is_strict = expected_code_state_count == Some(code_state_rows.len())
        && code_state_rows.iter().all(|row| {
            row.selected_state_relative_distance
                .less_than(row.theorem_five_two_strict_distance_ceiling)
                .unwrap_or(false)
                && row
                    .selected_state_relative_distance
                    .less_than(row.corollary_four_eleven_proximity_bound)
                    .unwrap_or(false)
                && row.false_state_minimum_error_count <= row.unique_decoding_radius
                && row.unique_decoding_radius.saturating_mul(2) < row.minimum_distance
                && row.unique_decoding_list_size_ceiling == 1
        });
    let expected_interleaving_lane_count = u32::try_from(plan.parameters.folding_factor)
        .ok()
        .and_then(|folding_factor| 1_usize.checked_shl(folding_factor));
    let interleaved_distance_is_exact = expected_code_state_count
        == Some(interleaved_unique_decoding_rows.len())
        && interleaved_unique_decoding_rows.iter().all(|row| {
            Some(row.lane_count) == expected_interleaving_lane_count
                && row.constituent_minimum_distance == row.interleaved_minimum_distance
                && row.selected_state_error_count_ceiling
                    < (row.interleaved_minimum_distance - 1) / 2
                && row.unique_decoding_list_size_ceiling == 1
                && row.lower_bound_uses_nonzero_component
                && row.upper_bound_uses_one_nonzero_component
        });
    let requirements = [
        (
            StatePredicateRequirement::OriginalBcsStrongStateRuntimeHashChainCorrespondence,
            StatePredicateDischargeAuthority::GeneratedStrongStateTypedOracleCorrespondence,
            strong_state_hash_chain.is_complete(),
        ),
        (
            StatePredicateRequirement::CompleteSemanticStateTransitionCorrespondence,
            StatePredicateDischargeAuthority::GeneratedWholeStateTransitionCorrespondence,
            whole_state_transition_correspondence_is_complete,
        ),
        (
            StatePredicateRequirement::CanonicalPlanCursorCoverage,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EmptyTranscriptIsFalse,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::ProverMoveCannotRepairFalseState,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::FullFalseTranscriptIsRejected,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryVerifierChallengeHasOneTypedFailureOwner,
            StatePredicateDischargeAuthority::GeneratedFailureOwnerPartition,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryProofSectionHasOnePredicateOwner,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::EveryCheckpointHasOneStateOwner,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::LifecycleNonAcceptanceAndFreshVerification,
            StatePredicateDischargeAuthority::GeneratedSelectedPlanStatePredicate,
            selected_plan_state_is_total,
        ),
        (
            StatePredicateRequirement::SelectedUniqueDecodingInequalitiesHold,
            StatePredicateDischargeAuthority::CheckedConstructionGeometry,
            selected_geometry_is_strict,
        ),
        (
            StatePredicateRequirement::InterleavedDistanceAndListSizeHold,
            StatePredicateDischargeAuthority::CheckedInterleavedDistanceLemma,
            interleaved_distance_is_exact,
        ),
        (
            StatePredicateRequirement::ExplicitUniqueDecoderExists,
            StatePredicateDischargeAuthority::ExplicitBerlekampWelchExtractor,
            selected_geometry_is_strict && interleaved_distance_is_exact,
        ),
        (
            StatePredicateRequirement::ExtractCompleteRelationPhaseCodewords,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompleteBoundCodewords,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompleteWhirEpochCodewords,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExplicitPointConstraintExtractorCorrespondence,
            StatePredicateDischargeAuthority::CheckedExplicitPointConstraintExtractor,
            point_constraint_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractThetaAndPhaseReductions,
            StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor,
            polynomial_protocol_extractor.is_complete() && point_constraint_extractor.is_complete(),
        ),
        (
            StatePredicateRequirement::ExactFailureMagnitudeCorrespondence,
            StatePredicateDischargeAuthority::CheckedExactFailureMagnitudeCorrespondence,
            exact_failure_magnitude.is_complete(),
        ),
        (
            StatePredicateRequirement::ExtractCompilerInterpreterRelationWitness,
            StatePredicateDischargeAuthority::IndependentCompilerInterpreterArithmeticOracle,
            relation_compiler_interpreter_semantics.is_complete(),
        ),
    ]
    .into_iter()
    .map(
        |(requirement, discharge_authority, is_discharged)| StatePredicateRequirementRow {
            requirement,
            discharge_authority,
            is_discharged,
        },
    )
    .collect();
    let proposition_eight_twelve_partition = vec![
        PropositionEightTwelvePartitionCase::AcceptingDatabaseContainsCollision,
        PropositionEightTwelvePartitionCase::CollisionFreeAcceptingDatabaseYieldsFullTranscript,
        PropositionEightTwelvePartitionCase::EarliestFalseToTrueVerifierStateTransition,
    ];
    Cms19StatePredicateCertificate {
        requirements,
        proposition_eight_twelve_partition,
        transcript_incompatibility_count: 0,
    }
}

struct Cms19ApplicabilityCertificateInput<'a> {
    plan: &'a RowCodeWhirConstructionPlan,
    catalog: &'a RowCodeWhirOracleEquationCatalog,
    selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    whole_state_transitions: &'a Cms19WholeStateTransitionCertificate,
    whole_database_support: &'a Cms19WholeDatabaseSupportCertificate,
    state_predicate: &'a Cms19StatePredicateCertificate,
    strong_state_hash_chain: &'a Cms19StrongStateHashChainCertificate,
    verifier_oracle_ledger: &'a CompleteVerifierOracleLedger,
    deployed_leaf_oracle: &'a DeployedAggregateLeafOracleCertificate,
    exact_failure_magnitude: &'a ExactFailureMagnitudeCertificate,
}

fn derive_cms19_applicability_certificate(
    input: Cms19ApplicabilityCertificateInput<'_>,
) -> Result<Cms19ApplicabilityCertificate, WhirTheoremCertificateError> {
    let Cms19ApplicabilityCertificateInput {
        plan,
        catalog,
        selected_plan_state_predicate,
        whole_state_transitions,
        whole_database_support,
        state_predicate,
        strong_state_hash_chain,
        verifier_oracle_ledger,
        deployed_leaf_oracle,
        exact_failure_magnitude,
    } = input;
    let complete_state_transition_correspondence =
        whole_state_transitions.is_complete_for(plan, catalog, selected_plan_state_predicate);
    let complete_query_ledger_correspondence = whole_database_support.is_complete()
        && whole_database_support.construction_plan_identity_hash
            == whole_state_transitions.construction_plan_identity_hash
        && whole_database_support.mapped_hash_query_count
            == deployed_leaf_oracle.deployed_verifier_hash_query_count
        && whole_database_support.mapped_accepting_database_equation_count
            == deployed_leaf_oracle.deployed_accepting_database_equation_count;
    Ok(Cms19ApplicabilityCertificate {
        transform: Cms19Transform::OriginalBcsStrongStateHashChainSectionEightSix,
        transcript_equation_count: verifier_oracle_ledger.transcript_equation_count,
        transcript_hash_query_count: verifier_oracle_ledger.transcript_hash_query_count,
        claimed_complete_equation_count: whole_database_support
            .claimed_accepting_database_equation_count,
        claimed_complete_hash_query_count: whole_database_support.claimed_hash_query_count,
        equation_count_without_catalog_correspondence: whole_database_support
            .uncovered_accepting_database_equation_count()
            .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?,
        hash_query_count_without_catalog_correspondence: whole_database_support
            .uncovered_hash_query_count()
            .ok_or(WhirTheoremCertificateError::IncompleteOracleEquationMapping)?,
        transcript_predecessor_support_ceiling: strong_state_hash_chain
            .transcript_predecessor_support_ceiling,
        complete_state_predicate_established: state_predicate.is_complete(),
        syntactic_proposition_eight_twelve_partition_catalogued: state_predicate
            .has_exact_abstract_partition(),
        proposition_eight_twelve_case_split_established: state_predicate.is_complete()
            && complete_state_transition_correspondence
            && complete_query_ledger_correspondence
            && exact_failure_magnitude.is_complete(),
        complete_query_ledger_correspondence_established: complete_query_ledger_correspondence,
        strong_state_typed_hash_chain_established: strong_state_hash_chain.is_complete(),
        semantic_state_transition_correspondence_established:
            complete_state_transition_correspondence
                && deployed_leaf_oracle.semantic_state_transition_correspondence_established(),
        deployed_oracle_output_geometry_established: deployed_leaf_oracle
            .is_eligible_for_uniform_required_output(),
    })
}

fn derive_cms19_arithmetic_certificate(
    verifier_hash_query_count: u64,
    accepting_database_equation_count: u64,
) -> Cms19ArithmeticCertificate {
    let adversarial_query_bound =
        (BigUint::from(1_u8) << CMS19_ADVERSARIAL_QUERY_EXPONENT) - BigUint::from(1_u8);
    let compiler_query_bound = &adversarial_query_bound + BigUint::from(verifier_hash_query_count);
    let classical_soundness_multiplier =
        BigUint::from(12_u8) * &compiler_query_bound * &compiler_query_bound;
    let ideal_oracle_penalty_numerator = BigUint::from(48_u8)
        * &compiler_query_bound
        * &compiler_query_bound
        * &compiler_query_bound
        + BigUint::from(2_u8) * BigUint::from(accepting_database_equation_count);
    Cms19ArithmeticCertificate {
        adversarial_query_bound,
        verifier_hash_query_count,
        accepting_database_equation_count,
        compiler_query_bound,
        classical_soundness_multiplier,
        ideal_oracle_penalty_numerator,
        ideal_oracle_penalty_denominator_bit_length: CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH,
    }
}

const EXACT_FAILURE_OWNER_COUNTS: [(ExactFailureOwnerKind, usize); 19] = [
    (ExactFailureOwnerKind::NonNativeThetaProduct, 3),
    (ExactFailureOwnerKind::NonNativeAlphaProduct, 0),
    (ExactFailureOwnerKind::RelationComposition, 4_046),
    (ExactFailureOwnerKind::OutOfDomainPoint, 1),
    (ExactFailureOwnerKind::PointSelector, 18),
    (ExactFailureOwnerKind::TraceColumnGroup, 63),
    (ExactFailureOwnerKind::QuotientGroup, 1),
    (ExactFailureOwnerKind::OpeningBatchMask, 1),
    (ExactFailureOwnerKind::BoundOpening, 44),
    (ExactFailureOwnerKind::BoundDegreeCoordinate, 50),
    (ExactFailureOwnerKind::OuterQueryVector, 1),
    (ExactFailureOwnerKind::BoundQueryVector, 1),
    (ExactFailureOwnerKind::WhirQueryVector, 7),
    (ExactFailureOwnerKind::WhirOpeningBatching, 1),
    (ExactFailureOwnerKind::MaskedSumcheckEpsilon, 6),
    (ExactFailureOwnerKind::MaskedSumcheckFold, 18),
    (ExactFailureOwnerKind::RoundCheckpoint, 5),
    (ExactFailureOwnerKind::RoundCombination, 5),
    (ExactFailureOwnerKind::BaseCaseBlinding, 1),
];

fn exact_failure_owner_kind(
    owner: SelectedPlanFailureEventOwner,
) -> Result<ExactFailureOwnerKind, WhirTheoremCertificateError> {
    match owner {
        SelectedPlanFailureEventOwner::CommonProductChallenge {
            challenge: CommonProofChallenge::Theta { .. },
        } => Ok(ExactFailureOwnerKind::NonNativeThetaProduct),
        SelectedPlanFailureEventOwner::CommonProductChallenge {
            challenge: CommonProofChallenge::Alpha { .. },
        } => Ok(ExactFailureOwnerKind::NonNativeAlphaProduct),
        SelectedPlanFailureEventOwner::CommonExtensionChallenge {
            challenge: CommonProofChallenge::Composition { .. },
        } => Ok(ExactFailureOwnerKind::RelationComposition),
        SelectedPlanFailureEventOwner::CommonExtensionChallenge {
            challenge: CommonProofChallenge::OutOfDomainPoint { .. },
        } => Ok(ExactFailureOwnerKind::OutOfDomainPoint),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::PointSelectorWeight { .. },
        } => Ok(ExactFailureOwnerKind::PointSelector),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::TraceColumnGroupWeight { .. },
        } => Ok(ExactFailureOwnerKind::TraceColumnGroup),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::QuotientGroupWeight { .. },
        } => Ok(ExactFailureOwnerKind::QuotientGroup),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::OpeningBatchMaskWeight { .. },
        } => Ok(ExactFailureOwnerKind::OpeningBatchMask),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::BoundOpeningWeight { .. },
        } => Ok(ExactFailureOwnerKind::BoundOpening),
        SelectedPlanFailureEventOwner::DirectExtensionChallenge {
            challenge: RowCodeWhirChallenge::BoundDegreeCoordinate { .. },
        } => Ok(ExactFailureOwnerKind::BoundDegreeCoordinate),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::Outer,
        } => Ok(ExactFailureOwnerKind::OuterQueryVector),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::Bound,
        } => Ok(ExactFailureOwnerKind::BoundQueryVector),
        SelectedPlanFailureEventOwner::DistinctQueryVector {
            role: RowCodeWhirQueryRole::WhirEpoch { .. },
        } => Ok(ExactFailureOwnerKind::WhirQueryVector),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::OpeningBatching,
        } => Ok(ExactFailureOwnerKind::WhirOpeningBatching),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { .. },
        } => Ok(ExactFailureOwnerKind::MaskedSumcheckEpsilon),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::MaskedSumcheckRound { .. },
        } => Ok(ExactFailureOwnerKind::MaskedSumcheckFold),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::RoundCheckpoint { .. },
        } => Ok(ExactFailureOwnerKind::RoundCheckpoint),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::RoundCombination { .. },
        } => Ok(ExactFailureOwnerKind::RoundCombination),
        SelectedPlanFailureEventOwner::WhirExtensionChallenge {
            role: RowCodeWhirExtensionRole::BaseCaseBlinding,
        } => Ok(ExactFailureOwnerKind::BaseCaseBlinding),
        _ => Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence),
    }
}

fn derive_exact_failure_owner_rows(
    selected_plan_state_predicate: &SelectedPlanStatePredicateCertificate,
) -> Result<Vec<ExactFailureOwnerRow>, WhirTheoremCertificateError> {
    let mut counts = EXACT_FAILURE_OWNER_COUNTS
        .iter()
        .map(|(kind, _)| (*kind, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for owner in selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter_map(|row| row.failure_event_owner)
    {
        let kind = exact_failure_owner_kind(owner)?;
        let count = counts
            .get_mut(&kind)
            .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        *count = count
            .checked_add(1)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    }
    Ok(EXACT_FAILURE_OWNER_COUNTS
        .iter()
        .map(|(kind, expected_transition_count)| ExactFailureOwnerRow {
            kind: *kind,
            transition_count: counts.get(kind).copied().unwrap_or(0),
            expected_transition_count: *expected_transition_count,
        })
        .collect())
}

fn derive_exact_theta_failure_rows(
    relation_variant: &RelationPlanVariant,
    catalog: &RowCodeWhirOracleEquationCatalog,
) -> Result<Vec<ExactThetaFailureRow>, WhirTheoremCertificateError> {
    let mut degrees_by_challenge = BTreeMap::<CommonProofChallenge, BTreeMap<u16, u64>>::new();
    for batch in relation_variant.ordered_integer_lift_batches() {
        let challenge = CommonProofChallenge::Theta {
            modulus_ordinal: relation_variant
                .non_native_modulus_ordinal(batch.modulus_reference())
                .map_err(|_| {
                    WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence
                })?,
        };
        let degree = batch
            .theta_bad_polynomial_degree(relation_variant.trace_domain_size())
            .map_err(|_| WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        if degrees_by_challenge
            .entry(challenge)
            .or_default()
            .insert(batch.challenge_ordinal(), degree)
            .is_some()
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
    }

    let mut rows = Vec::new();
    for operation in &catalog.operations {
        let RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(group) = operation.kind
        else {
            continue;
        };
        let challenge = group.challenge();
        if !matches!(challenge, CommonProofChallenge::Theta { .. }) {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let ordered_degrees = degrees_by_challenge
            .remove(&challenge)
            .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
        if group.modulus() != PROOF_BASE_FIELD_MODULUS
            || usize::from(group.coordinate_count()) != PROOF_CHALLENGE_EXTENSION_DEGREE
            || ordered_degrees.len() != usize::from(group.coordinate_count())
            || !ordered_degrees
                .keys()
                .copied()
                .eq(0..group.coordinate_count())
        {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        let ordered_bad_polynomial_degrees = ordered_degrees.into_values().collect::<Vec<_>>();
        if ordered_bad_polynomial_degrees != vec![32_766_u64; PROOF_CHALLENGE_EXTENSION_DEGREE] {
            return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
        }
        rows.push(ExactThetaFailureRow {
            challenge,
            bad_set_numerator: ordered_bad_polynomial_degrees
                .iter()
                .copied()
                .map(BigUint::from)
                .product(),
            sample_space_denominator: BigUint::from(group.modulus())
                .pow(u32::from(group.coordinate_count())),
            ordered_bad_polynomial_degrees,
        });
    }
    rows.sort_by_key(|row| row.challenge);
    if !degrees_by_challenge.is_empty() || rows.len() != 3 {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    Ok(rows)
}

fn derive_exact_query_failure_rows(
    plan: &RowCodeWhirConstructionPlan,
    code_state_rows: &[WhirCodeStateRow],
    aggregate_wide_masking: &AggregateWideMaskingCertificate,
) -> Result<Vec<ExactQueryFailureRow>, WhirTheoremCertificateError> {
    let shared_partition = selected_shared_query_partition();
    if shared_partition.map(|row| row.class)
        != [
            SharedQueryEventClass::OuterOpeningPointWords,
            SharedQueryEventClass::RelationPhaseColumns,
            SharedQueryEventClass::BoundTreeWords,
            SharedQueryEventClass::StatementRootWords,
        ]
        || shared_partition.iter().any(|row| {
            !row.words_fixed_before_sampling
                || !row.shares_one_query_vector
                || row.charged_term_count != 1
        })
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let bound_population = plan
        .bound_trees
        .first()
        .map(|tree| tree.leaf_count)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    if plan.bound_trees.len() != 11
        || plan
            .bound_trees
            .iter()
            .any(|tree| tree.leaf_count != bound_population)
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    let bound_population = u64::try_from(bound_population)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let outer_population = ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE;
    let shared_geometries = [
        (
            ExactQueryFailureEvent::OuterOpeningPointWords,
            ExactFailureOwnerKind::OuterQueryVector,
            outer_population,
            outer_population * 5 / 8,
        ),
        (
            ExactQueryFailureEvent::RelationPhaseColumns,
            ExactFailureOwnerKind::OuterQueryVector,
            outer_population,
            outer_population * 5 / 8,
        ),
        (
            ExactQueryFailureEvent::BoundTreeWords,
            ExactFailureOwnerKind::BoundQueryVector,
            bound_population,
            9_217,
        ),
        (
            ExactQueryFailureEvent::StatementRootWords,
            ExactFailureOwnerKind::BoundQueryVector,
            bound_population,
            bound_population * 65 / 128,
        ),
    ];
    let mut rows = Vec::with_capacity(
        shared_partition
            .len()
            .checked_add(
                plan.whir
                    .rounds
                    .len()
                    .checked_add(2)
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
            )
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    for (partition_row, (event, sponsoring_owner, population, agreement_ceiling)) in
        shared_partition.into_iter().zip(shared_geometries)
    {
        rows.push(ExactQueryFailureRow::derive(
            event,
            sponsoring_owner,
            partition_row.word_count,
            population,
            agreement_ceiling,
            u64::try_from(partition_row.sampled_coordinate_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            u64::try_from(partition_row.charged_term_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?);
    }

    let terminal_fold_ordinal = u32::try_from(plan.parameters.folding_factor)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let mut source_states = code_state_rows
        .iter()
        .copied()
        .filter(|row| row.fold_ordinal == terminal_fold_ordinal)
        .collect::<Vec<_>>();
    source_states.sort_by_key(|row| row.epoch_ordinal);
    let expected_source_epoch_count = plan
        .whir
        .rounds
        .len()
        .checked_add(1)
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    if source_states.len() != expected_source_epoch_count
        || source_states
            .iter()
            .enumerate()
            .any(|(epoch_index, row)| usize::try_from(row.epoch_ordinal).ok() != Some(epoch_index))
    {
        return Err(WhirTheoremCertificateError::InvalidSelectedGeometry);
    }
    for (epoch_index, code_state) in source_states.into_iter().enumerate() {
        let (message_length, randomness_length, domain_size, query_count, interleaving_width) =
            aggregate_wide_masking
                .folded_source_code_geometry(epoch_index)
                .ok_or(WhirTheoremCertificateError::IncompleteMaskingCorrespondence)?;
        if domain_size != usize::try_from(code_state.domain_size).unwrap_or(usize::MAX)
            || message_length.checked_add(randomness_length)
                != Some(
                    usize::try_from(code_state.dimension)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
            || interleaving_width
                != 1_usize
                    .checked_shl(
                        u32::try_from(plan.parameters.folding_factor)
                            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                    )
                    .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?
        {
            return Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence);
        }
        rows.push(ExactQueryFailureRow::derive(
            ExactQueryFailureEvent::WhirSource {
                epoch_ordinal: code_state.epoch_ordinal,
            },
            ExactFailureOwnerKind::WhirQueryVector,
            1,
            code_state.domain_size,
            code_state
                .domain_size
                .checked_sub(code_state.false_state_minimum_error_count)
                .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
            u64::try_from(query_count)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
            1,
        )?);
    }

    let (pad_message_length, pad_randomness_length, pad_domain_size, pad_query_count, pad_width) =
        aggregate_wide_masking.pad_code_geometry();
    let pad_dimension = pad_message_length
        .checked_add(pad_randomness_length)
        .and_then(|dimension| dimension.checked_mul(pad_width))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_domain_size = u64::try_from(pad_domain_size)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_dimension = u64::try_from(pad_dimension)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_unique_decoding_radius = pad_domain_size
        .checked_sub(pad_dimension)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
        / 2;
    let pad_selected_distance = ExactFraction::new(
        pad_unique_decoding_radius
            .checked_sub(1)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        pad_domain_size,
    )?;
    let pad_epoch_ordinal = u32::try_from(expected_source_epoch_count)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let pad_code_state = WhirCodeStateRow::derive(
        pad_epoch_ordinal,
        0,
        pad_domain_size,
        pad_dimension,
        pad_selected_distance,
    )?;
    rows.push(ExactQueryFailureRow::derive(
        ExactQueryFailureEvent::AggregateWidePad,
        ExactFailureOwnerKind::WhirQueryVector,
        1,
        pad_code_state.domain_size,
        pad_code_state
            .domain_size
            .checked_sub(pad_code_state.false_state_minimum_error_count)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
        u64::try_from(pad_query_count)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        1,
    )?);
    Ok(rows)
}

fn exact_owner_count(
    owner_rows: &[ExactFailureOwnerRow],
    kind: ExactFailureOwnerKind,
) -> Result<u64, WhirTheoremCertificateError> {
    let count = owner_rows
        .iter()
        .find(|row| row.kind == kind)
        .map(|row| row.transition_count)
        .ok_or(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence)?;
    u64::try_from(count).map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)
}

#[derive(Clone, Copy)]
struct ExactFailureMagnitudeDerivationInput<'a> {
    plan: &'a RowCodeWhirConstructionPlan,
    relation_variant: &'a RelationPlanVariant,
    catalog: &'a RowCodeWhirOracleEquationCatalog,
    selected_plan_state_predicate: &'a SelectedPlanStatePredicateCertificate,
    code_state_rows: &'a [WhirCodeStateRow],
    fold_rows: &'a [WhirFoldFailureRow],
    shift_rows: &'a [WhirShiftFailureRow],
    aggregate_wide_masking: &'a AggregateWideMaskingCertificate,
    initial_constraint_batch_numerator: u64,
    logical_verifier_message_count: u64,
    cms19_arithmetic: &'a Cms19ArithmeticCertificate,
}

fn derive_exact_algebraic_failure_rows(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    owner_rows: &[ExactFailureOwnerRow],
    theta_rows: &[ExactThetaFailureRow],
) -> Result<Vec<ExactAlgebraicFailureRow>, WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        code_state_rows,
        fold_rows,
        shift_rows,
        aggregate_wide_masking,
        initial_constraint_batch_numerator,
        ..
    } = input;
    let theta_numerator = theta_rows
        .iter()
        .map(|row| row.bad_set_numerator.clone())
        .sum::<BigUint>();
    let opening_point_count = plan
        .aggregate_column_roles
        .iter()
        .filter(|role| matches!(role, RowCodeWhirAggregateColumnRole::OpeningPoint { .. }))
        .count();
    let outer_population = ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE;
    let bound_population = u64::try_from(
        plan.bound_trees
            .first()
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .leaf_count,
    )
    .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let exceptional_set_numerator = outer_population
        .checked_add(
            outer_population
                .checked_mul(
                    u64::try_from(opening_point_count)
                        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
                )
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .and_then(|total| {
            bound_population
                .checked_mul(u64::try_from(plan.aggregate_column_roles.len()).ok()?)
                .and_then(|bound| total.checked_add(bound))
        })
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let phase_batch_numerator = u64::try_from(opening_point_count)
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?
        .checked_mul(
            u64::try_from(SAME_SECRET_AGGREGATE_TABLE_WIDTH)
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;
    let fold_numerator = fold_rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.total_numerator()?)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let shift_numerator = shift_rows.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.algebraic_numerator)
            .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)
    })?;
    let final_source_epoch_ordinal = u32::try_from(plan.whir.rounds.len())
        .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?;
    let final_source_domain_size = code_state_rows
        .iter()
        .find(|row| {
            row.epoch_ordinal == final_source_epoch_ordinal
                && usize::try_from(row.fold_ordinal).ok() == Some(plan.parameters.folding_factor)
        })
        .map(|row| row.domain_size)
        .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?;
    let base_blinding_numerator = final_source_domain_size
        .checked_add(
            u64::try_from(aggregate_wide_masking.pad_domain_size())
                .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?;

    Ok(vec![
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::NonNativeThetaExtraction,
            owner_kinds: vec![ExactFailureOwnerKind::NonNativeThetaProduct],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::NonNativeThetaProduct,
            )?,
            numerator: theta_numerator,
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::RelationCompositionBatch,
            owner_kinds: vec![ExactFailureOwnerKind::RelationComposition],
            theorem_event_count: 1,
            numerator: BigUint::one(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::OpeningPointExceptionalSets,
            owner_kinds: vec![ExactFailureOwnerKind::OutOfDomainPoint],
            theorem_event_count: 1,
            numerator: BigUint::from(exceptional_set_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::PhaseRowAndSelectorBatching,
            owner_kinds: vec![
                ExactFailureOwnerKind::PointSelector,
                ExactFailureOwnerKind::TraceColumnGroup,
                ExactFailureOwnerKind::QuotientGroup,
            ],
            theorem_event_count: phase_batch_numerator,
            numerator: BigUint::from(phase_batch_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::OpeningBatchMaskConsistency,
            owner_kinds: vec![ExactFailureOwnerKind::OpeningBatchMask],
            theorem_event_count: 0,
            numerator: BigUint::zero(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::BoundOpeningBatch,
            owner_kinds: vec![ExactFailureOwnerKind::BoundOpening],
            theorem_event_count: 1,
            numerator: BigUint::one(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::BoundDegreeSuffixes,
            owner_kinds: vec![ExactFailureOwnerKind::BoundDegreeCoordinate],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::BoundDegreeCoordinate,
            )?,
            numerator: BigUint::from(exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::BoundDegreeCoordinate,
            )?),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::WhirOpeningBatch,
            owner_kinds: vec![ExactFailureOwnerKind::WhirOpeningBatching],
            theorem_event_count: 1,
            numerator: BigUint::from(initial_constraint_batch_numerator),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::MaskedSumcheckInitialTransitions,
            owner_kinds: vec![ExactFailureOwnerKind::MaskedSumcheckEpsilon],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckEpsilon,
            )?,
            numerator: BigUint::from(exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckEpsilon,
            )?),
        },
        // CFW Construction 6.3 and Lemma 6.5 contribute the WHIR mutual
        // correlated-agreement domain numerator plus the cubic sumcheck term
        // for each of the fifteen masked folds.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::MaskedSumcheckFolds,
            owner_kinds: vec![ExactFailureOwnerKind::MaskedSumcheckFold],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::MaskedSumcheckFold,
            )?,
            numerator: BigUint::from(fold_numerator),
        },
        // The checkpoint scalar is sampled and transcript-bound but is not an
        // algebraic input. Its following query vector owns the query event.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::RoundCommitmentCheckpoints,
            owner_kinds: vec![ExactFailureOwnerKind::RoundCheckpoint],
            theorem_event_count: 0,
            numerator: BigUint::zero(),
        },
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::WhirQueryCombinations,
            owner_kinds: vec![ExactFailureOwnerKind::RoundCombination],
            theorem_event_count: exact_owner_count(
                owner_rows,
                ExactFailureOwnerKind::RoundCombination,
            )?,
            numerator: BigUint::from(shift_numerator),
        },
        // CFW Construction 7.2 and Lemma 7.4 give one source-code MCA term,
        // one pad-code MCA term, and the singleton list-product term.
        ExactAlgebraicFailureRow {
            event: ExactAlgebraicFailureEvent::AggregateWideBaseBlinding,
            owner_kinds: vec![ExactFailureOwnerKind::BaseCaseBlinding],
            theorem_event_count: 1,
            numerator: BigUint::from(base_blinding_numerator),
        },
    ])
}

fn exact_failure_owners_are_completely_mapped(
    owner_rows: &[ExactFailureOwnerRow],
    query_rows: &[ExactQueryFailureRow],
    algebraic_rows: &[ExactAlgebraicFailureRow],
) -> bool {
    let expected = owner_rows
        .iter()
        .filter(|row| row.transition_count > 0)
        .map(|row| row.kind)
        .collect::<BTreeSet<_>>();
    let query_sponsors = query_rows
        .iter()
        .map(|row| row.sponsoring_owner)
        .collect::<BTreeSet<_>>();
    let mut algebraic_owners = BTreeSet::new();
    for kind in algebraic_rows
        .iter()
        .flat_map(|row| row.owner_kinds.iter().copied())
    {
        if !algebraic_owners.insert(kind) {
            return false;
        }
    }
    query_sponsors.is_disjoint(&algebraic_owners)
        && query_sponsors
            .union(&algebraic_owners)
            .copied()
            .collect::<BTreeSet<_>>()
            == expected
}

fn sum_query_probability_ceiling(
    query_rows: &[ExactQueryFailureRow],
) -> Result<ExactBigFraction, WhirTheoremCertificateError> {
    query_rows
        .iter()
        .try_fold(ExactBigFraction::zero(), |total, row| {
            total.add(&row.charged_power_ceiling()?)
        })
}

fn sum_algebraic_numerator(algebraic_rows: &[ExactAlgebraicFailureRow]) -> BigUint {
    algebraic_rows.iter().map(|row| row.numerator.clone()).sum()
}

fn derive_exact_failure_magnitude_certificate(
    input: ExactFailureMagnitudeDerivationInput<'_>,
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    derive_exact_failure_magnitude_certificate_with_mutation(input, |_| {})
}

fn derive_exact_failure_magnitude_certificate_with_mutation(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    mutate: impl FnOnce(&mut ExactFailureMagnitudeCertificate),
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        relation_variant,
        catalog,
        selected_plan_state_predicate,
        code_state_rows,
        aggregate_wide_masking,
        logical_verifier_message_count,
        cms19_arithmetic,
        ..
    } = input;
    let owner_rows = derive_exact_failure_owner_rows(selected_plan_state_predicate)?;
    if owner_rows
        .iter()
        .any(|row| row.transition_count != row.expected_transition_count)
        || owner_rows.iter().try_fold(0_u64, |total, row| {
            total.checked_add(u64::try_from(row.transition_count).ok()?)
        }) != Some(logical_verifier_message_count)
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let query_rows =
        derive_exact_query_failure_rows(plan, code_state_rows, aggregate_wide_masking)?;
    let theta_rows = derive_exact_theta_failure_rows(relation_variant, catalog)?;
    let extension_field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    if theta_rows
        .iter()
        .any(|row| row.sample_space_denominator != extension_field_cardinality)
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    let algebraic_rows = derive_exact_algebraic_failure_rows(input, &owner_rows, &theta_rows)?;
    let query_failure_probability_ceiling = sum_query_probability_ceiling(&query_rows)?;
    let algebraic_failure_probability_ceiling = ExactBigFraction::new(
        sum_algebraic_numerator(&algebraic_rows),
        extension_field_cardinality.clone(),
    )?;
    let classical_failure_probability_ceiling =
        query_failure_probability_ceiling.add(&algebraic_failure_probability_ceiling)?;
    let ideal_oracle_penalty = ExactBigFraction::new(
        cms19_arithmetic.ideal_oracle_penalty_numerator.clone(),
        BigUint::one() << cms19_arithmetic.ideal_oracle_penalty_denominator_bit_length,
    )?;
    let qrom_failure_probability_ceiling = classical_failure_probability_ceiling
        .multiply_integer(&cms19_arithmetic.classical_soundness_multiplier)?
        .add(&ideal_oracle_penalty)?;
    let same_secret_family_multiplicity = u64::from(
        crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
    );
    let one = ExactBigFraction::from_u64(1, 1)?;
    let ordinary_family_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(
            &(BigUint::from(same_secret_family_multiplicity) << CMS19_ADVERSARIAL_QUERY_EXPONENT),
        )?
        .less_than_or_equal(&one);
    let transformed_initial_mass_gate_holds = classical_failure_probability_ceiling
        .multiply_integer(&(BigUint::from(same_secret_family_multiplicity * 12) << 176_usize))?
        .less_than_or_equal(&one);
    let complete_qrom_mass_gate_holds = qrom_failure_probability_ceiling
        .multiply_u64(
            same_secret_family_multiplicity
                .checked_mul(4)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?
        .less_than_or_equal(&one);
    let all_failure_owners_mapped_once =
        exact_failure_owners_are_completely_mapped(&owner_rows, &query_rows, &algebraic_rows);
    let exact_query_products_bounded = query_rows.iter().all(|row| {
        row.exact_without_replacement_probability
            .less_than_or_equal(&row.power_probability_ceiling)
    });
    let mut certificate = ExactFailureMagnitudeCertificate {
        owner_rows,
        query_rows,
        theta_rows,
        algebraic_rows,
        extension_field_cardinality,
        query_failure_probability_ceiling,
        algebraic_failure_probability_ceiling,
        classical_failure_probability_ceiling,
        qrom_failure_probability_ceiling,
        same_secret_family_multiplicity,
        cms19_verifier_hash_query_count: cms19_arithmetic.verifier_hash_query_count,
        cms19_accepting_database_equation_count: cms19_arithmetic.accepting_database_equation_count,
        all_failure_owners_mapped_once,
        exact_query_products_bounded,
        ordinary_family_mass_gate_holds,
        transformed_initial_mass_gate_holds,
        complete_qrom_mass_gate_holds,
    };
    mutate(&mut certificate);
    validate_exact_failure_magnitude_certificate(&certificate, input)?;
    Ok(certificate)
}

fn validate_exact_failure_magnitude_certificate(
    certificate: &ExactFailureMagnitudeCertificate,
    input: ExactFailureMagnitudeDerivationInput<'_>,
) -> Result<(), WhirTheoremCertificateError> {
    let ExactFailureMagnitudeDerivationInput {
        plan,
        relation_variant,
        catalog,
        selected_plan_state_predicate,
        code_state_rows,
        aggregate_wide_masking,
        logical_verifier_message_count,
        cms19_arithmetic,
        ..
    } = input;
    let expected_owner_rows = derive_exact_failure_owner_rows(selected_plan_state_predicate)?;
    let expected_query_rows =
        derive_exact_query_failure_rows(plan, code_state_rows, aggregate_wide_masking)?;
    let expected_theta_rows = derive_exact_theta_failure_rows(relation_variant, catalog)?;
    let expected_algebraic_rows =
        derive_exact_algebraic_failure_rows(input, &expected_owner_rows, &expected_theta_rows)?;
    let expected_extension_field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| WhirTheoremCertificateError::ArithmeticOverflow)?,
    );
    let expected_query_ceiling = sum_query_probability_ceiling(&expected_query_rows)?;
    let expected_algebraic_ceiling = ExactBigFraction::new(
        sum_algebraic_numerator(&expected_algebraic_rows),
        expected_extension_field_cardinality.clone(),
    )?;
    let expected_classical_ceiling = expected_query_ceiling.add(&expected_algebraic_ceiling)?;
    let expected_qrom_ceiling = expected_classical_ceiling
        .multiply_integer(&cms19_arithmetic.classical_soundness_multiplier)?
        .add(&ExactBigFraction::new(
            cms19_arithmetic.ideal_oracle_penalty_numerator.clone(),
            BigUint::one() << cms19_arithmetic.ideal_oracle_penalty_denominator_bit_length,
        )?)?;
    let expected_multiplicity = u64::from(
        crate::bgv::proof_suite::selected_profile::selected_proof_application_slot_ceilings()
            .map_err(|_| WhirTheoremCertificateError::InvalidSelectedGeometry)?
            .family_ceiling(ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER)
            .ok_or(WhirTheoremCertificateError::InvalidSelectedGeometry)?,
    );
    let one = ExactBigFraction::from_u64(1, 1)?;
    let expected_ordinary_gate = expected_classical_ceiling
        .multiply_integer(
            &(BigUint::from(expected_multiplicity) << CMS19_ADVERSARIAL_QUERY_EXPONENT),
        )?
        .less_than_or_equal(&one);
    let expected_transformed_gate = expected_classical_ceiling
        .multiply_integer(&(BigUint::from(expected_multiplicity * 12) << 176_usize))?
        .less_than_or_equal(&one);
    let expected_qrom_gate = expected_qrom_ceiling
        .multiply_u64(
            expected_multiplicity
                .checked_mul(4)
                .ok_or(WhirTheoremCertificateError::ArithmeticOverflow)?,
        )?
        .less_than_or_equal(&one);
    let expected_owner_count = expected_owner_rows.iter().try_fold(0_u64, |total, row| {
        total.checked_add(u64::try_from(row.transition_count).ok()?)
    });
    if certificate.owner_rows != expected_owner_rows
        || certificate.query_rows != expected_query_rows
        || certificate.theta_rows != expected_theta_rows
        || certificate.algebraic_rows != expected_algebraic_rows
        || certificate.extension_field_cardinality != expected_extension_field_cardinality
        || certificate.query_failure_probability_ceiling != expected_query_ceiling
        || certificate.algebraic_failure_probability_ceiling != expected_algebraic_ceiling
        || certificate.classical_failure_probability_ceiling != expected_classical_ceiling
        || certificate.qrom_failure_probability_ceiling != expected_qrom_ceiling
        || certificate.same_secret_family_multiplicity != expected_multiplicity
        || certificate.cms19_verifier_hash_query_count != cms19_arithmetic.verifier_hash_query_count
        || certificate.cms19_accepting_database_equation_count
            != cms19_arithmetic.accepting_database_equation_count
        || expected_owner_count != Some(logical_verifier_message_count)
        || certificate.all_failure_owners_mapped_once
            != exact_failure_owners_are_completely_mapped(
                &expected_owner_rows,
                &expected_query_rows,
                &expected_algebraic_rows,
            )
        || certificate.exact_query_products_bounded
            != expected_query_rows.iter().all(|row| {
                row.exact_without_replacement_probability
                    .less_than_or_equal(&row.power_probability_ceiling)
            })
        || certificate.ordinary_family_mass_gate_holds != expected_ordinary_gate
        || certificate.transformed_initial_mass_gate_holds != expected_transformed_gate
        || certificate.complete_qrom_mass_gate_holds != expected_qrom_gate
        || !certificate.is_complete()
    {
        return Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence);
    }
    Ok(())
}

#[cfg(test)]
fn checked_exact_failure_magnitude_with_fault(
    input: ExactFailureMagnitudeDerivationInput<'_>,
    fault: ExactFailureMagnitudeFault,
) -> Result<ExactFailureMagnitudeCertificate, WhirTheoremCertificateError> {
    derive_exact_failure_magnitude_certificate_with_mutation(input, |certificate| match fault {
        ExactFailureMagnitudeFault::DropFirstQueryRow => {
            certificate.query_rows.remove(0);
        }
        ExactFailureMagnitudeFault::ReduceFirstQueryAgreementCeiling => {
            certificate.query_rows[0].agreement_ceiling -= 1;
        }
        ExactFailureMagnitudeFault::DropRelationCompositionOwner => {
            certificate.algebraic_rows[1].owner_kinds.clear();
        }
        ExactFailureMagnitudeFault::ReduceAggregateWideBaseNumerator => {
            certificate.algebraic_rows[12].numerator -= BigUint::one();
        }
        ExactFailureMagnitudeFault::ChangeVerifierHashQueryCount => {
            certificate.cms19_verifier_hash_query_count += 1;
        }
    })
}

fn selected_same_secret_construction_plan() -> RowCodeWhirConstructionPlan {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected same-secret context exists");
    let compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives"),
        &context,
    )
    .expect("the selected same-secret relation compiles");
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the selected same-secret relation validates");
    RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .expect("the selected same-secret construction plan derives")
}

#[test]
fn production_construction_views_bind_every_physical_masking_map() {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected same-secret context exists");
    let compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives"),
        &context,
    )
    .expect("the selected same-secret relation compiles");
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the selected same-secret relation validates");
    let relation_variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the selected same-secret relation variant exists");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .expect("the selected same-secret construction derives");
    let certificate =
        derive_production_construction_masking_correspondence(&plan, relation_variant, &context)
            .expect("the production construction masking correspondence derives");

    assert!(certificate.is_complete_for(&plan, relation_variant, &context));
    assert_eq!(
        certificate.production_phase_order,
        [
            ConstructionMaskingPhase::Base,
            ConstructionMaskingPhase::Auxiliary,
            ConstructionMaskingPhase::Quotient,
        ]
    );
    assert_eq!(
        certificate.production_rank_requirements,
        [ConstructionMaskingRankRequirement {
            kind: ConstructionMaskingRankKind::RowPadEvaluation,
            source_dimension: 2_097_152,
            required_rank: 3_483,
            verification: ConstructionMaskingRankVerification::DistinctPointVandermonde,
        }]
    );
    assert_eq!(
        certificate.trace_chunk_placements.len(),
        certificate.expected_trace_chunks.len(),
    );
    assert_eq!(
        certificate.opened_polynomial_chunk_placements.len(),
        certificate.expected_opened_polynomial_chunks.len(),
    );
    assert_eq!(
        certificate.production_openings,
        certificate.relation_openings
    );
    assert_eq!(
        certificate.production_aggregate_opening_points,
        certificate.relation_aggregate_opening_points,
    );
    assert!(
        certificate
            .relation_graph
            .as_ref()
            .is_some_and(|graph| !graph.sources.is_empty() && !graph.views.is_empty())
    );

    let mut omitted_phase_chunk = certificate.clone();
    omitted_phase_chunk.trace_chunk_placements.remove(0);
    assert!(!omitted_phase_chunk.is_complete());

    let mut altered_quotient_coordinate = certificate.clone();
    altered_quotient_coordinate.opened_polynomial_chunk_placements[0]
        .key
        .extension_coordinate_ordinal += 1;
    assert!(!altered_quotient_coordinate.is_complete());

    let mut altered_telescoping_map = certificate.clone();
    let telescoping_dependency = altered_telescoping_map
        .production_views
        .iter_mut()
        .filter(|view| {
            matches!(
                view.identifier,
                ConstructionSecretViewIdentifier::Quotient { .. }
            )
        })
        .flat_map(|view| &mut view.direct_mask_dependencies)
        .find(|dependency| {
            matches!(
                dependency.source,
                ConstructionMaskSourceIdentifier::RelationMask {
                    purpose_class,
                    target_class,
                    ..
                } if purpose_class == RelationMaskKind::Telescoping as u16
                    && target_class
                        == RelationMaskTargetClass::QuotientComponent as u16
            )
        })
        .expect("the production quotient graph has a telescoping dependency");
    telescoping_dependency.coefficient = context.base_field_modulus - 2;
    assert!(!altered_telescoping_map.is_complete());

    let mut omitted_bound_opening = certificate.clone();
    let bound_opening_index = omitted_bound_opening
        .production_openings
        .iter()
        .position(|opening| {
            opening.source_class == RelationOpeningSourceClass::TreeColumn as u16
                && omitted_bound_opening
                    .production_bound_columns
                    .iter()
                    .any(|bound| {
                        bound.relation_tree_ordinal == opening.source_ordinal
                            && Some(bound.column_ordinal) == opening.column_ordinal
                    })
        })
        .expect("the selected same-secret construction has a bound opening");
    omitted_bound_opening
        .production_openings
        .remove(bound_opening_index);
    assert!(!omitted_bound_opening.is_complete());

    let mut altered_aggregate_batch = certificate.clone();
    altered_aggregate_batch
        .production_aggregate_opening_points
        .pop();
    assert!(!altered_aggregate_batch.is_complete());

    let mut deficient_row_pad_rank = certificate.clone();
    deficient_row_pad_rank.production_rank_requirements[0].required_rank += 1;
    assert!(!deficient_row_pad_rank.is_complete());

    let mut reused_row_pad = certificate.clone();
    let row_pad_source = reused_row_pad
        .production_sources
        .iter_mut()
        .find(|source| {
            matches!(
                source.identifier,
                ConstructionMaskSourceIdentifier::RowPad {
                    phase: ConstructionMaskingPhase::Base,
                }
            )
        })
        .expect("the selected same-secret construction has a base row pad");
    row_pad_source.authority = ConstructionMaskSourceAuthority::AuthenticatedPersistentObject;
    row_pad_source.lifetime = ConstructionMaskSourceLifetime::PersistentObject;
    row_pad_source.resume_rule = ConstructionMaskResumeRule::ImmutableAuthenticatedObject;
    assert!(!reused_row_pad.is_complete());

    let mut changed_query_schedule = plan.clone();
    let first_whir_query = changed_query_schedule
        .transcript_operations
        .iter_mut()
        .find(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal: 0 },
                    ..
                }
            )
        })
        .expect("the first WHIR query schedule exists");
    let RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } =
        first_whir_query
    else {
        unreachable!("the matching operation has the checked shape");
    };
    *output_count -= 1;
    assert_eq!(
        derive_production_construction_masking_correspondence(
            &changed_query_schedule,
            relation_variant,
            &context,
        ),
        Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
    );

    let mut omitted_production_chunk = plan;
    let first_chunk = omitted_production_chunk
        .base_phase
        .as_mut()
        .and_then(|phase| phase.rows.first_mut())
        .and_then(|row| row.logical_polynomial_chunks.first_mut())
        .expect("the selected base phase has a first physical chunk");
    *first_chunk = None;
    assert_eq!(
        derive_production_construction_masking_correspondence(
            &omitted_production_chunk,
            relation_variant,
            &context,
        ),
        Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
    );
}

#[test]
fn public_only_construction_has_physical_coverage_without_dummy_mask_sources() {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the collective-public-key context exists");
    let ring_degree = u64::try_from(crate::bgv::parameters::POLYNOMIAL_DEGREE)
        .expect("the selected ring degree fits u64");
    let ordered_component_moduli = (0..crate::bgv::parameters::DATA_PRIMES.len())
        .flat_map(|modulus_index| {
            let modulus_index =
                u16::try_from(modulus_index).expect("the selected data basis fits u16");
            [SuiteModulusReference::data(modulus_index); 2]
        })
        .collect();
    let compiled_plan = compile_collective_public_key_aggregate_relation_plan(
        &CollectivePublicKeyAggregatePlanInput {
            geometry: PublicAggregateRelationGeometry {
                ring_degree,
                evaluation_domain_size: ROW_CODE_WHIR_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: ROW_CODE_WHIR_OPENING_DEGREE_BOUND_EXCLUSIVE,
                public_polynomial_column_degree_bound_exclusive: ring_degree / 2,
                participant_count: crate::foundation::FOUNDATION_PROFILE.participant_count,
            },
            ordered_component_moduli,
        },
        &context,
    )
    .expect("the production collective-public-key relation compiles");
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the production collective-public-key relation validates");
    let relation_variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the collective-public-key variant exists");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(
        &artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .expect("the public-only production construction derives");
    let certificate =
        derive_production_construction_masking_correspondence(&plan, relation_variant, &context)
            .expect("the public-only physical correspondence derives");

    assert!(certificate.is_complete_for(&plan, relation_variant, &context));
    assert_eq!(certificate.proof_privacy_mode, ProofPrivacyMode::PublicOnly);
    assert!(certificate.relation_graph.is_none());
    assert!(certificate.production_sources.is_empty());
    assert!(certificate.production_views.is_empty());
    assert!(certificate.production_rank_requirements.is_empty());
    assert!(certificate.production_opening_batch_mask_source.is_none());
    assert!(certificate.production_aggregate_wide_pad_source.is_none());
    assert!(certificate.trace_chunk_placements.is_empty());
    assert!(!certificate.opened_polynomial_chunk_placements.is_empty());

    let mut dummy_public_mask = certificate;
    dummy_public_mask.production_aggregate_wide_pad_source =
        Some(ConstructionMaskSourceIdentifier::AggregateWidePad);
    assert!(!dummy_public_mask.is_complete());
}

#[test]
fn ballot_construction_views_bind_the_compact_physical_masking_map() {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected ballot context exists");
    let compiled_plan = selected_ballot_validity_relation_compilation()
        .expect("the selected ballot relation compiles")
        .into_relation_plan();
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the selected ballot relation validates");
    let relation_variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the selected ballot variant exists");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .expect("the selected ballot construction derives");
    let certificate =
        derive_production_construction_masking_correspondence(&plan, relation_variant, &context)
            .expect("the selected ballot construction correspondence derives");

    assert!(certificate.is_complete_for(&plan, relation_variant, &context));
    assert_eq!(certificate.logical_polynomials_per_physical_row, 8);
    assert_eq!(certificate.relation_aggregate_opening_points, [0, 1, 11]);
    assert_eq!(certificate.relation_all_opening_points.len(), 22);
    assert_eq!(
        certificate.production_aggregate_opening_points,
        certificate.relation_all_opening_points,
    );
    assert_eq!(
        certificate
            .production_views
            .iter()
            .filter(|view| matches!(
                view.identifier,
                ConstructionSecretViewIdentifier::Aggregate { .. }
            ))
            .count(),
        3,
    );

    let mut omitted_public_only_aggregate_coordinate = certificate;
    omitted_public_only_aggregate_coordinate
        .production_aggregate_opening_points
        .remove(2);
    assert!(!omitted_public_only_aggregate_coordinate.is_complete());
}

#[test]
fn production_aggregate_wide_views_bind_every_affine_and_nonlinear_catalog() {
    let plan = selected_same_secret_construction_plan();
    let configuration =
        super::super::hiding_whir::selected_hiding_whir_config(plan.selected_parameters())
            .expect("the selected hiding configuration derives");
    let masking = AggregateWideMaskingCertificate::derive(&configuration)
        .expect("the aggregate-wide masking certificate derives");
    let certificate = derive_production_aggregate_wide_view_correspondence(&plan, &masking)
        .expect("the production aggregate-wide view correspondence derives");

    assert!(certificate.is_complete_for(&plan, &masking));
    assert_eq!(certificate.affine_rows.len(), 15);
    assert_eq!(
        certificate
            .affine_rows
            .iter()
            .map(|row| (
                row.private_coordinate_count,
                row.joint_view_rank,
                row.conditional_entropy_dimension,
            ))
            .collect::<Vec<_>>(),
        [
            (9, 7, 2),
            (9, 7, 2),
            (9, 7, 2),
            (9, 7, 2),
            (9, 7, 2),
            (9, 7, 2),
            (3_483, 3_483, 0),
            (2_592, 2_592, 0),
            (2_412, 2_412, 0),
            (2_376, 2_376, 0),
            (2_367, 2_367, 0),
            (2_104, 2_104, 0),
            (393, 393, 0),
            (327, 327, 0),
            (1_917, 1_917, 0),
        ]
    );
    assert_eq!(certificate.transcript_affine_coordinate_count, 3_756);
    assert_eq!(certificate.primary_opened_affine_coordinate_count, 14_257);
    assert_eq!(certificate.derived_opened_affine_coordinate_count, 656);
    assert_eq!(
        certificate.delegated_opening_evaluation_coordinate_count,
        SAME_SECRET_SCALAR_OPENING_COUNT as usize
    );
    assert_eq!(certificate.transcript_derived_affine_coordinate_count, 6);
    assert_eq!(certificate.aggregate_wide_extension_challenge_count, 36);
    assert_eq!(certificate.aggregate_wide_distinct_query_vector_count, 7);
    assert_eq!(certificate.aggregate_wide_proof_of_work_witness_count, 0);
    assert_eq!(certificate.supplied_commitment_roles.len(), 9);
    assert_eq!(
        certificate
            .code_affine_maps
            .iter()
            .map(|row| (
                row.message_length_per_lane,
                row.randomness_length_per_lane,
                row.evaluation_domain_size,
                row.interleaving_width,
                row.shared_query_count,
                row.randomness_exponent_start,
                row.fixed_zero_suffix_length,
                row.evaluation_domain_logarithmic_size,
            ))
            .collect::<Vec<_>>(),
        [
            (2_097_152, 387, 8_388_608, 8, 387, 2_097_152, 6_291_069, 23),
            (262_144, 288, 4_194_304, 8, 288, 262_144, 3_931_872, 22),
            (32_768, 268, 2_097_152, 8, 268, 32_768, 2_064_116, 21),
            (4_096, 264, 1_048_576, 8, 264, 4_096, 1_044_216, 20),
            (512, 263, 524_288, 8, 263, 512, 523_513, 19),
            (64, 263, 262_144, 8, 263, 64, 261_817, 18),
            (1_524, 393, 8_192, 1, 393, 1_524, 6_275, 13),
            (64, 263, 262_144, 1, 263, 64, 261_817, 18),
            (1_524, 393, 8_192, 1, 393, 1_524, 6_275, 13),
        ],
    );
    assert_eq!(
        certificate
            .fold_affine_maps
            .iter()
            .map(|row| (
                row.epoch_ordinal,
                row.map.limb_count,
                row.map.input_coordinate_count_per_limb,
                row.map.output_coordinate_count,
                row.map.folding_variable_count,
            ))
            .collect::<Vec<_>>(),
        [
            (0, 8, 387, 387, 3),
            (1, 8, 288, 288, 3),
            (2, 8, 268, 268, 3),
            (3, 8, 264, 264, 3),
            (4, 8, 263, 263, 3),
            (5, 8, 263, 263, 3),
        ],
    );
    assert_eq!(certificate.derived_affine_identities.len(), 22);
    assert_eq!(certificate.chronology.len(), 30);
    assert_eq!(
        certificate.nonlinear_view_boundary,
        AggregateWideNonlinearViewBoundary {
            commitment_root_count: 9,
            compact_frontier_count: 9,
            code_switch_image_count: 5,
            fold_image_count: 6,
            hash_output_bit_length: 512,
        }
    );

    let mut deficient_rank = certificate.clone();
    deficient_rank.affine_rows[0].joint_view_rank -= 1;
    assert!(!deficient_rank.is_complete_for(&plan, &masking));

    let mut altered_sumcheck_map = certificate.clone();
    altered_sumcheck_map.affine_rows[0].rank_verification =
        AggregateWideJointAffineRankVerification::SumcheckConstantMinor {
            mask_count: 3,
            coefficients_per_mask: 3,
            visible_coordinate_count: 7,
            absolute_determinant: 1,
        };
    assert!(!altered_sumcheck_map.is_complete_for(&plan, &masking));

    let mut omitted_nonlinear_root = certificate.clone();
    omitted_nonlinear_root.supplied_commitment_roles.pop();
    assert!(!omitted_nonlinear_root.is_complete_for(&plan, &masking));

    let mut shifted_randomness_block = certificate.clone();
    shifted_randomness_block.code_affine_maps[0].randomness_exponent_start += 1;
    shifted_randomness_block.code_affine_maps[0].fixed_zero_suffix_length -= 1;
    assert!(!shifted_randomness_block.is_complete_for(&plan, &masking));

    let mut changed_fold_lane_count = certificate.clone();
    changed_fold_lane_count.fold_affine_maps[0].map.limb_count /= 2;
    assert!(!changed_fold_lane_count.is_complete_for(&plan, &masking));

    let mut wrong_fresh_source_query_epoch = certificate.clone();
    wrong_fresh_source_query_epoch.code_affine_maps[7].query_schedule =
        ProductionAggregateWideQuerySchedule::SourceEpoch { epoch_ordinal: 4 };
    assert!(!wrong_fresh_source_query_epoch.is_complete_for(&plan, &masking));

    let mut changed_query_schedule = plan.clone();
    let changed_query = changed_query_schedule
        .transcript_operations
        .iter_mut()
        .find(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal: 0 },
                    ..
                }
            )
        })
        .expect("the first WHIR query vector exists");
    let RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } = changed_query
    else {
        unreachable!("the matching operation has the checked shape");
    };
    *output_count -= 1;
    assert_eq!(
        derive_production_aggregate_wide_view_correspondence(&changed_query_schedule, &masking),
        Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
    );

    let mut omitted_reveal_coordinate = plan.clone();
    let omitted_reveal = omitted_reveal_coordinate
        .transcript_operations
        .iter_mut()
        .find(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                    role: RowCodeWhirObservationRole::BaseBlindedPadMessage,
                    ..
                }
            )
        })
        .expect("the fresh-pad reveal exists");
    let RowCodeWhirTranscriptOperation::ObserveExtensionValues { value_count, .. } = omitted_reveal
    else {
        unreachable!("the matching operation has the checked shape");
    };
    *value_count -= 1;
    assert_eq!(
        derive_production_aggregate_wide_view_correspondence(&omitted_reveal_coordinate, &masking),
        Err(WhirTheoremCertificateError::IncompleteMaskingCorrespondence),
    );

    let mut challenge_dependent_pad = certificate;
    challenge_dependent_pad.chronology.swap(2, 3);
    assert!(!challenge_dependent_pad.is_complete_for(&plan, &masking));
}

#[test]
fn production_row_pad_hybrid_refuses_256_bit_secret_prefixes() {
    let plan = selected_same_secret_construction_plan();
    let certificate = PrivateRowPadGeneratorHybridCertificate::derive(&plan)
        .expect("the production row-pad generator hybrid derives");

    assert!(certificate.is_complete_for_plan(&plan));
    assert_eq!(certificate.sampled_phase_seed_count, 3);
    assert_eq!(certificate.active_phase_seed_count, 3);
    assert_eq!(certificate.phase_seed_byte_length, 64);
    assert_eq!(certificate.phase_seed_material_byte_length, 192);
    assert_eq!(certificate.private_stream_block_byte_length, 64);
    assert_eq!(
        certificate
            .phase_rows
            .iter()
            .map(|phase| (phase.phase, phase.row_count))
            .collect::<Vec<_>>(),
        vec![
            (RowCodeWhirPhase::Base, 32),
            (RowCodeWhirPhase::Auxiliary, 15),
            (RowCodeWhirPhase::Quotient, 15),
        ],
    );
    assert!(
        certificate
            .phase_rows
            .iter()
            .all(|phase| phase.witness_values_per_row == 1 << 21)
    );
    assert_eq!(certificate.framed_xof_input_count, 62);
    assert_eq!(certificate.accepted_field_output_count, 130_023_424);
    assert_eq!(certificate.maximum_candidate_draws_per_output, 128);
    assert_eq!(certificate.maximum_candidate_draw_count, 16_642_998_272);
    assert_eq!(certificate.maximum_xof_output_byte_length, 133_143_986_176,);
    assert!(
        certificate
            .classical_action_root_guessing_advantage
            .is_at_most_inverse_power_of_two(432)
    );
    assert!(
        certificate
            .classical_action_root_guessing_advantage
            .is_greater_than_inverse_power_of_two(433)
    );
    assert!(
        certificate
            .quantum_action_root_search_advantage
            .is_at_most_inverse_power_of_two(350)
    );
    assert!(
        certificate
            .quantum_action_root_search_advantage
            .is_greater_than_inverse_power_of_two(351)
    );
    assert!(
        certificate
            .seed_collision_probability
            .is_at_most_inverse_power_of_two(510)
    );
    assert!(
        certificate
            .seed_collision_probability
            .is_greater_than_inverse_power_of_two(511)
    );
    assert!(
        certificate
            .classical_secret_prefix_replacement_advantage
            .is_at_most_inverse_power_of_two(430)
    );
    assert!(
        certificate
            .classical_secret_prefix_replacement_advantage
            .is_greater_than_inverse_power_of_two(431)
    );
    assert!(
        certificate
            .quantum_secret_prefix_replacement_advantage
            .is_at_most_inverse_power_of_two(173)
    );
    assert!(
        certificate
            .quantum_secret_prefix_replacement_advantage
            .is_greater_than_inverse_power_of_two(174)
    );
    assert!(
        certificate
            .rejection_sampler_exhaustion_probability
            .is_at_most_inverse_power_of_two(128)
    );

    let rejected_256_bit =
        PrivateRowPadGeneratorHybridCertificate::derive_with_seed_byte_length(&plan, 32)
            .expect("the rejected 256-bit candidate still has exact accounting");
    assert_eq!(rejected_256_bit.phase_seed_byte_length, 32);
    assert!(
        rejected_256_bit
            .quantum_secret_prefix_replacement_advantage
            .is_at_most_inverse_power_of_two(45)
    );
    assert!(
        rejected_256_bit
            .quantum_secret_prefix_replacement_advantage
            .is_greater_than_inverse_power_of_two(46)
    );
    assert!(
        !rejected_256_bit
            .quantum_secret_prefix_replacement_advantage
            .is_at_most_inverse_power_of_two(CMS19_ADVERSARIAL_QUERY_EXPONENT)
    );
    assert!(!rejected_256_bit.is_complete_for_plan(&plan));

    let mut wrong_domain = certificate.clone();
    wrong_domain.xof_domain.push(0);
    assert!(!wrong_domain.is_complete_for_plan(&plan));

    let mut missing_phase = certificate.clone();
    missing_phase.phase_rows.pop();
    assert!(!missing_phase.is_complete_for_plan(&plan));

    let mut noninjective_frames = certificate.clone();
    noninjective_frames.framed_xof_inputs_are_injective_given_distinct_phase_seeds = false;
    assert!(!noninjective_frames.is_complete_for_plan(&plan));

    let mut unbounded_quantum_replacement = certificate.clone();
    unbounded_quantum_replacement.quantum_secret_prefix_replacement_advantage =
        ExactBigFraction::from_u64(1, 1).expect("one is a valid exact fraction");
    assert!(!unbounded_quantum_replacement.is_complete_for_plan(&plan));

    let mut unbounded_action_root_search = certificate.clone();
    unbounded_action_root_search.quantum_action_root_search_advantage =
        ExactBigFraction::from_u64(1, 1).expect("one is a valid exact fraction");
    assert!(!unbounded_action_root_search.is_complete_for_plan(&plan));

    let mut reordered_phase_plan = plan.clone();
    reordered_phase_plan.phase_order.swap(0, 1);
    assert!(!certificate.is_complete_for_plan(&reordered_phase_plan));

    let mut changed_row_geometry_plan = plan.clone();
    changed_row_geometry_plan
        .base_phase
        .as_mut()
        .expect("the selected plan has a base phase")
        .geometry
        .row_count += 1;
    assert!(!certificate.is_complete_for_plan(&changed_row_geometry_plan));

    let mut public_only_plan = plan.clone();
    public_only_plan.proof_privacy_mode = ProofPrivacyMode::PublicOnly;
    let public_only_certificate =
        PrivateRowPadGeneratorHybridCertificate::derive(&public_only_plan)
            .expect("the public-only row-pad ledger derives");
    assert!(public_only_certificate.is_complete_for_plan(&public_only_plan));
    assert_eq!(public_only_certificate.sampled_phase_seed_count, 0);
    assert!(public_only_certificate.phase_rows.is_empty());
    assert_eq!(public_only_certificate.framed_xof_input_count, 0);
    assert_eq!(public_only_certificate.accepted_field_output_count, 0);

    let mut classical_block_replacement_in_quantum_ledger = certificate;
    classical_block_replacement_in_quantum_ledger.quantum_private_stream_hybrid[2].1 =
        MaskGeneratorHybridLoss::ComputationalReduction {
            assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
            key_bit_length: 512,
            classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
        };
    assert!(!classical_block_replacement_in_quantum_ledger.is_complete_for_plan(&plan));
}

fn assert_public_key_share_prefix_stacking_is_derived_from_its_production_plan(
    artifacts: &[ValidatedRelationPlanArtifact],
) {
    let artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected public-key-share relation artifact exists");
    let relation_variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .expect("the public-key-share relation has one variant");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(
        artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .expect("the selected public-key-share construction derives");
    let certificate =
        derive_prefix_stacking_certificate(&plan).expect("prefix stacking derives from the plan");
    let expected_scalar_opening_count = plan
        .opening_batches
        .iter()
        .map(|batch| batch.requested_aggregate_column_ordinals.len() as u64)
        .sum::<u64>();

    assert_eq!(certificate.source_table_count, 1);
    assert_eq!(certificate.committed_polynomial_count, 1);
    assert_eq!(certificate.table_width, plan.aggregate_table_width());
    assert_eq!(
        certificate.selector_variable_count,
        plan.parameters.polynomial_commitment_variable_count - plan.parameters.table_variable_count,
    );
    assert_eq!(certificate.opening_batch_count, plan.opening_batches.len());
    assert_eq!(
        certificate.scalar_opening_count,
        expected_scalar_opening_count
    );
    assert!(
        certificate.opening_batch_count != SAME_SECRET_OPENING_BATCH_COUNT
            || certificate.scalar_opening_count != SAME_SECRET_SCALAR_OPENING_COUNT,
        "the public-key-share geometry must not inherit same-secret opening constants",
    );

    let mut duplicate_column = plan.clone();
    let duplicated_ordinal =
        duplicate_column.opening_batches[0].requested_aggregate_column_ordinals[0];
    duplicate_column.opening_batches[0]
        .requested_aggregate_column_ordinals
        .push(duplicated_ordinal);
    assert_eq!(
        derive_prefix_stacking_certificate(&duplicate_column),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut changed_point_order = plan;
    changed_point_order.opening_batches[0].point_ordinal += 1;
    assert_eq!(
        derive_prefix_stacking_certificate(&changed_point_order),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );
}

fn assert_fixed_verifier_hash_rows_follow_each_relation_variant(
    artifacts: &[ValidatedRelationPlanArtifact],
) {
    let public_key_share_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected public-key-share relation artifact exists");
    let public_key_share_variant = public_key_share_artifact
        .compiled_plan()
        .variants()
        .first()
        .expect("the public-key-share relation has one variant");
    let public_key_share_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        public_key_share_artifact,
        public_key_share_variant.schedule_position(),
        public_key_share_variant.top_count(),
    )
    .expect("the selected public-key-share construction derives");
    let rows = derive_fixed_verifier_hash_rows(&public_key_share_plan, public_key_share_variant)
        .expect("fixed verifier hashes derive from the matching relation variant");
    let verifier_source_ordinals = public_key_share_variant
        .ordered_columns()
        .iter()
        .filter_map(|column| match column.origin() {
            RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                ..
            } => Some(*verifier_source_ordinal),
            _ => None,
        })
        .collect::<Vec<_>>();
    let distinct_verifier_source_ordinals = verifier_source_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let public_setup_row = rows
        .iter()
        .find(|row| row.role == FixedVerifierHashRole::PublicSetupVerifierSequence)
        .expect("the public setup verifier sequence has one ledger row");

    assert_eq!(rows.len(), 5);
    assert_eq!(
        public_setup_row.hash_query_count,
        verifier_source_ordinals.len() as u64
    );
    assert_eq!(
        public_setup_row.distinct_equation_count,
        distinct_verifier_source_ordinals.len() as u64
    );

    let collective_public_key_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected collective-public-key relation artifact exists");
    let collective_public_key_variant = collective_public_key_artifact
        .compiled_plan()
        .variants()
        .first()
        .expect("the collective-public-key relation has one variant");
    let collective_public_key_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        collective_public_key_artifact,
        collective_public_key_variant.schedule_position(),
        collective_public_key_variant.top_count(),
    )
    .expect("the selected collective-public-key construction derives");
    let collective_public_key_rows =
        derive_fixed_verifier_hash_rows(&collective_public_key_plan, collective_public_key_variant)
            .expect("the aggregate fixed-hash rows derive without an imaginary verifier sequence");
    assert_eq!(collective_public_key_rows.len(), 4);
    assert!(collective_public_key_rows.iter().all(|row| {
        row.role != FixedVerifierHashRole::PublicSetupVerifierSequence
            && row.hash_query_count == 1
            && row.distinct_equation_count == 1
    }));

    let same_secret_variant = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        })
        .and_then(|artifact| artifact.compiled_plan().variants().first())
        .expect("the selected same-secret relation variant exists");
    assert_eq!(
        derive_fixed_verifier_hash_rows(&public_key_share_plan, same_secret_variant),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
        "a fixed-hash ledger from another construction identity must refuse",
    );
}

fn assert_ballot_commitment_subtree_certificate_accepts_its_zero_bound_tree_geometry(
    artifacts: &[ValidatedRelationPlanArtifact],
) {
    let artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected ballot relation artifact exists");
    let relation_variant = artifact
        .compiled_plan()
        .variants()
        .first()
        .expect("the ballot relation has one variant");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(
        artifact,
        relation_variant.schedule_position(),
        relation_variant.top_count(),
    )
    .expect("the selected ballot construction derives");
    let merkle_rows =
        derive_merkle_oracle_equation_rows(&plan).expect("the ballot Merkle rows derive");
    let certificate = derive_commitment_subtree_extraction_certificate(&plan, &merkle_rows)
        .expect("the ballot subtree certificate derives");

    assert!(plan.bound_trees.is_empty());
    assert_eq!(certificate.bound_tree_root_count, 0);
    assert_eq!(
        certificate.supplied_commitment_root_count,
        certificate.rows.len(),
    );
    assert!(certificate.rows.iter().all(|row| {
        row.implementation != CoordinateDerivedOpeningImplementation::ExactBoundTree
    }));
    assert!(certificate.is_complete());
}

#[test]
fn every_width_64_construction_identity_has_a_complete_geometry_certificate() {
    let _certificate_test_guard = PRODUCTION_GEOMETRY_CERTIFICATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let artifacts = selected_relation_plans().expect("selected relation plans derive");
    assert_public_key_share_prefix_stacking_is_derived_from_its_production_plan(&artifacts);
    assert_fixed_verifier_hash_rows_follow_each_relation_variant(&artifacts);
    let inventory =
        checked_selected_row_code_whir_production_geometry_certificates(&artifacts, |plan| {
            plan.parameters.logical_polynomials_per_physical_row == 64
        })
        .expect("every width-64 production geometry certificate derives");
    let certificates = &inventory.records;
    assert_eq!(certificates.len(), 27);
    assert!(
        certificates
            .iter()
            .all(CheckedProductionGeometryCertificateRecord::is_complete)
    );

    let mut evaluator_top_counts = BTreeSet::new();
    for certificate in certificates {
        assert_eq!(
            certificate.parameters.logical_polynomials_per_physical_row,
            64
        );
        assert_eq!(certificate.parameters.row_code_log_inverse_rate, 2);
        if certificate.application_statement_schema_identifier
            == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        {
            evaluator_top_counts.insert(
                certificate
                    .top_count
                    .expect("every evaluator geometry carries its top count"),
            );
        }
    }
    assert_eq!(evaluator_top_counts, (1_u16..=20).collect::<BTreeSet<_>>());

    let same_secret = certificates
        .iter()
        .find(|certificate| {
            certificate.application_statement_schema_identifier
                == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the same-secret geometry certificate exists");
    assert_eq!(same_secret.maximum_transcript_hash_query_count, 1_141_598);
    assert_eq!(same_secret.logical_verifier_message_count, 4_272);
    assert_eq!(same_secret.deployed_verifier_hash_query_count, 1_232_362,);
    assert_eq!(
        same_secret.deployed_accepting_database_equation_count,
        1_229_573,
    );
}

#[test]
fn every_width_8_construction_identity_has_a_complete_geometry_certificate() {
    let _certificate_test_guard = PRODUCTION_GEOMETRY_CERTIFICATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let artifacts = selected_relation_plans().expect("selected relation plans derive");
    assert_ballot_commitment_subtree_certificate_accepts_its_zero_bound_tree_geometry(&artifacts);
    let inventory =
        checked_selected_row_code_whir_production_geometry_certificates(&artifacts, |plan| {
            plan.parameters.logical_polynomials_per_physical_row == 8
        })
        .expect("every width-8 production geometry certificate derives");
    let certificates = &inventory.records;
    assert_eq!(certificates.len(), 4);
    assert!(
        certificates
            .iter()
            .all(CheckedProductionGeometryCertificateRecord::is_complete)
    );
    assert!(certificates.iter().all(|certificate| {
        certificate.parameters.logical_polynomials_per_physical_row == 8
            && certificate.parameters.row_code_log_inverse_rate == 5
    }));
    assert_eq!(
        certificates
            .iter()
            .map(|certificate| certificate.application_statement_schema_identifier)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ]),
    );

    let vss_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected VSS relation artifact exists");
    let vss_variant = vss_artifact
        .compiled_plan()
        .variants()
        .first()
        .expect("the selected VSS relation has one variant");
    let vss_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected VSS context exists");
    let vss_certificate = certificates
        .iter()
        .find(|certificate| {
            certificate.application_statement_schema_identifier
                == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .expect("the selected VSS geometry certificate exists");
    let vss_masking_certificate = inventory
        .masking_certificates
        .iter()
        .find(|(parameters, _)| *parameters == vss_certificate.parameters)
        .map(|(_, certificate)| certificate)
        .expect("the VSS parameter class retains one masking certificate");
    let vss_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        vss_artifact,
        vss_variant.schedule_position(),
        vss_variant.top_count(),
    )
    .expect("the selected VSS construction derives");
    let changed_vss_plan_error = WhirTheoremCertificateError::SelectedProductionGeometry {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        schedule_position: vss_plan.schedule_position,
        top_count: vss_plan.top_count,
        stage: ProductionGeometryCertificateStage::ConstructionPlan,
        failure: ProductionGeometryCertificateFailure::InvalidSelectedGeometry,
    };

    let mut changed_coefficient_count = vss_plan.clone();
    changed_coefficient_count
        .parameters
        .logical_polynomial_coefficient_count /= 2;
    assert_eq!(
        checked_row_code_whir_production_geometry_certificate_with_masking(
            &changed_coefficient_count,
            vss_artifact,
            vss_variant,
            &vss_context,
            vss_masking_certificate,
        ),
        Err(changed_vss_plan_error),
    );

    let mut changed_transcript = vss_plan.clone();
    changed_transcript.transcript_operations.pop();
    assert_eq!(
        checked_row_code_whir_production_geometry_certificate_with_masking(
            &changed_transcript,
            vss_artifact,
            vss_variant,
            &vss_context,
            vss_masking_certificate,
        ),
        Err(changed_vss_plan_error),
    );

    let mut omitted_bound_tree = vss_plan;
    omitted_bound_tree.bound_trees.pop();
    assert_eq!(
        checked_row_code_whir_production_geometry_certificate_with_masking(
            &omitted_bound_tree,
            vss_artifact,
            vss_variant,
            &vss_context,
            vss_masking_certificate,
        ),
        Err(changed_vss_plan_error),
    );
}

#[test]
fn a_256_bit_transition_chain_refuses_a_uniform_512_bit_oracle_denominator() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the selected construction accounting derives");
    let rejected = derive_deployed_aggregate_leaf_oracle_certificate_with_output_widths(
        &plan,
        &certificate.aggregate_wide_masking,
        &certificate.complete_verifier_oracle_ledger,
        256,
        512,
    )
    .expect("the rejected predecessor call inventory derives");

    assert!(rejected.has_complete_call_inventory());
    assert_eq!(rejected.intermediate_oracle_output_bit_length, 256);
    assert_eq!(rejected.final_oracle_output_bit_length, 512);
    assert_eq!(rejected.minimum_oracle_output_bit_length, 256);
    assert_eq!(rejected.collision_penalty_denominator_bit_length, 256);
    assert!(!rejected.uniform_required_output_geometry_established);
    assert!(rejected.semantic_state_transitions.is_none());
    assert!(!rejected.semantic_state_transition_correspondence_established());
    assert!(!rejected.is_eligible_for_uniform_required_output());
    assert!(!rejected.classical_collision_penalty_is_below_inverse_power_of_two(128));
    assert!(!rejected.qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(128));
    assert!(
        (&rejected.classical_collision_penalty_numerator << 128_usize)
            < (BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    );
    assert!(
        (&rejected.qrom_ideal_oracle_penalty_numerator << 128_usize)
            < (BigUint::one() << CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH)
    );
}

#[test]
fn deployed_streaming_leaf_chain_uses_uniform_512_bit_oracle_outputs() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the selected construction accounting derives");
    let deployed = &certificate.deployed_aggregate_leaf_oracle;

    assert_eq!(
        ColumnStreamableLeafHasher::intermediate_output_bit_length(),
        512
    );
    assert_eq!(ColumnStreamableLeafHasher::final_output_bit_length(), 512);
    assert_eq!(deployed.intermediate_oracle_output_bit_length, 512);
    assert_eq!(deployed.final_oracle_output_bit_length, 512);
    assert_eq!(deployed.minimum_oracle_output_bit_length, 512);
    assert_eq!(deployed.collision_penalty_denominator_bit_length, 512);
    assert!(deployed.uniform_required_output_geometry_established);
    assert!(deployed.is_eligible_for_uniform_required_output());
    assert!(deployed.classical_collision_penalty_is_below_inverse_power_of_two(128));
    assert!(deployed.qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(128));
    assert!(
        certificate
            .cms19_applicability
            .semantic_state_transition_correspondence_established
    );
    let semantic = deployed
        .semantic_state_transitions
        .as_ref()
        .expect("the production semantic predecessor graph derives");
    assert!(semantic.is_complete_for_inventory(&deployed.rows));
    assert_eq!(
        semantic.frame_descriptors.map(|row| row.frame_tag),
        [0, 1, 2]
    );
    assert_eq!(
        semantic
            .frame_descriptors
            .map(|row| row.canonical_input_byte_length),
        [90, 194, 154],
    );
    assert_eq!(semantic.rows.len(), 62);
    assert_eq!(semantic.hash_query_count, 20_477);
    assert_eq!(semantic.accepting_database_equation_count_ceiling, 17_697);
    assert_eq!(semantic.maximum_predecessor_support_count, 1);

    let mut missing_transition = deployed.clone();
    missing_transition
        .semantic_state_transitions
        .as_mut()
        .expect("the semantic graph exists")
        .rows
        .pop();
    assert!(!missing_transition.semantic_state_transition_correspondence_established());

    let mut wrong_predecessor = deployed.clone();
    let transition = wrong_predecessor
        .semantic_state_transitions
        .as_mut()
        .expect("the semantic graph exists")
        .rows
        .iter_mut()
        .find(|row| {
            matches!(
                row.transition,
                AggregateLeafSemanticTransition::Column {
                    column_index: 0,
                    ..
                }
            )
        })
        .expect("the first transition exists");
    transition.predecessor = AggregateLeafSemanticPredecessor::None;
    assert!(!wrong_predecessor.semantic_state_transition_correspondence_established());

    let mut changed_frame = deployed.clone();
    changed_frame
        .semantic_state_transitions
        .as_mut()
        .expect("the semantic graph exists")
        .frame_descriptors[1]
        .frame_tag = 3;
    assert!(!changed_frame.semantic_state_transition_correspondence_established());

    let mut changed_schedule = deployed.clone();
    changed_schedule.rows[0].interleaving_width -= 1;
    assert!(!changed_schedule.semantic_state_transition_correspondence_established());

    assert!(certificate.cms19_applicability.is_complete());
    assert!(certificate.is_complete_construction_theorem());
}

#[test]
fn cms19_whole_state_and_database_support_are_exact_and_mutation_sensitive() {
    let plan = selected_same_secret_construction_plan();
    let catalog = plan
        .oracle_equation_catalog()
        .expect("the selected oracle-equation catalog derives");
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the selected construction theorem derives");
    let whole_state = &certificate.cms19_whole_state_transitions;
    let database_support = &certificate.cms19_whole_database_support;

    assert!(whole_state.is_complete_for(
        &plan,
        &catalog,
        &certificate.selected_plan_state_predicate,
    ));
    assert!(
        whole_state
            .matches_selected_plan_state_predicate(&certificate.selected_plan_state_predicate,)
    );
    assert_eq!(whole_state.rows.len(), catalog.operations.len());
    assert_eq!(
        whole_state.covered_transcript_equation_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        whole_state.verifier_message_fill_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
    );
    assert_eq!(
        whole_state.final_query_round_ordinal,
        whole_state
            .covered_bcs_round_count
            .checked_add(1)
            .expect("the selected BCS round count has a final query"),
    );
    let independently_counted_deterministic_observations = catalog
        .operations
        .iter()
        .filter(|operation| {
            matches!(
                &operation.kind,
                RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                    operation: RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. }
                        | RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                            role: RowCodeWhirObservationRole::OpeningPoint { .. },
                            ..
                        },
                    ..
                }
            )
        })
        .count();
    assert!(independently_counted_deterministic_observations > 0);
    assert_eq!(
        u64::try_from(independently_counted_deterministic_observations)
            .expect("the deterministic observation count fits u64"),
        whole_state.deterministic_observation_count,
    );
    assert_eq!(
        whole_state
            .rows
            .iter()
            .filter(|row| matches!(
                row.transition,
                Cms19SemanticStateTransition::VerifierMessageFill { .. }
            ))
            .count(),
        usize::try_from(SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT)
            .expect("the verifier-message count fits usize"),
    );
    let response_root_equation_slots = catalog
        .operations
        .iter()
        .flat_map(|operation| {
            operation
                .ranges
                .iter()
                .filter(|range| range.kind == RowCodeWhirOracleEquationRangeKind::ResponseRoot)
                .map(|range| {
                    operation
                        .first_equation_slot_ordinal
                        .checked_add(range.first_equation_offset)
                        .expect("the response-root equation slot fits u64")
                })
        })
        .collect::<BTreeSet<_>>();
    let response_digest_bindings = whole_state
        .rows
        .iter()
        .filter_map(|row| match row.transition {
            Cms19SemanticStateTransition::ProverOracle {
                binding:
                    Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { response_digest },
                ..
            }
            | Cms19SemanticStateTransition::DeterministicObservation {
                response_digest, ..
            }
            | Cms19SemanticStateTransition::TerminalDecision {
                response_digest, ..
            } => Some(response_digest),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(response_digest_bindings.len(), 2_059);
    assert!(response_digest_bindings.iter().all(|binding| {
        binding.response_root_domain == TRANSCRIPT_RESPONSE_ROOT_DOMAIN
            && binding.output_bit_length == CMS19_REQUIRED_ORACLE_OUTPUT_BIT_LENGTH
    }));
    let response_digest_slots = response_digest_bindings
        .iter()
        .map(|binding| binding.response_root_equation_slot_ordinal)
        .collect::<BTreeSet<_>>();
    assert_eq!(response_digest_slots, response_root_equation_slots);
    let bcs_complete_message_digest_count = whole_state
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::ProverOracle {
                    binding: Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { .. },
                    ..
                }
            )
        })
        .count();
    let deterministic_response_digest_count = whole_state
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::DeterministicObservation { .. }
            )
        })
        .count();
    let terminal_response_digest_count = whole_state
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::TerminalDecision { .. }
            )
        })
        .count();
    assert_eq!(bcs_complete_message_digest_count, 1_049);
    assert_eq!(deterministic_response_digest_count, 1_009);
    assert_eq!(terminal_response_digest_count, 1);
    assert_eq!(
        bcs_complete_message_digest_count
            + deterministic_response_digest_count
            + terminal_response_digest_count,
        response_digest_bindings.len(),
    );
    let expected_protocol_schedule_value_count = plan
        .transcript_operations
        .iter()
        .find_map(|operation| match operation {
            RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values } => {
                Some(canonical_values.len())
            }
            _ => None,
        })
        .expect("the selected plan has one protocol schedule");
    let expected_protocol_schedule_response_digest = whole_state
        .rows
        .iter()
        .find_map(|row| match row.transition {
            Cms19SemanticStateTransition::DeterministicObservation {
                owner: Cms19DeterministicObservationOwner::ProtocolSchedule,
                response_digest,
            } => Some(response_digest),
            _ => None,
        })
        .expect("the protocol schedule has one response digest");
    assert_eq!(
        expected_protocol_schedule_response_digest.message,
        Cms19CanonicalResponseMessage::ExtensionValueList {
            value_count: expected_protocol_schedule_value_count,
            canonical_message_byte_length: expected_protocol_schedule_value_count
                * PROOF_CHALLENGE_EXTENSION_DEGREE
                * std::mem::size_of::<u64>()
                + 6,
        },
    );
    let opening_point_response_digests = whole_state
        .rows
        .iter()
        .filter_map(|row| match row.transition {
            Cms19SemanticStateTransition::DeterministicObservation {
                owner: Cms19DeterministicObservationOwner::OpeningPoint { .. },
                response_digest,
            } => Some(response_digest),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(opening_point_response_digests.len(), 1_008);
    assert!(
        opening_point_response_digests
            .iter()
            .all(|response_digest| {
                response_digest.message
                    == (Cms19CanonicalResponseMessage::ExtensionValueList {
                        value_count: plan.parameters.table_variable_count,
                        canonical_message_byte_length: plan.parameters.table_variable_count
                            * PROOF_CHALLENGE_EXTENSION_DEGREE
                            * std::mem::size_of::<u64>()
                            + 6,
                    })
            })
    );
    let terminal_response_digest = whole_state
        .rows
        .iter()
        .find_map(|row| match row.transition {
            Cms19SemanticStateTransition::TerminalDecision {
                response_digest, ..
            } => Some(response_digest),
            _ => None,
        })
        .expect("the terminal proof stream has one response digest");
    assert_eq!(
        terminal_response_digest.message,
        Cms19CanonicalResponseMessage::CanonicalProofStream {
            proof_section_count: plan.proof_sections.len(),
            length_source:
                Cms19CanonicalProofLengthSource::TransportedHeaderValidatedByCanonicalDecoderAndStaticSectionLedger,
        },
    );
    for (operation, semantic_row) in catalog.operations.iter().zip(&whole_state.rows) {
        if matches!(
            semantic_row.transition,
            Cms19SemanticStateTransition::ProverOracle {
                binding: Cms19ProverOracleBinding::SuppliedCommitment { .. },
                ..
            }
        ) {
            assert!(
                operation
                    .ranges
                    .iter()
                    .all(|range| range.kind != RowCodeWhirOracleEquationRangeKind::ResponseRoot),
                "a supplied commitment root must not acquire a recomputed response-root equation",
            );
        }
    }

    let mut missing_deterministic_schedule = whole_state.clone();
    let deterministic_schedule_index = missing_deterministic_schedule
        .rows
        .iter()
        .position(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::DeterministicObservation {
                    owner: Cms19DeterministicObservationOwner::ProtocolSchedule,
                    ..
                }
            )
        })
        .expect("the deterministic protocol schedule has one semantic owner");
    missing_deterministic_schedule
        .rows
        .remove(deterministic_schedule_index);
    assert!(!missing_deterministic_schedule.is_complete());

    let mut opening_point_as_prover_oracle = whole_state.clone();
    let prover_oracle = whole_state
        .rows
        .iter()
        .find_map(|row| match row.transition {
            transition @ Cms19SemanticStateTransition::ProverOracle { .. } => Some(transition),
            _ => None,
        })
        .expect("the selected transcript has a prover-oracle transition");
    let opening_point_row = opening_point_as_prover_oracle
        .rows
        .iter_mut()
        .find(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::DeterministicObservation {
                    owner: Cms19DeterministicObservationOwner::OpeningPoint { .. },
                    ..
                }
            )
        })
        .expect("the selected transcript has a deterministic opening point");
    opening_point_row.transition = prover_oracle;
    assert!(!opening_point_as_prover_oracle.is_complete());

    let complete_message_digest_row_index = whole_state
        .rows
        .iter()
        .position(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::ProverOracle {
                    binding: Cms19ProverOracleBinding::CanonicalCompleteMessageDigest { .. },
                    ..
                }
            )
        })
        .expect("the selected transcript has a complete-message digest");
    let supplied_commitment_binding = whole_state
        .rows
        .iter()
        .find_map(|row| match row.transition {
            Cms19SemanticStateTransition::ProverOracle {
                binding: binding @ Cms19ProverOracleBinding::SuppliedCommitment { .. },
                ..
            } => Some(binding),
            _ => None,
        })
        .expect("the selected transcript has a supplied commitment");

    let mut omitted_complete_message_digest = whole_state.clone();
    let Cms19SemanticStateTransition::ProverOracle { binding, .. } =
        &mut omitted_complete_message_digest.rows[complete_message_digest_row_index].transition
    else {
        unreachable!("the selected row has the checked prover-oracle shape");
    };
    *binding = supplied_commitment_binding;
    assert!(!omitted_complete_message_digest.is_complete());

    let mut changed_complete_message_digest_width = whole_state.clone();
    let Cms19SemanticStateTransition::ProverOracle {
        binding:
            Cms19ProverOracleBinding::CanonicalCompleteMessageDigest {
                response_digest, ..
            },
        ..
    } = &mut changed_complete_message_digest_width.rows[complete_message_digest_row_index]
        .transition
    else {
        unreachable!("the selected row has the checked complete-message digest");
    };
    response_digest.output_bit_length = 256;
    assert!(!changed_complete_message_digest_width.is_complete());

    let mut changed_complete_message_digest_domain = whole_state.clone();
    let Cms19SemanticStateTransition::ProverOracle {
        binding:
            Cms19ProverOracleBinding::CanonicalCompleteMessageDigest {
                response_digest, ..
            },
        ..
    } = &mut changed_complete_message_digest_domain.rows[complete_message_digest_row_index]
        .transition
    else {
        unreachable!("the selected row has the checked complete-message digest");
    };
    response_digest.response_root_domain = "sealed-lattice/test/wrong-response-root-domain";
    assert!(!changed_complete_message_digest_domain.is_complete());

    let mut changed_response_root_equation_slot = whole_state.clone();
    let Cms19SemanticStateTransition::ProverOracle {
        binding:
            Cms19ProverOracleBinding::CanonicalCompleteMessageDigest {
                response_digest, ..
            },
        ..
    } = &mut changed_response_root_equation_slot.rows[complete_message_digest_row_index].transition
    else {
        unreachable!("the selected row has the checked complete-message digest");
    };
    response_digest.response_root_equation_slot_ordinal += 1;
    assert!(changed_response_root_equation_slot.is_complete());
    assert!(!changed_response_root_equation_slot.is_complete_for(
        &plan,
        &catalog,
        &certificate.selected_plan_state_predicate,
    ));

    let mut changed_protocol_schedule_digest_width = whole_state.clone();
    let changed_protocol_schedule_response_digest = changed_protocol_schedule_digest_width
        .rows
        .iter_mut()
        .find_map(|row| match &mut row.transition {
            Cms19SemanticStateTransition::DeterministicObservation {
                owner: Cms19DeterministicObservationOwner::ProtocolSchedule,
                response_digest,
            } => Some(response_digest),
            _ => None,
        })
        .expect("the protocol schedule has one mutable response digest");
    changed_protocol_schedule_response_digest.output_bit_length = 256;
    assert!(!changed_protocol_schedule_digest_width.is_complete());

    let mut changed_opening_point_digest_slot = whole_state.clone();
    let opening_point_response_digest = changed_opening_point_digest_slot
        .rows
        .iter_mut()
        .find_map(|row| match &mut row.transition {
            Cms19SemanticStateTransition::DeterministicObservation {
                owner: Cms19DeterministicObservationOwner::OpeningPoint { .. },
                response_digest,
            } => Some(response_digest),
            _ => None,
        })
        .expect("an opening point has one mutable response digest");
    opening_point_response_digest.response_root_equation_slot_ordinal += 1;
    assert!(changed_opening_point_digest_slot.is_complete());
    assert!(!changed_opening_point_digest_slot.is_complete_for(
        &plan,
        &catalog,
        &certificate.selected_plan_state_predicate,
    ));

    let mut changed_terminal_message_kind = whole_state.clone();
    let terminal_response_digest = changed_terminal_message_kind
        .rows
        .iter_mut()
        .find_map(|row| match &mut row.transition {
            Cms19SemanticStateTransition::TerminalDecision {
                response_digest, ..
            } => Some(response_digest),
            _ => None,
        })
        .expect("the terminal proof stream has one mutable response digest");
    terminal_response_digest.message = expected_protocol_schedule_response_digest.message;
    assert!(!changed_terminal_message_kind.is_complete());

    let mut changed_terminal_section_count = whole_state.clone();
    let terminal_response_digest = changed_terminal_section_count
        .rows
        .iter_mut()
        .find_map(|row| match &mut row.transition {
            Cms19SemanticStateTransition::TerminalDecision {
                response_digest, ..
            } => Some(response_digest),
            _ => None,
        })
        .expect("the terminal proof stream has one mutable response digest");
    let Cms19CanonicalResponseMessage::CanonicalProofStream {
        proof_section_count,
        ..
    } = &mut terminal_response_digest.message
    else {
        unreachable!("the terminal response has the checked proof-stream shape");
    };
    *proof_section_count -= 1;
    assert!(changed_terminal_section_count.is_complete());
    assert!(!changed_terminal_section_count.is_complete_for(
        &plan,
        &catalog,
        &certificate.selected_plan_state_predicate,
    ));

    let mut missing_sampler_terminal_block = whole_state.clone();
    let sampled_blocks = missing_sampler_terminal_block
        .rows
        .iter_mut()
        .find_map(|row| match &mut row.transition {
            Cms19SemanticStateTransition::VerifierMessageFill {
                block_count,
                terminal_round_ordinal,
                ..
            } if *block_count > 1 => Some((block_count, terminal_round_ordinal)),
            _ => None,
        })
        .expect("the selected transcript has a multi-block verifier fill");
    *sampled_blocks.0 -= 1;
    *sampled_blocks.1 -= 1;
    assert!(!missing_sampler_terminal_block.is_complete());

    let mut wrong_failure_owner = whole_state.clone();
    let distinct_failure_owners = whole_state
        .rows
        .iter()
        .filter_map(|row| match row.transition {
            Cms19SemanticStateTransition::VerifierMessageFill {
                failure_event_owner,
                ..
            } => Some(failure_event_owner),
            _ => None,
        })
        .collect::<Vec<_>>();
    let first_failure_owner = distinct_failure_owners
        .first()
        .copied()
        .expect("the selected transcript has one failure owner");
    let replacement_failure_owner = distinct_failure_owners
        .iter()
        .copied()
        .find(|owner| *owner != first_failure_owner)
        .expect("the selected transcript has distinct failure owners");
    let changed_failure_transition = wrong_failure_owner
        .rows
        .iter_mut()
        .find(|row| {
            matches!(
                row.transition,
                Cms19SemanticStateTransition::VerifierMessageFill {
                    failure_event_owner,
                    ..
                } if failure_event_owner == first_failure_owner
            )
        })
        .expect("the first failure owner has one transition");
    let Cms19SemanticStateTransition::VerifierMessageFill {
        failure_event_owner,
        ..
    } = &mut changed_failure_transition.transition
    else {
        unreachable!("the matching transition has the checked shape");
    };
    *failure_event_owner = replacement_failure_owner;
    assert!(
        !wrong_failure_owner
            .matches_selected_plan_state_predicate(&certificate.selected_plan_state_predicate,)
    );
    assert!(!wrong_failure_owner.is_complete_for(
        &plan,
        &catalog,
        &certificate.selected_plan_state_predicate,
    ));

    let mut changed_terminal_query = whole_state.clone();
    changed_terminal_query.final_query_round_ordinal += 1;
    assert!(!changed_terminal_query.is_complete());

    assert!(database_support.is_complete());
    assert_eq!(
        database_support.mapped_hash_query_count,
        certificate
            .deployed_aggregate_leaf_oracle
            .deployed_verifier_hash_query_count,
    );
    assert_eq!(
        database_support.mapped_accepting_database_equation_count,
        certificate
            .deployed_aggregate_leaf_oracle
            .deployed_accepting_database_equation_count,
    );
    assert_eq!(database_support.uncovered_hash_query_count(), Some(0));
    assert_eq!(
        database_support.uncovered_accepting_database_equation_count(),
        Some(0),
    );
    let response_root_database_row = database_support
        .rows
        .iter()
        .find(|row| {
            row.role
                == (Cms19DatabaseSupportRole::TypedTranscript {
                    role: OracleEquationRole::ResponseRoot,
                })
        })
        .expect("the response-root database-support row derives");
    assert_eq!(response_root_database_row.hash_query_count, 2_059);
    assert_eq!(
        response_root_database_row.accepting_database_equation_count,
        u64::try_from(response_digest_slots.len()).expect("the response-digest count fits u64"),
    );
    assert_eq!(response_root_database_row.predecessor_support_count, 0);
    let aggregate_initial_rows = database_support
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.role,
                Cms19DatabaseSupportRole::AggregateLeafInitial { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        aggregate_initial_rows.len(),
        usize::try_from(
            certificate
                .deployed_aggregate_leaf_oracle
                .distinct_initial_equation_count,
        )
        .expect("the initial-equation count fits usize"),
    );
    assert_eq!(
        aggregate_initial_rows
            .iter()
            .map(|row| row.hash_query_count)
            .sum::<u64>(),
        certificate
            .deployed_aggregate_leaf_oracle
            .rows
            .iter()
            .map(|row| row.initial_hash_query_count)
            .sum::<u64>(),
    );
    assert_eq!(
        aggregate_initial_rows
            .iter()
            .map(|row| row.accepting_database_equation_count)
            .sum::<u64>(),
        certificate
            .deployed_aggregate_leaf_oracle
            .distinct_initial_equation_count,
    );

    let mut omitted_database_role = database_support.clone();
    omitted_database_role.rows.pop();
    assert!(!omitted_database_role.is_complete());

    let mut repeated_initial_as_distinct_equations = database_support.clone();
    let initial_row = repeated_initial_as_distinct_equations
        .rows
        .iter_mut()
        .find(|row| {
            matches!(
                row.role,
                Cms19DatabaseSupportRole::AggregateLeafInitial { .. }
            )
        })
        .expect("the database support has an aggregate initial row");
    initial_row.accepting_database_equation_count = initial_row.hash_query_count;
    assert!(!repeated_initial_as_distinct_equations.is_complete());

    let mut changed_response_root_count = database_support.clone();
    let response_root_row = changed_response_root_count
        .rows
        .iter_mut()
        .find(|row| {
            row.role
                == (Cms19DatabaseSupportRole::TypedTranscript {
                    role: OracleEquationRole::ResponseRoot,
                })
        })
        .expect("the response-root support row exists");
    response_root_row.hash_query_count += 1;
    assert!(!changed_response_root_count.is_complete());

    let mut oversized_parent_support = database_support.clone();
    let parent_row = oversized_parent_support
        .rows
        .iter_mut()
        .find(|row| matches!(row.role, Cms19DatabaseSupportRole::MerkleParents { .. }))
        .expect("the database support has a Merkle-parent row");
    parent_row.predecessor_support_count = 3;
    assert!(!oversized_parent_support.is_complete());

    let mut altered_mapped_hash_count = database_support.clone();
    altered_mapped_hash_count.mapped_hash_query_count += 1;
    assert!(!altered_mapped_hash_count.is_complete());

    let mut theorem_with_wrong_failure_owner = certificate.clone();
    theorem_with_wrong_failure_owner.cms19_whole_state_transitions = wrong_failure_owner;
    assert!(!theorem_with_wrong_failure_owner.is_complete_construction_theorem());
}

#[test]
fn ballot_width_eight_has_complete_semantic_state_and_database_support() {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected ballot context exists");
    let compiled_plan = selected_ballot_validity_relation_compilation()
        .expect("the selected ballot relation compiles")
        .into_relation_plan();
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
        .expect("the selected ballot relation validates");
    let relation_variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the selected ballot relation variant exists");
    let plan = RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
        .expect("the selected ballot construction derives");
    let configuration =
        super::super::hiding_whir::selected_hiding_whir_config(plan.selected_parameters())
            .expect("the ballot hiding configuration derives");
    let aggregate_wide_masking = AggregateWideMaskingCertificate::derive(&configuration)
        .expect("the ballot aggregate-wide masking certificate derives");
    let whir_geometry = derive_production_whir_geometry_certificate(&plan, &aggregate_wide_masking)
        .expect("the ballot WHIR geometry derives");
    let catalog = plan
        .oracle_equation_catalog()
        .expect("the ballot oracle-equation catalog derives");
    let (state_epoch_rows, oracle_equation_rows) =
        derive_state_and_equation_rows(&catalog).expect("the ballot state rows derive");
    let selected_plan_state_predicate = derive_selected_plan_state_predicate_certificate(
        &plan,
        &catalog,
        &state_epoch_rows,
        &whir_geometry.code_state_rows,
    )
    .expect("the ballot state predicate derives");
    let whole_state = derive_cms19_whole_state_transition_certificate(
        &plan,
        &catalog,
        &selected_plan_state_predicate,
    )
    .expect("the ballot whole-state correspondence derives");
    let transcript_equation_count = catalog
        .maximum_equation_count()
        .expect("the ballot transcript equation count derives");
    let transcript_hash_query_count = catalog
        .maximum_transcript_hash_query_count()
        .expect("the ballot transcript hash-query count derives");
    let verifier_ledger = derive_complete_verifier_oracle_ledger(
        &plan,
        relation_variant,
        transcript_equation_count,
        transcript_hash_query_count,
    )
    .expect("the ballot verifier ledger derives");
    let deployed_leaf_oracle = derive_deployed_aggregate_leaf_oracle_certificate(
        &plan,
        &aggregate_wide_masking,
        &verifier_ledger,
    )
    .expect("the ballot deployed leaf inventory derives");
    let database_support = derive_cms19_whole_database_support_certificate(
        &plan,
        &verifier_ledger,
        &deployed_leaf_oracle,
        &whole_state,
        &oracle_equation_rows,
    )
    .expect("the ballot database-support correspondence derives");

    assert_eq!(
        plan.selected_parameters()
            .logical_polynomials_per_physical_row,
        8
    );
    assert!(whole_state.is_complete_for(&plan, &catalog, &selected_plan_state_predicate,));
    assert!(database_support.is_complete());
    assert_eq!(
        database_support.mapped_hash_query_count,
        deployed_leaf_oracle.deployed_verifier_hash_query_count,
    );
    assert_eq!(
        database_support.mapped_accepting_database_equation_count,
        deployed_leaf_oracle.deployed_accepting_database_equation_count,
    );
}

#[test]
fn one_transition_collision_propagates_through_the_shared_suffix_and_final_digest() {
    fn transition(state: u16, column_ordinal: usize, value: u16) -> u16 {
        if column_ordinal == 0 {
            value & 1
        } else {
            state.wrapping_mul(257).wrapping_add(value)
        }
    }
    fn leaf(values: &[u16]) -> u16 {
        let mut state = 19_u16;
        for (column_ordinal, value) in values.iter().copied().enumerate() {
            state = transition(state, column_ordinal, value);
        }
        state
            .wrapping_mul(769)
            .wrapping_add(u16::try_from(values.len()).expect("the test leaf width fits in u16"))
    }

    let first = [1_u16, 23, 29, 31];
    let second = [3_u16, 23, 29, 31];
    assert_ne!(first, second);
    assert_eq!(
        transition(19, 0, first[0]),
        transition(19, 0, second[0]),
        "the mock oracle supplies the one transition collision",
    );
    assert_eq!(
        leaf(&first),
        leaf(&second),
        "deterministic later transitions and finalization cannot repair a collided state",
    );
}

#[test]
fn generated_selected_whir_failure_partition_is_exact_and_mutation_sensitive() {
    let plan = selected_same_secret_construction_plan();
    let certificate = checked_row_code_whir_failure_partition(&plan)
        .expect("the checked WHIR theorem certificate derives");

    let mut challenge_kind_counts = [0_usize; 19];
    for owner in certificate
        .selected_plan_state_predicate
        .transition_rows
        .iter()
        .filter_map(|row| row.failure_event_owner)
    {
        let kind = match owner {
            SelectedPlanFailureEventOwner::CommonProductChallenge {
                challenge: CommonProofChallenge::Theta { .. },
            } => 0,
            SelectedPlanFailureEventOwner::CommonProductChallenge {
                challenge: CommonProofChallenge::Alpha { .. },
            } => 1,
            SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                challenge: CommonProofChallenge::Composition { .. },
            } => 2,
            SelectedPlanFailureEventOwner::CommonExtensionChallenge {
                challenge: CommonProofChallenge::OutOfDomainPoint { .. },
            } => 3,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::PointSelectorWeight { .. },
            } => 4,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::TraceColumnGroupWeight { .. },
            } => 5,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::QuotientGroupWeight { .. },
            } => 6,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::OpeningBatchMaskWeight { .. },
            } => 7,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::BoundOpeningWeight { .. },
            } => 8,
            SelectedPlanFailureEventOwner::DirectExtensionChallenge {
                challenge: RowCodeWhirChallenge::BoundDegreeCoordinate { .. },
            } => 9,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::Outer,
            } => 10,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::Bound,
            } => 11,
            SelectedPlanFailureEventOwner::DistinctQueryVector {
                role: RowCodeWhirQueryRole::WhirEpoch { .. },
            } => 12,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::OpeningBatching,
            } => 13,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { .. },
            } => 14,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::MaskedSumcheckRound { .. },
            } => 15,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::RoundCheckpoint { .. },
            } => 16,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::RoundCombination { .. },
            } => 17,
            SelectedPlanFailureEventOwner::WhirExtensionChallenge {
                role: RowCodeWhirExtensionRole::BaseCaseBlinding,
            } => 18,
            _ => unreachable!("selected failure owner is outside the closed schedule"),
        };
        challenge_kind_counts[kind] += 1;
    }
    assert_eq!(
        challenge_kind_counts,
        [
            3, 0, 4_046, 1, 18, 63, 1, 1, 44, 50, 1, 1, 7, 1, 6, 18, 5, 5, 1
        ],
    );

    assert_eq!(certificate.code_state_rows.len(), 24);
    assert_eq!(certificate.fold_rows.len(), 18);
    assert_eq!(certificate.shift_rows.len(), 5);
    assert_eq!(
        certificate
            .fold_rows
            .chunks(3)
            .map(|rows| {
                rows.iter().try_fold(0_u64, |total, row| {
                    total.checked_add(row.total_numerator().expect("row numerator"))
                })
            })
            .collect::<Option<Vec<_>>>(),
        Some(vec![
            58_720_265, 29_360_137, 14_680_073, 7_340_041, 3_670_025, 1_835_017,
        ]),
    );
    assert_eq!(certificate.fold_numerator(), Ok(115_605_558));
    assert_eq!(
        certificate
            .shift_rows
            .iter()
            .map(|row| row.algebraic_numerator)
            .collect::<Vec<_>>(),
        [388, 289, 269, 265, 264],
    );
    assert_eq!(certificate.shift_numerator(), Ok(1_475));
    assert_eq!(certificate.initial_constraint_batch_numerator(), 1_781);
    assert_eq!(certificate.final_sumcheck_numerator(), 0);
    assert_eq!(certificate.final_query_row.epoch_ordinal, 5);
    assert_eq!(certificate.final_query_row.query_count, 263);
    // The terminal source code includes 64 logical coefficients and 263
    // private encoding coefficients. Its domain is `262,144`, dimension is
    // therefore `327`, and a false state agrees in at most `131,236`
    // positions, or `32,809 / 65,536` in lowest terms.
    assert_eq!(
        certificate.final_query_row.bad_agreement,
        ExactFraction::new(32_809, 65_536).expect("the fraction is valid"),
    );
    assert_eq!(certificate.prefix_stacking.source_table_count, 1);
    assert_eq!(certificate.prefix_stacking.committed_polynomial_count, 1);
    assert_eq!(certificate.prefix_stacking.table_variable_count, 22);
    assert_eq!(certificate.prefix_stacking.selector_variable_count, 2);
    assert_eq!(certificate.prefix_stacking.stacked_variable_count, 24);
    assert_eq!(certificate.prefix_stacking.table_width, 4);
    assert_eq!(certificate.prefix_stacking.opening_batch_count, 1_008);
    assert_eq!(certificate.prefix_stacking.scalar_opening_count, 1_782);
    assert_eq!(certificate.prefix_stacking.selector_indices, [0, 1, 2, 3]);
    assert!(certificate.code_state_rows.iter().all(|row| {
        row.domain_size > row.dimension
            && row.minimum_distance == row.domain_size - row.dimension + 1
            && row.unique_decoding_radius * 2 < row.minimum_distance
            && row.selected_state_error_count_ceiling < row.unique_decoding_radius
            && row
                .selected_state_relative_distance
                .less_than(row.theorem_five_two_strict_distance_ceiling)
                .expect("the selected radius is strictly inside the theorem interval")
            && row.reed_solomon_rate.numerator > 0
            && row.reed_solomon_rate.denominator > 0
            && row.false_state_minimum_error_count == row.selected_state_error_count_ceiling + 1
            && row.false_state_agreement_ceiling
                == ExactFraction::new(
                    row.domain_size - row.false_state_minimum_error_count,
                    row.domain_size,
                )
                .expect("the false-state agreement ceiling derives")
            && row.unique_decoding_list_size_ceiling == 1
    }));
    assert_eq!(
        certificate
            .fold_rows
            .iter()
            .map(|row| (row.epoch_ordinal, row.fold_ordinal))
            .collect::<Vec<_>>(),
        (0_u32..6)
            .flat_map(|epoch_ordinal| {
                (1_u32..=3).map(move |fold_ordinal| (epoch_ordinal, fold_ordinal))
            })
            .collect::<Vec<_>>(),
    );
    assert!(certificate.fold_rows.iter().all(|row| {
        row.transcript_operation_ordinal > 0
            && row.target_domain_size == row.mutual_correlated_agreement_numerator
            && row.sumcheck_numerator == 3
    }));
    assert!(certificate.shift_rows.iter().all(|row| {
        row.transcript_operation_ordinal > 0
            && row.list_size == 1
            && row.algebraic_numerator == row.query_count + 1
    }));
    assert_eq!(
        certificate
            .shift_rows
            .iter()
            .map(|row| row.round_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3, 4],
    );
    assert_eq!(
        certificate.maximum_transcript_hash_query_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate.logical_verifier_message_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
    );
    let transcript_role_equation_count = |role| {
        certificate
            .oracle_equation_rows
            .iter()
            .filter(|row| row.role_pattern == OracleEquationRolePattern::Single(role))
            .map(|row| row.equation_count)
            .sum::<u64>()
    };
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseRoot),
        2_059,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseBinding),
        2_034,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ResponseAbsorption),
        2_071,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::AcceptedChallenge),
        4_272,
    );
    assert_eq!(
        transcript_role_equation_count(OracleEquationRole::ChallengeHandle),
        4_272,
    );
    let verifier_ledger = &certificate.complete_verifier_oracle_ledger;
    assert_eq!(verifier_ledger.transcript_equation_count, 1_141_598);
    assert_eq!(verifier_ledger.transcript_hash_query_count, 1_141_598);
    assert_eq!(verifier_ledger.merkle_rows.len(), 23);
    assert_eq!(
        verifier_ledger.merkle_rows[..3]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Base,
                },
                16_777_216,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Auxiliary,
                },
                16_777_216,
                387,
            ),
            (
                MerkleOracleEquationRole::RelationPhase {
                    phase: RowCodeWhirPhase::Quotient,
                },
                16_777_216,
                387,
            ),
        ],
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..20]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 0 },
                8_388_608,
                387,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 1 },
                4_194_304,
                288,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 2 },
                2_097_152,
                268,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 3 },
                1_048_576,
                264,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 4 },
                524_288,
                263,
            ),
            (
                MerkleOracleEquationRole::WhirEpoch { epoch_ordinal: 5 },
                262_144,
                263,
            ),
        ],
    );
    assert_eq!(
        verifier_ledger.merkle_rows[20..]
            .iter()
            .map(|row| (row.role, row.leaf_count, row.query_count))
            .collect::<Vec<_>>(),
        [
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::AggregateWidePad,
                },
                8_192,
                393,
            ),
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshSource,
                },
                262_144,
                263,
            ),
            (
                MerkleOracleEquationRole::AggregateWideMask {
                    commitment_role:
                        linear_bcs_transcript::LinearBcsCommittedOracleRole::BaseFreshPad,
                },
                8_192,
                393,
            ),
        ],
    );
    assert!(
        verifier_ledger
            .merkle_rows
            .iter()
            .all(|row| row.predecessor_support_ceiling <= 2)
    );
    assert_eq!(verifier_ledger.merkle_hash_query_count(), Ok(73_047));
    assert_eq!(
        verifier_ledger.merkle_rows[..3]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("phase row count"))
            }),
        Some(20_109),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[3..14]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("bound row count"))
            }),
        Some(19_767),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[14..20]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("WHIR row count"))
            }),
        Some(25_078),
    );
    assert_eq!(
        verifier_ledger.merkle_rows[20..]
            .iter()
            .try_fold(0_u64, |total, row| {
                total.checked_add(row.hash_query_count().expect("mask row count"))
            }),
        Some(8_093),
    );
    assert_eq!(verifier_ledger.fixed_hash_rows.len(), 5);
    assert_eq!(verifier_ledger.fixed_hash_query_count(), Ok(22));
    assert_eq!(verifier_ledger.fixed_distinct_equation_count(), Ok(13));
    assert_eq!(verifier_ledger.fixed_new_equation_count(), Ok(13));
    assert!(
        verifier_ledger
            .fixed_hash_rows
            .iter()
            .all(|row| row.transcript_catalog_equation_overlap_count == 0),
    );
    // Both complete ceilings are the transcript ceiling plus the plan's Merkle
    // ceiling of `73,047` plus the fixed rows: `1,141,598 + 73,047 + 13 =
    // 1,214,658` equations and `1,141,598 + 73,047 + 22 = 1,214,667` hash
    // queries. The Merkle and fixed components are independent of the
    // transcript catalog, and the two totals now differ only by the fixed
    // distinct-equation and hash-query rows because the catalog charges one
    // equation per hash query.
    assert_eq!(verifier_ledger.complete_equation_count_ceiling, 1_214_658);
    assert_eq!(verifier_ledger.complete_hash_query_count, 1_214_667);
    assert!(certificate.commitment_subtree_extraction.is_complete());
    assert_eq!(certificate.commitment_subtree_extraction.rows.len(), 23);
    assert_eq!(
        certificate
            .commitment_subtree_extraction
            .supplied_commitment_root_count,
        12,
    );
    assert!(
        certificate
            .commitment_subtree_extraction
            .canonical_complete_message_digest_count
            > 0,
    );
    assert!(
        certificate
            .commitment_subtree_extraction
            .one_edge_sampler_message_count
            > 0,
    );
    // The compiler query ceiling is the full adversarial budget plus every
    // deployed verifier hash query on an accepting path, including the initial,
    // transition, and final calls hidden by the abstract one-call leaf row.
    assert_eq!(
        certificate.cms19_arithmetic.compiler_query_bound,
        ((BigUint::from(1_u8) << 80_usize) - BigUint::from(1_u8))
            + BigUint::from(
                certificate
                    .deployed_aggregate_leaf_oracle
                    .deployed_verifier_hash_query_count,
            ),
    );
    assert_eq!(
        certificate.cms19_arithmetic.adversarial_query_bound,
        (BigUint::from(1_u8) << 80_usize) - BigUint::from(1_u8),
    );
    assert_eq!(
        certificate.cms19_arithmetic.verifier_hash_query_count,
        1_232_362
    );
    assert_eq!(
        certificate
            .cms19_arithmetic
            .accepting_database_equation_count,
        1_229_573,
    );
    assert_eq!(
        certificate.cms19_arithmetic.classical_soundness_multiplier,
        BigUint::from(12_u8)
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound,
    );
    assert_eq!(
        certificate.cms19_arithmetic.ideal_oracle_penalty_numerator,
        BigUint::from(48_u8)
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound
            * &certificate.cms19_arithmetic.compiler_query_bound
            + BigUint::from(2_u8) * BigUint::from(1_229_573_u64),
    );
    assert_eq!(
        certificate
            .cms19_arithmetic
            .ideal_oracle_penalty_denominator_bit_length,
        512,
    );
    assert_eq!(
        certificate.cms19_applicability.transform,
        Cms19Transform::OriginalBcsStrongStateHashChainSectionEightSix,
    );
    assert_eq!(
        certificate.cms19_applicability.transcript_equation_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate.cms19_applicability.transcript_hash_query_count,
        SELECTED_TRANSCRIPT_HASH_QUERY_COUNT,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .claimed_complete_equation_count,
        1_229_573,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .claimed_complete_hash_query_count,
        1_232_362,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .equation_count_without_catalog_correspondence,
        0,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .hash_query_count_without_catalog_correspondence,
        0,
    );
    assert_eq!(
        certificate
            .cms19_applicability
            .transcript_predecessor_support_ceiling,
        2,
    );
    assert!(
        certificate
            .cms19_applicability
            .complete_state_predicate_established
    );
    assert!(
        certificate
            .cms19_applicability
            .syntactic_proposition_eight_twelve_partition_catalogued
    );
    assert!(
        certificate
            .cms19_applicability
            .proposition_eight_twelve_case_split_established
    );
    assert!(
        certificate
            .cms19_applicability
            .complete_query_ledger_correspondence_established
    );
    assert!(
        certificate
            .cms19_applicability
            .strong_state_typed_hash_chain_established
    );
    assert!(
        certificate
            .cms19_applicability
            .deployed_oracle_output_geometry_established
    );
    assert!(
        certificate
            .cms19_applicability
            .semantic_state_transition_correspondence_established
    );
    let deployed_leaf_oracle = &certificate.deployed_aggregate_leaf_oracle;
    assert!(deployed_leaf_oracle.has_complete_call_inventory());
    assert_eq!(deployed_leaf_oracle.rows.len(), 9);
    assert_eq!(
        deployed_leaf_oracle
            .rows
            .iter()
            .map(|row| row.interleaving_width)
            .collect::<Vec<_>>(),
        [8, 8, 8, 8, 8, 8, 1, 1, 1],
    );
    assert_eq!(
        deployed_leaf_oracle
            .rows
            .iter()
            .map(|row| row.opened_leaf_count)
            .sum::<u64>(),
        2_782,
    );
    assert_eq!(deployed_leaf_oracle.distinct_initial_equation_count, 2);
    assert_eq!(
        deployed_leaf_oracle.repeated_initial_hash_query_count,
        2_780
    );
    assert_eq!(
        deployed_leaf_oracle.deployed_verifier_hash_query_count,
        1_232_362
    );
    assert_eq!(
        deployed_leaf_oracle.deployed_accepting_database_equation_count,
        1_229_573
    );
    assert_eq!(
        deployed_leaf_oracle.intermediate_oracle_output_bit_length,
        512
    );
    assert_eq!(deployed_leaf_oracle.final_oracle_output_bit_length, 512);
    assert_eq!(deployed_leaf_oracle.minimum_oracle_output_bit_length, 512);
    assert_eq!(
        deployed_leaf_oracle.collision_penalty_denominator_bit_length,
        512
    );
    assert!(deployed_leaf_oracle.transition_collision_propagates_to_final_leaf);
    assert!(deployed_leaf_oracle.uniform_required_output_geometry_established);
    assert!(
        deployed_leaf_oracle.classical_collision_penalty_is_below_inverse_power_of_two(128),
        "the 512-bit transition chain meets the classical collision allocation",
    );
    assert!(
        deployed_leaf_oracle.qrom_ideal_oracle_penalty_is_below_inverse_power_of_two(128),
        "the 512-bit transition chain meets the QROM ideal-oracle collision allocation",
    );
    assert!(deployed_leaf_oracle.is_eligible_for_uniform_required_output());
    assert!(certificate.cms19_strong_state_hash_chain.is_complete());
    assert_eq!(
        certificate
            .cms19_strong_state_hash_chain
            .logical_verifier_message_count,
        SELECTED_LOGICAL_VERIFIER_MESSAGE_COUNT,
    );
    assert!(
        certificate
            .cms19_state_predicate
            .has_exact_abstract_partition()
    );
    assert_eq!(
        certificate
            .cms19_state_predicate
            .transcript_incompatibility_count,
        0,
    );
    assert_eq!(certificate.cms19_state_predicate.requirements.len(), 20);
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement
                    == StatePredicateRequirement::CompleteSemanticStateTransitionCorrespondence
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::GeneratedWholeStateTransitionCorrespondence
                    && row.is_discharged
            }),
    );
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement == StatePredicateRequirement::SelectedUniqueDecodingInequalitiesHold
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedConstructionGeometry
                    && row.is_discharged
            }),
    );
    assert!(certificate.cms19_state_predicate.is_complete());
    assert!(certificate.construction_masking.is_complete());
    assert!(certificate.aggregate_wide_masking.is_complete());
    assert_eq!(
        certificate
            .aggregate_wide_masking
            .joint_affine_view_summary(),
        (18_025, 18_013, 12),
    );
    assert_eq!(
        certificate.aggregate_wide_masking.nonlinear_view_summary(),
        (9, 9, 5, 6),
    );
    assert_eq!(
        certificate
            .aggregate_wide_masking
            .generator_sample_summary(),
        (18_025, 90_125, 64, 10),
    );
    assert!(
        certificate
            .relation_compiler_interpreter_semantics
            .is_complete()
    );
    assert!(certificate.polynomial_protocol_extractor.is_complete());
    assert!(certificate.point_constraint_extractor.is_complete());
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement
                    == StatePredicateRequirement::ExtractCompilerInterpreterRelationWitness
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::IndependentCompilerInterpreterArithmeticOracle
                    && row.is_discharged
            }),
    );
    assert!(
        certificate
            .construction_masking
            .aggregate_claims_factor_through_masked_openings()
    );
    assert!(
        certificate
            .construction_masking
            .aggregate_wide_views_delegate_to_precommitted_pad()
    );
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .filter(|row| {
                matches!(
                    row.requirement,
                    StatePredicateRequirement::ExtractCompleteRelationPhaseCodewords
                        | StatePredicateRequirement::ExtractCompleteBoundCodewords
                        | StatePredicateRequirement::ExtractCompleteWhirEpochCodewords
                        | StatePredicateRequirement::ExtractThetaAndPhaseReductions
                )
            })
            .all(|row| {
                row.discharge_authority
                    == StatePredicateDischargeAuthority::CheckedRoundByRoundPolynomialExtractor
                    && row.is_discharged
            })
    );
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement
                    == StatePredicateRequirement::ExplicitPointConstraintExtractorCorrespondence
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedExplicitPointConstraintExtractor
                    && row.is_discharged
            })
    );
    assert!(certificate.exact_failure_magnitude.is_complete());
    assert!(certificate.cms19_applicability.is_complete());
    assert!(certificate.is_complete_construction_theorem());
    assert!(
        certificate
            .cms19_state_predicate
            .requirements
            .iter()
            .any(|row| {
                row.requirement == StatePredicateRequirement::ExactFailureMagnitudeCorrespondence
                    && row.discharge_authority
                        == StatePredicateDischargeAuthority::CheckedExactFailureMagnitudeCorrespondence
                    && row.is_discharged
            })
    );

    let exact_failure = &certificate.exact_failure_magnitude;
    assert_eq!(
        exact_failure
            .query_rows
            .iter()
            .map(|row| {
                (
                    row.event,
                    row.logical_word_count,
                    row.population,
                    row.agreement_ceiling,
                    row.query_count,
                    row.charged_term_count,
                )
            })
            .collect::<Vec<_>>(),
        [
            (
                ExactQueryFailureEvent::OuterOpeningPointWords,
                3,
                16_777_216,
                10_485_760,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::RelationPhaseColumns,
                3,
                16_777_216,
                10_485_760,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::BoundTreeWords,
                8,
                8_388_608,
                9_217,
                40,
                1,
            ),
            (
                ExactQueryFailureEvent::StatementRootWords,
                3,
                8_388_608,
                4_259_840,
                266,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 0 },
                1,
                8_388_608,
                5_243_074,
                387,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 1 },
                1,
                4_194_304,
                2_228_368,
                288,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 2 },
                1,
                2_097_152,
                1_065_094,
                268,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 3 },
                1,
                1_048_576,
                526_468,
                264,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 4 },
                1,
                524_288,
                262_532,
                263,
                1,
            ),
            (
                ExactQueryFailureEvent::WhirSource { epoch_ordinal: 5 },
                1,
                262_144,
                131_236,
                263,
                1,
            ),
            (
                ExactQueryFailureEvent::AggregateWidePad,
                1,
                8_192,
                5_055,
                393,
                1,
            ),
        ],
    );
    assert!(exact_failure.query_rows.iter().all(|row| {
        row.exact_without_replacement_probability
            .less_than_or_equal(&row.power_probability_ceiling)
    }));
    let single_theta_numerator = BigUint::from(32_766_u64).pow(5);
    assert_eq!(
        exact_failure
            .theta_rows
            .iter()
            .map(|row| row.bad_set_numerator.clone())
            .collect::<Vec<_>>(),
        vec![single_theta_numerator.clone(); 3],
    );
    let complete_algebraic_numerator = sum_algebraic_numerator(&exact_failure.algebraic_rows);
    let theta_numerator = BigUint::from(3_u8) * single_theta_numerator;
    assert_eq!(
        &complete_algebraic_numerator - &theta_numerator,
        BigUint::from(216_542_517_u64),
    );
    assert_eq!(
        complete_algebraic_numerator,
        BigUint::parse_bytes(b"113302212165600456748245", 10)
            .expect("the exact algebraic numerator parses"),
    );
    assert!(
        exact_failure
            .classical_failure_probability_ceiling
            .is_greater_than_inverse_power_of_two(244)
    );
    assert!(
        exact_failure
            .classical_failure_probability_ceiling
            .is_at_most_inverse_power_of_two(243)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .is_greater_than_inverse_power_of_two(80)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .is_at_most_inverse_power_of_two(79)
    );
    assert!(
        exact_failure
            .qrom_failure_probability_ceiling
            .less_than(&ExactBigFraction::from_u64(1, 1).expect("one derives"))
    );

    let extractor_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected same-secret context exists");
    let extractor_compiled_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives"),
        &extractor_context,
    )
    .expect("the selected same-secret relation compiles");
    let extractor_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
        extractor_compiled_plan,
        &extractor_context,
    )
    .expect("the selected same-secret relation validates");
    let extractor_variant = extractor_artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("the selected same-secret variant exists");
    let extractor_variant_hash = extractor_variant
        .canonical_hash()
        .expect("the selected same-secret variant hashes");
    let failure_catalog = plan
        .oracle_equation_catalog()
        .expect("the exact failure catalog derives");
    for fault in [
        ExactFailureMagnitudeFault::DropFirstQueryRow,
        ExactFailureMagnitudeFault::ReduceFirstQueryAgreementCeiling,
        ExactFailureMagnitudeFault::DropRelationCompositionOwner,
        ExactFailureMagnitudeFault::ReduceAggregateWideBaseNumerator,
        ExactFailureMagnitudeFault::ChangeVerifierHashQueryCount,
    ] {
        assert_eq!(
            checked_exact_failure_magnitude_with_fault(
                ExactFailureMagnitudeDerivationInput {
                    plan: &plan,
                    relation_variant: extractor_variant,
                    catalog: &failure_catalog,
                    selected_plan_state_predicate: &certificate.selected_plan_state_predicate,
                    code_state_rows: &certificate.code_state_rows,
                    fold_rows: &certificate.fold_rows,
                    shift_rows: &certificate.shift_rows,
                    aggregate_wide_masking: &certificate.aggregate_wide_masking,
                    initial_constraint_batch_numerator: certificate
                        .initial_constraint_batch_numerator,
                    logical_verifier_message_count: certificate.logical_verifier_message_count,
                    cms19_arithmetic: &certificate.cms19_arithmetic,
                },
                fault,
            ),
            Err(WhirTheoremCertificateError::IncompleteFailureMagnitudeCorrespondence),
            "the hostile failure-magnitude mutation {fault:?} must be rejected",
        );
    }
    for fault in [
        ExactExtractorCorrespondenceFault::DropFirstRelationPhasePolynomial,
        ExactExtractorCorrespondenceFault::ChangeFirstAggregateOpeningColumn,
        ExactExtractorCorrespondenceFault::ChangeScalarOpeningCount,
        ExactExtractorCorrespondenceFault::PermitProofSuppliedPoint,
        ExactExtractorCorrespondenceFault::ChangeFirstPolynomialBasisIdentity,
    ] {
        assert!(
            checked_exact_same_secret_extractor_correspondence_with_fault(
                &plan,
                extractor_variant,
                &extractor_context,
                extractor_artifact.canonical_plan_hash(),
                extractor_variant_hash,
                fault,
            )
            .is_err(),
            "the hostile extractor mutation {fault:?} must be rejected",
        );
    }

    let mut duplicated_tree_role = verifier_ledger.merkle_rows.clone();
    duplicated_tree_role[1].role = duplicated_tree_role[0].role;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &duplicated_tree_role),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut changed_tree_geometry = verifier_ledger.merkle_rows.clone();
    changed_tree_geometry[0].leaf_count /= 2;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &changed_tree_geometry),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut changed_parent_ceiling = verifier_ledger.merkle_rows.clone();
    changed_parent_ceiling[0].parent_hash_query_count -= 1;
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &changed_parent_ceiling),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut missing_tree_role = verifier_ledger.merkle_rows.clone();
    missing_tree_role.pop();
    assert_eq!(
        derive_commitment_subtree_extraction_certificate(&plan, &missing_tree_role),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );

    let mut changed_query_plan = plan.clone();
    changed_query_plan.whir.rounds[0].query_epoch.query_count -= 1;
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_query_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut changed_fold_plan = plan.clone();
    changed_fold_plan.whir.rounds[0]
        .encoded_oracle
        .evaluation_count /= 2;
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_fold_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut changed_opening_plan = plan.clone();
    changed_opening_plan.opening_batches[0]
        .requested_aggregate_column_ordinals
        .push(0);
    assert_eq!(
        checked_row_code_whir_failure_partition(&changed_opening_plan),
        Err(WhirTheoremCertificateError::InvalidSelectedGeometry),
    );

    let mut missing_equation_row = certificate.oracle_equation_rows.clone();
    missing_equation_row.remove(1);
    assert_eq!(
        validate_state_and_equation_rows(
            &plan.oracle_equation_catalog().expect("the catalog derives"),
            &certificate.state_epoch_rows,
            &missing_equation_row,
        ),
        Err(WhirTheoremCertificateError::IncompleteOracleEquationMapping),
    );
}

#[test]
fn independent_unique_decoder_and_explicit_constraint_filter_cover_hostile_words() {
    const MODULUS: u64 = 97;
    const DIMENSION: usize = 4;
    const DOMAIN_SIZE: usize = 12;
    const RADIUS: usize = (DOMAIN_SIZE - DIMENSION) / 2;

    let polynomial = [7_u64, 11, 3, 9];
    let evaluation_points = (1..=DOMAIN_SIZE)
        .map(|point| u64::try_from(point).expect("small point fits u64"))
        .collect::<Vec<_>>();
    let codeword = evaluation_points
        .iter()
        .map(|point| polynomial_evaluation(&polynomial, *point, MODULUS))
        .collect::<Vec<_>>();

    for error_count in [0_usize, 1, RADIUS] {
        let mut received = codeword.clone();
        for (error_ordinal, received_value) in received.iter_mut().enumerate().take(error_count) {
            *received_value = (*received_value
                + u64::try_from(error_ordinal + 1).expect("error fits u64"))
                % MODULUS;
        }
        let decoded = berlekamp_welch_unique_decode(
            &evaluation_points,
            &received,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| candidate == polynomial,
        )
        .expect("every word within the selected radius uniquely decodes");
        assert_eq!(decoded, polynomial);
    }

    let explicit_point = 17_u64;
    let genuine_terminal = polynomial_evaluation(&polynomial, explicit_point, MODULUS);
    let false_terminal = (genuine_terminal + 1) % MODULUS;
    assert!(
        berlekamp_welch_unique_decode(
            &evaluation_points,
            &codeword,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| polynomial_evaluation(candidate, explicit_point, MODULUS) == false_terminal,
        )
        .is_none(),
        "valid Boolean-domain authentication cannot self-authenticate a false explicit-point value",
    );

    let mut beyond_radius = codeword;
    for (error_ordinal, received_value) in beyond_radius.iter_mut().enumerate().take(RADIUS + 1) {
        *received_value =
            (*received_value + u64::try_from(error_ordinal + 1).expect("error fits u64")) % MODULUS;
    }
    assert!(
        berlekamp_welch_unique_decode(
            &evaluation_points,
            &beyond_radius,
            DIMENSION,
            RADIUS,
            MODULUS,
            |candidate| candidate == polynomial,
        )
        .is_none(),
    );
}

fn berlekamp_welch_unique_decode(
    evaluation_points: &[u64],
    received_values: &[u64],
    dimension: usize,
    radius: usize,
    modulus: u64,
    constraint_filter: impl Fn(&[u64]) -> bool,
) -> Option<Vec<u64>> {
    if evaluation_points.len() != received_values.len()
        || evaluation_points.len() != dimension.checked_add(radius.checked_mul(2)?)?
        || dimension == 0
        || modulus < 3
    {
        return None;
    }
    let quotient_coefficient_count = dimension.checked_add(radius)?;
    let locator_coefficient_count = radius.checked_add(1)?;
    let unknown_count = quotient_coefficient_count.checked_add(locator_coefficient_count)?;
    let mut matrix = Vec::with_capacity(evaluation_points.len());
    for (&point, &received) in evaluation_points.iter().zip(received_values) {
        let mut row = vec![0_u64; unknown_count];
        let mut power = 1_u64;
        for entry in &mut row[..quotient_coefficient_count] {
            *entry = power;
            power = modular_multiply(power, point, modulus);
        }
        power = 1;
        for entry in &mut row[quotient_coefficient_count..] {
            *entry = modular_negate(modular_multiply(received, power, modulus), modulus);
            power = modular_multiply(power, point, modulus);
        }
        matrix.push(row);
    }
    let solution = homogeneous_nullspace_vector(matrix, modulus)?;
    let quotient_polynomial = solution[..quotient_coefficient_count].to_vec();
    let locator_polynomial = solution[quotient_coefficient_count..].to_vec();
    let mut decoded = exact_polynomial_division(quotient_polynomial, locator_polynomial, modulus)?;
    trim_polynomial(&mut decoded);
    if decoded.len() > dimension {
        return None;
    }
    decoded.resize(dimension, 0);
    let disagreement_count = evaluation_points
        .iter()
        .zip(received_values)
        .filter(|(point, received)| polynomial_evaluation(&decoded, **point, modulus) != **received)
        .count();
    (disagreement_count <= radius && constraint_filter(&decoded)).then_some(decoded)
}

fn homogeneous_nullspace_vector(mut matrix: Vec<Vec<u64>>, modulus: u64) -> Option<Vec<u64>> {
    let row_count = matrix.len();
    let column_count = matrix.first()?.len();
    if matrix.iter().any(|row| row.len() != column_count) {
        return None;
    }
    let mut pivot_columns = Vec::new();
    let mut pivot_row = 0_usize;
    for column in 0..column_count {
        let source_row = (pivot_row..row_count).find(|row| matrix[*row][column] != 0);
        let Some(source_row) = source_row else {
            continue;
        };
        matrix.swap(pivot_row, source_row);
        let inverse = modular_inverse(matrix[pivot_row][column], modulus)?;
        for entry in &mut matrix[pivot_row] {
            *entry = modular_multiply(*entry, inverse, modulus);
        }
        for row in 0..row_count {
            if row == pivot_row || matrix[row][column] == 0 {
                continue;
            }
            let factor = matrix[row][column];
            for entry_index in column..column_count {
                let subtraction = modular_multiply(factor, matrix[pivot_row][entry_index], modulus);
                matrix[row][entry_index] =
                    modular_subtract(matrix[row][entry_index], subtraction, modulus);
            }
        }
        pivot_columns.push(column);
        pivot_row += 1;
        if pivot_row == row_count {
            break;
        }
    }
    let pivot_set = pivot_columns.iter().copied().collect::<BTreeSet<_>>();
    let free_column = (0..column_count).find(|column| !pivot_set.contains(column))?;
    let mut solution = vec![0_u64; column_count];
    solution[free_column] = 1;
    for (row, pivot_column) in pivot_columns.iter().copied().enumerate().rev() {
        let accumulated = ((pivot_column + 1)..column_count).fold(0_u64, |sum, column| {
            (sum + modular_multiply(matrix[row][column], solution[column], modulus)) % modulus
        });
        solution[pivot_column] = modular_negate(accumulated, modulus);
    }
    solution.iter().any(|entry| *entry != 0).then_some(solution)
}

fn exact_polynomial_division(
    mut numerator: Vec<u64>,
    mut denominator: Vec<u64>,
    modulus: u64,
) -> Option<Vec<u64>> {
    trim_polynomial(&mut numerator);
    trim_polynomial(&mut denominator);
    if denominator.is_empty() {
        return None;
    }
    if numerator.len() < denominator.len() {
        return numerator.is_empty().then(Vec::new);
    }
    let mut quotient = vec![0_u64; numerator.len() - denominator.len() + 1];
    let denominator_lead_inverse = modular_inverse(*denominator.last()?, modulus)?;
    while !numerator.is_empty() && numerator.len() >= denominator.len() {
        let degree_difference = numerator.len() - denominator.len();
        let factor = modular_multiply(*numerator.last()?, denominator_lead_inverse, modulus);
        quotient[degree_difference] = factor;
        for (denominator_index, denominator_coefficient) in denominator.iter().enumerate() {
            let numerator_index = degree_difference + denominator_index;
            numerator[numerator_index] = modular_subtract(
                numerator[numerator_index],
                modular_multiply(factor, *denominator_coefficient, modulus),
                modulus,
            );
        }
        trim_polynomial(&mut numerator);
    }
    numerator.is_empty().then_some(quotient)
}

fn trim_polynomial(polynomial: &mut Vec<u64>) {
    while polynomial.last() == Some(&0) {
        polynomial.pop();
    }
}

fn polynomial_evaluation(polynomial: &[u64], point: u64, modulus: u64) -> u64 {
    polynomial
        .iter()
        .rev()
        .fold(0_u64, |accumulated, coefficient| {
            (modular_multiply(accumulated, point, modulus) + *coefficient) % modulus
        })
}

fn modular_multiply(left: u64, right: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(left) * u128::from(right)) % u128::from(modulus))
        .expect("a modular product fits u64")
}

fn modular_subtract(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

fn modular_negate(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

fn modular_inverse(value: u64, modulus: u64) -> Option<u64> {
    if value == 0 {
        return None;
    }
    let mut exponent = modulus.checked_sub(2)?;
    let mut base = value;
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_multiply(result, base, modulus);
        }
        base = modular_multiply(base, base, modulus);
        exponent >>= 1;
    }
    (modular_multiply(value, result, modulus) == 1).then_some(result)
}
