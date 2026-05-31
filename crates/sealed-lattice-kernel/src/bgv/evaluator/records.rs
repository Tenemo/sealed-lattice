use serde_json::{Value, json};

use crate::{
    bgv::{
        evaluator::top_k::{TIE_POLICY, score_bit_count},
        profile::{
            DATA_PRIMES, POLYNOMIAL_DEGREE, aggregate_input_encoding_profile_hash,
            allowed_operation_registry_hash, ballot_score_encoding_profile_hash,
            ballot_share_layout_profile_hash, batch_encoder_hash,
            canonical_ciphertext_convention_hash, encoded_aggregate_layout_hash, layout_hash,
            profile_hash, top_k_evaluator_input_layout_hash,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
};

pub(crate) const SCORE_BIT_DERIVATION_CIRCUIT_ID: &str = "ScoreBitDerivationCircuit-v1";
pub(crate) const COMPARISON_INPUT_DERIVATION_CIRCUIT_ID: &str =
    "ComparisonInputDerivationCircuit-v1";
pub(crate) const BIT_SLICED_COMPARATOR_ID: &str = "BitSlicedGreaterThanEqual-v1";
pub(crate) const ENCRYPTED_SPARSE_TARGET_PROJECTION_ID: &str = "WinnerRankTopK-v1";
pub(crate) const BIT_SLICED_EVALUATOR_PROGRAM_ID: &str =
    "sealed-lattice-packed-bit-sliced-bgv-top-k-evaluator-v1";
pub(crate) const DIRECT_SCORE_COMPARISON_EVALUATOR_PROGRAM_ID: &str =
    "sealed-lattice-direct-score-comparison-bgv-top-k-evaluator-v1";
pub(crate) const OUTPUT_ENCODING_ID: &str = "sparse-winner-rank-top-k-slot-encoding-v1";
pub(crate) const EVALUATION_PROOF_PROFILE_ID: &str =
    "sealed-lattice-mandatory-post-quantum-evaluation-proof-v1";
// The maximum supported option count and top-count, matching the protocol
// envelope 1 <= K_top <= m <= 20.
pub(crate) const MAXIMUM_OPTION_COUNT: usize = 20;
const POWER_TABLE_COEFFICIENT_LIMIT: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvaluationComparisonProfile {
    ScoreBitSliced,
    DirectScoreComparison,
}

impl EvaluationComparisonProfile {
    pub(crate) fn profile_id(self) -> &'static str {
        match self {
            Self::ScoreBitSliced => "encrypted-score-bit-sliced-comparison-v1",
            Self::DirectScoreComparison => "direct-encrypted-score-comparison-v1",
        }
    }

    fn evaluator_program_id(self) -> &'static str {
        match self {
            Self::ScoreBitSliced => BIT_SLICED_EVALUATOR_PROGRAM_ID,
            Self::DirectScoreComparison => DIRECT_SCORE_COMPARISON_EVALUATOR_PROGRAM_ID,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RankPackingMethod {
    PerOptionBroadcast,
    GeneratorOrdered,
}

impl RankPackingMethod {
    pub(crate) fn profile_id(self) -> &'static str {
        match self {
            Self::PerOptionBroadcast => "per-option-broadcast",
            Self::GeneratorOrdered => "generator-ordered",
        }
    }

    fn slot_placement(self) -> &'static str {
        match self {
            Self::PerOptionBroadcast => "broadcast-per-option-then-plaintext-selector-assembly",
            Self::GeneratorOrdered => "generator-ordered-packed-scores-unordered-pair-rotations",
        }
    }

    fn rotation_count(self, option_count: usize) -> usize {
        match self {
            Self::PerOptionBroadcast => 0,
            Self::GeneratorOrdered => 2 * option_count.saturating_sub(1),
        }
    }

    fn operation_schedule(
        self,
        comparison_profile: EvaluationComparisonProfile,
    ) -> &'static [&'static str] {
        match (comparison_profile, self) {
            (EvaluationComparisonProfile::ScoreBitSliced, _) => &[
                "encryptedAggregateReconstruction",
                "encryptedScoreReconstruction",
                "scoreBitDerivation",
                "bitSlicedGreaterThanEqual",
                "aheadIndicator",
                "rankAccumulation",
                "topKIndicatorAndOrderValue",
                "encryptedSparseTargetProjection",
            ],
            (EvaluationComparisonProfile::DirectScoreComparison, Self::PerOptionBroadcast) => &[
                "encryptedAggregateReconstruction",
                "encryptedScoreReconstruction",
                "scoreDifferenceComparisonInput",
                "restrictedDomainScoreComparison",
                "aheadIndicator",
                "rankAccumulation",
                "topKIndicatorAndOrderValue",
                "encryptedSparseTargetProjection",
            ],
            (EvaluationComparisonProfile::DirectScoreComparison, Self::GeneratorOrdered) => &[
                "encryptedAggregateReconstruction",
                "encryptedScoreReconstruction",
                "generatorOrderedScorePacking",
                "packedUnorderedPairRotations",
                "restrictedDomainScoreComparison",
                "packedRankAccumulation",
                "topKIndicatorAndOrderValue",
                "encryptedSparseTargetProjection",
            ],
        }
    }
}

// The public inputs and parameters that pin one encrypted top-k evaluation. The
// hash fields are public roots produced upstream (manifest, roster, aggregate
// bridge, setup keys); the counts are the evaluation shape.
pub(crate) struct EvaluationParameters {
    pub(crate) ceremony_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) roster_hash: String,
    pub(crate) canonical_ballot_set_hash: String,
    pub(crate) aggregate_ready_record_hash: String,
    pub(crate) encrypted_aggregate_bridge_hash: String,
    pub(crate) encrypted_aggregate_target_basis_root: String,
    pub(crate) bgv_public_key_root: String,
    pub(crate) collective_public_key_root: String,
    pub(crate) evaluation_key_root: String,
    pub(crate) rot_set_hash: String,
    pub(crate) option_count: usize,
    pub(crate) top_count: usize,
    pub(crate) score_domain_max: u64,
    pub(crate) comparison_profile: EvaluationComparisonProfile,
    pub(crate) rank_packing_method: RankPackingMethod,
}

impl EvaluationParameters {
    fn validate(&self) -> CanonicalResult<()> {
        if self.option_count == 0 || self.option_count > MAXIMUM_OPTION_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "top-k evaluation option count must be between 1 and the supported maximum",
            ));
        }
        if self.top_count == 0 || self.top_count > self.option_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "top-k count must satisfy 1 <= K_top <= option count",
            ));
        }
        if self.rank_packing_method == RankPackingMethod::GeneratorOrdered
            && self.comparison_profile != EvaluationComparisonProfile::DirectScoreComparison
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "generator-ordered rank packing requires direct encrypted score comparison",
            ));
        }

        Ok(())
    }
}

pub(crate) fn tie_policy_hash() -> CanonicalResult<String> {
    derive_protocol_hash("TiePolicyHash", &json!({ "tiePolicy": TIE_POLICY }))
}

fn score_bit_derivation_circuit_hash(score_domain_max: u64) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ScoreBitDerivationCircuitHash",
        &json!({
            "circuitId": SCORE_BIT_DERIVATION_CIRCUIT_ID,
            "method": "restricted-domain-lookup-polynomial-per-bit",
            "scoreDomainMinimum": 0,
            "scoreDomainMaximum": score_domain_max,
            "scoreBitCount": score_bit_count(score_domain_max),
            "derivedInsideEvaluator": true,
            "usesPublicScoreBitFixtures": false,
            "usesShamirShareBitExtraction": false,
            "usesPlaintextAggregateScores": false,
            "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
        }),
    )
}

fn encrypted_score_bit_input_hash(score_domain_max: u64) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedScoreBitInputHash",
        &json!({
            "scoreBitCount": score_bit_count(score_domain_max),
            "booleanityEnforced": true,
            "reconstructsScoreOverDomain": true,
            "scoreDomainMaximum": score_domain_max,
            "scoreBitDerivationCircuitHash": score_bit_derivation_circuit_hash(score_domain_max)?,
        }),
    )
}

fn comparison_input_derivation_circuit_hash(score_domain_max: u64) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ComparisonInputDerivationCircuitHash",
        &json!({
            "circuitId": COMPARISON_INPUT_DERIVATION_CIRCUIT_ID,
            "method": "restricted-domain-score-difference-polynomial",
            "scoreDomainMinimum": 0,
            "scoreDomainMaximum": score_domain_max,
            "comparisonDomainMinimum": 0,
            "comparisonDomainMaximum": 2 * score_domain_max,
            "derivedInsideEvaluator": true,
            "usesPublicComparisonFixtures": false,
            "usesPlaintextAggregateScores": false,
            "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
            "tiePolicyHash": tie_policy_hash()?,
        }),
    )
}

fn encrypted_comparison_input_hash(score_domain_max: u64) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedComparisonInputHash",
        &json!({
            "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash(score_domain_max)?,
            "scoreDomainMaximum": score_domain_max,
            "comparisonDomainMaximum": 2 * score_domain_max,
            "derivedInsideEvaluator": true,
            "usesPublicComparisonFixtures": false,
        }),
    )
}

fn bit_sliced_comparator_hash(score_domain_max: u64) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BitSlicedComparatorHash",
        &json!({
            "comparatorId": BIT_SLICED_COMPARATOR_ID,
            "scoreBitCount": score_bit_count(score_domain_max),
            "greaterThan": "sum_bit a_bit*(1-b_bit)*suffix_equal",
            "equal": "product of per-bit equalities",
            "scalarDegree360ComparatorExcluded": true,
        }),
    )
}

fn selected_derivation_circuit_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    match parameters.comparison_profile {
        EvaluationComparisonProfile::ScoreBitSliced => {
            score_bit_derivation_circuit_hash(parameters.score_domain_max)
        }
        EvaluationComparisonProfile::DirectScoreComparison => {
            comparison_input_derivation_circuit_hash(parameters.score_domain_max)
        }
    }
}

fn selected_derivation_input_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    match parameters.comparison_profile {
        EvaluationComparisonProfile::ScoreBitSliced => {
            encrypted_score_bit_input_hash(parameters.score_domain_max)
        }
        EvaluationComparisonProfile::DirectScoreComparison => {
            encrypted_comparison_input_hash(parameters.score_domain_max)
        }
    }
}

fn encrypted_rank_accumulation_hash(option_count: usize) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedRankAccumulationHash",
        &json!({
            "optionCount": option_count,
            "rankRule": "rank_a = sum over challengers of ahead[challenger, a]",
            "aheadRule": "ahead = greaterThan OR (equal AND lowerIndexTieBreak)",
            "tiePolicyHash": tie_policy_hash()?,
            "orderedPairCount": option_count * option_count.saturating_sub(1),
        }),
    )
}

fn rank_packing_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    derive_protocol_hash(
        "RankPackingHash",
        &json!({
            "rankPackingMethod": parameters.rank_packing_method.profile_id(),
            "slotPlacement": parameters.rank_packing_method.slot_placement(),
            "optionCount": parameters.option_count,
            "rotationCount": parameters.rank_packing_method.rotation_count(parameters.option_count),
            "tiePolicyHash": tie_policy_hash()?,
        }),
    )
}

fn target_layout_hash(option_count: usize) -> CanonicalResult<String> {
    derive_protocol_hash(
        "TargetLayoutHash",
        &json!({
            "layoutId": ENCRYPTED_SPARSE_TARGET_PROJECTION_ID,
            "optionCount": option_count,
            "targetIdSlotRule": "(option + 1) * [rank < K_top]",
            "targetOrderSlotRule": "(rank + 1) * [rank < K_top]",
            "forbiddenSemanticSlotsZero": true,
            "slotCount": POLYNOMIAL_DEGREE,
        }),
    )
}

fn encrypted_sparse_target_projection_hash(
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedSparseTargetProjectionHash",
        &json!({
            "projectionId": ENCRYPTED_SPARSE_TARGET_PROJECTION_ID,
            "optionCount": option_count,
            "topCount": top_count,
            "targetLayoutHash": target_layout_hash(option_count)?,
            "producesCipherTargetWithoutPlaintextWitnesses": true,
        }),
    )
}

// The canonical operation schedule executed by the deterministic evaluator. The
// schedule defines the evaluator program; later objects bind its digest.
fn evaluator_program_value(parameters: &EvaluationParameters) -> CanonicalResult<Value> {
    parameters.validate()?;
    Ok(json!({
        "programId": parameters.comparison_profile.evaluator_program_id(),
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "operationSchedule": parameters.rank_packing_method.operation_schedule(parameters.comparison_profile),
        "slotPlacement": parameters.rank_packing_method.slot_placement(),
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "profileHash": profile_hash()?,
        "plaintextComparatorOperationsRejected": true,
    }))
}

fn evaluator_program_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluatorProgramHash",
        &evaluator_program_value(parameters)?,
    )
}

fn top_k_circuit_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    let mut circuit = json!({
        "evaluatorProgramHash": evaluator_program_hash(parameters)?,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "selectedDerivationCircuitHash": selected_derivation_circuit_hash(parameters)?,
        "selectedDerivationInputHash": selected_derivation_input_hash(parameters)?,
        "encryptedRankAccumulationHash": encrypted_rank_accumulation_hash(parameters.option_count)?,
        "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash(parameters.option_count, parameters.top_count)?,
        "rotSetHash": parameters.rot_set_hash,
        "tiePolicyHash": tie_policy_hash()?,
        "topCount": parameters.top_count,
    });
    match parameters.comparison_profile {
        EvaluationComparisonProfile::ScoreBitSliced => {
            circuit["scoreBitDerivationCircuitHash"] = Value::String(
                score_bit_derivation_circuit_hash(parameters.score_domain_max)?,
            );
            circuit["encryptedScoreBitInputHash"] =
                Value::String(encrypted_score_bit_input_hash(parameters.score_domain_max)?);
            circuit["bitSlicedComparatorHash"] =
                Value::String(bit_sliced_comparator_hash(parameters.score_domain_max)?);
        }
        EvaluationComparisonProfile::DirectScoreComparison => {
            circuit["comparisonInputDerivationCircuitHash"] = Value::String(
                comparison_input_derivation_circuit_hash(parameters.score_domain_max)?,
            );
            circuit["encryptedComparisonInputHash"] = Value::String(
                encrypted_comparison_input_hash(parameters.score_domain_max)?,
            );
            circuit["bitSlicedComparatorHash"] = Value::Null;
        }
    }

    derive_protocol_hash("TopKCircuitHash", &circuit)
}

fn evaluation_parameter_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluationParameterHash",
        &json!({
            "profileHash": profile_hash()?,
            "bgvPublicKeyRoot": parameters.bgv_public_key_root,
            "collectivePublicKeyRoot": parameters.collective_public_key_root,
            "evaluationKeyRoot": parameters.evaluation_key_root,
            "comparisonProfile": parameters.comparison_profile.profile_id(),
            "rankPackingMethod": parameters.rank_packing_method.profile_id(),
            "rankPackingHash": rank_packing_hash(parameters)?,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "batchEncoderHash": batch_encoder_hash()?,
        }),
    )
}

fn evaluation_noise_profile_hash(parameters: &EvaluationParameters) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EvaluationNoiseProfileHash",
        &json!({
            "profileHash": profile_hash()?,
            "comparisonProfile": parameters.comparison_profile.profile_id(),
            "rankPackingMethod": parameters.rank_packing_method.profile_id(),
            "rankPackingHash": rank_packing_hash(parameters)?,
            "scoreBitCount": score_bit_count(parameters.score_domain_max),
            "modulusSwitchingPerMultiplication": true,
            "keySwitchVariant": "rns-digit-decomposition",
        }),
    )
}

// The canonical evaluation context digest. It is defined here and reused by
// target finality, evaluation proofs, local replay, target acceptance, and
// target decryption; later objects must bind it rather than recompute a variant.
pub(crate) fn evaluation_context_hash(
    parameters: &EvaluationParameters,
) -> CanonicalResult<String> {
    parameters.validate()?;
    derive_protocol_hash(
        "EvaluationContextHash",
        &json!({
            "ceremonyId": parameters.ceremony_id,
            "manifestHash": parameters.manifest_hash,
            "rosterHash": parameters.roster_hash,
            "canonicalBallotSetHash": parameters.canonical_ballot_set_hash,
            "aggregateReadyRecordHash": parameters.aggregate_ready_record_hash,
            "encryptedAggregateBridgeHash": parameters.encrypted_aggregate_bridge_hash,
            "encryptedAggregateTargetBasisDataRoot": parameters.encrypted_aggregate_target_basis_root,
            "evaluationParameterHash": evaluation_parameter_hash(parameters)?,
            "bgvProfileHash": profile_hash()?,
            "bgvPublicKeyRoot": parameters.bgv_public_key_root,
            "collectivePublicKeyRoot": parameters.collective_public_key_root,
            "evaluationKeyRoot": parameters.evaluation_key_root,
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()?,
            "batchEncoderHash": batch_encoder_hash()?,
            "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
            "ballotShareLayoutProfileHash": ballot_share_layout_profile_hash()?,
            "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
            "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
            "targetBasisDataLayoutHash": layout_hash()?,
            "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
            "comparisonProfile": parameters.comparison_profile.profile_id(),
            "selectedDerivationCircuitHash": selected_derivation_circuit_hash(parameters)?,
            "selectedDerivationInputHash": selected_derivation_input_hash(parameters)?,
            "scoreBitDerivationCircuitHash": score_bit_derivation_circuit_hash(parameters.score_domain_max)?,
            "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash(parameters.score_domain_max)?,
            "encryptedScoreBitInputHash": encrypted_score_bit_input_hash(parameters.score_domain_max)?,
            "encryptedComparisonInputHash": encrypted_comparison_input_hash(parameters.score_domain_max)?,
            "bitSlicedComparatorHash": match parameters.comparison_profile {
                EvaluationComparisonProfile::ScoreBitSliced => Value::String(bit_sliced_comparator_hash(parameters.score_domain_max)?),
                EvaluationComparisonProfile::DirectScoreComparison => Value::Null,
            },
            "encryptedRankAccumulationHash": encrypted_rank_accumulation_hash(parameters.option_count)?,
            "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash(parameters.option_count, parameters.top_count)?,
            "evaluationNoiseProfileHash": evaluation_noise_profile_hash(parameters)?,
            "evaluationNoiseCertHash": evaluation_noise_certificate(parameters)?["evaluationNoiseCertHash"].clone(),
            "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
            "topKCircuitHash": top_k_circuit_hash(parameters)?,
            "rotSetHash": parameters.rot_set_hash,
            "targetLayoutHash": target_layout_hash(parameters.option_count)?,
            "evaluatorProgramHash": evaluator_program_hash(parameters)?,
            "tiePolicyHash": tie_policy_hash()?,
            "topCount": parameters.top_count,
            "outputEncodingHash": output_encoding_hash()?,
        }),
    )
}

pub(crate) fn output_encoding_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "OutputEncodingHash",
        &json!({
            "outputEncodingId": OUTPUT_ENCODING_ID,
            "targetIdSlot": "option ordinal, 1-based",
            "targetOrderSlot": "rank position, 1-based",
            "unusedAndForbiddenSlots": "zero",
        }),
    )
}

// The public layout mask hash. The mask is manifest-pinned public layout
// material that does not encode winners, selected option IDs, target plaintext,
// ranks, comparison bits, or aggregate score bits.
pub(crate) fn public_slot_mask_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicSlotMaskHash",
        &json!({
            "maskId": "manifest-pinned-public-layout-mask-v1",
            "encodesWinners": false,
            "encodesSelectedOptionIds": false,
            "encodesTargetPlaintext": false,
            "encodesRanks": false,
            "encodesComparisonBits": false,
            "encodesAggregateScoreBits": false,
        }),
    )
}

// A compact description of the deterministic evaluator program and its circuit
// identity for a given evaluation shape.
pub(crate) fn describe_evaluator_program(
    parameters: &EvaluationParameters,
) -> CanonicalResult<Value> {
    parameters.validate()?;
    Ok(json!({
        "program": evaluator_program_value(parameters)?,
        "evaluatorProgramHash": evaluator_program_hash(parameters)?,
        "topKCircuitHash": top_k_circuit_hash(parameters)?,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "selectedDerivationCircuitHash": selected_derivation_circuit_hash(parameters)?,
        "selectedDerivationInputHash": selected_derivation_input_hash(parameters)?,
        "tiePolicyHash": tie_policy_hash()?,
        "outputEncodingHash": output_encoding_hash()?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "scoreBitCount": score_bit_count(parameters.score_domain_max),
    }))
}

// Estimated evaluator operation and depth counts for the certificate. These are
// derived analytically from the evaluation shape and the implemented schedule.
fn operation_counts(parameters: &EvaluationParameters) -> Value {
    let bit_count = score_bit_count(parameters.score_domain_max);
    let option_count = parameters.option_count;
    let ordered_pairs = option_count * option_count.saturating_sub(1);
    let domain_points = parameters.score_domain_max + 1;
    // The score-bit path uses the default high-degree polynomial schedule:
    // depth-optimal power tables for small polynomials and Paterson-Stockmeyer
    // for high-degree polynomials. The direct comparison path uses the
    // depth-optimized power-table schedule because the full score-domain-200
    // comparison is depth-bound under the selected modulus chain.
    let extraction_depth = implemented_polynomial_depth(domain_points - 1);
    let comparator_depth = bit_count as u64 + 2;
    let indicator_depth = ceil_log2(option_count as u64);
    // The sparse projection itself is a plaintext mask/scalar assembly. Target
    // order is evaluated as a factored rank-prefix polynomial, so projection
    // does not add a ciphertext multiplication beyond the rank indicator/order
    // depth.
    let projection_depth = 0_u64;
    let multiplicative_depth = extraction_depth + comparator_depth + indicator_depth;
    // The comparison-input path compares via one difference polynomial over
    // [0, 2*score_domain_max] with no per-bit extraction. The selected
    // schedule uses the multiplication-heavy all-powers table because it
    // reaches the depth floor ceil(log2(2*max+1)).
    let comparison_polynomial_degree = 2 * parameters.score_domain_max;
    let comparison_input_depth_optimal_comparator_depth =
        ceil_log2(comparison_polynomial_degree + 1);
    let comparison_input_comparator_depth = comparison_input_depth_optimal_comparator_depth;
    let comparison_input_multiplicative_depth =
        comparison_input_comparator_depth + indicator_depth + projection_depth;
    let comparison_input_depth_optimal_multiplicative_depth =
        comparison_input_depth_optimal_comparator_depth + indicator_depth + projection_depth;
    let comparison_input_polynomial_evaluations = match parameters.rank_packing_method {
        RankPackingMethod::PerOptionBroadcast => ordered_pairs,
        RankPackingMethod::GeneratorOrdered => option_count.saturating_sub(1),
    };
    let comparison_input_polynomial_ciphertext_multiplication_estimate =
        comparison_input_polynomial_evaluations
            * usize::try_from(comparison_polynomial_degree.saturating_sub(1))
                .expect("comparison degree fits usize");

    json!({
        "scoreBitCount": bit_count,
        "orderedComparisonCount": ordered_pairs,
        "unorderedComparisonCount": option_count * option_count.saturating_sub(1) / 2,
        "multiplicativeDepth": multiplicative_depth,
        "extractionDepth": extraction_depth,
        "comparatorDepth": comparator_depth,
        "indicatorDepth": indicator_depth,
        "projectionDepth": projection_depth,
        "comparisonInputComparatorDepth": comparison_input_comparator_depth,
        "comparisonInputMultiplicativeDepth": comparison_input_multiplicative_depth,
        "comparisonInputDepthOptimalComparatorDepth": comparison_input_depth_optimal_comparator_depth,
        "comparisonInputDepthOptimalMultiplicativeDepth": comparison_input_depth_optimal_multiplicative_depth,
        "comparisonInputPolynomialEvaluationCount": comparison_input_polynomial_evaluations,
        "comparisonInputPolynomialCiphertextMultiplicationEstimate": comparison_input_polynomial_ciphertext_multiplication_estimate,
        "scoreBitHighDegreePolynomialSchedule": "paterson-stockmeyer",
        "comparisonInputPolynomialSchedule": match parameters.rank_packing_method {
            RankPackingMethod::PerOptionBroadcast => "per-pair-depth-optimized-power-table",
            RankPackingMethod::GeneratorOrdered => "per-shift-depth-optimized-power-table",
        },
        "highDegreePolynomialSchedule": "mixed-by-selected-profile",
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rotationCount": parameters.rank_packing_method.rotation_count(parameters.option_count),
        "keySwitchCount": parameters.rank_packing_method.rotation_count(parameters.option_count),
        "availableModulusLevels": DATA_PRIMES.len(),
    })
}

fn implemented_polynomial_depth(degree: u64) -> u64 {
    if degree < POWER_TABLE_COEFFICIENT_LIMIT {
        ceil_log2(degree + 1)
    } else {
        paterson_stockmeyer_depth(degree)
    }
}

fn paterson_stockmeyer_depth(degree: u64) -> u64 {
    if degree == 0 {
        return 0;
    }
    let baby_step_count = integer_square_root_ceil(degree + 1).max(2);
    let block_count = (degree + 1).div_ceil(baby_step_count);
    let baby_depth = ceil_log2(baby_step_count);
    if block_count <= 1 {
        baby_depth
    } else {
        baby_depth + ceil_log2(block_count - 1) + 1
    }
}

fn integer_square_root_ceil(value: u64) -> u64 {
    let mut root = 1_u64;
    while root.saturating_mul(root) < value {
        root += 1;
    }

    root
}

fn ceil_log2(value: u64) -> u64 {
    if value <= 1 {
        return 0;
    }
    u64::from(u64::BITS - (value - 1).leading_zeros())
}

// The Appendix A evaluator/noise certificate. It records the evaluator
// correctness scope, operation/depth counts, key-size budget, and a feasibility
// label: the bit-sliced evaluator profile is rejected when the multiplicative
// depth exceeds the available modulus levels.
pub(crate) fn evaluation_noise_certificate(
    parameters: &EvaluationParameters,
) -> CanonicalResult<Value> {
    parameters.validate()?;
    let counts = operation_counts(parameters);
    let depth = counts["multiplicativeDepth"].as_u64().unwrap_or(u64::MAX);
    let available_levels = DATA_PRIMES.len() as u64;
    // One ciphertext component limb is N u64 values; a two-component ciphertext
    // at the full data basis is 2 * 16 * N * 8 bytes. A key-switching key at the
    // full level is quadratic in the number of primes.
    let full_ciphertext_bytes = 2 * DATA_PRIMES.len() * POLYNOMIAL_DEGREE * 8;
    let full_key_switch_key_bytes =
        DATA_PRIMES.len() * 2 * DATA_PRIMES.len() * POLYNOMIAL_DEGREE * 8;
    // A depth-D circuit still needs one retained limb after the final modulus
    // switch: the full-rank-domain target tail passes at level 6 and fails at
    // bottom level in the development evaluator, so a depth-14 direct
    // comparison schedule can fit the 16-prime chain while a depth-15 schedule
    // cannot.
    let noise_headroom_levels = 1_u64;
    let usable_multiplicative_depth = (available_levels - 1).saturating_sub(noise_headroom_levels);
    let depth_fits = depth <= usable_multiplicative_depth;
    let bit_sliced_profile_label = if depth_fits {
        "BitSlicedEvaluatorProfileAccepted"
    } else {
        "BitSlicedEvaluatorProfileRejected"
    };
    // The reserved comparison-input path is lower depth, but once noise headroom
    // is included it still exceeds the usable depth at the full profile.
    let comparison_input_depth = counts["comparisonInputMultiplicativeDepth"]
        .as_u64()
        .unwrap_or(u64::MAX);
    let comparison_input_depth_fits = comparison_input_depth <= usable_multiplicative_depth;
    let comparison_input_label = if comparison_input_depth_fits {
        "DirectScoreComparisonProfileFitsDepthBudget"
    } else {
        "DirectScoreComparisonProfileRejected"
    };
    let (selected_depth_fits, selected_profile_label) = match parameters.comparison_profile {
        EvaluationComparisonProfile::ScoreBitSliced => (depth_fits, bit_sliced_profile_label),
        EvaluationComparisonProfile::DirectScoreComparison => {
            (comparison_input_depth_fits, comparison_input_label)
        }
    };

    let body = json!({
        "objectType": "TopKEvaluatorNoiseCertificate",
        "objectVersion": 1,
        "profileHash": profile_hash()?,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "operationCounts": counts,
        "depthFitsModulusChain": selected_depth_fits,
        "bitSlicedDepthFitsModulusChain": depth_fits,
        "noiseHeadroomLevels": noise_headroom_levels,
        "noiseHeadroomJustification": "development full-rank-domain projection tail requires one retained level beyond nominal multiplicative depth for exact decryption",
        "usableMultiplicativeDepth": usable_multiplicative_depth,
        "bitSlicedProfileLabel": bit_sliced_profile_label,
        "comparisonInputProfileLabel": comparison_input_label,
        "comparisonInputDepthFitsModulusChain": comparison_input_depth_fits,
        "fullCiphertextByteEstimate": full_ciphertext_bytes,
        "fullLevelKeySwitchKeyByteEstimate": full_key_switch_key_bytes,
        "noiseProfileHash": evaluation_noise_profile_hash(parameters)?,
        "mobileRuntimeMeasured": false,
        "profileLabel": selected_profile_label,
        "statusLabels": [
            selected_profile_label,
            bit_sliced_profile_label,
            comparison_input_label,
            "AppendixAEvaluatorNoiseEvidenceOnly",
            "MobileRuntimeProfilePending",
            "NotSupportedPhoneCertified"
        ],
    });
    let certificate_hash = derive_protocol_hash("EvaluationNoiseCertHash", &body)?;
    let mut certificate = body;
    certificate["evaluationNoiseCertHash"] = Value::String(certificate_hash);

    Ok(certificate)
}

// The mandatory post-quantum evaluation proof public-input statement.
// The evaluator generates it; it does not close target acceptance.
pub(crate) fn appendix_d_public_input_statement(
    parameters: &EvaluationParameters,
    top_k_ciphertext_hash: &str,
    target_ciphertext_hash: &str,
    public_slot_mask_hash: &str,
    target_proposal_hash: &str,
) -> CanonicalResult<Value> {
    parameters.validate()?;
    let statement = json!({
        "objectType": "TopKEvaluationProofPublicInputStatement",
        "objectVersion": 1,
        "ceremonyId": parameters.ceremony_id,
        "manifestHash": parameters.manifest_hash,
        "rosterHash": parameters.roster_hash,
        "aggregateReadyRecordHash": parameters.aggregate_ready_record_hash,
        "encryptedAggregateBridgeHash": parameters.encrypted_aggregate_bridge_hash,
        "encryptedAggregateTargetBasisDataRoot": parameters.encrypted_aggregate_target_basis_root,
        "bgvProfileHash": profile_hash()?,
        "bgvPublicKeyRoot": parameters.bgv_public_key_root,
        "collectivePublicKeyRoot": parameters.collective_public_key_root,
        "evaluationKeyRoot": parameters.evaluation_key_root,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "evaluatorProgramHash": evaluator_program_hash(parameters)?,
        "allowedEvaluatorOpsHash": allowed_operation_registry_hash()?,
        "tiePolicyHash": tie_policy_hash()?,
        "topCount": parameters.top_count,
        "publicSlotMaskHash": public_slot_mask_hash,
        "topKCiphertextHash": top_k_ciphertext_hash,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash(parameters.option_count)?,
        "targetProposalHash": target_proposal_hash,
        "evaluationContextHash": evaluation_context_hash(parameters)?,
        "evaluationNoiseCertHash": evaluation_noise_certificate(parameters)?["evaluationNoiseCertHash"].clone(),
        "evaluationProofProfileId": EVALUATION_PROOF_PROFILE_ID,
        "statusLabels": [
            "AppendixDPublicInputStatementGenerated",
            "AppendixDNotClosed",
            "EvaluationProofRemainsLater"
        ],
    });
    let statement_hash = derive_protocol_hash("EvaluatorInputStatementHash", &statement)?;
    let mut output = statement;
    output["evaluatorInputStatementHash"] = Value::String(statement_hash);

    Ok(output)
}

// The output ciphertext roots produced by the evaluator run.
pub(crate) struct EvaluatorOutputRoots {
    pub(crate) encrypted_aggregate_reconstruction_root: String,
    pub(crate) encrypted_score_bit_input_root: String,
    pub(crate) greater_than_root: String,
    pub(crate) equal_root: String,
    pub(crate) ahead_root: String,
    pub(crate) rank_root: String,
    pub(crate) target_id_root: String,
    pub(crate) target_order_root: String,
    pub(crate) public_slot_mask_hash: String,
    pub(crate) output_encoding_hash: String,
    pub(crate) pre_target_board_head: String,
    pub(crate) evaluator_signature: String,
}

pub(crate) fn top_k_ciphertext_hash(roots: &EvaluatorOutputRoots) -> CanonicalResult<String> {
    // The canonical encrypted evaluator output bundle: a public encrypted
    // artifact that is never a valid decryption target.
    derive_protocol_hash(
        "TopKCiphertextHash",
        &json!({
            "encryptedAggregateReconstructionRoot": roots.encrypted_aggregate_reconstruction_root,
            "encryptedDerivationInputRoot": roots.encrypted_score_bit_input_root,
            "greaterThanRoot": roots.greater_than_root,
            "equalRoot": roots.equal_root,
            "aheadRoot": roots.ahead_root,
            "rankRoot": roots.rank_root,
            "notAValidDecryptionTarget": true,
        }),
    )
}

pub(crate) fn target_ciphertext_hash(roots: &EvaluatorOutputRoots) -> CanonicalResult<String> {
    derive_protocol_hash(
        "TargetCiphertextHash",
        &json!({
            "targetIdRoot": roots.target_id_root,
            "targetOrderRoot": roots.target_order_root,
            "publicSlotMaskHash": roots.public_slot_mask_hash,
        }),
    )
}

// The TopKEvaluationRecord: the deterministic untrusted evaluator output and
// target proposal that later finality, proof, replay, and decryption flows bind.
pub(crate) fn top_k_evaluation_record(
    parameters: &EvaluationParameters,
    roots: &EvaluatorOutputRoots,
) -> CanonicalResult<Value> {
    let evaluation_context = evaluation_context_hash(parameters)?;
    let top_k_ciphertext = top_k_ciphertext_hash(roots)?;
    let target_ciphertext = target_ciphertext_hash(roots)?;
    let record = json!({
        "objectType": "TopKEvaluationRecord",
        "objectVersion": 1,
        "evaluationContextHash": evaluation_context,
        "encryptedAggregateReconstructionRoot": roots.encrypted_aggregate_reconstruction_root,
        "bgvPublicKeyRoot": parameters.bgv_public_key_root,
        "evaluationKeyRoot": parameters.evaluation_key_root,
        "encryptedAggregateBridgeHash": parameters.encrypted_aggregate_bridge_hash,
        "encryptedAggregateTargetBasisDataRoot": parameters.encrypted_aggregate_target_basis_root,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "rankPackingHash": rank_packing_hash(parameters)?,
        "selectedDerivationCircuitHash": selected_derivation_circuit_hash(parameters)?,
        "encryptedDerivationInputRoot": roots.encrypted_score_bit_input_root,
        "scoreBitDerivationCircuitHash": score_bit_derivation_circuit_hash(parameters.score_domain_max)?,
        "comparisonInputDerivationCircuitHash": comparison_input_derivation_circuit_hash(parameters.score_domain_max)?,
        "encryptedScoreBitInputRoot": match parameters.comparison_profile {
            EvaluationComparisonProfile::ScoreBitSliced => Value::String(roots.encrypted_score_bit_input_root.clone()),
            EvaluationComparisonProfile::DirectScoreComparison => Value::Null,
        },
        "encryptedComparisonInputRoot": match parameters.comparison_profile {
            EvaluationComparisonProfile::ScoreBitSliced => Value::Null,
            EvaluationComparisonProfile::DirectScoreComparison => Value::String(roots.encrypted_score_bit_input_root.clone()),
        },
        "bitSlicedComparatorHash": match parameters.comparison_profile {
            EvaluationComparisonProfile::ScoreBitSliced => Value::String(bit_sliced_comparator_hash(parameters.score_domain_max)?),
            EvaluationComparisonProfile::DirectScoreComparison => Value::Null,
        },
        "encryptedRankAccumulationHash": encrypted_rank_accumulation_hash(parameters.option_count)?,
        "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash(parameters.option_count, parameters.top_count)?,
        "topKCircuitHash": top_k_circuit_hash(parameters)?,
        "rotSetHash": parameters.rot_set_hash,
        "acceptedOutputCiphertextRoots": {
            "greaterThanRoot": roots.greater_than_root,
            "equalRoot": roots.equal_root,
            "aheadRoot": roots.ahead_root,
            "rankRoot": roots.rank_root,
            "targetIdRoot": roots.target_id_root,
            "targetOrderRoot": roots.target_order_root
        },
        "topKCiphertextHash": top_k_ciphertext,
        "publicSlotMaskHash": roots.public_slot_mask_hash,
        "targetCiphertextHash": target_ciphertext,
        "outputEncodingHash": roots.output_encoding_hash,
        "preTargetBoardHead": roots.pre_target_board_head,
        "evaluatorSignature": roots.evaluator_signature,
        "statusLabels": [
            "TopKEvaluationProposalGenerated",
            "NotAcceptedTarget",
            "EvaluationProofRequiredForAcceptance"
        ],
    });
    let record_hash = derive_protocol_hash("TopKEvaluationRecordHash", &record)?;
    let mut output = record;
    output["topKEvaluationRecordHash"] = Value::String(record_hash);

    Ok(output)
}

// The TargetProposalDigest inputs required by exact target finality.
pub(crate) fn target_proposal_hash(
    parameters: &EvaluationParameters,
    record: &Value,
) -> CanonicalResult<String> {
    let read = |field: &str| -> CanonicalResult<String> {
        record
            .get(field)
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "target proposal requires a complete evaluation record",
                )
            })
    };
    derive_protocol_hash(
        "TargetProposalHash",
        &json!({
            "evaluationContextHash": read("evaluationContextHash")?,
            "topKEvaluationRecordHash": read("topKEvaluationRecordHash")?,
            "topKCiphertextHash": read("topKCiphertextHash")?,
            "publicSlotMaskHash": read("publicSlotMaskHash")?,
            "targetCiphertextHash": read("targetCiphertextHash")?,
            "targetLayoutHash": target_layout_hash(parameters.option_count)?,
            "encryptedSparseTargetProjectionHash": encrypted_sparse_target_projection_hash(parameters.option_count, parameters.top_count)?,
            "evaluationProofProfileId": EVALUATION_PROOF_PROFILE_ID,
            "finalityPolicy": "exact-target-finality-plus-verified-evaluation-proof",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        EvaluationComparisonProfile, EvaluationParameters, EvaluatorOutputRoots, RankPackingMethod,
        appendix_d_public_input_statement, evaluation_context_hash, evaluation_noise_certificate,
        target_proposal_hash, top_k_evaluation_record,
    };

    fn parameters() -> EvaluationParameters {
        EvaluationParameters {
            ceremony_id: "ceremony-1".to_string(),
            manifest_hash: "11".repeat(64),
            roster_hash: "22".repeat(64),
            canonical_ballot_set_hash: "33".repeat(64),
            aggregate_ready_record_hash: "44".repeat(64),
            encrypted_aggregate_bridge_hash: "55".repeat(64),
            encrypted_aggregate_target_basis_root: "66".repeat(64),
            bgv_public_key_root: "77".repeat(64),
            collective_public_key_root: "88".repeat(64),
            evaluation_key_root: "99".repeat(64),
            rot_set_hash: "aa".repeat(64),
            option_count: 20,
            top_count: 5,
            score_domain_max: 200,
            comparison_profile: EvaluationComparisonProfile::DirectScoreComparison,
            rank_packing_method: RankPackingMethod::GeneratorOrdered,
        }
    }

    fn roots() -> EvaluatorOutputRoots {
        EvaluatorOutputRoots {
            encrypted_aggregate_reconstruction_root: "01".repeat(64),
            encrypted_score_bit_input_root: "02".repeat(64),
            greater_than_root: "03".repeat(64),
            equal_root: "04".repeat(64),
            ahead_root: "05".repeat(64),
            rank_root: "06".repeat(64),
            target_id_root: "07".repeat(64),
            target_order_root: "08".repeat(64),
            public_slot_mask_hash: "09".repeat(64),
            output_encoding_hash: "0a".repeat(64),
            pre_target_board_head: "0b".repeat(64),
            evaluator_signature: "0c".repeat(64),
        }
    }

    #[test]
    fn evaluation_context_hash_is_stable_and_binds_inputs() {
        let context = evaluation_context_hash(&parameters()).expect("context");
        assert_eq!(context.len(), 128);
        let mut mutated = parameters();
        mutated.top_count = 4;
        assert_ne!(
            context,
            evaluation_context_hash(&mutated).expect("mutated context")
        );
        let mut mutated_manifest = parameters();
        mutated_manifest.manifest_hash = "fe".repeat(64);
        assert_ne!(
            context,
            evaluation_context_hash(&mutated_manifest).expect("mutated manifest context")
        );
    }

    #[test]
    fn target_proposal_changes_with_every_finality_bound_field() {
        let parameters = parameters();
        let mut record = top_k_evaluation_record(&parameters, &roots()).expect("record");
        let proposal = target_proposal_hash(&parameters, &record).expect("proposal");
        record["targetCiphertextHash"] = serde_json::Value::String("ff".repeat(64));
        let mutated = target_proposal_hash(&parameters, &record).expect("mutated proposal");
        assert_ne!(proposal, mutated);
    }

    #[test]
    fn evaluation_record_binds_selected_comparison_profile() {
        let direct_parameters = parameters();
        let direct_context =
            evaluation_context_hash(&direct_parameters).expect("direct context hash");
        let direct_record =
            top_k_evaluation_record(&direct_parameters, &roots()).expect("direct record");

        let mut bit_sliced_parameters = parameters();
        bit_sliced_parameters.comparison_profile = EvaluationComparisonProfile::ScoreBitSliced;
        bit_sliced_parameters.rank_packing_method = RankPackingMethod::PerOptionBroadcast;
        let bit_sliced_context =
            evaluation_context_hash(&bit_sliced_parameters).expect("bit-sliced context hash");
        let bit_sliced_record =
            top_k_evaluation_record(&bit_sliced_parameters, &roots()).expect("bit-sliced record");

        assert_ne!(direct_context, bit_sliced_context);
        assert_ne!(
            direct_record["topKCircuitHash"],
            bit_sliced_record["topKCircuitHash"]
        );
        assert_eq!(
            direct_record["comparisonProfile"],
            "direct-encrypted-score-comparison-v1"
        );
        assert_eq!(
            direct_record["encryptedComparisonInputRoot"],
            "02".repeat(64)
        );
        assert!(direct_record["encryptedScoreBitInputRoot"].is_null());
        assert_eq!(
            bit_sliced_record["comparisonProfile"],
            "encrypted-score-bit-sliced-comparison-v1"
        );
        assert_eq!(
            bit_sliced_record["encryptedScoreBitInputRoot"],
            "02".repeat(64)
        );
        assert!(bit_sliced_record["encryptedComparisonInputRoot"].is_null());
    }

    #[test]
    fn evaluation_record_binds_rank_packing_method() {
        let generator_ordered_parameters = parameters();
        let generator_ordered_context =
            evaluation_context_hash(&generator_ordered_parameters).expect("packed context");
        let generator_ordered_record =
            top_k_evaluation_record(&generator_ordered_parameters, &roots())
                .expect("packed record");

        let mut broadcast_parameters = parameters();
        broadcast_parameters.rank_packing_method = RankPackingMethod::PerOptionBroadcast;
        let broadcast_context =
            evaluation_context_hash(&broadcast_parameters).expect("broadcast context");
        let broadcast_record =
            top_k_evaluation_record(&broadcast_parameters, &roots()).expect("broadcast record");

        assert_ne!(generator_ordered_context, broadcast_context);
        assert_ne!(
            generator_ordered_record["topKCircuitHash"],
            broadcast_record["topKCircuitHash"]
        );
        assert_eq!(
            generator_ordered_record["rankPackingMethod"],
            "generator-ordered"
        );
        assert_eq!(
            broadcast_record["rankPackingMethod"],
            "per-option-broadcast"
        );
    }

    #[test]
    fn noise_certificate_flags_depth_feasibility() {
        // The full 200-domain direct-comparison profile fits the conservative
        // usable-depth budget only with the depth-optimized comparison schedule.
        // The bit-sliced profile remains rejected.
        let heavy = evaluation_noise_certificate(&parameters()).expect("heavy certificate");
        assert_eq!(
            heavy["profileLabel"],
            "DirectScoreComparisonProfileFitsDepthBudget"
        );
        assert_eq!(
            heavy["bitSlicedProfileLabel"],
            "BitSlicedEvaluatorProfileRejected"
        );
        assert_eq!(
            heavy["comparisonInputProfileLabel"],
            "DirectScoreComparisonProfileFitsDepthBudget"
        );
        assert_eq!(
            heavy["operationCounts"]["comparisonInputMultiplicativeDepth"],
            14
        );
        assert_eq!(
            heavy["operationCounts"]["comparisonInputDepthOptimalMultiplicativeDepth"],
            14
        );
        assert_eq!(heavy["usableMultiplicativeDepth"], 14);
        // A tiny domain fits the chain and is accepted.
        let mut small = parameters();
        small.score_domain_max = 3;
        small.option_count = 2;
        small.top_count = 1;
        small.comparison_profile = EvaluationComparisonProfile::ScoreBitSliced;
        small.rank_packing_method = RankPackingMethod::PerOptionBroadcast;
        let light = evaluation_noise_certificate(&small).expect("light certificate");
        assert_eq!(light["profileLabel"], "BitSlicedEvaluatorProfileAccepted");
    }

    #[test]
    fn appendix_d_statement_binds_target_and_context() {
        let parameters = parameters();
        let record = top_k_evaluation_record(&parameters, &roots()).expect("record");
        let proposal = target_proposal_hash(&parameters, &record).expect("proposal");
        let statement = appendix_d_public_input_statement(
            &parameters,
            record["topKCiphertextHash"].as_str().expect("top-k hash"),
            record["targetCiphertextHash"]
                .as_str()
                .expect("target hash"),
            "09".repeat(64).as_str(),
            &proposal,
        )
        .expect("statement");
        assert_eq!(statement["statusLabels"][1], "AppendixDNotClosed");
        assert!(statement["evaluatorInputStatementHash"].as_str().is_some());
    }
}
