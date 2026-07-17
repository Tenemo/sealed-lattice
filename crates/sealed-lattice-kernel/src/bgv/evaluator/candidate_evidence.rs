//! Deterministic evaluator candidate generation and parameter evidence.
//!
//! These records are independent parameter evidence. They are not protocol
//! artifacts, are never accepted from a producer, and never mint a suite
//! identifier. Candidate acceptance is a typed gate over recomputed values.

use num_bigint::{BigInt, BigUint};
use num_traits::Signed;
use serde_json::{Value, json};

use crate::{
    bgv::{
        direct_ballots::{MAXIMUM_SCORE, MINIMUM_SCORE},
        key_switch_topology::KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::FOUNDATION_PROFILE,
    hashing::{canonical_json, hash512_hex},
};

use super::{
    noise_recurrence::{
        DirectBallotTargetNoiseBound, SymbolicCiphertextBound,
        direct_ballot_target_noise_bounds_at_working_level,
    },
    top_k::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, DIRECT_COMPARISON_OUTPUT_LEVEL,
        RANK_LOOKUP_BABY_STEP_COUNT, SELECTED_EVALUATOR_WORKING_LEVEL, comparison_polynomials,
        direct_comparison_baby_step_count, interpolate_coefficients,
        selected_evaluator_rotation_key_schedule,
    },
};

const CANDIDATE_INPUT_HASH_DOMAIN: &str = "sealed-lattice/evaluator/candidate-input-evidence/v1";
const CANDIDATE_OUTPUT_HASH_DOMAIN: &str = "sealed-lattice/evaluator/candidate-output-evidence/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvaluatorKeySwitchMethod {
    HybridExactInteger,
}

impl EvaluatorKeySwitchMethod {
    fn identifier(self) -> &'static str {
        match self {
            Self::HybridExactInteger => "hybrid-exact-integer",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorTargetSelectionInput {
    pub(crate) top_count: usize,
    pub(crate) indicator_coefficients: Vec<u64>,
    pub(crate) order_coefficients: Vec<u64>,
}

impl EvaluatorTargetSelectionInput {
    fn canonical_value(&self) -> Value {
        json!({
            "topCount": self.top_count,
            "indicatorCoefficients": self.indicator_coefficients,
            "orderCoefficients": self.order_coefficients,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorCandidateInput {
    pub(crate) participant_count: u64,
    pub(crate) maximum_ballot_count: usize,
    pub(crate) option_count: usize,
    pub(crate) minimum_score: u64,
    pub(crate) maximum_score: u64,
    pub(crate) polynomial_degree: usize,
    pub(crate) plaintext_modulus: u64,
    pub(crate) data_primes: Vec<u64>,
    pub(crate) special_primes: Vec<u64>,
    pub(crate) key_switch_method: EvaluatorKeySwitchMethod,
    pub(crate) key_switch_data_primes_per_block: usize,
    pub(crate) evaluator_working_level: usize,
    pub(crate) comparison_output_level: usize,
    pub(crate) target_ciphertext_level: usize,
    pub(crate) comparison_baby_step_count: usize,
    pub(crate) rank_lookup_baby_step_count: usize,
    pub(crate) comparison_coefficients: Vec<u64>,
    pub(crate) target_selections: Vec<EvaluatorTargetSelectionInput>,
    pub(crate) relinearization_levels: Vec<usize>,
    pub(crate) galois_key_schedule: Vec<(usize, usize)>,
}

impl EvaluatorCandidateInput {
    pub(crate) fn implemented() -> CanonicalResult<Self> {
        let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
        let option_count = usize::from(FOUNDATION_PROFILE.option_count);
        let score_difference_bound = (MAXIMUM_SCORE - MINIMUM_SCORE)
            .checked_mul(participant_count)
            .ok_or_else(|| invalid_candidate_evidence("comparison domain overflowed"))?;
        let (_, comparison_coefficients) = comparison_polynomials(score_difference_bound)?;
        let target_selections = (1..=option_count)
            .map(|top_count| {
                if top_count == option_count {
                    return Ok(EvaluatorTargetSelectionInput {
                        top_count,
                        indicator_coefficients: Vec::new(),
                        order_coefficients: Vec::new(),
                    });
                }
                let indicator_values = (0..option_count)
                    .map(|rank_value| u64::from(rank_value < top_count))
                    .collect::<Vec<_>>();
                let order_values = (0..option_count)
                    .map(|rank_value| {
                        if rank_value < top_count {
                            u64::try_from(rank_value + 1).expect("rank value fits u64")
                        } else {
                            0
                        }
                    })
                    .collect::<Vec<_>>();
                Ok(EvaluatorTargetSelectionInput {
                    top_count,
                    indicator_coefficients: interpolate_coefficients(&indicator_values)?,
                    order_coefficients: interpolate_coefficients(&order_values)?,
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        Ok(Self {
            participant_count,
            maximum_ballot_count: usize::try_from(participant_count)
                .expect("participant count fits usize"),
            option_count,
            minimum_score: MINIMUM_SCORE,
            maximum_score: MAXIMUM_SCORE,
            polynomial_degree: POLYNOMIAL_DEGREE,
            plaintext_modulus: PLAINTEXT_MODULUS,
            data_primes: DATA_PRIMES.to_vec(),
            special_primes: SPECIAL_PRIMES.to_vec(),
            key_switch_method: EvaluatorKeySwitchMethod::HybridExactInteger,
            key_switch_data_primes_per_block: KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
            evaluator_working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
            comparison_output_level: DIRECT_COMPARISON_OUTPUT_LEVEL,
            target_ciphertext_level: CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            comparison_baby_step_count: direct_comparison_baby_step_count(score_difference_bound)?,
            rank_lookup_baby_step_count: RANK_LOOKUP_BABY_STEP_COUNT,
            comparison_coefficients,
            target_selections,
            relinearization_levels: vec![SELECTED_EVALUATOR_WORKING_LEVEL],
            galois_key_schedule: selected_evaluator_rotation_key_schedule(option_count)?,
        })
    }

    fn canonical_value(&self) -> Value {
        json!({
            "objectType": "EvaluatorCandidateInputEvidence",
            "version": 1,
            "participantCount": self.participant_count,
            "maximumBallotCount": self.maximum_ballot_count,
            "optionCount": self.option_count,
            "minimumScore": self.minimum_score,
            "maximumScore": self.maximum_score,
            "polynomialDegree": self.polynomial_degree,
            "plaintextModulus": self.plaintext_modulus,
            "dataPrimes": self.data_primes,
            "specialPrimes": self.special_primes,
            "keySwitchMethod": self.key_switch_method.identifier(),
            "keySwitchDataPrimesPerBlock": self.key_switch_data_primes_per_block,
            "evaluatorWorkingLevel": self.evaluator_working_level,
            "comparisonOutputLevel": self.comparison_output_level,
            "targetCiphertextLevel": self.target_ciphertext_level,
            "comparisonBabyStepCount": self.comparison_baby_step_count,
            "rankLookupBabyStepCount": self.rank_lookup_baby_step_count,
            "comparisonCoefficients": self.comparison_coefficients,
            "targetSelections": self.target_selections.iter()
                .map(EvaluatorTargetSelectionInput::canonical_value)
                .collect::<Vec<_>>(),
            "relinearizationLevels": self.relinearization_levels,
            "galoisKeySchedule": self.galois_key_schedule.iter()
                .map(|(galois_element, level)| json!({
                    "galoisElement": galois_element,
                    "level": level,
                }))
                .collect::<Vec<_>>(),
        })
    }

    pub(crate) fn canonical_bytes(&self) -> CanonicalResult<Vec<u8>> {
        Ok(canonical_json(&self.canonical_value())?.into_bytes())
    }

    pub(crate) fn evidence_hash(&self) -> CanonicalResult<String> {
        let bytes = self.canonical_bytes()?;
        Ok(hash512_hex(CANDIDATE_INPUT_HASH_DOMAIN, &[&bytes]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorCiphertextBoundEvidence {
    pub(crate) level: usize,
    pub(crate) decrypt_scaling: u64,
    pub(crate) component_count: usize,
    pub(crate) message_coefficient_bound: BigUint,
    pub(crate) error_coefficient_bound: BigUint,
    pub(crate) raw_decryption_bound: BigUint,
    pub(crate) active_modulus: BigUint,
    pub(crate) final_decryption_margin: BigInt,
    pub(crate) minimum_decryption_margin: BigInt,
}

impl EvaluatorCiphertextBoundEvidence {
    fn from_symbolic_bound(bound: &SymbolicCiphertextBound) -> Self {
        Self {
            level: bound.level,
            decrypt_scaling: bound.decrypt_scaling,
            component_count: bound.component_count,
            message_coefficient_bound: bound.message_coefficient_bound.clone(),
            error_coefficient_bound: bound.error_coefficient_bound.clone(),
            raw_decryption_bound: bound.raw_decryption_bound(),
            active_modulus: bound.active_modulus(),
            final_decryption_margin: bound.final_decryption_margin(),
            minimum_decryption_margin: bound.minimum_decryption_margin.clone(),
        }
    }

    fn canonical_value(&self) -> Value {
        json!({
            "level": self.level,
            "decryptScaling": self.decrypt_scaling,
            "componentCount": self.component_count,
            "messageCoefficientBound": self.message_coefficient_bound.to_string(),
            "errorCoefficientBound": self.error_coefficient_bound.to_string(),
            "rawDecryptionBound": self.raw_decryption_bound.to_string(),
            "activeModulus": self.active_modulus.to_string(),
            "finalDecryptionMargin": self.final_decryption_margin.to_string(),
            "minimumDecryptionMargin": self.minimum_decryption_margin.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorTargetOutputEvidence {
    pub(crate) top_count: usize,
    pub(crate) target_identifier: EvaluatorCiphertextBoundEvidence,
    pub(crate) target_order: EvaluatorCiphertextBoundEvidence,
}

impl EvaluatorTargetOutputEvidence {
    fn from_noise_bound(bound: &DirectBallotTargetNoiseBound) -> Self {
        Self {
            top_count: bound.top_count,
            target_identifier: EvaluatorCiphertextBoundEvidence::from_symbolic_bound(
                &bound.target_identifier,
            ),
            target_order: EvaluatorCiphertextBoundEvidence::from_symbolic_bound(
                &bound.target_order,
            ),
        }
    }

    fn canonical_value(&self) -> Value {
        json!({
            "topCount": self.top_count,
            "targetIdentifier": self.target_identifier.canonical_value(),
            "targetOrder": self.target_order.canonical_value(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EvaluatorBallotCountEvidence {
    Outputs {
        ballot_count: usize,
        targets: Vec<EvaluatorTargetOutputEvidence>,
    },
    RecurrenceFailure {
        ballot_count: usize,
        error_code: CanonicalErrorCode,
        message: String,
    },
}

impl EvaluatorBallotCountEvidence {
    fn canonical_value(&self) -> Value {
        match self {
            Self::Outputs {
                ballot_count,
                targets,
            } => json!({
                "ballotCount": ballot_count,
                "targets": targets.iter()
                    .map(EvaluatorTargetOutputEvidence::canonical_value)
                    .collect::<Vec<_>>(),
            }),
            Self::RecurrenceFailure {
                ballot_count,
                error_code,
                message,
            } => json!({
                "ballotCount": ballot_count,
                "recurrenceFailure": {
                    "errorCode": error_code.as_str(),
                    "message": message,
                },
            }),
        }
    }

    fn ballot_count(&self) -> usize {
        match self {
            Self::Outputs { ballot_count, .. } | Self::RecurrenceFailure { ballot_count, .. } => {
                *ballot_count
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorCandidateOutputEvidence {
    pub(crate) input_evidence_hash: String,
    pub(crate) ballot_counts: Vec<EvaluatorBallotCountEvidence>,
}

impl EvaluatorCandidateOutputEvidence {
    fn canonical_value(&self) -> Value {
        json!({
            "objectType": "EvaluatorCandidateOutputEvidence",
            "version": 1,
            "inputEvidenceHash": self.input_evidence_hash,
            "ballotCounts": self.ballot_counts.iter()
                .map(EvaluatorBallotCountEvidence::canonical_value)
                .collect::<Vec<_>>(),
        })
    }

    pub(crate) fn canonical_bytes(&self) -> CanonicalResult<Vec<u8>> {
        Ok(canonical_json(&self.canonical_value())?.into_bytes())
    }

    pub(crate) fn evidence_hash(&self) -> CanonicalResult<String> {
        let bytes = self.canonical_bytes()?;
        Ok(hash512_hex(CANDIDATE_OUTPUT_HASH_DOMAIN, &[&bytes]))
    }
}

pub(crate) fn generate_implemented_evaluator_candidate_evidence()
-> CanonicalResult<(EvaluatorCandidateInput, EvaluatorCandidateOutputEvidence)> {
    let input = EvaluatorCandidateInput::implemented()?;
    let input_evidence_hash = input.evidence_hash()?;
    let ballot_counts = (1..=input.maximum_ballot_count)
        .map(|ballot_count| generate_ballot_count_evidence(&input, ballot_count))
        .collect();
    Ok((
        input,
        EvaluatorCandidateOutputEvidence {
            input_evidence_hash,
            ballot_counts,
        },
    ))
}

fn generate_ballot_count_evidence(
    input: &EvaluatorCandidateInput,
    ballot_count: usize,
) -> EvaluatorBallotCountEvidence {
    generate_ballot_count_evidence_at_working_level(
        input,
        ballot_count,
        input.evaluator_working_level,
    )
}

fn generate_ballot_count_evidence_at_working_level(
    input: &EvaluatorCandidateInput,
    ballot_count: usize,
    working_level: usize,
) -> EvaluatorBallotCountEvidence {
    match direct_ballot_target_noise_bounds_at_working_level(
        input.participant_count,
        ballot_count,
        input.option_count,
        input.minimum_score,
        input.maximum_score,
        working_level,
    ) {
        Ok(bounds) => EvaluatorBallotCountEvidence::Outputs {
            ballot_count,
            targets: bounds
                .iter()
                .map(EvaluatorTargetOutputEvidence::from_noise_bound)
                .collect(),
        },
        Err(error) => EvaluatorBallotCountEvidence::RecurrenceFailure {
            ballot_count,
            error_code: error.code,
            message: error.message,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EvaluatorCandidateFailure {
    InputEvidenceHashMismatch,
    MissingOrDisorderedBallotCount {
        expected_ballot_count: usize,
        observed_ballot_count: Option<usize>,
    },
    RecurrenceFailure {
        ballot_count: usize,
        error_code: CanonicalErrorCode,
        message: String,
    },
    TargetCountMismatch {
        ballot_count: usize,
        observed_target_count: usize,
    },
    TerminalLevelMismatch {
        ballot_count: usize,
        top_count: usize,
        expected_level: usize,
        identifier_level: usize,
        order_level: usize,
    },
    CiphertextShapeMismatch {
        ballot_count: usize,
        top_count: usize,
        identifier_component_count: usize,
        order_component_count: usize,
    },
    NonpositiveDecryptionMargin {
        ballot_count: usize,
        top_count: usize,
        identifier_minimum_margin: BigInt,
        order_minimum_margin: BigInt,
    },
}

impl EvaluatorCandidateFailure {
    fn canonical_value(&self) -> Value {
        match self {
            Self::InputEvidenceHashMismatch => json!({
                "failureCode": "input-evidence-hash-mismatch",
            }),
            Self::MissingOrDisorderedBallotCount {
                expected_ballot_count,
                observed_ballot_count,
            } => json!({
                "failureCode": "missing-or-disordered-ballot-count",
                "expectedBallotCount": expected_ballot_count,
                "observedBallotCount": observed_ballot_count,
            }),
            Self::RecurrenceFailure {
                ballot_count,
                error_code,
                message,
            } => json!({
                "failureCode": "recurrence-failure",
                "ballotCount": ballot_count,
                "errorCode": error_code.as_str(),
                "message": message,
            }),
            Self::TargetCountMismatch {
                ballot_count,
                observed_target_count,
            } => json!({
                "failureCode": "target-count-mismatch",
                "ballotCount": ballot_count,
                "observedTargetCount": observed_target_count,
            }),
            Self::TerminalLevelMismatch {
                ballot_count,
                top_count,
                expected_level,
                identifier_level,
                order_level,
            } => json!({
                "failureCode": "terminal-level-mismatch",
                "ballotCount": ballot_count,
                "topCount": top_count,
                "expectedLevel": expected_level,
                "identifierLevel": identifier_level,
                "orderLevel": order_level,
            }),
            Self::CiphertextShapeMismatch {
                ballot_count,
                top_count,
                identifier_component_count,
                order_component_count,
            } => json!({
                "failureCode": "ciphertext-shape-mismatch",
                "ballotCount": ballot_count,
                "topCount": top_count,
                "identifierComponentCount": identifier_component_count,
                "orderComponentCount": order_component_count,
            }),
            Self::NonpositiveDecryptionMargin {
                ballot_count,
                top_count,
                identifier_minimum_margin,
                order_minimum_margin,
            } => json!({
                "failureCode": "nonpositive-decryption-margin",
                "ballotCount": ballot_count,
                "topCount": top_count,
                "identifierMinimumMargin": identifier_minimum_margin.to_string(),
                "orderMinimumMargin": order_minimum_margin.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorCandidateInfeasibilityCertificate {
    pub(crate) input_evidence_hash: String,
    pub(crate) output_evidence_hash: String,
    pub(crate) failures: Vec<EvaluatorCandidateFailure>,
}

impl EvaluatorCandidateInfeasibilityCertificate {
    fn canonical_value(&self) -> Value {
        json!({
            "objectType": "EvaluatorCandidateInfeasibilityCertificate",
            "version": 1,
            "inputEvidenceHash": self.input_evidence_hash,
            "outputEvidenceHash": self.output_evidence_hash,
            "failures": self.failures.iter()
                .map(EvaluatorCandidateFailure::canonical_value)
                .collect::<Vec<_>>(),
        })
    }

    pub(crate) fn canonical_bytes(&self) -> CanonicalResult<Vec<u8>> {
        Ok(canonical_json(&self.canonical_value())?.into_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedEvaluatorCandidate {
    pub(crate) input_evidence_hash: String,
    pub(crate) output_evidence_hash: String,
}

pub(crate) fn apply_evaluator_candidate_gates(
    input: &EvaluatorCandidateInput,
    output: &EvaluatorCandidateOutputEvidence,
) -> CanonicalResult<Result<AcceptedEvaluatorCandidate, EvaluatorCandidateInfeasibilityCertificate>>
{
    let input_evidence_hash = input.evidence_hash()?;
    let output_evidence_hash = output.evidence_hash()?;
    let mut failures = Vec::new();
    if output.input_evidence_hash != input_evidence_hash {
        failures.push(EvaluatorCandidateFailure::InputEvidenceHashMismatch);
    }
    for expected_ballot_count in 1..=input.maximum_ballot_count {
        let Some(ballot_evidence) = output.ballot_counts.get(expected_ballot_count - 1) else {
            failures.push(EvaluatorCandidateFailure::MissingOrDisorderedBallotCount {
                expected_ballot_count,
                observed_ballot_count: None,
            });
            continue;
        };
        if ballot_evidence.ballot_count() != expected_ballot_count {
            failures.push(EvaluatorCandidateFailure::MissingOrDisorderedBallotCount {
                expected_ballot_count,
                observed_ballot_count: Some(ballot_evidence.ballot_count()),
            });
            continue;
        }
        let targets = match ballot_evidence {
            EvaluatorBallotCountEvidence::Outputs { targets, .. } => targets,
            EvaluatorBallotCountEvidence::RecurrenceFailure {
                ballot_count,
                error_code,
                message,
            } => {
                failures.push(EvaluatorCandidateFailure::RecurrenceFailure {
                    ballot_count: *ballot_count,
                    error_code: error_code.clone(),
                    message: message.clone(),
                });
                continue;
            }
        };
        if targets.len() != input.option_count
            || targets
                .iter()
                .enumerate()
                .any(|(index, target)| target.top_count != index + 1)
        {
            failures.push(EvaluatorCandidateFailure::TargetCountMismatch {
                ballot_count: expected_ballot_count,
                observed_target_count: targets.len(),
            });
            continue;
        }
        for target in targets {
            if target.target_identifier.level != input.target_ciphertext_level
                || target.target_order.level != input.target_ciphertext_level
            {
                failures.push(EvaluatorCandidateFailure::TerminalLevelMismatch {
                    ballot_count: expected_ballot_count,
                    top_count: target.top_count,
                    expected_level: input.target_ciphertext_level,
                    identifier_level: target.target_identifier.level,
                    order_level: target.target_order.level,
                });
            }
            if target.target_identifier.component_count != 2
                || target.target_order.component_count != 2
            {
                failures.push(EvaluatorCandidateFailure::CiphertextShapeMismatch {
                    ballot_count: expected_ballot_count,
                    top_count: target.top_count,
                    identifier_component_count: target.target_identifier.component_count,
                    order_component_count: target.target_order.component_count,
                });
            }
            if !target
                .target_identifier
                .minimum_decryption_margin
                .is_positive()
                || !target.target_order.minimum_decryption_margin.is_positive()
            {
                failures.push(EvaluatorCandidateFailure::NonpositiveDecryptionMargin {
                    ballot_count: expected_ballot_count,
                    top_count: target.top_count,
                    identifier_minimum_margin: target
                        .target_identifier
                        .minimum_decryption_margin
                        .clone(),
                    order_minimum_margin: target.target_order.minimum_decryption_margin.clone(),
                });
            }
        }
    }
    if output.ballot_counts.len() > input.maximum_ballot_count {
        failures.push(EvaluatorCandidateFailure::MissingOrDisorderedBallotCount {
            expected_ballot_count: input.maximum_ballot_count + 1,
            observed_ballot_count: output
                .ballot_counts
                .get(input.maximum_ballot_count)
                .map(EvaluatorBallotCountEvidence::ballot_count),
        });
    }

    if failures.is_empty() {
        Ok(Ok(AcceptedEvaluatorCandidate {
            input_evidence_hash,
            output_evidence_hash,
        }))
    } else {
        Ok(Err(EvaluatorCandidateInfeasibilityCertificate {
            input_evidence_hash,
            output_evidence_hash,
            failures,
        }))
    }
}

fn invalid_candidate_evidence(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn implemented_evidence() -> (EvaluatorCandidateInput, EvaluatorCandidateOutputEvidence) {
        generate_implemented_evaluator_candidate_evidence()
            .expect("implemented evaluator evidence derives")
    }

    #[test]
    fn implemented_candidate_inputs_and_outputs_are_byte_stable() {
        let (first_input, first_output) = implemented_evidence();
        let (second_input, second_output) = implemented_evidence();
        assert_eq!(
            first_input.canonical_bytes(),
            second_input.canonical_bytes()
        );
        assert_eq!(
            first_output.canonical_bytes(),
            second_output.canonical_bytes()
        );
        assert_eq!(first_input.evidence_hash(), second_input.evidence_hash());
        assert_eq!(first_output.evidence_hash(), second_output.evidence_hash());
    }

    #[test]
    fn candidate_input_bytes_bind_parameters_programs_and_key_catalogs() {
        let (input, _) = implemented_evidence();
        let baseline = input.canonical_bytes().unwrap();

        let mut changed_special_prime = input.clone();
        changed_special_prime.special_primes[0] -= 1;
        assert_ne!(changed_special_prime.canonical_bytes().unwrap(), baseline);

        let mut changed_program = input.clone();
        changed_program.target_selections[0].indicator_coefficients[0] ^= 1;
        assert_ne!(changed_program.canonical_bytes().unwrap(), baseline);

        let mut changed_key_catalog = input.clone();
        changed_key_catalog.galois_key_schedule.swap(0, 1);
        assert_ne!(changed_key_catalog.canonical_bytes().unwrap(), baseline);
    }

    #[test]
    fn current_candidate_certificate_preserves_recomputed_margin_failures() {
        let (input, output) = implemented_evidence();
        assert_eq!(
            input.key_switch_method,
            EvaluatorKeySwitchMethod::HybridExactInteger
        );
        let certificate = apply_evaluator_candidate_gates(&input, &output)
            .unwrap()
            .expect_err("the implemented candidate must not be accepted");
        let recurrence_failure_count = certificate
            .failures
            .iter()
            .filter(|failure| {
                matches!(failure, EvaluatorCandidateFailure::RecurrenceFailure { .. })
            })
            .count();
        let nonpositive_margin_failure_count = certificate
            .failures
            .iter()
            .filter(|failure| {
                matches!(
                    failure,
                    EvaluatorCandidateFailure::NonpositiveDecryptionMargin { .. }
                )
            })
            .count();
        assert_eq!(recurrence_failure_count, 0);
        assert_eq!(nonpositive_margin_failure_count, 190);
        assert_eq!(
            certificate.failures.len(),
            recurrence_failure_count + nonpositive_margin_failure_count
        );
        assert!(matches!(
            certificate.failures.first(),
            Some(EvaluatorCandidateFailure::NonpositiveDecryptionMargin {
                ballot_count: 1,
                top_count: 1,
                ..
            })
        ));
        assert!(certificate.failures.iter().any(|failure| matches!(
            failure,
            EvaluatorCandidateFailure::NonpositiveDecryptionMargin {
                ballot_count,
                top_count: 19,
                ..
            } if *ballot_count == usize::from(FOUNDATION_PROFILE.participant_count)
        )));
        assert!(!certificate.failures.iter().any(|failure| matches!(
            failure,
            EvaluatorCandidateFailure::NonpositiveDecryptionMargin { top_count: 20, .. }
        )));
        assert_eq!(
            certificate.canonical_bytes().unwrap(),
            apply_evaluator_candidate_gates(&input, &output)
                .unwrap()
                .expect_err("candidate remains rejected")
                .canonical_bytes()
                .unwrap()
        );
    }

    #[test]
    fn selected_profile_evidence_retains_all_twenty_target_bounds() {
        let (_, output) = implemented_evidence();
        let selected_profile_index = usize::from(FOUNDATION_PROFILE.participant_count - 1);
        let EvaluatorBallotCountEvidence::Outputs { targets, .. } =
            &output.ballot_counts[selected_profile_index]
        else {
            panic!("selected-profile recurrence must produce target evidence");
        };
        assert_eq!(targets.len(), 20);
        let expected_error_bound_bit_lengths = vec![
            5195, 5196, 5196, 5196, 5195, 5195, 5195, 5196, 5196, 5196, 5196, 5196, 5195, 5195,
            5193, 5194, 5195, 5196, 5195, 74,
        ];
        let actual_error_bound_bit_lengths = targets
            .iter()
            .map(|target| {
                target
                    .target_identifier
                    .error_coefficient_bound
                    .clone()
                    .max(target.target_order.error_coefficient_bound.clone())
                    .bits()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual_error_bound_bit_lengths,
            expected_error_bound_bit_lengths
        );
        let (all_options_target, bounded_targets) = targets
            .split_last()
            .expect("the selected-profile evidence retains every target");
        assert_eq!(all_options_target.top_count, 20);
        assert!(
            all_options_target
                .target_identifier
                .minimum_decryption_margin
                .is_positive()
        );
        assert!(
            all_options_target
                .target_order
                .minimum_decryption_margin
                .is_positive()
        );
        for target in bounded_targets {
            assert!(
                target
                    .target_identifier
                    .minimum_decryption_margin
                    .is_negative()
            );
            assert!(target.target_order.minimum_decryption_margin.is_negative());
        }
    }

    #[test]
    fn one_ballot_evidence_uses_the_canonical_working_level() {
        let (_, output) = implemented_evidence();
        let EvaluatorBallotCountEvidence::Outputs {
            ballot_count,
            targets,
        } = &output.ballot_counts[0]
        else {
            panic!("one-ballot recurrence must use the canonical evaluator level");
        };
        assert_eq!(*ballot_count, 1);
        assert_eq!(targets.len(), 20);
        assert!(
            targets
                .iter()
                .enumerate()
                .all(|(target_index, target)| target.top_count == target_index + 1)
        );
        let (all_options_target, bounded_targets) = targets
            .split_last()
            .expect("one-ballot evidence retains every target");
        assert_eq!(all_options_target.top_count, 20);
        assert!(
            all_options_target
                .target_identifier
                .minimum_decryption_margin
                .is_positive()
        );
        assert!(
            all_options_target
                .target_order
                .minimum_decryption_margin
                .is_positive()
        );
        assert!(bounded_targets.iter().all(|target| {
            target
                .target_identifier
                .minimum_decryption_margin
                .is_negative()
                && target.target_order.minimum_decryption_margin.is_negative()
        }));
    }
}
