//! Deterministic correspondence evidence for the checked common construction.
//!
//! This test-only module derives every row from production relation and
//! construction catalogs. It does not turn catalog coverage into a proof of
//! the construction theorem.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::bgv::proof_suite::prover::{
    persisted_pre_challenge_column_coefficient_position_counts,
    requested_pre_challenge_source_column_ordinals,
};
use crate::bgv::proof_suite::relation_plan::RelationPlanVariant;
use crate::bgv::proof_suite::transcript::{RowCodeWhirChallenge, RowCodeWhirTracePhase};
use crate::bgv::proof_suite::{
    ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
    selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
};
use crate::foundation::{
    CanonicalItem, Hash512, ProofApplicationSlotCeilings, hash_foundation_tuple_512,
};

use super::construction_plan::{
    RowCodeWhirCheckpointBoundary, RowCodeWhirCommitmentRole, RowCodeWhirConstructionPlan,
    RowCodeWhirExtensionRole, RowCodeWhirObservationRole, RowCodeWhirPhase,
    RowCodeWhirProofSectionPlan, RowCodeWhirProofSectionRole, RowCodeWhirQueryRole,
    RowCodeWhirTranscriptOperation,
};

const CORRESPONDENCE_ARTIFACT_DIGEST_DOMAIN: &str =
    "sealed-lattice/row-code-whir/construction-correspondence-artifact/v1";
const EXPECTED_CORRESPONDENCE_ARTIFACT_DIGEST: Hash512 =
    Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]);
const TRANSCRIPT_SOURCE: &str = include_str!("../transcript.rs");
const EXACT_VERIFIER_SOURCE: &str = include_str!("exact_same_secret/exact_proof.rs");
const PLAIN_WHIR_SOURCE: &str = include_str!("plain_whir.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TranscriptVerifierConsumer {
    AbsorbOpeningBatchMaskEvaluations,
    AbsorbProtocolSchedule,
    SampleDirectExtension,
    SampleDirectDistinctIndices,
    ObserveCommitment,
    ObserveWhirValues,
    SampleWhirExtension,
    SampleWhirQueryVector,
    BeginFinalProofStream,
}

impl TranscriptVerifierConsumer {
    const ALL: [Self; 9] = [
        Self::AbsorbOpeningBatchMaskEvaluations,
        Self::AbsorbProtocolSchedule,
        Self::SampleDirectExtension,
        Self::SampleDirectDistinctIndices,
        Self::ObserveCommitment,
        Self::ObserveWhirValues,
        Self::SampleWhirExtension,
        Self::SampleWhirQueryVector,
        Self::BeginFinalProofStream,
    ];

    const fn identifier(self) -> &'static str {
        match self {
            Self::AbsorbOpeningBatchMaskEvaluations => {
                "RowCodeWhirTranscript::absorb_opening_batch_mask_evaluations"
            }
            Self::AbsorbProtocolSchedule => "RowCodeWhirTranscript::absorb_protocol_schedule",
            Self::SampleDirectExtension => "RowCodeWhirTranscript::sample_direct_extension",
            Self::SampleDirectDistinctIndices => {
                "RowCodeWhirTranscript::sample_direct_distinct_indices"
            }
            Self::ObserveCommitment => "RowCodeWhirTranscript::observe_commitment",
            Self::ObserveWhirValues => "RowCodeWhirTranscript::observe_whir_values",
            Self::SampleWhirExtension => "RowCodeWhirTranscript::sample_whir_extension",
            Self::SampleWhirQueryVector => "RowCodeWhirTranscript::sample_whir_query_vector",
            Self::BeginFinalProofStream => "RowCodeWhirTranscript::begin_final_proof_stream",
        }
    }

    const fn rust_function_name(self) -> &'static str {
        match self {
            Self::AbsorbOpeningBatchMaskEvaluations => "absorb_opening_batch_mask_evaluations",
            Self::AbsorbProtocolSchedule => "absorb_protocol_schedule",
            Self::SampleDirectExtension => "sample_direct_extension",
            Self::SampleDirectDistinctIndices => "sample_direct_distinct_indices",
            Self::ObserveCommitment => "observe_commitment",
            Self::ObserveWhirValues => "observe_whir_values",
            Self::SampleWhirExtension => "sample_whir_extension",
            Self::SampleWhirQueryVector => "sample_whir_query_vector",
            Self::BeginFinalProofStream => "begin_final_proof_stream",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ProofSectionVerifierConsumer {
    ExactTranscriptPrefix,
    VerifyProductionOutOfDomainComposition,
    VerifyOpeningBatchMaskChunkEvaluations,
    VerifyPlainAggregateBatchesAtPointsAfterCommitment,
    VerifyPhaseOpenings,
    VerifyBoundTreeAuthentications,
}

impl ProofSectionVerifierConsumer {
    const fn identifier(self) -> &'static str {
        match self {
            Self::ExactTranscriptPrefix => {
                "exact_same_secret::exact_proof::exact_transcript_prefix"
            }
            Self::VerifyProductionOutOfDomainComposition => {
                "exact_same_secret::exact_proof::verify_production_out_of_domain_composition"
            }
            Self::VerifyOpeningBatchMaskChunkEvaluations => {
                "exact_same_secret::exact_proof::verify_opening_batch_mask_chunk_evaluations"
            }
            Self::VerifyPlainAggregateBatchesAtPointsAfterCommitment => {
                "plain_whir::verify_plain_aggregate_batches_at_points_after_commitment"
            }
            Self::VerifyPhaseOpenings => "exact_same_secret::exact_proof::verify_phase_openings",
            Self::VerifyBoundTreeAuthentications => {
                "exact_same_secret::exact_proof::verify_bound_tree_authentications"
            }
        }
    }

    const fn rust_function_name(self) -> &'static str {
        match self {
            Self::ExactTranscriptPrefix => "exact_transcript_prefix",
            Self::VerifyProductionOutOfDomainComposition => {
                "verify_production_out_of_domain_composition"
            }
            Self::VerifyOpeningBatchMaskChunkEvaluations => {
                "verify_opening_batch_mask_chunk_evaluations"
            }
            Self::VerifyPlainAggregateBatchesAtPointsAfterCommitment => {
                "verify_plain_aggregate_batches_at_points_after_commitment"
            }
            Self::VerifyPhaseOpenings => "verify_phase_openings",
            Self::VerifyBoundTreeAuthentications => "verify_bound_tree_authentications",
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::VerifyPlainAggregateBatchesAtPointsAfterCommitment => PLAIN_WHIR_SOURCE,
            _ => EXACT_VERIFIER_SOURCE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ConstructionTheoremObligation {
    InstanceAndPlanIdentity,
    BaseAffineSpan,
    ThetaExtraction,
    AuxiliaryAffineSpan,
    QuotientAffineSpan,
    OutputRootAffineSpan,
    PriorVssInputIdentity,
    SelectorAndBatchingCancellation,
    OuterRowCodeProximity,
    ExplicitPointConstrainedCode,
    WhirFoldAndQueryState,
    CanonicalTerminalProof,
    MaskCorrespondence,
    ExactResume,
}

impl ConstructionTheoremObligation {
    const ALL: [Self; 14] = [
        Self::InstanceAndPlanIdentity,
        Self::BaseAffineSpan,
        Self::ThetaExtraction,
        Self::AuxiliaryAffineSpan,
        Self::QuotientAffineSpan,
        Self::OutputRootAffineSpan,
        Self::PriorVssInputIdentity,
        Self::SelectorAndBatchingCancellation,
        Self::OuterRowCodeProximity,
        Self::ExplicitPointConstrainedCode,
        Self::WhirFoldAndQueryState,
        Self::CanonicalTerminalProof,
        Self::MaskCorrespondence,
        Self::ExactResume,
    ];

    const fn identifier(self) -> &'static str {
        match self {
            Self::InstanceAndPlanIdentity => "instance-and-plan-identity",
            Self::BaseAffineSpan => "base-affine-span",
            Self::ThetaExtraction => "theta-extraction",
            Self::AuxiliaryAffineSpan => "auxiliary-affine-span",
            Self::QuotientAffineSpan => "quotient-affine-span",
            Self::OutputRootAffineSpan => "output-root-affine-span",
            Self::PriorVssInputIdentity => "prior-vss-input-identity",
            Self::SelectorAndBatchingCancellation => "selector-and-batching-cancellation",
            Self::OuterRowCodeProximity => "outer-row-code-proximity",
            Self::ExplicitPointConstrainedCode => "explicit-point-constrained-code",
            Self::WhirFoldAndQueryState => "whir-fold-and-query-state",
            Self::CanonicalTerminalProof => "canonical-terminal-proof",
            Self::MaskCorrespondence => "mask-correspondence",
            Self::ExactResume => "exact-resume",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConstructionApplicabilityHypothesis {
    RelationAndStateCorrespondence,
    WhirConstructionParameters,
    CorrelatedAgreementAndConstraintBatching,
    KnowledgeCompilerHypotheses,
    ExplicitPointAdapter,
    ExactFailurePartition,
    TypedCms19Chain,
    OracleAndCommitmentAssumptions,
}

impl ConstructionApplicabilityHypothesis {
    const UNDISCHARGED: [Self; 7] = [
        Self::RelationAndStateCorrespondence,
        Self::WhirConstructionParameters,
        Self::CorrelatedAgreementAndConstraintBatching,
        Self::KnowledgeCompilerHypotheses,
        Self::ExplicitPointAdapter,
        Self::ExactFailurePartition,
        Self::TypedCms19Chain,
    ];

    const COMPUTATIONAL_ASSUMPTIONS: [Self; 1] = [Self::OracleAndCommitmentAssumptions];

    const fn identifier(self) -> &'static str {
        match self {
            Self::RelationAndStateCorrespondence => "relation-and-state-correspondence",
            Self::WhirConstructionParameters => "whir-construction-parameters",
            Self::CorrelatedAgreementAndConstraintBatching => {
                "correlated-agreement-and-constraint-batching"
            }
            Self::KnowledgeCompilerHypotheses => "knowledge-compiler-hypotheses",
            Self::ExplicitPointAdapter => "explicit-point-adapter",
            Self::ExactFailurePartition => "exact-failure-partition",
            Self::TypedCms19Chain => "typed-cms19-chain",
            Self::OracleAndCommitmentAssumptions => "oracle-and-commitment-assumptions",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptCorrespondenceRow {
    operation_ordinal: u32,
    operation: RowCodeWhirTranscriptOperation,
    verifier_consumer: TranscriptVerifierConsumer,
    theorem_obligations: BTreeSet<ConstructionTheoremObligation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CorrespondenceValidationError {
    MissingOperation,
    DuplicateOperationConsumer,
    OperationReordered,
    StaleVerifierConsumer,
    StaleTheoremMapping,
    MissingVerifierFunction,
    MissingTheoremObligation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SameSecretSourceCorrespondence {
    authenticated_source_polynomial_count: u64,
    persisted_pre_challenge_coefficient_count: u64,
    deterministic_reversed_column_count: u64,
    stored_pre_challenge_column_count: u64,
}

fn selected_same_secret_plan_and_source_correspondence()
-> Result<(RowCodeWhirConstructionPlan, SameSecretSourceCorrespondence), String> {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or_else(|| "the selected same-secret relation context is missing".to_owned())?;
    let relation_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input()
            .map_err(|error| format!("derive selected same-secret relation input: {error:?}"))?,
        &context,
    )
    .map_err(|error| format!("compile selected same-secret relation: {error:?}"))?;
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(relation_plan, &context)
        .map_err(|error| format!("validate selected same-secret relation: {error:?}"))?;
    let variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .map_err(|error| format!("select same-secret relation variant: {error:?}"))?;
    let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
        &artifact,
        variant.schedule_position(),
        variant.top_count(),
    )
    .map_err(|error| format!("derive same-secret construction plan: {error:?}"))?;
    let source_correspondence = same_secret_source_correspondence(&construction_plan, variant)?;
    Ok((construction_plan, source_correspondence))
}

fn same_secret_source_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
) -> Result<SameSecretSourceCorrespondence, String> {
    let requested_source_column_ordinals = requested_pre_challenge_source_column_ordinals(variant)
        .map_err(|error| format!("derive authenticated source catalog: {error:?}"))?;
    if requested_source_column_ordinals != construction_plan.requested_source_column_ordinals {
        return Err("the construction plan and production source catalog diverged".to_owned());
    }
    let source_coefficient_position_counts =
        persisted_pre_challenge_column_coefficient_position_counts(variant)
            .map_err(|error| format!("derive persisted source position counts: {error:?}"))?;
    if source_coefficient_position_counts
        .keys()
        .copied()
        .ne(requested_source_column_ordinals.iter().copied())
    {
        return Err("the source ordinal and coefficient-position catalogs diverged".to_owned());
    }
    let persisted_pre_challenge_coefficient_count = source_coefficient_position_counts
        .values()
        .try_fold(0_u64, |count, coefficient_position_count| {
            count
                .checked_add(*coefficient_position_count)
                .ok_or_else(|| "the persisted coefficient count overflowed".to_owned())
        })?;

    let mut reversed_columns_by_source = BTreeMap::new();
    let mut sources_by_reversed_column = BTreeMap::new();
    let requested_source_columns = requested_source_column_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for batch in variant.ordered_integer_lift_batches() {
        for binding in &batch.ordered_reversed_column_bindings {
            if !requested_source_columns.contains(&binding.source_column_ordinal)
                || requested_source_columns.contains(&binding.reversed_column_ordinal)
            {
                return Err(
                    "a deterministic reversed column is outside the authenticated source flow"
                        .to_owned(),
                );
            }
            if let Some(existing) = reversed_columns_by_source.insert(
                binding.source_column_ordinal,
                binding.reversed_column_ordinal,
            ) && existing != binding.reversed_column_ordinal
            {
                return Err("one source column maps to multiple reversed columns".to_owned());
            }
            if let Some(existing) = sources_by_reversed_column.insert(
                binding.reversed_column_ordinal,
                binding.source_column_ordinal,
            ) && existing != binding.source_column_ordinal
            {
                return Err("one reversed column maps to multiple source columns".to_owned());
            }
        }
    }
    let authenticated_source_polynomial_count =
        u64::try_from(requested_source_column_ordinals.len())
            .map_err(|_| "the authenticated source count does not fit u64".to_owned())?;
    let deterministic_reversed_column_count = u64::try_from(sources_by_reversed_column.len())
        .map_err(|_| "the reversed-column count does not fit u64".to_owned())?;
    let stored_pre_challenge_column_count = authenticated_source_polynomial_count
        .checked_add(deterministic_reversed_column_count)
        .ok_or_else(|| "the stored pre-challenge column count overflowed".to_owned())?;
    Ok(SameSecretSourceCorrespondence {
        authenticated_source_polynomial_count,
        persisted_pre_challenge_coefficient_count,
        deterministic_reversed_column_count,
        stored_pre_challenge_column_count,
    })
}

fn transcript_verifier_consumer(
    operation: &RowCodeWhirTranscriptOperation,
) -> TranscriptVerifierConsumer {
    match operation {
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. } => {
            TranscriptVerifierConsumer::AbsorbOpeningBatchMaskEvaluations
        }
        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. } => {
            TranscriptVerifierConsumer::AbsorbProtocolSchedule
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(_),
            ..
        } => TranscriptVerifierConsumer::SampleDirectExtension,
        RowCodeWhirTranscriptOperation::SampleExtension {
            role:
                RowCodeWhirExtensionRole::InitialOutOfDomainPoint { .. }
                | RowCodeWhirExtensionRole::OpeningBatching
                | RowCodeWhirExtensionRole::InitialSumcheck { .. }
                | RowCodeWhirExtensionRole::RoundOutOfDomainPoint { .. }
                | RowCodeWhirExtensionRole::RoundCheckpoint { .. }
                | RowCodeWhirExtensionRole::RoundCombination { .. }
                | RowCodeWhirExtensionRole::RoundSumcheck { .. }
                | RowCodeWhirExtensionRole::FinalSumcheck { .. },
            ..
        } => TranscriptVerifierConsumer::SampleWhirExtension,
        RowCodeWhirTranscriptOperation::ObserveCommitment { .. } => {
            TranscriptVerifierConsumer::ObserveCommitment
        }
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::Outer | RowCodeWhirQueryRole::Bound,
            ..
        } => TranscriptVerifierConsumer::SampleDirectDistinctIndices,
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::WhirEpoch { .. },
            ..
        } => TranscriptVerifierConsumer::SampleWhirQueryVector,
        RowCodeWhirTranscriptOperation::ObserveExtensionValues { .. } => {
            TranscriptVerifierConsumer::ObserveWhirValues
        }
        RowCodeWhirTranscriptOperation::FinishProofStream => {
            TranscriptVerifierConsumer::BeginFinalProofStream
        }
    }
}

fn theorem_obligations_for_operation(
    operation: &RowCodeWhirTranscriptOperation,
) -> BTreeSet<ConstructionTheoremObligation> {
    use ConstructionTheoremObligation as Obligation;

    let mut obligations = BTreeSet::new();
    match operation {
        RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. } => {
            obligations.insert(Obligation::MaskCorrespondence);
        }
        RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. } => {
            obligations.extend([
                Obligation::InstanceAndPlanIdentity,
                Obligation::ThetaExtraction,
                Obligation::ExplicitPointConstrainedCode,
            ]);
        }
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(challenge),
            ..
        } => match challenge {
            RowCodeWhirChallenge::PointSelectorWeight { .. } => {
                obligations.insert(Obligation::SelectorAndBatchingCancellation);
            }
            RowCodeWhirChallenge::TraceColumnGroupWeight { phase, .. } => {
                obligations.insert(match phase {
                    RowCodeWhirTracePhase::Base => Obligation::BaseAffineSpan,
                    RowCodeWhirTracePhase::Auxiliary => Obligation::AuxiliaryAffineSpan,
                });
                obligations.insert(Obligation::SelectorAndBatchingCancellation);
            }
            RowCodeWhirChallenge::QuotientGroupWeight { .. } => {
                obligations.extend([
                    Obligation::QuotientAffineSpan,
                    Obligation::SelectorAndBatchingCancellation,
                ]);
            }
            RowCodeWhirChallenge::OpeningBatchMaskWeight { .. } => {
                obligations.extend([
                    Obligation::SelectorAndBatchingCancellation,
                    Obligation::MaskCorrespondence,
                ]);
            }
            RowCodeWhirChallenge::BoundOpeningWeight { .. } => {
                obligations.extend([
                    Obligation::OutputRootAffineSpan,
                    Obligation::PriorVssInputIdentity,
                    Obligation::SelectorAndBatchingCancellation,
                ]);
            }
            RowCodeWhirChallenge::BoundDegreeCoordinate { .. } => {
                obligations.insert(Obligation::OutputRootAffineSpan);
            }
            RowCodeWhirChallenge::OuterQueryVector | RowCodeWhirChallenge::BoundQueryVector => {
                unreachable!("query vectors are cataloged as distinct-index operations")
            }
        },
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::Outer,
            ..
        } => {
            obligations.insert(Obligation::OuterRowCodeProximity);
        }
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::Bound,
            ..
        } => obligations.extend([
            Obligation::OutputRootAffineSpan,
            Obligation::PriorVssInputIdentity,
        ]),
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::Aggregate,
        } => {
            obligations.insert(Obligation::OuterRowCodeProximity);
        }
        RowCodeWhirTranscriptOperation::ObserveCommitment {
            role: RowCodeWhirCommitmentRole::WhirRound { .. },
        } => {
            obligations.insert(Obligation::WhirFoldAndQueryState);
        }
        RowCodeWhirTranscriptOperation::SampleExtension { role, .. } => {
            obligations.insert(Obligation::WhirFoldAndQueryState);
            match role {
                RowCodeWhirExtensionRole::InitialOutOfDomainPoint { .. }
                | RowCodeWhirExtensionRole::OpeningBatching => {
                    obligations.insert(Obligation::ExplicitPointConstrainedCode);
                }
                RowCodeWhirExtensionRole::InitialSumcheck { .. }
                | RowCodeWhirExtensionRole::RoundOutOfDomainPoint { .. }
                | RowCodeWhirExtensionRole::RoundCheckpoint { .. }
                | RowCodeWhirExtensionRole::RoundCombination { .. }
                | RowCodeWhirExtensionRole::RoundSumcheck { .. }
                | RowCodeWhirExtensionRole::FinalSumcheck { .. } => {}
                RowCodeWhirExtensionRole::Direct(_) => {
                    unreachable!("direct challenges were handled above")
                }
            }
        }
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role: RowCodeWhirQueryRole::WhirEpoch { .. },
            ..
        } => {
            obligations.insert(Obligation::WhirFoldAndQueryState);
        }
        RowCodeWhirTranscriptOperation::ObserveExtensionValues { role, .. } => {
            obligations.insert(Obligation::WhirFoldAndQueryState);
            match role {
                RowCodeWhirObservationRole::InitialOutOfDomainAnswer { .. }
                | RowCodeWhirObservationRole::OpeningPoint { .. } => {
                    obligations.insert(Obligation::ExplicitPointConstrainedCode);
                }
                RowCodeWhirObservationRole::OpeningEvaluations { .. } => {
                    obligations.extend([
                        Obligation::ExplicitPointConstrainedCode,
                        Obligation::MaskCorrespondence,
                    ]);
                }
                RowCodeWhirObservationRole::RoundOutOfDomainAnswer { .. }
                | RowCodeWhirObservationRole::InitialSumcheckPolynomial { .. }
                | RowCodeWhirObservationRole::RoundSumcheckPolynomial { .. } => {}
                RowCodeWhirObservationRole::FinalPolynomial
                | RowCodeWhirObservationRole::FinalSumcheckPolynomial { .. } => {
                    obligations.insert(Obligation::CanonicalTerminalProof);
                }
            }
        }
        RowCodeWhirTranscriptOperation::FinishProofStream => {
            obligations.extend([Obligation::CanonicalTerminalProof, Obligation::ExactResume]);
        }
    }
    obligations
}

fn build_transcript_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<TranscriptCorrespondenceRow>, String> {
    construction_plan
        .transcript_operations()
        .iter()
        .enumerate()
        .map(|(operation_index, operation)| {
            Ok(TranscriptCorrespondenceRow {
                operation_ordinal: u32::try_from(operation_index)
                    .map_err(|_| "the operation ordinal does not fit u32".to_owned())?,
                operation: operation.clone(),
                verifier_consumer: transcript_verifier_consumer(operation),
                theorem_obligations: theorem_obligations_for_operation(operation),
            })
        })
        .collect()
}

fn rust_source_defines_function(source: &str, function_name: &str) -> bool {
    source.contains(&format!("fn {function_name}("))
}

fn validate_transcript_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
    rows: &[TranscriptCorrespondenceRow],
) -> Result<(), CorrespondenceValidationError> {
    if rows.len() != construction_plan.transcript_operations().len() {
        return Err(CorrespondenceValidationError::MissingOperation);
    }
    let mut observed_ordinals = BTreeSet::new();
    let mut observed_consumers = BTreeSet::new();
    let mut observed_obligations = BTreeSet::new();
    for (operation_index, (operation, row)) in construction_plan
        .transcript_operations()
        .iter()
        .zip(rows)
        .enumerate()
    {
        if !observed_ordinals.insert(row.operation_ordinal) {
            return Err(CorrespondenceValidationError::DuplicateOperationConsumer);
        }
        if row.operation_ordinal
            != u32::try_from(operation_index)
                .map_err(|_| CorrespondenceValidationError::OperationReordered)?
            || row.operation != *operation
        {
            return Err(CorrespondenceValidationError::OperationReordered);
        }
        if row.verifier_consumer != transcript_verifier_consumer(operation) {
            return Err(CorrespondenceValidationError::StaleVerifierConsumer);
        }
        if row.theorem_obligations != theorem_obligations_for_operation(operation) {
            return Err(CorrespondenceValidationError::StaleTheoremMapping);
        }
        observed_consumers.insert(row.verifier_consumer);
        observed_obligations.extend(row.theorem_obligations.iter().copied());
    }
    if observed_consumers != BTreeSet::from(TranscriptVerifierConsumer::ALL) {
        return Err(CorrespondenceValidationError::MissingVerifierFunction);
    }
    for consumer in observed_consumers {
        if !rust_source_defines_function(TRANSCRIPT_SOURCE, consumer.rust_function_name()) {
            return Err(CorrespondenceValidationError::MissingVerifierFunction);
        }
    }
    if observed_obligations != BTreeSet::from(ConstructionTheoremObligation::ALL) {
        return Err(CorrespondenceValidationError::MissingTheoremObligation);
    }
    Ok(())
}

fn proof_section_verifier_consumer(
    section: RowCodeWhirProofSectionPlan,
) -> ProofSectionVerifierConsumer {
    match section.role {
        RowCodeWhirProofSectionRole::RelationCommitment { .. } => {
            ProofSectionVerifierConsumer::ExactTranscriptPrefix
        }
        RowCodeWhirProofSectionRole::OutOfDomainEvaluations => {
            ProofSectionVerifierConsumer::VerifyProductionOutOfDomainComposition
        }
        RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => {
            ProofSectionVerifierConsumer::VerifyOpeningBatchMaskChunkEvaluations
        }
        RowCodeWhirProofSectionRole::AggregateCommitment => {
            ProofSectionVerifierConsumer::VerifyPlainAggregateBatchesAtPointsAfterCommitment
        }
        RowCodeWhirProofSectionRole::PhaseOpenings { .. } => {
            ProofSectionVerifierConsumer::VerifyPhaseOpenings
        }
        RowCodeWhirProofSectionRole::BoundTreeOpenings { .. } => {
            ProofSectionVerifierConsumer::VerifyBoundTreeAuthentications
        }
        RowCodeWhirProofSectionRole::PlainWhir => {
            ProofSectionVerifierConsumer::VerifyPlainAggregateBatchesAtPointsAfterCommitment
        }
    }
}

fn theorem_obligations_for_section(
    section: RowCodeWhirProofSectionPlan,
) -> BTreeSet<ConstructionTheoremObligation> {
    use ConstructionTheoremObligation as Obligation;
    match section.role {
        RowCodeWhirProofSectionRole::RelationCommitment { phase } => BTreeSet::from([
            Obligation::InstanceAndPlanIdentity,
            theorem_obligation_for_phase(phase),
        ]),
        RowCodeWhirProofSectionRole::OutOfDomainEvaluations => BTreeSet::from([
            Obligation::QuotientAffineSpan,
            Obligation::ThetaExtraction,
            Obligation::SelectorAndBatchingCancellation,
        ]),
        RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => BTreeSet::from([
            Obligation::SelectorAndBatchingCancellation,
            Obligation::MaskCorrespondence,
        ]),
        RowCodeWhirProofSectionRole::AggregateCommitment => BTreeSet::from([
            Obligation::OuterRowCodeProximity,
            Obligation::ExplicitPointConstrainedCode,
        ]),
        RowCodeWhirProofSectionRole::PhaseOpenings { phase } => BTreeSet::from([
            theorem_obligation_for_phase(phase),
            Obligation::OuterRowCodeProximity,
            Obligation::SelectorAndBatchingCancellation,
        ]),
        RowCodeWhirProofSectionRole::BoundTreeOpenings { .. } => BTreeSet::from([
            Obligation::OutputRootAffineSpan,
            Obligation::PriorVssInputIdentity,
            Obligation::SelectorAndBatchingCancellation,
        ]),
        RowCodeWhirProofSectionRole::PlainWhir => BTreeSet::from([
            Obligation::ExplicitPointConstrainedCode,
            Obligation::WhirFoldAndQueryState,
            Obligation::CanonicalTerminalProof,
        ]),
    }
}

const fn theorem_obligation_for_phase(phase: RowCodeWhirPhase) -> ConstructionTheoremObligation {
    match phase {
        RowCodeWhirPhase::Base => ConstructionTheoremObligation::BaseAffineSpan,
        RowCodeWhirPhase::Auxiliary => ConstructionTheoremObligation::AuxiliaryAffineSpan,
        RowCodeWhirPhase::Quotient => ConstructionTheoremObligation::QuotientAffineSpan,
    }
}

fn phase_identifier(phase: RowCodeWhirPhase) -> &'static str {
    match phase {
        RowCodeWhirPhase::Base => "base",
        RowCodeWhirPhase::Auxiliary => "auxiliary",
        RowCodeWhirPhase::Quotient => "quotient",
    }
}

fn proof_section_role_identifier(role: RowCodeWhirProofSectionRole) -> String {
    match role {
        RowCodeWhirProofSectionRole::RelationCommitment { phase } => {
            format!("relation-commitment/{}", phase_identifier(phase))
        }
        RowCodeWhirProofSectionRole::OutOfDomainEvaluations => {
            "out-of-domain-evaluations".to_owned()
        }
        RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations => {
            "opening-batch-mask-evaluations".to_owned()
        }
        RowCodeWhirProofSectionRole::AggregateCommitment => "aggregate-commitment".to_owned(),
        RowCodeWhirProofSectionRole::PhaseOpenings { phase } => {
            format!("phase-openings/{}", phase_identifier(phase))
        }
        RowCodeWhirProofSectionRole::BoundTreeOpenings { bound_tree_ordinal } => {
            format!("bound-tree-openings/{bound_tree_ordinal}")
        }
        RowCodeWhirProofSectionRole::PlainWhir => "plain-whir".to_owned(),
    }
}

fn checkpoint_boundary_identifier(boundary: RowCodeWhirCheckpointBoundary) -> String {
    match boundary {
        RowCodeWhirCheckpointBoundary::SourcesAndConstruction => {
            "sources-and-construction".to_owned()
        }
        RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => {
            format!("phase-commitment/{}", phase_identifier(phase))
        }
        RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => {
            "relation-evaluations-and-mask".to_owned()
        }
        RowCodeWhirCheckpointBoundary::AggregateCommitmentAndQueries => {
            "aggregate-commitment-and-queries".to_owned()
        }
        RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal } => {
            format!("whir-round/{round_ordinal}")
        }
        RowCodeWhirCheckpointBoundary::CompletedProofStream => "completed-proof-stream".to_owned(),
    }
}

fn checkpoint_supports_obligation(
    boundary: RowCodeWhirCheckpointBoundary,
    obligation: ConstructionTheoremObligation,
) -> bool {
    use ConstructionTheoremObligation as Obligation;

    match obligation {
        Obligation::InstanceAndPlanIdentity => {
            matches!(
                boundary,
                RowCodeWhirCheckpointBoundary::SourcesAndConstruction
            )
        }
        Obligation::BaseAffineSpan | Obligation::ThetaExtraction => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Base,
            }
        ),
        Obligation::AuxiliaryAffineSpan => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Auxiliary,
            }
        ),
        Obligation::QuotientAffineSpan => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Quotient,
            } | RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask
        ),
        Obligation::OutputRootAffineSpan
        | Obligation::PriorVssInputIdentity
        | Obligation::OuterRowCodeProximity => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::AggregateCommitmentAndQueries
        ),
        Obligation::SelectorAndBatchingCancellation => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask
                | RowCodeWhirCheckpointBoundary::AggregateCommitmentAndQueries
        ),
        Obligation::ExplicitPointConstrainedCode => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::AggregateCommitmentAndQueries
                | RowCodeWhirCheckpointBoundary::WhirRound { .. }
        ),
        Obligation::WhirFoldAndQueryState => {
            matches!(boundary, RowCodeWhirCheckpointBoundary::WhirRound { .. })
        }
        Obligation::CanonicalTerminalProof => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::CompletedProofStream
        ),
        Obligation::MaskCorrespondence => matches!(
            boundary,
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask
        ),
        Obligation::ExactResume => true,
    }
}

fn compressed_ordinal_ranges(mut ordinals: Vec<u32>) -> Vec<Value> {
    ordinals.sort_unstable();
    ordinals.dedup();
    let mut ranges = Vec::new();
    let Some(mut first) = ordinals.first().copied() else {
        return ranges;
    };
    let mut last = first;
    for ordinal in ordinals.into_iter().skip(1) {
        if last.checked_add(1) == Some(ordinal) {
            last = ordinal;
        } else {
            ranges.push(json!([first, last]));
            first = ordinal;
            last = ordinal;
        }
    }
    ranges.push(json!([first, last]));
    ranges
}

fn hexadecimal_hash(hash: [u8; Hash512::BYTE_LENGTH]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn correspondence_artifact_digest(rendered_artifact: &str) -> Result<Hash512, String> {
    let artifact_item = CanonicalItem::variable_bytes(rendered_artifact.as_bytes())
        .map_err(|error| format!("frame construction correspondence: {error:?}"))?;
    hash_foundation_tuple_512(CORRESPONDENCE_ARTIFACT_DIGEST_DOMAIN, &[artifact_item])
        .map_err(|error| format!("hash construction correspondence: {error:?}"))
}

fn generated_correspondence_artifact(
    construction_plan: &RowCodeWhirConstructionPlan,
    source_correspondence: SameSecretSourceCorrespondence,
    transcript_rows: &[TranscriptCorrespondenceRow],
) -> Result<String, String> {
    validate_transcript_correspondence(construction_plan, transcript_rows)
        .map_err(|error| format!("validate transcript correspondence: {error:?}"))?;

    let mut consumer_ranges = Vec::new();
    let mut first_ordinal = 0_u32;
    let mut active_consumer = transcript_rows
        .first()
        .ok_or_else(|| "the transcript catalog is empty".to_owned())?
        .verifier_consumer;
    for row in transcript_rows.iter().skip(1) {
        if row.verifier_consumer != active_consumer {
            consumer_ranges.push(json!({
                "firstOperationOrdinal": first_ordinal,
                "lastOperationOrdinal": row.operation_ordinal - 1,
                "verifierConsumerIdentifier": active_consumer.identifier(),
            }));
            first_ordinal = row.operation_ordinal;
            active_consumer = row.verifier_consumer;
        }
    }
    consumer_ranges.push(json!({
        "firstOperationOrdinal": first_ordinal,
        "lastOperationOrdinal": transcript_rows
            .last()
            .ok_or_else(|| "the transcript catalog is empty".to_owned())?
            .operation_ordinal,
        "verifierConsumerIdentifier": active_consumer.identifier(),
    }));

    let proof_sections = construction_plan
        .proof_sections()
        .iter()
        .copied()
        .map(|section| {
            let consumer = proof_section_verifier_consumer(section);
            if !rust_source_defines_function(consumer.source(), consumer.rust_function_name()) {
                return Err(format!(
                    "the proof-section verifier consumer {} is stale",
                    consumer.identifier()
                ));
            }
            Ok(json!({
                "itemCount": section.item_count,
                "role": proof_section_role_identifier(section.role),
                "sectionOrdinal": section.section_ordinal,
                "verifierConsumerIdentifier": consumer.identifier(),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let checkpoints = construction_plan
        .checkpoints()
        .iter()
        .map(|checkpoint| {
            json!({
                "boundary": checkpoint_boundary_identifier(checkpoint.boundary),
                "checkpointOrdinal": checkpoint.checkpoint_ordinal,
                "nextProofSectionOrdinal": checkpoint.next_proof_section_ordinal,
                "nextTranscriptOperationOrdinal": checkpoint.next_transcript_operation_ordinal,
            })
        })
        .collect::<Vec<_>>();

    let theorem_correspondence = ConstructionTheoremObligation::ALL
        .into_iter()
        .map(|obligation| {
            let operation_rows = transcript_rows
                .iter()
                .filter(|row| row.theorem_obligations.contains(&obligation))
                .collect::<Vec<_>>();
            let mut verifier_consumers = operation_rows
                .iter()
                .map(|row| row.verifier_consumer.identifier())
                .collect::<BTreeSet<_>>();
            let matching_proof_sections = construction_plan
                .proof_sections()
                .iter()
                .filter(|section| theorem_obligations_for_section(**section).contains(&obligation))
                .collect::<Vec<_>>();
            verifier_consumers.extend(
                matching_proof_sections
                    .iter()
                    .map(|section| proof_section_verifier_consumer(**section).identifier()),
            );
            let proof_section_ordinals = matching_proof_sections
                .into_iter()
                .map(|section| section.section_ordinal)
                .collect::<Vec<_>>();
            let checkpoint_ordinals = construction_plan
                .checkpoints()
                .iter()
                .filter(|checkpoint| {
                    checkpoint_supports_obligation(checkpoint.boundary, obligation)
                })
                .map(|checkpoint| checkpoint.checkpoint_ordinal)
                .collect::<Vec<_>>();
            json!({
                "checkpointOrdinals": checkpoint_ordinals,
                "obligationIdentifier": obligation.identifier(),
                "proofSectionOrdinals": proof_section_ordinals,
                "transcriptOperationOrdinalRanges": compressed_ordinal_ranges(
                    operation_rows
                        .iter()
                        .map(|row| row.operation_ordinal)
                        .collect(),
                ),
                "verifierConsumerIdentifiers": verifier_consumers,
            })
        })
        .collect::<Vec<_>>();

    let construction_identity_hash = construction_plan
        .canonical_identity_hash()
        .map_err(|error| format!("hash construction identity: {error:?}"))?;
    let artifact = json!({
        "artifactSchema": "sealed-lattice/row-code-whir/construction-correspondence/v1",
        "constructionIdentityHash": hexadecimal_hash(construction_identity_hash),
        "evidenceScope": "Structural catalog correspondence only; this artifact does not discharge construction hypotheses, the exhaustive masking gate, production source-manifest authentication, or required suite bindings.",
        "independentOpenGateIdentifiers": ["construction-level-masking-correspondence"],
        "productionSameSecretSourceCorrespondence": {
            "persistedPreChallengeCoefficientCount": source_correspondence.persisted_pre_challenge_coefficient_count,
            "authenticatedSourcePolynomialCount": source_correspondence.authenticated_source_polynomial_count,
            "deterministicReversedColumnCount": source_correspondence.deterministic_reversed_column_count,
            "storedPreChallengeColumnCount": source_correspondence.stored_pre_challenge_column_count,
        },
        "proofSections": proof_sections,
        "recordedComputationalAssumptionIdentifiers": ConstructionApplicabilityHypothesis::COMPUTATIONAL_ASSUMPTIONS
            .into_iter()
            .map(ConstructionApplicabilityHypothesis::identifier)
            .collect::<Vec<_>>(),
        "relationPlanHash": hexadecimal_hash(construction_plan.relation_plan_hash()),
        "requiredSuiteBindingIsComplete": false,
        "theoremCorrespondence": theorem_correspondence,
        "theoremCorrespondenceRowCount": ConstructionTheoremObligation::ALL.len(),
        "transcriptOperationCount": transcript_rows.len(),
        "transcriptVerifierConsumerRanges": consumer_ranges,
        "unavailableRequiredSuiteBindingIdentifiers": [
            "construction-plan-hash-binding",
            "transcript-catalog-digest-binding",
            "exact-soundness-ledger-digest-binding",
            "verifier-equation-digest-binding",
        ],
        "undischargedConstructionHypothesisIdentifiers": ConstructionApplicabilityHypothesis::UNDISCHARGED
            .into_iter()
            .map(ConstructionApplicabilityHypothesis::identifier)
            .collect::<Vec<_>>(),
        "durableCheckpoints": checkpoints,
    });
    serde_json::to_string_pretty(&artifact)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|error| format!("encode construction correspondence: {error}"))
}

fn generated_correspondence_matches_checked_production_catalogs(
    construction_plan: &RowCodeWhirConstructionPlan,
    source_correspondence: SameSecretSourceCorrespondence,
    transcript_rows: &[TranscriptCorrespondenceRow],
) {
    let generated = generated_correspondence_artifact(
        construction_plan,
        source_correspondence,
        transcript_rows,
    )
    .expect("the production correspondence artifact derives deterministically");
    let observed_digest = correspondence_artifact_digest(&generated)
        .expect("the generated correspondence artifact is canonically hashable");
    assert_eq!(
        observed_digest, EXPECTED_CORRESPONDENCE_ARTIFACT_DIGEST,
        "the generated correspondence bytes changed:\n{generated}",
    );
}

fn correspondence_rejects_omission_duplication_reordering_and_stale_mappings(
    construction_plan: &RowCodeWhirConstructionPlan,
    rows: &[TranscriptCorrespondenceRow],
) {
    validate_transcript_correspondence(construction_plan, rows)
        .expect("the complete correspondence is valid");

    let mut omitted = rows.to_vec();
    omitted.pop();
    assert_eq!(
        validate_transcript_correspondence(construction_plan, &omitted),
        Err(CorrespondenceValidationError::MissingOperation),
    );
    drop(omitted);

    let mut duplicated = rows.to_vec();
    duplicated[1].operation_ordinal = duplicated[0].operation_ordinal;
    assert_eq!(
        validate_transcript_correspondence(construction_plan, &duplicated),
        Err(CorrespondenceValidationError::DuplicateOperationConsumer),
    );
    drop(duplicated);

    let mut reordered = rows.to_vec();
    reordered.swap(0, 1);
    assert_eq!(
        validate_transcript_correspondence(construction_plan, &reordered),
        Err(CorrespondenceValidationError::OperationReordered),
    );
    drop(reordered);

    let mut stale_consumer = rows.to_vec();
    stale_consumer[0].verifier_consumer = TranscriptVerifierConsumer::BeginFinalProofStream;
    assert_eq!(
        validate_transcript_correspondence(construction_plan, &stale_consumer),
        Err(CorrespondenceValidationError::StaleVerifierConsumer),
    );
    drop(stale_consumer);

    let mut stale_theorem_mapping = rows.to_vec();
    let removed_obligation = stale_theorem_mapping[0]
        .theorem_obligations
        .first()
        .copied()
        .expect("every operation has construction-state obligations");
    assert!(
        stale_theorem_mapping[0]
            .theorem_obligations
            .remove(&removed_obligation)
    );
    assert_eq!(
        validate_transcript_correspondence(construction_plan, &stale_theorem_mapping),
        Err(CorrespondenceValidationError::StaleTheoremMapping),
    );
}

fn production_same_secret_source_counts_are_catalog_derived(
    correspondence: SameSecretSourceCorrespondence,
) {
    assert_eq!(correspondence.authenticated_source_polynomial_count, 2_018);
    assert_eq!(
        correspondence.persisted_pre_challenge_coefficient_count,
        34_462_440,
    );
    assert_eq!(correspondence.deterministic_reversed_column_count, 12);
    assert_eq!(correspondence.stored_pre_challenge_column_count, 2_030);
}

fn implementation_checkpoint_cadence_is_not_cryptographic_schedule_identity(
    construction_plan: &RowCodeWhirConstructionPlan,
) {
    let construction_identity = construction_plan
        .canonical_identity_hash()
        .expect("the construction identity is canonical");
    let checkpoint_schedule = construction_plan
        .canonical_checkpoint_schedule_bytes()
        .expect("the checkpoint schedule is canonical");

    let mut implementation_rescheduled = construction_plan.clone();
    implementation_rescheduled.checkpoints.reverse();
    assert_eq!(
        implementation_rescheduled
            .canonical_identity_hash()
            .expect("implementation rescheduling preserves a canonical identity"),
        construction_identity,
    );
    assert_ne!(
        implementation_rescheduled
            .canonical_checkpoint_schedule_bytes()
            .expect("the changed checkpoint schedule is canonical"),
        checkpoint_schedule,
    );
    drop(implementation_rescheduled);

    let mut cryptographically_rescheduled = construction_plan.clone();
    let outer_query = cryptographically_rescheduled
        .transcript_operations
        .iter_mut()
        .find(|operation| {
            matches!(
                operation,
                RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: RowCodeWhirQueryRole::Outer,
                    ..
                }
            )
        })
        .expect("the selected catalog has an outer query operation");
    let RowCodeWhirTranscriptOperation::SampleDistinctIndices { output_count, .. } = outer_query
    else {
        unreachable!("the matched operation is an outer distinct-index query")
    };
    *output_count = output_count
        .checked_sub(1)
        .expect("the selected outer query count is nonzero");
    assert_ne!(
        cryptographically_rescheduled
            .canonical_identity_hash()
            .expect("the changed cryptographic schedule remains canonically encodable"),
        construction_identity,
    );
}

fn every_proof_section_consumer_still_exists_in_the_production_verifier(
    construction_plan: &RowCodeWhirConstructionPlan,
) {
    for section in construction_plan.proof_sections() {
        let consumer = proof_section_verifier_consumer(*section);
        assert!(
            rust_source_defines_function(consumer.source(), consumer.rust_function_name()),
            "stale verifier mapping for {}",
            consumer.identifier(),
        );
    }
}

#[test]
#[ignore = "guarded exact production-catalog correspondence evidence"]
fn heavy_rust_kernel_generated_construction_correspondence() {
    let (construction_plan, source_correspondence) =
        selected_same_secret_plan_and_source_correspondence()
            .expect("the selected same-secret plan and source correspondence derive");
    let transcript_rows = build_transcript_correspondence(&construction_plan)
        .expect("the production transcript correspondence derives");

    generated_correspondence_matches_checked_production_catalogs(
        &construction_plan,
        source_correspondence,
        &transcript_rows,
    );
    correspondence_rejects_omission_duplication_reordering_and_stale_mappings(
        &construction_plan,
        &transcript_rows,
    );
    production_same_secret_source_counts_are_catalog_derived(source_correspondence);
    implementation_checkpoint_cadence_is_not_cryptographic_schedule_identity(&construction_plan);
    every_proof_section_consumer_still_exists_in_the_production_verifier(&construction_plan);
}
