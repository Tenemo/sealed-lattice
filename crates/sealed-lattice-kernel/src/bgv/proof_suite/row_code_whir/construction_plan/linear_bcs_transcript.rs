//! Original-BCS strong-state correspondence derived from the checked
//! construction plan.
//!
//! The live sampler uses one typed hash edge per expansion block; that answer
//! is both the sampled block and the next predecessor. Sampler blocks therefore
//! do not acquire a synthetic second prover-root absorption edge. Fully
//! transported messages use their deployed framed 512-bit response digest;
//! this plan never invents a parallel Merkle tree for those bytes. Supplied
//! polynomial-oracle roots remain bound to their production commitment and
//! compact-opening geometry.

use super::*;
use crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE;
use crate::hashing::hash_framed_parts_512;

const LINEAR_BCS_TRANSCRIPT_PLAN_ENCODING_VERSION: u16 = 5;
const LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH: usize = 64;
const LINEAR_BCS_TRANSCRIPT_PLAN_HASH_DOMAIN: &str =
    "sealed-lattice/proof/row-code-whir/linear-bcs-transcript-plan/v5";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsChallengeSelectionRule {
    FirstAcceptedInCompleteFixedBlockRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsCommittedOracleRole {
    RelationPhase { phase: RowCodeWhirPhase },
    Aggregate,
    AggregateWidePad,
    WhirRound { round_ordinal: u32 },
    BaseFreshSource,
    BaseFreshPad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsSuppliedCommitmentOpeningOwner {
    OuterQueryVector,
    WhirEpoch { epoch_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsOpeningQueryOrder {
    AcceptedTranscriptOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsMerkleTraversalOrder {
    SortedCoordinates,
}

/// Plan-owned association between one supplied BCS commitment and the query
/// vector that authenticates its payload symbols.
///
/// Several relation-phase roots deliberately share the outer query vector,
/// but every supplied root has exactly one row and no row can name an absent
/// root. The payload length and query count are derived rather than accepted
/// from proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct LinearBcsSuppliedCommitmentOpeningPlan {
    pub(in crate::bgv::proof_suite) commitment_role: LinearBcsCommittedOracleRole,
    pub(in crate::bgv::proof_suite) owner: LinearBcsSuppliedCommitmentOpeningOwner,
    pub(in crate::bgv::proof_suite) payload_leaf_count: usize,
    pub(in crate::bgv::proof_suite) query_count: usize,
    pub(in crate::bgv::proof_suite) query_order: LinearBcsOpeningQueryOrder,
    pub(in crate::bgv::proof_suite) merkle_traversal_order: LinearBcsMerkleTraversalOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsProverOracleRoot {
    SuppliedCommitment {
        role: LinearBcsCommittedOracleRole,
        payload_leaf_count: usize,
    },
    CanonicalCompleteMessageDigest {
        value_count: usize,
        canonical_message_byte_length: usize,
    },
    OneEdgeSamplerBlock {
        source_operation_ordinal: u32,
        first_block_ordinal: u64,
    },
}

impl LinearBcsProverOracleRoot {
    fn validate_geometry(self) -> Result<(), RowCodeWhirConstructionPlanError> {
        match self {
            Self::SuppliedCommitment {
                payload_leaf_count, ..
            } => {
                if payload_leaf_count == 0 || !payload_leaf_count.is_power_of_two() {
                    return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                }
            }
            Self::CanonicalCompleteMessageDigest {
                value_count,
                canonical_message_byte_length,
            } => {
                let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
                    .checked_mul(std::mem::size_of::<u64>())
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
                let expected_message_byte_length = value_count
                    .checked_mul(value_byte_length)
                    .and_then(|length| length.checked_add(6))
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
                if value_count == 0 || canonical_message_byte_length != expected_message_byte_length
                {
                    return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                }
            }
            Self::OneEdgeSamplerBlock { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) enum LinearBcsVerifierMessageRole {
    UnusedRoundMessageBeforeProverOracle {
        source_operation_ordinal: u32,
    },
    SamplerPrefixBlock {
        source_operation_ordinal: u32,
        first_block_ordinal: u64,
    },
    SamplerTerminalBlock {
        source_operation_ordinal: u32,
        block_ordinal: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct LinearBcsRoundRangePlan {
    pub(in crate::bgv::proof_suite) first_round_ordinal: u64,
    pub(in crate::bgv::proof_suite) round_count: u64,
    pub(in crate::bgv::proof_suite) verifier_message_role: LinearBcsVerifierMessageRole,
    pub(in crate::bgv::proof_suite) prover_oracle_root: LinearBcsProverOracleRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct LinearBcsFinalQueryPlan {
    pub(in crate::bgv::proof_suite) verifier_message_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct LinearBcsTranscriptPlan {
    round_ranges: Vec<LinearBcsRoundRangePlan>,
    supplied_commitment_openings: Vec<LinearBcsSuppliedCommitmentOpeningPlan>,
    final_query: LinearBcsFinalQueryPlan,
    challenge_selection_rule: LinearBcsChallengeSelectionRule,
}

impl LinearBcsTranscriptPlan {
    pub(in crate::bgv::proof_suite) fn round_ranges(&self) -> &[LinearBcsRoundRangePlan] {
        &self.round_ranges
    }

    pub(in crate::bgv::proof_suite) fn supplied_commitment_openings(
        &self,
    ) -> &[LinearBcsSuppliedCommitmentOpeningPlan] {
        &self.supplied_commitment_openings
    }

    pub(in crate::bgv::proof_suite) const fn final_query(&self) -> LinearBcsFinalQueryPlan {
        self.final_query
    }

    pub(in crate::bgv::proof_suite) const fn challenge_selection_rule(
        &self,
    ) -> LinearBcsChallengeSelectionRule {
        self.challenge_selection_rule
    }

    pub(in crate::bgv::proof_suite) fn round_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.round_ranges.iter().try_fold(0_u64, |total, range| {
            total
                .checked_add(range.round_count)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })
    }

    /// Counts only the live typed chain edges represented by this candidate
    /// correspondence. A prover-oracle round has the two ordinary response
    /// edges; a sampler block has exactly one expansion edge. There is no
    /// synthetic terminal query or fixed-continuation absorption.
    pub(in crate::bgv::proof_suite) fn chain_hash_query_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.round_ranges.iter().try_fold(0_u64, |total, range| {
            let hashes_per_entry = match range.prover_oracle_root {
                LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => 1_u64,
                LinearBcsProverOracleRoot::SuppliedCommitment { .. }
                | LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest { .. } => 2_u64,
            };
            let range_hashes = hashes_per_entry
                .checked_mul(range.round_count)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            total
                .checked_add(range_hashes)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
        })
    }

    pub(in crate::bgv::proof_suite) fn complete_message_digest_hash_query_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.round_ranges.iter().try_fold(0_u64, |total, range| {
            if matches!(
                range.prover_oracle_root,
                LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest { .. }
            ) {
                total
                    .checked_add(range.round_count)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
            } else {
                Ok(total)
            }
        })
    }

    pub(in crate::bgv::proof_suite) fn supplied_commitment_opening_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.supplied_commitment_openings
            .iter()
            .try_fold(0_u64, |total, opening| {
                total
                    .checked_add(
                        u64::try_from(opening.query_count)
                            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
                    )
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
            })
    }

    pub(in crate::bgv::proof_suite) fn one_edge_sampler_block_count(
        &self,
    ) -> Result<u64, RowCodeWhirConstructionPlanError> {
        self.round_ranges.iter().try_fold(0_u64, |total, range| {
            if matches!(
                range.prover_oracle_root,
                LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. }
            ) {
                total
                    .checked_add(range.round_count)
                    .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)
            } else {
                Ok(total)
            }
        })
    }

    pub(in crate::bgv::proof_suite) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, RowCodeWhirConstructionPlanError> {
        validate_linear_bcs_transcript_plan(self)?;
        let mut encoder = RowCodeWhirConstructionPlanIdentityEncoder::default();
        encoder.push_u16(LINEAR_BCS_TRANSCRIPT_PLAN_ENCODING_VERSION);
        encoder.push_usize(LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH)?;
        encoder.push_u16(match self.challenge_selection_rule {
            LinearBcsChallengeSelectionRule::FirstAcceptedInCompleteFixedBlockRange => 1,
        });
        encoder.push_length(self.round_ranges.len())?;
        for range in &self.round_ranges {
            encoder.push_u64(range.first_round_ordinal);
            encoder.push_u64(range.round_count);
            encode_verifier_message_role(&mut encoder, range.verifier_message_role);
            encode_prover_oracle_root(&mut encoder, range.prover_oracle_root)?;
        }
        encoder.push_length(self.supplied_commitment_openings.len())?;
        for opening in &self.supplied_commitment_openings {
            encode_committed_oracle_role(&mut encoder, opening.commitment_role);
            match opening.owner {
                LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector => encoder.push_u16(1),
                LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { epoch_ordinal } => {
                    encoder.push_u16(3);
                    encoder.push_u32(epoch_ordinal);
                }
            }
            encoder.push_usize(opening.payload_leaf_count)?;
            encoder.push_usize(opening.query_count)?;
            encoder.push_u16(match opening.query_order {
                LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder => 1,
            });
            encoder.push_u16(match opening.merkle_traversal_order {
                LinearBcsMerkleTraversalOrder::SortedCoordinates => 1,
            });
        }
        encoder.push_u64(self.final_query.verifier_message_ordinal);
        Ok(encoder.finish())
    }

    pub(in crate::bgv::proof_suite) fn canonical_hash(
        &self,
    ) -> Result<[u8; 64], RowCodeWhirConstructionPlanError> {
        let canonical_bytes = self.canonical_bytes()?;
        Ok(hash_framed_parts_512(
            LINEAR_BCS_TRANSCRIPT_PLAN_HASH_DOMAIN,
            &[&canonical_bytes],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinearBcsSemanticStep {
    ProverOracle {
        source_operation_ordinal: u32,
        root: LinearBcsProverOracleRoot,
    },
    Sampler {
        source_operation_ordinal: u32,
        fixed_block_count: u64,
    },
}

pub(in crate::bgv::proof_suite) fn linear_bcs_round_ordinal_encoding(
    round_ordinal: u64,
) -> Result<[u8; LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH], RowCodeWhirConstructionPlanError> {
    if round_ordinal == 0 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let mut encoded = [0_u8; LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH];
    encoded[..8].copy_from_slice(b"SLXBCS01");
    encoded[8] = 1;
    encoded[16..24].copy_from_slice(&round_ordinal.to_le_bytes());
    Ok(encoded)
}

pub(in crate::bgv::proof_suite) fn linear_bcs_sampler_block_address_encoding(
    source_operation_ordinal: u32,
    block_ordinal: u64,
) -> [u8; LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH] {
    let mut encoded = [0_u8; LINEAR_BCS_ORACLE_VALUE_BYTE_LENGTH];
    encoded[..8].copy_from_slice(b"SLXBCS01");
    encoded[8] = 2;
    encoded[12..16].copy_from_slice(&source_operation_ordinal.to_le_bytes());
    encoded[16..24].copy_from_slice(&block_ordinal.to_le_bytes());
    encoded
}

pub(in crate::bgv::proof_suite) fn derive_linear_bcs_transcript_plan(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<LinearBcsTranscriptPlan, RowCodeWhirConstructionPlanError> {
    let source_catalog = oracle_equation_catalog_for_plan(plan)?;
    let mut semantic_steps = Vec::new();
    let mut saw_terminal_marker = false;
    for operation in source_catalog.operations.iter().skip(1) {
        let source_operation_ordinal = operation.operation_ordinal;
        let semantic_step = match &operation.kind {
            RowCodeWhirOracleEquationOperationKind::InitialTranscript => {
                return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
            }
            RowCodeWhirOracleEquationOperationKind::CommonRound(round) => {
                common_round_root(plan, *round)?.map(|root| LinearBcsSemanticStep::ProverOracle {
                    source_operation_ordinal,
                    root,
                })
            }
            RowCodeWhirOracleEquationOperationKind::CommonProductChallenge(_)
            | RowCodeWhirOracleEquationOperationKind::CommonExtensionChallenge(_) => {
                Some(LinearBcsSemanticStep::Sampler {
                    source_operation_ordinal,
                    fixed_block_count: fixed_sampler_block_count(operation)?,
                })
            }
            RowCodeWhirOracleEquationOperationKind::RowCodeWhir {
                operation: transcript_operation,
                ..
            } => match transcript_operation {
                RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count }
                | RowCodeWhirTranscriptOperation::ObserveExtensionValues { value_count, .. } => {
                    if matches!(
                        transcript_operation,
                        RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                            role: RowCodeWhirObservationRole::OpeningPoint { .. },
                            ..
                        }
                    ) {
                        None
                    } else {
                        Some(LinearBcsSemanticStep::ProverOracle {
                            source_operation_ordinal,
                            root: canonical_extension_message_root(*value_count)?,
                        })
                    }
                }
                RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { .. } => None,
                RowCodeWhirTranscriptOperation::ObserveCommitment { role } => {
                    Some(LinearBcsSemanticStep::ProverOracle {
                        source_operation_ordinal,
                        root: row_code_whir_commitment_root(plan, *role)?,
                    })
                }
                RowCodeWhirTranscriptOperation::SampleExtension { .. }
                | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. } => {
                    Some(LinearBcsSemanticStep::Sampler {
                        source_operation_ordinal,
                        fixed_block_count: fixed_sampler_block_count(operation)?,
                    })
                }
                RowCodeWhirTranscriptOperation::FinishProofStream => {
                    if saw_terminal_marker {
                        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
                    }
                    saw_terminal_marker = true;
                    None
                }
            },
        };
        if saw_terminal_marker && semantic_step.is_some() {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        if let Some(semantic_step) = semantic_step {
            semantic_steps.push(semantic_step);
        }
    }
    if !saw_terminal_marker || semantic_steps.is_empty() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }

    let mut round_ranges = Vec::new();
    let mut next_round_ordinal = 1_u64;
    for semantic_step in semantic_steps {
        match semantic_step {
            LinearBcsSemanticStep::ProverOracle {
                source_operation_ordinal,
                root,
            } => push_round_range(
                &mut round_ranges,
                &mut next_round_ordinal,
                1,
                LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
                    source_operation_ordinal,
                },
                root,
            )?,
            LinearBcsSemanticStep::Sampler {
                source_operation_ordinal,
                fixed_block_count,
            } => {
                let prefix_block_count = fixed_block_count
                    .checked_sub(1)
                    .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
                if prefix_block_count > 0 {
                    push_round_range(
                        &mut round_ranges,
                        &mut next_round_ordinal,
                        prefix_block_count,
                        LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                            source_operation_ordinal,
                            first_block_ordinal: 0,
                        },
                        LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                            source_operation_ordinal,
                            first_block_ordinal: 0,
                        },
                    )?;
                }
                push_round_range(
                    &mut round_ranges,
                    &mut next_round_ordinal,
                    1,
                    LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                        source_operation_ordinal,
                        block_ordinal: prefix_block_count,
                    },
                    LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                        source_operation_ordinal,
                        first_block_ordinal: prefix_block_count,
                    },
                )?;
            }
        }
    }
    let supplied_commitment_openings =
        derive_supplied_commitment_opening_plans(plan, &round_ranges)?;
    let transcript_plan = LinearBcsTranscriptPlan {
        round_ranges,
        supplied_commitment_openings,
        final_query: LinearBcsFinalQueryPlan {
            verifier_message_ordinal: next_round_ordinal,
        },
        challenge_selection_rule:
            LinearBcsChallengeSelectionRule::FirstAcceptedInCompleteFixedBlockRange,
    };
    validate_linear_bcs_transcript_plan(&transcript_plan)?;
    Ok(transcript_plan)
}

fn push_round_range(
    ranges: &mut Vec<LinearBcsRoundRangePlan>,
    next_round_ordinal: &mut u64,
    round_count: u64,
    verifier_message_role: LinearBcsVerifierMessageRole,
    prover_oracle_root: LinearBcsProverOracleRoot,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if round_count == 0 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    ranges.push(LinearBcsRoundRangePlan {
        first_round_ordinal: *next_round_ordinal,
        round_count,
        verifier_message_role,
        prover_oracle_root,
    });
    *next_round_ordinal = next_round_ordinal
        .checked_add(round_count)
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    Ok(())
}

fn common_round_root(
    plan: &RowCodeWhirConstructionPlan,
    round: CommonProofRound,
) -> Result<Option<LinearBcsProverOracleRoot>, RowCodeWhirConstructionPlanError> {
    let supplied = |role, leaf_count| checked_supplied_commitment_root(role, leaf_count).map(Some);
    match round {
        CommonProofRound::BaseRoot { tree_ordinal: 0 } => supplied(
            LinearBcsCommittedOracleRole::RelationPhase {
                phase: RowCodeWhirPhase::Base,
            },
            plan.base_phase
                .as_ref()
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?
                .geometry
                .encoded_column_count,
        ),
        CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 } => supplied(
            LinearBcsCommittedOracleRole::RelationPhase {
                phase: RowCodeWhirPhase::Auxiliary,
            },
            plan.auxiliary_phase
                .as_ref()
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?
                .geometry
                .encoded_column_count,
        ),
        CommonProofRound::RowCodeWhirQuotientPhaseRoot => supplied(
            LinearBcsCommittedOracleRole::RelationPhase {
                phase: RowCodeWhirPhase::Quotient,
            },
            plan.quotient_phase.geometry.encoded_column_count,
        ),
        CommonProofRound::OutOfDomainEvaluations => canonical_extension_message_root(
            usize::try_from(plan.relation_prefix_schedule.opening_claim_count())
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .map(Some),
        CommonProofRound::BaseRoot { .. } | CommonProofRound::AuxiliaryRoot { .. } => {
            Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
        }
    }
}

fn row_code_whir_commitment_root(
    plan: &RowCodeWhirConstructionPlan,
    role: RowCodeWhirCommitmentRole,
) -> Result<LinearBcsProverOracleRoot, RowCodeWhirConstructionPlanError> {
    let committed_role = match role {
        RowCodeWhirCommitmentRole::Aggregate => LinearBcsCommittedOracleRole::Aggregate,
        RowCodeWhirCommitmentRole::AggregateWidePad => {
            LinearBcsCommittedOracleRole::AggregateWidePad
        }
        RowCodeWhirCommitmentRole::WhirRound { round_ordinal } => {
            LinearBcsCommittedOracleRole::WhirRound { round_ordinal }
        }
        RowCodeWhirCommitmentRole::BaseFreshSource => LinearBcsCommittedOracleRole::BaseFreshSource,
        RowCodeWhirCommitmentRole::BaseFreshPad => LinearBcsCommittedOracleRole::BaseFreshPad,
    };
    let payload_leaf_count = match role {
        RowCodeWhirCommitmentRole::Aggregate | RowCodeWhirCommitmentRole::WhirRound { .. } => {
            whir_commitment_opening_geometry(plan, role)?.0.leaf_count
        }
        RowCodeWhirCommitmentRole::AggregateWidePad | RowCodeWhirCommitmentRole::BaseFreshPad => {
            aggregate_wide_pad_domain_size(plan)?
        }
        RowCodeWhirCommitmentRole::BaseFreshSource => {
            plan.whir.final_round.encoded_oracle.leaf_count
        }
    };
    checked_supplied_commitment_root(committed_role, payload_leaf_count)
}

fn whir_commitment_opening_geometry(
    plan: &RowCodeWhirConstructionPlan,
    role: RowCodeWhirCommitmentRole,
) -> Result<
    (RowCodeWhirEncodedOraclePlan, RowCodeWhirQueryEpochPlan),
    RowCodeWhirConstructionPlanError,
> {
    match role {
        RowCodeWhirCommitmentRole::AggregateWidePad
        | RowCodeWhirCommitmentRole::BaseFreshSource
        | RowCodeWhirCommitmentRole::BaseFreshPad => {
            Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
        }
        RowCodeWhirCommitmentRole::Aggregate => plan
            .whir
            .rounds
            .first()
            .map(|round| (round.encoded_oracle, round.query_epoch))
            .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
        RowCodeWhirCommitmentRole::WhirRound { round_ordinal } => {
            let round_index = plan
                .whir
                .rounds
                .iter()
                .position(|round| round.round_ordinal == round_ordinal)
                .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
            let successor_index = round_index
                .checked_add(1)
                .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
            Ok(plan
                .whir
                .rounds
                .get(successor_index)
                .map(|successor| (successor.encoded_oracle, successor.query_epoch))
                .unwrap_or((
                    plan.whir.final_round.encoded_oracle,
                    plan.whir.final_round.query_epoch,
                )))
        }
    }
}

fn derive_supplied_commitment_opening_plans(
    plan: &RowCodeWhirConstructionPlan,
    round_ranges: &[LinearBcsRoundRangePlan],
) -> Result<Vec<LinearBcsSuppliedCommitmentOpeningPlan>, RowCodeWhirConstructionPlanError> {
    let outer_query_geometry = unique_query_geometry(plan, RowCodeWhirQueryRole::Outer)?;
    if outer_query_geometry.1 != plan.parameters.outer_query_count {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }

    let mut openings = Vec::new();
    for (phase, phase_geometry) in [
        (
            RowCodeWhirPhase::Base,
            plan.base_phase.as_ref().map(|phase| phase.geometry),
        ),
        (
            RowCodeWhirPhase::Auxiliary,
            plan.auxiliary_phase.as_ref().map(|phase| phase.geometry),
        ),
        (
            RowCodeWhirPhase::Quotient,
            Some(plan.quotient_phase.geometry),
        ),
    ] {
        let Some(phase_geometry) = phase_geometry else {
            continue;
        };
        if phase_geometry.encoded_column_count != outer_query_geometry.0 {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        openings.push(LinearBcsSuppliedCommitmentOpeningPlan {
            commitment_role: LinearBcsCommittedOracleRole::RelationPhase { phase },
            owner: LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
            payload_leaf_count: phase_geometry.encoded_column_count,
            query_count: outer_query_geometry.1,
            query_order: LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder,
            merkle_traversal_order: LinearBcsMerkleTraversalOrder::SortedCoordinates,
        });
    }

    let (aggregate_oracle, aggregate_opening_epoch) =
        whir_commitment_opening_geometry(plan, RowCodeWhirCommitmentRole::Aggregate)?;
    push_whir_owned_opening(
        plan,
        &mut openings,
        LinearBcsCommittedOracleRole::Aggregate,
        aggregate_oracle,
        aggregate_opening_epoch,
    )?;

    let pad_query_epoch_ordinal = plan
        .whir
        .final_round
        .query_epoch
        .epoch_ordinal
        .checked_add(1)
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    push_epoch_owned_opening(
        plan,
        &mut openings,
        LinearBcsCommittedOracleRole::AggregateWidePad,
        aggregate_wide_pad_domain_size(plan)?,
        pad_query_epoch_ordinal,
    )?;

    for (round_index, round) in plan.whir.rounds.iter().enumerate() {
        if usize::try_from(round.round_ordinal)
            .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?
            != round_index
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        let commitment_role = RowCodeWhirCommitmentRole::WhirRound {
            round_ordinal: round.round_ordinal,
        };
        let (opened_oracle, opening_epoch) =
            whir_commitment_opening_geometry(plan, commitment_role)?;
        push_whir_owned_opening(
            plan,
            &mut openings,
            LinearBcsCommittedOracleRole::WhirRound {
                round_ordinal: round.round_ordinal,
            },
            opened_oracle,
            opening_epoch,
        )?;
    }

    push_epoch_owned_opening(
        plan,
        &mut openings,
        LinearBcsCommittedOracleRole::BaseFreshSource,
        plan.whir.final_round.encoded_oracle.leaf_count,
        plan.whir.final_round.query_epoch.epoch_ordinal,
    )?;
    push_epoch_owned_opening(
        plan,
        &mut openings,
        LinearBcsCommittedOracleRole::BaseFreshPad,
        aggregate_wide_pad_domain_size(plan)?,
        pad_query_epoch_ordinal,
    )?;

    validate_supplied_commitment_root_owner_bijection(round_ranges, &openings)?;
    Ok(openings)
}

fn push_epoch_owned_opening(
    plan: &RowCodeWhirConstructionPlan,
    openings: &mut Vec<LinearBcsSuppliedCommitmentOpeningPlan>,
    commitment_role: LinearBcsCommittedOracleRole,
    payload_leaf_count: usize,
    epoch_ordinal: u32,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let (domain_size, query_count) =
        unique_query_geometry(plan, RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal })?;
    if payload_leaf_count == 0 || payload_leaf_count != domain_size {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    openings.push(LinearBcsSuppliedCommitmentOpeningPlan {
        commitment_role,
        owner: LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { epoch_ordinal },
        payload_leaf_count,
        query_count,
        query_order: LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder,
        merkle_traversal_order: LinearBcsMerkleTraversalOrder::SortedCoordinates,
    });
    Ok(())
}

fn aggregate_wide_pad_domain_size(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<usize, RowCodeWhirConstructionPlanError> {
    aggregate_wide_pad_query_geometry(plan).map(|geometry| geometry.0)
}

pub(super) fn aggregate_wide_pad_query_geometry(
    plan: &RowCodeWhirConstructionPlan,
) -> Result<(usize, usize), RowCodeWhirConstructionPlanError> {
    let configuration = super::super::hiding_whir::selected_hiding_whir_config(plan.parameters)
        .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    let pad_layout =
        super::super::aggregate_wide_hiding::AggregateWidePadLayout::derive(&configuration)
            .map_err(|_| RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    Ok((
        p3_whir::MaskCodeShape::new(
            pad_layout.message_length(),
            configuration.sumcheck_mask.randomness_len,
            super::super::aggregate_wide_hiding::AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
        )
        .domain_size,
        configuration.mask_queries,
    ))
}

fn push_whir_owned_opening(
    plan: &RowCodeWhirConstructionPlan,
    openings: &mut Vec<LinearBcsSuppliedCommitmentOpeningPlan>,
    commitment_role: LinearBcsCommittedOracleRole,
    opened_oracle: RowCodeWhirEncodedOraclePlan,
    opening_epoch: RowCodeWhirQueryEpochPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let expected_domain_size = 1_usize
        .checked_shl(
            u32::try_from(opening_epoch.bit_length)
                .map_err(|_| RowCodeWhirConstructionPlanError::CountOverflow)?,
        )
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    if opened_oracle.leaf_count == 0
        || opened_oracle.leaf_width == 0
        || opened_oracle
            .leaf_count
            .checked_mul(opened_oracle.leaf_width)
            != Some(opened_oracle.evaluation_count)
        || opening_epoch.domain_size != opened_oracle.leaf_count
        || opening_epoch.domain_size != expected_domain_size
        || opening_epoch.query_count == 0
        || opening_epoch.query_count > opening_epoch.domain_size
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let owner = LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
        epoch_ordinal: opening_epoch.epoch_ordinal,
    };
    if unique_query_geometry(
        plan,
        RowCodeWhirQueryRole::WhirEpoch {
            epoch_ordinal: opening_epoch.epoch_ordinal,
        },
    )? != (opening_epoch.domain_size, opening_epoch.query_count)
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    openings.push(LinearBcsSuppliedCommitmentOpeningPlan {
        commitment_role,
        owner,
        payload_leaf_count: opened_oracle.leaf_count,
        query_count: opening_epoch.query_count,
        query_order: LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder,
        merkle_traversal_order: LinearBcsMerkleTraversalOrder::SortedCoordinates,
    });
    Ok(())
}

fn unique_query_geometry(
    plan: &RowCodeWhirConstructionPlan,
    expected_role: RowCodeWhirQueryRole,
) -> Result<(usize, usize), RowCodeWhirConstructionPlanError> {
    let mut matches = plan
        .transcript_operations
        .iter()
        .filter_map(|operation| match operation {
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role,
                upper_bound,
                output_count,
            } if *role == expected_role => Some((*upper_bound, *output_count)),
            _ => None,
        });
    let geometry = matches
        .next()
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)?;
    if matches.next().is_some() || geometry.0 == 0 || geometry.1 == 0 || geometry.1 > geometry.0 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(geometry)
}

fn validate_supplied_commitment_root_owner_bijection(
    round_ranges: &[LinearBcsRoundRangePlan],
    openings: &[LinearBcsSuppliedCommitmentOpeningPlan],
) -> Result<(), RowCodeWhirConstructionPlanError> {
    let supplied_roots = round_ranges
        .iter()
        .filter_map(|range| match range.prover_oracle_root {
            LinearBcsProverOracleRoot::SuppliedCommitment {
                role,
                payload_leaf_count,
            } => Some((range.round_count, role, payload_leaf_count)),
            LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest { .. }
            | LinearBcsProverOracleRoot::OneEdgeSamplerBlock { .. } => None,
        })
        .collect::<Vec<_>>();
    if supplied_roots.is_empty() || supplied_roots.len() != openings.len() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    for ((round_count, role, payload_leaf_count), opening) in supplied_roots.iter().zip(openings) {
        let owner_is_correct = match (opening.commitment_role, opening.owner) {
            (
                LinearBcsCommittedOracleRole::RelationPhase { .. },
                LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector,
            ) => true,
            (
                LinearBcsCommittedOracleRole::Aggregate,
                LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { epoch_ordinal: 0 },
            ) => true,
            (
                LinearBcsCommittedOracleRole::WhirRound { round_ordinal },
                LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { epoch_ordinal },
            ) => round_ordinal.checked_add(1) == Some(epoch_ordinal),
            (
                LinearBcsCommittedOracleRole::AggregateWidePad
                | LinearBcsCommittedOracleRole::BaseFreshPad,
                LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { .. },
            ) => true,
            (
                LinearBcsCommittedOracleRole::BaseFreshSource,
                LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { .. },
            ) => true,
            _ => false,
        };
        if *round_count != 1
            || opening.commitment_role != *role
            || opening.payload_leaf_count != *payload_leaf_count
            || opening.payload_leaf_count == 0
            || opening.query_count == 0
            || opening.query_count > opening.payload_leaf_count
            || opening.query_order != LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order != LinearBcsMerkleTraversalOrder::SortedCoordinates
            || !owner_is_correct
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
    }
    for (opening_index, opening) in openings.iter().enumerate() {
        if openings
            .iter()
            .enumerate()
            .filter(|(candidate_index, candidate)| {
                *candidate_index != opening_index
                    && candidate.commitment_role == opening.commitment_role
            })
            .count()
            != 0
        {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
    }
    Ok(())
}

fn checked_supplied_commitment_root(
    role: LinearBcsCommittedOracleRole,
    payload_leaf_count: usize,
) -> Result<LinearBcsProverOracleRoot, RowCodeWhirConstructionPlanError> {
    if payload_leaf_count == 0 || !payload_leaf_count.is_power_of_two() {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    Ok(LinearBcsProverOracleRoot::SuppliedCommitment {
        role,
        payload_leaf_count,
    })
}

fn canonical_extension_message_root(
    value_count: usize,
) -> Result<LinearBcsProverOracleRoot, RowCodeWhirConstructionPlanError> {
    if value_count == 0 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    let canonical_message_byte_length = value_count
        .checked_mul(value_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    Ok(LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
        value_count,
        canonical_message_byte_length,
    })
}

fn fixed_sampler_block_count(
    operation: &RowCodeWhirOracleEquationOperationPlan,
) -> Result<u64, RowCodeWhirConstructionPlanError> {
    let expansion_counts = operation
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
    if expansion_counts.len() != 1 {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    expansion_counts[0]
        .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?
        .checked_add(0)
        .filter(|count| *count > 0)
        .ok_or(RowCodeWhirConstructionPlanError::InvalidVariantGeometry)
}

fn validate_linear_bcs_transcript_plan(
    plan: &LinearBcsTranscriptPlan,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    if plan.round_ranges.is_empty()
        || plan.supplied_commitment_openings.is_empty()
        || plan.challenge_selection_rule
            != LinearBcsChallengeSelectionRule::FirstAcceptedInCompleteFixedBlockRange
    {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    let mut next_round_ordinal = 1_u64;
    for range in &plan.round_ranges {
        if range.first_round_ordinal != next_round_ordinal || range.round_count == 0 {
            return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
        }
        match (range.verifier_message_role, range.prover_oracle_root) {
            (
                LinearBcsVerifierMessageRole::SamplerPrefixBlock {
                    source_operation_ordinal,
                    first_block_ordinal,
                },
                LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                    source_operation_ordinal: root_source_operation_ordinal,
                    first_block_ordinal: root_first_block_ordinal,
                },
            ) if source_operation_ordinal == root_source_operation_ordinal
                && first_block_ordinal == root_first_block_ordinal => {}
            (
                LinearBcsVerifierMessageRole::SamplerTerminalBlock {
                    source_operation_ordinal,
                    block_ordinal,
                },
                LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
                    source_operation_ordinal: root_source_operation_ordinal,
                    first_block_ordinal: root_first_block_ordinal,
                },
            ) if range.round_count == 1
                && source_operation_ordinal == root_source_operation_ordinal
                && block_ordinal == root_first_block_ordinal => {}
            (
                LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle { .. },
                root @ (LinearBcsProverOracleRoot::SuppliedCommitment { .. }
                | LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest { .. }),
            ) if range.round_count == 1 => root.validate_geometry()?,
            _ => return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry),
        }
        next_round_ordinal = next_round_ordinal
            .checked_add(range.round_count)
            .ok_or(RowCodeWhirConstructionPlanError::CountOverflow)?;
    }
    if plan.final_query.verifier_message_ordinal != next_round_ordinal {
        return Err(RowCodeWhirConstructionPlanError::InvalidVariantGeometry);
    }
    validate_supplied_commitment_root_owner_bijection(
        &plan.round_ranges,
        &plan.supplied_commitment_openings,
    )?;
    linear_bcs_round_ordinal_encoding(plan.final_query.verifier_message_ordinal)?;
    Ok(())
}

fn encode_verifier_message_role(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    role: LinearBcsVerifierMessageRole,
) {
    match role {
        LinearBcsVerifierMessageRole::UnusedRoundMessageBeforeProverOracle {
            source_operation_ordinal,
        } => {
            encoder.push_u16(1);
            encoder.push_u32(source_operation_ordinal);
        }
        LinearBcsVerifierMessageRole::SamplerPrefixBlock {
            source_operation_ordinal,
            first_block_ordinal,
        } => {
            encoder.push_u16(2);
            encoder.push_u32(source_operation_ordinal);
            encoder.push_u64(first_block_ordinal);
        }
        LinearBcsVerifierMessageRole::SamplerTerminalBlock {
            source_operation_ordinal,
            block_ordinal,
        } => {
            encoder.push_u16(3);
            encoder.push_u32(source_operation_ordinal);
            encoder.push_u64(block_ordinal);
        }
    }
}

fn encode_prover_oracle_root(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    root: LinearBcsProverOracleRoot,
) -> Result<(), RowCodeWhirConstructionPlanError> {
    match root {
        LinearBcsProverOracleRoot::SuppliedCommitment {
            role,
            payload_leaf_count,
        } => {
            encoder.push_u16(1);
            encode_committed_oracle_role(encoder, role);
            encoder.push_usize(payload_leaf_count)?;
        }
        LinearBcsProverOracleRoot::CanonicalCompleteMessageDigest {
            value_count,
            canonical_message_byte_length,
        } => {
            encoder.push_u16(2);
            encoder.push_usize(value_count)?;
            encoder.push_usize(canonical_message_byte_length)?;
        }
        LinearBcsProverOracleRoot::OneEdgeSamplerBlock {
            source_operation_ordinal,
            first_block_ordinal,
        } => {
            encoder.push_u16(3);
            encoder.push_u32(source_operation_ordinal);
            encoder.push_u64(first_block_ordinal);
        }
    }
    Ok(())
}

fn encode_committed_oracle_role(
    encoder: &mut RowCodeWhirConstructionPlanIdentityEncoder,
    role: LinearBcsCommittedOracleRole,
) {
    match role {
        LinearBcsCommittedOracleRole::RelationPhase { phase } => {
            encoder.push_u16(1);
            encoder.push_u16(row_code_whir_phase_tag(phase));
        }
        LinearBcsCommittedOracleRole::Aggregate => encoder.push_u16(2),
        LinearBcsCommittedOracleRole::AggregateWidePad => encoder.push_u16(3),
        LinearBcsCommittedOracleRole::WhirRound { round_ordinal } => {
            encoder.push_u16(4);
            encoder.push_u32(round_ordinal);
        }
        LinearBcsCommittedOracleRole::BaseFreshSource => encoder.push_u16(5),
        LinearBcsCommittedOracleRole::BaseFreshPad => encoder.push_u16(6),
    }
}
