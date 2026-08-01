//! Construction-derived verifier oracle accounting.
//!
//! The transcript catalog counts every typed Fiat-Shamir edge, while the
//! commitment plan identifies every transported compact Merkle opening. This
//! module joins those two production plans and expands the deployed
//! column-streamable leaf construction into its actual SHAKE calls: one
//! initial call, one transition per opened column, and one final call.
//!
//! This is a call and accepting-equation census. It deliberately does not
//! claim the still-open construction-wide QROM reduction.

use std::collections::BTreeSet;

use super::column_commitment::COLUMN_DIGEST_BYTE_LENGTH;
use super::construction_plan::{
    RowCodeWhirConstructionPlan, RowCodeWhirPhase,
    linear_bcs_transcript::{
        LinearBcsCommittedOracleRole, LinearBcsMerkleTraversalOrder, LinearBcsOpeningQueryOrder,
        LinearBcsSuppliedCommitmentOpeningOwner,
    },
};
use super::{ColumnStreamableLeafHasher, MERKLE_DIGEST_BYTE_LENGTH, MERKLE_DIGEST_WORD_LENGTH};
use crate::bgv::proof_suite::merkle::maximum_minimal_frontier_parent_hash_count;
use crate::bgv::proof_suite::relation_plan::{RelationColumnOrigin, RelationPlanVariant};
use crate::foundation::Hash512;

const FOUNDATION_HASH_OUTPUT_BIT_LENGTH: usize = Hash512::BYTE_LENGTH * u8::BITS as usize;
const COLUMN_COMMITMENT_OUTPUT_BIT_LENGTH: usize = COLUMN_DIGEST_BYTE_LENGTH * u8::BITS as usize;
const ROW_CODE_MERKLE_OUTPUT_BIT_LENGTH: usize = MERKLE_DIGEST_BYTE_LENGTH * u8::BITS as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifierMerkleOpeningRole {
    SuppliedCommitment(LinearBcsCommittedOracleRole),
    BoundTree { bound_tree_ordinal: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifierLeafHashConstruction {
    SingleCall {
        output_bit_length: usize,
    },
    ColumnStreamable {
        column_count: usize,
        intermediate_output_bit_length: usize,
        final_output_bit_length: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VerifierMerkleOracleAccountingRow {
    role: VerifierMerkleOpeningRole,
    leaf_count: usize,
    query_count: usize,
    leaf_hash_construction: VerifierLeafHashConstruction,
    initial_hash_query_count: u64,
    transition_hash_query_count: u64,
    final_hash_query_count: u64,
    parent_hash_query_count: u64,
    parent_output_bit_length: usize,
}

impl VerifierMerkleOracleAccountingRow {
    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn role(self) -> VerifierMerkleOpeningRole {
        self.role
    }

    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn leaf_count(self) -> usize {
        self.leaf_count
    }

    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn query_count(self) -> usize {
        self.query_count
    }

    pub(super) const fn leaf_hash_construction(self) -> VerifierLeafHashConstruction {
        self.leaf_hash_construction
    }

    pub(super) const fn initial_hash_query_count(self) -> u64 {
        self.initial_hash_query_count
    }

    pub(super) const fn transition_hash_query_count(self) -> u64 {
        self.transition_hash_query_count
    }

    pub(super) const fn final_hash_query_count(self) -> u64 {
        self.final_hash_query_count
    }

    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn parent_hash_query_count(self) -> u64 {
        self.parent_hash_query_count
    }

    pub(super) const fn parent_output_bit_length(self) -> usize {
        self.parent_output_bit_length
    }

    pub(super) fn leaf_hash_query_count(self) -> Result<u64, String> {
        self.initial_hash_query_count
            .checked_add(self.transition_hash_query_count)
            .and_then(|count| count.checked_add(self.final_hash_query_count))
            .ok_or_else(|| "verifier leaf hash-query count overflowed".to_owned())
    }

    fn complete_hash_query_count(self) -> Result<u64, String> {
        self.leaf_hash_query_count()?
            .checked_add(self.parent_hash_query_count)
            .ok_or_else(|| "verifier Merkle hash-query count overflowed".to_owned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FixedVerifierHashRole {
    RelationPlanIdentity,
    RelationPlanVariantIdentity,
    ConstructionPlanIdentity,
    ApplicationStatement,
    PublicSetupVerifierSequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FixedVerifierHashAccountingRow {
    role: FixedVerifierHashRole,
    hash_query_count: u64,
    distinct_equation_count: u64,
    output_bit_length: usize,
}

impl FixedVerifierHashAccountingRow {
    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn role(self) -> FixedVerifierHashRole {
        self.role
    }

    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn hash_query_count(self) -> u64 {
        self.hash_query_count
    }

    #[cfg(feature = "theorem-evidence")]
    pub(super) const fn distinct_equation_count(self) -> u64 {
        self.distinct_equation_count
    }

    pub(super) const fn output_bit_length(self) -> usize {
        self.output_bit_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeployedVerifierOracleAccounting {
    maximum_transcript_hash_query_count: u64,
    logical_verifier_message_count: u64,
    transcript_output_bit_length: usize,
    merkle_rows: Vec<VerifierMerkleOracleAccountingRow>,
    fixed_hash_rows: Vec<FixedVerifierHashAccountingRow>,
    distinct_streaming_initial_equation_count: u64,
    repeated_streaming_initial_hash_query_count: u64,
    maximum_verifier_hash_query_count: u64,
    maximum_accepting_database_equation_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecomputedVerifierOracleTotals {
    distinct_streaming_initial_equation_count: u64,
    repeated_streaming_initial_hash_query_count: u64,
    maximum_verifier_hash_query_count: u64,
    maximum_accepting_database_equation_count: u64,
}

impl DeployedVerifierOracleAccounting {
    pub(super) const fn maximum_transcript_hash_query_count(&self) -> u64 {
        self.maximum_transcript_hash_query_count
    }

    pub(super) const fn logical_verifier_message_count(&self) -> u64 {
        self.logical_verifier_message_count
    }

    pub(super) const fn transcript_output_bit_length(&self) -> usize {
        self.transcript_output_bit_length
    }

    pub(super) fn merkle_rows(&self) -> &[VerifierMerkleOracleAccountingRow] {
        &self.merkle_rows
    }

    pub(super) fn fixed_hash_rows(&self) -> &[FixedVerifierHashAccountingRow] {
        &self.fixed_hash_rows
    }

    pub(super) const fn distinct_streaming_initial_equation_count(&self) -> u64 {
        self.distinct_streaming_initial_equation_count
    }

    pub(super) const fn repeated_streaming_initial_hash_query_count(&self) -> u64 {
        self.repeated_streaming_initial_hash_query_count
    }

    pub(super) const fn maximum_verifier_hash_query_count(&self) -> u64 {
        self.maximum_verifier_hash_query_count
    }

    pub(super) const fn maximum_accepting_database_equation_count(&self) -> u64 {
        self.maximum_accepting_database_equation_count
    }

    fn recompute_totals(&self) -> Result<RecomputedVerifierOracleTotals, String> {
        if self.maximum_transcript_hash_query_count == 0
            || self.logical_verifier_message_count == 0
            || self.transcript_output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
            || self.merkle_rows.is_empty()
            || self.fixed_hash_rows.is_empty()
            || ColumnStreamableLeafHasher::intermediate_output_bit_length()
                != MERKLE_DIGEST_WORD_LENGTH * u64::BITS as usize
            || ColumnStreamableLeafHasher::final_output_bit_length()
                != MERKLE_DIGEST_WORD_LENGTH * u64::BITS as usize
        {
            return Err("deployed verifier oracle accounting is incomplete".to_owned());
        }

        let mut streaming_initial_widths = BTreeSet::new();
        let mut seen_merkle_roles = Vec::new();
        let mut streaming_initial_hash_query_count = 0_u64;
        let mut merkle_hash_query_count = 0_u64;
        let mut merkle_equation_count = 0_u64;
        for row in &self.merkle_rows {
            if row.leaf_count == 0
                || !row.leaf_count.is_power_of_two()
                || row.query_count == 0
                || row.query_count > row.leaf_count
                || row.parent_hash_query_count
                    != maximum_compact_parent_hash_query_count(row.leaf_count, row.query_count)?
                || row.parent_output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
                || seen_merkle_roles.contains(&row.role)
            {
                return Err("deployed verifier Merkle row has invalid geometry".to_owned());
            }
            seen_merkle_roles.push(row.role);
            let opened_leaf_count = u64::try_from(row.query_count)
                .map_err(|_| "opened verifier leaf count exceeds u64".to_owned())?;
            match row.leaf_hash_construction {
                VerifierLeafHashConstruction::SingleCall { output_bit_length } => {
                    if row.initial_hash_query_count != 0
                        || row.transition_hash_query_count != opened_leaf_count
                        || row.final_hash_query_count != 0
                        || output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
                    {
                        return Err(
                            "single-call verifier leaf row has the wrong call schedule".to_owned()
                        );
                    }
                    merkle_equation_count = merkle_equation_count
                        .checked_add(opened_leaf_count)
                        .ok_or_else(|| "verifier Merkle equation count overflowed".to_owned())?;
                }
                VerifierLeafHashConstruction::ColumnStreamable {
                    column_count,
                    intermediate_output_bit_length,
                    final_output_bit_length,
                } => {
                    if column_count == 0
                        || row.initial_hash_query_count != opened_leaf_count
                        || row.transition_hash_query_count
                            != opened_leaf_count
                                .checked_mul(u64::try_from(column_count).map_err(|_| {
                                    "streaming verifier leaf width exceeds u64".to_owned()
                                })?)
                                .ok_or_else(|| {
                                    "streaming verifier transition count overflowed".to_owned()
                                })?
                        || row.final_hash_query_count != opened_leaf_count
                        || intermediate_output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
                        || final_output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
                    {
                        return Err(
                            "column-streamable verifier leaf row has the wrong call schedule"
                                .to_owned(),
                        );
                    }
                    streaming_initial_widths.insert(column_count);
                    streaming_initial_hash_query_count = streaming_initial_hash_query_count
                        .checked_add(row.initial_hash_query_count)
                        .ok_or_else(|| {
                            "streaming verifier initial call count overflowed".to_owned()
                        })?;
                    merkle_equation_count = merkle_equation_count
                        .checked_add(row.transition_hash_query_count)
                        .and_then(|count| count.checked_add(row.final_hash_query_count))
                        .ok_or_else(|| "streaming verifier equation count overflowed".to_owned())?;
                }
            }
            merkle_hash_query_count = merkle_hash_query_count
                .checked_add(row.complete_hash_query_count()?)
                .ok_or_else(|| "verifier Merkle hash-query count overflowed".to_owned())?;
            merkle_equation_count = merkle_equation_count
                .checked_add(row.parent_hash_query_count)
                .ok_or_else(|| "verifier parent equation count overflowed".to_owned())?;
        }

        let distinct_streaming_initial_equation_count =
            u64::try_from(streaming_initial_widths.len())
                .map_err(|_| "streaming initial-equation count exceeds u64".to_owned())?;
        merkle_equation_count = merkle_equation_count
            .checked_add(distinct_streaming_initial_equation_count)
            .ok_or_else(|| "streaming initial-equation count overflowed".to_owned())?;
        let repeated_streaming_initial_hash_query_count = streaming_initial_hash_query_count
            .checked_sub(distinct_streaming_initial_equation_count)
            .ok_or_else(|| "streaming initial-call repetition count underflowed".to_owned())?;

        let mut seen_fixed_roles = Vec::new();
        let (fixed_hash_query_count, fixed_equation_count) =
            self.fixed_hash_rows
                .iter()
                .try_fold((0_u64, 0_u64), |(queries, equations), row| {
                    if row.hash_query_count == 0
                        || row.distinct_equation_count == 0
                        || row.distinct_equation_count > row.hash_query_count
                        || row.output_bit_length != FOUNDATION_HASH_OUTPUT_BIT_LENGTH
                        || seen_fixed_roles.contains(&row.role)
                    {
                        return Err("fixed verifier hash row is invalid".to_owned());
                    }
                    seen_fixed_roles.push(row.role);
                    Ok((
                        queries
                            .checked_add(row.hash_query_count)
                            .ok_or_else(|| "fixed verifier hash count overflowed".to_owned())?,
                        equations
                            .checked_add(row.distinct_equation_count)
                            .ok_or_else(|| "fixed verifier equation count overflowed".to_owned())?,
                    ))
                })?;
        let expected_hash_query_count = self
            .maximum_transcript_hash_query_count
            .checked_add(merkle_hash_query_count)
            .and_then(|count| count.checked_add(fixed_hash_query_count))
            .ok_or_else(|| "complete verifier hash-query count overflowed".to_owned())?;
        let expected_equation_count = self
            .maximum_transcript_hash_query_count
            .checked_add(merkle_equation_count)
            .and_then(|count| count.checked_add(fixed_equation_count))
            .ok_or_else(|| "complete verifier equation count overflowed".to_owned())?;
        Ok(RecomputedVerifierOracleTotals {
            distinct_streaming_initial_equation_count,
            repeated_streaming_initial_hash_query_count,
            maximum_verifier_hash_query_count: expected_hash_query_count,
            maximum_accepting_database_equation_count: expected_equation_count,
        })
    }

    fn validate(&self) -> Result<(), String> {
        let totals = self.recompute_totals()?;
        if self.distinct_streaming_initial_equation_count
            != totals.distinct_streaming_initial_equation_count
            || self.repeated_streaming_initial_hash_query_count
                != totals.repeated_streaming_initial_hash_query_count
            || self.maximum_verifier_hash_query_count != totals.maximum_verifier_hash_query_count
            || self.maximum_accepting_database_equation_count
                != totals.maximum_accepting_database_equation_count
            || totals.maximum_accepting_database_equation_count
                > totals.maximum_verifier_hash_query_count
        {
            return Err("deployed verifier oracle totals do not reconcile".to_owned());
        }
        Ok(())
    }
}

fn maximum_compact_parent_hash_query_count(
    leaf_count: usize,
    query_count: usize,
) -> Result<u64, String> {
    u64::try_from(
        maximum_minimal_frontier_parent_hash_count(leaf_count, query_count)
            .map_err(|_| "compact Merkle query geometry is invalid".to_owned())?,
    )
    .map_err(|_| "compact Merkle parent count exceeds u64".to_owned())
}

fn phase_leaf_count(
    construction_plan: &RowCodeWhirConstructionPlan,
    phase: RowCodeWhirPhase,
) -> Result<usize, String> {
    match phase {
        RowCodeWhirPhase::Base => construction_plan
            .base_phase
            .as_ref()
            .map(|phase| phase.geometry.encoded_column_count),
        RowCodeWhirPhase::Auxiliary => construction_plan
            .auxiliary_phase
            .as_ref()
            .map(|phase| phase.geometry.encoded_column_count),
        RowCodeWhirPhase::Quotient => Some(
            construction_plan
                .quotient_phase
                .geometry
                .encoded_column_count,
        ),
    }
    .ok_or_else(|| "supplied relation phase is absent from the construction plan".to_owned())
}

fn whir_opening_geometry(
    construction_plan: &RowCodeWhirConstructionPlan,
    role: LinearBcsCommittedOracleRole,
) -> Result<(u32, usize, usize, usize), String> {
    let (epoch_ordinal, encoded_oracle, query_epoch) = match role {
        LinearBcsCommittedOracleRole::Aggregate => {
            let first_round = construction_plan
                .whir
                .rounds
                .first()
                .ok_or_else(|| "aggregate commitment has no WHIR opening epoch".to_owned())?;
            (
                first_round.query_epoch.epoch_ordinal,
                first_round.encoded_oracle,
                first_round.query_epoch,
            )
        }
        LinearBcsCommittedOracleRole::WhirRound { round_ordinal } => {
            let round_index = construction_plan
                .whir
                .rounds
                .iter()
                .position(|round| round.round_ordinal == round_ordinal)
                .ok_or_else(|| "WHIR commitment round is absent".to_owned())?;
            let following_index = round_index
                .checked_add(1)
                .ok_or_else(|| "WHIR opening epoch overflowed".to_owned())?;
            let (encoded_oracle, query_epoch) = construction_plan
                .whir
                .rounds
                .get(following_index)
                .map(|round| (round.encoded_oracle, round.query_epoch))
                .unwrap_or((
                    construction_plan.whir.final_round.encoded_oracle,
                    construction_plan.whir.final_round.query_epoch,
                ));
            (query_epoch.epoch_ordinal, encoded_oracle, query_epoch)
        }
        _ => return Err("commitment role is not a carried WHIR oracle".to_owned()),
    };
    if query_epoch.domain_size != encoded_oracle.leaf_count
        || encoded_oracle
            .leaf_count
            .checked_mul(encoded_oracle.leaf_width)
            != Some(encoded_oracle.evaluation_count)
    {
        return Err("WHIR commitment opening geometry is invalid".to_owned());
    }
    Ok((
        epoch_ordinal,
        encoded_oracle.leaf_count,
        query_epoch.query_count,
        encoded_oracle.leaf_width,
    ))
}

fn streaming_opening_width(
    construction_plan: &RowCodeWhirConstructionPlan,
    role: LinearBcsCommittedOracleRole,
    owner: LinearBcsSuppliedCommitmentOpeningOwner,
    leaf_count: usize,
    query_count: usize,
) -> Result<Option<usize>, String> {
    match role {
        LinearBcsCommittedOracleRole::RelationPhase { phase } => {
            if owner != LinearBcsSuppliedCommitmentOpeningOwner::OuterQueryVector
                || leaf_count != phase_leaf_count(construction_plan, phase)?
                || query_count != construction_plan.parameters.outer_query_count
            {
                return Err("relation-phase opening geometry is invalid".to_owned());
            }
            Ok(None)
        }
        LinearBcsCommittedOracleRole::Aggregate
        | LinearBcsCommittedOracleRole::WhirRound { .. } => {
            let (epoch_ordinal, expected_leaf_count, expected_query_count, leaf_width) =
                whir_opening_geometry(construction_plan, role)?;
            if owner != (LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch { epoch_ordinal })
                || leaf_count != expected_leaf_count
                || query_count != expected_query_count
                || leaf_width == 0
            {
                return Err("WHIR opening geometry is invalid".to_owned());
            }
            Ok(Some(leaf_width))
        }
        LinearBcsCommittedOracleRole::AggregateWidePad
        | LinearBcsCommittedOracleRole::BaseFreshSource
        | LinearBcsCommittedOracleRole::BaseFreshPad => {
            let final_source_epoch_ordinal =
                construction_plan.whir.final_round.query_epoch.epoch_ordinal;
            let pad_epoch_ordinal = final_source_epoch_ordinal
                .checked_add(1)
                .ok_or_else(|| "aggregate-wide pad epoch overflowed".to_owned())?;
            let expected_epoch_ordinal = if role == LinearBcsCommittedOracleRole::BaseFreshSource {
                final_source_epoch_ordinal
            } else {
                pad_epoch_ordinal
            };
            if owner
                != (LinearBcsSuppliedCommitmentOpeningOwner::WhirEpoch {
                    epoch_ordinal: expected_epoch_ordinal,
                })
            {
                return Err("aggregate-wide mask opening has the wrong query owner".to_owned());
            }
            let (expected_leaf_count, expected_query_count) =
                if role == LinearBcsCommittedOracleRole::BaseFreshSource {
                    (
                        construction_plan.whir.final_round.encoded_oracle.leaf_count,
                        construction_plan.whir.final_round.query_epoch.query_count,
                    )
                } else {
                    construction_plan
                        .aggregate_wide_pad_query_geometry()
                        .map_err(|error| {
                            format!("derive aggregate-wide pad query geometry: {error:?}")
                        })?
                };
            if leaf_count != expected_leaf_count || query_count != expected_query_count {
                return Err("aggregate-wide mask opening geometry is invalid".to_owned());
            }
            Ok(Some(1))
        }
    }
}

fn derive_merkle_rows(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<Vec<VerifierMerkleOracleAccountingRow>, String> {
    let transcript_plan = construction_plan
        .linear_bcs_transcript_plan()
        .map_err(|error| format!("derive supplied commitment openings: {error:?}"))?;
    let mut rows = Vec::new();
    for opening in transcript_plan.supplied_commitment_openings() {
        if opening.query_order != LinearBcsOpeningQueryOrder::AcceptedTranscriptOrder
            || opening.merkle_traversal_order != LinearBcsMerkleTraversalOrder::SortedCoordinates
        {
            return Err("supplied commitment opening is not canonical".to_owned());
        }
        let opened_leaf_count = u64::try_from(opening.query_count)
            .map_err(|_| "supplied opening query count exceeds u64".to_owned())?;
        let streaming_width = streaming_opening_width(
            construction_plan,
            opening.commitment_role,
            opening.owner,
            opening.payload_leaf_count,
            opening.query_count,
        )?;
        let leaf_hash_construction = streaming_width.map_or(
            VerifierLeafHashConstruction::SingleCall {
                output_bit_length: COLUMN_COMMITMENT_OUTPUT_BIT_LENGTH,
            },
            |column_count| VerifierLeafHashConstruction::ColumnStreamable {
                column_count,
                intermediate_output_bit_length:
                    ColumnStreamableLeafHasher::intermediate_output_bit_length(),
                final_output_bit_length: ColumnStreamableLeafHasher::final_output_bit_length(),
            },
        );
        let (initial_hash_query_count, transition_hash_query_count, final_hash_query_count) =
            match leaf_hash_construction {
                VerifierLeafHashConstruction::SingleCall { .. } => (0, opened_leaf_count, 0),
                VerifierLeafHashConstruction::ColumnStreamable { column_count, .. } => (
                    opened_leaf_count,
                    opened_leaf_count
                        .checked_mul(
                            u64::try_from(column_count)
                                .map_err(|_| "streaming opening width exceeds u64".to_owned())?,
                        )
                        .ok_or_else(|| {
                            "streaming opening transition count overflowed".to_owned()
                        })?,
                    opened_leaf_count,
                ),
            };
        rows.push(VerifierMerkleOracleAccountingRow {
            role: VerifierMerkleOpeningRole::SuppliedCommitment(opening.commitment_role),
            leaf_count: opening.payload_leaf_count,
            query_count: opening.query_count,
            leaf_hash_construction,
            initial_hash_query_count,
            transition_hash_query_count,
            final_hash_query_count,
            parent_hash_query_count: maximum_compact_parent_hash_query_count(
                opening.payload_leaf_count,
                opening.query_count,
            )?,
            parent_output_bit_length: if streaming_width.is_some() {
                ROW_CODE_MERKLE_OUTPUT_BIT_LENGTH
            } else {
                COLUMN_COMMITMENT_OUTPUT_BIT_LENGTH
            },
        });
    }

    for tree in &construction_plan.bound_trees {
        let opened_leaf_count = u64::try_from(tree.query_count)
            .map_err(|_| "bound-tree query count exceeds u64".to_owned())?;
        rows.push(VerifierMerkleOracleAccountingRow {
            role: VerifierMerkleOpeningRole::BoundTree {
                bound_tree_ordinal: tree.bound_tree_ordinal,
            },
            leaf_count: tree.leaf_count,
            query_count: tree.query_count,
            leaf_hash_construction: VerifierLeafHashConstruction::SingleCall {
                output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
            },
            initial_hash_query_count: 0,
            transition_hash_query_count: opened_leaf_count,
            final_hash_query_count: 0,
            parent_hash_query_count: maximum_compact_parent_hash_query_count(
                tree.leaf_count,
                tree.query_count,
            )?,
            parent_output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        });
    }
    Ok(rows)
}

fn derive_fixed_hash_rows(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<Vec<FixedVerifierHashAccountingRow>, String> {
    if relation_variant
        .canonical_hash()
        .map_err(|error| format!("hash verifier relation variant: {error:?}"))?
        != construction_plan.relation_plan_variant_hash
        || relation_variant.schedule_position() != construction_plan.schedule_position
        || relation_variant.top_count() != construction_plan.top_count
        || relation_variant.trace_domain_size() != construction_plan.trace_domain_size
        || relation_variant.proof_privacy_mode() != construction_plan.proof_privacy_mode
        || construction_plan.relation_plan_hash == [0_u8; 64]
        || construction_plan.relation_plan_variant_hash == [0_u8; 64]
    {
        return Err("fixed verifier hash accounting has the wrong relation geometry".to_owned());
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
    let distinct_verifier_source_count = verifier_source_ordinals
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len();
    let public_setup_hash_query_count = u64::try_from(verifier_source_ordinals.len())
        .map_err(|_| "public setup hash-query count exceeds u64".to_owned())?;
    let public_setup_distinct_equation_count = u64::try_from(distinct_verifier_source_count)
        .map_err(|_| "public setup equation count exceeds u64".to_owned())?;
    // The transcript header is not a fixed row here. Its independent header
    // root and zero-state absorption are already the first two equations in
    // the production oracle-equation catalog.
    let mut rows = vec![
        FixedVerifierHashAccountingRow {
            role: FixedVerifierHashRole::RelationPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        },
        FixedVerifierHashAccountingRow {
            role: FixedVerifierHashRole::RelationPlanVariantIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        },
        FixedVerifierHashAccountingRow {
            role: FixedVerifierHashRole::ConstructionPlanIdentity,
            hash_query_count: 1,
            distinct_equation_count: 1,
            output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        },
        FixedVerifierHashAccountingRow {
            role: FixedVerifierHashRole::ApplicationStatement,
            hash_query_count: 1,
            distinct_equation_count: 1,
            output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        },
    ];
    if public_setup_hash_query_count > 0 {
        if public_setup_distinct_equation_count == 0 {
            return Err("public setup hashes have no distinct equations".to_owned());
        }
        rows.push(FixedVerifierHashAccountingRow {
            role: FixedVerifierHashRole::PublicSetupVerifierSequence,
            hash_query_count: public_setup_hash_query_count,
            distinct_equation_count: public_setup_distinct_equation_count,
            output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        });
    }
    Ok(rows)
}

pub(super) fn derive_deployed_verifier_oracle_accounting(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<DeployedVerifierOracleAccounting, String> {
    let oracle_equation_catalog = construction_plan
        .oracle_equation_catalog()
        .map_err(|error| format!("derive verifier oracle-equation catalog: {error:?}"))?;
    let maximum_transcript_hash_query_count = oracle_equation_catalog
        .maximum_transcript_hash_query_count()
        .map_err(|error| format!("derive transcript hash-query ceiling: {error:?}"))?;
    let logical_verifier_message_count =
        oracle_equation_catalog
            .logical_verifier_message_count()
            .map_err(|error| format!("derive logical verifier-message count: {error:?}"))?;
    let merkle_rows = derive_merkle_rows(construction_plan)?;
    let fixed_hash_rows = derive_fixed_hash_rows(construction_plan, relation_variant)?;
    let mut accounting = DeployedVerifierOracleAccounting {
        maximum_transcript_hash_query_count,
        logical_verifier_message_count,
        transcript_output_bit_length: FOUNDATION_HASH_OUTPUT_BIT_LENGTH,
        merkle_rows,
        fixed_hash_rows,
        distinct_streaming_initial_equation_count: 0,
        repeated_streaming_initial_hash_query_count: 0,
        maximum_verifier_hash_query_count: 0,
        maximum_accepting_database_equation_count: 0,
    };
    let totals = accounting.recompute_totals()?;
    accounting.distinct_streaming_initial_equation_count =
        totals.distinct_streaming_initial_equation_count;
    accounting.repeated_streaming_initial_hash_query_count =
        totals.repeated_streaming_initial_hash_query_count;
    accounting.maximum_verifier_hash_query_count = totals.maximum_verifier_hash_query_count;
    accounting.maximum_accepting_database_equation_count =
        totals.maximum_accepting_database_equation_count;
    accounting.validate()?;
    Ok(accounting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    use crate::bgv::proof_suite::relation_plan::ProofPrivacyMode;
    use crate::bgv::proof_suite::{
        ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
        selected_ballot_validity_relation_compilation, selected_relation_plan_check_context,
        selected_same_secret_relation_plan_input,
    };
    use crate::foundation::ProofApplicationSlotCeilings;

    fn selected_same_secret_construction() -> (RowCodeWhirConstructionPlan, RelationPlanVariant) {
        static SELECTED_SAME_SECRET_CONSTRUCTION: OnceLock<(
            RowCodeWhirConstructionPlan,
            RelationPlanVariant,
        )> = OnceLock::new();
        SELECTED_SAME_SECRET_CONSTRUCTION
            .get_or_init(|| {
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
                let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                    compiled_plan,
                    &context,
                )
                .expect("the selected same-secret relation validates");
                let relation_variant = artifact
                    .compiled_plan()
                    .select_variant(None, None)
                    .expect("the selected same-secret variant exists")
                    .clone();
                let construction_plan =
                    RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
                        .expect("the selected same-secret construction derives");
                (construction_plan, relation_variant)
            })
            .clone()
    }

    fn selected_ballot_construction() -> (RowCodeWhirConstructionPlan, RelationPlanVariant) {
        static SELECTED_BALLOT_CONSTRUCTION: OnceLock<(
            RowCodeWhirConstructionPlan,
            RelationPlanVariant,
        )> = OnceLock::new();
        SELECTED_BALLOT_CONSTRUCTION
            .get_or_init(|| {
                let context = selected_relation_plan_check_context(
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .expect("the selected ballot context exists");
                let compiled_plan = selected_ballot_validity_relation_compilation()
                    .expect("the selected ballot relation compiles")
                    .into_relation_plan();
                let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                    compiled_plan,
                    &context,
                )
                .expect("the selected ballot relation validates");
                let relation_variant = artifact
                    .compiled_plan()
                    .select_variant(None, None)
                    .expect("the selected ballot variant exists")
                    .clone();
                let construction_plan =
                    RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
                        .expect("the selected ballot construction derives");
                (construction_plan, relation_variant)
            })
            .clone()
    }

    #[test]
    fn deployed_verifier_accounting_expands_every_streaming_leaf_call() {
        let (construction_plan, relation_variant) = selected_same_secret_construction();
        let accounting =
            derive_deployed_verifier_oracle_accounting(&construction_plan, &relation_variant)
                .expect("the deployed verifier accounting derives");

        assert_eq!(
            relation_variant.proof_privacy_mode(),
            ProofPrivacyMode::SecretBearing
        );
        assert_eq!(accounting.maximum_transcript_hash_query_count(), 14_673);
        assert_eq!(accounting.logical_verifier_message_count(), 4_272);
        assert_eq!(accounting.transcript_output_bit_length(), 512);
        assert_eq!(accounting.maximum_verifier_hash_query_count(), 105_437);
        assert_eq!(
            accounting.maximum_accepting_database_equation_count(),
            102_648
        );
        assert_eq!(accounting.merkle_rows().len(), 23);
        assert_eq!(accounting.fixed_hash_rows().len(), 5);

        let streaming_rows = accounting
            .merkle_rows()
            .iter()
            .filter(|row| {
                matches!(
                    row.leaf_hash_construction(),
                    VerifierLeafHashConstruction::ColumnStreamable { .. }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(streaming_rows.len(), 9);
        assert_eq!(
            streaming_rows
                .iter()
                .map(|row| match row.leaf_hash_construction() {
                    VerifierLeafHashConstruction::ColumnStreamable { column_count, .. } => {
                        column_count
                    }
                    VerifierLeafHashConstruction::SingleCall { .. } => unreachable!(),
                })
                .collect::<Vec<_>>(),
            [8, 1, 8, 8, 8, 8, 8, 1, 1],
        );
        assert_eq!(
            streaming_rows
                .iter()
                .map(|row| row.initial_hash_query_count())
                .sum::<u64>(),
            2_782
        );
        assert_eq!(
            streaming_rows
                .iter()
                .map(|row| row.leaf_hash_query_count().expect("the leaf count adds"))
                .sum::<u64>(),
            20_477
        );
        assert_eq!(accounting.distinct_streaming_initial_equation_count(), 2);
        assert_eq!(
            accounting.repeated_streaming_initial_hash_query_count(),
            2_780
        );
        assert_eq!(
            streaming_rows
                .iter()
                .map(|row| { row.transition_hash_query_count() + row.final_hash_query_count() })
                .sum::<u64>()
                + accounting.distinct_streaming_initial_equation_count(),
            17_697
        );
        assert!(accounting.merkle_rows().iter().all(|row| {
            row.parent_output_bit_length() == 512
                && match row.leaf_hash_construction() {
                    VerifierLeafHashConstruction::SingleCall { output_bit_length } => {
                        output_bit_length == 512
                    }
                    VerifierLeafHashConstruction::ColumnStreamable {
                        intermediate_output_bit_length,
                        final_output_bit_length,
                        ..
                    } => intermediate_output_bit_length == 512 && final_output_bit_length == 512,
                }
        }));
        assert!(
            accounting
                .fixed_hash_rows()
                .iter()
                .all(|row| row.output_bit_length() == 512)
        );
    }

    #[test]
    fn deployed_verifier_accounting_refuses_leaf_schedule_omissions_and_width_changes() {
        let (construction_plan, relation_variant) = selected_same_secret_construction();
        let accounting =
            derive_deployed_verifier_oracle_accounting(&construction_plan, &relation_variant)
                .expect("the deployed verifier accounting derives");
        let streaming_row_index = accounting
            .merkle_rows
            .iter()
            .position(|row| {
                matches!(
                    row.leaf_hash_construction,
                    VerifierLeafHashConstruction::ColumnStreamable {
                        column_count: 8,
                        ..
                    }
                )
            })
            .expect("the selected accounting has a width-eight leaf row");
        let single_call_row_index = accounting
            .merkle_rows
            .iter()
            .position(|row| {
                matches!(
                    row.leaf_hash_construction,
                    VerifierLeafHashConstruction::SingleCall { .. }
                )
            })
            .expect("the selected accounting has a single-call leaf row");

        let mut omitted_transition = accounting.clone();
        omitted_transition.merkle_rows[streaming_row_index].transition_hash_query_count -= 1;
        assert!(omitted_transition.validate().is_err());

        let mut omitted_final = accounting.clone();
        omitted_final.merkle_rows[streaming_row_index].final_hash_query_count = 0;
        assert!(omitted_final.validate().is_err());

        let mut omitted_compact_parent = accounting.clone();
        omitted_compact_parent.merkle_rows[streaming_row_index].parent_hash_query_count -= 1;
        assert!(omitted_compact_parent.validate().is_err());

        let mut wrong_width = accounting.clone();
        wrong_width.merkle_rows[streaming_row_index].leaf_hash_construction =
            VerifierLeafHashConstruction::ColumnStreamable {
                column_count: 4,
                intermediate_output_bit_length:
                    ColumnStreamableLeafHasher::intermediate_output_bit_length(),
                final_output_bit_length: ColumnStreamableLeafHasher::final_output_bit_length(),
            };
        assert!(wrong_width.validate().is_err());

        let mut wrong_transition_output_width = accounting.clone();
        let VerifierLeafHashConstruction::ColumnStreamable {
            intermediate_output_bit_length,
            ..
        } = &mut wrong_transition_output_width.merkle_rows[streaming_row_index]
            .leaf_hash_construction
        else {
            unreachable!()
        };
        *intermediate_output_bit_length = 256;
        assert!(wrong_transition_output_width.validate().is_err());

        let mut wrong_final_output_width = accounting.clone();
        let VerifierLeafHashConstruction::ColumnStreamable {
            final_output_bit_length,
            ..
        } = &mut wrong_final_output_width.merkle_rows[streaming_row_index].leaf_hash_construction
        else {
            unreachable!()
        };
        *final_output_bit_length = 256;
        assert!(wrong_final_output_width.validate().is_err());

        let mut wrong_single_call_output_width = accounting.clone();
        let VerifierLeafHashConstruction::SingleCall { output_bit_length } =
            &mut wrong_single_call_output_width.merkle_rows[single_call_row_index]
                .leaf_hash_construction
        else {
            unreachable!()
        };
        *output_bit_length = 256;
        assert!(wrong_single_call_output_width.validate().is_err());

        let mut wrong_parent_output_width = accounting.clone();
        wrong_parent_output_width.merkle_rows[streaming_row_index].parent_output_bit_length = 256;
        assert!(wrong_parent_output_width.validate().is_err());

        let mut wrong_transcript_output_width = accounting.clone();
        wrong_transcript_output_width.transcript_output_bit_length = 256;
        assert!(wrong_transcript_output_width.validate().is_err());

        let mut wrong_fixed_output_width = accounting.clone();
        wrong_fixed_output_width.fixed_hash_rows[0].output_bit_length = 256;
        assert!(wrong_fixed_output_width.validate().is_err());

        let mut collapsed_initial_equations = accounting;
        collapsed_initial_equations.distinct_streaming_initial_equation_count = 1;
        assert!(collapsed_initial_equations.validate().is_err());
    }

    #[test]
    fn deployed_verifier_accounting_refuses_duplicate_opening_and_fixed_roles() {
        let (construction_plan, relation_variant) = selected_same_secret_construction();
        let accounting =
            derive_deployed_verifier_oracle_accounting(&construction_plan, &relation_variant)
                .expect("the deployed verifier accounting derives");

        let mut duplicate_opening = accounting.clone();
        duplicate_opening
            .merkle_rows
            .push(duplicate_opening.merkle_rows[0]);
        assert!(duplicate_opening.recompute_totals().is_err());

        let mut duplicate_fixed = accounting;
        duplicate_fixed
            .fixed_hash_rows
            .push(duplicate_fixed.fixed_hash_rows[0]);
        assert!(duplicate_fixed.recompute_totals().is_err());
    }

    #[test]
    fn deployed_verifier_accounting_refuses_changed_construction_geometry() {
        let (construction_plan, relation_variant) = selected_same_secret_construction();

        let mut changed_leaf_width = construction_plan.clone();
        changed_leaf_width.whir.rounds[0].encoded_oracle.leaf_width /= 2;
        assert!(
            derive_deployed_verifier_oracle_accounting(&changed_leaf_width, &relation_variant)
                .is_err()
        );

        let mut changed_query_schedule = construction_plan.clone();
        changed_query_schedule.whir.rounds[0]
            .query_epoch
            .query_count -= 1;
        assert!(
            derive_deployed_verifier_oracle_accounting(&changed_query_schedule, &relation_variant)
                .is_err()
        );

        let (_, wrong_relation_geometry) = selected_ballot_construction();
        assert!(
            derive_deployed_verifier_oracle_accounting(
                &construction_plan,
                &wrong_relation_geometry
            )
            .is_err()
        );
    }

    #[test]
    fn deployed_verifier_accounting_derives_width_eight_geometry() {
        let (construction_plan, relation_variant) = selected_ballot_construction();
        let accounting =
            derive_deployed_verifier_oracle_accounting(&construction_plan, &relation_variant)
                .expect("the width-eight verifier accounting derives");

        assert_eq!(
            construction_plan
                .parameters
                .logical_polynomials_per_physical_row,
            8
        );
        assert!(
            accounting.maximum_verifier_hash_query_count()
                > accounting.maximum_transcript_hash_query_count()
        );
        assert!(
            accounting
                .merkle_rows()
                .iter()
                .filter_map(|row| match row.leaf_hash_construction() {
                    VerifierLeafHashConstruction::SingleCall { .. } => None,
                    VerifierLeafHashConstruction::ColumnStreamable { column_count, .. } => {
                        Some(column_count)
                    }
                })
                .all(|column_count| column_count == 1 || column_count == 8)
        );
    }
}
