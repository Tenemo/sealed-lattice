//! Construction-driven streaming verification for every selected relation.
//!
//! The canonical proof carries values and compact frontier nodes only. Phase,
//! tree, query, row, and opening coordinates are reconstructed from the
//! checked construction plan and the Fiat-Shamir transcript.

use p3_challenger::CanObserve;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_sumcheck::OpeningBatch;
use p3_symmetric::MerkleCap;
use zeroize::Zeroizing;

use super::aggregate_wide_pcs::{
    AggregateWideCommitment, aggregate_wide_challenger_from_transcript,
    aggregate_wide_pcs_for_construction_plan,
};
use super::column_commitment::{
    ColumnDigest, hash_opened_column, verify_prehashed_column_frontier,
};
use super::compact_merkle_frontier::verify_materialized_bound_frontier;
use super::construction_plan::{
    RowCodeWhirBoundLowDegreeMode, RowCodeWhirConstructionPlan, RowCodeWhirPhase,
};
use super::opening_schedule::{
    RowCodeWhirBoundOpeningClaim, RowCodeWhirOpeningSchedule,
    accumulate_bound_leaf_reduction_evaluations, accumulate_phase_query_column_evaluations,
    bound_degree_test_count, bound_reduction_evaluation_count, derive_bound_opening_claims,
    derive_opening_schedule_after_observed_commitment, derive_point_row_weights,
    ensure_bound_opening_points_are_outside_evaluation_domains,
    expected_out_of_domain_aggregate_evaluations, opening_schedule_continuation, phase_index,
};
use super::{ChallengeField, ExtensionFieldChallenger, RowCodeWhirChallengerProofStreamAbsorber};
use crate::bgv::proof_suite::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofRelationPlanCapability,
    CommonProofTranscript, IncrementalExpectedProofObjectHeaderComparator,
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, OutOfDomainCompositionVerificationInput,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofByteSource,
    ProofChallengeExtensionElement, ProofTreeCatalogEntry, ProofTreeRole, ProofTreeValue,
    RelationPlanVariant, RelationProofTreeInput, SelectedApplicationStatementContext,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedRelationColumnEvaluator, VerifiedStatementOwnedTree,
    build_relation_bound_public_tree_catalog_entries, canonical_proof_object_header_bytes,
    decode_application_statement, decode_selected_application_statement,
    decode_selected_public_key_share_statement, derive_relation_tree_inputs,
    sample_relation_application_challenges, selected_evaluator_aggregate_entry_roots_in_order,
    selected_evaluator_entry_positions, validate_evaluator_auxiliary_root_linkage,
    verify_out_of_domain_composition_with_verified_sequences,
};
use crate::bgv::{
    proof_suite::relation_plan::{BoundTreeConstructionKind, BoundTreeRootUse, ProofPrivacyMode},
    setup::{
        VerifiedEvaluatorSourceLowDegreePrerequisite, VerifiedSetupPolynomialLowDegreePrerequisite,
    },
};
use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItemType, FOUNDATION_PROFILE, Hash512, ProofApplicationSlot,
    ProofApplicationSlotCeilings, ProofObjectHeader,
};

const ROW_CODE_WHIR_PROOF_WIRE_MAGIC: &[u8; 8] = b"SLXPRF08";

struct RowCodeWhirVerificationContext {
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_proof_object_header_bytes: Vec<u8>,
}

struct PreparedRowCodeWhirRelation {
    verification_context: RowCodeWhirVerificationContext,
    relation_variant: RelationPlanVariant,
    relation_context: crate::bgv::proof_suite::RelationPlanCheckContext,
    construction_plan: RowCodeWhirConstructionPlan,
    bound_tree_entries: Vec<ProofTreeCatalogEntry>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
}

pub(crate) struct PreparedRowCodeWhirVerification {
    prepared_relation: PreparedRowCodeWhirRelation,
    header_comparator: IncrementalExpectedProofObjectHeaderComparator,
}

#[derive(Clone, Copy)]
enum VerifiedSetupPolynomialBoundPrerequisite<'prerequisite> {
    PublicKeyShare(&'prerequisite VerifiedSetupPolynomialLowDegreePrerequisite),
    EvaluatorSources(&'prerequisite VerifiedEvaluatorSourceLowDegreePrerequisite),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_row_code_whir_verification(
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    expected_proof_header_hash: Hash512,
    expected_canonical_proof_byte_length: u64,
    relation_plan: &CommonProofRelationPlanCapability,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
) -> Result<PreparedRowCodeWhirVerification, String> {
    prepare_row_code_whir_verification_with_bound_prerequisite(
        None,
        protocol_version,
        application_slot,
        canonical_application_statement_bytes,
        expected_proof_header_hash,
        expected_canonical_proof_byte_length,
        relation_plan,
        statement_owned_trees,
        evaluator_auxiliary_roots,
        verified_column_evaluator,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_setup_polynomial_bound_row_code_whir_verification(
    prerequisite: &VerifiedSetupPolynomialLowDegreePrerequisite,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    expected_proof_header_hash: Hash512,
    expected_canonical_proof_byte_length: u64,
    relation_plan: &CommonProofRelationPlanCapability,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
) -> Result<PreparedRowCodeWhirVerification, String> {
    prepare_row_code_whir_verification_with_bound_prerequisite(
        Some(VerifiedSetupPolynomialBoundPrerequisite::PublicKeyShare(
            prerequisite,
        )),
        protocol_version,
        application_slot,
        canonical_application_statement_bytes,
        expected_proof_header_hash,
        expected_canonical_proof_byte_length,
        relation_plan,
        statement_owned_trees,
        evaluator_auxiliary_roots,
        verified_column_evaluator,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_evaluator_source_bound_row_code_whir_verification(
    prerequisite: &VerifiedEvaluatorSourceLowDegreePrerequisite,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    expected_proof_header_hash: Hash512,
    expected_canonical_proof_byte_length: u64,
    relation_plan: &CommonProofRelationPlanCapability,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
) -> Result<PreparedRowCodeWhirVerification, String> {
    prepare_row_code_whir_verification_with_bound_prerequisite(
        Some(VerifiedSetupPolynomialBoundPrerequisite::EvaluatorSources(
            prerequisite,
        )),
        protocol_version,
        application_slot,
        canonical_application_statement_bytes,
        expected_proof_header_hash,
        expected_canonical_proof_byte_length,
        relation_plan,
        statement_owned_trees,
        evaluator_auxiliary_roots,
        verified_column_evaluator,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_row_code_whir_verification_with_bound_prerequisite(
    setup_polynomial_prerequisite: Option<VerifiedSetupPolynomialBoundPrerequisite<'_>>,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    expected_proof_header_hash: Hash512,
    expected_canonical_proof_byte_length: u64,
    relation_plan: &CommonProofRelationPlanCapability,
    statement_owned_trees: Vec<VerifiedStatementOwnedTree>,
    evaluator_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    verified_column_evaluator: Box<dyn VerifiedRelationColumnEvaluator>,
) -> Result<PreparedRowCodeWhirVerification, String> {
    if protocol_version == 0
        || relation_plan.application_statement_schema_identifier()
            != application_slot.application_statement_schema_identifier()
        || relation_plan.schedule_position() != application_slot.schedule_position()
    {
        return Err("row-code WHIR verification context has the wrong application slot".to_owned());
    }
    let relation_variant = relation_plan
        .compiled_plan()
        .select_variant(relation_plan.schedule_position(), relation_plan.top_count())
        .map_err(|error| format!("select row-code WHIR relation variant: {error:?}"))?
        .clone();
    let relation_context = relation_plan.relation_context().clone();
    let application_statement = decode_application_statement(
        canonical_application_statement_bytes,
        application_slot.application_statement_schema_identifier(),
        protocol_version,
        application_slot.suite_identifier().into_bytes(),
        relation_plan.schedule_position(),
        relation_plan.top_count(),
        &relation_context,
    )
    .map_err(|error| format!("decode row-code WHIR application statement: {error:?}"))?;
    validate_evaluator_auxiliary_root_linkage(
        &application_statement,
        application_slot.application_statement_schema_identifier(),
        relation_plan.schedule_position(),
        relation_plan.top_count(),
        &evaluator_auxiliary_roots,
        &relation_context,
    )
    .map_err(|error| format!("validate evaluator auxiliary roots: {error:?}"))?;
    let construction_plan = relation_plan.row_code_whir_construction_plan().clone();
    validate_optional_setup_polynomial_low_degree_prerequisite(
        setup_polynomial_prerequisite,
        protocol_version,
        application_slot,
        canonical_application_statement_bytes,
        &construction_plan,
        &statement_owned_trees,
    )?;
    let relation_trees = derive_relation_tree_inputs(
        &relation_variant,
        &application_statement,
        &statement_owned_trees,
    )
    .map_err(|error| format!("derive row-code WHIR relation trees: {error:?}"))?;
    let bound_tree_entries = checked_bound_tree_entries(&construction_plan, &relation_trees)?;
    let canonical_proof_object_header_bytes =
        canonical_proof_object_header_bytes(canonical_application_statement_bytes)
            .map_err(|error| format!("encode row-code WHIR proof-object header: {error:?}"))?;
    let actual_proof_header_hash = ProofObjectHeader::decode(
        &canonical_proof_object_header_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.proof_header_hash())
    .map_err(|error| format!("hash row-code WHIR proof-object header: {error:?}"))?;
    if actual_proof_header_hash != expected_proof_header_hash {
        return Err(
            "row-code WHIR proof-object header has the wrong authenticated hash".to_owned(),
        );
    }
    let expected_canonical_proof_byte_length =
        usize::try_from(expected_canonical_proof_byte_length)
            .map_err(|_| "row-code WHIR proof byte length exceeds usize".to_owned())?;
    validate_declared_proof_byte_length(expected_canonical_proof_byte_length)?;
    let header_comparator = IncrementalExpectedProofObjectHeaderComparator::new(
        canonical_proof_object_header_bytes.clone(),
        expected_canonical_proof_byte_length,
        MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    )
    .map_err(|error| format!("validate row-code WHIR proof-object framing: {error:?}"))?;
    Ok(PreparedRowCodeWhirVerification {
        prepared_relation: PreparedRowCodeWhirRelation {
            verification_context: RowCodeWhirVerificationContext {
                protocol_version,
                application_slot,
                canonical_proof_object_header_bytes,
            },
            relation_variant,
            relation_context,
            construction_plan,
            bound_tree_entries,
            verified_column_evaluator,
        },
        header_comparator,
    })
}

fn validate_optional_setup_polynomial_low_degree_prerequisite(
    prerequisite: Option<VerifiedSetupPolynomialBoundPrerequisite<'_>>,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    construction_plan: &RowCodeWhirConstructionPlan,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<(), String> {
    match prerequisite {
        Some(VerifiedSetupPolynomialBoundPrerequisite::PublicKeyShare(prerequisite)) => {
            validate_setup_polynomial_low_degree_prerequisite(
                prerequisite,
                protocol_version,
                application_slot,
                canonical_application_statement_bytes,
                construction_plan,
                statement_owned_trees,
            )
        }
        Some(VerifiedSetupPolynomialBoundPrerequisite::EvaluatorSources(prerequisite)) => {
            validate_evaluator_source_low_degree_prerequisite(
                prerequisite,
                protocol_version,
                application_slot,
                canonical_application_statement_bytes,
                construction_plan,
                statement_owned_trees,
            )
        }
        None if construction_plan.requires_verified_setup_polynomial_bound_prerequisite() => {
            Err("row-code WHIR verification is missing its prior setup-polynomial proof".to_owned())
        }
        None => Ok(()),
    }
}

fn validate_setup_polynomial_low_degree_prerequisite(
    prerequisite: &VerifiedSetupPolynomialLowDegreePrerequisite,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    construction_plan: &RowCodeWhirConstructionPlan,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<(), String> {
    let schema_identifier =
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let statement = decode_selected_public_key_share_statement(
        canonical_application_statement_bytes,
        SelectedApplicationStatementContext::new(
            protocol_version,
            application_slot.suite_identifier().into_bytes(),
            None,
            None,
        ),
    )
    .map_err(|_| "decode setup-polynomial prerequisite statement".to_owned())?;
    if protocol_version != prerequisite.protocol_version()
        || application_slot.application_statement_schema_identifier() != schema_identifier
        || application_slot.suite_identifier().into_bytes() != prerequisite.suite_identifier()
        || application_slot.ceremony_context_hash().into_bytes()
            != prerequisite.ceremony_context_hash()
        || application_slot.action_context_hash().into_bytes() != prerequisite.action_context_hash()
        || application_slot.roster_position() != Some(prerequisite.roster_position())
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_some()
        || statement.setup_proof_context_hash() != prerequisite.setup_proof_context_hash()
        || statement.participant_identity() != prerequisite.participant_identity()
        || statement.roster_position() != prerequisite.roster_position()
        || statement.anchor_commitment_roots() != prerequisite.anchor_commitment_roots()
        || construction_plan.application_statement_schema_identifier != schema_identifier
        || construction_plan.schedule_position.is_some()
        || construction_plan.top_count.is_some()
        || construction_plan.requires_verified_vss_bound_prerequisite()
        || !construction_plan.requires_verified_setup_polynomial_bound_prerequisite()
    {
        return Err("setup-polynomial prerequisite has the wrong proof context".to_owned());
    }

    let prior_proof_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired
        })
        .collect::<Vec<_>>();
    let direct_output_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::Direct)
        .collect::<Vec<_>>();
    if prior_proof_trees.len() != prerequisite.anchor_commitment_roots().len()
        || direct_output_trees.len() != 1
        || prior_proof_trees.iter().any(|tree| {
            tree.construction_kind != BoundTreeConstructionKind::SetupPolynomial
                || tree.root_use != BoundTreeRootUse::Input
                || tree.query_count != construction_plan.parameters.prior_proof_bound_query_count
        })
        || direct_output_trees.iter().any(|tree| {
            tree.construction_kind != BoundTreeConstructionKind::SetupPolynomial
                || tree.root_use != BoundTreeRootUse::Output
                || tree.query_count != construction_plan.parameters.direct_bound_query_count
        })
    {
        return Err("setup-polynomial prerequisite has the wrong construction geometry".to_owned());
    }

    for (anchor_root, bound_tree) in prerequisite
        .anchor_commitment_roots()
        .iter()
        .zip(prior_proof_trees)
    {
        let statement_tree = statement_owned_trees
            .iter()
            .find(|tree| tree.ordered_tree_ordinal() == bound_tree.relation_tree_ordinal)
            .ok_or_else(|| {
                "setup-polynomial prerequisite is missing an authenticated input tree".to_owned()
            })?;
        if statement_tree.expected_root() != *anchor_root {
            return Err(
                "setup-polynomial prerequisite is bound to a different input root".to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_evaluator_source_low_degree_prerequisite(
    prerequisite: &VerifiedEvaluatorSourceLowDegreePrerequisite,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: &[u8],
    construction_plan: &RowCodeWhirConstructionPlan,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<(), String> {
    let schema_identifier =
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let top_count = construction_plan
        .top_count
        .filter(|top_count| (1..=FOUNDATION_PROFILE.option_count).contains(top_count))
        .ok_or_else(|| {
            "evaluator-source prerequisite has the wrong candidate topology".to_owned()
        })?;
    let statement = decode_selected_application_statement(
        canonical_application_statement_bytes,
        schema_identifier,
        SelectedApplicationStatementContext::new(
            protocol_version,
            application_slot.suite_identifier().into_bytes(),
            None,
            Some(top_count),
        ),
    )
    .map_err(|_| "decode evaluator-source prerequisite statement".to_owned())?;
    let statement_setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH] = statement
        .items
        .first()
        .filter(|item| {
            item.item_type() == CanonicalItemType::Hash512
                && item.canonical_bytes().len() == Hash512::BYTE_LENGTH
        })
        .and_then(|item| item.canonical_bytes().try_into().ok())
        .ok_or_else(|| "decode evaluator-source setup context".to_owned())?;
    if protocol_version != prerequisite.protocol_version()
        || application_slot.application_statement_schema_identifier() != schema_identifier
        || application_slot.suite_identifier().into_bytes() != prerequisite.suite_identifier()
        || application_slot.ceremony_context_hash().into_bytes()
            != prerequisite.ceremony_context_hash()
        || application_slot.action_context_hash().into_bytes() != prerequisite.action_context_hash()
        || application_slot.roster_position().is_some()
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_some()
        || statement_setup_proof_context_hash != prerequisite.setup_proof_context_hash()
        || construction_plan.application_statement_schema_identifier != schema_identifier
        || construction_plan.schedule_position.is_some()
        || construction_plan.top_count != Some(top_count)
        || construction_plan.requires_verified_vss_bound_prerequisite()
        || !construction_plan.requires_verified_setup_polynomial_bound_prerequisite()
    {
        return Err("evaluator-source prerequisite has the wrong proof context".to_owned());
    }

    let positions = selected_evaluator_entry_positions(top_count)
        .map_err(|_| "derive evaluator-source prerequisite positions".to_owned())?;
    let ordered_statement_roots =
        selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
            .map_err(|_| "derive evaluator-source prerequisite roots".to_owned())?;
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let expected_source_tree_count = positions
        .len()
        .checked_mul(participant_count)
        .ok_or_else(|| "evaluator-source prerequisite tree count overflows".to_owned())?;
    let prior_proof_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| {
            tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired
        })
        .collect::<Vec<_>>();
    let direct_output_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| tree.low_degree_mode == RowCodeWhirBoundLowDegreeMode::Direct)
        .collect::<Vec<_>>();
    if positions.is_empty()
        || ordered_statement_roots.len() != positions.len()
        || prerequisite.ordered_source_trees().len() != expected_source_tree_count
        || prior_proof_trees.len() != expected_source_tree_count
        || direct_output_trees.len() != positions.len()
        || construction_plan.bound_trees.len()
            != expected_source_tree_count
                .checked_add(positions.len())
                .ok_or_else(|| "evaluator-source bound-tree count overflows".to_owned())?
        || prior_proof_trees.iter().any(|tree| {
            tree.construction_kind != BoundTreeConstructionKind::SetupPolynomial
                || tree.root_use != BoundTreeRootUse::Input
                || tree.query_count != construction_plan.parameters.prior_proof_bound_query_count
        })
        || direct_output_trees.iter().any(|tree| {
            tree.construction_kind != BoundTreeConstructionKind::SetupPolynomial
                || tree.root_use != BoundTreeRootUse::Output
                || tree.query_count != construction_plan.parameters.direct_bound_query_count
        })
    {
        return Err("evaluator-source prerequisite has the wrong construction geometry".to_owned());
    }

    let expected_sources =
        ordered_statement_roots
            .iter()
            .zip(&positions)
            .flat_map(|(entry, expected_position)| {
                entry.source_component_roots().iter().enumerate().map(
                    move |(roster_position, root)| (*expected_position, roster_position, *root),
                )
            });
    for (
        ((expected_position, roster_position, statement_root), prerequisite_binding),
        bound_tree,
    ) in expected_sources
        .zip(prerequisite.ordered_source_trees())
        .zip(prior_proof_trees)
    {
        let roster_position = u16::try_from(roster_position)
            .map_err(|_| "evaluator-source roster position overflows".to_owned())?;
        let mut matching_statement_trees = statement_owned_trees.iter().filter(|tree| {
            tree.ordered_tree_ordinal() == bound_tree.relation_tree_ordinal
                && tree.expected_root_source_ordinal() == bound_tree.expected_root_source_ordinal
        });
        let statement_tree = matching_statement_trees.next().ok_or_else(|| {
            "evaluator-source prerequisite is missing an authenticated input tree".to_owned()
        })?;
        if matching_statement_trees.next().is_some()
            || prerequisite_binding.evaluator_position() != expected_position
            || prerequisite_binding.roster_position() != roster_position
            || prerequisite_binding.expected_root() != statement_root
            || statement_tree.expected_root() != statement_root
            || statement_tree.public_polynomial_context_hash()
                != Some(prerequisite_binding.public_polynomial_context_hash())
        {
            return Err(
                "evaluator-source prerequisite is bound to a different input tree".to_owned(),
            );
        }
    }

    for ((entry, expected_position), bound_tree) in ordered_statement_roots
        .iter()
        .zip(positions)
        .zip(direct_output_trees)
    {
        let mut matching_statement_trees = statement_owned_trees.iter().filter(|tree| {
            tree.ordered_tree_ordinal() == bound_tree.relation_tree_ordinal
                && tree.expected_root_source_ordinal() == bound_tree.expected_root_source_ordinal
        });
        let statement_tree = matching_statement_trees.next().ok_or_else(|| {
            "evaluator-source prerequisite is missing an authenticated output tree".to_owned()
        })?;
        if matching_statement_trees.next().is_some()
            || entry.position() != expected_position
            || statement_tree.expected_root() != entry.runtime_component_root()
            || statement_tree.public_polynomial_context_hash().is_none()
        {
            return Err(
                "evaluator-source prerequisite has the wrong aggregate output tree".to_owned(),
            );
        }
    }
    Ok(())
}

fn checked_bound_tree_entries(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_trees: &[RelationProofTreeInput],
) -> Result<Vec<ProofTreeCatalogEntry>, String> {
    let entries = build_relation_bound_public_tree_catalog_entries(relation_trees)
        .map_err(|error| format!("build row-code WHIR bound tree catalog: {error:?}"))?;
    if entries.len() != construction_plan.bound_trees.len() {
        return Err("bound tree catalog does not match the construction".to_owned());
    }
    for (entry, tree) in entries.iter().zip(&construction_plan.bound_trees) {
        if u32::from(entry.tree_catalog_index()) != tree.relation_tree_ordinal
            || entry.bound_root().is_none()
            || entry
                .materialized_row_width()
                .ok()
                .is_none_or(|width| width != tree.ordered_columns.len() || width == 0)
        {
            return Err("bound tree catalog entry has the wrong construction geometry".to_owned());
        }
    }
    Ok(entries)
}

impl PreparedRowCodeWhirVerification {
    /// Conservative resident-memory ceiling for the streaming verifier.
    ///
    /// One complete declared proof length bounds the largest canonical
    /// section that can be decoded at once. A second complete length bounds
    /// all construction-derived accumulators, catalogs, schedules, and
    /// transcript state retained alongside that section. Fixed Rust state is
    /// added explicitly. This intentionally over-approximates the measured
    /// streaming peak while keeping admission independent of allocator
    /// behavior.
    pub(crate) fn maximum_resident_byte_length(&self) -> Result<u64, String> {
        row_code_whir_verification_resident_memory_ceiling(
            self.header_comparator.declared_complete_proof_byte_length(),
        )
    }

    pub(crate) fn into_incremental(self) -> Result<RowCodeWhirIncrementalVerification, String> {
        RowCodeWhirIncrementalVerification::new(self.prepared_relation, self.header_comparator)
    }
}

/// Conservative resident-memory ceiling shared by runtime admission and
/// construction-derived static evidence.
///
/// One complete declared proof bounds the largest canonical section decoded
/// at once. A second complete length bounds construction-derived accumulators,
/// catalogs, schedules, and transcript state retained beside that section.
pub(crate) fn row_code_whir_verification_resident_memory_ceiling(
    declared_proof_byte_length: usize,
) -> Result<u64, String> {
    if declared_proof_byte_length == 0
        || declared_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    {
        return Err("row-code WHIR proof length exceeds the common hard limit".to_owned());
    }
    let declared_proof_byte_length = u64::try_from(declared_proof_byte_length)
        .map_err(|_| "row-code WHIR proof length exceeds u64".to_owned())?;
    let fixed_state_byte_length = u64::try_from(
        core::mem::size_of::<PreparedRowCodeWhirVerification>()
            .saturating_add(core::mem::size_of::<RowCodeWhirIncrementalVerification>())
            .saturating_add(core::mem::size_of::<RowCodeWhirIncrementalDecoder>())
            .saturating_add(core::mem::size_of::<RowCodeWhirIncrementalSemanticVerifier>()),
    )
    .map_err(|_| "row-code WHIR verifier state length exceeds u64".to_owned())?;
    declared_proof_byte_length
        .checked_mul(2)
        .and_then(|length| length.checked_add(fixed_state_byte_length))
        .ok_or_else(|| "row-code WHIR verifier memory bound overflowed".to_owned())
}

struct RowCodeWhirTranscriptPrefix {
    transcript: Option<CommonProofTranscript>,
    application_challenges: Vec<crate::bgv::proof_suite::RelationApplicationChallengeAssignment>,
    composition_challenges: Vec<ProofChallengeExtensionElement>,
    out_of_domain_points: Vec<ProofChallengeExtensionElement>,
    opening_points: Vec<ProofChallengeExtensionElement>,
}

fn absorb_phase_root(
    transcript: &mut CommonProofTranscript,
    relation_variant: &RelationPlanVariant,
    phase: RowCodeWhirPhase,
    root: ColumnDigest,
    ordered_tree_ordinals: &[u16],
) -> Result<(), String> {
    let role = match phase {
        RowCodeWhirPhase::Base => ProofTreeRole::BaseOracle,
        RowCodeWhirPhase::Auxiliary => ProofTreeRole::AuxiliaryOracle,
        RowCodeWhirPhase::Quotient => {
            return transcript
                .absorb_row_code_whir_quotient_phase_root(column_digest_bytes(root))
                .map_err(|error| format!("absorb quotient phase root: {error:?}"));
        }
    };
    let role_tree_count = relation_variant
        .ordered_trees()
        .iter()
        .filter(|tree| {
            matches!(
                tree,
                crate::bgv::proof_suite::RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ..
                } if *proof_tree_role == role as u16
            )
        })
        .count();
    let root_bytes = column_digest_bytes(root);
    for tree_ordinal in ordered_tree_ordinals {
        if usize::from(*tree_ordinal) >= role_tree_count {
            return Err("transcript tree ordinal is outside the relation".to_owned());
        }
        match role {
            ProofTreeRole::BaseOracle => transcript
                .absorb_base_root(*tree_ordinal, root_bytes)
                .map_err(|error| format!("absorb base phase root: {error:?}"))?,
            ProofTreeRole::AuxiliaryOracle => transcript
                .absorb_auxiliary_root(*tree_ordinal, root_bytes)
                .map_err(|error| format!("absorb auxiliary phase root: {error:?}"))?,
        }
    }
    Ok(())
}

fn direct_transcript_prefix(
    prepared_relation: &mut PreparedRowCodeWhirRelation,
    phase_roots: &[Option<ColumnDigest>; 3],
) -> Result<RowCodeWhirTranscriptPrefix, String> {
    let schedule = prepared_relation
        .construction_plan
        .relation_prefix_schedule()
        .clone();
    let context = &prepared_relation.verification_context;
    let mut transcript = CommonProofTranscript::new_relation_prefix_for_construction_plan(
        context.protocol_version,
        context.application_slot.suite_identifier().into_bytes(),
        &prepared_relation.construction_plan,
        context
            .application_slot
            .application_statement_schema_identifier(),
        &context.canonical_proof_object_header_bytes,
        schedule.clone(),
    )
    .map_err(|error| format!("construct row-code WHIR transcript: {error:?}"))?;
    if !schedule.ordered_base_tree_ordinals().is_empty() {
        absorb_phase_root(
            &mut transcript,
            &prepared_relation.relation_variant,
            RowCodeWhirPhase::Base,
            phase_roots[phase_index(RowCodeWhirPhase::Base)]
                .ok_or_else(|| "base phase root is absent".to_owned())?,
            schedule.ordered_base_tree_ordinals(),
        )?;
    }
    let application_challenges = sample_relation_application_challenges(&mut transcript, &schedule)
        .map_err(|error| format!("sample relation application challenges: {error:?}"))?;
    if !schedule.ordered_auxiliary_tree_ordinals().is_empty() {
        absorb_phase_root(
            &mut transcript,
            &prepared_relation.relation_variant,
            RowCodeWhirPhase::Auxiliary,
            phase_roots[phase_index(RowCodeWhirPhase::Auxiliary)]
                .ok_or_else(|| "auxiliary phase root is absent".to_owned())?,
            schedule.ordered_auxiliary_tree_ordinals(),
        )?;
    }
    let mut composition_challenges =
        Vec::with_capacity(prepared_relation.relation_variant.constraint_count());
    for constraint_ordinal in 0..prepared_relation.relation_variant.constraint_count() {
        composition_challenges.push(
            transcript
                .sample_composition_challenge(
                    u32::try_from(constraint_ordinal)
                        .map_err(|_| "constraint ordinal exceeds u32".to_owned())?,
                )
                .map_err(|error| format!("sample composition challenge: {error:?}"))?,
        );
    }
    absorb_phase_root(
        &mut transcript,
        &prepared_relation.relation_variant,
        RowCodeWhirPhase::Quotient,
        phase_roots[phase_index(RowCodeWhirPhase::Quotient)]
            .ok_or_else(|| "quotient phase root is absent".to_owned())?,
        &[],
    )?;
    let point_count = schedule.out_of_domain_point_count();
    let mut out_of_domain_points = Vec::with_capacity(usize::from(point_count));
    for point_ordinal in 0..point_count {
        let mut relation_error = None;
        let point = transcript
            .sample_out_of_domain_point(point_ordinal, |candidate| {
                match prepared_relation
                    .relation_variant
                    .out_of_domain_point_candidate_is_forbidden(
                        &prepared_relation.relation_context,
                        point_ordinal,
                        candidate,
                        &out_of_domain_points,
                    ) {
                    Ok(forbidden) => forbidden,
                    Err(error) => {
                        relation_error = Some(error);
                        true
                    }
                }
            })
            .map_err(|error| format!("sample out-of-domain point: {error:?}"))?;
        if let Some(error) = relation_error {
            return Err(format!("validate out-of-domain point: {error:?}"));
        }
        out_of_domain_points.push(point);
    }
    let opening_points = prepared_relation
        .relation_variant
        .derive_opening_points(&prepared_relation.relation_context, &out_of_domain_points)
        .map_err(|error| format!("derive relation opening points: {error:?}"))?;
    Ok(RowCodeWhirTranscriptPrefix {
        transcript: Some(transcript),
        application_challenges,
        composition_challenges,
        out_of_domain_points,
        opening_points,
    })
}

fn finish_direct_transcript(
    prefix: &mut RowCodeWhirTranscriptPrefix,
    privacy_mode: ProofPrivacyMode,
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement],
) -> Result<crate::bgv::proof_suite::transcript::RowCodeWhirTranscript, String> {
    prefix
        .transcript
        .as_mut()
        .ok_or_else(|| "row-code WHIR transcript was already consumed".to_owned())?
        .absorb_out_of_domain_evaluations(out_of_domain_evaluations)
        .map_err(|error| format!("absorb out-of-domain evaluations: {error:?}"))?;
    let transcript = prefix
        .transcript
        .take()
        .ok_or_else(|| "row-code WHIR transcript was already consumed".to_owned())?;
    match privacy_mode {
        ProofPrivacyMode::SecretBearing => transcript
            .into_secret_bearing_row_code_whir_transcript(opening_batch_mask_chunk_evaluations),
        ProofPrivacyMode::PublicOnly => transcript.into_public_row_code_whir_transcript(),
    }
    .map_err(|error| format!("handoff row-code WHIR transcript: {error:?}"))
}

fn column_digest_bytes(digest: ColumnDigest) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    for (word_index, word) in digest.into_iter().enumerate() {
        let start = word_index * core::mem::size_of::<u64>();
        bytes[start..start + core::mem::size_of::<u64>()].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

struct RowCodeWhirIncrementalSemanticVerifier {
    prepared_relation: PreparedRowCodeWhirRelation,
    canonical_proof_byte_length: usize,
    phase_roots: Option<[Option<ColumnDigest>; 3]>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    bound_claims: Vec<RowCodeWhirBoundOpeningClaim>,
    opening_schedule_continuation:
        Option<super::opening_schedule::RowCodeWhirOpeningScheduleContinuation>,
    opening_schedule: Option<RowCodeWhirOpeningSchedule>,
    challenger: Option<ExtensionFieldChallenger>,
    aggregate_commitment: Option<AggregateWideCommitment>,
    aggregate_wide_pad_commitment: Option<AggregateWideCommitment>,
    expected_out_of_domain: Option<Vec<ChallengeField>>,
    expected_queries: Vec<Vec<ChallengeField>>,
    pending_phase_column_digests: [Vec<(usize, ColumnDigest)>; 3],
    pending_phase_expected_queries: [Vec<Vec<ChallengeField>>; 3],
    next_phase_column_indices: [usize; 3],
    expected_bound_reduction: Vec<ChallengeField>,
    pending_bound_leaf_digests: Vec<(u64, [u8; 64])>,
    pending_bound_reduction_delta: Vec<ChallengeField>,
    consumed_phase_count: usize,
    consumed_bound_tree_count: usize,
}

impl RowCodeWhirIncrementalSemanticVerifier {
    fn new(
        prepared_relation: PreparedRowCodeWhirRelation,
        canonical_proof_byte_length: usize,
    ) -> Self {
        Self {
            prepared_relation,
            canonical_proof_byte_length,
            phase_roots: None,
            opening_points: Vec::new(),
            bound_claims: Vec::new(),
            opening_schedule_continuation: None,
            opening_schedule: None,
            challenger: None,
            aggregate_commitment: None,
            aggregate_wide_pad_commitment: None,
            expected_out_of_domain: None,
            expected_queries: Vec::new(),
            pending_phase_column_digests: std::array::from_fn(|_| Vec::new()),
            pending_phase_expected_queries: std::array::from_fn(|_| Vec::new()),
            next_phase_column_indices: [0; 3],
            expected_bound_reduction: Vec::new(),
            pending_bound_leaf_digests: Vec::new(),
            pending_bound_reduction_delta: Vec::new(),
            consumed_phase_count: 0,
            consumed_bound_tree_count: 0,
        }
    }

    fn resident_accumulator_payload_byte_length(&self) -> usize {
        let point_coordinate_byte_length = self
            .opening_schedule
            .as_ref()
            .map(|schedule| {
                schedule
                    .points()
                    .iter()
                    .map(|point| point.as_slice().len())
                    .sum::<usize>()
                    .saturating_mul(core::mem::size_of::<ChallengeField>())
            })
            .unwrap_or(0);
        self.opening_points
            .capacity()
            .saturating_mul(core::mem::size_of::<ProofChallengeExtensionElement>())
            .saturating_add(
                self.bound_claims
                    .capacity()
                    .saturating_mul(core::mem::size_of::<RowCodeWhirBoundOpeningClaim>()),
            )
            .saturating_add(
                self.expected_queries
                    .iter()
                    .map(Vec::capacity)
                    .sum::<usize>()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            )
            .saturating_add(
                self.expected_bound_reduction
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            )
            .saturating_add(
                self.pending_bound_leaf_digests
                    .capacity()
                    .saturating_mul(core::mem::size_of::<(u64, [u8; 64])>()),
            )
            .saturating_add(point_coordinate_byte_length)
    }

    fn consume_transcript_material(
        &mut self,
        phase_roots: [Option<ColumnDigest>; 3],
        out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
        opening_batch_mask_chunk_evaluations: Vec<ProofChallengeExtensionElement>,
    ) -> Result<(), String> {
        if self.phase_roots.is_some()
            || self.challenger.is_some()
            || self.opening_schedule_continuation.is_some()
        {
            return Err("row-code WHIR transcript material was supplied more than once".to_owned());
        }
        for phase in [
            RowCodeWhirPhase::Base,
            RowCodeWhirPhase::Auxiliary,
            RowCodeWhirPhase::Quotient,
        ] {
            let scheduled = self
                .prepared_relation
                .construction_plan
                .phase_order
                .contains(&phase);
            if phase_roots[phase_index(phase)].is_some() != scheduled {
                return Err("phase-root presence does not match the construction".to_owned());
            }
        }
        let mut prefix = direct_transcript_prefix(&mut self.prepared_relation, &phase_roots)?;
        verify_out_of_domain_composition_with_verified_sequences(
            &self.prepared_relation.relation_variant,
            OutOfDomainCompositionVerificationInput::new(
                &self.prepared_relation.relation_context,
                &prefix.application_challenges,
                &prefix.composition_challenges,
                &prefix.out_of_domain_points,
                &prefix.opening_points,
                &out_of_domain_evaluations,
            ),
            self.prepared_relation.verified_column_evaluator.as_mut(),
        )
        .map_err(|error| format!("verify out-of-domain composition: {error:?}"))?;
        let row_code_whir_transcript = finish_direct_transcript(
            &mut prefix,
            self.prepared_relation.relation_variant.proof_privacy_mode(),
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
        )?;
        let pcs =
            aggregate_wide_pcs_for_construction_plan(&self.prepared_relation.construction_plan)?;
        let mut challenger = aggregate_wide_challenger_from_transcript(
            &pcs,
            &self.prepared_relation.construction_plan,
            row_code_whir_transcript,
        )?;
        let point_row_weights = derive_point_row_weights(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_variant,
            &prefix.opening_points,
            &mut challenger,
        )?;
        let bound_claims = derive_bound_opening_claims(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_variant,
            &prefix.opening_points,
            &out_of_domain_evaluations,
            &mut challenger,
        )?;
        ensure_bound_opening_points_are_outside_evaluation_domains(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_context,
            &bound_claims,
        )?;
        let expected_out_of_domain = expected_out_of_domain_aggregate_evaluations(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_variant,
            &prefix.opening_points,
            &out_of_domain_evaluations,
            &opening_batch_mask_chunk_evaluations,
            &point_row_weights,
        )?;
        let schedule_continuation = opening_schedule_continuation(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_context,
            point_row_weights,
        )?;
        self.phase_roots = Some(phase_roots);
        self.opening_points = prefix.opening_points;
        self.bound_claims = bound_claims;
        self.opening_schedule_continuation = Some(schedule_continuation);
        self.challenger = Some(challenger);
        self.expected_out_of_domain = Some(expected_out_of_domain);
        Ok(())
    }

    fn consume_aggregate_commitments(
        &mut self,
        aggregate_commitment: AggregateWideCommitment,
        aggregate_wide_pad_commitment: AggregateWideCommitment,
    ) -> Result<(), String> {
        if self.phase_roots.is_none()
            || self.aggregate_commitment.is_some()
            || self.aggregate_wide_pad_commitment.is_some()
            || self.opening_schedule.is_some()
        {
            return Err("aggregate commitments are out of order".to_owned());
        }
        let challenger = self
            .challenger
            .as_mut()
            .ok_or_else(|| "aggregate commitments precede transcript material".to_owned())?;
        challenger.observe(aggregate_commitment.clone());
        challenger.observe(aggregate_wide_pad_commitment.clone());
        let schedule = derive_opening_schedule_after_observed_commitment(
            self.opening_schedule_continuation
                .take()
                .ok_or_else(|| "opening schedule continuation is absent".to_owned())?,
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_context,
            &self.opening_points,
            challenger,
        )?;
        let point_count = self.opening_points.len();
        let outer_query_count = self.prepared_relation.construction_plan.outer_query_count();
        self.expected_queries = vec![vec![ChallengeField::ZERO; point_count]; outer_query_count];
        for phase in &self.prepared_relation.construction_plan.phase_order {
            let phase_index = phase_index(*phase);
            self.pending_phase_column_digests[phase_index] = Vec::with_capacity(outer_query_count);
            self.pending_phase_expected_queries[phase_index] =
                vec![vec![ChallengeField::ZERO; point_count]; outer_query_count];
        }
        self.expected_bound_reduction =
            vec![
                ChallengeField::ZERO;
                bound_reduction_evaluation_count(&self.prepared_relation.construction_plan,)?
            ];
        self.aggregate_commitment = Some(aggregate_commitment);
        self.aggregate_wide_pad_commitment = Some(aggregate_wide_pad_commitment);
        self.opening_schedule = Some(schedule);
        Ok(())
    }

    fn consume_phase_column(
        &mut self,
        phase: RowCodeWhirPhase,
        column_ordinal: usize,
        values: Vec<Goldilocks>,
    ) -> Result<(), String> {
        let ordered_phase = self
            .prepared_relation
            .construction_plan
            .phase_order
            .get(self.consumed_phase_count)
            .copied();
        let phase_index = phase_index(phase);
        if ordered_phase != Some(phase)
            || self.next_phase_column_indices[phase_index] != column_ordinal
            || self.aggregate_commitment.is_none()
        {
            return Err("authenticated phase column is out of order".to_owned());
        }
        let schedule = self
            .opening_schedule
            .as_ref()
            .ok_or_else(|| "opening schedule is absent".to_owned())?;
        let authenticated_column_index = *schedule
            .outer_traversal_query_indices()
            .get(column_ordinal)
            .ok_or_else(|| "phase column has no verifier-derived query index".to_owned())?;
        let encoded_column_count = self
            .prepared_relation
            .construction_plan
            .phase_encoded_column_count(phase)
            .ok_or_else(|| "authenticated phase is absent from the construction".to_owned())?;
        let digest = hash_opened_column(&values, encoded_column_count);
        self.pending_phase_column_digests[phase_index].push((authenticated_column_index, digest));
        accumulate_phase_query_column_evaluations(
            &self.prepared_relation.construction_plan,
            phase,
            column_ordinal,
            authenticated_column_index,
            &values,
            schedule.point_row_weights(),
            &mut self.pending_phase_expected_queries[phase_index],
        )?;
        self.next_phase_column_indices[phase_index] = self.next_phase_column_indices[phase_index]
            .checked_add(1)
            .ok_or_else(|| "phase column ordinal overflowed".to_owned())?;
        Ok(())
    }

    fn expected_phase_frontier_node_count(&self, phase: RowCodeWhirPhase) -> Result<usize, String> {
        let encoded_column_count = self
            .prepared_relation
            .construction_plan
            .phase_encoded_column_count(phase)
            .ok_or_else(|| "authenticated phase is absent from the construction".to_owned())?;
        let indices = self
            .opening_schedule
            .as_ref()
            .ok_or_else(|| "opening schedule is absent".to_owned())?
            .outer_traversal_query_indices()
            .iter()
            .map(|index| {
                u64::try_from(*index)
                    .map_err(|_| "phase query index exceeds the canonical width".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(
            crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(
                &indices,
                encoded_column_count,
            )
            .map_err(|error| format!("derive phase frontier coordinates: {error:?}"))?
            .len(),
        )
    }

    fn expected_bound_frontier_node_count(
        &self,
        bound_tree_ordinal: usize,
    ) -> Result<usize, String> {
        let tree = self
            .prepared_relation
            .construction_plan
            .bound_trees
            .get(bound_tree_ordinal)
            .ok_or_else(|| "bound tree ordinal is outside the construction".to_owned())?;
        let indices = self
            .opening_schedule
            .as_ref()
            .ok_or_else(|| "opening schedule is absent".to_owned())?
            .bound_tree_traversal_query_indices(bound_tree_ordinal)?
            .iter()
            .map(|index| {
                u64::try_from(*index)
                    .map_err(|_| "bound query index exceeds the canonical width".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(
            crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(
                &indices,
                tree.leaf_count,
            )
            .map_err(|error| format!("derive bound frontier coordinates: {error:?}"))?
            .len(),
        )
    }

    fn consume_phase_frontier(
        &mut self,
        phase: RowCodeWhirPhase,
        frontier: Vec<ColumnDigest>,
    ) -> Result<(), String> {
        let phase_index = phase_index(phase);
        if self
            .prepared_relation
            .construction_plan
            .phase_order
            .get(self.consumed_phase_count)
            .copied()
            != Some(phase)
            || self.next_phase_column_indices[phase_index]
                != self.prepared_relation.construction_plan.outer_query_count()
        {
            return Err("authenticated phase frontier is out of order".to_owned());
        }
        let root = self
            .phase_roots
            .as_ref()
            .and_then(|roots| roots[phase_index])
            .ok_or_else(|| "authenticated phase root is absent".to_owned())?;
        let encoded_column_count = self
            .prepared_relation
            .construction_plan
            .phase_encoded_column_count(phase)
            .ok_or_else(|| "authenticated phase is absent from the construction".to_owned())?;
        verify_prehashed_column_frontier(
            &root,
            encoded_column_count,
            &self.pending_phase_column_digests[phase_index],
            &frontier,
        )?;
        for (accepted, pending) in self
            .expected_queries
            .iter_mut()
            .zip(&self.pending_phase_expected_queries[phase_index])
        {
            if accepted.len() != pending.len() {
                return Err("phase query accumulator has the wrong point count".to_owned());
            }
            for (accepted, pending) in accepted.iter_mut().zip(pending) {
                *accepted += *pending;
            }
        }
        self.pending_phase_column_digests[phase_index].clear();
        self.pending_phase_expected_queries[phase_index].clear();
        self.consumed_phase_count += 1;
        Ok(())
    }

    fn consume_bound_leaf(
        &mut self,
        bound_tree_ordinal: usize,
        query_ordinal: usize,
        opening: RowCodeWhirBoundLeafOpening,
    ) -> Result<(), String> {
        if self.consumed_phase_count != self.prepared_relation.construction_plan.phase_order.len()
            || bound_tree_ordinal != self.consumed_bound_tree_count
            || query_ordinal != self.pending_bound_leaf_digests.len()
        {
            return Err("bound leaf is out of order".to_owned());
        }
        let schedule = self
            .opening_schedule
            .as_ref()
            .ok_or_else(|| "opening schedule is absent".to_owned())?;
        let leaf_index = *schedule
            .bound_tree_traversal_query_indices(bound_tree_ordinal)?
            .get(query_ordinal)
            .ok_or_else(|| "bound leaf has no verifier-derived query index".to_owned())?;
        let accepted_query_ordinal = schedule.accepted_bound_query_ordinal(
            &self.prepared_relation.construction_plan,
            bound_tree_ordinal,
            leaf_index,
        )?;
        let entry = self
            .prepared_relation
            .bound_tree_entries
            .get(bound_tree_ordinal)
            .ok_or_else(|| "bound tree catalog entry is absent".to_owned())?;
        if opening.persistent_salt.is_some() != entry.requires_persistent_leaf_salt() {
            return Err("bound leaf has the wrong salt shape".to_owned());
        }
        let leaf_index_u64 =
            u64::try_from(leaf_index).map_err(|_| "bound leaf index exceeds u64".to_owned())?;
        let (_, leaf_digest) = entry
            .encode_materialized_leaf(
                leaf_index_u64,
                opening.persistent_salt,
                Zeroizing::new(
                    opening
                        .first_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
                Zeroizing::new(
                    opening
                        .opposite_point_values
                        .iter()
                        .copied()
                        .map(ProofTreeValue::Base)
                        .collect(),
                ),
            )
            .map_err(|error| format!("encode bound leaf: {error:?}"))?;
        if self.pending_bound_reduction_delta.is_empty() {
            self.pending_bound_reduction_delta =
                vec![
                    ChallengeField::ZERO;
                    bound_reduction_evaluation_count(&self.prepared_relation.construction_plan,)?
                ];
        }
        accumulate_bound_leaf_reduction_evaluations(
            &self.prepared_relation.construction_plan,
            &self.prepared_relation.relation_context,
            bound_tree_ordinal,
            accepted_query_ordinal,
            leaf_index,
            &opening.first_point_values,
            &opening.opposite_point_values,
            &self.bound_claims,
            &mut self.pending_bound_reduction_delta,
        )?;
        self.pending_bound_leaf_digests
            .push((leaf_index_u64, leaf_digest));
        Ok(())
    }

    fn consume_bound_frontier(
        &mut self,
        bound_tree_ordinal: usize,
        frontier: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if bound_tree_ordinal != self.consumed_bound_tree_count {
            return Err("bound frontier is out of order".to_owned());
        }
        let schedule = self
            .opening_schedule
            .as_ref()
            .ok_or_else(|| "opening schedule is absent".to_owned())?;
        let expected_query_count = schedule
            .bound_tree_traversal_query_indices(bound_tree_ordinal)?
            .len();
        let entry = self
            .prepared_relation
            .bound_tree_entries
            .get(bound_tree_ordinal)
            .ok_or_else(|| "bound tree catalog entry is absent".to_owned())?;
        let leaf_count = self
            .prepared_relation
            .construction_plan
            .bound_trees
            .get(bound_tree_ordinal)
            .ok_or_else(|| "bound tree plan is absent".to_owned())?
            .leaf_count;
        verify_materialized_bound_frontier(
            entry,
            leaf_count,
            &self.pending_bound_leaf_digests,
            &frontier,
            expected_query_count,
        )?;
        if self.pending_bound_reduction_delta.len() != self.expected_bound_reduction.len() {
            return Err("bound reduction delta has the wrong shape".to_owned());
        }
        for (accepted, pending) in self
            .expected_bound_reduction
            .iter_mut()
            .zip(&self.pending_bound_reduction_delta)
        {
            *accepted += *pending;
        }
        self.pending_bound_leaf_digests.clear();
        self.pending_bound_reduction_delta.clear();
        self.consumed_bound_tree_count += 1;
        Ok(())
    }

    fn finish_aggregate_wide(
        mut self,
        proof: super::aggregate_wide_wire::CompactAggregateWideOpeningProof,
        maximum_resident_decoded_payload_byte_length: usize,
    ) -> Result<RowCodeWhirFinalProofVerification, String> {
        let construction_plan = &self.prepared_relation.construction_plan;
        if self.consumed_phase_count != construction_plan.phase_order.len()
            || self.consumed_bound_tree_count != construction_plan.bound_trees.len()
        {
            return Err(
                "aggregate-wide opening preceded an authenticated proof section".to_owned(),
            );
        }
        let expected_out_of_domain = self
            .expected_out_of_domain
            .take()
            .ok_or_else(|| "out-of-domain accumulator is absent".to_owned())?;
        let expected_queries = core::mem::take(&mut self.expected_queries);
        let expected_bound_reduction = core::mem::take(&mut self.expected_bound_reduction);
        let degree_test_count = bound_degree_test_count(construction_plan)?;
        let schedule = self
            .opening_schedule
            .take()
            .ok_or_else(|| "opening schedule is absent".to_owned())?;
        let expected_evaluation_count = expected_out_of_domain
            .len()
            .checked_add(expected_queries.len())
            .and_then(|count| count.checked_add(expected_bound_reduction.len()))
            .and_then(|count| count.checked_add(degree_test_count))
            .ok_or_else(|| "aggregate-wide evaluation count overflowed".to_owned())?;
        let mut expected_evaluations = Vec::with_capacity(expected_evaluation_count);
        expected_evaluations.extend(
            expected_out_of_domain
                .into_iter()
                .map(|evaluation| OpeningBatch::new(vec![evaluation], Vec::new())),
        );
        expected_evaluations.extend(
            expected_queries
                .into_iter()
                .map(|evaluations| OpeningBatch::new(evaluations, Vec::new())),
        );
        expected_evaluations.extend(
            expected_bound_reduction
                .into_iter()
                .map(|evaluation| OpeningBatch::new(vec![evaluation], Vec::new())),
        );
        expected_evaluations.extend(
            (0..degree_test_count)
                .map(|_| OpeningBatch::new(vec![ChallengeField::ZERO], Vec::new())),
        );
        if expected_evaluations.len() != schedule.points().len()
            || schedule.requested_columns_by_point().len() != schedule.points().len()
        {
            return Err("aggregate-wide opening catalog changed during verification".to_owned());
        }
        let pcs = aggregate_wide_pcs_for_construction_plan(construction_plan)?;
        let configuration = super::hiding_whir::selected_hiding_whir_config(
            construction_plan.selected_parameters(),
        )
        .map_err(|error| format!("derive aggregate-wide configuration: {error:?}"))?;
        let source_commitment = self
            .aggregate_commitment
            .take()
            .ok_or_else(|| "aggregate source commitment is absent".to_owned())?;
        let pad_commitment = self
            .aggregate_wide_pad_commitment
            .take()
            .ok_or_else(|| "aggregate-wide pad commitment is absent".to_owned())?;
        let mut challenger = self
            .challenger
            .take()
            .ok_or_else(|| "aggregate-wide challenger is absent".to_owned())?;
        super::aggregate_wide_verifier::verify_compact_aggregate_wide_opening_after_observed_commitments(
            &pcs,
            &configuration,
            &proof,
            &source_commitment,
            &pad_commitment,
            construction_plan.aggregate_table_width(),
            schedule.points(),
            schedule.requested_columns_by_point(),
            &expected_evaluations,
            &mut challenger,
        )?;
        let oracle_equation_catalog = construction_plan
            .oracle_equation_catalog()
            .map_err(|error| format!("derive oracle-equation catalog: {error:?}"))?;
        let expected_transcript_hash_query_count = oracle_equation_catalog
            .maximum_transcript_hash_query_count()
            .map_err(|error| format!("derive transcript hash-query count: {error:?}"))?;
        let expected_logical_verifier_message_count = oracle_equation_catalog
            .logical_verifier_message_count()
            .map_err(|error| format!("derive verifier message count: {error:?}"))?;
        let absorber = challenger.begin_final_proof_stream(self.canonical_proof_byte_length)?;
        Ok(RowCodeWhirFinalProofVerification {
            absorber,
            absorbed_byte_length: 0,
            proof_byte_length: self.canonical_proof_byte_length,
            query_count: construction_plan.outer_query_count(),
            maximum_resident_decoded_payload_byte_length,
            expected_transcript_hash_query_count,
            expected_logical_verifier_message_count,
        })
    }
}

struct RowCodeWhirBoundLeafOpening {
    persistent_salt: Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>,
    first_point_values: Vec<ProofBaseFieldElement>,
    opposite_point_values: Vec<ProofBaseFieldElement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirDecoderPhase {
    TranscriptMaterial,
    PhaseColumns {
        phase_order_index: usize,
        next_column_index: usize,
    },
    PhaseFrontierCount {
        phase_order_index: usize,
    },
    PhaseFrontier {
        phase_order_index: usize,
        frontier_count: usize,
    },
    BoundLeaves {
        tree_index: usize,
        next_query_index: usize,
    },
    BoundFrontierCount {
        tree_index: usize,
    },
    BoundFrontier {
        tree_index: usize,
        frontier_count: usize,
    },
    AggregateWide,
    Complete,
}

struct RowCodeWhirIncrementalDecoder {
    construction_plan: RowCodeWhirConstructionPlan,
    opening_claim_count: usize,
    opening_widths: Vec<usize>,
    bound_tree_requires_persistent_salt: Vec<bool>,
    bound_tree_row_widths: Vec<usize>,
    declared_proof_byte_length: usize,
    offset: usize,
    phase: RowCodeWhirDecoderPhase,
    maximum_resident_section_byte_length: usize,
    semantic_verifier: Option<RowCodeWhirIncrementalSemanticVerifier>,
    final_semantic_verification: Option<RowCodeWhirFinalProofVerification>,
    complete: bool,
}

impl RowCodeWhirIncrementalDecoder {
    fn new(
        prepared_relation: PreparedRowCodeWhirRelation,
        declared_proof_byte_length: usize,
        canonical_complete_proof_byte_length: usize,
    ) -> Result<Self, String> {
        validate_declared_proof_byte_length(declared_proof_byte_length)?;
        let opening_claim_count = prepared_relation
            .relation_variant
            .ordered_opening_claims()
            .len();
        let opening_widths = prepared_relation
            .construction_plan
            .opening_batches()
            .iter()
            .map(|batch| batch.requested_aggregate_column_ordinals.len())
            .collect::<Vec<_>>();
        if opening_widths.is_empty()
            || opening_widths.iter().any(|width| *width == 0)
            || prepared_relation.bound_tree_entries.len()
                != prepared_relation.construction_plan.bound_trees.len()
            || prepared_relation.bound_tree_entries.iter().any(|entry| {
                entry
                    .materialized_row_width()
                    .ok()
                    .is_none_or(|width| width == 0)
            })
        {
            return Err("row-code WHIR decoder geometry is invalid".to_owned());
        }
        let bound_tree_requires_persistent_salt = prepared_relation
            .bound_tree_entries
            .iter()
            .map(ProofTreeCatalogEntry::requires_persistent_leaf_salt)
            .collect();
        let bound_tree_row_widths = prepared_relation
            .bound_tree_entries
            .iter()
            .map(|entry| {
                entry
                    .materialized_row_width()
                    .expect("the decoder validated every bound-tree row width")
            })
            .collect();
        let semantic_verifier = RowCodeWhirIncrementalSemanticVerifier::new(
            prepared_relation,
            canonical_complete_proof_byte_length,
        );
        Ok(Self {
            construction_plan: semantic_verifier
                .prepared_relation
                .construction_plan
                .clone(),
            opening_claim_count,
            opening_widths,
            bound_tree_requires_persistent_salt,
            bound_tree_row_widths,
            declared_proof_byte_length,
            offset: 0,
            phase: RowCodeWhirDecoderPhase::TranscriptMaterial,
            maximum_resident_section_byte_length: 0,
            semantic_verifier: Some(semantic_verifier),
            final_semantic_verification: None,
            complete: false,
        })
    }

    const fn is_complete(&self) -> bool {
        self.complete
    }

    fn consume_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), String> {
        if source.byte_length() != self.declared_proof_byte_length
            || available_end_offset > self.declared_proof_byte_length
            || available_end_offset < self.offset
        {
            return Err("row-code WHIR decoder received the wrong authenticated range".to_owned());
        }
        if self.complete {
            return Ok(());
        }
        loop {
            let progressed = match self.phase {
                RowCodeWhirDecoderPhase::TranscriptMaterial => {
                    self.consume_transcript_material(source, available_end_offset)?
                }
                RowCodeWhirDecoderPhase::PhaseColumns {
                    phase_order_index,
                    next_column_index,
                } => self.consume_phase_column(
                    source,
                    available_end_offset,
                    phase_order_index,
                    next_column_index,
                )?,
                RowCodeWhirDecoderPhase::PhaseFrontierCount { phase_order_index } => self
                    .consume_phase_frontier_count(
                        source,
                        available_end_offset,
                        phase_order_index,
                    )?,
                RowCodeWhirDecoderPhase::PhaseFrontier {
                    phase_order_index,
                    frontier_count,
                } => self.consume_phase_frontier(
                    source,
                    available_end_offset,
                    phase_order_index,
                    frontier_count,
                )?,
                RowCodeWhirDecoderPhase::BoundLeaves {
                    tree_index,
                    next_query_index,
                } => self.consume_bound_leaf(
                    source,
                    available_end_offset,
                    tree_index,
                    next_query_index,
                )?,
                RowCodeWhirDecoderPhase::BoundFrontierCount { tree_index } => {
                    self.consume_bound_frontier_count(source, available_end_offset, tree_index)?
                }
                RowCodeWhirDecoderPhase::BoundFrontier {
                    tree_index,
                    frontier_count,
                } => self.consume_bound_frontier(
                    source,
                    available_end_offset,
                    tree_index,
                    frontier_count,
                )?,
                RowCodeWhirDecoderPhase::AggregateWide => {
                    self.consume_aggregate_wide(source, available_end_offset)?
                }
                RowCodeWhirDecoderPhase::Complete => {
                    self.complete = true;
                    false
                }
            };
            if !progressed {
                break;
            }
        }
        if available_end_offset == self.declared_proof_byte_length
            && !matches!(self.phase, RowCodeWhirDecoderPhase::Complete)
        {
            return Err("row-code WHIR proof ended before its canonical terminal".to_owned());
        }
        self.complete = matches!(self.phase, RowCodeWhirDecoderPhase::Complete);
        Ok(())
    }

    fn consume_transcript_material<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<bool, String> {
        let extension_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "transcript extension width overflowed".to_owned())?;
        let mask_chunk_count = self
            .construction_plan
            .opening_batch_mask_chunk_evaluation_count()
            .map_err(|_| "opening-batch mask geometry is invalid".to_owned())?;
        let extension_count = self
            .opening_claim_count
            .checked_add(mask_chunk_count)
            .ok_or_else(|| "transcript extension count overflowed".to_owned())?;
        let section_byte_length = ROW_CODE_WHIR_PROOF_WIRE_MAGIC
            .len()
            .checked_add(
                self.construction_plan
                    .phase_order
                    .len()
                    .checked_mul(64)
                    .ok_or_else(|| "phase root byte length overflowed".to_owned())?,
            )
            .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
            .and_then(|length| {
                extension_count
                    .checked_mul(extension_byte_length)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .and_then(|length| length.checked_add(2 * 64))
            .ok_or_else(|| "transcript section length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "transcript material",
        )?
        else {
            return Ok(false);
        };
        let mut reader = RowCodeWhirCanonicalReader::new(&canonical);
        if reader.read_array::<8>()? != *ROW_CODE_WHIR_PROOF_WIRE_MAGIC {
            return Err("row-code WHIR proof has the wrong wire magic".to_owned());
        }
        let mut phase_roots: [Option<ColumnDigest>; 3] = std::array::from_fn(|_| None);
        for phase in &self.construction_plan.phase_order {
            if phase_roots[phase_index(*phase)]
                .replace(reader.read_digest()?)
                .is_some()
            {
                return Err("construction repeats a proof phase".to_owned());
            }
        }
        let out_of_domain_count = reader.read_u32()? as usize;
        if out_of_domain_count != self.opening_claim_count {
            return Err("out-of-domain evaluation count does not match the relation".to_owned());
        }
        let out_of_domain_evaluations = (0..out_of_domain_count)
            .map(|_| reader.read_production_extension())
            .collect::<Result<Vec<_>, _>>()?;
        let opening_batch_mask_chunk_evaluations = (0..mask_chunk_count)
            .map(|_| reader.read_production_extension())
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate_commitment = MerkleCap::new(vec![reader.read_digest()?]);
        let pad_commitment = MerkleCap::new(vec![reader.read_digest()?]);
        if !reader.remaining().is_empty() {
            return Err("transcript section has trailing bytes".to_owned());
        }
        let semantic_verifier = self
            .semantic_verifier
            .as_mut()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?;
        semantic_verifier.consume_transcript_material(
            phase_roots,
            out_of_domain_evaluations,
            opening_batch_mask_chunk_evaluations,
        )?;
        semantic_verifier.consume_aggregate_commitments(aggregate_commitment, pad_commitment)?;
        self.phase = RowCodeWhirDecoderPhase::PhaseColumns {
            phase_order_index: 0,
            next_column_index: 0,
        };
        Ok(true)
    }

    fn consume_phase_column<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_order_index: usize,
        next_column_index: usize,
    ) -> Result<bool, String> {
        let phase = *self
            .construction_plan
            .phase_order
            .get(phase_order_index)
            .ok_or_else(|| "phase order index is outside the construction".to_owned())?;
        if next_column_index == self.construction_plan.outer_query_count() {
            self.phase = RowCodeWhirDecoderPhase::PhaseFrontierCount { phase_order_index };
            return Ok(true);
        }
        let row_count = self
            .construction_plan
            .phase_row_count(phase)
            .ok_or_else(|| "phase row count is absent".to_owned())?;
        let section_byte_length = row_count
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "phase column length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "phase column",
        )?
        else {
            return Ok(false);
        };
        let mut reader = RowCodeWhirCanonicalReader::new(&canonical);
        let values = (0..row_count)
            .map(|_| reader.read_goldilocks())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.remaining().is_empty() {
            return Err("phase column has trailing bytes".to_owned());
        }
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .consume_phase_column(phase, next_column_index, values)?;
        self.phase = RowCodeWhirDecoderPhase::PhaseColumns {
            phase_order_index,
            next_column_index: next_column_index + 1,
        };
        Ok(true)
    }

    fn consume_phase_frontier_count<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_order_index: usize,
    ) -> Result<bool, String> {
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            core::mem::size_of::<u32>(),
            "phase frontier count",
        )?
        else {
            return Ok(false);
        };
        let frontier_count = u32::from_le_bytes(
            canonical
                .as_slice()
                .try_into()
                .map_err(|_| "phase frontier count has the wrong width".to_owned())?,
        ) as usize;
        let phase = *self
            .construction_plan
            .phase_order
            .get(phase_order_index)
            .ok_or_else(|| "phase order index is outside the construction".to_owned())?;
        let expected_frontier_count = self
            .semantic_verifier
            .as_ref()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .expected_phase_frontier_node_count(phase)?;
        if frontier_count != expected_frontier_count {
            return Err("phase frontier count is not coordinate-derived".to_owned());
        }
        self.phase = RowCodeWhirDecoderPhase::PhaseFrontier {
            phase_order_index,
            frontier_count,
        };
        Ok(true)
    }

    fn consume_phase_frontier<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        phase_order_index: usize,
        frontier_count: usize,
    ) -> Result<bool, String> {
        let section_byte_length = frontier_count
            .checked_mul(64)
            .ok_or_else(|| "phase frontier length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "phase frontier",
        )?
        else {
            return Ok(false);
        };
        let mut reader = RowCodeWhirCanonicalReader::new(&canonical);
        let frontier = (0..frontier_count)
            .map(|_| reader.read_digest())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.remaining().is_empty() {
            return Err("phase frontier has trailing bytes".to_owned());
        }
        let phase = *self
            .construction_plan
            .phase_order
            .get(phase_order_index)
            .ok_or_else(|| "phase order index is outside the construction".to_owned())?;
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .consume_phase_frontier(phase, frontier)?;
        if phase_order_index + 1 < self.construction_plan.phase_order.len() {
            self.phase = RowCodeWhirDecoderPhase::PhaseColumns {
                phase_order_index: phase_order_index + 1,
                next_column_index: 0,
            };
        } else if self.construction_plan.bound_trees.is_empty() {
            self.phase = RowCodeWhirDecoderPhase::AggregateWide;
        } else {
            self.phase = RowCodeWhirDecoderPhase::BoundLeaves {
                tree_index: 0,
                next_query_index: 0,
            };
        }
        Ok(true)
    }

    fn consume_bound_leaf<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
        next_query_index: usize,
    ) -> Result<bool, String> {
        let tree = self
            .construction_plan
            .bound_trees
            .get(tree_index)
            .ok_or_else(|| "bound tree index is outside the construction".to_owned())?;
        if next_query_index == tree.query_count {
            self.phase = RowCodeWhirDecoderPhase::BoundFrontierCount { tree_index };
            return Ok(true);
        }
        let salt_byte_length = if self.bound_tree_requires_persistent_salt[tree_index] {
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
        } else {
            0
        };
        let row_width = self
            .bound_tree_row_widths
            .get(tree_index)
            .copied()
            .ok_or_else(|| "bound tree row width is absent".to_owned())?;
        let section_byte_length = 2_usize
            .checked_mul(row_width)
            .and_then(|count| count.checked_mul(core::mem::size_of::<u64>()))
            .and_then(|length| length.checked_add(salt_byte_length))
            .ok_or_else(|| "bound leaf length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "bound leaf",
        )?
        else {
            return Ok(false);
        };
        let mut reader = RowCodeWhirCanonicalReader::new(&canonical);
        let persistent_salt = if salt_byte_length == 0 {
            None
        } else {
            Some(reader.read_array()?)
        };
        let first_point_values = (0..row_width)
            .map(|_| reader.read_base_field())
            .collect::<Result<Vec<_>, _>>()?;
        let opposite_point_values = (0..row_width)
            .map(|_| reader.read_base_field())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.remaining().is_empty() {
            return Err("bound leaf has trailing bytes".to_owned());
        }
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .consume_bound_leaf(
                tree_index,
                next_query_index,
                RowCodeWhirBoundLeafOpening {
                    persistent_salt,
                    first_point_values,
                    opposite_point_values,
                },
            )?;
        self.phase = RowCodeWhirDecoderPhase::BoundLeaves {
            tree_index,
            next_query_index: next_query_index + 1,
        };
        Ok(true)
    }

    fn consume_bound_frontier_count<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
    ) -> Result<bool, String> {
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            core::mem::size_of::<u32>(),
            "bound frontier count",
        )?
        else {
            return Ok(false);
        };
        let frontier_count = u32::from_le_bytes(
            canonical
                .as_slice()
                .try_into()
                .map_err(|_| "bound frontier count has the wrong width".to_owned())?,
        ) as usize;
        let expected_frontier_count = self
            .semantic_verifier
            .as_ref()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .expected_bound_frontier_node_count(tree_index)?;
        if frontier_count != expected_frontier_count {
            return Err("bound frontier count is not coordinate-derived".to_owned());
        }
        self.phase = RowCodeWhirDecoderPhase::BoundFrontier {
            tree_index,
            frontier_count,
        };
        Ok(true)
    }

    fn consume_bound_frontier<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        tree_index: usize,
        frontier_count: usize,
    ) -> Result<bool, String> {
        let section_byte_length = frontier_count
            .checked_mul(64)
            .ok_or_else(|| "bound frontier length overflowed".to_owned())?;
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "bound frontier",
        )?
        else {
            return Ok(false);
        };
        let mut reader = RowCodeWhirCanonicalReader::new(&canonical);
        let frontier = (0..frontier_count)
            .map(|_| reader.read_array())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.remaining().is_empty() {
            return Err("bound frontier has trailing bytes".to_owned());
        }
        self.semantic_verifier
            .as_mut()
            .ok_or_else(|| "semantic verifier is absent".to_owned())?
            .consume_bound_frontier(tree_index, frontier)?;
        if tree_index + 1 < self.construction_plan.bound_trees.len() {
            self.phase = RowCodeWhirDecoderPhase::BoundLeaves {
                tree_index: tree_index + 1,
                next_query_index: 0,
            };
        } else {
            self.phase = RowCodeWhirDecoderPhase::AggregateWide;
        }
        Ok(true)
    }

    fn consume_aggregate_wide<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<bool, String> {
        let section_byte_length = self
            .declared_proof_byte_length
            .checked_sub(self.offset)
            .ok_or_else(|| "aggregate-wide section offset overflowed".to_owned())?;
        if section_byte_length == 0 {
            return Err("proof omitted its aggregate-wide opening".to_owned());
        }
        let Some(canonical) = self.copy_available_section(
            source,
            available_end_offset,
            section_byte_length,
            "aggregate-wide opening",
        )?
        else {
            return Ok(false);
        };
        let configuration = super::hiding_whir::selected_hiding_whir_config(
            self.construction_plan.selected_parameters(),
        )
        .map_err(|error| format!("derive aggregate-wide configuration: {error:?}"))?;
        let compact_proof = super::aggregate_wide_wire::decode_compact_aggregate_wide_opening(
            &configuration,
            &canonical,
            &self.opening_widths,
            self.construction_plan.aggregate_table_width(),
        )?;
        let semantic_verifier = self
            .semantic_verifier
            .take()
            .ok_or_else(|| "semantic verifier disappeared before completion".to_owned())?;
        let maximum_resident_decoded_payload_byte_length =
            self.maximum_resident_section_byte_length.max(
                canonical
                    .len()
                    .saturating_add(compact_proof.resident_byte_length())
                    .saturating_add(semantic_verifier.resident_accumulator_payload_byte_length()),
            );
        self.final_semantic_verification =
            Some(semantic_verifier.finish_aggregate_wide(
                compact_proof,
                maximum_resident_decoded_payload_byte_length,
            )?);
        self.phase = RowCodeWhirDecoderPhase::Complete;
        Ok(true)
    }

    fn copy_available_section<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
        section_byte_length: usize,
        section_label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let section_end_offset = self
            .offset
            .checked_add(section_byte_length)
            .filter(|end_offset| *end_offset <= self.declared_proof_byte_length)
            .ok_or_else(|| format!("{section_label} exceeds the declared proof length"))?;
        if section_end_offset > available_end_offset {
            return Ok(None);
        }
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(section_byte_length)
            .map_err(|_| format!("{section_label} allocation failed"))?;
        canonical.resize(section_byte_length, 0);
        if !source.copy_bytes(self.offset, &mut canonical) {
            return Err(format!(
                "proof source did not expose the authenticated {section_label} range"
            ));
        }
        self.offset = section_end_offset;
        self.maximum_resident_section_byte_length = self
            .maximum_resident_section_byte_length
            .max(section_byte_length);
        Ok(Some(canonical))
    }

    fn finish_semantic(mut self) -> Result<RowCodeWhirFinalProofVerification, String> {
        if !self.complete || self.offset != self.declared_proof_byte_length {
            return Err("proof ended before its canonical terminal".to_owned());
        }
        if self.semantic_verifier.is_some() {
            return Err("semantic verifier retained unfinished state".to_owned());
        }
        self.final_semantic_verification
            .take()
            .ok_or_else(|| "semantic verification result is absent".to_owned())
    }
}

pub(crate) struct RowCodeWhirIncrementalVerification {
    header_comparator: IncrementalExpectedProofObjectHeaderComparator,
    decoder: RowCodeWhirIncrementalDecoder,
    declared_complete_proof_byte_length: usize,
}

impl RowCodeWhirIncrementalVerification {
    fn new(
        prepared_relation: PreparedRowCodeWhirRelation,
        header_comparator: IncrementalExpectedProofObjectHeaderComparator,
    ) -> Result<Self, String> {
        let declared_complete_proof_byte_length =
            header_comparator.declared_complete_proof_byte_length();
        let family_body_byte_length = header_comparator.family_body_byte_length();
        let decoder = RowCodeWhirIncrementalDecoder::new(
            prepared_relation,
            family_body_byte_length,
            declared_complete_proof_byte_length,
        )?;
        Ok(Self {
            header_comparator,
            decoder,
            declared_complete_proof_byte_length,
        })
    }

    pub(crate) fn decoded_byte_length(&self) -> usize {
        if !self.header_comparator.is_complete() {
            return self.header_comparator.compared_header_byte_length();
        }
        self.header_comparator
            .expected_header_byte_length()
            .checked_add(self.decoder.offset)
            .unwrap_or(self.declared_complete_proof_byte_length)
    }

    pub(crate) fn is_decoding_complete(&self) -> bool {
        self.header_comparator.is_complete() && self.decoder.is_complete()
    }

    pub(crate) fn consume_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), String> {
        self.header_comparator
            .compare_available(source, available_end_offset)
            .map_err(|error| format!("compare canonical proof-object header: {error:?}"))?;
        if !self.header_comparator.is_complete() {
            return Ok(());
        }
        let header_byte_length = self.header_comparator.expected_header_byte_length();
        let body_available_end_offset = available_end_offset
            .checked_sub(header_byte_length)
            .ok_or_else(|| "proof body availability precedes its header".to_owned())?;
        let body_source = self
            .header_comparator
            .body_source(source)
            .map_err(|error| format!("construct family-body source: {error:?}"))?;
        self.decoder
            .consume_available(&body_source, body_available_end_offset)
    }

    pub(crate) fn finish_decoding(self) -> Result<RowCodeWhirFinalProofVerification, String> {
        let Self {
            header_comparator,
            decoder,
            declared_complete_proof_byte_length,
        } = self;
        if !header_comparator.is_complete()
            || declared_complete_proof_byte_length
                != header_comparator.declared_complete_proof_byte_length()
        {
            return Err("proof-object header is incomplete or changed".to_owned());
        }
        decoder.finish_semantic()
    }
}

pub(crate) struct RowCodeWhirFinalProofVerification {
    absorber: RowCodeWhirChallengerProofStreamAbsorber,
    absorbed_byte_length: usize,
    proof_byte_length: usize,
    pub(crate) query_count: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) maximum_resident_decoded_payload_byte_length: usize,
    expected_transcript_hash_query_count: u64,
    expected_logical_verifier_message_count: u64,
}

impl RowCodeWhirFinalProofVerification {
    pub(crate) const fn absorbed_byte_length(&self) -> usize {
        self.absorbed_byte_length
    }

    pub(crate) fn absorb(&mut self, canonical_proof_byte_chunk: &[u8]) -> Result<(), String> {
        let following_byte_length = self
            .absorbed_byte_length
            .checked_add(canonical_proof_byte_chunk.len())
            .ok_or_else(|| "final proof-stream length overflowed".to_owned())?;
        if following_byte_length > self.proof_byte_length {
            return Err("final proof stream exceeds its authenticated length".to_owned());
        }
        self.absorber.absorb(canonical_proof_byte_chunk)?;
        self.absorbed_byte_length = following_byte_length;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<RowCodeWhirVerificationMetrics, String> {
        if self.absorbed_byte_length != self.proof_byte_length {
            return Err("final proof stream ended before its authenticated length".to_owned());
        }
        let transcript_summary = self.absorber.finish()?;
        if transcript_summary.maximum_hash_query_count()
            != self.expected_transcript_hash_query_count
            || transcript_summary.logical_verifier_message_count()
                != self.expected_logical_verifier_message_count
        {
            return Err(
                "transcript execution diverges from the checked operation catalog".to_owned(),
            );
        }
        Ok(RowCodeWhirVerificationMetrics {
            proof_byte_length: self.proof_byte_length,
            query_count: self.query_count,
            maximum_resident_decoded_payload_byte_length: self
                .maximum_resident_decoded_payload_byte_length,
        })
    }
}

pub(crate) struct RowCodeWhirVerificationMetrics {
    pub(crate) proof_byte_length: usize,
    pub(crate) query_count: usize,
    #[allow(dead_code)]
    pub(crate) maximum_resident_decoded_payload_byte_length: usize,
}

struct RowCodeWhirCanonicalReader<'a> {
    canonical: &'a [u8],
    offset: usize,
}

impl<'a> RowCodeWhirCanonicalReader<'a> {
    const fn new(canonical: &'a [u8]) -> Self {
        Self {
            canonical,
            offset: 0,
        }
    }

    fn read_array<const BYTE_COUNT: usize>(&mut self) -> Result<[u8; BYTE_COUNT], String> {
        let following_offset = self
            .offset
            .checked_add(BYTE_COUNT)
            .filter(|offset| *offset <= self.canonical.len())
            .ok_or_else(|| "row-code WHIR wire is truncated".to_owned())?;
        let bytes = self.canonical[self.offset..following_offset]
            .try_into()
            .map_err(|_| "row-code WHIR primitive has the wrong length".to_owned())?;
        self.offset = following_offset;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_digest(&mut self) -> Result<ColumnDigest, String> {
        let bytes = self.read_array::<64>()?;
        Ok(core::array::from_fn(|word_index| {
            u64::from_le_bytes(
                bytes[word_index * 8..(word_index + 1) * 8]
                    .try_into()
                    .expect("a digest word has exactly eight bytes"),
            )
        }))
    }

    fn read_goldilocks(&mut self) -> Result<Goldilocks, String> {
        let canonical = u64::from_le_bytes(self.read_array()?);
        if canonical >= super::GOLDILOCKS_MODULUS {
            return Err("row-code WHIR base-field value is non-canonical".to_owned());
        }
        Ok(Goldilocks::new(canonical))
    }

    fn read_base_field(&mut self) -> Result<ProofBaseFieldElement, String> {
        ProofBaseFieldElement::from_canonical(u64::from_le_bytes(self.read_array()?))
            .map_err(|_| "bound opening contains a non-canonical field value".to_owned())
    }

    fn read_production_extension(&mut self) -> Result<ProofChallengeExtensionElement, String> {
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = u64::from_le_bytes(self.read_array()?);
        }
        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map_err(|_| "extension element is non-canonical".to_owned())
    }

    fn remaining(&self) -> &'a [u8] {
        &self.canonical[self.offset..]
    }
}

fn validate_declared_proof_byte_length(declared_proof_byte_length: usize) -> Result<(), String> {
    if declared_proof_byte_length == 0
        || declared_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    {
        return Err("row-code WHIR proof length is outside the common hard bound".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::application_statement::{
        SelectedEvaluatorAggregateEntryInput, canonical_selected_evaluator_aggregate_statement,
    };
    use crate::bgv::proof_suite::{
        StatementOwnedProofTreeInput, ValidatedRelationPlanArtifact,
        canonical_selected_public_key_share_statement, compile_public_key_share_relation_plan,
        selected_evaluator_aggregate_relation_plan, selected_public_key_share_relation_plan_input,
        selected_relation_plan_check_context,
    };
    use crate::foundation::FOUNDATION_PROFILE;
    use std::sync::OnceLock;

    type EvaluatorSourceTestBinding = (
        crate::bgv::proof_suite::SelectedEvaluatorEntryPosition,
        u16,
        [u8; 64],
        [u8; 64],
    );

    struct EvaluatorSourcePrerequisiteFixture {
        construction_plan: RowCodeWhirConstructionPlan,
        canonical_statement: Vec<u8>,
        application_slot: ProofApplicationSlot,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        setup_proof_context_hash: [u8; 64],
        ordered_source_bindings: Vec<EvaluatorSourceTestBinding>,
    }

    fn distinct_test_hash(domain: u8, ordinal: usize) -> [u8; 64] {
        let mut hash = [domain; 64];
        hash[..8].copy_from_slice(
            &u64::try_from(ordinal)
                .expect("the test ordinal fits u64")
                .to_le_bytes(),
        );
        hash
    }

    fn evaluator_source_prerequisite_fixture() -> &'static EvaluatorSourcePrerequisiteFixture {
        static FIXTURE: OnceLock<EvaluatorSourcePrerequisiteFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let schema_identifier =
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .expect("the selected evaluator relation context exists");
            let compiled_relation_plan = selected_evaluator_aggregate_relation_plan()
                .expect("the selected evaluator relation compiles");
            let selected_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                compiled_relation_plan,
                &relation_context,
            )
            .expect("the selected evaluator relation is valid");
            let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
                &selected_artifact,
                None,
                Some(FOUNDATION_PROFILE.option_count),
            )
            .expect("the active evaluator construction is valid");
            let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                .expect("the evaluator positions derive");
            let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
            let ordered_source_roots = positions
                .iter()
                .enumerate()
                .map(|(entry_ordinal, _)| {
                    (0..participant_count)
                        .map(|roster_position| {
                            distinct_test_hash(
                                0x41,
                                entry_ordinal * participant_count + roster_position,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let ordered_runtime_roots = (0..positions.len())
                .map(|entry_ordinal| distinct_test_hash(0x51, entry_ordinal))
                .collect::<Vec<_>>();
            let ordered_auxiliary_roots = (0..positions.len())
                .map(|entry_ordinal| distinct_test_hash(0x61, entry_ordinal))
                .collect::<Vec<_>>();
            let statement_entries = ordered_source_roots
                .iter()
                .zip(&ordered_runtime_roots)
                .zip(&ordered_auxiliary_roots)
                .map(|((source_roots, runtime_root), auxiliary_root)| {
                    SelectedEvaluatorAggregateEntryInput::new(
                        source_roots,
                        *runtime_root,
                        *auxiliary_root,
                    )
                })
                .collect::<Vec<_>>();
            let setup_proof_context_hash = [0x31; 64];
            let canonical_statement = canonical_selected_evaluator_aggregate_statement(
                setup_proof_context_hash,
                FOUNDATION_PROFILE.option_count,
                &statement_entries,
                [0x71; 64],
            )
            .expect("the evaluator statement is canonical");
            let application_slot = ProofApplicationSlot::new(
                Hash512::from_bytes([0x81; 64]),
                Hash512::from_bytes([0x82; 64]),
                Hash512::from_bytes([0x83; 64]),
                schema_identifier,
                None,
                None,
                None,
            )
            .expect("the evaluator application slot is valid");
            let ordered_source_bindings =
                positions
                    .iter()
                    .copied()
                    .zip(&ordered_source_roots)
                    .enumerate()
                    .flat_map(|(entry_ordinal, (position, source_roots))| {
                        source_roots.iter().copied().enumerate().map(
                            move |(roster_position, root)| {
                                let flat_ordinal = entry_ordinal
                                    .checked_mul(participant_count)
                                    .and_then(|offset| offset.checked_add(roster_position))
                                    .expect("the evaluator test ordinal fits usize");
                                (
                                    position,
                                    u16::try_from(roster_position)
                                        .expect("the roster position fits u16"),
                                    root,
                                    distinct_test_hash(0x91, flat_ordinal),
                                )
                            },
                        )
                    })
                    .collect::<Vec<_>>();
            let flattened_source_roots = ordered_source_roots
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            let flattened_source_contexts = ordered_source_bindings
                .iter()
                .map(|binding| binding.3)
                .collect::<Vec<_>>();
            let mut next_source_tree = 0_usize;
            let mut next_output_tree = 0_usize;
            let statement_trees = construction_plan
                .bound_trees
                .iter()
                .map(|tree| {
                    let (expected_root, public_polynomial_context_hash) = match tree.root_use {
                        BoundTreeRootUse::Input => {
                            let tree_input = (
                                flattened_source_roots[next_source_tree],
                                flattened_source_contexts[next_source_tree],
                            );
                            next_source_tree += 1;
                            tree_input
                        }
                        BoundTreeRootUse::Output => {
                            let tree_output = (
                                ordered_runtime_roots[next_output_tree],
                                distinct_test_hash(0xa1, next_output_tree),
                            );
                            next_output_tree += 1;
                            tree_output
                        }
                    };
                    VerifiedStatementOwnedTree::from_test_relation_input(
                        tree.relation_tree_ordinal,
                        tree.expected_root_source_ordinal,
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash,
                            row_width: u32::try_from(tree.ordered_columns.len())
                                .expect("the test row width fits u32"),
                            expected_root,
                        },
                        vec![None; tree.ordered_columns.len()],
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(next_source_tree, flattened_source_roots.len());
            assert_eq!(next_output_tree, ordered_runtime_roots.len());
            EvaluatorSourcePrerequisiteFixture {
                construction_plan,
                canonical_statement,
                application_slot,
                statement_trees,
                setup_proof_context_hash,
                ordered_source_bindings,
            }
        })
    }

    fn evaluator_fixture_prerequisite(
        fixture: &EvaluatorSourcePrerequisiteFixture,
        ordered_source_bindings: Vec<EvaluatorSourceTestBinding>,
    ) -> VerifiedEvaluatorSourceLowDegreePrerequisite {
        VerifiedEvaluatorSourceLowDegreePrerequisite::for_test(
            FOUNDATION_PROFILE.protocol_version,
            fixture.application_slot.suite_identifier().into_bytes(),
            fixture
                .application_slot
                .ceremony_context_hash()
                .into_bytes(),
            fixture.application_slot.action_context_hash().into_bytes(),
            fixture.setup_proof_context_hash,
            ordered_source_bindings,
        )
    }

    struct SetupPolynomialPrerequisiteFixture {
        construction_plan: RowCodeWhirConstructionPlan,
        canonical_statement: Vec<u8>,
        application_slot: ProofApplicationSlot,
        statement_trees: Vec<VerifiedStatementOwnedTree>,
        setup_proof_context_hash: [u8; 64],
        participant_identity: [u8; 64],
        anchor_roots: [[u8; 64]; 3],
    }

    fn setup_polynomial_prerequisite_fixture() -> &'static SetupPolynomialPrerequisiteFixture {
        static FIXTURE: OnceLock<SetupPolynomialPrerequisiteFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let schema_identifier =
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .expect("the selected public-key relation context exists");
            let compiled_relation_plan = compile_public_key_share_relation_plan(
                &selected_public_key_share_relation_plan_input()
                    .expect("the selected public-key relation input exists"),
                &relation_context,
            )
            .expect("the selected public-key relation compiles");
            let selected_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                compiled_relation_plan,
                &relation_context,
            )
            .expect("the selected public-key relation is valid");
            let construction_plan =
                RowCodeWhirConstructionPlan::for_selected_variant(&selected_artifact, None, None)
                    .expect("the selected public-key construction is valid");
            let setup_proof_context_hash = [0x31; 64];
            let participant_identity = [0x32; 64];
            let anchor_roots = [[0x41; 64], [0x42; 64], [0x43; 64]];
            let public_key_share_root = [0x51; 64];
            let canonical_statement = canonical_selected_public_key_share_statement(
                setup_proof_context_hash,
                participant_identity,
                0,
                &anchor_roots,
                public_key_share_root,
            )
            .expect("the public-key statement is canonical");
            let application_slot = ProofApplicationSlot::new(
                Hash512::from_bytes([0x61; 64]),
                Hash512::from_bytes([0x62; 64]),
                Hash512::from_bytes([0x63; 64]),
                schema_identifier,
                Some(0),
                None,
                None,
            )
            .expect("the public-key application slot is valid");
            let mut next_anchor_ordinal = 0_usize;
            let statement_trees = construction_plan
                .bound_trees
                .iter()
                .map(|tree| {
                    let expected_root = match tree.root_use {
                        BoundTreeRootUse::Input => {
                            let root = anchor_roots[next_anchor_ordinal];
                            next_anchor_ordinal += 1;
                            root
                        }
                        BoundTreeRootUse::Output => public_key_share_root,
                    };
                    VerifiedStatementOwnedTree::from_test_relation_input(
                        tree.relation_tree_ordinal,
                        tree.expected_root_source_ordinal,
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: [0x71; 64],
                            row_width: u32::try_from(tree.ordered_columns.len())
                                .expect("the test row width fits u32"),
                            expected_root,
                        },
                        vec![None; tree.ordered_columns.len()],
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(next_anchor_ordinal, anchor_roots.len());
            SetupPolynomialPrerequisiteFixture {
                construction_plan,
                canonical_statement,
                application_slot,
                statement_trees,
                setup_proof_context_hash,
                participant_identity,
                anchor_roots,
            }
        })
    }

    fn fixture_prerequisite(
        fixture: &SetupPolynomialPrerequisiteFixture,
    ) -> VerifiedSetupPolynomialLowDegreePrerequisite {
        VerifiedSetupPolynomialLowDegreePrerequisite::for_test(
            FOUNDATION_PROFILE.protocol_version,
            fixture.application_slot.suite_identifier().into_bytes(),
            fixture
                .application_slot
                .ceremony_context_hash()
                .into_bytes(),
            fixture.application_slot.action_context_hash().into_bytes(),
            fixture.setup_proof_context_hash,
            fixture.participant_identity,
            0,
            fixture.anchor_roots,
        )
    }

    #[test]
    fn evaluator_source_reuse_requires_the_exact_verified_catalog_authority() {
        let fixture = evaluator_source_prerequisite_fixture();
        let prerequisite =
            evaluator_fixture_prerequisite(fixture, fixture.ordered_source_bindings.clone());
        validate_optional_setup_polynomial_low_degree_prerequisite(
            Some(VerifiedSetupPolynomialBoundPrerequisite::EvaluatorSources(
                &prerequisite,
            )),
            FOUNDATION_PROFILE.protocol_version,
            fixture.application_slot,
            &fixture.canonical_statement,
            &fixture.construction_plan,
            &fixture.statement_trees,
        )
        .expect("the exact evaluator-source authority is accepted");

        assert!(
            validate_optional_setup_polynomial_low_degree_prerequisite(
                None,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "statement roots alone cannot authorize evaluator source reuse",
        );

        let public_key_fixture = setup_polynomial_prerequisite_fixture();
        let public_key_prerequisite = fixture_prerequisite(public_key_fixture);
        assert!(
            validate_optional_setup_polynomial_low_degree_prerequisite(
                Some(VerifiedSetupPolynomialBoundPrerequisite::PublicKeyShare(
                    &public_key_prerequisite,
                )),
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "a different prior-proof family cannot authorize evaluator source reuse",
        );
    }

    #[test]
    fn evaluator_source_reuse_refuses_stale_reordered_or_incomplete_authority() {
        let fixture = evaluator_source_prerequisite_fixture();
        let assert_refused = |bindings: Vec<EvaluatorSourceTestBinding>, message: &str| {
            let prerequisite = evaluator_fixture_prerequisite(fixture, bindings);
            assert!(
                validate_evaluator_source_low_degree_prerequisite(
                    &prerequisite,
                    FOUNDATION_PROFILE.protocol_version,
                    fixture.application_slot,
                    &fixture.canonical_statement,
                    &fixture.construction_plan,
                    &fixture.statement_trees,
                )
                .is_err(),
                "{message}",
            );
        };

        let mut wrong_root = fixture.ordered_source_bindings.clone();
        wrong_root[0].2 = [0xb1; 64];
        assert_refused(wrong_root, "a changed source root must be refused");

        let mut stale_context = fixture.ordered_source_bindings.clone();
        stale_context[0].3 = [0xb2; 64];
        assert_refused(
            stale_context,
            "a stale public-polynomial context must be refused",
        );

        let mut reordered = fixture.ordered_source_bindings.clone();
        reordered.swap(0, 1);
        assert_refused(reordered, "reordered source authority must be refused");

        let mut incomplete = fixture.ordered_source_bindings.clone();
        incomplete.pop();
        assert_refused(incomplete, "an omitted source coordinate must be refused");

        let prerequisite =
            evaluator_fixture_prerequisite(fixture, fixture.ordered_source_bindings.clone());
        let wrong_action_slot = ProofApplicationSlot::new(
            fixture.application_slot.suite_identifier(),
            fixture.application_slot.ceremony_context_hash(),
            Hash512::from_bytes([0xb3; 64]),
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
            None,
        )
        .expect("the hostile evaluator slot is structurally valid");
        assert!(
            validate_evaluator_source_low_degree_prerequisite(
                &prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                wrong_action_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "authority from another action must be refused",
        );

        let mut wrong_statement_trees = fixture.statement_trees.clone();
        wrong_statement_trees[0] = wrong_statement_trees[0].with_test_expected_root([0xb4; 64]);
        assert!(
            validate_evaluator_source_low_degree_prerequisite(
                &prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &wrong_statement_trees,
            )
            .is_err(),
            "a changed verifier-owned statement tree must be refused",
        );

        let mut wrong_query_schedule = fixture.construction_plan.clone();
        let first_reused_tree = wrong_query_schedule
            .bound_trees
            .iter_mut()
            .find(|tree| {
                tree.low_degree_mode
                    == RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired
            })
            .expect("the evaluator construction has reused source trees");
        first_reused_tree.query_count += 1;
        assert!(
            validate_evaluator_source_low_degree_prerequisite(
                &prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &wrong_query_schedule,
                &fixture.statement_trees,
            )
            .is_err(),
            "a changed shared-query schedule must be refused",
        );
    }

    #[test]
    fn setup_polynomial_reuse_requires_the_exact_prior_same_secret_capability() {
        let fixture = setup_polynomial_prerequisite_fixture();
        let prerequisite = fixture_prerequisite(fixture);
        validate_optional_setup_polynomial_low_degree_prerequisite(
            Some(VerifiedSetupPolynomialBoundPrerequisite::PublicKeyShare(
                &prerequisite,
            )),
            FOUNDATION_PROFILE.protocol_version,
            fixture.application_slot,
            &fixture.canonical_statement,
            &fixture.construction_plan,
            &fixture.statement_trees,
        )
        .expect("the exact prior same-secret capability is accepted");

        assert!(
            validate_optional_setup_polynomial_low_degree_prerequisite(
                None,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "statement roots alone cannot authorize prior-proof low-degree reuse",
        );

        let mut wrong_root_trees = fixture.statement_trees.clone();
        let first_input_tree_ordinal = fixture
            .construction_plan
            .bound_trees
            .iter()
            .find(|tree| tree.root_use == BoundTreeRootUse::Input)
            .expect("the selected public-key relation has input trees")
            .relation_tree_ordinal;
        let input_tree_index = wrong_root_trees
            .iter()
            .position(|tree| tree.ordered_tree_ordinal() == first_input_tree_ordinal)
            .expect("the authenticated input tree exists");
        wrong_root_trees[input_tree_index] =
            wrong_root_trees[input_tree_index].with_test_expected_root([0x91; 64]);
        assert!(
            validate_setup_polynomial_low_degree_prerequisite(
                &prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &wrong_root_trees,
            )
            .is_err(),
            "an authenticated tree with a different root is refused",
        );
    }

    #[test]
    fn setup_polynomial_reuse_refuses_wrong_context_and_participant() {
        let fixture = setup_polynomial_prerequisite_fixture();
        let wrong_action_slot = ProofApplicationSlot::new(
            fixture.application_slot.suite_identifier(),
            fixture.application_slot.ceremony_context_hash(),
            Hash512::from_bytes([0xa1; 64]),
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            None,
        )
        .expect("the hostile slot is structurally valid");
        let prerequisite = fixture_prerequisite(fixture);
        assert!(
            validate_setup_polynomial_low_degree_prerequisite(
                &prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                wrong_action_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "a prerequisite from another action is refused",
        );

        let wrong_participant_prerequisite = VerifiedSetupPolynomialLowDegreePrerequisite::for_test(
            FOUNDATION_PROFILE.protocol_version,
            fixture.application_slot.suite_identifier().into_bytes(),
            fixture
                .application_slot
                .ceremony_context_hash()
                .into_bytes(),
            fixture.application_slot.action_context_hash().into_bytes(),
            fixture.setup_proof_context_hash,
            [0xa2; 64],
            0,
            fixture.anchor_roots,
        );
        assert!(
            validate_setup_polynomial_low_degree_prerequisite(
                &wrong_participant_prerequisite,
                FOUNDATION_PROFILE.protocol_version,
                fixture.application_slot,
                &fixture.canonical_statement,
                &fixture.construction_plan,
                &fixture.statement_trees,
            )
            .is_err(),
            "a prerequisite from another participant is refused",
        );
    }
}
