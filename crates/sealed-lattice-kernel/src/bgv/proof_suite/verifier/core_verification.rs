use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    PROOF_OBJECT_HEADER_SCHEMA_VERSION, ProofApplicationSlotCeilings,
};
use crate::hashing::hash_framed_parts_512;

use super::{CommonProofVerifierError, VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN};
use crate::bgv::proof_suite::application_statement::{
    SelectedApplicationStatementContext, decode_selected_application_statement,
    selected_evaluator_aggregate_entry_roots, selected_evaluator_entry_positions,
};
use crate::bgv::proof_suite::field::ProofChallengeExtensionElement;
use crate::bgv::proof_suite::merkle::{ProofLeafVisibility, ProofTreeRole};
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeConstructionKind, OutOfDomainCompositionVerificationInput, RelationColumnOrigin,
    RelationColumnValueType, RelationPlanCheckContext, RelationPlanVariant,
    RelationSelectorPathStep, RelationTreeDescriptor, SelectorPathStepKind,
};
use crate::bgv::proof_suite::selected_profile::selected_relation_plan_check_context;
use crate::bgv::proof_suite::verifier::{
    VerifiedEvaluatorAuxiliaryRoot, VerifiedStatementOwnedTree,
};
use crate::bgv::proof_suite::{RelationProofTreeInput, StatementOwnedProofTreeInput};

/// Resolves plan-addressed verifier-sequence columns from verified statement,
/// suite, slot, sampler, or protocol sources. Proof bytes never supply these
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRelationColumnEvaluatorMemoryAccounting {
    maximum_cached_column_resident_byte_length: u64,
    maximum_evaluation_transient_byte_length: u64,
    maximum_resident_byte_length: u64,
}

impl VerifiedRelationColumnEvaluatorMemoryAccounting {
    pub(crate) fn new(
        fixed_and_input_resident_byte_length: u64,
        maximum_cached_column_resident_byte_length: u64,
        maximum_evaluation_transient_byte_length: u64,
    ) -> Result<Self, CommonProofVerifierError> {
        let maximum_resident_byte_length = fixed_and_input_resident_byte_length
            .checked_add(maximum_cached_column_resident_byte_length)
            .and_then(|length| length.checked_add(maximum_evaluation_transient_byte_length))
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        Ok(Self {
            maximum_cached_column_resident_byte_length,
            maximum_evaluation_transient_byte_length,
            maximum_resident_byte_length,
        })
    }

    #[cfg(test)]
    pub(crate) const fn maximum_cached_column_resident_byte_length(self) -> u64 {
        self.maximum_cached_column_resident_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn maximum_evaluation_transient_byte_length(self) -> u64 {
        self.maximum_evaluation_transient_byte_length
    }

    pub(crate) const fn maximum_resident_byte_length(self) -> u64 {
        self.maximum_resident_byte_length
    }
}

pub(crate) trait VerifiedRelationColumnEvaluator {
    fn memory_accounting(
        &self,
    ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError>;

    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement>;
}

pub(crate) fn verified_application_statement_hash(
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
) -> [u8; 64] {
    hash_framed_parts_512(
        VERIFIED_COMMON_PROOF_STATEMENT_HASH_DOMAIN,
        &[
            &protocol_version.to_le_bytes(),
            &suite_identifier,
            &application_statement_schema_identifier.to_le_bytes(),
            canonical_application_statement_bytes,
        ],
    )
}

pub(crate) fn decode_application_statement(
    canonical_bytes: &[u8],
    expected_schema_identifier: u16,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    relation_context: &RelationPlanCheckContext,
) -> Result<CanonicalTuple, CommonProofVerifierError> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    if selected_relation_plan_check_context(expected_schema_identifier)
        .as_ref()
        .is_some_and(|selected_context| relation_context == selected_context)
    {
        return decode_selected_application_statement(
            canonical_bytes,
            expected_schema_identifier,
            SelectedApplicationStatementContext::new(
                protocol_version,
                suite_identifier,
                schedule_position,
                top_count,
            ),
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement);
    }
    let statement = CanonicalTuple::decode(canonical_bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if statement.schema_identifier != expected_schema_identifier
        || statement.schema_version != PROOF_OBJECT_HEADER_SCHEMA_VERSION
        || statement
            .encode()
            .map_err(|_| CommonProofVerifierError::CanonicalEncoding)?
            != canonical_bytes
    {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    Ok(statement)
}

pub(crate) fn validate_evaluator_auxiliary_root_linkage(
    application_statement: &CanonicalTuple,
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    verified_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    relation_context: &RelationPlanCheckContext,
) -> Result<(), CommonProofVerifierError> {
    if !selected_relation_plan_check_context(application_statement_schema_identifier)
        .as_ref()
        .is_some_and(|selected_context| relation_context == selected_context)
    {
        return if verified_auxiliary_roots.is_empty() {
            Ok(())
        } else {
            Err(CommonProofVerifierError::InvalidApplicationStatement)
        };
    }
    if application_statement_schema_identifier
        != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
    {
        return if verified_auxiliary_roots.is_empty() {
            Ok(())
        } else {
            Err(CommonProofVerifierError::InvalidApplicationStatement)
        };
    }
    if schedule_position.is_some() {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    let top_count = top_count
        .filter(|top_count| (1..=FOUNDATION_PROFILE.option_count).contains(top_count))
        .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
    let positions = selected_evaluator_entry_positions(top_count)
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    if verified_auxiliary_roots.len() != positions.len() {
        return Err(CommonProofVerifierError::InvalidApplicationStatement);
    }
    for (entry_ordinal, (position, verified_auxiliary_root)) in
        positions.iter().zip(verified_auxiliary_roots).enumerate()
    {
        let entry_ordinal = u32::try_from(entry_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        let entry = selected_evaluator_aggregate_entry_roots(
            application_statement,
            top_count,
            entry_ordinal,
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
        if entry.entry_ordinal() != entry_ordinal
            || entry.position() != *position
            || verified_auxiliary_root.position() != *position
            || entry.auxiliary_component_root()
                != verified_auxiliary_root.auxiliary_component_root()
        {
            return Err(CommonProofVerifierError::InvalidApplicationStatement);
        }
    }
    Ok(())
}

pub(crate) fn derive_relation_tree_inputs(
    variant: &RelationPlanVariant,
    application_statement: &CanonicalTuple,
    statement_owned_trees: &[VerifiedStatementOwnedTree],
) -> Result<Vec<RelationProofTreeInput>, CommonProofVerifierError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(variant.ordered_trees().len())
        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
    let mut consumed_statement_trees = vec![false; statement_owned_trees.len()];

    for (tree_index, tree) in variant.ordered_trees().iter().enumerate() {
        let ordered_tree_ordinal =
            u32::try_from(tree_index).map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofVerifierError::InvalidTreeLayout),
                };
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                validate_tree_columns(variant, ordered_column_ordinals, None)?;
                inputs.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                expected_root_source_ordinal,
                ordered_column_ordinals,
                ..
            } => {
                validate_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let mut matches = statement_owned_trees
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| {
                        input.ordered_tree_ordinal == ordered_tree_ordinal
                            && input.expected_root_source_ordinal == *expected_root_source_ordinal
                    });
                let (input_index, input) = matches
                    .next()
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if matches.next().is_some() || consumed_statement_trees[input_index] {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let expected_row_width = ordered_column_ordinals.len();
                let expected_canonical_residue_moduli = ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        variant
                            .ordered_columns()
                            .get(*column_ordinal as usize)
                            .map(|column| column.canonical_residue_modulus())
                            .ok_or(CommonProofVerifierError::InvalidTreeLayout)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let construction_matches = match (&input.tree, construction_kind) {
                    (
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                        BoundTreeConstructionKind::CommittedMaterial,
                    ) => expected_row_width == 4,
                    (
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                        BoundTreeConstructionKind::SetupPolynomial,
                    ) => usize::try_from(*row_width).is_ok_and(|width| width == expected_row_width),
                    _ => false,
                };
                if !construction_matches
                    || input.ordered_canonical_residue_moduli != expected_canonical_residue_moduli
                {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                let value_path = variant
                    .verifier_source(*expected_root_source_ordinal)
                    .and_then(|source| source.application_statement_scalar_hash_path())
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                let expected_statement_root =
                    select_application_statement_hash(application_statement, value_path)?;
                let supplied_root = match &input.tree {
                    StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
                    | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. } => {
                        *expected_root
                    }
                };
                if supplied_root != expected_statement_root {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                }
                consumed_statement_trees[input_index] = true;
                inputs.push(RelationProofTreeInput::BoundPublic(input.tree.clone()));
            }
        }
    }
    if consumed_statement_trees.iter().any(|consumed| !consumed) {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    Ok(inputs)
}

enum SelectedApplicationStatementValue {
    Tuple(CanonicalTuple),
    Item(CanonicalItem),
}

fn select_application_statement_hash(
    application_statement: &CanonicalTuple,
    value_path: &[RelationSelectorPathStep],
) -> Result<[u8; 64], CommonProofVerifierError> {
    if value_path.is_empty() {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let mut selected = SelectedApplicationStatementValue::Tuple(application_statement.clone());
    for step in value_path {
        selected = match step.step_kind() {
            SelectorPathStepKind::TupleField => {
                let tuple = match selected {
                    SelectedApplicationStatementValue::Tuple(tuple) => tuple,
                    SelectedApplicationStatementValue::Item(item)
                        if item.item_type() == CanonicalItemType::NestedTuple =>
                    {
                        CanonicalTuple::decode(
                            item.canonical_bytes(),
                            &CanonicalDecodeLimits::default(),
                        )
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?
                    }
                    SelectedApplicationStatementValue::Item(_) => {
                        return Err(CommonProofVerifierError::InvalidBoundTree);
                    }
                };
                SelectedApplicationStatementValue::Item(
                    tuple
                        .items
                        .get(
                            usize::try_from(step.argument())
                                .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                        )
                        .cloned()
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )
            }
            SelectorPathStepKind::LiteralListIndex => {
                let SelectedApplicationStatementValue::Item(item) = selected else {
                    return Err(CommonProofVerifierError::InvalidBoundTree);
                };
                SelectedApplicationStatementValue::Item(select_homogeneous_list_item(
                    &item,
                    usize::try_from(step.argument())
                        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?,
                )?)
            }
        };
    }
    let SelectedApplicationStatementValue::Item(item) = selected else {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    };
    if item.item_type() != CanonicalItemType::Hash512 || item.canonical_bytes().len() != 64 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    item.canonical_bytes()
        .try_into()
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn select_homogeneous_list_item(
    list: &CanonicalItem,
    selected_index: usize,
) -> Result<CanonicalItem, CommonProofVerifierError> {
    if list.item_type() != CanonicalItemType::HomogeneousList {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let bytes = list.canonical_bytes();
    if bytes.len() < 6 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let element_type =
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    let element_count =
        usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
            .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    if selected_index >= element_count {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let payload = &bytes[6..];
    let selected_bytes = match element_type {
        CanonicalItemType::Hash512 => {
            let expected_byte_length = element_count
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            if payload.len() != expected_byte_length {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let start = selected_index
                .checked_mul(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            let end = start
                .checked_add(64)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        CanonicalItemType::NestedTuple => {
            let mut offset = 0_usize;
            let mut selected_range = None;
            for element_index in 0..element_count {
                let tuple_byte_length = encoded_tuple_byte_length(
                    payload
                        .get(offset..)
                        .ok_or(CommonProofVerifierError::InvalidBoundTree)?,
                )?;
                let next_offset = offset
                    .checked_add(tuple_byte_length)
                    .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
                if element_index == selected_index {
                    selected_range = Some((offset, next_offset));
                }
                offset = next_offset;
            }
            if offset != payload.len() {
                return Err(CommonProofVerifierError::InvalidBoundTree);
            }
            let (start, end) = selected_range.ok_or(CommonProofVerifierError::InvalidBoundTree)?;
            payload
                .get(start..end)
                .ok_or(CommonProofVerifierError::InvalidBoundTree)?
        }
        _ => return Err(CommonProofVerifierError::InvalidBoundTree),
    };
    CanonicalItem::from_canonical_bytes(
        element_type,
        selected_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CommonProofVerifierError::InvalidBoundTree)
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, CommonProofVerifierError> {
    if bytes.len() < 8 {
        return Err(CommonProofVerifierError::InvalidBoundTree);
    }
    let item_count = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
    let mut offset = 8_usize;
    for _ in 0..item_count {
        let header = bytes
            .get(offset..offset + 6)
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([header[0], header[1]]))
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
        let value_byte_length = usize::try_from(u32::from_le_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .map_err(|_| CommonProofVerifierError::InvalidBoundTree)?;
        offset = offset
            .checked_add(6)
            .and_then(|value| value.checked_add(value_byte_length))
            .filter(|value| *value <= bytes.len())
            .ok_or(CommonProofVerifierError::InvalidBoundTree)?;
    }
    Ok(offset)
}

fn validate_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofVerifierError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofVerifierError::InvalidTreeLayout);
    }
    for column_ordinal in ordered_column_ordinals {
        let column_index = usize::try_from(*column_ordinal)
            .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?;
        let column = variant
            .ordered_columns()
            .get(column_index)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            (RelationColumnOrigin::VerifierSequence { .. }, None) => {
                return Err(CommonProofVerifierError::InvalidTreeLayout);
            }
            (RelationColumnOrigin::Prover, None) => {}
        }
    }
    Ok(())
}

pub(crate) fn verify_out_of_domain_composition_with_verified_sequences<ColumnEvaluator>(
    variant: &RelationPlanVariant,
    input: OutOfDomainCompositionVerificationInput<'_>,
    evaluate_verified_column: &mut ColumnEvaluator,
) -> Result<(), CommonProofVerifierError>
where
    ColumnEvaluator: VerifiedRelationColumnEvaluator + ?Sized,
{
    if input.ordered_out_of_domain_evaluations().len() != variant.ordered_opening_claims().len() {
        return Err(CommonProofVerifierError::InvalidOpeningClaim);
    }
    let mut missing_verified_column_value = false;
    let result = variant.verify_out_of_domain_composition(input, |column_ordinal, point| {
        let value = evaluate_verified_column.evaluate_at_extension_point(column_ordinal, point);
        if value.is_none() {
            missing_verified_column_value = true;
        }
        value
    });
    if missing_verified_column_value {
        return Err(CommonProofVerifierError::MissingVerifiedColumnValue);
    }
    result.map_err(CommonProofVerifierError::from)
}
