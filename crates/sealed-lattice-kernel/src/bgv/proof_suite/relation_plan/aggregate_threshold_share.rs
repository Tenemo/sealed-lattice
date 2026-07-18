use super::committed_material::{
    CommittedMaterialPlanBuilder, CommittedMaterialRelationPlanInput, IntegerTerm, MaterialRootUse,
    root_path,
};
use super::{CompiledRelationPlan, RelationPlanCheckContext, RelationPlanError};

const AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
const ORDERED_SOURCE_SHARE_ROOTS_FIELD_ORDINAL: u64 = 8;
const AGGREGATE_THRESHOLD_SHARE_ROOTS_FIELD_ORDINAL: u64 = 9;

pub(crate) fn compile_aggregate_threshold_share_relation_plan(
    input: &CommittedMaterialRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    let sharing_limb_count = input.sharing_data_modulus_indices.len();
    let participant_count = usize::from(input.participant_count);
    let roots_per_limb = participant_count
        .checked_add(1)
        .ok_or(RelationPlanError::CountOverflow)?;
    let root_count = sharing_limb_count
        .checked_mul(roots_per_limb)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut root_paths = Vec::with_capacity(root_count);
    for sharing_limb_ordinal in 0..sharing_limb_count {
        for source_ordinal in 0..participant_count {
            let statement_root_ordinal = source_ordinal
                .checked_mul(sharing_limb_count)
                .and_then(|offset| offset.checked_add(sharing_limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            root_paths.push(root_path(
                ORDERED_SOURCE_SHARE_ROOTS_FIELD_ORDINAL,
                u64::try_from(statement_root_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        root_paths.push(root_path(
            AGGREGATE_THRESHOLD_SHARE_ROOTS_FIELD_ORDINAL,
            u64::try_from(sharing_limb_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
        ));
    }

    let mut builder = CommittedMaterialPlanBuilder::new(
        AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        input,
        check_context,
        root_paths,
    )?;
    let mut source_messages = Vec::with_capacity(sharing_limb_count);
    let mut aggregate_messages = Vec::with_capacity(sharing_limb_count);
    let mut logical_root_ordinal = 0_usize;
    for sharing_limb_ordinal in 0..sharing_limb_count {
        let roots_per_limb = participant_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        let roots = (0..roots_per_limb)
            .map(|root_offset| {
                logical_root_ordinal
                    .checked_add(root_offset)
                    .map(|root_ordinal| {
                        let root_use = if root_offset < participant_count {
                            MaterialRootUse::Input
                        } else {
                            MaterialRootUse::Output
                        };
                        (root_ordinal, root_use)
                    })
                    .ok_or(RelationPlanError::CountOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let messages = builder.add_material_messages(&roots, sharing_limb_ordinal)?;
        let (limb_sources, aggregate) = messages.split_at(participant_count);
        source_messages.push(limb_sources.to_vec());
        aggregate_messages.push(
            aggregate
                .first()
                .cloned()
                .ok_or(RelationPlanError::InvalidColumn)?,
        );
        logical_root_ordinal = logical_root_ordinal
            .checked_add(roots_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
    }

    let quotient_count = sharing_limb_count
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut quotient_columns = builder
        .add_packed_unsigned_quotient_columns(
            quotient_count,
            u64::from(input.participant_count.saturating_sub(1)),
        )?
        .into_iter();
    for sharing_limb_ordinal in 0..sharing_limb_count {
        for physical_half_ordinal in 0..2 {
            let mut terms = Vec::<IntegerTerm>::new();
            for source_message in &source_messages[sharing_limb_ordinal] {
                builder.append_unrotated_message_integer_term(
                    &mut terms,
                    source_message,
                    physical_half_ordinal,
                    false,
                )?;
            }
            builder.append_unrotated_message_integer_term(
                &mut terms,
                &aggregate_messages[sharing_limb_ordinal],
                physical_half_ordinal,
                true,
            )?;
            let quotient_column = quotient_columns
                .next()
                .ok_or(RelationPlanError::InvalidColumn)?;
            builder.append_modulus_quotient_integer_term(
                &mut terms,
                sharing_limb_ordinal,
                quotient_column,
            )?;
            let residual = builder.integer_residual(terms)?;
            builder.add_deterministic_residual(residual)?;
        }
    }
    if quotient_columns.next().is_some() {
        return Err(RelationPlanError::InvalidColumn);
    }
    builder.finish()
}
