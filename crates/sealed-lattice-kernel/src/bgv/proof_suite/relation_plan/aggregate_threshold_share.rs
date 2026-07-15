use super::committed_material::{
    CommittedMaterialPlanBuilder, CommittedMaterialRelationPlanInput, IntegerTerm,
    MaterialRootUse, root_path,
};
use super::{CompiledRelationPlan, RelationPlanCheckContext, RelationPlanError};

const AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2111;
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
            u64::try_from(sharing_limb_ordinal)
                .map_err(|_| RelationPlanError::CountOverflow)?,
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
        let mut limb_sources = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            limb_sources.push(builder.add_material_message(
                logical_root_ordinal,
                sharing_limb_ordinal,
                MaterialRootUse::Input,
            )?);
            logical_root_ordinal = logical_root_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        source_messages.push(limb_sources);
        aggregate_messages.push(builder.add_material_message(
            logical_root_ordinal,
            sharing_limb_ordinal,
            MaterialRootUse::Output,
        )?);
        logical_root_ordinal = logical_root_ordinal
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }

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
            let quotient_column = builder.add_unsigned_quotient_column(u64::from(
                input.participant_count.saturating_sub(1),
            ))?;
            builder.append_modulus_quotient_integer_term(
                &mut terms,
                sharing_limb_ordinal,
                quotient_column,
            )?;
            let residual = builder.integer_residual(terms)?;
            builder.add_deterministic_residual(residual)?;
        }
    }
    builder.finish()
}
