use super::committed_material::{
    CommittedMaterialPlanBuilder, CommittedMaterialRelationPlanInput, IntegerTerm, MaterialRootUse,
    root_path,
};
use super::{CompiledRelationPlan, RelationPlanCheckContext, RelationPlanError};

const VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x2110;
const COEFFICIENT_MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 8;
const RECIPIENT_SHARE_MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 9;

pub(crate) fn compile_vss_share_linkage_relation_plan(
    input: &CommittedMaterialRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    let sharing_limb_count = input.sharing_data_modulus_indices.len();
    let threshold = usize::from(input.threshold);
    let participant_count = usize::from(input.participant_count);
    let roots_per_limb = threshold
        .checked_add(participant_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let root_count = sharing_limb_count
        .checked_mul(roots_per_limb)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut root_paths = Vec::with_capacity(root_count);
    for sharing_limb_ordinal in 0..sharing_limb_count {
        for coefficient_ordinal in 0..threshold {
            let statement_root_ordinal = sharing_limb_ordinal
                .checked_mul(threshold)
                .and_then(|offset| offset.checked_add(coefficient_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            root_paths.push(root_path(
                COEFFICIENT_MATERIAL_ROOTS_FIELD_ORDINAL,
                u64::try_from(statement_root_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        for recipient_ordinal in 0..participant_count {
            let statement_root_ordinal = sharing_limb_ordinal
                .checked_mul(participant_count)
                .and_then(|offset| offset.checked_add(recipient_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            root_paths.push(root_path(
                RECIPIENT_SHARE_MATERIAL_ROOTS_FIELD_ORDINAL,
                u64::try_from(statement_root_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
    }

    let mut builder = CommittedMaterialPlanBuilder::new(
        VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        input,
        check_context,
        root_paths,
    )?;
    let mut coefficient_messages = Vec::with_capacity(sharing_limb_count);
    let mut recipient_messages = Vec::with_capacity(sharing_limb_count);
    let mut logical_root_ordinal = 0_usize;
    for sharing_limb_ordinal in 0..sharing_limb_count {
        let mut limb_coefficients = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            limb_coefficients.push(builder.add_material_message(
                logical_root_ordinal,
                sharing_limb_ordinal,
                MaterialRootUse::Output,
            )?);
            logical_root_ordinal = logical_root_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        coefficient_messages.push(limb_coefficients);

        let mut limb_recipients = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            limb_recipients.push(builder.add_material_message(
                logical_root_ordinal,
                sharing_limb_ordinal,
                MaterialRootUse::Output,
            )?);
            logical_root_ordinal = logical_root_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        recipient_messages.push(limb_recipients);
    }

    let point_stride = input.point_stride()?;
    for sharing_limb_ordinal in 0..sharing_limb_count {
        let mut residuals_by_half = [Vec::new(), Vec::new()];
        for (physical_half_ordinal, residuals) in residuals_by_half.iter_mut().enumerate() {
            residuals.reserve(participant_count);
            for recipient_ordinal in 0..participant_count {
                let mut terms = Vec::<IntegerTerm>::new();
                for coefficient_ordinal in 0..threshold {
                    let exponent = u64::try_from(recipient_ordinal)
                        .ok()
                        .and_then(|recipient| {
                            u64::try_from(coefficient_ordinal)
                                .ok()
                                .and_then(|coefficient| recipient.checked_mul(coefficient))
                        })
                        .and_then(|product| product.checked_mul(point_stride))
                        .ok_or(RelationPlanError::CountOverflow)?;
                    builder.append_monomial_action_message_integer_terms(
                        &mut terms,
                        &coefficient_messages[sharing_limb_ordinal][coefficient_ordinal],
                        exponent,
                        physical_half_ordinal,
                        false,
                    )?;
                }
                builder.append_unrotated_message_integer_term(
                    &mut terms,
                    &recipient_messages[sharing_limb_ordinal][recipient_ordinal],
                    physical_half_ordinal,
                    true,
                )?;
                let quotient_column =
                    builder.add_signed_quotient_column(u64::from(input.threshold))?;
                builder.append_modulus_quotient_integer_term(
                    &mut terms,
                    sharing_limb_ordinal,
                    quotient_column,
                )?;
                residuals.push(builder.integer_residual(terms)?);
            }
        }
        for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
            for (physical_half_ordinal, residuals) in residuals_by_half.iter().enumerate() {
                builder.add_randomized_residual_batch(
                    sharing_limb_ordinal,
                    challenge_ordinal,
                    u16::try_from(physical_half_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    residuals,
                )?;
            }
        }
    }
    builder.finish()
}
