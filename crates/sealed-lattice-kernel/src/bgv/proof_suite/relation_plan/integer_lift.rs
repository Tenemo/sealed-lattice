use crate::foundation::{CanonicalItem, CanonicalTuple};

use super::{
    checking::full_trace_zeroifier_expression,
    compiled_plan::RelationPlanCheckContext,
    expressions::{
        RelationExpressionInstruction, canonical_nested_list, checked_resident_payload_add,
        modular_power, resident_vec_storage_byte_length, strictly_sorted_unique,
    },
    model::{
        RelationChallengeRole, RelationPlanError, SuiteModulusReference, canonical_encoding_error,
    },
    schema::{
        COEFFICIENT_LOCAL_IDENTITY_BATCH_SCHEMA_IDENTIFIER,
        COEFFICIENT_LOCAL_RESIDUAL_SCHEMA_IDENTIFIER, INTEGER_LIFT_BATCH_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_COMPONENT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_CONSTANT_COEFFICIENT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_CONVOLUTION_PRODUCT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_FULL_RING_NEGACYCLIC_PRODUCT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_LINEAR_TERM_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_MODULUS_COEFFICIENT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_MODULUS_RADIX_DIGIT_COEFFICIENT_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_NEGACYCLIC_AUTOMORPHISM_PERMUTATION_SCHEMA_IDENTIFIER,
        INTEGER_LIFT_REVERSED_COLUMN_BINDING_SCHEMA_IDENTIFIER, SCHEMA_VERSION,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationIntegerLiftCoefficient {
    Constant(u64),
    Modulus {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
    },
    ModulusRadixDigit {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
        radix: u64,
        digit_ordinal: u16,
    },
}

impl RelationIntegerLiftCoefficient {
    pub(super) fn canonical_tuple(self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::Constant(value) => CanonicalTuple::new(
                INTEGER_LIFT_CONSTANT_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned64(value)],
            ),
            Self::Modulus {
                modulus_reference,
                multiplier,
            } => CanonicalTuple::new(
                INTEGER_LIFT_MODULUS_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(multiplier),
                ],
            ),
            Self::ModulusRadixDigit {
                modulus_reference,
                multiplier,
                radix,
                digit_ordinal,
            } => CanonicalTuple::new(
                INTEGER_LIFT_MODULUS_RADIX_DIGIT_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(multiplier),
                    CanonicalItem::unsigned64(radix),
                    CanonicalItem::unsigned16(digit_ordinal),
                ],
            ),
        })
    }
}

pub(crate) fn resolved_modulus_radix_digit(
    modulus_reference: SuiteModulusReference,
    multiplier: u16,
    radix: u64,
    digit_ordinal: u16,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    if multiplier == 0 || !(2..context.base_field_modulus).contains(&radix) {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut value = u128::from(context.resolved_modulus(modulus_reference)?)
        .checked_mul(u128::from(multiplier))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let radix = u128::from(radix);
    for _ in 0..digit_ordinal {
        value /= radix;
    }
    u64::try_from(value % radix).map_err(|_| RelationPlanError::IntegerBoundOverflow)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationIntegerLiftLinearTermDescriptor {
    pub(crate) negative: bool,
    pub(crate) column_ordinal: u32,
    pub(crate) column_offset: u64,
    pub(crate) coefficient: RelationIntegerLiftCoefficient,
}

impl RelationIntegerLiftLinearTermDescriptor {
    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_LINEAR_TERM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned32(self.column_ordinal),
                CanonicalItem::unsigned64(self.column_offset),
                CanonicalItem::nested_tuple(&self.coefficient.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
            ],
        ))
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RelationIntegerLiftConvolutionKind {
    Negacyclic = 1,
    OrdinaryLowHalf = 2,
    OrdinaryHighHalf = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftConvolutionProductDescriptor {
    pub(crate) negative: bool,
    pub(crate) convolution_kind: RelationIntegerLiftConvolutionKind,
    pub(crate) multiplicand_column_ordinal: u32,
    pub(crate) reversed_multiplier_column_ordinal: u32,
    pub(crate) multiplier_offset: u64,
    pub(crate) suffix_evaluation_column_ordinal: u32,
    pub(crate) reversed_transpose_column_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum RelationIntegerLiftFullRingHalf {
    Low = 1,
    High = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftFullRingNegacyclicProductDescriptor {
    pub(crate) negative: bool,
    pub(crate) selected_half: RelationIntegerLiftFullRingHalf,
    pub(crate) multiplicand_low_column_ordinal: u32,
    pub(crate) multiplicand_high_column_ordinal: u32,
    pub(crate) multiplier_low_column_ordinal: u32,
    pub(crate) multiplier_high_column_ordinal: u32,
    pub(crate) reversed_multiplier_low_column_ordinal: u32,
    pub(crate) reversed_multiplier_high_column_ordinal: u32,
    pub(crate) multiplier_low_offset: u64,
    pub(crate) multiplier_high_offset: u64,
    pub(crate) multiplicand_low_suffix_evaluation_column_ordinal: u32,
    pub(crate) multiplicand_high_suffix_evaluation_column_ordinal: u32,
    pub(crate) reversed_multiplier_low_transpose_column_ordinal: u32,
    pub(crate) reversed_multiplier_high_transpose_column_ordinal: u32,
}

impl RelationIntegerLiftFullRingNegacyclicProductDescriptor {
    pub(super) fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_FULL_RING_NEGACYCLIC_PRODUCT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned16(self.selected_half as u16),
                CanonicalItem::unsigned32(self.multiplicand_low_column_ordinal),
                CanonicalItem::unsigned32(self.multiplicand_high_column_ordinal),
                CanonicalItem::unsigned32(self.multiplier_low_column_ordinal),
                CanonicalItem::unsigned32(self.multiplier_high_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_low_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_high_column_ordinal),
                CanonicalItem::unsigned64(self.multiplier_low_offset),
                CanonicalItem::unsigned64(self.multiplier_high_offset),
                CanonicalItem::unsigned32(self.multiplicand_low_suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.multiplicand_high_suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_low_transpose_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_high_transpose_column_ordinal),
            ],
        )
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftReversedColumnBindingDescriptor {
    pub(crate) source_column_ordinal: u32,
    pub(crate) reversed_column_ordinal: u32,
    pub(crate) source_prefix_evaluation_column_ordinal: u32,
    pub(crate) reversed_suffix_evaluation_column_ordinal: u32,
}

impl RelationIntegerLiftReversedColumnBindingDescriptor {
    pub(super) fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_REVERSED_COLUMN_BINDING_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.source_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_column_ordinal),
                CanonicalItem::unsigned32(self.source_prefix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_suffix_evaluation_column_ordinal),
            ],
        )
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
    pub(crate) galois_element: u64,
    pub(crate) mapping_verifier_source_ordinal: u32,
    pub(crate) source_low_column_ordinal: u32,
    pub(crate) source_high_column_ordinal: u32,
    pub(crate) target_low_column_ordinal: u32,
    pub(crate) target_high_column_ordinal: u32,
    pub(crate) mapped_low_position_column_ordinal: u32,
    pub(crate) low_negation_bit_column_ordinal: u32,
    pub(crate) mapped_high_position_column_ordinal: u32,
    pub(crate) high_negation_bit_column_ordinal: u32,
    pub(crate) target_low_position_column_ordinal: u32,
    pub(crate) target_high_position_column_ordinal: u32,
    pub(crate) source_product_before_column_ordinal: u32,
    pub(crate) source_low_product_column_ordinal: u32,
    pub(crate) target_product_before_column_ordinal: u32,
    pub(crate) target_low_product_column_ordinal: u32,
}

impl RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
    pub(super) fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_NEGACYCLIC_AUTOMORPHISM_PERMUTATION_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned64(self.galois_element),
                CanonicalItem::unsigned32(self.mapping_verifier_source_ordinal),
                CanonicalItem::unsigned32(self.source_low_column_ordinal),
                CanonicalItem::unsigned32(self.source_high_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_column_ordinal),
                CanonicalItem::unsigned32(self.target_high_column_ordinal),
                CanonicalItem::unsigned32(self.mapped_low_position_column_ordinal),
                CanonicalItem::unsigned32(self.low_negation_bit_column_ordinal),
                CanonicalItem::unsigned32(self.mapped_high_position_column_ordinal),
                CanonicalItem::unsigned32(self.high_negation_bit_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_position_column_ordinal),
                CanonicalItem::unsigned32(self.target_high_position_column_ordinal),
                CanonicalItem::unsigned32(self.source_product_before_column_ordinal),
                CanonicalItem::unsigned32(self.source_low_product_column_ordinal),
                CanonicalItem::unsigned32(self.target_product_before_column_ordinal),
                CanonicalItem::unsigned32(self.target_low_product_column_ordinal),
            ],
        )
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

impl RelationIntegerLiftConvolutionProductDescriptor {
    pub(super) fn canonical_tuple(&self) -> CanonicalTuple {
        CanonicalTuple::new(
            INTEGER_LIFT_CONVOLUTION_PRODUCT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::boolean(self.negative),
                CanonicalItem::unsigned16(self.convolution_kind as u16),
                CanonicalItem::unsigned32(self.multiplicand_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_multiplier_column_ordinal),
                CanonicalItem::unsigned64(self.multiplier_offset),
                CanonicalItem::unsigned32(self.suffix_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.reversed_transpose_column_ordinal),
            ],
        )
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftComponentDescriptor {
    pub(crate) ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
    pub(crate) ordered_convolution_products: Vec<RelationIntegerLiftConvolutionProductDescriptor>,
    pub(crate) ordered_full_ring_negacyclic_products:
        Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>,
    pub(crate) linear_evaluation_column_ordinal: u32,
    pub(crate) product_accumulator_column_ordinal: u32,
}

impl RelationIntegerLiftComponentDescriptor {
    fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        [
            resident_vec_storage_byte_length(&self.ordered_linear_terms)?,
            resident_vec_storage_byte_length(&self.ordered_convolution_products)?,
            resident_vec_storage_byte_length(&self.ordered_full_ring_negacyclic_products)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_resident_payload_add)
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_COMPONENT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                canonical_nested_list(
                    self.ordered_linear_terms
                        .iter()
                        .map(RelationIntegerLiftLinearTermDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.ordered_convolution_products
                        .iter()
                        .map(RelationIntegerLiftConvolutionProductDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_full_ring_negacyclic_products.iter().map(
                        RelationIntegerLiftFullRingNegacyclicProductDescriptor::canonical_tuple,
                    ),
                )?,
                CanonicalItem::unsigned32(self.linear_evaluation_column_ordinal),
                CanonicalItem::unsigned32(self.product_accumulator_column_ordinal),
            ],
        ))
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftBatchDescriptor {
    pub(crate) modulus_reference: SuiteModulusReference,
    pub(crate) challenge_ordinal: u16,
    pub(crate) ordered_reversed_column_bindings:
        Vec<RelationIntegerLiftReversedColumnBindingDescriptor>,
    pub(crate) ordered_negacyclic_automorphism_permutations:
        Vec<RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor>,
    pub(crate) ordered_components: Vec<RelationIntegerLiftComponentDescriptor>,
}

impl RelationIntegerLiftBatchDescriptor {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        let mut total = [
            resident_vec_storage_byte_length(&self.ordered_reversed_column_bindings)?,
            resident_vec_storage_byte_length(
                &self.ordered_negacyclic_automorphism_permutations,
            )?,
            resident_vec_storage_byte_length(&self.ordered_components)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_resident_payload_add)?;
        for component in &self.ordered_components {
            total = checked_resident_payload_add(
                total,
                component.resident_owned_payload_byte_length()?,
            )?;
        }
        Ok(total)
    }

    pub(crate) const fn modulus_reference(&self) -> SuiteModulusReference {
        self.modulus_reference
    }

    pub(crate) const fn challenge_ordinal(&self) -> u16 {
        self.challenge_ordinal
    }

    pub(crate) fn negacyclic_automorphism_permutations(
        &self,
    ) -> &[RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor] {
        &self.ordered_negacyclic_automorphism_permutations
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            INTEGER_LIFT_BATCH_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.modulus_reference.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.challenge_ordinal),
                canonical_nested_list(
                    self.ordered_reversed_column_bindings
                        .iter()
                        .map(RelationIntegerLiftReversedColumnBindingDescriptor::canonical_tuple),
                )?,
                canonical_nested_list(
                    self.ordered_negacyclic_automorphism_permutations
                        .iter()
                        .map(
                            RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor::canonical_tuple,
                        ),
                )?,
                canonical_nested_list(
                    self.ordered_components
                        .iter()
                        .map(RelationIntegerLiftComponentDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationCoefficientLocalResidualDescriptor {
    pub(crate) unit_ordinal: u32,
    pub(crate) residual_postfix_expression: Vec<RelationExpressionInstruction>,
}

impl RelationCoefficientLocalResidualDescriptor {
    fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        self.residual_postfix_expression.iter().try_fold(
            resident_vec_storage_byte_length(&self.residual_postfix_expression)?,
            |total, expression| {
                checked_resident_payload_add(
                    total,
                    expression.resident_owned_payload_byte_length()?,
                )
            },
        )
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            COEFFICIENT_LOCAL_RESIDUAL_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.unit_ordinal),
                canonical_nested_list(
                    self.residual_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationCoefficientLocalIdentityBatchDescriptor {
    pub(crate) modulus_reference: SuiteModulusReference,
    pub(crate) challenge_ordinal: u16,
    pub(crate) batch_ordinal: u16,
    pub(crate) constraint_ordinal: u32,
    pub(crate) ordered_residuals: Vec<RelationCoefficientLocalResidualDescriptor>,
}

impl RelationCoefficientLocalIdentityBatchDescriptor {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        self.ordered_residuals.iter().try_fold(
            resident_vec_storage_byte_length(&self.ordered_residuals)?,
            |total, residual| {
                checked_resident_payload_add(
                    total,
                    residual.resident_owned_payload_byte_length()?,
                )
            },
        )
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            COEFFICIENT_LOCAL_IDENTITY_BATCH_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::nested_tuple(&self.modulus_reference.canonical_tuple())
                    .map_err(canonical_encoding_error)?,
                CanonicalItem::unsigned16(self.challenge_ordinal),
                CanonicalItem::unsigned16(self.batch_ordinal),
                CanonicalItem::unsigned32(self.constraint_ordinal),
                canonical_nested_list(
                    self.ordered_residuals
                        .iter()
                        .map(RelationCoefficientLocalResidualDescriptor::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
            ],
        ))
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, RelationPlanError> {
        self.canonical_tuple()?
            .encode()
            .map_err(canonical_encoding_error)
    }

    pub(super) fn numerator_postfix_expression(
        &self,
        modulus_ordinal: u16,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        let mut expression = Vec::new();
        for (residual_index, residual) in self.ordered_residuals.iter().enumerate() {
            if residual.unit_ordinal
                != u32::try_from(residual_index).map_err(|_| RelationPlanError::CountOverflow)?
                || residual.residual_postfix_expression.is_empty()
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            expression.push(RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: RelationChallengeRole::NonNativeAlpha,
                role_coordinates: vec![
                    u64::from(modulus_ordinal),
                    u64::from(self.challenge_ordinal),
                    u64::from(residual.unit_ordinal),
                ],
            });
            expression.extend_from_slice(&residual.residual_postfix_expression);
            expression.push(RelationExpressionInstruction::Multiplication);
            if residual_index > 0 {
                expression.push(RelationExpressionInstruction::Addition);
            }
        }
        if expression.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(expression)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationIntegerLiftConstraintProgram {
    pub(crate) numerator_postfix_expression: Vec<RelationExpressionInstruction>,
    pub(crate) zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
}

impl RelationIntegerLiftBatchDescriptor {
    pub(crate) fn constraint_programs(
        &self,
        modulus_ordinal: u16,
        trace_domain_size: u64,
        evaluation_domain_size: u64,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
        let theta_expression =
            integer_lift_theta_expression(modulus_ordinal, self.challenge_ordinal);
        let last_row = trace_domain_size
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidDomain)?;
        let point_last = integer_lift_point_zeroifier(
            last_row,
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;
        let point_zero =
            integer_lift_point_zeroifier(0, trace_domain_size, evaluation_domain_size, context)?;
        let except_zero = integer_lift_trace_except_rows_zeroifier(
            &[0],
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;
        let except_last = integer_lift_trace_except_rows_zeroifier(
            &[last_row],
            trace_domain_size,
            evaluation_domain_size,
            context,
        )?;

        let mut programs = Vec::new();
        for permutation in &self.ordered_negacyclic_automorphism_permutations {
            programs.extend(
                integer_lift_negacyclic_automorphism_permutation_constraint_programs(
                    permutation,
                    &theta_expression,
                    point_zero.clone(),
                    point_last.clone(),
                    except_last.clone(),
                    trace_domain_size,
                )?,
            );
        }
        for binding in &self.ordered_reversed_column_bindings {
            programs.extend(integer_lift_reversed_column_binding_constraint_programs(
                binding,
                &theta_expression,
                point_zero.clone(),
                point_last.clone(),
                except_zero.clone(),
                except_last.clone(),
            ));
        }
        for component in &self.ordered_components {
            for product in &component.ordered_convolution_products {
                programs.extend(integer_lift_product_constraint_programs(
                    product,
                    &theta_expression,
                    trace_domain_size,
                    point_last.clone(),
                    except_zero.clone(),
                    except_last.clone(),
                )?);
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                programs.extend(integer_lift_full_ring_product_constraint_programs(
                    product,
                    &theta_expression,
                    trace_domain_size,
                    point_last.clone(),
                    except_last.clone(),
                )?);
            }
            programs.extend(integer_lift_component_constraint_programs(
                component,
                self.modulus_reference,
                &theta_expression,
                point_zero.clone(),
                point_last.clone(),
                except_last.clone(),
                context,
            )?);
        }
        Ok(programs)
    }
}

pub(super) fn negacyclic_automorphism_encoded_source_expression(
    position_column_ordinal: u32,
    negation_bit_column_ordinal: u32,
    value_column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    let tagged_position = multiply_integer_lift_expressions(
        integer_lift_column_expression(position_column_ordinal, false, 0),
        vec![RelationExpressionInstruction::BaseFieldConstant(3)],
    );
    let signed_value = subtract_integer_lift_expressions(
        integer_lift_column_expression(value_column_ordinal, false, 0),
        multiply_integer_lift_expressions(
            multiply_integer_lift_expressions(
                integer_lift_column_expression(negation_bit_column_ordinal, false, 0),
                vec![RelationExpressionInstruction::BaseFieldConstant(2)],
            ),
            integer_lift_column_expression(value_column_ordinal, false, 0),
        ),
    );
    add_integer_lift_expressions(
        add_integer_lift_expressions(
            tagged_position,
            vec![RelationExpressionInstruction::BaseFieldConstant(1)],
        ),
        signed_value,
    )
}

pub(super) fn negacyclic_automorphism_encoded_target_expression(
    position_column_ordinal: u32,
    value_column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    add_integer_lift_expressions(
        add_integer_lift_expressions(
            multiply_integer_lift_expressions(
                integer_lift_column_expression(position_column_ordinal, false, 0),
                vec![RelationExpressionInstruction::BaseFieldConstant(3)],
            ),
            vec![RelationExpressionInstruction::BaseFieldConstant(1)],
        ),
        integer_lift_column_expression(value_column_ordinal, false, 0),
    )
}

pub(super) fn negacyclic_automorphism_product_factor_expression(
    theta_expression: &[RelationExpressionInstruction],
    encoded_value_expression: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    subtract_integer_lift_expressions(theta_expression.to_vec(), encoded_value_expression)
}

pub(super) fn integer_lift_negacyclic_automorphism_permutation_constraint_programs(
    descriptor: &RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    point_zero: Vec<RelationExpressionInstruction>,
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
    trace_domain_size: u64,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    if trace_domain_size == 0 {
        return Err(RelationPlanError::InvalidDomain);
    }
    let source_low_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_source_expression(
            descriptor.mapped_low_position_column_ordinal,
            descriptor.low_negation_bit_column_ordinal,
            descriptor.source_low_column_ordinal,
        ),
    );
    let source_high_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_source_expression(
            descriptor.mapped_high_position_column_ordinal,
            descriptor.high_negation_bit_column_ordinal,
            descriptor.source_high_column_ordinal,
        ),
    );
    let target_low_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_target_expression(
            descriptor.target_low_position_column_ordinal,
            descriptor.target_low_column_ordinal,
        ),
    );
    let target_high_factor = negacyclic_automorphism_product_factor_expression(
        theta_expression,
        negacyclic_automorphism_encoded_target_expression(
            descriptor.target_high_position_column_ordinal,
            descriptor.target_high_column_ordinal,
        ),
    );
    let source_before = descriptor.source_product_before_column_ordinal;
    let source_low_product = descriptor.source_low_product_column_ordinal;
    let target_before = descriptor.target_product_before_column_ordinal;
    let target_low_product = descriptor.target_low_product_column_ordinal;
    let one = vec![RelationExpressionInstruction::BaseFieldConstant(1)];
    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_before, false, 0),
                one.clone(),
            ),
            zeroifier_postfix_expression: point_zero.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_before, false, 0),
                one,
            ),
            zeroifier_postfix_expression: point_zero,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_low_product, false, 0),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_before, false, 0),
                    source_low_factor,
                ),
            ),
            zeroifier_postfix_expression: full_trace_zeroifier_expression(trace_domain_size),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_low_product, false, 0),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_before, false, 0),
                    target_low_factor,
                ),
            ),
            zeroifier_postfix_expression: full_trace_zeroifier_expression(trace_domain_size),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(source_before, false, 1),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_low_product, false, 0),
                    source_high_factor.clone(),
                ),
            ),
            zeroifier_postfix_expression: except_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(target_before, false, 1),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_low_product, false, 0),
                    target_high_factor.clone(),
                ),
            ),
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(source_low_product, false, 0),
                    source_high_factor,
                ),
                multiply_integer_lift_expressions(
                    integer_lift_column_expression(target_low_product, false, 0),
                    target_high_factor,
                ),
            ),
            zeroifier_postfix_expression: point_last,
        },
    ])
}

pub(super) fn integer_lift_reversed_column_binding_constraint_programs(
    binding: &RelationIntegerLiftReversedColumnBindingDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    point_zero: Vec<RelationExpressionInstruction>,
    point_last: Vec<RelationExpressionInstruction>,
    except_zero: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Vec<RelationIntegerLiftConstraintProgram> {
    let source = binding.source_column_ordinal;
    let reversed = binding.reversed_column_ordinal;
    let prefix = binding.source_prefix_evaluation_column_ordinal;
    let suffix = binding.reversed_suffix_evaluation_column_ordinal;
    vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(prefix, false, 0),
                integer_lift_column_expression(source, false, 0),
            ),
            zeroifier_postfix_expression: point_zero.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(prefix, false, 0),
                    integer_lift_column_expression(source, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(prefix, true, 1),
                ),
            ),
            zeroifier_postfix_expression: except_zero,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(suffix, false, 0),
                integer_lift_column_expression(reversed, false, 0),
            ),
            zeroifier_postfix_expression: point_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(suffix, false, 0),
                    integer_lift_column_expression(reversed, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(suffix, false, 1),
                ),
            ),
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(prefix, true, 1),
                integer_lift_column_expression(suffix, false, 0),
            ),
            zeroifier_postfix_expression: point_zero,
        },
    ]
}

pub(super) fn integer_lift_full_ring_product_constraint_programs(
    product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    half_ring_degree: u64,
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let mut programs = Vec::with_capacity(8);
    for (multiplicand, suffix) in [
        (
            product.multiplicand_low_column_ordinal,
            product.multiplicand_low_suffix_evaluation_column_ordinal,
        ),
        (
            product.multiplicand_high_column_ordinal,
            product.multiplicand_high_suffix_evaluation_column_ordinal,
        ),
    ] {
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                integer_lift_column_expression(suffix, false, 0),
                integer_lift_column_expression(multiplicand, false, 0),
            ),
            zeroifier_postfix_expression: point_last.clone(),
        });
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: subtract_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    integer_lift_column_expression(suffix, false, 0),
                    integer_lift_column_expression(multiplicand, false, 0),
                ),
                multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(suffix, false, 1),
                ),
            ),
            zeroifier_postfix_expression: except_last.clone(),
        });
    }

    let mut theta_to_half_ring_degree = theta_expression.to_vec();
    theta_to_half_ring_degree.push(RelationExpressionInstruction::NonnegativePower(
        half_ring_degree,
    ));
    let low_multiplicand_next =
        integer_lift_column_expression(product.multiplicand_low_column_ordinal, false, 1);
    let high_multiplicand_next =
        integer_lift_column_expression(product.multiplicand_high_column_ordinal, false, 1);
    let theta_to_half_times_low = multiply_integer_lift_expressions(
        theta_to_half_ring_degree.clone(),
        low_multiplicand_next.clone(),
    );
    let theta_to_half_times_high = multiply_integer_lift_expressions(
        theta_to_half_ring_degree,
        high_multiplicand_next.clone(),
    );

    for (is_low_multiplier, transpose) in [
        (
            true,
            product.reversed_multiplier_low_transpose_column_ordinal,
        ),
        (
            false,
            product.reversed_multiplier_high_transpose_column_ordinal,
        ),
    ] {
        let boundary = match (product.selected_half, is_low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => subtract_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_low_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
            (RelationIntegerLiftFullRingHalf::Low, false) => add_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
            (RelationIntegerLiftFullRingHalf::High, true) => subtract_integer_lift_expressions(
                integer_lift_column_expression(transpose, false, 0),
                integer_lift_column_expression(
                    product.multiplicand_high_suffix_evaluation_column_ordinal,
                    false,
                    1,
                ),
            ),
        };
        let transpose_minus_theta_next = subtract_integer_lift_expressions(
            integer_lift_column_expression(transpose, false, 0),
            multiply_integer_lift_expressions(
                theta_expression.to_vec(),
                integer_lift_column_expression(transpose, false, 1),
            ),
        );
        let recurrence = match (product.selected_half, is_low_multiplier) {
            (RelationIntegerLiftFullRingHalf::Low, true)
            | (RelationIntegerLiftFullRingHalf::High, false) => add_integer_lift_expressions(
                add_integer_lift_expressions(
                    transpose_minus_theta_next,
                    theta_to_half_times_low.clone(),
                ),
                high_multiplicand_next.clone(),
            ),
            (RelationIntegerLiftFullRingHalf::Low, false) => subtract_integer_lift_expressions(
                add_integer_lift_expressions(
                    transpose_minus_theta_next,
                    low_multiplicand_next.clone(),
                ),
                theta_to_half_times_high.clone(),
            ),
            (RelationIntegerLiftFullRingHalf::High, true) => add_integer_lift_expressions(
                subtract_integer_lift_expressions(
                    transpose_minus_theta_next,
                    low_multiplicand_next.clone(),
                ),
                theta_to_half_times_high.clone(),
            ),
        };
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: boundary,
            zeroifier_postfix_expression: point_last.clone(),
        });
        programs.push(RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: recurrence,
            zeroifier_postfix_expression: except_last.clone(),
        });
    }
    Ok(programs)
}

pub(super) fn integer_lift_product_constraint_programs(
    product: &RelationIntegerLiftConvolutionProductDescriptor,
    theta_expression: &[RelationExpressionInstruction],
    trace_domain_size: u64,
    point_last: Vec<RelationExpressionInstruction>,
    except_zero: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let suffix = product.suffix_evaluation_column_ordinal;
    let multiplicand = product.multiplicand_column_ordinal;
    let transpose = product.reversed_transpose_column_ordinal;
    let suffix_last = subtract_integer_lift_expressions(
        integer_lift_column_expression(suffix, false, 0),
        integer_lift_column_expression(multiplicand, false, 0),
    );

    let theta_times_next_suffix = multiply_integer_lift_expressions(
        theta_expression.to_vec(),
        integer_lift_column_expression(suffix, false, 1),
    );
    let suffix_recurrence = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(suffix, false, 0),
            integer_lift_column_expression(multiplicand, false, 0),
        ),
        theta_times_next_suffix,
    );

    let mut theta_to_ring_degree_plus_one = theta_expression.to_vec();
    theta_to_ring_degree_plus_one.push(RelationExpressionInstruction::NonnegativePower(
        trace_domain_size,
    ));
    theta_to_ring_degree_plus_one.extend([
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Addition,
    ]);
    let (transpose_boundary, transpose_recurrence, transpose_zeroifier) =
        match product.convolution_kind {
            RelationIntegerLiftConvolutionKind::Negacyclic => {
                let boundary = subtract_integer_lift_expressions(
                    integer_lift_column_expression(transpose, false, 0),
                    integer_lift_column_expression(suffix, false, 1),
                );
                let theta_times_transpose = multiply_integer_lift_expressions(
                    theta_expression.to_vec(),
                    integer_lift_column_expression(transpose, false, 0),
                );
                let wrap_correction = multiply_integer_lift_expressions(
                    theta_to_ring_degree_plus_one,
                    integer_lift_column_expression(multiplicand, false, 0),
                );
                let recurrence = add_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, true, 1),
                        theta_times_transpose,
                    ),
                    wrap_correction,
                );
                (boundary, recurrence, except_zero)
            }
            RelationIntegerLiftConvolutionKind::OrdinaryLowHalf => {
                let boundary = subtract_integer_lift_expressions(
                    integer_lift_column_expression(transpose, false, 0),
                    integer_lift_column_expression(suffix, false, 1),
                );
                let mut theta_to_ring_degree = theta_expression.to_vec();
                theta_to_ring_degree.push(RelationExpressionInstruction::NonnegativePower(
                    trace_domain_size,
                ));
                let recurrence = add_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, false, 0),
                        multiply_integer_lift_expressions(
                            theta_expression.to_vec(),
                            integer_lift_column_expression(transpose, false, 1),
                        ),
                    ),
                    multiply_integer_lift_expressions(
                        theta_to_ring_degree,
                        integer_lift_column_expression(multiplicand, false, 1),
                    ),
                );
                (boundary, recurrence, except_last.clone())
            }
            RelationIntegerLiftConvolutionKind::OrdinaryHighHalf => {
                let boundary = integer_lift_column_expression(transpose, false, 0);
                let recurrence = subtract_integer_lift_expressions(
                    subtract_integer_lift_expressions(
                        integer_lift_column_expression(transpose, false, 0),
                        integer_lift_column_expression(multiplicand, false, 1),
                    ),
                    multiply_integer_lift_expressions(
                        theta_expression.to_vec(),
                        integer_lift_column_expression(transpose, false, 1),
                    ),
                );
                (boundary, recurrence, except_last.clone())
            }
        };

    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: suffix_last,
            zeroifier_postfix_expression: point_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: suffix_recurrence,
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: transpose_boundary,
            zeroifier_postfix_expression: point_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: transpose_recurrence,
            zeroifier_postfix_expression: transpose_zeroifier,
        },
    ])
}

pub(super) fn integer_lift_component_constraint_programs(
    component: &RelationIntegerLiftComponentDescriptor,
    _modulus_reference: SuiteModulusReference,
    theta_expression: &[RelationExpressionInstruction],
    point_zero: Vec<RelationExpressionInstruction>,
    point_last: Vec<RelationExpressionInstruction>,
    except_last: Vec<RelationExpressionInstruction>,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationIntegerLiftConstraintProgram>, RelationPlanError> {
    let coefficient_expression = integer_lift_component_coefficient_expression(component, context)?;
    let linear_evaluation = component.linear_evaluation_column_ordinal;
    let linear_last = subtract_integer_lift_expressions(
        integer_lift_column_expression(linear_evaluation, false, 0),
        coefficient_expression.clone(),
    );
    let linear_recurrence = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(linear_evaluation, false, 0),
            coefficient_expression,
        ),
        multiply_integer_lift_expressions(
            theta_expression.to_vec(),
            integer_lift_column_expression(linear_evaluation, false, 1),
        ),
    );

    let product_expression = integer_lift_component_product_expression(component)?;
    let accumulator = component.product_accumulator_column_ordinal;
    let accumulator_initial = integer_lift_column_expression(accumulator, false, 0);
    let accumulator_step = subtract_integer_lift_expressions(
        subtract_integer_lift_expressions(
            integer_lift_column_expression(accumulator, false, 1),
            integer_lift_column_expression(accumulator, false, 0),
        ),
        product_expression.clone(),
    );
    let accumulator_terminal = subtract_integer_lift_expressions(
        accumulator_step.clone(),
        integer_lift_column_expression(linear_evaluation, false, 1),
    );

    Ok(vec![
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: linear_last,
            zeroifier_postfix_expression: point_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: linear_recurrence,
            zeroifier_postfix_expression: except_last.clone(),
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: accumulator_initial,
            zeroifier_postfix_expression: point_zero,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: accumulator_step,
            zeroifier_postfix_expression: except_last,
        },
        RelationIntegerLiftConstraintProgram {
            numerator_postfix_expression: accumulator_terminal,
            zeroifier_postfix_expression: point_last,
        },
    ])
}

pub(super) fn integer_lift_component_coefficient_expression(
    component: &RelationIntegerLiftComponentDescriptor,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let terms = component
        .ordered_linear_terms
        .iter()
        .map(|term| integer_lift_linear_term_expression(term, context))
        .collect::<Result<Vec<_>, _>>()?;
    sum_integer_lift_expressions(terms)
}

pub(super) fn integer_lift_component_product_expression(
    component: &RelationIntegerLiftComponentDescriptor,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut terms = component
        .ordered_convolution_products
        .iter()
        .map(|product| {
            let shifted_multiplier = subtract_integer_lift_expressions(
                integer_lift_column_expression(
                    product.reversed_multiplier_column_ordinal,
                    false,
                    0,
                ),
                vec![RelationExpressionInstruction::BaseFieldConstant(
                    product.multiplier_offset,
                )],
            );
            let expression = multiply_integer_lift_expressions(
                integer_lift_column_expression(product.reversed_transpose_column_ordinal, false, 0),
                shifted_multiplier,
            );
            if product.negative {
                negate_integer_lift_expression(expression)
            } else {
                expression
            }
        })
        .collect::<Vec<_>>();
    terms.extend(
        component
            .ordered_full_ring_negacyclic_products
            .iter()
            .map(|product| {
                let low_multiplier = subtract_integer_lift_expressions(
                    integer_lift_column_expression(
                        product.reversed_multiplier_low_column_ordinal,
                        false,
                        0,
                    ),
                    vec![RelationExpressionInstruction::BaseFieldConstant(
                        product.multiplier_low_offset,
                    )],
                );
                let high_multiplier = subtract_integer_lift_expressions(
                    integer_lift_column_expression(
                        product.reversed_multiplier_high_column_ordinal,
                        false,
                        0,
                    ),
                    vec![RelationExpressionInstruction::BaseFieldConstant(
                        product.multiplier_high_offset,
                    )],
                );
                let expression = add_integer_lift_expressions(
                    multiply_integer_lift_expressions(
                        integer_lift_column_expression(
                            product.reversed_multiplier_low_transpose_column_ordinal,
                            false,
                            0,
                        ),
                        low_multiplier,
                    ),
                    multiply_integer_lift_expressions(
                        integer_lift_column_expression(
                            product.reversed_multiplier_high_transpose_column_ordinal,
                            false,
                            0,
                        ),
                        high_multiplier,
                    ),
                );
                if product.negative {
                    negate_integer_lift_expression(expression)
                } else {
                    expression
                }
            }),
    );
    if terms.is_empty() {
        Ok(vec![RelationExpressionInstruction::BaseFieldConstant(0)])
    } else {
        sum_integer_lift_expressions(terms)
    }
}

pub(super) fn integer_lift_linear_term_expression(
    term: &RelationIntegerLiftLinearTermDescriptor,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let shifted_column = subtract_integer_lift_expressions(
        integer_lift_column_expression(term.column_ordinal, false, 0),
        vec![RelationExpressionInstruction::BaseFieldConstant(
            term.column_offset,
        )],
    );
    let coefficient = match term.coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => {
            RelationExpressionInstruction::BaseFieldConstant(value)
        }
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => RelationExpressionInstruction::NonNativeModulusConstant {
            modulus_reference,
            multiplier,
        },
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => RelationExpressionInstruction::BaseFieldConstant(resolved_modulus_radix_digit(
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
            context,
        )?),
    };
    let expression = multiply_integer_lift_expressions(vec![coefficient], shifted_column);
    Ok(if term.negative {
        negate_integer_lift_expression(expression)
    } else {
        expression
    })
}

pub(super) fn integer_lift_theta_expression(
    modulus_ordinal: u16,
    challenge_ordinal: u16,
) -> Vec<RelationExpressionInstruction> {
    vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![u64::from(modulus_ordinal), u64::from(challenge_ordinal)],
    }]
}

pub(super) fn integer_lift_column_expression(
    column_ordinal: u32,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
) -> Vec<RelationExpressionInstruction> {
    vec![RelationExpressionInstruction::ColumnValue {
        column_ordinal,
        rotation_is_negative,
        rotation_magnitude,
    }]
}

pub(super) fn add_integer_lift_expressions(
    mut left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    left.extend(right);
    left.push(RelationExpressionInstruction::Addition);
    left
}

pub(super) fn subtract_integer_lift_expressions(
    left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    add_integer_lift_expressions(left, negate_integer_lift_expression(right))
}

pub(super) fn multiply_integer_lift_expressions(
    mut left: Vec<RelationExpressionInstruction>,
    right: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    left.extend(right);
    left.push(RelationExpressionInstruction::Multiplication);
    left
}

pub(super) fn negate_integer_lift_expression(
    mut expression: Vec<RelationExpressionInstruction>,
) -> Vec<RelationExpressionInstruction> {
    expression.push(RelationExpressionInstruction::Negation);
    expression
}

pub(super) fn sum_integer_lift_expressions(
    expressions: Vec<Vec<RelationExpressionInstruction>>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expressions = expressions.into_iter();
    let mut sum = expressions
        .next()
        .ok_or(RelationPlanError::InvalidConstraint)?;
    for expression in expressions {
        sum = add_integer_lift_expressions(sum, expression);
    }
    Ok(sum)
}

pub(super) fn integer_lift_point_zeroifier(
    row_ordinal: u64,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let root = integer_lift_trace_root(
        row_ordinal,
        trace_domain_size,
        evaluation_domain_size,
        context,
    )?;
    Ok(vec![
        RelationExpressionInstruction::EvaluationVariable,
        RelationExpressionInstruction::BaseFieldConstant(root),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ])
}

pub(super) fn integer_lift_trace_except_rows_zeroifier(
    excluded_rows: &[u64],
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    if excluded_rows.is_empty() {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut ordered_excluded_roots = excluded_rows
        .iter()
        .map(|row_ordinal| {
            integer_lift_trace_root(
                *row_ordinal,
                trace_domain_size,
                evaluation_domain_size,
                context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ordered_excluded_roots.sort_unstable();
    if !strictly_sorted_unique(&ordered_excluded_roots) {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    Ok(vec![
        RelationExpressionInstruction::TraceDomainExceptRoots {
            trace_domain_size,
            ordered_excluded_roots,
        },
    ])
}

pub(super) fn integer_lift_trace_root(
    row_ordinal: u64,
    trace_domain_size: u64,
    evaluation_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    if row_ordinal >= trace_domain_size || !evaluation_domain_size.is_multiple_of(trace_domain_size)
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let trace_generator = modular_power(
        context.evaluation_domain_generator,
        evaluation_domain_size / trace_domain_size,
        context.base_field_modulus,
    );
    Ok(modular_power(
        trace_generator,
        row_ordinal,
        context.base_field_modulus,
    ))
}
