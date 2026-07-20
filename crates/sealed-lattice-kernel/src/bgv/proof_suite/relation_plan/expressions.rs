use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
    StreamingFoundationTupleHash512,
};

use super::{
    bounds::{RelationConstraintDescriptor, SignedIntegerInterval},
    compiled_plan::RelationPlanCheckContext,
    layout::{RelationPlanVariant, challenge_descriptor},
    model::{
        RelationChallengeDescriptor, RelationChallengeRole, RelationColumnValueType,
        RelationPlanError, RelationRadixConvolutionDescriptor, SuiteModulusReference,
        canonical_encoding_error,
    },
    schema::{
        ADDITION_SCHEMA_IDENTIFIER, BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
        COLUMN_VALUE_SCHEMA_IDENTIFIER,
        CONSTANT_COLUMN_VERIFIER_SEQUENCE_PRODUCT_SUM_SCHEMA_IDENTIFIER,
        CONSTANT_COLUMN_VERIFIER_SEQUENCE_PRODUCT_TERM_SCHEMA_IDENTIFIER,
        EVALUATION_VARIABLE_SCHEMA_IDENTIFIER, MULTIPLICATION_SCHEMA_IDENTIFIER,
        NEGATION_SCHEMA_IDENTIFIER, NON_NATIVE_MODULUS_CONSTANT_SCHEMA_IDENTIFIER,
        NONNEGATIVE_POWER_SCHEMA_IDENTIFIER, SCHEMA_VERSION,
        TRACE_DOMAIN_EXCEPT_ROOTS_SCHEMA_IDENTIFIER, TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER,
    },
};

#[cfg(test)]
use super::{
    model::RelationRadixFactorDescriptor, schema::RADIX_CONVOLUTION_COEFFICIENT_SCHEMA_IDENTIFIER,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationConstantColumnVerifierSequenceProductTerm {
    pub(crate) constant_column_ordinal: u32,
    pub(crate) verifier_sequence_column_ordinal: u32,
    pub(crate) verifier_sequence_rotation_is_negative: bool,
    pub(crate) verifier_sequence_rotation_magnitude: u64,
}

impl RelationConstantColumnVerifierSequenceProductTerm {
    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            CONSTANT_COLUMN_VERIFIER_SEQUENCE_PRODUCT_TERM_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.constant_column_ordinal),
                CanonicalItem::unsigned32(self.verifier_sequence_column_ordinal),
                CanonicalItem::boolean(self.verifier_sequence_rotation_is_negative),
                CanonicalItem::unsigned64(self.verifier_sequence_rotation_magnitude),
            ],
        )
    }
}

pub(super) fn checked_resident_payload_add(
    left: u64,
    right: u64,
) -> Result<u64, RelationPlanError> {
    left.checked_add(right)
        .ok_or(RelationPlanError::CountOverflow)
}

pub(super) fn resident_vec_storage_byte_length<Value>(
    values: &Vec<Value>,
) -> Result<u64, RelationPlanError> {
    u64::try_from(values.capacity())
        .ok()
        .and_then(|capacity| {
            capacity.checked_mul(u64::try_from(std::mem::size_of::<Value>()).ok()?)
        })
        .ok_or(RelationPlanError::CountOverflow)
}

pub(super) fn resident_string_payload_byte_length(
    value: &String,
) -> Result<u64, RelationPlanError> {
    u64::try_from(value.capacity()).map_err(|_| RelationPlanError::CountOverflow)
}

pub(super) fn resident_big_unsigned_integer_payload_byte_length(
    value: &BigUint,
) -> Result<u64, RelationPlanError> {
    value
        .bits()
        .checked_add(31)
        .and_then(|bits| bits.div_ceil(32).checked_mul(4))
        .ok_or(RelationPlanError::CountOverflow)
}

pub(super) fn resident_big_signed_integer_payload_byte_length(
    value: &BigInt,
) -> Result<u64, RelationPlanError> {
    resident_big_unsigned_integer_payload_byte_length(value.magnitude())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationExpressionInstruction {
    BaseFieldConstant(u64),
    NonNativeModulusConstant {
        modulus_reference: SuiteModulusReference,
        multiplier: u16,
    },
    EvaluationVariable,
    ColumnValue {
        column_ordinal: u32,
        rotation_is_negative: bool,
        rotation_magnitude: u64,
    },
    ConstantColumnVerifierSequenceProductSum {
        coefficient_period: u16,
        ordered_terms: Vec<RelationConstantColumnVerifierSequenceProductTerm>,
    },
    TranscriptChallenge {
        challenge_role: RelationChallengeRole,
        role_coordinates: Vec<u64>,
    },
    Addition,
    Multiplication,
    Negation,
    NonnegativePower(u64),
    #[cfg(test)]
    RadixConvolutionCoefficient {
        convolution_ordinal: u32,
        coefficient_ordinal: u32,
    },
    TraceDomainExceptRoots {
        trace_domain_size: u64,
        ordered_excluded_roots: Vec<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationConstraintColumnQuery {
    pub(super) column_ordinal: u32,
    pub(super) rotation_is_negative: bool,
    pub(super) rotation_magnitude: u64,
}

impl RelationConstraintColumnQuery {
    pub(crate) const fn column_ordinal(self) -> u32 {
        self.column_ordinal
    }

    pub(crate) const fn rotation_is_negative(self) -> bool {
        self.rotation_is_negative
    }

    pub(crate) const fn rotation_magnitude(self) -> u64 {
        self.rotation_magnitude
    }
}

impl RelationExpressionInstruction {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        match self {
            Self::ConstantColumnVerifierSequenceProductSum { ordered_terms, .. } => {
                resident_vec_storage_byte_length(ordered_terms)
            }
            Self::TranscriptChallenge {
                role_coordinates, ..
            } => resident_vec_storage_byte_length(role_coordinates),
            Self::TraceDomainExceptRoots {
                ordered_excluded_roots,
                ..
            } => resident_vec_storage_byte_length(ordered_excluded_roots),
            Self::BaseFieldConstant(_)
            | Self::NonNativeModulusConstant { .. }
            | Self::EvaluationVariable
            | Self::ColumnValue { .. }
            | Self::Addition
            | Self::Multiplication
            | Self::Negation
            | Self::NonnegativePower(_) => Ok(0),
            #[cfg(test)]
            Self::RadixConvolutionCoefficient { .. } => Ok(0),
        }
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::BaseFieldConstant(value) => CanonicalTuple::new(
                BASE_FIELD_CONSTANT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::from_canonical_bytes(
                        CanonicalItemType::FieldElement,
                        value.to_le_bytes().to_vec(),
                        &CanonicalDecodeLimits::default(),
                    )
                    .map_err(canonical_encoding_error)?,
                ],
            ),
            Self::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => CanonicalTuple::new(
                NON_NATIVE_MODULUS_CONSTANT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned16(*multiplier),
                ],
            ),
            Self::EvaluationVariable => CanonicalTuple::new(
                EVALUATION_VARIABLE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                Vec::new(),
            ),
            Self::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => CanonicalTuple::new(
                COLUMN_VALUE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*column_ordinal),
                    CanonicalItem::unsigned8(u8::from(*rotation_is_negative)),
                    CanonicalItem::unsigned64(*rotation_magnitude),
                ],
            ),
            Self::ConstantColumnVerifierSequenceProductSum {
                coefficient_period,
                ordered_terms,
            } => {
                CanonicalTuple::new(
                    CONSTANT_COLUMN_VERIFIER_SEQUENCE_PRODUCT_SUM_SCHEMA_IDENTIFIER,
                    SCHEMA_VERSION,
                    vec![
                        CanonicalItem::unsigned16(*coefficient_period),
                        canonical_nested_list(ordered_terms.iter().copied().map(
                            RelationConstantColumnVerifierSequenceProductTerm::canonical_tuple,
                        ))?,
                    ],
                )
            }
            Self::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => CanonicalTuple::new(
                TRANSCRIPT_CHALLENGE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned16(*challenge_role as u16),
                    canonical_u64_list(role_coordinates)?,
                ],
            ),
            Self::Addition => {
                CanonicalTuple::new(ADDITION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::Multiplication => {
                CanonicalTuple::new(MULTIPLICATION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::Negation => {
                CanonicalTuple::new(NEGATION_SCHEMA_IDENTIFIER, SCHEMA_VERSION, Vec::new())
            }
            Self::NonnegativePower(exponent) => CanonicalTuple::new(
                NONNEGATIVE_POWER_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned64(*exponent)],
            ),
            #[cfg(test)]
            Self::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => CanonicalTuple::new(
                RADIX_CONVOLUTION_COEFFICIENT_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*convolution_ordinal),
                    CanonicalItem::unsigned32(*coefficient_ordinal),
                ],
            ),
            Self::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => CanonicalTuple::new(
                TRACE_DOMAIN_EXCEPT_ROOTS_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned64(*trace_domain_size),
                    canonical_u64_list(ordered_excluded_roots)?,
                ],
            ),
        })
    }
}

pub(crate) fn unsigned_radix_comparator_digit_expression(
    maximum_digit: u64,
    value_digit_column_ordinal: u32,
    difference_digit_column_ordinal: u32,
    incoming_borrow_column_ordinal: Option<u32>,
    outgoing_borrow_column_ordinal: Option<u32>,
    radix: u64,
) -> Vec<RelationExpressionInstruction> {
    let mut expression = vec![
        RelationExpressionInstruction::BaseFieldConstant(maximum_digit),
        unrotated_column_expression(value_digit_column_ordinal),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ];
    if let Some(incoming_borrow_column_ordinal) = incoming_borrow_column_ordinal {
        expression.extend([
            unrotated_column_expression(incoming_borrow_column_ordinal),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ]);
    }
    if let Some(outgoing_borrow_column_ordinal) = outgoing_borrow_column_ordinal {
        expression.extend([
            unrotated_column_expression(outgoing_borrow_column_ordinal),
            RelationExpressionInstruction::BaseFieldConstant(radix),
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Addition,
        ]);
    }
    expression.extend([
        unrotated_column_expression(difference_digit_column_ordinal),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]);
    expression
}

pub(super) fn unrotated_column_expression(column_ordinal: u32) -> RelationExpressionInstruction {
    RelationExpressionInstruction::ColumnValue {
        column_ordinal,
        rotation_is_negative: false,
        rotation_magnitude: 0,
    }
}

pub(super) fn binary_constraint_expression(
    column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    let column = unrotated_column_expression(column_ordinal);
    vec![
        column.clone(),
        column,
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
    ]
}

pub(super) fn trinary_constraint_expression(
    column_ordinal: u32,
) -> Vec<RelationExpressionInstruction> {
    let column = unrotated_column_expression(column_ordinal);
    vec![
        column.clone(),
        column.clone(),
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
        column,
        RelationExpressionInstruction::BaseFieldConstant(2),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
        RelationExpressionInstruction::Multiplication,
    ]
}

pub(super) fn radix_recomposition_expression(
    target_column_ordinal: u32,
    radix: u64,
    offset: Option<&BigUint>,
    ordered_digit_column_ordinals: &[u32],
    proof_base_field_modulus: u64,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expression = vec![unrotated_column_expression(target_column_ordinal)];
    if let Some(offset) = offset {
        expression.push(RelationExpressionInstruction::BaseFieldConstant(
            bounded_biguint_as_u64(offset, proof_base_field_modulus)?,
        ));
        expression.push(RelationExpressionInstruction::Addition);
    }

    let mut weight = BigUint::one();
    let radix = BigUint::from(radix);
    for (digit_ordinal, digit_column_ordinal) in
        ordered_digit_column_ordinals.iter().copied().enumerate()
    {
        expression.push(unrotated_column_expression(digit_column_ordinal));
        expression.push(RelationExpressionInstruction::BaseFieldConstant(
            bounded_biguint_as_u64(&weight, proof_base_field_modulus)?,
        ));
        expression.push(RelationExpressionInstruction::Multiplication);
        if digit_ordinal > 0 {
            expression.push(RelationExpressionInstruction::Addition);
        }
        weight *= &radix;
    }
    expression.push(RelationExpressionInstruction::Negation);
    expression.push(RelationExpressionInstruction::Addition);
    Ok(expression)
}

pub(super) fn bounded_biguint_as_u64(
    value: &BigUint,
    exclusive_upper_bound: u64,
) -> Result<u64, RelationPlanError> {
    let digits = value.to_u64_digits();
    if digits.len() > 1 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    let value = digits.first().copied().unwrap_or(0);
    if value >= exclusive_upper_bound {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    Ok(value)
}

pub(crate) fn finite_integer_set_constraint_expressions(
    column_ordinal: u32,
    ordered_values: &[BigInt],
    proof_base_field_modulus: u64,
) -> Result<
    (
        Vec<RelationExpressionInstruction>,
        Vec<Vec<RelationExpressionInstruction>>,
    ),
    RelationPlanError,
> {
    if ordered_values.len() < 2 || !strictly_sorted_unique(ordered_values) {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let ordered_factor_expressions = ordered_values
        .iter()
        .map(|value| {
            finite_integer_set_factor_expression(column_ordinal, value, proof_base_field_modulus)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let product_expression =
        ordered_injective_integer_factor_product_expression(&ordered_factor_expressions)?;
    Ok((product_expression, ordered_factor_expressions))
}

pub(super) fn finite_integer_set_factor_expression(
    column_ordinal: u32,
    value: &BigInt,
    proof_base_field_modulus: u64,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let (sign, magnitude_bytes) = value.to_bytes_be();
    let magnitude = BigUint::from_bytes_be(&magnitude_bytes);
    let magnitude = bounded_biguint_as_u64(&magnitude, proof_base_field_modulus)?;
    let encoded_value = match sign {
        Sign::Minus if magnitude != 0 => proof_base_field_modulus - magnitude,
        Sign::NoSign if magnitude == 0 => 0,
        Sign::Plus => magnitude,
        _ => return Err(RelationPlanError::InvalidSignedMagnitude),
    };
    Ok(vec![
        unrotated_column_expression(column_ordinal),
        RelationExpressionInstruction::BaseFieldConstant(modular_negation(
            encoded_value,
            proof_base_field_modulus,
        )),
        RelationExpressionInstruction::Addition,
    ])
}

pub(crate) fn ordered_injective_integer_factor_product_expression(
    ordered_factor_expressions: &[Vec<RelationExpressionInstruction>],
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    if ordered_factor_expressions.len() < 2
        || ordered_factor_expressions
            .iter()
            .any(|factor_expression| factor_expression.is_empty())
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let instruction_count = ordered_factor_expressions.iter().try_fold(
        ordered_factor_expressions.len() - 1,
        |count, factor_expression| {
            count
                .checked_add(factor_expression.len())
                .ok_or(RelationPlanError::CountOverflow)
        },
    )?;
    let mut product_expression = Vec::with_capacity(instruction_count);
    for (factor_ordinal, factor_expression) in ordered_factor_expressions.iter().enumerate() {
        product_expression.extend_from_slice(factor_expression);
        if factor_ordinal > 0 {
            product_expression.push(RelationExpressionInstruction::Multiplication);
        }
    }
    Ok(product_expression)
}

pub(super) fn expression_column_ordinals(
    expression: &[RelationExpressionInstruction],
    variant: &RelationPlanVariant,
) -> Result<BTreeSet<u32>, RelationPlanError> {
    let column_ordinals = relation_column_queries(
        &[expression],
        &variant.ordered_radix_convolutions,
        RelationPlanError::InvalidConstraint,
    )?
    .into_iter()
    .map(RelationConstraintColumnQuery::column_ordinal)
    .collect::<BTreeSet<_>>();
    if column_ordinals.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(column_ordinals)
}

pub(super) fn required_column_rotations(
    constraints: &[RelationConstraintDescriptor],
    radix_convolutions: &[RelationRadixConvolutionDescriptor],
) -> Result<BTreeMap<u32, BTreeSet<(bool, u64)>>, RelationPlanError> {
    let mut rotations_by_column = BTreeMap::<u32, BTreeSet<_>>::new();
    for constraint in constraints {
        for query in relation_column_queries(
            &[&constraint.numerator_postfix_expression],
            radix_convolutions,
            RelationPlanError::InvalidOpening,
        )? {
            rotations_by_column
                .entry(query.column_ordinal)
                .or_default()
                .insert((query.rotation_is_negative, query.rotation_magnitude));
        }
    }
    Ok(rotations_by_column)
}

pub(super) fn relation_column_queries(
    expressions: &[&[RelationExpressionInstruction]],
    radix_convolutions: &[RelationRadixConvolutionDescriptor],
    invalid_reference_error: RelationPlanError,
) -> Result<BTreeSet<RelationConstraintColumnQuery>, RelationPlanError> {
    let mut queries = BTreeSet::new();
    visit_relation_column_queries(
        expressions,
        radix_convolutions,
        invalid_reference_error,
        |query| {
            queries.insert(query);
            Ok(())
        },
    )?;
    Ok(queries)
}

pub(super) fn visit_relation_column_queries<Visit>(
    expressions: &[&[RelationExpressionInstruction]],
    radix_convolutions: &[RelationRadixConvolutionDescriptor],
    invalid_reference_error: RelationPlanError,
    mut visit: Visit,
) -> Result<(), RelationPlanError>
where
    Visit: FnMut(RelationConstraintColumnQuery) -> Result<(), RelationPlanError>,
{
    #[cfg(not(test))]
    if !radix_convolutions.is_empty() {
        return Err(invalid_reference_error);
    }

    for instruction in expressions.iter().flat_map(|expression| expression.iter()) {
        match instruction {
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => {
                visit(RelationConstraintColumnQuery {
                    column_ordinal: *column_ordinal,
                    rotation_is_negative: *rotation_is_negative,
                    rotation_magnitude: *rotation_magnitude,
                })?;
            }
            RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                ordered_terms,
                ..
            } => {
                for term in ordered_terms {
                    visit(RelationConstraintColumnQuery {
                        column_ordinal: term.constant_column_ordinal,
                        rotation_is_negative: false,
                        rotation_magnitude: 0,
                    })?;
                    visit(RelationConstraintColumnQuery {
                        column_ordinal: term.verifier_sequence_column_ordinal,
                        rotation_is_negative: term.verifier_sequence_rotation_is_negative,
                        rotation_magnitude: term.verifier_sequence_rotation_magnitude,
                    })?;
                }
            }
            #[cfg(test)]
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                ..
            } => {
                let convolution = radix_convolutions
                    .get(
                        usize::try_from(*convolution_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(invalid_reference_error)?;
                for factor in convolution
                    .ordered_terms
                    .iter()
                    .flat_map(|term| &term.ordered_factors)
                {
                    match factor {
                        RelationRadixFactorDescriptor::ColumnDigits {
                            ordered_column_ordinals,
                            rotation_is_negative,
                            rotation_magnitude,
                        } => {
                            for column_ordinal in ordered_column_ordinals {
                                visit(RelationConstraintColumnQuery {
                                    column_ordinal: *column_ordinal,
                                    rotation_is_negative: *rotation_is_negative,
                                    rotation_magnitude: *rotation_magnitude,
                                })?;
                            }
                        }
                        RelationRadixFactorDescriptor::ScalarColumn { column_ordinal, .. } => {
                            visit(RelationConstraintColumnQuery {
                                column_ordinal: *column_ordinal,
                                rotation_is_negative: false,
                                rotation_magnitude: 0,
                            })?;
                        }
                        RelationRadixFactorDescriptor::ConstantDigits { .. } => {}
                    }
                }
            }
            RelationExpressionInstruction::BaseFieldConstant(_)
            | RelationExpressionInstruction::NonNativeModulusConstant { .. }
            | RelationExpressionInstruction::EvaluationVariable
            | RelationExpressionInstruction::TranscriptChallenge { .. }
            | RelationExpressionInstruction::TraceDomainExceptRoots { .. }
            | RelationExpressionInstruction::Addition
            | RelationExpressionInstruction::Multiplication
            | RelationExpressionInstruction::Negation
            | RelationExpressionInstruction::NonnegativePower(_) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ExpressionShape {
    pub(super) value_type: RelationColumnValueType,
    pub(super) degree: u64,
    pub(super) constant_value: Option<u64>,
}

pub(super) fn check_expression(
    expression: &[RelationExpressionInstruction],
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
    zeroifier: bool,
) -> Result<ExpressionShape, RelationPlanError> {
    if expression.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut stack = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                if *value >= context.base_field_modulus {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: 0,
                    constant_value: Some(*value),
                });
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                let value = resolved_modulus_multiple(*modulus_reference, *multiplier, context)?;
                if value >= context.base_field_modulus {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: 0,
                    constant_value: Some(value),
                });
            }
            RelationExpressionInstruction::EvaluationVariable => stack.push(ExpressionShape {
                value_type: RelationColumnValueType::BaseField,
                degree: 1,
                constant_value: None,
            }),
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => {
                if zeroifier
                    || (*rotation_magnitude == 0 && *rotation_is_negative)
                    || *rotation_magnitude >= variant.trace_domain_size
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let column = variant
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(ExpressionShape {
                    value_type: column.value_type,
                    degree: column.source_degree_bound_exclusive - 1,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                coefficient_period,
                ordered_terms,
            } => {
                if zeroifier
                    || *coefficient_period == 0
                    || !variant
                        .trace_domain_size
                        .is_multiple_of(u64::from(*coefficient_period))
                    || ordered_terms.is_empty()
                    || ordered_terms.windows(2).any(|terms| terms[0] >= terms[1])
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let mut maximum_degree = None;
                for term in ordered_terms {
                    if (term.verifier_sequence_rotation_magnitude == 0
                        && term.verifier_sequence_rotation_is_negative)
                        || term.verifier_sequence_rotation_magnitude >= variant.trace_domain_size
                    {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    let constant_column = variant
                        .ordered_columns
                        .get(term.constant_column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    let verifier_sequence_column = variant
                        .ordered_columns
                        .get(term.verifier_sequence_column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    if !matches!(
                        constant_column.origin,
                        super::model::RelationColumnOrigin::Prover
                    ) || !matches!(
                        verifier_sequence_column.origin,
                        super::model::RelationColumnOrigin::VerifierSequence { .. }
                    ) || constant_column.value_type != RelationColumnValueType::BaseField
                        || verifier_sequence_column.value_type != RelationColumnValueType::BaseField
                        || constant_column.source_degree_bound_exclusive
                            >= variant.trace_domain_size.saturating_mul(2)
                        || verifier_sequence_column.source_degree_bound_exclusive
                            != variant.trace_domain_size
                    {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    let product_degree = constant_column
                        .source_degree_bound_exclusive
                        .checked_sub(1)
                        .and_then(|degree| {
                            degree.checked_add(
                                verifier_sequence_column.source_degree_bound_exclusive - 1,
                            )
                        })
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    maximum_degree = Some(maximum_degree.unwrap_or(0_u64).max(product_degree));
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: maximum_degree.ok_or(RelationPlanError::InvalidConstraint)?,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role,
                role_coordinates,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                challenge_descriptor(
                    *challenge_role,
                    role_coordinates.clone(),
                    1,
                    variant,
                    context,
                )?;
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::ChallengeExtension,
                    degree: 0,
                    constant_value: None,
                });
            }
            #[cfg(test)]
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => {
                if zeroifier {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                stack.push(radix_convolution_expression_shape(
                    variant,
                    *convolution_ordinal,
                    *coefficient_ordinal,
                )?);
            }
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => {
                if !zeroifier
                    || *trace_domain_size != variant.trace_domain_size
                    || ordered_excluded_roots.is_empty()
                    || !strictly_sorted_unique(ordered_excluded_roots)
                    || ordered_excluded_roots.len() as u64 >= *trace_domain_size
                    || ordered_excluded_roots.iter().any(|root| {
                        *root == 0
                            || *root >= context.base_field_modulus
                            || modular_power(*root, *trace_domain_size, context.base_field_modulus)
                                != 1
                    })
                {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                stack.push(ExpressionShape {
                    value_type: RelationColumnValueType::BaseField,
                    degree: trace_domain_size
                        .checked_sub(ordered_excluded_roots.len() as u64)
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?,
                    constant_value: None,
                });
            }
            RelationExpressionInstruction::Addition
            | RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let value_type = if left.value_type == RelationColumnValueType::ChallengeExtension
                    || right.value_type == RelationColumnValueType::ChallengeExtension
                {
                    RelationColumnValueType::ChallengeExtension
                } else {
                    RelationColumnValueType::BaseField
                };
                let (degree, constant_value) =
                    if matches!(instruction, RelationExpressionInstruction::Addition) {
                        (
                            left.degree.max(right.degree),
                            left.constant_value
                                .zip(right.constant_value)
                                .map(|(left, right)| {
                                    modular_sum(left, right, context.base_field_modulus)
                                }),
                        )
                    } else {
                        (
                            left.degree
                                .checked_add(right.degree)
                                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
                            left.constant_value
                                .zip(right.constant_value)
                                .map(|(left, right)| {
                                    modular_product(left, right, context.base_field_modulus)
                                }),
                        )
                    };
                stack.push(ExpressionShape {
                    value_type,
                    degree,
                    constant_value,
                });
            }
            RelationExpressionInstruction::Negation => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                value.constant_value = value
                    .constant_value
                    .map(|constant| modular_negation(constant, context.base_field_modulus));
                stack.push(value);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                value.degree = value
                    .degree
                    .checked_mul(*exponent)
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                value.constant_value = value
                    .constant_value
                    .map(|constant| modular_power(constant, *exponent, context.base_field_modulus));
                stack.push(value);
            }
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

#[cfg(test)]
pub(super) fn radix_convolution_expression_shape(
    variant: &RelationPlanVariant,
    convolution_ordinal: u32,
    coefficient_ordinal: u32,
) -> Result<ExpressionShape, RelationPlanError> {
    let convolution = variant
        .ordered_radix_convolutions
        .get(convolution_ordinal as usize)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    let coefficient_ordinal = u64::from(coefficient_ordinal);
    let mut maximum_degree = None;
    for term in &convolution.ordered_terms {
        let mut maximum_coefficient_ordinal = 0_u64;
        let mut term_degree = 0_u64;
        let mut has_column_factor = false;
        for factor in &term.ordered_factors {
            match factor {
                RelationRadixFactorDescriptor::ColumnDigits {
                    ordered_column_ordinals,
                    ..
                } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(
                            u64::try_from(ordered_column_ordinals.len() - 1)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    let factor_degree = ordered_column_ordinals
                        .iter()
                        .map(|column_ordinal| {
                            variant
                                .ordered_columns
                                .get(*column_ordinal as usize)
                                .map(|column| column.source_degree_bound_exclusive - 1)
                                .ok_or(RelationPlanError::InvalidConstraint)
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .max()
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    term_degree = term_degree
                        .checked_add(factor_degree)
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    has_column_factor = true;
                }
                RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => {
                    maximum_coefficient_ordinal = maximum_coefficient_ordinal
                        .checked_add(
                            u64::try_from(ordered_digits.len() - 1)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                }
                RelationRadixFactorDescriptor::ScalarColumn { column_ordinal, .. } => {
                    term_degree = term_degree
                        .checked_add(
                            variant
                                .ordered_columns
                                .get(*column_ordinal as usize)
                                .map(|column| column.source_degree_bound_exclusive - 1)
                                .ok_or(RelationPlanError::InvalidConstraint)?,
                        )
                        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
                    has_column_factor = true;
                }
            }
        }
        if !has_column_factor {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if coefficient_ordinal <= maximum_coefficient_ordinal {
            maximum_degree = Some(maximum_degree.unwrap_or(0_u64).max(term_degree));
        }
    }
    Ok(ExpressionShape {
        value_type: RelationColumnValueType::BaseField,
        degree: maximum_degree.ok_or(RelationPlanError::InvalidConstraint)?,
        constant_value: None,
    })
}

pub(super) fn evaluate_integer_interval(
    expression: &[RelationExpressionInstruction],
    column_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let mut stack = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                let centered = if *value > context.base_field_modulus / 2 {
                    BigInt::from(*value) - BigInt::from(context.base_field_modulus)
                } else {
                    BigInt::from(*value)
                };
                stack.push(SignedIntegerInterval::from_bigints(
                    centered.clone(),
                    centered,
                )?);
            }
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier,
            } => {
                let value = resolved_modulus_multiple(*modulus_reference, *multiplier, context)?;
                if value >= context.base_field_modulus {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
                stack.push(SignedIntegerInterval::from_bigints(
                    BigInt::from(value),
                    BigInt::from(value),
                )?);
            }
            RelationExpressionInstruction::ColumnValue { column_ordinal, .. } => {
                stack.push(
                    column_bounds
                        .get(column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?,
                );
            }
            RelationExpressionInstruction::ConstantColumnVerifierSequenceProductSum {
                ordered_terms,
                ..
            } => {
                let mut sum = SignedIntegerInterval::new(0, 0);
                for term in ordered_terms {
                    let constant = column_bounds
                        .get(&term.constant_column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?;
                    let verifier_sequence = column_bounds
                        .get(&term.verifier_sequence_column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?;
                    sum = sum.add(constant.multiply(verifier_sequence)?)?;
                }
                stack.push(sum);
            }
            #[cfg(test)]
            RelationExpressionInstruction::RadixConvolutionCoefficient {
                convolution_ordinal,
                coefficient_ordinal,
            } => {
                let convolution = variant
                    .ordered_radix_convolutions
                    .get(*convolution_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(evaluate_radix_convolution_interval(
                    convolution,
                    *coefficient_ordinal,
                    column_bounds,
                )?);
            }
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.add(right)?);
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(left.multiply(right)?);
            }
            RelationExpressionInstruction::Negation => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.negate()?);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidConstraint)?;
                stack.push(value.power(*exponent)?);
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role:
                    challenge_role @ (RelationChallengeRole::NonNativeTheta
                    | RelationChallengeRole::NonNativeAlpha),
                role_coordinates,
            } => {
                challenge_descriptor(
                    *challenge_role,
                    role_coordinates.clone(),
                    1,
                    variant,
                    context,
                )?;
                let modulus_ordinal = role_coordinates
                    .first()
                    .copied()
                    .and_then(|ordinal| usize::try_from(ordinal).ok())
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                let modulus_reference = variant
                    .ordered_non_native_moduli
                    .get(modulus_ordinal)
                    .copied()
                    .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                let modulus = context.resolved_modulus(modulus_reference)?;
                stack.push(SignedIntegerInterval::from_bigints(
                    BigInt::zero(),
                    BigInt::from(modulus - 1),
                )?);
            }
            RelationExpressionInstruction::EvaluationVariable
            | RelationExpressionInstruction::TranscriptChallenge { .. }
            | RelationExpressionInstruction::TraceDomainExceptRoots { .. } => {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    stack.pop().ok_or(RelationPlanError::InvalidConstraint)
}

#[cfg(test)]
pub(super) fn evaluate_radix_convolution_interval(
    convolution: &RelationRadixConvolutionDescriptor,
    coefficient_ordinal: u32,
    column_bounds: &BTreeMap<u32, SignedIntegerInterval>,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let coefficient_ordinal =
        usize::try_from(coefficient_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
    let mut sum = SignedIntegerInterval::new(0, 0);
    for term in &convolution.ordered_terms {
        let mut coefficients = vec![SignedIntegerInterval::new(1, 1)];
        for factor in &term.ordered_factors {
            let factor_coefficients = match factor {
                RelationRadixFactorDescriptor::ColumnDigits {
                    ordered_column_ordinals,
                    ..
                } => ordered_column_ordinals
                    .iter()
                    .map(|column_ordinal| {
                        column_bounds
                            .get(column_ordinal)
                            .cloned()
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => ordered_digits
                    .iter()
                    .map(|digit| {
                        SignedIntegerInterval::from_bigints(
                            BigInt::from(*digit),
                            BigInt::from(*digit),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                RelationRadixFactorDescriptor::ScalarColumn {
                    column_ordinal,
                    complement_binary_value,
                } => {
                    let interval = column_bounds
                        .get(column_ordinal)
                        .cloned()
                        .ok_or(RelationPlanError::InvalidSemanticCell)?;
                    vec![if *complement_binary_value {
                        SignedIntegerInterval::from_bigints(
                            BigInt::one() - interval.maximum,
                            BigInt::one() - interval.minimum,
                        )?
                    } else {
                        interval
                    }]
                }
            };
            coefficients = convolve_interval_vectors(
                &coefficients,
                &factor_coefficients,
                coefficient_ordinal,
            )?;
        }
        let mut coefficient = coefficients
            .get(coefficient_ordinal)
            .cloned()
            .unwrap_or_else(|| SignedIntegerInterval::new(0, 0));
        if term.negative {
            coefficient = coefficient.negate()?;
        }
        sum = sum.add(coefficient)?;
    }
    Ok(sum)
}

pub(super) fn minimum_radix_digit_count(
    maximum_value: u64,
    radix: u64,
) -> Result<u16, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut remaining = maximum_value;
    let mut digit_count = 1_u16;
    while remaining >= radix {
        remaining /= radix;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(digit_count)
}

pub(super) fn resolved_modulus_multiple(
    modulus_reference: SuiteModulusReference,
    multiplier: u16,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    if multiplier == 0 {
        return Err(RelationPlanError::InvalidModulus);
    }
    let modulus = context.resolved_modulus(modulus_reference)?;
    match modulus.checked_mul(u64::from(multiplier)) {
        Some(value) => Ok(value),
        None => {
            #[cfg(test)]
            eprintln!(
                "resolved_modulus_multiple overflow: modulus_reference={modulus_reference:?}, modulus={modulus}, multiplier={multiplier}, exact_product={}",
                u128::from(modulus) * u128::from(multiplier)
            );
            Err(RelationPlanError::IntegerBoundOverflow)
        }
    }
}

pub(super) fn fixed_radix_u64_digits(
    mut value: u64,
    digit_count: usize,
    radix: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if digit_count == 0 || radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digits = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        digits.push(value % radix);
        value /= radix;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

#[cfg(test)]
pub(super) fn convolve_interval_vectors(
    left: &[SignedIntegerInterval],
    right: &[SignedIntegerInterval],
    maximum_coefficient_ordinal: usize,
) -> Result<Vec<SignedIntegerInterval>, RelationPlanError> {
    let output_length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?
        .min(
            maximum_coefficient_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    let mut output = vec![SignedIntegerInterval::new(0, 0); output_length];
    for (left_ordinal, left_interval) in left.iter().enumerate() {
        for (right_ordinal, right_interval) in right.iter().enumerate() {
            let output_ordinal = left_ordinal
                .checked_add(right_ordinal)
                .ok_or(RelationPlanError::CountOverflow)?;
            if output_ordinal >= output_length {
                break;
            }
            output[output_ordinal] = output[output_ordinal]
                .clone()
                .add(left_interval.clone().multiply(right_interval.clone())?)?;
        }
    }
    Ok(output)
}

pub(super) fn compile_base_field_polynomial(
    expression: &[RelationExpressionInstruction],
    modulus: u64,
    maximum_coefficient_count: usize,
) -> Result<Vec<u64>, RelationPlanError> {
    let mut stack: Vec<Vec<u64>> = Vec::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                stack.push(vec![*value]);
            }
            RelationExpressionInstruction::EvaluationVariable => stack.push(vec![0, 1]),
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                stack.push(polynomial_add(&left, &right, modulus)?);
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let left = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let product = polynomial_multiply(&left, &right, modulus)?;
                if product.len() > maximum_coefficient_count {
                    return Err(RelationPlanError::DegreeBoundExceeded);
                }
                stack.push(product);
            }
            RelationExpressionInstruction::Negation => {
                let mut value = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                for coefficient in &mut value {
                    *coefficient = modular_negation(*coefficient, modulus);
                }
                stack.push(value);
            }
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let value = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
                let mut result = vec![1];
                let mut base = value;
                let mut remaining = *exponent;
                while remaining > 0 {
                    if remaining & 1 == 1 {
                        result = polynomial_multiply(&result, &base, modulus)?;
                        if result.len() > maximum_coefficient_count {
                            return Err(RelationPlanError::DegreeBoundExceeded);
                        }
                    }
                    remaining >>= 1;
                    if remaining > 0 {
                        base = polynomial_multiply(&base, &base, modulus)?;
                        if base.len() > maximum_coefficient_count {
                            return Err(RelationPlanError::DegreeBoundExceeded);
                        }
                    }
                }
                stack.push(result);
            }
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size,
                ordered_excluded_roots,
            } => {
                let coefficient_count = usize::try_from(
                    trace_domain_size
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?,
                )
                .map_err(|_| RelationPlanError::CountOverflow)?;
                if coefficient_count > maximum_coefficient_count
                    || ordered_excluded_roots.is_empty()
                    || !strictly_sorted_unique(ordered_excluded_roots)
                {
                    return Err(RelationPlanError::InvalidZeroifier);
                }
                let mut polynomial = vec![0; coefficient_count];
                polynomial[0] = modulus - 1;
                polynomial[coefficient_count - 1] = 1;
                for root in ordered_excluded_roots {
                    polynomial = divide_polynomial_by_root(&polynomial, *root, modulus)?;
                }
                stack.push(polynomial);
            }
            _ => return Err(RelationPlanError::InvalidZeroifier),
        }
    }
    if stack.len() != 1 {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut polynomial = stack.pop().ok_or(RelationPlanError::InvalidZeroifier)?;
    while polynomial.len() > 1 && polynomial.last() == Some(&0) {
        polynomial.pop();
    }
    Ok(polynomial)
}

pub(super) fn divide_polynomial_by_root(
    polynomial: &[u64],
    root: u64,
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if polynomial.len() < 2 || root == 0 || root >= modulus {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    let mut quotient = vec![0; polynomial.len() - 1];
    quotient[polynomial.len() - 2] = polynomial[polynomial.len() - 1];
    for coefficient_ordinal in (1..polynomial.len() - 1).rev() {
        quotient[coefficient_ordinal - 1] = modular_sum(
            polynomial[coefficient_ordinal],
            modular_product(root, quotient[coefficient_ordinal], modulus),
            modulus,
        );
    }
    if modular_sum(
        polynomial[0],
        modular_product(root, quotient[0], modulus),
        modulus,
    ) != 0
    {
        return Err(RelationPlanError::InvalidZeroifier);
    }
    Ok(quotient)
}

pub(super) fn polynomial_add(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    let mut result = vec![0; left.len().max(right.len())];
    for (index, value) in left.iter().enumerate() {
        result[index] = *value;
    }
    for (index, value) in right.iter().enumerate() {
        result[index] = modular_sum(result[index], *value, modulus);
    }
    Ok(result)
}

pub(super) fn polynomial_multiply(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    let length = left
        .len()
        .checked_add(right.len())
        .and_then(|length| length.checked_sub(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut result = vec![0; length];
    for (left_index, left_value) in left.iter().enumerate() {
        for (right_index, right_value) in right.iter().enumerate() {
            let position = left_index + right_index;
            result[position] = modular_sum(
                result[position],
                modular_product(*left_value, *right_value, modulus),
                modulus,
            );
        }
    }
    Ok(result)
}

pub(super) fn evaluate_polynomial(polynomial: &[u64], point: u64, modulus: u64) -> u64 {
    polynomial.iter().rev().fold(0, |value, coefficient| {
        modular_sum(
            modular_product(value, point, modulus),
            *coefficient,
            modulus,
        )
    })
}

pub(super) fn modular_sum(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

pub(super) fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

pub(super) fn modular_negation(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

pub(super) fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        exponent >>= 1;
        if exponent > 0 {
            base = modular_product(base, base, modulus);
        }
    }
    result
}

pub(super) fn validate_challenge_catalog(
    catalog: &[RelationChallengeDescriptor],
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    if catalog.is_empty() || !strictly_sorted_unique(catalog) {
        return Err(RelationPlanError::InvalidChallengeCatalog);
    }
    for descriptor in catalog {
        descriptor.validate(variant, context)?;
    }
    Ok(())
}

pub(super) fn strictly_sorted_unique<Value: Ord>(values: &[Value]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

pub(super) fn strictly_sorted_unique_by_key<Value, Key: Ord + Copy>(
    values: &[Value],
    key: impl Fn(&Value) -> Key,
) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

pub(super) fn canonical_u32_list(values: &[u32]) -> Result<CanonicalItem, RelationPlanError> {
    let values = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned32)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned32, &values)
}

pub(super) fn canonical_u64_list(values: &[u64]) -> Result<CanonicalItem, RelationPlanError> {
    let values = values
        .iter()
        .copied()
        .map(CanonicalItem::unsigned64)
        .collect::<Vec<_>>();
    canonical_generated_list(CanonicalItemType::Unsigned64, &values)
}

pub(super) fn canonical_nested_list(
    tuples: impl IntoIterator<Item = CanonicalTuple>,
) -> Result<CanonicalItem, RelationPlanError> {
    let values = tuples
        .into_iter()
        .map(|tuple| {
            let limits = generated_tuple_encoding_limits(&tuple, true)?;
            CanonicalItem::nested_tuple_with_limits(&tuple, &limits)
                .map_err(canonical_encoding_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical_generated_list(CanonicalItemType::NestedTuple, &values)
}

pub(super) fn canonical_generated_list(
    element_type: CanonicalItemType,
    values: &[CanonicalItem],
) -> Result<CanonicalItem, RelationPlanError> {
    let canonical_byte_length = values.iter().try_fold(6_usize, |length, value| {
        length
            .checked_add(value.canonical_bytes().len())
            .ok_or(RelationPlanError::CountOverflow)
    })?;
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: canonical_byte_length,
        maximum_item_count: values.len(),
        maximum_item_byte_length: canonical_byte_length,
        ..CanonicalDecodeLimits::default()
    };
    CanonicalItem::homogeneous_list_with_limits(element_type, values, &limits)
        .map_err(canonical_encoding_error)
}

pub(super) fn generated_tuple_encoding_limits(
    tuple: &CanonicalTuple,
    nested_item: bool,
) -> Result<CanonicalDecodeLimits, RelationPlanError> {
    let tuple_byte_length = tuple.items.iter().try_fold(8_usize, |length, item| {
        u32::try_from(item.canonical_bytes().len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        length
            .checked_add(6)
            .and_then(|value| value.checked_add(item.canonical_bytes().len()))
            .ok_or(RelationPlanError::CountOverflow)
    })?;
    let maximum_contained_item_byte_length = tuple
        .items
        .iter()
        .map(|item| item.canonical_bytes().len())
        .max()
        .unwrap_or(0);
    Ok(CanonicalDecodeLimits {
        maximum_tuple_byte_length: tuple_byte_length,
        maximum_item_count: tuple.items.len(),
        maximum_item_byte_length: if nested_item {
            maximum_contained_item_byte_length.max(tuple_byte_length)
        } else {
            maximum_contained_item_byte_length
        },
        ..CanonicalDecodeLimits::default()
    })
}

pub(super) fn encode_generated_tuple(tuple: &CanonicalTuple) -> Result<Vec<u8>, RelationPlanError> {
    tuple
        .encode_with_limits(&generated_tuple_encoding_limits(tuple, false)?)
        .map_err(canonical_encoding_error)
}

pub(super) fn hash_generated_variable_bytes(
    domain: &str,
    canonical_bytes: &[u8],
) -> Result<[u8; 64], RelationPlanError> {
    let mut hasher =
        StreamingFoundationTupleHash512::new_variable_bytes(domain, &[], canonical_bytes.len())
            .map_err(|_| RelationPlanError::CanonicalEncoding)?;
    hasher
        .absorb(canonical_bytes)
        .map_err(|_| RelationPlanError::CanonicalEncoding)?;
    Ok(hasher
        .finalize()
        .map_err(|_| RelationPlanError::CanonicalEncoding)?
        .into_bytes())
}
