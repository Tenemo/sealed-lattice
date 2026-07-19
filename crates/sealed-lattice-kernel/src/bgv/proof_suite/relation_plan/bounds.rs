use num_bigint::{BigInt, BigUint, Sign};
use num_traits::Zero;

use crate::foundation::{CanonicalItem, CanonicalTuple};

use super::{
    expressions::{
        RelationExpressionInstruction, canonical_nested_list, canonical_u32_list,
        canonical_u64_list, checked_resident_payload_add,
        resident_big_signed_integer_payload_byte_length,
        resident_big_unsigned_integer_payload_byte_length, resident_vec_storage_byte_length,
    },
    model::{RelationPlanError, SuiteModulusReference, canonical_encoding_error},
    schema::{
        BINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
        CANONICAL_MODULUS_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
        FINITE_INTEGER_SET_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
        INJECTIVE_INTEGER_FACTOR_PROGRAM_SCHEMA_IDENTIFIER, RELATION_CONSTRAINT_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION, SEMANTIC_CELL_SCHEMA_IDENTIFIER,
        SHIFTED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
        SIGNED_INTEGER_SCHEMA_IDENTIFIER, TRINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
        UNSIGNED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SignedIntegerInterval {
    pub(super) minimum: BigInt,
    pub(super) maximum: BigInt,
}

impl SignedIntegerInterval {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_resident_payload_add(
            resident_big_signed_integer_payload_byte_length(&self.minimum)?,
            resident_big_signed_integer_payload_byte_length(&self.maximum)?,
        )
    }

    pub(super) fn new(minimum: i128, maximum: i128) -> Self {
        Self {
            minimum: BigInt::from(minimum),
            maximum: BigInt::from(maximum),
        }
    }

    pub(super) fn from_bigints(
        minimum: BigInt,
        maximum: BigInt,
    ) -> Result<Self, RelationPlanError> {
        if minimum > maximum {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(Self { minimum, maximum })
    }

    pub(super) fn canonical_items(&self) -> Result<[CanonicalItem; 2], RelationPlanError> {
        Ok([
            CanonicalItem::nested_tuple(&canonical_signed_integer_tuple(&self.minimum)?)
                .map_err(canonical_encoding_error)?,
            CanonicalItem::nested_tuple(&canonical_signed_integer_tuple(&self.maximum)?)
                .map_err(canonical_encoding_error)?,
        ])
    }

    pub(super) fn add(self, other: Self) -> Result<Self, RelationPlanError> {
        Self::from_bigints(self.minimum + other.minimum, self.maximum + other.maximum)
    }

    pub(super) fn multiply(self, other: Self) -> Result<Self, RelationPlanError> {
        let products = [
            &self.minimum * &other.minimum,
            &self.minimum * &other.maximum,
            &self.maximum * &other.minimum,
            &self.maximum * &other.maximum,
        ];
        Self::from_bigints(
            products
                .iter()
                .min()
                .cloned()
                .ok_or(RelationPlanError::InvalidConstraint)?,
            products
                .iter()
                .max()
                .cloned()
                .ok_or(RelationPlanError::InvalidConstraint)?,
        )
    }

    pub(super) fn negate(self) -> Result<Self, RelationPlanError> {
        Self::from_bigints(-self.maximum, -self.minimum)
    }

    pub(super) fn power(self, exponent: u64) -> Result<Self, RelationPlanError> {
        if exponent == 0 {
            return Ok(Self::new(1, 1));
        }
        let mut result = Self::new(1, 1);
        let mut base = self;
        let mut remaining = exponent;
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = result.multiply(base.clone())?;
            }
            remaining >>= 1;
            if remaining > 0 {
                base = base.clone().multiply(base)?;
            }
        }
        Ok(result)
    }

    pub(super) fn is_injective_modulo(&self, modulus: &BigInt) -> bool {
        self.minimum > -modulus.clone() && self.maximum < modulus.clone()
    }
}

pub(super) fn canonical_signed_integer_tuple(
    value: &BigInt,
) -> Result<CanonicalTuple, RelationPlanError> {
    let (sign, mut magnitude) = value.to_bytes_be();
    if value.is_zero() {
        magnitude.clear();
    }
    let sign_code = match sign {
        Sign::Minus => 1,
        Sign::NoSign | Sign::Plus => 0,
    };
    validate_signed_magnitude(sign_code, &magnitude)?;
    Ok(CanonicalTuple::new(
        SIGNED_INTEGER_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned8(sign_code),
            CanonicalItem::variable_bytes(magnitude).map_err(canonical_encoding_error)?,
        ],
    ))
}

#[cfg(test)]
pub(super) fn signed_integer_from_magnitude(
    sign_code: u8,
    magnitude: &[u8],
) -> Result<BigInt, RelationPlanError> {
    validate_signed_magnitude(sign_code, magnitude)?;
    Ok(if magnitude.is_empty() {
        BigInt::zero()
    } else if sign_code == 1 {
        -BigInt::from_bytes_be(Sign::Plus, magnitude)
    } else {
        BigInt::from_bytes_be(Sign::Plus, magnitude)
    })
}

pub(super) fn validate_signed_magnitude(
    sign_code: u8,
    magnitude: &[u8],
) -> Result<(), RelationPlanError> {
    if sign_code > 1
        || (!magnitude.is_empty() && magnitude[0] == 0)
        || (sign_code == 1 && magnitude.is_empty())
    {
        return Err(RelationPlanError::InvalidSignedMagnitude);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationBoundCertificate {
    Trinary {
        constraint_ordinal: u32,
    },
    Binary {
        constraint_ordinal: u32,
    },
    UnsignedRadixRecomposition {
        constraint_ordinal: u32,
        radix: u64,
        ordered_digit_column_ordinals: Vec<u32>,
    },
    ShiftedRadixRecomposition {
        constraint_ordinal: u32,
        radix: u64,
        offset: BigUint,
        ordered_digit_column_ordinals: Vec<u32>,
    },
    CanonicalModulusRecomposition {
        recomposition_constraint_ordinal: u32,
        modulus_reference: SuiteModulusReference,
        radix: u64,
        ordered_digit_column_ordinals: Vec<u32>,
        ordered_comparator_constraint_ordinals: Vec<u32>,
        ordered_difference_digit_column_ordinals: Vec<u32>,
        ordered_borrow_column_ordinals: Vec<u32>,
    },
    FiniteIntegerSet {
        constraint_ordinal: u32,
        ordered_values: Vec<BigInt>,
    },
}

impl RelationBoundCertificate {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        match self {
            Self::Trinary { .. } | Self::Binary { .. } => Ok(0),
            Self::UnsignedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            } => resident_vec_storage_byte_length(ordered_digit_column_ordinals),
            Self::ShiftedRadixRecomposition {
                offset,
                ordered_digit_column_ordinals,
                ..
            } => checked_resident_payload_add(
                resident_big_unsigned_integer_payload_byte_length(offset)?,
                resident_vec_storage_byte_length(ordered_digit_column_ordinals)?,
            ),
            Self::CanonicalModulusRecomposition {
                ordered_digit_column_ordinals,
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
                ..
            } => [
                resident_vec_storage_byte_length(ordered_digit_column_ordinals)?,
                resident_vec_storage_byte_length(ordered_comparator_constraint_ordinals)?,
                resident_vec_storage_byte_length(ordered_difference_digit_column_ordinals)?,
                resident_vec_storage_byte_length(ordered_borrow_column_ordinals)?,
            ]
            .into_iter()
            .try_fold(0_u64, checked_resident_payload_add),
            Self::FiniteIntegerSet { ordered_values, .. } => {
                let value_storage = resident_vec_storage_byte_length(ordered_values)?;
                ordered_values
                    .iter()
                    .try_fold(value_storage, |total, value| {
                        checked_resident_payload_add(
                            total,
                            resident_big_signed_integer_payload_byte_length(value)?,
                        )
                    })
            }
        }
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(match self {
            Self::Trinary { constraint_ordinal } => CanonicalTuple::new(
                TRINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*constraint_ordinal)],
            ),
            Self::Binary { constraint_ordinal } => CanonicalTuple::new(
                BINARY_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![CanonicalItem::unsigned32(*constraint_ordinal)],
            ),
            Self::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix,
                ordered_digit_column_ordinals,
            } => CanonicalTuple::new(
                UNSIGNED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    CanonicalItem::unsigned64(*radix),
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                ],
            ),
            Self::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix,
                offset,
                ordered_digit_column_ordinals,
            } => CanonicalTuple::new(
                SHIFTED_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    CanonicalItem::unsigned64(*radix),
                    canonical_unsigned_magnitude_item(offset)?,
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                ],
            ),
            Self::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                modulus_reference,
                radix,
                ordered_digit_column_ordinals,
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
            } => CanonicalTuple::new(
                CANONICAL_MODULUS_RECOMPOSITION_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*recomposition_constraint_ordinal),
                    CanonicalItem::nested_tuple(&modulus_reference.canonical_tuple())
                        .map_err(canonical_encoding_error)?,
                    CanonicalItem::unsigned64(*radix),
                    canonical_u32_list(ordered_digit_column_ordinals)?,
                    canonical_u32_list(ordered_comparator_constraint_ordinals)?,
                    canonical_u32_list(ordered_difference_digit_column_ordinals)?,
                    canonical_u32_list(ordered_borrow_column_ordinals)?,
                ],
            ),
            Self::FiniteIntegerSet {
                constraint_ordinal,
                ordered_values,
            } => CanonicalTuple::new(
                FINITE_INTEGER_SET_BOUND_CERTIFICATE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(*constraint_ordinal),
                    canonical_nested_list(
                        ordered_values
                            .iter()
                            .map(canonical_signed_integer_tuple)
                            .collect::<Result<Vec<_>, _>>()?,
                    )?,
                ],
            ),
        })
    }

    pub(super) fn constraint_ordinal(&self) -> u32 {
        match self {
            Self::Trinary { constraint_ordinal }
            | Self::Binary { constraint_ordinal }
            | Self::UnsignedRadixRecomposition {
                constraint_ordinal, ..
            }
            | Self::ShiftedRadixRecomposition {
                constraint_ordinal, ..
            } => *constraint_ordinal,
            Self::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                ..
            } => *recomposition_constraint_ordinal,
            Self::FiniteIntegerSet {
                constraint_ordinal, ..
            } => *constraint_ordinal,
        }
    }
}

pub(super) fn canonical_unsigned_magnitude_item(
    value: &BigUint,
) -> Result<CanonicalItem, RelationPlanError> {
    let mut magnitude = value.to_bytes_be();
    if value.is_zero() {
        magnitude.clear();
    }
    if !magnitude.is_empty() && magnitude[0] == 0 {
        return Err(RelationPlanError::InvalidSignedMagnitude);
    }
    CanonicalItem::variable_bytes(magnitude).map_err(canonical_encoding_error)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticCellDescriptor {
    pub(super) semantic_cell_ordinal: u32,
    pub(super) column_ordinal: u32,
    pub(super) claimed_interval: SignedIntegerInterval,
    pub(super) bound_certificate: RelationBoundCertificate,
}

impl SemanticCellDescriptor {
    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        checked_resident_payload_add(
            self.claimed_interval.resident_owned_payload_byte_length()?,
            self.bound_certificate
                .resident_owned_payload_byte_length()?,
        )
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        let [minimum, maximum] = self.claimed_interval.canonical_items()?;
        Ok(CanonicalTuple::new(
            SEMANTIC_CELL_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned32(self.semantic_cell_ordinal),
                CanonicalItem::unsigned32(self.column_ordinal),
                minimum,
                maximum,
                CanonicalItem::nested_tuple(&self.bound_certificate.canonical_tuple()?)
                    .map_err(canonical_encoding_error)?,
            ],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationConstraintDescriptor {
    pub(super) constraint_role: u16,
    pub(super) role_coordinates: Vec<u64>,
    pub(super) numerator_postfix_expression: Vec<RelationExpressionInstruction>,
    pub(super) zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
    pub(super) enforce_proof_base_field_no_wrap: bool,
    pub(super) ordered_injective_integer_factor_expressions:
        Vec<Vec<RelationExpressionInstruction>>,
}

impl RelationConstraintDescriptor {
    pub(crate) fn numerator_postfix_expression(&self) -> &[RelationExpressionInstruction] {
        &self.numerator_postfix_expression
    }

    pub(super) fn resident_owned_payload_byte_length(&self) -> Result<u64, RelationPlanError> {
        let expression_payload_byte_length = |expression: &RelationExpressionInstruction| {
            expression.resident_owned_payload_byte_length()
        };
        let mut total = [
            resident_vec_storage_byte_length(&self.role_coordinates)?,
            resident_vec_storage_byte_length(&self.numerator_postfix_expression)?,
            resident_vec_storage_byte_length(&self.zeroifier_postfix_expression)?,
            resident_vec_storage_byte_length(&self.ordered_injective_integer_factor_expressions)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_resident_payload_add)?;
        for expression in self
            .numerator_postfix_expression
            .iter()
            .chain(&self.zeroifier_postfix_expression)
        {
            total =
                checked_resident_payload_add(total, expression_payload_byte_length(expression)?)?;
        }
        for factor_expression in &self.ordered_injective_integer_factor_expressions {
            total = checked_resident_payload_add(
                total,
                resident_vec_storage_byte_length(factor_expression)?,
            )?;
            for expression in factor_expression {
                total = checked_resident_payload_add(
                    total,
                    expression_payload_byte_length(expression)?,
                )?;
            }
        }
        Ok(total)
    }

    pub(super) fn canonical_tuple(&self) -> Result<CanonicalTuple, RelationPlanError> {
        Ok(CanonicalTuple::new(
            RELATION_CONSTRAINT_SCHEMA_IDENTIFIER,
            SCHEMA_VERSION,
            vec![
                CanonicalItem::unsigned16(self.constraint_role),
                canonical_u64_list(&self.role_coordinates)?,
                canonical_nested_list(
                    self.numerator_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                canonical_nested_list(
                    self.zeroifier_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?,
                CanonicalItem::boolean(self.enforce_proof_base_field_no_wrap),
                canonical_nested_list(
                    self.ordered_injective_integer_factor_expressions
                        .iter()
                        .map(|factor_expression| {
                            Ok(CanonicalTuple::new(
                                INJECTIVE_INTEGER_FACTOR_PROGRAM_SCHEMA_IDENTIFIER,
                                SCHEMA_VERSION,
                                vec![canonical_nested_list(
                                    factor_expression
                                        .iter()
                                        .map(RelationExpressionInstruction::canonical_tuple)
                                        .collect::<Result<Vec<_>, _>>()?,
                                )?],
                            ))
                        })
                        .collect::<Result<Vec<_>, RelationPlanError>>()?,
                )?,
            ],
        ))
    }
}
