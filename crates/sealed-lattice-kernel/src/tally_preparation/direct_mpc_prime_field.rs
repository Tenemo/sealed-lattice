use core::fmt;

pub(crate) const DIRECT_MPC_PRIME_FIELD_MODULUS: u32 = 65_537;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMpcPrimeFieldError {
    CanonicalByteLength { expected: usize, actual: usize },
    NonCanonicalValue { value: u32 },
    ZeroHasNoMultiplicativeInverse,
    InterpolationDomainTooLarge { value_count: usize },
}

impl fmt::Display for DirectMpcPrimeFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalByteLength { expected, actual } => write!(
                formatter,
                "direct MPC field element has {actual} bytes; expected {expected}"
            ),
            Self::NonCanonicalValue { value } => write!(
                formatter,
                "direct MPC field value {value} is not below {DIRECT_MPC_PRIME_FIELD_MODULUS}"
            ),
            Self::ZeroHasNoMultiplicativeInverse => {
                formatter.write_str("zero has no multiplicative inverse in the direct MPC field")
            }
            Self::InterpolationDomainTooLarge { value_count } => write!(
                formatter,
                "direct MPC interpolation domain of {value_count} points does not fit the field"
            ),
        }
    }
}

impl std::error::Error for DirectMpcPrimeFieldError {}

/// Scalar prime-field element used only by the unactivated direct-MPC route.
///
/// The canonical representation is exactly three little-endian bytes. The
/// small Fermat prime is an arithmetic representation, not a computational
/// security parameter: privacy comes from degree-three Shamir sharing, while
/// every probabilistic field check carries its own repetition bound.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DirectMpcPrimeFieldElement(u32);

impl DirectMpcPrimeFieldElement {
    pub(crate) const CANONICAL_BYTE_LENGTH: usize = 3;
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);

    pub(crate) fn from_canonical_u32(value: u32) -> Result<Self, DirectMpcPrimeFieldError> {
        if value >= DIRECT_MPC_PRIME_FIELD_MODULUS {
            return Err(DirectMpcPrimeFieldError::NonCanonicalValue { value });
        }
        Ok(Self(value))
    }

    pub(crate) const fn from_u16(value: u16) -> Self {
        Self(value as u32)
    }

    pub(crate) fn from_u64_reduced(value: u64) -> Self {
        Self((value % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS)) as u32)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DirectMpcPrimeFieldError> {
        if bytes.len() != Self::CANONICAL_BYTE_LENGTH {
            return Err(DirectMpcPrimeFieldError::CanonicalByteLength {
                expected: Self::CANONICAL_BYTE_LENGTH,
                actual: bytes.len(),
            });
        }
        let value = u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16);
        Self::from_canonical_u32(value)
    }

    pub(crate) const fn canonical_u32(self) -> u32 {
        self.0
    }

    pub(crate) const fn canonical_bytes(self) -> [u8; Self::CANONICAL_BYTE_LENGTH] {
        let bytes = self.0.to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    }

    pub(crate) fn add(self, right: Self) -> Self {
        let sum = self.0 + right.0;
        if sum >= DIRECT_MPC_PRIME_FIELD_MODULUS {
            Self(sum - DIRECT_MPC_PRIME_FIELD_MODULUS)
        } else {
            Self(sum)
        }
    }

    pub(crate) fn subtract(self, right: Self) -> Self {
        if self.0 >= right.0 {
            Self(self.0 - right.0)
        } else {
            Self(DIRECT_MPC_PRIME_FIELD_MODULUS - (right.0 - self.0))
        }
    }

    pub(crate) fn negate(self) -> Self {
        if self == Self::ZERO {
            Self::ZERO
        } else {
            Self(DIRECT_MPC_PRIME_FIELD_MODULUS - self.0)
        }
    }

    pub(crate) fn multiply(self, right: Self) -> Self {
        Self::from_u64_reduced(u64::from(self.0) * u64::from(right.0))
    }

    pub(crate) fn power(self, mut exponent: u32) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result.multiply(base);
            }
            exponent >>= 1;
            if exponent > 0 {
                base = base.multiply(base);
            }
        }
        result
    }

    pub(crate) fn multiplicative_inverse(self) -> Result<Self, DirectMpcPrimeFieldError> {
        if self == Self::ZERO {
            return Err(DirectMpcPrimeFieldError::ZeroHasNoMultiplicativeInverse);
        }
        Ok(self.power(DIRECT_MPC_PRIME_FIELD_MODULUS - 2))
    }
}

impl fmt::Debug for DirectMpcPrimeFieldElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Returns power-basis coefficients for values at the consecutive points
/// `0, 1, ..., values.len() - 1`.
pub(crate) fn interpolate_consecutive_prime_field_values(
    values: &[DirectMpcPrimeFieldElement],
) -> Result<Box<[DirectMpcPrimeFieldElement]>, DirectMpcPrimeFieldError> {
    if values.len() >= DIRECT_MPC_PRIME_FIELD_MODULUS as usize {
        return Err(DirectMpcPrimeFieldError::InterpolationDomainTooLarge {
            value_count: values.len(),
        });
    }
    if values.is_empty() {
        return Ok(Box::new([]));
    }

    let mut forward_differences = values.to_vec();
    let mut newton_coefficients = Vec::with_capacity(values.len());
    for order in 0..values.len() {
        newton_coefficients.push(forward_differences[0]);
        let remaining_difference_count = values.len() - order - 1;
        for position in 0..remaining_difference_count {
            forward_differences[position] =
                forward_differences[position + 1].subtract(forward_differences[position]);
        }
    }

    let mut power_basis_coefficients = vec![DirectMpcPrimeFieldElement::ZERO; values.len()];
    let mut falling_factorial = vec![DirectMpcPrimeFieldElement::ONE];
    let mut inverse_factorial = DirectMpcPrimeFieldElement::ONE;

    for (order, newton_coefficient) in newton_coefficients.into_iter().enumerate() {
        if order > 0 {
            let root = DirectMpcPrimeFieldElement::from_u64_reduced((order - 1) as u64);
            falling_factorial = multiply_polynomial_by_linear_factor(&falling_factorial, root);
            inverse_factorial = inverse_factorial.multiply(
                DirectMpcPrimeFieldElement::from_u64_reduced(order as u64)
                    .multiplicative_inverse()?,
            );
        }
        let scale = newton_coefficient.multiply(inverse_factorial);
        for (power, coefficient) in falling_factorial.iter().copied().enumerate() {
            power_basis_coefficients[power] =
                power_basis_coefficients[power].add(coefficient.multiply(scale));
        }
    }

    Ok(power_basis_coefficients.into_boxed_slice())
}

pub(crate) fn evaluate_prime_field_polynomial(
    coefficients: &[DirectMpcPrimeFieldElement],
    value: DirectMpcPrimeFieldElement,
) -> DirectMpcPrimeFieldElement {
    coefficients.iter().rev().copied().fold(
        DirectMpcPrimeFieldElement::ZERO,
        |evaluation, coefficient| evaluation.multiply(value).add(coefficient),
    )
}

fn multiply_polynomial_by_linear_factor(
    coefficients: &[DirectMpcPrimeFieldElement],
    root: DirectMpcPrimeFieldElement,
) -> Vec<DirectMpcPrimeFieldElement> {
    let mut product = vec![DirectMpcPrimeFieldElement::ZERO; coefficients.len() + 1];
    for (power, coefficient) in coefficients.iter().copied().enumerate() {
        product[power] = product[power].subtract(coefficient.multiply(root));
        product[power + 1] = product[power + 1].add(coefficient);
    }
    product
}
