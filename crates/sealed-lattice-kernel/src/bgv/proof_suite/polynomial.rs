//! Scalar radix-two polynomial arithmetic for the common proof field.
//!
//! The implementation is intentionally single-threaded and allocation-bounded
//! so the same code path is available to native Rust and `wasm32`.

use super::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS, ProofBaseFieldElement,
    ProofChallengeExtensionElement, ProofFieldError,
};

const PROOF_BASE_FIELD_TWO_ADICITY: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofPolynomialError {
    InvalidDomainSize,
    InvalidCosetOffset,
    InputLengthMismatch,
    DegreeBoundExceeded,
    SizeOverflow,
    Field(ProofFieldError),
}

impl From<ProofFieldError> for ProofPolynomialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofEvaluationDomain {
    size: usize,
    generator: ProofBaseFieldElement,
    coset_offset: ProofBaseFieldElement,
}

impl ProofEvaluationDomain {
    pub(crate) fn new(size: usize, coset_offset: u64) -> Result<Self, ProofPolynomialError> {
        Self::with_offset(size, coset_offset, false)
    }

    pub(crate) fn new_subgroup(size: usize) -> Result<Self, ProofPolynomialError> {
        Self::with_offset(size, 1, true)
    }

    fn with_offset(
        size: usize,
        coset_offset: u64,
        allow_subgroup: bool,
    ) -> Result<Self, ProofPolynomialError> {
        if size < 2 || !size.is_power_of_two() {
            return Err(ProofPolynomialError::InvalidDomainSize);
        }
        let logarithmic_size = size.trailing_zeros();
        if logarithmic_size > PROOF_BASE_FIELD_TWO_ADICITY {
            return Err(ProofPolynomialError::InvalidDomainSize);
        }
        let root_exponent = 1_u64
            .checked_shl(PROOF_BASE_FIELD_TWO_ADICITY - logarithmic_size)
            .ok_or(ProofPolynomialError::InvalidDomainSize)?;
        let maximum_generator =
            ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR)?;
        let generator = maximum_generator.power(root_exponent);
        let offset = ProofBaseFieldElement::from_canonical(coset_offset)?;
        if offset == ProofBaseFieldElement::ZERO
            || (!allow_subgroup
                && offset
                    .power(u64::try_from(size).map_err(|_| ProofPolynomialError::SizeOverflow)?)
                    == ProofBaseFieldElement::ONE)
        {
            return Err(ProofPolynomialError::InvalidCosetOffset);
        }
        let size_exponent = u64::try_from(size).map_err(|_| ProofPolynomialError::SizeOverflow)?;
        if generator.power(size_exponent) != ProofBaseFieldElement::ONE
            || generator.power(size_exponent / 2)
                != ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS - 1)?
        {
            return Err(ProofPolynomialError::InvalidDomainSize);
        }
        Ok(Self {
            size,
            generator,
            coset_offset: offset,
        })
    }

    pub(crate) const fn size(self) -> usize {
        self.size
    }

    pub(crate) const fn generator(self) -> ProofBaseFieldElement {
        self.generator
    }

    pub(crate) const fn coset_offset(self) -> ProofBaseFieldElement {
        self.coset_offset
    }

    pub(crate) fn point(
        self,
        position: usize,
    ) -> Result<ProofBaseFieldElement, ProofPolynomialError> {
        if position >= self.size {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        Ok(self.coset_offset.multiply(
            self.generator
                .power(u64::try_from(position).map_err(|_| ProofPolynomialError::SizeOverflow)?),
        ))
    }

    pub(crate) fn evaluate_base_polynomial(
        self,
        coefficients: &[ProofBaseFieldElement],
    ) -> Result<Vec<ProofBaseFieldElement>, ProofPolynomialError> {
        if coefficients.len() > self.size {
            return Err(ProofPolynomialError::DegreeBoundExceeded);
        }
        let mut evaluations = vec![ProofBaseFieldElement::ZERO; self.size];
        let mut offset_power = ProofBaseFieldElement::ONE;
        for (destination, coefficient) in evaluations.iter_mut().zip(coefficients) {
            *destination = coefficient.multiply(offset_power);
            offset_power = offset_power.multiply(self.coset_offset);
        }
        radix_two_base_transform(&mut evaluations, self.generator, false)?;
        Ok(evaluations)
    }

    /// Converts one owned base-field coefficient buffer into evaluations in
    /// place. The buffer is extended to the domain size before the transform,
    /// so streaming family adapters never retain a second whole-domain copy.
    pub(crate) fn evaluate_base_polynomial_in_place(
        self,
        coefficients: &mut Vec<ProofBaseFieldElement>,
    ) -> Result<(), ProofPolynomialError> {
        if coefficients.len() > self.size {
            return Err(ProofPolynomialError::DegreeBoundExceeded);
        }
        coefficients.resize(self.size, ProofBaseFieldElement::ZERO);
        let mut offset_power = ProofBaseFieldElement::ONE;
        for coefficient in coefficients.iter_mut() {
            *coefficient = coefficient.multiply(offset_power);
            offset_power = offset_power.multiply(self.coset_offset);
        }
        radix_two_base_transform(coefficients, self.generator, false)
    }

    pub(crate) fn interpolate_base_polynomial(
        self,
        evaluations: &[ProofBaseFieldElement],
    ) -> Result<Vec<ProofBaseFieldElement>, ProofPolynomialError> {
        if evaluations.len() != self.size {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        let mut coefficients = evaluations.to_vec();
        radix_two_base_transform(&mut coefficients, self.generator, true)?;
        let offset_inverse = self.coset_offset.inverse()?;
        let mut offset_inverse_power = ProofBaseFieldElement::ONE;
        for coefficient in &mut coefficients {
            *coefficient = coefficient.multiply(offset_inverse_power);
            offset_inverse_power = offset_inverse_power.multiply(offset_inverse);
        }
        trim_trailing_base_zeroes(&mut coefficients);
        Ok(coefficients)
    }

    /// Converts one owned base-field evaluation buffer into coefficients in
    /// place. This is the generation path for replayed relation columns, where
    /// retaining a second trace-sized allocation would defeat streaming
    /// custody.
    pub(crate) fn interpolate_base_polynomial_in_place(
        self,
        evaluations: &mut Vec<ProofBaseFieldElement>,
    ) -> Result<(), ProofPolynomialError> {
        if evaluations.len() != self.size {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        radix_two_base_transform(evaluations, self.generator, true)?;
        let offset_inverse = self.coset_offset.inverse()?;
        let mut offset_inverse_power = ProofBaseFieldElement::ONE;
        for coefficient in evaluations.iter_mut() {
            *coefficient = coefficient.multiply(offset_inverse_power);
            offset_inverse_power = offset_inverse_power.multiply(offset_inverse);
        }
        trim_trailing_base_zeroes(evaluations);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn evaluate_extension_polynomial(
        self,
        coefficients: &[ProofChallengeExtensionElement],
    ) -> Result<Vec<ProofChallengeExtensionElement>, ProofPolynomialError> {
        if coefficients.len() > self.size {
            return Err(ProofPolynomialError::DegreeBoundExceeded);
        }
        let mut evaluations = vec![ProofChallengeExtensionElement::ZERO; self.size];
        let mut offset_power = ProofBaseFieldElement::ONE;
        for (destination, coefficient) in evaluations.iter_mut().zip(coefficients) {
            *destination = coefficient.multiply_base(offset_power);
            offset_power = offset_power.multiply(self.coset_offset);
        }
        radix_two_extension_transform(&mut evaluations, self.generator, false)?;
        Ok(evaluations)
    }

    /// Converts one owned coefficient buffer into its evaluation vector in
    /// place. The caller does not retain a second whole-domain coefficient
    /// vector while the transform is resident.
    pub(crate) fn evaluate_extension_polynomial_in_place(
        self,
        coefficients: &mut Vec<ProofChallengeExtensionElement>,
    ) -> Result<(), ProofPolynomialError> {
        if coefficients.len() > self.size {
            return Err(ProofPolynomialError::DegreeBoundExceeded);
        }
        coefficients.resize(self.size, ProofChallengeExtensionElement::ZERO);
        let mut offset_power = ProofBaseFieldElement::ONE;
        for coefficient in coefficients.iter_mut() {
            *coefficient = coefficient.multiply_base(offset_power);
            offset_power = offset_power.multiply(self.coset_offset);
        }
        radix_two_extension_transform(coefficients, self.generator, false)
    }

    #[cfg(test)]
    pub(crate) fn interpolate_extension_polynomial(
        self,
        evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<Vec<ProofChallengeExtensionElement>, ProofPolynomialError> {
        if evaluations.len() != self.size {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        let mut coefficients = evaluations.to_vec();
        radix_two_extension_transform(&mut coefficients, self.generator, true)?;
        let offset_inverse = self.coset_offset.inverse()?;
        let mut offset_inverse_power = ProofBaseFieldElement::ONE;
        for coefficient in &mut coefficients {
            *coefficient = coefficient.multiply_base(offset_inverse_power);
            offset_inverse_power = offset_inverse_power.multiply(offset_inverse);
        }
        trim_trailing_extension_zeroes(&mut coefficients);
        Ok(coefficients)
    }

    /// Converts one owned evaluation vector into coefficients in place.
    pub(crate) fn interpolate_extension_polynomial_in_place(
        self,
        evaluations: &mut Vec<ProofChallengeExtensionElement>,
    ) -> Result<(), ProofPolynomialError> {
        if evaluations.len() != self.size {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        radix_two_extension_transform(evaluations, self.generator, true)?;
        let offset_inverse = self.coset_offset.inverse()?;
        let mut offset_inverse_power = ProofBaseFieldElement::ONE;
        for coefficient in evaluations.iter_mut() {
            *coefficient = coefficient.multiply_base(offset_inverse_power);
            offset_inverse_power = offset_inverse_power.multiply(offset_inverse);
        }
        trim_trailing_extension_zeroes(evaluations);
        Ok(())
    }
}

pub(crate) fn evaluate_extension_at(
    coefficients: &[ProofChallengeExtensionElement],
    point: ProofChallengeExtensionElement,
) -> ProofChallengeExtensionElement {
    coefficients.iter().rev().fold(
        ProofChallengeExtensionElement::ZERO,
        |accumulated, coefficient| accumulated.multiply(point).add(*coefficient),
    )
}

fn radix_two_base_transform(
    values: &mut [ProofBaseFieldElement],
    root: ProofBaseFieldElement,
    inverse: bool,
) -> Result<(), ProofPolynomialError> {
    if values.len() < 2 || !values.len().is_power_of_two() {
        return Err(ProofPolynomialError::InvalidDomainSize);
    }
    bit_reverse_permute(values);
    let transform_root = if inverse { root.inverse()? } else { root };
    let mut block_size = 2_usize;
    while block_size <= values.len() {
        let twiddle_step = transform_root.power(
            u64::try_from(values.len() / block_size)
                .map_err(|_| ProofPolynomialError::SizeOverflow)?,
        );
        for block_start in (0..values.len()).step_by(block_size) {
            let mut twiddle = ProofBaseFieldElement::ONE;
            for offset in 0..block_size / 2 {
                let left = values[block_start + offset];
                let right = values[block_start + offset + block_size / 2].multiply(twiddle);
                values[block_start + offset] = left.add(right);
                values[block_start + offset + block_size / 2] = left.subtract(right);
                twiddle = twiddle.multiply(twiddle_step);
            }
        }
        block_size = block_size
            .checked_mul(2)
            .ok_or(ProofPolynomialError::SizeOverflow)?;
    }
    if inverse {
        let inverse_size = ProofBaseFieldElement::from_canonical(
            u64::try_from(values.len()).map_err(|_| ProofPolynomialError::SizeOverflow)?,
        )?
        .inverse()?;
        for value in values {
            *value = value.multiply(inverse_size);
        }
    }
    Ok(())
}

fn radix_two_extension_transform(
    values: &mut [ProofChallengeExtensionElement],
    root: ProofBaseFieldElement,
    inverse: bool,
) -> Result<(), ProofPolynomialError> {
    if values.len() < 2 || !values.len().is_power_of_two() {
        return Err(ProofPolynomialError::InvalidDomainSize);
    }
    bit_reverse_permute(values);
    let transform_root = if inverse { root.inverse()? } else { root };
    let mut block_size = 2_usize;
    while block_size <= values.len() {
        let twiddle_step = transform_root.power(
            u64::try_from(values.len() / block_size)
                .map_err(|_| ProofPolynomialError::SizeOverflow)?,
        );
        for block_start in (0..values.len()).step_by(block_size) {
            let mut twiddle = ProofBaseFieldElement::ONE;
            for offset in 0..block_size / 2 {
                let left = values[block_start + offset];
                let right = values[block_start + offset + block_size / 2].multiply_base(twiddle);
                values[block_start + offset] = left.add(right);
                values[block_start + offset + block_size / 2] = left.subtract(right);
                twiddle = twiddle.multiply(twiddle_step);
            }
        }
        block_size = block_size
            .checked_mul(2)
            .ok_or(ProofPolynomialError::SizeOverflow)?;
    }
    if inverse {
        let inverse_size = ProofBaseFieldElement::from_canonical(
            u64::try_from(values.len()).map_err(|_| ProofPolynomialError::SizeOverflow)?,
        )?
        .inverse()?;
        for value in values {
            *value = value.multiply_base(inverse_size);
        }
    }
    Ok(())
}

fn bit_reverse_permute<Value>(values: &mut [Value]) {
    let bit_count = values.len().trailing_zeros();
    for index in 0..values.len() {
        let reversed = index.reverse_bits() >> (usize::BITS - bit_count);
        if reversed > index {
            values.swap(index, reversed);
        }
    }
}

fn trim_trailing_base_zeroes(coefficients: &mut Vec<ProofBaseFieldElement>) {
    while coefficients.len() > 1 && coefficients.last() == Some(&ProofBaseFieldElement::ZERO) {
        coefficients.pop();
    }
}

fn trim_trailing_extension_zeroes(coefficients: &mut Vec<ProofChallengeExtensionElement>) {
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofChallengeExtensionElement::ZERO)
    {
        coefficients.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::PROOF_EVALUATION_COSET_OFFSET;

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("test value is canonical")
    }

    fn extension(values: [u64; 5]) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates(values)
            .expect("test coordinates are canonical")
    }

    #[test]
    fn base_and_extension_coset_transforms_round_trip() {
        for size in [2_usize, 4, 8, 16, 64] {
            let domain = ProofEvaluationDomain::new(size, PROOF_EVALUATION_COSET_OFFSET)
                .expect("valid proof domain");
            let base_coefficients = (0..size / 2 + 1)
                .map(|index| base((index as u64 + 1).pow(3)))
                .collect::<Vec<_>>();
            let base_evaluations = domain
                .evaluate_base_polynomial(&base_coefficients)
                .expect("base evaluation");
            let mut in_place_base_coefficients = base_coefficients.clone();
            domain
                .evaluate_base_polynomial_in_place(&mut in_place_base_coefficients)
                .expect("in-place base evaluation");
            assert_eq!(in_place_base_coefficients, base_evaluations);
            assert_eq!(
                domain
                    .interpolate_base_polynomial(&base_evaluations)
                    .expect("base interpolation"),
                base_coefficients,
            );
            let mut in_place_base_evaluations = base_evaluations;
            domain
                .interpolate_base_polynomial_in_place(&mut in_place_base_evaluations)
                .expect("in-place base interpolation");
            assert_eq!(in_place_base_evaluations, base_coefficients);

            let extension_coefficients = (0..size / 2 + 1)
                .map(|index| {
                    extension([
                        index as u64 + 1,
                        index as u64 * 2,
                        index as u64 * 3,
                        index as u64 * 5,
                        index as u64 * 7,
                    ])
                })
                .collect::<Vec<_>>();
            let extension_evaluations = domain
                .evaluate_extension_polynomial(&extension_coefficients)
                .expect("extension evaluation");
            let mut in_place_extension_coefficients = extension_coefficients.clone();
            domain
                .evaluate_extension_polynomial_in_place(&mut in_place_extension_coefficients)
                .expect("in-place extension evaluation");
            assert_eq!(in_place_extension_coefficients, extension_evaluations);
            assert_eq!(
                domain
                    .interpolate_extension_polynomial(&extension_evaluations)
                    .expect("extension interpolation"),
                extension_coefficients,
            );
        }
    }

    #[test]
    fn domains_refuse_subgroups_as_coset_offsets_and_oversized_inputs() {
        assert_eq!(
            ProofEvaluationDomain::new(8, 1),
            Err(ProofPolynomialError::InvalidCosetOffset),
        );
        let domain = ProofEvaluationDomain::new(8, PROOF_EVALUATION_COSET_OFFSET)
            .expect("valid proof domain");
        assert_eq!(
            domain.evaluate_base_polynomial(&[ProofBaseFieldElement::ONE; 9]),
            Err(ProofPolynomialError::DegreeBoundExceeded),
        );
    }
}
