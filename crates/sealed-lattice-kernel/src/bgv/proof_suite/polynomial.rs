//! Scalar radix-two polynomial arithmetic for the common proof field.
//!
//! The implementation is intentionally single-threaded and allocation-bounded
//! so the same code path is available to native Rust and `wasm32`.

use zeroize::{Zeroize, Zeroizing};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedProofPolynomialTransformStage {
    Resize,
    ForwardCosetScale,
    BitReverse,
    Butterflies,
    InverseNormalize,
    InverseCosetScale,
    TrimInverse,
    Complete,
}

pub(crate) trait ProofTransformValue: Copy + PartialEq + Zeroize {
    const ZERO: Self;

    fn add(self, other: Self) -> Self;
    fn subtract(self, other: Self) -> Self;
    fn multiply_base(self, scalar: ProofBaseFieldElement) -> Self;
}

impl ProofTransformValue for ProofBaseFieldElement {
    const ZERO: Self = Self::ZERO;

    fn add(self, other: Self) -> Self {
        self.add(other)
    }

    fn subtract(self, other: Self) -> Self {
        self.subtract(other)
    }

    fn multiply_base(self, scalar: ProofBaseFieldElement) -> Self {
        self.multiply(scalar)
    }
}

impl ProofTransformValue for ProofChallengeExtensionElement {
    const ZERO: Self = Self::ZERO;

    fn add(self, other: Self) -> Self {
        self.add(other)
    }

    fn subtract(self, other: Self) -> Self {
        self.subtract(other)
    }

    fn multiply_base(self, scalar: ProofBaseFieldElement) -> Self {
        self.multiply_base(scalar)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundedProofPolynomialTransformPoll {
    pub(crate) completed_work_unit_count: u64,
    pub(crate) is_complete: bool,
}

/// Allocation-stable scalar transform whose poll bound covers coefficient
/// initialization, bit reversal, every butterfly, inverse normalization, and
/// coset scaling. The transform owns its one operative buffer and exposes it
/// only after completion.
pub(crate) struct BoundedProofPolynomialTransform<Value>
where
    Value: ProofTransformValue,
{
    values: Zeroizing<Vec<Value>>,
    domain: ProofEvaluationDomain,
    inverse: bool,
    stage: BoundedProofPolynomialTransformStage,
    next_index: usize,
    block_size: usize,
    next_butterfly_index: usize,
    running_coset_power: ProofBaseFieldElement,
    transform_root: ProofBaseFieldElement,
    inverse_size: ProofBaseFieldElement,
}

impl<Value> BoundedProofPolynomialTransform<Value>
where
    Value: ProofTransformValue,
{
    fn begin(
        domain: ProofEvaluationDomain,
        mut values: Zeroizing<Vec<Value>>,
        inverse: bool,
    ) -> Result<Self, ProofPolynomialError> {
        if inverse {
            if values.len() != domain.size {
                return Err(ProofPolynomialError::InputLengthMismatch);
            }
        } else if values.len() > domain.size {
            return Err(ProofPolynomialError::DegreeBoundExceeded);
        } else {
            let missing_value_count = domain.size - values.len();
            values
                .try_reserve_exact(missing_value_count)
                .map_err(|_| ProofPolynomialError::SizeOverflow)?;
        }
        let transform_root = if inverse {
            domain.generator.inverse()?
        } else {
            domain.generator
        };
        let inverse_size = if inverse {
            ProofBaseFieldElement::from_canonical(
                u64::try_from(domain.size).map_err(|_| ProofPolynomialError::SizeOverflow)?,
            )?
            .inverse()?
        } else {
            ProofBaseFieldElement::ONE
        };
        Ok(Self {
            values,
            domain,
            inverse,
            stage: if inverse {
                BoundedProofPolynomialTransformStage::BitReverse
            } else {
                BoundedProofPolynomialTransformStage::Resize
            },
            next_index: 0,
            block_size: 2,
            next_butterfly_index: 0,
            running_coset_power: ProofBaseFieldElement::ONE,
            transform_root,
            inverse_size,
        })
    }

    pub(crate) fn advance(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<BoundedProofPolynomialTransformPoll, ProofPolynomialError> {
        let maximum_work_unit_count = usize::try_from(maximum_work_unit_count)
            .map_err(|_| ProofPolynomialError::SizeOverflow)?;
        if maximum_work_unit_count == 0 {
            return Err(ProofPolynomialError::SizeOverflow);
        }
        let mut completed_work_unit_count = 0_usize;
        loop {
            if self.stage == BoundedProofPolynomialTransformStage::Complete {
                return Ok(BoundedProofPolynomialTransformPoll {
                    completed_work_unit_count: u64::try_from(completed_work_unit_count)
                        .map_err(|_| ProofPolynomialError::SizeOverflow)?,
                    is_complete: true,
                });
            }
            if completed_work_unit_count == maximum_work_unit_count {
                return Ok(BoundedProofPolynomialTransformPoll {
                    completed_work_unit_count: u64::try_from(completed_work_unit_count)
                        .map_err(|_| ProofPolynomialError::SizeOverflow)?,
                    is_complete: false,
                });
            }
            let remaining_work_unit_count = maximum_work_unit_count
                .checked_sub(completed_work_unit_count)
                .ok_or(ProofPolynomialError::SizeOverflow)?;
            match self.stage {
                BoundedProofPolynomialTransformStage::Resize => {
                    let appended_count =
                        (self.domain.size - self.values.len()).min(remaining_work_unit_count);
                    self.values
                        .extend(core::iter::repeat_n(Value::ZERO, appended_count));
                    completed_work_unit_count += appended_count;
                    if self.values.len() == self.domain.size {
                        self.stage = BoundedProofPolynomialTransformStage::ForwardCosetScale;
                    }
                }
                BoundedProofPolynomialTransformStage::ForwardCosetScale => {
                    let end = self
                        .next_index
                        .saturating_add(remaining_work_unit_count)
                        .min(self.domain.size);
                    for value in &mut self.values[self.next_index..end] {
                        *value = value.multiply_base(self.running_coset_power);
                        self.running_coset_power =
                            self.running_coset_power.multiply(self.domain.coset_offset);
                    }
                    completed_work_unit_count += end - self.next_index;
                    self.next_index = end;
                    if end == self.domain.size {
                        self.next_index = 0;
                        self.stage = BoundedProofPolynomialTransformStage::BitReverse;
                    }
                }
                BoundedProofPolynomialTransformStage::BitReverse => {
                    let end = self
                        .next_index
                        .saturating_add(remaining_work_unit_count)
                        .min(self.domain.size);
                    let bit_count = self.domain.size.trailing_zeros();
                    for index in self.next_index..end {
                        let reversed = index.reverse_bits() >> (usize::BITS - bit_count);
                        if reversed > index {
                            self.values.swap(index, reversed);
                        }
                    }
                    completed_work_unit_count += end - self.next_index;
                    self.next_index = end;
                    if end == self.domain.size {
                        self.next_index = 0;
                        self.stage = BoundedProofPolynomialTransformStage::Butterflies;
                    }
                }
                BoundedProofPolynomialTransformStage::Butterflies => {
                    let butterfly_count = self.domain.size / 2;
                    let end = self
                        .next_butterfly_index
                        .saturating_add(remaining_work_unit_count)
                        .min(butterfly_count);
                    let half_block_size = self.block_size / 2;
                    let twiddle_step = self.transform_root.power(
                        u64::try_from(self.domain.size / self.block_size)
                            .map_err(|_| ProofPolynomialError::SizeOverflow)?,
                    );
                    let mut butterfly_index = self.next_butterfly_index;
                    while butterfly_index < end {
                        let block_index = butterfly_index / half_block_size;
                        let within_block_index = butterfly_index % half_block_size;
                        let block_end = end.min(
                            block_index
                                .checked_add(1)
                                .and_then(|index| index.checked_mul(half_block_size))
                                .ok_or(ProofPolynomialError::SizeOverflow)?,
                        );
                        let mut twiddle = twiddle_step.power(
                            u64::try_from(within_block_index)
                                .map_err(|_| ProofPolynomialError::SizeOverflow)?,
                        );
                        while butterfly_index < block_end {
                            let local_index = butterfly_index % half_block_size;
                            let left_index = block_index
                                .checked_mul(self.block_size)
                                .and_then(|offset| offset.checked_add(local_index))
                                .ok_or(ProofPolynomialError::SizeOverflow)?;
                            let right_index = left_index
                                .checked_add(half_block_size)
                                .ok_or(ProofPolynomialError::SizeOverflow)?;
                            let left = self.values[left_index];
                            let right = self.values[right_index].multiply_base(twiddle);
                            self.values[left_index] = left.add(right);
                            self.values[right_index] = left.subtract(right);
                            twiddle = twiddle.multiply(twiddle_step);
                            butterfly_index += 1;
                        }
                    }
                    completed_work_unit_count += end - self.next_butterfly_index;
                    self.next_butterfly_index = end;
                    if end == butterfly_count {
                        self.next_butterfly_index = 0;
                        self.block_size = self
                            .block_size
                            .checked_mul(2)
                            .ok_or(ProofPolynomialError::SizeOverflow)?;
                        if self.block_size > self.domain.size {
                            self.stage = if self.inverse {
                                BoundedProofPolynomialTransformStage::InverseNormalize
                            } else {
                                BoundedProofPolynomialTransformStage::Complete
                            };
                        }
                    }
                }
                BoundedProofPolynomialTransformStage::InverseNormalize => {
                    let end = self
                        .next_index
                        .saturating_add(remaining_work_unit_count)
                        .min(self.domain.size);
                    for value in &mut self.values[self.next_index..end] {
                        *value = value.multiply_base(self.inverse_size);
                    }
                    completed_work_unit_count += end - self.next_index;
                    self.next_index = end;
                    if end == self.domain.size {
                        self.next_index = 0;
                        self.running_coset_power = ProofBaseFieldElement::ONE;
                        self.stage = BoundedProofPolynomialTransformStage::InverseCosetScale;
                    }
                }
                BoundedProofPolynomialTransformStage::InverseCosetScale => {
                    let end = self
                        .next_index
                        .saturating_add(remaining_work_unit_count)
                        .min(self.domain.size);
                    let offset_inverse = self.domain.coset_offset.inverse()?;
                    for value in &mut self.values[self.next_index..end] {
                        *value = value.multiply_base(self.running_coset_power);
                        self.running_coset_power =
                            self.running_coset_power.multiply(offset_inverse);
                    }
                    completed_work_unit_count += end - self.next_index;
                    self.next_index = end;
                    if end == self.domain.size {
                        self.stage = BoundedProofPolynomialTransformStage::TrimInverse;
                    }
                }
                BoundedProofPolynomialTransformStage::TrimInverse => {
                    let mut inspected_count = 0_usize;
                    while inspected_count < remaining_work_unit_count {
                        inspected_count += 1;
                        if self.values.len() == 1 || self.values.last() != Some(&Value::ZERO) {
                            self.stage = BoundedProofPolynomialTransformStage::Complete;
                            break;
                        }
                        self.values.pop();
                    }
                    completed_work_unit_count += inspected_count;
                }
                BoundedProofPolynomialTransformStage::Complete => unreachable!(),
            }
        }
    }

    pub(crate) fn into_values(mut self) -> Result<Zeroizing<Vec<Value>>, ProofPolynomialError> {
        if self.stage != BoundedProofPolynomialTransformStage::Complete {
            return Err(ProofPolynomialError::InputLengthMismatch);
        }
        Ok(core::mem::take(&mut self.values))
    }
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

    pub(crate) fn begin_bounded_base_evaluation(
        self,
        values: Zeroizing<Vec<ProofBaseFieldElement>>,
    ) -> Result<BoundedProofPolynomialTransform<ProofBaseFieldElement>, ProofPolynomialError> {
        BoundedProofPolynomialTransform::begin(self, values, false)
    }

    pub(crate) fn begin_bounded_extension_evaluation(
        self,
        values: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<BoundedProofPolynomialTransform<ProofChallengeExtensionElement>, ProofPolynomialError>
    {
        BoundedProofPolynomialTransform::begin(self, values, false)
    }

    pub(crate) fn begin_bounded_extension_interpolation(
        self,
        values: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ) -> Result<BoundedProofPolynomialTransform<ProofChallengeExtensionElement>, ProofPolynomialError>
    {
        BoundedProofPolynomialTransform::begin(self, values, true)
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
    fn bounded_transforms_match_canonical_bytes_under_aggressive_poll_budgets() {
        for size in [2_usize, 8, 64] {
            let domain = ProofEvaluationDomain::new(size, PROOF_EVALUATION_COSET_OFFSET)
                .expect("valid proof domain");
            let base_coefficients = (0..size / 2 + 1)
                .map(|index| base((index as u64 + 3).pow(3)))
                .collect::<Vec<_>>();
            let extension_coefficients = (0..size / 2 + 1)
                .map(|index| {
                    extension([
                        index as u64 + 1,
                        index as u64 * 2 + 3,
                        index as u64 * 5 + 7,
                        index as u64 * 11 + 13,
                        index as u64 * 17 + 19,
                    ])
                })
                .collect::<Vec<_>>();
            let expected_base_evaluations = domain
                .evaluate_base_polynomial(&base_coefficients)
                .expect("canonical base evaluation");
            let expected_extension_evaluations = domain
                .evaluate_extension_polynomial(&extension_coefficients)
                .expect("canonical extension evaluation");
            let butterfly_count = size / 2 * size.ilog2() as usize;
            let expected_forward_work_unit_count =
                (size - base_coefficients.len()) + size + size + butterfly_count;
            let expected_inverse_work_unit_count =
                size + butterfly_count + size + size + (size - extension_coefficients.len()) + 1;

            for maximum_work_unit_count in [1_u64, 2, 3, 17, 257] {
                let mut base_transform = domain
                    .begin_bounded_base_evaluation(Zeroizing::new(base_coefficients.clone()))
                    .expect("bounded base evaluation");
                let mut observed_base_work_unit_count = 0_u64;
                loop {
                    let poll = base_transform
                        .advance(maximum_work_unit_count)
                        .expect("bounded base poll");
                    assert!(poll.completed_work_unit_count > 0);
                    assert!(poll.completed_work_unit_count <= maximum_work_unit_count);
                    observed_base_work_unit_count += poll.completed_work_unit_count;
                    if poll.is_complete {
                        break;
                    }
                }
                assert_eq!(
                    observed_base_work_unit_count,
                    expected_forward_work_unit_count as u64,
                );
                assert_eq!(
                    base_transform
                        .into_values()
                        .expect("completed base transform")
                        .as_slice(),
                    expected_base_evaluations,
                );

                let mut extension_transform = domain
                    .begin_bounded_extension_evaluation(Zeroizing::new(
                        extension_coefficients.clone(),
                    ))
                    .expect("bounded extension evaluation");
                loop {
                    let poll = extension_transform
                        .advance(maximum_work_unit_count)
                        .expect("bounded extension poll");
                    assert!(poll.completed_work_unit_count > 0);
                    assert!(poll.completed_work_unit_count <= maximum_work_unit_count);
                    if poll.is_complete {
                        break;
                    }
                }
                assert_eq!(
                    extension_transform
                        .into_values()
                        .expect("completed extension transform")
                        .as_slice(),
                    expected_extension_evaluations,
                );

                let mut inverse_transform = domain
                    .begin_bounded_extension_interpolation(Zeroizing::new(
                        expected_extension_evaluations.clone(),
                    ))
                    .expect("bounded extension interpolation");
                let mut observed_inverse_work_unit_count = 0_u64;
                loop {
                    let poll = inverse_transform
                        .advance(maximum_work_unit_count)
                        .expect("bounded inverse poll");
                    assert!(poll.completed_work_unit_count > 0);
                    assert!(poll.completed_work_unit_count <= maximum_work_unit_count);
                    observed_inverse_work_unit_count += poll.completed_work_unit_count;
                    if poll.is_complete {
                        break;
                    }
                }
                assert_eq!(
                    observed_inverse_work_unit_count,
                    expected_inverse_work_unit_count as u64,
                );
                assert_eq!(
                    inverse_transform
                        .into_values()
                        .expect("completed inverse transform")
                        .as_slice(),
                    extension_coefficients,
                );
            }
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
