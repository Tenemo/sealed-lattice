use crate::foundation::RefusalReason;
use zeroize::Zeroize;

use super::{ProtocolRefusal, ProtocolResult};

pub(crate) const PARTICIPANT_COUNT: usize = 10;
pub(crate) const CORRUPTION_BOUND: usize = 3;
pub(crate) const PRODUCT_DEGREE: usize = CORRUPTION_BOUND * 2;
pub(crate) const DIRECT_CHECK_REPETITION_COUNT: usize = 384;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FieldElement(u8);

impl FieldElement {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);

    pub(crate) const fn new(value: u8) -> Option<Self> {
        if value < 16 { Some(Self(value)) } else { None }
    }

    pub(crate) const fn value(self) -> u8 {
        self.0
    }

    pub(crate) const fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    pub(crate) fn multiply(self, other: Self) -> Self {
        let left_0 = self.0 & 1;
        let left_1 = (self.0 >> 1) & 1;
        let left_2 = (self.0 >> 2) & 1;
        let left_3 = (self.0 >> 3) & 1;
        let right_0 = other.0 & 1;
        let right_1 = (other.0 >> 1) & 1;
        let right_2 = (other.0 >> 2) & 1;
        let right_3 = (other.0 >> 3) & 1;

        let product_0 = left_0 & right_0;
        let product_1 = (left_0 & right_1) ^ (left_1 & right_0);
        let product_2 = (left_0 & right_2) ^ (left_1 & right_1) ^ (left_2 & right_0);
        let product_3 =
            (left_0 & right_3) ^ (left_1 & right_2) ^ (left_2 & right_1) ^ (left_3 & right_0);
        let product_4 = (left_1 & right_3) ^ (left_2 & right_2) ^ (left_3 & right_1);
        let product_5 = (left_2 & right_3) ^ (left_3 & right_2);
        let product_6 = left_3 & right_3;

        Self(
            (product_0 ^ product_4)
                | ((product_1 ^ product_4 ^ product_5) << 1)
                | ((product_2 ^ product_5 ^ product_6) << 2)
                | ((product_3 ^ product_6) << 3),
        )
    }

    pub(crate) fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        let mut exponent = 14_u8;
        let mut value = self;
        let mut result = Self::ONE;
        while exponent > 0 {
            let selected = 0_u8.wrapping_sub(exponent & 1);
            let multiplied = result.multiply(value);
            result = Self((result.0 & !selected) | (multiplied.0 & selected));
            value = value.multiply(value);
            exponent >>= 1;
        }
        Some(result)
    }
}

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BitCodeword {
    coordinates: [FieldElement; PARTICIPANT_COUNT],
}

impl BitCodeword {
    pub(crate) fn from_coefficients(
        coefficients: [FieldElement; CORRUPTION_BOUND + 1],
    ) -> ProtocolResult<Self> {
        if coefficients[0] != FieldElement::ZERO && coefficients[0] != FieldElement::ONE {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "bit codeword constant is outside the embedded binary field",
            ));
        }
        Ok(Self {
            coordinates: evaluate_at_participant_points(&coefficients),
        })
    }

    pub(crate) fn verify(coordinates: [FieldElement; PARTICIPANT_COUNT]) -> ProtocolResult<Self> {
        let constant = verify_degree_and_recover_constant(&coordinates, CORRUPTION_BOUND)?;
        if constant != FieldElement::ZERO && constant != FieldElement::ONE {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "bit codeword constant is outside the embedded binary field",
            ));
        }
        Ok(Self { coordinates })
    }

    pub(crate) const fn coordinates(&self) -> &[FieldElement; PARTICIPANT_COUNT] {
        &self.coordinates
    }

    pub(crate) fn constant(&self) -> FieldElement {
        interpolate_at_zero(&self.coordinates, CORRUPTION_BOUND)
            .expect("a verified bit codeword has distinct canonical points")
    }
}

impl Zeroize for BitCodeword {
    fn zeroize(&mut self) {
        self.coordinates.zeroize();
    }
}

impl Drop for BitCodeword {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductCodeword {
    coordinates: [FieldElement; PARTICIPANT_COUNT],
}

impl ProductCodeword {
    pub(crate) fn from_coefficients(
        coefficients: [FieldElement; PRODUCT_DEGREE + 1],
    ) -> ProtocolResult<Self> {
        if coefficients[0] != FieldElement::ZERO && coefficients[0] != FieldElement::ONE {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "product codeword constant is outside the embedded binary field",
            ));
        }
        Ok(Self {
            coordinates: evaluate_at_participant_points(&coefficients),
        })
    }

    pub(crate) fn verify(coordinates: [FieldElement; PARTICIPANT_COUNT]) -> ProtocolResult<Self> {
        let constant = verify_degree_and_recover_constant(&coordinates, PRODUCT_DEGREE)?;
        if constant != FieldElement::ZERO && constant != FieldElement::ONE {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "product codeword constant is outside the embedded binary field",
            ));
        }
        Ok(Self { coordinates })
    }

    pub(crate) const fn coordinates(&self) -> &[FieldElement; PARTICIPANT_COUNT] {
        &self.coordinates
    }

    pub(crate) fn constant(&self) -> FieldElement {
        interpolate_at_zero(&self.coordinates, PRODUCT_DEGREE)
            .expect("a verified product codeword has distinct canonical points")
    }
}

impl Zeroize for ProductCodeword {
    fn zeroize(&mut self) {
        self.coordinates.zeroize();
    }
}

impl Drop for ProductCodeword {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZeroCodeword {
    coordinates: [FieldElement; PARTICIPANT_COUNT],
}

impl ZeroCodeword {
    pub(crate) fn from_coefficients(
        coefficients: [FieldElement; CORRUPTION_BOUND + 1],
    ) -> ProtocolResult<Self> {
        if coefficients[0] != FieldElement::ZERO {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "zero codeword has a nonzero constant",
            ));
        }
        Ok(Self {
            coordinates: evaluate_at_participant_points(&coefficients),
        })
    }

    pub(crate) fn verify(coordinates: [FieldElement; PARTICIPANT_COUNT]) -> ProtocolResult<Self> {
        if verify_degree_and_recover_constant(&coordinates, CORRUPTION_BOUND)? != FieldElement::ZERO
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "zero codeword has a nonzero constant",
            ));
        }
        Ok(Self { coordinates })
    }

    pub(crate) const fn coordinates(&self) -> &[FieldElement; PARTICIPANT_COUNT] {
        &self.coordinates
    }
}

impl Zeroize for ZeroCodeword {
    fn zeroize(&mut self) {
        self.coordinates.zeroize();
    }
}

impl Drop for ZeroCodeword {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaskPairCodeword {
    pub(crate) low: BitCodeword,
    pub(crate) high: ProductCodeword,
}

impl MaskPairCodeword {
    pub(crate) fn verify(
        low_coordinates: [FieldElement; PARTICIPANT_COUNT],
        high_coordinates: [FieldElement; PARTICIPANT_COUNT],
    ) -> ProtocolResult<Self> {
        let low = BitCodeword::verify(low_coordinates)?;
        let high = ProductCodeword::verify(high_coordinates)?;
        if low.constant() != high.constant() {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "mask-pair codewords do not share one binary constant",
            ));
        }
        Ok(Self { low, high })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparationCandidate {
    pub(crate) mask_pair: MaskPairCodeword,
    pub(crate) output_zero_mask: ZeroCodeword,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparationCandidateCoordinates {
    pub(crate) low: [FieldElement; PARTICIPANT_COUNT],
    pub(crate) high: [FieldElement; PARTICIPANT_COUNT],
    pub(crate) output_zero: [FieldElement; PARTICIPANT_COUNT],
}

impl From<PreparationCandidate> for PreparationCandidateCoordinates {
    fn from(candidate: PreparationCandidate) -> Self {
        Self {
            low: *candidate.mask_pair.low.coordinates(),
            high: *candidate.mask_pair.high.coordinates(),
            output_zero: *candidate.output_zero_mask.coordinates(),
        }
    }
}

impl Zeroize for PreparationCandidateCoordinates {
    fn zeroize(&mut self) {
        self.low.zeroize();
        self.high.zeroize();
        self.output_zero.zeroize();
    }
}

impl Drop for PreparationCandidateCoordinates {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparationResponse {
    pub(crate) low: [FieldElement; PARTICIPANT_COUNT],
    pub(crate) high: [FieldElement; PARTICIPANT_COUNT],
    pub(crate) output_zero: [FieldElement; PARTICIPANT_COUNT],
}

impl PreparationResponse {
    pub(crate) fn verify(&self) -> ProtocolResult<()> {
        MaskPairCodeword::verify(self.low, self.high)?;
        ZeroCodeword::verify(self.output_zero)?;
        Ok(())
    }
}

pub(crate) fn create_preparation_response(
    candidates: &[PreparationCandidateCoordinates],
    challenge_coefficients: &[bool],
    pad: &PreparationCandidateCoordinates,
) -> ProtocolResult<PreparationResponse> {
    if candidates.len() != challenge_coefficients.len() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation challenge coefficient count is wrong",
        ));
    }
    let mut response = PreparationResponse {
        low: pad.low,
        high: pad.high,
        output_zero: pad.output_zero,
    };
    for (candidate, coefficient) in candidates.iter().zip(challenge_coefficients) {
        if !coefficient {
            continue;
        }
        add_coordinates(&mut response.low, &candidate.low);
        add_coordinates(&mut response.high, &candidate.high);
        add_coordinates(&mut response.output_zero, &candidate.output_zero);
    }
    Ok(response)
}

pub(crate) fn verify_preparation_response_batch(
    responses: &[PreparationResponse],
) -> ProtocolResult<()> {
    if responses.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "preparation response batch has the wrong repetition count",
        ));
    }
    for response in responses {
        response.verify()?;
    }
    Ok(())
}

pub(crate) fn create_source_response(
    candidate_coordinates: &[FieldElement; PARTICIPANT_COUNT],
    challenge_coefficient: bool,
    pad_coordinates: &[FieldElement; PARTICIPANT_COUNT],
) -> [FieldElement; PARTICIPANT_COUNT] {
    let mut response = *pad_coordinates;
    if challenge_coefficient {
        add_coordinates(&mut response, candidate_coordinates);
    }
    response
}

pub(crate) fn verify_source_response_batch(
    responses: &[[FieldElement; PARTICIPANT_COUNT]],
) -> ProtocolResult<()> {
    if responses.len() != DIRECT_CHECK_REPETITION_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source response batch has the wrong repetition count",
        ));
    }
    for response in responses {
        BitCodeword::verify(*response)?;
    }
    Ok(())
}

pub(crate) fn pack_field_elements(values: &[FieldElement]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(values.len().div_ceil(2));
    for pair in values.chunks(2) {
        let low = pair[0].value();
        let high = pair.get(1).copied().unwrap_or(FieldElement::ZERO).value();
        packed.push(low | (high << 4));
    }
    packed
}

pub(crate) fn unpack_field_elements(
    packed: &[u8],
    expected_element_count: usize,
) -> ProtocolResult<Vec<FieldElement>> {
    if packed.len() != expected_element_count.div_ceil(2) {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "packed field vector has the wrong byte length",
        ));
    }
    if expected_element_count % 2 == 1 && packed.last().is_some_and(|byte| byte & 0xf0 != 0) {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "packed field vector has a nonzero unused nibble",
        ));
    }
    let mut values = Vec::with_capacity(expected_element_count);
    for byte in packed {
        values.push(FieldElement(byte & 0x0f));
        if values.len() < expected_element_count {
            values.push(FieldElement(byte >> 4));
        }
    }
    Ok(values)
}

fn add_coordinates(
    target: &mut [FieldElement; PARTICIPANT_COUNT],
    source: &[FieldElement; PARTICIPANT_COUNT],
) {
    for (target_coordinate, source_coordinate) in target.iter_mut().zip(source) {
        *target_coordinate = target_coordinate.add(*source_coordinate);
    }
}

fn evaluate_at_participant_points<const COEFFICIENT_COUNT: usize>(
    coefficients: &[FieldElement; COEFFICIENT_COUNT],
) -> [FieldElement; PARTICIPANT_COUNT] {
    core::array::from_fn(|position| evaluate_polynomial(coefficients, participant_point(position)))
}

fn evaluate_polynomial(coefficients: &[FieldElement], point: FieldElement) -> FieldElement {
    coefficients
        .iter()
        .rev()
        .fold(FieldElement::ZERO, |value, coefficient| {
            value.multiply(point).add(*coefficient)
        })
}

fn verify_degree_and_recover_constant(
    coordinates: &[FieldElement; PARTICIPANT_COUNT],
    maximum_degree: usize,
) -> ProtocolResult<FieldElement> {
    let interpolation_count = maximum_degree.checked_add(1).ok_or_else(|| {
        ProtocolRefusal::new(
            RefusalReason::OutsideSupportedProfile,
            "codeword degree overflows",
        )
    })?;
    if interpolation_count > PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::OutsideSupportedProfile,
            "codeword degree exceeds the participant profile",
        ));
    }
    let source_points = (0..interpolation_count)
        .map(participant_point)
        .collect::<Vec<_>>();
    for position in interpolation_count..PARTICIPANT_COUNT {
        let expected = lagrange_evaluate(
            &source_points,
            &coordinates[..interpolation_count],
            participant_point(position),
        )?;
        if coordinates[position] != expected {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "field coordinates are outside the required polynomial code",
            ));
        }
    }
    lagrange_evaluate(
        &source_points,
        &coordinates[..interpolation_count],
        FieldElement::ZERO,
    )
}

fn interpolate_at_zero(
    coordinates: &[FieldElement; PARTICIPANT_COUNT],
    maximum_degree: usize,
) -> ProtocolResult<FieldElement> {
    let interpolation_count = maximum_degree + 1;
    let source_points = (0..interpolation_count)
        .map(participant_point)
        .collect::<Vec<_>>();
    lagrange_evaluate(
        &source_points,
        &coordinates[..interpolation_count],
        FieldElement::ZERO,
    )
}

fn lagrange_evaluate(
    points: &[FieldElement],
    values: &[FieldElement],
    target: FieldElement,
) -> ProtocolResult<FieldElement> {
    if points.len() != values.len() || points.is_empty() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "interpolation vectors have inconsistent lengths",
        ));
    }
    let mut result = FieldElement::ZERO;
    for (index, point) in points.iter().enumerate() {
        let mut numerator = FieldElement::ONE;
        let mut denominator = FieldElement::ONE;
        for (other_index, other_point) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            numerator = numerator.multiply(target.add(*other_point));
            denominator = denominator.multiply(point.add(*other_point));
        }
        let inverse = denominator.inverse().ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::DuplicateIdentity,
                "interpolation points are not distinct",
            )
        })?;
        result = result.add(values[index].multiply(numerator).multiply(inverse));
    }
    Ok(result)
}

fn participant_point(position: usize) -> FieldElement {
    FieldElement((position + 1) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(value: u8) -> FieldElement {
        FieldElement::new(value).expect("test field value is canonical")
    }

    fn bit_word(bit: u8, offset: u8) -> BitCodeword {
        BitCodeword::from_coefficients([element(bit), element(offset), element(7), element(11)])
            .expect("test bit word is valid")
    }

    fn product_word(bit: u8, offset: u8) -> ProductCodeword {
        ProductCodeword::from_coefficients([
            element(bit),
            element(offset),
            element(2),
            element(3),
            element(4),
            element(5),
            element(6),
        ])
        .expect("test product word is valid")
    }

    fn zero_word(offset: u8) -> ZeroCodeword {
        ZeroCodeword::from_coefficients([
            FieldElement::ZERO,
            element(offset),
            element(9),
            element(12),
        ])
        .expect("test zero word is valid")
    }

    #[test]
    fn multiplication_is_the_pinned_gf16_field() {
        for left in 0_u8..16 {
            for right in 0_u8..16 {
                assert_eq!(
                    element(left).multiply(element(right)),
                    element(reference_multiply(left, right))
                );
            }
            let value = element(left);
            if value != FieldElement::ZERO {
                assert_eq!(
                    value.multiply(value.inverse().expect("nonzero inverse")),
                    FieldElement::ONE
                );
            }
        }
        assert_eq!(element(2).multiply(element(8)), element(3));
    }

    #[test]
    fn bit_product_and_zero_codes_reject_semantic_mutations() {
        let bit = bit_word(1, 4);
        assert_eq!(BitCodeword::verify(*bit.coordinates()), Ok(bit.clone()));
        let product = product_word(1, 9);
        assert_eq!(ProductCodeword::verify(*product.coordinates()), Ok(product));
        let zero = zero_word(13);
        assert_eq!(ZeroCodeword::verify(*zero.coordinates()), Ok(zero));

        let mut mutated_bit = *bit.coordinates();
        mutated_bit[9] = mutated_bit[9].add(FieldElement::ONE);
        assert!(BitCodeword::verify(mutated_bit).is_err());

        let nonbit = BitCodeword::from_coefficients([
            element(2),
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
        ]);
        assert!(nonbit.is_err());

        let nonzero = ZeroCodeword::from_coefficients([
            FieldElement::ONE,
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
        ]);
        assert!(nonzero.is_err());
    }

    #[test]
    fn mask_pair_requires_one_common_bit() {
        let low = bit_word(0, 3);
        let high = product_word(0, 5);
        assert!(MaskPairCodeword::verify(*low.coordinates(), *high.coordinates()).is_ok());
        let wrong = product_word(1, 5);
        assert!(MaskPairCodeword::verify(*low.coordinates(), *wrong.coordinates()).is_err());
    }

    #[test]
    fn direct_responses_accept_valid_combinations_and_reject_mutations() {
        let candidates = (0_u8..10)
            .map(|dealer| PreparationCandidate {
                mask_pair: MaskPairCodeword {
                    low: bit_word(dealer & 1, dealer),
                    high: product_word(dealer & 1, dealer ^ 7),
                },
                output_zero_mask: zero_word(dealer ^ 11),
            })
            .map(PreparationCandidateCoordinates::from)
            .collect::<Vec<_>>();
        let rows = (0..DIRECT_CHECK_REPETITION_COUNT)
            .map(|row| {
                let pad = PreparationCandidateCoordinates::from(PreparationCandidate {
                    mask_pair: MaskPairCodeword {
                        low: bit_word((row & 1) as u8, (row & 15) as u8),
                        high: product_word((row & 1) as u8, ((row + 3) & 15) as u8),
                    },
                    output_zero_mask: zero_word(((row + 5) & 15) as u8),
                });
                create_preparation_response(
                    &candidates,
                    &(0..candidates.len())
                        .map(|candidate| (row + candidate) % 3 == 0)
                        .collect::<Vec<_>>(),
                    &pad,
                )
                .expect("challenge dimensions match")
            })
            .collect::<Vec<_>>();
        verify_preparation_response_batch(&rows).expect("valid responses verify");

        let mut mutated = rows;
        mutated[173].high[8] = mutated[173].high[8].add(FieldElement::ONE);
        assert!(verify_preparation_response_batch(&mutated).is_err());

        let mut invalid_candidates = candidates;
        invalid_candidates[4].high[9] = invalid_candidates[4].high[9].add(FieldElement::ONE);
        let invalid_rows = (0..DIRECT_CHECK_REPETITION_COUNT)
            .map(|row| {
                let pad = PreparationCandidateCoordinates::from(PreparationCandidate {
                    mask_pair: MaskPairCodeword {
                        low: bit_word((row & 1) as u8, (row & 15) as u8),
                        high: product_word((row & 1) as u8, ((row + 3) & 15) as u8),
                    },
                    output_zero_mask: zero_word(((row + 5) & 15) as u8),
                });
                create_preparation_response(
                    &invalid_candidates,
                    &[
                        false, false, false, false, true, false, false, false, false, false,
                    ],
                    &pad,
                )
                .expect("challenge dimensions match")
            })
            .collect::<Vec<_>>();
        assert!(verify_preparation_response_batch(&invalid_rows).is_err());
    }

    #[test]
    fn source_batch_accepts_valid_responses_and_rejects_one_bad_coordinate() {
        let source = bit_word(1, 6);
        let mut rows = (0..DIRECT_CHECK_REPETITION_COUNT)
            .map(|row| {
                let pad = bit_word((row & 1) as u8, ((row + 9) & 15) as u8);
                create_source_response(source.coordinates(), row % 2 == 0, pad.coordinates())
            })
            .collect::<Vec<_>>();
        verify_source_response_batch(&rows).expect("valid source responses verify");
        rows[211][7] = rows[211][7].add(FieldElement::ONE);
        assert!(verify_source_response_batch(&rows).is_err());
    }

    #[test]
    fn packed_field_encoding_is_canonical() {
        let values = (0_u8..15).map(element).collect::<Vec<_>>();
        let packed = pack_field_elements(&values);
        assert_eq!(unpack_field_elements(&packed, values.len()), Ok(values));

        let mut noncanonical = packed;
        *noncanonical.last_mut().expect("packed vector is nonempty") |= 0xf0;
        assert_eq!(
            unpack_field_elements(&noncanonical, 15)
                .expect_err("unused high nibble refuses")
                .reason,
            RefusalReason::MalformedEncoding
        );
    }

    fn reference_multiply(mut left: u8, mut right: u8) -> u8 {
        let mut product = 0_u8;
        for _ in 0..4 {
            product ^= left & 0_u8.wrapping_sub(right & 1);
            let carry = left >> 3;
            left = (left << 1) & 0x0f;
            left ^= 0x03 & 0_u8.wrapping_sub(carry);
            right >>= 1;
        }
        product & 0x0f
    }
}
