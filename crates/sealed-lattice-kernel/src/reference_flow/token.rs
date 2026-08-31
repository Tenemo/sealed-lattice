use zeroize::Zeroizing;

use crate::foundation::RefusalReason;

use super::{
    ProtocolRefusal, ProtocolResult,
    field::{FieldElement, PARTICIPANT_COUNT},
};

pub(crate) const TOKEN_BYTE_LENGTH: usize = 48;
const TOKEN_FIELD_ELEMENT_COUNT: usize = TOKEN_BYTE_LENGTH * 2;
const CONTINUATION_DEGREE: usize = PARTICIPANT_COUNT - 1;
const RECEIVER_DIFFERENCE_DEGREE: usize = 3;
pub(crate) const RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH: usize =
    (CONTINUATION_DEGREE + 1 + RECEIVER_DIFFERENCE_DEGREE + 1) * TOKEN_BYTE_LENGTH;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretToken(Zeroizing<[u8; TOKEN_BYTE_LENGTH]>);

impl core::fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretToken([redacted])")
    }
}

impl SecretToken {
    pub(crate) fn zero() -> Self {
        Self(Zeroizing::new([0; TOKEN_BYTE_LENGTH]))
    }

    pub(crate) fn from_bytes(bytes: [u8; TOKEN_BYTE_LENGTH]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; TOKEN_BYTE_LENGTH] {
        &self.0
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let mut result = [0_u8; TOKEN_BYTE_LENGTH];
        for ((result_byte, left), right) in result.iter_mut().zip(self.0.iter()).zip(other.0.iter())
        {
            *result_byte = left ^ right;
        }
        Self::from_bytes(result)
    }

    pub(crate) fn multiply(&self, scalar: FieldElement) -> Self {
        let mut result = [0_u8; TOKEN_BYTE_LENGTH];
        for (result_byte, source_byte) in result.iter_mut().zip(self.0.iter()) {
            let low = FieldElement::new(source_byte & 0x0f)
                .expect("a packed token nibble is a canonical field element")
                .multiply(scalar)
                .value();
            let high = FieldElement::new(source_byte >> 4)
                .expect("a packed token nibble is a canonical field element")
                .multiply(scalar)
                .value();
            *result_byte = low | (high << 4);
        }
        Self::from_bytes(result)
    }
}

pub(crate) struct ReceiverTokenSetup {
    a_evaluations: [SecretToken; PARTICIPANT_COUNT],
    b_evaluations: [SecretToken; PARTICIPANT_COUNT],
    zero_key: SecretToken,
    one_key: SecretToken,
}

impl core::fmt::Debug for ReceiverTokenSetup {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReceiverTokenSetup([redacted])")
    }
}

impl ReceiverTokenSetup {
    pub(crate) fn evaluation_for_garbler(
        &self,
        garbler_position: usize,
    ) -> (&SecretToken, &SecretToken) {
        (
            &self.a_evaluations[garbler_position],
            &self.b_evaluations[garbler_position],
        )
    }

    pub(crate) fn selected_contribution(
        &self,
        garbler_position: usize,
        masked_coordinate: FieldElement,
    ) -> SecretToken {
        let (a_evaluation, b_evaluation) = self.evaluation_for_garbler(garbler_position);
        a_evaluation.add(&b_evaluation.multiply(masked_coordinate))
    }

    pub(crate) fn key_for_bit(&self, bit: bool) -> &SecretToken {
        if bit { &self.one_key } else { &self.zero_key }
    }

    pub(crate) fn clone_evaluation_for_garbler(
        &self,
        garbler_position: usize,
    ) -> (SecretToken, SecretToken) {
        let (a_evaluation, b_evaluation) = self.evaluation_for_garbler(garbler_position);
        (a_evaluation.clone(), b_evaluation.clone())
    }

    pub(crate) fn clone_continuation_keys(&self) -> [SecretToken; 2] {
        [self.zero_key.clone(), self.one_key.clone()]
    }
}

pub(crate) fn create_receiver_token_setup(
    random_bytes: &[u8],
) -> ProtocolResult<ReceiverTokenSetup> {
    if random_bytes.len() != RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "receiver token-setup randomness has the wrong length",
        ));
    }
    let mut chunks = random_bytes.chunks_exact(TOKEN_BYTE_LENGTH);
    let a_coefficients = (0..=CONTINUATION_DEGREE)
        .map(|_| read_token(&mut chunks))
        .collect::<ProtocolResult<Vec<_>>>()?;
    let b_coefficients = (0..=RECEIVER_DIFFERENCE_DEGREE)
        .map(|_| read_token(&mut chunks))
        .collect::<ProtocolResult<Vec<_>>>()?;
    if !chunks.remainder().is_empty() {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "receiver token-setup randomness has trailing bytes",
        ));
    }
    if b_coefficients[0].is_zero() {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "receiver token difference has a zero constant",
        ));
    }
    let a_evaluations = core::array::from_fn(|position| {
        evaluate_token_polynomial(&a_coefficients, participant_point(position))
    });
    let b_evaluations = core::array::from_fn(|position| {
        evaluate_token_polynomial(&b_coefficients, participant_point(position))
    });
    let zero_key = a_coefficients[0].clone();
    let one_key = a_coefficients[0].add(&b_coefficients[0]);
    Ok(ReceiverTokenSetup {
        a_evaluations,
        b_evaluations,
        zero_key,
        one_key,
    })
}

pub(crate) fn reconstruct_selected_token(
    contributions: &[SecretToken],
) -> ProtocolResult<SecretToken> {
    if contributions.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "continuation token reconstruction requires every roster position",
        ));
    }
    let mut result = SecretToken::zero();
    for (position, contribution) in contributions.iter().enumerate() {
        let point = participant_point(position);
        let mut numerator = FieldElement::ONE;
        let mut denominator = FieldElement::ONE;
        for other_position in 0..PARTICIPANT_COUNT {
            if position == other_position {
                continue;
            }
            let other_point = participant_point(other_position);
            numerator = numerator.multiply(other_point);
            denominator = denominator.multiply(point.add(other_point));
        }
        let weight = numerator.multiply(denominator.inverse().ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::DuplicateIdentity,
                "continuation interpolation points are not distinct",
            )
        })?);
        result = result.add(&contribution.multiply(weight));
    }
    Ok(result)
}

fn read_token(chunks: &mut core::slice::ChunksExact<'_, u8>) -> ProtocolResult<SecretToken> {
    let bytes = chunks.next().ok_or_else(|| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "receiver token-setup randomness is truncated",
        )
    })?;
    let bytes = bytes.try_into().map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "receiver token has the wrong length",
        )
    })?;
    Ok(SecretToken::from_bytes(bytes))
}

fn evaluate_token_polynomial(coefficients: &[SecretToken], point: FieldElement) -> SecretToken {
    coefficients
        .iter()
        .rev()
        .fold(SecretToken::zero(), |value, coefficient| {
            value.multiply(point).add(coefficient)
        })
}

fn participant_point(position: usize) -> FieldElement {
    FieldElement::new((position + 1) as u8)
        .expect("the completion roster points are canonical nonzero field elements")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::field::ProductCodeword;

    fn setup_bytes() -> Vec<u8> {
        let mut bytes = (0..RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH)
            .map(|offset| (offset as u8).wrapping_mul(73).wrapping_add(19))
            .collect::<Vec<_>>();
        bytes[10 * TOKEN_BYTE_LENGTH] |= 1;
        bytes
    }

    #[test]
    fn selected_degree_nine_contributions_reconstruct_exact_binary_key() {
        let setup = create_receiver_token_setup(&setup_bytes())
            .expect("test setup has a nonzero difference constant");
        for bit in [false, true] {
            let masked_word = ProductCodeword::from_coefficients([
                if bit {
                    FieldElement::ONE
                } else {
                    FieldElement::ZERO
                },
                FieldElement::new(2).unwrap(),
                FieldElement::new(3).unwrap(),
                FieldElement::new(5).unwrap(),
                FieldElement::new(7).unwrap(),
                FieldElement::new(11).unwrap(),
                FieldElement::new(13).unwrap(),
            ])
            .expect("masked word has a bit constant");
            let contributions = masked_word
                .coordinates()
                .iter()
                .enumerate()
                .map(|(position, coordinate)| setup.selected_contribution(position, *coordinate))
                .collect::<Vec<_>>();
            let reconstructed = reconstruct_selected_token(&contributions)
                .expect("all ten contributions reconstruct");
            assert_eq!(&reconstructed, setup.key_for_bit(bit));
        }
    }

    #[test]
    fn setup_refuses_zero_difference_and_reconstruction_refuses_missing_position() {
        let zero = vec![0; RECEIVER_TOKEN_SETUP_RANDOM_BYTE_LENGTH];
        assert!(create_receiver_token_setup(&zero).is_err());

        let setup = create_receiver_token_setup(&setup_bytes())
            .expect("test setup has a nonzero difference constant");
        let contributions = (0..PARTICIPANT_COUNT - 1)
            .map(|position| setup.selected_contribution(position, FieldElement::ZERO))
            .collect::<Vec<_>>();
        assert!(reconstruct_selected_token(&contributions).is_err());
    }

    #[test]
    fn token_module_scalar_multiplication_matches_nibble_field_arithmetic() {
        assert_eq!(TOKEN_FIELD_ELEMENT_COUNT, 96);
        let token = SecretToken::from_bytes([0x81; TOKEN_BYTE_LENGTH]);
        let product = token.multiply(FieldElement::new(2).unwrap());
        assert!(product.as_bytes().iter().all(|byte| *byte == 0x32));
    }
}
