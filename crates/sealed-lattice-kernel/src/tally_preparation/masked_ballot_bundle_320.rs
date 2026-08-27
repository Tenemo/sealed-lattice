use core::fmt;

use zeroize::Zeroize;

use crate::tally_circuit::{
    CompiledTallyCircuit, TALLY_BALLOT_ATTEMPT_COUNT, TallyBallotAttemptInput, TallyCircuitError,
    encode_tally_ballot_attempt_input_bits,
};

use super::binary_field_320::BinaryFieldElement320;

/// Failure to construct or decode the unactivated direct masked-ballot bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBundleError320 {
    TallyCircuit(TallyCircuitError),
    FieldCapacityExceeded {
        input_bit_count: usize,
        field_bit_count: usize,
    },
    InputMaskBitCountMismatch {
        expected: usize,
        actual: usize,
    },
    CanonicalByteLengthMismatch {
        expected: usize,
        actual: usize,
    },
    NonzeroCanonicalPadding,
    CompilerInputGeometryMismatch,
}

impl fmt::Display for MaskedBallotBundleError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TallyCircuit(error) => error.fmt(formatter),
            Self::FieldCapacityExceeded {
                input_bit_count,
                field_bit_count,
            } => write!(
                formatter,
                "masked ballot has {input_bit_count} input bits; candidate field capacity is {field_bit_count} bits"
            ),
            Self::InputMaskBitCountMismatch { expected, actual } => write!(
                formatter,
                "masked ballot input mask has {actual} bits; expected {expected}"
            ),
            Self::CanonicalByteLengthMismatch { expected, actual } => write!(
                formatter,
                "masked ballot bundle has {actual} canonical bytes; expected {expected}"
            ),
            Self::NonzeroCanonicalPadding => {
                formatter.write_str("masked ballot bundle has nonzero canonical padding bits")
            }
            Self::CompilerInputGeometryMismatch => {
                formatter.write_str("masked ballot bundle does not match compiler input geometry")
            }
        }
    }
}

impl std::error::Error for MaskedBallotBundleError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TallyCircuit(error) => Some(error),
            Self::FieldCapacityExceeded { .. }
            | Self::InputMaskBitCountMismatch { .. }
            | Self::CanonicalByteLengthMismatch { .. }
            | Self::NonzeroCanonicalPadding
            | Self::CompilerInputGeometryMismatch => None,
        }
    }
}

impl From<TallyCircuitError> for MaskedBallotBundleError320 {
    fn from(error: TallyCircuitError) -> Self {
        Self::TallyCircuit(error)
    }
}

/// One participant's compiler-ordered `input xor mask` bundle.
///
/// This value is only the exact scalar and codec owner needed to evaluate the
/// direct ballot-custody candidate. It authenticates no author, root, holder,
/// receipt, selected ballot set, or release and cannot authorize progress.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBundle320 {
    field_element: BinaryFieldElement320,
    input_bit_count: usize,
}

impl MaskedBallotBundle320 {
    pub(crate) fn derive(
        circuit: &CompiledTallyCircuit,
        participant_position: u16,
        ballot_attempts: &[TallyBallotAttemptInput],
        input_mask_bits: &[bool],
    ) -> Result<Self, MaskedBallotBundleError320> {
        let input_bits = encode_tally_ballot_attempt_input_bits(
            circuit,
            usize::from(participant_position),
            ballot_attempts,
        )?;
        let expected_input_bit_count = masked_ballot_bundle_input_bit_count(circuit)?;
        if input_bits.len() != expected_input_bit_count {
            return Err(MaskedBallotBundleError320::CompilerInputGeometryMismatch);
        }
        if input_mask_bits.len() != expected_input_bit_count {
            return Err(MaskedBallotBundleError320::InputMaskBitCountMismatch {
                expected: expected_input_bit_count,
                actual: input_mask_bits.len(),
            });
        }

        let masked_input_bits = input_bits
            .iter()
            .copied()
            .zip(input_mask_bits.iter().copied())
            .map(|(input_bit, input_mask_bit)| input_bit ^ input_mask_bit)
            .collect::<Vec<_>>();
        Self::from_masked_input_bits(masked_input_bits)
    }

    pub(crate) fn from_canonical_bytes(
        circuit: &CompiledTallyCircuit,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBundleError320> {
        let input_bit_count = masked_ballot_bundle_input_bit_count(circuit)?;
        let expected_byte_length = canonical_byte_length(input_bit_count);
        if bytes.len() != expected_byte_length {
            return Err(MaskedBallotBundleError320::CanonicalByteLengthMismatch {
                expected: expected_byte_length,
                actual: bytes.len(),
            });
        }
        require_zero_padding(bytes, input_bit_count)?;

        let mut field_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
        field_bytes[..bytes.len()].copy_from_slice(bytes);
        let field_element = BinaryFieldElement320::from_canonical_bytes(&field_bytes)
            .expect("a fixed 40-byte array is a canonical candidate-field element");
        Ok(Self {
            field_element,
            input_bit_count,
        })
    }

    /// Decodes a reconstructed sharing constant through the same minimal
    /// bundle language used by ballot production.
    ///
    /// A malicious sharing can reconstruct any field element. The unused
    /// coefficients therefore have to be checked after interpolation rather
    /// than discarded while converting the 40-byte field element to the
    /// compiler-derived bundle width.
    pub(crate) fn from_field_element(
        circuit: &CompiledTallyCircuit,
        field_element: BinaryFieldElement320,
    ) -> Result<Self, MaskedBallotBundleError320> {
        let input_bit_count = masked_ballot_bundle_input_bit_count(circuit)?;
        let byte_length = canonical_byte_length(input_bit_count);
        let field_bytes = field_element.canonical_bytes();
        require_zero_padding(&field_bytes[..byte_length], input_bit_count)?;
        if field_bytes[byte_length..].iter().any(|byte| *byte != 0) {
            return Err(MaskedBallotBundleError320::NonzeroCanonicalPadding);
        }
        Ok(Self {
            field_element,
            input_bit_count,
        })
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let byte_length = canonical_byte_length(self.input_bit_count);
        self.field_element.canonical_bytes()[..byte_length].to_vec()
    }

    pub(crate) const fn field_element(&self) -> BinaryFieldElement320 {
        self.field_element
    }

    pub(crate) const fn input_bit_count(&self) -> usize {
        self.input_bit_count
    }

    pub(crate) fn masked_input_bits(&self) -> Vec<bool> {
        let bytes = self.field_element.canonical_bytes();
        (0..self.input_bit_count)
            .map(|bit_position| ((bytes[bit_position / 8] >> (bit_position % 8)) & 1_u8) == 1_u8)
            .collect()
    }

    fn from_masked_input_bits(
        masked_input_bits: Vec<bool>,
    ) -> Result<Self, MaskedBallotBundleError320> {
        let input_bit_count = masked_input_bits.len();
        let field_bit_count = BinaryFieldElement320::CANONICAL_BYTE_LENGTH * 8;
        if input_bit_count > field_bit_count {
            return Err(MaskedBallotBundleError320::FieldCapacityExceeded {
                input_bit_count,
                field_bit_count,
            });
        }
        let mut field_bytes = [0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH];
        for (bit_position, bit) in masked_input_bits.into_iter().enumerate() {
            field_bytes[bit_position / 8] |= u8::from(bit) << (bit_position % 8);
        }
        let field_element = BinaryFieldElement320::from_canonical_bytes(&field_bytes)
            .expect("a fixed 40-byte array is a canonical candidate-field element");
        Ok(Self {
            field_element,
            input_bit_count,
        })
    }
}

impl fmt::Debug for MaskedBallotBundle320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBundle320")
            .field("input_bit_count", &self.input_bit_count)
            .field("field_element", &"[redacted]")
            .finish()
    }
}

impl Zeroize for MaskedBallotBundle320 {
    fn zeroize(&mut self) {
        self.field_element.zeroize();
        self.input_bit_count.zeroize();
    }
}

pub(crate) fn masked_ballot_bundle_input_bit_count(
    circuit: &CompiledTallyCircuit,
) -> Result<usize, MaskedBallotBundleError320> {
    let participant_count = usize::from(circuit.profile().participant_count());
    let score_bit_count_per_attempt = usize::from(circuit.profile().option_count())
        .checked_mul(circuit.geometry().score_bit_width)
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    let input_bit_count = TALLY_BALLOT_ATTEMPT_COUNT
        .checked_mul(
            1_usize
                .checked_add(score_bit_count_per_attempt)
                .ok_or(TallyCircuitError::ArithmeticOverflow)?,
        )
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    let expected_total_input_bit_count = participant_count
        .checked_mul(input_bit_count)
        .ok_or(TallyCircuitError::ArithmeticOverflow)?;
    if circuit.geometry().input_bit_count != expected_total_input_bit_count
        || circuit.geometry().ballot_attempt_count != TALLY_BALLOT_ATTEMPT_COUNT
        || circuit.geometry().ballot_attempt_presence_input_bit_count
            != participant_count
                .checked_mul(TALLY_BALLOT_ATTEMPT_COUNT)
                .ok_or(TallyCircuitError::ArithmeticOverflow)?
    {
        return Err(MaskedBallotBundleError320::CompilerInputGeometryMismatch);
    }
    let field_bit_count = BinaryFieldElement320::CANONICAL_BYTE_LENGTH * 8;
    if input_bit_count > field_bit_count {
        return Err(MaskedBallotBundleError320::FieldCapacityExceeded {
            input_bit_count,
            field_bit_count,
        });
    }
    Ok(input_bit_count)
}

fn canonical_byte_length(input_bit_count: usize) -> usize {
    input_bit_count.div_ceil(8)
}

fn require_zero_padding(
    bytes: &[u8],
    input_bit_count: usize,
) -> Result<(), MaskedBallotBundleError320> {
    let used_bits_in_last_byte = input_bit_count % 8;
    if used_bits_in_last_byte == 0 {
        return Ok(());
    }
    let used_bit_mask = (1_u8 << used_bits_in_last_byte) - 1_u8;
    if bytes.last().copied().unwrap_or(0) & !used_bit_mask != 0 {
        return Err(MaskedBallotBundleError320::NonzeroCanonicalPadding);
    }
    Ok(())
}
