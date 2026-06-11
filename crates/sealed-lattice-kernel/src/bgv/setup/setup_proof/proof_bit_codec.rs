use super::*;

pub(super) struct LnpBitWriter {
    bytes: Vec<u8>,
    bit_offset: usize,
}

impl LnpBitWriter {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_offset: 0,
        }
    }

    pub(super) fn write_big_uint_le_bits(
        &mut self,
        value: &BigUint,
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if value.bits() > bit_count as u64 {
            return Err(setup_proof_error(
                "setup proof LNP bit writer value exceeds the declared bit width",
            ));
        }
        for bit_index in 0..bit_count {
            let bit = ((value >> bit_index) & BigUint::one()).is_one();
            self.write_bit(bit);
        }

        Ok(())
    }

    pub(super) fn write_u64_le_bits(
        &mut self,
        value: u64,
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bit_count > u64::BITS as usize && value != 0 {
            return Err(setup_proof_error(
                "setup proof LNP bit writer u64 value exceeds the declared bit width",
            ));
        }
        for bit_index in 0..bit_count {
            let bit = if bit_index < u64::BITS as usize {
                ((value >> bit_index) & 1) == 1
            } else {
                false
            };
            self.write_bit(bit);
        }

        Ok(())
    }

    pub(super) fn write_bit(&mut self, bit: bool) {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        if byte_index == self.bytes.len() {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;
    }

    pub(super) fn finish_with_lazer_padding(&mut self) {
        self.write_bit(true);
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(false);
        }
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
pub(super) struct LnpBitReader<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
}

#[allow(
    dead_code,
    reason = "used by the LNP tbox proof-byte verifier entry point"
)]
impl<'a> LnpBitReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_offset: 0,
        }
    }

    pub(super) fn read_big_uint_le_bits(&mut self, bit_count: usize) -> CanonicalResult<BigUint> {
        let mut value = BigUint::zero();
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= BigUint::one() << bit_index;
            }
        }

        Ok(value)
    }

    pub(super) fn read_u64_le_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count > u64::BITS as usize {
            return Err(setup_proof_error(
                "setup proof LNP tbox u64 bit read exceeds u64 width",
            ));
        }
        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            if self.read_bit()? {
                value |= 1_u64 << bit_index;
            }
        }

        Ok(value)
    }

    pub(super) fn read_bit(&mut self) -> CanonicalResult<bool> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof ended before the declared field layout",
            ));
        };
        let bit = ((*byte >> bit_index) & 1) == 1;
        self.bit_offset = self
            .bit_offset
            .checked_add(1)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox bit offset overflowed"))?;

        Ok(bit)
    }

    fn skip_bits(&mut self, bit_count: usize) -> CanonicalResult<()> {
        for _ in 0..bit_count {
            self.read_bit()?;
        }

        Ok(())
    }

    pub(super) fn finish_exact_end(&mut self, label: &str) -> CanonicalResult<()> {
        let consumed_bits = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| setup_proof_error(format!("{label} bit length overflowed")))?;
        if self.bit_offset != consumed_bits {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{label} ended before the declared prefix layout"),
            ));
        }

        Ok(())
    }

    pub(super) fn finish_with_lazer_padding(&mut self) -> CanonicalResult<()> {
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let Some(byte) = self.bytes.get(byte_index) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof LNP tbox proof is missing its final padding byte",
            ));
        };
        let high_bits = *byte & (!0_u8 << bit_index);
        if high_bits != (1_u8 << bit_index) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "setup proof LNP tbox final padding is not canonical",
            ));
        }
        let consumed_bytes = byte_index.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox consumed byte count overflowed")
        })?;
        if consumed_bytes != self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "setup proof LNP tbox proof has trailing bytes after final padding",
            ));
        }
        self.bit_offset = consumed_bytes
            .checked_mul(8)
            .ok_or_else(|| setup_proof_error("setup proof LNP tbox final bit offset overflowed"))?;

        Ok(())
    }
}
