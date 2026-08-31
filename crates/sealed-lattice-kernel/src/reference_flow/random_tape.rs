use crate::foundation::RefusalReason;

use super::{ProtocolRefusal, ProtocolResult};

pub(crate) struct RandomBitTape<'a> {
    bytes: &'a [u8],
    bit_offset: usize,
    required_bit_length: usize,
}

impl<'a> RandomBitTape<'a> {
    pub(crate) fn new(bytes: &'a [u8], required_bit_length: usize) -> ProtocolResult<Self> {
        let required_byte_length = required_bit_length.div_ceil(8);
        if bytes.len() != required_byte_length {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "random tape has the wrong byte length",
            ));
        }
        Ok(Self {
            bytes,
            bit_offset: 0,
            required_bit_length,
        })
    }

    pub(crate) fn read_bit(&mut self) -> ProtocolResult<bool> {
        if self.bit_offset == self.required_bit_length {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "random tape is exhausted",
            ));
        }
        let byte = self.bytes[self.bit_offset / 8];
        let bit = ((byte >> (self.bit_offset % 8)) & 1) != 0;
        self.bit_offset += 1;
        Ok(bit)
    }

    pub(crate) fn read_low_bits(&mut self, bit_length: usize) -> ProtocolResult<u8> {
        if bit_length > 8 {
            return Err(ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "random tape scalar width exceeds eight bits",
            ));
        }
        let mut value = 0_u8;
        for position in 0..bit_length {
            value |= u8::from(self.read_bit()?) << position;
        }
        Ok(value)
    }

    pub(crate) fn finish(self) -> ProtocolResult<()> {
        if self.bit_offset != self.required_bit_length {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "random tape was not consumed exactly once",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tape_consumes_little_endian_bits_once() {
        let mut tape = RandomBitTape::new(&[0b1011_0010, 0b1110_0101], 13)
            .expect("two bytes hold thirteen bits");
        assert_eq!(tape.read_low_bits(4), Ok(0b0010));
        assert_eq!(tape.read_low_bits(4), Ok(0b1011));
        assert_eq!(tape.read_low_bits(5), Ok(0b0_0101));
        tape.finish().expect("all required bits were consumed");
    }

    #[test]
    fn tape_refuses_wrong_length_exhaustion_and_partial_use() {
        assert!(RandomBitTape::new(&[0; 1], 9).is_err());

        let mut exhausted = RandomBitTape::new(&[0], 1).expect("one bit fits");
        assert_eq!(exhausted.read_bit(), Ok(false));
        assert!(exhausted.read_bit().is_err());

        let mut partial = RandomBitTape::new(&[0], 2).expect("two bits fit");
        partial.read_bit().expect("first bit exists");
        assert!(partial.finish().is_err());
    }
}
