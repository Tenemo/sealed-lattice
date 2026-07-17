use super::{FOUNDATION_PROFILE, RefusalReason};

type RuntimeResult<Value> = Result<Value, u32>;

pub(super) struct RuntimeInputReader<'input> {
    bytes: &'input [u8],
    offset: usize,
}

impl<'input> RuntimeInputReader<'input> {
    pub(super) const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn read_u8(&mut self) -> RuntimeResult<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    pub(super) fn read_u16(&mut self) -> RuntimeResult<u16> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    pub(super) fn read_u32(&mut self) -> RuntimeResult<u32> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    pub(super) fn read_u64(&mut self) -> RuntimeResult<u64> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    pub(super) fn read_array<const BYTE_LENGTH: usize>(
        &mut self,
    ) -> RuntimeResult<[u8; BYTE_LENGTH]> {
        self.read_bytes(BYTE_LENGTH)?
            .try_into()
            .map_err(|_| malformed_status())
    }

    pub(super) fn read_bytes(&mut self, byte_length: usize) -> RuntimeResult<&'input [u8]> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or_else(malformed_status)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(malformed_status)?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn read_length_prefixed_bytes(&mut self) -> RuntimeResult<&'input [u8]> {
        let byte_length = usize::try_from(self.read_u32()?)
            .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
        if byte_length == 0 || byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
            return Err(refusal_status(RefusalReason::WrongTypeOrLength));
        }
        self.read_bytes(byte_length)
    }

    pub(super) fn read_remaining(&mut self) -> &'input [u8] {
        let remaining = &self.bytes[self.offset..];
        self.offset = self.bytes.len();
        remaining
    }

    pub(super) fn finish(self) -> RuntimeResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed_status())
        }
    }
}

const fn malformed_status() -> u32 {
    refusal_status(RefusalReason::MalformedEncoding)
}

pub(super) const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}
