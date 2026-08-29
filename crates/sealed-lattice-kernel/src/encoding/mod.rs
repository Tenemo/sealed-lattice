use core::str;

mod foundation_command;

const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8_388_608;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalErrorCode {
    InvalidEnum,
    InvalidProtocolObject,
    InvalidUtf8,
    MalformedLength,
    #[cfg(test)]
    MalformedVarUint,
    #[cfg(test)]
    NonCanonicalVarUint,
    TrailingBytes,
}

impl CanonicalErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEnum => "InvalidEnum",
            Self::InvalidProtocolObject => "InvalidProtocolObject",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::MalformedLength => "MalformedLength",
            #[cfg(test)]
            Self::MalformedVarUint => "MalformedVarUint",
            #[cfg(test)]
            Self::NonCanonicalVarUint => "NonCanonicalVarUint",
            Self::TrailingBytes => "TrailingBytes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError {
    pub code: CanonicalErrorCode,
    pub message: String,
}

impl CanonicalError {
    pub fn new(code: CanonicalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl core::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CanonicalError {}

pub type CanonicalResult<T> = Result<T, CanonicalError>;

pub(super) struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn finish(self) -> CanonicalResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonicalError::new(
                CanonicalErrorCode::TrailingBytes,
                "foundation command contains trailing bytes",
            ))
        }
    }

    pub fn read_exact(&mut self, length: usize) -> CanonicalResult<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(CanonicalErrorCode::MalformedLength, "length overflow")
        })?;
        if end > self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "foundation command field exceeds the remaining bytes",
            ));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    pub fn read_u8(&mut self) -> CanonicalResult<u8> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u16(&mut self) -> CanonicalResult<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> CanonicalResult<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64(&mut self) -> CanonicalResult<u64> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::MalformedLength, "u64"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_bytes(&mut self) -> CanonicalResult<&'a [u8]> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "field length does not fit usize",
            )
        })?;
        self.read_exact(length)
    }

    pub fn read_string(&mut self) -> CanonicalResult<&'a str> {
        str::from_utf8(self.read_bytes()?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidUtf8,
                "foundation command string is not valid UTF-8",
            )
        })
    }
}

pub(super) struct BinaryWriter {
    bytes: Vec<u8>,
}

impl BinaryWriter {
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn extend(&mut self, value: &[u8]) -> CanonicalResult<()> {
        let required_length = self.bytes.len().checked_add(value.len()).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "response length overflow",
            )
        })?;
        if required_length > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "foundation command response exceeds the copied-buffer limit",
            ));
        }
        self.bytes.try_reserve(value.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "foundation command response allocation failed",
            )
        })?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub fn write_u8(&mut self, value: u8) -> CanonicalResult<()> {
        self.extend(&[value])
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> CanonicalResult<()> {
        let length = u32::try_from(value.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "response field length does not fit u32",
            )
        })?;
        self.extend(&length.to_le_bytes())?;
        self.extend(value)
    }

    pub fn write_string(&mut self, value: &str) -> CanonicalResult<()> {
        self.write_bytes(value.as_bytes())
    }

    pub fn write_fixed(&mut self, value: &[u8]) -> CanonicalResult<()> {
        self.extend(value)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode_error(error: CanonicalError) -> Vec<u8> {
    let encoded: CanonicalResult<Vec<u8>> = (|| {
        let mut writer = BinaryWriter::new();
        writer.write_u8(1)?;
        writer.write_string(error.code.as_str())?;
        writer.write_string(&error.message)?;
        Ok(writer.into_bytes())
    })();
    encoded.unwrap_or_else(|_| vec![1])
}

fn encode_success(payload: Vec<u8>) -> Vec<u8> {
    let encoded: CanonicalResult<Vec<u8>> = (|| {
        let mut writer = BinaryWriter::new();
        writer.write_u8(0)?;
        writer.write_fixed(&payload)?;
        Ok(writer.into_bytes())
    })();
    encoded.unwrap_or_else(encode_error)
}

pub fn run_foundation_command(input: &[u8]) -> Vec<u8> {
    if input.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return encode_error(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "foundation command exceeds the copied-buffer limit",
        ));
    }

    match foundation_command::run(input) {
        Ok(payload) => encode_success(payload),
        Err(error) => encode_error(error),
    }
}

#[cfg(test)]
pub fn encode_varuint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return output;
        }
    }
}

#[cfg(test)]
pub fn append_varuint(output: &mut Vec<u8>, value: u64) {
    output.extend(encode_varuint(value));
}

#[cfg(test)]
pub fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    append_varuint(output, value.len() as u64);
    output.extend(value);
}

#[cfg(test)]
pub struct CanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(test)]
impl<'a> CanonicalReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub fn read_exact(&mut self, length: usize) -> CanonicalResult<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(CanonicalErrorCode::MalformedLength, "length overflow")
        })?;
        if end > self.bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "length exceeds remaining bytes",
            ));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    pub fn read_varuint(&mut self) -> CanonicalResult<u64> {
        let start = self.offset;
        let mut shift = 0_u32;
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = self.read_exact(1)?[0];
            let payload = u64::from(byte & 0x7f);
            if index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint exceeds u64",
                ));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                if self.bytes[start..self.offset] != encode_varuint(value) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::NonCanonicalVarUint,
                        "varuint is not minimally encoded",
                    ));
                }
                return Ok(value);
            }
            shift += 7;
        }
        Err(CanonicalError::new(
            CanonicalErrorCode::MalformedVarUint,
            "varuint is too long",
        ))
    }

    pub fn read_bytes(&mut self) -> CanonicalResult<Vec<u8>> {
        let length = usize::try_from(self.read_varuint()?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "length does not fit usize",
            )
        })?;
        Ok(self.read_exact(length)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_command_refuses_unknown_and_trailing_input() {
        assert_eq!(run_foundation_command(&[0xff])[0], 1);
        assert_eq!(run_foundation_command(&[2, 0, 0, 0, 0, 1])[0], 1);
    }

    #[test]
    fn canonical_varuint_reader_rejects_nonminimal_encoding() {
        let error = CanonicalReader::new(&[0x80, 0x00])
            .read_varuint()
            .expect_err("overlong zero must refuse");
        assert_eq!(error.code, CanonicalErrorCode::NonCanonicalVarUint);
    }
}
