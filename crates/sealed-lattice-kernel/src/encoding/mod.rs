use core::str;

use crate::foundation::MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH;

mod construction_command;
mod foundation_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalErrorCode {
    InvalidEnum,
    InvalidProtocolObject,
    InvalidUtf8,
    MalformedLength,
    TrailingBytes,
}

impl CanonicalErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEnum => "InvalidEnum",
            Self::InvalidProtocolObject => "InvalidProtocolObject",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::MalformedLength => "MalformedLength",
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

    pub fn read_u32(&mut self) -> CanonicalResult<u32> {
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
        if required_length > MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH {
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

    pub fn write_u16(&mut self, value: u16) -> CanonicalResult<()> {
        self.extend(&value.to_le_bytes())
    }

    pub fn write_u32(&mut self, value: u32) -> CanonicalResult<()> {
        self.extend(&value.to_le_bytes())
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

pub(super) fn run_foundation_command(input: &[u8]) -> Vec<u8> {
    if input.len() > MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH {
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

pub(super) fn run_construction_command(input: &[u8]) -> Vec<u8> {
    if input.len() > MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH {
        return encode_error(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "construction command exceeds the copied-buffer limit",
        ));
    }

    match construction_command::run(input) {
        Ok(payload) => encode_success(payload),
        Err(error) => encode_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_command_error(response: &[u8]) -> (&str, &str) {
        let mut reader = BinaryReader::new(response);
        assert_eq!(reader.read_u8().expect("command status is present"), 1);
        let code = reader.read_string().expect("error code is present");
        let message = reader.read_string().expect("error message is present");
        reader.finish().expect("error response is fully consumed");
        (code, message)
    }

    #[test]
    fn binary_command_refuses_unknown_and_trailing_input() {
        assert_eq!(
            decode_command_error(&run_foundation_command(&[0xff])).0,
            CanonicalErrorCode::InvalidEnum.as_str()
        );
        assert_eq!(
            decode_command_error(&run_foundation_command(&[2, 0, 0, 0, 0, 1])).0,
            CanonicalErrorCode::TrailingBytes.as_str()
        );
    }

    #[test]
    fn binary_command_enforces_the_exact_input_limit() {
        let mut command = vec![0_u8; MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH];
        command[0] = 0xff;
        assert_eq!(
            decode_command_error(&run_foundation_command(&command)).0,
            CanonicalErrorCode::InvalidEnum.as_str(),
            "an exact-limit command must reach command decoding"
        );

        command.push(0);
        assert_eq!(
            decode_command_error(&run_foundation_command(&command)),
            (
                CanonicalErrorCode::MalformedLength.as_str(),
                "foundation command exceeds the copied-buffer limit"
            )
        );
    }

    #[test]
    fn binary_response_writer_enforces_the_exact_output_limit() {
        let exact_limit = vec![0_u8; MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH];
        let mut writer = BinaryWriter::new();
        writer
            .write_fixed(&exact_limit)
            .expect("the exact copied-buffer limit is accepted");
        let error = writer
            .write_u8(0)
            .expect_err("one byte beyond the copied-buffer limit must refuse");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        assert_eq!(
            error.message,
            "foundation command response exceeds the copied-buffer limit"
        );
        assert_eq!(
            writer.into_bytes().len(),
            MAXIMUM_FOUNDATION_COPIED_BUFFER_BYTE_LENGTH
        );
    }

    #[test]
    fn binary_command_refuses_truncated_lengths_and_invalid_utf8() {
        assert_eq!(
            decode_command_error(&run_foundation_command(&[2, 0, 0, 0])).0,
            CanonicalErrorCode::MalformedLength.as_str()
        );
        assert_eq!(
            decode_command_error(&run_foundation_command(&[5, 1, 0, 0, 0, 0xff])).0,
            CanonicalErrorCode::InvalidUtf8.as_str()
        );
    }
}
