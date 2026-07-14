use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Write};

mod command;
mod foundation_command;
mod json_ingress;
mod mailbox_command;
mod private_randomness_command;
mod proof_suite_command;

const MAXIMUM_TRANSCRIPT_CORE_COMMAND_RESPONSE_BYTE_LENGTH: usize = 256 * 1024 * 1024;

#[cfg(test)]
use command::run_transcript_core_command_inner;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CanonicalErrorCode {
    DuplicateField,
    FixtureMismatch,
    InvalidChunkSize,
    InvalidEnum,
    InvalidFixture,
    InvalidProtocolObject,
    InvalidHex,
    InvalidUtf8,
    MalformedLength,
    MalformedMagic,
    MalformedVarUint,
    NonCanonicalVarUint,
    ComponentMismatch,
    TrailingBytes,
    UnsupportedObjectType,
    UnsupportedObjectVersion,
}

impl CanonicalErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateField => "DuplicateField",
            Self::FixtureMismatch => "FixtureMismatch",
            Self::InvalidChunkSize => "InvalidChunkSize",
            Self::InvalidEnum => "InvalidEnum",
            Self::InvalidFixture => "InvalidFixture",
            Self::InvalidProtocolObject => "InvalidProtocolObject",
            Self::InvalidHex => "InvalidHex",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::MalformedLength => "MalformedLength",
            Self::MalformedMagic => "MalformedMagic",
            Self::MalformedVarUint => "MalformedVarUint",
            Self::NonCanonicalVarUint => "NonCanonicalVarUint",
            Self::ComponentMismatch => "ComponentMismatch",
            Self::TrailingBytes => "TrailingBytes",
            Self::UnsupportedObjectType => "UnsupportedObjectType",
            Self::UnsupportedObjectVersion => "UnsupportedObjectVersion",
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

    pub fn to_json_value(&self) -> Value {
        json!({
            "code": self.code.as_str(),
            "message": self.message,
        })
    }
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CanonicalError {}

pub type CanonicalResult<T> = Result<T, CanonicalError>;

// LEB128: 7 payload bits per byte, high bit set marks a continuation byte.
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
            break;
        }
    }
    output
}

pub fn append_varuint(output: &mut Vec<u8>, value: u64) {
    output.extend(encode_varuint(value));
}

pub fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    append_varuint(output, value.len() as u64);
    output.extend(value);
}

pub fn append_string(output: &mut Vec<u8>, value: &str) {
    append_bytes(output, value.as_bytes());
}

pub struct CanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

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
        let slice = &self.bytes[self.offset..end];
        self.offset = end;

        Ok(slice)
    }

    pub fn read_varuint(&mut self) -> CanonicalResult<u64> {
        let start = self.offset;
        let mut shift = 0_u32;
        let mut value = 0_u64;

        for index in 0..10 {
            if self.offset >= self.bytes.len() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint is truncated",
                ));
            }

            let byte = self.bytes[self.offset];
            self.offset += 1;
            let payload = u64::from(byte & 0x7f);
            // 10th byte (index 9) carries only 1 usable bit of a u64; payload > 1
            // would overflow, so reject it.
            if index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint exceeds u64",
                ));
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                // Enforce minimal/canonical encoding: re-encode the decoded value
                // and require the consumed bytes to match exactly.
                let consumed = &self.bytes[start..self.offset];
                if consumed != encode_varuint(value).as_slice() {
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

    pub fn read_string(&mut self) -> CanonicalResult<String> {
        String::from_utf8(self.read_bytes()?).map_err(|_| {
            CanonicalError::new(CanonicalErrorCode::InvalidUtf8, "string is not valid UTF-8")
        })
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum_byte_length: usize,
    limit_exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(maximum_byte_length: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_byte_length,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let required_byte_length = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("command response byte length overflows usize"))?;
        if required_byte_length > self.maximum_byte_length {
            self.limit_exceeded = true;
            return Err(io::Error::other(
                "command response exceeds the accepted byte length",
            ));
        }
        if required_byte_length > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(buffer.len())
                .map_err(|_| io::Error::other("command response allocation failed"))?;
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_json_response_with_limit(
    response: &Value,
    maximum_byte_length: usize,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = BoundedJsonWriter::new(maximum_byte_length);
    if let Err(error) = serde_json::to_writer(&mut writer, response) {
        let (code, message) = if writer.limit_exceeded {
            (
                CanonicalErrorCode::MalformedLength,
                "command response exceeds the accepted byte length".to_owned(),
            )
        } else {
            (
                CanonicalErrorCode::InvalidProtocolObject,
                format!("command response serialization failed: {error}"),
            )
        };
        return Err(CanonicalError::new(code, message));
    }
    Ok(writer.bytes)
}

pub fn encode_success(value: Value) -> Vec<u8> {
    let response = json!({
        "success": true,
        "value": value,
    });
    encode_json_response_with_limit(
        &response,
        MAXIMUM_TRANSCRIPT_CORE_COMMAND_RESPONSE_BYTE_LENGTH,
    )
    .unwrap_or_else(encode_error)
}

pub fn encode_error(error: CanonicalError) -> Vec<u8> {
    let response = json!({
        "success": false,
        "error": error.to_json_value(),
    });
    encode_json_response_with_limit(
        &response,
        MAXIMUM_TRANSCRIPT_CORE_COMMAND_RESPONSE_BYTE_LENGTH,
    )
    .expect("serializing a bounded command error response should not fail")
}

pub fn run_transcript_core_command(input: &[u8]) -> Vec<u8> {
    let command_result = command::run_transcript_core_command_inner(input);

    match command_result {
        Ok(value) => encode_success(value),
        Err(error) => encode_error(error),
    }
}

pub(crate) fn run_accepted_setup_command(input: &[u8], session_handle: u32) -> Vec<u8> {
    match command::run_accepted_setup_command_inner(input, session_handle) {
        Ok(value) => encode_success(value),
        Err(error) => encode_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalErrorCode, CanonicalReader, append_varuint, encode_error,
        encode_json_response_with_limit, encode_varuint,
    };

    #[test]
    fn varuint_round_trips_boundary_values() {
        for value in [0, 1, 2, 127, 128, 255, 16_384, u32::MAX as u64, u64::MAX] {
            let encoded = encode_varuint(value);
            let mut reader = CanonicalReader::new(&encoded);

            assert_eq!(reader.read_varuint().expect("value should decode"), value);
            assert!(reader.is_finished());
        }
    }

    #[test]
    fn rejects_non_canonical_varuint() {
        let mut reader = CanonicalReader::new(&[0x80, 0x00]);
        let error = reader
            .read_varuint()
            .expect_err("redundant varuint should fail");

        assert_eq!(error.code, CanonicalErrorCode::NonCanonicalVarUint);
    }

    #[test]
    fn response_serialization_accepts_the_exact_boundary_and_refuses_one_byte_over() {
        let response = serde_json::json!({
            "success": true,
            "value": { "payload": "bounded response" },
        });
        let expected = serde_json::to_vec(&response).expect("test response serializes");
        assert_eq!(
            encode_json_response_with_limit(&response, expected.len())
                .expect("the exact response boundary must serialize"),
            expected
        );
        let error = encode_json_response_with_limit(&response, expected.len() - 1)
            .expect_err("one byte over the response limit must refuse");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn append_varuint_uses_canonical_encoding() {
        let mut output = Vec::new();
        append_varuint(&mut output, 128);

        assert_eq!(output, vec![0x80, 0x01]);
    }

    #[test]
    fn command_errors_are_json_encoded() {
        let encoded = encode_error(super::CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bad command",
        ));
        let response = String::from_utf8(encoded).expect("error should be UTF-8 JSON");

        assert!(response.contains("\"success\":false"));
        assert!(response.contains("\"InvalidFixture\""));
    }

    #[test]
    fn command_derives_canonical_object_hash_with_kernel_canonical_json() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "DeriveCanonicalObjectHash",
                "value": {
                    "objectType": "PollSpec",
                    "poll": "main"
                }
            })
            .to_string()
            .as_bytes(),
        )
        .expect("canonical object hash command should succeed");

        assert_eq!(
            response["canonicalObjectHash"]
                .as_str()
                .expect("canonical object hash")
                .len(),
            128
        );
        // A typeless value is rejected by the canonical-object domain.
        assert!(
            super::run_transcript_core_command_inner(
                serde_json::json!({
                    "command": "DeriveCanonicalObjectHash",
                    "value": { "poll": "main" }
                })
                .to_string()
                .as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn generic_command_refuses_setup_verification_without_an_opaque_session() {
        let error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "VerifyCollectiveBgvSetup",
                "setupPackage": {},
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("the generic command cannot own accepted-setup material roots");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert_eq!(
            error.message,
            "accepted setup verification requires an opaque material-ownership session"
        );
    }
}
