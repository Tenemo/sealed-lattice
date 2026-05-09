use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    fixtures::{TranscriptCoreFixture, verify_fixture},
    hashing::{chunk_root, hash512_hex},
    transcript_core::{analyze_canonical_object_hex, invalid_response},
};

pub const MODULE_MARKER: &str = "encoding";
pub const TRANSCRIPT_CORE_COMMAND_CONTRACT_VERSION: &str =
    "sealed-lattice-transcript-core-command-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CanonicalErrorCode {
    DuplicateField,
    FieldOrder,
    FixtureMismatch,
    InvalidChunkSize,
    InvalidEnum,
    InvalidFixture,
    InvalidHex,
    InvalidUtf8,
    MalformedLength,
    MalformedMagic,
    MalformedVarUint,
    MissingField,
    NonCanonicalVarUint,
    ProfileComponentMismatch,
    TrailingBytes,
    UnknownField,
    UnknownBaseClaimProfile,
    UnknownMheSecurityStage,
    UnknownProofProfile,
    UnsupportedCanonicalEnvelopeVersion,
    UnsupportedObjectType,
    UnsupportedObjectVersion,
}

impl CanonicalErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateField => "DuplicateField",
            Self::FieldOrder => "FieldOrder",
            Self::FixtureMismatch => "FixtureMismatch",
            Self::InvalidChunkSize => "InvalidChunkSize",
            Self::InvalidEnum => "InvalidEnum",
            Self::InvalidFixture => "InvalidFixture",
            Self::InvalidHex => "InvalidHex",
            Self::InvalidUtf8 => "InvalidUtf8",
            Self::MalformedLength => "MalformedLength",
            Self::MalformedMagic => "MalformedMagic",
            Self::MalformedVarUint => "MalformedVarUint",
            Self::MissingField => "MissingField",
            Self::NonCanonicalVarUint => "NonCanonicalVarUint",
            Self::ProfileComponentMismatch => "ProfileComponentMismatch",
            Self::TrailingBytes => "TrailingBytes",
            Self::UnknownField => "UnknownField",
            Self::UnknownBaseClaimProfile => "UnknownBaseClaimProfile",
            Self::UnknownMheSecurityStage => "UnknownMheSecurityStage",
            Self::UnknownProofProfile => "UnknownProofProfile",
            Self::UnsupportedCanonicalEnvelopeVersion => "UnsupportedCanonicalEnvelopeVersion",
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

pub fn roundtrip_bytes(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

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

    pub fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
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
            if index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedVarUint,
                    "varuint exceeds u64",
                ));
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
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

pub fn encode_success(value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "success": true,
        "value": value,
    }))
    .expect("serializing command success response should not fail")
}

pub fn encode_error(error: CanonicalError) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "success": false,
        "error": error.to_json_value(),
    }))
    .expect("serializing command error response should not fail")
}

pub fn run_transcript_core_command(input: &[u8]) -> Vec<u8> {
    let command_result = run_transcript_core_command_inner(input);

    match command_result {
        Ok(value) => encode_success(value),
        Err(error) => encode_error(error),
    }
}

fn run_transcript_core_command_inner(input: &[u8]) -> CanonicalResult<Value> {
    let request: Value = serde_json::from_slice(input).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("command JSON is invalid: {error}"),
        )
    })?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "command must be a string",
            )
        })?;

    match command {
        "AnalyzeCanonicalObject" => {
            let canonical_bytes_hex = request
                .get("canonicalBytesHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "canonicalBytesHex must be a string",
                    )
                })?;
            let chunk_size = request
                .get("chunkSize")
                .and_then(Value::as_u64)
                .unwrap_or(16);

            analyze_canonical_object_hex(canonical_bytes_hex, chunk_size)
        }
        "ComputeChunkRoot" => {
            let input_hex = request
                .get("inputHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "inputHex must be a string",
                    )
                })?;
            let chunk_size = request
                .get("chunkSize")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "chunkSize must be an integer",
                    )
                })?;
            let bytes = crate::transcript_core::decode_hex(input_hex)?;
            let root = chunk_root(
                &bytes,
                usize::try_from(chunk_size).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidChunkSize,
                        "chunkSize does not fit usize",
                    )
                })?,
            )?;

            Ok(json!({
                "chunkRoot": root,
            }))
        }
        "HashRaw" => {
            let input_hex = request
                .get("inputHex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "inputHex must be a string",
                    )
                })?;
            let bytes = crate::transcript_core::decode_hex(input_hex)?;

            Ok(json!({
                "hash512": hash512_hex("transcript-core/raw", &[&bytes]),
            }))
        }
        "VerifyFixture" => {
            let fixture_value = request.get("fixture").ok_or_else(|| {
                CanonicalError::new(CanonicalErrorCode::InvalidFixture, "fixture is required")
            })?;
            let fixture: TranscriptCoreFixture = serde_json::from_value(fixture_value.clone())
                .map_err(|error| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("fixture shape is invalid: {error}"),
                    )
                })?;

            verify_fixture(&fixture)
        }
        _ => invalid_response(
            CanonicalErrorCode::InvalidFixture,
            format!("unsupported command: {command}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalErrorCode, CanonicalReader, append_varuint, encode_error, encode_varuint,
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
}
