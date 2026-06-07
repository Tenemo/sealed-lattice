use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    fixtures::{TranscriptCoreFixture, verify_fixture},
    hashing::{RESERVED_ROOT_NAMESPACES, chunk_root, derive_protocol_hash, hash512_hex},
    ring::{
        MAXIMUM_SHAMIR_INTERPOLATION_POINTS, ShamirSharePoint, evaluate_plaintext_comparison,
        interpolate_shamir_constant_term,
    },
    transcript_core::analyze_canonical_object_hex,
};

mod command;

#[cfg(test)]
use command::run_transcript_core_command_inner;

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
    InvalidProtocolObject,
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
    UnknownSecurityClosure,
    UnknownProofProfile,
    UnsupportedCanonicalEnvelopeVersion,
    UnsupportedObjectType,
    UnsupportedObjectVersion,
}

/// All canonical error code variants in declaration order.
///
/// Adding a new variant to `CanonicalErrorCode` requires extending this slice
/// and the exhaustive `match` in `all_canonical_error_codes_is_exhaustive`.
/// The compiler enforces both.
pub const ALL_CANONICAL_ERROR_CODES: &[CanonicalErrorCode] = &[
    CanonicalErrorCode::DuplicateField,
    CanonicalErrorCode::FieldOrder,
    CanonicalErrorCode::FixtureMismatch,
    CanonicalErrorCode::InvalidChunkSize,
    CanonicalErrorCode::InvalidEnum,
    CanonicalErrorCode::InvalidFixture,
    CanonicalErrorCode::InvalidProtocolObject,
    CanonicalErrorCode::InvalidHex,
    CanonicalErrorCode::InvalidUtf8,
    CanonicalErrorCode::MalformedLength,
    CanonicalErrorCode::MalformedMagic,
    CanonicalErrorCode::MalformedVarUint,
    CanonicalErrorCode::MissingField,
    CanonicalErrorCode::NonCanonicalVarUint,
    CanonicalErrorCode::ProfileComponentMismatch,
    CanonicalErrorCode::TrailingBytes,
    CanonicalErrorCode::UnknownField,
    CanonicalErrorCode::UnknownBaseClaimProfile,
    CanonicalErrorCode::UnknownSecurityClosure,
    CanonicalErrorCode::UnknownProofProfile,
    CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion,
    CanonicalErrorCode::UnsupportedObjectType,
    CanonicalErrorCode::UnsupportedObjectVersion,
];

impl CanonicalErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateField => "DuplicateField",
            Self::FieldOrder => "FieldOrder",
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
            Self::MissingField => "MissingField",
            Self::NonCanonicalVarUint => "NonCanonicalVarUint",
            Self::ProfileComponentMismatch => "ProfileComponentMismatch",
            Self::TrailingBytes => "TrailingBytes",
            Self::UnknownField => "UnknownField",
            Self::UnknownBaseClaimProfile => "UnknownBaseClaimProfile",
            Self::UnknownSecurityClosure => "UnknownSecurityClosure",
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
    let command_result = command::run_transcript_core_command_inner(input);

    match command_result {
        Ok(value) => encode_success(value),
        Err(error) => encode_error(error),
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

    #[test]
    fn command_rejects_missing_command_with_stable_message() {
        let error = super::run_transcript_core_command_inner(br#"{}"#)
            .expect_err("missing command should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert_eq!(error.message, "command must be a string");
    }

    #[test]
    fn command_rejects_unknown_command_with_stable_message() {
        let error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "NotACommand"
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("unknown command should fail");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert_eq!(error.message, "unsupported command: NotACommand");
    }

    #[test]
    fn command_derives_protocol_hash_with_kernel_canonical_json() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "DeriveProtocolHash",
                "namespace": "PollSpecHash",
                "value": {
                    "poll": "main"
                }
            })
            .to_string()
            .as_bytes(),
        )
        .expect("protocol hash command should succeed");

        assert_eq!(
            response["protocolHash"],
            "43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4"
        );
    }

    #[test]
    fn command_exposes_kernel_field_interpolation() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "InterpolateShamirConstantTerm",
                "sharePoints": [
                    { "rosterPosition": 1, "value": 15 },
                    { "rosterPosition": 2, "value": 25 }
                ]
            })
            .to_string()
            .as_bytes(),
        )
        .expect("field interpolation command should succeed");

        assert_eq!(response["fieldElement"], 5);
    }

    #[test]
    fn command_exposes_plaintext_comparison() {
        let response = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "EvaluatePlaintextComparison",
                "leftTotalScore": 41,
                "rightTotalScore": 40,
                "rosterSize": 5
            })
            .to_string()
            .as_bytes(),
        )
        .expect("plaintext comparison command should succeed");

        assert_eq!(response["greaterThan"], 1);
        assert_eq!(response["equal"], 0);
        assert_eq!(response["scoreDifference"], 1);
    }

    #[test]
    fn all_canonical_error_codes_is_exhaustive() {
        // The compiler enforces exhaustiveness here. If a new variant is added
        // to `CanonicalErrorCode`, this match fails and the dev must extend
        // both the match arm and `ALL_CANONICAL_ERROR_CODES`.
        fn ensure_exhaustive(code: CanonicalErrorCode) {
            match code {
                CanonicalErrorCode::DuplicateField
                | CanonicalErrorCode::FieldOrder
                | CanonicalErrorCode::FixtureMismatch
                | CanonicalErrorCode::InvalidChunkSize
                | CanonicalErrorCode::InvalidEnum
                | CanonicalErrorCode::InvalidFixture
                | CanonicalErrorCode::InvalidProtocolObject
                | CanonicalErrorCode::InvalidHex
                | CanonicalErrorCode::InvalidUtf8
                | CanonicalErrorCode::MalformedLength
                | CanonicalErrorCode::MalformedMagic
                | CanonicalErrorCode::MalformedVarUint
                | CanonicalErrorCode::MissingField
                | CanonicalErrorCode::NonCanonicalVarUint
                | CanonicalErrorCode::ProfileComponentMismatch
                | CanonicalErrorCode::TrailingBytes
                | CanonicalErrorCode::UnknownField
                | CanonicalErrorCode::UnknownBaseClaimProfile
                | CanonicalErrorCode::UnknownSecurityClosure
                | CanonicalErrorCode::UnknownProofProfile
                | CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion
                | CanonicalErrorCode::UnsupportedObjectType
                | CanonicalErrorCode::UnsupportedObjectVersion => {}
            }
        }

        for code in super::ALL_CANONICAL_ERROR_CODES {
            ensure_exhaustive(code.clone());
        }

        assert_eq!(super::ALL_CANONICAL_ERROR_CODES.len(), 23);
    }
}
