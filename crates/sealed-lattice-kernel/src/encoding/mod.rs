use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Write};

use crate::{
    hashing::{chunk_root, hash512_hex},
    ring::{
        MAXIMUM_SHAMIR_INTERPOLATION_POINTS, ShamirSharePoint, evaluate_plaintext_comparison,
        interpolate_shamir_constant_term,
    },
};

mod command;
mod json_ingress;

const MAXIMUM_TRANSCRIPT_CORE_COMMAND_RESPONSE_BYTE_LENGTH: usize = 256 * 1024 * 1024;

#[cfg(test)]
use command::run_transcript_core_command_inner;

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
    ComponentMismatch,
    TrailingBytes,
    UnknownField,
    UnsupportedCanonicalEnvelopeVersion,
    UnsupportedObjectType,
    UnsupportedObjectVersion,
}

/// All canonical error code variants in declaration order.
///
/// Adding a new variant to `CanonicalErrorCode` requires extending this slice.
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
    CanonicalErrorCode::ComponentMismatch,
    CanonicalErrorCode::TrailingBytes,
    CanonicalErrorCode::UnknownField,
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
            Self::ComponentMismatch => "ComponentMismatch",
            Self::TrailingBytes => "TrailingBytes",
            Self::UnknownField => "UnknownField",
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

pub(crate) fn run_accepted_setup_command(
    input: &[u8],
    session_handle: u32,
    capability: &[u8; crate::foundation::CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Vec<u8> {
    match command::run_accepted_setup_command_inner(input, session_handle, capability) {
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
    use crate::foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, ProofObjectHeader,
    };

    fn foundation_item_tuple_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001_u16.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&0x03_u16.to_le_bytes());
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0201_u16.to_le_bytes());
        bytes.extend_from_slice(&0x01_u16.to_le_bytes());
        bytes.extend_from_slice(&7_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[7, 8, 9]);
        bytes
    }

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

    #[test]
    fn command_validates_and_hashes_foundation_canonical_items() {
        let tuple_bytes = foundation_item_tuple_bytes();
        let tuple_hex = crate::transcript_core::encode_hex(&tuple_bytes);
        let validation = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationCanonicalTuple",
                "canonicalTupleHex": tuple_hex,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("foundation tuple should validate");
        assert_eq!(validation["schemaIdentifier"], 1);
        assert_eq!(validation["schemaVersion"], 1);
        assert_eq!(validation["itemCount"], 2);
        assert_eq!(validation["canonicalTupleHex"], tuple_hex);

        let hash = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ComputeFoundationHash512",
                "domain": "sealed-lattice/test/hash/v1",
                "canonicalItemsTupleHex": tuple_hex,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("foundation hash should derive");
        assert_eq!(
            hash["hash512"]
                .as_str()
                .expect("foundation hash should be a string")
                .len(),
            128
        );
    }

    #[test]
    fn command_refuses_trailing_and_hostile_foundation_tuple_lengths() {
        let mut trailing_bytes = foundation_item_tuple_bytes();
        trailing_bytes.push(0);
        let trailing_error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationCanonicalTuple",
                "canonicalTupleHex": crate::transcript_core::encode_hex(&trailing_bytes),
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("trailing bytes must refuse");
        assert_eq!(trailing_error.code, CanonicalErrorCode::TrailingBytes);

        let mut hostile_count = Vec::new();
        hostile_count.extend_from_slice(&0x0001_u16.to_le_bytes());
        hostile_count.extend_from_slice(&1_u16.to_le_bytes());
        hostile_count.extend_from_slice(&u32::MAX.to_le_bytes());
        let count_error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationCanonicalTuple",
                "canonicalTupleHex": crate::transcript_core::encode_hex(&hostile_count),
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("hostile item count must refuse before allocation");
        assert_eq!(count_error.code, CanonicalErrorCode::MalformedLength);

        let mut hostile_item_length = Vec::new();
        hostile_item_length.extend_from_slice(&0x0001_u16.to_le_bytes());
        hostile_item_length.extend_from_slice(&1_u16.to_le_bytes());
        hostile_item_length.extend_from_slice(&1_u32.to_le_bytes());
        hostile_item_length.extend_from_slice(&0x01_u16.to_le_bytes());
        hostile_item_length.extend_from_slice(&u32::MAX.to_le_bytes());
        let length_error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationCanonicalTuple",
                "canonicalTupleHex": crate::transcript_core::encode_hex(&hostile_item_length),
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("hostile item length must refuse before allocation");
        assert_eq!(length_error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn schema_object_command_accepts_the_copy_boundary_and_refuses_one_byte_over() {
        const PROOF_HEADER_AND_INNER_TUPLE_OVERHEAD_BYTE_LENGTH: usize = 32;

        let maximum_byte_length = FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
        let inner_payload_byte_length = maximum_byte_length
            .checked_sub(PROOF_HEADER_AND_INNER_TUPLE_OVERHEAD_BYTE_LENGTH)
            .expect("foundation copy boundary holds the canonical framing");
        let canonical_application_statement = CanonicalTuple::new(
            0x7fff,
            1,
            vec![
                CanonicalItem::fixed_bytes(vec![0x5a; inner_payload_byte_length])
                    .expect("boundary payload fits the canonical item limit"),
            ],
        )
        .encode()
        .expect("boundary application statement encodes");
        let canonical_object = ProofObjectHeader {
            canonical_application_statement,
        }
        .encode(&CanonicalDecodeLimits::default())
        .expect("boundary proof header encodes");
        assert_eq!(canonical_object.len(), maximum_byte_length);

        let validation = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationSchemaObject",
                "canonicalObjectHex": crate::transcript_core::encode_hex(&canonical_object),
            })
            .to_string()
            .as_bytes(),
        )
        .expect("the exact foundation copy boundary must validate");
        assert_eq!(validation["canonicalByteLength"], maximum_byte_length);

        let mut one_byte_over = canonical_object;
        one_byte_over.push(0);
        let error = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "ValidateFoundationSchemaObject",
                "canonicalObjectHex": crate::transcript_core::encode_hex(&one_byte_over),
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("one byte over the foundation copy boundary must refuse before decoding");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn command_derives_identity_only_from_an_exact_ml_dsa_key() {
        let signing_verification_key_hex = "00".repeat(1_952);
        let identity = super::run_transcript_core_command_inner(
            serde_json::json!({
                "command": "DeriveFoundationParticipantIdentity",
                "signingVerificationKeyHex": signing_verification_key_hex,
            })
            .to_string()
            .as_bytes(),
        )
        .expect("an exact ML-DSA-65 key should derive an identity");
        assert_eq!(
            identity["participantIdentity"]
                .as_str()
                .expect("participant identity should be a string")
                .len(),
            128
        );

        for invalid_byte_length in [0, 1_951, 1_953] {
            let error = super::run_transcript_core_command_inner(
                serde_json::json!({
                    "command": "DeriveFoundationParticipantIdentity",
                    "signingVerificationKeyHex": "00".repeat(invalid_byte_length),
                })
                .to_string()
                .as_bytes(),
            )
            .expect_err("an inexact ML-DSA-65 key length must refuse");
            assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        }
    }
}
