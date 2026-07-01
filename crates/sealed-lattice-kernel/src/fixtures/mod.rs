use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::{analyze_canonical_object, decode_hex, parse_transcript_core_object},
};

#[cfg(test)]
use crate::transcript_core::{
    canonical_transcript_core_object, encode_hex, mutate_duplicate_field_fixture,
    mutate_field_order_fixture, mutate_invalid_utf8_fixture, mutate_malformed_length_fixture,
    mutate_malformed_magic_fixture, mutate_missing_field_fixture,
    mutate_non_canonical_varuint_fixture, mutate_trailing_bytes_fixture,
    mutate_unknown_field_fixture, mutate_unsupported_envelope_version_fixture,
    mutate_unsupported_object_type_fixture, mutate_unsupported_object_version_fixture,
    serialize_transcript_core_object,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum TranscriptCoreFixture {
    #[serde(rename = "golden-transcript-core")]
    GoldenTranscriptCore(Box<GoldenTranscriptCoreFixture>),
    #[serde(rename = "malformed-object")]
    MalformedObject(MalformedObjectFixture),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GoldenTranscriptCoreFixture {
    #[serde(rename = "fixtureVersion")]
    pub fixture_version: u64,
    #[serde(rename = "caseName")]
    pub case_name: String,
    #[serde(rename = "canonicalBytesHex")]
    pub canonical_bytes_hex: String,
    #[serde(rename = "objectType")]
    pub object_type: String,
    #[serde(rename = "objectVersion")]
    pub object_version: u64,
    #[serde(rename = "expectedObjectHash512")]
    pub expected_object_hash512: String,
    #[serde(rename = "expectedChunkRoot")]
    pub expected_chunk_root: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MalformedObjectFixture {
    #[serde(rename = "fixtureVersion")]
    pub fixture_version: u64,
    #[serde(rename = "caseName")]
    pub case_name: String,
    #[serde(rename = "canonicalBytesHex")]
    pub canonical_bytes_hex: String,
    #[serde(rename = "expectedErrorCode")]
    pub expected_error_code: String,
}

pub fn verify_fixture(fixture: &TranscriptCoreFixture) -> CanonicalResult<Value> {
    match fixture {
        TranscriptCoreFixture::GoldenTranscriptCore(golden_fixture) => {
            verify_golden_fixture(golden_fixture)
        }
        TranscriptCoreFixture::MalformedObject(malformed_fixture) => {
            verify_malformed_fixture(malformed_fixture)
        }
    }
}

#[cfg(test)]
pub fn canonical_fixture_set() -> CanonicalResult<Vec<TranscriptCoreFixture>> {
    Ok(vec![
        TranscriptCoreFixture::GoldenTranscriptCore(Box::new(build_golden_fixture(
            "foundation-transcript-roots",
        )?)),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "duplicate-field",
            mutate_duplicate_field_fixture(),
            CanonicalErrorCode::DuplicateField,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "field-order",
            mutate_field_order_fixture(),
            CanonicalErrorCode::FieldOrder,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "unknown-field",
            mutate_unknown_field_fixture(),
            CanonicalErrorCode::UnknownField,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "non-canonical-varuint",
            mutate_non_canonical_varuint_fixture(),
            CanonicalErrorCode::NonCanonicalVarUint,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "malformed-length",
            mutate_malformed_length_fixture(),
            CanonicalErrorCode::MalformedLength,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "trailing-bytes",
            mutate_trailing_bytes_fixture(),
            CanonicalErrorCode::TrailingBytes,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "malformed-magic",
            mutate_malformed_magic_fixture(),
            CanonicalErrorCode::MalformedMagic,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "unsupported-envelope-version",
            mutate_unsupported_envelope_version_fixture(),
            CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "unsupported-object-type",
            mutate_unsupported_object_type_fixture(),
            CanonicalErrorCode::UnsupportedObjectType,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "unsupported-object-version",
            mutate_unsupported_object_version_fixture(),
            CanonicalErrorCode::UnsupportedObjectVersion,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "missing-field",
            mutate_missing_field_fixture(),
            CanonicalErrorCode::MissingField,
        )),
        TranscriptCoreFixture::MalformedObject(build_malformed_fixture(
            "invalid-utf8",
            mutate_invalid_utf8_fixture(),
            CanonicalErrorCode::InvalidUtf8,
        )),
    ])
}

fn verify_golden_fixture(fixture: &GoldenTranscriptCoreFixture) -> CanonicalResult<Value> {
    if fixture.fixture_version != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "fixtureVersion must be 1",
        ));
    }
    let canonical_bytes = decode_hex(&fixture.canonical_bytes_hex)?;
    let analysis = analyze_canonical_object(&canonical_bytes, fixture.chunk_size)?;

    compare_fixture_value(
        "objectType",
        fixture.object_type.as_str(),
        analysis.object_type,
    )?;
    compare_fixture_value(
        "objectVersion",
        fixture.object_version,
        analysis.object_version,
    )?;
    compare_fixture_value(
        "expectedObjectHash512",
        fixture.expected_object_hash512.as_str(),
        analysis.object_hash512.as_str(),
    )?;
    compare_fixture_value(
        "expectedChunkRoot",
        fixture.expected_chunk_root.as_str(),
        analysis.chunk_root.as_str(),
    )?;
    Ok(json!({
        "caseName": fixture.case_name,
        "objectHash512": analysis.object_hash512,
        "chunkRoot": analysis.chunk_root,
    }))
}

fn verify_malformed_fixture(fixture: &MalformedObjectFixture) -> CanonicalResult<Value> {
    if fixture.fixture_version != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "fixtureVersion must be 1",
        ));
    }
    let canonical_bytes = decode_hex(&fixture.canonical_bytes_hex)?;
    let error = match parse_transcript_core_object(&canonical_bytes) {
        Ok(_) => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::FixtureMismatch,
                "malformed fixture unexpectedly parsed",
            ));
        }
        Err(error) => error,
    };
    if error.code.as_str() != fixture.expected_error_code {
        return Err(CanonicalError::new(
            CanonicalErrorCode::FixtureMismatch,
            format!(
                "expected {}, received {}",
                fixture.expected_error_code,
                error.code.as_str(),
            ),
        ));
    }

    Ok(json!({
        "caseName": fixture.case_name,
        "expectedErrorCode": error.code.as_str(),
    }))
}

#[cfg(test)]
fn build_golden_fixture(case_name: &str) -> CanonicalResult<GoldenTranscriptCoreFixture> {
    let object = canonical_transcript_core_object();
    let canonical_bytes = serialize_transcript_core_object(&object);
    let analysis = analyze_canonical_object(&canonical_bytes, 8)?;

    Ok(GoldenTranscriptCoreFixture {
        fixture_version: 1,
        case_name: case_name.to_string(),
        canonical_bytes_hex: encode_hex(&canonical_bytes),
        object_type: analysis.object_type.to_string(),
        object_version: analysis.object_version,
        expected_object_hash512: analysis.object_hash512,
        expected_chunk_root: analysis.chunk_root,
        chunk_size: analysis.chunk_size,
    })
}

#[cfg(test)]
fn build_malformed_fixture(
    case_name: &str,
    canonical_bytes_hex: String,
    expected_error_code: CanonicalErrorCode,
) -> MalformedObjectFixture {
    MalformedObjectFixture {
        fixture_version: 1,
        case_name: case_name.to_string(),
        canonical_bytes_hex,
        expected_error_code: expected_error_code.as_str().to_string(),
    }
}

fn compare_fixture_value<T>(name: &str, expected: T, actual: T) -> CanonicalResult<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if expected != actual {
        return Err(CanonicalError::new(
            CanonicalErrorCode::FixtureMismatch,
            format!("{name} mismatch: expected {expected:?}, received {actual:?}"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{canonical_fixture_set, verify_fixture};

    #[test]
    fn canonical_fixture_set_verifies() {
        for fixture in canonical_fixture_set().expect("fixtures should build") {
            verify_fixture(&fixture).expect("fixture should verify");
        }
    }
}
