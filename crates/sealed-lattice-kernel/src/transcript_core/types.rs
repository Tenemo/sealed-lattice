use serde::Serialize;
use serde_json::Value;

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(super) const MAGIC: &[u8; 4] = b"SLBE";
pub(super) const ENVELOPE_VERSION: u64 = 1;
pub(super) const TRANSCRIPT_CORE_OBJECT_TYPE: u64 = 1;
pub(super) const TRANSCRIPT_CORE_OBJECT_VERSION: u64 = 1;

pub(super) const FIELD_TITLE: u64 = 1;
pub(super) const FIELD_SEQUENCE: u64 = 2;
pub(super) const FIELD_PAYLOAD: u64 = 3;
pub(super) const FIELD_TAGS: u64 = 4;
pub(super) const FIELD_CHECKPOINTS: u64 = 5;
pub(super) const REQUIRED_FIELDS: [u64; 5] = [
    FIELD_TITLE,
    FIELD_SEQUENCE,
    FIELD_PAYLOAD,
    FIELD_TAGS,
    FIELD_CHECKPOINTS,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptCoreObject {
    pub title: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub tags: Vec<String>,
    pub checkpoints: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TranscriptCoreAnalysis {
    #[serde(rename = "canonicalBytesHex")]
    pub canonical_bytes_hex: String,
    #[serde(rename = "objectType")]
    pub object_type: &'static str,
    #[serde(rename = "objectHash512")]
    pub object_hash512: String,
    #[serde(rename = "chunkRoot")]
    pub chunk_root: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
    pub title: String,
    pub sequence: u64,
    #[serde(rename = "payloadHex")]
    pub payload_hex: String,
    pub tags: Vec<String>,
    pub checkpoints: Vec<u64>,
}

impl TranscriptCoreAnalysis {
    pub fn to_json_value(&self) -> CanonicalResult<Value> {
        serde_json::to_value(self).map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("analysis JSON serialization failed: {error}"),
            )
        })
    }
}
