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
pub(super) const FIELD_STATUS: u64 = 4;
pub(super) const FIELD_TAGS: u64 = 5;
pub(super) const FIELD_CHECKPOINTS: u64 = 6;
pub(super) const REQUIRED_FIELDS: [u64; 6] = [
    FIELD_TITLE,
    FIELD_SEQUENCE,
    FIELD_PAYLOAD,
    FIELD_STATUS,
    FIELD_TAGS,
    FIELD_CHECKPOINTS,
];

pub const FOUNDATION_TRANSCRIPT_PROFILE_ID: &str =
    "transcript-core-foundation-transcript-profile-v1";
pub const FOUNDATION_ONLY_PROFILE_ID: &str = "transcript-core-foundation-only-profile-v1";
pub const NO_HE_SETUP_PROOF_PROFILE_ID: &str = "transcript-core-no-he-setup-proof-v1";
pub const NO_EVALUATOR_REPLAY_PROFILE_ID: &str = "transcript-core-no-evaluator-replay-proof-v1";
pub const NO_DECRYPTION_PROOF_PROFILE_ID: &str = "transcript-core-no-decryption-proof-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BaseClaimProfile {
    FoundationTranscript,
}

impl BaseClaimProfile {
    pub fn code(self) -> u64 {
        match self {
            Self::FoundationTranscript => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FoundationTranscript => "FoundationTranscript",
        }
    }

    pub fn expected_profile_id(self) -> &'static str {
        match self {
            Self::FoundationTranscript => FOUNDATION_TRANSCRIPT_PROFILE_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TranscriptCoreSecurityClosure {
    FoundationOnly,
}

impl TranscriptCoreSecurityClosure {
    pub fn code(self) -> u64 {
        match self {
            Self::FoundationOnly => 3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FoundationOnly => "FoundationOnly",
        }
    }

    pub fn expected_profile_id(self) -> &'static str {
        match self {
            Self::FoundationOnly => FOUNDATION_ONLY_PROFILE_ID,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptCoreProfile {
    pub base_claim_profile: BaseClaimProfile,
    pub security_closure: TranscriptCoreSecurityClosure,
}

#[cfg(test)]
impl TranscriptCoreProfile {
    pub const fn new(
        base_claim_profile: BaseClaimProfile,
        security_closure: TranscriptCoreSecurityClosure,
    ) -> Self {
        Self {
            base_claim_profile,
            security_closure,
        }
    }

    pub(super) fn seed_label(self) -> String {
        format!(
            "{}:{}",
            self.base_claim_profile.label(),
            self.security_closure.label()
        )
    }
}

#[cfg(test)]
pub const FOUNDATION_TRANSCRIPT_CORE_PROFILE: TranscriptCoreProfile = TranscriptCoreProfile::new(
    BaseClaimProfile::FoundationTranscript,
    TranscriptCoreSecurityClosure::FoundationOnly,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TranscriptCoreStatus {
    TranscriptCoreVerified,
}

impl TranscriptCoreStatus {
    pub fn code(self) -> u64 {
        match self {
            Self::TranscriptCoreVerified => 1,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TranscriptCoreVerified => "TranscriptCoreVerified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptCoreObject {
    pub base_claim_profile: BaseClaimProfile,
    pub security_closure: TranscriptCoreSecurityClosure,
    pub base_claim_profile_id: String,
    pub security_profile_id: String,
    pub he_setup_proof_profile_id: String,
    pub evaluator_replay_profile_id: String,
    pub decryption_proof_profile_id: String,
    pub title: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub status: TranscriptCoreStatus,
    pub tags: Vec<String>,
    pub checkpoints: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TranscriptCoreAnalysis {
    #[serde(rename = "canonicalBytesHex")]
    pub canonical_bytes_hex: String,
    #[serde(rename = "objectType")]
    pub object_type: &'static str,
    #[serde(rename = "objectVersion")]
    pub object_version: u64,
    #[serde(rename = "baseClaimProfile")]
    pub base_claim_profile: &'static str,
    #[serde(rename = "securityClosure")]
    pub security_closure: &'static str,
    #[serde(rename = "baseClaimProfileId")]
    pub base_claim_profile_id: String,
    #[serde(rename = "securityProfileId")]
    pub security_profile_id: String,
    #[serde(rename = "heSetupProofProfileId")]
    pub he_setup_proof_profile_id: String,
    #[serde(rename = "evaluatorReplayProfileId")]
    pub evaluator_replay_profile_id: String,
    #[serde(rename = "decryptionProofProfileId")]
    pub decryption_proof_profile_id: String,
    #[serde(rename = "objectHash512")]
    pub object_hash512: String,
    #[serde(rename = "chunkRoot")]
    pub chunk_root: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
    #[serde(rename = "statusLabels")]
    pub status_labels: Vec<&'static str>,
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
