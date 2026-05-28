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

pub const FULLY_VERIFIED_RESULT_PROFILE_ID: &str =
    "transcript-core-fully-verified-result-profile-v1";
pub const PASSIVE_MHE_PROTOTYPE_PROFILE_ID: &str =
    "transcript-core-passive-mhe-prototype-profile-v1";
pub const ACTIVE_MALICIOUS_MHE_PROFILE_ID: &str = "transcript-core-active-malicious-mhe-profile-v1";
pub const NO_HE_SETUP_PROOF_PROFILE_ID: &str = "transcript-core-no-he-setup-proof-v1";
pub const MANDATORY_EVALUATION_PROOF_PROFILE_ID: &str = "PQEvalProof-STARK-BGVReplay-v1";
pub const NO_DECRYPTION_PROOF_PROFILE_ID: &str = "transcript-core-no-decryption-proof-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BaseClaimProfile {
    FullyVerifiedResult,
}

impl BaseClaimProfile {
    pub fn code(self) -> u64 {
        match self {
            Self::FullyVerifiedResult => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FullyVerifiedResult => "FullyVerifiedResult",
        }
    }

    pub fn expected_profile_id(self) -> &'static str {
        match self {
            Self::FullyVerifiedResult => FULLY_VERIFIED_RESULT_PROFILE_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MheSecurityClosure {
    PassiveMhePrototype,
    ActiveMalicious,
}

impl MheSecurityClosure {
    pub fn code(self) -> u64 {
        match self {
            Self::PassiveMhePrototype => 1,
            Self::ActiveMalicious => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::PassiveMhePrototype => "PassiveMHEPrototype",
            Self::ActiveMalicious => "ActiveMalicious",
        }
    }

    pub fn expected_profile_id(self) -> &'static str {
        match self {
            Self::PassiveMhePrototype => PASSIVE_MHE_PROTOTYPE_PROFILE_ID,
            Self::ActiveMalicious => ACTIVE_MALICIOUS_MHE_PROFILE_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptCoreProfile {
    pub base_claim_profile: BaseClaimProfile,
    pub mhe_security_closure: MheSecurityClosure,
}

impl TranscriptCoreProfile {
    pub const fn new(
        base_claim_profile: BaseClaimProfile,
        mhe_security_closure: MheSecurityClosure,
    ) -> Self {
        Self {
            base_claim_profile,
            mhe_security_closure,
        }
    }

    pub(super) fn seed_label(self) -> String {
        format!(
            "{}:{}",
            self.base_claim_profile.label(),
            self.mhe_security_closure.label()
        )
    }
}

pub const FULLY_VERIFIED_PASSIVE_MHE_PROFILE: TranscriptCoreProfile = TranscriptCoreProfile::new(
    BaseClaimProfile::FullyVerifiedResult,
    MheSecurityClosure::PassiveMhePrototype,
);
pub const FULLY_VERIFIED_ACTIVE_MALICIOUS_PROFILE: TranscriptCoreProfile =
    TranscriptCoreProfile::new(
        BaseClaimProfile::FullyVerifiedResult,
        MheSecurityClosure::ActiveMalicious,
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
    pub mhe_security_closure: MheSecurityClosure,
    pub base_claim_profile_id: String,
    pub mhe_security_profile_id: String,
    pub he_setup_proof_profile_id: String,
    pub evaluation_proof_profile_id: String,
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
    #[serde(rename = "mheSecurityClosure")]
    pub mhe_security_closure: &'static str,
    #[serde(rename = "baseClaimProfileId")]
    pub base_claim_profile_id: String,
    #[serde(rename = "mheSecurityProfileId")]
    pub mhe_security_profile_id: String,
    #[serde(rename = "heSetupProofProfileId")]
    pub he_setup_proof_profile_id: String,
    #[serde(rename = "evaluationProofProfileId")]
    pub evaluation_proof_profile_id: String,
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
