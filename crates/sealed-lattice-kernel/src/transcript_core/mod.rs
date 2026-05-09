use serde::Serialize;
use serde_json::Value;

use crate::{
    encoding::{
        CanonicalError, CanonicalErrorCode, CanonicalReader, CanonicalResult, append_bytes,
        append_string, append_varuint,
    },
    hashing::{chunk_root, object_root, to_hex},
};

pub const MODULE_MARKER: &str = "transcript-core";

const MAGIC: &[u8; 4] = b"SLBE";
const ENVELOPE_VERSION: u64 = 1;
const TRANSCRIPT_CORE_OBJECT_TYPE: u64 = 1;
const TRANSCRIPT_CORE_OBJECT_VERSION: u64 = 1;

const FIELD_TITLE: u64 = 1;
const FIELD_SEQUENCE: u64 = 2;
const FIELD_PAYLOAD: u64 = 3;
const FIELD_STATUS: u64 = 4;
const FIELD_TAGS: u64 = 5;
const FIELD_CHECKPOINTS: u64 = 6;
const REQUIRED_FIELDS: [u64; 6] = [
    FIELD_TITLE,
    FIELD_SEQUENCE,
    FIELD_PAYLOAD,
    FIELD_STATUS,
    FIELD_TAGS,
    FIELD_CHECKPOINTS,
];

pub const PASSIVE_AUDIT_PROOF_PROFILE_ID: &str = "transcript-core-passive-audit-proof-profile-v1";
pub const EVALUATION_PROOF_PROFILE_ID: &str = "transcript-core-evaluation-proof-profile-v1";
pub const ACTIVE_SECURITY_PROOF_PROFILE_ID: &str =
    "transcript-core-active-security-proof-profile-v1";
pub const NO_HE_SETUP_PROOF_PROFILE_ID: &str = "transcript-core-no-he-setup-proof-v1";
pub const NO_EVALUATION_PROOF_PROFILE_ID: &str = "transcript-core-no-evaluation-proof-v1";
pub const OPTIONAL_EVALUATION_PROOF_PROFILE_ID: &str =
    "transcript-core-optional-evaluation-proof-profile-v1";
pub const NO_DECRYPTION_PROOF_PROFILE_ID: &str = "transcript-core-no-decryption-proof-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SecurityProfile {
    PassiveAudit,
    EvaluationProof,
    ActiveSecurity,
}

impl SecurityProfile {
    pub fn code(self) -> u64 {
        match self {
            Self::PassiveAudit => 1,
            Self::EvaluationProof => 3,
            Self::ActiveSecurity => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::PassiveAudit => "PassiveAudit",
            Self::EvaluationProof => "EvaluationProof",
            Self::ActiveSecurity => "ActiveSecurity",
        }
    }

    pub fn expected_proof_profile_id(self) -> &'static str {
        match self {
            Self::PassiveAudit => PASSIVE_AUDIT_PROOF_PROFILE_ID,
            Self::EvaluationProof => EVALUATION_PROOF_PROFILE_ID,
            Self::ActiveSecurity => ACTIVE_SECURITY_PROOF_PROFILE_ID,
        }
    }
}

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
    pub security_profile: SecurityProfile,
    pub proof_profile_id: String,
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

pub struct DeterministicFixtureRng {
    seed: Vec<u8>,
    counter: u64,
    buffer: [u8; 64],
    offset: usize,
}

impl DeterministicFixtureRng {
    pub fn new(seed: &str) -> Self {
        Self {
            seed: seed.as_bytes().to_vec(),
            counter: 0,
            buffer: [0_u8; 64],
            offset: 64,
        }
    }

    pub fn next_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            let available = self.buffer.len() - self.offset;
            let needed = length - output.len();
            let copied = available.min(needed);
            output.extend_from_slice(&self.buffer[self.offset..self.offset + copied]);
            self.offset += copied;
        }

        output
    }

    pub fn next_u64_below(&mut self, exclusive_upper_bound: u64) -> CanonicalResult<u64> {
        if exclusive_upper_bound == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "deterministic fixture RNG bound must be greater than zero",
            ));
        }

        let bytes = self.next_bytes(8);
        let mut value = 0_u64;
        for byte in bytes {
            value = (value << 8) | u64::from(byte);
        }

        Ok(value % exclusive_upper_bound)
    }

    fn refill(&mut self) {
        let mut counter_bytes = Vec::new();
        append_varuint(&mut counter_bytes, self.counter);
        self.buffer = crate::hashing::hash512(
            "transcript-core/deterministic-fixture-rng-block",
            &[&self.seed, &counter_bytes],
        );
        self.counter += 1;
        self.offset = 0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TranscriptCoreAnalysis {
    #[serde(rename = "canonicalBytesHex")]
    pub canonical_bytes_hex: String,
    #[serde(rename = "objectType")]
    pub object_type: &'static str,
    #[serde(rename = "objectVersion")]
    pub object_version: u64,
    #[serde(rename = "securityProfile")]
    pub security_profile: &'static str,
    #[serde(rename = "proofProfileId")]
    pub proof_profile_id: String,
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

pub fn invalid_response(
    error_code: CanonicalErrorCode,
    message: impl Into<String>,
) -> CanonicalResult<Value> {
    Err(CanonicalError::new(error_code, message))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

pub fn decode_hex(hex: &str) -> CanonicalResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "hex string must have an even length",
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut index = 0;
    while index < hex.len() {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string contains a non-hexadecimal byte",
            )
        })?;
        bytes.push(byte);
        index += 2;
    }

    Ok(bytes)
}

pub fn canonical_transcript_core_object(security_profile: SecurityProfile) -> TranscriptCoreObject {
    let mut fixture_rng = DeterministicFixtureRng::new(security_profile.label());

    TranscriptCoreObject {
        security_profile,
        proof_profile_id: security_profile.expected_proof_profile_id().to_string(),
        he_setup_proof_profile_id: NO_HE_SETUP_PROOF_PROFILE_ID.to_string(),
        evaluation_proof_profile_id: match security_profile {
            SecurityProfile::EvaluationProof => OPTIONAL_EVALUATION_PROOF_PROFILE_ID.to_string(),
            SecurityProfile::PassiveAudit | SecurityProfile::ActiveSecurity => {
                NO_EVALUATION_PROOF_PROFILE_ID.to_string()
            }
        },
        decryption_proof_profile_id: NO_DECRYPTION_PROOF_PROFILE_ID.to_string(),
        title: match security_profile {
            SecurityProfile::PassiveAudit => "Transcript core passive audit".to_string(),
            SecurityProfile::EvaluationProof => "Transcript core evaluation proof".to_string(),
            SecurityProfile::ActiveSecurity => "Transcript core active security".to_string(),
        },
        sequence: match security_profile {
            SecurityProfile::PassiveAudit => 42,
            SecurityProfile::EvaluationProof => 44,
            SecurityProfile::ActiveSecurity => 43,
        },
        payload: fixture_rng.next_bytes(6),
        status: TranscriptCoreStatus::TranscriptCoreVerified,
        tags: match security_profile {
            SecurityProfile::PassiveAudit => vec![
                "canonical".to_string(),
                "passive-audit".to_string(),
                "wasm-parity".to_string(),
            ],
            SecurityProfile::EvaluationProof => vec![
                "canonical".to_string(),
                "evaluation-proof".to_string(),
                "optional-proof-reserved".to_string(),
            ],
            SecurityProfile::ActiveSecurity => vec![
                "canonical".to_string(),
                "active-security".to_string(),
                "profile-reserved".to_string(),
            ],
        },
        checkpoints: match security_profile {
            SecurityProfile::PassiveAudit => vec![1, 3, 5, 8, 13],
            SecurityProfile::EvaluationProof => vec![3, 6, 9, 12, 15],
            SecurityProfile::ActiveSecurity => vec![2, 4, 8, 16, 32],
        },
    }
}

pub fn serialize_transcript_core_object(object: &TranscriptCoreObject) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(MAGIC);
    append_varuint(&mut output, ENVELOPE_VERSION);
    append_varuint(&mut output, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut output, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut output, object.security_profile.code());
    append_string(&mut output, &object.proof_profile_id);
    append_string(&mut output, &object.he_setup_proof_profile_id);
    append_string(&mut output, &object.evaluation_proof_profile_id);
    append_string(&mut output, &object.decryption_proof_profile_id);
    append_varuint(&mut output, REQUIRED_FIELDS.len() as u64);

    append_varuint(&mut output, FIELD_TITLE);
    append_string(&mut output, &object.title);
    append_varuint(&mut output, FIELD_SEQUENCE);
    append_varuint(&mut output, object.sequence);
    append_varuint(&mut output, FIELD_PAYLOAD);
    append_bytes(&mut output, &object.payload);
    append_varuint(&mut output, FIELD_STATUS);
    append_varuint(&mut output, object.status.code());
    append_varuint(&mut output, FIELD_TAGS);
    append_varuint(&mut output, object.tags.len() as u64);
    for tag in &object.tags {
        append_string(&mut output, tag);
    }
    append_varuint(&mut output, FIELD_CHECKPOINTS);
    append_varuint(&mut output, object.checkpoints.len() as u64);
    for checkpoint in &object.checkpoints {
        append_varuint(&mut output, *checkpoint);
    }

    output
}

pub fn parse_transcript_core_object(bytes: &[u8]) -> CanonicalResult<TranscriptCoreObject> {
    let mut reader = CanonicalReader::new(bytes);
    if reader.read_exact(MAGIC.len())? != MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedMagic,
            "object does not start with SLBE magic",
        ));
    }

    let envelope_version = reader.read_varuint()?;
    if envelope_version != ENVELOPE_VERSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedEnvelopeVersion,
            "unsupported envelope version",
        ));
    }

    let object_type = reader.read_varuint()?;
    if object_type != TRANSCRIPT_CORE_OBJECT_TYPE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "unsupported object type",
        ));
    }

    let object_version = reader.read_varuint()?;
    if object_version != TRANSCRIPT_CORE_OBJECT_VERSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "unsupported object version",
        ));
    }

    let security_profile = parse_security_profile(reader.read_varuint()?)?;
    let proof_profile_id = reader.read_string()?;
    let he_setup_proof_profile_id = reader.read_string()?;
    let evaluation_proof_profile_id = reader.read_string()?;
    let decryption_proof_profile_id = reader.read_string()?;
    validate_profiles(
        security_profile,
        &proof_profile_id,
        &he_setup_proof_profile_id,
        &evaluation_proof_profile_id,
        &decryption_proof_profile_id,
    )?;

    let field_count = reader.read_varuint()?;

    let mut previous_field_id = 0_u64;
    let mut title = None;
    let mut sequence = None;
    let mut payload = None;
    let mut status = None;
    let mut tags = None;
    let mut checkpoints = None;

    for _ in 0..field_count {
        let field_id = reader.read_varuint()?;
        if field_id == previous_field_id {
            return Err(CanonicalError::new(
                CanonicalErrorCode::DuplicateField,
                "field ID is duplicated",
            ));
        }
        if field_id < previous_field_id {
            return Err(CanonicalError::new(
                CanonicalErrorCode::FieldOrder,
                "field IDs must be strictly increasing",
            ));
        }
        previous_field_id = field_id;

        match field_id {
            FIELD_TITLE => title = Some(reader.read_string()?),
            FIELD_SEQUENCE => sequence = Some(reader.read_varuint()?),
            FIELD_PAYLOAD => payload = Some(reader.read_bytes()?),
            FIELD_STATUS => status = Some(parse_status(reader.read_varuint()?)?),
            FIELD_TAGS => tags = Some(read_string_list(&mut reader)?),
            FIELD_CHECKPOINTS => checkpoints = Some(read_varuint_list(&mut reader)?),
            _ => {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::UnknownField,
                    "field ID is not defined for transcript core objects",
                ));
            }
        }
    }

    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TrailingBytes,
            "object has trailing bytes after the field set",
        ));
    }

    let object = TranscriptCoreObject {
        security_profile,
        proof_profile_id,
        he_setup_proof_profile_id,
        evaluation_proof_profile_id,
        decryption_proof_profile_id,
        title: title.ok_or_else(|| missing_field("title"))?,
        sequence: sequence.ok_or_else(|| missing_field("sequence"))?,
        payload: payload.ok_or_else(|| missing_field("payload"))?,
        status: status.ok_or_else(|| missing_field("status"))?,
        tags: tags.ok_or_else(|| missing_field("tags"))?,
        checkpoints: checkpoints.ok_or_else(|| missing_field("checkpoints"))?,
    };

    if serialize_transcript_core_object(&object) != bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::FixtureMismatch,
            "parsed object does not reserialize to identical bytes",
        ));
    }

    Ok(object)
}

pub fn analyze_canonical_object(
    bytes: &[u8],
    chunk_size: u64,
) -> CanonicalResult<TranscriptCoreAnalysis> {
    let chunk_size_usize = usize::try_from(chunk_size).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "chunk size does not fit usize",
        )
    })?;
    let object = parse_transcript_core_object(bytes)?;

    Ok(TranscriptCoreAnalysis {
        canonical_bytes_hex: encode_hex(bytes),
        object_type: "TranscriptCore",
        object_version: TRANSCRIPT_CORE_OBJECT_VERSION,
        security_profile: object.security_profile.label(),
        proof_profile_id: object.proof_profile_id,
        he_setup_proof_profile_id: object.he_setup_proof_profile_id,
        evaluation_proof_profile_id: object.evaluation_proof_profile_id,
        decryption_proof_profile_id: object.decryption_proof_profile_id,
        object_hash512: object_root(bytes),
        chunk_root: chunk_root(bytes, chunk_size_usize)?,
        chunk_size,
        status_labels: vec![object.status.label()],
        title: object.title,
        sequence: object.sequence,
        payload_hex: encode_hex(&object.payload),
        tags: object.tags,
        checkpoints: object.checkpoints,
    })
}

pub fn analyze_canonical_object_hex(
    canonical_bytes_hex: &str,
    chunk_size: u64,
) -> CanonicalResult<Value> {
    let bytes = decode_hex(canonical_bytes_hex)?;

    analyze_canonical_object(&bytes, chunk_size)?.to_json_value()
}

fn parse_security_profile(value: u64) -> CanonicalResult<SecurityProfile> {
    match value {
        1 => Ok(SecurityProfile::PassiveAudit),
        3 => Ok(SecurityProfile::EvaluationProof),
        2 => Ok(SecurityProfile::ActiveSecurity),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::UnknownSecurityProfile,
            "security profile is not supported",
        )),
    }
}

fn parse_status(value: u64) -> CanonicalResult<TranscriptCoreStatus> {
    match value {
        1 => Ok(TranscriptCoreStatus::TranscriptCoreVerified),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            "transcript core status is not supported",
        )),
    }
}

fn validate_profiles(
    security_profile: SecurityProfile,
    proof_profile_id: &str,
    he_setup_proof_profile_id: &str,
    evaluation_proof_profile_id: &str,
    decryption_proof_profile_id: &str,
) -> CanonicalResult<()> {
    if proof_profile_id != security_profile.expected_proof_profile_id() {
        let allowed = [
            PASSIVE_AUDIT_PROOF_PROFILE_ID,
            EVALUATION_PROOF_PROFILE_ID,
            ACTIVE_SECURITY_PROOF_PROFILE_ID,
        ];
        if !allowed.contains(&proof_profile_id) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::UnknownProofProfile,
                "proof profile ID is not supported",
            ));
        }
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProofProfileMismatch,
            "proof profile ID does not match security profile",
        ));
    }
    if he_setup_proof_profile_id != NO_HE_SETUP_PROOF_PROFILE_ID
        || decryption_proof_profile_id != NO_DECRYPTION_PROOF_PROFILE_ID
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnknownProofProfile,
            "one or more reserved proof profile IDs are not supported",
        ));
    }
    match evaluation_proof_profile_id {
        NO_EVALUATION_PROOF_PROFILE_ID => {
            if security_profile == SecurityProfile::EvaluationProof {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProofProfileMismatch,
                    "EvaluationProof requires the reserved optional evaluation-proof profile",
                ));
            }
        }
        OPTIONAL_EVALUATION_PROOF_PROFILE_ID => {
            if security_profile != SecurityProfile::EvaluationProof {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProofProfileMismatch,
                    "optional evaluation-proof profile does not match security profile",
                ));
            }
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::UnknownProofProfile,
                "evaluation proof profile ID is not supported",
            ));
        }
    }

    Ok(())
}

fn read_string_list(reader: &mut CanonicalReader<'_>) -> CanonicalResult<Vec<String>> {
    let count = reader.read_varuint()?;
    let mut items = Vec::with_capacity(usize::try_from(count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "list count does not fit usize",
        )
    })?);
    for _ in 0..count {
        items.push(reader.read_string()?);
    }

    Ok(items)
}

fn read_varuint_list(reader: &mut CanonicalReader<'_>) -> CanonicalResult<Vec<u64>> {
    let count = reader.read_varuint()?;
    let mut items = Vec::with_capacity(usize::try_from(count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "list count does not fit usize",
        )
    })?);
    for _ in 0..count {
        items.push(reader.read_varuint()?);
    }

    Ok(items)
}

fn missing_field(field_name: &str) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::MissingField,
        format!("missing required field: {field_name}"),
    )
}

pub fn mutate_field_order_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.security_profile.code());
    append_string(&mut bytes, &object.proof_profile_id);
    append_string(&mut bytes, &object.he_setup_proof_profile_id);
    append_string(&mut bytes, &object.evaluation_proof_profile_id);
    append_string(&mut bytes, &object.decryption_proof_profile_id);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_SEQUENCE);
    append_varuint(&mut bytes, object.sequence);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_duplicate_field_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.security_profile.code());
    append_string(&mut bytes, &object.proof_profile_id);
    append_string(&mut bytes, &object.he_setup_proof_profile_id);
    append_string(&mut bytes, &object.evaluation_proof_profile_id);
    append_string(&mut bytes, &object.decryption_proof_profile_id);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_unknown_field_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    object.tags.clear();
    let mut bytes = serialize_transcript_core_object(&object);
    let field_count_offset = header_length_before_field_count(&object);
    bytes[field_count_offset] = 1;
    let mut with_unknown = bytes[..field_count_offset + 1].to_vec();
    append_varuint(&mut with_unknown, 99);

    encode_hex(&with_unknown)
}

pub fn mutate_invalid_enum_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.security_profile.code());
    append_string(&mut bytes, &object.proof_profile_id);
    append_string(&mut bytes, &object.he_setup_proof_profile_id);
    append_string(&mut bytes, &object.evaluation_proof_profile_id);
    append_string(&mut bytes, &object.decryption_proof_profile_id);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_STATUS);
    append_varuint(&mut bytes, 99);

    encode_hex(&bytes)
}

pub fn mutate_non_canonical_varuint_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    bytes.extend([0x81, 0x00]);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.security_profile.code());
    append_string(&mut bytes, &object.proof_profile_id);
    append_string(&mut bytes, &object.he_setup_proof_profile_id);
    append_string(&mut bytes, &object.evaluation_proof_profile_id);
    append_string(&mut bytes, &object.decryption_proof_profile_id);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_malformed_length_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.security_profile.code());
    append_varuint(&mut bytes, 10);
    bytes.extend(b"short");

    encode_hex(&bytes)
}

pub fn mutate_trailing_bytes_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = serialize_transcript_core_object(&object);
    bytes.push(0);

    encode_hex(&bytes)
}

pub fn mutate_invalid_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    object.proof_profile_id = "transcript-core-unknown-proof-profile".to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_unknown_evaluation_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    object.evaluation_proof_profile_id =
        "transcript-core-unknown-evaluation-proof-profile".to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_malformed_magic_fixture() -> String {
    encode_hex(b"BAD!")
}

pub fn mutate_unsupported_envelope_version_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION + 1);

    encode_hex(&bytes)
}

pub fn mutate_unsupported_object_type_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE + 98);

    encode_hex(&bytes)
}

pub fn mutate_unsupported_object_version_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION + 1);

    encode_hex(&bytes)
}

pub fn mutate_unknown_security_profile_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, 99);

    encode_hex(&bytes)
}

pub fn mutate_proof_profile_mismatch_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    object.proof_profile_id = ACTIVE_SECURITY_PROOF_PROFILE_ID.to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_passive_audit_optional_evaluation_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    object.evaluation_proof_profile_id = OPTIONAL_EVALUATION_PROOF_PROFILE_ID.to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_evaluation_proof_missing_evaluation_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(SecurityProfile::EvaluationProof);
    object.evaluation_proof_profile_id = NO_EVALUATION_PROOF_PROFILE_ID.to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_missing_field_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_invalid_utf8_fixture() -> String {
    let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_varuint(&mut bytes, 1);
    bytes.push(0xff);

    encode_hex(&bytes)
}

fn append_transcript_core_header(output: &mut Vec<u8>, object: &TranscriptCoreObject) {
    output.extend(MAGIC);
    append_varuint(output, ENVELOPE_VERSION);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(output, object.security_profile.code());
    append_string(output, &object.proof_profile_id);
    append_string(output, &object.he_setup_proof_profile_id);
    append_string(output, &object.evaluation_proof_profile_id);
    append_string(output, &object.decryption_proof_profile_id);
}

fn header_length_before_field_count(object: &TranscriptCoreObject) -> usize {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, object);

    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalErrorCode, DeterministicFixtureRng, SecurityProfile, analyze_canonical_object,
        canonical_transcript_core_object, mutate_duplicate_field_fixture,
        mutate_evaluation_proof_missing_evaluation_profile_fixture, mutate_field_order_fixture,
        mutate_invalid_enum_fixture, mutate_invalid_profile_fixture, mutate_invalid_utf8_fixture,
        mutate_malformed_length_fixture, mutate_malformed_magic_fixture,
        mutate_missing_field_fixture, mutate_non_canonical_varuint_fixture,
        mutate_passive_audit_optional_evaluation_profile_fixture,
        mutate_proof_profile_mismatch_fixture, mutate_trailing_bytes_fixture,
        mutate_unknown_evaluation_profile_fixture, mutate_unknown_field_fixture,
        mutate_unknown_security_profile_fixture, mutate_unsupported_envelope_version_fixture,
        mutate_unsupported_object_type_fixture, mutate_unsupported_object_version_fixture,
        parse_transcript_core_object, serialize_transcript_core_object,
    };

    #[test]
    fn canonical_object_round_trips_byte_identically() {
        let object = canonical_transcript_core_object(SecurityProfile::PassiveAudit);
        let canonical_bytes = serialize_transcript_core_object(&object);
        let parsed = parse_transcript_core_object(&canonical_bytes).expect("object should parse");

        assert_eq!(serialize_transcript_core_object(&parsed), canonical_bytes);
    }

    #[test]
    fn security_profiles_keep_the_same_shape_but_distinct_roots() {
        let passive_audit_bytes = serialize_transcript_core_object(
            &canonical_transcript_core_object(SecurityProfile::PassiveAudit),
        );
        let evaluation_proof_bytes = serialize_transcript_core_object(
            &canonical_transcript_core_object(SecurityProfile::EvaluationProof),
        );
        let active_security_bytes = serialize_transcript_core_object(
            &canonical_transcript_core_object(SecurityProfile::ActiveSecurity),
        );
        let passive_audit = analyze_canonical_object(&passive_audit_bytes, 8)
            .expect("passive audit profile should analyze");
        let evaluation_proof = analyze_canonical_object(&evaluation_proof_bytes, 8)
            .expect("evaluation proof profile should analyze");
        let active_security = analyze_canonical_object(&active_security_bytes, 8)
            .expect("active security profile should analyze");

        assert_eq!(passive_audit.object_type, evaluation_proof.object_type);
        assert_eq!(passive_audit.object_type, active_security.object_type);
        assert_eq!(
            passive_audit.object_version,
            evaluation_proof.object_version
        );
        assert_eq!(passive_audit.object_version, active_security.object_version);
        assert_ne!(
            passive_audit.security_profile,
            evaluation_proof.security_profile
        );
        assert_ne!(
            passive_audit.security_profile,
            active_security.security_profile
        );
        assert_ne!(
            evaluation_proof.security_profile,
            active_security.security_profile
        );
        assert_ne!(
            passive_audit.object_hash512,
            evaluation_proof.object_hash512
        );
        assert_ne!(passive_audit.object_hash512, active_security.object_hash512);
        assert_ne!(
            evaluation_proof.object_hash512,
            active_security.object_hash512
        );
        assert_eq!(
            passive_audit.evaluation_proof_profile_id,
            super::NO_EVALUATION_PROOF_PROFILE_ID,
        );
        assert_eq!(
            evaluation_proof.evaluation_proof_profile_id,
            super::OPTIONAL_EVALUATION_PROOF_PROFILE_ID,
        );
    }

    #[test]
    fn deterministic_fixture_rng_replays_byte_streams_by_seed() {
        let mut split_rng = DeterministicFixtureRng::new("fixture-seed");
        let first = split_rng.next_bytes(3);
        let second = split_rng.next_bytes(80);

        let mut single_rng = DeterministicFixtureRng::new("fixture-seed");
        let combined = single_rng.next_bytes(83);
        let mut replayed = first;
        replayed.extend(second);

        assert_eq!(replayed, combined);
        assert_ne!(
            combined,
            DeterministicFixtureRng::new("different-seed").next_bytes(83),
        );
    }

    #[test]
    fn deterministic_fixture_rng_rejects_empty_ranges() {
        let mut rng = DeterministicFixtureRng::new("fixture-seed");
        let error = rng
            .next_u64_below(0)
            .expect_err("empty range should reject");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    }

    #[test]
    fn malformed_fixture_variants_reject_with_targeted_errors() {
        let cases = [
            (
                mutate_duplicate_field_fixture(),
                CanonicalErrorCode::DuplicateField,
            ),
            (mutate_field_order_fixture(), CanonicalErrorCode::FieldOrder),
            (
                mutate_unknown_field_fixture(),
                CanonicalErrorCode::UnknownField,
            ),
            (
                mutate_invalid_enum_fixture(),
                CanonicalErrorCode::InvalidEnum,
            ),
            (
                mutate_non_canonical_varuint_fixture(),
                CanonicalErrorCode::NonCanonicalVarUint,
            ),
            (
                mutate_malformed_length_fixture(),
                CanonicalErrorCode::MalformedLength,
            ),
            (
                mutate_trailing_bytes_fixture(),
                CanonicalErrorCode::TrailingBytes,
            ),
            (
                mutate_invalid_profile_fixture(),
                CanonicalErrorCode::UnknownProofProfile,
            ),
            (
                mutate_unknown_evaluation_profile_fixture(),
                CanonicalErrorCode::UnknownProofProfile,
            ),
            (
                mutate_malformed_magic_fixture(),
                CanonicalErrorCode::MalformedMagic,
            ),
            (
                mutate_unsupported_envelope_version_fixture(),
                CanonicalErrorCode::UnsupportedEnvelopeVersion,
            ),
            (
                mutate_unsupported_object_type_fixture(),
                CanonicalErrorCode::UnsupportedObjectType,
            ),
            (
                mutate_unsupported_object_version_fixture(),
                CanonicalErrorCode::UnsupportedObjectVersion,
            ),
            (
                mutate_unknown_security_profile_fixture(),
                CanonicalErrorCode::UnknownSecurityProfile,
            ),
            (
                mutate_proof_profile_mismatch_fixture(),
                CanonicalErrorCode::ProofProfileMismatch,
            ),
            (
                mutate_passive_audit_optional_evaluation_profile_fixture(),
                CanonicalErrorCode::ProofProfileMismatch,
            ),
            (
                mutate_evaluation_proof_missing_evaluation_profile_fixture(),
                CanonicalErrorCode::ProofProfileMismatch,
            ),
            (
                mutate_missing_field_fixture(),
                CanonicalErrorCode::MissingField,
            ),
            (
                mutate_invalid_utf8_fixture(),
                CanonicalErrorCode::InvalidUtf8,
            ),
        ];

        for (fixture_hex, expected_code) in cases {
            let bytes = super::decode_hex(&fixture_hex).expect("fixture hex should decode");
            let error =
                parse_transcript_core_object(&bytes).expect_err("malformed fixture should reject");

            assert_eq!(error.code, expected_code);
        }
    }
}
