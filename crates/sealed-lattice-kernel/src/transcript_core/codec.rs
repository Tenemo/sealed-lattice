use serde_json::Value;

use super::rng::DeterministicFixtureRng;
use super::types::{
    ACTIVE_MALICIOUS_MHE_PROFILE_ID, BaseClaimProfile, ENVELOPE_VERSION, FIELD_CHECKPOINTS,
    FIELD_PAYLOAD, FIELD_SEQUENCE, FIELD_STATUS, FIELD_TAGS, FIELD_TITLE, MAGIC,
    MANDATORY_EVALUATION_PROOF_PROFILE_ID, MheSecurityClosure, NO_DECRYPTION_PROOF_PROFILE_ID,
    NO_HE_SETUP_PROOF_PROFILE_ID, PASSIVE_MHE_PROTOTYPE_PROFILE_ID, REQUIRED_FIELDS,
    TRANSCRIPT_CORE_OBJECT_TYPE, TRANSCRIPT_CORE_OBJECT_VERSION, TranscriptCoreAnalysis,
    TranscriptCoreObject, TranscriptCoreProfile, TranscriptCoreStatus,
};
use crate::encoding::{
    CanonicalError, CanonicalErrorCode, CanonicalReader, CanonicalResult, append_bytes,
    append_string, append_varuint,
};
use crate::hashing::{chunk_root, object_root, to_hex};

const MAX_TRANSCRIPT_CORE_CANONICAL_BYTE_LENGTH: usize = 16 * 1024 * 1024;

pub fn encode_hex(bytes: &[u8]) -> String {
    to_hex(bytes)
}

fn decode_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn decode_hex(hex: &str) -> CanonicalResult<Vec<u8>> {
    let hex_bytes = hex.as_bytes();
    if !hex_bytes.len().is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "hex string must have an even length",
        ));
    }

    let mut bytes = Vec::with_capacity(hex_bytes.len() / 2);
    for pair in hex_bytes.chunks_exact(2) {
        let high = decode_lower_hex_nibble(pair[0]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        let low = decode_lower_hex_nibble(pair[1]).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidHex,
                "hex string must use lowercase hexadecimal bytes",
            )
        })?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

pub fn canonical_transcript_core_object(profile: TranscriptCoreProfile) -> TranscriptCoreObject {
    let mut fixture_rng = DeterministicFixtureRng::new(&profile.seed_label());
    let base_claim_profile = profile.base_claim_profile;
    let mhe_security_closure = profile.mhe_security_closure;

    TranscriptCoreObject {
        base_claim_profile,
        mhe_security_closure,
        base_claim_profile_id: base_claim_profile.expected_profile_id().to_string(),
        mhe_security_profile_id: mhe_security_closure.expected_profile_id().to_string(),
        he_setup_proof_profile_id: NO_HE_SETUP_PROOF_PROFILE_ID.to_string(),
        evaluation_proof_profile_id: MANDATORY_EVALUATION_PROOF_PROFILE_ID.to_string(),
        decryption_proof_profile_id: NO_DECRYPTION_PROOF_PROFILE_ID.to_string(),
        title: match (base_claim_profile, mhe_security_closure) {
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::PassiveMhePrototype) => {
                "Transcript core fully verified passive MHE prototype".to_string()
            }
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::ActiveMalicious) => {
                "Transcript core fully verified active malicious".to_string()
            }
        },
        sequence: match (base_claim_profile, mhe_security_closure) {
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::PassiveMhePrototype) => 44,
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::ActiveMalicious) => 45,
        },
        payload: fixture_rng.next_bytes(6),
        status: TranscriptCoreStatus::TranscriptCoreVerified,
        tags: match (base_claim_profile, mhe_security_closure) {
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::PassiveMhePrototype) => {
                vec![
                    "canonical".to_string(),
                    "fully-verified".to_string(),
                    "passive-mhe-prototype".to_string(),
                    "mandatory-proof-profile".to_string(),
                ]
            }
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::ActiveMalicious) => vec![
                "canonical".to_string(),
                "fully-verified".to_string(),
                "active-malicious".to_string(),
                "mandatory-proof-profile".to_string(),
            ],
        },
        checkpoints: match (base_claim_profile, mhe_security_closure) {
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::PassiveMhePrototype) => {
                vec![3, 6, 9, 12, 15]
            }
            (BaseClaimProfile::FullyVerifiedResult, MheSecurityClosure::ActiveMalicious) => {
                vec![5, 10, 15, 20, 25]
            }
        },
    }
}

// Writes the fixed field-ID schema: each field is emitted as its numeric field
// ID followed by its value, in strictly increasing ID order (parser enforced).
pub fn serialize_transcript_core_object(object: &TranscriptCoreObject) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend(MAGIC);
    append_varuint(&mut output, ENVELOPE_VERSION);
    append_varuint(&mut output, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut output, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut output, object.base_claim_profile.code());
    append_varuint(&mut output, object.mhe_security_closure.code());
    append_string(&mut output, &object.base_claim_profile_id);
    append_string(&mut output, &object.mhe_security_profile_id);
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
            CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion,
            "unsupported canonical object envelope version",
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

    let base_claim_profile = parse_base_claim_profile(reader.read_varuint()?)?;
    let mhe_security_closure = parse_mhe_security_closure(reader.read_varuint()?)?;
    let base_claim_profile_id = reader.read_string()?;
    let mhe_security_profile_id = reader.read_string()?;
    let he_setup_proof_profile_id = reader.read_string()?;
    let evaluation_proof_profile_id = reader.read_string()?;
    let decryption_proof_profile_id = reader.read_string()?;
    validate_profiles(
        base_claim_profile,
        mhe_security_closure,
        &base_claim_profile_id,
        &mhe_security_profile_id,
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

    // Canonical ordering: field IDs must be strictly increasing, so duplicate or
    // reordered fields are rejected and the encoding stays unique.
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
        base_claim_profile,
        mhe_security_closure,
        base_claim_profile_id,
        mhe_security_profile_id,
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
            CanonicalErrorCode::InvalidFixture,
            "parsed object is not canonical because it does not reserialize to identical bytes",
        ));
    }

    Ok(object)
}

pub fn analyze_canonical_object(
    bytes: &[u8],
    chunk_size: u64,
) -> CanonicalResult<TranscriptCoreAnalysis> {
    if bytes.len() > MAX_TRANSCRIPT_CORE_CANONICAL_BYTE_LENGTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "canonicalBytesHex exceeds the supported transcript-core object byte limit",
        ));
    }
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
        base_claim_profile: object.base_claim_profile.label(),
        mhe_security_closure: object.mhe_security_closure.label(),
        base_claim_profile_id: object.base_claim_profile_id,
        mhe_security_profile_id: object.mhe_security_profile_id,
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
    if canonical_bytes_hex.len() / 2 > MAX_TRANSCRIPT_CORE_CANONICAL_BYTE_LENGTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "canonicalBytesHex exceeds the supported transcript-core object byte limit",
        ));
    }
    let bytes = decode_hex(canonical_bytes_hex)?;

    analyze_canonical_object(&bytes, chunk_size)?.to_json_value()
}

fn parse_base_claim_profile(value: u64) -> CanonicalResult<BaseClaimProfile> {
    match value {
        2 => Ok(BaseClaimProfile::FullyVerifiedResult),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::UnknownBaseClaimProfile,
            "base claim profile is not supported",
        )),
    }
}

fn parse_mhe_security_closure(value: u64) -> CanonicalResult<MheSecurityClosure> {
    match value {
        1 => Ok(MheSecurityClosure::PassiveMhePrototype),
        2 => Ok(MheSecurityClosure::ActiveMalicious),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::UnknownMheSecurityClosure,
            "MHE security closure is not supported",
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
    base_claim_profile: BaseClaimProfile,
    mhe_security_closure: MheSecurityClosure,
    base_claim_profile_id: &str,
    mhe_security_profile_id: &str,
    he_setup_proof_profile_id: &str,
    evaluation_proof_profile_id: &str,
    decryption_proof_profile_id: &str,
) -> CanonicalResult<()> {
    if base_claim_profile_id != base_claim_profile.expected_profile_id() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnknownProofProfile,
            "base claim profile ID is not supported",
        ));
    }
    if mhe_security_profile_id != mhe_security_closure.expected_profile_id() {
        let allowed = [
            PASSIVE_MHE_PROTOTYPE_PROFILE_ID,
            ACTIVE_MALICIOUS_MHE_PROFILE_ID,
        ];
        if !allowed.contains(&mhe_security_profile_id) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::UnknownProofProfile,
                "MHE security profile ID is not supported",
            ));
        }
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "MHE security profile ID does not match MHE security closure",
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
    if evaluation_proof_profile_id != MANDATORY_EVALUATION_PROOF_PROFILE_ID {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "fullyVerified requires the mandatory evaluation-proof profile",
        ));
    }

    Ok(())
}

fn read_list_count(reader: &mut CanonicalReader<'_>, item_name: &str) -> CanonicalResult<usize> {
    let count = reader.read_varuint()?;
    let count_usize = usize::try_from(count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "list count does not fit usize",
        )
    })?;
    if count_usize > reader.remaining_len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{item_name} list count exceeds remaining encoded items"),
        ));
    }

    Ok(count_usize)
}

fn read_string_list(reader: &mut CanonicalReader<'_>) -> CanonicalResult<Vec<String>> {
    let count = read_list_count(reader, "string")?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.read_string()?);
    }

    Ok(items)
}

fn read_varuint_list(reader: &mut CanonicalReader<'_>) -> CanonicalResult<Vec<u64>> {
    let count = read_list_count(reader, "varuint")?;
    let mut items = Vec::with_capacity(count);
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

pub(super) fn append_transcript_core_header(output: &mut Vec<u8>, object: &TranscriptCoreObject) {
    output.extend(MAGIC);
    append_varuint(output, ENVELOPE_VERSION);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(output, object.base_claim_profile.code());
    append_varuint(output, object.mhe_security_closure.code());
    append_string(output, &object.base_claim_profile_id);
    append_string(output, &object.mhe_security_profile_id);
    append_string(output, &object.he_setup_proof_profile_id);
    append_string(output, &object.evaluation_proof_profile_id);
    append_string(output, &object.decryption_proof_profile_id);
}

pub(super) fn header_length_before_field_count(object: &TranscriptCoreObject) -> usize {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, object);

    bytes.len()
}
