use serde_json::Value;

#[cfg(test)]
use super::rng::DeterministicFixtureRng;
use super::types::{
    ENVELOPE_VERSION, FIELD_CHECKPOINTS, FIELD_PAYLOAD, FIELD_SEQUENCE, FIELD_TAGS, FIELD_TITLE,
    MAGIC, REQUIRED_FIELDS, TRANSCRIPT_CORE_OBJECT_TYPE, TRANSCRIPT_CORE_OBJECT_VERSION,
    TranscriptCoreAnalysis, TranscriptCoreObject,
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

pub fn encode_standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);

        encoded.push(ALPHABET[(first >> 2) as usize] as char);
        encoded.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            encoded.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() == 3 {
            encoded.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

// Canonical standard-base64 decoder: fixed four-byte chunks, padding only in
// the final chunk, and zeroed padding bits, so exactly one encoding maps to
// each byte string and transported proof bytes stay canonically bound.
pub fn decode_standard_base64(encoded: &str, field_name: &str) -> CanonicalResult<Vec<u8>> {
    let encoded_bytes = encoded.as_bytes();
    if !encoded_bytes.len().is_multiple_of(4) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} length must be a multiple of four"),
        ));
    }

    let mut decoded = Vec::with_capacity(encoded_bytes.len() / 4 * 3);
    for (chunk_index, chunk) in encoded_bytes.chunks_exact(4).enumerate() {
        let is_final_chunk = (chunk_index + 1) * 4 == encoded_bytes.len();
        let first = decode_standard_base64_digit(chunk[0], field_name)?;
        let second = decode_standard_base64_digit(chunk[1], field_name)?;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                if !is_final_chunk {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} padding must appear only in the final chunk"),
                    ));
                }
                if second & 0x0f != 0 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} must use canonical padding bits"),
                    ));
                }
                decoded.push((first << 2) | (second >> 4));
            }
            (_, b'=') => {
                if !is_final_chunk {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} padding must appear only in the final chunk"),
                    ));
                }
                let third = decode_standard_base64_digit(chunk[2], field_name)?;
                if third & 0x03 != 0 {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} must use canonical padding bits"),
                    ));
                }
                decoded.push((first << 2) | (second >> 4));
                decoded.push(((second & 0x0f) << 4) | (third >> 2));
            }
            (b'=', _) => {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name} padding is malformed"),
                ));
            }
            (_, _) => {
                let third = decode_standard_base64_digit(chunk[2], field_name)?;
                let fourth = decode_standard_base64_digit(chunk[3], field_name)?;
                decoded.push((first << 2) | (second >> 4));
                decoded.push(((second & 0x0f) << 4) | (third >> 2));
                decoded.push(((third & 0x03) << 6) | fourth);
            }
        }
    }

    Ok(decoded)
}

fn decode_standard_base64_digit(byte: u8, field_name: &str) -> CanonicalResult<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must use standard base64"),
        )),
    }
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

#[cfg(test)]
pub fn canonical_transcript_core_object() -> TranscriptCoreObject {
    let mut fixture_rng = DeterministicFixtureRng::new("transcript-core-foundation");

    TranscriptCoreObject {
        title: "Foundation transcript roots".to_string(),
        sequence: 10,
        payload: fixture_rng.next_bytes(6),
        tags: vec![
            "canonical".to_string(),
            "foundation-transcript".to_string(),
            "direct-route".to_string(),
        ],
        checkpoints: vec![10, 20, 10],
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
    append_varuint(&mut output, REQUIRED_FIELDS.len() as u64);

    append_varuint(&mut output, FIELD_TITLE);
    append_string(&mut output, &object.title);
    append_varuint(&mut output, FIELD_SEQUENCE);
    append_varuint(&mut output, object.sequence);
    append_varuint(&mut output, FIELD_PAYLOAD);
    append_bytes(&mut output, &object.payload);
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

    let field_count = reader.read_varuint()?;

    let mut previous_field_id = 0_u64;
    let mut title = None;
    let mut sequence = None;
    let mut payload = None;
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
        title: title.ok_or_else(|| missing_field("title"))?,
        sequence: sequence.ok_or_else(|| missing_field("sequence"))?,
        payload: payload.ok_or_else(|| missing_field("payload"))?,
        tags: tags.ok_or_else(|| missing_field("tags"))?,
        checkpoints: checkpoints.ok_or_else(|| missing_field("checkpoints"))?,
    };

    // Canonical-form gate: an object is accepted only if it re-serializes byte-identically to the input, guaranteeing one unique encoding per object for stable hashing.
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
        object_hash512: object_root(bytes),
        chunk_root: chunk_root(bytes, chunk_size_usize)?,
        chunk_size,
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

// Each list item is at least one encoded byte, so a count exceeding the remaining bytes is malformed; reject before allocating to avoid an OOM from a forged length.
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

#[cfg(test)]
pub(super) fn append_transcript_core_header(output: &mut Vec<u8>) {
    output.extend(MAGIC);
    append_varuint(output, ENVELOPE_VERSION);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(output, TRANSCRIPT_CORE_OBJECT_VERSION);
}

#[cfg(test)]
pub(super) fn header_length_before_field_count() -> usize {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);

    bytes.len()
}
