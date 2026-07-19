use serde_json::Value;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::cmp::Ordering;

use crate::encoding::{
    CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint,
};

pub const HASH512_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/hash512";
// Canonical objects are separated by their mandatory `objectType`
// discriminator inside canonical JSON rather than per-type domain strings.
pub const CANONICAL_OBJECT_HASH_NAMESPACE: &str = "sealed-lattice-root/canonical-object";

pub fn to_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(LOWER_HEX[(byte >> 4) as usize] as char);
        output.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
    }

    output
}
/// Computes the protocol's domain-separated 64-byte SHAKE256 hash output.
///
/// The `Hash512` name describes the output length. Security is bounded by
/// SHAKE256, not by a generic 512-bit random-oracle assumption.
///
/// This helper frames the `sealed.vote/hash512` prefix, a caller-supplied
/// protocol step domain, and each supplied part. Canonical protocol objects
/// must pass the frozen ceremony, statement, and encoded object material as
/// explicit framed parts rather than using an informal parallel convention.
pub fn hash_framed_parts_512(domain: &str, parts: &[&[u8]]) -> [u8; 64] {
    // Length-framed, domain-separated preimage: fixed prefix, then the length-
    // framed domain, then a varuint part count, then each part length-prefixed.
    // This unambiguous framing is security-critical (no concatenation
    // collisions) and MUST byte-match the TypeScript reference, or every
    // protocol hash forks across the two implementations.
    let mut preimage = Vec::new();
    preimage.extend(HASH512_PREIMAGE_PREFIX);
    append_bytes(&mut preimage, domain.as_bytes());
    append_varuint(&mut preimage, parts.len() as u64);
    for part in parts {
        append_bytes(&mut preimage, part);
    }

    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    output
}

#[cfg(test)]
pub fn hash512_hex(domain: &str, parts: &[&[u8]]) -> String {
    to_hex(&hash_framed_parts_512(domain, parts))
}

/// Streaming form of [`hash_framed_parts_512`] for a caller that produces one
/// framed part incrementally. The caller declares the part count and streamed
/// byte length before supplying bytes, preserving the exact canonical framing
/// without buffering a complete proof row.
pub(crate) struct StreamingHash512 {
    hasher: Shake256,
}

impl StreamingHash512 {
    pub(crate) fn new(domain: &str, part_count: u64) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(HASH512_PREIMAGE_PREFIX);
        update_varuint(&mut hasher, domain.len() as u64);
        hasher.update(domain.as_bytes());
        update_varuint(&mut hasher, part_count);
        Self { hasher }
    }

    pub(crate) fn absorb_part(&mut self, part: &[u8]) {
        update_varuint(&mut self.hasher, part.len() as u64);
        self.hasher.update(part);
    }

    pub(crate) fn begin_part(&mut self, byte_length: u64) {
        update_varuint(&mut self.hasher, byte_length);
    }

    pub(crate) fn absorb_raw(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    pub(crate) fn finalize(self) -> [u8; 64] {
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; 64];
        reader.read(&mut output);
        output
    }
}

fn update_varuint(hasher: &mut Shake256, value: u64) {
    for byte in encode_varuint_for_hash(value) {
        hasher.update(&[byte]);
    }
}

fn encode_varuint_for_hash(mut value: u64) -> Vec<u8> {
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

fn update_bytes_prefix(hasher: &mut Shake256, value_length: usize) -> CanonicalResult<()> {
    let length = u64::try_from(value_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "hash input length does not fit u64",
        )
    })?;
    update_varuint(hasher, length);

    Ok(())
}

fn finalize_hash512_hex(hasher: Shake256) -> String {
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    to_hex(&output)
}

#[cfg(test)]
pub fn namespace_root(namespace: &str, canonical_bytes: &[u8]) -> String {
    hash512_hex(namespace, &[canonical_bytes])
}

// Match the JavaScript reference's key ordering exactly. Canonical hash keys
// are ASCII-only, but keeping the comparator explicit prevents runtime drift.
fn compare_utf16(left: &str, right: &str) -> Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();

    loop {
        match (left_units.next(), right_units.next()) {
            (Some(left_unit), Some(right_unit)) => match left_unit.cmp(&right_unit) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn canonical_json_string(value: &str) -> CanonicalResult<&str> {
    if !value.is_ascii() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "canonical JSON hash strings must contain only ASCII characters; use the foundation display-text codec for Unicode",
        ));
    }

    Ok(value)
}

fn serialize_json_string(value: &str) -> CanonicalResult<String> {
    serde_json::to_string(value).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("canonical JSON string serialization failed: {error}"),
        )
    })
}

fn serialize_json_number(value: &serde_json::Number) -> CanonicalResult<String> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    if let Some(unsigned_value) = value.as_u64() {
        if unsigned_value > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(unsigned_value.to_string());
    }
    if let Some(signed_value) = value.as_i64() {
        if signed_value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(signed_value.to_string());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "canonical JSON values must not contain fractional numbers",
    ))
}

trait CanonicalJsonSink {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()>;

    fn write_char(&mut self, value: char) -> CanonicalResult<()> {
        let mut buffer = [0_u8; 4];
        self.write_str(value.encode_utf8(&mut buffer))
    }
}

struct HashingCanonicalJsonSink<'hasher> {
    hasher: &'hasher mut Shake256,
}

impl CanonicalJsonSink for HashingCanonicalJsonSink<'_> {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        self.hasher.update(value.as_bytes());

        Ok(())
    }
}

fn checked_len_add(left: usize, right: usize) -> CanonicalResult<usize> {
    left.checked_add(right).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "canonical JSON length overflowed usize",
        )
    })
}

fn serialized_json_string_len(value: &str) -> CanonicalResult<usize> {
    Ok(serialize_json_string(value)?.len())
}

fn canonical_json_len(value: &Value) -> CanonicalResult<usize> {
    match value {
        Value::Null => Ok(4),
        Value::Bool(boolean) => Ok(boolean.to_string().len()),
        Value::Number(number) => Ok(serialize_json_number(number)?.len()),
        Value::String(string) => serialized_json_string_len(canonical_json_string(string)?),
        Value::Array(items) => {
            let mut length = 2_usize;
            for (item_index, item) in items.iter().enumerate() {
                if item_index > 0 {
                    length = checked_len_add(length, 1)?;
                }
                length = checked_len_add(length, canonical_json_len(item)?)?;
            }

            Ok(length)
        }
        Value::Object(map) => {
            let mut length = 2_usize;
            for (key, entry_value) in map {
                if length > 2 {
                    length = checked_len_add(length, 1)?;
                }
                length = checked_len_add(
                    length,
                    serialized_json_string_len(canonical_json_string(key)?)?,
                )?;
                length = checked_len_add(length, 1)?;
                length = checked_len_add(length, canonical_json_len(entry_value)?)?;
            }

            Ok(length)
        }
    }
}

fn write_canonical_json(value: &Value, sink: &mut impl CanonicalJsonSink) -> CanonicalResult<()> {
    match value {
        Value::Null => sink.write_str("null"),
        Value::Bool(boolean) => sink.write_str(&boolean.to_string()),
        Value::Number(number) => sink.write_str(&serialize_json_number(number)?),
        Value::String(string) => {
            sink.write_str(&serialize_json_string(canonical_json_string(string)?)?)
        }
        Value::Array(items) => {
            sink.write_char('[')?;
            for (item_index, item) in items.iter().enumerate() {
                if item_index > 0 {
                    sink.write_char(',')?;
                }
                write_canonical_json(item, sink)?;
            }
            sink.write_char(']')
        }
        Value::Object(map) => {
            let mut entries = Vec::<(String, &Value)>::with_capacity(map.len());
            for (key, entry_value) in map {
                let canonical_key = canonical_json_string(key)?.to_owned();
                entries.push((canonical_key, entry_value));
            }
            entries.sort_by(|left, right| compare_utf16(&left.0, &right.0));

            sink.write_char('{')?;
            for (entry_index, (canonical_key, entry_value)) in entries.iter().enumerate() {
                if entry_index > 0 {
                    sink.write_char(',')?;
                }
                sink.write_str(&serialize_json_string(canonical_key)?)?;
                sink.write_char(':')?;
                write_canonical_json(entry_value, sink)?;
            }
            sink.write_char('}')
        }
    }
}

/// Single structural domain for canonical typed protocol objects, records, and
/// roots. Domain separation comes from the mandatory `objectType` discriminator
/// already inside the canonical JSON, not from a per-type namespace string. The
/// non-empty-objectType check is required: it makes "never merge a typeless
/// preimage into the shared domain" a hard rejection, not a convention.
pub fn derive_canonical_object_hash(value: &Value) -> CanonicalResult<String> {
    let has_object_type = value
        .get("objectType")
        .and_then(Value::as_str)
        .is_some_and(|object_type| !object_type.is_empty());
    if !has_object_type {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "canonical object hash requires a non-empty objectType discriminator",
        ));
    }

    // Single structural hash domain. Length-framed preimage: fixed prefix, the
    // canonical-object domain, a varuint part count, then the length-framed
    // canonical JSON. This MUST byte-match the TypeScript reference.
    let canonical_json_length = canonical_json_len(value)?;
    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    update_bytes_prefix(&mut hasher, CANONICAL_OBJECT_HASH_NAMESPACE.len())?;
    hasher.update(CANONICAL_OBJECT_HASH_NAMESPACE.as_bytes());
    update_varuint(&mut hasher, 1);
    update_bytes_prefix(&mut hasher, canonical_json_length)?;
    write_canonical_json(
        value,
        &mut HashingCanonicalJsonSink {
            hasher: &mut hasher,
        },
    )?;

    Ok(finalize_hash512_hex(hasher))
}

#[cfg(test)]
mod tests {
    use super::hash512_hex;
    use crate::encoding::CanonicalErrorCode;

    #[test]
    fn hash512_is_domain_separated() {
        let left = hash512_hex("transcript-core/a", &[b"same"]);
        let right = hash512_hex("transcript-core/b", &[b"same"]);

        assert_ne!(left, right);
    }

    #[test]
    fn canonical_object_hash_matches_typescript_known_answers() {
        let cases = [
            (
                serde_json::json!({
                    "objectType": "CanonicalHashParityCase",
                    "b": [2, 1],
                    "a": {
                        "z": true
                    }
                }),
                "40bf0c90300eb006c7651ea9d876005bacf7766c149aca024fb07d7743a35c47d78c86729ead75e4ba017e54b5122857ad05e1956f7af59b9e0ba64a74aead93",
            ),
            (
                serde_json::json!({
                    "objectType": "CanonicalHashParityCase",
                    "10": "a",
                    "2": "b"
                }),
                "d78c2fa846f253977f207061878268b1d3440e84f1237c81cedac4ec4077ee838f0baeb8f4daf08996e0416379d49c4f9070645a11ebff2612ffe52aef9d7813",
            ),
        ];

        for (value, expected_hash) in cases {
            assert_eq!(
                super::derive_canonical_object_hash(&value)
                    .expect("canonical object hash should compute"),
                expected_hash
            );
        }
        assert!(
            super::derive_canonical_object_hash(&serde_json::json!({
                "objectType": "CanonicalHashParityCase",
                "fraction": 1.5,
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_object_hash_rejects_non_ascii_keys_and_values() {
        for value in [
            serde_json::json!({ "objectType": "CanonicalHashParityCase", "value": "\u{00e9}" }),
            serde_json::json!({ "objectType": "CanonicalHashParityCase", "\u{0065}\u{0301}": 1 }),
            serde_json::json!({ "objectType": "CanonicalHashParityCase", "value": "\u{10000}" }),
        ] {
            let error = super::derive_canonical_object_hash(&value)
                .expect_err("non-ASCII canonical JSON must be rejected");
            assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
            assert!(error.message.contains("only ASCII characters"));
        }
    }

    #[test]
    fn canonical_object_hash_separates_by_object_type_and_requires_it() {
        let alpha = serde_json::json!({ "objectType": "Alpha", "value": 7 });
        let beta = serde_json::json!({ "objectType": "Beta", "value": 7 });
        let alpha_hash = super::derive_canonical_object_hash(&alpha).expect("alpha should hash");
        let beta_hash = super::derive_canonical_object_hash(&beta).expect("beta should hash");

        // Same body, different objectType -> different hash (separation holds).
        assert_ne!(alpha_hash, beta_hash);
        // A typeless preimage is rejected, never silently merged into the domain.
        assert!(super::derive_canonical_object_hash(&serde_json::json!({ "value": 7 })).is_err());
        assert!(
            super::derive_canonical_object_hash(&serde_json::json!({ "objectType": "" })).is_err()
        );
    }
}
