use serde_json::Value;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{borrow::Cow, cmp::Ordering};
use unicode_normalization::UnicodeNormalization;

use crate::encoding::{
    CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint,
};

mod chunk_tree;
mod namespaces;

pub use chunk_tree::chunk_root;
pub use namespaces::*;

pub const HASH512_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/v1/hash512";

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
/// This helper frames the `sealed.vote/v1/hash512` prefix, a caller-supplied
/// protocol step domain, and each supplied part. Canonical protocol objects
/// must pass the frozen ceremony, statement, and encoded object material as
/// explicit framed parts rather than using an informal parallel convention.
pub fn hash512(domain: &str, parts: &[&[u8]]) -> [u8; 64] {
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

pub fn hash512_hex(domain: &str, parts: &[&[u8]]) -> String {
    to_hex(&hash512(domain, parts))
}

/// Computes the protocol's domain-separated 32-byte SHAKE256 hash output with
/// the same length-framed preimage shape as `hash512`, under its own fixed
/// prefix. Used for internal Merkle commitment nodes where the 256-bit width
/// is the disclosed binding length.
pub(crate) fn hash256(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    const HASH256_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/v1/hash256";
    let mut preimage = Vec::new();
    preimage.extend(HASH256_PREIMAGE_PREFIX);
    append_bytes(&mut preimage, domain.as_bytes());
    append_varuint(&mut preimage, parts.len() as u64);
    for part in parts {
        append_bytes(&mut preimage, part);
    }

    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 32];
    reader.read(&mut output);

    output
}

/// A streaming variant of [`hash256`] producing byte-identical output for the
/// same domain and parts, without buffering the whole preimage. The caller
/// declares the part count up front, then either supplies whole framed parts or
/// opens one part with its byte length and streams its bytes. Used by the atom
/// family backend's streamed Merkle leaf hashing, where one leaf's row part is
/// produced one committed column at a time.
pub(crate) struct StreamingHash256 {
    hasher: Shake256,
}

impl StreamingHash256 {
    pub(crate) fn new(domain: &str, part_count: u64) -> Self {
        const HASH256_PREIMAGE_PREFIX: &[u8] = b"sealed.vote/v1/hash256";
        let mut hasher = Shake256::default();
        hasher.update(HASH256_PREIMAGE_PREFIX);
        update_varuint(&mut hasher, domain.len() as u64);
        hasher.update(domain.as_bytes());
        update_varuint(&mut hasher, part_count);
        Self { hasher }
    }

    // Absorb one whole length-framed part.
    pub(crate) fn absorb_part(&mut self, part: &[u8]) {
        update_varuint(&mut self.hasher, part.len() as u64);
        self.hasher.update(part);
    }

    // Open a length-framed part whose bytes will follow through `absorb_raw`.
    // The caller must then absorb exactly `byte_length` bytes.
    pub(crate) fn begin_part(&mut self, byte_length: u64) {
        update_varuint(&mut self.hasher, byte_length);
    }

    // Absorb raw bytes belonging to the currently open part.
    pub(crate) fn absorb_raw(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    pub(crate) fn finalize(self) -> [u8; 32] {
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; 32];
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

pub fn canonical_root(type_id: u64, version: u64, canonical_bytes: &[u8]) -> String {
    let mut type_id_bytes = Vec::new();
    append_varuint(&mut type_id_bytes, type_id);
    let mut version_bytes = Vec::new();
    append_varuint(&mut version_bytes, version);

    hash512_hex(
        "sealed-lattice-root/canonical-root-v1",
        &[&type_id_bytes, &version_bytes, canonical_bytes],
    )
}

pub fn object_root(canonical_bytes: &[u8]) -> String {
    canonical_root(1, 1, canonical_bytes)
}

pub fn namespace_root(namespace: &str, canonical_bytes: &[u8]) -> String {
    hash512_hex(namespace, &[canonical_bytes])
}

// Orders strings by UTF-16 code-unit value to match the JavaScript reference's
// key sort. This deliberately differs from Rust's native UTF-8 str ordering;
// using str ordering would fork every canonical-JSON hash from the TS side.
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

// Non-ASCII strings are NFC-normalized before hashing (ASCII is already NFC);
// this keeps the canonical form stable across Unicode-equivalent encodings.
fn normalize_json_string(value: &str) -> Cow<'_, str> {
    if value.is_ascii() {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(value.nfc().collect())
    }
}

fn serialize_json_string(value: &str) -> CanonicalResult<String> {
    serde_json::to_string(value).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("canonical JSON string serialization failed: {error}"),
        )
    })
}

fn serialize_json_number(value: &serde_json::Number) -> CanonicalResult<String> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    if let Some(unsigned_value) = value.as_u64() {
        if unsigned_value > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(unsigned_value.to_string());
    }
    if let Some(signed_value) = value.as_i64() {
        if signed_value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "canonical JSON integers must be JavaScript-safe",
            ));
        }

        return Ok(signed_value.to_string());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
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

impl CanonicalJsonSink for String {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        self.push_str(value);

        Ok(())
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

#[cfg(test)]
struct ByteComparisonCanonicalJsonSink<'expected> {
    expected_bytes: &'expected [u8],
    offset: usize,
    matches: bool,
}

#[cfg(test)]
impl<'expected> ByteComparisonCanonicalJsonSink<'expected> {
    fn new(expected_bytes: &'expected [u8]) -> Self {
        Self {
            expected_bytes,
            offset: 0,
            matches: true,
        }
    }

    fn complete(self) -> bool {
        self.matches && self.offset == self.expected_bytes.len()
    }
}

#[cfg(test)]
impl CanonicalJsonSink for ByteComparisonCanonicalJsonSink<'_> {
    fn write_str(&mut self, value: &str) -> CanonicalResult<()> {
        if !self.matches {
            return Ok(());
        }

        let value_bytes = value.as_bytes();
        let end = self.offset.saturating_add(value_bytes.len());
        if self.expected_bytes.get(self.offset..end) != Some(value_bytes) {
            self.matches = false;
            return Ok(());
        }
        self.offset = end;

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
        Value::String(string) => serialized_json_string_len(&normalize_json_string(string)),
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
            let mut entries = Vec::<String>::with_capacity(map.len());
            let mut length = 2_usize;
            for (key, entry_value) in map {
                let normalized_key = normalize_json_string(key).into_owned();
                if entries
                    .iter()
                    .any(|existing_key| existing_key == &normalized_key)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::DuplicateField,
                        "canonical JSON object keys collide after normalization",
                    ));
                }
                entries.push(normalized_key.clone());
                if entries.len() > 1 {
                    length = checked_len_add(length, 1)?;
                }
                length = checked_len_add(length, serialized_json_string_len(&normalized_key)?)?;
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
            sink.write_str(&serialize_json_string(&normalize_json_string(string))?)
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
                let normalized_key = normalize_json_string(key).into_owned();
                if entries
                    .iter()
                    .any(|(existing_key, _)| existing_key == &normalized_key)
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::DuplicateField,
                        "canonical JSON object keys collide after normalization",
                    ));
                }
                entries.push((normalized_key, entry_value));
            }
            entries.sort_by(|left, right| compare_utf16(&left.0, &right.0));

            sink.write_char('{')?;
            for (entry_index, (key, entry_value)) in entries.iter().enumerate() {
                if entry_index > 0 {
                    sink.write_char(',')?;
                }
                sink.write_str(&serialize_json_string(key)?)?;
                sink.write_char(':')?;
                write_canonical_json(entry_value, sink)?;
            }
            sink.write_char('}')
        }
    }
}

pub fn canonical_json(value: &Value) -> CanonicalResult<String> {
    let mut output = String::with_capacity(canonical_json_len(value)?);
    write_canonical_json(value, &mut output)?;

    Ok(output)
}

#[cfg(test)]
pub fn canonical_json_matches_bytes(value: &Value, expected_bytes: &[u8]) -> CanonicalResult<bool> {
    if canonical_json_len(value)? != expected_bytes.len() {
        return Ok(false);
    }
    let mut sink = ByteComparisonCanonicalJsonSink::new(expected_bytes);
    write_canonical_json(value, &mut sink)?;

    Ok(sink.complete())
}

/// Single structural domain for canonical typed protocol objects, records, and
/// roots. Domain separation comes from the mandatory `objectType` discriminator
/// already inside the canonical JSON, not from a per-type namespace string. The
/// non-empty-objectType check is load-bearing: it makes "never merge a typeless
/// preimage into the shared domain" a hard rejection, not a convention.
pub fn derive_canonical_object_hash(value: &Value) -> CanonicalResult<String> {
    let has_object_type = value
        .get("objectType")
        .and_then(Value::as_str)
        .is_some_and(|object_type| !object_type.is_empty());
    if !has_object_type {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
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
    use super::{
        canonical_json, canonical_json_matches_bytes, canonical_root, chunk_root, hash512_hex,
    };

    #[test]
    fn hash512_is_domain_separated() {
        let left = hash512_hex("transcript-core/a", &[b"same"]);
        let right = hash512_hex("transcript-core/b", &[b"same"]);

        assert_ne!(left, right);
    }

    #[test]
    fn canonical_json_matches_the_typescript_reference_shape() {
        let canonical = canonical_json(&serde_json::json!({
            "b": [2, 1],
            "a": {
                "z": true
            }
        }))
        .expect("canonical JSON should serialize supported values");

        assert_eq!(canonical, "{\"a\":{\"z\":true},\"b\":[2,1]}");
        assert!(canonical_json(&serde_json::json!({ "fraction": 1.5 })).is_err());
    }

    #[test]
    fn canonical_object_hash_matches_typescript_known_answers() {
        let cases = [
            (
                serde_json::json!({
                    "objectType": "CanonicalHashParityCase",
                    "objectVersion": 1,
                    "b": [2, 1],
                    "a": {
                        "z": true
                    }
                }),
                "{\"a\":{\"z\":true},\"b\":[2,1],\"objectType\":\"CanonicalHashParityCase\",\"objectVersion\":1}",
                "2ed1fd2293f48e6b4f7b9d7d4b0f105d3d6a9c4c392f70a3b9c6cade53247ee5f286f9b565258ef1f29fd6416aa349ab0388ef719303242382979a27da5a3589",
            ),
            (
                serde_json::json!({
                    "objectType": "CanonicalHashParityCase",
                    "objectVersion": 1,
                    "10": "a",
                    "2": "b"
                }),
                "{\"10\":\"a\",\"2\":\"b\",\"objectType\":\"CanonicalHashParityCase\",\"objectVersion\":1}",
                "629347ec581398f06eea18e87c00946ec8eefa12574725b41a42b0056b97ec744d79ef8ed6d9c8b8a38e064e2dbde92f517206c3a32727bbd606e4e0c45de6b8",
            ),
            (
                serde_json::json!({
                    "objectType": "CanonicalHashParityCase",
                    "objectVersion": 1,
                    "value": "\u{0065}\u{0301}",
                    "supplementary": "\u{10000}"
                }),
                "{\"objectType\":\"CanonicalHashParityCase\",\"objectVersion\":1,\"supplementary\":\"\u{10000}\",\"value\":\"\u{00e9}\"}",
                "4421299dcece175cc568f13535276189cf09949bc0e0babf88444a42584ce0e51306a8dc26329ec1be1f490589486a9bd1040589bfe0a21ec868ed413d7947a2",
            ),
        ];

        for (value, expected_canonical_json, expected_hash) in cases {
            assert_eq!(
                canonical_json(&value).expect("canonical JSON should serialize"),
                expected_canonical_json
            );
            assert_eq!(
                super::derive_canonical_object_hash(&value)
                    .expect("canonical object hash should compute"),
                expected_hash
            );
        }
    }

    #[test]
    fn canonical_json_byte_comparison_matches_streamed_encoding() {
        let value = serde_json::json!({
            "z": [true, null, "plain-ascii"],
            "a": { "nested": 17 }
        });
        let canonical = canonical_json(&value).expect("canonical JSON should serialize");

        assert!(
            canonical_json_matches_bytes(&value, canonical.as_bytes())
                .expect("byte comparison should run")
        );
        assert!(
            !canonical_json_matches_bytes(&value, b"{\"a\":0}")
                .expect("byte comparison should reject mismatched bytes")
        );
    }

    #[test]
    fn canonical_root_binds_object_type_and_version() {
        let canonical_bytes = b"canonical";

        assert_ne!(
            canonical_root(1, 1, canonical_bytes),
            canonical_root(2, 1, canonical_bytes),
        );
        assert_ne!(
            canonical_root(1, 1, canonical_bytes),
            canonical_root(1, 2, canonical_bytes),
        );
    }

    #[test]
    fn chunk_root_changes_with_chunk_size() {
        let input = b"0123456789abcdef";

        assert_ne!(
            chunk_root(input, 4).expect("chunk root should compute"),
            chunk_root(input, 8).expect("chunk root should compute"),
        );
    }

    #[test]
    fn chunk_root_separates_empty_input_from_zero_leaf_input() {
        assert_ne!(
            chunk_root(&[], 1).expect("empty chunk root should compute"),
            chunk_root(&[0], 1).expect("single zero chunk root should compute"),
        );
        assert_ne!(
            chunk_root(&[], 64).expect("empty chunk root should compute"),
            chunk_root(&[0; 64], 64).expect("full zero chunk root should compute"),
        );
    }

    #[test]
    fn canonical_object_hash_separates_by_object_type_and_requires_it() {
        let alpha = serde_json::json!({ "objectType": "Alpha", "objectVersion": 1, "value": 7 });
        let beta = serde_json::json!({ "objectType": "Beta", "objectVersion": 1, "value": 7 });
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
