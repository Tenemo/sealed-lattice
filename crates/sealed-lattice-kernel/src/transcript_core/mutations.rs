use super::codec::{
    append_transcript_core_header, canonical_transcript_core_object, encode_hex,
    header_length_before_field_count, serialize_transcript_core_object,
};
use super::types::{
    ENVELOPE_VERSION, FIELD_SEQUENCE, FIELD_TITLE, MAGIC, TRANSCRIPT_CORE_OBJECT_TYPE,
    TRANSCRIPT_CORE_OBJECT_VERSION,
};
use crate::encoding::{append_string, append_varuint};

pub fn mutate_field_order_fixture() -> String {
    let object = canonical_transcript_core_object();
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_SEQUENCE);
    append_varuint(&mut bytes, object.sequence);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_duplicate_field_fixture() -> String {
    let object = canonical_transcript_core_object();
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_unknown_field_fixture() -> String {
    let mut object = canonical_transcript_core_object();
    object.tags.clear();
    let mut bytes = serialize_transcript_core_object(&object);
    let field_count_offset = header_length_before_field_count();
    bytes[field_count_offset] = 1;
    let mut with_unknown = bytes[..field_count_offset + 1].to_vec();
    append_varuint(&mut with_unknown, 99);

    encode_hex(&with_unknown)
}

pub fn mutate_non_canonical_varuint_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    bytes.extend([0x81, 0x00]);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_malformed_length_fixture() -> String {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_varuint(&mut bytes, 10);
    bytes.extend(b"short");

    encode_hex(&bytes)
}

pub fn mutate_trailing_bytes_fixture() -> String {
    let object = canonical_transcript_core_object();
    let mut bytes = serialize_transcript_core_object(&object);
    bytes.push(0);

    encode_hex(&bytes)
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

pub fn mutate_missing_field_fixture() -> String {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_invalid_utf8_fixture() -> String {
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_varuint(&mut bytes, 1);
    bytes.push(0xff);

    encode_hex(&bytes)
}
