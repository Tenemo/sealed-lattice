use super::codec::{
    append_transcript_core_header, canonical_transcript_core_object, encode_hex,
    header_length_before_field_count, serialize_transcript_core_object,
};
use super::types::{
    BaseClaimProfile, ENVELOPE_VERSION, FIELD_SEQUENCE, FIELD_STATUS, FIELD_TITLE,
    FOUNDATION_TRANSCRIPT_CORE_PROFILE, FOUNDATION_TRANSCRIPT_PROFILE_ID, MAGIC,
    TRANSCRIPT_CORE_OBJECT_TYPE, TRANSCRIPT_CORE_OBJECT_VERSION,
};
use crate::encoding::{append_string, append_varuint};

pub fn mutate_field_order_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_SEQUENCE);
    append_varuint(&mut bytes, object.sequence);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_duplicate_field_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 2);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_string(&mut bytes, &object.title);

    encode_hex(&bytes)
}

pub fn mutate_unknown_field_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.tags.clear();
    let mut bytes = serialize_transcript_core_object(&object);
    let field_count_offset = header_length_before_field_count(&object);
    bytes[field_count_offset] = 1;
    let mut with_unknown = bytes[..field_count_offset + 1].to_vec();
    append_varuint(&mut with_unknown, 99);

    encode_hex(&with_unknown)
}

pub fn mutate_invalid_enum_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_STATUS);
    append_varuint(&mut bytes, 99);

    encode_hex(&bytes)
}

pub fn mutate_non_canonical_varuint_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    bytes.extend([0x81, 0x00]);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.base_claim_profile.code());
    append_varuint(&mut bytes, object.security_closure.code());
    append_string(&mut bytes, &object.base_claim_profile_id);
    append_string(&mut bytes, &object.security_profile_id);
    append_string(&mut bytes, &object.he_setup_proof_profile_id);
    append_string(&mut bytes, &object.evaluator_replay_profile_id);
    append_string(&mut bytes, &object.decryption_proof_profile_id);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_malformed_length_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, object.base_claim_profile.code());
    append_varuint(&mut bytes, object.security_closure.code());
    append_varuint(&mut bytes, 10);
    bytes.extend(b"short");

    encode_hex(&bytes)
}

pub fn mutate_trailing_bytes_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = serialize_transcript_core_object(&object);
    bytes.push(0);

    encode_hex(&bytes)
}

pub fn mutate_invalid_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.base_claim_profile_id = "transcript-core-unknown-base-claim-profile".to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_unknown_evaluator_replay_profile_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.evaluator_replay_profile_id =
        "transcript-core-unknown-evaluator-replay-profile".to_string();

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

pub fn mutate_unknown_base_claim_profile_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, 99);

    encode_hex(&bytes)
}

pub fn mutate_unknown_security_closure_fixture() -> String {
    let mut bytes = Vec::new();
    bytes.extend(MAGIC);
    append_varuint(&mut bytes, ENVELOPE_VERSION);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_TYPE);
    append_varuint(&mut bytes, TRANSCRIPT_CORE_OBJECT_VERSION);
    append_varuint(&mut bytes, BaseClaimProfile::FoundationTranscript.code());
    append_varuint(&mut bytes, 99);

    encode_hex(&bytes)
}

pub fn mutate_base_claim_profile_mismatch_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.base_claim_profile_id = "transcript-core-unknown-base-claim-profile-v1".to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_security_profile_mismatch_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.security_profile_id = FOUNDATION_TRANSCRIPT_PROFILE_ID.to_string();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_evaluator_replay_profile_mismatch_fixture() -> String {
    let mut object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    object.evaluator_replay_profile_id = String::new();

    encode_hex(&serialize_transcript_core_object(&object))
}

pub fn mutate_missing_field_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 0);

    encode_hex(&bytes)
}

pub fn mutate_invalid_utf8_fixture() -> String {
    let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
    let mut bytes = Vec::new();
    append_transcript_core_header(&mut bytes, &object);
    append_varuint(&mut bytes, 1);
    append_varuint(&mut bytes, FIELD_TITLE);
    append_varuint(&mut bytes, 1);
    bytes.push(0xff);

    encode_hex(&bytes)
}
