mod codec;
#[cfg(test)]
mod mutations;
#[cfg(test)]
mod rng;
mod types;

#[cfg(any(test, feature = "target-decryption-development-commands"))]
pub use codec::encode_standard_base64;
pub use codec::{
    analyze_canonical_object, analyze_canonical_object_hex, decode_hex, decode_standard_base64,
    encode_hex, parse_transcript_core_object,
};
#[cfg(test)]
pub use codec::{canonical_transcript_core_object, serialize_transcript_core_object};
#[cfg(test)]
pub use mutations::{
    mutate_base_profile_mismatch_fixture, mutate_duplicate_field_fixture,
    mutate_evaluator_replay_profile_mismatch_fixture, mutate_field_order_fixture,
    mutate_invalid_enum_fixture, mutate_invalid_profile_fixture, mutate_invalid_utf8_fixture,
    mutate_malformed_length_fixture, mutate_malformed_magic_fixture, mutate_missing_field_fixture,
    mutate_non_canonical_varuint_fixture, mutate_security_profile_mismatch_fixture,
    mutate_trailing_bytes_fixture, mutate_unknown_base_profile_fixture,
    mutate_unknown_evaluator_replay_profile_fixture, mutate_unknown_field_fixture,
    mutate_unknown_security_closure_fixture, mutate_unsupported_envelope_version_fixture,
    mutate_unsupported_object_type_fixture, mutate_unsupported_object_version_fixture,
};
#[cfg(test)]
pub use rng::DeterministicFixtureRng;
#[cfg(test)]
pub use types::{FOUNDATION_TRANSCRIPT_CORE_PROFILE, TranscriptCoreProfile};

#[cfg(test)]
mod tests {
    use super::{
        DeterministicFixtureRng, FOUNDATION_TRANSCRIPT_CORE_PROFILE, analyze_canonical_object,
        canonical_transcript_core_object, decode_hex, mutate_base_profile_mismatch_fixture,
        mutate_duplicate_field_fixture, mutate_evaluator_replay_profile_mismatch_fixture,
        mutate_field_order_fixture, mutate_invalid_enum_fixture, mutate_invalid_profile_fixture,
        mutate_invalid_utf8_fixture, mutate_malformed_length_fixture,
        mutate_malformed_magic_fixture, mutate_missing_field_fixture,
        mutate_non_canonical_varuint_fixture, mutate_security_profile_mismatch_fixture,
        mutate_trailing_bytes_fixture, mutate_unknown_base_profile_fixture,
        mutate_unknown_evaluator_replay_profile_fixture, mutate_unknown_field_fixture,
        mutate_unknown_security_closure_fixture, mutate_unsupported_envelope_version_fixture,
        mutate_unsupported_object_type_fixture, mutate_unsupported_object_version_fixture,
        parse_transcript_core_object, serialize_transcript_core_object,
    };
    use crate::encoding::{CanonicalErrorCode, append_varuint};
    use crate::transcript_core::types::FIELD_TAGS;

    #[test]
    fn canonical_object_round_trips_byte_identically() {
        let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
        let canonical_bytes = serialize_transcript_core_object(&object);
        let parsed = parse_transcript_core_object(&canonical_bytes).expect("object should parse");

        assert_eq!(serialize_transcript_core_object(&parsed), canonical_bytes);
    }

    #[test]
    fn decode_hex_rejects_uppercase_hex() {
        let error = decode_hex("AB").expect_err("uppercase hex must be non-canonical");

        assert_eq!(error.code, CanonicalErrorCode::InvalidHex);
    }

    #[test]
    fn malformed_list_count_rejects_without_allocation() {
        let object = canonical_transcript_core_object(FOUNDATION_TRANSCRIPT_CORE_PROFILE);
        let mut bytes = Vec::new();
        super::codec::append_transcript_core_header(&mut bytes, &object);
        append_varuint(&mut bytes, 1);
        append_varuint(&mut bytes, FIELD_TAGS);
        append_varuint(&mut bytes, u64::from(u32::MAX));

        let error = parse_transcript_core_object(&bytes).expect_err("malformed list should reject");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn foundation_profile_analyzes_expected_boundary() {
        let foundation_bytes = serialize_transcript_core_object(&canonical_transcript_core_object(
            FOUNDATION_TRANSCRIPT_CORE_PROFILE,
        ));
        let analysis = analyze_canonical_object(&foundation_bytes, 8)
            .expect("foundation profile should analyze");

        assert_eq!(
            analysis.evaluator_replay_profile_id,
            "transcript-core-no-evaluator-replay-proof-v1",
        );
        assert!(analysis.tags.iter().any(|tag| tag == "direct-route"));
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
        let cases: [(String, CanonicalErrorCode); 20] = [
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
                mutate_unknown_evaluator_replay_profile_fixture(),
                CanonicalErrorCode::ProfileComponentMismatch,
            ),
            (
                mutate_malformed_magic_fixture(),
                CanonicalErrorCode::MalformedMagic,
            ),
            (
                mutate_unsupported_envelope_version_fixture(),
                CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion,
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
                mutate_unknown_base_profile_fixture(),
                CanonicalErrorCode::UnknownBaseProfile,
            ),
            (
                mutate_unknown_security_closure_fixture(),
                CanonicalErrorCode::UnknownSecurityClosure,
            ),
            (
                mutate_base_profile_mismatch_fixture(),
                CanonicalErrorCode::UnknownProofProfile,
            ),
            (
                mutate_security_profile_mismatch_fixture(),
                CanonicalErrorCode::ProfileComponentMismatch,
            ),
            (
                mutate_evaluator_replay_profile_mismatch_fixture(),
                CanonicalErrorCode::ProfileComponentMismatch,
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
            let bytes = decode_hex(&fixture_hex).expect("fixture hex should decode");
            let error =
                parse_transcript_core_object(&bytes).expect_err("malformed fixture should reject");

            assert_eq!(error.code, expected_code);
        }
    }
}
