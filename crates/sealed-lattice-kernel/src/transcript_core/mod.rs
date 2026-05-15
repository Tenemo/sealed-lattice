mod codec;
mod mutations;
mod rng;
mod types;

pub use codec::{
    analyze_canonical_object, analyze_canonical_object_hex, canonical_transcript_core_object,
    decode_hex, encode_hex, parse_transcript_core_object, serialize_transcript_core_object,
};
pub use mutations::{
    mutate_base_claim_profile_mismatch_fixture, mutate_duplicate_field_fixture,
    mutate_field_order_fixture, mutate_fully_verified_missing_evaluation_profile_fixture,
    mutate_invalid_enum_fixture, mutate_invalid_profile_fixture, mutate_invalid_utf8_fixture,
    mutate_malformed_length_fixture, mutate_malformed_magic_fixture,
    mutate_mhe_security_profile_mismatch_fixture, mutate_missing_field_fixture,
    mutate_non_canonical_varuint_fixture, mutate_trailing_bytes_fixture,
    mutate_unknown_base_claim_profile_fixture, mutate_unknown_evaluation_profile_fixture,
    mutate_unknown_field_fixture, mutate_unknown_mhe_security_closure_fixture,
    mutate_unsupported_envelope_version_fixture, mutate_unsupported_object_type_fixture,
    mutate_unsupported_object_version_fixture, mutate_wrong_evaluation_profile_fixture,
};
pub use rng::DeterministicFixtureRng;
pub use types::{
    ACTIVE_MALICIOUS_MHE_PROFILE_ID, BaseClaimProfile, FULLY_VERIFIED_ACTIVE_MALICIOUS_PROFILE,
    FULLY_VERIFIED_PASSIVE_MHE_PROFILE, FULLY_VERIFIED_RESULT_PROFILE_ID,
    MANDATORY_EVALUATION_PROOF_PROFILE_ID, MheSecurityClosure, NO_DECRYPTION_PROOF_PROFILE_ID,
    NO_HE_SETUP_PROOF_PROFILE_ID, PASSIVE_MHE_PROTOTYPE_PROFILE_ID, TranscriptCoreAnalysis,
    TranscriptCoreObject, TranscriptCoreProfile, TranscriptCoreStatus, invalid_response,
};

pub const MODULE_MARKER: &str = "transcript-core";

#[cfg(test)]
mod tests {
    use super::{
        DeterministicFixtureRng, FULLY_VERIFIED_ACTIVE_MALICIOUS_PROFILE,
        FULLY_VERIFIED_PASSIVE_MHE_PROFILE, MANDATORY_EVALUATION_PROOF_PROFILE_ID,
        analyze_canonical_object, canonical_transcript_core_object, decode_hex,
        mutate_base_claim_profile_mismatch_fixture, mutate_duplicate_field_fixture,
        mutate_field_order_fixture, mutate_fully_verified_missing_evaluation_profile_fixture,
        mutate_invalid_enum_fixture, mutate_invalid_profile_fixture, mutate_invalid_utf8_fixture,
        mutate_malformed_length_fixture, mutate_malformed_magic_fixture,
        mutate_mhe_security_profile_mismatch_fixture, mutate_missing_field_fixture,
        mutate_non_canonical_varuint_fixture, mutate_trailing_bytes_fixture,
        mutate_unknown_base_claim_profile_fixture, mutate_unknown_evaluation_profile_fixture,
        mutate_unknown_field_fixture, mutate_unknown_mhe_security_closure_fixture,
        mutate_unsupported_envelope_version_fixture, mutate_unsupported_object_type_fixture,
        mutate_unsupported_object_version_fixture, mutate_wrong_evaluation_profile_fixture,
        parse_transcript_core_object, serialize_transcript_core_object,
    };
    use crate::encoding::CanonicalErrorCode;

    #[test]
    fn canonical_object_round_trips_byte_identically() {
        let object = canonical_transcript_core_object(FULLY_VERIFIED_ACTIVE_MALICIOUS_PROFILE);
        let canonical_bytes = serialize_transcript_core_object(&object);
        let parsed = parse_transcript_core_object(&canonical_bytes).expect("object should parse");

        assert_eq!(serialize_transcript_core_object(&parsed), canonical_bytes);
    }

    #[test]
    fn profile_components_keep_the_same_shape_but_distinct_roots() {
        let fully_verified_passive_bytes = serialize_transcript_core_object(
            &canonical_transcript_core_object(FULLY_VERIFIED_PASSIVE_MHE_PROFILE),
        );
        let fully_verified_active_bytes = serialize_transcript_core_object(
            &canonical_transcript_core_object(FULLY_VERIFIED_ACTIVE_MALICIOUS_PROFILE),
        );
        let fully_verified_passive = analyze_canonical_object(&fully_verified_passive_bytes, 8)
            .expect("fully verified passive profile should analyze");
        let fully_verified_active = analyze_canonical_object(&fully_verified_active_bytes, 8)
            .expect("fully verified active profile should analyze");

        assert_eq!(
            fully_verified_passive.object_type,
            fully_verified_active.object_type
        );
        assert_eq!(
            fully_verified_passive.object_version,
            fully_verified_active.object_version
        );
        assert_ne!(
            fully_verified_passive.object_hash512,
            fully_verified_active.object_hash512
        );
        assert_eq!(
            fully_verified_active.evaluation_proof_profile_id,
            MANDATORY_EVALUATION_PROOF_PROFILE_ID,
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
        let cases: [(String, CanonicalErrorCode); 21] = [
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
                mutate_unknown_base_claim_profile_fixture(),
                CanonicalErrorCode::UnknownBaseClaimProfile,
            ),
            (
                mutate_unknown_mhe_security_closure_fixture(),
                CanonicalErrorCode::UnknownMheSecurityClosure,
            ),
            (
                mutate_base_claim_profile_mismatch_fixture(),
                CanonicalErrorCode::UnknownProofProfile,
            ),
            (
                mutate_mhe_security_profile_mismatch_fixture(),
                CanonicalErrorCode::ProfileComponentMismatch,
            ),
            (
                mutate_wrong_evaluation_profile_fixture(),
                CanonicalErrorCode::ProfileComponentMismatch,
            ),
            (
                mutate_fully_verified_missing_evaluation_profile_fixture(),
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
