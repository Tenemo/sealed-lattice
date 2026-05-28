use super::{CanonicalErrorCode, CanonicalReader, append_varuint, encode_error, encode_varuint};

#[test]
fn varuint_round_trips_boundary_values() {
    for value in [0, 1, 2, 127, 128, 255, 16_384, u32::MAX as u64, u64::MAX] {
        let encoded = encode_varuint(value);
        let mut reader = CanonicalReader::new(&encoded);

        assert_eq!(reader.read_varuint().expect("value should decode"), value);
        assert!(reader.is_finished());
    }
}

#[test]
fn rejects_non_canonical_varuint() {
    let mut reader = CanonicalReader::new(&[0x80, 0x00]);
    let error = reader
        .read_varuint()
        .expect_err("redundant varuint should fail");

    assert_eq!(error.code, CanonicalErrorCode::NonCanonicalVarUint);
}

#[test]
fn append_varuint_uses_canonical_encoding() {
    let mut output = Vec::new();
    append_varuint(&mut output, 128);

    assert_eq!(output, vec![0x80, 0x01]);
}

#[test]
fn command_errors_are_json_encoded() {
    let encoded = encode_error(super::CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        "bad command",
    ));
    let response = String::from_utf8(encoded).expect("error should be UTF-8 JSON");

    assert!(response.contains("\"success\":false"));
    assert!(response.contains("\"InvalidFixture\""));
}

#[test]
fn command_rejects_missing_command_with_stable_message() {
    let error = super::run_transcript_core_command_inner(br#"{}"#)
        .expect_err("missing command should fail");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert_eq!(error.message, "command must be a string");
}

#[test]
fn command_rejects_unknown_command_with_stable_message() {
    let error = super::run_transcript_core_command_inner(
        serde_json::json!({
            "command": "NotACommand"
        })
        .to_string()
        .as_bytes(),
    )
    .expect_err("unknown command should fail");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert_eq!(error.message, "unsupported command: NotACommand");
}

#[test]
fn category_dispatchers_reject_wrong_command_families() {
    let request = serde_json::json!({});
    let ballot_error = super::run_ballot_privacy_command(
        super::TranscriptCoreCommand::DescribeBgvRnsProfile,
        &request,
    )
    .expect_err("BGV command must not dispatch through ballot privacy");
    let bgv_error =
        super::run_bgv_command(super::TranscriptCoreCommand::GenerateBallotProof, &request)
            .expect_err("ballot command must not dispatch through BGV");

    assert_eq!(ballot_error.code, CanonicalErrorCode::InvalidFixture);
    assert_eq!(
        ballot_error.message,
        "non-ballot command dispatched to ballot privacy handler"
    );
    assert_eq!(bgv_error.code, CanonicalErrorCode::InvalidFixture);
    assert_eq!(
        bgv_error.message,
        "non-BGV command dispatched to BGV handler"
    );
}

#[test]
fn command_derives_protocol_hash_with_kernel_canonical_json() {
    let response = super::run_transcript_core_command_inner(
        serde_json::json!({
            "command": "DeriveProtocolHash",
            "namespace": "PollSpecHash",
            "value": {
                "poll": "main"
            }
        })
        .to_string()
        .as_bytes(),
    )
    .expect("protocol hash command should succeed");

    assert_eq!(
        response["protocolHash"],
        "43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4"
    );
}

#[test]
fn analyze_canonical_object_requires_explicit_chunk_size() {
    let error = super::run_transcript_core_command_inner(
        serde_json::json!({
            "command": "AnalyzeCanonicalObject",
            "canonicalBytesHex": ""
        })
        .to_string()
        .as_bytes(),
    )
    .expect_err("missing chunk size should fail");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert_eq!(error.message, "chunkSize must be an integer");
}

#[test]
fn command_exposes_kernel_field_interpolation() {
    let response = super::run_transcript_core_command_inner(
        serde_json::json!({
            "command": "InterpolateShamirConstantTerm",
            "sharePoints": [
                { "rosterPosition": 1, "value": 15 },
                { "rosterPosition": 2, "value": 25 }
            ]
        })
        .to_string()
        .as_bytes(),
    )
    .expect("field interpolation command should succeed");

    assert_eq!(response["fieldElement"], 5);
}

#[test]
fn command_exposes_plaintext_comparison() {
    let response = super::run_transcript_core_command_inner(
        serde_json::json!({
            "command": "EvaluatePlaintextComparison",
            "leftTotalScore": 41,
            "rightTotalScore": 40,
            "rosterSize": 5
        })
        .to_string()
        .as_bytes(),
    )
    .expect("plaintext comparison command should succeed");

    assert_eq!(response["greaterThan"], 1);
    assert_eq!(response["equal"], 0);
    assert_eq!(response["scoreDifference"], 1);
}

#[test]
fn all_canonical_error_codes_is_exhaustive() {
    // The compiler enforces exhaustiveness here. If a new variant is added
    // to `CanonicalErrorCode`, this match fails and the dev must extend
    // both the match arm and `ALL_CANONICAL_ERROR_CODES`.
    fn ensure_exhaustive(code: CanonicalErrorCode) {
        match code {
            CanonicalErrorCode::DuplicateField
            | CanonicalErrorCode::FieldOrder
            | CanonicalErrorCode::FixtureMismatch
            | CanonicalErrorCode::InvalidChunkSize
            | CanonicalErrorCode::InvalidEnum
            | CanonicalErrorCode::InvalidFixture
            | CanonicalErrorCode::InvalidHex
            | CanonicalErrorCode::InvalidUtf8
            | CanonicalErrorCode::MalformedLength
            | CanonicalErrorCode::MalformedMagic
            | CanonicalErrorCode::MalformedVarUint
            | CanonicalErrorCode::MissingField
            | CanonicalErrorCode::NonCanonicalVarUint
            | CanonicalErrorCode::ProfileComponentMismatch
            | CanonicalErrorCode::TrailingBytes
            | CanonicalErrorCode::UnknownField
            | CanonicalErrorCode::UnknownBaseClaimProfile
            | CanonicalErrorCode::UnknownMheSecurityClosure
            | CanonicalErrorCode::UnknownProofProfile
            | CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion
            | CanonicalErrorCode::UnsupportedObjectType
            | CanonicalErrorCode::UnsupportedObjectVersion => {}
        }
    }

    for code in super::ALL_CANONICAL_ERROR_CODES {
        ensure_exhaustive(code.clone());
    }

    assert_eq!(super::ALL_CANONICAL_ERROR_CODES.len(), 22);
}
