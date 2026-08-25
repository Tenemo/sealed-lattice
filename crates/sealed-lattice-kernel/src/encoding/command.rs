use super::*;

use super::json_ingress::parse_transcript_core_request;

use crate::hashing::derive_canonical_object_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum TranscriptCoreCommand {
    DeriveCanonicalObjectHash,
    EncodeFoundationManifest,
    VerifyFoundationManifest,
    EncodeFoundationActionDefinition,
    VerifyFoundationActionDefinition,
    EncodeFoundationBoardPolicy,
    VerifyFoundationBoardPolicy,
    VerifyFoundationCeremonyContext,
    VerifyFoundationActionContext,
}

fn parse_transcript_core_command(command_name: &str) -> CanonicalResult<TranscriptCoreCommand> {
    serde_json::from_value(json!({ "command": command_name })).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("unsupported command: {command_name}"),
        )
    })
}

pub(super) fn run_transcript_core_command_inner(input: &[u8]) -> CanonicalResult<Value> {
    let request = parse_transcript_core_request(input)?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "command must be a string",
            )
        })?;
    let command = parse_transcript_core_command(command)?;

    match command {
        TranscriptCoreCommand::DeriveCanonicalObjectHash => {
            let value = request.get("value").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "value field is required",
                )
            })?;

            Ok(json!({
                "canonicalObjectHash": derive_canonical_object_hash(value)?,
            }))
        }
        TranscriptCoreCommand::EncodeFoundationManifest => {
            super::foundation_command::encode_foundation_manifest(&request)
        }
        TranscriptCoreCommand::VerifyFoundationManifest => {
            super::foundation_command::verify_foundation_manifest(&request)
        }
        TranscriptCoreCommand::EncodeFoundationActionDefinition => {
            super::foundation_command::encode_foundation_action_definition(&request)
        }
        TranscriptCoreCommand::VerifyFoundationActionDefinition => {
            super::foundation_command::verify_foundation_action_definition(&request)
        }
        TranscriptCoreCommand::EncodeFoundationBoardPolicy => {
            super::foundation_command::encode_foundation_board_policy(&request)
        }
        TranscriptCoreCommand::VerifyFoundationBoardPolicy => {
            super::foundation_command::verify_foundation_board_policy(&request)
        }
        TranscriptCoreCommand::VerifyFoundationCeremonyContext => {
            super::foundation_command::verify_foundation_ceremony_context(&request)
        }
        TranscriptCoreCommand::VerifyFoundationActionContext => {
            super::foundation_command::verify_foundation_action_context(&request)
        }
    }
}
