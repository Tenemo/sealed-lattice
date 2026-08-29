use super::*;

use super::json_ingress::parse_foundation_command_request;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "command")]
enum FoundationCommand {
    EncodeFoundationManifest,
    VerifyFoundationManifest,
    EncodeFoundationActionDefinition,
    VerifyFoundationActionDefinition,
    EncodeFoundationBoardPolicy,
    VerifyFoundationBoardPolicy,
    VerifyFoundationCeremonyContext,
    VerifyFoundationActionContext,
}

fn parse_foundation_command(command_name: &str) -> CanonicalResult<FoundationCommand> {
    serde_json::from_value(json!({ "command": command_name })).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("unsupported command: {command_name}"),
        )
    })
}

pub(super) fn run_foundation_command_inner(input: &[u8]) -> CanonicalResult<Value> {
    let request = parse_foundation_command_request(input)?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "command must be a string",
            )
        })?;
    let command = parse_foundation_command(command)?;

    match command {
        FoundationCommand::EncodeFoundationManifest => {
            super::foundation_command::encode_foundation_manifest(&request)
        }
        FoundationCommand::VerifyFoundationManifest => {
            super::foundation_command::verify_foundation_manifest(&request)
        }
        FoundationCommand::EncodeFoundationActionDefinition => {
            super::foundation_command::encode_foundation_action_definition(&request)
        }
        FoundationCommand::VerifyFoundationActionDefinition => {
            super::foundation_command::verify_foundation_action_definition(&request)
        }
        FoundationCommand::EncodeFoundationBoardPolicy => {
            super::foundation_command::encode_foundation_board_policy(&request)
        }
        FoundationCommand::VerifyFoundationBoardPolicy => {
            super::foundation_command::verify_foundation_board_policy(&request)
        }
        FoundationCommand::VerifyFoundationCeremonyContext => {
            super::foundation_command::verify_foundation_ceremony_context(&request)
        }
        FoundationCommand::VerifyFoundationActionContext => {
            super::foundation_command::verify_foundation_action_context(&request)
        }
    }
}
