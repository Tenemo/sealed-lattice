use super::*;

pub(super) fn read_passive_setup_input(request: &Value) -> CanonicalResult<PassiveSetupInput> {
    let ceremony_id = read_non_empty_string(request, "ceremonyId")?.to_string();
    let manifest_digest = read_digest_field(request, "manifestDigest")?.to_string();
    let roster_digest = read_digest_field(request, "rosterDigest")?.to_string();
    let threshold_profile_digest =
        read_digest_field(request, "thresholdProfileDigest")?.to_string();
    let setup_seed_provided = request.get("setupSeed").is_some();
    let setup_seed = request
        .get("setupSeed")
        .and_then(Value::as_str)
        .unwrap_or("sealed-lattice-m8-passive-development-seed-v1");
    if setup_seed.trim().is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupSeed must not be empty when supplied",
        ));
    }
    let setup_seed_digest = hash512_hex(
        "sealed-lattice-bgv-rns/passive-setup-seed-digest-v1",
        &[
            ceremony_id.as_bytes(),
            manifest_digest.as_bytes(),
            roster_digest.as_bytes(),
            threshold_profile_digest.as_bytes(),
            setup_seed.as_bytes(),
        ],
    );
    let participants = read_setup_participants(request)?;
    if participants.len() < MINIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup requires at least three frozen roster participants",
        ));
    }
    if participants.len() > MAXIMUM_PASSIVE_SETUP_ROSTER_SIZE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M8 passive setup supports at most fifty frozen roster participants",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    for participant in &participants {
        if !identities.insert(participant.trustee_identity.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup participant identities must be unique",
            ));
        }
        if participant.roster_position >= participants.len()
            || !roster_positions.insert(participant.roster_position)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M8 passive setup roster positions must be unique and cover the frozen roster",
            ));
        }
    }

    Ok(PassiveSetupInput {
        ceremony_id,
        manifest_digest,
        roster_digest,
        threshold_profile_digest,
        setup_seed_provided,
        setup_seed_digest,
        participants,
    })
}

fn is_nfc_normalized(value: &str) -> bool {
    value.nfc().eq(value.chars())
}

pub(super) fn ensure_nfc_identity(value: &str, field_name: &str) -> CanonicalResult<()> {
    if is_nfc_normalized(value) {
        Ok(())
    } else {
        Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be NFC-normalized"),
        ))
    }
}

fn read_setup_participants(request: &Value) -> CanonicalResult<Vec<SetupParticipant>> {
    let participants = request
        .get("participants")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants must be an array",
            )
        })?;
    participants
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::String(identity) => {
                if identity.trim().is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "participant identity must not be empty",
                    ));
                }
                ensure_nfc_identity(identity, "participant identity")?;
                Ok(SetupParticipant {
                    trustee_identity: identity.clone(),
                    roster_position: index,
                    board_position: index,
                    recovery_epoch: 0,
                    device_epoch: 0,
                })
            }
            Value::Object(_) => {
                reject_forbidden_setup_fields(value)?;
                let trustee_identity = read_non_empty_string(value, "trusteeIdentity")?.to_string();
                ensure_nfc_identity(&trustee_identity, "participant trusteeIdentity")?;
                Ok(SetupParticipant {
                    trustee_identity,
                    roster_position: read_optional_usize(value, "rosterPosition")?.unwrap_or(index),
                    board_position: read_optional_usize(value, "boardPosition")?.unwrap_or(index),
                    recovery_epoch: read_optional_u64(value, "recoveryEpoch")?.unwrap_or(0),
                    device_epoch: read_optional_u64(value, "deviceEpoch")?.unwrap_or(0),
                })
            }
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "participants entries must be trustee identity strings or participant objects",
            )),
        })
        .collect()
}
