use super::*;

use crate::hashing::derive_canonical_object_hash;

const SETUP_INTENT_OBJECT_TYPE: &str = "CollectiveBgvSetupIntent";
const SETUP_INTENT_REGISTRATION_OBJECT_TYPE: &str =
    "CollectiveBgvSetupIntentTrusteeRegistration";
const SETUP_INTENT_SIGNATURE_CONTEXT_OBJECT_TYPE: &str =
    "CollectiveBgvSetupIntentSignatureContext";

#[derive(Clone)]
pub(super) struct SetupIntentTrusteeRegistration {
    pub(super) trustee_identity: String,
    pub(super) signing_public_key_hash: String,
    pub(super) private_vss_mailbox_public_key_hash: String,
}

pub(super) type SetupIntentTrusteeRegistrationMap =
    BTreeMap<u64, SetupIntentTrusteeRegistration>;

pub(super) enum SetupIntentVerification {
    Verified(SetupIntentTrusteeRegistrationMap),
    Refused(Value),
}

pub(super) fn verify_setup_intent(
    setup_package: &Value,
) -> CanonicalResult<SetupIntentVerification> {
    let Some(setup_intent) = setup_package.get("setupIntent") else {
        return Ok(SetupIntentVerification::Refused(verification_response(
            vec!["setupIntent".to_string()],
            Vec::new(),
        )?));
    };
    if !setup_intent.is_object() {
        return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
            "setupIntentNotObject",
            "setupIntent must be an object",
            "setupPackage.setupIntent",
        )?));
    }
    if setup_intent.get("objectType").and_then(Value::as_str)
        != Some(SETUP_INTENT_OBJECT_TYPE)
    {
        return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
            "setupIntentTypeMismatch",
            format!("setupIntent.objectType must be {SETUP_INTENT_OBJECT_TYPE}"),
            "setupPackage.setupIntent.objectType",
        )?));
    }

    let Some(registration_values) = setup_intent
        .get("trusteeRegistrations")
        .and_then(Value::as_array)
    else {
        return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
            "setupIntentTrusteeRegistrationsMalformed",
            "setupIntent.trusteeRegistrations must be an array",
            "setupPackage.setupIntent.trusteeRegistrations",
        )?));
    };
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup-intent verification",
        )
    })?;
    let roster = super::accepted_roster_from_setup_context(setup_context)?;
    if registration_values.len() != roster.participant_count as usize {
        return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
            "setupIntentTrusteeRegistrationCountMismatch",
            "setupIntent.trusteeRegistrations must contain one signed registration per participant",
            "setupPackage.setupIntent.trusteeRegistrations",
        )?));
    }

    let mut registrations = BTreeMap::new();
    for (registration_index, registration_value) in registration_values.iter().enumerate() {
        let registration = match verify_setup_intent_registration(
            registration_value,
            setup_context,
            &roster,
        )? {
            Ok(registration) => registration,
            Err(response) => return Ok(SetupIntentVerification::Refused(response)),
        };
        let roster_position = registration_value["rosterPosition"]
            .as_u64()
            .expect("setup-intent registration roster position was verified");
        if registrations
            .insert(roster_position, registration)
            .is_some()
        {
            return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
                "setupIntentRosterPositionDuplicate",
                "setupIntent.trusteeRegistrations contains duplicate roster positions",
                "setupPackage.setupIntent.trusteeRegistrations",
            )?));
        }
        if roster_position != registration_index as u64 {
            return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
                "setupIntentTrusteeRegistrationOrderMismatch",
                "setupIntent.trusteeRegistrations must be ordered by rosterPosition",
                format!(
                    "setupPackage.setupIntent.trusteeRegistrations.{registration_index}.rosterPosition"
                ),
            )?));
        }
    }

    Ok(SetupIntentVerification::Verified(registrations))
}

fn verify_setup_intent_registration(
    registration_value: &Value,
    setup_context: &Value,
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Result<SetupIntentTrusteeRegistration, Value>> {
    const REGISTRATION_PATH: &str = "setupPackage.setupIntent.trusteeRegistrations";
    if !registration_value.is_object() {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeRegistrationNotObject",
            "setup-intent trustee registrations must be objects",
            REGISTRATION_PATH,
        )?));
    }
    if registration_value
        .get("objectType")
        .and_then(Value::as_str)
        != Some(SETUP_INTENT_REGISTRATION_OBJECT_TYPE)
    {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeRegistrationTypeMismatch",
            format!(
                "setup-intent trustee registrations must use {SETUP_INTENT_REGISTRATION_OBJECT_TYPE}"
            ),
            REGISTRATION_PATH,
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if registration_value.get(field_name) != setup_context.get(field_name) {
            return Ok(Err(setup_intent_refusal(
                "setupIntentTrusteeRegistrationContextMismatch",
                format!("setup-intent trustee registration {field_name} must match setupContext"),
                format!("{REGISTRATION_PATH}.{field_name}"),
            )?));
        }
    }

    let Some(trustee_identity) = registration_value
        .get("trusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeIdentityMissing",
            "setup-intent trustee registration must bind trusteeIdentity",
            format!("{REGISTRATION_PATH}.trusteeIdentity"),
        )?));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeIdentityMalformed",
            "setup-intent trustee identity must be non-empty NFC text",
            format!("{REGISTRATION_PATH}.trusteeIdentity"),
        )?));
    }
    let Some(roster_position) = registration_value
        .get("rosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentRosterPositionMissing",
            "setup-intent trustee registration must bind rosterPosition",
            format!("{REGISTRATION_PATH}.rosterPosition"),
        )?));
    };
    if roster_position >= roster.participant_count {
        return Ok(Err(setup_intent_refusal(
            "setupIntentRosterPositionOutsideParameters",
            "setup-intent trustee registration rosterPosition is outside the accepted roster",
            format!("{REGISTRATION_PATH}.rosterPosition"),
        )?));
    }
    let Some(recovery_epoch) = registration_value
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeEpochMissing",
            "setup-intent trustee registration must bind recoveryEpoch",
            format!("{REGISTRATION_PATH}.recoveryEpoch"),
        )?));
    };
    let Some(device_epoch) = registration_value
        .get("deviceEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeEpochMissing",
            "setup-intent trustee registration must bind deviceEpoch",
            format!("{REGISTRATION_PATH}.deviceEpoch"),
        )?));
    };
    let Some(signing_public_key_hash) = registration_value
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentSigningKeyHashMissing",
            "setup-intent trustee registration must bind signingPublicKeyHash",
            format!("{REGISTRATION_PATH}.signingPublicKeyHash"),
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "setupIntent.trusteeRegistrations.signingPublicKeyHash",
    )?;
    let Some(private_vss_mailbox_public_key_hash) = registration_value
        .get("privateVssMailboxPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentMailboxKeyHashMissing",
            "setup-intent trustee registration must bind privateVssMailboxPublicKeyHash",
            format!("{REGISTRATION_PATH}.privateVssMailboxPublicKeyHash"),
        )?));
    };
    validate_hash_string(
        private_vss_mailbox_public_key_hash,
        "setupIntent.trusteeRegistrations.privateVssMailboxPublicKeyHash",
    )?;

    let registration_payload = json!({
        "objectType": SETUP_INTENT_REGISTRATION_OBJECT_TYPE,
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupParametersHash": setup_context_string(setup_context, "setupParametersHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "recoveryEpoch": recovery_epoch,
        "deviceEpoch": device_epoch,
        "signingPublicKeyHash": signing_public_key_hash,
        "privateVssMailboxPublicKeyHash": private_vss_mailbox_public_key_hash,
    });
    let registration_root = derive_canonical_object_hash(&registration_payload)?;
    let signature_context_hash = derive_canonical_object_hash(&json!({
        "objectType": SETUP_INTENT_SIGNATURE_CONTEXT_OBJECT_TYPE,
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupParametersHash": setup_context_string(setup_context, "setupParametersHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "setupIntentRegistrationRoot": registration_root,
    }))?;
    let Some(signature_envelope) = registration_value.get("signatureEnvelope") else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentSignatureEnvelopeMissing",
            "setup-intent trustee registration must include an ML-DSA signature envelope",
            format!("{REGISTRATION_PATH}.signatureEnvelope"),
        )?));
    };
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: SETUP_INTENT_REGISTRATION_OBJECT_TYPE,
            signer_role: "Trustee",
            signer_identity: trustee_identity,
            ceremony_id: setup_context_string(setup_context, "ceremonyId")?,
            public_key_hash: signing_public_key_hash,
            manifest_hash: Some(setup_context_string(setup_context, "manifestHash")?),
            object_root: Some(&registration_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &signature_context_hash,
            recovery_epoch,
            device_epoch,
        },
    )?;
    if let Err(failure) = verification {
        return Ok(Err(setup_intent_refusal(
            failure.reason_code,
            failure.message,
            format!("{REGISTRATION_PATH}.signatureEnvelope"),
        )?));
    }

    Ok(Ok(SetupIntentTrusteeRegistration {
        trustee_identity: trustee_identity.to_string(),
        signing_public_key_hash: signing_public_key_hash.to_string(),
        private_vss_mailbox_public_key_hash: private_vss_mailbox_public_key_hash.to_string(),
    }))
}

pub(super) fn setup_context_string<'a>(
    setup_context: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    setup_context
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupContext.{field_name} must be a string"),
            )
        })
}

pub(super) fn setup_intent_trustee_registrations_from_package(
    setup_package: &Value,
) -> CanonicalResult<SetupIntentTrusteeRegistrationMap> {
    let registration_values = setup_package
        .get("setupIntent")
        .and_then(|setup_intent| setup_intent.get("trusteeRegistrations"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent.trusteeRegistrations was required before trustee registration extraction",
            )
        })?;
    let mut registrations = BTreeMap::new();
    for (registration_index, registration_value) in registration_values.iter().enumerate() {
        let roster_position = value_u64(registration_value, "rosterPosition")?;
        if roster_position != registration_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent.trusteeRegistrations must be ordered by rosterPosition",
            ));
        }
        let registration = SetupIntentTrusteeRegistration {
            trustee_identity: value_string(registration_value, "trusteeIdentity")?.to_string(),
            signing_public_key_hash: value_string(registration_value, "signingPublicKeyHash")?
                .to_string(),
            private_vss_mailbox_public_key_hash: value_string(
                registration_value,
                "privateVssMailboxPublicKeyHash",
            )?
            .to_string(),
        };
        if registrations
            .insert(roster_position, registration)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent.trusteeRegistrations contains duplicate roster positions",
            ));
        }
    }
    Ok(registrations)
}

pub(super) fn expected_trustees_from_setup_intent(
    registrations: &SetupIntentTrusteeRegistrationMap,
) -> BTreeMap<u64, String> {
    registrations
        .iter()
        .map(|(roster_position, registration)| {
            (*roster_position, registration.trustee_identity.clone())
        })
        .collect()
}

pub(crate) fn accepted_setup_participant_roster_from_package(
    setup_package: &Value,
) -> CanonicalResult<Vec<(usize, String)>> {
    setup_intent_trustee_registrations_from_package(setup_package)?
        .into_iter()
        .map(|(roster_position, registration)| {
            let roster_position = usize::try_from(roster_position).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "accepted setup roster position does not fit usize",
                )
            })?;
            Ok((roster_position, registration.trustee_identity))
        })
        .collect()
}

pub(super) fn verify_setup_intent_roster_hash(
    setup_package: &Value,
    registrations: &SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Value>> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup roster hash verification",
        )
    })?;
    let roster_hash = setup_context_string(setup_context, "rosterHash")?;
    let expected_roster_hash = setup_intent_roster_hash_from_registrations(registrations)?;
    if roster_hash != expected_roster_hash {
        return Ok(Some(verification_response(
            Vec::new(),
            vec![Refusal::new(
                "setupRosterHashMismatch",
                "setupContext.rosterHash must match the setup-intent trustee identity and signing-key registrations",
                "setupPackage.setupContext.rosterHash",
            )],
        )?));
    }
    Ok(None)
}

pub(super) fn setup_intent_roster_hash_from_registrations(
    registrations: &SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<String> {
    let roster_entries = registrations
        .iter()
        .map(|(roster_position, registration)| {
            json!({
                "objectType": "CollectiveBgvSetupRosterEntry",
                "rosterPosition": roster_position,
                "trusteeIdentity": registration.trustee_identity,
                "signingPublicKeyHash": registration.signing_public_key_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvSetupRoster",
        "rosterEntries": roster_entries,
    }))
}

fn setup_intent_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
