use super::*;

use crate::hashing::derive_canonical_object_hash;

const SETUP_INTENT_OBJECT_TYPE: &str = "CollectiveBgvSetupIntent";
const SETUP_INTENT_REGISTRATION_OBJECT_TYPE: &str = "CollectiveBgvSetupIntentTrusteeRegistration";
const SETUP_INTENT_SIGNATURE_CONTEXT_OBJECT_TYPE: &str = "CollectiveBgvSetupIntentSignatureContext";

#[derive(Clone)]
pub(super) struct SetupIntentTrusteeRegistration {
    pub(super) trustee_identity: String,
    pub(super) signing_public_key_hash: String,
    pub(super) private_vss_mailbox_public_key_hash: String,
}

pub(super) type SetupIntentTrusteeRegistrationMap = BTreeMap<u64, SetupIntentTrusteeRegistration>;

pub(super) enum SetupIntentVerification {
    Verified(SetupIntentTrusteeRegistrationMap),
    Refused(Refusals),
}

pub(super) fn verify_setup_intent(
    setup_package: &Value,
) -> CanonicalResult<SetupIntentVerification> {
    let Some(setup_intent) = setup_package.get("setupIntent") else {
        return Ok(SetupIntentVerification::Refused(setup_refusals(
            vec!["setupIntent".to_string()],
            Vec::new(),
        )));
    };
    if !setup_intent.is_object() {
        return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
            "setupIntentNotObject",
            "setupIntent must be an object",
            "setupPackage.setupIntent",
        )?));
    }
    if setup_intent.get("objectType").and_then(Value::as_str) != Some(SETUP_INTENT_OBJECT_TYPE) {
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
    let mut trustee_identities = BTreeSet::new();
    let mut signing_public_key_hashes = BTreeSet::new();
    let mut private_vss_mailbox_public_key_hashes = BTreeSet::new();
    for (registration_index, registration_value) in registration_values.iter().enumerate() {
        let roster_position = u64::try_from(registration_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup-intent registration index does not fit u64",
            )
        })?;
        let registration = match verify_setup_intent_registration(
            registration_value,
            setup_context,
            roster_position,
        )? {
            Ok(registration) => registration,
            Err(response) => return Ok(SetupIntentVerification::Refused(response)),
        };
        if !trustee_identities.insert(registration.trustee_identity.clone()) {
            return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
                "setupIntentTrusteeIdentityDuplicate",
                "setupIntent.trusteeRegistrations must bind distinct trustee identities",
                "setupPackage.setupIntent.trusteeRegistrations",
            )?));
        }
        if !signing_public_key_hashes.insert(registration.signing_public_key_hash.clone()) {
            return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
                "setupIntentSigningKeyDuplicate",
                "setupIntent.trusteeRegistrations must bind distinct signing keys",
                "setupPackage.setupIntent.trusteeRegistrations",
            )?));
        }
        if !private_vss_mailbox_public_key_hashes
            .insert(registration.private_vss_mailbox_public_key_hash.clone())
        {
            return Ok(SetupIntentVerification::Refused(setup_intent_refusal(
                "setupIntentMailboxKeyDuplicate",
                "setupIntent.trusteeRegistrations must bind distinct private VSS mailbox keys",
                "setupPackage.setupIntent.trusteeRegistrations",
            )?));
        }
        registrations.insert(roster_position, registration);
    }

    Ok(SetupIntentVerification::Verified(registrations))
}

fn verify_setup_intent_registration(
    registration_value: &Value,
    setup_context: &Value,
    roster_position: u64,
) -> CanonicalResult<Result<SetupIntentTrusteeRegistration, Refusals>> {
    const REGISTRATION_PATH: &str = "setupPackage.setupIntent.trusteeRegistrations";
    if !registration_value.is_object() {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeRegistrationNotObject",
            "setup-intent trustee registrations must be objects",
            REGISTRATION_PATH,
        )?));
    }
    if registration_value.get("objectType").and_then(Value::as_str)
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
    let Some(signature_envelope) = registration_value.get("signatureEnvelope") else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentSignatureEnvelopeMissing",
            "setup-intent trustee registration must include an ML-DSA signature envelope",
            format!("{REGISTRATION_PATH}.signatureEnvelope"),
        )?));
    };
    let Some(signed_root) = signature_envelope
        .get("signedRoot")
        .and_then(Value::as_object)
    else {
        return Ok(Err(setup_intent_refusal(
            "InvalidSignedRoot",
            "setup-intent signature envelope must include a signedRoot object",
            format!("{REGISTRATION_PATH}.signatureEnvelope.signedRoot"),
        )?));
    };
    let Some(trustee_identity) = signed_root.get("signerIdentity").and_then(Value::as_str) else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeIdentityMissing",
            "setup-intent signed root must bind signerIdentity",
            format!("{REGISTRATION_PATH}.signatureEnvelope.signedRoot.signerIdentity"),
        )?));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeIdentityMalformed",
            "setup-intent trustee identity must be non-empty NFC text",
            format!("{REGISTRATION_PATH}.signatureEnvelope.signedRoot.signerIdentity"),
        )?));
    }
    let Some(recovery_epoch) = signed_root.get("recoveryEpoch").and_then(Value::as_u64) else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeEpochMissing",
            "setup-intent signed root must bind recoveryEpoch",
            format!("{REGISTRATION_PATH}.signatureEnvelope.signedRoot.recoveryEpoch"),
        )?));
    };
    let Some(device_epoch) = signed_root.get("deviceEpoch").and_then(Value::as_u64) else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentTrusteeEpochMissing",
            "setup-intent signed root must bind deviceEpoch",
            format!("{REGISTRATION_PATH}.signatureEnvelope.signedRoot.deviceEpoch"),
        )?));
    };
    let Some(signing_public_key_hash) = signature_envelope
        .get("publicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Err(setup_intent_refusal(
            "setupIntentSigningKeyHashMissing",
            "setup-intent signature envelope must bind publicKeyHash",
            format!("{REGISTRATION_PATH}.signatureEnvelope.publicKeyHash"),
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "setupIntent.trusteeRegistrations.signatureEnvelope.publicKeyHash",
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
        "setupContextHash": setup_context_hash(setup_context)?,
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
        "setupIntentRegistrationRoot": registration_root,
    }))?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: SETUP_INTENT_REGISTRATION_OBJECT_TYPE,
            signer_role: "Trustee",
            signer_identity: trustee_identity,
            ceremony_id: setup_context_string(setup_context, "ceremonyId")?,
            public_key_hash: signing_public_key_hash,
            manifest_hash: setup_context_string(setup_context, "manifestHash")?,
            object_root: &registration_root,
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
        let roster_position = u64::try_from(registration_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup-intent registration index does not fit u64",
            )
        })?;
        let signature_envelope = registration_value.get("signatureEnvelope").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setup-intent registration signatureEnvelope is required",
            )
        })?;
        let signed_root = signature_envelope.get("signedRoot").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setup-intent registration signedRoot is required",
            )
        })?;
        let registration = SetupIntentTrusteeRegistration {
            trustee_identity: value_string(signed_root, "signerIdentity")?.to_string(),
            signing_public_key_hash: value_string(signature_envelope, "publicKeyHash")?.to_string(),
            private_vss_mailbox_public_key_hash: value_string(
                registration_value,
                "privateVssMailboxPublicKeyHash",
            )?
            .to_string(),
        };
        registrations.insert(roster_position, registration);
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
) -> CanonicalResult<Option<Refusals>> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup roster hash verification",
        )
    })?;
    let roster_hash = setup_context_string(setup_context, "rosterHash")?;
    let expected_roster_hash = setup_intent_roster_hash_from_registrations(registrations)?;
    if roster_hash != expected_roster_hash {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                "setupRosterHashMismatch",
                "setupContext.rosterHash must match the setup-intent trustee identity and signing-key registrations",
                "setupPackage.setupContext.rosterHash",
            )],
        )));
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
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    ))
}
