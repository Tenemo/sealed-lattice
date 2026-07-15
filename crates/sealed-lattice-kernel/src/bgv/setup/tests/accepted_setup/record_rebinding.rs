use crate::hashing::derive_canonical_object_hash;
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};

fn package_setup_context_hash(package: &serde_json::Value) -> String {
    crate::bgv::setup::accepted_setup::setup_context_hash(&package["setupContext"])
        .expect("setup context hash")
}

pub(super) fn rebind_collective_setup_intent_registration(
    package: &mut serde_json::Value,
    registration_index: usize,
) {
    let trustee_identity =
        package["setupIntent"]["trusteeRegistrations"][registration_index]["trusteeIdentity"]
            .as_str()
            .expect("setup-intent trustee identity")
            .to_string();
    rebind_collective_setup_intent_registration_with_signature_seed(
        package,
        registration_index,
        &format!("{trustee_identity}-setup-signing"),
    );
}

pub(super) fn rebind_collective_setup_intent_registration_with_signature_seed(
    package: &mut serde_json::Value,
    registration_index: usize,
    signature_seed_label: &str,
) {
    let mut registration =
        package["setupIntent"]["trusteeRegistrations"][registration_index].clone();
    let trustee_identity = registration["trusteeIdentity"]
        .as_str()
        .expect("setup-intent trustee identity")
        .to_string();
    let recovery_epoch = registration["recoveryEpoch"]
        .as_u64()
        .expect("setup-intent recovery epoch");
    let device_epoch = registration["deviceEpoch"]
        .as_u64()
        .expect("setup-intent device epoch");
    let roster_position =
        u64::try_from(registration_index).expect("setup-intent registration index must fit u64");
    let signing_public_key_hash = create_ml_dsa_public_key_hash_fixture(signature_seed_label)
        .expect("setup-intent signing public-key hash");
    let setup_context_hash = package_setup_context_hash(package);
    let registration_payload = serde_json::json!({
        "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
        "setupContextHash": setup_context_hash,
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "recoveryEpoch": recovery_epoch,
        "deviceEpoch": device_epoch,
        "signingPublicKeyHash": signing_public_key_hash,
        "privateVssMailboxPublicKeyHash": registration["privateVssMailboxPublicKeyHash"],
    });
    let registration_root = derive_canonical_object_hash(&registration_payload)
        .expect("setup-intent registration root");
    registration["signatureEnvelope"] = create_protocol_signature_fixture(
        signature_seed_label,
        serde_json::json!({
            "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
            "objectRoot": registration_root,
        }),
    )
    .expect("setup-intent signature fixture")
    .envelope;
    package["setupIntent"]["trusteeRegistrations"][registration_index] = registration;
}

pub(super) fn rebind_collective_setup_intent_signatures(package: &mut serde_json::Value) {
    let registration_count = package["setupIntent"]["trusteeRegistrations"]
        .as_array()
        .expect("setup-intent trustee registrations")
        .len();
    for registration_index in 0..registration_count {
        rebind_collective_setup_intent_registration(package, registration_index);
    }
}

pub(super) fn private_vss_envelope_commitment_set_root_input(
    commitment_set: &serde_json::Value,
) -> serde_json::Value {
    let mut root_input = commitment_set.clone();
    if let Some(envelope_references) = root_input
        .get_mut("envelopeReferences")
        .and_then(serde_json::Value::as_array_mut)
    {
        for envelope_reference in envelope_references {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
                envelope_reference_object.remove("encryptedEnvelope");
            }
        }
    }
    root_input
}

pub(super) fn rebind_first_private_vss_encrypted_envelope_hash(package: &mut serde_json::Value) {
    let encrypted_envelope =
        &mut package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"];
    let encrypted_envelope_hash =
        derive_canonical_object_hash(encrypted_envelope).expect("encrypted envelope hash");
    package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
        serde_json::json!(encrypted_envelope_hash);
}
