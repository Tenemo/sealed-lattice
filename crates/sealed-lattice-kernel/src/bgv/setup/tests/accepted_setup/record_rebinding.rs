use crate::bgv::setup::accepted_setup::derive_collective_setup_package_hash;
use crate::hashing::derive_canonical_object_hash;
use crate::protocol_signatures::create_protocol_signature_fixture;

pub(super) fn rebind_collective_setup_package_hash(package: &mut serde_json::Value) {
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("setupPackageHash");
    let setup_package_hash =
        derive_collective_setup_package_hash(package).expect("setup package hash");
    package["setupPackageHash"] = serde_json::json!(setup_package_hash);
}

pub(super) fn rebind_collective_setup_intent_registration(
    package: &mut serde_json::Value,
    registration_index: usize,
) {
    let mut registration = package["setupIntent"]["trusteeRegistrations"][registration_index]
        .clone();
    registration
        .as_object_mut()
        .expect("setup-intent trustee registration")
        .remove("signatureEnvelope");
    let registration_root =
        derive_canonical_object_hash(&registration).expect("setup-intent registration root");
    let trustee_identity = registration["trusteeIdentity"]
        .as_str()
        .expect("setup-intent trustee identity");
    let roster_position = registration["rosterPosition"]
        .as_u64()
        .expect("setup-intent roster position");
    let signature_context_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvSetupIntentSignatureContext",
        "ceremonyId": registration["ceremonyId"],
        "manifestHash": registration["manifestHash"],
        "rosterHash": registration["rosterHash"],
        "setupParametersHash": registration["setupParametersHash"],
        "setupEpoch": registration["setupEpoch"],
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "setupIntentRegistrationRoot": registration_root,
    }))
    .expect("setup-intent signature context hash");
    let signature_seed_label = format!("{trustee_identity}-setup-signing");
    registration["signatureEnvelope"] = create_protocol_signature_fixture(
        &signature_seed_label,
        serde_json::json!({
            "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
            "ceremonyId": registration["ceremonyId"],
            "manifestHash": registration["manifestHash"],
            "boardHeadHash": null,
            "objectRoot": registration_root,
            "chunkMerkleRoot": null,
            "signerRole": "Trustee",
            "signerIdentity": trustee_identity,
            "recoveryEpoch": registration["recoveryEpoch"],
            "deviceEpoch": registration["deviceEpoch"],
            "contextHash": signature_context_hash,
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

pub(super) fn rebind_collective_private_vss_envelope_commitment_root(
    package: &mut serde_json::Value,
) {
    package["privateVssEnvelopeCommitments"]
        .as_object_mut()
        .expect("private VSS envelope commitment set")
        .remove("privateVssEnvelopeCommitmentRoot");
    let private_vss_envelope_commitment_root = derive_canonical_object_hash(
        &private_vss_envelope_commitment_set_root_input(&package["privateVssEnvelopeCommitments"]),
    )
    .expect("private VSS envelope commitment root");
    package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(private_vss_envelope_commitment_root);
}

pub(super) fn private_vss_envelope_commitment_record_root_input(
    envelope_reference: &serde_json::Value,
) -> serde_json::Value {
    let mut root_input = envelope_reference.clone();
    root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference")
        .remove("encryptedEnvelope");
    root_input
}

pub(super) fn rebind_first_private_vss_envelope_commitment_record_root(
    package: &mut serde_json::Value,
) {
    let envelope_reference = &mut package["privateVssEnvelopeCommitments"]["envelopeReferences"][0];
    envelope_reference
        .as_object_mut()
        .expect("private VSS envelope commitment reference")
        .remove("privateEnvelopeCommitmentRoot");
    let record_root = derive_canonical_object_hash(
        &private_vss_envelope_commitment_record_root_input(envelope_reference),
    )
    .expect("private VSS envelope commitment record root");
    envelope_reference["privateEnvelopeCommitmentRoot"] = serde_json::json!(record_root);
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

pub(super) fn rebind_collective_public_key_succinct_proof_roots(package: &mut serde_json::Value) {
    package["publicKeyShareSuccinctProofs"]
        .as_object_mut()
        .expect("public-key succinct proof set")
        .remove("publicKeyShareSuccinctProofSetRoot");
    package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["publicKeyShareSuccinctProofs"])
            .expect("public-key succinct proof set root")
    );
}

pub(super) fn rebind_collective_public_key_root(package: &mut serde_json::Value) {
    package["collectivePublicKey"]
        .as_object_mut()
        .expect("collective public key")
        .remove("collectivePublicKeyRoot");
    package["collectivePublicKey"]["collectivePublicKeyRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["collectivePublicKey"])
            .expect("collective public-key root")
    );
}

pub(super) fn rebind_collective_public_key_share_roots(package: &mut serde_json::Value) {
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array_mut()
        .expect("public-key share records");
    for share_record in share_records {
        share_record
            .as_object_mut()
            .expect("public-key share record")
            .remove("publicKeyShareRoot");
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_canonical_object_hash(share_record).expect("public-key share root")
        );
    }
    package["publicKeyShares"]
        .as_object_mut()
        .expect("public-key share set")
        .remove("publicKeyShareSetRoot");
    package["publicKeyShares"]["publicKeyShareSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["publicKeyShares"])
            .expect("public-key share set root")
    );
}

pub(super) fn rebind_collective_evaluator_key_schedule_root(package: &mut serde_json::Value) {
    package["evaluatorKeySchedule"]
        .as_object_mut()
        .expect("evaluator key schedule")
        .remove("evaluatorKeyScheduleRoot");
    package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["evaluatorKeySchedule"])
            .expect("evaluator key schedule root")
    );
}
