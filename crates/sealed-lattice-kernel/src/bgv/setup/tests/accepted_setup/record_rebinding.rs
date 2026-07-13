use crate::bgv::setup::accepted_setup::derive_collective_setup_package_hash;
use crate::hashing::derive_canonical_object_hash;
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};

fn package_setup_context_hash(package: &serde_json::Value) -> String {
    crate::bgv::setup::accepted_setup::setup_context_hash(&package["setupContext"])
        .expect("setup context hash")
}

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
    let trustee_identity = package["setupIntent"]["trusteeRegistrations"][registration_index]
        ["signatureEnvelope"]["signedRoot"]["signerIdentity"]
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
    let setup_context = package["setupContext"].clone();
    let signed_root = registration["signatureEnvelope"]["signedRoot"].clone();
    let trustee_identity = signed_root["signerIdentity"]
        .as_str()
        .expect("setup-intent trustee identity")
        .to_string();
    let recovery_epoch = signed_root["recoveryEpoch"]
        .as_u64()
        .expect("setup-intent recovery epoch");
    let device_epoch = signed_root["deviceEpoch"]
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
    let signature_context_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvSetupIntentSignatureContext",
        "setupIntentRegistrationRoot": registration_root,
    }))
    .expect("setup-intent signature context hash");
    registration["signatureEnvelope"] = create_protocol_signature_fixture(
        signature_seed_label,
        serde_json::json!({
            "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "objectRoot": registration_root,
            "signerRole": "Trustee",
            "signerIdentity": trustee_identity,
            "recoveryEpoch": recovery_epoch,
            "deviceEpoch": device_epoch,
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
    let root_input = serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "setupContextHash": package_setup_context_hash(package),
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
        "envelopeReferences": package["privateVssEnvelopeCommitments"]["envelopeReferences"],
    });
    let private_vss_envelope_commitment_root =
        derive_canonical_object_hash(&private_vss_envelope_commitment_set_root_input(&root_input))
            .expect("private VSS envelope commitment root");
    package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(private_vss_envelope_commitment_root);
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
    let setup_context_hash = package_setup_context_hash(package);
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array()
        .expect("public-key share records")
        .clone();
    let material_roots = package["publicKeyShareMaterial"]
        .get("publicKeyShareMaterialRoots")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            package["publicKeyShareMaterial"]["shareMaterialRecords"]
                .as_array()
                .expect("public-key share material records")
                .iter()
                .map(|record| record["publicKeyShareMaterialRoot"].clone())
                .collect()
        });
    let bridge_statements = package["sameSecretBridgeStatementSet"]["statementRecords"]
        .as_array()
        .expect("same-secret bridge statements")
        .clone();
    let bridge_proofs = package["sameSecretBridgeProofMaterialSet"]["proofRecords"]
        .as_array()
        .expect("same-secret bridge proofs")
        .clone();
    let proof_records = package["publicKeyShareSuccinctProofs"]["proofRecords"]
        .as_array()
        .expect("public-key succinct proof records")
        .clone();
    let logical_proof_records = proof_records
        .iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("public-key proof trustee roster position")
                as usize;
            let share_record = &share_records[trustee_roster_position];
            let bridge_statement = &bridge_statements[trustee_roster_position];
            let bridge_proof = bridge_proofs
                .iter()
                .find(|bridge_proof| {
                    bridge_proof["sameSecretBridgeStatementRoot"]
                        == bridge_statement["sameSecretBridgeStatementRoot"]
                })
                .expect("same-secret bridge proof for public-key proof");
            serde_json::json!({
                "objectType": "PublicKeyShareSuccinctProof",
                "setupContextHash": setup_context_hash,
                "trusteeIdentity": share_record["trusteeIdentity"],
                "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
                "publicKeyShareRoot": share_record["publicKeyShareRoot"],
                "publicKeyShareMaterialRoot": material_roots[trustee_roster_position],
                "sameSecretBridgeStatementRoot": bridge_statement["sameSecretBridgeStatementRoot"],
                "sameSecretBridgeProofRecordRoot": bridge_proof["sameSecretBridgeProofRecordRoot"],
                "statementHash": proof_record["statementHash"],
                "proofBytesHash": proof_record["proofBytesHash"],
                "proofMaterialRoot": proof_record["proofMaterialRoot"],
            })
        })
        .collect::<Vec<_>>();
    package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PublicKeyShareSuccinctProofSet",
            "proofRecords": logical_proof_records,
        }))
        .expect("public-key succinct proof set root")
    );
}

pub(super) fn rebind_collective_public_key_root(package: &mut serde_json::Value) {
    let root_input = serde_json::json!({
        "objectType": "CollectivePublicKey",
        "setupContextHash": package_setup_context_hash(package),
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareMaterialSetRoot": package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "aggregateCoefficientVectorsByLimb": package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"],
    });
    package["collectivePublicKey"]["collectivePublicKeyRoot"] = serde_json::json!(
        derive_canonical_object_hash(&root_input).expect("collective public-key root")
    );
}

pub(super) fn rebind_collective_public_key_share_roots(package: &mut serde_json::Value) {
    let setup_context_hash = package_setup_context_hash(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"].clone();
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array_mut()
        .expect("public-key share records");
    for share_record in share_records {
        share_record
            .as_object_mut()
            .expect("public-key share record")
            .remove("publicKeyShareRoot");
        let root_input = serde_json::json!({
            "objectType": "PublicKeyShare",
            "setupContextHash": setup_context_hash,
            "trusteeIdentity": share_record["trusteeIdentity"],
            "trusteeRosterPosition": share_record["trusteeRosterPosition"],
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "shareCoefficientVectorHash512ByLimb":
                share_record["shareCoefficientVectorHash512ByLimb"],
        });
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_canonical_object_hash(&root_input).expect("public-key share root")
        );
    }
    let public_key_share_set_root_input = serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "shareRecords": package["publicKeyShares"]["shareRecords"],
    });
    package["publicKeyShares"]["publicKeyShareSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&public_key_share_set_root_input)
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
