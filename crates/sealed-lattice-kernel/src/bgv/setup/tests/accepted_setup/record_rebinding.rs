use crate::bgv::setup::accepted_setup::derive_collective_setup_package_hash;
use crate::hashing::derive_canonical_object_hash;

pub(super) fn rebind_collective_setup_package_hash(package: &mut serde_json::Value) {
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("setupPackageHash");
    let setup_package_hash =
        derive_collective_setup_package_hash(package).expect("setup package hash");
    package["setupPackageHash"] = serde_json::json!(setup_package_hash);
}

pub(super) fn rebind_collective_phase_roots(package: &mut serde_json::Value) {
    let phases = package["phaseTranscript"]
        .as_array_mut()
        .expect("phase transcript");
    let mut previous_phase_root = serde_json::Value::Null;
    for phase in phases {
        phase["previousPhaseRoot"] = previous_phase_root.clone();
        phase
            .as_object_mut()
            .expect("phase record")
            .remove("phaseRoot");
        let phase_root = derive_canonical_object_hash(phase).expect("phase root");
        phase["phaseRoot"] = serde_json::json!(phase_root.clone());
        previous_phase_root = serde_json::json!(phase_root);
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

pub(super) fn rebind_collective_vss_acceptance_root(package: &mut serde_json::Value) {
    package["vssShareAcceptances"]
        .as_object_mut()
        .expect("VSS share acceptance set")
        .remove("vssShareAcceptanceRoot");
    package["vssShareAcceptances"]["vssShareAcceptanceRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["vssShareAcceptances"])
            .expect("VSS share acceptance set root")
    );
}

pub(super) fn rebind_collective_public_key_succinct_proof_roots(package: &mut serde_json::Value) {
    let proof_records = package["publicKeyShareSuccinctProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key succinct proof records");
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key succinct proof record")
            .remove("publicKeyShareSuccinctProofRoot");
        proof_record["publicKeyShareSuccinctProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record).expect("public-key succinct proof root")
        );
    }
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

pub(super) fn rebind_collective_public_key_share_proof_roots(package: &mut serde_json::Value) {
    let proof_records = package["publicKeyShareProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key share proof records");
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key share proof record")
            .remove("publicKeyShareProofRoot");
        proof_record["publicKeyShareProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record).expect("public-key share proof root")
        );
    }
    package["publicKeyShareProofs"]
        .as_object_mut()
        .expect("public-key share proof set")
        .remove("publicKeyShareProofSetRoot");
    package["publicKeyShareProofs"]["publicKeyShareProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["publicKeyShareProofs"])
            .expect("public-key share proof set root")
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
