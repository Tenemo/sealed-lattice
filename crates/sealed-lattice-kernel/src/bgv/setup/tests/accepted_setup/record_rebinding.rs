use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn rebind_collective_setup_package_hash(package: &mut serde_json::Value) {
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("setupPackageHash");
    // Compute the canonical hash input in place instead of cloning the whole
    // package. The embedded proof and key-switch material can be multiple
    // gigabytes, so the previous clone dominated each heavy test's peak memory.
    // Detaching the large private VSS envelopes (which the hash input excludes),
    // hashing by reference, and restoring them yields the identical hash without
    // the copy. Key order is irrelevant because the protocol hash canonicalizes.
    let detached_envelopes = detach_private_vss_encrypted_envelopes(package);
    let setup_package_hash = derive_canonical_object_hash(package).expect("setup package hash");
    restore_private_vss_encrypted_envelopes(package, detached_envelopes);
    package["setupPackageHash"] = serde_json::json!(setup_package_hash);
}

/// Flip the leading hex digit of a bound hash so the result stays valid
/// lowercase hex but no longer equals the value the verifier recomputes.
pub(super) fn drift_hash(hash: &str) -> String {
    let mut characters: Vec<char> = hash.chars().collect();
    if let Some(first) = characters.first_mut() {
        *first = if *first == '0' { '1' } else { '0' };
    }
    characters.into_iter().collect()
}

/// Replace every string field equal to `target` with `replacement`, returning
/// the number of substitutions. Drifting a bound root at every occurrence stops
/// the verifier from falling back to an undrifted copy of the same value.
pub(super) fn drift_all_occurrences(
    value: &mut serde_json::Value,
    target: &str,
    replacement: &str,
) -> usize {
    match value {
        serde_json::Value::String(text) => {
            if text == target {
                *text = replacement.to_string();
                1
            } else {
                0
            }
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .map(|item| drift_all_occurrences(item, target, replacement))
            .sum(),
        serde_json::Value::Object(map) => map
            .values_mut()
            .map(|child| drift_all_occurrences(child, target, replacement))
            .sum(),
        _ => 0,
    }
}

fn detach_private_vss_encrypted_envelopes(
    package: &mut serde_json::Value,
) -> Vec<(usize, serde_json::Value)> {
    let mut detached_envelopes = Vec::new();
    if let Some(envelope_references) = package
        .get_mut("privateVssEnvelopeCommitments")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|private_vss_envelope_commitments| {
            private_vss_envelope_commitments.get_mut("envelopeReferences")
        })
        .and_then(serde_json::Value::as_array_mut)
    {
        for (reference_index, envelope_reference) in envelope_references.iter_mut().enumerate() {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut()
                && let Some(encrypted_envelope) =
                    envelope_reference_object.remove("encryptedEnvelope")
            {
                detached_envelopes.push((reference_index, encrypted_envelope));
            }
        }
    }
    detached_envelopes
}

fn restore_private_vss_encrypted_envelopes(
    package: &mut serde_json::Value,
    detached_envelopes: Vec<(usize, serde_json::Value)>,
) {
    if detached_envelopes.is_empty() {
        return;
    }
    if let Some(envelope_references) = package
        .get_mut("privateVssEnvelopeCommitments")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|private_vss_envelope_commitments| {
            private_vss_envelope_commitments.get_mut("envelopeReferences")
        })
        .and_then(serde_json::Value::as_array_mut)
    {
        for (reference_index, encrypted_envelope) in detached_envelopes {
            if let Some(envelope_reference_object) = envelope_references
                .get_mut(reference_index)
                .and_then(serde_json::Value::as_object_mut)
            {
                envelope_reference_object
                    .insert("encryptedEnvelope".to_string(), encrypted_envelope);
            }
        }
    }
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

pub(super) fn rebind_collective_vss_commitment_roots(package: &mut serde_json::Value) {
    let source_trustee_records = package["vssCoefficientCommitments"]["sourceTrusteeRecords"]
        .as_array_mut()
        .expect("source trustee records");
    for source_trustee_record in source_trustee_records {
        source_trustee_record
            .as_object_mut()
            .expect("source trustee record")
            .remove("sourceTrusteeCommitmentRoot");
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_canonical_object_hash(source_trustee_record)
                .expect("source trustee commitment root")
        );
    }
    package["vssCoefficientCommitments"]
        .as_object_mut()
        .expect("VSS commitment set")
        .remove("vssCoefficientCommitmentRoot");
    package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["vssCoefficientCommitments"])
            .expect("VSS commitment set root")
    );
}

pub(super) fn rebind_collective_vss_coefficient_commitment_material_root(
    package: &mut serde_json::Value,
) {
    package["vssCoefficientCommitmentMaterial"]
        .as_object_mut()
        .expect("VSS coefficient commitment material set")
        .remove("vssCoefficientCommitmentMaterialRoot");
    package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["vssCoefficientCommitmentMaterial"])
            .expect("VSS coefficient commitment material root")
    );
}

pub(super) fn rebind_collective_threshold_share_commitment_root(package: &mut serde_json::Value) {
    package["thresholdShareCommitments"]
        .as_object_mut()
        .expect("threshold-share commitment set")
        .remove("thresholdShareCommitmentRoot");
    package["thresholdShareCommitments"]["thresholdShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["thresholdShareCommitments"])
            .expect("threshold-share commitment root")
    );
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
        serde_json::json!(private_vss_envelope_commitment_root.clone());
    package["privateVssEnvelopeCommitmentRoot"] =
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
    encrypted_envelope
        .as_object_mut()
        .expect("encrypted envelope")
        .remove("encryptedEnvelopeHash");
    let encrypted_envelope_hash =
        derive_canonical_object_hash(encrypted_envelope).expect("encrypted envelope hash");
    encrypted_envelope["encryptedEnvelopeHash"] =
        serde_json::json!(encrypted_envelope_hash.clone());
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

pub(super) fn rebind_collective_vss_complaint_root(package: &mut serde_json::Value) {
    package["vssComplaints"]
        .as_object_mut()
        .expect("VSS complaint set")
        .remove("vssComplaintRoot");
    package["vssComplaints"]["vssComplaintRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["vssComplaints"]).expect("VSS complaint set root")
    );
}

pub(super) fn rebind_collective_same_secret_statement_roots(package: &mut serde_json::Value) {
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array_mut()
        .expect("same-secret statement records");
    for statement_record in statement_records {
        statement_record
            .as_object_mut()
            .expect("same-secret statement record")
            .remove("sameSecretStatementRoot");
        statement_record["sameSecretStatementRoot"] = serde_json::json!(
            derive_canonical_object_hash(statement_record).expect("same-secret statement root")
        );
    }
    rebind_collective_same_secret_consistency_root(package);
}

pub(super) fn rebind_collective_same_secret_consistency_root(package: &mut serde_json::Value) {
    package["sameSecretConsistency"]
        .as_object_mut()
        .expect("same-secret statement set")
        .remove("sameSecretConsistencyRoot");
    package["sameSecretConsistency"]["sameSecretConsistencyRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["sameSecretConsistency"])
            .expect("same-secret consistency root")
    );
}

pub(super) fn rebind_same_secret_proof_record_root(
    package: &mut serde_json::Value,
    proof_record_index: usize,
) {
    let proof_record = &mut package["sameSecretProofs"]["proofRecords"]
        .as_array_mut()
        .expect("same-secret proof records")[proof_record_index];
    proof_record
        .as_object_mut()
        .expect("same-secret proof record")
        .remove("sameSecretProofRoot");
    proof_record["sameSecretProofRoot"] = serde_json::json!(
        derive_canonical_object_hash(proof_record).expect("same-secret proof root")
    );
}

pub(super) fn rebind_collective_same_secret_proof_roots(package: &mut serde_json::Value) {
    let proof_roots = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records")
        .iter()
        .map(|proof_record| {
            serde_json::json!({
                "trusteeIdentity": proof_record["trusteeIdentity"],
                "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
            })
        })
        .collect::<Vec<_>>();
    package["sameSecretProofs"]["sameSecretProofRoots"] = serde_json::json!(proof_roots);
}

pub(super) fn rebind_collective_same_secret_proof_set_root(package: &mut serde_json::Value) {
    package["sameSecretProofs"]
        .as_object_mut()
        .expect("same-secret proof set")
        .remove("sameSecretProofSetRoot");
    package["sameSecretProofs"]["sameSecretProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["sameSecretProofs"])
            .expect("same-secret proof set root")
    );
    rebind_active_static_setup_theorem_certificate(package);
}

pub(super) fn rebind_collective_public_key_succinct_proof_roots(package: &mut serde_json::Value) {
    let proof_records = package["publicKeyShareSuccinctProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key succinct proof records");
    let mut proof_roots = Vec::new();
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key succinct proof record")
            .remove("publicKeyShareSuccinctProofRoot");
        proof_record["publicKeyShareSuccinctProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record).expect("public-key succinct proof root")
        );
        proof_roots.push(serde_json::json!({
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "publicKeyShareSuccinctProofRoot": proof_record["publicKeyShareSuccinctProofRoot"],
        }));
    }
    package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofRoots"] =
        serde_json::json!(proof_roots);
    package["publicKeyShareSuccinctProofs"]
        .as_object_mut()
        .expect("public-key succinct proof set")
        .remove("publicKeyShareSuccinctProofSetRoot");
    package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["publicKeyShareSuccinctProofs"])
            .expect("public-key succinct proof set root")
    );
    rebind_active_static_setup_theorem_certificate(package);
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
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_active_static_setup_theorem_certificate(package);
}

pub(super) fn rebind_collective_public_key_share_roots(package: &mut serde_json::Value) {
    let share_records = package["publicKeyShares"]["shareRecords"]
        .as_array_mut()
        .expect("public-key share records");
    let mut public_key_share_roots = Vec::new();
    for share_record in share_records {
        share_record
            .as_object_mut()
            .expect("public-key share record")
            .remove("publicKeyShareRoot");
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_canonical_object_hash(share_record).expect("public-key share root")
        );
        public_key_share_roots.push(serde_json::json!({
            "trusteeIdentity": share_record["trusteeIdentity"],
            "trusteeRosterPosition": share_record["trusteeRosterPosition"],
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
        }));
    }
    package["publicKeyShares"]["publicKeyShareRoots"] = serde_json::json!(public_key_share_roots);
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
    let mut public_key_share_proof_roots = Vec::new();
    for proof_record in proof_records {
        proof_record
            .as_object_mut()
            .expect("public-key share proof record")
            .remove("publicKeyShareProofRoot");
        proof_record["publicKeyShareProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record).expect("public-key share proof root")
        );
        public_key_share_proof_roots.push(serde_json::json!({
            "trusteeIdentity": proof_record["trusteeIdentity"],
            "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
            "publicKeyShareProofRoot": proof_record["publicKeyShareProofRoot"],
        }));
    }
    package["publicKeyShareProofs"]["publicKeyShareProofRoots"] =
        serde_json::json!(public_key_share_proof_roots);
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

pub(super) fn rebind_trustee_evaluation_key_proof_set_root(package: &mut serde_json::Value) {
    package["trusteeEvaluationKeyProofs"]
        .as_object_mut()
        .expect("trustee evaluation-key proof set")
        .remove("trusteeEvaluationKeyProofSetRoot");
    package["trusteeEvaluationKeyProofs"]["trusteeEvaluationKeyProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&package["trusteeEvaluationKeyProofs"])
            .expect("trustee evaluation-key proof set root")
    );
}

pub(super) fn rebind_trustee_evaluation_key_proof_record_root(
    package: &mut serde_json::Value,
    proof_record_index: usize,
) {
    let proof_record = &mut package["trusteeEvaluationKeyProofs"]["proofRecords"]
        .as_array_mut()
        .expect("trustee evaluation-key proof records")[proof_record_index];
    proof_record
        .as_object_mut()
        .expect("trustee evaluation-key proof record")
        .remove("trusteeEvaluationKeyProofRoot");
    proof_record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
        derive_canonical_object_hash(proof_record).expect("trustee evaluation-key proof root")
    );
}

pub(super) fn rebind_collective_he_security_certificate_hash(package: &mut serde_json::Value) {
    package["heSecurityCertificate"]
        .as_object_mut()
        .expect("HE security certificate")
        .remove("heSecurityCertificateHash");
    let he_security_certificate_hash =
        derive_canonical_object_hash(&package["heSecurityCertificate"])
            .expect("HE security certificate hash");
    package["heSecurityCertificate"]["heSecurityCertificateHash"] =
        serde_json::json!(he_security_certificate_hash.clone());
    package["heSecurityCertificateHash"] = serde_json::json!(he_security_certificate_hash);
}

pub(super) fn rebind_setup_proof_accounting_certificate_hash(package: &mut serde_json::Value) {
    package["setupProofAccountingCertificate"]
        .as_object_mut()
        .expect("setup proof accounting certificate")
        .remove("setupProofAccountingCertificateHash");
    let setup_proof_accounting_certificate_hash =
        derive_canonical_object_hash(&package["setupProofAccountingCertificate"])
            .expect("setup proof accounting certificate hash");
    package["setupProofAccountingCertificate"]["setupProofAccountingCertificateHash"] =
        serde_json::json!(setup_proof_accounting_certificate_hash.clone());
    package["setupProofAccountingCertificateHash"] =
        serde_json::json!(setup_proof_accounting_certificate_hash);
}

pub(super) fn rebind_setup_key_correctness_certificate(package: &mut serde_json::Value) {
    let mut certificate = setup_key_correctness_certificate_value(package)
        .expect("setup key correctness certificate");
    let certificate_hash = setup_key_correctness_certificate_hash(package)
        .expect("setup key correctness certificate hash");
    certificate["setupKeyCorrectnessCertificateHash"] = serde_json::json!(certificate_hash.clone());
    package["setupKeyCorrectnessCertificate"] = certificate;
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(certificate_hash);
    rebind_active_static_setup_theorem_certificate(package);
}

pub(super) fn rebind_active_static_setup_theorem_certificate(package: &mut serde_json::Value) {
    let mut certificate = active_static_setup_theorem_certificate_value(package)
        .expect("active-static setup theorem certificate");
    let certificate_hash = active_static_setup_theorem_certificate_hash(package)
        .expect("active-static setup theorem certificate hash");
    certificate["activeStaticSetupTheoremCertificateHash"] =
        serde_json::json!(certificate_hash.clone());
    package["activeStaticSetupTheoremCertificate"] = certificate;
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(certificate_hash);
}
