use super::commitment_sets::*;
use super::same_secret_bridge::*;
use super::share_linkage::*;
use super::*;

pub(in super::super::super) fn finalize_collective_setup_package(
    mut package: serde_json::Value,
) -> serde_json::Value {
    let participant_count = participant_count_from_package(&package);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    package["vssShareLinkageProofMaterialSet"] =
        vss_share_linkage_proof_material_set_object(&package);
    // Rebuild the same-secret consistency statements to bind the constant
    // coefficient commitments. The statement builder reads the full-VSS field
    // names (sourceTrusteeCommitmentRoot, per-commitment commitmentRoot), so pass
    // a coefficient view that aliases those to the roots the accepted-setup
    // verifier recomputes. The same-secret proofs and bridge below then reference
    // these statements.
    let coefficient_set = package["vssPublicCoefficientCommitmentSet"].clone();
    let consistency_source_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("source trustee records")
        .iter()
        .map(|source_record| {
            let commitments = source_record["coefficientCommitments"]
                .as_array()
                .expect("coefficient commitments")
                .iter()
                .map(|commitment| {
                    let mut commitment = commitment.clone();
                    commitment["commitmentRoot"] = commitment["coefficientCommitmentRoot"].clone();
                    commitment
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "sourceTrusteeRosterPosition": source_record["sourceTrusteeRosterPosition"],
                "sourceTrusteeIdentity": source_record["sourceTrusteeIdentity"],
                "sourceTrusteeCommitmentRoot": source_record["sourceCoefficientCommitmentRoot"],
                "coefficientCommitments": commitments,
            })
        })
        .collect::<Vec<_>>();
    let consistency_view = serde_json::json!({
        "vssCoefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "sourceTrusteeRecords": consistency_source_records,
    });
    package["sameSecretConsistency"] =
        super::super::package_fixtures::same_secret_consistency_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &consistency_view,
            participant_count,
        );
    // The public key shares and their proofs bind the same-secret statement roots,
    // which the rebuild changed, so rebuild them against the new statements.
    let rebuilt_public_key_shares = super::super::package_fixtures::public_key_shares_object(
        package["setupContext"]["ceremonyId"]
            .as_str()
            .expect("ceremony id"),
        package["setupContext"]["manifestHash"]
            .as_str()
            .expect("manifest hash"),
        package["setupContext"]["rosterHash"]
            .as_str()
            .expect("roster hash"),
        package["setupContext"]["setupParametersHash"]
            .as_str()
            .expect("setup parameters hash"),
        package["setupContext"]["setupEpoch"]
            .as_str()
            .expect("setup epoch"),
        &package["commonRandomness"],
        &package["sameSecretConsistency"],
        participant_count,
    );
    package["publicKeyShares"] = rebuilt_public_key_shares;
    let rebuilt_public_key_share_proofs =
        super::super::package_fixtures::public_key_share_proofs_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &package["commonRandomness"],
            &package["sameSecretConsistency"],
            &package["publicKeyShares"],
            participant_count,
        );
    package["publicKeyShareProofs"] = rebuilt_public_key_share_proofs;
    // The evaluator key schedule also binds the same-secret statement root and the
    // rebuilt public key share material.
    let setup_parameters =
        crate::bgv::setup::accepted_setup::describe_collective_bgv_setup_parameters()
            .expect("setup parameters");
    let rebuilt_evaluator_key_schedule =
        super::super::package_fixtures::evaluator_key_schedule_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &setup_parameters,
            &package["commonRandomness"],
            &package["sameSecretConsistency"],
            &package["publicKeyShares"],
            &package["publicKeyShareProofs"],
            participant_count,
        );
    package["evaluatorKeySchedule"] = rebuilt_evaluator_key_schedule;
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] =
        same_secret_bridge_proof_material_set_object(&package, None);

    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let statement = &package["vssShareLinkageStatement"];
    let mut threshold_binding = serde_json::json!({
        "objectType": "ThresholdShareCommitmentBinding",
        "objectVersion": 1,
        "publicMatrixSeedHash": coefficient_set["publicMatrixSeedHash"],
        "participantCount": coefficient_set["participantCount"],
        "thresholdDegree": coefficient_set["thresholdDegree"],
        "targetRnsLimbCount": statement["targetRnsLimbCount"],
        "ringDegree": coefficient_set["ringDegree"],
        "aggregateThresholdCommitmentRoot":
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "shareLinkageStatementRoot": statement["statementRoot"],
        "shareLinkageProofMaterialSetRoot":
            package["vssShareLinkageProofMaterialSet"]["proofMaterialSetRoot"],
    });
    threshold_binding["thresholdShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&threshold_binding)
            .expect("threshold-share commitment binding root")
    );
    package["thresholdShareCommitments"] = threshold_binding;

    // The public VSS coefficient material is replaced by the embedded commitment
    // sets.
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("vssCoefficientCommitments");
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("vssCoefficientCommitmentMaterial");

    // The private VSS envelopes bind (as AAD) to the accepted coefficient
    // commitment root and each source trustee's per-trustee coefficient root,
    // which are the commitment set root and each source record's
    // sourceCoefficientCommitmentRoot, so rebuild the envelopes against that
    // coefficient view.
    let ceremony_id = package["setupContext"]["ceremonyId"]
        .as_str()
        .expect("ceremony id")
        .to_string();
    let manifest_hash = package["setupContext"]["manifestHash"]
        .as_str()
        .expect("manifest hash")
        .to_string();
    let roster_hash = package["setupContext"]["rosterHash"]
        .as_str()
        .expect("roster hash")
        .to_string();
    let setup_parameters_hash = package["setupContext"]["setupParametersHash"]
        .as_str()
        .expect("setup parameters hash")
        .to_string();
    let setup_epoch = package["setupContext"]["setupEpoch"]
        .as_str()
        .expect("setup epoch")
        .to_string();
    let common_randomness = package["commonRandomness"].clone();
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let source_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("source trustee records")
        .iter()
        .map(|source_record| {
            serde_json::json!({
                "sourceTrusteeRosterPosition": source_record["sourceTrusteeRosterPosition"],
                "sourceTrusteeCommitmentRoot": source_record["sourceCoefficientCommitmentRoot"],
            })
        })
        .collect::<Vec<_>>();
    let coefficient_view = serde_json::json!({
        "vssCoefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "sourceTrusteeRecords": source_records,
    });
    let rebuilt_envelopes = super::super::package_fixtures::private_vss_envelope_commitments_object(
        &ceremony_id,
        &manifest_hash,
        &roster_hash,
        &setup_parameters_hash,
        &setup_epoch,
        &common_randomness,
        &coefficient_view,
        participant_count,
    );
    // The VSS share acceptances reference the rebuilt envelopes and the same
    // coefficient view, so rebuild them to match.
    let rebuilt_acceptances = super::super::package_fixtures::vss_share_acceptances_object(
        &ceremony_id,
        &manifest_hash,
        &roster_hash,
        &setup_parameters_hash,
        &setup_epoch,
        &rebuilt_envelopes,
        &coefficient_view,
        participant_count,
    );
    package["privateVssEnvelopeCommitmentRoot"] =
        rebuilt_envelopes["privateVssEnvelopeCommitmentRoot"].clone();
    package["privateVssEnvelopeCommitments"] = rebuilt_envelopes;
    package["vssShareAcceptances"] = rebuilt_acceptances;

    // The commitment sets are embedded and proof-verified in-package, so there is
    // no large public VSS material to stream: the transport certificate carries no
    // transported objects.
    let mut transport_certificate = package["setupTransportCertificate"].clone();
    {
        let certificate_object = transport_certificate
            .as_object_mut()
            .expect("transport certificate object");
        certificate_object.insert("transportedObjects".to_string(), serde_json::json!([]));
        certificate_object.insert("totalByteLength".to_string(), serde_json::json!(0));
        certificate_object.insert("chunkCount".to_string(), serde_json::json!(0));
        certificate_object.remove("setupTransportCertificateHash");
    }
    let transport_certificate_hash =
        derive_canonical_object_hash(&transport_certificate).expect("transport certificate hash");
    transport_certificate["setupTransportCertificateHash"] =
        serde_json::json!(transport_certificate_hash);
    package["setupTransportCertificateHash"] = serde_json::json!(transport_certificate_hash);
    package["setupTransportCertificate"] = transport_certificate;

    rebind_collective_setup_package_hash(&mut package);
    package
}

// The reference finalized package: the reduced-ring three-trustee base package
// run through the finalize transform. Accepted-setup verification is exercised
// against it.
pub(in super::super::super) fn minimal_finalized_collective_setup_package() -> serde_json::Value {
    finalize_collective_setup_package(minimal_collective_setup_package_for_participant_count(3))
}

// The finalized setup package flows through every accepted-setup phase: the
// public coefficient commitment material is replaced by the embedded commitment
// sets and same-secret bridge, and every downstream phase (private VSS envelopes,
// share acceptances, same-secret consistency, public key shares and proofs,
// evaluator schedule, transport certificate, final objects) binds those roots.
// Like the full-VSS minimal package this reduced-ring package is pre-terminal (no
// collective public key runtime material), so it is not fully valid; the check is
// that it passes every phase and object requirement, leaving only the terminal
// runtime objects missing.
#[test]
fn minimal_finalized_collective_setup_package_passes_accepted_setup() {
    let package = minimal_finalized_collective_setup_package();
    let result = crate::bgv::setup::accepted_setup::verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({}),
    )
    .expect("finalized collective setup package verification result");
    let context = || serde_json::to_string_pretty(&result).unwrap();
    // No phase refuses the material.
    assert!(
        result["refusedObjects"]
            .as_array()
            .is_none_or(|refused| refused.is_empty()),
        "finalized package must not be refused at any phase: {}",
        context()
    );
    // Every phase passed, so the flow reached the final phase.
    assert_eq!(
        result["currentPhase"],
        "setupPackageVerification",
        "{}",
        context()
    );
    // The embedded commitment sets satisfy the coefficient-commitment requirement;
    // only the terminal runtime objects a pre-terminal setup package lacks may
    // remain.
    let missing_objects = result["missingObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        missing_objects.iter().all(|missing_object| matches!(
            missing_object.as_str(),
            Some("publicKeyShareMaterial")
                | Some("publicKeyShareSuccinctProofs")
                | Some("collectivePublicKey")
                | Some("collectivePublicKeyRoot")
        )),
        "only terminal runtime objects may remain missing for the pre-terminal finalized package: {}",
        context()
    );
}
