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
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] =
        same_secret_bridge_proof_material_set_object(&package);

    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let statement = &package["vssShareLinkageStatement"];
    let mut threshold_binding = serde_json::json!({
        "objectType": "ThresholdShareCommitmentBinding",
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

    // The small canonical BDLOP commitment-root set remains public. Bridge
    // construction above consumes the full opening material and carries only
    // the constant commitment bodies its proof needs; the large material store
    // is replaced with its binary-chunked transport reference below.

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

    replace_vss_coefficient_commitment_material_with_transport_reference(&mut package);

    rebind_collective_setup_package_hash(&mut package);
    package
}

fn replace_vss_coefficient_commitment_material_with_transport_reference(
    package: &mut serde_json::Value,
) {
    let material = package["vssCoefficientCommitmentMaterial"].clone();
    let transported_object = package["setupTransportCertificate"]["transportedObjects"]
        .as_array()
        .expect("setup transport certificate objects")
        .iter()
        .find(|transported_object| {
            transported_object["objectName"] == "vssCoefficientCommitmentMaterial"
        })
        .cloned()
        .expect("transported VSS coefficient commitment material");
    assert_eq!(
        transported_object["objectRoot"], material["vssCoefficientCommitmentMaterialRoot"],
        "transport certificate must bind the VSS coefficient commitment material root"
    );

    package["vssCoefficientCommitmentMaterial"] = serde_json::json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "ceremonyId": material["ceremonyId"],
        "manifestHash": material["manifestHash"],
        "rosterHash": material["rosterHash"],
        "setupParametersHash": material["setupParametersHash"],
        "setupEpoch": material["setupEpoch"],
        "publicMatrixSeedHash": material["publicMatrixSeedHash"],
        "vssCoefficientCommitmentRoot": material["vssCoefficientCommitmentRoot"],
        "materialEncoding": VSS_COEFFICIENT_COMMITMENT_MATERIAL_TRANSPORT_ENCODING,
        "participantCount": material["participantCount"],
        "thresholdDegree": material["thresholdDegree"],
        "rnsLimbCount": material["rnsLimbCount"],
        "ringDegree": material["ringDegree"],
        "materialRecordCount": material["materialRecordCount"],
        "vssCoefficientCommitmentMaterialRoot": material["vssCoefficientCommitmentMaterialRoot"],
        "chunkCount": transported_object["chunkCount"],
        "totalByteLength": transported_object["byteLength"],
        "fullObjectHash": transported_object["fullObjectHash"],
        "chunkRoot": transported_object["chunkRoot"],
        "chunkHashes": transported_object["chunkHashes"],
    });
}

// The reference finalized package: the reduced-ring three-trustee base package
// run through the finalize transform. Accepted-setup verification is exercised
// against it.
pub(in super::super::super) fn minimal_finalized_collective_setup_package() -> serde_json::Value {
    finalize_collective_setup_package(minimal_collective_setup_package_for_participant_count(3))
}

// The finalized setup package flows through every accepted-setup phase: the
// canonical BDLOP commitment roots and bridge-carried constant bodies remain
// alongside the committed-material sets, while the large opening-material store
// is represented only by its binary-chunked transport reference. Every downstream phase
// (private VSS envelopes, share acceptances, public key shares and proofs,
// evaluator schedule, transport certificate, final objects) binds the relevant
// roots.
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
