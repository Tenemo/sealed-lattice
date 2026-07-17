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
    let coefficient_view = package["vssPublicCoefficientCommitmentSet"].clone();
    let rebuilt_envelopes =
        super::super::package_fixtures::private_vss_envelope_commitments_object(participant_count);
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
    package["privateVssEnvelopeCommitments"] = rebuilt_envelopes;
    package["vssShareAcceptances"] = rebuilt_acceptances;

    package
        .as_object_mut()
        .expect("collective setup package")
        .remove("vssCoefficientCommitmentMaterial");

    package
}

// Finalization retains the canonical BDLOP roots and bridge-carried commitment
// bodies while omitting prover-only opening material. This is structural
// evidence only: until the common-proof verifier grants authority for the
// referenced bytes, accepted setup must refuse before downstream runtime
// objects can matter.
#[test]
fn finalized_structural_material_reaches_but_cannot_bypass_common_proof_authority() {
    let fixture = structural_vss_collective_setup_fixture();
    let package = &fixture.package;
    assert_eq!(
        vss_commitment_ring_degree_from_fixture_package(package),
        128,
        "finalized fixtures must retain the accepted public commitment ring degree",
    );
    let result = fixture
        .verify()
        .expect("finalized collective setup package verification result");
    let result_diagnostics =
        || serde_json::to_string_pretty(&result).expect("finalized setup verification result JSON");
    assert_eq!(
        result["isValid"],
        false,
        "structural proof references must not grant acceptance: {}",
        result_diagnostics(),
    );
    assert_eq!(
        result["refusalReason"],
        "malformedEncoding",
        "the missing common-proof authority must refuse at the proof boundary: {}",
        result_diagnostics(),
    );
}
