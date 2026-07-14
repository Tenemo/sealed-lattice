use super::commitment_sets::*;
use super::same_secret_bridge::*;
use super::share_linkage::*;
use super::*;

#[derive(Clone)]
pub(in super::super::super) struct FinalizedCollectiveSetupPackageFixture {
    pub(in super::super::super) package: serde_json::Value,
    pub(in super::super::super) proof_binding_leases:
        Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

pub(in super::super::super) fn finalize_collective_setup_package(
    mut package: serde_json::Value,
) -> FinalizedCollectiveSetupPackageFixture {
    let participant_count = participant_count_from_package(&package);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    let aggregate_threshold_commitment_set =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] = aggregate_threshold_commitment_set.value;
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    let share_linkage_proof_material_set = vss_share_linkage_proof_material_set_object(&package);
    package["vssShareLinkageProofMaterialSet"] = share_linkage_proof_material_set.value;
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    let same_secret_bridge_proof_material_set =
        same_secret_bridge_proof_material_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] = same_secret_bridge_proof_material_set.value;

    // The small canonical BDLOP commitment-root set remains public. Bridge
    // construction above consumes the full opening material and carries only
    // the constant commitment bodies its proof needs. The final package omits
    // the prover-only full opening material below.

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
        .enumerate()
        .map(|(source_trustee_roster_position, source_record)| {
            serde_json::json!({
                "sourceTrusteeRosterPosition": source_trustee_roster_position,
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
    package["privateVssEnvelopeCommitments"] = rebuilt_envelopes;
    package["vssShareAcceptances"] = rebuilt_acceptances;

    package
        .as_object_mut()
        .expect("collective setup package")
        .remove("vssCoefficientCommitmentMaterial");

    rebind_collective_setup_package_hash(&mut package);
    let mut proof_binding_leases = aggregate_threshold_commitment_set.proof_binding_leases;
    proof_binding_leases.extend(share_linkage_proof_material_set.proof_binding_leases);
    proof_binding_leases.extend(same_secret_bridge_proof_material_set.proof_binding_leases);
    FinalizedCollectiveSetupPackageFixture {
        package,
        proof_binding_leases,
    }
}

// The reference finalized fixture carries the descriptor-backed package and
// the matching authenticated-material request. The cached fixture getter
// rehydrates proof material before each verification because the verifier
// consumes it at the end of the call.
fn minimal_finalized_collective_setup_fixture() -> CollectiveSetupVerificationFixture {
    descriptor_backed_vss_collective_setup_fixture()
}

// The finalized setup package flows through the accepted-setup verification
// path: the canonical BDLOP commitment roots and bridge-carried constant bodies remain
// alongside the committed-material sets, while the prover-only full opening
// material is omitted. Every downstream verifier
// (private VSS envelopes, share acceptances, public key shares and proofs,
// evaluator schedule and final objects) binds the relevant
// roots.
// Like the full-VSS minimal package this reduced-ring package is pre-terminal (no
// collective public key runtime material), so it is not fully valid; the check is
// that it passes every object requirement, leaving only the terminal
// runtime objects missing.
#[test]
fn minimal_finalized_collective_setup_package_passes_accepted_setup() {
    let fixture = minimal_finalized_collective_setup_fixture();
    let package = &fixture.package;
    assert_eq!(
        vss_commitment_ring_degree_from_fixture_package(package),
        128,
        "finalized fixtures must retain the accepted public commitment ring degree",
    );
    let result = fixture
        .verify()
        .expect("finalized collective setup package verification result");
    let context = || serde_json::to_string_pretty(&result).unwrap();
    // The embedded commitment sets satisfy the coefficient-commitment requirement;
    // only the terminal runtime objects a pre-terminal setup package lacks may
    // remain.
    let refused_objects = result["refusedObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !refused_objects.is_empty()
            && refused_objects.iter().all(|refusal| {
                refusal["reasonCode"] == "setupObjectMissing"
                    && matches!(
                        refusal["objectPath"].as_str(),
                        Some("setupPackage.publicKeyShareMaterial")
                            | Some("setupPackage.publicKeyShareSuccinctProofs")
                    )
            }),
        "only terminal runtime objects may remain missing for the pre-terminal finalized package: {}",
        context()
    );
}
