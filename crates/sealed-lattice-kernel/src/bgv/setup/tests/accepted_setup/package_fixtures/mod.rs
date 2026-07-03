use super::*;

use crate::hashing::derive_canonical_object_hash;

static MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> = OnceLock::new();
static PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    serde_json::Value,
> = OnceLock::new();
static COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<serde_json::Value> =
    OnceLock::new();

struct VssMaterialPackageComponents {
    vss_coefficient_commitments: serde_json::Value,
    vss_coefficient_commitment_material: serde_json::Value,
    threshold_share_commitments: serde_json::Value,
}

struct CollectiveSetupPackageFixture {
    package: serde_json::Value,
}

fn private_vss_mailbox_public_key_hash(roster_position: u64) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "MlKemMailboxPublicKey",
        "algorithm": "ML-KEM-768",
        "keyPurpose": "private-vss-mailbox",
        "recipientRosterPosition": roster_position,
    }))
    .expect("recipient mailbox public key hash")
}

fn private_vss_mailbox_public_key_bytes_hash(roster_position: u64) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "MlKemMailboxPublicKeyBytes",
        "fixture": "recipient-mailbox-public-key-bytes",
        "recipientRosterPosition": roster_position,
    }))
    .expect("recipient mailbox public key bytes hash")
}

fn setup_trustee_signature_seed_label(trustee_identity: &str) -> String {
    format!("{trustee_identity}-setup-signing")
}

fn collective_setup_roster_hash_fixture(participant_count: u64) -> String {
    let roster_entries = (0..participant_count)
        .map(|roster_position| {
            let trustee_identity = format!("trustee-{roster_position}");
            let signing_public_key_hash = create_ml_dsa_public_key_hash_fixture(
                &setup_trustee_signature_seed_label(&trustee_identity),
            )
            .expect("setup trustee signing public-key hash");
            serde_json::json!({
                "objectType": "CollectiveBgvSetupRosterEntry",
                "objectVersion": 1,
                "rosterPosition": roster_position,
                "trusteeIdentity": trustee_identity,
                "signingPublicKeyHash": signing_public_key_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "CollectiveBgvSetupRoster",
        "rosterEntries": roster_entries,
    }))
    .expect("collective setup roster hash")
}

/// The n = 10 fixture roster size used by the minimal package.
const FIXTURE_FIRST_CLOSURE_PARTICIPANT_COUNT: u64 = 10;

pub(super) fn minimal_collective_setup_package() -> serde_json::Value {
    // The reduced development ring must stay provable by the trustee
    // evaluation-key argument: the trace splits each vector in two and the
    // smallest supported trace is sixty-four, so the development ring is one
    // hundred twenty-eight.
    MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(|| {
            super::proof_record_fixtures::compactify_collective_setup_package(
                minimal_collective_setup_package_for_participant_count(
                    FIXTURE_FIRST_CLOSURE_PARTICIPANT_COUNT,
                ),
            )
        })
        .clone()
}

/// Reduced development-ring (128) collective setup package for an arbitrary
/// supported roster size, built through the non-streamed VSS path. Drives the
/// same per-trustee material and roster-derived certificates as the n = 10
/// path. At n = 10 this is byte identical to `minimal_collective_setup_package`.
pub(super) fn minimal_collective_setup_package_for_participant_count(
    participant_count: u64,
) -> serde_json::Value {
    build_collective_setup_package_fixture(128, "development-reduced-ring", participant_count)
}

fn build_collective_setup_package_fixture(
    vss_material_ring_degree: usize,
    vss_material_ring_degree_status: &str,
    participant_count: u64,
) -> serde_json::Value {
    build_collective_setup_package_fixture_parts(
        vss_material_ring_degree,
        vss_material_ring_degree_status,
        participant_count,
    )
    .package
}

// The collective setup context shared by the package fixtures. Every fixture
// builds the same first-closure context shape, so this keeps one definition of
// it instead of repeating the json! block at each construction site.
fn collective_setup_context_fixture(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    participant_count: u64,
) -> serde_json::Value {
    // Full-roster quorums equal the participant count and the decryption
    // threshold is floor(n/3) + 1; these match the production verifier's
    // roster-derived parameters (accepted_setup.rs), so the context is accepted
    // for any supported roster size.
    serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
        "qSetupComplete": participant_count,
        "qBallotRelease": participant_count,
        "qFinal": participant_count,
        "qDec": participant_count / 3 + 1,
    })
}

fn build_collective_setup_package_fixture_parts(
    vss_material_ring_degree: usize,
    vss_material_ring_degree_status: &str,
    participant_count: u64,
) -> CollectiveSetupPackageFixture {
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "ElectionManifestHash",
        "manifest": "collective-bgv-setup-test",
    }))
    .expect("manifest hash");
    let roster_hash = collective_setup_roster_hash_fixture(participant_count);
    // The setup parameters hash is a roster family, distinct per n. It binds
    // Q_share, the carry-aware VSS relation, commitment, setup proof, transport,
    // evaluator key schedule, and BGV parameters. The verifier checks
    // setupContext.setupParametersHash against setup_parameters_hash_for_roster,
    // so the fixture binds the roster-derived hash here.
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(
                participant_count,
            ),
        )
        .expect("roster-derived setup parameters hash");
    let setup_parameters_hash = setup_parameters_hash.as_str();
    let setup_epoch = "setup-epoch-1";
    let setup_context = collective_setup_context_fixture(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        participant_count,
    );
    let mut previous_phase_root = serde_json::Value::Null;
    let phase_transcript = setup_parameters["phaseOrder"]
        .as_array()
        .expect("phase order")
        .iter()
        .map(|phase| {
            let phase_identifier = phase["phaseId"].as_str().expect("phase id");
            let phase_number = phase["phaseNumber"].as_u64().expect("phase number");
            let participant_phase_objects = (0..participant_count)
                .map(|roster_position| {
                    let trustee_identity = format!("trustee-{roster_position}");
                    let signature_seed_label =
                        setup_trustee_signature_seed_label(&trustee_identity);
                    let signing_public_key_hash =
                        create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                            .expect("signature key fixture");
                    let mut phase_payload = serde_json::json!({
                        "objectType": "SetupPhaseParticipantObject",
                        "objectVersion": 1,
                        "phaseId": phase_identifier,
                        "phaseNumber": phase_number,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupParametersHash": setup_parameters_hash,
                        "setupEpoch": setup_epoch,
                        "signerRole": "Trustee",
                        "trusteeIdentity": trustee_identity,
                        "rosterPosition": roster_position,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "signingPublicKeyHash": signing_public_key_hash,
                    });
                    if phase_identifier == "setupIntent" {
                        phase_payload["privateVssMailboxPublicKeyHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_hash(roster_position));
                        phase_payload["privateVssMailboxPublicKeyBytesHash"] = serde_json::json!(
                            private_vss_mailbox_public_key_bytes_hash(roster_position)
                        );
                    }
                    let phase_object_root = derive_canonical_object_hash(&phase_payload)
                        .expect("phase object root");
                    let phase_object_byte_length =
                        u64::try_from(canonical_json(&phase_payload).expect("phase payload").len())
                            .expect("phase payload length");
                    let phase_signature_context_hash = derive_canonical_object_hash(&serde_json::json!({
                            "objectType": "SetupPhaseSignatureContext",
                            "phaseId": phase_identifier,
                            "phaseNumber": phase_number,
                            "ceremonyId": ceremony_id,
                            "manifestHash": manifest_hash,
                            "rosterHash": roster_hash,
                            "setupParametersHash": setup_parameters_hash,
                            "setupEpoch": setup_epoch,
                            "trusteeIdentity": trustee_identity,
                            "rosterPosition": roster_position,
                            "phaseObjectRoot": phase_object_root,
                        }),
                    )
                    .expect("phase signature context hash");
                    let signature_fixture = create_protocol_signature_fixture(
                        &signature_seed_label,
                        serde_json::json!({
                            "objectType": "SetupPhaseParticipantObject",
                            "objectVersion": 1,
                            "ceremonyId": ceremony_id,
                            "manifestHash": manifest_hash,
                            "boardHeadHash": null,
                            "objectRoot": phase_object_root,
                            "chunkMerkleRoot": null,
                            "byteLength": phase_object_byte_length,
                            "signerRole": "Trustee",
                            "signerIdentity": trustee_identity,
                            "recoveryEpoch": 0,
                            "deviceEpoch": 0,
                            "contextHash": phase_signature_context_hash,
                        }),
                    )
                    .expect("phase signature fixture");
                    let signature_envelope = signature_fixture.envelope;
                    let signature_envelope_hash = signature_envelope["signatureHash"].clone();
                    let mut participant_phase_object = serde_json::json!({
                        "objectType": "SetupPhaseParticipantObject",
                        "objectVersion": 1,
                        "phaseId": phase_identifier,
                        "phaseNumber": phase_number,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupParametersHash": setup_parameters_hash,
                        "setupEpoch": setup_epoch,
                        "signerRole": "Trustee",
                        "trusteeIdentity": trustee_identity,
                        "rosterPosition": roster_position,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "signingPublicKeyHash": signing_public_key_hash,
                        "phaseObjectRoot": phase_object_root,
                        "phaseObjectByteLength": phase_object_byte_length,
                        "phaseSignatureContextHash": phase_signature_context_hash,
                        "signatureEnvelopeHash": signature_envelope_hash,
                        "signatureEnvelope": signature_envelope,
                    });
                    if phase_identifier == "setupIntent" {
                        participant_phase_object["privateVssMailboxPublicKeyHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_hash(roster_position));
                        participant_phase_object["privateVssMailboxPublicKeyBytesHash"] =
                            serde_json::json!(private_vss_mailbox_public_key_bytes_hash(
                                roster_position
                            ));
                    }

                    participant_phase_object
                })
                .collect::<Vec<_>>();
            let mut phase_record = serde_json::json!({
                "objectType": "SetupPhaseRecord",
                "phaseId": phase_identifier,
                "phaseNumber": phase_number,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupParametersHash": setup_parameters_hash,
                "setupEpoch": setup_epoch,
                "previousPhaseRoot": previous_phase_root.clone(),
                "participantPhaseObjects": participant_phase_objects,
            });
            let phase_root = derive_canonical_object_hash(&phase_record).expect("phase root");
            phase_record["phaseRoot"] = serde_json::json!(phase_root.clone());
            previous_phase_root = serde_json::json!(phase_root);

            phase_record
        })
        .collect::<Vec<_>>();
    let common_randomness = common_randomness_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        participant_count,
    );
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let vss_components = {
        let (vss_coefficient_commitments, vss_coefficient_commitment_material) =
            vss_coefficient_commitments_object(
                ceremony_id,
                &manifest_hash,
                &roster_hash,
                setup_parameters_hash,
                setup_epoch,
                public_matrix_seed_hash,
                vss_material_ring_degree,
                vss_material_ring_degree_status,
                participant_count,
            );
        let threshold_share_commitments =
            derive_threshold_share_commitments_from_request(&serde_json::json!({
                "setupContext": setup_context.clone(),
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "sourceTrusteeCoefficientCommitmentRecords": vss_coefficient_commitments["sourceTrusteeRecords"].clone(),
                "coefficientCommitments": vss_coefficient_commitment_material["coefficientCommitments"].clone(),
            }))
            .expect("threshold-share commitments")["thresholdShareCommitments"]
                .clone();
        VssMaterialPackageComponents {
            vss_coefficient_commitments,
            vss_coefficient_commitment_material,
            threshold_share_commitments,
        }
    };
    let vss_coefficient_commitments = vss_components.vss_coefficient_commitments.clone();
    let vss_coefficient_commitment_material =
        vss_components.vss_coefficient_commitment_material.clone();
    let threshold_share_commitments = vss_components.threshold_share_commitments.clone();
    let private_vss_envelope_commitments = private_vss_envelope_commitments_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &common_randomness,
        &vss_coefficient_commitments,
        participant_count,
    );
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root")
            .to_string();
    let vss_share_acceptances = vss_share_acceptances_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &private_vss_envelope_commitments,
        &vss_coefficient_commitments,
        participant_count,
    );
    let same_secret_consistency = same_secret_consistency_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &vss_coefficient_commitments,
        participant_count,
    );
    let public_key_shares = public_key_shares_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &common_randomness,
        &same_secret_consistency,
        participant_count,
    );
    let public_key_share_proofs = public_key_share_proofs_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &common_randomness,
        &same_secret_consistency,
        &public_key_shares,
        participant_count,
    );
    let evaluator_key_schedule = evaluator_key_schedule_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &setup_parameters,
        &common_randomness,
        &same_secret_consistency,
        &public_key_shares,
        &public_key_share_proofs,
        participant_count,
    );
    let setup_transport_certificate = setup_transport_certificate_fixture(
        &setup_parameters,
        &vss_coefficient_commitment_material,
    );
    let setup_transport_certificate_hash = setup_transport_certificate
        .get("setupTransportCertificateHash")
        .and_then(serde_json::Value::as_str)
        .expect("setup transport certificate hash")
        .to_string();
    let mut package = serde_json::json!({
        "objectType": "SetupPackage",
        "objectVersion": 1,
        "setupContext": setup_context,
        "qShare": setup_parameters["qShare"].clone(),
        "phaseTranscript": phase_transcript,
        "commonRandomness": common_randomness,
        "vssCoefficientCommitments": vss_coefficient_commitments,
        "vssCoefficientCommitmentMaterial": vss_coefficient_commitment_material,
        "privateVssEnvelopeCommitments": private_vss_envelope_commitments,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "vssShareAcceptances": vss_share_acceptances,
        "thresholdShareCommitments": threshold_share_commitments,
        "sameSecretConsistency": same_secret_consistency,
        "publicKeyShares": public_key_shares,
        "publicKeyShareProofs": public_key_share_proofs,
        "evaluatorKeySchedule": evaluator_key_schedule,
        "relinearizationKeyShareRounds": {},
        "galoisKeyShareBatches": [],
        "trusteeEvaluationKeyProofs": {},
        "evaluationKeys": {},
        "setupTransportCertificate": setup_transport_certificate,
        "setupTransportCertificateHash": setup_transport_certificate_hash,
    });
    rebind_collective_setup_package_hash(&mut package);

    CollectiveSetupPackageFixture { package }
}

// The compact transform binds the same-secret proofs and the compact same-secret
// bridge that references them, so the compact minimal package is already
// same-secret-proof-bearing: this is exactly the minimal package. Reusing its
// cache (rather than compactifying the same base into a second cache) avoids a
// redundant heavy compact build that would otherwise race the minimal one under
// parallel test execution.
pub(super) fn same_secret_proof_bearing_collective_setup_package() -> serde_json::Value {
    minimal_collective_setup_package()
}

pub(super) fn public_key_share_succinct_proof_bearing_collective_setup_package() -> serde_json::Value
{
    PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_public_key_share_succinct_proof_bearing_collective_setup_package)
        .clone()
}

fn build_public_key_share_succinct_proof_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = same_secret_proof_bearing_collective_setup_package();
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    package["publicKeyShareSuccinctProofs"] = public_key_share_succinct_proofs_object(&package);
    rebind_collective_setup_package_hash(&mut package);

    package
}

pub(super) fn collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_collective_public_key_bearing_collective_setup_package)
        .clone()
}

fn build_collective_public_key_bearing_collective_setup_package() -> serde_json::Value {
    let mut package = build_public_key_share_succinct_proof_bearing_collective_setup_package();
    package["collectivePublicKey"] = collective_public_key_object(&package);
    package["collectivePublicKeyRoot"] =
        package["collectivePublicKey"]["collectivePublicKeyRoot"].clone();
    rebind_collective_setup_package_hash(&mut package);

    package
}

mod certificates;
mod common_randomness;
mod private_vss_envelopes;
mod public_key_shares;
mod same_secret_consistency;
mod vss_coefficient_commitments;

pub(super) use certificates::*;
use common_randomness::*;
pub(super) use private_vss_envelopes::*;
pub(super) use public_key_shares::*;
pub(super) use same_secret_consistency::*;
pub(super) use vss_coefficient_commitments::*;
