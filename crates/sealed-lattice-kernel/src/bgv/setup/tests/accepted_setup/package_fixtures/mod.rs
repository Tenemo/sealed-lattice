use super::proof_record_fixtures::{
    FinalizedCollectiveSetupPackageFixture, descriptor_backed_vss_proof_material_fixture,
    finalize_collective_setup_package,
};
use super::*;

use crate::hashing::derive_canonical_object_hash;

static MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<FinalizedCollectiveSetupPackageFixture> =
    OnceLock::new();
static COLLECTIVE_SETUP_INTENT_PACKAGE_CACHE: OnceLock<serde_json::Value> = OnceLock::new();
static DESCRIPTOR_BACKED_VSS_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    CachedDescriptorBackedVssCollectiveSetupFixture,
> = OnceLock::new();
static PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    CachedPublicKeyShareCollectiveSetupFixture,
> = OnceLock::new();
static COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE: OnceLock<
    CollectiveSetupVerificationFixture,
> = OnceLock::new();

const DEVELOPMENT_RING_DEGREE: usize = 128;

struct VssMaterialPackageComponents {
    vss_coefficient_commitments: serde_json::Value,
    vss_coefficient_commitment_material: serde_json::Value,
}

struct CollectiveSetupPackageFixture {
    package: serde_json::Value,
}

#[derive(Clone)]
pub(super) struct CollectiveSetupVerificationFixture {
    pub(super) package: serde_json::Value,
    pub(super) verification_request: serde_json::Value,
    proof_binding_leases: Vec<crate::bgv::setup::CanonicalSetupProofBindingLease>,
}

impl CollectiveSetupVerificationFixture {
    pub(super) fn begin_proof_binding_session(
        &self,
    ) -> crate::bgv::setup::AcceptedSetupProofBindingSession {
        self.begin_proof_binding_session_for_package(&self.package)
    }

    fn begin_proof_binding_session_for_package(
        &self,
        package: &serde_json::Value,
    ) -> crate::bgv::setup::AcceptedSetupProofBindingSession {
        let proof_binding_session =
            crate::bgv::setup::AcceptedSetupProofBindingSession::begin_fresh()
                .expect("begin accepted-setup fixture proof binding session");
        self.restore_proof_binding_leases(proof_binding_session);
        super::proof_record_fixtures::authenticate_public_key_share_material_fixture(
            package,
            proof_binding_session,
        );
        proof_binding_session
    }

    pub(super) fn restore_proof_binding_leases(
        &self,
        proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    ) {
        for proof_binding_lease in &self.proof_binding_leases {
            crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
                proof_binding_session.session_handle,
                proof_binding_lease,
            )
            .expect("restore accepted-setup fixture proof binding lease");
        }
    }

    pub(super) fn verify(&self) -> crate::encoding::CanonicalResult<serde_json::Value> {
        self.verify_values(&self.package, &self.verification_request)
    }

    pub(super) fn verify_values(
        &self,
        package: &serde_json::Value,
        verification_request: &serde_json::Value,
    ) -> crate::encoding::CanonicalResult<serde_json::Value> {
        let proof_binding_session = self.begin_proof_binding_session_for_package(package);
        crate::bgv::setup::accepted_setup::verify_collective_bgv_setup_package_for_test_ring_degree_in_proof_binding_session(
            package,
            verification_request,
            proof_binding_session,
            DEVELOPMENT_RING_DEGREE,
        )
    }

    pub(super) fn verify_values_in_session(
        &self,
        package: &serde_json::Value,
        verification_request: &serde_json::Value,
        proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    ) -> crate::encoding::CanonicalResult<serde_json::Value> {
        crate::bgv::setup::accepted_setup::
            verify_collective_bgv_setup_package_for_test_ring_degree_in_proof_binding_session(
                package,
                verification_request,
                proof_binding_session,
                DEVELOPMENT_RING_DEGREE,
            )
    }

    pub(super) fn verify_in_session(
        &self,
        proof_binding_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
    ) -> crate::encoding::CanonicalResult<serde_json::Value> {
        self.verify_values_in_session(
            &self.package,
            &self.verification_request,
            proof_binding_session,
        )
    }
}

struct CachedPublicKeyShareCollectiveSetupFixture {
    verification_fixture: CollectiveSetupVerificationFixture,
}

struct CachedDescriptorBackedVssCollectiveSetupFixture {
    verification_fixture: CollectiveSetupVerificationFixture,
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

/// The ten-participant parameter profile used by the lightweight setup-intent fixture.
const PARAMETER_PROFILE_PARTICIPANT_COUNT: u64 = 10;

/// The minimum roster accepted by the setup verifier. Proof-bearing rejection
/// tests use this roster because their purpose is to exercise bindings and
/// refusal behavior, not to benchmark proof material growth with roster size.
const MINIMUM_SUPPORTED_PARTICIPANT_COUNT: u64 = 3;

pub(super) fn minimal_collective_setup_package_fixture() -> FinalizedCollectiveSetupPackageFixture {
    cached_minimal_collective_setup_package_fixture().clone()
}

fn cached_minimal_collective_setup_package_fixture()
-> &'static FinalizedCollectiveSetupPackageFixture {
    MINIMAL_COLLECTIVE_SETUP_PACKAGE_CACHE.get_or_init(|| {
        super::proof_record_fixtures::finalize_collective_setup_package(
            minimal_collective_setup_package_for_participant_count(
                MINIMUM_SUPPORTED_PARTICIPANT_COUNT,
            ),
        )
    })
}

/// Setup package with signed trustee registrations, before proof-bearing setup
/// material is attached. Setup-intent tests use this fixture so the ordinary
/// Rust lane does not generate unrelated succinct proofs.
pub(super) fn collective_setup_intent_package() -> serde_json::Value {
    COLLECTIVE_SETUP_INTENT_PACKAGE_CACHE
        .get_or_init(|| {
            minimal_collective_setup_package_for_participant_count(
                PARAMETER_PROFILE_PARTICIPANT_COUNT,
            )
        })
        .clone()
}

/// Reduced development-ring (128) collective setup package for an arbitrary
/// supported roster size, built through the non-streamed VSS path. Drives the
/// same per-trustee material and roster-derived bindings as the ten-participant
/// setup-intent package path. The finalized fixture adds proof-bearing setup material
/// on top of this package.
pub(super) fn minimal_collective_setup_package_for_participant_count(
    participant_count: u64,
) -> serde_json::Value {
    build_collective_setup_package_fixture(DEVELOPMENT_RING_DEGREE, participant_count)
}

fn build_collective_setup_package_fixture(
    vss_material_ring_degree: usize,
    participant_count: u64,
) -> serde_json::Value {
    build_collective_setup_package_fixture_parts(vss_material_ring_degree, participant_count)
        .package
}

// The collective setup context shared by the package fixtures. Every fixture
// builds the same foundation context shape, so this keeps one definition of
// it instead of repeating the json! block at each construction site.
fn collective_setup_context_fixture(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    participant_count: u64,
) -> serde_json::Value {
    serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
    })
}

fn build_collective_setup_package_fixture_parts(
    vss_material_ring_degree: usize,
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
    // The setup parameters hash is a roster family, distinct per participant
    // count. It binds the evaluator key schedule and canonical BGV parameters.
    // The verifier checks
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
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
        .expect("setup context hash");
    let trustee_registrations = (0..participant_count)
        .map(|roster_position| {
            let trustee_identity = format!("trustee-{roster_position}");
            let signature_seed_label = setup_trustee_signature_seed_label(&trustee_identity);
            let signing_public_key_hash =
                create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                    .expect("signature key fixture");
            let private_vss_mailbox_public_key_hash =
                private_vss_mailbox_public_key_hash(roster_position);
            let registration_payload = serde_json::json!({
                "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                "setupContextHash": setup_context_hash,
                "trusteeIdentity": trustee_identity,
                "rosterPosition": roster_position,
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "signingPublicKeyHash": signing_public_key_hash,
                "privateVssMailboxPublicKeyHash": private_vss_mailbox_public_key_hash,
            });
            let registration_root = derive_canonical_object_hash(&registration_payload)
                .expect("setup-intent registration root");
            let signature_envelope = create_protocol_signature_fixture(
                &signature_seed_label,
                serde_json::json!({
                    "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                    "objectRoot": registration_root,
                }),
            )
            .expect("setup-intent signature fixture")
            .envelope;

            serde_json::json!({
                "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                "trusteeIdentity": trustee_identity,
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "privateVssMailboxPublicKeyHash": private_vss_mailbox_public_key_hash,
                "signatureEnvelope": signature_envelope,
            })
        })
        .collect::<Vec<_>>();
    let setup_intent = serde_json::json!({
        "objectType": "CollectiveBgvSetupIntent",
        "trusteeRegistrations": trustee_registrations,
    });
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
                participant_count,
            );
        VssMaterialPackageComponents {
            vss_coefficient_commitments,
            vss_coefficient_commitment_material,
        }
    };
    let vss_coefficient_commitments = vss_components.vss_coefficient_commitments.clone();
    let vss_coefficient_commitment_material =
        vss_components.vss_coefficient_commitment_material.clone();
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
    let public_key_shares = public_key_shares_object(participant_count);
    let evaluator_key_schedule = evaluator_key_schedule_object(
        ceremony_id,
        &manifest_hash,
        &roster_hash,
        setup_parameters_hash,
        setup_epoch,
        &setup_parameters,
        &common_randomness,
        &public_key_shares,
        participant_count,
    );
    let package = serde_json::json!({
        "objectType": "SetupPackage",
        "setupContext": setup_context,
        "setupIntent": setup_intent,
        "commonRandomness": common_randomness,
        "vssCoefficientCommitments": vss_coefficient_commitments,
        "vssCoefficientCommitmentMaterial": vss_coefficient_commitment_material,
        "privateVssEnvelopeCommitments": private_vss_envelope_commitments,
        "vssShareAcceptances": vss_share_acceptances,
        "publicKeyShares": public_key_shares,
        "evaluatorKeySchedule": evaluator_key_schedule,
        "relinearizationKeyShareRounds": {},
        "galoisKeyShareBatches": [],
        "trusteeEvaluationKeyProofs": {},
    });
    CollectiveSetupPackageFixture { package }
}

pub(super) fn public_key_share_succinct_proof_bearing_collective_setup_fixture()
-> CollectiveSetupVerificationFixture {
    let _ = descriptor_backed_vss_collective_setup_fixture();
    let cached_fixture = PUBLIC_KEY_SHARE_SUCCINCT_PROOF_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_public_key_share_succinct_proof_bearing_collective_setup_package);
    cached_fixture.verification_fixture.clone()
}

fn build_public_key_share_succinct_proof_bearing_collective_setup_package()
-> CachedPublicKeyShareCollectiveSetupFixture {
    let descriptor_backed_vss_fixture = descriptor_backed_vss_collective_setup_fixture();
    let proof_binding_session = descriptor_backed_vss_fixture.begin_proof_binding_session();
    let mut proof_binding_leases = descriptor_backed_vss_fixture.proof_binding_leases;
    let mut package = descriptor_backed_vss_fixture.package;
    let verification_request = descriptor_backed_vss_fixture.verification_request;
    replace_public_key_share_hashes_with_material_hashes(&mut package);
    package["publicKeyShareMaterial"] = public_key_share_material_object(&package);
    let succinct_proof_fixture =
        public_key_share_succinct_proofs_fixture(&package, &proof_binding_session);
    proof_binding_leases.extend(succinct_proof_fixture.proof_binding_leases.iter().cloned());
    crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
        proof_binding_session.session_handle,
    )
    .expect("cancel public-key share fixture proof binding session");
    package["publicKeyShareSuccinctProofs"] = succinct_proof_fixture.proof_set.clone();
    CachedPublicKeyShareCollectiveSetupFixture {
        verification_fixture: CollectiveSetupVerificationFixture {
            package,
            verification_request,
            proof_binding_leases,
        },
    }
}

pub(super) fn descriptor_backed_vss_collective_setup_fixture() -> CollectiveSetupVerificationFixture
{
    let cached_fixture = DESCRIPTOR_BACKED_VSS_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_descriptor_backed_vss_collective_setup_fixture);
    cached_fixture.verification_fixture.clone()
}

fn build_descriptor_backed_vss_collective_setup_fixture()
-> CachedDescriptorBackedVssCollectiveSetupFixture {
    build_descriptor_backed_vss_collective_setup_fixture_from_package(
        minimal_collective_setup_package_fixture(),
    )
}

fn build_descriptor_backed_vss_collective_setup_fixture_from_package(
    mut finalized_fixture: FinalizedCollectiveSetupPackageFixture,
) -> CachedDescriptorBackedVssCollectiveSetupFixture {
    let proof_material_fixture = descriptor_backed_vss_proof_material_fixture(
        &mut finalized_fixture.package,
        &finalized_fixture.proof_binding_leases,
    );
    let package = finalized_fixture.package;

    CachedDescriptorBackedVssCollectiveSetupFixture {
        verification_fixture: CollectiveSetupVerificationFixture {
            package,
            verification_request: serde_json::json!({}),
            proof_binding_leases: proof_material_fixture.proof_binding_leases(),
        },
    }
}

/// The explicit ten-participant proof-bearing fixture used only by its
/// dedicated guarded evidence lane. Routine accepted-setup tests retain the
/// minimum supported roster because their rejection assertions do not gain
/// coverage by regenerating the same proof relations for a larger roster.
pub(super) fn ten_participant_descriptor_backed_vss_collective_setup_fixture()
-> CollectiveSetupVerificationFixture {
    let fixture = build_descriptor_backed_vss_collective_setup_fixture_from_package(
        finalize_collective_setup_package(minimal_collective_setup_package_for_participant_count(
            PARAMETER_PROFILE_PARTICIPANT_COUNT,
        )),
    );
    fixture.verification_fixture
}

pub(super) fn collective_public_key_bearing_collective_setup_fixture()
-> CollectiveSetupVerificationFixture {
    let _ = public_key_share_succinct_proof_bearing_collective_setup_fixture();
    COLLECTIVE_PUBLIC_KEY_BEARING_COLLECTIVE_SETUP_PACKAGE_CACHE
        .get_or_init(build_collective_public_key_bearing_collective_setup_package)
        .clone()
}

fn build_collective_public_key_bearing_collective_setup_package()
-> CollectiveSetupVerificationFixture {
    let public_key_share_fixture =
        public_key_share_succinct_proof_bearing_collective_setup_fixture();
    let proof_binding_leases = public_key_share_fixture.proof_binding_leases;
    let mut package = public_key_share_fixture.package;
    package["collectivePublicKey"] = collective_public_key_object(&package);

    CollectiveSetupVerificationFixture {
        package,
        verification_request: public_key_share_fixture.verification_request,
        proof_binding_leases,
    }
}

mod common_randomness;
mod private_vss_envelopes;
mod public_key_shares;
mod vss_coefficient_commitments;

use common_randomness::*;
pub(super) use private_vss_envelopes::*;
pub(super) use public_key_shares::*;
pub(super) use vss_coefficient_commitments::*;
