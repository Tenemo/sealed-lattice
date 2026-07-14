use super::super::*;
use super::*;
use crate::bgv::setup::accepted_setup::{
    TrusteeEvaluationKeyStatementInputs, trustee_evaluation_key_statement_from_package,
    verified_same_secret_bridge_material_from_package,
};
use crate::bgv::setup::evaluation_key_share_material::EvaluationKeyShareProofFamily;
use crate::bgv::setup::setup_proof::authenticate_setup_proof_material_stream_for_test;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, KeyBearingWitness, SameSecretLinkageWitness,
    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, prove_trustee_evaluation_key_proof_bytes,
    trustee_evaluation_key_proof_bytes_hash, verify_trustee_evaluation_key_proof_bytes,
};
use crate::hashing::{derive_canonical_object_hash, to_hex};

pub(in super::super) struct TrusteeEvaluationKeyProofFixture {
    pub(in super::super) proof_set: serde_json::Value,
}

pub(in super::super) fn trustee_evaluation_key_proof_material_root_from_fixture_record(
    proof_record: &serde_json::Value,
) -> String {
    crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        proof_record["proofBytesHash"]
            .as_str()
            .expect("trustee evaluation-key proofBytesHash"),
    )
    .expect("trustee evaluation-key proof material root")
}

// Builds the trustee evaluation-key succinct proof set, one proof per trustee
// covering the whole scheduled relinearization and Galois key material, bound to
// the same-secret bridge. Each statement is rebuilt through the same
// `trustee_evaluation_key_statement_from_package` the accepted-setup verifier
// calls, so a proof verifies against the exact records, aggregates, and bridge
// the verifier reconstructs. Each generated proof is stream-authenticated and
// semantically verified, then replaced by an opaque verifier binding before the
// next trustee; package records and the request carry only canonical references.

pub(in super::super) fn trustee_evaluation_key_proofs_object(
    package: &serde_json::Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    round_one_aggregate_diagonals_by_level: &BTreeMap<u64, Vec<Vec<u64>>>,
) -> TrusteeEvaluationKeyProofFixture {
    let setup_context = &package["setupContext"];
    let participant_count = participant_count_from_package(package);
    let trustee_roster_positions = (0..participant_count).collect::<Vec<_>>();
    // The bridge material the verifier reconstructs from the package records
    // and authenticated session material.
    let verified_same_secret_bridge = package.get("sameSecretBridgeStatementSet").map(|_| {
        verified_same_secret_bridge_material_from_package(package, Some(proof_binding_session))
            .expect("same-secret bridge material")
    });
    assert!(
        verified_same_secret_bridge.is_some(),
        "the trustee evaluation-key fixture is the same-secret-bridge-bound terminal path"
    );
    let ring_degree = package["sameSecretBridgeStatementSet"]["ringDegree"]
        .as_u64()
        .expect("same-secret bridge ring degree") as usize;

    let mut proof_records = Vec::with_capacity(trustee_roster_positions.len());
    for trustee_roster_position in trustee_roster_positions {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement =
            trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
                setup_package: package,
                verified_same_secret_bridge: verified_same_secret_bridge.as_ref(),
                round_one_aggregate_diagonals_by_level,
                trustee_roster_position,
                accepted_setup_session: proof_binding_session,
            })
            .expect("trustee evaluation-key statement");
        let witness = trustee_evaluation_key_witness_for_fixture(
            trustee_roster_position,
            ring_degree,
            &statement,
        );
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "TrusteeEvaluationKeyProofRandomness",
            "fixture": "trustee-evaluation-key-proof-randomness",
            "trusteeRosterPosition": trustee_roster_position,
        }))
        .expect("trustee proof randomness seed");
        let statement_hash_hex = to_hex(&statement.statement_hash());
        // The checkpoint key carries the schedule container tag plus a
        // prover-revision suffix so stale bytes (same statement hash) never
        // collide across format or prover changes. Bump the revision when
        // the atom prover's transcript changes; slksats4 binds the combined
        // source-constant relation directly.
        let checkpoint_key = format!("{statement_hash_hex}-slksats4");
        let CheckpointedProofBytes {
            proof_bytes,
            was_semantically_verified,
        } = checkpointed_proof_bytes_with_verification_state(
            TRUSTEE_EVALUATION_KEY_PROOF_CHECKPOINT_DIRECTORY,
            &checkpoint_key,
            |proof_bytes| verify_trustee_evaluation_key_proof_bytes(&statement, proof_bytes),
            || {
                prove_trustee_evaluation_key_proof_bytes(
                    &statement,
                    &witness,
                    &proof_randomness_seed_hex,
                )
                .expect("trustee evaluation-key proof bytes")
            },
        );
        let proof_bytes_hash = trustee_evaluation_key_proof_bytes_hash(&proof_bytes);
        let mut record = serde_json::json!({
            "objectType": "TrusteeEvaluationKeyProof",
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupParametersHash": setup_context["setupParametersHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "statementHash": statement_hash_hex,
            "proofBytesHash": proof_bytes_hash,
        });
        let proof_material_root =
            trustee_evaluation_key_proof_material_root_from_fixture_record(&record);
        authenticate_setup_proof_material_stream_for_test(
            TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            &proof_material_root,
            &proof_bytes,
        )
        .expect("authenticate trustee evaluation-key proof material stream");
        record["proofMaterialRoot"] = serde_json::json!(&proof_material_root);
        final_package_phase(&format!(
            "generated trustee evaluation-key proof trustee {trustee_roster_position}"
        ));

        if !was_semantically_verified {
            verify_trustee_evaluation_key_proof_bytes(&statement, &proof_bytes)
                .expect("verify generated trustee evaluation-key proof bytes");
        }
        let verification_binding_hash = crate::bgv::setup::accepted_setup::
            trustee_evaluation_key_proof_verification_binding_hash(&record, &statement)
            .expect("trustee evaluation-key proof verification binding");
        crate::bgv::setup::retain_accepted_setup_proof_binding(
            proof_binding_session.session_handle,
            TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            &proof_material_root,
            verification_binding_hash,
        )
        .expect("retain trustee evaluation-key proof binding");
        proof_records.push(record);
    }

    let proof_set = serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofSet",
        "proofRecords": proof_records,
    });

    TrusteeEvaluationKeyProofFixture { proof_set }
}

// The deterministic fixture witness for one trustee's batched statement: the
// shared VSS secret, per-key fixture errors in statement order, and the
// same-secret bridge openings. It populates only the key-relation and linkage
// columns.
pub(in super::super) fn trustee_evaluation_key_witness_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    statement: &TrusteeEvaluationKeyStatement,
) -> TrusteeEvaluationKeyWitness {
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let error_coefficients_by_key = statement
        .keys()
        .iter()
        .map(|key| {
            let (proof_family, rotation) = match key.kind {
                EvaluationKeyShareKind::RelinearizationRoundOne
                | EvaluationKeyShareKind::RelinearizationRoundTwo => {
                    (EvaluationKeyShareProofFamily::Relinearization, None)
                }
                EvaluationKeyShareKind::GaloisRotation { galois_element } => (
                    EvaluationKeyShareProofFamily::Galois,
                    Some(u64::try_from(galois_element).expect("rotation fits u64")),
                ),
                EvaluationKeyShareKind::PublicKeyShare => {
                    unreachable!(
                        "the evaluation-key witness fixture never carries a public-key share key"
                    );
                }
            };
            (0..=key.level)
                .map(|digit_index| {
                    evaluation_key_error_coefficients_for_fixture(
                        proof_family,
                        trustee_roster_position,
                        key.level,
                        rotation,
                        digit_index,
                        ring_degree,
                    )
                })
                .collect()
        })
        .collect();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect();
    // The atom opens one original BDLOP source constant commitment. Its five
    // ternary randomness columns are the exact opening used to construct the
    // accepted VSS coefficient commitment at source limb zero.
    let opening_randomness_by_limb = vec![
        accepted_vss_randomness_fixture(trustee_roster_position, 0, 0, ring_degree)
            .into_iter()
            .map(|column| {
                column
                    .into_iter()
                    .map(|value| i64::try_from(value).expect("ternary randomness fits i64"))
                    .collect()
            })
            .collect(),
    ];

    TrusteeEvaluationKeyWitness::TrusteeEvaluationKey {
        key: KeyBearingWitness {
            secret_coefficients,
            error_coefficients_by_key,
        },
        linkage: SameSecretLinkageWitness {
            negative_indicator_coefficients,
            opening_randomness_by_limb,
        },
    }
}
