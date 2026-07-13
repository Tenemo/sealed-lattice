use super::*;

const PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE: usize = 128;

struct TestPrivateVssProofMaterialEvictionGuard {
    proof_material_roots: Vec<String>,
}

impl TestPrivateVssProofMaterialEvictionGuard {
    fn from_material_set(material_set: &serde_json::Value) -> Self {
        let proof_material_roots = material_set["proofMaterials"]
            .as_array()
            .expect("private VSS proof material references")
            .iter()
            .map(|proof_material| {
                proof_material["proofMaterialRoot"]
                    .as_str()
                    .expect("private VSS proof material root")
                    .to_string()
            })
            .collect();
        Self {
            proof_material_roots,
        }
    }
}

impl Drop for TestPrivateVssProofMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_setup_proof_materials(
            &self.proof_material_roots,
        );
    }
}

#[test]
fn private_vss_share_envelope_verifier_accepts_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "accepts-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], true);
    assert_eq!(result["isValid"], true);
    assert_eq!(result["refusedObjects"], serde_json::json!([]));
    assert_eq!(
        result["limbVerifications"]
            .as_array()
            .expect("limb verifications")
            .len(),
        DATA_PRIMES.len()
    );
    for limb_verification in result["limbVerifications"]
        .as_array()
        .expect("limb verifications")
    {
        assert!(
            limb_verification["privateVssShareProofHash"]
                .as_str()
                .expect("proof hash")
                .len()
                == 128
        );
        assert!(
            limb_verification["proofStatementRoot"]
                .as_str()
                .expect("proof statement root")
                .len()
                == 128
        );
    }
}

#[test]
// Run through the guarded focused Rust runner:
//   pnpm run test:rust:kernel:full-profile-evidence -- private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs
#[ignore = "foundation-roster private VSS verification; run via the guarded full-profile-evidence runner"]
fn private_vss_share_envelope_verifier_accepts_foundation_roster_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        crate::bgv::parameters::POLYNOMIAL_DEGREE,
        "accepts-foundation-roster-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("foundation-roster private VSS envelope verification");

    assert_eq!(result["isValid"], true);
    assert_eq!(result["refusedObjects"], serde_json::json!([]));
    assert_eq!(
        result["limbVerifications"]
            .as_array()
            .expect("limb verifications")
            .len(),
        DATA_PRIMES.len()
    );
    // The recipient-local verification root and envelope hash are the integration
    // handles a signed VssShareAcceptance commits to, so the foundation-roster path
    // produces the same accepted evidence the reduced-ring path does at scale.
    assert_eq!(
        result["localVerificationRoot"]
            .as_str()
            .expect("local verification root")
            .len(),
        128
    );
    assert_eq!(
        result["privateEnvelopeHash"]
            .as_str()
            .expect("private envelope hash")
            .len(),
        128
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_noncanonical_succinct_context() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-noncanonical-succinct-context",
    );
    request["setupContext"]["setupEpoch"] = serde_json::json!("setup epoch 1");

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssContextMismatch"
    );
}

#[test]
fn private_vss_succinct_proof_verifier_accepts_canonical_record() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
    let request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let private_envelope = &request["privateEnvelope"];
    let private_envelope_aad_hash = private_envelope["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash");
    let source_trustee_commitment_root = private_envelope["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let limb_opening = &private_envelope["rnsShareOpenings"][0];
    let rns_prime = limb_opening["rnsPrime"].as_u64().expect("RNS prime");
    let coefficient_messages_by_shamir_index = vec![vec![0_u64; ring_degree]; 4];
    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    let coefficient_commitments = opening_randomness_by_shamir_index
        .iter()
        .enumerate()
        .map(|(shamir_coefficient_index, opening_randomness)| {
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                0,
                rns_prime,
                shamir_coefficient_index as u64,
                &vec![0_u128; ring_degree],
                opening_randomness,
                ring_degree,
            )
            .expect("zero coefficient commitment")
        })
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("commitment root"))
        .collect::<Vec<_>>();
    let share_values = vec![0_u64; ring_degree];
    let share_values_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssShareValueVector",
        "rnsLimbIndex": 0,
        "rnsPrime": rns_prime,
        "shareValues": share_values,
    }))
    .expect("share values hash");
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssLocalVerificationRoot",
        "fixture": "private-vss-succinct-proof-record",
        "rnsLimbIndex": 0,
    }))
    .expect("private VSS proof randomness seed");
    let proof_record =
        private_vss_share_succinct_proof_record(PrivateVssShareSuccinctProofGenerationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: "trustee-0",
            source_trustee_roster_position: 0,
            recipient_identity: "trustee-2",
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitments,
            witness: &PrivateVssShareSuccinctProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index,
                carry_witnesses: vec![0_i128; ring_degree],
            },
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        })
        .expect("private VSS proof record");
    assert_eq!(proof_record["proofFamily"], "vss-opening-carry");
    assert_eq!(
        proof_record["proofMaterialRoot"]
            .as_str()
            .expect("proof material root")
            .len(),
        128
    );
    let transported_proof_material = private_vss_proof_material_reference_set(&[&proof_record]);
    let _proof_material_eviction_guard =
        TestPrivateVssProofMaterialEvictionGuard::from_material_set(&transported_proof_material);

    let verification = verify_private_vss_share_succinct_relation_proof(
        PrivateVssShareSuccinctProofVerificationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: "trustee-0",
            source_trustee_roster_position: 0,
            recipient_identity: "trustee-2",
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitments,
            proof_record: &proof_record,
            transported_proof_material: Some(&transported_proof_material),
        },
    )
    .expect("private VSS succinct proof verifies");

    assert_eq!(
        verification.proof_bytes_hash,
        proof_record["proofBytesHash"]
            .as_str()
            .expect("proof bytes hash")
    );
}

// Multi-recipient consistency is what makes the reduced message-claim set sound:
// a single recipient's proof does not pin the Shamir coefficients across the RNS
// commitment fields, so soundness comes from >= t honest recipients each
// verifying the same source commitment. This test exercises that structure: one
// committed degree-(t-1) polynomial, verified at four distinct recipient points
// for threshold t = 4, all accepting. The shares differ per recipient (distinct
// evaluation points) yet every proof binds the identical coefficient commitments.
//
// The dual negative direction - a single recipient accepting an inconsistent or
// out-of-range coefficient set that >= t honest recipients would jointly reject -
// cannot be expressed through this generation path: the witness API carries one
// integer message per coefficient, reduced consistently into each commitment
// field, so it structurally cannot emit per-field-inconsistent messages.
// Demonstrating that requires constructing the committed columns below the prover
// (bypassing validate_private_vss_witness).
#[test]
fn private_vss_succinct_proof_accepts_one_polynomial_across_threshold_recipients() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
    let request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let private_envelope = &request["privateEnvelope"];
    let private_envelope_aad_hash = private_envelope["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash");
    let source_trustee_commitment_root = private_envelope["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let rns_prime = private_envelope["rnsShareOpenings"][0]["rnsPrime"]
        .as_u64()
        .expect("RNS prime");

    // One committed degree-(t-1) polynomial, shared by every recipient: four
    // non-zero Shamir coefficient messages and their commitments.
    let coefficient_messages_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            coefficient_message_fixture(0, shamir_coefficient_index, rns_prime, ring_degree)
        })
        .collect::<Vec<_>>();
    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    let coefficient_commitments = coefficient_messages_by_shamir_index
        .iter()
        .zip(opening_randomness_by_shamir_index.iter())
        .enumerate()
        .map(
            |(shamir_coefficient_index, (messages, opening_randomness))| {
                let messages_u128 = messages
                    .iter()
                    .map(|value| u128::from(*value))
                    .collect::<Vec<_>>();
                compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    0,
                    rns_prime,
                    shamir_coefficient_index as u64,
                    &messages_u128,
                    opening_randomness,
                    ring_degree,
                )
                .expect("coefficient commitment")
            },
        )
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("commitment root"))
        .collect::<Vec<_>>();

    // Four distinct recipient points for threshold t = 4, each inside the
    // n = 10 accepted roster fixture.
    for recipient_roster_position in [1_usize, 3, 5, 8] {
        let (share_values, carry_strings) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            recipient_roster_position,
            rns_prime,
            ring_degree,
        );
        let carry_witnesses = carry_strings
            .iter()
            .map(|carry| carry.parse::<i128>().expect("carry witness parses"))
            .collect::<Vec<_>>();
        let share_values_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssShareValueVector",
            "rnsLimbIndex": 0,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
        }))
        .expect("share values hash");
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssLocalVerificationRoot",
            "fixture": "private-vss-multi-recipient-consistency",
            "recipientRosterPosition": recipient_roster_position,
        }))
        .expect("private VSS proof randomness seed");
        let recipient_identity = format!("trustee-{recipient_roster_position}");
        let proof_record =
            private_vss_share_succinct_proof_record(PrivateVssShareSuccinctProofGenerationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash,
                private_envelope_aad_hash,
                source_trustee_identity: "trustee-0",
                source_trustee_roster_position: 0,
                recipient_identity: &recipient_identity,
                recipient_roster_position: recipient_roster_position as u64,
                source_trustee_commitment_root,
                rns_limb_index: 0,
                rns_prime,
                ring_degree,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                share_values_hash: &share_values_hash,
                coefficient_commitments: &coefficient_commitments,
                witness: &PrivateVssShareSuccinctProofWitness {
                    coefficient_messages_by_shamir_index: coefficient_messages_by_shamir_index
                        .clone(),
                    opening_randomness_by_shamir_index: opening_randomness_by_shamir_index.clone(),
                    carry_witnesses,
                },
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            })
            .unwrap_or_else(|error| {
                panic!(
                    "proof record for recipient {recipient_roster_position}: {}",
                    error.message
                )
            });
        let transported_proof_material = private_vss_proof_material_reference_set(&[&proof_record]);
        let _proof_material_eviction_guard =
            TestPrivateVssProofMaterialEvictionGuard::from_material_set(
                &transported_proof_material,
            );

        verify_private_vss_share_succinct_relation_proof(
            PrivateVssShareSuccinctProofVerificationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash,
                private_envelope_aad_hash,
                source_trustee_identity: "trustee-0",
                source_trustee_roster_position: 0,
                recipient_identity: &recipient_identity,
                recipient_roster_position: recipient_roster_position as u64,
                source_trustee_commitment_root,
                rns_limb_index: 0,
                rns_prime,
                ring_degree,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                share_values_hash: &share_values_hash,
                coefficient_commitments: &coefficient_commitments,
                proof_record: &proof_record,
                transported_proof_material: Some(&transported_proof_material),
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "verification for recipient {recipient_roster_position}: {}",
                error.message
            )
        });
    }
}

// The Shamir coefficient message columns carry no per-field consistency
// assertion, so the commitment opening lincheck is the message column's only
// binding. This test confirms that binding is required: a coefficient message
// that disagrees with what its commitment opens to cannot be packaged into an
// accepted proof. The tamper keeps the recipient-share Shamir relation satisfied
// (so the witness-relation self-check and shape checks pass) and leaves the
// randomness, the carry, and the commitments themselves intact; only the witness
// message diverges from the zero message the commitment binds. Proof construction
// enforces exactly the lincheck the verifier checks, so an inconsistent message
// is rejected at the sumcheck/lincheck stage. If this ever succeeded, the message
// would be unbound.
// The honest baseline (identical setup, untampered) is covered by
// private_vss_succinct_proof_verifier_accepts_canonical_record above.
#[test]
fn private_vss_succinct_proof_refuses_message_inconsistent_with_commitment_opening() {
    let ring_degree = PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE;
    let request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let private_envelope = &request["privateEnvelope"];
    let private_envelope_aad_hash = private_envelope["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash");
    let source_trustee_commitment_root = private_envelope["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let limb_opening = &private_envelope["rnsShareOpenings"][0];
    let rns_prime = limb_opening["rnsPrime"].as_u64().expect("RNS prime");

    let opening_randomness_by_shamir_index = (0..4_u64)
        .map(|shamir_coefficient_index| {
            randomness_fixture(0, shamir_coefficient_index, ring_degree)
        })
        .collect::<Vec<_>>();
    // The commitments bind the honest, all-zero coefficient messages.
    let coefficient_commitments = opening_randomness_by_shamir_index
        .iter()
        .enumerate()
        .map(|(shamir_coefficient_index, opening_randomness)| {
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                0,
                rns_prime,
                shamir_coefficient_index as u64,
                &vec![0_u128; ring_degree],
                opening_randomness,
                ring_degree,
            )
            .expect("zero coefficient commitment")
        })
        .collect::<Vec<_>>();
    let coefficient_commitment_roots = coefficient_commitments
        .iter()
        .map(|commitment| setup_commitment_root(commitment).expect("commitment root"))
        .collect::<Vec<_>>();

    // Tamper the constant-term message of the first Shamir coefficient at one
    // position. The constant term contributes with trustee-point power one, so the
    // recipient share at that position must move by the same amount to keep the
    // witness Shamir relation satisfied; the carry stays zero. The commitments
    // above still bind the zero message, so the only inconsistency in the witness
    // is between the message column and its commitment opening.
    let tampered_message: u64 = 1;
    let mut coefficient_messages_by_shamir_index = vec![vec![0_u64; ring_degree]; 4];
    coefficient_messages_by_shamir_index[0][0] = tampered_message;
    let mut share_values = vec![0_u64; ring_degree];
    share_values[0] = tampered_message;
    let share_values_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssShareValueVector",
        "rnsLimbIndex": 0,
        "rnsPrime": rns_prime,
        "shareValues": share_values,
    }))
    .expect("share values hash");
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssLocalVerificationRoot",
        "fixture": "private-vss-succinct-proof-tampered-message",
        "rnsLimbIndex": 0,
    }))
    .expect("private VSS proof randomness seed");

    let generation =
        private_vss_share_succinct_proof_record(PrivateVssShareSuccinctProofGenerationInput {
            setup_context: &setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: "trustee-0",
            source_trustee_roster_position: 0,
            recipient_identity: "trustee-2",
            recipient_roster_position: 2,
            source_trustee_commitment_root,
            rns_limb_index: 0,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitments,
            witness: &PrivateVssShareSuccinctProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index,
                carry_witnesses: vec![0_i128; ring_degree],
            },
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        });

    let error = generation.expect_err(
        "a coefficient message that disagrees with its commitment opening must be refused: \
         the opening lincheck binds the message column even though it carries no consistency claim",
    );
    assert!(
        error.message.contains("sumcheck"),
        "the rejection must come from the commitment-opening lincheck (the batched sumcheck claim), \
         not an earlier shape or share-relation check; got: {}",
        error.message
    );
}

#[test]
fn private_vss_share_envelope_verifier_accepts_transported_succinct_private_share_proofs() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "accepts-transported-succinct-private-share-proofs",
    );

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], true);
    for limb_opening in request["privateEnvelope"]["rnsShareOpenings"]
        .as_array()
        .expect("limb openings")
    {
        let proof_record = &limb_opening["privateVssShareProof"];
        assert_eq!(
            proof_record["proofMaterialRoot"]
                .as_str()
                .expect("proof material root")
                .len(),
            128
        );
    }
}

#[test]
fn private_vss_share_envelope_verifier_refuses_missing_transported_succinct_private_share_proofs() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-missing-transported-succinct-private-share-proofs",
    );
    let transported_proof_material = request["transportedPrivateVssShareProofMaterial"].clone();
    let _proof_material_eviction_guard =
        TestPrivateVssProofMaterialEvictionGuard::from_material_set(&transported_proof_material);
    request
        .as_object_mut()
        .expect("private VSS request")
        .remove("transportedPrivateVssShareProofMaterial");

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transportedPrivateVssShareProofMaterial")
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_transported_private_share_proof_material_root_drift()
{
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-transported-private-share-proof-material-root-drift",
    );
    replace_first_private_vss_proof_hash(
        &mut request,
        "proofMaterialRoot",
        "private-vss-transported-proof-material-root-drift",
    );

    assert_private_vss_share_proof_refusal_contains(
        &request,
        "missing the requested proofMaterialRoot",
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_private_share_proof_statement_root_drift() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-private-share-proof-statement-root-drift",
    );
    replace_first_private_vss_proof_hash(
        &mut request,
        "proofStatementRoot",
        "private-vss-proof-statement-root-drift",
    );

    assert_private_vss_share_proof_refusal_contains(&request, "proofStatementRoot");
}

#[test]
fn private_vss_share_envelope_verifier_refuses_private_share_statement_hash_drift() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-private-share-statement-hash-drift",
    );
    replace_first_private_vss_proof_hash(
        &mut request,
        "statementHash",
        "private-vss-statement-hash-drift",
    );

    assert_private_vss_share_proof_refusal_contains(&request, "proofMaterialRoot");
}

#[test]
fn private_vss_share_envelope_verifier_refuses_duplicate_transported_private_share_proof_material_root()
 {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-duplicate-transported-private-share-proof-material-root",
    );
    let first_proof_material =
        request["transportedPrivateVssShareProofMaterial"]["proofMaterials"][0].clone();
    request["transportedPrivateVssShareProofMaterial"]["proofMaterials"]
        .as_array_mut()
        .expect("transported proof materials")
        .push(first_proof_material);

    assert_private_vss_share_proof_refusal_contains(&request, "duplicate proofMaterialRoot");
}

#[test]
fn private_vss_share_envelope_verifier_refuses_unauthenticated_proof_material_reference() {
    let request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-unauthenticated-proof-material-reference",
    );
    let proof_material_root = request["privateEnvelope"]["rnsShareOpenings"][0]
        ["privateVssShareProof"]["proofMaterialRoot"]
        .as_str()
        .expect("private VSS proof material root");
    let _removed_proof_material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        "vss-opening-carry",
        proof_material_root,
    )
    .expect("private VSS proof material store lookup")
    .expect("private VSS proof material was retained");

    assert_private_vss_share_proof_refusal_contains(
        &request,
        "not authenticated by the canonical binary stream",
    );
}

#[test]
fn private_vss_share_envelope_verifier_refuses_share_value_drift_after_proof_generation() {
    let mut request = proof_shaped_private_vss_share_envelope_request(
        PRIVATE_VSS_SUCCINCT_TEST_RING_DEGREE,
        "refuses-share-value-drift-after-proof-generation",
    );
    let rns_prime = request["privateEnvelope"]["rnsShareOpenings"][0]["rnsPrime"]
        .as_u64()
        .expect("RNS prime");
    let first_share_value = request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0]
        .as_u64()
        .expect("share value");
    request["privateEnvelope"]["rnsShareOpenings"][0]["shareValues"][0] =
        serde_json::json!((first_share_value + 1) % rns_prime);

    let result = verify_private_vss_share_envelope_from_request(&request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
}

fn replace_first_private_vss_proof_hash(
    request: &mut serde_json::Value,
    field_name: &str,
    fixture_label: &str,
) {
    let replacement_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssLocalVerificationRoot",
        "fixture": "private-vss-proof-drift-refusal",
        "label": fixture_label,
    }))
    .expect("private VSS drift hash");
    let proof_record =
        &mut request["privateEnvelope"]["rnsShareOpenings"][0]["privateVssShareProof"];
    assert_ne!(
        proof_record[field_name].as_str().expect("proof hash field"),
        replacement_hash
    );
    proof_record[field_name] = serde_json::json!(replacement_hash);
}

fn assert_private_vss_share_proof_refusal_contains(
    request: &serde_json::Value,
    expected_message_fragment: &str,
) {
    let result = verify_private_vss_share_envelope_from_request(request)
        .expect("private VSS envelope verification");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "privateVssShareProofVerificationFailed"
    );
    let refusal_message = result["refusedObjects"][0]["message"]
        .as_str()
        .expect("refusal message");
    assert!(
        refusal_message.contains(expected_message_fragment),
        "expected refusal message to contain {expected_message_fragment:?}, got {refusal_message:?}"
    );
}

fn private_vss_share_envelope_request(ring_degree: usize) -> serde_json::Value {
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_canonical_object_hash(
        &serde_json::json!({ "objectType": "ElectionManifestHash", "manifest": "private-vss-envelope-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_canonical_object_hash(
        &serde_json::json!({ "objectType": "RosterHash", "roster": "private-vss-envelope-test" }),
    )
    .expect("roster hash");
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(10),
        )
        .expect("roster-derived setup parameters hash");
    let setup_parameters_hash = setup_parameters_hash.as_str();
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
    });
    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupPublicMatrixSeedHash",
        "fixture": "private-vss-envelope-test-public-matrix",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
    }))
    .expect("public matrix seed hash");
    let private_envelope_aad_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "PrivateVssEnvelopeAadHash",
        "fixture": "private-vss-envelope-aad",
        "recipientRosterPosition": 2,
    }))
    .expect("private VSS envelope AAD hash");

    let mut source_trustee_coefficient_commitments = Vec::new();
    let mut source_trustee_coefficient_commitment_material_records = Vec::new();
    let mut rns_share_openings = Vec::new();
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let mut coefficient_openings = Vec::new();
        let mut coefficient_messages_by_shamir_index = Vec::new();
        let mut coefficient_commitment_roots = Vec::new();
        for shamir_coefficient_index in 0..4_u64 {
            let coefficient_message = coefficient_message_fixture(
                rns_limb_index,
                shamir_coefficient_index,
                rns_prime,
                ring_degree,
            );
            let randomness_by_column =
                randomness_fixture(rns_limb_index, shamir_coefficient_index, ring_degree);
            let coefficient_message_wide = coefficient_message
                .iter()
                .map(|coefficient| u128::from(*coefficient))
                .collect::<Vec<_>>();
            let commitment = compute_setup_commitment_for_tests(
                &public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                shamir_coefficient_index,
                &coefficient_message_wide,
                &randomness_by_column,
                ring_degree,
            )
            .expect("setup commitment");
            let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
            coefficient_commitment_roots.push(commitment_root.clone());
            source_trustee_coefficient_commitments.push(serde_json::json!({
                "objectType": "VssCoefficientCommitment",
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupParametersHash": setup_parameters_hash,
                "setupEpoch": setup_epoch,
                "sourceTrusteeIdentity": "trustee-0",
                "sourceTrusteeRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root.clone(),
            }));
            source_trustee_coefficient_commitment_material_records.push(serde_json::json!({
                "objectType": "VssCoefficientCommitmentMaterial",
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "rosterHash": roster_hash,
                "setupParametersHash": setup_parameters_hash,
                "setupEpoch": setup_epoch,
                "sourceTrusteeIdentity": "trustee-0",
                "sourceTrusteeRosterPosition": 0,
                "publicMatrixSeedHash": public_matrix_seed_hash,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": commitment_root.clone(),
                "commitment": setup_commitment_full_value(&commitment),
            }));
            coefficient_openings.push(serde_json::json!({
                "shamirCoefficientIndex": shamir_coefficient_index,
                "commitmentRoot": coefficient_commitment_roots
                    .last()
                    .expect("coefficient commitment root"),
                "randomnessByColumn": randomness_by_column,
            }));
            coefficient_messages_by_shamir_index.push(coefficient_message);
        }
        let (share_values, carry_witnesses_decimal) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            2,
            rns_prime,
            ring_degree,
        );
        let aggregate_opening_columns =
            aggregate_opening_columns(&coefficient_openings, 2, ring_degree);
        rns_share_openings.push(serde_json::json!({
            "objectType": "PrivateVssShareLimbOpening",
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
            "carryWitnessesDecimal": carry_witnesses_decimal,
            "coefficientCommitmentRoots": coefficient_commitment_roots,
            "aggregateOpening": {
                "objectType": "PrivateVssAggregateOpening",
                "openingColumns": aggregate_opening_columns,
            },
        }));
    }

    let mut source_trustee_record = serde_json::json!({
        "objectType": "VssSourceTrusteeCoefficientCommitments",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": source_trustee_coefficient_commitments,
    });
    source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_trustee_record)
            .expect("source trustee commitment root")
    );

    let private_envelope = serde_json::json!({
        "objectType": "PrivateVssShareEnvelope",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "sourceTrusteeIdentity": "trustee-0",
        "sourceTrusteeRosterPosition": 0,
        "recipientIdentity": "trustee-2",
        "recipientRosterPosition": 2,
        "sourceTrusteeCommitmentRoot": source_trustee_record["sourceTrusteeCommitmentRoot"],
        "rnsShareOpenings": rns_share_openings,
    });

    serde_json::json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeCoefficientCommitmentRecord": source_trustee_record,
        "sourceTrusteeCoefficientCommitmentMaterialRecords": source_trustee_coefficient_commitment_material_records,
        "privateEnvelope": private_envelope,
    })
}

fn proof_shaped_private_vss_share_envelope_request(
    ring_degree: usize,
    proof_fixture_label: &str,
) -> serde_json::Value {
    let mut request = private_vss_share_envelope_request(ring_degree);
    let setup_context = request["setupContext"].clone();
    let public_matrix_seed_hash = request["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash")
        .to_string();
    let private_envelope_aad_hash = request["privateEnvelope"]["privateEnvelopeAadHash"]
        .as_str()
        .expect("private envelope AAD hash")
        .to_string();
    let source_trustee_commitment_root = request["privateEnvelope"]["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root")
        .to_string();
    let material_records = request["sourceTrusteeCoefficientCommitmentMaterialRecords"]
        .as_array()
        .expect("material records")
        .clone();
    let rns_share_openings = request["privateEnvelope"]["rnsShareOpenings"]
        .as_array_mut()
        .expect("private envelope limb openings");
    for (rns_limb_index, limb_opening) in rns_share_openings.iter_mut().enumerate() {
        let limb_object = limb_opening
            .as_object_mut()
            .expect("private envelope limb opening object");
        let rns_prime = limb_object
            .get("rnsPrime")
            .and_then(serde_json::Value::as_u64)
            .expect("RNS prime");
        let share_values = limb_object
            .get("shareValues")
            .and_then(serde_json::Value::as_array)
            .expect("share values")
            .iter()
            .map(|value| value.as_u64().expect("share value"))
            .collect::<Vec<_>>();
        let coefficient_commitment_roots = limb_object
            .get("coefficientCommitmentRoots")
            .and_then(serde_json::Value::as_array)
            .expect("coefficient commitment roots")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("coefficient commitment root")
                    .to_string()
            })
            .collect::<Vec<_>>();
        let coefficient_commitments = (0..4_u64)
            .map(|shamir_coefficient_index| {
                let material_record = material_records
                    .iter()
                    .find(|record| {
                        record["rnsLimbIndex"].as_u64() == Some(rns_limb_index as u64)
                            && record["shamirCoefficientIndex"].as_u64()
                                == Some(shamir_coefficient_index)
                    })
                    .expect("coefficient commitment material");
                parse_setup_commitment_full_value(&material_record["commitment"])
                    .expect("setup commitment")
            })
            .collect::<Vec<_>>();
        let coefficient_messages_by_shamir_index = (0..4_u64)
            .map(|shamir_coefficient_index| {
                coefficient_message_fixture(
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>();
        let opening_randomness_by_shamir_index = (0..4_u64)
            .map(|shamir_coefficient_index| {
                randomness_fixture(rns_limb_index, shamir_coefficient_index, ring_degree)
            })
            .collect::<Vec<_>>();
        let (expected_share_values, carry_witnesses_decimal) = share_values_and_carries(
            &coefficient_messages_by_shamir_index,
            2,
            rns_prime,
            ring_degree,
        );
        assert_eq!(share_values, expected_share_values);
        let carry_witnesses = carry_witnesses_decimal
            .iter()
            .map(|carry| carry.parse::<i128>().expect("carry witness"))
            .collect::<Vec<_>>();
        let share_values_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssShareValueVector",
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shareValues": share_values,
        }))
        .expect("share values hash");
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "PrivateVssLocalVerificationRoot",
            "fixture": proof_fixture_label,
            "rnsLimbIndex": rns_limb_index,
        }))
        .expect("private VSS proof randomness seed");
        let private_vss_share_proof =
            private_vss_share_succinct_proof_record(PrivateVssShareSuccinctProofGenerationInput {
                setup_context: &setup_context,
                public_matrix_seed_hash: &public_matrix_seed_hash,
                private_envelope_aad_hash: &private_envelope_aad_hash,
                source_trustee_identity: "trustee-0",
                source_trustee_roster_position: 0,
                recipient_identity: "trustee-2",
                recipient_roster_position: 2,
                source_trustee_commitment_root: &source_trustee_commitment_root,
                rns_limb_index,
                rns_prime,
                ring_degree,
                coefficient_commitment_roots: &coefficient_commitment_roots,
                share_values: &share_values,
                share_values_hash: &share_values_hash,
                coefficient_commitments: &coefficient_commitments,
                witness: &PrivateVssShareSuccinctProofWitness {
                    coefficient_messages_by_shamir_index,
                    opening_randomness_by_shamir_index,
                    carry_witnesses,
                },
                proof_randomness_seed_hex: &proof_randomness_seed_hex,
            })
            .expect("private VSS share proof");
        limb_object.remove("aggregateOpening");
        limb_object.remove("carryWitnessesDecimal");
        limb_object.insert("privateVssShareProof".to_string(), private_vss_share_proof);
    }

    let transported_proof_material = {
        let proof_records = request["privateEnvelope"]["rnsShareOpenings"]
            .as_array()
            .expect("private VSS limb openings")
            .iter()
            .map(|limb_opening| &limb_opening["privateVssShareProof"])
            .collect::<Vec<_>>();
        private_vss_proof_material_reference_set(&proof_records)
    };
    request["transportedPrivateVssShareProofMaterial"] = transported_proof_material;

    request
}

fn private_vss_proof_material_reference_set(
    proof_records: &[&serde_json::Value],
) -> serde_json::Value {
    let proof_materials = proof_records
        .iter()
        .map(|proof_record| {
            serde_json::json!({
                "objectType": "SetupTransportedPrivateVssShareProofMaterial",
                "proofFamily": "vss-opening-carry",
                "proofMaterialRoot": proof_record["proofMaterialRoot"],
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "objectType": "SetupTransportedPrivateVssShareProofMaterialSet",
        "proofFamily": "vss-opening-carry",
        "proofMaterials": proof_materials,
    })
}

fn coefficient_message_fixture(
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    (0..ring_degree)
        .map(|coefficient_position| {
            let value = ((rns_limb_index as u64 + 1) * (shamir_coefficient_index + 2))
                + (coefficient_position as u64 % 7);
            value % rns_prime
        })
        .collect()
}

fn randomness_fixture(
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (rns_limb_index
                        + shamir_coefficient_index as usize
                        + randomness_column_index
                        + coefficient_position)
                        % 3
                    {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    }
                })
                .collect()
        })
        .collect()
}

fn share_values_and_carries(
    coefficient_messages_by_shamir_index: &[Vec<u64>],
    recipient_roster_position: usize,
    rns_prime: u64,
    ring_degree: usize,
) -> (Vec<u64>, Vec<String>) {
    let trustee_point = u128::from((recipient_roster_position + 1) as u64);
    let mut trustee_point_powers = Vec::new();
    let mut power = 1_u128;
    for _ in 0..coefficient_messages_by_shamir_index.len() {
        trustee_point_powers.push(power);
        power *= trustee_point;
    }

    let mut share_values = Vec::with_capacity(ring_degree);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let unreduced_value = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .map(|(coefficient_message, trustee_point_power)| {
                u128::from(coefficient_message[coefficient_position]) * trustee_point_power
            })
            .sum::<u128>();
        share_values.push((unreduced_value % u128::from(rns_prime)) as u64);
        carry_witnesses.push((unreduced_value / u128::from(rns_prime)).to_string());
    }

    (share_values, carry_witnesses)
}

fn aggregate_opening_columns(
    coefficient_openings: &[serde_json::Value],
    recipient_roster_position: usize,
    ring_degree: usize,
) -> Vec<Vec<i128>> {
    let trustee_point = i128::try_from(recipient_roster_position + 1).expect("trustee point");
    let mut trustee_point_powers = Vec::new();
    let mut power = 1_i128;
    for _ in coefficient_openings {
        trustee_point_powers.push(power);
        power *= trustee_point;
    }

    let first_opening = coefficient_openings
        .first()
        .expect("coefficient openings must be non-empty");
    let randomness_width = first_opening["randomnessByColumn"]
        .as_array()
        .expect("randomness columns")
        .len();
    let mut aggregate_columns = vec![vec![0_i128; ring_degree]; randomness_width];
    for (opening, trustee_point_power) in coefficient_openings.iter().zip(trustee_point_powers) {
        let randomness_columns = opening["randomnessByColumn"]
            .as_array()
            .expect("randomness columns");
        for (column_index, randomness_column) in randomness_columns.iter().enumerate() {
            let coefficients = randomness_column.as_array().expect("randomness column");
            for (coefficient_position, coefficient) in coefficients.iter().enumerate() {
                aggregate_columns[column_index][coefficient_position] += coefficient
                    .as_i64()
                    .map(i128::from)
                    .expect("randomness coefficient")
                    * trustee_point_power;
            }
        }
    }

    aggregate_columns
}
