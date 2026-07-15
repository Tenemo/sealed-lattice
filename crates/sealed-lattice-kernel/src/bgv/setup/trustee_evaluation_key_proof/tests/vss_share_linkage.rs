use super::super::relation::{
    SetupProofStatement, VssCommittedMaterialWitness, VssShareLinkageCommitment,
    VssShareLinkageItem, VssShareLinkageStatement, masked_claim_bounds_for_global_claim,
    masked_claim_lift_residue_count_for_moduli,
};
use super::super::{
    VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT, VSS_PUBLIC_SHARE_LINKAGE_TRIT_CLAIM_MASK_DIGIT_COUNT,
};
use super::*;
use crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_TRIT_BASE;
use crate::encoding::CanonicalErrorCode;
use num_bigint::BigInt;
use serde_json::json;

#[test]
fn vss_share_linkage_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = vss_share_linkage_instance();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify share-linkage proof");

    let (invalid_share_statement, mut invalid_share_witness) = vss_share_linkage_instance();
    let recipient_messages =
        invalid_share_witness.vss_public_recipient_share_messages_by_item_mut();
    recipient_messages[0][0] =
        (recipient_messages[0][0] + 1) % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(
            &invalid_share_statement,
            &invalid_share_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a recipient-share witness that no longer opens its committed material"
    );

    // A witness coefficient message that disagrees with the committed material
    // makes the regenerated material root differ from the published one, so
    // the prover refuses fail-closed before any proof is produced.
    let (mismatched_material_statement, mut mismatched_material_witness) =
        vss_share_linkage_instance();
    let coefficient_messages =
        mismatched_material_witness.vss_public_coefficient_messages_by_shamir_index_mut();
    coefficient_messages[0][0] =
        (coefficient_messages[0][0] + 1) % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(
            &mismatched_material_statement,
            &mismatched_material_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a witness message that does not open the published material commitment"
    );

    let (mut wrong_context_statement, wrong_context_witness) = vss_share_linkage_instance();
    wrong_context_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .recipient_share_commitment
        .commitment_context_hash = repeated_hash("a7");
    assert!(
        prove_evaluation_key_share(
            &wrong_context_statement,
            &wrong_context_witness,
            PROOF_RANDOMNESS_SEED,
        )
        .is_err(),
        "proving must derive the tree domain from the public commitment context hash"
    );

    let (mut tampered_statement, _unused_witness) = vss_share_linkage_instance();
    tampered_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .recipient_share_commitment
        .material_roots_by_commitment_field[0][0] ^= 0x01;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the published recipient-share material root must reject"
    );

    let (mut tampered_additional_statement, _unused_witness) = vss_share_linkage_instance();
    tampered_additional_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .additional_linkage_items[0]
        .recipient_share_commitment
        .material_roots_by_commitment_field[0][0] ^= 0x01;

    assert!(
        verify_evaluation_key_share(&tampered_additional_statement, &proof).is_err(),
        "tampering with an additional recipient-share material root must reject"
    );
}

#[test]
fn vss_share_linkage_proof_rejects_tampered_committed_material_openings() {
    let (statement, witness) = vss_share_linkage_instance();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let encoded_proof = encode_trustee_evaluation_key_proof(&proof);

    let mut proof_with_tampered_material_row =
        decode_trustee_evaluation_key_proof(&statement, &encoded_proof).expect("decode proof");
    let opened_residue = &mut proof_with_tampered_material_row.limb_proofs[0]
        .material_query_openings[0][0]
        .rows[0][0];
    *opened_residue = if *opened_residue == 0 { 1 } else { 0 };
    let row_error = verify_evaluation_key_share(&statement, &proof_with_tampered_material_row)
        .expect_err("a changed opened material row must reject without changing the statement");
    assert_eq!(row_error.code, CanonicalErrorCode::InvalidProtocolObject);

    let mut proof_with_tampered_material_authentication_node =
        decode_trustee_evaluation_key_proof(&statement, &encoded_proof).expect("decode proof");
    let authentication_node = proof_with_tampered_material_authentication_node.limb_proofs[0]
        .material_batch_openings[0]
        .authentication_nodes
        .first_mut()
        .expect("small-ring material opening has an authentication node");
    authentication_node[0] ^= 0x01;
    let authentication_error = verify_evaluation_key_share(
        &statement,
        &proof_with_tampered_material_authentication_node,
    )
    .expect_err("a changed material authentication node must reject against the statement root");
    assert_eq!(
        authentication_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert_eq!(
        authentication_error.message,
        "material tree query openings failed batched Merkle verification against the statement root"
    );
}

#[test]
fn vss_threshold_aggregate_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = vss_threshold_aggregate_instance();
    let proof = prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED)
        .expect("prove threshold-aggregate");

    verify_evaluation_key_share(&statement, &proof).expect("verify threshold-aggregate proof");

    // A summand witness that no longer sums to the committed aggregate makes the
    // regenerated recipient-share material root differ from the published one,
    // so the prover refuses fail-closed before producing a proof.
    let (mismatched_statement, mut mismatched_witness) = vss_threshold_aggregate_instance();
    let coefficient_messages =
        mismatched_witness.vss_public_coefficient_messages_by_shamir_index_mut();
    coefficient_messages[0][0] =
        (coefficient_messages[0][0] + 1) % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(
            &mismatched_statement,
            &mismatched_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a summand witness that does not open its published recipient-share material"
    );

    // An aggregate witness that is not the modular sum of the summands breaks the
    // unit-point lincheck, so proving refuses.
    let (bad_sum_statement, mut bad_sum_witness) = vss_threshold_aggregate_instance();
    let recipient_messages = bad_sum_witness.vss_public_recipient_share_messages_by_item_mut();
    recipient_messages[0][0] =
        (recipient_messages[0][0] + 1) % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(&bad_sum_statement, &bad_sum_witness, PROOF_RANDOMNESS_SEED)
            .is_err(),
        "proving must reject an aggregate witness that is not the modular sum of the summands"
    );

    // Tampering with the published aggregate (recipient) material root rejects.
    let (mut tampered_aggregate_statement, _unused_witness) = vss_threshold_aggregate_instance();
    tampered_aggregate_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .recipient_share_commitment
        .material_roots_by_commitment_field[0][0] ^= 0x01;
    assert!(
        verify_evaluation_key_share(&tampered_aggregate_statement, &proof).is_err(),
        "tampering with the published aggregate material root must reject"
    );

    // Tampering with a summand (coefficient) material root rejects.
    let (mut tampered_summand_statement, _unused_witness) = vss_threshold_aggregate_instance();
    tampered_summand_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .coefficient_commitments[0]
        .material_roots_by_commitment_field[0][0] ^= 0x01;
    assert!(
        verify_evaluation_key_share(&tampered_summand_statement, &proof).is_err(),
        "tampering with a published summand material root must reject"
    );

    // Flipping the threshold-aggregate flag changes the relation (unit point vs
    // recipient trustee point) and the statement hash, so the proof no longer
    // verifies against the mutated statement.
    let (mut flipped_flag_statement, _unused_witness) = vss_threshold_aggregate_instance();
    flipped_flag_statement
        .vss_share_linkage_mut()
        .expect("statement")
        .is_threshold_aggregate = false;
    assert!(
        verify_evaluation_key_share(&flipped_flag_statement, &proof).is_err(),
        "clearing the threshold-aggregate flag must reject the aggregate proof"
    );
}

// Build a single-recipient threshold-aggregate instance: three source recipient
// shares (the summands) and their modular sum T with the per-coefficient wrap,
// proved through the share-linkage relation with a unit evaluation point.
fn vss_threshold_aggregate_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let source_message_modulus = DATA_PRIMES[0];
    let source_rns_limb_index = 0_usize;
    let recipient_roster_position = 2_u64;
    let summand_count = 3_usize;

    // Three summands with large residues so several coefficient positions wrap
    // the modulus when summed, exercising the wrap (carry) witness.
    let summand_messages: Vec<Vec<u64>> = (0..summand_count)
        .map(|summand_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    let base = source_message_modulus / 3 * 2;
                    let jitter = (summand_index as u64 * 131 + coefficient_position as u64 * 17)
                        % (source_message_modulus / 6).max(1);
                    (base + jitter) % source_message_modulus
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut aggregate_values = Vec::with_capacity(ring_degree);
    let mut wrap_values = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let summed = summand_messages.iter().fold(0_u128, |sum, messages| {
            sum + u128::from(messages[coefficient_position])
        });
        aggregate_values.push((summed % u128::from(source_message_modulus)) as u64);
        wrap_values.push((summed / u128::from(source_message_modulus)) as i64);
    }
    assert!(
        wrap_values.iter().any(|wrap| *wrap > 0),
        "threshold-aggregate fixture must exercise wrapped coefficient sums"
    );

    let summand_commitment_computations: Vec<CommitmentComputationForTest> = summand_messages
        .iter()
        .enumerate()
        .map(|(summand_index, messages)| {
            commitment_computation_for_test(
                "recipient-share",
                json!({
                    "testPurpose": "threshold-aggregate-proof",
                    "sourceRosterPosition": summand_index,
                    "recipientRosterPosition": recipient_roster_position,
                }),
                source_rns_limb_index,
                source_message_modulus,
                ring_degree,
                messages,
            )
        })
        .collect();
    let aggregate_commitment_computation = commitment_computation_for_test(
        "aggregate-threshold-share",
        json!({
            "testPurpose": "threshold-aggregate-proof",
            "recipientRosterPosition": recipient_roster_position,
        }),
        source_rns_limb_index,
        source_message_modulus,
        ring_degree,
        &aggregate_values,
    );

    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            setup_context_hash: repeated_hash("11"),
            trustee_identity: "vss-threshold-aggregate".to_string(),
            trustee_roster_position: 0,
            binding_roots: Vec::new(),
        },
        ring_degree,
        proof: SetupProofStatement::VssShareLinkage(VssShareLinkageStatement {
            public_matrix_seed_hash: repeated_hash("bc"),
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            recipient_identity: format!("trustee-{recipient_roster_position}"),
            recipient_roster_position,
            source_coefficient_commitment_root: repeated_hash("91"),
            source_recipient_share_commitment_root: repeated_hash("92"),
            source_rns_limb_index,
            coefficient_commitment_roots: summand_commitment_computations
                .iter()
                .map(|computation| computation.commitment_root.clone())
                .collect(),
            coefficient_commitments: summand_commitment_computations
                .iter()
                .map(|computation| computation.commitment.clone())
                .collect(),
            recipient_share_commitment_root: aggregate_commitment_computation
                .commitment_root
                .clone(),
            recipient_share_commitment: aggregate_commitment_computation.commitment.clone(),
            additional_linkage_items: Vec::new(),
            is_threshold_aggregate: true,
        }),
    };
    statement
        .validate_shape()
        .expect("threshold-aggregate statement");

    // Bound-commitment order: the three summand slots, then the aggregate.
    let bound_commitment_computations: Vec<&CommitmentComputationForTest> =
        summand_commitment_computations
            .iter()
            .chain(std::iter::once(&aggregate_commitment_computation))
            .collect();

    let witness = super::super::relation::TrusteeEvaluationKeyWitness::VssShareLinkage {
        coefficient_messages_by_shamir_index: summand_messages
            .iter()
            .map(|messages| {
                messages
                    .iter()
                    .map(|value| i64::try_from(*value).expect("summand fits i64"))
                    .collect()
            })
            .collect(),
        recipient_share_messages_by_item: vec![
            aggregate_values
                .iter()
                .map(|value| i64::try_from(*value).expect("aggregate fits i64"))
                .collect(),
        ],
        carry_witnesses_by_item: vec![wrap_values],
        committed_material: VssCommittedMaterialWitness {
            vss_committed_material_seeds_by_bound_message: bound_commitment_computations
                .iter()
                .map(|computation| computation.material_seed_hex.clone())
                .collect(),
        },
    };

    (statement, witness)
}

#[test]
fn prover_and_verifier_transcript_order_matches_for_share_linkage() {
    use crate::bgv::setup::transcript_order_audit::{
        capture_transcript_order_audit, run_length_encode_transcript_order_audit,
    };

    let (statement, witness) = vss_threshold_aggregate_instance();
    let (proof_result, prover_events) = capture_transcript_order_audit(|| {
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED)
    });
    let proof = proof_result.expect("audit proof generation");
    let (verification_result, verifier_events) =
        capture_transcript_order_audit(|| verify_evaluation_key_share(&statement, &proof));

    verification_result.expect("audit proof verification");
    assert_eq!(prover_events, verifier_events);
    let event_count = prover_events.len();
    let transcripts = run_length_encode_transcript_order_audit(&prover_events);
    let audit_artifact = serde_json::json!({
        "formatVersion": 1,
        "proofFamily": "trustee-evaluation-key",
        "fixture": {
            "proofRelation": "threshold-aggregate-share-linkage",
            "ringDegree": statement.ring_degree,
            "sourceRnsLimbIndex": 0,
            "summandCount": 3,
        },
        "eventCount": event_count,
        "transcripts": transcripts,
    });
    let expected_artifact: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/fiat-shamir-trustee-evaluation-key-transcript-order.json"
    )))
    .expect("parse transcript-order audit artifact");
    assert_eq!(audit_artifact, expected_artifact);
}

fn vss_share_linkage_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("bc");
    let primary_item = share_linkage_item_for_test("primary", ring_degree, 0, 2, 3, 10);
    let mut same_source_additional_item =
        share_linkage_item_for_test("same-source-additional", ring_degree, 0, 4, 3, 10);
    same_source_additional_item.coefficient_commitment_computations =
        primary_item.coefficient_commitment_computations.clone();
    let additional_item = share_linkage_item_for_test("additional", ring_degree, 1, 3, 2, 70);

    let source_coefficient_commitment_root = repeated_hash("91");
    let source_recipient_share_commitment_root = repeated_hash("92");
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            setup_context_hash: repeated_hash("11"),
            trustee_identity: "vss-share-linkage".to_string(),
            trustee_roster_position: 0,
            binding_roots: Vec::new(),
        },
        ring_degree,
        proof: SetupProofStatement::VssShareLinkage(VssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            recipient_identity: primary_item.recipient_identity.clone(),
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root,
            source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            coefficient_commitment_roots: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.commitment_root.clone())
                .collect(),
            coefficient_commitments: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.commitment.clone())
                .collect(),
            recipient_share_commitment_root: primary_item
                .recipient_share_commitment_computation
                .commitment_root
                .clone(),
            recipient_share_commitment: primary_item
                .recipient_share_commitment_computation
                .commitment
                .clone(),
            additional_linkage_items: vec![
                share_linkage_item_statement(&same_source_additional_item),
                share_linkage_item_statement(&additional_item),
            ],
            is_threshold_aggregate: false,
        }),
    };
    statement.validate_shape().expect("share-linkage statement");
    let layout = LimbColumnLayout::new(&statement, 0).expect("share-linkage layout");
    assert_eq!(
        layout.vss_public_coefficient_relation_columns, 8,
        "three share-linkage items bind eight public coefficient commitments"
    );
    assert_eq!(
        layout.vss_public_coefficient_columns, 5,
        "the share-linkage trace keeps one coefficient column per unique commitment opening"
    );
    assert_eq!(
        layout.vss_public_item_columns, 3,
        "the share-linkage statement should batch three carried share relations"
    );
    assert_eq!(
        layout.base_ring_degree, 128,
        "the share-linkage layout keeps the source ring degree as the proof row count"
    );
    assert_eq!(
        layout.ring_degree, 128,
        "share-linkage batches items by columns without increasing the trace row count"
    );
    assert_eq!(
        layout.vss_committed_material_bound_message_count(),
        8,
        "five unique coefficient trees plus three recipient-share trees are bound"
    );
    // Each of the eight messages contributes both digits' base-three trits
    // (17 + 13 = 30), and the three item carries bring the total to 243.
    assert_eq!(
        layout.consistency_vector_count(),
        243,
        "three item carries plus eight messages of thirty trits each"
    );
    assert!(
        layout.consistency_vector_count()
            > layout.vss_public_item_columns
                + layout.vss_public_message_vector_count()
                    * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "trit-granular claims must expand beyond the whole-digit claim count"
    );
    assert_eq!(
        layout.claim_count(),
        layout.consistency_vector_count() * layout.consistency_repetitions
    );
    let later_commitment_limb_layout =
        LimbColumnLayout::new(&statement, 1).expect("share-linkage second limb layout");
    assert_eq!(
        layout.vss_public_coefficient_decoder_digit_count(),
        crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "share-linkage coefficient digits must carry verifier-side decoder rows"
    );
    assert_eq!(
        layout.vss_public_recipient_decoder_digit_count(),
        crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "share-linkage recipient digits must carry verifier-side decoder rows"
    );
    assert!(
        layout.vss_public_message_encoding_column_count(0)
            > crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "share-linkage coefficient messages must carry digit and trit columns"
    );
    assert!(
        layout.vss_public_message_encoding_column_count(layout.vss_public_coefficient_columns)
            > crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "share-linkage recipient messages must carry digit and trit columns"
    );
    assert!(
        layout.vss_public_message_trit_count(layout.vss_public_coefficient_columns, 0) > 0,
        "share-linkage recipient digits must carry trit decoder columns"
    );
    assert!(
        later_commitment_limb_layout.vss_public_coefficient_decoder_digit_count()
            == crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT
            && later_commitment_limb_layout.vss_public_recipient_decoder_digit_count()
                == crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT,
        "later share-linkage limbs must also carry decoder-backed encodings"
    );
    assert_eq!(
        later_commitment_limb_layout.consistency_vector_count(),
        layout.consistency_vector_count(),
        "decoder-backed limbs must keep the same cross-field claim set"
    );
    assert_eq!(
        later_commitment_limb_layout.vss_public_message_encoding_columns(),
        layout.vss_public_message_encoding_columns(),
        "all share-linkage limbs should use the same decoder-backed message width"
    );

    // Bound-commitment order (matching vss_committed_material_bound_commitments):
    // the five unique coefficient slots (primary's three, then additional's
    // two), then the three items' recipient-share commitments. same_source
    // shares primary's coefficient trees, so it adds no new coefficient slots.
    let bound_commitment_computations: Vec<&CommitmentComputationForTest> = primary_item
        .coefficient_commitment_computations
        .iter()
        .chain(additional_item.coefficient_commitment_computations.iter())
        .chain([
            &primary_item.recipient_share_commitment_computation,
            &same_source_additional_item.recipient_share_commitment_computation,
            &additional_item.recipient_share_commitment_computation,
        ])
        .collect();

    let witness = super::super::relation::TrusteeEvaluationKeyWitness::VssShareLinkage {
        coefficient_messages_by_shamir_index: primary_item
            .coefficient_messages
            .iter()
            .chain(additional_item.coefficient_messages.iter())
            .map(|messages| {
                messages
                    .iter()
                    .map(|value| i64::try_from(*value).expect("message fits i64"))
                    .collect()
            })
            .collect(),
        recipient_share_messages_by_item: vec![
            primary_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
            same_source_additional_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
            additional_item
                .recipient_share_values
                .iter()
                .map(|value| i64::try_from(*value).expect("share fits i64"))
                .collect(),
        ],
        carry_witnesses_by_item: vec![
            primary_item.recipient_share_carry_values,
            same_source_additional_item.recipient_share_carry_values,
            additional_item.recipient_share_carry_values,
        ],
        committed_material: VssCommittedMaterialWitness {
            vss_committed_material_seeds_by_bound_message: bound_commitment_computations
                .iter()
                .map(|computation| computation.material_seed_hex.clone())
                .collect(),
        },
    };

    (statement, witness)
}

fn share_linkage_item_statement(item: &ShareLinkageItemForTest) -> VssShareLinkageItem {
    VssShareLinkageItem {
        source_trustee_identity: "trustee-0".to_string(),
        source_trustee_roster_position: 0,
        source_coefficient_commitment_root: repeated_hash("91"),
        source_recipient_share_commitment_root: repeated_hash("92"),
        recipient_identity: item.recipient_identity.clone(),
        recipient_roster_position: item.recipient_roster_position,
        source_rns_limb_index: item.source_rns_limb_index,
        coefficient_commitment_roots: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.commitment_root.clone())
            .collect(),
        coefficient_commitments: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.commitment.clone())
            .collect(),
        recipient_share_commitment_root: item
            .recipient_share_commitment_computation
            .commitment_root
            .clone(),
        recipient_share_commitment: item
            .recipient_share_commitment_computation
            .commitment
            .clone(),
    }
}

struct ShareLinkageItemForTest {
    recipient_identity: String,
    recipient_roster_position: u64,
    source_rns_limb_index: usize,
    coefficient_messages: Vec<Vec<u64>>,
    recipient_share_values: Vec<u64>,
    recipient_share_carry_values: Vec<i64>,
    coefficient_commitment_computations: Vec<CommitmentComputationForTest>,
    recipient_share_commitment_computation: CommitmentComputationForTest,
}

fn share_linkage_item_for_test(
    item_label: &str,
    ring_degree: usize,
    source_rns_limb_index: usize,
    recipient_roster_position: u64,
    coefficient_count: usize,
    seed_offset: i64,
) -> ShareLinkageItemForTest {
    let source_message_modulus = DATA_PRIMES[source_rns_limb_index];
    let recipient_trustee_point = recipient_roster_position + 1;
    let coefficient_messages = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    if coefficient_index % 11 == shamir_coefficient_index {
                        source_message_modulus - 4 - shamir_coefficient_index as u64
                    } else {
                        (17 + seed_offset as u64
                            + 19 * shamir_coefficient_index as u64
                            + 23 * coefficient_index as u64)
                            % source_message_modulus
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut recipient_share_values = Vec::with_capacity(ring_degree);
    let mut recipient_share_carry_values = Vec::with_capacity(ring_degree);
    let mut trustee_point_powers = Vec::with_capacity(coefficient_count);
    let mut trustee_point_power = 1_u128;
    for _ in 0..coefficient_count {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power *= u128::from(recipient_trustee_point);
    }
    for coefficient_index in 0..ring_degree {
        let lifted_share = coefficient_messages
            .iter()
            .zip(trustee_point_powers.iter())
            .fold(0_u128, |sum, (messages, point_power)| {
                sum + u128::from(messages[coefficient_index]) * *point_power
            });
        recipient_share_values.push((lifted_share % u128::from(source_message_modulus)) as u64);
        recipient_share_carry_values
            .push((lifted_share / u128::from(source_message_modulus)) as i64);
    }
    assert!(
        recipient_share_carry_values
            .iter()
            .any(|carry_value| *carry_value > 0),
        "share-linkage fixture must exercise carried share values"
    );

    let coefficient_commitment_computations = coefficient_messages
        .iter()
        .enumerate()
        .map(|(shamir_coefficient_index, messages)| {
            commitment_computation_for_test(
                "coefficient",
                json!({
                    "testPurpose": "share-linkage-proof",
                    "itemLabel": item_label,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                }),
                source_rns_limb_index,
                source_message_modulus,
                ring_degree,
                messages,
            )
        })
        .collect::<Vec<_>>();
    let recipient_share_commitment_computation = commitment_computation_for_test(
        "recipient-share",
        json!({
            "testPurpose": "share-linkage-proof",
            "itemLabel": item_label,
            "recipientRosterPosition": recipient_roster_position,
        }),
        source_rns_limb_index,
        source_message_modulus,
        ring_degree,
        &recipient_share_values,
    );

    ShareLinkageItemForTest {
        recipient_identity: format!("trustee-{recipient_roster_position}"),
        recipient_roster_position,
        source_rns_limb_index,
        coefficient_messages,
        recipient_share_values,
        recipient_share_carry_values,
        coefficient_commitment_computations,
        recipient_share_commitment_computation,
    }
}

#[derive(Clone)]
struct CommitmentComputationForTest {
    commitment: VssShareLinkageCommitment,
    commitment_root: String,
    // The holder's regeneration seed, threaded into the witness so the prover
    // rebuilds byte-identical material trees and the binding rows hold.
    material_seed_hex: String,
}

fn commitment_computation_for_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
) -> CommitmentComputationForTest {
    let material = test_committed_material_commitment(
        commitment_role,
        commitment_context,
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients,
        rns_prime,
    );

    CommitmentComputationForTest {
        commitment: material.commitment,
        commitment_root: material.commitment_root,
        material_seed_hex: material.material_seed_hex,
    }
}

// The cross-limb consistency soundness mechanism the other setup families use
// requires a masked claim's CRT lift to leave at least one commitment field
// unconsumed: the lift pins the centered integer from the consumed fields and
// the remaining field's residue is the check that catches an inconsistent
// per-field witness. Message consistency claims are trit-granular with witness
// bound two. Under the twenty-repetition eight-bit schedule and 58-digit mask,
// every claim class consumes two of the three commitment fields and leaves one
// check field. The separate assertion below pins the trit witness bound because
// the residue count alone cannot distinguish it from a wider witness.
#[test]
fn vss_share_linkage_consistency_lift_geometry_is_pinned() {
    let (statement, _witness) = vss_share_linkage_instance();
    let field_moduli = statement
        .proof_limb_indices()
        .iter()
        .map(|limb_index| DATA_PRIMES[*limb_index])
        .collect::<Vec<_>>();
    let family_shape = statement.family_shape();
    let consistency_repetitions = family_shape.consistency_repetitions();
    let item_count = statement
        .vss_share_linkage()
        .expect("share linkage statement")
        .item_count();

    for (claim_class, global_claim_id) in [
        ("primary carry", 0_u64),
        ("additional-item carry", consistency_repetitions as u64),
        (
            "message trit",
            (item_count * consistency_repetitions) as u64,
        ),
    ] {
        let (lower_bound, upper_bound) =
            masked_claim_bounds_for_global_claim(&statement, global_claim_id)
                .expect("masked claim bounds");
        let required_residue_count = masked_claim_lift_residue_count_for_moduli(
            field_moduli.iter().copied(),
            &lower_bound,
            &upper_bound,
        );
        eprintln!(
            "share-linkage {claim_class} claim: clear/mask window [{lower_bound}, {upper_bound}] \
             ({} bits), lift consumes {required_residue_count} of {} fields",
            upper_bound.bits(),
            field_moduli.len(),
        );
        assert_eq!(
            required_residue_count,
            field_moduli.len() - 1,
            "share-linkage {claim_class} lift must consume fewer than all commitment fields \
             so the remaining field is the check field; if this moved, re-derive the \
             check-field decision record",
        );
    }

    // A message consistency claim lifts one base-three trit with bound two.
    // The negated lower claim bound recovers its clear span and pins that witness
    // bound independently of the residue-count check above.
    let share_linkage = statement
        .vss_share_linkage()
        .expect("share linkage statement");
    let coefficient_bound = (1_i128 << family_shape.consistency_coefficient_bits()) - 1;
    let packed_ring_degree = share_linkage
        .packed_ring_degree(statement.ring_degree)
        .expect("packed ring degree");
    let expected_trit_clear_span = BigInt::from(
        i128::from(VSS_PUBLIC_MESSAGE_TRIT_BASE - 1)
            * coefficient_bound
            * packed_ring_degree as i128,
    );
    let (message_trit_lower, _message_trit_upper) = masked_claim_bounds_for_global_claim(
        &statement,
        (item_count * consistency_repetitions) as u64,
    )
    .expect("message trit masked claim bounds");
    assert_eq!(
        -message_trit_lower, expected_trit_clear_span,
        "message consistency claims must bind a single base-three trit (bound two); a wider clear \
         span means the claim reverted to whole-digit granularity and widened the leakage window",
    );

    // The mask selection must pair with the claim-bound selection: every
    // vector below the item count is a carry claim and takes the carry mask,
    // including the additional linkage items' carries.
    assert!(
        item_count > 1,
        "fixture must cover additional linkage items"
    );
    for item_vector_index in 0..item_count {
        let global_claim_id = (item_vector_index * consistency_repetitions) as u64;
        assert_eq!(
            super::super::relation::claim_mask_digit_count_for_global_claim(
                &statement,
                global_claim_id,
            ),
            VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT,
            "carry vector {item_vector_index} must take the carry claim mask",
        );
    }
    assert_eq!(
        super::super::relation::claim_mask_digit_count_for_global_claim(
            &statement,
            (item_count * consistency_repetitions) as u64,
        ),
        VSS_PUBLIC_SHARE_LINKAGE_TRIT_CLAIM_MASK_DIGIT_COUNT,
        "the first message trit vector after the carries must take the share-linkage claim mask",
    );
}
