use super::super::relation::{
    VssShareLinkageCommitment, VssShareLinkageItem, VssShareLinkageStatement,
    masked_claim_bounds_for_global_claim, masked_claim_lift_residue_count_for_moduli,
};
use super::super::{
    VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT, VSS_PUBLIC_SHARE_LINKAGE_DIGIT_CLAIM_MASK_DIGIT_COUNT,
};
use super::*;
use crate::bgv::setup::vss_commitment::{
    VSS_PUBLIC_MESSAGE_TRIT_BASE, VssPublicCommitmentOpeningInput,
    compute_vss_public_commitment_from_opening, vss_public_canonical_message_digit_columns,
};
use num_bigint::BigInt;
use serde_json::json;

#[test]
fn vss_share_linkage_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = vss_share_linkage_instance();
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify share-linkage proof");

    let (invalid_share_statement, mut invalid_share_witness) = vss_share_linkage_instance();
    invalid_share_witness.vss_public_recipient_share_messages_by_item[0][0] =
        (invalid_share_witness.vss_public_recipient_share_messages_by_item[0][0] + 1)
            % i64::try_from(DATA_PRIMES[0]).expect("modulus fits i64");
    assert!(
        prove_evaluation_key_share(
            &invalid_share_statement,
            &invalid_share_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a witness whose lifted share relation does not match"
    );

    let (non_ternary_statement, mut non_ternary_witness) = vss_share_linkage_instance();
    non_ternary_witness.vss_public_recipient_share_opening_randomness_by_item[1][0][0] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_ternary_statement,
            &non_ternary_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject non-ternary opening randomness"
    );

    let (mut tampered_statement, _unused_witness) = vss_share_linkage_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_statement
        .vss_share_linkage
        .as_mut()
        .expect("statement")
        .recipient_share_commitment
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the public recipient-share commitment must reject"
    );

    let (mut tampered_opening_statement, _unused_witness) = vss_share_linkage_instance();
    tampered_opening_statement
        .vss_share_linkage
        .as_mut()
        .expect("statement")
        .coefficient_opening_roots[0] = repeated_hash("fa");

    assert!(
        verify_evaluation_key_share(&tampered_opening_statement, &proof).is_err(),
        "tampering with a coefficient opening root must reject"
    );

    let (mut tampered_additional_statement, _unused_witness) = vss_share_linkage_instance();
    let modulus = DATA_PRIMES[0];
    let coordinate = &mut tampered_additional_statement
        .vss_share_linkage
        .as_mut()
        .expect("statement")
        .additional_linkage_items[0]
        .recipient_share_commitment
        .coordinates_by_commitment_modulus[0][0];
    *coordinate = (*coordinate + 1) % modulus;

    assert!(
        verify_evaluation_key_share(&tampered_additional_statement, &proof).is_err(),
        "tampering with an additional recipient-share commitment must reject"
    );
}

fn vss_share_linkage_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("bc");
    let primary_item = share_linkage_item_for_test(
        "primary",
        &public_matrix_seed_hash,
        ring_degree,
        0,
        2,
        3,
        10,
    );
    let mut same_source_additional_item = share_linkage_item_for_test(
        "same-source-additional",
        &public_matrix_seed_hash,
        ring_degree,
        0,
        4,
        3,
        10,
    );
    same_source_additional_item.coefficient_commitment_computations =
        primary_item.coefficient_commitment_computations.clone();
    let additional_item = share_linkage_item_for_test(
        "additional",
        &public_matrix_seed_hash,
        ring_degree,
        1,
        3,
        2,
        70,
    );

    let source_coefficient_commitment_root = repeated_hash("91");
    let source_recipient_share_commitment_root = repeated_hash("92");
    let share_linkage_statement_root = repeated_hash("93");
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: super::super::VSS_SHARE_LINKAGE_PROOF_FAMILY.to_string(),
            ceremony_id: "vss-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "vss-share-linkage".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: vec![(
                "shareLinkageStatementRoot".to_string(),
                share_linkage_statement_root,
            )],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        vss_share_linkage: Some(VssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            recipient_identity: primary_item.recipient_identity.clone(),
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root,
            source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            source_message_modulus: primary_item.source_message_modulus,
            coefficient_commitment_roots: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.commitment_root.clone())
                .collect(),
            coefficient_opening_roots: primary_item
                .coefficient_commitment_computations
                .iter()
                .map(|computation| computation.opening_root.clone())
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
            recipient_share_opening_root: primary_item
                .recipient_share_commitment_computation
                .opening_root
                .clone(),
            recipient_share_commitment: primary_item
                .recipient_share_commitment_computation
                .commitment
                .clone(),
            additional_linkage_items: vec![
                share_linkage_item_statement(&same_source_additional_item),
                share_linkage_item_statement(&additional_item),
            ],
        }),
        same_secret_bridge: None,
        target_decryption_share: None,
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
    assert!(
        layout.vss_public_randomness_columns > 0,
        "opening randomness must remain in the opening lincheck"
    );
    // With Branch 2 the message consistency claims are trit-granular: each of the
    // eight messages (five coefficient + three item) contributes both digits'
    // base-three trits (17 + 13 = 30 for this fixture's message modulus), so the
    // count is the three item carries plus 8 * 30 = 240 message trits. This is
    // strictly more than the old whole-digit count (3 + 8 * 2 = 19); the wider
    // claim set with the narrower per-trit witness is what tightens the leakage.
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

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: primary_item
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
        vss_public_recipient_share_messages: primary_item
            .recipient_share_values
            .iter()
            .map(|value| i64::try_from(*value).expect("share fits i64"))
            .collect(),
        vss_public_coefficient_opening_randomness_by_shamir_index: primary_item
            .coefficient_randomness
            .iter()
            .chain(additional_item.coefficient_randomness.iter())
            .cloned()
            .collect(),
        vss_public_recipient_share_opening_randomness: primary_item
            .recipient_share_randomness
            .clone(),
        vss_public_carry_witnesses: primary_item.recipient_share_carry_values.clone(),
        vss_public_recipient_share_messages_by_item: vec![
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
        vss_public_recipient_share_opening_randomness_by_item: vec![
            primary_item.recipient_share_randomness,
            same_source_additional_item.recipient_share_randomness,
            additional_item.recipient_share_randomness,
        ],
        vss_public_carry_witnesses_by_item: vec![
            primary_item.recipient_share_carry_values,
            same_source_additional_item.recipient_share_carry_values,
            additional_item.recipient_share_carry_values,
        ],
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
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
        source_message_modulus: item.source_message_modulus,
        coefficient_commitment_roots: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.commitment_root.clone())
            .collect(),
        coefficient_opening_roots: item
            .coefficient_commitment_computations
            .iter()
            .map(|computation| computation.opening_root.clone())
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
        recipient_share_opening_root: item
            .recipient_share_commitment_computation
            .opening_root
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
    source_message_modulus: u64,
    coefficient_messages: Vec<Vec<u64>>,
    coefficient_randomness: Vec<Vec<Vec<i64>>>,
    recipient_share_values: Vec<u64>,
    recipient_share_randomness: Vec<Vec<i64>>,
    recipient_share_carry_values: Vec<i64>,
    coefficient_commitment_computations: Vec<CommitmentComputationForTest>,
    recipient_share_commitment_computation: CommitmentComputationForTest,
}

fn share_linkage_item_for_test(
    item_label: &str,
    public_matrix_seed_hash: &str,
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
    let coefficient_randomness = (0..coefficient_count)
        .map(|shamir_coefficient_index| {
            ternary_randomness_columns(ring_degree, seed_offset + shamir_coefficient_index as i64)
        })
        .collect::<Vec<_>>();
    let recipient_share_randomness = ternary_randomness_columns(ring_degree, seed_offset + 31);

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
        .zip(coefficient_randomness.iter())
        .enumerate()
        .map(
            |(shamir_coefficient_index, (messages, randomness_by_column))| {
                commitment_computation_for_test(
                    "coefficient",
                    json!({
                        "testPurpose": "share-linkage-proof",
                        "itemLabel": item_label,
                        "shamirCoefficientIndex": shamir_coefficient_index,
                    }),
                    public_matrix_seed_hash,
                    source_rns_limb_index,
                    source_message_modulus,
                    ring_degree,
                    messages,
                    randomness_by_column,
                )
            },
        )
        .collect::<Vec<_>>();
    let recipient_share_commitment_computation = commitment_computation_for_test(
        "recipient-share",
        json!({
            "testPurpose": "share-linkage-proof",
            "itemLabel": item_label,
            "recipientRosterPosition": recipient_roster_position,
        }),
        public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        ring_degree,
        &recipient_share_values,
        &recipient_share_randomness,
    );

    ShareLinkageItemForTest {
        recipient_identity: format!("trustee-{recipient_roster_position}"),
        recipient_roster_position,
        source_rns_limb_index,
        source_message_modulus,
        coefficient_messages,
        coefficient_randomness,
        recipient_share_values,
        recipient_share_randomness,
        recipient_share_carry_values,
        coefficient_commitment_computations,
        recipient_share_commitment_computation,
    }
}

#[derive(Clone)]
struct CommitmentComputationForTest {
    commitment: VssShareLinkageCommitment,
    commitment_root: String,
    opening_root: String,
}

fn ternary_randomness_columns(ring_degree: usize, seed_offset: i64) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    ((seed_offset + column_index as i64 * 5 + coefficient_index as i64 * 7)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn commitment_computation_for_test(
    commitment_role: &str,
    commitment_context: serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    message_coefficients: &[u64],
    randomness_by_column: &[Vec<i64>],
) -> CommitmentComputationForTest {
    let message_digit_columns =
        vss_public_canonical_message_digit_columns(message_coefficients, ring_degree)
            .expect("VSS message digit columns");
    let computation = compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
        commitment_role,
        commitment_context: &commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        rns_prime,
        ring_degree,
        message_coefficients,
        message_digit_columns: &message_digit_columns,
        message_coefficient_bound: rns_prime,
        randomness_by_column,
    })
    .expect("VSS commitment");

    let coordinates_by_commitment_modulus = computation
        .commitment
        .get("commitmentLimbs")
        .and_then(serde_json::Value::as_array)
        .expect("commitment limbs")
        .iter()
        .map(|limb| {
            limb.get("coordinates")
                .and_then(serde_json::Value::as_array)
                .expect("commitment coordinates")
                .iter()
                .map(|coordinate| coordinate.as_u64().expect("coordinate"))
                .collect()
        })
        .collect();

    CommitmentComputationForTest {
        commitment: VssShareLinkageCommitment {
            coordinates_by_commitment_modulus,
        },
        commitment_root: computation.commitment_root,
        opening_root: computation.opening_root,
    }
}

// The cross-limb consistency soundness mechanism the other setup families use
// requires a masked claim's CRT lift to leave at least one commitment field
// unconsumed: the lift pins the centered integer from the consumed fields and
// the remaining field's residue is the check that catches an inconsistent
// per-field witness. This probe pins the share-linkage geometry after the
// Branch 2 change (2026-07-06): message consistency claims are trit-granular
// (each digit split into base-three trits, witness bound two), and under the
// standard twenty-repetition eight-bit schedule with the 58-digit mask every
// claim class still consumes two of the three commitment fields, leaving one
// check field. The trit witness bound is what narrows the per-claim leakage
// window; the separate assertion below pins that bound so a regression to
// whole-digit claims is caught even though the residue count is unchanged. If
// these pins move, re-derive the check-field decision record in
// setup-proof-decisions.md.
#[test]
fn vss_share_linkage_consistency_lift_geometry_is_pinned() {
    let (statement, _witness) = vss_share_linkage_instance();
    let field_moduli = statement
        .proof_limb_indices()
        .iter()
        .map(|limb_index| DATA_PRIMES[*limb_index])
        .collect::<Vec<_>>();
    let family_shape = statement.family_shape().expect("family shape");
    let consistency_repetitions = family_shape.consistency_repetitions();
    let item_count = statement
        .vss_share_linkage
        .as_ref()
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

    // Pin the message-trit witness bound. A message consistency claim lifts a
    // single base-three trit (bound VSS_PUBLIC_MESSAGE_TRIT_BASE - 1 = 2), not a
    // whole digit. masked_claim_bounds_for_global_claim returns the clear window
    // as (-clear, mask + clear) with clear = witness_bound * coefficient_bound *
    // ring_degree, so the negated lower bound recovers the clear span and pins
    // witness_bound. The residue-count check above cannot see this pin, because
    // the 58-digit mask dominates the window for both trit and digit bounds;
    // without it a silent regression to whole-digit claims (leakage back to
    // 2^-42 from 2^-68) would pass unnoticed.
    let share_linkage = statement
        .vss_share_linkage
        .as_ref()
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
        VSS_PUBLIC_SHARE_LINKAGE_DIGIT_CLAIM_MASK_DIGIT_COUNT,
        "the first message trit vector after the carries must take the share-linkage claim mask",
    );
}
