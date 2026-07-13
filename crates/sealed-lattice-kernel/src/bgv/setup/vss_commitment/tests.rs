use serde_json::json;

use super::share_linkage::verify_vss_aggregate_threshold_statement_root;
use super::{
    VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, VSS_PUBLIC_MESSAGE_DIGIT_BASE,
    verify_vss_public_aggregate_threshold_commitment_set_request,
    verify_vss_public_coefficient_commitment_set_request,
    verify_vss_public_recipient_share_commitment_set_request,
    verify_vss_share_linkage_bindings_request, vss_public_message_encoding_layout,
    vss_public_share_linkage_packed_message_encoding_layout,
};
use crate::bgv::parameters::DATA_PRIMES;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[test]
fn message_encoding_layout_uses_digit_bounds_for_trit_columns() -> CanonicalResult<()> {
    let small_layout = vss_public_message_encoding_layout(33)?;
    assert_eq!(small_layout.digit_trit_count(0)?, 4);
    assert_eq!(small_layout.digit_trit_count(1)?, 0);
    assert_eq!(small_layout.encoding_column_count(), 6);

    let full_low_digit_layout = vss_public_message_encoding_layout(
        VSS_PUBLIC_MESSAGE_DIGIT_BASE
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .expect("test bound fits u64"),
    )?;
    assert_eq!(
        full_low_digit_layout.digit_trit_count(0)?,
        VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT
    );
    assert_eq!(full_low_digit_layout.digit_trit_count(1)?, 1);

    Ok(())
}

#[test]
fn threshold_aggregate_layout_uses_digit_only_source_messages() -> CanonicalResult<()> {
    let message_bound = 33;
    let source_message_count = 2;
    let first_aggregate_source_layout = vss_public_share_linkage_packed_message_encoding_layout(
        true,
        0,
        source_message_count,
        message_bound,
    )?;
    let second_aggregate_source_layout = vss_public_share_linkage_packed_message_encoding_layout(
        true,
        1,
        source_message_count,
        message_bound,
    )?;
    let aggregate_recipient_layout = vss_public_share_linkage_packed_message_encoding_layout(
        true,
        source_message_count,
        source_message_count,
        message_bound,
    )?;
    let ordinary_source_layout = vss_public_share_linkage_packed_message_encoding_layout(
        false,
        0,
        source_message_count,
        message_bound,
    )?;

    assert_eq!(first_aggregate_source_layout.total_trit_count(), 0);
    assert_eq!(second_aggregate_source_layout.total_trit_count(), 0);
    assert_eq!(aggregate_recipient_layout.total_trit_count(), 4);
    assert_eq!(ordinary_source_layout.total_trit_count(), 4);

    Ok(())
}

#[test]
fn coefficient_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
    let coefficient_set = coefficient_commitment_set()?;
    let verification = verify_vss_public_coefficient_commitment_set_request(&json!({
        "command": "VerifyVssPublicCoefficientCommitmentSet",
        "coefficientCommitmentSet": coefficient_set,
    }))?;

    assert_eq!(
        verification["coefficientCommitmentRoot"],
        coefficient_set["coefficientCommitmentRoot"]
    );
    assert_eq!(verification["participantCount"], json!(2_u64));
    assert_eq!(verification["rnsLimbCount"], json!(2_u64));
    assert_eq!(verification["thresholdDegree"], json!(2_u64));

    let mut tampered_set = coefficient_set;
    tampered_set["sourceTrusteeRecords"][1]["coefficientCommitments"][2]["coefficientCommitmentRoot"] =
        json!("0".repeat(128));
    assert!(
        verify_vss_public_coefficient_commitment_set_request(&json!({
            "command": "VerifyVssPublicCoefficientCommitmentSet",
            "coefficientCommitmentSet": tampered_set,
        }))
        .is_err(),
        "tampered coefficient commitment root must reject"
    );

    Ok(())
}

#[test]
fn coefficient_commitment_set_rejects_a_rebound_noncanonical_rns_prime() -> CanonicalResult<()> {
    let mut coefficient_set = coefficient_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let coefficient_record =
        &mut coefficient_set["sourceTrusteeRecords"][0]["coefficientCommitments"][0];
    coefficient_record["rnsPrime"] = json!(noncanonical_prime);
    coefficient_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);
    coefficient_record["coefficientCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&coefficient_record["commitment"])?
    );
    rebind_canonical_object_root(
        &mut coefficient_set["sourceTrusteeRecords"][0],
        "sourceCoefficientCommitmentRoot",
    )?;
    rebind_canonical_object_root(&mut coefficient_set, "coefficientCommitmentRoot")?;

    let error = verify_vss_public_coefficient_commitment_set_request(&json!({
        "command": "VerifyVssPublicCoefficientCommitmentSet",
        "coefficientCommitmentSet": coefficient_set,
    }))
    .expect_err("a rebound coefficient record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("canonical Q_share basis"));
    Ok(())
}

#[test]
fn recipient_share_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
    let recipient_set = recipient_share_commitment_set()?;
    let verification = verify_vss_public_recipient_share_commitment_set_request(&json!({
        "command": "VerifyVssPublicRecipientShareCommitmentSet",
        "recipientShareCommitmentSet": recipient_set,
    }))?;

    assert_eq!(
        verification["recipientShareCommitmentRoot"],
        recipient_set["recipientShareCommitmentRoot"]
    );
    assert_eq!(verification["participantCount"], json!(2_u64));
    assert_eq!(verification["rnsLimbCount"], json!(2_u64));
    assert_eq!(verification["ringDegree"], json!(128_u64));

    let mut tampered_set = recipient_set;
    tampered_set["sourceTrusteeRecords"][0]["recipientShareCommitments"][1]["shareCommitmentRoot"] =
        json!("f".repeat(128));
    assert!(
        verify_vss_public_recipient_share_commitment_set_request(&json!({
            "command": "VerifyVssPublicRecipientShareCommitmentSet",
            "recipientShareCommitmentSet": tampered_set,
        }))
        .is_err(),
        "tampered recipient-share commitment root must reject"
    );

    Ok(())
}

#[test]
fn recipient_share_commitment_set_rejects_a_rebound_noncanonical_rns_prime() -> CanonicalResult<()>
{
    let mut recipient_set = recipient_share_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let recipient_share_record =
        &mut recipient_set["sourceTrusteeRecords"][0]["recipientShareCommitments"][0];
    recipient_share_record["rnsPrime"] = json!(noncanonical_prime);
    recipient_share_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);
    recipient_share_record["shareCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&recipient_share_record["commitment"])?
    );
    rebind_canonical_object_root(
        &mut recipient_set["sourceTrusteeRecords"][0],
        "sourceRecipientShareCommitmentRoot",
    )?;
    rebind_canonical_object_root(&mut recipient_set, "recipientShareCommitmentRoot")?;

    let error = verify_vss_public_recipient_share_commitment_set_request(&json!({
        "command": "VerifyVssPublicRecipientShareCommitmentSet",
        "recipientShareCommitmentSet": recipient_set,
    }))
    .expect_err("a rebound recipient-share record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("canonical Q_share basis"));
    Ok(())
}

#[test]
fn aggregate_threshold_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let verification = verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
        "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdCommitmentSet": aggregate_set,
    }))?;

    assert_eq!(
        verification["aggregateThresholdCommitmentRoot"],
        aggregate_set["aggregateThresholdCommitmentRoot"]
    );
    assert_eq!(verification["participantCount"], json!(2_u64));
    assert_eq!(verification["rnsLimbCount"], json!(2_u64));
    assert_eq!(verification["ringDegree"], json!(128_u64));

    let mut tampered_set = aggregate_set;
    tampered_set["recipientRecords"][0]["aggregateCommitmentRoot"] = json!("f".repeat(128));
    assert!(
        verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
            "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
            "aggregateThresholdCommitmentSet": tampered_set,
        }))
        .is_err(),
        "tampered aggregate threshold commitment root must reject"
    );

    Ok(())
}

#[test]
fn aggregate_threshold_commitment_set_rejects_a_rebound_noncanonical_rns_prime()
-> CanonicalResult<()> {
    let mut aggregate_set = aggregate_threshold_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let aggregate_record = &mut aggregate_set["recipientRecords"][0];
    aggregate_record["rnsPrime"] = json!(noncanonical_prime);
    aggregate_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);
    aggregate_record["aggregateCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&aggregate_record["commitment"])?
    );
    rebind_canonical_object_root(&mut aggregate_set, "aggregateThresholdCommitmentRoot")?;

    let error = verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
        "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdCommitmentSet": aggregate_set,
    }))
    .expect_err("a rebound aggregate-threshold record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("canonical Q_share basis"));
    Ok(())
}

#[test]
fn aggregate_threshold_statement_root_rejects_changed_bound_fields() -> CanonicalResult<()> {
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": "1".repeat(128),
        "sourceTrusteeIdentity": "trustee-1",
        "sourceTrusteeRosterPosition": 0,
        "sourceCoefficientCommitmentRoot": "2".repeat(128),
        "sourceRecipientShareCommitmentRoot": "3".repeat(128),
        "recipientIdentity": "trustee-1",
        "recipientRosterPosition": 0,
        "sourceRnsLimbIndex": 0,
        "sourceMessageModulus": 17,
        "coefficientCommitmentRoots": ["4".repeat(128), "5".repeat(128)],
        "coefficientCommitments": [
            { "objectType": "VssCommittedMaterialCommitment", "slot": 0 },
            { "objectType": "VssCommittedMaterialCommitment", "slot": 1 },
        ],
        "recipientShareCommitmentRoot": "8".repeat(128),
        "recipientShareCommitment": {
            "objectType": "VssCommittedMaterialCommitment",
            "slot": 2,
        },
        "additionalLinkageItems": [],
    });
    let expected_statement_root =
        crate::hashing::derive_canonical_object_hash(&statement_without_root)?;
    let mut statement = statement_without_root;
    statement["shareLinkageStatementRoot"] = json!(expected_statement_root.clone());

    assert_eq!(
        verify_vss_aggregate_threshold_statement_root(&statement)?,
        expected_statement_root,
        "the canonical aggregate statement must round-trip through root verification"
    );

    statement["recipientIdentity"] = json!("trustee-2");
    let error = verify_vss_aggregate_threshold_statement_root(&statement)
        .expect_err("a changed recognized field with a stale root must reject");
    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error
            .message
            .contains("share-linkage statement root does not match its canonical binding"),
        "root mismatch should identify the canonical aggregate statement binding: {error}"
    );

    Ok(())
}

#[test]
fn share_linkage_bindings_command_verifies_bound_roots() -> CanonicalResult<()> {
    let coefficient_set = coefficient_commitment_set()?;
    let recipient_set = recipient_share_commitment_set()?;
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let statement =
        share_linkage_statement_from_evidence(&coefficient_set, &recipient_set, &aggregate_set);
    let verification = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
        "statement": statement.clone(),
        "coefficientCommitmentSet": coefficient_set.clone(),
        "recipientShareCommitmentSet": recipient_set.clone(),
        "aggregateThresholdCommitmentSet": aggregate_set.clone(),
    }))?;

    assert_eq!(verification["statementRoot"], statement["statementRoot"]);
    assert_eq!(
        verification["aggregateThresholdCommitmentRoot"],
        statement["aggregateThresholdCommitmentRoot"]
    );

    let missing_evidence_error = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
        "statement": statement.clone(),
    }))
    .expect_err("share-linkage statement verification must require evidence sets");
    assert!(
        missing_evidence_error
            .to_string()
            .contains("requires coefficient, recipient-share, and aggregate-threshold"),
        "missing share-linkage evidence should report the required evidence sets: {missing_evidence_error}"
    );

    // This check binds the committed roots across the sets. The accepted-setup
    // material path verifies the threshold-aggregate relation itself.

    let mut tampered_statement = statement;
    tampered_statement["aggregateThresholdCommitmentRoot"] = json!("8".repeat(128));
    assert!(
        verify_vss_share_linkage_bindings_request(&json!({
            "command": "VerifyVssShareLinkageBindings",
            "statement": tampered_statement,
            "coefficientCommitmentSet": coefficient_set,
            "recipientShareCommitmentSet": recipient_set,
            "aggregateThresholdCommitmentSet": aggregate_set,
        }))
        .is_err(),
        "tampered share-linkage statement root must reject"
    );

    Ok(())
}

pub(in crate::bgv::setup) fn coefficient_commitment_set() -> CanonicalResult<serde_json::Value> {
    let mut source_trustee_records = Vec::new();
    for source_trustee_roster_position in 0..2_usize {
        source_trustee_records.push(source_coefficient_record(source_trustee_roster_position)?);
    }
    let set_without_root = json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": "7".repeat(128),
        "participantCount": 2,
        "rnsLimbCount": 2,
        "thresholdDegree": 2,
        "ringDegree": test_ring_degree(),
        "sourceTrusteeRecords": source_trustee_records,
    });
    let mut coefficient_set = set_without_root;
    coefficient_set["coefficientCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&coefficient_set)
            .expect("coefficient set root")
    );

    Ok(coefficient_set)
}

fn source_coefficient_record(
    source_trustee_roster_position: usize,
) -> CanonicalResult<serde_json::Value> {
    let mut coefficient_commitments = Vec::new();
    for rns_limb_index in 0..test_rns_limb_count() {
        let rns_prime = test_rns_prime(rns_limb_index);
        for shamir_coefficient_index in 0..test_threshold_degree() {
            let computation = test_commitment(
                "coefficient",
                rns_limb_index,
                rns_prime,
                &[
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    0,
                ],
            )?;
            coefficient_commitments.push(json!({
                "objectType": "VssPublicCoefficientCommitment",
                "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
                "sourceTrusteeRosterPosition": source_trustee_roster_position,
                "publicMatrixSeedHash": "7".repeat(128),
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": shamir_coefficient_index,
                "coefficientCommitmentRoot": computation.commitment_root,
                "commitment": computation.commitment,
            }));
        }
    }
    let source_without_root = json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "publicMatrixSeedHash": "7".repeat(128),
        "coefficientCommitments": coefficient_commitments,
    });
    let mut source_record = source_without_root;
    source_record["sourceCoefficientCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&source_record)
            .expect("source coefficient root")
    );

    Ok(source_record)
}

fn test_participant_count() -> usize {
    2
}

fn test_rns_limb_count() -> usize {
    2
}

fn test_threshold_degree() -> usize {
    2
}

fn test_ring_degree() -> usize {
    // The committed-material commitment hosts TRACE_SPLIT half-columns over a
    // trace domain with a minimum size, so the set-verifier fixtures use a valid
    // supported ring degree rather than a tiny structural one.
    128
}

fn test_public_matrix_seed_hash() -> String {
    "7".repeat(128)
}

fn test_rns_prime(rns_limb_index: usize) -> u64 {
    DATA_PRIMES[rns_limb_index]
}

fn test_seed(seed_parts: &[usize]) -> usize {
    seed_parts
        .iter()
        .fold(0_usize, |seed, seed_part| seed * 31 + seed_part + 1)
}

fn test_hash_from_seed(seed: usize, domain_offset: usize) -> String {
    let digit = (seed + domain_offset) % 16;
    format!("{digit:x}").repeat(128)
}

fn test_message_coefficients(seed: usize, modulus: u64) -> Vec<u64> {
    (0..test_ring_degree())
        .map(|coefficient_index| {
            ((seed as u64)
                .wrapping_mul(17)
                .wrapping_add((coefficient_index as u64 + 1) * 19))
                % modulus
        })
        .collect()
}

// The committed-material computation fields the set-builder fixtures consume:
// the commitment body plus its canonical and opening roots.
struct TestVssCommitmentComputation {
    commitment: serde_json::Value,
    commitment_root: String,
    opening_root: String,
}

fn test_committed_material_seed(seed: usize) -> String {
    // A distinct valid 128-hex protocol-hash-shaped seed per fixture commitment.
    let mut material_seed = String::with_capacity(128);
    let mut state = seed as u64;
    for _ in 0..128 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let nibble = (state >> 60) & 0x0f;
        material_seed.push(char::from_digit(nibble as u32, 16).expect("hex nibble"));
    }

    material_seed
}

fn test_commitment(
    commitment_role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    seed_parts: &[usize],
) -> CanonicalResult<TestVssCommitmentComputation> {
    let message_coefficients = test_message_coefficients(test_seed(seed_parts), rns_prime);
    test_committed_material_commitment(
        commitment_role,
        rns_limb_index,
        rns_prime,
        seed_parts,
        &message_coefficients,
    )
}

fn test_committed_material_commitment(
    commitment_role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    seed_parts: &[usize],
    message_coefficients: &[u64],
) -> CanonicalResult<TestVssCommitmentComputation> {
    let seed = test_seed(seed_parts);
    let commitment_context = json!({
        "objectType": "VssPublicTestCommitmentContext",
        "commitmentRole": commitment_role,
        "seedHash": test_hash_from_seed(seed, 9),
    });
    let response = crate::bgv::setup::compute_vss_committed_material_commitment_request(&json!({
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": test_ring_degree(),
        "messageCoefficients": message_coefficients,
        "messageCoefficientBound": rns_prime,
        "materialSeedHex": test_committed_material_seed(seed),
    }))?;

    Ok(TestVssCommitmentComputation {
        commitment: response["commitment"].clone(),
        commitment_root: response["commitmentRoot"]
            .as_str()
            .expect("commitment root")
            .to_string(),
        opening_root: response["openingRoot"]
            .as_str()
            .expect("opening root")
            .to_string(),
    })
}

pub(in crate::bgv::setup) fn recipient_share_commitment_set() -> CanonicalResult<serde_json::Value>
{
    let mut source_trustee_records = Vec::new();
    for source_trustee_roster_position in 0..test_participant_count() {
        source_trustee_records.push(source_recipient_share_record(
            source_trustee_roster_position,
        )?);
    }
    let set_without_root = json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": test_public_matrix_seed_hash(),
        "participantCount": test_participant_count(),
        "rnsLimbCount": test_rns_limb_count(),
        "ringDegree": test_ring_degree(),
        "sourceTrusteeRecords": source_trustee_records,
    });
    let mut recipient_set = set_without_root;
    recipient_set["recipientShareCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&recipient_set)
            .expect("recipient-share set root")
    );

    Ok(recipient_set)
}

fn source_recipient_share_record(
    source_trustee_roster_position: usize,
) -> CanonicalResult<serde_json::Value> {
    let mut recipient_share_commitments = Vec::new();
    for recipient_roster_position in 0..test_participant_count() {
        for rns_limb_index in 0..test_rns_limb_count() {
            recipient_share_commitments.push(recipient_share_commitment_record(
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
            )?);
        }
    }
    let source_without_root = json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientShareCommitments": recipient_share_commitments,
    });
    let mut source_record = source_without_root;
    source_record["sourceRecipientShareCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&source_record)
            .expect("source recipient-share root")
    );

    Ok(source_record)
}

fn recipient_share_commitment_record(
    source_trustee_roster_position: usize,
    recipient_roster_position: usize,
    rns_limb_index: usize,
) -> CanonicalResult<serde_json::Value> {
    let rns_prime = test_rns_prime(rns_limb_index);
    let computation = test_commitment(
        "recipient-share",
        rns_limb_index,
        rns_prime,
        &[
            source_trustee_roster_position,
            recipient_roster_position,
            rns_limb_index,
            1,
        ],
    )?;
    Ok(json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": format!("recipient-{recipient_roster_position}"),
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shareCommitmentRoot": computation.commitment_root,
        "commitment": computation.commitment,
    }))
}

fn aggregate_threshold_commitment_set() -> CanonicalResult<serde_json::Value> {
    let recipient_set = recipient_share_commitment_set()?;
    aggregate_threshold_commitment_set_from_recipient_set(&recipient_set)
}

pub(in crate::bgv::setup) fn aggregate_threshold_commitment_set_from_recipient_set(
    _recipient_set: &serde_json::Value,
) -> CanonicalResult<serde_json::Value> {
    let mut recipient_records = Vec::new();
    for recipient_roster_position in 0..test_participant_count() {
        for rns_limb_index in 0..test_rns_limb_count() {
            recipient_records.push(aggregate_threshold_commitment_record(
                recipient_roster_position,
                rns_limb_index,
            )?);
        }
    }
    let set_without_root = json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": test_public_matrix_seed_hash(),
        "participantCount": test_participant_count(),
        "rnsLimbCount": test_rns_limb_count(),
        "ringDegree": test_ring_degree(),
        "recipientRecords": recipient_records,
    });
    let mut aggregate_set = set_without_root;
    aggregate_set["aggregateThresholdCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&aggregate_set)
            .expect("aggregate threshold set root")
    );

    Ok(aggregate_set)
}

fn aggregate_threshold_commitment_record(
    recipient_roster_position: usize,
    rns_limb_index: usize,
) -> CanonicalResult<serde_json::Value> {
    let rns_prime = test_rns_prime(rns_limb_index);
    // The threshold share is the modular sum of every source's recipient share
    // for this recipient and limb, recomputed from the same fixture messages the
    // recipient-share records commit and committed as committed material. The
    // "T = sum" binding itself is a threshold-aggregate proof, not this record.
    let mut aggregate_message = vec![0_u64; test_ring_degree()];
    for source_trustee_roster_position in 0..test_participant_count() {
        let source_message = test_message_coefficients(
            test_seed(&[
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
                1,
            ]),
            rns_prime,
        );
        for (accumulator, value) in aggregate_message.iter_mut().zip(source_message.iter()) {
            *accumulator =
                ((u128::from(*accumulator) + u128::from(*value)) % u128::from(rns_prime)) as u64;
        }
    }
    let computation = test_committed_material_commitment(
        "aggregate-threshold-share",
        rns_limb_index,
        rns_prime,
        &[recipient_roster_position, rns_limb_index, 5],
        &aggregate_message,
    )?;

    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "recipientIdentity": format!("recipient-{recipient_roster_position}"),
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "aggregateCommitmentRoot": computation.commitment_root,
        "aggregateOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    }))
}

pub(in crate::bgv::setup) fn share_linkage_statement_from_evidence(
    coefficient_set: &serde_json::Value,
    recipient_set: &serde_json::Value,
    aggregate_set: &serde_json::Value,
) -> serde_json::Value {
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "ceremonyId": "vss-test",
        "manifestHash": "1".repeat(128),
        "rosterHash": "2".repeat(128),
        "setupParametersHash": "3".repeat(128),
        "setupEpoch": "setup-epoch",
        "publicMatrixSeedHash": "7".repeat(128),
        "ringDegree": test_ring_degree(),
        "participantCount": 2,
        "qShareRnsLimbCount": 2,
        "thresholdDegree": 2,
        "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
        "recipientShareCommitmentRoot": recipient_set["recipientShareCommitmentRoot"].clone(),
        "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
    });

    let mut statement = statement_without_root;
    statement["statementRoot"] =
        json!(crate::hashing::derive_canonical_object_hash(&statement).expect("statement root"));
    statement
}

fn rebind_canonical_object_root(
    object: &mut serde_json::Value,
    root_field_name: &str,
) -> CanonicalResult<()> {
    let mut root_input = object
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS commitment root input must be an object",
            )
        })?
        .clone();
    root_input.remove(root_field_name);
    object[root_field_name] = json!(crate::hashing::derive_canonical_object_hash(
        &serde_json::Value::Object(root_input),
    )?);

    Ok(())
}
