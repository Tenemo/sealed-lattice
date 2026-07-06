use serde_json::json;

use super::{
    VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, VSS_PUBLIC_MESSAGE_DIGIT_BASE,
    VSS_PUBLIC_OUTPUT_COORDINATE_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
    VssPublicCommitmentComputation, VssPublicCommitmentOpeningInput,
    compute_vss_public_commitment_from_opening, compute_vss_public_commitment_from_opening_request,
    verify_vss_public_aggregate_threshold_commitment_set_request,
    verify_vss_public_coefficient_commitment_set_request,
    verify_vss_public_recipient_share_commitment_set_request,
    verify_vss_share_linkage_statement_request, vss_public_canonical_message_digit_columns,
    vss_public_encoded_commitment_byte_length, vss_public_message_encoding_layout,
};
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
fn commitment_command_verifies_and_rejects_tampering() -> CanonicalResult<()> {
    let request = opening_request();
    let response = compute_vss_public_commitment_from_opening_request(&request)?;

    assert_eq!(
        response["operation"],
        "computeVssPublicCommitmentFromOpening"
    );
    assert_eq!(response["encodedCommitmentByteLength"], json!(384_u64));
    assert_eq!(
        response["commitment"]["commitmentLimbs"]
            .as_array()
            .expect("commitment limbs")
            .len(),
        3
    );
    assert_eq!(
        response["commitmentRoot"]
            .as_str()
            .expect("commitment root")
            .len(),
        128
    );

    let mut tampered_opening = opening_request();
    tampered_opening["messageCoefficients"][3] = json!(12_u64);
    assert!(
        compute_vss_public_commitment_from_opening_request(&tampered_opening).is_err(),
        "tampered opening must reject"
    );

    let mut wrong_shape = opening_request();
    wrong_shape["randomnessByColumn"][0] = json!([0, 1]);
    assert!(
        compute_vss_public_commitment_from_opening_request(&wrong_shape).is_err(),
        "wrong randomness shape must reject"
    );

    let mut missing_digit_columns = opening_request();
    missing_digit_columns
        .as_object_mut()
        .expect("opening request")
        .remove("messageDigitColumns");
    assert!(
        compute_vss_public_commitment_from_opening_request(&missing_digit_columns).is_err(),
        "opening command must require message digit columns"
    );

    Ok(())
}

#[test]
fn commitment_opening_root_binds_explicit_message_digit_columns() -> CanonicalResult<()> {
    let carried_message = VSS_PUBLIC_MESSAGE_DIGIT_BASE + 7;
    let mut request = opening_request();
    request["messageCoefficientBound"] = json!(VSS_PUBLIC_MESSAGE_DIGIT_BASE * 2);
    request["messageCoefficients"][2] = json!(carried_message);
    request["messageDigitColumns"] = json!([
        [1_u64, 2, carried_message, 4, 5, 6, 7, 8],
        [0_u64, 0, 0, 0, 0, 0, 0, 0],
    ]);
    let response = compute_vss_public_commitment_from_opening_request(&request)?;

    let mut canonical_digits_request = request.clone();
    canonical_digits_request["messageDigitColumns"] =
        json!([[1_u64, 2, 7, 4, 5, 6, 7, 8], [0_u64, 0, 1, 0, 0, 0, 0, 0],]);
    let canonical_digits_response =
        compute_vss_public_commitment_from_opening_request(&canonical_digits_request)?;
    assert_ne!(
        response["commitmentRoot"],
        canonical_digits_response["commitmentRoot"]
    );
    assert_ne!(
        response["openingRoot"],
        canonical_digits_response["openingRoot"]
    );

    let mut mismatched_digits_request = request;
    mismatched_digits_request["messageDigitColumns"][0][2] = json!(carried_message - 1);
    assert!(
        compute_vss_public_commitment_from_opening_request(&mismatched_digits_request).is_err(),
        "explicit VSS message digit columns must decode to the declared message coefficients"
    );

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
        verification["operation"],
        "verifyVssPublicCoefficientCommitmentSet"
    );
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
fn recipient_share_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
    let recipient_set = recipient_share_commitment_set()?;
    let verification = verify_vss_public_recipient_share_commitment_set_request(&json!({
        "command": "VerifyVssPublicRecipientShareCommitmentSet",
        "recipientShareCommitmentSet": recipient_set,
    }))?;

    assert_eq!(
        verification["operation"],
        "verifyVssPublicRecipientShareCommitmentSet"
    );
    assert_eq!(
        verification["recipientShareCommitmentRoot"],
        recipient_set["recipientShareCommitmentRoot"]
    );
    assert_eq!(verification["participantCount"], json!(2_u64));
    assert_eq!(verification["rnsLimbCount"], json!(2_u64));
    assert_eq!(verification["ringDegree"], json!(8_u64));

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
fn aggregate_threshold_commitment_set_command_verifies_bound_roots() -> CanonicalResult<()> {
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let verification = verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
        "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdCommitmentSet": aggregate_set,
    }))?;

    assert_eq!(
        verification["operation"],
        "verifyVssPublicAggregateThresholdCommitmentSet"
    );
    assert_eq!(
        verification["aggregateThresholdCommitmentRoot"],
        aggregate_set["aggregateThresholdCommitmentRoot"]
    );
    assert_eq!(verification["participantCount"], json!(2_u64));
    assert_eq!(verification["rnsLimbCount"], json!(2_u64));
    assert_eq!(verification["ringDegree"], json!(8_u64));

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
fn share_linkage_statement_command_verifies_bound_roots() -> CanonicalResult<()> {
    let coefficient_set = coefficient_commitment_set()?;
    let recipient_set = recipient_share_commitment_set()?;
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let statement =
        share_linkage_statement_from_evidence(&coefficient_set, &recipient_set, &aggregate_set);
    let verification = verify_vss_share_linkage_statement_request(&json!({
        "command": "VerifyVssShareLinkageStatement",
        "statement": statement.clone(),
        "coefficientCommitmentSet": coefficient_set.clone(),
        "recipientShareCommitmentSet": recipient_set.clone(),
        "aggregateThresholdCommitmentSet": aggregate_set.clone(),
    }))?;

    assert_eq!(verification["operation"], "verifyVssShareLinkageStatement");
    assert_eq!(verification["statementRoot"], statement["statementRoot"]);
    assert_eq!(
        verification["aggregateThresholdCommitmentRoot"],
        statement["aggregateThresholdCommitmentRoot"]
    );

    let mut forged_source_statement = statement.clone();
    forged_source_statement["sourceStatementRecords"][0]["sourceRecipientShareCommitmentRoot"] =
        json!("0".repeat(128));
    rebind_share_linkage_source_statement_root(
        &mut forged_source_statement["sourceStatementRecords"][0],
    )?;
    rebind_share_linkage_statement_root(&mut forged_source_statement)?;
    let missing_evidence_error = verify_vss_share_linkage_statement_request(&json!({
        "command": "VerifyVssShareLinkageStatement",
        "statement": forged_source_statement.clone(),
    }))
    .expect_err("share-linkage statement verification must require evidence sets");
    assert!(
        missing_evidence_error
            .to_string()
            .contains("requires coefficient, recipient-share, and aggregate-threshold"),
        "missing share-linkage evidence should report the required evidence sets: {missing_evidence_error}"
    );
    assert!(
        verify_vss_share_linkage_statement_request(&json!({
            "command": "VerifyVssShareLinkageStatement",
            "statement": forged_source_statement,
            "coefficientCommitmentSet": coefficient_set.clone(),
            "recipientShareCommitmentSet": recipient_set.clone(),
            "aggregateThresholdCommitmentSet": aggregate_set.clone(),
        }))
        .is_err(),
        "evidence-backed linkage verification must reject a source root absent from the recipient-share set"
    );

    let mut mismatched_aggregate_set = aggregate_set.clone();
    tamper_aggregate_commitment_body(&mut mismatched_aggregate_set)?;
    assert!(
        verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
            "command": "VerifyVssPublicAggregateThresholdCommitmentSet",
            "aggregateThresholdCommitmentSet": mismatched_aggregate_set.clone(),
        }))
        .is_ok(),
        "aggregate set verification only checks aggregate body canonical roots"
    );
    let mismatched_statement = share_linkage_statement_from_evidence(
        &coefficient_set,
        &recipient_set,
        &mismatched_aggregate_set,
    );
    let mismatch_error = verify_vss_share_linkage_statement_request(&json!({
        "command": "VerifyVssShareLinkageStatement",
        "statement": mismatched_statement,
        "coefficientCommitmentSet": coefficient_set.clone(),
        "recipientShareCommitmentSet": recipient_set.clone(),
        "aggregateThresholdCommitmentSet": mismatched_aggregate_set,
    }))
    .expect_err("evidence-backed linkage verification must reject a non-sum aggregate body");
    assert!(
        mismatch_error.to_string().contains("public sum"),
        "aggregate body mismatch should be reported as a public-sum failure: {mismatch_error}"
    );

    let mut tampered_statement = statement;
    tampered_statement["aggregateThresholdCommitmentRoot"] = json!("8".repeat(128));
    assert!(
        verify_vss_share_linkage_statement_request(&json!({
            "command": "VerifyVssShareLinkageStatement",
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

fn opening_request() -> serde_json::Value {
    json!({
        "command": "ComputeVssPublicCommitmentFromOpening",
        "commitmentRole": "aggregate-threshold-share",
        "commitmentContext": {
            "objectType": "VssPublicAggregateThresholdShareCommitmentContext",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "setupEpoch": "setup-epoch",
            "recipientIdentity": "trustee-1",
            "recipientRosterPosition": 0,
            "rnsLimbIndex": 0,
            "rnsPrime": 97,
        },
        "publicMatrixSeedHash": "7".repeat(128),
        "rnsLimbIndex": 0,
        "rnsPrime": 97,
        "ringDegree": 8,
        "messageCoefficients": [1, 2, 3, 4, 5, 6, 7, 8],
        "messageDigitColumns": [
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0, 0, 0, 0, 0, 0, 0, 0]
        ],
        "randomnessByColumn": [
            [0, 1, -1, 2, -2, 3, -3, 4],
            [5, -5, 6, -6, 7, -7, 8, -8]
        ],
    })
}

// Small final check for the public VSS commitment: the public commitment
// body is a fixed set of field residues (three commitment limbs times
// sixteen output coordinates), independent of the ring degree, whereas a
// full-ring VSS coefficient commitment stores one residue per ring
// coefficient. The constant-size property is the point of the public
// commitment; the reduction against the first-profile ring is measured and
// printed, never gated on.
#[test]
fn vss_public_commitment_body_is_constant_size_across_ring_degrees() -> CanonicalResult<()> {
    let mut encoded_byte_lengths = Vec::new();
    for ring_degree in [8_usize, 64] {
        let message_coefficients: Vec<u64> =
            (0..ring_degree).map(|index| (index % 7) as u64).collect();
        let low_digit_column = message_coefficients.clone();
        let high_digit_column = vec![0_u64; ring_degree];
        let randomness_first: Vec<i64> = (0..ring_degree)
            .map(|index| ((index % 3) as i64) - 1)
            .collect();
        let randomness_second: Vec<i64> = (0..ring_degree)
            .map(|index| 1 - ((index % 3) as i64))
            .collect();
        let request = json!({
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContext": {
                "objectType": "VssPublicAggregateThresholdShareCommitmentContext",
                "ceremonyId": "vss-measurement",
                "manifestHash": "1".repeat(128),
                "rosterHash": "2".repeat(128),
                "setupParametersHash": "3".repeat(128),
                "qShareHash": "4".repeat(128),
                "setupEpoch": "setup-epoch",
                "recipientIdentity": "trustee-1",
                "recipientRosterPosition": 0,
                "rnsLimbIndex": 0,
                "rnsPrime": 97,
            },
            "publicMatrixSeedHash": "7".repeat(128),
            "rnsLimbIndex": 0,
            "rnsPrime": 97,
            "ringDegree": ring_degree,
            "messageCoefficients": message_coefficients,
            "messageDigitColumns": [low_digit_column, high_digit_column],
            "randomnessByColumn": [randomness_first, randomness_second],
        });
        compute_vss_public_commitment_from_opening_request(&request)?;
        encoded_byte_lengths.push(vss_public_encoded_commitment_byte_length() as u64);
    }

    assert_eq!(
        encoded_byte_lengths[0], encoded_byte_lengths[1],
        "public commitment body must be a constant size independent of the ring degree"
    );
    let public_commitment_body_bytes = encoded_byte_lengths[0];
    // Model a full-ring VSS coefficient commitment over the first-profile
    // ring: one ~6-byte residue per ring coefficient per commitment limb.
    let modeled_full_bytes_per_commitment =
        crate::bgv::parameters::POLYNOMIAL_DEGREE as u64 * 3 * 6;
    println!(
        "sealed-lattice-vss-public-commitment-measurement public-commitment-body-bytes={public_commitment_body_bytes} modeled-full-bytes-per-commitment={modeled_full_bytes_per_commitment} reduction={}x",
        modeled_full_bytes_per_commitment / public_commitment_body_bytes.max(1)
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
        "ringDegree": 8,
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
                "coefficientOpeningRoot": computation.opening_root,
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
    8
}

fn test_public_matrix_seed_hash() -> String {
    "7".repeat(128)
}

fn test_rns_prime(rns_limb_index: usize) -> u64 {
    if rns_limb_index == 0 { 97 } else { 193 }
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

fn test_randomness_by_column(seed: usize) -> Vec<Vec<i64>> {
    (0..VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..test_ring_degree())
                .map(|coefficient_index| {
                    let magnitude =
                        ((seed + column_index * 11 + coefficient_index * 7) % 29) as i64;
                    if (seed + column_index + coefficient_index).is_multiple_of(2) {
                        magnitude
                    } else {
                        -magnitude
                    }
                })
                .collect()
        })
        .collect()
}

fn test_commitment(
    commitment_role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    seed_parts: &[usize],
) -> CanonicalResult<VssPublicCommitmentComputation> {
    let seed = test_seed(seed_parts);
    let commitment_context = json!({
        "objectType": "VssPublicTestCommitmentContext",
        "commitmentRole": commitment_role,
        "seedHash": test_hash_from_seed(seed, 9),
    });
    let public_matrix_seed_hash = test_public_matrix_seed_hash();
    let message_coefficients = test_message_coefficients(seed, rns_prime);
    let message_digit_columns =
        vss_public_canonical_message_digit_columns(&message_coefficients, test_ring_degree())?;
    let randomness_by_column = test_randomness_by_column(seed);
    let computation =
        compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
            commitment_role,
            commitment_context: &commitment_context,
            public_matrix_seed_hash: &public_matrix_seed_hash,
            rns_limb_index,
            rns_prime,
            ring_degree: test_ring_degree(),
            message_coefficients: &message_coefficients,
            message_digit_columns: &message_digit_columns,
            message_coefficient_bound: rns_prime,
            randomness_by_column: &randomness_by_column,
        })?;

    Ok(computation)
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
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shareCommitmentRoot": computation.commitment_root,
        "shareOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    }))
}

fn aggregate_threshold_commitment_set() -> CanonicalResult<serde_json::Value> {
    let recipient_set = recipient_share_commitment_set()?;
    aggregate_threshold_commitment_set_from_recipient_set(&recipient_set)
}

pub(in crate::bgv::setup) fn aggregate_threshold_commitment_set_from_recipient_set(
    recipient_set: &serde_json::Value,
) -> CanonicalResult<serde_json::Value> {
    let mut recipient_records = Vec::new();
    for recipient_roster_position in 0..test_participant_count() {
        for rns_limb_index in 0..test_rns_limb_count() {
            recipient_records.push(aggregate_threshold_commitment_record(
                recipient_set,
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
    recipient_set: &serde_json::Value,
    recipient_roster_position: usize,
    rns_limb_index: usize,
) -> CanonicalResult<serde_json::Value> {
    let source_share_records = source_share_records_for_recipient(
        recipient_set,
        recipient_roster_position,
        rns_limb_index,
    )?;
    let rns_prime = test_rns_prime(rns_limb_index);
    let commitment = aggregate_commitment_body(
        recipient_roster_position,
        rns_limb_index,
        rns_prime,
        &source_share_records,
    )?;
    let source_share_commitment_roots = source_share_records
        .iter()
        .map(|source_share_record| source_share_record["shareCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let source_share_opening_roots = source_share_records
        .iter()
        .map(|source_share_record| source_share_record["shareOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let seed = test_seed(&[recipient_roster_position, rns_limb_index, 5]);

    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "recipientIdentity": format!("recipient-{recipient_roster_position}"),
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "aggregateCommitmentRoot": crate::hashing::derive_canonical_object_hash(&commitment,
        )?,
        "aggregateOpeningRoot": test_hash_from_seed(seed, 0),
        "commitment": commitment,
        "sourceShareCommitmentRoots": source_share_commitment_roots,
        "sourceShareOpeningRoots": source_share_opening_roots,
    }))
}

fn source_share_records_for_recipient(
    recipient_set: &serde_json::Value,
    recipient_roster_position: usize,
    rns_limb_index: usize,
) -> CanonicalResult<Vec<serde_json::Value>> {
    let recipient_share_record_index = recipient_roster_position
        .checked_mul(test_rns_limb_count())
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS fixture recipient-share index overflowed",
            )
        })?;
    let source_records = recipient_set["sourceTrusteeRecords"]
        .as_array()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS fixture recipient source records must be an array",
            )
        })?;
    source_records
        .iter()
        .map(|source_record| {
            let recipient_share_records = source_record["recipientShareCommitments"]
                .as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS fixture recipient-share records must be an array",
                    )
                })?;
            recipient_share_records
                .get(recipient_share_record_index)
                .cloned()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS fixture recipient-share record is missing",
                    )
                })
        })
        .collect()
}

fn aggregate_commitment_body(
    recipient_roster_position: usize,
    rns_limb_index: usize,
    rns_prime: u64,
    source_share_records: &[serde_json::Value],
) -> CanonicalResult<serde_json::Value> {
    let first_source_share_record = source_share_records.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS fixture aggregate body must have source share records",
        )
    })?;
    let first_commitment_limbs = first_source_share_record["commitment"]["commitmentLimbs"]
        .as_array()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS fixture commitment limbs must be an array",
            )
        })?;
    let mut commitment_limbs = Vec::new();
    for (commitment_limb_position, first_limb) in first_commitment_limbs.iter().enumerate() {
        let commitment_modulus_index =
            first_limb["commitmentModulusIndex"]
                .as_u64()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS fixture commitment modulus index must be an unsigned integer",
                    )
                })?;
        let modulus = first_limb["modulus"].as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS fixture commitment modulus must be an unsigned integer",
            )
        })?;
        let mut summed_coordinates = Vec::new();
        for coordinate_index in 0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
            let mut summed_coordinate = 0_u128;
            for source_share_record in source_share_records {
                let source_limb = source_share_record["commitment"]["commitmentLimbs"]
                    .as_array()
                    .and_then(|limbs| limbs.get(commitment_limb_position))
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "VSS fixture source commitment limb is missing",
                        )
                    })?;
                let coordinate = source_limb["coordinates"]
                    .as_array()
                    .and_then(|coordinates| coordinates.get(coordinate_index))
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "VSS fixture source commitment coordinate must be an unsigned integer",
                        )
                    })?;
                summed_coordinate =
                    (summed_coordinate + u128::from(coordinate)) % u128::from(modulus);
            }
            summed_coordinates.push(summed_coordinate as u64);
        }
        commitment_limbs.push(json!({
            "commitmentModulusIndex": commitment_modulus_index,
            "modulus": modulus,
            "coordinates": summed_coordinates,
        }));
    }

    let seed = test_seed(&[recipient_roster_position, rns_limb_index, 4]);
    Ok(json!({
        "objectType": "VssPublicCommitment",
        "commitmentRole": "aggregate-threshold-share",
        "commitmentContextHash": test_hash_from_seed(seed, 0),
        "publicMatrixSeedHash": test_public_matrix_seed_hash(),
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": test_ring_degree(),
        "outputCoordinateCount": VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    }))
}

pub(in crate::bgv::setup) fn share_linkage_statement_from_evidence(
    coefficient_set: &serde_json::Value,
    recipient_set: &serde_json::Value,
    aggregate_set: &serde_json::Value,
) -> serde_json::Value {
    // The primitive statement verifier binds targetBasisHash as data; the
    // canonical-basis check lives in the same-secret bridge, so any
    // well-formed deterministic hash serves the fixture here.
    let target_basis_hash =
        crate::hashing::hash512_hex("sealed-lattice-vss-test/target-basis", &[b"target-basis"]);
    let source_statement_records = (0..2_usize)
            .map(|source_trustee_roster_position| {
                let coefficient_source_record =
                    &coefficient_set["sourceTrusteeRecords"][source_trustee_roster_position];
                let recipient_source_record =
                    &recipient_set["sourceTrusteeRecords"][source_trustee_roster_position];
                let coefficient_opening_roots = coefficient_source_record["coefficientCommitments"]
                    .as_array()
                    .expect("coefficient records")
                    .iter()
                    .map(|coefficient_record| {
                        coefficient_record["coefficientOpeningRoot"].clone()
                    })
                    .collect::<Vec<_>>();
                let recipient_share_opening_roots = recipient_source_record
                    ["recipientShareCommitments"]
                    .as_array()
                    .expect("recipient-share records")
                    .iter()
                    .map(|recipient_share_record| {
                        recipient_share_record["shareOpeningRoot"].clone()
                    })
                    .collect::<Vec<_>>();
                let source_statement_without_root = json!({
                    "objectType": "VssShareLinkageSourceStatement",
                    "ceremonyId": "vss-test",
                    "manifestHash": "1".repeat(128),
                    "rosterHash": "2".repeat(128),
                    "setupParametersHash": "3".repeat(128),
                    "setupEpoch": "setup-epoch",
                    "publicMatrixSeedHash": "7".repeat(128),
                    "targetBasisHash": target_basis_hash.clone(),
                    "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "ringDegree": 8,
                    "participantCount": 2,
                    "targetRnsLimbCount": 2,
                    "thresholdDegree": 2,
                    "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
                    "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"].clone(),
                    "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"].clone(),
                    "coefficientOpeningRoots": coefficient_opening_roots,
                    "recipientShareOpeningRoots": recipient_share_opening_roots,
                    "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
                });
                let mut source_statement = source_statement_without_root;
                source_statement["sourceStatementRoot"] = json!(
                    crate::hashing::derive_canonical_object_hash(&source_statement,
                    )
                    .expect("source statement root")
                );
                source_statement
            })
            .collect::<Vec<_>>();
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "ceremonyId": "vss-test",
        "manifestHash": "1".repeat(128),
        "rosterHash": "2".repeat(128),
        "setupParametersHash": "3".repeat(128),
        "setupEpoch": "setup-epoch",
        "publicMatrixSeedHash": "7".repeat(128),
        "targetBasisHash": target_basis_hash,
        "ringDegree": 8,
        "participantCount": 2,
        "targetRnsLimbCount": 2,
        "thresholdDegree": 2,
        "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
        "recipientShareCommitmentRoot": recipient_set["recipientShareCommitmentRoot"].clone(),
        "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
        "sourceStatementRecords": source_statement_records,
    });

    let mut statement = statement_without_root;
    statement["statementRoot"] =
        json!(crate::hashing::derive_canonical_object_hash(&statement).expect("statement root"));
    statement
}

fn rebind_share_linkage_source_statement_root(
    source_statement: &mut serde_json::Value,
) -> CanonicalResult<()> {
    let mut source_statement_without_root = source_statement
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share linkage source statement must be an object",
            )
        })?
        .clone();
    source_statement_without_root.remove("sourceStatementRoot");
    source_statement["sourceStatementRoot"] = json!(crate::hashing::derive_canonical_object_hash(
        &serde_json::Value::Object(source_statement_without_root),
    )?);

    Ok(())
}

fn rebind_share_linkage_statement_root(statement: &mut serde_json::Value) -> CanonicalResult<()> {
    let mut statement_without_root = statement
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share linkage statement must be an object",
            )
        })?
        .clone();
    statement_without_root.remove("statementRoot");
    statement["statementRoot"] = json!(crate::hashing::derive_canonical_object_hash(
        &serde_json::Value::Object(statement_without_root),
    )?);

    Ok(())
}

fn tamper_aggregate_commitment_body(aggregate_set: &mut serde_json::Value) -> CanonicalResult<()> {
    let aggregate_record = &mut aggregate_set["recipientRecords"][0];
    let modulus = aggregate_record["commitment"]["commitmentLimbs"][0]["modulus"]
        .as_u64()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS fixture aggregate modulus must be an unsigned integer",
            )
        })?;
    let coordinate = aggregate_record["commitment"]["commitmentLimbs"][0]["coordinates"][0]
        .as_u64()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS fixture aggregate coordinate must be an unsigned integer",
            )
        })?;
    aggregate_record["commitment"]["commitmentLimbs"][0]["coordinates"][0] =
        json!((coordinate + 1) % modulus);
    aggregate_record["aggregateCommitmentRoot"] = json!(
        crate::hashing::derive_canonical_object_hash(&aggregate_record["commitment"],)?
    );
    rebind_aggregate_threshold_commitment_set_root(aggregate_set)
}

fn rebind_aggregate_threshold_commitment_set_root(
    aggregate_set: &mut serde_json::Value,
) -> CanonicalResult<()> {
    let mut aggregate_set_without_root = aggregate_set
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS aggregate threshold commitment set must be an object",
            )
        })?
        .clone();
    aggregate_set_without_root.remove("aggregateThresholdCommitmentRoot");
    aggregate_set["aggregateThresholdCommitmentRoot"] =
        json!(crate::hashing::derive_canonical_object_hash(
            &serde_json::Value::Object(aggregate_set_without_root),
        )?);

    Ok(())
}
