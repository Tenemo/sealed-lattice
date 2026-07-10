use serde_json::json;

use super::{
    VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, VSS_PUBLIC_MESSAGE_DIGIT_BASE,
    verify_vss_public_aggregate_threshold_commitment_set_request,
    verify_vss_public_coefficient_commitment_set_request,
    verify_vss_public_recipient_share_commitment_set_request,
    verify_vss_share_linkage_bindings_request, vss_public_message_encoding_layout,
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

    assert_eq!(verification["operation"], "verifyVssShareLinkageBindings");
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
    let missing_evidence_error = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
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
        verify_vss_share_linkage_bindings_request(&json!({
            "command": "VerifyVssShareLinkageBindings",
            "statement": forged_source_statement,
            "coefficientCommitmentSet": coefficient_set.clone(),
            "recipientShareCommitmentSet": recipient_set.clone(),
            "aggregateThresholdCommitmentSet": aggregate_set.clone(),
        }))
        .is_err(),
        "evidence-backed linkage verification must reject a source root absent from the recipient-share set"
    );

    // The "T = sum" aggregate binding is no longer a public homomorphic sum
    // checked here; it is a threshold-aggregate proof verified on the
    // accepted-setup material path. The statement evidence check binds only the
    // committed roots across the sets.

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
    // The committed-material commitment hosts TRACE_SPLIT half-columns over a
    // trace domain with a minimum size, so the set-verifier fixtures use a valid
    // supported ring degree rather than a tiny structural one.
    128
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
        "recipientTrusteePoint": recipient_roster_position + 1,
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
                    "ringDegree": test_ring_degree(),
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
        "ringDegree": test_ring_degree(),
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
