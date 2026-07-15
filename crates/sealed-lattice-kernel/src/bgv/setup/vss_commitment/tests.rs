use serde_json::json;

use super::{
    VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT, VSS_PUBLIC_MESSAGE_DIGIT_BASE,
    VssPublicAggregateThresholdCommitmentSetContext, VssPublicCoefficientCommitmentSetContext,
    VssPublicRecipientShareCommitmentSetContext,
    verify_vss_public_aggregate_threshold_commitment_set,
    verify_vss_public_coefficient_commitment_set, verify_vss_public_recipient_share_commitment_set,
    verify_vss_share_linkage_bindings_request, vss_public_message_encoding_layout,
    vss_public_share_linkage_packed_message_encoding_layout,
};
use crate::bgv::parameters::DATA_PRIMES;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::derive_canonical_object_hash;

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
fn coefficient_commitment_set_derives_its_canonical_root() -> CanonicalResult<()> {
    let coefficient_set = coefficient_commitment_set()?;
    let verification = verify_vss_public_coefficient_commitment_set(
        &coefficient_set,
        &coefficient_commitment_set_context(&coefficient_set),
    )?;

    assert_eq!(
        verification,
        derive_canonical_object_hash(&coefficient_set)?
    );

    Ok(())
}

#[test]
fn coefficient_commitment_set_rejects_a_rebound_noncanonical_rns_prime() -> CanonicalResult<()> {
    let mut coefficient_set = coefficient_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let coefficient_record =
        &mut coefficient_set["sourceTrusteeRecords"][0]["coefficientCommitments"][0];
    coefficient_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);

    let error = verify_vss_public_coefficient_commitment_set(
        &coefficient_set,
        &coefficient_commitment_set_context(&coefficient_set),
    )
    .expect_err("a rebound coefficient record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("rnsPrime"));
    Ok(())
}

#[test]
fn coefficient_commitment_set_rejects_a_rebound_wrong_ring_degree() -> CanonicalResult<()> {
    let mut coefficient_set = coefficient_commitment_set()?;
    let coefficient_record =
        &mut coefficient_set["sourceTrusteeRecords"][0]["coefficientCommitments"][0];
    coefficient_record["commitment"]["ringDegree"] = json!(test_ring_degree() * 2);

    let error = verify_vss_public_coefficient_commitment_set(
        &coefficient_set,
        &coefficient_commitment_set_context(&coefficient_set),
    )
    .expect_err("a rebound commitment using a different ring degree must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("ringDegree"));
    Ok(())
}

#[test]
fn commitment_sets_reject_rebound_caller_selected_context_hashes() -> CanonicalResult<()> {
    let forged_context_hash = "a".repeat(128);

    let mut coefficient_set = coefficient_commitment_set()?;
    let coefficient_record =
        &mut coefficient_set["sourceTrusteeRecords"][0]["coefficientCommitments"][0];
    coefficient_record["commitment"]["commitmentContextHash"] = json!(forged_context_hash.clone());
    let coefficient_error = verify_vss_public_coefficient_commitment_set(
        &coefficient_set,
        &coefficient_commitment_set_context(&coefficient_set),
    )
    .expect_err("a rebound coefficient context hash must reject");
    assert!(coefficient_error.message.contains("commitmentContextHash"));

    let mut recipient_set = recipient_share_commitment_set()?;
    let recipient_record =
        &mut recipient_set["sourceTrusteeRecords"][0]["recipientShareCommitments"][0];
    recipient_record["commitment"]["commitmentContextHash"] = json!(forged_context_hash.clone());
    let recipient_error = verify_vss_public_recipient_share_commitment_set(
        &recipient_set,
        &recipient_share_commitment_set_context(&recipient_set),
    )
    .expect_err("a rebound recipient-share context hash must reject");
    assert!(recipient_error.message.contains("commitmentContextHash"));

    let mut aggregate_set = aggregate_threshold_commitment_set()?;
    let aggregate_record = &mut aggregate_set["recipientRecords"][0];
    aggregate_record["commitment"]["commitmentContextHash"] = json!(forged_context_hash);
    let aggregate_error = verify_vss_public_aggregate_threshold_commitment_set(
        &aggregate_set,
        &aggregate_threshold_commitment_set_context(&aggregate_set),
    )
    .expect_err("a rebound aggregate context hash must reject");
    assert!(aggregate_error.message.contains("commitmentContextHash"));

    Ok(())
}

#[test]
fn recipient_share_commitment_set_derives_its_canonical_root() -> CanonicalResult<()> {
    let recipient_set = recipient_share_commitment_set()?;
    let verification = verify_vss_public_recipient_share_commitment_set(
        &recipient_set,
        &recipient_share_commitment_set_context(&recipient_set),
    )?;

    assert_eq!(verification, derive_canonical_object_hash(&recipient_set)?);

    Ok(())
}

#[test]
fn recipient_share_commitment_set_rejects_a_rebound_noncanonical_rns_prime() -> CanonicalResult<()>
{
    let mut recipient_set = recipient_share_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let recipient_share_record =
        &mut recipient_set["sourceTrusteeRecords"][0]["recipientShareCommitments"][0];
    recipient_share_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);

    let error = verify_vss_public_recipient_share_commitment_set(
        &recipient_set,
        &recipient_share_commitment_set_context(&recipient_set),
    )
    .expect_err("a rebound recipient-share record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("rnsPrime"));
    Ok(())
}

#[test]
fn aggregate_threshold_commitment_set_derives_its_canonical_root() -> CanonicalResult<()> {
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let verification = verify_vss_public_aggregate_threshold_commitment_set(
        &aggregate_set,
        &aggregate_threshold_commitment_set_context(&aggregate_set),
    )?;

    assert_eq!(verification, derive_canonical_object_hash(&aggregate_set)?);

    Ok(())
}

#[test]
fn aggregate_threshold_commitment_set_rejects_a_rebound_noncanonical_rns_prime()
-> CanonicalResult<()> {
    let mut aggregate_set = aggregate_threshold_commitment_set()?;
    let noncanonical_prime = DATA_PRIMES[1];
    let aggregate_record = &mut aggregate_set["recipientRecords"][0];
    aggregate_record["commitment"]["rnsPrime"] = json!(noncanonical_prime);

    let error = verify_vss_public_aggregate_threshold_commitment_set(
        &aggregate_set,
        &aggregate_threshold_commitment_set_context(&aggregate_set),
    )
    .expect_err("a rebound aggregate-threshold record using another limb's prime must reject");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("rnsPrime"));
    Ok(())
}

#[test]
fn commitment_sets_reject_rebound_noncanonical_record_order() -> CanonicalResult<()> {
    let mut coefficient_set = coefficient_commitment_set()?;
    coefficient_set["sourceTrusteeRecords"][0]["coefficientCommitments"]
        .as_array_mut()
        .expect("coefficient records")
        .swap(0, test_threshold_degree());
    let coefficient_error = verify_vss_public_coefficient_commitment_set(
        &coefficient_set,
        &coefficient_commitment_set_context(&coefficient_set),
    )
    .expect_err("reordered coefficient records must reject");
    assert_eq!(
        coefficient_error.code,
        CanonicalErrorCode::ComponentMismatch
    );

    let mut recipient_set = recipient_share_commitment_set()?;
    recipient_set["sourceTrusteeRecords"][0]["recipientShareCommitments"]
        .as_array_mut()
        .expect("recipient-share records")
        .swap(0, 1);
    let recipient_error = verify_vss_public_recipient_share_commitment_set(
        &recipient_set,
        &recipient_share_commitment_set_context(&recipient_set),
    )
    .expect_err("reordered recipient-share records must reject");
    assert_eq!(recipient_error.code, CanonicalErrorCode::ComponentMismatch);

    let mut aggregate_set = aggregate_threshold_commitment_set()?;
    aggregate_set["recipientRecords"]
        .as_array_mut()
        .expect("aggregate records")
        .swap(0, 1);
    let aggregate_error = verify_vss_public_aggregate_threshold_commitment_set(
        &aggregate_set,
        &aggregate_threshold_commitment_set_context(&aggregate_set),
    )
    .expect_err("reordered aggregate records must reject");
    assert_eq!(aggregate_error.code, CanonicalErrorCode::ComponentMismatch);

    Ok(())
}

#[test]
fn share_linkage_bindings_command_derives_commitment_roots() -> CanonicalResult<()> {
    let coefficient_set = coefficient_commitment_set()?;
    let recipient_set = recipient_share_commitment_set()?;
    let aggregate_set = aggregate_threshold_commitment_set()?;
    let statement = share_linkage_statement();
    let verification = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
        "statement": statement.clone(),
        "coefficientCommitmentSet": coefficient_set.clone(),
        "recipientShareCommitmentSet": recipient_set.clone(),
        "aggregateThresholdCommitmentSet": aggregate_set.clone(),
    }))?;

    assert_eq!(
        verification["coefficientCommitmentRoot"],
        derive_canonical_object_hash(&coefficient_set)?
    );
    assert_eq!(
        verification["recipientShareCommitmentRoot"],
        derive_canonical_object_hash(&recipient_set)?
    );
    assert_eq!(
        verification["aggregateThresholdCommitmentRoot"],
        derive_canonical_object_hash(&aggregate_set)?
    );

    let missing_evidence_error = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
        "statement": statement.clone(),
    }))
    .expect_err("share-linkage statement verification must require evidence sets");
    assert!(
        missing_evidence_error
            .to_string()
            .contains("coefficientCommitmentSet"),
        "missing share-linkage evidence should identify the required commitment set: {missing_evidence_error}"
    );

    let mut changed_aggregate_set = aggregate_set;
    changed_aggregate_set["recipientRecords"][0]["commitment"]["commitmentFields"][0]["materialRootHex"] =
        json!("8".repeat(128));
    let changed_verification = verify_vss_share_linkage_bindings_request(&json!({
        "command": "VerifyVssShareLinkageBindings",
        "statement": statement,
        "coefficientCommitmentSet": coefficient_set,
        "recipientShareCommitmentSet": recipient_set,
        "aggregateThresholdCommitmentSet": changed_aggregate_set.clone(),
    }))?;
    assert_eq!(
        changed_verification["aggregateThresholdCommitmentRoot"],
        derive_canonical_object_hash(&changed_aggregate_set)?
    );
    assert_ne!(
        changed_verification["aggregateThresholdCommitmentRoot"],
        verification["aggregateThresholdCommitmentRoot"]
    );

    Ok(())
}

pub(in crate::bgv::setup) fn coefficient_commitment_set() -> CanonicalResult<serde_json::Value> {
    let mut source_trustee_records = Vec::new();
    for source_trustee_roster_position in 0..2_usize {
        source_trustee_records.push(source_coefficient_record(source_trustee_roster_position)?);
    }
    Ok(json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": "7".repeat(128),
        "sourceTrusteeRecords": source_trustee_records,
    }))
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
                "commitment": computation.commitment,
            }));
        }
    }
    Ok(json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
        "coefficientCommitments": coefficient_commitments,
    }))
}

fn test_participant_count() -> usize {
    2
}

fn test_rns_limb_count() -> usize {
    DATA_PRIMES.len()
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

fn test_setup_context_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| "1".repeat(128))
}

fn coefficient_commitment_set_context(
    coefficient_set: &serde_json::Value,
) -> VssPublicCoefficientCommitmentSetContext<'_> {
    VssPublicCoefficientCommitmentSetContext {
        setup_context_hash: test_setup_context_hash(),
        public_matrix_seed_hash: coefficient_set["publicMatrixSeedHash"]
            .as_str()
            .expect("coefficient public matrix seed hash"),
        participant_count: test_participant_count(),
        rns_limb_count: test_rns_limb_count(),
        threshold_degree: test_threshold_degree(),
        ring_degree: test_ring_degree(),
    }
}

fn recipient_share_commitment_set_context(
    recipient_set: &serde_json::Value,
) -> VssPublicRecipientShareCommitmentSetContext<'_> {
    VssPublicRecipientShareCommitmentSetContext {
        setup_context_hash: test_setup_context_hash(),
        public_matrix_seed_hash: recipient_set["publicMatrixSeedHash"]
            .as_str()
            .expect("recipient-share public matrix seed hash"),
        participant_count: test_participant_count(),
        rns_limb_count: test_rns_limb_count(),
        ring_degree: test_ring_degree(),
    }
}

fn aggregate_threshold_commitment_set_context(
    aggregate_set: &serde_json::Value,
) -> VssPublicAggregateThresholdCommitmentSetContext<'_> {
    VssPublicAggregateThresholdCommitmentSetContext {
        setup_context_hash: test_setup_context_hash(),
        public_matrix_seed_hash: aggregate_set["publicMatrixSeedHash"]
            .as_str()
            .expect("aggregate public matrix seed hash"),
        participant_count: test_participant_count(),
        rns_limb_count: test_rns_limb_count(),
        ring_degree: test_ring_degree(),
    }
}

fn test_rns_prime(rns_limb_index: usize) -> u64 {
    DATA_PRIMES[rns_limb_index]
}

fn test_seed(seed_parts: &[usize]) -> usize {
    seed_parts
        .iter()
        .fold(0_usize, |seed, seed_part| seed * 31 + seed_part + 1)
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

struct TestVssCommitmentComputation {
    commitment: serde_json::Value,
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
    let commitment_context = match commitment_role {
        "coefficient" => json!({
            "objectType": "VssPublicCoefficientCommitmentContext",
            "setupContextHash": test_setup_context_hash(),
            "sourceTrusteeIdentity": format!("source-{}", seed_parts[0]),
            "sourceTrusteeRosterPosition": seed_parts[0],
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shamirCoefficientIndex": seed_parts[2],
        }),
        "recipient-share" => json!({
            "objectType": "VssPublicRecipientShareCommitmentContext",
            "setupContextHash": test_setup_context_hash(),
            "sourceTrusteeIdentity": format!("source-{}", seed_parts[0]),
            "sourceTrusteeRosterPosition": seed_parts[0],
            "recipientIdentity": format!("recipient-{}", seed_parts[1]),
            "recipientRosterPosition": seed_parts[1],
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
        }),
        "aggregate-threshold-share" => json!({
            "objectType": "VssPublicAggregateThresholdCommitmentContext",
            "setupContextHash": test_setup_context_hash(),
            "recipientIdentity": format!("recipient-{}", seed_parts[0]),
            "recipientRosterPosition": seed_parts[0],
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
        }),
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "unsupported test commitment role",
            ));
        }
    };
    let response = crate::bgv::setup::compute_vss_committed_material_commitment_request(&json!({
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
        "rnsLimbIndex": rns_limb_index,
        "ringDegree": test_ring_degree(),
        "messageCoefficients": message_coefficients,
        "materialSeedHex": test_committed_material_seed(seed),
    }))?;

    Ok(TestVssCommitmentComputation {
        commitment: response["commitment"].clone(),
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
    Ok(json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": test_public_matrix_seed_hash(),
        "sourceTrusteeRecords": source_trustee_records,
    }))
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
    Ok(json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": format!("source-{source_trustee_roster_position}"),
        "recipientShareCommitments": recipient_share_commitments,
    }))
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
        "recipientIdentity": format!("recipient-{recipient_roster_position}"),
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
    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": test_public_matrix_seed_hash(),
        "recipientRecords": recipient_records,
    }))
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
        "aggregateOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    }))
}

fn share_linkage_statement() -> serde_json::Value {
    json!({
        "objectType": "VssShareLinkageStatement",
        "setupContextHash": "1".repeat(128),
        "publicMatrixSeedHash": "7".repeat(128),
        "ringDegree": test_ring_degree(),
    })
}
