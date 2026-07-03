use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::accounting::{
    succinct_evaluation_key_proof_accounting_hash, succinct_evaluation_key_proof_accounting_value,
    succinct_private_vss_share_accounting_hash, succinct_private_vss_share_accounting_value,
    succinct_public_key_share_accounting_hash, succinct_public_key_share_accounting_value,
    succinct_same_secret_linkage_anchor_accounting_hash,
    succinct_same_secret_linkage_anchor_accounting_value,
    succinct_target_decryption_share_accounting_hash,
    succinct_target_decryption_share_accounting_value,
};
use super::proof_codec::{
    decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    CompactSameSecretBridgeStatement, CompactVssShareLinkageCommitment, CompactVssShareLinkageItem,
    CompactVssShareLinkageStatement, EvaluationKeyShareDescriptor, EvaluationKeyShareKind,
    SameSecretLinkageStatement, SuccinctSetupProofContext, SuccinctSetupProofFamilyShape,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
};
#[cfg(any(feature = "target-decryption-development-commands", test))]
use super::relation::{LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, TargetDecryptionMessageClaimKind};
use super::relation::{
    TargetDecryptionShareLimbStatement, TargetDecryptionShareRoleStatement,
    TargetDecryptionShareStatement,
};
use super::verifier::verify_evaluation_key_share;
use super::*;
use crate::bgv::profile::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_setup_commitment_full_value,
};
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_COMMITMENT_PROFILE_ID, COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
    COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
};
use crate::bgv::setup::setup_proof::SETUP_PROOF_PROFILE_ID;
use crate::hashing::{derive_protocol_hash, hash512_hex, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/compact-vss-share-linkage/proof-bytes-v1";
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE: &str =
    "target-decryption-smudging-polynomial-coefficient";
const TARGET_DECRYPTION_PROOF_TARGET_ROLES: [&str; 2] = ["targetId", "targetOrder"];

#[cfg(any(feature = "target-decryption-development-commands", test))]
#[derive(Debug)]
pub(crate) struct GeneratedTargetDecryptionShareProofBytes {
    pub(crate) target_roles: Vec<String>,
    pub(crate) target_rns_limb_indices: Vec<usize>,
    pub(crate) proof_bytes: Vec<u8>,
}

pub(in crate::bgv::setup) struct CompactVssCommandCommitmentExpectation<'a> {
    pub(in crate::bgv::setup) field_name: String,
    pub(in crate::bgv::setup) root: &'a str,
    pub(in crate::bgv::setup) role: &'a str,
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) rns_prime: u64,
    pub(in crate::bgv::setup) ring_degree: usize,
}

// The accounting object each migrated family carries on its command responses.
// The argument machinery is shared, so only the family label and accounting
// object differ.
fn family_accounting_hash(shape: SuccinctSetupProofFamilyShape) -> CanonicalResult<String> {
    match shape {
        SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
            succinct_same_secret_linkage_anchor_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            succinct_public_key_share_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::PrivateVssShare => {
            succinct_private_vss_share_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::CompactVssShareLinkage => Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage accounting is not exposed through the trustee proof command",
        )),
        SuccinctSetupProofFamilyShape::CompactSameSecretBridge => {
            Err(invalid_succinct_setup_proof(
                "compact same-secret bridge accounting is not exposed through the trustee proof command",
            ))
        }
        SuccinctSetupProofFamilyShape::TargetDecryptionShare => {
            succinct_target_decryption_share_accounting_hash()
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            succinct_evaluation_key_proof_accounting_hash()
        }
    }
}

fn family_accounting_value(shape: SuccinctSetupProofFamilyShape) -> CanonicalResult<Value> {
    match shape {
        SuccinctSetupProofFamilyShape::SameSecretLinkageAnchor => {
            succinct_same_secret_linkage_anchor_accounting_value()
        }
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            succinct_public_key_share_accounting_value()
        }
        SuccinctSetupProofFamilyShape::PrivateVssShare => {
            succinct_private_vss_share_accounting_value()
        }
        SuccinctSetupProofFamilyShape::CompactVssShareLinkage => Err(invalid_succinct_setup_proof(
            "compact VSS share-linkage accounting is not exposed through the trustee proof command",
        )),
        SuccinctSetupProofFamilyShape::CompactSameSecretBridge => {
            Err(invalid_succinct_setup_proof(
                "compact same-secret bridge accounting is not exposed through the trustee proof command",
            ))
        }
        SuccinctSetupProofFamilyShape::TargetDecryptionShare => {
            succinct_target_decryption_share_accounting_value()
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            succinct_evaluation_key_proof_accounting_value()
        }
    }
}

// Generate one trustee-batched evaluation-key proof from a JSON request. The
// statement carries the ceremony context, the key descriptors with embedded
// component material, and the same-secret linkage commitments; the witness
// carries the shared secret, per-key errors, and the linkage openings. The
// response returns canonical proof bytes; chunked transport wraps those bytes
// at the protocol layer.
pub(crate) fn generate_trustee_evaluation_key_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = statement_from_request(request)?;
    let secret_coefficients = read_i64_array(request, "secretCoefficients")?;
    let error_coefficients_by_key = match request.get("errorCoefficientsByKey") {
        Some(_) => read_i64_matrix(request, "errorCoefficientsByKey")?,
        None => Vec::new(),
    };
    let negative_indicator_coefficients = match request.get("negativeIndicatorCoefficients") {
        Some(_) => read_i64_array(request, "negativeIndicatorCoefficients")?,
        None => Vec::new(),
    };
    let opening_randomness_by_limb = match request.get("openingRandomnessByLimb") {
        Some(_) => read_i64_matrix(request, "openingRandomnessByLimb")?,
        None => Vec::new(),
    };
    let witness = TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key,
        negative_indicator_coefficients,
        opening_randomness_by_limb,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_messages: Vec::new(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_opening_randomness: Vec::new(),
        compact_vss_carry_witnesses: Vec::new(),
        compact_vss_recipient_share_messages_by_item: Vec::new(),
        compact_vss_recipient_share_opening_randomness_by_item: Vec::new(),
        compact_vss_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    };
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;

    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let shape = statement.family_shape()?;

    Ok(json!({
        "ok": true,
        "operation": "generateTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "proofAccountingHash": family_accounting_hash(shape)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "keyCount": statement.keys.len(),
        "sameSecretLinkageIncluded": statement.same_secret_linkage.is_some(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

fn statement_bound_proof_randomness_seed_hex(
    statement: &TrusteeEvaluationKeyStatement,
    proof_randomness_seed_hex: &str,
    proof_randomness_nonce_hex: &str,
) -> CanonicalResult<String> {
    let seed_bytes = decode_exact_hex_bytes(
        proof_randomness_seed_hex,
        PROOF_RANDOMNESS_SEED_BYTES,
        "proofRandomnessSeedHex",
    )?;
    decode_exact_hex_bytes(
        proof_randomness_nonce_hex,
        PROOF_RANDOMNESS_NONCE_BYTES,
        "proofRandomnessNonceHex",
    )?;
    let statement_hash = to_hex(&statement.statement_hash());

    derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &json!({
            "objectType": "TrusteeEvaluationKeyProofRandomnessBinding",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": &statement.context.proof_family,
            "statementHash": statement_hash,
            "trusteeIdentity": &statement.context.trustee_identity,
            "trusteeRosterPosition": statement.context.trustee_roster_position,
            "setupEpoch": &statement.context.setup_epoch,
            "proofRandomnessNonceHex": proof_randomness_nonce_hex,
            "proofRandomnessSeedHex": to_hex(&seed_bytes),
        }),
    )
}

pub(crate) fn verify_trustee_evaluation_key_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let shape = statement.family_shape()?;

    Ok(json!({
        "ok": true,
        "operation": "verifyTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "proofAccountingHash": family_accounting_hash(shape)?,
        "proofAccounting": family_accounting_value(shape)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "keyCount": statement.keys.len(),
        "sameSecretLinkageIncluded": statement.same_secret_linkage.is_some(),
        "proofByteLength": proof_bytes.len(),
    }))
}

pub(crate) fn generate_compact_vss_share_linkage_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = compact_vss_share_linkage_statement_from_request(request)?;
    let witness = compact_vss_share_linkage_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let compact_statement = statement
        .compact_vss_share_linkage
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("compact share-linkage statement missing"))?;

    Ok(json!({
        "ok": true,
        "operation": "generateCompactVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "coefficientCommitmentCount": compact_statement.total_coefficient_commitment_count(),
        "coefficientWitnessColumnCount": compact_statement.unique_coefficient_witness_slot_count(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

pub(crate) fn verify_compact_vss_share_linkage_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = compact_vss_share_linkage_statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let compact_statement = statement
        .compact_vss_share_linkage
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("compact share-linkage statement missing"))?;

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "coefficientCommitmentCount": compact_statement.total_coefficient_commitment_count(),
        "coefficientWitnessColumnCount": compact_statement.unique_coefficient_witness_slot_count(),
        "proofByteLength": proof_bytes.len(),
    }))
}

struct CompactVssShareLinkageMaterialRecordStatementInput<'a> {
    proof_statement: &'a Value,
    statement: &'a Value,
    statement_root: &'a str,
    coefficient_commitment_set: &'a Value,
    recipient_share_commitment_set: &'a Value,
    participant_count: usize,
    target_rns_limb_count: usize,
    threshold_degree: usize,
}

struct CompactVssShareLinkagePublicRecordInput<'a> {
    item: &'a Value,
    statement: &'a Value,
    coefficient_commitment_set: &'a Value,
    recipient_share_commitment_set: &'a Value,
    participant_count: usize,
    target_rns_limb_count: usize,
    threshold_degree: usize,
    item_index: usize,
}

fn compare_string_value(actual: &str, expected: &str, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(invalid_succinct_setup_proof(format!(
            "{description} must match"
        )));
    }

    Ok(())
}

fn compare_u64_value(actual: u64, expected: u64, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(invalid_succinct_setup_proof(format!(
            "{description} must match"
        )));
    }

    Ok(())
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))
}

fn compact_vss_share_linkage_item_values(proof_statement: &Value) -> CanonicalResult<Vec<&Value>> {
    let mut items = vec![proof_statement];
    match proof_statement.get("additionalLinkageItems") {
        None => {}
        Some(Value::Array(additional_items)) => items.extend(additional_items.iter()),
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "compactVssShareLinkage.additionalLinkageItems must be an array",
            ));
        }
    }

    Ok(items)
}

fn verify_compact_vss_share_linkage_material_record_statement(
    input: CompactVssShareLinkageMaterialRecordStatementInput<'_>,
) -> CanonicalResult<Vec<Value>> {
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            read_string(input.statement, "publicMatrixSeedHash")?,
        ),
        ("shareLinkageStatementRoot", input.statement_root),
    ] {
        compare_string_value(
            read_string(input.proof_statement, field_name)?,
            expected_value,
            &format!("compact share-linkage proof statement {field_name}"),
        )?;
    }

    let items = compact_vss_share_linkage_item_values(input.proof_statement)?;
    if items.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof statement must cover at least one item",
        ));
    }
    let mut coverage = Vec::with_capacity(items.len());
    for (item_index, &item) in items.iter().enumerate() {
        coverage.push(
            verify_compact_vss_share_linkage_item_against_public_records(
                CompactVssShareLinkagePublicRecordInput {
                    item,
                    statement: input.statement,
                    coefficient_commitment_set: input.coefficient_commitment_set,
                    recipient_share_commitment_set: input.recipient_share_commitment_set,
                    participant_count: input.participant_count,
                    target_rns_limb_count: input.target_rns_limb_count,
                    threshold_degree: input.threshold_degree,
                    item_index,
                },
            )?,
        );
    }

    Ok(coverage)
}

fn verify_compact_vss_share_linkage_item_against_public_records(
    input: CompactVssShareLinkagePublicRecordInput<'_>,
) -> CanonicalResult<Value> {
    let item = input.item;
    let statement = input.statement;
    let coefficient_commitment_set = input.coefficient_commitment_set;
    let recipient_share_commitment_set = input.recipient_share_commitment_set;
    let participant_count = input.participant_count;
    let target_rns_limb_count = input.target_rns_limb_count;
    let threshold_degree = input.threshold_degree;
    let item_index = input.item_index;
    let source_roster_position = usize::try_from(read_u64(item, "sourceTrusteeRosterPosition")?)
        .map_err(|_| {
            invalid_succinct_setup_proof(
                "compact share-linkage item sourceTrusteeRosterPosition does not fit usize",
            )
        })?;
    let recipient_roster_position = usize::try_from(read_u64(item, "recipientRosterPosition")?)
        .map_err(|_| {
            invalid_succinct_setup_proof(
                "compact share-linkage item recipientRosterPosition does not fit usize",
            )
        })?;
    let source_rns_limb_index =
        usize::try_from(read_u64(item, "sourceRnsLimbIndex")?).map_err(|_| {
            invalid_succinct_setup_proof(
                "compact share-linkage item sourceRnsLimbIndex does not fit usize",
            )
        })?;
    if recipient_roster_position >= participant_count
        || source_rns_limb_index >= target_rns_limb_count
    {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage item coverage is outside the source statement dimensions",
        ));
    }
    let source_statement_records = array_field(statement, "sourceStatementRecords")?;
    let source_statement = source_statement_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage item source is outside the statement",
            )
        })?;
    compare_string_value(
        read_string(item, "sourceTrusteeIdentity")?,
        read_string(source_statement, "sourceTrusteeIdentity")?,
        "compact share-linkage proof item sourceTrusteeIdentity",
    )?;
    compare_string_value(
        read_string(item, "sourceCoefficientCommitmentRoot")?,
        read_string(source_statement, "sourceCoefficientCommitmentRoot")?,
        "compact share-linkage proof item sourceCoefficientCommitmentRoot",
    )?;
    compare_string_value(
        read_string(item, "sourceRecipientShareCommitmentRoot")?,
        read_string(source_statement, "sourceRecipientShareCommitmentRoot")?,
        "compact share-linkage proof item sourceRecipientShareCommitmentRoot",
    )?;

    let coefficient_source_records =
        array_field(coefficient_commitment_set, "sourceTrusteeRecords")?;
    let recipient_source_records =
        array_field(recipient_share_commitment_set, "sourceTrusteeRecords")?;
    let coefficient_source_record = coefficient_source_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage coefficient set is missing the proof source",
            )
        })?;
    let recipient_source_record = recipient_source_records
        .get(source_roster_position)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage recipient-share set is missing the proof source",
            )
        })?;
    for source_record in [coefficient_source_record, recipient_source_record] {
        compare_string_value(
            read_string(source_record, "sourceTrusteeIdentity")?,
            read_string(source_statement, "sourceTrusteeIdentity")?,
            "compact share-linkage proof sourceTrusteeIdentity",
        )?;
        compare_u64_value(
            read_u64(source_record, "sourceTrusteeRosterPosition")?,
            source_roster_position as u64,
            "compact share-linkage proof sourceTrusteeRosterPosition",
        )?;
    }
    compare_string_value(
        read_string(coefficient_source_record, "sourceCoefficientCommitmentRoot")?,
        read_string(source_statement, "sourceCoefficientCommitmentRoot")?,
        "compact share-linkage proof sourceCoefficientCommitmentRoot",
    )?;
    compare_string_value(
        read_string(
            recipient_source_record,
            "sourceRecipientShareCommitmentRoot",
        )?,
        read_string(source_statement, "sourceRecipientShareCommitmentRoot")?,
        "compact share-linkage proof sourceRecipientShareCommitmentRoot",
    )?;

    let source_message_modulus = read_u64(item, "sourceMessageModulus")?;
    let coefficient_commitment_roots = read_string_array(item, "coefficientCommitmentRoots")?;
    let coefficient_opening_roots = read_string_array(item, "coefficientOpeningRoots")?;
    let coefficient_commitments = array_field(item, "coefficientCommitments")?;
    if coefficient_commitment_roots.len() != threshold_degree
        || coefficient_opening_roots.len() != threshold_degree
        || coefficient_commitments.len() != threshold_degree
    {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof item must carry one coefficient commitment per threshold coefficient",
        ));
    }
    let coefficient_records = array_field(coefficient_source_record, "coefficientCommitments")?;
    let source_statement_coefficient_opening_roots =
        array_field(source_statement, "coefficientOpeningRoots")?;
    for coefficient_index in 0..threshold_degree {
        let coefficient_record_index = source_rns_limb_index
            .checked_mul(threshold_degree)
            .and_then(|offset| offset.checked_add(coefficient_index))
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact share-linkage coefficient record index overflowed",
                )
            })?;
        let coefficient_record = coefficient_records
            .get(coefficient_record_index)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact share-linkage coefficient set is missing a proof item coefficient",
                )
            })?;
        compare_u64_value(
            read_u64(coefficient_record, "rnsLimbIndex")?,
            source_rns_limb_index as u64,
            "compact share-linkage proof coefficient rnsLimbIndex",
        )?;
        compare_u64_value(
            read_u64(coefficient_record, "rnsPrime")?,
            source_message_modulus,
            "compact share-linkage proof coefficient rnsPrime",
        )?;
        compare_u64_value(
            read_u64(coefficient_record, "shamirCoefficientIndex")?,
            coefficient_index as u64,
            "compact share-linkage proof coefficient shamirCoefficientIndex",
        )?;
        compare_string_value(
            &coefficient_commitment_roots[coefficient_index],
            read_string(coefficient_record, "coefficientCommitmentRoot")?,
            "compact share-linkage proof coefficientCommitmentRoot",
        )?;
        compare_string_value(
            &coefficient_opening_roots[coefficient_index],
            read_string(coefficient_record, "coefficientOpeningRoot")?,
            "compact share-linkage proof coefficientOpeningRoot",
        )?;
        if source_statement_coefficient_opening_roots
            .get(coefficient_record_index)
            .and_then(Value::as_str)
            != Some(coefficient_opening_roots[coefficient_index].as_str())
        {
            return Err(invalid_succinct_setup_proof(
                "compact share-linkage proof coefficient opening root must match the source statement",
            ));
        }
        if coefficient_commitments.get(coefficient_index) != coefficient_record.get("commitment") {
            return Err(invalid_succinct_setup_proof(
                "compact share-linkage proof coefficient commitment body must match the public coefficient record",
            ));
        }
    }

    let recipient_records = array_field(recipient_source_record, "recipientShareCommitments")?;
    let recipient_record_index = recipient_roster_position
        .checked_mul(target_rns_limb_count)
        .and_then(|offset| offset.checked_add(source_rns_limb_index))
        .ok_or_else(|| {
            invalid_succinct_setup_proof("compact share-linkage recipient record index overflowed")
        })?;
    let recipient_record = recipient_records
        .get(recipient_record_index)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage recipient-share set is missing a proof item recipient",
            )
        })?;
    compare_string_value(
        read_string(item, "recipientIdentity")?,
        read_string(recipient_record, "recipientIdentity")?,
        "compact share-linkage proof recipientIdentity",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "recipientRosterPosition")?,
        recipient_roster_position as u64,
        "compact share-linkage proof recipientRosterPosition",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "rnsLimbIndex")?,
        source_rns_limb_index as u64,
        "compact share-linkage proof recipient rnsLimbIndex",
    )?;
    compare_u64_value(
        read_u64(recipient_record, "rnsPrime")?,
        source_message_modulus,
        "compact share-linkage proof recipient rnsPrime",
    )?;
    compare_string_value(
        read_string(item, "recipientShareCommitmentRoot")?,
        read_string(recipient_record, "shareCommitmentRoot")?,
        "compact share-linkage proof recipientShareCommitmentRoot",
    )?;
    compare_string_value(
        read_string(item, "recipientShareOpeningRoot")?,
        read_string(recipient_record, "shareOpeningRoot")?,
        "compact share-linkage proof recipientShareOpeningRoot",
    )?;
    let source_statement_recipient_opening_roots =
        array_field(source_statement, "recipientShareOpeningRoots")?;
    if source_statement_recipient_opening_roots
        .get(recipient_record_index)
        .and_then(Value::as_str)
        != Some(read_string(item, "recipientShareOpeningRoot")?)
    {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof recipient opening root must match the source statement",
        ));
    }
    if item.get("recipientShareCommitment") != recipient_record.get("commitment") {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof recipient-share commitment body must match the public recipient-share record",
        ));
    }

    Ok(json!({
        "sourceTrusteeRosterPosition": source_roster_position,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": source_rns_limb_index,
        "itemIndex": item_index,
    }))
}

pub(crate) fn verify_compact_vss_share_linkage_proof_material_set_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = request.get("statement").ok_or_else(|| {
        invalid_succinct_setup_proof("compact share-linkage material statement must be present")
    })?;
    let statement_verification =
        super::super::verify_compact_vss_share_linkage_statement_request(request)?;
    let statement_root = read_string(&statement_verification, "statementRoot")?;
    let participant_count = usize::try_from(read_u64(&statement_verification, "participantCount")?)
        .map_err(|_| invalid_succinct_setup_proof("participantCount does not fit usize"))?;
    let target_rns_limb_count =
        usize::try_from(read_u64(&statement_verification, "targetRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("targetRnsLimbCount does not fit usize"))?;
    let threshold_degree =
        usize::try_from(read_u64(&statement_verification, "thresholdDegree")?)
            .map_err(|_| invalid_succinct_setup_proof("thresholdDegree does not fit usize"))?;
    let coefficient_commitment_set = request.get("coefficientCommitmentSet").ok_or_else(|| {
        invalid_succinct_setup_proof(
            "compact share-linkage material coefficientCommitmentSet must be present",
        )
    })?;
    let recipient_share_commitment_set =
        request.get("recipientShareCommitmentSet").ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage material recipientShareCommitmentSet must be present",
            )
        })?;
    let ring_degree = usize::try_from(read_u64(coefficient_commitment_set, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let proof_material_set = request.get("proofMaterialSet").ok_or_else(|| {
        invalid_succinct_setup_proof("compact share-linkage proofMaterialSet must be present")
    })?;

    compare_string_value(
        read_string(proof_material_set, "objectType")?,
        "CompactVssShareLinkageProofMaterialSet",
        "compact share-linkage proof material set objectType",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "objectVersion")?,
        1,
        "compact share-linkage proof material set objectVersion",
    )?;
    for (field_name, expected_value) in [
        ("setupProfileId", "CollectiveBgvSetup-v1"),
        ("profileId", COMPACT_VSS_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY),
        ("ceremonyId", read_string(statement, "ceremonyId")?),
        ("setupEpoch", read_string(statement, "setupEpoch")?),
    ] {
        compare_string_value(
            read_string(proof_material_set, field_name)?,
            expected_value,
            &format!("compact share-linkage proof material set {field_name}"),
        )?;
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "publicMatrixSeedHash",
        "targetBasisHash",
        "coefficientCommitmentRoot",
        "recipientShareCommitmentRoot",
        "aggregateThresholdCommitmentRoot",
    ] {
        compare_string_value(
            read_string(proof_material_set, field_name)?,
            read_string(statement, field_name)?,
            &format!("compact share-linkage proof material set {field_name}"),
        )?;
    }
    compare_string_value(
        read_string(proof_material_set, "statementRoot")?,
        statement_root,
        "compact share-linkage proof material set statementRoot",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "participantCount")?,
        participant_count as u64,
        "compact share-linkage proof material set participantCount",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "targetRnsLimbCount")?,
        target_rns_limb_count as u64,
        "compact share-linkage proof material set targetRnsLimbCount",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "thresholdDegree")?,
        threshold_degree as u64,
        "compact share-linkage proof material set thresholdDegree",
    )?;
    compare_u64_value(
        read_u64(proof_material_set, "ringDegree")?,
        ring_degree as u64,
        "compact share-linkage proof material set ringDegree",
    )?;

    let proof_records = proof_material_set
        .get("proofRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compact share-linkage proof material set proofRecords must be an array",
            )
        })?;
    if proof_records.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof material set must contain proof records",
        ));
    }

    let mut covered_items = BTreeSet::new();
    let mut verified_records = Vec::with_capacity(proof_records.len());
    let mut total_proof_byte_length = 0usize;
    let mut proof_verification_count = 0usize;
    for (proof_record_index, proof_record) in proof_records.iter().enumerate() {
        compare_string_value(
            read_string(proof_record, "objectType")?,
            "CompactVssShareLinkageProofRecord",
            "compact share-linkage proof record objectType",
        )?;
        compare_u64_value(
            read_u64(proof_record, "objectVersion")?,
            1,
            "compact share-linkage proof record objectVersion",
        )?;
        compare_string_value(
            read_string(proof_record, "proofFamily")?,
            COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "compact share-linkage proof record proofFamily",
        )?;

        let compact_vss_share_linkage =
            proof_record.get("compactVssShareLinkage").ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact share-linkage proof record compactVssShareLinkage must be present",
                )
            })?;
        let coverage = verify_compact_vss_share_linkage_material_record_statement(
            CompactVssShareLinkageMaterialRecordStatementInput {
                proof_statement: compact_vss_share_linkage,
                statement,
                statement_root,
                coefficient_commitment_set,
                recipient_share_commitment_set,
                participant_count,
                target_rns_limb_count,
                threshold_degree,
            },
        )?;
        let record_linkage_items = proof_record
            .get("linkageItems")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact share-linkage proof record linkageItems must be an array",
                )
            })?;
        if record_linkage_items.len() != coverage.len() {
            return Err(invalid_succinct_setup_proof(
                "compact share-linkage proof record linkageItems must match the proof statement coverage",
            ));
        }
        for (item_index, coverage_item) in coverage.iter().enumerate() {
            if record_linkage_items.get(item_index) != Some(coverage_item) {
                return Err(invalid_succinct_setup_proof(
                    "compact share-linkage proof record linkageItems must be the canonical proof statement coverage",
                ));
            }
            let source_roster_position = usize::try_from(read_u64(
                coverage_item,
                "sourceTrusteeRosterPosition",
            )?)
            .map_err(|_| {
                invalid_succinct_setup_proof(
                    "compact share-linkage coverage sourceTrusteeRosterPosition does not fit usize",
                )
            })?;
            let recipient_roster_position = usize::try_from(read_u64(
                coverage_item,
                "recipientRosterPosition",
            )?)
            .map_err(|_| {
                invalid_succinct_setup_proof(
                    "compact share-linkage coverage recipientRosterPosition does not fit usize",
                )
            })?;
            let source_rns_limb_index =
                usize::try_from(read_u64(coverage_item, "sourceRnsLimbIndex")?).map_err(|_| {
                    invalid_succinct_setup_proof(
                        "compact share-linkage coverage sourceRnsLimbIndex does not fit usize",
                    )
                })?;
            if !covered_items.insert((
                source_roster_position,
                recipient_roster_position,
                source_rns_limb_index,
            )) {
                return Err(invalid_succinct_setup_proof(
                    "compact share-linkage proof material set repeats a source recipient-limb item",
                ));
            }
        }

        let proof_bytes_base64 = read_string(proof_record, "proofBytesBase64")?;
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_bytes_base64,
            "compact share-linkage proofBytesBase64",
        )?;
        let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?;
        let expected_proof_bytes_hash = hash512_hex(
            COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        );
        compare_string_value(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "compact share-linkage proof record proofBytesHash",
        )?;
        total_proof_byte_length = total_proof_byte_length
            .checked_add(proof_bytes.len())
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compact share-linkage proof material byte length overflowed",
                )
            })?;

        let proof_record_without_root = json!({
            "objectType": "CompactVssShareLinkageProofRecord",
            "objectVersion": 1,
            "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "linkageItems": coverage,
            "compactVssShareLinkage": compact_vss_share_linkage,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesBase64": proof_bytes_base64,
        });
        let expected_record_root =
            derive_protocol_hash("SetupProofRecordBindingHash", &proof_record_without_root)?;
        compare_string_value(
            read_string(proof_record, "proofRecordRoot")?,
            &expected_record_root,
            "compact share-linkage proof record proofRecordRoot",
        )?;

        let proof_request = json!({
            "context": {
                "ceremonyId": read_string(statement, "ceremonyId")?,
                "manifestHash": read_string(statement, "manifestHash")?,
                "rosterHash": read_string(statement, "rosterHash")?,
                "trusteeIdentity": "compact-vss-share-linkage",
                "trusteeRosterPosition": 0,
                "setupEpoch": read_string(statement, "setupEpoch")?,
                "shareLinkageStatementRoot": statement_root,
            },
            "ringDegree": ring_degree,
            "compactVssShareLinkage": compact_vss_share_linkage,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        verify_compact_vss_share_linkage_proof_from_request(&proof_request).map_err(|error| {
            CanonicalError::new(
                error.code,
                format!(
                    "compact share-linkage proof record {proof_record_index} did not verify: {}",
                    error.message
                ),
            )
        })?;
        proof_verification_count += 1;

        let mut verified_record = proof_record_without_root;
        verified_record["proofRecordRoot"] = json!(expected_record_root);
        verified_records.push(verified_record);
    }

    let expected_coverage_count = participant_count
        .checked_mul(participant_count)
        .and_then(|count| count.checked_mul(target_rns_limb_count))
        .ok_or_else(|| {
            invalid_succinct_setup_proof("compact share-linkage coverage count overflowed")
        })?;
    if covered_items.len() != expected_coverage_count {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage proof material set must cover every source, recipient, and target limb exactly once",
        ));
    }
    for source_roster_position in 0..participant_count {
        for recipient_roster_position in 0..participant_count {
            for source_rns_limb_index in 0..target_rns_limb_count {
                if !covered_items.contains(&(
                    source_roster_position,
                    recipient_roster_position,
                    source_rns_limb_index,
                )) {
                    return Err(invalid_succinct_setup_proof(
                        "compact share-linkage proof material set is missing a source recipient-limb item",
                    ));
                }
            }
        }
    }

    let proof_material_set_without_root = json!({
        "objectType": "CompactVssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": read_string(statement, "ceremonyId")?,
        "manifestHash": read_string(statement, "manifestHash")?,
        "rosterHash": read_string(statement, "rosterHash")?,
        "setupProfileHash": read_string(statement, "setupProfileHash")?,
        "qShareHash": read_string(statement, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": read_string(statement, "carryAwareVssShareRelationProfileHash")?,
        "commitmentProfileHash": read_string(statement, "commitmentProfileHash")?,
        "setupEpoch": read_string(statement, "setupEpoch")?,
        "publicMatrixSeedHash": read_string(statement, "publicMatrixSeedHash")?,
        "targetBasisHash": read_string(statement, "targetBasisHash")?,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": read_string(statement, "coefficientCommitmentRoot")?,
        "recipientShareCommitmentRoot": read_string(statement, "recipientShareCommitmentRoot")?,
        "aggregateThresholdCommitmentRoot": read_string(statement, "aggregateThresholdCommitmentRoot")?,
        "statementRoot": statement_root,
        "proofRecords": verified_records,
    });
    let expected_material_root = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &proof_material_set_without_root,
    )?;
    compare_string_value(
        read_string(proof_material_set, "proofMaterialSetRoot")?,
        &expected_material_root,
        "compact share-linkage proof material set proofMaterialSetRoot",
    )?;

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssShareLinkageProofMaterialSet",
        "setupProfileId": "CollectiveBgvSetup-v1",
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "statementRoot": statement_root,
        "proofMaterialSetRoot": expected_material_root,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "ringDegree": ring_degree,
        "proofRecordCount": proof_records.len(),
        "coveredLinkageItemCount": covered_items.len(),
        "totalProofByteLength": total_proof_byte_length,
        "proofVerificationCount": proof_verification_count,
    }))
}

pub(crate) fn generate_compact_same_secret_bridge_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = compact_same_secret_bridge_statement_from_request(request)?;
    let witness = compact_same_secret_bridge_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let compact_statement = statement
        .compact_same_secret_bridge
        .as_ref()
        .ok_or_else(|| {
            invalid_succinct_setup_proof("compact same-secret bridge statement missing")
        })?;

    Ok(json!({
        "ok": true,
        "operation": "generateCompactSameSecretBridgeProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRnsLimbCount": compact_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

pub(crate) fn verify_compact_same_secret_bridge_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = compact_same_secret_bridge_statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let compact_statement = statement
        .compact_same_secret_bridge
        .as_ref()
        .ok_or_else(|| {
            invalid_succinct_setup_proof("compact same-secret bridge statement missing")
        })?;

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactSameSecretBridgeProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRnsLimbCount": compact_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
    }))
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(crate) fn generate_target_decryption_share_proof_bytes_from_request(
    request: &Value,
) -> CanonicalResult<GeneratedTargetDecryptionShareProofBytes> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let witness = target_decryption_share_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let target_statement = statement
        .target_decryption_share
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("target-decryption share statement missing"))?;

    Ok(GeneratedTargetDecryptionShareProofBytes {
        target_roles: target_statement
            .limb_statements
            .first()
            .into_iter()
            .flat_map(|limb_statement| limb_statement.role_statements.iter())
            .map(|role_statement| role_statement.target_role.clone())
            .collect(),
        target_rns_limb_indices: target_statement
            .limb_statements
            .iter()
            .map(|limb_statement| limb_statement.target_rns_limb_index)
            .collect(),
        proof_bytes,
    })
}

pub(crate) fn verify_target_decryption_share_proof_bytes_from_request(
    request: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<Value> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let shape = statement.family_shape()?;
    let target_statement = statement
        .target_decryption_share
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("target-decryption share statement missing"))?;

    let target_roles = target_statement
        .limb_statements
        .first()
        .into_iter()
        .flat_map(|limb_statement| limb_statement.role_statements.iter())
        .map(|role_statement| role_statement.target_role.clone())
        .collect::<Vec<_>>();
    let single_target_role = target_roles
        .first()
        .filter(|_| target_roles.len() == 1)
        .cloned();
    let target_rns_limb_indices = target_statement
        .limb_statements
        .iter()
        .map(|limb_statement| limb_statement.target_rns_limb_index)
        .collect::<Vec<_>>();
    let single_target_limb_index = target_rns_limb_indices
        .first()
        .filter(|_| target_rns_limb_indices.len() == 1)
        .copied();
    let mut response = json!({
        "ok": true,
        "operation": "verifyTargetDecryptionProofBytes",
        "proofFamily": statement.context.proof_family,
        "proofAccountingHash": family_accounting_hash(shape)?,
        "proofAccounting": family_accounting_value(shape)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "targetRoles": target_roles,
        "targetRnsLimbIndices": target_rns_limb_indices,
        "proofByteLength": proof_bytes.len(),
    });
    if let Some(target_role) = single_target_role {
        response["targetRole"] = json!(target_role);
    }
    if let Some(target_rns_limb_index) = single_target_limb_index {
        response["targetRnsLimbIndex"] = json!(target_rns_limb_index);
    }

    Ok(response)
}

fn statement_from_request(request: &Value) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let key_values = request
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof("keys must be an array"))?;
    let keys = key_values
        .iter()
        .map(key_descriptor_from_value)
        .collect::<CanonicalResult<Vec<_>>>()?;
    // The key kinds decide the family, and the family decides which labeled
    // binding roots the context must carry.
    let shape = SuccinctSetupProofFamilyShape::from_key_kinds(
        &keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
    )?;
    let context = proof_context_from_value(context_value, shape)?;
    let same_secret_linkage = match request.get("sameSecretLinkage") {
        None | Some(Value::Null) => None,
        Some(linkage_value) => {
            let commitment_values = linkage_value
                .get("commitments")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof("sameSecretLinkage.commitments must be an array")
                })?;
            let commitments = commitment_values
                .iter()
                .map(parse_setup_commitment_full_value)
                .collect::<CanonicalResult<Vec<_>>>()?;
            Some(SameSecretLinkageStatement {
                public_matrix_seed_hash: read_string(linkage_value, "publicMatrixSeedHash")?
                    .to_string(),
                commitments,
            })
        }
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys,
        same_secret_linkage,
        private_vss_share: None,
        compact_vss_share_linkage: None,
        compact_same_secret_bridge: None,
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn proof_context_from_value(
    context_value: &Value,
    shape: SuccinctSetupProofFamilyShape,
) -> CanonicalResult<SuccinctSetupProofContext> {
    Ok(SuccinctSetupProofContext {
        proof_family: shape.proof_family().to_string(),
        ceremony_id: read_string(context_value, "ceremonyId")?.to_string(),
        manifest_hash: read_string(context_value, "manifestHash")?.to_string(),
        roster_hash: read_string(context_value, "rosterHash")?.to_string(),
        trustee_identity: read_string(context_value, "trusteeIdentity")?.to_string(),
        trustee_roster_position: read_u64(context_value, "trusteeRosterPosition")?,
        setup_epoch: read_string(context_value, "setupEpoch")?.to_string(),
        binding_roots: shape
            .binding_labels()
            .iter()
            .map(|label| {
                Ok((
                    (*label).to_string(),
                    read_string(context_value, label)?.to_string(),
                ))
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

fn compact_vss_share_linkage_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("compactVssShareLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("compactVssShareLinkage must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::CompactVssShareLinkage,
    )?;
    let share_linkage_statement_root = read_string(statement_value, "shareLinkageStatementRoot")?;
    if context.binding_roots[0].1 != share_linkage_statement_root {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage context root must match the share-linkage statement root",
        ));
    }
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let primary_item = compact_vss_share_linkage_item_from_value(
        statement_value,
        "compactVssShareLinkage",
        &public_matrix_seed_hash,
        ring_degree,
    )?;
    let additional_linkage_items = match statement_value.get("additionalLinkageItems") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(item_index, item_value)| {
                compact_vss_share_linkage_item_from_value(
                    item_value,
                    &format!("compactVssShareLinkage.additionalLinkageItems.{item_index}"),
                    &public_matrix_seed_hash,
                    ring_degree,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "compactVssShareLinkage.additionalLinkageItems must be an array",
            ));
        }
    };

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: Some(CompactVssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: primary_item.source_trustee_identity,
            source_trustee_roster_position: primary_item.source_trustee_roster_position,
            recipient_identity: primary_item.recipient_identity,
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root: primary_item.source_coefficient_commitment_root,
            source_recipient_share_commitment_root: primary_item
                .source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            source_message_modulus: primary_item.source_message_modulus,
            coefficient_commitment_roots: primary_item.coefficient_commitment_roots,
            coefficient_opening_roots: primary_item.coefficient_opening_roots,
            coefficient_commitments: primary_item.coefficient_commitments,
            recipient_share_commitment_root: primary_item.recipient_share_commitment_root,
            recipient_share_opening_root: primary_item.recipient_share_opening_root,
            recipient_share_commitment: primary_item.recipient_share_commitment,
            additional_linkage_items,
        }),
        compact_same_secret_bridge: None,
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn compact_vss_share_linkage_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: read_i64_matrix2(
            request,
            "coefficientMessagesByShamirIndex",
        )?,
        compact_vss_recipient_share_messages: read_i64_array(request, "recipientShareMessages")?,
        compact_vss_coefficient_opening_randomness_by_shamir_index: read_i64_matrix(
            request,
            "coefficientOpeningRandomnessByShamirIndex",
        )?,
        compact_vss_recipient_share_opening_randomness: read_i64_matrix2(
            request,
            "recipientShareOpeningRandomness",
        )?,
        compact_vss_carry_witnesses: read_i64_array(request, "carryWitnesses")?,
        compact_vss_recipient_share_messages_by_item: read_optional_i64_matrix2(
            request,
            "recipientShareMessagesByItem",
        )?,
        compact_vss_recipient_share_opening_randomness_by_item: read_optional_i64_matrix(
            request,
            "recipientShareOpeningRandomnessByItem",
        )?,
        compact_vss_carry_witnesses_by_item: read_optional_i64_matrix2(
            request,
            "carryWitnessesByItem",
        )?,
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    })
}

fn compact_same_secret_bridge_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("compactSameSecretBridge")
        .ok_or_else(|| invalid_succinct_setup_proof("compactSameSecretBridge must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::CompactSameSecretBridge,
    )?;
    let compact_same_secret_bridge_statement_root =
        read_string(statement_value, "compactSameSecretBridgeStatementRoot")?;
    let same_secret_statement_root = read_string(statement_value, "sameSecretStatementRoot")?;
    let same_secret_proof_root = read_string(statement_value, "sameSecretProofRoot")?;
    let same_secret_proof_family_binding_root =
        read_string(statement_value, "sameSecretProofFamilyBindingRoot")?;
    if context.binding_roots[0].1 != compact_same_secret_bridge_statement_root
        || context.binding_roots[1].1 != same_secret_statement_root
        || context.binding_roots[2].1 != same_secret_proof_root
        || context.binding_roots[3].1 != same_secret_proof_family_binding_root
    {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge context roots must match the statement roots",
        ));
    }
    let source_trustee_identity =
        read_string(statement_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = read_u64(statement_value, "sourceTrusteeRosterPosition")?;
    if context.trustee_identity != source_trustee_identity
        || context.trustee_roster_position != source_trustee_roster_position
    {
        return Err(invalid_succinct_setup_proof(
            "compact same-secret bridge context trustee must match the source trustee",
        ));
    }
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let target_basis_hash = read_string(statement_value, "targetBasisHash")?.to_string();
    let target_rns_primes = read_u64_array(statement_value, "targetRnsPrimes")?;
    let target_constant_commitment_roots =
        read_string_array(statement_value, "targetConstantCommitmentRoots")?;
    let target_constant_commitment_values = statement_value
        .get("targetConstantCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compactSameSecretBridge.targetConstantCommitments must be an array",
            )
        })?;
    if target_constant_commitment_roots.len() != target_rns_primes.len()
        || target_constant_commitment_values.len() != target_rns_primes.len()
    {
        return Err(invalid_succinct_setup_proof(
            "compactSameSecretBridge target primes, roots, and commitments must be aligned",
        ));
    }
    let target_constant_commitments = target_constant_commitment_values
        .iter()
        .zip(target_constant_commitment_roots.iter())
        .zip(target_rns_primes.iter())
        .enumerate()
        .map(
            |(target_rns_limb_index, ((value, expected_commitment_root), target_rns_prime))| {
                compact_vss_share_linkage_commitment_from_value(
                    value,
                    CompactVssCommandCommitmentExpectation {
                        field_name: format!("targetConstantCommitments.{target_rns_limb_index}"),
                        root: expected_commitment_root,
                        role: "coefficient",
                        public_matrix_seed_hash: &public_matrix_seed_hash,
                        rns_limb_index: target_rns_limb_index,
                        rns_prime: *target_rns_prime,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: None,
        compact_same_secret_bridge: Some(CompactSameSecretBridgeStatement {
            public_matrix_seed_hash,
            source_trustee_identity,
            source_trustee_roster_position,
            target_basis_hash,
            target_rns_primes,
            target_constant_commitment_roots,
            target_constant_commitments,
        }),
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn compact_same_secret_bridge_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: read_i64_array(request, "secretCoefficients")?,
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: read_i64_array(request, "negativeIndicatorCoefficients")?,
        opening_randomness_by_limb: read_i64_matrix(request, "openingRandomnessByLimb")?,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_messages: Vec::new(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_opening_randomness: Vec::new(),
        compact_vss_carry_witnesses: Vec::new(),
        compact_vss_recipient_share_messages_by_item: Vec::new(),
        compact_vss_recipient_share_opening_randomness_by_item: Vec::new(),
        compact_vss_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
    })
}

fn target_decryption_share_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let target_value = request
        .get("targetDecryptionShare")
        .ok_or_else(|| invalid_succinct_setup_proof("targetDecryptionShare must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::TargetDecryptionShare,
    )?;
    let target_share_proof_statement_root =
        read_string(target_value, "targetShareProofStatementRoot")?;
    if context.binding_roots[0].1 != target_share_proof_statement_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the target share proof statement root",
        ));
    }

    let public_matrix_seed_hash = read_string(target_value, "publicMatrixSeedHash")?.to_string();
    let target_basis_hash = read_string(target_value, "targetBasisHash")?.to_string();
    let trustee_identity = read_string(target_value, "trusteeIdentity")?.to_string();
    let trustee_roster_position = read_u64(target_value, "trusteeRosterPosition")?;
    let smudging_commitment_set = target_value
        .get("smudgingCommitmentSet")
        .ok_or_else(|| invalid_succinct_setup_proof("smudgingCommitmentSet must be present"))?;
    let smudging_commitment_set_root =
        validated_target_decryption_smudging_commitment_set_root(smudging_commitment_set)?;
    if context.binding_roots[2].1 != smudging_commitment_set_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the smudging commitment set root",
        ));
    }
    if read_string(smudging_commitment_set, "publicMatrixSeedHash")? != public_matrix_seed_hash
        || read_string(smudging_commitment_set, "targetBasisHash")? != target_basis_hash
        || read_u64(smudging_commitment_set, "ringDegree")? != ring_degree as u64
        || read_string(smudging_commitment_set, "commitmentRole")?
            != TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE
    {
        return Err(invalid_succinct_setup_proof(
            "smudging commitment set metadata must match the target-decryption share statement",
        ));
    }
    let smudging_active_limb_count =
        usize::try_from(read_u64(smudging_commitment_set, "activeRnsLimbCount")?)
            .map_err(|_| invalid_succinct_setup_proof("activeRnsLimbCount does not fit usize"))?;
    let smudging_polynomial_degree = usize::try_from(read_u64(
        smudging_commitment_set,
        "smudgingPolynomialDegree",
    )?)
    .map_err(|_| invalid_succinct_setup_proof("smudgingPolynomialDegree does not fit usize"))?;
    let smudging_coefficient_bound = read_i64(smudging_commitment_set, "smudgingCoefficientBound")?;
    let smudging_signed_coefficient_offset =
        read_i64(smudging_commitment_set, "signedCoefficientOffset")?;
    let smudging_message_coefficient_bound =
        read_u64(smudging_commitment_set, "messageCoefficientBound")?;
    let active_credential_binding_root =
        read_string(target_value, "activeCredentialBindingRoot")?.to_string();
    if context.binding_roots[1].1 != active_credential_binding_root {
        return Err(invalid_succinct_setup_proof(
            "target-decryption share context root must match the active aggregate credential binding root",
        ));
    }
    let limb_statements = target_decryption_share_limb_statements_from_request(
        target_value,
        smudging_commitment_set,
        &public_matrix_seed_hash,
        ring_degree,
        smudging_polynomial_degree,
    )?;
    if limb_statements.len() != smudging_active_limb_count
        || limb_statements
            .iter()
            .enumerate()
            .any(|(expected_limb_index, limb_statement)| {
                limb_statement.target_rns_limb_index != expected_limb_index
            })
    {
        return Err(invalid_succinct_setup_proof(
            "target-decryption proof must cover every active target limb in canonical order",
        ));
    }

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: None,
        compact_same_secret_bridge: None,
        target_decryption_share: Some(TargetDecryptionShareStatement {
            public_matrix_seed_hash,
            target_basis_hash,
            trustee_identity,
            trustee_roster_position,
            active_credential_binding_root,
            interpolation_point: read_u64(target_value, "interpolationPoint")?,
            aggregate_message_coefficient_bound: read_u64(
                target_value,
                "aggregateMessageCoefficientBound",
            )?,
            smudging_commitment_set_root,
            limb_statements,
            smudging_polynomial_degree,
            smudging_coefficient_bound,
            smudging_signed_coefficient_offset,
            smudging_message_coefficient_bound,
            plaintext_multiple: read_u64(target_value, "plaintextMultiple")?,
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(crate) fn describe_target_decryption_share_proof_layout_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = target_decryption_share_statement_from_request(request)?;
    let target_statement = statement.target_decryption_share.as_ref().ok_or_else(|| {
        invalid_succinct_setup_proof("target-decryption share statement must be present")
    })?;
    let proof_limb_indices = statement.proof_limb_indices();
    let mut limb_summaries = Vec::with_capacity(proof_limb_indices.len());
    for proof_limb_index in &proof_limb_indices {
        let layout = LimbColumnLayout::new(&statement, *proof_limb_index)?;
        let mut message_summaries = Vec::with_capacity(layout.target_decryption_message_columns);
        for local_message_index in 0..layout.target_decryption_message_columns {
            let global_message_index = statement
                .target_decryption_message_global_index(*proof_limb_index, local_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message index is outside the statement",
                    )
                })?;
            let claim_kind = match statement
                .target_decryption_message_claim_kind(global_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message claim kind is missing",
                    )
                })? {
                TargetDecryptionMessageClaimKind::AggregateOpening => "aggregateOpening",
                TargetDecryptionMessageClaimKind::SmudgingOpening => "smudgingOpening",
            };
            let message_bound = statement
                .target_decryption_message_bound(global_message_index)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "target-decryption layout message bound is missing",
                    )
                })?;
            let low_digit_trit_count =
                layout.target_decryption_message_trit_count(local_message_index, 0);
            let high_digit_trit_count =
                layout.target_decryption_message_trit_count(local_message_index, 1);
            let total_trit_count = low_digit_trit_count + high_digit_trit_count;
            message_summaries.push(json!({
                "localMessageIndex": local_message_index,
                "globalMessageIndex": global_message_index,
                "claimKind": claim_kind,
                "messageBound": message_bound,
                "encodingColumnCount": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_MESSAGE_DIGIT_COUNT + total_trit_count,
                "lowDigitTritCount": low_digit_trit_count,
                "highDigitTritCount": high_digit_trit_count,
                "totalTritCount": total_trit_count,
            }));
        }
        limb_summaries.push(json!({
            "proofLimbIndex": proof_limb_index,
            "traceSize": layout.trace_size,
            "targetDecryptionMessageColumns": layout.target_decryption_message_columns,
            "targetDecryptionRandomnessColumns": layout.target_decryption_randomness_columns,
            "targetDecryptionMessageEncodingColumns": layout.target_decryption_message_encoding_columns(),
            "claimCount": layout.claim_count(),
            "maskColumnCount": layout.mask_column_count,
            "phaseOnePhysicalColumnCount": layout.phase_one_physical_count(),
            "totalColumnCount": layout.phase_one_physical_count() + PHASE_TWO_COLUMN_COUNT,
            "messages": message_summaries,
        }));
    }

    Ok(json!({
        "objectType": "BgvTargetDecryptionShareProofLayoutDescription",
        "objectVersion": 1,
        "ringDegree": statement.ring_degree,
        "proofLimbIndices": proof_limb_indices,
        "aggregateMessageCoefficientBound": target_statement.aggregate_message_coefficient_bound,
        "smudgingMessageCoefficientBound": target_statement.smudging_message_coefficient_bound,
        "totalMessageCount": statement.target_decryption_total_message_count(),
        "totalMessageDigitCount": statement.target_decryption_total_message_digit_count(),
        "limbs": limb_summaries,
    }))
}

fn target_decryption_share_limb_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<Vec<TargetDecryptionShareLimbStatement>> {
    let limb_statement_values = target_value
        .get("targetRnsLimbStatements")
        .ok_or_else(|| invalid_succinct_setup_proof("targetRnsLimbStatements must be present"))?
        .as_array()
        .ok_or_else(|| invalid_succinct_setup_proof("targetRnsLimbStatements must be an array"))?;
    if limb_statement_values.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "targetRnsLimbStatements must not be empty",
        ));
    }

    limb_statement_values
        .iter()
        .map(|limb_statement_value| {
            target_decryption_share_limb_statement_from_value(
                limb_statement_value,
                smudging_commitment_set,
                public_matrix_seed_hash,
                ring_degree,
                smudging_polynomial_degree,
            )
        })
        .collect()
}

fn target_decryption_share_limb_statement_from_value(
    limb_statement_value: &Value,
    smudging_commitment_set: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<TargetDecryptionShareLimbStatement> {
    let target_rns_limb_index =
        usize::try_from(read_u64(limb_statement_value, "targetRnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("targetRnsLimbIndex does not fit usize"))?;
    let target_rns_prime = read_u64(limb_statement_value, "targetRnsPrime")?;
    let aggregate_commitment_root =
        read_string(limb_statement_value, "aggregateCommitmentRoot")?.to_string();
    let aggregate_opening_root =
        read_string(limb_statement_value, "aggregateOpeningRoot")?.to_string();
    let aggregate_commitment_value = limb_statement_value
        .get("aggregateCommitment")
        .ok_or_else(|| invalid_succinct_setup_proof("aggregateCommitment must be present"))?;
    let aggregate_commitment = compact_vss_share_linkage_commitment_from_value(
        aggregate_commitment_value,
        CompactVssCommandCommitmentExpectation {
            field_name: "targetDecryptionShare.aggregateCommitment".to_string(),
            root: &aggregate_commitment_root,
            role: "aggregate-threshold-share",
            public_matrix_seed_hash,
            rns_limb_index: target_rns_limb_index,
            rns_prime: target_rns_prime,
            ring_degree,
        },
    )?;
    let role_statements = target_decryption_share_role_statements_from_request(
        limb_statement_value,
        smudging_commitment_set,
        target_rns_limb_index,
        target_rns_prime,
        public_matrix_seed_hash,
        ring_degree,
        smudging_polynomial_degree,
    )?;

    Ok(TargetDecryptionShareLimbStatement {
        target_rns_limb_index,
        target_rns_prime,
        aggregate_commitment_root,
        aggregate_opening_root,
        aggregate_commitment,
        role_statements,
    })
}

fn target_decryption_share_role_statements_from_request(
    target_value: &Value,
    smudging_commitment_set: &Value,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<Vec<TargetDecryptionShareRoleStatement>> {
    let role_statement_values = target_value
        .get("targetRoleStatements")
        .ok_or_else(|| invalid_succinct_setup_proof("targetRoleStatements must be present"))?
        .as_array()
        .ok_or_else(|| invalid_succinct_setup_proof("targetRoleStatements must be an array"))?;
    if role_statement_values.len() != TARGET_DECRYPTION_PROOF_TARGET_ROLES.len() {
        return Err(invalid_succinct_setup_proof(
            "targetRoleStatements must cover the canonical target roles",
        ));
    }

    role_statement_values
        .iter()
        .enumerate()
        .map(|(target_role_index, role_statement_value)| {
            let expected_target_role = TARGET_DECRYPTION_PROOF_TARGET_ROLES[target_role_index];
            if read_string(role_statement_value, "targetRole")? != expected_target_role {
                return Err(invalid_succinct_setup_proof(
                    "targetRoleStatements must be in canonical target-role order",
                ));
            }
            target_decryption_share_role_statement_from_value(
                role_statement_value,
                smudging_commitment_set,
                target_rns_limb_index,
                target_rns_prime,
                public_matrix_seed_hash,
                ring_degree,
                smudging_polynomial_degree,
            )
        })
        .collect()
}

fn target_decryption_share_role_statement_from_value(
    role_statement_value: &Value,
    smudging_commitment_set: &Value,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<TargetDecryptionShareRoleStatement> {
    let target_role = read_string(role_statement_value, "targetRole")?.to_string();
    let (smudging_commitment_roots, smudging_commitments) =
        target_decryption_smudging_commitments_from_set(
            smudging_commitment_set,
            &target_role,
            target_rns_limb_index,
            target_rns_prime,
            public_matrix_seed_hash,
            ring_degree,
            smudging_polynomial_degree,
        )?;

    Ok(TargetDecryptionShareRoleStatement {
        target_role,
        target_ciphertext_component_one: read_u64_array(
            role_statement_value,
            "targetCiphertextComponentOne",
        )?,
        released_partial_decryption: read_u64_array(
            role_statement_value,
            "releasedPartialDecryption",
        )?,
        smudging_commitment_roots,
        smudging_commitments,
    })
}

fn validated_target_decryption_smudging_commitment_set_root(
    smudging_commitment_set: &Value,
) -> CanonicalResult<String> {
    if read_string(smudging_commitment_set, "objectType")?
        != "TargetDecryptionSmudgingCommitmentSet"
        || read_u64(smudging_commitment_set, "objectVersion")? != 1
    {
        return Err(invalid_succinct_setup_proof(
            "smudgingCommitmentSet must be TargetDecryptionSmudgingCommitmentSet version 1",
        ));
    }
    let root = read_string(smudging_commitment_set, "smudgingCommitmentSetRoot")?;
    let mut without_root = smudging_commitment_set.clone();
    without_root
        .as_object_mut()
        .ok_or_else(|| invalid_succinct_setup_proof("smudgingCommitmentSet must be an object"))?
        .remove("smudgingCommitmentSetRoot")
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet must include its root")
        })?;
    let expected_root =
        derive_protocol_hash("TargetDecryptionSmudgingCommitmentSetRoot", &without_root)?;
    if root != expected_root {
        return Err(invalid_succinct_setup_proof(
            "smudgingCommitmentSetRoot does not match its canonical payload",
        ));
    }

    Ok(root.to_string())
}

fn target_decryption_smudging_commitments_from_set(
    smudging_commitment_set: &Value,
    target_role: &str,
    target_rns_limb_index: usize,
    target_rns_prime: u64,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    smudging_polynomial_degree: usize,
) -> CanonicalResult<(Vec<String>, Vec<CompactVssShareLinkageCommitment>)> {
    let records = smudging_commitment_set
        .get("commitmentRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("smudgingCommitmentSet.commitmentRecords must be an array")
        })?;
    let mut roots_by_degree = vec![None; smudging_polynomial_degree];
    let mut commitments_by_degree = vec![None; smudging_polynomial_degree];

    for (record_index, record) in records.iter().enumerate() {
        if read_string(record, "objectType")? != "TargetDecryptionSmudgingCommitment"
            || read_u64(record, "objectVersion")? != 1
        {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment records must be TargetDecryptionSmudgingCommitment version 1",
            ));
        }
        let record_role = read_string(record, "role")?;
        let record_limb_index = usize::try_from(read_u64(record, "rnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("rnsLimbIndex does not fit usize"))?;
        let record_rns_prime = read_u64(record, "rnsPrime")?;
        let polynomial_degree = usize::try_from(read_u64(record, "polynomialDegree")?)
            .map_err(|_| invalid_succinct_setup_proof("polynomialDegree does not fit usize"))?;
        if record_role != target_role
            || record_limb_index != target_rns_limb_index
            || record_rns_prime != target_rns_prime
        {
            continue;
        }
        if polynomial_degree == 0 || polynomial_degree > smudging_polynomial_degree {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment record polynomial degree is outside the statement range",
            ));
        }
        let degree_index = polynomial_degree - 1;
        if roots_by_degree[degree_index].is_some() {
            return Err(invalid_succinct_setup_proof(
                "smudging commitment set has duplicate records for the target slice",
            ));
        }
        let commitment_root = read_string(record, "commitmentRoot")?.to_string();
        let commitment_value = record.get("commitment").ok_or_else(|| {
            invalid_succinct_setup_proof("smudging commitment record must include a commitment")
        })?;
        let commitment = compact_vss_share_linkage_commitment_from_value(
            commitment_value,
            CompactVssCommandCommitmentExpectation {
                field_name: format!(
                    "smudgingCommitmentSet.commitmentRecords.{record_index}.commitment"
                ),
                root: &commitment_root,
                role: TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
                public_matrix_seed_hash,
                rns_limb_index: target_rns_limb_index,
                rns_prime: target_rns_prime,
                ring_degree,
            },
        )?;
        roots_by_degree[degree_index] = Some(commitment_root);
        commitments_by_degree[degree_index] = Some(commitment);
    }

    let roots = roots_by_degree
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "smudging commitment set is missing a target-slice polynomial degree",
            )
        })?;
    let commitments = commitments_by_degree
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "smudging commitment set is missing a target-slice commitment",
            )
        })?;

    Ok((roots, commitments))
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
fn target_decryption_share_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness {
        secret_coefficients: Vec::new(),
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients: Vec::new(),
        opening_randomness_by_limb: Vec::new(),
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        compact_vss_coefficient_messages_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_messages: Vec::new(),
        compact_vss_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        compact_vss_recipient_share_opening_randomness: Vec::new(),
        compact_vss_carry_witnesses: Vec::new(),
        compact_vss_recipient_share_messages_by_item: Vec::new(),
        compact_vss_recipient_share_opening_randomness_by_item: Vec::new(),
        compact_vss_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: read_i64_matrix2(
            request,
            "targetDecryptionMessageVectors",
        )?,
        target_decryption_opening_randomness_by_commitment: read_i64_matrix(
            request,
            "targetDecryptionOpeningRandomnessByCommitment",
        )?,
    })
}

fn compact_vss_share_linkage_item_from_value(
    value: &Value,
    field_name: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
) -> CanonicalResult<CompactVssShareLinkageItem> {
    if !value.is_object() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be an object"
        )));
    }
    let source_rns_limb_index =
        usize::try_from(read_u64(value, "sourceRnsLimbIndex")?).map_err(|_| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.sourceRnsLimbIndex does not fit usize"
            ))
        })?;
    let source_message_modulus = read_u64(value, "sourceMessageModulus")?;
    let coefficient_commitment_roots = read_string_array(value, "coefficientCommitmentRoots")?;
    let coefficient_opening_roots = read_string_array(value, "coefficientOpeningRoots")?;
    let coefficient_commitment_values = value
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.coefficientCommitments must be an array"
            ))
        })?;
    if coefficient_commitment_values.len() != coefficient_commitment_roots.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} coefficient commitments and roots must be aligned"
        )));
    }
    if coefficient_commitment_values.len() != coefficient_opening_roots.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} coefficient commitments and opening roots must be aligned"
        )));
    }
    let coefficient_commitments = coefficient_commitment_values
        .iter()
        .zip(coefficient_commitment_roots.iter())
        .enumerate()
        .map(
            |(coefficient_index, (commitment_value, expected_commitment_root))| {
                compact_vss_share_linkage_commitment_from_value(
                    commitment_value,
                    CompactVssCommandCommitmentExpectation {
                        field_name: format!(
                            "{field_name}.coefficientCommitments.{coefficient_index}"
                        ),
                        root: expected_commitment_root,
                        role: "coefficient",
                        public_matrix_seed_hash,
                        rns_limb_index: source_rns_limb_index,
                        rns_prime: source_message_modulus,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let recipient_share_commitment_root =
        read_string(value, "recipientShareCommitmentRoot")?.to_string();
    let recipient_share_opening_root = read_string(value, "recipientShareOpeningRoot")?.to_string();
    let recipient_share_commitment = compact_vss_share_linkage_commitment_from_value(
        value.get("recipientShareCommitment").ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.recipientShareCommitment must be present"
            ))
        })?,
        CompactVssCommandCommitmentExpectation {
            field_name: format!("{field_name}.recipientShareCommitment"),
            root: &recipient_share_commitment_root,
            role: "recipient-share",
            public_matrix_seed_hash,
            rns_limb_index: source_rns_limb_index,
            rns_prime: source_message_modulus,
            ring_degree,
        },
    )?;

    Ok(CompactVssShareLinkageItem {
        source_trustee_identity: read_string(value, "sourceTrusteeIdentity")?.to_string(),
        source_trustee_roster_position: read_u64(value, "sourceTrusteeRosterPosition")?,
        source_coefficient_commitment_root: read_string(value, "sourceCoefficientCommitmentRoot")?
            .to_string(),
        source_recipient_share_commitment_root: read_string(
            value,
            "sourceRecipientShareCommitmentRoot",
        )?
        .to_string(),
        recipient_identity: read_string(value, "recipientIdentity")?.to_string(),
        recipient_roster_position: read_u64(value, "recipientRosterPosition")?,
        source_rns_limb_index,
        source_message_modulus,
        coefficient_commitment_roots,
        coefficient_opening_roots,
        coefficient_commitments,
        recipient_share_commitment_root,
        recipient_share_opening_root,
        recipient_share_commitment,
    })
}

pub(in crate::bgv::setup) fn compact_vss_share_linkage_commitment_from_value(
    value: &Value,
    expected: CompactVssCommandCommitmentExpectation<'_>,
) -> CanonicalResult<CompactVssShareLinkageCommitment> {
    if read_string(value, "objectType")? != "CompactVssCommitment" {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.objectType must be CompactVssCommitment",
            expected.field_name
        )));
    }
    if read_string(value, "profileId")? != COMPACT_VSS_COMMITMENT_PROFILE_ID
        || read_u64(value, "outputCoordinateCount")? != COMPACT_VSS_OUTPUT_COORDINATE_COUNT as u64
        || read_u64(value, "randomnessColumnCount")? != COMPACT_VSS_RANDOMNESS_COLUMN_COUNT as u64
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{} profile metadata must match the compact commitment profile",
            expected.field_name
        )));
    }
    let computed_commitment_root = derive_protocol_hash("SetupCommitmentRoot", value)?;
    if computed_commitment_root != expected.root {
        return Err(invalid_succinct_setup_proof(format!(
            "{} root does not match its compact commitment object",
            expected.field_name
        )));
    }
    if read_string(value, "commitmentRole")? != expected.role
        || read_string(value, "publicMatrixSeedHash")? != expected.public_matrix_seed_hash
        || read_u64(value, "rnsLimbIndex")? != expected.rns_limb_index as u64
        || read_u64(value, "rnsPrime")? != expected.rns_prime
        || read_u64(value, "ringDegree")?
            != u64::try_from(expected.ring_degree)
                .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit u64"))?
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{} metadata must match the compact share-linkage statement",
            expected.field_name
        )));
    }

    let limbs = value
        .get("commitmentLimbs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs must be an array",
                expected.field_name
            ))
        })?;
    if limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.commitmentLimbs must cover the compact commitment fields",
            expected.field_name
        )));
    }
    let mut coordinates_by_commitment_modulus = Vec::with_capacity(limbs.len());
    for (expected_limb_index, limb) in limbs.iter().enumerate() {
        if read_u64(limb, "commitmentModulusIndex")? != expected_limb_index as u64 {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs must be ordered by commitmentModulusIndex",
                expected.field_name
            )));
        }
        let expected_modulus = DATA_PRIMES[expected_limb_index];
        if read_u64(limb, "modulus")? != expected_modulus {
            return Err(invalid_succinct_setup_proof(format!(
                "{}.commitmentLimbs modulus must match the compact commitment field",
                expected.field_name
            )));
        }
        let coordinates = limb
            .get("coordinates")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{}.commitmentLimbs coordinates must be arrays",
                    expected.field_name
                ))
            })?
            .iter()
            .map(|entry| {
                entry.as_u64().ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{}.commitmentLimbs coordinates must be non-negative integers",
                        expected.field_name
                    ))
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        coordinates_by_commitment_modulus.push(coordinates);
    }

    Ok(CompactVssShareLinkageCommitment {
        coordinates_by_commitment_modulus,
    })
}

fn key_descriptor_from_value(key_value: &Value) -> CanonicalResult<EvaluationKeyShareDescriptor> {
    let kind = match read_string(key_value, "proofFamily")? {
        "relinearization-round-one" => EvaluationKeyShareKind::RelinearizationRoundOne,
        "relinearization-round-two" => EvaluationKeyShareKind::RelinearizationRoundTwo,
        "galois-rotation" => EvaluationKeyShareKind::GaloisRotation {
            galois_element: usize::try_from(read_u64(key_value, "rotation")?)
                .map_err(|_| invalid_succinct_setup_proof("rotation does not fit usize"))?,
        },
        "public-key-share" => EvaluationKeyShareKind::PublicKeyShare,
        unknown => {
            return Err(invalid_succinct_setup_proof(format!(
                "unknown evaluation-key proof family {unknown}"
            )));
        }
    };
    let level = usize::try_from(read_u64(key_value, "level")?)
        .map_err(|_| invalid_succinct_setup_proof("level does not fit usize"))?;
    let component_b_by_digit = match (
        key_value.get("componentBByDigit"),
        key_value.get("componentMaterialBytesHex"),
    ) {
        (Some(_), None) => read_u64_matrix3(key_value, "componentBByDigit")?,
        (None, Some(_)) => decode_component_material_bytes(
            &read_hex_bytes(key_value, "componentMaterialBytesHex")?,
            level,
        )?,
        _ => {
            return Err(invalid_succinct_setup_proof(
                "exactly one of componentBByDigit and componentMaterialBytesHex must be supplied",
            ));
        }
    };
    let round_one_aggregate_diagonal = match key_value.get("roundOneAggregateDiagonal") {
        Some(_) => read_u64_matrix(key_value, "roundOneAggregateDiagonal")?,
        None => Vec::new(),
    };

    Ok(EvaluationKeyShareDescriptor {
        kind,
        level,
        key_switch_domain: read_string(key_value, "keySwitchDomain")?.to_string(),
        key_switch_seed_hex: read_string(key_value, "keySwitchSeedHex")?.to_string(),
        component_b_by_digit,
        round_one_aggregate_diagonal,
    })
}

// Canonical binary key-switch component vector material: the same format the
// chunked component-material transport carries.
const COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";

fn decode_component_material_bytes(
    material_bytes: &[u8],
    expected_level: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let read_word = |cursor: &mut usize| -> CanonicalResult<u64> {
        let end = cursor
            .checked_add(8)
            .ok_or_else(|| invalid_succinct_setup_proof("component material cursor overflowed"))?;
        let slice = material_bytes
            .get(*cursor..end)
            .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
        *cursor = end;
        let mut word = [0_u8; 8];
        word.copy_from_slice(slice);
        Ok(u64::from_le_bytes(word))
    };
    let magic = material_bytes
        .get(..8)
        .ok_or_else(|| invalid_succinct_setup_proof("component material ended unexpectedly"))?;
    if magic != COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_succinct_setup_proof(
            "component material has the wrong format marker",
        ));
    }
    let mut cursor = 8_usize;
    let level = usize::try_from(read_word(&mut cursor)?)
        .map_err(|_| invalid_succinct_setup_proof("component material level does not fit usize"))?;
    let ring_degree = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material ring degree does not fit usize")
    })?;
    let digit_count = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material digit count does not fit usize")
    })?;
    let limb_count = usize::try_from(read_word(&mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("component material limb count does not fit usize")
    })?;
    if level != expected_level
        || digit_count != level + 1
        || limb_count != level + 1
        || limb_count > DATA_PRIMES.len()
    {
        return Err(invalid_succinct_setup_proof(
            "component material shape does not match the key descriptor level",
        ));
    }
    let mut component_b_by_digit = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        let mut by_limb = Vec::with_capacity(limb_count);
        for &limb_prime in DATA_PRIMES.iter().take(limb_count) {
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = read_word(&mut cursor)?;
                if coefficient >= limb_prime {
                    return Err(invalid_succinct_setup_proof(
                        "component material contains noncanonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            by_limb.push(coefficients);
        }
        component_b_by_digit.push(by_limb);
    }
    if cursor != material_bytes.len() {
        return Err(invalid_succinct_setup_proof(
            "component material has trailing bytes",
        ));
    }

    Ok(component_b_by_digit)
}

fn read_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be a string")))
}

fn read_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!("{field_name} must be a non-negative integer"))
        })
}

fn read_i64(value: &Value, field_name: &str) -> CanonicalResult<i64> {
    value
        .get(field_name)
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!("{field_name} must be a signed integer"))
        })
}

fn read_hex_bytes(value: &Value, field_name: &str) -> CanonicalResult<Vec<u8>> {
    let text = read_string(value, field_name)?;
    decode_hex_bytes(text, field_name)
}

fn decode_exact_hex_bytes(
    text: &str,
    expected_byte_length: usize,
    field_name: &str,
) -> CanonicalResult<Vec<u8>> {
    let bytes = decode_hex_bytes(text, field_name)?;
    if bytes.len() != expected_byte_length {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be {expected_byte_length} bytes of lowercase hex"
        )));
    }

    Ok(bytes)
}

fn decode_hex_bytes(text: &str, field_name: &str) -> CanonicalResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must contain whole bytes"
        )));
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be lowercase hex"
        )));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| {
                invalid_succinct_setup_proof(format!("{field_name} must be lowercase hex"))
            })
        })
        .collect()
}

fn read_i64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<i64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_i64().ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name} entries must be signed integers"
                ))
            })
        })
        .collect()
}

fn read_string_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<String>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                invalid_succinct_setup_proof(format!("{field_name} entries must be strings"))
            })
        })
        .collect()
}

fn read_u64_array(value: &Value, field_name: &str) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|entry| {
            entry.as_u64().ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name} entries must be non-negative integers"
                ))
            })
        })
        .collect()
}

fn read_i64_matrix2(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i64>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!("{field_name} rows must be arrays"))
                })?
                .iter()
                .map(|entry| {
                    entry.as_i64().ok_or_else(|| {
                        invalid_succinct_setup_proof(format!(
                            "{field_name} coefficients must be signed integers"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn read_optional_i64_matrix2(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i64>>> {
    if value.get(field_name).is_some() {
        read_i64_matrix2(value, field_name)
    } else {
        Ok(Vec::new())
    }
}

fn read_i64_matrix(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<Vec<i64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|outer| {
            outer
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} entries must be arrays of arrays"
                    ))
                })?
                .iter()
                .map(|inner| {
                    inner
                        .as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} inner entries must be arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_i64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be signed integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn read_optional_i64_matrix(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<Vec<Vec<i64>>>> {
    if value.get(field_name).is_some() {
        read_i64_matrix(value, field_name)
    } else {
        Ok(Vec::new())
    }
}

fn read_u64_matrix(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<u64>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!("{field_name} rows must be arrays"))
                })?
                .iter()
                .map(|entry| {
                    entry.as_u64().ok_or_else(|| {
                        invalid_succinct_setup_proof(format!(
                            "{field_name} coefficients must be non-negative integers"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn read_u64_matrix3(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be an array")))?
        .iter()
        .map(|digit| {
            digit
                .as_array()
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(format!(
                        "{field_name} digits must be arrays of limbs"
                    ))
                })?
                .iter()
                .map(|limb| {
                    limb.as_array()
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(format!(
                                "{field_name} limbs must be coefficient arrays"
                            ))
                        })?
                        .iter()
                        .map(|entry| {
                            entry.as_u64().ok_or_else(|| {
                                invalid_succinct_setup_proof(format!(
                                    "{field_name} coefficients must be non-negative integers"
                                ))
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
