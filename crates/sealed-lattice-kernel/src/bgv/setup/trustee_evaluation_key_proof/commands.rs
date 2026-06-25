use serde_json::{Value, json};

use super::accounting::{
    succinct_evaluation_key_proof_accounting_hash, succinct_evaluation_key_proof_accounting_value,
    succinct_private_vss_share_accounting_hash, succinct_private_vss_share_accounting_value,
    succinct_public_key_share_accounting_hash, succinct_public_key_share_accounting_value,
    succinct_same_secret_linkage_anchor_accounting_hash,
    succinct_same_secret_linkage_anchor_accounting_value,
};
use super::proof_codec::{
    decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    CompactSameSecretBridgeStatement, CompactVssShareLinkageCommitment,
    CompactVssShareLinkageStatement, EvaluationKeyShareDescriptor, EvaluationKeyShareKind,
    SameSecretLinkageStatement, SuccinctSetupProofContext, SuccinctSetupProofFamilyShape,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
};
use super::verifier::verify_evaluation_key_share;
use super::*;
use crate::bgv::profile::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_setup_commitment_full_value,
};
use crate::bgv::setup::compact_vss_commitment::{
    COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE, COMPACT_VSS_COMMITMENT_PROFILE_ID,
    COMPACT_VSS_OUTPUT_COORDINATE_COUNT, COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
};
use crate::bgv::setup::setup_proof::SETUP_PROOF_PROFILE_ID;
use crate::hashing::{derive_protocol_hash, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BOUNDARY: &str = "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_BOUNDARY: &str = "restricted native compact same-secret bridge proof over target-basis compact constant commitments; not target-ready package proof evidence";

struct CompactVssCommandCommitmentExpectation<'a> {
    field_name: String,
    root: &'a str,
    role: &'a str,
    public_matrix_seed_hash: &'a str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
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
    };
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let proof_randomness_source = read_string(request, "proofRandomnessSource")?;
    if !matches!(
        proof_randomness_source,
        "fresh-csprng" | "development-deterministic-fixture"
    ) {
        return Err(invalid_succinct_setup_proof(
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        ));
    }
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
        "limbCount": statement.limb_count(),
        "keyCount": statement.keys.len(),
        "sameSecretLinkageIncluded": statement.same_secret_linkage.is_some(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "binding": "seed and nonce are bound to statement hash, proof family, trustee identity, roster position, and setup epoch before proof masking",
            "nonceHash": proof_randomness_nonce_hash(proof_randomness_nonce_hex)?,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        },
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

fn proof_randomness_nonce_hash(proof_randomness_nonce_hex: &str) -> CanonicalResult<String> {
    let nonce_bytes = decode_exact_hex_bytes(
        proof_randomness_nonce_hex,
        PROOF_RANDOMNESS_NONCE_BYTES,
        "proofRandomnessNonceHex",
    )?;

    derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &json!({
            "objectType": "TrusteeEvaluationKeyProofRandomnessNonceHash",
            "objectVersion": 1,
            "nonceBytesHex": to_hex(&nonce_bytes),
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
        "limbCount": statement.limb_count(),
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
    let proof_randomness_source = read_string(request, "proofRandomnessSource")?;
    if !matches!(
        proof_randomness_source,
        "fresh-csprng" | "development-deterministic-fixture"
    ) {
        return Err(invalid_succinct_setup_proof(
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        ));
    }
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
        "proofBoundary": COMPACT_VSS_SHARE_LINKAGE_PROOF_BOUNDARY,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "coefficientCommitmentCount": compact_statement.coefficient_commitments.len(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "binding": "statement-bound",
            "nonceHash": proof_randomness_nonce_hash(proof_randomness_nonce_hex)?,
            "retention": "do not persist proof randomness after proof generation"
        },
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
        "proofBoundary": COMPACT_VSS_SHARE_LINKAGE_PROOF_BOUNDARY,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "coefficientCommitmentCount": compact_statement.coefficient_commitments.len(),
        "proofByteLength": proof_bytes.len(),
    }))
}

pub(crate) fn generate_compact_same_secret_bridge_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = compact_same_secret_bridge_statement_from_request(request)?;
    let witness = compact_same_secret_bridge_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let proof_randomness_source = read_string(request, "proofRandomnessSource")?;
    if !matches!(
        proof_randomness_source,
        "fresh-csprng" | "development-deterministic-fixture"
    ) {
        return Err(invalid_succinct_setup_proof(
            "proofRandomnessSource must be fresh-csprng or development-deterministic-fixture",
        ));
    }
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
        "proofBoundary": COMPACT_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "targetRnsLimbCount": compact_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "binding": "statement-bound",
            "nonceHash": proof_randomness_nonce_hash(proof_randomness_nonce_hex)?,
            "retention": "do not persist proof randomness after proof generation"
        },
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
        "proofBoundary": COMPACT_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.limb_count(),
        "targetRnsLimbCount": compact_statement.target_rns_primes.len(),
        "proofByteLength": proof_bytes.len(),
    }))
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
    let source_coefficient_commitment_root =
        read_string(statement_value, "sourceCoefficientCommitmentRoot")?.to_string();
    let source_recipient_share_commitment_root =
        read_string(statement_value, "sourceRecipientShareCommitmentRoot")?.to_string();
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::CompactVssShareLinkage,
    )?;
    if context.binding_roots[0].1 != source_coefficient_commitment_root
        || context.binding_roots[1].1 != source_recipient_share_commitment_root
    {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage context roots must match the statement roots",
        ));
    }
    let source_trustee_identity =
        read_string(statement_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = read_u64(statement_value, "sourceTrusteeRosterPosition")?;
    if context.trustee_identity != source_trustee_identity
        || context.trustee_roster_position != source_trustee_roster_position
    {
        return Err(invalid_succinct_setup_proof(
            "compact share-linkage context trustee must match the source trustee",
        ));
    }
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let source_rns_limb_index =
        usize::try_from(read_u64(statement_value, "sourceRnsLimbIndex")?)
            .map_err(|_| invalid_succinct_setup_proof("sourceRnsLimbIndex does not fit usize"))?;
    let source_message_modulus = read_u64(statement_value, "sourceMessageModulus")?;
    let coefficient_commitment_roots =
        read_string_array(statement_value, "coefficientCommitmentRoots")?;
    let coefficient_commitment_values = statement_value
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "compactVssShareLinkage.coefficientCommitments must be an array",
            )
        })?;
    if coefficient_commitment_values.len() != coefficient_commitment_roots.len() {
        return Err(invalid_succinct_setup_proof(
            "compactVssShareLinkage coefficient commitments and roots must be aligned",
        ));
    }
    let coefficient_commitments = coefficient_commitment_values
        .iter()
        .zip(coefficient_commitment_roots.iter())
        .enumerate()
        .map(|(coefficient_index, (value, expected_commitment_root))| {
            compact_vss_share_linkage_commitment_from_value(
                value,
                CompactVssCommandCommitmentExpectation {
                    field_name: format!("coefficientCommitments.{coefficient_index}"),
                    root: expected_commitment_root,
                    role: "coefficient",
                    public_matrix_seed_hash: &public_matrix_seed_hash,
                    rns_limb_index: source_rns_limb_index,
                    rns_prime: source_message_modulus,
                    ring_degree,
                },
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let recipient_share_commitment_root =
        read_string(statement_value, "recipientShareCommitmentRoot")?.to_string();
    let recipient_share_commitment = compact_vss_share_linkage_commitment_from_value(
        statement_value
            .get("recipientShareCommitment")
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "compactVssShareLinkage.recipientShareCommitment must be present",
                )
            })?,
        CompactVssCommandCommitmentExpectation {
            field_name: "recipientShareCommitment".to_string(),
            root: &recipient_share_commitment_root,
            role: "recipient-share",
            public_matrix_seed_hash: &public_matrix_seed_hash,
            rns_limb_index: source_rns_limb_index,
            rns_prime: source_message_modulus,
            ring_degree,
        },
    )?;

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: None,
        private_vss_share: None,
        compact_vss_share_linkage: Some(CompactVssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity,
            source_trustee_roster_position,
            recipient_identity: read_string(statement_value, "recipientIdentity")?.to_string(),
            recipient_roster_position: read_u64(statement_value, "recipientRosterPosition")?,
            source_coefficient_commitment_root,
            source_recipient_share_commitment_root,
            source_rns_limb_index,
            source_message_modulus,
            coefficient_commitment_roots,
            coefficient_commitments,
            recipient_share_commitment_root,
            recipient_share_commitment,
        }),
        compact_same_secret_bridge: None,
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
    })
}

fn compact_vss_share_linkage_commitment_from_value(
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
        || read_string(value, "developmentScope")? != COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE
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
