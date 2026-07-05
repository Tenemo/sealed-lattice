use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use super::proof_codec::{
    decode_trustee_evaluation_key_proof, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretBridgeStatement,
    SameSecretLinkageStatement, SuccinctSetupProofContext, SuccinctSetupProofFamilyShape,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, VssShareLinkageCommitment,
    VssShareLinkageItem, VssShareLinkageStatement,
};
#[cfg(test)]
use super::relation::{LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, TargetDecryptionMessageClaimKind};
use super::relation::{
    TargetDecryptionShareLimbStatement, TargetDecryptionShareRoleStatement,
    TargetDecryptionShareStatement,
};
use super::*;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_setup_commitment_full_value,
};
use crate::bgv::setup::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialTransportHashes, setup_proof_material_transport_hashes,
    verified_setup_proof_material_chunks_from_request,
};
use crate::bgv::setup::vss_commitment::{
    VSS_PUBLIC_OUTPUT_COORDINATE_COUNT, VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
};
use crate::hashing::{derive_canonical_object_hash, hash512_hex, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;
const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes-v1";
const VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterialSet";
const VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterial";
const TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE: &str =
    "target-decryption-smudging-polynomial-coefficient";
const TARGET_DECRYPTION_PROOF_TARGET_ROLES: [&str; 2] = ["targetId", "targetOrder"];

pub(in crate::bgv::setup) struct VssPublicCommandCommitmentExpectation<'a> {
    pub(in crate::bgv::setup) field_name: String,
    pub(in crate::bgv::setup) root: &'a str,
    pub(in crate::bgv::setup) role: &'a str,
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) rns_prime: u64,
    pub(in crate::bgv::setup) ring_degree: usize,
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
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages: Vec::new(),
        vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        vss_public_recipient_share_opening_randomness: Vec::new(),
        vss_public_carry_witnesses: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
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
    Ok(json!({
        "operation": "generateTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
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

    derive_canonical_object_hash(&json!({
        "objectType": "TrusteeEvaluationKeyProofRandomnessBinding",
        "objectVersion": 1,
        "proofFamily": &statement.context.proof_family,
        "statementHash": statement_hash,
        "trusteeIdentity": &statement.context.trustee_identity,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
        "setupEpoch": &statement.context.setup_epoch,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
        "proofRandomnessSeedHex": to_hex(&seed_bytes),
    }))
}

pub(crate) fn generate_vss_share_linkage_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = vss_share_linkage_statement_from_request(request)?;
    let witness = vss_share_linkage_witness_from_request(request)?;
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof = prove_evaluation_key_share(&statement, &witness, &bound_proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let share_linkage_statement = statement
        .vss_share_linkage
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("share-linkage statement missing"))?;

    Ok(json!({
        "ok": true,
        "operation": "generateVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "coefficientCommitmentCount": share_linkage_statement.total_coefficient_commitment_count(),
        "coefficientWitnessColumnCount": share_linkage_statement.unique_coefficient_witness_slot_count(),
        "proofByteLength": proof_bytes.len(),
        "proofBytesHex": to_hex(&proof_bytes),
    }))
}

pub(crate) fn verify_vss_share_linkage_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = vss_share_linkage_statement_from_request(request)?;
    let proof_bytes = read_hex_bytes(request, "proofBytesHex")?;
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let share_linkage_statement = statement
        .vss_share_linkage
        .as_ref()
        .ok_or_else(|| invalid_succinct_setup_proof("share-linkage statement missing"))?;

    Ok(json!({
        "ok": true,
        "operation": "verifyVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "coefficientCommitmentCount": share_linkage_statement.total_coefficient_commitment_count(),
        "coefficientWitnessColumnCount": share_linkage_statement.unique_coefficient_witness_slot_count(),
        "proofByteLength": proof_bytes.len(),
    }))
}

mod bridge_target_commands;
mod decoding;
mod request_parsing;
mod share_linkage_transport;
mod share_linkage_verification;
mod target_decryption_parsing;

use decoding::*;
use request_parsing::*;

#[cfg(any(test, feature = "target-decryption-development-commands"))]
pub(crate) use bridge_target_commands::generate_target_decryption_share_proof_bytes_from_request;
pub(crate) use bridge_target_commands::{
    generate_same_secret_bridge_proof_from_request, verify_same_secret_bridge_proof_from_request,
    verify_target_decryption_share_proof_bytes_from_request,
};
pub(crate) use share_linkage_verification::verify_vss_share_linkage_proof_material_set_from_request;
#[cfg(test)]
pub(crate) use target_decryption_parsing::describe_target_decryption_share_proof_layout_from_request;
pub(in crate::bgv::setup) use target_decryption_parsing::vss_share_linkage_commitment_from_value;
