use serde_json::{Value, json};
use std::collections::BTreeSet;

use super::proof_codec::{
    decode_trustee_evaluation_key_proof_from_source, encode_trustee_evaluation_key_proof,
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
use crate::bgv::setup::ProofByteSource;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, parse_setup_commitment_full_value,
};
use crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule as atom_schedule;
use crate::bgv::setup::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SetupProofMaterialBytes,
    verified_setup_proof_material_bytes_from_request,
};
use crate::hashing::{derive_canonical_object_hash, hash512_hex, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;
const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";
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
    pub(in crate::bgv::setup) rns_limb_index: usize,
    pub(in crate::bgv::setup) rns_prime: u64,
    pub(in crate::bgv::setup) ring_degree: usize,
}

// The single byte-level dispatch for trustee evaluation-key proofs: key-bearing
// statements are proven by the key-switch atom backend (the statement-bound
// randomness binding still gates the request shape; the per-key salt streams
// derive from the statement hash), every other family stays on the shared
// succinct engine.
pub(in crate::bgv::setup) fn prove_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    if atom_schedule::statement_is_key_bearing(statement) {
        atom_schedule::prove_key_bearing_trustee_evaluation_keys(statement, witness)
    } else {
        let proof = prove_evaluation_key_share(statement, witness, proof_randomness_seed_hex)?;
        Ok(encode_trustee_evaluation_key_proof(&proof))
    }
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &(impl ProofByteSource + Sync + ?Sized),
) -> CanonicalResult<()> {
    if atom_schedule::statement_is_key_bearing(statement) {
        atom_schedule::verify_key_bearing_trustee_evaluation_keys(statement, proof_bytes)
    } else {
        let proof = decode_trustee_evaluation_key_proof_from_source(statement, proof_bytes)?;
        verify_evaluation_key_share(statement, &proof)
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
        vss_committed_material_seeds_by_bound_message: match request
            .get("vssCommittedMaterialSeedsByBoundMessage")
        {
            Some(_) => read_string_array(request, "vssCommittedMaterialSeedsByBoundMessage")?,
            None => Vec::new(),
        },
        vss_committed_material_context_hashes_by_bound_message: match request
            .get("vssCommittedMaterialContextHashesByBoundMessage")
        {
            Some(_) => {
                read_string_array(request, "vssCommittedMaterialContextHashesByBoundMessage")?
            }
            None => Vec::new(),
        },
    };
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let proof_randomness_nonce_hex = read_string(request, "proofRandomnessNonceHex")?;
    let bound_proof_randomness_seed_hex = statement_bound_proof_randomness_seed_hex(
        &statement,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;

    let proof_bytes = prove_trustee_evaluation_key_proof_bytes(
        &statement,
        &witness,
        &bound_proof_randomness_seed_hex,
    )?;
    let proof_bytes_hash_domain = match statement.context.proof_family.as_str() {
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY => TRUSTEE_EVALUATION_KEY_PROOF_BYTES_HASH_DOMAIN,
        PUBLIC_KEY_SHARE_PROOF_FAMILY => PUBLIC_KEY_SHARE_PROOF_BYTES_HASH_DOMAIN,
        _ => {
            return Err(invalid_succinct_setup_proof(
                "trustee proof generator returned an unsupported proof family",
            ));
        }
    };
    let proof_bytes_hash = hash512_hex(proof_bytes_hash_domain, &[&proof_bytes]);
    let statement_hash = to_hex(&statement.statement_hash());
    let (proof_material_object_type, proof_family) = match statement.context.proof_family.as_str() {
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY => (
            "TrusteeEvaluationKeyProofMaterialReference",
            TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        ),
        PUBLIC_KEY_SHARE_PROOF_FAMILY => (
            "PublicKeyShareSuccinctProofMaterialReference",
            PUBLIC_KEY_SHARE_PROOF_FAMILY,
        ),
        _ => unreachable!("proof family was validated above"),
    };
    let proof_material_root = derive_canonical_object_hash(&json!({
        "objectType": proof_material_object_type,
        "proofFamily": proof_family,
        "trusteeIdentity": statement.context.trustee_identity,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
        "statementHash": statement_hash,
        "proofBytesHash": proof_bytes_hash,
    }))?;
    crate::bgv::setup::retain_generated_canonical_proof_material(
        proof_family,
        proof_material_root.clone(),
        proof_bytes,
    )?;
    Ok(json!({
        "operation": "generateTrusteeEvaluationKeyProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": statement_hash,
        "limbCount": statement.proof_limb_count(),
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

// Describe a trustee-batched evaluation-key statement without proving it. The
// key-bearing same-secret relation is linked to its BDLOP source constant
// commitment, so its statement hash is obtained without running the expensive
// prover. This parses the statement and returns its proof family and canonical
// statement hash directly, matching the native statement-hash vector path and
// letting the WASM kernel pin the key-bearing statement encoding across the
// Rust and JavaScript boundary.
pub(crate) fn describe_trustee_evaluation_key_statement_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement = statement_from_request(request)?;
    Ok(json!({
        "operation": "describeTrusteeEvaluationKeyStatement",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
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

    let proof_bytes_hash = hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        &proof_bytes_hash,
    )?;
    crate::bgv::setup::retain_generated_canonical_proof_material(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_material_root.clone(),
        proof_bytes,
    )?;
    Ok(json!({
        "operation": "generateVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
        "limbCount": statement.proof_limb_count(),
        "coefficientCommitmentCount": share_linkage_statement.total_coefficient_commitment_count(),
        "coefficientWitnessColumnCount": share_linkage_statement.unique_coefficient_witness_slot_count(),
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

pub(crate) fn verify_vss_share_linkage_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<Value> {
    let statement = vss_share_linkage_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;

    Ok(json!({
        "operation": "verifyVssShareLinkageProof",
        "proofFamily": statement.context.proof_family,
        "statementHash": to_hex(&statement.statement_hash()),
    }))
}

mod bridge_target_commands;
mod decoding;
mod request_parsing;
mod share_linkage_transport;
mod share_linkage_verification;
mod target_decryption_parsing;

use decoding::*;
#[cfg(test)]
pub(in crate::bgv::setup::trustee_evaluation_key_proof) use request_parsing::same_secret_bridge_statement_from_request;
pub(in crate::bgv::setup::trustee_evaluation_key_proof) use request_parsing::statement_from_request;
use request_parsing::*;

pub(in crate::bgv::setup) use share_linkage_transport::verified_vss_share_linkage_proof_material_bytes;

pub(crate) use bridge_target_commands::generate_target_decryption_share_proof_bytes_from_request;
#[cfg(test)]
pub(crate) use bridge_target_commands::verify_target_decryption_share_proof_bytes_from_request;
pub(crate) use bridge_target_commands::{
    generate_same_secret_bridge_proof_from_request,
    verify_same_secret_bridge_proof_source_from_request,
    verify_target_decryption_share_proof_source_from_request,
};
pub(crate) use share_linkage_verification::verify_vss_share_linkage_proof_material_set_from_request;
#[cfg(test)]
pub(crate) use target_decryption_parsing::describe_target_decryption_share_proof_layout_from_request;
pub(in crate::bgv::setup) use target_decryption_parsing::vss_share_linkage_commitment_from_value;
