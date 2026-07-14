use serde_json::{Value, json};
use std::collections::BTreeSet;

use super::proof_codec::{
    decode_trustee_evaluation_key_proof_from_source, encode_trustee_evaluation_key_proof,
};
use super::prover::prove_evaluation_key_share;
use super::relation::{
    KeyBearingWitness, SameSecretLinkageWitness, SetupProofStatement,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, VssCommittedMaterialWitness,
};
use super::verifier::verify_evaluation_key_share;
use super::{VSS_SHARE_LINKAGE_PROOF_FAMILY, invalid_succinct_setup_proof};
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::ProofByteSource;
use crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule as atom_schedule;
use crate::bgv::setup::same_secret_bridge::SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN;
use crate::bgv::setup::setup_proof::{
    SetupProofFamily, SetupProofMaterialBytes, take_verified_setup_proof_material_bytes,
};
use crate::bgv::setup::vss_commitment::VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN;
use crate::encoding::CanonicalResult;
use crate::hashing::{derive_canonical_object_hash, hash512_hex, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;
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

fn statement_proof_family(statement: &TrusteeEvaluationKeyStatement) -> SetupProofFamily {
    match &statement.proof {
        SetupProofStatement::PublicKeyShare { .. } => SetupProofFamily::PublicKeyShare,
        SetupProofStatement::PrivateVssShare(_) => SetupProofFamily::PrivateVssShare,
        SetupProofStatement::VssShareLinkage(_) => SetupProofFamily::VssShareLinkage,
        SetupProofStatement::SameSecretBridge { .. } => SetupProofFamily::SameSecretBridge,
        SetupProofStatement::TargetDecryptionShare(_) => SetupProofFamily::TargetDecryptionShare,
        SetupProofStatement::TrusteeEvaluationKey { .. } => SetupProofFamily::TrusteeEvaluationKey,
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
    let error_coefficients_by_key = read_i64_matrix(request, "errorCoefficientsByKey")?;
    let witness = match &statement.proof {
        SetupProofStatement::PublicKeyShare { .. } => TrusteeEvaluationKeyWitness::PublicKeyShare {
            key: KeyBearingWitness {
                secret_coefficients,
                error_coefficients_by_key,
            },
            negative_indicator_coefficients: read_i64_array(
                request,
                "negativeIndicatorCoefficients",
            )?,
            committed_material: VssCommittedMaterialWitness {
                vss_committed_material_seeds_by_bound_message: read_string_array(
                    request,
                    "vssCommittedMaterialSeedsByBoundMessage",
                )?,
                vss_committed_material_context_hashes_by_bound_message: read_string_array(
                    request,
                    "vssCommittedMaterialContextHashesByBoundMessage",
                )?,
            },
        },
        SetupProofStatement::TrusteeEvaluationKey { .. } => {
            TrusteeEvaluationKeyWitness::TrusteeEvaluationKey {
                key: KeyBearingWitness {
                    secret_coefficients,
                    error_coefficients_by_key,
                },
                linkage: SameSecretLinkageWitness {
                    negative_indicator_coefficients: read_i64_array(
                        request,
                        "negativeIndicatorCoefficients",
                    )?,
                    opening_randomness_by_limb: read_i64_matrix(
                        request,
                        "openingRandomnessByLimb",
                    )?,
                },
            }
        }
        _ => {
            return Err(invalid_succinct_setup_proof(
                "trustee proof generator requires a key-bearing proof statement",
            ));
        }
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
    let proof_family = statement_proof_family(&statement);
    let proof_bytes_hash = hash512_hex(
        proof_family.proof_bytes_hash_domain().ok_or_else(|| {
            invalid_succinct_setup_proof("proof family has no proof-byte hash domain")
        })?,
        &[&proof_bytes],
    );
    let statement_hash = to_hex(&statement.statement_hash());
    let proof_material_root = crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
        proof_family.wire_label(),
        &proof_bytes_hash,
    )?;
    crate::bgv::setup::retain_generated_canonical_proof_material(
        proof_family.wire_label(),
        proof_material_root.clone(),
        proof_bytes,
    )?;
    Ok(json!({
        "statementHash": statement_hash,
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
    let proof_family = statement_proof_family(&statement);
    Ok(json!({
        "proofFamily": proof_family.wire_label(),
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
    let proof_family = statement_proof_family(statement);

    derive_canonical_object_hash(&json!({
        "objectType": "TrusteeEvaluationKeyProofRandomnessBinding",
        "proofFamily": proof_family.wire_label(),
        "statementHash": statement_hash,
        "trusteeIdentity": &statement.context.trustee_identity,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
        "setupContextHash": &statement.context.setup_context_hash,
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
        "statementHash": to_hex(&statement.statement_hash()),
        "proofBytesHash": proof_bytes_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

pub(crate) fn verify_vss_share_linkage_proof_source_from_request(
    request: &Value,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    let statement = vss_share_linkage_statement_from_request(request)?;
    let proof = decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)
}

pub(in crate::bgv::setup) fn vss_share_linkage_proof_verification_binding_hash(
    proof_material_root: &str,
    verification_request: &Value,
) -> CanonicalResult<String> {
    let context = verification_request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = read_u64(verification_request, "ringDegree")?;
    let vss_share_linkage = verification_request
        .get("vssShareLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("vssShareLinkage must be present"))?;
    derive_canonical_object_hash(&json!({
        "objectType": "VssShareLinkageProofVerificationBinding",
        "proofMaterialRoot": proof_material_root,
        // Bind only the public relation consumed by the verifier. Prover-only
        // witnesses and randomness may be present in a generation request, but
        // they cannot change the semantic verification lease.
        "verificationRequest": {
            "context": context,
            "ringDegree": ring_degree,
            "vssShareLinkage": vss_share_linkage,
        },
    }))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_and_retain_vss_share_linkage_proof_binding(
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    proof_material_root: &str,
    verification_request: &Value,
) -> CanonicalResult<()> {
    let proof_bytes = crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_material_root,
    )?
    .ok_or_else(|| {
        invalid_succinct_setup_proof(
            "VSS share-linkage proof binding requires authenticated proof bytes",
        )
    })?;
    let proof_bytes_hash = proof_bytes.hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_string_value(
        proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "VSS share-linkage proof material root",
    )?;
    verify_vss_share_linkage_proof_source_from_request(verification_request, proof_bytes.as_ref())?;
    drop(proof_bytes);
    crate::bgv::setup::retain_accepted_setup_proof_binding(
        proof_binding_session.session_handle,
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        proof_material_root,
        vss_share_linkage_proof_verification_binding_hash(
            proof_material_root,
            verification_request,
        )?,
    )?;
    Ok(())
}

mod bridge_target_commands;
mod decoding;
mod request_parsing;
mod share_linkage_transport;
mod share_linkage_verification;
mod target_decryption_parsing;

use decoding::{
    decode_exact_hex_bytes, read_i64_array, read_i64_matrix, read_string, read_string_array,
    read_u64,
};
#[cfg(test)]
pub(in crate::bgv::setup::trustee_evaluation_key_proof) use request_parsing::same_secret_bridge_statement_from_request;
pub(in crate::bgv::setup::trustee_evaluation_key_proof) use request_parsing::statement_from_request;
use request_parsing::{
    vss_share_linkage_statement_from_request, vss_share_linkage_witness_from_request,
};
#[cfg(test)]
use share_linkage_verification::compare_string_value;

pub(in crate::bgv::setup) use share_linkage_transport::verified_vss_share_linkage_proof_material_bytes;

pub(crate) use bridge_target_commands::generate_target_decryption_share_proof_bytes_from_request;
#[cfg(test)]
pub(crate) use bridge_target_commands::verify_target_decryption_share_proof_bytes_from_request;
pub(crate) use bridge_target_commands::{
    generate_same_secret_bridge_proof_from_request,
    verify_same_secret_bridge_proof_source_from_request,
    verify_target_decryption_share_proof_source_from_request,
};
#[cfg(test)]
pub(crate) use share_linkage_verification::verify_vss_share_linkage_proof_material_set_from_request;
pub(in crate::bgv::setup) use share_linkage_verification::verify_vss_share_linkage_statement_and_proof_material_set_from_request;
pub(in crate::bgv::setup) use target_decryption_parsing::vss_share_linkage_commitment_from_value;

#[cfg(test)]
mod verification_binding_tests {
    use super::*;

    #[test]
    fn share_linkage_binding_ignores_prover_inputs_but_binds_public_relation_fields() {
        let proof_material_root = "a".repeat(128);
        let public_request = json!({
            "context": {
                "setupContextHash": "b".repeat(128),
                "trusteeIdentity": "vss-share-linkage",
                "trusteeRosterPosition": 0,
                "shareLinkageStatementRoot": "d".repeat(128),
            },
            "ringDegree": 32_768,
            "vssShareLinkage": {
                "shareLinkageStatementRoot": "d".repeat(128),
                "sourceTrusteeRosterPosition": 0,
            },
        });
        let expected_binding = vss_share_linkage_proof_verification_binding_hash(
            &proof_material_root,
            &public_request,
        )
        .expect("public share-linkage verification binding");

        let mut prover_request = public_request.clone();
        prover_request["coefficientMessagesByShamirIndex"] = json!([[1, -1, 0]]);
        prover_request["proofRandomnessSeedHex"] = json!("e".repeat(128));
        assert_eq!(
            vss_share_linkage_proof_verification_binding_hash(
                &proof_material_root,
                &prover_request,
            )
            .expect("prover request share-linkage verification binding"),
            expected_binding,
            "prover-only inputs must not alter a verifier-owned semantic binding",
        );

        let mut changed_public_request = public_request;
        changed_public_request["ringDegree"] = json!(16_384);
        assert_ne!(
            vss_share_linkage_proof_verification_binding_hash(
                &proof_material_root,
                &changed_public_request,
            )
            .expect("changed public share-linkage verification binding"),
            expected_binding,
            "an operative public relation field must alter the semantic binding",
        );
    }
}
