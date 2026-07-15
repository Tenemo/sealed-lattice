use serde_json::{Value, json};

use super::invalid_succinct_setup_proof;
use super::relation::{
    KeyBearingWitness, SameSecretLinkageWitness, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness,
};
use crate::bgv::setup::ProofByteSource;
use crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule as atom_schedule;
use crate::bgv::setup::setup_proof::SetupProofFamily;
use crate::encoding::CanonicalResult;
use crate::hashing::{derive_canonical_object_hash, hash512_hex, to_hex};

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
pub(in crate::bgv::setup) struct VssPublicCommandCommitmentExpectation<'a> {
    pub(in crate::bgv::setup) field_name: String,
    pub(in crate::bgv::setup) root: &'a str,
}

// Trustee evaluation-key statements use the key-switch atom backend. The
// common proof suite owns public-key, same-secret, VSS-linkage, and target
// decryption relations.
pub(in crate::bgv::setup) fn prove_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    atom_schedule::prove_key_bearing_trustee_evaluation_keys(
        statement,
        witness,
        proof_randomness_seed_hex,
    )
}

fn statement_proof_family(_: &TrusteeEvaluationKeyStatement) -> SetupProofFamily {
    SetupProofFamily::TrusteeEvaluationKey
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    atom_schedule::verify_key_bearing_trustee_evaluation_keys(statement, proof_bytes)
}

fn negative_indicator_coefficients_from_ternary_secret(
    secret_coefficients: &[i64],
) -> CanonicalResult<Vec<i64>> {
    secret_coefficients
        .iter()
        .map(|coefficient| match *coefficient {
            -1 => Ok(1),
            0 | 1 => Ok(0),
            _ => Err(invalid_succinct_setup_proof(
                "secretCoefficients must contain only ternary coefficients",
            )),
        })
        .collect()
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
    let negative_indicator_coefficients =
        negative_indicator_coefficients_from_ternary_secret(&secret_coefficients)?;
    let error_coefficients_by_key = read_i64_matrix(request, "errorCoefficientsByKey")?;
    let witness = TrusteeEvaluationKeyWitness::TrusteeEvaluationKey {
        key: KeyBearingWitness {
            secret_coefficients,
            error_coefficients_by_key,
        },
        linkage: SameSecretLinkageWitness {
            negative_indicator_coefficients,
            opening_randomness_by_source_limb_and_commitment_limb: read_i64_matrix4(
                request,
                "openingRandomnessBySourceLimbAndCommitmentLimb",
            )?,
        },
    };
    let proof_randomness_seed_hex = read_string(request, "proofRandomnessSeedHex")?;
    let bound_proof_randomness_seed_hex =
        statement_bound_proof_randomness_seed_hex(&statement, proof_randomness_seed_hex)?;

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
    crate::bgv::setup::retain_generated_canonical_proof_material(
        proof_family.wire_label(),
        proof_bytes_hash.clone(),
        proof_bytes,
    )?;
    Ok(json!({ "proofBytesHash": proof_bytes_hash }))
}

fn statement_bound_proof_randomness_seed_hex(
    statement: &TrusteeEvaluationKeyStatement,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<String> {
    let seed_bytes = decode_exact_hex_bytes(
        proof_randomness_seed_hex,
        PROOF_RANDOMNESS_SEED_BYTES,
        "proofRandomnessSeedHex",
    )?;
    let statement_hash = to_hex(&statement.statement_hash());
    let proof_family = statement_proof_family(statement);

    derive_canonical_object_hash(&json!({
        "objectType": "TrusteeEvaluationKeyProofRandomnessBinding",
        "proofFamily": proof_family.wire_label(),
        "statementHash": statement_hash,
        "trusteeRosterPosition": statement.context.trustee_roster_position,
        "setupContextHash": &statement.context.setup_context_hash,
        "proofRandomnessSeedHex": to_hex(&seed_bytes),
    }))
}
mod decoding;
mod request_parsing;
mod target_decryption_parsing;

use decoding::{
    decode_exact_hex_bytes, read_i64_array, read_i64_matrix, read_i64_matrix4, read_string,
};
pub(in crate::bgv::setup::trustee_evaluation_key_proof) use request_parsing::statement_from_request;
pub(in crate::bgv::setup) use target_decryption_parsing::vss_share_linkage_commitment_from_value;
