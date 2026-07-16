use serde_json::Value;

use super::super::invalid_succinct_setup_proof;
use super::super::relation::VssShareLinkageCommitment;
use super::VssPublicCommandCommitmentExpectation;
use crate::bgv::setup_helpers::validate_hash_string;
use crate::encoding::CanonicalResult;
use crate::hashing::derive_canonical_object_hash;

fn read_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_succinct_setup_proof(format!("{field_name} must be a string")))
}

pub(in crate::bgv::setup) fn vss_share_linkage_commitment_from_value(
    value: &Value,
    expected: VssPublicCommandCommitmentExpectation<'_>,
) -> CanonicalResult<VssShareLinkageCommitment> {
    if read_string(value, "objectType")? != "VssCommittedMaterialCommitment" {
        return Err(invalid_succinct_setup_proof(format!(
            "{}.objectType must be VssCommittedMaterialCommitment",
            expected.field_name
        )));
    }
    let computed_commitment_root = derive_canonical_object_hash(value)?;
    if computed_commitment_root != expected.root {
        return Err(invalid_succinct_setup_proof(format!(
            "{} root does not match its commitment object",
            expected.field_name
        )));
    }
    let commitment_context_hash = read_string(value, "commitmentContextHash")?.to_string();
    validate_hash_string(
        &commitment_context_hash,
        &format!("{}.commitmentContextHash", expected.field_name),
    )?;
    let material_root_bytes =
        crate::transcript_core::decode_hex(read_string(value, "materialRootHex")?)?;
    let material_root: super::super::merkle_commitment::MerkleDigest =
        material_root_bytes.as_slice().try_into().map_err(|_| {
            invalid_succinct_setup_proof(format!(
                "{}.materialRootHex must be a full Merkle digest",
                expected.field_name
            ))
        })?;

    let _ = (commitment_context_hash, material_root);
    Ok(VssShareLinkageCommitment)
}
