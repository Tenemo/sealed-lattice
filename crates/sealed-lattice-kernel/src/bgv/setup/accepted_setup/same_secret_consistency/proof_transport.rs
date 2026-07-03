use super::*;

use crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY;
use crate::hashing::derive_canonical_object_hash;

// No relation prefix is needed because statementHash already transcript-binds
// the family and ceremony; the material root only binds proof-byte identity.
#[cfg(test)]
pub(in crate::bgv::setup) fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretLinkageAnchorProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "statementHash": value_string(proof_record, "statementHash")?,
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}
