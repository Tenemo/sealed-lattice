pub(in crate::bgv::setup) mod material_transport;

pub(crate) use self::material_transport::{
    BgvProofMaterialBytes, CanonicalProofMaterialBytes, ProofByteSource,
};
pub(in crate::bgv::setup) use self::material_transport::{
    SetupProofMaterialBytes, verified_setup_proof_material_bytes_from_request,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::material_transport::{
    VerifiedSetupProofMaterialEvictionGuard, authenticate_setup_proof_material_stream_for_test,
    authenticate_setup_proof_material_stream_in_session_for_test,
};

use serde_json::{Value, json};

use crate::{
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ComponentMismatch, message)
}

pub(in crate::bgv::setup) fn setup_proof_material_reference_root(
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SetupProofMaterialReference",
        "proofFamily": proof_family,
        "proofBytesHash": proof_bytes_hash,
    }))
}
