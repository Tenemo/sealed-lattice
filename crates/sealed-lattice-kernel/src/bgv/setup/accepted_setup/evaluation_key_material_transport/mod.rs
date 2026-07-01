use super::*;

mod expected_roots;
mod manifest;
mod material_transport;
mod public_key_reconstruction;
mod set_verification;

pub(super) use material_transport::transported_evaluation_key_share_component_material_from_request;
pub(super) use set_verification::{
    verify_public_evaluation_key_set, verify_required_public_evaluation_key_set,
};

#[cfg(test)]
pub(in crate::bgv::setup) use manifest::encode_public_evaluation_key_material_manifest;
#[cfg(test)]
pub(in crate::bgv::setup) use manifest::public_evaluation_key_material_manifest;
#[cfg(test)]
pub(in crate::bgv::setup) use material_transport::{
    public_evaluation_key_material_reference_root, public_evaluation_key_material_transport_hashes,
};
#[cfg(test)]
pub(in crate::bgv::setup) use public_key_reconstruction::{
    accepted_setup_public_galois_keys_from_transport,
    accepted_setup_public_relinearization_keys_from_transport,
};

#[derive(Debug, Clone)]
pub(in crate::bgv::setup) struct PublicEvaluationKeyMaterialTransportHashes {
    pub(in crate::bgv::setup) full_object_hash: String,
    pub(in crate::bgv::setup) chunk_hashes: Vec<String>,
    pub(in crate::bgv::setup) chunk_root: String,
    pub(in crate::bgv::setup) total_byte_length: u64,
}

pub(super) fn evaluation_key_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("relinearizationRoundOne"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
