use super::*;

use crate::bgv::coefficient_codec::coefficient_vector_hash512;

// Canonical per-limb hash of a public-key share coefficient vector, bound into
// the public-key share records and the public-key share material records.
const PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-share-coefficient-vector";

pub(in crate::bgv::setup) fn public_key_share_coefficient_vector_hash(
    coefficients: &[u64],
) -> String {
    coefficient_vector_hash512(
        coefficients,
        PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN,
    )
}

#[derive(Clone)]
pub(super) struct PublicKeyShareMaterialBinding {
    pub(super) coefficients_by_limb: Vec<Vec<u64>>,
}

pub(super) fn verify_collective_public_key_material(
    setup_package: &Value,
    ring_degree: usize,
    material_bindings: &BTreeMap<u64, PublicKeyShareMaterialBinding>,
) -> CanonicalResult<Option<Refusals>> {
    let Some(aggregate_object) = setup_package.get("collectivePublicKey") else {
        return Ok(Some(setup_refusals(
            vec!["collectivePublicKey".to_string()],
            Vec::new(),
        )));
    };
    if !aggregate_object.is_object() {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "collectivePublicKey must be an object",
        )));
    }
    if aggregate_object.get("objectType").and_then(Value::as_str)
        != Some(COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE)
    {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "collectivePublicKey.objectType must be CollectivePublicKey",
        )));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    if let Err(error) = verify_collective_public_key_coefficients(
        aggregate_object,
        material_bindings,
        ring_degree,
        roster.participant_count,
    ) {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            error.message,
        )));
    }
    Ok(None)
}

mod collective_public_key;
mod material_records;
mod material_set;
mod transport;

use collective_public_key::*;

pub(super) use material_records::verify_public_key_share_material_set;
pub(in crate::bgv::setup) use transport::{
    CanonicalPublicKeyShareMaterialStream, VerifiedCanonicalPublicKeyShareMaterialHandle,
    VerifiedCanonicalPublicKeyShareMaterialStoreEntry,
    absorb_verified_canonical_public_key_share_material_chunk,
    begin_verified_canonical_public_key_share_material_stream,
    cancel_verified_canonical_public_key_share_material_stream,
    finish_verified_canonical_public_key_share_material_stream,
};
