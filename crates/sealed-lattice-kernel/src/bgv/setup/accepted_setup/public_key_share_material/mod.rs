use super::*;

use crate::hashing::derive_canonical_object_hash;

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
    trustee_identity: String,
    trustee_roster_position: u64,
    pub(super) public_key_share_root: String,
    pub(super) public_key_share_material_root: String,
    pub(super) coefficients_by_limb: Vec<Vec<u64>>,
}

pub(super) fn verify_collective_public_key_material(
    setup_package: &Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Option<Refusals>> {
    let Some(aggregate_object) = setup_package.get("collectivePublicKey") else {
        return Ok(Some(setup_refusals(
            vec!["collectivePublicKey".to_string()],
            Vec::new(),
        )));
    };
    if !aggregate_object.is_object() {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyNotObject",
            "collectivePublicKey must be a root-bound object",
            "setupPackage.collectivePublicKey",
        )?));
    }
    if aggregate_object.get("objectType").and_then(Value::as_str)
        != Some(COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyTypeMismatch",
            "collectivePublicKey.objectType must be CollectivePublicKey",
            "setupPackage.collectivePublicKey.objectType",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before collective public-key verification",
        )
    })?;
    let material_set = setup_package.get("publicKeyShareMaterial").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial was required before collective public-key verification",
        )
    })?;
    let succinct_proof_set = setup_package
        .get("publicKeyShareSuccinctProofs")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSuccinctProofs was required before collective public-key verification",
            )
        })?;
    let common_binding = public_key_common_binding(setup_package)?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let public_key_share_set_root = value_string(
        setup_package.get("publicKeyShares").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShares was required before collective public-key verification",
            )
        })?,
        "publicKeyShareSetRoot",
    )?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        public_key_share_set_root,
        &share_records,
        proof_binding_session,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(Some(public_key_refusal(
                "collectivePublicKeySourceMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    let roster = super::accepted_roster_from_package(setup_package)?;
    let ring_degree = POLYNOMIAL_DEGREE;
    if let Err(error) = verify_collective_public_key_coefficients(
        aggregate_object,
        &material_bindings,
        ring_degree,
        roster.participant_count,
    ) {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyVerificationFailed",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
    let Some(collective_public_key_root) = aggregate_object
        .get("collectivePublicKeyRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(setup_refusals(
            vec!["collectivePublicKey.collectivePublicKeyRoot".to_string()],
            Vec::new(),
        )));
    };
    validate_hash_string(
        collective_public_key_root,
        "collectivePublicKey.collectivePublicKeyRoot",
    )?;
    let root_input = json!({
        "objectType": COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": common_binding.public_matrix_seed_hash.as_str(),
        "publicKeyShareSetRoot": public_key_share_set_root,
        "publicKeyShareMaterialSetRoot": value_string(
            material_set,
            "publicKeyShareMaterialSetRoot",
        )?,
        "publicKeyShareSuccinctProofSetRoot": value_string(
            succinct_proof_set,
            "publicKeyShareSuccinctProofSetRoot",
        )?,
        "aggregateCoefficientVectorsByLimb": aggregate_object
            .get("aggregateCoefficientVectorsByLimb")
            .ok_or_else(|| CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            ))?,
    });
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if collective_public_key_root != expected_root {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyRootMismatch",
            "collectivePublicKeyRoot does not match the canonical collective public key",
            "setupPackage.collectivePublicKey.collectivePublicKeyRoot",
        )?));
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
