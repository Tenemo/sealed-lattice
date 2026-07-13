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
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(aggregate_object) = setup_package.get("collectivePublicKey") else {
        return Ok(Some(verification_response(
            Some("setupPackageAssembly"),
            vec!["collectivePublicKey".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
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
    if let Err(error) =
        verify_context_fields_match(aggregate_object, setup_context, "collectivePublicKey")
    {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyContextMismatch",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
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
    if public_key_share_material_uses_transport(material_set)
        && request.get("transportedPublicKeyShareMaterial").is_none()
    {
        return Ok(Some(verification_response(
            Some("setupPackageAssembly"),
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    let common_binding = public_key_common_binding(setup_package)?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        value_string(
            setup_package.get("publicKeyShares").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShares was required before collective public-key verification",
                )
            })?,
            "publicKeyShareSetRoot",
        )?,
        &share_records,
        request,
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
    let roster = super::accepted_roster_from_package(setup_package);
    let ring_degree = value_u64(aggregate_object, "ringDegree")?;
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE as u64
        || aggregate_object
            .get("participantCount")
            .and_then(Value::as_u64)
            != Some(roster.participant_count)
        || aggregate_object.get("rnsLimbCount").and_then(Value::as_u64)
            != Some(DATA_PRIMES.len() as u64)
    {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyParametersCountMismatch",
            "collectivePublicKey participant count, limb count, and ring degree must match the selected setup parameters",
            "setupPackage.collectivePublicKey",
        )?));
    }
    let expected_source_bindings = [
        (
            "publicMatrixSeedHash",
            Some(common_binding.public_matrix_seed_hash.as_str()),
        ),
        (
            "publicKeyCrpRoot",
            Some(common_binding.public_key_crp_root.as_str()),
        ),
        (
            "publicAPolynomialRoot",
            Some(common_binding.public_a_polynomial_root.as_str()),
        ),
        (
            "publicKeyShareSetRoot",
            setup_package
                .get("publicKeyShares")
                .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareProofSetRoot",
            setup_package
                .get("publicKeyShareProofs")
                .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareMaterialSetRoot",
            material_set
                .get("publicKeyShareMaterialSetRoot")
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            succinct_proof_set
                .get("publicKeyShareSuccinctProofSetRoot")
                .and_then(Value::as_str),
        ),
    ];
    for (field_name, expected_value) in expected_source_bindings {
        if aggregate_object.get(field_name).and_then(Value::as_str) != expected_value {
            return Ok(Some(public_key_refusal(
                "collectivePublicKeySourceRootMismatch",
                format!("collectivePublicKey.{field_name} must bind the verified source root"),
                format!("setupPackage.collectivePublicKey.{field_name}"),
            )?));
        }
    }
    if let Err(error) = verify_collective_public_key_coefficients(
        aggregate_object,
        &material_bindings,
        usize::try_from(ring_degree).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public-key ring degree does not fit usize",
            )
        })?,
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
        return Ok(Some(verification_response(
            Some("setupPackageAssembly"),
            vec!["collectivePublicKey.collectivePublicKeyRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        collective_public_key_root,
        "collectivePublicKey.collectivePublicKeyRoot",
    )?;
    let mut root_input = aggregate_object.clone();
    root_input
        .as_object_mut()
        .expect("collective public-key object was checked")
        .remove("collectivePublicKeyRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if collective_public_key_root != expected_root {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyRootMismatch",
            "collectivePublicKeyRoot does not match the canonical collective public key",
            "setupPackage.collectivePublicKey.collectivePublicKeyRoot",
        )?));
    }
    if ring_degree == POLYNOMIAL_DEGREE as u64
        && let Err(error) = accepted_setup_collective_public_key_from_package(setup_package)
    {
        return Ok(Some(public_key_refusal(
            "collectivePublicKeyRuntimeMaterialInvalid",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }

    Ok(None)
}

mod collective_public_key;
mod material_records;
mod material_set;
mod transport;

use collective_public_key::*;

pub(in crate::bgv::setup) use collective_public_key::accepted_setup_collective_public_key_from_package;
pub(super) use material_records::verify_public_key_share_material_set;
pub(super) use material_set::public_key_share_material_uses_transport;
#[cfg(test)]
pub(in crate::bgv::setup) use transport::authenticated_public_key_share_material_stream_summary;
#[cfg(test)]
pub(in crate::bgv::setup) use transport::evict_verified_canonical_public_key_share_materials;
pub(in crate::bgv::setup) use transport::{
    CanonicalPublicKeyShareMaterialStream,
    absorb_verified_canonical_public_key_share_material_chunk,
    authenticated_public_key_share_material_stream_summary_in_session,
    begin_verified_canonical_public_key_share_material_stream,
    cancel_verified_canonical_public_key_share_material_stream,
    drain_verified_canonical_public_key_share_materials,
    finish_verified_canonical_public_key_share_material_stream,
};
