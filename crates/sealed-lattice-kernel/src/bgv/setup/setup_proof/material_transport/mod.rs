use super::*;

use std::sync::Arc;

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct SetupProofMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

pub(in crate::bgv::setup) type SetupProofMaterialBytes = Arc<Vec<u8>>;

pub(in crate::bgv::setup) fn setup_proof_record_binding_value(
    setup_parameters_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
        "setupParametersHash": setup_parameters_hash,
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_BYTE_DECODER,
    }))
}

pub(in crate::bgv::setup) fn verified_setup_proof_material_bytes_from_request(
    _request: &Value,
    proof_family: &str,
    expected_proof_material_root: &str,
    _transported_proof_material: &Value,
    transported_material_path: &str,
) -> CanonicalResult<SetupProofMaterialBytes> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof parameters",
        ));
    }
    validate_hash_string(
        expected_proof_material_root,
        &format!("{transported_material_path}.proofMaterialRoot"),
    )?;
    crate::bgv::setup::verified_canonical_setup_proof_material_bytes(
        proof_family,
        expected_proof_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{transported_material_path} is missing canonical stream-authenticated proof material"
            ),
        )
    })
}

fn request_verified_canonical_setup_proof_material_roots(request: &Value) -> Vec<String> {
    [
        "transportedPrivateVssShareProofMaterial",
        "transportedPublicKeyShareProofMaterial",
        "transportedVssShareLinkageProofMaterial",
        "transportedSameSecretBridgeProofMaterial",
        "transportedEvaluationKeyShareProofMaterial",
    ]
    .into_iter()
    .filter_map(|field_name| request.get(field_name))
    .filter_map(|material_set| material_set.get("proofMaterials"))
    .filter_map(Value::as_array)
    .flatten()
    .filter_map(|proof_material| proof_material.get("proofMaterialRoot"))
    .filter_map(Value::as_str)
    .map(str::to_string)
    .collect()
}

pub(in crate::bgv::setup) struct VerifiedSetupProofMaterialEvictionGuard {
    canonical_proof_material_roots: Vec<String>,
}

impl VerifiedSetupProofMaterialEvictionGuard {
    pub(in crate::bgv::setup) fn for_request(request: &Value) -> Self {
        Self {
            canonical_proof_material_roots: request_verified_canonical_setup_proof_material_roots(
                request,
            ),
        }
    }
}

impl Drop for VerifiedSetupProofMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_setup_proof_materials(
            &self.canonical_proof_material_roots,
        );
    }
}

#[cfg(test)]
mod helpers;
#[cfg(test)]
mod verification;

#[cfg(test)]
pub(crate) use verification::setup_proof_material_transport_hashes;
