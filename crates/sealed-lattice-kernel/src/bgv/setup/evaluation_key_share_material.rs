// Public key-switch component material for evaluation-key share records: the
// canonical component-vector encoding, the chunked binary transport, and the
// deterministic fixture algebra used to build share material in tests. The
// correctness proof over this material is the per-trustee succinct argument
// in trustee_evaluation_key_proof; this module carries no proof logic.

mod component_material;
#[cfg(test)]
mod ring_algebra;

pub(super) use self::component_material::component_b_vectors_from_record;
#[cfg(test)]
pub(super) use self::component_material::{
    KeySwitchComponentBFixtureInput, encode_evaluation_key_share_component_vectors,
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_material_transport_hashes,
    evaluation_key_share_component_vector_hash, evaluation_key_share_component_vector_root,
    key_switch_component_b_for_evaluation_key_fixture,
    register_verified_evaluation_key_share_component_material_chunks,
};
#[cfg(test)]
pub(super) use self::ring_algebra::automorphism_i128_for_evaluation_key_fixture;
#[cfg(test)]
use self::ring_algebra::{deterministic_key_switch_public_sample, signed_i128_residue_u64};

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
#[cfg(test)]
use std::{fs, io::Write};

use serde_json::{Value, json};

#[cfg(test)]
use crate::bgv::evaluator::key_switch::{KEY_SWITCH_SAMPLE_DOMAIN, PLAINTEXT_MODULUS_I64};
#[cfg(test)]
use crate::bgv::evaluator::prg::DeterministicSampler;
#[cfg(test)]
use crate::bgv::modular_arithmetic::{add_mod, mul_mod, sub_mod};
use crate::{
    bgv::coefficient_codec::{
        coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
    },
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_varuint},
    hashing::{derive_protocol_hash, hash512_hex},
};

use super::accepted_setup::COLLECTIVE_BGV_SETUP_PROFILE_ID;
#[cfg(test)]
use super::sampling::negacyclic_product_mod;
use super::setup_proof::{SETUP_PROOF_PROFILE_ID, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES};

pub(super) const EVALUATION_KEY_SHARE_COMPONENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING: &str =
    "binary-chunked-key-switch-component-vectors";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareComponentMaterialSet";
pub(super) const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyShareComponentMaterial";
const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";

// Key-share families whose component material this module encodes; the family
// string scopes the component hash domains and the transported material
// references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvaluationKeyShareProofFamily {
    Relinearization,
    Galois,
}

impl EvaluationKeyShareProofFamily {
    pub(super) fn proof_family(self) -> &'static str {
        match self {
            Self::Relinearization => "relinearization-key-share",
            Self::Galois => "galois-key-share",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct EvaluationKeyShareComponentMaterialTransportHashes {
    pub(super) full_object_hash: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) chunk_root: String,
    pub(super) total_byte_length: u64,
}

fn invalid_evaluation_key_share_material(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(format!(
                "{field_name} must be a non-empty string"
            ))
        })
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(format!("{field_name} must be an array"))
        })
}

fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(format!(
                "{field_name} must be an unsigned integer"
            ))
        })
}

fn value_usize(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let unsigned = value_u64(value, field_name)?;
    usize::try_from(unsigned).map_err(|_| {
        invalid_evaluation_key_share_material(format!("{field_name} does not fit usize"))
    })
}

fn validate_hex_string(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.is_empty() || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_evaluation_key_share_material(format!(
            "{field_name} must be non-empty hexadecimal"
        )));
    }

    Ok(())
}

#[cfg(test)]
fn validate_lowercase_hash(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_evaluation_key_share_material(format!(
        "{field_name} must be lowercase 512-bit hex"
    )))
}

fn read_u64(material_bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    let bytes = read_fixed::<8>(material_bytes, cursor)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_fixed<const LENGTH: usize>(
    material_bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; LENGTH]> {
    let end = cursor.checked_add(LENGTH).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key component material cursor overflowed")
    })?;
    let bytes = material_bytes.get(*cursor..end).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key component material ended early")
    })?;
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(bytes);
    *cursor = end;
    Ok(output)
}

#[cfg(test)]
fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}
