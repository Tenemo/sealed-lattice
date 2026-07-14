// Public key-switch component material for evaluation-key share records: the
// canonical component-vector encoding and the chunked binary transport. The
// correctness proof over this material is the per-trustee succinct argument
// in trustee_evaluation_key_proof; this module carries no proof logic.

mod component_material;

pub(in crate::bgv::setup) use self::component_material::{
    CanonicalComponentMaterialStream, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry,
    absorb_verified_canonical_component_material_chunk,
    begin_verified_canonical_component_material_stream,
    cancel_verified_canonical_component_material_stream, discard_session_component_material,
    finish_verified_canonical_component_material_stream,
};
pub(super) use self::component_material::{
    DecodedEvaluationKeyShareComponentMaterial, EvaluationKeyShareDerivedMaterialBinding,
    component_b_vectors_from_record,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::component_material::{
    evaluation_key_share_component_material_reference_root,
    evaluation_key_share_component_vector_root,
};

use std::{collections::BTreeMap, sync::Arc};
// The component-material stream only touches the filesystem on native; the
// browser wasm runtime stages in memory and never opens a file.
#[cfg(not(target_arch = "wasm32"))]
use std::{fs::File, io::Read, path::PathBuf};

use serde_json::{Value, json};

use crate::{
    bgv::coefficient_codec::coefficient_vector_le_hex,
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    bgv::setup_helpers::string_field,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::VerifiedCanonicalStreamSummary,
};

const EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC: &[u8; 8] = b"SLEKCMV1";

// Key-share families whose component material this module encodes; the family
// string scopes the component hash domains and material references.
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

fn invalid_evaluation_key_share_material(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
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
