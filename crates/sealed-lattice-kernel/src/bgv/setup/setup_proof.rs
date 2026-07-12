mod material_transport;

pub(super) use self::material_transport::setup_proof_record_binding_value;
#[cfg(test)]
pub(crate) use self::material_transport::{
    setup_proof_material_transport_hashes, SetupProofMaterialTransportHashes,
};
pub(in crate::bgv::setup) use self::material_transport::{
    verified_setup_proof_material_bytes_from_request, SetupProofMaterialBytes,
    VerifiedSetupProofMaterialEvictionGuard,
};

use serde_json::{json, Value};
#[cfg(test)]
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};
#[cfg(test)]
use crate::{
    encoding::{append_bytes, append_varuint},
    hashing::{hash512_hex, to_hex, HASH512_PREIMAGE_PREFIX},
};

pub(super) const SETUP_PROOF_BYTES_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/succinct-proof-bytes";
pub(super) const SETUP_PROOF_SERIALIZATION: &str = "binary";
pub(crate) const SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
pub(crate) const SETUP_PROOF_MATERIAL_ENCODING: &str = "binary-chunked-proof-bytes";
#[cfg(test)]
const SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupProofMaterialChunkManifest";
const SETUP_PROOF_BYTE_DECODER: &str = "sealed-lattice-succinct-setup-proof-byte-decoder";
// Families whose proof bytes ride the chunked setup proof-material transport.
pub(super) const SETUP_PROOF_TRANSPORT_FAMILIES: &[&str] = &[
    "vss-opening-carry",
    "public-key-share",
    "trustee-evaluation-key",
    // Public VSS material proof families. At production roster sizes the
    // share-linkage and same-secret bridge proof material are the largest
    // objects in the setup package, so they stream through the same sidecar
    // transport as the families above instead of riding embedded in the
    // package JSON (which overflows the canonical string encoder at n=10).
    "vss-share-linkage",
    "same-secret-bridge",
];

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
