mod material_transport;

pub(super) use self::material_transport::setup_proof_record_binding_value;
pub(in crate::bgv::setup) use self::material_transport::verified_setup_proof_material_chunks_from_request;
pub(crate) use self::material_transport::{
    SetupProofMaterialTransportHashes, absorb_setup_proof_material_transport_stream_chunk_request,
    begin_setup_proof_material_transport_stream_request,
    finish_setup_proof_material_transport_stream_request, setup_proof_material_transport_hashes,
};

use serde_json::{Value, json};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, derive_protocol_hash, hash512_hex, to_hex},
};

pub(super) const SETUP_PROOF_PROFILE_ID: &str = "SealedLattice-SetupProof-v1";
pub(super) const SETUP_PROOF_BYTES_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/succinct-proof-bytes-v1";
pub(super) const SETUP_PROOF_SERIALIZATION: &str = "binary";
pub(crate) const SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
pub(crate) const SETUP_PROOF_MATERIAL_ENCODING: &str = "binary-chunked-proof-bytes";
const SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupProofMaterialChunkManifest";
const SETUP_PROOF_BYTE_DECODER: &str = "sealed-lattice-succinct-setup-proof-byte-decoder-v1";
// Families whose proof bytes ride the chunked setup proof-material transport:
// private VSS plus the same-secret linkage anchor, public-key share, and
// trustee evaluation-key succinct arguments. Their theorem accounting is bound
// per family rather than through the legacy LNP/tbox profile.
pub(super) const SETUP_PROOF_TRANSPORT_FAMILIES: &[&str] = &[
    "vss-opening-carry",
    "public-key-share",
    "same-secret-linkage-anchor",
    "trustee-evaluation-key",
];

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ProfileComponentMismatch, message)
}
