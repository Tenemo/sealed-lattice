//! Shared proof primitives and deterministic transcript-domain bindings.

mod decoder;
mod domain;
mod merkle;
mod transcript;

pub(crate) use decoder::{BoundedProofDecoder, ProofDecodeError};
pub(crate) use domain::{
    common_proof_randomness_purpose_is_assigned, common_proof_transcript_domain_id,
};
pub(crate) use merkle::{
    leaf_hash as canonical_merkle_leaf_hash, node_hash as canonical_merkle_node_hash,
};
pub(crate) use transcript::{CanonicalProofTranscript, CanonicalTranscriptEngine};

#[cfg(test)]
mod tests;
