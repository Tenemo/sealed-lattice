//! Deterministic common-proof profile and suite construction.
//!
//! This module owns the proof field, transcript, commitment format, bounded
//! decoder, relation-plan catalog, and suite arithmetic as one unit. The older
//! proof engines remain accepted only by their existing call sites while their
//! relations are lowered and differentially tested against this profile.

mod decoder;
mod deterministic_artifacts;
mod field;
mod merkle;
mod profile;
mod profile_artifact;
mod relation_plan;
mod suite;
mod transcript;

pub(crate) use decoder::{BoundedProofDecoder, ProofDecodeError};
pub(crate) use merkle::{
    leaf_hash as canonical_merkle_leaf_hash, node_hash as canonical_merkle_node_hash,
};
pub(crate) use profile::{COMMON_PROOF_PROFILE, SecurityAccounting};
pub(crate) use profile_artifact::validate_proof_profile_set_bytes;
pub(crate) use relation_plan::{ProofFamily, RelationPlanCatalog, build_relation_plan_catalog};
#[cfg(test)]
pub(crate) use suite::generate_incomplete_development_proof_suite_candidate;
pub(crate) use suite::{
    common_proof_randomness_purpose_is_assigned, common_proof_suite_id,
    generate_proof_suite_candidate,
};
pub(crate) use transcript::{CanonicalProofTranscript, CanonicalTranscriptEngine};

#[cfg(test)]
mod tests;
