use super::evaluation_domain::negacyclic_transpose_product;
use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentValue,
    StructuralMatrixPolynomial, setup_commitment_matrix_coefficients_cached,
    structural_matrix_polynomial_kind,
};
use crate::bgv::setup::sampling::dense_public_residues_with_degree;
use crate::bgv::setup::sharing::canonical_trustee_point;
use crate::bgv::{
    evaluator::{
        key_switch::{KEY_SWITCH_SAMPLE_DOMAIN, PLAINTEXT_MODULUS_I64},
        prg::DeterministicSampler,
    },
    profile::DATA_PRIMES,
};
use crate::hashing::hash512;

// Re-import the proof-family labels (defined in the parent module) so the
// sub-modules keep referencing them as `super::<LABEL>` after the move under
// this `relation/` directory.
use super::{
    COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY, PRIVATE_VSS_SHARE_PROOF_FAMILY,
    PUBLIC_KEY_SHARE_PROOF_FAMILY, SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
};

// The trustee evaluation-key relation is split by responsibility. Each
// sub-module begins with `use super::super::*;` (to reach the parent module's
// constants and helpers such as `signed_value_residue`, `invalid_succinct_setup_proof`,
// the trace/consistency parameters, and the fast modular arithmetic) and
// `use super::*;` (to reach the shared imports above and the sibling relation
// items re-exported here). Items consumed by the sibling prover/verifier/codec
// modules are re-exported at crate visibility because those consumers sit a
// directory level above these sub-modules.
mod column_layout;
mod compact_vss_vectors;
mod constraint_kernels;
mod diagonal_source_algebra;
mod family_shape_and_validation;
mod linkage_and_vss_vectors;
mod statement_types;

pub(crate) use column_layout::*;
pub(crate) use compact_vss_vectors::*;
pub(crate) use constraint_kernels::*;
pub(crate) use diagonal_source_algebra::*;
pub(crate) use family_shape_and_validation::*;
pub(crate) use linkage_and_vss_vectors::*;
pub(crate) use statement_types::*;

#[cfg(test)]
mod development_instances;
#[cfg(test)]
pub(crate) use development_instances::*;
