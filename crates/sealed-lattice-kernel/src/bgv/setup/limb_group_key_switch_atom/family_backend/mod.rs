//! Development atom-family proof backend: a masked univariate FRI
//! polynomial-IOP over one limb-group proof field.
//!
//! This path exercises, for one key at one level, the 16 digit-atom
//! congruences
//!
//! ```text
//! B_j + A_j (*) s - t e_j - G_j source_j - Q c_j = 0   over Z_p[X]/(X^N+1),
//! ```
//!
//! where `A_j`, `B_j`, `G_j`, `Q` are the CRT recombination of the transported
//! per-limb key material (the spike's `limb_group_statement` layer), together
//! with the witness support constraints (ternary `s`, eta-2 `e_j`, bounded
//! carry `c_j` by bit range). The witness columns are committed as evaluations
//! over a coset low-degree extension in salted Merkle trees, and the atom
//! congruences and support rows are batched into one composition polynomial
//! checked with a quotient and radix-2 FRI proximity layer. Merkle binding is
//! computational and depends on collision resistance. These implementation
//! checks do not establish the repository-wide knowledge-soundness, QROM, or
//! zero-knowledge composition claims, which remain separate research work.

pub(crate) mod atom_reduction;
#[cfg(test)]
mod bench;
pub(crate) mod carry_range_lookup;
pub(crate) mod column_commitment;
pub(crate) mod domain;
pub(crate) mod key_proof;
pub(crate) mod low_degree;
pub(crate) mod material_aggregate;
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) mod material_aggregate_creation;
pub(crate) mod material_aggregate_opening;
#[allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::unusual_byte_groupings
)]
pub(crate) mod material_aggregate_verify;
pub(crate) mod merkle;
pub(crate) mod polynomial;
pub(crate) mod proof_codec;
pub(crate) mod schedule;
pub(crate) mod statement_bridge;
pub(crate) mod transcript;
