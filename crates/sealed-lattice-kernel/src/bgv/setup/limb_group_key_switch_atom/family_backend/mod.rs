//! Atom-family proof backend: a masked univariate FRI polynomial-IOP over one
//! limb-group proof field.
//!
//! For one scheduled key limb group, it checks the digit-atom congruences
//!
//! ```text
//! B_j + A_j (*) s - t e_j - G_j source_j - Q c_j = 0   over Z_p[X]/(X^N+1),
//! ```
//!
//! where `A_j`, `B_j`, `G_j`, and `Q` are CRT recombinations of transported
//! per-limb key material. The witness constraints require ternary `s`, eta-2
//! `e_j`, and an exact range lookup for `c_j`. Salted Merkle trees commit the
//! witness columns over a coset low-degree extension; quotients and a radix-2
//! FRI layer check the batched congruence and support compositions.

pub(crate) mod atom_reduction;
#[cfg(test)]
mod bench;
pub(crate) mod carry_range_lookup;
pub(crate) mod column_commitment;
pub(crate) mod domain;
pub(crate) mod key_proof;
pub(crate) mod low_degree;
pub(crate) mod merkle;
pub(crate) mod polynomial;
pub(crate) mod proof_codec;
pub(crate) mod schedule;
pub(crate) mod statement_bridge;
#[cfg(test)]
mod test_support;
pub(crate) mod transcript;
