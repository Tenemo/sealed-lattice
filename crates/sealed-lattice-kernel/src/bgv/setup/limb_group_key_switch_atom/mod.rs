//! Key-switch digit atom over a limb-group modulus.
//!
//! For one key-switch digit, the verifier recombines limb residues by CRT and
//! checks a single integer congruence modulo the product of the active limb
//! primes. The shared witnesses are the ternary trustee secret and one
//! centered-binomial error polynomial for the digit; the congruence uses a
//! bounded carry polynomial over a large proof field. This test-only module
//! implements the arithmetic needed for that relation:
//!
//! - fixed-width Montgomery arithmetic over generalized-Fermat proof fields
//!   whose shape is simultaneously NTT-friendly (2^16 divides p - 1) and
//!   base-b digit-encodable (p = b^64 + 1);
//! - a negacyclic number-theoretic transform over those fields;
//! - CRT recombination of limb-group kernel material into centered mod-Q
//!   representatives, where the CRT basis constants are also the key-switch
//!   gadget idempotents;
//! - the limb-group digit-atom congruence check with an exact carry bound;
//! - signed base-b witness digit encoding and a seeded Ajtai commitment
//!   round sized for prover-cost measurement.
//!
//! The commitment-round dimensions are for measurement only, not a security
//! parameter selection.

pub(crate) mod commitment_round;
pub(crate) mod limb_group_statement;
pub(crate) mod negacyclic_transform;
pub(crate) mod proof_field;
pub(crate) mod wide_unsigned;
pub(crate) mod witness_encoding;

#[cfg(test)]
mod gate_benchmark;

#[cfg(test)]
mod folded_opening_pricing;

#[cfg(test)]
mod witness_commitment;

#[cfg(test)]
mod atom_argument;

#[cfg(test)]
mod linear_opening;

#[cfg(test)]
mod atom_backend;

#[cfg(test)]
mod material_transport;

#[cfg(test)]
mod product_check;

#[cfg(test)]
mod support_proof;

#[cfg(test)]
mod eta2_support;

#[cfg(test)]
mod carry_range;

#[cfg(test)]
mod zk_linear_opening;

#[cfg(test)]
mod key_aggregation;

#[cfg(test)]
mod trustee_schedule_aggregation;
