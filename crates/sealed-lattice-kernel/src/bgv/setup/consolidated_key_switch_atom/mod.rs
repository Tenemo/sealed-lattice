//! Consolidated key-switch digit atom: development gate for the mobile
//! trustee evaluation-key proving path.
//!
//! The production trustee evaluation-key relation is checked per (digit,
//! limb) pair over each active data prime. Because the CRT map is a ring
//! isomorphism, the full set of per-limb congruences for one digit with the
//! shared small witnesses (ternary secret, one centered-binomial error per
//! digit) is exactly equivalent to a single congruence modulo the limb-group
//! product, provable over one large prime proof field with a single small
//! carry polynomial. This module implements that consolidated relation and
//! the arithmetic it needs:
//!
//! - fixed-width Montgomery arithmetic over generalized-Fermat proof fields
//!   whose shape is simultaneously NTT-friendly (2^16 divides p - 1) and
//!   base-b digit-encodable (p = b^64 + 1);
//! - a negacyclic number-theoretic transform over those fields;
//! - CRT recombination of per-limb kernel material into centered mod-Q
//!   representatives, where the CRT basis constants are also the key-switch
//!   gadget idempotents;
//! - the consolidated digit-atom congruence check with an exact carry bound;
//! - signed base-b witness digit encoding and a seeded Ajtai commitment
//!   round sized for prover-cost measurement.
//!
//! This module is currently registered for test builds only: it is exercised
//! by its unit tests and by the ignored gate benchmark, and it changes no
//! shipped kernel behavior. The commitment-round dimensions here are
//! measurement-scale placeholders, not a security parameter selection.

pub(crate) mod commitment_round;
pub(crate) mod consolidated_statement;
pub(crate) mod negacyclic_transform;
pub(crate) mod proof_field;
pub(crate) mod wide_unsigned;
pub(crate) mod witness_encoding;

#[cfg(test)]
mod gate_benchmark;
