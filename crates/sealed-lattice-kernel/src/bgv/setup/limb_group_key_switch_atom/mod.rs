//! Key-switch digit atom over a limb-group modulus.
//!
//! For one key-switch digit, the verifier recombines limb residues by CRT and
//! checks a single integer congruence modulo the product of the active limb
//! primes. The shared witnesses are the ternary trustee secret and one
//! centered-binomial error polynomial for the digit; the congruence uses a
//! bounded carry polynomial over a large proof field. This test-only module
//! implements the arithmetic substrate for that relation and the proof backend
//! built on top of it:
//!
//! - fixed-width Montgomery arithmetic over generalized-Fermat proof fields
//!   whose shape is simultaneously NTT-friendly (a high power of two divides
//!   p - 1) and base-b digit-encodable (p = b^64 + 1);
//! - a negacyclic number-theoretic transform over those fields;
//! - CRT recombination of limb-group kernel material into centered mod-Q
//!   representatives, where the CRT basis constants are also the key-switch
//!   gadget idempotents;
//! - the limb-group digit-atom congruence check with an exact carry bound.
//!
//! The atom-family proof backend under `family_backend` is the single
//! production backend: a masked univariate FRI polynomial-IOP over the proof
//! field that commits the atom witness columns, checks the digit-atom
//! congruences and the ternary/eta-2/carry support constraints, and opens a
//! shared query set. It is the replacement for the per-limb multi-key FRI
//! trustee evaluation-key prover, built and tested here before the command path
//! is switched over to it.

pub(crate) mod limb_group_statement;
pub(crate) mod negacyclic_transform;
pub(crate) mod proof_field;
pub(crate) mod wide_unsigned;

pub(crate) mod family_backend;
