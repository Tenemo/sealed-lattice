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
//! - the limb-group digit-atom congruence check with an exact carry bound;
//! - signed base-b witness digit encoding and a seeded ring commitment for the
//!   transported evaluation-key material (the material-transport commitment the
//!   family backend binds into its transcript).
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
#[cfg(test)]
pub(crate) mod witness_encoding;

pub(crate) mod family_backend;

// The ring commitment over transported evaluation-key component material stays
// test-gated: the accepted-setup verifier already binds each component's
// material through the verified component-vector root and the published
// aggregate through per-limb reconstruction, so the homomorphic commitment is
// not on the acceptance path. It is retained, with its binding/hiding/
// homomorphism tests, as the substrate for the review-gated flag-day change in
// which atoms verify committed material and reconstruction retires (recorded in
// the key-switch atom family section of `setup-proof-decisions.md`).
#[cfg(test)]
pub(crate) mod witness_commitment;
