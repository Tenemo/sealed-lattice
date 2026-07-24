# Upstream provenance

This directory contains `p3-sumcheck` from
`https://github.com/Plonky3/Plonky3.git` at exact revision
`f07da1c479c519040cca27924184c2730315e202`. The original
`Cargo.toml.orig`, changelog, benchmark, test sources, and MIT and Apache 2.0
license files are retained. `Cargo.toml` expands inherited workspace metadata
and dependencies so this single modified crate can be used as a local Cargo
patch.

The production dependency graph remains pinned to that exact upstream
revision. The repository root contains the authoritative Cargo patch table and
lockfile. The patch redirects only `p3-sumcheck` and the already-vendored
Rust-1.90 compatibility copy of `p3-util`; every other Plonky3 crate continues
to come from the exact upstream revision.

The source modification adds the explicit-point opening hooks needed by the
sealed-lattice WHIR reduction:

- `Layout::eval_at_point` records a prover opening at a caller-derived
  multilinear point, absorbs the point before its evaluations, and retains the
  same prefix or suffix layout claim data used by ordinary openings.
- `Verifier::add_claim_at_point` checks the opening shape, absorbs the same
  point and evaluations in the same order, and records the corresponding
  verifier claim.

The changes are confined to:

- `src/layout/prover/mod.rs`
- `src/layout/prover/prefix.rs`
- `src/layout/prover/suffix.rs`
- `src/layout/verifier.rs`

Focused local tests require explicit-point prover and verifier transcript
agreement for both layout strategies, reject a changed point, and reject an
opening-shape mismatch. Production integration additionally tests the
valid-Boolean-openings and false-non-Boolean-terminal forgery at the complete
proof boundary.
