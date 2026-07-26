# Upstream provenance

This directory contains `p3-sumcheck` from
`https://github.com/Plonky3/Plonky3.git` at exact revision
`f07da1c479c519040cca27924184c2730315e202`. The original
`Cargo.toml.orig`, changelog, benchmark, test sources, and MIT and Apache 2.0
license files are retained. `Cargo.toml` expands inherited workspace metadata
and dependencies so this single modified crate can be used as a local Cargo
patch. The vendored manifest contains neither a nested patch table nor a
lockfile; the repository root is the sole dependency-graph authority.

The production dependency graph remains pinned to that exact upstream
revision. The repository root contains the authoritative Cargo patch table and
lockfile. The patch redirects only `p3-sumcheck` and the already-vendored
Rust-1.90 compatibility copy of `p3-util`; every other Plonky3 crate continues
to come from the exact upstream revision.

The source modifications add the explicit-point opening hooks and the
query-restoration batching recurrence needed by the sealed-lattice WHIR
reduction:

- `Layout::eval_at_point` records a prover opening at a caller-derived
  multilinear point, absorbs the point before its evaluations, and retains the
  same prefix or suffix layout claim data used by ordinary openings.
- `Verifier::add_claim_at_point` checks the opening shape, absorbs the same
  point and evaluations in the same order, and records the corresponding
  verifier claim.
- Incremental constraint batching reserves `gamma^m` for the carried claim and
  assigns powers `0..m` to a batch's `m` fresh constraints. This is the
  coefficient-reversed form of WHIR's carried-plus-fresh random combination:
  it preserves the same degree while preventing a fresh constant coefficient
  from cancelling the carried claim deterministically.
- The scalar prover, packed prover, running verifier claim, and final
  constraint-polynomial evaluation all use that same chronological recurrence.

The changes are confined to:

- `src/constraints/mod.rs`
- `src/layout/prover/mod.rs`
- `src/layout/prover/prefix.rs`
- `src/layout/prover/suffix.rs`
- `src/layout/verifier.rs`
- `src/product_polynomial.rs`
- `src/strategy.rs`

Each retained modified Rust source file carries a local-modification notice
that identifies its deviation and points back to this provenance record.

Focused local tests require explicit-point prover and verifier transcript
agreement for both layout strategies, reject a changed point, and reject an
opening-shape mismatch. They also exercise deterministic cancellation attempts
against two fresh constraints and require scalar, packed, running-verifier, and
final-verifier batching agreement.
