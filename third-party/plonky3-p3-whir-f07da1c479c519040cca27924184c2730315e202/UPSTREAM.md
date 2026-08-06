# Upstream provenance

This directory contains `p3-whir` from
`https://github.com/Plonky3/Plonky3.git` at exact revision
`f07da1c479c519040cca27924184c2730315e202`. The original
`Cargo.toml.orig`, README, changelog, benchmark, example, test sources, and MIT
and Apache 2.0 license files are retained. `Cargo.toml` expands inherited
workspace metadata and dependencies so this single modified crate can be used
as a local Cargo patch. The vendored manifest contains neither a nested patch
table nor a lockfile; the repository root is the sole dependency-graph
authority.

The production dependency graph remains pinned to that exact upstream
revision. The repository root contains the authoritative Cargo patch table and
lockfile. Unmodified Plonky3 crates continue to come from the exact upstream
revision.

The source modification adds a resumable verifier replay state. It consumes
the same transcript messages, sumcheck equations, STIR query sampler, Merkle
checks, constraint batching, and terminal identity as the original verifier,
but accepts one proof section or one authenticated query at a time. The
original complete-proof verifier is retained as an adapter that drives the
same replay state. This lets a browser verifier release each decoded query
value and authentication path before reading the next one instead of retaining
a complete `WhirProof`.

The local patch is required because the upstream verifier API accepts a
complete `WhirProof` and therefore cannot release earlier query/path sections.
For the exact selected geometry, the checked
`selected_whir_resumable_api_reduces_required_proof_payload_residency` test
derives a 2,183,808-byte lower bound for the directly owned field, Merkle-path,
and final-polynomial payload of that complete proof. The same geometry has a
1,502,600-byte maximum incremental section-state peak, a reduction of 681,208
bytes (the complete-proof lower bound is 1.4533 times the section peak). These
figures are dependency-selection evidence derived from the checked protocol
configuration; they are not proof admission limits and do not replace the
repository's absolute common-proof bound.

The selected hiding integration also requires two bounded-prover changes that
the upstream API does not expose. First, mask encoders and the Construction
7.2 base case accept explicit caller-owned one-time material, so every secret
coin is drawn by sealed-lattice's domain-separated private-coin source rather
than by an entropy source hidden inside the dependency. Second, the base case
can return a transcript-complete prepared state after its source positions are
sampled, then accept exactly those authenticated source openings. This permits
the browser worker to fetch bounded rows from authenticated external storage
without changing commitment-before-challenge order, transcript bytes, or
verification equations. The original convenience prover remains as an
adapter that samples material and drives the same implementation.

The hiding implementation is gated behind a default-off `zk` feature. That
feature enables the vendored `p3-sumcheck/zk` feature and the optional
`p3-zk-codes` and `rand` dependencies. The selected aggregate-wide masking
path deliberately enables it. Hiding-only transcript labels and shared
polynomial-evaluation helpers remain gated by the same feature. Although
upstream generic bounds retain `rand`, the selected integration supplies all
secret material through explicit caller-owned inputs drawn from
sealed-lattice's domain-separated private-coin source.

The compact constrained-code path additionally needs an outer relation
handoff that upstream hiding WHIR does not expose. The local prover can commit
an extension-field source oracle and accept mask groups that an outer protocol
already committed before its relation-batching challenge. The matching
verifier carries the same commitments and dense linear covectors through every
masked sumcheck and into the base case without observing the earlier roots a
second time. Both sides validate caller-owned source, group, message,
randomness, and covector dimensions with typed errors. The ordinary
point-opening adapter remains unchanged and drives the same internal reduction
with no external groups.

The hiding configuration also derives unique-decoding source queries from the
physical Reed-Solomon dimension `message length + hiding randomness length`.
Each source query count is the least fixed point whose exact strict integer
decoding-radius failure reaches the configured security level. The exported
source-code shape records the complete dimension, minimum distance, strict
radius, minimum agreement, and resulting query security so sealed-lattice can
independently reconcile every committed source oracle. Mask query derivation
remains the upstream rate-based conservative bound and is checked separately
against the complete grouped final verifier move.

The obsolete complete-proof commitment reader and unused round proof-of-work
getter were removed. Neither the plain prover, resumable verifier, complete
verifier adapter, hiding implementation, nor tests consumed them. The
resumable verifier owns commitment transcript replay and reads each round's
proof-of-work witness from the round proof it is currently validating.

The changes are confined to:

- `src/pcs/verifier/mod.rs`
- `src/pcs/verifier/errors.rs`
- `src/pcs/mod.rs`
- `src/pcs/committer/mod.rs`
- `src/pcs/committer/writer.rs`
- `src/pcs/committer/reader.rs` (removed)
- `src/pcs/proof.rs`
- `src/pcs/zk/base_case/mod.rs`
- `src/pcs/zk/base_case/prover.rs`
- `src/pcs/zk/constraint/source.rs`
- `src/pcs/zk/config.rs`
- `src/pcs/zk/mask.rs`
- `src/pcs/zk/mod.rs`
- `src/pcs/zk/prover/data.rs`
- `src/pcs/zk/prover/masks.rs`
- `src/pcs/zk/prover/mod.rs`
- `src/pcs/zk/relation.rs` (added)
- `src/pcs/zk/verifier/masks.rs`
- `src/pcs/zk/verifier/mod.rs`
- `src/fiat_shamir/domain_separator.rs`
- `src/fiat_shamir/pattern.rs`
- `src/lib.rs`
- `Cargo.toml`

Each modified Rust source file carries a local-modification notice that points
back to this provenance record.
