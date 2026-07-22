# Upstream provenance

This directory contains `p3-util` from
`https://github.com/Plonky3/Plonky3.git` at exact revision
`f07da1c479c519040cca27924184c2730315e202`. The original source,
`Cargo.toml.orig`, changelog, benchmarks, and MIT and Apache 2.0 license files
are retained. `Cargo.toml` expands inherited workspace metadata and
dependencies so the isolated crate can be used as a local Cargo patch. Its
standalone test graph also redirects the exact upstream source back to this
local crate, ensuring the compatibility substitution is exercised there too.
The local `Cargo.toml` and `src/lib.rs` carry explicit modification notices as
required when redistributing the modified source under Apache 2.0.

The repository-root `Cargo.lock` and the root
`proof-backend-bakeoff` feature gates are the authoritative reproducible
dependency graph for this patched crate. The excluded crate's standalone
development graph has no committed lockfile and is diagnostic only; do not
cite a standalone run as commit-pinned closure evidence unless that graph is
independently locked first.

The sole source compatibility substitution is in `apply_to_chunks`. The
upstream call to the initialized-slice convenience method is not stable under
the repository's Rust 1.90 toolchain. The local code constructs the same slice
with `core::slice::from_raw_parts` over the first `n` elements, which the
existing producer has initialized and bounded by the array length. This is
semantically identical to the initialized-slice cast stabilized in Rust 1.93.
One local boundary regression test covers empty, partial, exact, and
multi-chunk inputs for this substitution.
