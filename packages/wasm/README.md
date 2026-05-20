# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific instantiation details.

The current release ships the transcript-core command contract and ballot privacy proof verification path around the Rust crate. It verifies canonical objects, fixture replays, chunk roots, reserved protocol digest derivation, `GF(65537)` interpolation/comparison checks, receiver-key and encoded-score ballot proof records, scoped relation-bearing ballot packages, stable canonical rejection codes, and explicit WASM kernel integrity expectations in Node and browser/WASM builds.
