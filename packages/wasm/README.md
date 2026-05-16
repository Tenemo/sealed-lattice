# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific
instantiation details.

The current release ships the transcript core command contract around the Rust
crate. It verifies canonical objects, fixture replays, chunk roots, reserved
protocol digest derivation, `GF(65537)` interpolation/comparison checks, and
stable canonical rejection codes in Node and browser/WASM builds.
