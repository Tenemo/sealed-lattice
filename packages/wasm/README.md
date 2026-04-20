# Wasm package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific
instantiation details.

The current release ships a byte-buffer round-trip contract around the Rust
crate so the toolchain and browser/Node loading path are proven before real
arithmetic lands.
