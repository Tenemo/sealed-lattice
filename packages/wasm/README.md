# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific instantiation details.

The current release exposes typed wrappers around the Rust kernel for canonical verification, setup-development verification, transported material handling, and package integration tests in Node and browsers. It supports the workspace packages and the published SDK facade; it is not a public voting API.

The canonical participant build must retain a scalar WebAssembly baseline. A
SIMD build is optional acceleration only after feature detection and
byte-for-byte acceptance and refusal parity. The canonical producer does not
enable WebAssembly SIMD globally.
Long-running workers cannot assume background execution or a final lifecycle
callback. Their owning protocol runtime must provide proactive authenticated
checkpoint custody and bounded deterministic resume.

No compact CFW/WHIR packing factor is selected or exported for proof
generation. Current factor byte and lifecycle values are static host-side
development estimates, not release-WASM or browser evidence. Factor eight is
ineligible under the retained-tree scratch bound, while factors one, two, and
four still require theorem closure, live transcript driving, authenticated
restart, selected-size execution, and one reproducible scalar browser artifact.

Raw cryptographic operations, proof witnesses, setup secrets, and decryption helpers remain internal.
