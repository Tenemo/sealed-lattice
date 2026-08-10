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
four still require the remaining masking and emitted-byte theorem closure, live
transcript driving, authenticated restart, selected-size execution, and one
reproducible scalar browser artifact.

The reduced compact kernel chain now publishes all 24 response boundaries
through the common authenticated checkpoint event chain, binding the exact
schedule and response ordinal plus the combined construction-private and
transcript cursor. Its focused owner covers genesis replay, continuation
authority, exact target-cursor release, and changed-target refusal. This is
kernel checkpoint-publication evidence only: browser custody does not yet
append and replay the compact chain's authenticated live-object and deletion
trailer, restore a live compact state at the target, or checkpoint internal CFW
and WHIR safe boundaries. No selected-size durable-restart or release-WASM
evidence follows from it.

The browser bridge must transfer ordinary owned binary buffers rather than a
`WebAssembly.Memory` buffer. Any operation that may grow memory invalidates its
previous JavaScript views; the bridge must reacquire the current buffer before
access. Selected-size evidence must cover the exact growth bound, refusal one
unit over, allocation failure below the bound, ordinary-buffer detachment and
attempted reuse, copy counts, and simultaneous WASM, JavaScript, transfer, and
storage-I/O residency. None of that physical-phone evidence exists yet.

Raw cryptographic operations, proof witnesses, setup secrets, and decryption helpers remain internal.
