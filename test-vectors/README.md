# Test vectors

Deterministic known-answer vectors consumed by the test suite. Each vector carries its inputs and the expected outputs (hashes, tallies, slot encodings); the consuming tests re-derive those outputs from the producing code and assert they match, so every vector is bound to the code that generates it.

## Files

- `succinct-setup-statement-hashes.json`: byte-identical succinct-setup statement hashes the Rust and TS/WASM provers must both reproduce.
- `fiat-shamir-limb-group-key-switch-atom-transcript-order.json`: the exact run-length-encoded initialize, absorb, and squeeze order shared by the atom prover and verifier fixture.
- `fiat-shamir-trustee-evaluation-key-transcript-order.json`: the exact root and per-limb transcript order shared by the trustee evaluation-key share-linkage prover and verifier fixture.

When the producing code changes a vector's output on purpose, update the expected values in the JSON; the consuming test verifies them, and git tracks the change.
