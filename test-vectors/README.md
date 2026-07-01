# Test vectors

Deterministic known-answer vectors consumed by the test suite. Each vector carries its inputs and the expected outputs (hashes, tallies, slot encodings); the consuming tests re-derive those outputs from the producing code and assert they match, so every vector is bound to the code that generates it.

## Files

- `plaintext-oracle/`: comparator polynomials, field arithmetic, Shamir recovery, sparse targets, and top-k derivation, exercised by the `plaintext-oracle-*` protocol tests.
- `succinct-setup-statement-hashes.json`: byte-identical succinct-setup statement hashes the Rust and TS/WASM provers must both reproduce.

When the producing code changes a vector's output on purpose, update the expected values in the JSON; the consuming test verifies them, and git tracks the change.
