# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific instantiation details.

The current release ships the transcript-core command contract around the Rust crate. It verifies canonical objects, fixture replays, chunk roots, reserved protocol hash derivation, `GF(65537)` interpolation/comparison checks, development passive BGV setup package verification, the internal direct encrypted ballot command, stable canonical rejection codes, and explicit WASM kernel integrity expectations in Node and browser/WASM builds.

The WASM package is not a public voting API. Raw BGV operations, proof witnesses, encryption randomness, plaintext oracle helpers, evaluator intermediate openings, raw VSS shares, setup secrets, and decryption helpers remain internal. The passive setup command is development evidence only and cannot close `CollectiveBgvSetup-v1`.
