# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific instantiation details.

The current release exposes typed wrappers around the Rust kernel for canonical verification, setup-development verification, transported material handling, and package integration tests in Node and browsers.

The WASM package is not a public voting API. Raw BGV operations, proof witnesses, encryption randomness, plaintext oracle helpers, evaluator intermediate openings, raw VSS shares, setup secrets, and decryption helpers remain internal. Development commands and fixtures are not supported mobile evidence and do not complete the public voting workflow.
