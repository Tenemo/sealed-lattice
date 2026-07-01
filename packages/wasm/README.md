# WASM package

This package owns Rust/WASM loading, typed wrappers, and runtime-specific instantiation details.

The current release exposes typed wrappers around the Rust kernel for canonical verification, setup-development verification, transported material handling, and package integration tests in Node and browsers. It supports the workspace packages and the published SDK facade; it is not a public voting API.

Raw cryptographic operations, proof witnesses, setup secrets, and decryption helpers remain internal.
