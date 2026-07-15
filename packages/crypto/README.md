# Crypto package

This private package owns the current domain-separated cryptographic wrappers used by the election foundation.

The current release implements protocol hash derivation, canonical JSON serialization with fail-closed ASCII-only strings, signature helpers, signed-root verification, private mailbox envelope encryption/decryption, and encrypted local trustee state storage for the workspace packages. Unicode display text belongs to the pinned Rust/WebAssembly foundation codec.

Private mailbox encryption authenticates the encrypted envelope and associated data to the recipient; source provenance for protocol objects must still come from signed transcript roots where the protocol requires it.

It is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or low-level key-management controls.
