# Crypto package

This private package owns the current domain-separated cryptographic wrappers used by the election foundation.

The current release implements protocol hash derivation, canonical JSON serialization with fail-closed ASCII-only strings, signature helpers, signed-root verification, private mailbox envelope verification and decryption, and encrypted local trustee state storage for the workspace packages. Unicode display text belongs to the pinned Rust/WebAssembly foundation codec.

Production setup-mailbox sealing currently refuses before consuming plaintext or private capabilities. Reset-safe ML-KEM encapsulation is closed inside the worker, but the signing key and action-randomness root are not yet held behind one closed reset-safe ML-DSA operation. Test-only carrier builders exercise opening, authentication, and refusal behavior without claiming a production sealing path. Source provenance for protocol objects must still come from signed transcript roots where the protocol requires it.

It is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or low-level key-management controls.
