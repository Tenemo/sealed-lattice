# Crypto package

This private package owns the current domain-separated cryptographic wrappers used by the election foundation.

The current release implements protocol hash derivation, canonical JSON normalization, signature helpers, signed-root verification, private mailbox envelope encryption/decryption, and encrypted local trustee state storage for the workspace packages.

It is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or provider controls.
