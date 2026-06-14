# Crypto package

This private package owns the current domain-separated cryptographic wrappers used by the election foundation.

The current release implements transcript-core hash-512 SHAKE256 framing, protocol hash derivation, canonical JSON normalization, ML-DSA-65 fixture key generation, ML-DSA signature profile construction, canonical signed-root fixture signing, signed-root verification, internal private VSS mailbox envelope encryption/decryption with ML-KEM-768, HKDF-SHA-384, and AES-256-GCM with recomputed byte-hash checks, and encrypted local trustee state storage with a positive sealed-payload schema.

It is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or provider controls.
