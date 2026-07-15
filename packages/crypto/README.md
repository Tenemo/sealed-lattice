# Crypto package

This private package owns the current domain-separated cryptographic wrappers used by the election foundation.

The current release implements protocol hash derivation, canonical JSON serialization with fail-closed ASCII-only strings, browser-local key capabilities, and authenticated private-mailbox sealing and opening for the workspace packages. Unicode display text belongs to the pinned Rust/WebAssembly foundation codec.

Setup-mailbox sealing now composes the worker-owned action-randomness root with the browser-local signing capability behind one closed operation. It derives and immediately consumes the slot-bound ML-KEM input and envelope-bound ML-DSA hedge, publishes ciphertext only after the byte-identical signed carrier and chunks commit, and replays a committed carrier without rereading plaintext or producing another cryptographic view. A provider that cannot perform this exact operation in the dedicated custody worker fails closed; generic hidden-randomness and remote-provider interfaces remain unsupported. Source provenance for protocol objects must still come from signed transcript roots where the protocol requires it.

It is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or low-level key-management controls.
