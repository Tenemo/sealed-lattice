# Crypto package

This private package owns domain-separated cryptographic wrappers used by the sealed-lattice foundation.

## Responsibilities

- Derive protocol hashes and canonical private-envelope bindings.
- Hold browser-local key capabilities without exporting raw private keys.
- Seal and open authenticated private-mailbox records through closed, domain-separated operations.
- Keep cryptographic randomness under the participant worker's canonical action and attempt authority.

## Boundaries

The package must fail closed when a provider cannot perform the exact participant-worker operation. Generic hidden-randomness and remote-provider interfaces are unsupported. Protocol-object provenance still comes from the signed transcript roots required by the protocol, not from successful envelope transport.

This is not a public API surface. The published `sealed-lattice` package vendors the required runtime internally and does not export raw hash, signing, mailbox encryption, or low-level key-management controls. Current implementation status and limitations belong to the repository [README](../../README.md) and [SECURITY.md](../../SECURITY.md).
