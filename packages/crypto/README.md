# Crypto package

This private package owns domain-separated cryptographic wrappers used by the sealed-lattice foundation.

## Responsibilities

- Derive protocol hashes and canonical private-envelope bindings.
- Keep private keys inside browser-local operations.
- Seal and open authenticated private-mailbox records through closed, domain-separated operations.
- Bind cryptographic randomness to the participant worker's canonical action and authenticated resume state.

## Boundaries

The package must fail closed when a provider cannot perform the exact participant-worker operation. It does not support generic randomness providers or remote cryptography. Protocol objects still derive their authority from signed transcript roots, not from successful envelope transport.

This is not a public API. The published `sealed-lattice` package includes the runtime internally and does not expose low-level cryptographic or key-management controls. Implementation status and limitations belong to the repository [README](../../README.md) and [SECURITY.md](../../SECURITY.md).
