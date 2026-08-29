# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input.
- Translate validated poll input into the canonical foundation manifest.
- Provide authenticated storage, local-record protection, checkpoints, and strict IndexedDB handling without approving protocol transitions.
- Expose only those implemented helpers through the package entry point.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package does not implement the complete ceremony. Storage and checkpoint helpers manage local data only; they cannot approve a protocol transition or create a verified protocol result. The package entry point and tests define the export and verification boundaries. TypeScript must not replace kernel cryptography or treat successful transport or persistence as protocol acceptance.

Implementation status belongs to the repository [README](../../README.md), and security limitations belong to [SECURITY.md](../../SECURITY.md). This package document does not repeat proofs, measurements, or historical design decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
