# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input.
- Translate validated poll input into the canonical foundation-manifest ingress shape.
- Provide internal authenticated storage, local-record protection, checkpoint, and strict IndexedDB foundations without minting protocol capabilities.
- Expose only those implemented helpers through the package entry point.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package does not implement the complete collective-preparation-to-release ceremony. Its storage, checkpoint, and unactivated candidate helpers return only inert bytes, typed refusals, or local custody outcomes; they cannot mint preparation, selected-set, input-activation, evaluation, finality, release, or result capabilities. Exact exports and verifier boundaries are owned by the package entry point and tests. TypeScript must not replace kernel cryptography or turn transport and persistence status into acceptance.

Current implementation status belongs to the repository [README](../../README.md), and current security limitations belong to [SECURITY.md](../../SECURITY.md). Package documentation intentionally does not repeat proof geometry, benchmark snapshots, theorem ledgers, or historical backend decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
