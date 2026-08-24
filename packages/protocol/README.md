# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input and compile canonical manifests.
- Derive roster, threshold, option-count, pair-layout, and evaluator schedules from canonical inputs.
- Coordinate canonical board state, authenticated mailbox delivery, browser-local encrypted custody, checkpoints, and state witnessing.
- Bind kernel-owned verifier cursor profiles to exact source digests in the authenticated checkpoint store, preserve the previous committed cursor until replacement is durable, and keep fresh and resumed custody mutually exclusive. Cursor sizes, boundary counts, source coordinates, and state domains come from canonical kernel owners rather than TypeScript copies.
- Assemble inputs for setup, ballot, aggregation, evaluator, finality, and target-release verification without reimplementing certified cryptography in TypeScript.
- Expose typed protocol helpers through the package entry point for workspace consumers.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package may coordinate bytes, storage, cancellation, and typed results. It does not replace Rust/WebAssembly proof generation or verification, establish parameter security, freeze a suite, or turn a partial workflow into an accepted ceremony. Relays and storage remain untrusted.

Current implementation status belongs to the repository [README](../../README.md), and current security limitations belong to [SECURITY.md](../../SECURITY.md). Package documentation intentionally does not repeat proof geometry, benchmark snapshots, theorem ledgers, or historical backend decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
