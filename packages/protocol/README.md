# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input.
- Translate validated poll input into the canonical foundation-manifest ingress shape.
- Provide internal authenticated storage, local-record protection, checkpoint, and strict IndexedDB foundations without minting protocol capabilities.
- Expose only those implemented helpers through the package entry point.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package does not currently orchestrate collective preparation, selected ballot sets, activation, certified evaluation, finality, release, or complete browser custody. Its checkpoint and storage modules are internal persistence mechanisms only. Unactivated seed-mailbox state owners persist sender source and randomness before generation, persist one recipient's exact local custody, receipt intent, and signing randomness before receipt production, and persist one participant's complete receipt-terminal endorsement intent and signing randomness before endorsement production. Each retains its complete public carrier before publication and coordinates those mutations with an abstract external-recency anchor. No owner yet retains the complete local source-and-salt catalog before root publication or atomically persists joined masters and provenance before raw-source erasure. The owners are not connected to the Rust mailbox, receipt, endorsement, and join types, a production anchor, or the participant worker and authorize no protocol transition. The remaining operations require Rust/WebAssembly-backed integration. TypeScript must not replace their cryptography or mint acceptance from transport or persistence status. No cryptographic suite is activated.

Current implementation status belongs to the repository [README](../../README.md), and current security limitations belong to [SECURITY.md](../../SECURITY.md). Package documentation intentionally does not repeat proof geometry, benchmark snapshots, theorem ledgers, or historical backend decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
