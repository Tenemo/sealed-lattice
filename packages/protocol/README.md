# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input.
- Translate validated poll input into the canonical foundation-manifest ingress shape.
- Provide internal authenticated storage, local-record protection, checkpoint, and strict IndexedDB foundations without minting protocol capabilities.
- Expose only those implemented helpers through the package entry point.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package does not currently orchestrate collective preparation, selected ballot sets, activation, certified evaluation, finality, release, or complete browser custody. Its checkpoint and storage modules are internal persistence mechanisms only. Integrity-pinned scalar Rust/WebAssembly adapters now back pre-root catalog production, sender-mailbox carrier production, receipt-terminal endorsement production, and joined-master retention. The endorsement adapter opens only from a one-shot authorization over the completed authenticated local receipt, positively verifies the exact public receipt inventory and local carrier match, and lets the durable owner lock one prepared alternative before signing. Recipient-receipt production, authenticated burn, a production external-recency anchor, the participant worker, and physical reclamation remain open. These owners return inert custody or publication bytes only and authorize no preparation continuation. TypeScript must not replace their cryptography or mint acceptance from transport or persistence status. No cryptographic suite is activated.

Current implementation status belongs to the repository [README](../../README.md), and current security limitations belong to [SECURITY.md](../../SECURITY.md). Package documentation intentionally does not repeat proof geometry, benchmark snapshots, theorem ledgers, or historical backend decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
