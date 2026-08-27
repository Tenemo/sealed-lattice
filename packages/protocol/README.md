# Protocol package

`@sealed-lattice/protocol` is an internal workspace package for deterministic protocol orchestration around the Rust/WebAssembly cryptographic kernel. It is not a separately supported public voting API.

## Responsibilities

- Validate pre-protocol poll input.
- Translate validated poll input into the canonical foundation-manifest ingress shape.
- Provide internal authenticated storage, local-record protection, checkpoint, and strict IndexedDB foundations without minting protocol capabilities.
- Expose only those implemented helpers through the package entry point.

## Boundaries

General structural code covers `3 <= n <= 20` participants and `2 <= optionCount <= 20` options. Only the exact `n = 10`, `optionCount = 10` profile is the current cryptographic and runtime evidence target; admitting another size does not qualify it.

The package does not currently orchestrate collective preparation, selected ballot sets, activation, certified evaluation, finality, release, or complete browser custody. Its checkpoint and storage modules are internal persistence mechanisms only. Integrity-pinned scalar Rust/WebAssembly adapters now back pre-root catalog production, sender-mailbox carrier production, recipient-receipt production, receipt-terminal endorsement production, joined-master retention, and one-shot typed joined-record restoration validation. The recipient adapter verifies the complete ordered signed carrier inventory, returns its verified context, and requires that exact public selection to be durably retained before invoking the browser-local mailbox key. A genuine Rust-reported authenticated plaintext inconsistency or a conflicting durable receipt or terminal-endorsement intent durably burns that recipient action; malformed or publicly inconsistent transport does not. Receipt and endorsement custody share an opaque action guard bound to the exact authenticated context and storage coordinator, suppress stale publication after a burn, and accept outputs only after positive kernel verification. A successful joined-master transition atomically converts the selection to a compact terminal marker while removing the raw source and receipt records, which blocks same-action replay. Later protocol burn stages, a source-consuming cursor transition, a complete action-wide index and head, a production external-recency anchor, the participant worker, and physical reclamation remain open. These owners return inert custody, burn or joined status, publication bytes, or restoration validation only and authorize no preparation continuation. TypeScript must not replace their cryptography or mint acceptance from transport or persistence status. No cryptographic suite is activated.

Current implementation status belongs to the repository [README](../../README.md), and current security limitations belong to [SECURITY.md](../../SECURITY.md). Package documentation intentionally does not repeat proof geometry, benchmark snapshots, theorem ledgers, or historical backend decisions.

## Development

Build this package through the workspace so its package-to-package imports use the current generated WebAssembly artifact:

```bash
pnpm --filter @sealed-lattice/protocol run build
```

Runtime consumers must import from the package entry point rather than another workspace package's internal source.
