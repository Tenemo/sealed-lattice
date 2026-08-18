# WASM package

`@sealed-lattice/wasm` is the internal producer and loader for the
sealed-lattice Rust/WebAssembly kernel. It provides typed wrappers and the
runtime-specific bridge used by workspace packages and the published SDK.

## Responsibilities

- Build the canonical kernel from Rust source and optimize its generated
  WebAssembly artifact.
- Load fresh or cached kernel instances and expose typed boundary wrappers.
- Preserve canonical byte, hash, refusal, and verification behavior across
  Node.js and browser consumers.
- Copy the exact producer bytes into the public SDK build and verify their
  integrity.

## Runtime boundaries

The canonical participant artifact must remain scalar-capable. Optional SIMD
measurement cannot replace the scalar baseline without feature detection and
byte-for-byte output, transcript, verification, and refusal parity.

The browser bridge transfers ordinary owned binary buffers. It must reacquire
WebAssembly memory views after any operation that can grow memory. Long-running
protocol orchestration must publish proactive authenticated checkpoints and
cannot assume that a hidden page or worker will keep running or receive a
termination callback.

The release package exposes foundation and integration wrappers plus a compact
transport validator. That boundary strictly decodes canonical proof and
public-input bytes, derives verifier messages and response queries, and
validates salted Merkle openings; it does not verify the CFW or WHIR equations
or mint a proof capability.

The scalar CFW and bounded external-memory machinery, authenticated assignment
loader, structured row source, transpose path, incremental proof assembly,
response-tree custody, and response checkpoints compile into the release
kernel. The internal pollable verifier independently checks the compact CFW and
WHIR algebra after transport, and guarded native evidence accepts one complete
selected-size public-key proof. Raw kernel exports can begin, bounded-poll, and
cancel that verifier state. They can also copy a fixed 400-byte source-bound
safe cursor and restore only by revalidating the exact transported bytes and
replaying deterministically from genesis. An internal common-proof worker
driver yields between bounded polls, publishes and restores that cursor through
an authenticated-custody contract, prevents publication during replay,
preserves typed refusals, returns a positive `VerificationResult` only at
algebraic completion, and cancels unfinished operations. The five CFW
polynomial transforms are incremental. The kernel exposes 290 fixed cursor
ordinals at 65,536-work-unit intervals across 19,005,440 of the selected CFW
phase's 19,038,593 work units; the remaining 33,153 CFW units and terminal WHIR
work do not yet form another durable boundary. The protocol package supplies a
concrete authenticated-store adapter for those cursors, including
copy-on-write predecessor retention and one-shot restoration after
checkpoint-store reconstruction, but the production browser-worker host does
not install it yet. The driver does not mint proof authority. Compact
generation and proof capabilities are not worker-facing runtime capabilities.

Test-only proof workbenches and native or desktop results are not an accepted
ceremony or supported-phone evidence. The repository [README](../../README.md)
owns current implementation status, and [SECURITY.md](../../SECURITY.md) owns
security limitations.

## Development

Do not edit generated WebAssembly output directly. Build it from the Rust
kernel through the package-owned command:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be
regenerated together.
