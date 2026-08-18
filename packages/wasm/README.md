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
selected-size public-key proof. The same guarded owner independently derives
its verifier statement and checks all 122 transported public columns, including
rebuilding the four statement-owned setup-polynomial roots. That source
correspondence now gates a source-bound accepted-setup capability. Release
kernel exports prepare from the accepted package, begin or restore,
bounded-poll, copy a fixed 412-byte accepted-verifier cursor, cancel, finish the
positive capability, and explicitly discard every other linear state. This is
distinct from the 408-byte algebra-only cursor. Restoration revalidates the
exact transported bytes and replays deterministically from genesis. An
internal common-proof worker driver yields between bounded polls,
publishes and restores that cursor through an authenticated-custody contract,
prevents publication during replay, preserves typed refusals, and returns a
positive `VerificationResult` only after source correspondence and one-shot
accepted-setup terminal commit. The five CFW polynomial transforms and the
seven WHIR folds remaining after the CFW handoff are incremental. The accepted
verifier exposes 4,541 fixed cursor ordinals: 290 at 65,536-work-unit intervals
across 19,005,440 of the selected CFW phase's 19,038,593 work units, 32 WHIR
interval boundaries plus terminal WHIR, and 4,218 across all 122 public columns
and all 1,024 cosets of each of four statement roots. Contract geometry derives
2,129,904 remaining WHIR fold work units, and the current transported candidate
completes them in 33 outer polls of at most 65,536 units. The bounded fold reuses
and truncates
the original source allocation in both production covector consumers instead
of retaining a clone and separate output. The verifier-derived public-covector
replay still drains the shared primitive synchronously. The accepted cursor has
32 intermediate WHIR ordinals, while code-switch and base-case transitions are
not separately metered. Guarded native execution destroys and restores the
actual proof at the first WHIR boundary, but there is no equivalent scalar
release-WASM or live browser memory evidence. The protocol package now owns
distinct authenticated-store adapters for the 408-byte
algebra-only cursor and the accepted cursor. The accepted adapter reads its
412-byte, 4,541-boundary geometry from kernel exports and uses a separate
canonical state-stream domain. Worker options make fresh and resumed custody
mutually exclusive, and the runtime rejects hostile dual-custody input before
kernel preparation while releasing every distinct identity. The protocol
custody-worker host installs the accepted adapter, copies its four checkpoint
source digests from the prepared Rust authority, and evicts terminal state. Its
current host test uses same-realm synthetic cursor bytes. Dedicated-worker
destruction and recreation, bounded transport, and scalar release-WASM selected
actual-byte cold restoration remain open. Compact generation is
not a worker-facing runtime capability, and no complete generation and
verification ABI pair exists.

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
