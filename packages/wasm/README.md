# WASM package

`@sealed-lattice/wasm` is the internal producer and loader for the sealed-lattice Rust/WebAssembly kernel. It provides typed wrappers and the runtime-specific bridge used by workspace packages and the published SDK.

## Responsibilities

- Build the canonical kernel from Rust source and optimize its generated WebAssembly artifact.
- Load fresh or cached kernel instances and expose the canonical foundation command boundary.
- Preserve foundation byte, hash, refusal, and verification behavior across Node.js and browser consumers.
- Copy the exact producer bytes into the public SDK build and verify their integrity.

## Runtime boundaries

The canonical participant artifact must remain scalar-capable. Optional SIMD measurement cannot replace the scalar baseline without feature detection and byte-for-byte output, transcript, verification, and refusal parity.

The browser bridge transfers ordinary owned binary buffers. It must reacquire WebAssembly memory views after any operation that can grow memory. Long-running protocol orchestration must publish proactive authenticated checkpoints and cannot assume that a hidden page or worker will keep running or receive a termination callback.

The current internal scalar artifact exports allocation and secret-aware deallocation, the foundation-command entry point, and private unactivated seed-candidate commands for catalog production, mailbox sending, recipient receipt, terminal endorsement, joined custody, and joined-record validation. The public SDK still exposes foundation operations only. These private commands return bounded inert bytes or typed refusals and cannot mint preparation, activation, evaluation, finality, release, or result capabilities. Feature-gated field and zero-sharing measurement exports are manual development surfaces and are absent from the ordinary build.

Production long-running kernel work must use canonical source-bound cursors, authenticated browser custody, restore validation, bounded polling, cancellation, and linear-state disposal. A feature-gated zero-sharing measurement cursor provides native/scalar-Wasm byte parity, bounded steps, authenticated inner checkpoints, acknowledgement, and cold restoration for development only. It is not connected to durable joined custody and omits encrypted production checkpoints, rollback reconciliation, the all-roster codeword verifier, browser lifecycle, and continuation authority.

Test-only workbenches and native or desktop results are not an accepted ceremony or supported-phone evidence. No suite is activated, and rejected protocol bridges have been removed. The repository [README](../../README.md) owns current implementation status, and [SECURITY.md](../../SECURITY.md) owns security limitations.

## Development

Do not edit generated WebAssembly output directly. Build it from the Rust kernel through the package-owned command:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be regenerated together.
