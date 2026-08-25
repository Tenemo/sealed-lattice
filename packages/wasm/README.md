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

The current scalar artifact exports allocation, deallocation, and one foundation-command entry point. It does not expose preparation, opening, garbling, state, finality, release, or long-operation cursor APIs. Adding those operations requires matched Rust generation and verification plus typed positive-verification results; transport status cannot mint a capability.

Future long-running kernel work must use canonical source-bound cursors, authenticated browser custody, restore validation, bounded polling, cancellation, and linear-state disposal. None of that lifecycle is implemented by the current package.

Test-only workbenches and native or desktop results are not an accepted ceremony or supported-phone evidence. No suite is activated, and rejected protocol bridges have been removed. The repository [README](../../README.md) owns current implementation status, and [SECURITY.md](../../SECURITY.md) owns security limitations.

## Development

Do not edit generated WebAssembly output directly. Build it from the Rust kernel through the package-owned command:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be regenerated together.
