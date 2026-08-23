# WASM package

`@sealed-lattice/wasm` is the internal producer and loader for the sealed-lattice Rust/WebAssembly kernel. It provides typed wrappers and the runtime-specific bridge used by workspace packages and the published SDK.

## Responsibilities

- Build the canonical kernel from Rust source and optimize its generated WebAssembly artifact.
- Load fresh or cached kernel instances and expose typed boundary wrappers.
- Preserve canonical byte, hash, refusal, and verification behavior across Node.js and browser consumers.
- Copy the exact producer bytes into the public SDK build and verify their integrity.

## Runtime boundaries

The canonical participant artifact must remain scalar-capable. Optional SIMD measurement cannot replace the scalar baseline without feature detection and byte-for-byte output, transcript, verification, and refusal parity.

The browser bridge transfers ordinary owned binary buffers. It must reacquire WebAssembly memory views after any operation that can grow memory. Long-running protocol orchestration must publish proactive authenticated checkpoints and cannot assume that a hidden page or worker will keep running or receive a termination callback.

Transport validation is deliberately narrower than proof verification. It may check canonical structure and openings but cannot verify all equations or mint a positive capability. Full acceptance belongs to the Rust kernel, and only a completed positive result may cross the typed bridge. Generation and verification must remain a matched release-WebAssembly pair.

Long-running kernel cursors contain canonical, source-bound progress rather than opaque runtime state. The protocol package owns authenticated custody and worker orchestration; this package owns cursor encoding, restore validation, bounded polling, cancellation, and linear-state disposal.

Test-only proof workbenches and native or desktop results are not an accepted ceremony or supported-phone evidence. The repository [README](../../README.md) owns current implementation status, and [SECURITY.md](../../SECURITY.md) owns security limitations.

## Development

Do not edit generated WebAssembly output directly. Build it from the Rust kernel through the package-owned command:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be regenerated together.
