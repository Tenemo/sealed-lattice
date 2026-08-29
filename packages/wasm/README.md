# WASM package

`@sealed-lattice/wasm` is the internal producer and loader for the sealed-lattice Rust/WebAssembly kernel. It provides typed wrappers and the runtime-specific bridge used by workspace packages and the published SDK.

## Responsibilities

- Build the canonical kernel from Rust source and optimize its generated WebAssembly artifact.
- Load fresh or cached kernel instances and expose the canonical foundation command boundary.
- Preserve foundation byte, hash, refusal, and verification behavior across Node.js and browser consumers.
- Copy the exact producer bytes into the public SDK build and verify their integrity.

## Runtime boundaries

The canonical participant artifact must remain scalar-capable. SIMD is optional. It may become a runtime optimization only behind feature detection and after proving that it preserves bytes, transcripts, verification, and refusal results.

The browser bridge transfers ordinary owned binary buffers. It must reacquire WebAssembly memory views after any operation that can grow memory. Long-running work must save authenticated checkpoints at deterministic safe boundaries so an unexpected interruption loses only bounded work. It cannot assume that a hidden page or worker will keep running or receive a termination callback.

The public SDK exposes only implemented foundation operations. Internal measurement commands cannot authorize protocol state changes. Source and package tests own the exact command inventory.

Long-running production kernel work must keep authenticated state in the browser, validate every restored cursor against its source, poll at bounded intervals, support cancellation, and dispose of consumed one-use state. Measurement-only cursors do not prove that production checkpointing, rollback protection, browser lifecycle handling, or resumption is safe, and they are not supported-phone evidence.

Native and desktop workbench results are development evidence only; they do not establish participant ceremony or supported-phone behavior. The repository [README](../../README.md) owns implementation status, and [SECURITY.md](../../SECURITY.md) owns security limitations.

## Development

Do not edit generated WebAssembly output directly. Build it from the Rust kernel through the package-owned command:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be regenerated together.
