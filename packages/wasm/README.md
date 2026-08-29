# WASM package

`@sealed-lattice/wasm` is the internal producer and loader for the sealed-lattice Rust/WebAssembly kernel. It provides typed wrappers and the runtime-specific bridge used by workspace packages and the published SDK.

## Responsibilities

- Build the canonical kernel from Rust source and optimize its generated WebAssembly artifact.
- Load fresh or cached kernel instances and expose the canonical foundation command boundary.
- Preserve foundation byte, hash, refusal, and verification behavior across Node.js and browser consumers.
- Copy the exact producer bytes into the public SDK build and verify their integrity.

## Runtime boundaries

The canonical participant artifact must remain scalar-capable. SIMD is optional. It may become a runtime optimization only behind feature detection and after proving that it preserves bytes, transcripts, verification, and refusal results.

The browser bridge transfers owned binary buffers and reacquires WebAssembly memory views after any operation that can grow memory.

The public SDK exposes only implemented foundation operations. Source and package tests define the exact command inventory.

Package tests establish only their named byte, refusal, and runtime properties. See the repository [README](../../README.md) for implementation status and [SECURITY.md](../../SECURITY.md) for security limitations.

## Development

Do not edit generated WebAssembly output directly. The package-owned build uses a dedicated Cargo target and per-invocation optimizer staging, then atomically replaces the generated artifact. Run:

```bash
pnpm --filter @sealed-lattice/wasm run build:wasm
```

Use the workspace build when package declarations and copied SDK bytes must be regenerated together. After that build, the reproducibility gate repeats only WebAssembly generation and the SDK copy, then requires every package byte to match:

```bash
pnpm run build:verify-reproducible
```
