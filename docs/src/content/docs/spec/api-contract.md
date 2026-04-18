---
title: API contract
description: The hard boundary between what sealed-lattice commits to today and what remains outside the current milestone.
sidebar:
    order: 2
---

The package draws a hard boundary between the current public surface and the
future post-quantum design space.

## Package responsibilities

- Expose `sha256Hex(input: string | Uint8Array): Promise<string>`
- Expose `UnsupportedRuntimeError`
- Use native Web Crypto digest support instead of hidden fallback implementations
- Keep the current public surface documented, tested, and packaging-verified

## Caller responsibilities

- Choose runtimes that expose the required Web Crypto surface
- Handle wider transport, protocol, threshold, and proof concerns outside the current package
- Avoid depending on future public subpath names before they are explicitly published
- Treat the current milestone as a stable shell around a deliberately narrow feature set
