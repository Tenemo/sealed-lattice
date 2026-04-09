---
title: Library invariants
description: Stable invariants for the current sealed-lattice package surface.
---

The current milestone keeps the following invariants stable:

- The package is ESM-only.
- The root export remains intentionally tiny and safe.
- `sha256Hex` accepts `string | Uint8Array` and returns lowercase hexadecimal output.
- Missing Web Crypto hashing support throws `UnsupportedRuntimeError`.
- The only committed public entry point is `sealed-lattice`.
- Future capability boundaries remain intentionally unfrozen until the lattice-native flow is stable enough to publish them safely.
- Docs, Typedoc, tests, coverage, CI, and tarball policy must continue to pass before the package surface expands.
