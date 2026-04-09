---
title: Library invariants
description: Stable invariants for the phase-one sealed-lattice scaffold.
---

The current milestone keeps the following invariants stable:

- The package is ESM-only.
- The root export remains intentionally tiny and safe.
- `sha256Hex` accepts `string | Uint8Array` and returns lowercase hexadecimal output.
- Missing Web Crypto hashing support throws `UnsupportedRuntimeError`.
- The published subpath set is fixed to `.`, `./core`, `./proofs`, `./protocol`, `./runtime`, `./serialize`, `./threshold`, and `./transport`.
- Placeholder subpaths stay importable but empty until later milestones replace them with real APIs.
- Docs, Typedoc, tests, coverage, CI, and tarball policy must continue to pass before the scaffold advances.
