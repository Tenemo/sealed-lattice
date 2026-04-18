---
title: Library invariants
description: Stable rules for the current package surface and its verification process.
sidebar:
    order: 1
---

This page records the invariants of the current `sealed-lattice` milestone.

## Package surface

- The package is ESM-only.
- The only committed public entry point is `sealed-lattice`.
- The root export remains intentionally tiny and safe.
- No public subpaths are promised yet.

## Runtime behavior

- `sha256Hex` accepts `string | Uint8Array`.
- Strings are encoded as UTF-8 before hashing.
- Output is always lowercase hexadecimal.
- Missing Web Crypto hashing support throws `UnsupportedRuntimeError`.

## Process guardrails

- Docs, Typedoc, tests, coverage, CI, and tarball policy must continue to pass before the package surface expands.
- Deterministic vectors remain the source of truth for shipped digest behavior.
- Future capability boundaries remain intentionally unfrozen until the lattice-native flow is stable enough to publish safely.
