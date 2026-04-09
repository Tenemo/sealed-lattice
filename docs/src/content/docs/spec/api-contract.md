---
title: API contract
description: Exact public contract for the current sealed-lattice milestone.
---

Phase one commits to the following contract:

## Root package

- `sha256Hex(input: string | Uint8Array): Promise<string>`
- `UnsupportedRuntimeError`

## Core package

- `sha256Hex(input: string | Uint8Array): Promise<string>`
- `UnsupportedRuntimeError`

## Placeholder subpaths

- `proofs`
- `protocol`
- `runtime`
- `serialize`
- `threshold`
- `transport`

These placeholder subpaths are public only in the package-shape sense. They currently export no callable APIs and should not be treated as feature-complete modules.
