---
title: API contract
description: Exact public contract for the current sealed-lattice milestone.
---

The current package commits to the following contract:

## Root package

- `sha256Hex(input: string | Uint8Array): Promise<string>`
- `UnsupportedRuntimeError`

No additional public subpaths are committed yet. Future capability areas such as serialization, transport, threshold coordination, proofs, protocol types, or runtime helpers may eventually become public, but their module boundaries are intentionally not frozen at this stage.
