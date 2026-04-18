---
title: Get started
description: The shortest safe path into the root package and the current sealed-lattice milestone.
sidebar:
    order: 1
---

Start with the root package. The current public surface is intentionally small
and centered on one real helper: `sha256Hex`.

## Start with these rules

- The only committed public entry point is `sealed-lattice`.
- The current root package exposes `sha256Hex` and `UnsupportedRuntimeError`.
- `sha256Hex` accepts `string | Uint8Array`.
- The output is always lowercase hexadecimal.
- If native Web Crypto digest support is missing, the package throws `UnsupportedRuntimeError`.

## Safe quickstart

```typescript
import { sha256Hex } from "sealed-lattice";

const digest = await sha256Hex("sealed-lattice");

console.log(digest);
```

## What this milestone includes

- a real SHA-256 helper on the root package
- a typed `UnsupportedRuntimeError` when Web Crypto hashing is unavailable
- hardened docs, testing, browser coverage, tarball checks, and publish workflow around that narrow API
- an intentionally narrow public surface while the future lattice-native architecture remains open

## What it still does not freeze

- lattice encryption
- threshold key generation or decryption
- transport payloads
- proofs
- protocol types
- WASM kernels
- frozen public subpaths for future PQ capabilities

## Related pages

- For runtime prerequisites, read [Runtime and compatibility](../runtime-and-compatibility/).
- For browser and worker calling patterns, read [Browser and worker usage](../browser-and-worker-usage/).
- For the current security boundary, read [Security and non-goals](../security-and-non-goals/).
- The [API docs](../../api/) list the exact public contract.
