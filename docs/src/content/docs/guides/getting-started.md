---
title: Get started
description: The shortest safe path into the current sealed-lattice package surface.
sidebar:
  order: 1
---

Use the safe root package. The current public surface is intentionally small and centered on one real helper: `sha256Hex`.

## Installation

```bash
pnpm add sealed-lattice
```

## Safe quickstart

```typescript
import { sha256Hex } from 'sealed-lattice';

const digest = await sha256Hex('sealed-lattice');

console.log(digest);
```

## What the current surface includes

- a real SHA-256 helper on the root package
- a typed `UnsupportedRuntimeError` when Web Crypto hashing is unavailable
- repo, CI, docs, coverage, testing, and publish DX parity with the classical baseline
- a public API that stays narrow while the future lattice-native module layout remains open

## What the current surface does not include

- lattice encryption
- threshold key generation or decryption
- transport payloads
- proofs
- protocol types
- WASM kernels
- frozen public subpaths for future PQ capabilities

Use the current milestone to establish the project shell. Do not assume that future capabilities will appear under any specific subpath until those contracts are stable enough to publish.
