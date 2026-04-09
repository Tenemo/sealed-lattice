---
title: Get started
description: The shortest safe path into the phase-one sealed-lattice scaffold.
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

## What phase one includes

- a real SHA-256 helper on the root package and `./core`
- a typed `UnsupportedRuntimeError` when Web Crypto hashing is unavailable
- placeholder subpaths that already resolve and document correctly
- repo, CI, docs, coverage, testing, and publish DX parity with the classical baseline

## What phase one does not include

- lattice encryption
- threshold key generation or decryption
- transport payloads
- proofs
- protocol types
- WASM kernels

Use the current milestone to establish the project shell. Do not treat the placeholder subpaths as cryptographic implementations.
