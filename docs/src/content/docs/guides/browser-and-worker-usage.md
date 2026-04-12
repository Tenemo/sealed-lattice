---
title: Browser and worker usage
description: Running the current sealed-lattice package safely in browsers and Web Workers.
sidebar:
  order: 2
---

`sealed-lattice` currently ships one real cryptographic helper: `sha256Hex`. The runtime requirement is intentionally small, which makes the browser and worker story straightforward.

## Browser main thread

Use the root package and rely on the platform Web Crypto implementation.

```typescript
import { sha256Hex } from 'sealed-lattice';

const digest = await sha256Hex('sealed-lattice');

console.log(digest);
```

What the runtime must provide:

- `globalThis.crypto.subtle.digest`
- `TextEncoder`
- ESM support

## Web Workers

The same helper works inside a dedicated worker as long as the worker runtime exposes the same Web Crypto surface.

```typescript
import { sha256Hex } from 'sealed-lattice';

self.addEventListener('message', async (event) => {
    const digest = await sha256Hex(event.data);
    self.postMessage(digest);
});
```

## Input rules

- strings are encoded as UTF-8 before hashing
- `Uint8Array` inputs are copied before hashing
- output is always lowercase hexadecimal

## Failure mode

If the runtime does not expose `globalThis.crypto.subtle.digest`, the helper throws `UnsupportedRuntimeError` instead of silently falling back to a weaker or inconsistent path.

Use this package only in runtimes where the native Web Crypto surface is part of your supported deployment contract.
