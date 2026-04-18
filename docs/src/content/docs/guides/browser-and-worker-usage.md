---
title: Browser and worker usage
description: Browser-native usage of the current sealed-lattice root package on the main thread and inside Web Workers.
sidebar:
    order: 3
---

The current milestone is browser-native. Use the root package directly inside
the browser or inside Web Workers for the supported hashing flow.

## Browser flow

```typescript
import { sha256Hex } from "sealed-lattice";

const textDigest = await sha256Hex("sealed-lattice");
const byteDigest = await sha256Hex(new Uint8Array([0x00, 0xff, 0x10, 0x20]));

console.log(textDigest);
console.log(byteDigest);
```

This covers the browser-native pieces most callers need first:

- text hashing through UTF-8 conversion
- raw byte hashing
- one stable root import surface

## Keeping hashing inside a worker

The package can be imported inside a worker directly:

```typescript
import { sha256Hex } from "sealed-lattice";

self.onmessage = async (event) => {
    const digest = await sha256Hex(event.data);

    self.postMessage(digest);
};
```

Keep the worker responsible for any surrounding message protocol, retries, and
storage. The package only owns hashing and the typed runtime error boundary.

For local browser target validation, run `pnpm run test:browser`.

## What stays outside the package

The package does not manage:

- worker lifecycle
- retries and reconnects
- persistence
- bulletin-board posting
- future PQ orchestration that is not public yet

## Failure mode

If the runtime does not expose `globalThis.crypto.subtle.digest`, the helper
throws `UnsupportedRuntimeError` instead of silently falling back to a weaker or
inconsistent path.

For exact runtime constraints, read [Runtime and compatibility](../runtime-and-compatibility/).
