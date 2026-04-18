---
title: Runtime and compatibility
description: Browser, Node, ESM, and Web Crypto expectations for the current sealed-lattice milestone.
sidebar:
    order: 2
---

The current workflow is intentionally small and assumes:

- ESM imports
- native Web Crypto digest support through `crypto.subtle.digest`
- `TextEncoder` for UTF-8 conversion

For a concrete browser integration example, read
[Browser and worker usage](../browser-and-worker-usage/).

## Supported environments

- Modern browsers must expose `globalThis.crypto.subtle.digest`
- Browsers must expose `TextEncoder`
- Node must satisfy the package `engines.node` requirement and expose `globalThis.crypto`
- The package does not expose CommonJS entry points

## Browser requirements

The browser path is intentionally simple:

- use modern browsers with native Web Crypto digest support
- require `TextEncoder`
- validate your target environments with `pnpm run test:browser`

CI verifies digest parity in Chromium, Firefox, and WebKit on desktop, plus
Chromium and WebKit in mobile emulation on macOS through the browser Vitest
projects.

## Application-owned runtime concerns

Keep these concerns outside the package:

- worker orchestration
- retries and reconnects
- storage and persistence
- transport and bulletin-board delivery
- any future PQ flow coordination that is not public yet

The package can be imported inside workers, but it does not create or manage
workers itself.

## Current helper boundary

- The shipped helper uses SHA-256 only.
- Inputs are UTF-8 strings or raw `Uint8Array` values.
- Output is always a lowercase hexadecimal string.
- Missing native digest support raises `UnsupportedRuntimeError`.

The [API reference](../../api/) lists the exact function contract.
