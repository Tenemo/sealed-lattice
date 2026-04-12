---
title: Runtime and compatibility
description: Runtime expectations for the current sealed-lattice package surface.
sidebar:
  order: 2
---

Phase one is ESM-only and requires Web Crypto hashing.

## Node

- Use Node `24.14.1` or newer.
- `globalThis.crypto.subtle.digest` must be available.
- The package does not expose CommonJS entry points.

## Browsers

- `globalThis.crypto.subtle.digest` must be available.
- `TextEncoder` must be available for UTF-8 conversion.
- CI verifies digest parity in Chromium, Firefox, and WebKit on desktop, plus Chromium and WebKit mobile emulation through Vitest browser mode and Playwright.

See [Browser and worker usage](../browser-and-worker-usage/) for the supported in-browser calling patterns.

## Current compatibility boundary

- The shipped helper uses SHA-256 only.
- Inputs are either UTF-8 strings or raw `Uint8Array` values.
- The output is always a lowercase hexadecimal string.
- If the runtime is missing the required Web Crypto surface, `UnsupportedRuntimeError` is thrown.
