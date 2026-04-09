---
title: Runtime and compatibility
description: Runtime expectations for the current sealed-lattice scaffold.
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
- The browser test suite currently verifies digest parity in Chromium through Vitest browser mode and Playwright.

## Current compatibility boundary

- The shipped helper uses SHA-256 only.
- Inputs are either UTF-8 strings or raw `Uint8Array` values.
- The output is always a lowercase hexadecimal string.
- If the runtime is missing the required Web Crypto surface, `UnsupportedRuntimeError` is thrown.
