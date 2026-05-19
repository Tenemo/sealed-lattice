---
title: Development workflow
description: The commands and verification gates that define the sealed-lattice engineering shell.
sidebar:
    order: 3
---

The workspace is only in a good state when the checks, docs, smoke tests, and Rust/WASM transcript core path all pass together.

## Prerequisites

- Node `24.14.1` or newer
- `pnpm` `10.33.0`
- Rust with the `wasm32-unknown-unknown` target installed
- Playwright browser runtimes for the browser matrix

## Main commands

```bash
pnpm install
pnpm run check
pnpm run vectors
pnpm exec playwright install chromium firefox webkit
pnpm run test:node:fast
pnpm run test:node:heavy:kernel
pnpm run test
pnpm run test:proof-benchmarks
pnpm run verify:docs
pnpm run docs:build:site
pnpm run smoke:pack
pnpm run smoke:pack:npm
pnpm run build
```

## What each command proves

- `pnpm run check`: package typechecks, repo lint, Rust checks, package-boundary checks, vector manifest verification, and dead-code analysis
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test:node:fast`: pre-commit-friendly Node tests, excluding the slow kernel-heavy WASM integration suite
- `pnpm run test:node:heavy:kernel`: transcript-core WASM loader, parity, fixture, proof-generation, and proof-record integration tests
- `pnpm run test`: fast Node tests, kernel-heavy Node tests, and browser tests
- `pnpm run test:proof-benchmarks`: full proof benchmark lane for Node, desktop Chromium, and calibrated mobile Chromium proof generation and verification
- `pnpm run verify:docs`: generated API pages and docs link structure stay consistent
- `pnpm run smoke:pack` and `pnpm run smoke:pack:npm`: the published package tarball installs cleanly and exposes the transcript core fixture verifier plus election foundation helpers
- `pnpm run build`: every package builds, the private crypto/runtime bridge is vendored into the SDK, the WASM transcript core artifact is copied into the internal loader package, and the published SDK loader is pinned to the packaged kernel digest

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace root is private and is never published.
