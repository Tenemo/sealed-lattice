---
title: Development workflow
description: The commands and verification gates that define the sealed-lattice engineering shell.
sidebar:
    order: 3
---

The workspace is only in a good state when the checks, docs, smoke tests, and
Rust/WASM proof path all pass together.

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
pnpm run test
pnpm run verify:docs
pnpm run docs:build:site
pnpm run smoke:pack
pnpm run smoke:pack:npm
pnpm run build
```

## What each command proves

- `pnpm run check`: package shell typechecks, repo lint, package-boundary checks, vector manifest verification, and dead-code analysis
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test`: Node tests, browser tests, and the internal WASM placeholder loader path
- `pnpm run verify:docs`: generated API pages and docs link structure stay consistent
- `pnpm run smoke:pack` and `pnpm run smoke:pack:npm`: the published package tarball installs cleanly and still exposes an empty runtime facade
- `pnpm run build`: every package shell builds and the WASM placeholder artifact is copied into the internal loader package

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace
root is private and is never published.
