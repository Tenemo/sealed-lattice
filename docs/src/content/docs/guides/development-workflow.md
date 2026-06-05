---
title: Development workflow
description: The commands and verification gates that define the sealed-lattice engineering shell.
sidebar:
    order: 3
---

The workspace is only in a good state when the checks, docs, smoke tests, Rust/WASM transcript paths, and selected direct-path verification lanes pass together.

## Prerequisites

- Node `24.14.1` or newer
- `pnpm` `10.33.0`
- Rust with the `wasm32-unknown-unknown` target installed
- Playwright browser runtimes for browser tests

## Main commands

```bash
pnpm install
pnpm run build
pnpm run api-surface:generate
pnpm run check
pnpm run vectors
pnpm exec playwright install chromium firefox webkit
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test
pnpm run test:proof-benchmark
pnpm run test:proof-benchmark:node
pnpm run test:proof-benchmark:browser:desktop
pnpm run verify:docs
pnpm run smoke:pack:npm
```

## What each command proves

- `pnpm run build`: every package builds, the private crypto/runtime facade is vendored into the SDK, the WASM transcript-core artifact is copied into the internal loader package, and the published SDK loader is pinned to the packaged kernel hash
- `pnpm run api-surface:generate`: runs the full build and regenerates the compact public API surface summary for manual PR review
- `pnpm run check`: builds the workspace once, runs TypeScript, then runs lint, docs verification, npm package smoke verification, public package policy, package-boundary checks, vector manifest verification, dead-code analysis, and the fast Node tests in parallel against the built output before running Rust formatting, Rust clippy, and Rust tests in an isolated lane
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test:node:fast`: pre-commit-friendly Node tests
- `pnpm run test:node:protocol`: slower protocol and relation tests that remain useful for the selected direct path and shared substrate
- `pnpm run test:node:kernel`: transcript-core WASM loader, parity, fixture, proof, and kernel integration tests
- `pnpm run test`: runs the Node lanes and browser lanes through the package scripts
- `pnpm run test:proof-benchmark`: direct proof benchmark evidence where applicable
- `pnpm run test:proof-benchmark:node`: Node proof benchmark lane
- `pnpm run test:proof-benchmark:browser:desktop`: desktop Chromium proof benchmark lane
- `pnpm run coverage:badge`: runs the fast Node coverage lane and writes the Shields-compatible badge and summary JSON that GitHub Pages publishes for the README badge
- `pnpm run verify:docs`: generated API pages, docs link structure, and the production docs site build stay consistent
- `pnpm run docs:build`: builds the docs site without the surrounding verification checks when that narrower target is needed
- `pnpm run smoke:pack:npm`: the published package tarball installs cleanly through npm and exposes the current safe public boundary

## Local hooks

The pre-commit hook runs `pnpm run check`.

Protocol, kernel, browser, and proof benchmark lanes remain explicit commands so they can use targeted reruns instead of slowing every local commit. The coverage badge is generated locally in the Pages workflow, not by Codecov.

## Local run logs

Heavy local runners write timestamped logs under gitignored `logs/` directories.

Each run gets `logs/YYYY-MM-DD/YYYY-MM-DDTHH-mm-ss-SSSZ-script-name/` with `metadata.json`, `summary.json`, `combined.log`, and per-command logs.

CI disables local log emission with `--no-run-log`; use the same trailing argument locally when a one-off run should skip logs, for example `pnpm run test:node:kernel -- --no-run-log`.

## Heavy gate policy

Default and release gates should stay lean and direct-path-only.

Use explicit heavy lanes only when the change touches the selected direct path area:

```text
direct proof benchmark;
direct Node/WASM proof-copy measurement;
direct browser proof-copy measurement;
fully encrypted evaluator replay benchmark;
target-bound decryption benchmark;
manual mobile proof and replay lane.
```

Default, release, docs, package-smoke, browser, and mobile gates should cover only the selected direct path and shared substrate.

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace root is private and is never published.
