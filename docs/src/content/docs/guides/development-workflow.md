---
title: Development workflow
description: The commands and verification gates that define the sealed-lattice engineering shell.
sidebar:
    order: 3
---

The workspace is only in a good state when the checks, docs, smoke tests, and Rust/WASM transcript plus ballot privacy verification paths all pass together.

## Prerequisites

- Node `24.14.1` or newer
- `pnpm` `10.33.0`
- Rust with the `wasm32-unknown-unknown` target installed
- Playwright browser runtimes for the browser matrix

## Main commands

```bash
pnpm install
pnpm run build
pnpm run api-surface:update
pnpm run api-surface:check
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
pnpm run test:encrypted-aggregate-bridge
pnpm run test:encrypted-aggregate-bridge:representative
pnpm run verify:docs
pnpm run smoke:pack:npm
```

## What each command proves

- `pnpm run build`: every package builds, the private crypto/runtime bridge is vendored into the SDK, the WASM transcript-core artifact is copied into the internal loader package, and the published SDK loader is pinned to the packaged kernel hash
- `pnpm run api-surface:update`: runs the full build and updates the compact public API snapshot
- `pnpm run api-surface:check`: runs the full build and verifies it against the compact public API snapshot
- `pnpm run check`: builds the workspace once, runs TypeScript, then runs lint, docs verification, npm package smoke verification, public API snapshot verification, public package policy, dependency-boundary checks, vector manifest verification, dead-code analysis, and the fast Node tests in parallel against the built output before running Rust formatting, Rust clippy, and Rust tests in an isolated lane; the first failing lane aborts the remaining work
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test:node:fast`: pre-commit-friendly Node tests, excluding slow protocol, kernel-heavy WASM, and proof-benchmark suites
- `pnpm run test:node:protocol`: slow protocol relation and proof-record generation input tests that remain part of the default Node gate without running under coverage instrumentation
- `pnpm run test:node:kernel`: transcript-core WASM loader, parity, fixture, proof-generation, proof-record integration, and aggregate-derivation transcript-core WASM integration tests
- `pnpm run test`: runs the fast, protocol, and kernel Node lanes, then the desktop and mobile browser lanes through the package scripts
- `pnpm run test:proof-benchmark`: Node and desktop Chromium proof benchmark lanes, built once and then run concurrently; the desktop Chromium lane mirrors the Node lane one-to-one
- `pnpm run test:proof-benchmark:node`: Node proof benchmark lane, suitable for a separate CI worker
- `pnpm run test:proof-benchmark:browser:desktop`: desktop Chromium proof benchmark lane, suitable for a separate CI worker
- `pnpm run coverage:badge`: runs the fast Node coverage lane and writes the Shields-compatible badge and summary JSON that GitHub Pages publishes for the README badge
- `pnpm run test:encrypted-aggregate-bridge`: builds once, runs the cheap all-row bridge shape/config guardrail, then runs the full encrypted aggregate bridge matrix with 8 workers
- `pnpm run test:encrypted-aggregate-bridge:representative`: builds once, then runs the selected representative bridge rows with 4 workers
- `pnpm run verify:docs`: generated API pages, docs link structure, and the production docs site build stay consistent
- `pnpm run docs:build`: builds the docs site without the surrounding verification checks when that narrower target is needed
- `pnpm run smoke:pack:npm`: the published package tarball installs cleanly through npm and exposes safe-by-default helpers for transcript-core fixture verification, election foundation checks, and verification-oriented ballot privacy APIs

## Local hooks

The pre-commit hook runs `pnpm run check`.
This builds the workspace once, then runs static verification, docs verification, npm package smoke verification, and the fast Node Vitest project in parallel against the built output before running Rust verification in isolation; the first failing lane aborts the remaining work.
Protocol, kernel, browser, and proof benchmark lanes remain explicit commands so they can use checkpoints and targeted reruns instead of slowing every local commit. The Node kernel command runs its merged heavy WASM project sequentially, the proof benchmark command runs its Node and desktop lanes concurrently on one machine, and the encrypted aggregate bridge matrix defaults to parallel local execution. The coverage lane covers the fast Node project only; heavy protocol, kernel, and proof-benchmark coverage comes from their explicit test lanes rather than V8 coverage instrumentation. The coverage badge is generated locally in the Pages workflow, not by Codecov.

## Local run logs

Heavy local runners write timestamped logs under gitignored `logs/` directories.
Logged runners include `pnpm run test:node:protocol`, `pnpm run test:node:kernel`, `pnpm run test:node`, `pnpm run test:browser`, all proof-benchmark scripts, and the encrypted aggregate bridge matrix scripts.
Each run gets `logs/YYYY-MM-DD/YYYY-MM-DDTHH-mm-ss-SSSZ-script-name/` with `metadata.json`, `summary.json`, `combined.log`, and per-command logs.
Encrypted aggregate bridge matrix runs also write per-row worker logs under `workers/`.
CI disables local log emission with `--no-run-log`; use the same trailing argument locally when a one-off run should skip logs, for example `pnpm run test:node:kernel -- --no-run-log`.

## Heavy proof checkpoints

Heavy ballot privacy proof flows write resumable development checkpoints to `temp/test-checkpoints/`.
The checkpoints are scratch artifacts and remain outside the published package and source tree.
Checkpoint filenames are named after their test suite and step.
Set `SEALED_LATTICE_RESUME_TEST_CHECKPOINTS=1` only when debugging a failed long run and intentionally reusing the latest local checkpoint.

The checkpoint set currently covers relation requests, lowered statements, generated proof records, scoped relation-bearing ballot packages, and verification reports.

## Heavy gate policy

The default Node runner can execute selected Vitest projects side by side, and the proof benchmark command runs its Node and desktop lanes concurrently; the merged kernel project keeps its heavy work sequential on one machine.
The full encrypted aggregate bridge matrix first runs the cheap all-row shape/config guardrail, then uses 8 workers; the representative bridge matrix uses 4 workers.

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace root is private and is never published.
