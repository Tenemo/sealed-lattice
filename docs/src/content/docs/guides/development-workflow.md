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
pnpm run test:proof-benchmark:browser:mobile:throttled
pnpm run test:encrypted-aggregate-bridge
pnpm run test:encrypted-aggregate-bridge:representative
pnpm run verify:docs
pnpm run smoke:pack:npm
```

## What each command proves

- `pnpm run build`: every package builds, the private crypto/runtime bridge is vendored into the SDK, the WASM transcript-core artifact is copied into the internal loader package, and the published SDK loader is pinned to the packaged kernel hash
- `pnpm run api-surface:update`: runs the full build and updates the compact public API snapshot
- `pnpm run api-surface:check`: runs the full build and verifies it against the compact public API snapshot
- `pnpm run check`: runs repo lint, TypeScript, public API snapshot verification, package build verification, dependency-boundary checks, public package policy, vector manifest verification, dead-code analysis, Rust formatting, Rust clippy, and Rust tests
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test:node:fast`: pre-commit-friendly Node tests, excluding slow protocol, kernel-heavy WASM, and proof-benchmark suites
- `pnpm run test:node:protocol`: slow protocol relation and proof-record generation input tests that remain part of the default Node gate without running under coverage instrumentation
- `pnpm run test:node:kernel`: transcript-core WASM loader, parity, fixture, proof-generation, proof-record integration, and aggregate-derivation transcript-core WASM integration tests
- `pnpm run test`: runs the split Node test lanes, then the desktop and mobile browser lanes through the package scripts
- `pnpm run test:proof-benchmark`: Node and desktop Chromium proof benchmark lanes, run in parallel after one build
- `pnpm run test:proof-benchmark:node`: Node proof benchmark lane, suitable for a separate CI worker
- `pnpm run test:proof-benchmark:browser:desktop`: desktop Chromium proof benchmark lane, suitable for a separate CI worker
- `pnpm run test:proof-benchmark:browser:mobile:throttled`: manual-only calibrated mobile CPU-throttled benchmark lane
- `pnpm run test:encrypted-aggregate-bridge`: builds once, runs the cheap all-row bridge shape/config guardrail, then runs the full encrypted aggregate bridge matrix with a default 16-worker floor
- `pnpm run test:encrypted-aggregate-bridge:representative`: builds once, then runs the ten selected representative bridge rows with a default ten-worker floor
- `pnpm run verify:docs`: generated API pages, docs link structure, and the production docs site build stay consistent
- `pnpm run docs:build:site`: builds the docs site without the surrounding verification checks when that narrower target is needed
- `pnpm run smoke:pack:npm`: the published package tarball installs cleanly through npm and exposes safe-by-default helpers for transcript-core fixture verification, election foundation checks, and verification-oriented ballot privacy APIs

## Local hooks

The pre-commit hook runs `pnpm run check` and `pnpm exec vitest --project node --project browser-desktop --project browser-mobile --run`.
This leaves a full package build in place through the check command, runs static verification once, runs Rust verification once, then exercises fast Node and browser Vitest projects against the built output.
Split Node and proof benchmark lanes remain explicit commands so they can use checkpoints and targeted reruns instead of slowing every local commit. The Node kernel command runs its merged heavy WASM project sequentially, while the proof benchmark command and encrypted aggregate bridge matrix default to parallel local execution. The coverage lane covers the fast Node project only; heavy protocol, kernel, and proof-benchmark coverage comes from their explicit test lanes rather than V8 coverage instrumentation.

## Heavy proof checkpoints

Heavy ballot privacy proof flows write resumable development checkpoints to `temp/test-checkpoints/`.
The checkpoints are scratch artifacts and remain outside the published package and source tree.
Checkpoint filenames are named after their test suite and step.
Set `SEALED_LATTICE_RESUME_TEST_CHECKPOINTS=1` only when debugging a failed long run and intentionally reusing the latest local checkpoint.

The checkpoint set currently covers relation requests, lowered statements, generated proof records, scoped relation-bearing ballot packages, and verification reports.

## Heavy gate policy

Heavyweight Node, proof benchmark, and encrypted aggregate bridge lanes default to parallel execution on local machines.
The full encrypted aggregate bridge matrix first runs the cheap all-row shape/config guardrail, then uses 16 workers; the representative bridge matrix uses one worker per selected row.
The mobile proof benchmark is throttled-only and manual-only. Do not run it from default CI, prebuild, check, package, or verification commands.

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace root is private and is never published.
