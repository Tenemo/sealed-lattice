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
pnpm run check
pnpm run check:static
pnpm run vectors
pnpm exec playwright install chromium firefox webkit
pnpm run test:precommit
pnpm run test:node:fast
pnpm run test:node:heavy
pnpm run test:node:heavy:kernel
pnpm run test
pnpm run test:proof-benchmark
pnpm run test:proof-benchmark:node
pnpm run test:proof-benchmark:browser:desktop
pnpm run test:proof-benchmark:browser:mobile:throttled
pnpm run verify:docs
pnpm run smoke:pack
pnpm run smoke:pack:npm
```

## What each command proves

- `pnpm run build`: every package builds, the private crypto/runtime bridge is vendored into the SDK, the WASM transcript-core artifact is copied into the internal loader package, and the published SDK loader is pinned to the packaged kernel digest
- `pnpm run check`: runs `pnpm run build`, then `pnpm run check:static`
- `pnpm run check:static`: repo lint, TypeScript project typechecking, Rust formatting, Rust clippy, Rust tests, package-boundary checks, vector manifest verification, and dead-code analysis without an implicit build
- `pnpm run vectors`: committed test vector files match `test-vectors/manifest.json`
- `pnpm run test:precommit`: fast Node tests plus desktop and mobile browser Vitest projects against the current built output
- `pnpm run test:node:fast`: pre-commit-friendly Node tests, excluding slow protocol, kernel-heavy WASM, and proof-benchmark suites
- `pnpm run test:node:heavy`: slow protocol relation and proof-record input tests that remain part of the default Node gate without running under coverage instrumentation
- `pnpm run test:node:heavy:kernel`: transcript-core WASM loader, parity, fixture, proof-generation, and proof-record integration tests
- `pnpm run test`: fast Node tests, heavy protocol Node tests, kernel-heavy Node tests, and browser tests
- `pnpm run test:proof-benchmark`: Node and desktop Chromium proof benchmark lanes, run sequentially on one machine
- `pnpm run test:proof-benchmark:node`: Node proof benchmark lane, suitable for a separate CI worker
- `pnpm run test:proof-benchmark:browser:desktop`: desktop Chromium proof benchmark lane, suitable for a separate CI worker
- `pnpm run test:proof-benchmark:browser:mobile:throttled`: manual-only calibrated mobile CPU-throttled benchmark lane
- `pnpm run verify:docs`: generated API pages, docs link structure, and the production docs site build stay consistent
- `pnpm run docs:build:site`: builds the docs site without the surrounding verification checks when that narrower target is needed
- `pnpm run smoke:pack` and `pnpm run smoke:pack:npm`: the published package tarball installs cleanly and exposes safe-by-default helpers for transcript-core fixture verification, election foundation checks, and verification-oriented ballot privacy APIs

## Local hooks

The pre-commit hook runs `pnpm run build`, `pnpm run check:static`, and `pnpm run test:precommit`.
This builds once, runs static verification once, then exercises fast Node and browser Vitest projects against the built output.
Node-heavy and proof benchmark lanes remain explicit commands so they can use checkpoints and focused reruns instead of slowing every local commit. The coverage lane covers the fast Node project only; heavy protocol, kernel, and proof-benchmark coverage comes from their explicit test lanes rather than V8 coverage instrumentation.

## Heavy proof checkpoints

Heavy ballot privacy proof flows write resumable development checkpoints to `temp/test-checkpoints/`.
The checkpoints are scratch artifacts and remain outside the published package and source tree.
Checkpoint filenames are named after their test suite and step.
Set `SEALED_LATTICE_RESUME_TEST_CHECKPOINTS=1` only when debugging a failed long run and intentionally reusing the latest local checkpoint.

The checkpoint set currently covers relation requests, lowered statements, generated proof records, scoped relation-bearing ballot packages, and verification reports.

## Heavy gate policy

Run heavyweight proof/browser benchmark lanes sequentially on one machine.
Run them in parallel only when each lane has its own CI worker or isolated machine resources.
The mobile proof benchmark is throttled-only and manual-only. Do not run it from default CI, prebuild, check, package, or verification commands.

## Release-facing rule

The release workflow bumps and publishes only `packages/sdk`. The workspace root is private and is never published.
