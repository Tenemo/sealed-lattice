---
title: Workspace layout
description: The package split, ownership boundaries, and dependency rules for the sealed-lattice workspace.
sidebar:
    order: 2
---

The repo is a private workspace with one published package and five private internal packages.

## Package map

- `packages/sdk`: the only published package directory, with the public package name `sealed-lattice`
- `packages/types`: canonical shared type definitions inlined into the published package during SDK builds
- `packages/protocol`: deterministic election model and transcript verification helpers
- `packages/crypto`: internal Hash512, digest, ML-DSA-65 profile, fixture signing, and signed-root verification wrappers
- `packages/wasm`: typed Rust/WASM loader for transcript-core analysis, protocol digest derivation, ballot privacy proof verification, and kernel field checks
- `packages/testkit`: deterministic integration scaffolding package shell
- `crates/sealed-lattice-kernel`: Rust transcript-core and ballot privacy proof crate that exports the WASM command path for transcript fixtures, reserved digest derivation, proof verification, and `GF(65537)` checks

## Dependency direction

- `sealed-lattice` may depend on `@sealed-lattice/types`, `@sealed-lattice/protocol`, `@sealed-lattice/crypto`, and `@sealed-lattice/wasm`.
- `@sealed-lattice/protocol` may depend on `@sealed-lattice/types` and `@sealed-lattice/crypto`.
- `@sealed-lattice/crypto` and `@sealed-lattice/wasm` may depend on `@sealed-lattice/types`.
- `@sealed-lattice/testkit` may depend on all internal packages and on `sealed-lattice`.
- No private package may depend on `sealed-lattice` unless it is `@sealed-lattice/testkit`.
- Deep imports like `@sealed-lattice/crypto/src/...` are forbidden.
- Relative imports that cross from one package directory into another package directory are forbidden.

## Why the public facade stays narrow

The goal of the current release is to freeze packaging and package boundaries before the full voting API is real enough to publish safely. Shipping only safe transcript-core, election foundation, and ballot privacy verification helpers is deliberate.

## Enforcement

- package `exports` maps keep each package root explicit
- ESLint resolves the workspace packages and rejects invalid imports
- `tools/ci/check-package-boundaries.ts` rejects forbidden internal dependencies, cycles, deep imports, and cross-package relative imports
