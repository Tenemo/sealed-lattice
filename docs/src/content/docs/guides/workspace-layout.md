---
title: Workspace layout
description: The package split, ownership boundaries, and dependency rules for the sealed-lattice workspace.
sidebar:
    order: 2
---

The repo is a private workspace with one published package, four private TypeScript packages, and one private Rust crate.

## Package map

- `packages/sdk`: the only published package directory, with the public package name `sealed-lattice`
- `packages/types`: canonical shared type definitions inlined into the published package during SDK builds
- `packages/protocol`: deterministic election model and transcript verification helpers
- `packages/crypto`: internal Hash512, hash, ML-DSA-65 profile, fixture signing, and signed-root verification wrappers
- `packages/wasm`: typed Rust/WASM loader for transcript-core analysis, protocol hash derivation, direct ballot proof work, and kernel checks
- `crates/sealed-lattice-kernel`: Rust transcript-core, proof, and BGV kernel crate that exports the WASM command path for transcript fixtures, reserved hash derivation, direct ballot proof experiments, and field checks

## Dependency direction

- `sealed-lattice` may depend on `@sealed-lattice/types`, `@sealed-lattice/protocol`, `@sealed-lattice/crypto`, and `@sealed-lattice/wasm`.
- `@sealed-lattice/protocol` may depend on `@sealed-lattice/types` and `@sealed-lattice/crypto`.
- `@sealed-lattice/crypto` and `@sealed-lattice/wasm` may depend on `@sealed-lattice/types`.
- No private package may depend on `sealed-lattice`.
- Deep imports like `@sealed-lattice/crypto/src/...` are forbidden.
- Relative imports that cross from one package directory into another package directory are forbidden.

## Why the public facade stays narrow

The goal of the current release is to keep package boundaries safe while the direct encrypted ballot API is still being built. The final public surface will expose direct-path voting and verification operations only after their proof, replay, target finality, decryption, and supported-phone mobile evidence gates close.

## Enforcement

- package `exports` maps keep each package root explicit
- ESLint resolves the workspace packages and rejects invalid imports
- dependency-cruiser rejects forbidden internal dependencies, cycles, deep imports, and cross-package relative imports
