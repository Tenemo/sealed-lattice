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
- `packages/crypto`: internal canonical hashing, signing, and encrypted envelope helpers
- `packages/wasm`: typed Rust/WASM loader for package verification helpers
- `crates/sealed-lattice-kernel`: Rust transcript, proof, and BGV kernel crate

## Dependency direction

- `sealed-lattice` may depend on `@sealed-lattice/types`, `@sealed-lattice/protocol`, `@sealed-lattice/crypto`, and `@sealed-lattice/wasm`.
- `@sealed-lattice/protocol` may depend on `@sealed-lattice/types` and `@sealed-lattice/crypto`.
- `@sealed-lattice/crypto` and `@sealed-lattice/wasm` may depend on `@sealed-lattice/types`.
- No private package may depend on `sealed-lattice`.
- Deep imports like `@sealed-lattice/crypto/src/...` are forbidden.
- Relative imports that cross from one package directory into another package directory are forbidden.

## Why the public facade stays narrow

The goal of the current release is to keep package boundaries safe while the complete voting API is still being built. The final public surface will expose voting and verification operations only after the matching package APIs are implemented; the security-evidence boundary is maintained in the repository security policy.

## Enforcement

- package `exports` maps keep each package root explicit
- ESLint resolves the workspace packages and rejects invalid imports
- the package-boundary checker rejects forbidden internal dependencies, deep imports, and cross-package relative imports
