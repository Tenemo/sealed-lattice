---
title: Workspace layout
description: The package split, ownership boundaries, and dependency rules for the sealed-lattice workspace.
sidebar:
    order: 2
---

The repo is a private workspace with one published package and four private
internal packages.

## Package map

- `packages/sdk`: the only published package directory, with the public package name `sealed-lattice`
- `packages/protocol`: deterministic election model and transcript package shell
- `packages/crypto`: provider and capability package shell
- `packages/wasm`: typed Rust/WASM loader and placeholder proof path
- `packages/testkit`: deterministic integration scaffolding package shell
- `crates/sealed-lattice-kernel`: Rust placeholder crate that exports one trivial WASM function

## Dependency direction

- `sealed-lattice` may depend on `@sealed-lattice/protocol`, `@sealed-lattice/crypto`, and `@sealed-lattice/wasm`.
- `@sealed-lattice/testkit` may depend on all internal packages and on `sealed-lattice`.
- No private package may depend on `sealed-lattice` unless it is `@sealed-lattice/testkit`.
- Deep imports like `@sealed-lattice/crypto/src/...` are forbidden.
- Relative imports that cross from one package directory into another package directory are forbidden.

## Why the public facade stays empty

The goal of the current release is to freeze packaging and package boundaries
before the protocol-facing API is real enough to publish safely. Shipping an
empty public runtime facade is deliberate.

## Enforcement

- package `exports` maps keep each package root explicit
- ESLint resolves the workspace packages and rejects invalid imports
- `tools/ci/check-package-boundaries.ts` rejects forbidden internal dependencies, cycles, deep imports, and cross-package relative imports
