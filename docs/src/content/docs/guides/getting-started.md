---
title: Get started
description: The shortest path to the current sealed-lattice public boundary and workspace contract.
sidebar:
    order: 1
---

Start with the public package name and the current rule: `sealed-lattice`
exposes only the safe transcript-core fixture verifier.

## Public package rules

- The only committed public package name is `sealed-lattice`.
- The public runtime facade currently exports `verifyTranscriptCoreFixture`.
- No public subpaths are promised yet.
- The current release freezes packaging, docs, smoke checks, transcript-core fixtures, and the workspace shape.

## Consumer posture

```typescript
import { verifyTranscriptCoreFixture } from "sealed-lattice";
```

The verifier accepts transcript-core fixture objects and returns deterministic
verification or rejection labels.

## What the current release includes

- the private Turborepo workspace layout
- the published `sealed-lattice` package identity
- private protocol, crypto, wasm, and testkit shells
- a Rust transcript core plus an internal WASM loader
- docs, TypeDoc, pack smoke, vector manifest verification, and CI verification

## What is not published yet

- protocol lifecycle helpers
- manifest types
- ballot or tally APIs
- proof systems
- public crypto provider wrappers
- public WASM or native arithmetic entry points

## Next reads

- [Workspace layout](../workspace-layout/) for package ownership and dependency direction
- [Development workflow](../development-workflow/) for the actual build and verification path
- [Security and non-goals](../security-and-non-goals/) for the current claim boundary
