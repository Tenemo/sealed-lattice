---
title: Get started
description: The shortest path to the current sealed-lattice public boundary and workspace contract.
sidebar:
    order: 1
---

Start with the public package name and the current rule: `sealed-lattice`
exposes the safe transcript core fixture verifier and protocol shell.

## Public package rules

- The only committed public package name is `sealed-lattice`.
- The public runtime facade currently exports transcript core fixture verification plus threshold, lifecycle, poll-spec, and capability helpers.
- No public subpaths are promised yet.
- The current release freezes packaging, docs, smoke checks, transcript core fixtures, protocol shell vectors, and the workspace shape.

## Consumer posture

```typescript
import {
    deriveThresholdProfile,
    validatePollSpec,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

The verifier accepts transcript core fixture objects and returns deterministic
verification or rejection labels. The protocol shell helpers validate public poll shape,
derive threshold profiles, check lifecycle transitions, derive status labels,
and refuse premature protocol actions. They do not implement voting.

## What the current release includes

- the private Turborepo workspace layout
- the published `sealed-lattice` package identity
- private protocol, crypto, wasm, and testkit shells
- a Rust transcript core plus an internal WASM loader
- a deterministic threshold, lifecycle, poll-spec, and capability shell
- docs, TypeDoc, pack smoke, vector manifest verification, and CI verification

## What is not published yet

- manifest types
- ballot or tally APIs
- proof systems
- public crypto provider wrappers
- public WASM or native arithmetic entry points

## Next reads

- [Workspace layout](../workspace-layout/) for package ownership and dependency direction
- [Development workflow](../development-workflow/) for the actual build and verification path
- [Security and non-goals](../security-and-non-goals/) for the current claim boundary
