---
title: Get started
description: The shortest path to the current sealed-lattice public boundary and workspace contract.
sidebar:
    order: 1
---

Start with the public package name and the current rule: `sealed-lattice` exposes the safe transcript core fixture verifier and election foundation.

## Public package rules

- The only committed public package name is `sealed-lattice`.
- The public runtime facade currently exports transcript core fixture verification plus threshold, lifecycle, poll specification, capability, board, target-finality, roster-manifest, cast receipt, close record, first-valid, and recovery helpers.
- No public subpaths are promised yet.
- The current release freezes packaging, docs, smoke checks, transcript core fixtures, election foundation vectors, and the workspace shape.

## Consumer posture

```typescript
import {
    deriveThresholdProfile,
    validatePollSpec,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

The verifier accepts transcript core fixture objects and returns deterministic verification or rejection labels. The election foundation helpers validate public poll shape, derive threshold profiles, check lifecycle transitions, derive status labels, and refuse premature protocol actions. They do not implement voting.

## What the current release includes

- the private Turborepo workspace layout
- the published `sealed-lattice` package identity
- private types, protocol, crypto, wasm, and testkit shells
- a Rust transcript core plus an internal WASM loader
- deterministic election foundation helpers for threshold, lifecycle, poll specification, capability, board/finality, roster-manifest, cast/close receipt, first-valid, and recovery checks
- docs, TypeDoc, pack smoke, vector manifest verification, and CI verification

## What is not published yet

- ballot or tally APIs
- proof systems
- local replay record helpers, semantic target acceptance, decryption-share shell helpers, or decryption APIs
- public crypto provider wrappers
- public WASM or native arithmetic entry points

## Next reads

- [Workspace layout](../workspace-layout/) for package ownership and dependency direction
- [Development workflow](../development-workflow/) for the actual build and verification path
- [Security and non-goals](../security-and-non-goals/) for the current claim boundary
