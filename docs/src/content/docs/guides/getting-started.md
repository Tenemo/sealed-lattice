---
title: Get started
description: The shortest path to the current sealed-lattice public verification boundary and workspace contract.
sidebar:
    order: 1
---

Start with the public package name and the current rule: `sealed-lattice` exposes safe-by-default helpers for transcript-core fixture verification, election foundation checks, and verification-oriented ballot privacy APIs.

## Public package rules

- The only committed public package name is `sealed-lattice`.
- The public runtime facade currently exports transcript-core fixture verification plus threshold, lifecycle, poll specification, capability, board, target-finality, roster-manifest, cast receipt, close record, first-valid, recovery, receiver-key proof, ballot proof record, and scoped relation-bearing ballot package verification helpers.
- No public subpaths are promised yet.
- The current release freezes packaging, docs, smoke checks, transcript-core fixtures, election foundation vectors, ballot privacy verification APIs, and the workspace shape.

## Consumer posture

```typescript
import {
    deriveThresholdProfile,
    validatePollSpec,
    verifyClaimBearingBallotPackage,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

The transcript-core verifier accepts fixture objects and returns deterministic verification or rejection labels. The election foundation helpers validate public poll shape, derive threshold profiles, check lifecycle transitions, derive status labels, and refuse premature protocol actions. The ballot privacy verifier APIs verify supported receiver-key proofs, ballot proof records, and scoped relation-bearing encoded-score ballot packages through the packaged Rust/WASM backend. They do not implement a full voting workflow.

## What the current release includes

- the private Turborepo workspace layout
- the published `sealed-lattice` package identity
- private types, protocol, crypto, wasm, and testkit shells
- a Rust transcript-core and ballot privacy proof backend plus an internal WASM loader
- election foundation checks for threshold, lifecycle, poll specification, capability, board/finality, roster-manifest, cast/close receipt, first-valid, and recovery behavior
- verification-oriented receiver-key proof, ballot proof record, and scoped relation-bearing encoded-score ballot package APIs
- docs, TypeDoc, pack smoke, vector manifest verification, and CI verification

## What is not published yet

- ballot generation, casting, aggregation, or tally APIs
- proof construction APIs or unsafe generation helpers
- local replay record helpers, semantic target acceptance, decryption-share shell helpers, or decryption APIs
- public crypto provider wrappers
- public WASM or native arithmetic entry points

## Next reads

- [Workspace layout](../workspace-layout/) for package ownership and dependency direction
- [Development workflow](../development-workflow/) for the actual build and verification path
- [Security and non-goals](../security-and-non-goals/) for the current claim boundary
