---
title: Get started
description: Install sealed-lattice and use the current public verification helpers.
sidebar:
    order: 1
---

`sealed-lattice` provides verification helpers for post-quantum threshold voting artifacts in Node and browsers.

Use it to validate poll definitions, derive threshold profiles, check lifecycle and action rules, verify public board and roster evidence, and verify supported ballot privacy proof records with the bundled Rust/WASM verifier.

The package is under active implementation and has not been independently audited. Use it for development, integration experiments, and verification tooling, not production elections.

## Install

```bash
npm install sealed-lattice
```

```bash
pnpm add sealed-lattice
```

## Validate a poll

```typescript
import { deriveThresholdProfile, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposal should be adopted?",
    options: ["Proposal A", "Proposal B"],
    topOptionCount: 1,
});

if (!pollValidation.ok) {
    throw new Error(
        pollValidation.errors[0]?.message ?? "Invalid poll specification.",
    );
}

const thresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
});
```

`pollValidation.normalized` contains the validated poll with defaults applied. `thresholdProfile` contains the derived threshold, quorum, corruption-bound, and warning fields for the frozen roster size.

## Import verification helpers

```typescript
import {
    verifyBallotProof,
    verifyBoardConsistency,
    verifyClaimBearingBallotPackage,
    verifyReceiverKeyProof,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

These helpers verify structured public evidence and return accepted Hashes, status labels, and refusal records where applicable.

## What you can use today

- poll specification validation and canonical hash derivation
- threshold and frozen roster profile derivation
- lifecycle label, lifecycle transition, and action capability checks
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, and first-valid ordering checks
- transcript-core fixture verification through the bundled Rust/WASM kernel
- receiver-key proof, ballot proof record, and claim-bearing ballot package verification
- aggregate derivation component verification for post-close contribution evidence

## What is not available yet

- ballot generation or casting APIs
- proof construction APIs
- aggregation or tally evaluation APIs
- production target-bound decryption or result release
- production-readiness, audit, or certification claims

Reserved complete-protocol entry points fail closed with `OperationUnavailable` until the matching protocol layer exists.

## Next reads

- [API reference](../../api/) for the public function and type surface
- [Security and non-goals](../security-and-non-goals/) for current safety boundaries
- [Development workflow](../development-workflow/) for local build and verification commands
