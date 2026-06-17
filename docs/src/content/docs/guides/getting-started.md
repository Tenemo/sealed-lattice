---
title: Get started
description: Install sealed-lattice and use the current public verification helpers.
sidebar:
    order: 1
---

`sealed-lattice` provides development verification helpers for a mobile-first post-quantum threshold homomorphic voting prototype.

The selected direction is active-static secure-with-abort collective BGV setup, direct encrypted ballots, ballot validity proofs for the fixed encrypted-ballot relation, public ciphertext aggregation, bounded-domain mobile evaluator replay, unanimous target finality for the first profile, and one-shot target-bound threshold decryption of `C_target` only.

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
    rosterSize: 10,
});
```

`pollValidation.normalized` contains the validated poll with defaults applied. `thresholdProfile` contains the derived threshold, quorum, corruption-bound, and warning fields for the frozen roster size.

## Import verification helpers

```typescript
import {
    aggregateDirectEncryptedBallotPackages,
    createDirectEncryptedBallotPackages,
    createSetupContribution,
    createSetupPackageVerificationInput,
    createVssShareAcceptance,
    deriveThresholdProfile,
    validatePollSpec,
    verifyBoardConsistency,
    verifyFoundationTranscript,
    verifyDirectEncryptedBallotPackage,
    verifyPrivateVssShare,
    verifySetupPackage,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

These helpers are useful for current development verification and package integration. The public encrypted ballot package helpers create and verify package artifacts from accepted public-key material and an accepted setup handoff, and public aggregation sums verified ciphertexts; they are not a complete voting workflow.

## What you can use today

- poll specification validation and canonical hash derivation
- threshold and frozen roster profile derivation
- lifecycle label, lifecycle transition, and action capability checks
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, and first-valid ordering checks
- narrow accepted-setup helpers for setup intent records, setup phase records, common-randomness records, private VSS share verification, signed VSS acceptance and complaint records, roots-only setup contributions, proof-material records, binary setup-material transports, public-only setup package verification input construction, setup package verification, encrypted local trustee setup state export, and restore-after-restart validation
- encrypted ballot package creation, package verification, public proof transport, and public ciphertext aggregation as development evidence from accepted public setup material
- transcript-core fixture verification through the bundled Rust/WASM kernel
- package-boundary and public API smoke coverage

## What is not available yet

- production setup ceremony, ballot generation, or casting APIs
- claim-bearing encrypted ballot package creation, package verification, public proof transport, or aggregation APIs
- public bounded-domain mobile evaluator replay APIs
- production target-bound decryption or result release
- production-readiness, audit, certification, or supported-phone claims

Reserved complete-protocol entry points fail closed with `OperationUnavailable` until the matching direct-path layer exists.

## Next reads

- [API reference](../../api/) for the public function and type surface
- [Security and non-goals](../security-and-non-goals/) for current safety boundaries
- [Development workflow](../development-workflow/) for local build and verification commands
