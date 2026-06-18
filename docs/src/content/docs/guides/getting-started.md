---
title: Get started
description: Install sealed-lattice and use the current public verification helpers.
sidebar:
    order: 1
---

`sealed-lattice` provides development verification helpers for a mobile-first post-quantum threshold homomorphic voting prototype.

The selected direction is active-static secure-with-abort collective BGV setup, direct encrypted ballots, ballot validity proofs for the fixed encrypted-ballot relation, public ciphertext aggregation, bounded-domain mobile evaluator replay, unanimous target finality for the first profile, and one-shot target-bound threshold decryption of `C_target` only.

The package is under active implementation. Use it for development, integration experiments, and verification tooling, not production elections, and read the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before treating any verification result as security evidence.

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
    createSetupPackageVerificationInput,
    deriveThresholdProfile,
    validatePollSpec,
    verifyBoardConsistency,
    verifyFoundationTranscript,
    verifyPrivateVssShare,
    verifySetupPackage,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

These helpers are useful for current development verification and package integration. Complete active-static direct encrypted ballot voting entry points are not public yet.

## What you can use today

- poll specification validation and canonical hash derivation
- threshold and frozen roster profile derivation
- lifecycle transition and action capability checks
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, and first-valid ordering checks
- narrow accepted-setup verifier helpers for private VSS share verification, public-only setup package verification input construction, and setup package verification
- transcript-core fixture verification through the bundled Rust/WASM kernel
- package-boundary and public API smoke coverage

## What is not available yet

- production setup ceremony, ballot generation, or casting APIs
- public encrypted ballot package creation or verification APIs
- public encrypted ballot aggregation APIs
- public bounded-domain mobile evaluator replay APIs
- production target-bound decryption or result release
- production security claims; see the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md)

Reserved complete-protocol entry points fail closed with `OperationUnavailable` until the matching direct-path layer exists.

## Next reads

- [API reference](../../api/) for the public function and type surface
- [Security and non-goals](../security-and-non-goals/) for the canonical security policy pointer
- [Development workflow](../development-workflow/) for local build and verification commands
