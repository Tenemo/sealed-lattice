# sealed-lattice

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` provides verification helpers for post-quantum threshold voting artifacts in Node and browsers.

Use it to validate poll definitions, derive threshold profiles, check lifecycle and action rules, verify public board and roster evidence, and verify supported ballot privacy proof records with the bundled Rust/WASM verifier.

The package is under active implementation and has not been independently audited. It is suitable for development, integration experiments, and verification tooling, not production elections.

## Install

```bash
npm install sealed-lattice
```

```bash
pnpm add sealed-lattice
```

## Start with a poll

```ts
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

console.log(pollValidation.normalized);
console.log(thresholdProfile.privacyCorruptionBound);
```

## Verify public artifacts

```ts
import {
    verifyBallotProof,
    verifyBoardConsistency,
    verifyClaimBearingBallotPackage,
    verifyReceiverKeyProof,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

The package currently exposes helpers for:

- poll specification validation and canonical digest derivation
- threshold and frozen roster profile derivation; non-benchmark dynamic proof verification remains blocked until approved roster-profile parameter certificate rows exist
- lifecycle label, lifecycle transition, and action capability checks
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, and first-valid ordering checks
- transcript-core fixture verification through the bundled Rust/WASM kernel
- receiver-key proof, ballot proof record, and claim-bearing ballot package verification
- aggregate derivation component verification for post-close contribution evidence
- internal encrypted-aggregate bridge object-model helpers and private Rust/WASM bridge-encryption generation plus full public-statement and proof-target contract digest evidence checking, explicit pending relation-gap status checks, sampled-relation diagnostic-only policy checks, same-witness target-contract guards with a bound shared-witness layout digest rejecting separate-subproof closure and public plaintext-root closure evidence, aggregate subproof summary binding across Rust/WASM and TypeScript pending-record assembly, pending bridge proof-record assembly, checked-proof-record contribution assembly, fail-closed bridge-encryption shell guards, and public SDK export guards for witness-clean contribution records, first-valid contribution selection, and aggregate-ready handoff records
- explicit non-closure markers for receiver-encryption parameter-security evidence and aggregate-derivation claim closure

Verification helpers return structured results with accepted digests, status labels, and refusal records where applicable. Reserved complete-protocol entry points fail closed with `OperationUnavailable` until the matching protocol layer exists.

## What is not available yet

`sealed-lattice` does not currently provide:

- ballot generation or casting APIs
- proof construction APIs
- aggregation or tally evaluation APIs
- standalone receiver-encryption parameter-security certification for the current Module-LWE profile
- claim-strength aggregate-opening proof closure
- claim-bearing encrypted aggregate bridge proof generation or verification
- HE-bearing security certification; the private BGV profile remains pending final `Q_target` and Appendix A acceptance, and ML-KEM/ML-DSA transport/signature choices do not imply category-3 end-to-end security
- production target-bound decryption or result release
- production-readiness, audit, or certification claims

Do not use the package for real ballot secrecy until the missing voting workflow, proof, aggregation, evaluation, decryption, audit, and deployment work is complete.

## Documentation

- [Getting started](https://tenemo.github.io/sealed-lattice/guides/getting-started/)
- [API reference](https://tenemo.github.io/sealed-lattice/api/)
- [Security and non-goals](https://tenemo.github.io/sealed-lattice/guides/security-and-non-goals/)
- [Documentation site](https://tenemo.github.io/sealed-lattice/)

## Development

Install dependencies:

```bash
pnpm install
```

Run the main verification gate:

```bash
pnpm run check
```

Build and package-smoke the published SDK:

```bash
pnpm run build
pnpm run smoke:pack
pnpm run smoke:pack:npm
```

Run the docs gate when public API or documentation changes:

```bash
pnpm run verify:docs
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
