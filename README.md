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
- internal encrypted-aggregate bridge object-model helpers, private Rust/WASM bridge-encryption generation, a non-exported private Rust relation evaluator for the `n=3..20`, `m=2..20` matrix domain, and a private Rust/WASM same-witness bridge relation backend for representative rows `3:2`, `3:20`, `4:2`, `9:20`, `10:2`, `10:20`, `16:2`, `16:20`, `20:2`, and `20:20`. The verifier emits `BridgeProofRelationChecked` and `BridgeProofImplementationEvidenceOnly` only after checking the shared M6 aggregate relation, mod-65537 reduction, BGV batch encoding, full data-basis development ciphertext equation, context bindings, witness-clean disclosure flags, and diagnostic-only sampled-check policy. Bridge verification also emits `bridgeClaimClosureVerified: false`, `BridgeProofClaimClosureMissing`, and a row-evidence label, so `ok: true` means the command accepted implementation evidence, not claim-bearing bridge closure. The bridge digest purposes and relation scope now use stable sealed-lattice aggregate-bridge terms, while matrix outputs use local evidence labels rather than closure labels. The target contract records two 64-bit shared-witness checks and explicitly labels the missing zero-knowledge distribution proof, BGV randomness-bound proof, and bridge claim closure as open. Internal TypeScript bridge records, checked aggregate contributions, first-valid selection, aggregate-ready handoff helpers, and representative matrix artifacts remain private package internals.
- explicit non-closure markers for receiver-encryption parameter-security evidence and aggregate-derivation claim closure

Verification helpers return structured results with accepted digests, status labels, and refusal records where applicable. The bundled Rust/WASM transcript-core loader pins the packaged kernel digest by default. Reserved complete-protocol entry points fail closed with `OperationUnavailable` until the matching protocol layer exists.

## What is not available yet

`sealed-lattice` does not currently provide:

- ballot generation or casting APIs
- proof construction APIs
- aggregation or tally evaluation APIs
- standalone receiver-encryption parameter-security certification for the current Module-LWE profile
- claim-strength aggregate-opening proof closure
- full M9 encrypted aggregate bridge closure across the required `n=3..20`, `m=2..20` variant matrix; representative e2e rows pass the private Rust/WASM shared-witness bridge implementation-evidence verifier path, but the zero-knowledge distribution proof, BGV randomness-bound proof, full 342-row matrix, full negative suite, and public SDK bridge verifier remain pending
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
