# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace.

The published npm package is intentionally narrow while the protocol implementation is still being built and verified. Use it for development verification, package integration, transcript helpers, and foundation checks. It is not a complete voting library and must not be used for real ballots or ballot secrecy.

## Selected direction

The active project route is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> ballot validity proofs for the fixed encrypted-ballot relation
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first ballot proof backend candidate is the LaZer/LNP-derived no-wrap
profile. The public ballot package boundary is relation-fixed so that the proof
backend can be replaced if soundness, zero-knowledge, QROM, proof size, or
mobile-compatible runtime evidence fails to close.

The first claim-bearing mobile profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. That profile is not closed yet.

## Current package boundary

The public package currently exposes development verification helpers while the full voting API is being built and verified. These cover poll specification and threshold derivation, lifecycle and transcript checks, foundation transcript verification through the bundled Rust/WASM kernel, and a set of narrow development helpers for the collective BGV setup ceremony (setup intent, common-randomness commit/reveal, recipient-local private VSS verification, signed VSS acceptances and complaints, setup contribution and certificate assembly, encrypted local trustee state export and restore, and setup package verification). Reserved complete-protocol entry points fail closed until their claim gates are actually implemented.

Foundation helpers include an integrated public foundation verifier. One deterministic direct-route foundation transcript fixture verifies through the public package in Node and browser, integrated foundation mutations fail with structured refusals, and the packaged Rust/WASM transcript-core path matches the fixture roots under a foundation-only profile. Browser and mobile-emulated browser coverage is useful package evidence, but it is not supported-phone evidence.

## Installation

```bash
npm install sealed-lattice
```

```bash
pnpm add sealed-lattice
```

## Basic usage

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

## What you can use today

- poll specification validation and canonical hash derivation;
- threshold and frozen roster profile derivation;
- lifecycle label, lifecycle transition, and action capability checks;
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, first-valid ordering, and foundation transcript checks;
- development helpers for the collective BGV setup ceremony: setup intent, common-randomness commit/reveal, recipient-local private VSS verification, signed VSS acceptances and complaints, setup contribution and certificate assembly, encrypted local trustee state export and restore, and setup package verification;
- transcript-core fixture verification through the bundled Rust/WASM kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- claim-bearing accepted setup for `CollectiveBgvSetup-v1`;
- production setup ceremony, VSS, ballot generation, or casting APIs;
- public SDK encrypted ballot package creation, package verification, or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- production target-bound decryption, target recombination, or result release APIs;
- production-readiness, audit, certification, or supported-phone claims.

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Safety boundaries

All current setup, ballot, aggregation, evaluator, and target-decryption code is development evidence only. The Rust/WASM transcript-core kernel can create and verify development `EncryptedBallotPackage` artifacts from package objects, canonical ciphertext bytes, public proof chunks, accepted public-key material, and an accepted setup handoff root without `setupPackage`, `setupPublicMaterial`, `setupPrivateWitness`, top-count evaluator requests, or public evaluation-key material in the public package commands, but those artifacts are still internal relation evidence and not accepted encrypted ballot packages. The package must not be used for real ballots or ballot secrecy, and nothing in it is supported-phone, production, audited, or certified.

In particular, the accepted collective BGV setup for `CollectiveBgvSetup-v1` is not claim-complete: a profile-scale Rust terminal setup-package lane now passes, but cross-runtime/public-package confirmation, transport/profile measurement rows, final adversarial package coverage, and final verification gates are still pending. The accepted ballot package path now refuses passive setup material, loads handoff-bound accepted public-key material, and uses closed `EncryptedBallotPackage` and `BallotProofChunkManifest` schemas with canonical statement-hash vectors plus root-bound ballot layout, reserved-slot rule, witness partition profile, arithmetic certificate hash, proof profile hash, and batch encoder matrix identifiers. The internal ballot proof now uses statement-derived projected scalar BGV commitments, three projections per RNS limb component, row-specific projected no-wrap quotient response bounds, statement-derived random-projected support commitments for one-hot, randomizer, and error witnesses over the first three data-prime support fields, and an appended salted masked committed trace proof for one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and packed-column shape. That proof measures 31,618,904 bytes and 31 one-mebibyte transport chunks for one proof in the current package fixture. The committed trace is bound into public proof bytes, the proof profile, and the arithmetic certificate, and now enforces encoder carry bit Booleanity, slack bit Booleanity, carry bit decomposition, carry-plus-slack range, projected no-wrap carry shifted/slack ternary digits, shifted carry decomposition, and the projected carry range equation, but proof soundness, zero-knowledge accounting, and Fiat-Shamir/QROM accounting are still open. The arithmetic certificate records score, encoder, support, response, verifier, and BGV quotient rows; the accepted backend path is still scoped to accepted approximate-range/no-wrap accounting rather than appending explicit carry response polynomials. The accepted ballot path still needs accepted proof soundness, zero-knowledge accounting, Fiat-Shamir/QROM accounting, accepted binary proof transport, accepted randomness boundaries, accepted package verifier closure, and mobile-compatible proof readiness; supported-phone evidence remains a later runtime target. The evaluator and target-decryption paths still need bounded-domain all-`K_top` replay, target share proof certification, C1-C4 closure, public recombination, and supported-phone evidence.

Development runs on native, Node, desktop browser, or mobile-emulated browser do not count as supported-phone or production evidence. Internal package names, private workspace commands, and fixture evidence are not stable public APIs.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  docs/                         Public documentation site and API documentation tools
  packages/
    crypto/                     Internal canonical JSON, hashes, signatures
    protocol/                   Internal protocol logic and reference paths
    sdk/                        Published sealed-lattice package
    types/                      Shared TypeScript type declarations
    wasm/                       Internal WASM loader package
  test-vectors/                 Canonical public regression vectors
  tools/                        CI, vector, packaging, and documentation tools
```

## Documentation

- [Documentation site](https://tenemo.github.io/sealed-lattice/)
- [Guides](https://tenemo.github.io/sealed-lattice/guides/)
- [Protocol spec](https://tenemo.github.io/sealed-lattice/spec/)
- [API reference](https://tenemo.github.io/sealed-lattice/api/)

## Development

Install dependencies:

```bash
pnpm install
```

Run the main local validation gate:

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, runs the type-check, then runs lint, docs verification, package smoke verification, public package policy verification, package-boundary verification, test vector verification, dead-code scan, Rust formatting, Rust clippy, fast Rust kernel tests, fast Node tests, and the non-heavy kernel Node tests through the repository check runner.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Run focused verification:

```bash
pnpm run vectors
pnpm run test:rust:kernel:heavy
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test:node:kernel:heavy
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run verify:docs
pnpm run smoke:pack:npm
```

Keep default and release gates focused on the selected direct path and shared substrate. Heavy proof, browser, and mobile evidence lanes should be added only when they measure accepted direct-path evidence.

Build and package-smoke the published SDK:

```bash
pnpm run build
pnpm run smoke:pack:npm
```

Install browser engines before the first local browser test run:

```bash
pnpm exec playwright install chromium firefox webkit
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
