# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace.

The published npm package is intentionally narrow while the protocol implementation is still being built and verified. Use it for development verification, package integration, transcript helpers, and foundation checks. It is not a complete voting library and must not be used for real ballots or ballot secrecy.

## Selected direction

The active project route is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> LaZer/LNP-derived no-wrap ballot validity proofs
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first claim-bearing mobile profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. That profile is not closed yet.

## Current package boundary

The public package currently exposes development verification helpers while the final direct voting API is being built. It also exposes narrow accepted-setup helpers for signed setup intent creation, deterministic setup phase records, full-roster common-randomness commit/reveal assembly, recipient-local private VSS share verification, signed VSS acceptance and complaint records, roots-only setup contribution assembly, proof-material-only same-secret, public-key, and evaluation-key record assembly, verifier-derived threshold-share commitments during setup package assembly, root-bound setup certificate generation, encrypted local trustee setup state export, restore-after-restart validation, and setup package verification. Reserved complete-protocol entry points fail closed until their direct-path claim gates are actually implemented.

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
- signed setup intent creation, deterministic setup phase records, full-roster common-randomness commit/reveal assembly, recipient-local private VSS share verification, signed VSS acceptance and complaint records, roots-only accepted setup contribution assembly, proof-material-only same-secret, public-key, and evaluation-key record assembly, verifier-derived threshold-share commitments during setup package assembly, root-bound setup certificate generation, encrypted local trustee setup state export, restore-after-restart validation, and setup package verification for development integration;
- transcript-core fixture verification through the bundled Rust/WASM kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- claim-bearing accepted setup for `CollectiveBgvSetup-v1`;
- production setup ceremony, VSS, ballot generation, or casting APIs;
- public direct ballot proof construction or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- production target-bound decryption, target recombination, or result release APIs;
- production-readiness, audit, certification, or supported-phone claims.

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Safety boundaries

The current setup, direct proof, aggregation, evaluator, browser, and target-decryption evidence is development evidence only. The current setup completion target means claim-bearing accepted setup for `CollectiveBgvSetup-v1`; it is not gated on external validation, independent audit, or third-party proof review, but the repository must still close profile-scale transport and terminal setup-package evidence before that label can be used. Internal direct evaluator replay can consume supplied development public evaluation-key material; the accepted setup verifier can reconstruct a package-closure-pending public-only collective encryption key plus aggregate relinearization and Galois runtime keys from profile-ring material, and its terminal profile-ring gate refuses reduced-ring VSS material, same-secret proof records, public-key share material, public-key LNP proof records, collective public-key material, relinearization records, and Galois proof records before accepted handoff; the internal kernel can generate self-verified evaluation-key share proof bytes with accepted setup proof accounting for relinearization and Galois proof records while refusing round-two relinearization generation unless the source witness equals the trustee secret times the accepted round-one aggregate source, and the accepted setup verifier recomputes round-two source-square binding and aggregate roots; protocol setup assembly can invoke that generator while constructing root-bound evaluation-key proof records; the setup package now requires root-bound public-key closure inputs, commitment-security, transport, setup proof accounting with per-family verifier-closed relation/transcript/bound checks, 63-bit scalar relation challenges with canonical decimal-string proof-record metadata and z34 hash metadata, response-mask/no-wrap accounting including centered signed private VSS coefficient-response, same-secret committed-secret, public-key committed-secret, and evaluation-key committed-secret response verification over a three-limb setup commitment modulus product with big-integer comparisons and fixed-width signed big-integer public-key/evaluation-key relation commitments, deterministic statement-and-relation-bound full-width tbox commitment-prefix generation and verifier recomputation, proof-record-bound LaZer `check_z34` seed-material, challenge-seed, challenge-tail, lower-protocol challenge hash, row-domain, full-width brandom R/Rprime row-set hashes, signed z3/z4 check-window hashes, and measured z3/z4 norm values, generated LaZer `check_z34` 256-coefficient z3/z4 norm-bound enforcement, generated z1/z21 Gaussian L2 checks, generated hint range checks, signed LaZer hint/Gaussian suffix decoding, h zero-position enforcement, z34-bound lower-protocol challenge sampling, generated lower-protocol tbox suffix enforcement, closed generated-tbox accounting with all five tbox profile hashes and the challenge audit hash, closed Fiat-Shamir transcript-domain and challenge-input accounting with DFM20/DFMS22/LNP22 reference rows, all-family challenge-space audit binding, repo-owned LNP22 small-coefficient challenge-difference invertibility accounting, accepted setup proof theorem accounting for LNP22 soundness, simulator zero-knowledge, and fixed-profile QROM composition across all setup proof families, accepted setup commitment parameter accounting for Module-SIS/Module-LWE rows, accepted key-correctness certificates for verifier-recomputed collective public-key coefficients and public evaluation-key roots, an accepted HE parameter boundary for current Q_data/Q_share setup/evaluator exposure while refusing Q_target readiness, and a root-bound active-static secure-with-abort setup theorem certificate that records verified setup gates, dependency hashes, accepted abort behavior, local reference rows, integration-dependency labels, and the no-external-validation completion boundary, while the verifier checks present public proof, key, and certificate objects before returning terminal missing-object `pending`; the internal protocol package can assemble full-roster VSS commitments, private mailbox delivery, recipient re-verification, signed acceptances, verifier-derived threshold commitments, same-secret statements and LNP proof records, public-key share/proof/material/LNP records, the root-bound collective public key, frozen evaluator-key schedules, relinearization/Galois proof records, public evaluation-key roots, the final root-bound setup package, encrypted local trustee state, and roots-only setup contributions without exporting raw shares or caller-supplied aggregate public-key material; and the public package now wraps signed setup intent creation, setup phase records, full-roster common-randomness assembly with Rust/WASM-derived public matrices, recipient-local private VSS verification, signed acceptance and complaint records, roots-only setup contribution, proof-material-only same-secret and public-key share records, evaluator-key schedules, relinearization/Galois proof record assembly, public evaluation-key root assembly, verifier-derived threshold-share commitments, root-bound setup certificate generation, encrypted local-state restore, and setup package verification without exposing raw shares, aggregate public-key inputs, or proof-generation witnesses. Accepted setup-package evidence, accepted ballot proof evidence, supported-phone evidence, production readiness, and a complete public voting API are still not closed.

The accepted ballot proof path still needs soundness accounting, zero-knowledge accounting, Fiat-Shamir/QROM accounting, accepted binary proof transport, accepted randomness boundaries, and supported-phone proof verification. The accepted evaluator and target-decryption path still needs bounded-domain all-`K_top` replay, target share proof certification, C1-C4 target-decryption closure, public recombination integration, and supported-phone evidence.

Do not treat internal package names, private workspace commands, fixture evidence, native runs, Node/WASM runs, desktop browser runs, or mobile-emulated browser runs as stable public APIs or supported-phone evidence.

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
