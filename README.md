# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Its public package is intentionally narrow while the protocol implementation is still being built and verified.

## Prototype API policy

This repository is an early prototype and is not in production use. Public API stability is not protected for legacy consumers yet; obsolete labels, helper-role surfaces, and compatibility-only names are removed when they conflict with the current documentation and claim boundaries. Existing v1 transcript digest namespaces remain only where current vectors require them, while new public-facing names use Hash terminology.

## What the package exposes

The published `sealed-lattice` package currently exposes safe-by-default helpers for:

- transcript-core fixture verification through the packaged Rust/WASM kernel;
- poll-spec validation, canonical poll/profile Hash-facing derivation over v1 transcript digest namespaces, threshold profile derivation, and frozen roster-profile derivation;
- compact lifecycle labels, structured status reasons, lifecycle transitions, and action capability checks;
- signed board consistency, cast receipt shells, close record shells, and target finality checks;
- roster manifest verification, participant roster acceptance, deterministic first-valid ordering, and recovery-epoch checks;
- verification-oriented ballot privacy APIs for receiver-key proofs, ballot proof records, and proof-byte-bearing scoped relation packages through the packaged Rust/WASM verifier;
- aggregate derivation component verification for the scoped post-close M6 relation, without exposing aggregate shares, aggregate histograms, exact aggregate scores, aggregate score bits, openings, quotients, plaintext comparison inputs, receiver plaintexts, or proof witnesses.

Reserved complete-protocol entry points such as transcript verification, bridge-proof creation, bridge-proof verification, and one-shot share-policy verification currently fail closed with `OperationUnavailable`.

```ts
import {
    validatePollSpec,
    verifyAggregateDerivationComponent,
    verifyClaimBearingBallotPackage,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

## What is internal

Several protocol components exist only as workspace-internal implementation, test, or vector infrastructure:

- plaintext `GF(65537)` arithmetic, Shamir interpolation, top-k tallying, and sparse target fixtures;
- deterministic PVSS ballot-algebra helpers used for regression tests;
- ballot privacy profile, relation, proof-record, receiver-key proof, and scoped relation package shell infrastructure;
- M7 sealed-lattice Rust/WASM BGV-RNS profile, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext-lifted base conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, encrypted aggregate input layout binding, object validation, allowed-operation registry, and report commands for the encrypted aggregate path;
- M8 passive full-roster BGV setup commands, including participant setup records, public-key share roots, collective public key roots, KLLPS-compatible threshold verification roots, provisional relin/rotation/key-switch evaluation-key roots, actual secret/error distribution certificates, public RLWE sample accounting, setup parameter certificates, evaluation-key-size reports, and development encryption fixtures;
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- offline proof-oracle comparison tooling, development-only Lattigo oracle tooling, and generated public test vectors.

These pieces are not exported as a public voting API and must not be used for real ballot secrecy.

## Ballot privacy status

The ballot privacy implementation currently exposes verification-oriented APIs only. It can verify receiver-key proof records, ballot proof records, and proof-byte-bearing scoped relation packages through the packaged Rust/WASM proof backend. Package verification requires the public verifier inputs carried with the package shell and is not a complete voting API or measured runtime profile-certified result.

The public status surface uses compact claim labels such as `pending`, `rosterFrozen`, `ballotSubmitted`, `targetAccepted`, `evaluationProofVerified`, `cpadProfileVerified`, `fullyVerified`, `forkDetected`, and `outsideClaim`, with structured reasons for missing evidence or outside-claim cases. Local replay is diagnostic only and never accepts a target or replaces the mandatory evaluation proof.

Successful M6 aggregate derivation proof generation and component verification still report `pending`, because the encrypted aggregate bridge, evaluation proof, target acceptance, threshold decryption, CPAD closure, and final result claims remain unavailable.

Current M5 dimensions are: 2 to 20 options; `shareVectorWidth = 11 * optionCount`; `n = 20` as the mandatory benchmark receiver count; dynamic frozen receiver counts from 10 to 50 only when the ballot proof statement carries bound roster-profile evidence; and explicitly acknowledged 3 to 9 receiver casual micro-roster verification only outside claim-bearing package acceptance. The casual micro-roster path has verifier and proof-record generation harness coverage for every receiver count from 3 through 9, but claim-bearing package acceptance still rejects those rosters. Current proof-size and runtime benchmark evidence has only been run for the mandatory `n = 20`, `m = 20`, threshold-7 profile; micro-roster and dynamic-roster benchmark evidence remains future full-suite work.

Implemented internally:

- frozen ballot privacy profile objects and digest namespaces;
- encoded score-share layout metadata for scalar score coordinates plus hidden one-hot score-bucket coordinates;
- relation lowering for score/Shamir rows, receiver-payload plaintext binding, share-commitment rows, receiver-encryption structure, and receiver-key binding;
- receiver-key proof records with proof-byte metadata and Rust/WASM verification for supported linear proof vectors;
- ballot proof records that bind backend statements, component proof bundles, proof bytes, proof encodings, proof parameter sets, and public randomness;
- scoped relation-bearing ballot package verification that recomputes the package digest, requires accepted receiver-key proof root evidence, checks receiver coverage, rejects witness leakage, binds the full ballot relation to the supplied component bundle, and verifies the top-level and component proof bytes;
- aggregate derivation statements and components that bind a canonical post-close counted set of proof-byte-bearing package shells, voting-closed close-record evidence, contributor action context, contributor identity, homomorphic aggregate share commitment, full encoded share layout, no-wraparound certificate, and Rust/WASM proof bytes for hidden aggregate opening knowledge. Component verification reruns the counted packages through the accepted M5 Rust/WASM package verifier, recomputes the aggregate package references, ballot-set digest, and public aggregate commitment sum, and rejects public leakage of aggregate histograms, exact aggregate scores, aggregate score bits, plaintext comparison inputs, and raw aggregate witnesses;
- native and WASM verification of public vectors for the supported internal linear proof slices and full encoded-score package path, including LaZer-oracle parity for canonical matrix and target coefficient representations.
- M7 BGV-RNS backend evidence is implemented internally for the selected v63 encrypted aggregate path: `N = 32768`, `p = 65537`, 16 selected 47-bit data primes, one 47-bit special prime, coefficient-domain canonical RNS objects, `PlaintextRoot`, `CiphertextRoot`, `BGVProfileDigest`, `BGVBatchEncoderDigest`, `BGVBatchEncoderLayoutBindingDigest`, allowed evaluator-operation registry, and M6-to-M7 encrypted aggregate input layout/report bindings. The pinned Lattigo oracle lane is development-only, builds from the verified archive rather than the mutable local checkout, and covers comparable all-selected-moduli ring/RNS/NTT and coefficient-arithmetic behavior only.
- M8 passive setup evidence is implemented internally for full-roster BGV setup. It emits transcript-bound participant setup roots, public-key share roots, collective key roots, KLLPS-compatible threshold verification material, provisional evaluation-key roots for the current M10 rotation set, actual collective-secret and error-distribution certificates, public RLWE sample counts, setup parameter certificates, and evaluation-key-size reports. M8 remains passive setup evidence only: it does not implement M9 bridge proofs, M10 evaluator closure, M12 evaluation proofs, KLLPS `PartDec`/`FinDec`, final Appendix B acceptance with `Q_target`, measured runtime closure, or active-malicious setup proofs.

Still unavailable:

- public ballot generation or casting APIs;
- generated parameter certificate rows and benchmark evidence for every dynamic frozen roster size and every casual micro-roster benchmark profile that later evaluation chooses to measure;
- the M9 encrypted aggregate bridge from committed aggregate shares to encrypted aggregate input, preserving bridge witness privacy;
- the M10 encrypted aggregate reconstruction, evaluator-side score-bit/comparison derivation, packed bit-sliced BGV evaluator, and mandatory evaluation proof;
- production target-bound decryption and result release.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  docs/                         Public documentation site
  implementation-documentation/ Internal protocol planning notes
  reference-projects/          Ignored development-only external reference checkouts
  packages/
    crypto/                     Internal canonical JSON, digests, signatures
    protocol/                   Internal protocol logic and reference paths
    sdk/                        Published sealed-lattice package
    testkit/                    Internal fixture loading helpers
    types/                      Shared TypeScript type declarations
    wasm/                       Internal WASM bridge package
  test-vectors/                 Canonical public regression vectors
  tools/                        CI, vector, packaging, and documentation tools
  typedoc/                      API documentation generation support
```

## Documentation

- [Documentation site](https://tenemo.github.io/sealed-lattice/)
- [Guides](https://tenemo.github.io/sealed-lattice/guides/)
- [Protocol spec](https://tenemo.github.io/sealed-lattice/spec/)
- [API reference](https://tenemo.github.io/sealed-lattice/api/)

## Installation

```bash
pnpm add sealed-lattice
```

The package is not a complete voting library yet. Treat it as a safe public verification surface for the implemented transcript-core fixture checks, election-foundation checks, and scoped ballot privacy verification APIs.

## Development

Install dependencies:

```bash
pnpm install
```

Run the main CI-equivalent check:

```bash
pnpm run check
```

`pnpm run check` builds first, then runs the static gate. Use `pnpm run check:static` after an explicit build when you only need lint, TypeScript, Rust, package-boundary, vector, and dead-code checks.

Run targeted verification:

```bash
pnpm run test:precommit
pnpm run vectors
pnpm run test:node:fast
pnpm run test:node:heavy
pnpm run test:node:heavy:kernel
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run test:proof-benchmark
pnpm run test:proof-benchmark:node
pnpm run test:proof-benchmark:browser:desktop
pnpm run test:proof-benchmark:browser:mobile:throttled
pnpm run verify:docs
```

The pre-commit test command runs the fast Node project plus desktop and mobile browser Vitest projects against already built output. The default Node test command runs the fast Node project plus the heavy protocol and kernel projects. The Node coverage command covers the fast Node project only; heavy protocol, kernel, and proof-benchmark flows still run through their explicit non-coverage lanes. The proof benchmark command builds once, then runs the Node and desktop Chromium benchmark projects sequentially to avoid benchmark worker memory contention on one machine. Use the individual proof-benchmark commands on separate CI workers when parallel resources are available. The mobile proof benchmark is throttled-only and manual-only through `pnpm run test:proof-benchmark:browser:mobile:throttled`.

Heavy ballot privacy proof flows write resumable development checkpoints to `temp/test-checkpoints/`. Checkpoint filenames are named after their test suite and step. Set `SEALED_LATTICE_RESUME_TEST_CHECKPOINTS=1` only when intentionally debugging from the latest local checkpoint.

Build and package-smoke the published SDK:

```bash
pnpm run build
pnpm run smoke:pack
pnpm run smoke:pack:npm
```

Install browser engines before the first local browser test run:

```bash
pnpm exec playwright install chromium firefox webkit
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
