# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Its public package is intentionally narrow while the protocol implementation is still being built and verified.

## What the package exposes

The published `sealed-lattice` package currently exposes safe-by-default helpers for:

- transcript-core fixture verification through the packaged Rust/WASM kernel;
- threshold profile derivation and poll-spec validation;
- lifecycle labels, lifecycle transitions, and action capability checks;
- signed board consistency, cast receipt shells, close record shells, and target finality checks;
- roster manifest verification, participant roster acceptance, deterministic first-valid ordering, and recovery-epoch checks;
- verification-oriented ballot privacy APIs for receiver-key proofs and ballot proof records, with scoped relation-bearing package shells kept fail-closed until package verification can rederive lowered relations and trusted public randomness.
- aggregate derivation component verification for the scoped post-close M6 relation, without exposing aggregate shares, openings, quotients, receiver plaintexts, or proof witnesses.

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
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- offline proof-oracle comparison tooling and generated public test vectors.

These pieces are not exported as a public voting API and must not be used for real ballot secrecy.

## Ballot privacy status

The ballot privacy implementation currently exposes verification-oriented APIs only. It can verify receiver-key proof records and ballot proof records through the packaged Rust/WASM proof backend, but scoped relation-bearing package verification is fail-closed until the verifier can rederive the lowered relation statements and trusted public randomness from the package. It is not a complete voting API and is not supported-phone-certified.

Implemented internally:

- frozen ballot privacy profile objects and digest namespaces;
- encoded score-share layout metadata for scalar score coordinates plus hidden one-hot score-bucket coordinates;
- relation lowering for score/Shamir rows, receiver-payload plaintext binding, share-commitment rows, receiver-encryption structure, and receiver-key binding;
- receiver-key proof records with proof-byte metadata and Rust/WASM verification for supported linear proof vectors;
- ballot proof records that bind backend statements, component proof bundles, proof bytes, proof encodings, proof parameter sets, and public randomness;
- scoped relation-bearing ballot package shell validation that recomputes the package digest, requires accepted receiver-key proof root evidence, checks receiver coverage, rejects witness leakage, and then rejects package acceptance until verifier-derived lowering and trusted public randomness checks exist;
- aggregate derivation statements and components that bind a canonical post-close counted set of proof-byte-bearing package shells, contributor identity, homomorphic aggregate share commitment, full encoded share layout, no-wraparound certificate, and Rust/WASM proof bytes for hidden aggregate opening knowledge;
- native and WASM verification of public vectors for the supported internal linear proof slices and full encoded-score package path.

Still unavailable:

- public ballot generation or casting APIs;
- the encoded aggregate bridge and `ScoreBitAggregationRelation-v1` encrypted score-bit input path;
- the packed bit-sliced BGV evaluator and mandatory evaluation proof;
- production target-bound decryption and result release.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  docs/                         Public documentation site
  implementation-documentation/ Internal protocol planning notes
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
