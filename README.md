# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Its public package is intentionally narrow while the protocol implementation is still being built and verified.

## What the package exposes

`sealed-lattice` package currently exposes safe-by-default helpers for:

- transcript-core fixture verification through the packaged Rust/WASM kernel;
- poll-spec validation, canonical poll/profile hash derivation, threshold profile derivation, and frozen roster-profile derivation;
- lifecycle labels, lifecycle transitions, and action capability checks;
- signed board consistency, cast receipt shells, close record shells, and target finality checks;
- roster manifest verification, participant roster acceptance, deterministic first-valid ordering, and recovery-epoch checks;
- verification-oriented ballot privacy APIs for receiver-key proofs, ballot proof records, and proof-byte-bearing scoped relation packages through the packaged Rust/WASM verifier;
- aggregate derivation component verification for the scoped post-close aggregate derivation relation, without exposing aggregate shares, aggregate histograms, exact aggregate scores, aggregate score bits, openings, quotients, plaintext comparison inputs, receiver plaintexts, or proof witnesses;
- a fail-closed `verifyBridgeProof` placeholder for the encrypted aggregate bridge. Internal bridge evidence exists, but the public SDK verifier remains unavailable until the claim-appropriate verifier contract, canonical-lift/key/entropy gates, target-threshold decryptability boundary, setup/evaluator integration, and package-boundary checks are complete.

Reserved complete-protocol entry points such as transcript verification, bridge-proof creation, bridge-proof acceptance, and one-shot share-policy verification currently fail closed with `OperationUnavailable`.

```ts
import {
    validatePollSpec,
    verifyAggregateDerivationComponent,
    verifyBridgeProof,
    verifyClaimBearingBallotPackage,
    verifyTranscriptCoreFixture,
} from "sealed-lattice";
```

## Current implementation status

The public package is a verification surface, not a complete voting API. It can verify transcript-core fixtures, election-foundation objects, receiver-key proof records, ballot proof records, proof-byte-bearing scoped relation packages, and scoped aggregate-derivation components when the caller supplies the required public verifier inputs.

Current accepted ballot package dimensions are:

- 2 to 20 options;
- `shareVectorWidth = 11 * optionCount`;
- `n = 20` as the mandatory benchmark receiver count;
- dynamic frozen receiver counts from 10 to 50 only when the statement carries bound roster-profile evidence;
- explicitly acknowledged 3 to 9 receiver casual micro-roster verification only outside claim-bearing package acceptance.

The workspace also contains internal ballot-privacy, aggregate-derivation, BGV-RNS, encrypted aggregate bridge, and top-k evaluator evidence. Those pieces remain internal implementation evidence unless explicitly exposed above. Bridge proof acceptance, claim-bearing evaluation, target decryption, CPAD, supported-phone evidence, active-malicious closure, and production result release remain unavailable. The detailed implementation ledger is [implementation-documentation/CURRENT_STATUS.md](implementation-documentation/CURRENT_STATUS.md).

Still unavailable:

- public ballot generation or casting APIs;
- generated certificate/workbook rows and benchmark evidence for every dynamic frozen roster size and every casual micro-roster benchmark profile that later evaluation chooses to measure;
- encrypted aggregate bridge closure from committed aggregate shares to encrypted aggregate input data, preserving bridge witness privacy;
- claim-bearing top-k evaluation on production collective keys and accepted encrypted aggregate inputs, a modulus chain that fits the full 20-option evaluator depth, the mandatory post-quantum evaluation proof, and target acceptance;
- production target-bound decryption and result release.

## What is internal

Several protocol components exist only as workspace-internal implementation, test, or vector infrastructure:

- plaintext `GF(65537)` arithmetic, Shamir interpolation, top-k tallying, and sparse target fixtures;
- deterministic PVSS ballot-algebra helpers used for regression tests;
- ballot privacy profile, relation, proof-record, receiver-key proof, and scoped relation package shell infrastructure;
- sealed-lattice Rust/WASM BGV-RNS profile, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext-lifted base conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, object validation, and allowed-operation registry for the encrypted aggregate path;
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- offline proof-oracle comparison tooling, development-only Lattigo oracle tooling, and generated public test vectors.

These pieces are not exported as a public voting API and must not be used for real ballot secrecy.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  docs/                         Public documentation site
  implementation-documentation/ Internal protocol notes
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

Run the full local validation gate (the pre-commit hook runs this):

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, then runs the type-check, lint, public API snapshot, public package policy, package-boundary, vector, dead-code, and Rust format/clippy/test checks together with the fast Node test lane. The build and type-check run first because they emit `dist/`; every other lane runs in parallel against that built output, and the first lane to fail aborts the rest. The heavier protocol and kernel Node projects and the Playwright browser projects are not in this gate; run `pnpm run test:node` and `pnpm run test:browser` before a push. It ends with a per-lane pass/fail summary and writes per-lane logs under `logs/` unless you pass `--no-run-log`.

Run targeted verification:

```bash
pnpm run vectors
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run test:proof-benchmark
pnpm run test:proof-benchmark:node
pnpm run test:proof-benchmark:browser:desktop
pnpm run test:encrypted-aggregate-bridge:representative
pnpm run test:encrypted-aggregate-bridge
pnpm run verify:docs
```

The default Node test command runs the fast Node project plus the heavy protocol and kernel projects. The Node coverage command covers the fast Node project only; heavy protocol, kernel, and proof-benchmark flows still run through their explicit non-coverage lanes. `pnpm run coverage:badge` runs the Node coverage lane, writes Shields-compatible coverage JSON into `docs/public`, and the Pages workflow publishes that JSON with the docs site for the README badge. The proof benchmark command builds once, then runs the Node and desktop Chromium benchmark projects concurrently; the desktop Chromium lane mirrors the Node lane one-to-one. Use the individual proof-benchmark commands on separate CI workers when you want to isolate a single runtime.

Heavy local runners write timestamped logs under `logs/`, which is gitignored. Logged runners include `pnpm run check`, `pnpm run test:node:protocol`, `pnpm run test:node:kernel`, `pnpm run test:node`, `pnpm run test:browser`, all proof-benchmark scripts, and the encrypted aggregate bridge matrix scripts. Each run gets `logs/YYYY-MM-DD/YYYY-MM-DDTHH-mm-ss-SSSZ-script-name/` with `metadata.json`, `summary.json`, `combined.log`, and per-command logs; matrix runs also write per-row worker logs under `workers/`. CI disables local log emission by passing `--no-run-log`; use the same trailing argument locally when a one-off run should skip logs, for example `pnpm run test:node:kernel -- --no-run-log`.

Heavy ballot privacy proof flows write resumable development checkpoints to `temp/test-checkpoints/`. Checkpoint filenames are named after their test suite and step. Set `SEALED_LATTICE_RESUME_TEST_CHECKPOINTS=1` only when intentionally debugging from the latest local checkpoint.

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
