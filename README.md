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
- verification-oriented `verifyBridgeProof` support for encrypted aggregate bridge evidence through the packaged Rust/WASM verifier. Internal bridge evidence includes checked integer-lifted plaintext encoding, proof-friendly plaintext coefficient binding, target-threshold decryptability compatibility under the passive setup key, full aggregate-derivation verification binding when close/counting context is supplied, five-check shared-witness challenge-context binding with a 159-bit effective soundness floor, relation proof closure-field refusal, and randomness-source evidence consistency checks. Representative selected bridge contributors now verify as claim-bearing bridge encryption under the decryptable setup key; refreshed full-matrix evidence, claim-bearing evaluator integration, and production result release remain unavailable.

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

The workspace also contains internal ballot-privacy, aggregate-derivation, BGV-RNS, encrypted aggregate bridge, and top-k evaluator evidence, including compact evaluator checks that keep bridge key, claim-status, proof-context roots, and fresh randomness-source evidence consistent across accepted bridge input records. Passive BGV setup now binds compact public collective-key coefficient byte strings directly in the setup package, so bridge encryption consumes package-bound public key material rather than re-expanding it from the public setup seed hash; secret/error sampling has a separate private setup witness that is not exported in the public setup package. Setup can now emit public evaluation-key material sidecars from the private witness, prepare root-bound in-process public evaluation-key handles for accepted-input evaluator slices that must avoid giant coefficient JSON, default omitted rotation requests to the selected evaluator rotation schedule for the requested working level through the same internal schedule helper used by the evaluator, and reject duplicate rotation requests before key material generation. The setup package commits the full selected relin/rotation schedule and target layout hash, and a manual representative full-level sidecar check exercises every relin level plus selected rotations from both required rotation levels without exposing the private witness. The encrypted evaluator consumes public material or a prepared public-material handle instead of accepting the private witness itself. The public-material consumer explicitly binds setup, collective-key, BGV-key, decomposition, rotation-set, and evaluation-key roots and rejects secret fields, duplicate key material, and missing generator-basis rotation keys before encrypted evaluation starts. The encrypted evaluator command requires selected encrypted aggregate inputs that carry accepted aggregate contributions plus bridge evidence verification, together with a supplied mandatory 20-option, 20-receiver aggregate-ready record and explicit canonical hashes for the ballot set, pre-target board head, and evaluator signature; it rejects reduced option counts, reduced setup rosters, reduced aggregate-ready roster sizes, reduced score-domain requests, development randomness evidence, drifted bridge proof context, setup-profile drift, malformed roster/quorum handoff, selected-contributor identity drift, rehashed bridge proof records or aggregate contributions, aggregate-contribution public-field drift against the nested bridge proof record, rehashed aggregate-ready records with wrong selected-order or reconstruction roots, wrong setup target layout, plaintext target/rank artifacts, public score-bit/comparison fixtures, development key material, trusted-dealer or full-secret material, raw or threshold secret shares, target-decryption shares, incoming proof-verified or target-accepted claims, private setup or proof witnesses, and unbound top-level request fields on this accepted-input path. The command now emits encrypted top-k bundle and sparse target ciphertext artifacts without decoded targets or ranks; their canonical bytes are root-bound by the top-k and target ciphertext digests, which also bind the target layout, sparse projection profile, public mask, output encoding, option count, and top-count. Earlier public-binding score-ciphertext and raw verifier-on-the-fly shortcuts are not accepted input shapes. This is still not claim-bearing evaluation closure because full-profile accepted-input runs for every supported top-count, complete native/WASM parity, the release negative sweep, and benchmarks remain open. The packed direct-comparison evaluator remains internal implementation evidence and now uses a 17-prime data chain, one pre-comparison modulus-switch refresh, and a fixed Paterson-Stockmeyer comparison schedule with baby-step count 31 for the score-domain-200 profile; the selected setup rotation schedule now materializes 20 compact generator-basis keys, covering 39 logical aggregate-score packing rotations, 19 logical full-level packed-rank shifts, and 19 logical comparison-output return shifts by composition. Full bridge matrix refresh, claim-bearing evaluation, target decryption, CPAD, supported-phone evidence, active-malicious closure, and production result release remain unavailable. This README is the public implementation ledger for the package boundary.

Still unavailable:

- public ballot generation or casting APIs;
- generated certificate/workbook rows and benchmark evidence for every dynamic frozen roster size and every casual micro-roster benchmark profile that later evaluation chooses to measure;
- refreshed full-matrix encrypted aggregate bridge closure evidence from committed aggregate shares to encrypted aggregate input data, preserving bridge witness privacy;
- claim-bearing top-k evaluation on production collective keys and accepted encrypted aggregate inputs, accepted full-profile noise/runtime evidence for the 20-option evaluator, the mandatory post-quantum evaluation proof, and target acceptance;
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

`pnpm run check` builds the workspace once, then runs the type-check before launching the independent docs, package-smoke, lint, package-policy, vector, knip, API summary, boundary, and fast Node lanes in parallel against that built output. The Rust formatting, clippy, and test lane runs afterward in isolation, so memory-heavy Rust tests do not compete with docs rendering, linting, package smoke verification, and Node tests. The build and type-check run first because they emit `dist/`; the docs and package-smoke lanes reuse those artifacts instead of running their standalone rebuild scripts. The first independent lane to fail aborts the remaining work. It runs:

- workspace package build;
- workspace type-check;
- lint;
- generated docs, docs link verification, and rendered docs smoke verification;
- npm package smoke verification;
- public API surface summary generation;
- public package policy verification;
- package-boundary verification;
- test vector verification;
- dead-code scan;
- Rust formatting, clippy, and tests;
- fast Node tests.

The heavier protocol and kernel Node projects and the Playwright browser projects are not in this gate; run `pnpm run test:node` and `pnpm run test:browser` before a push. Locally, it shows a live progress view with elapsed time, latest captured output, previous successful check duration when local history is available, command counts for real command-series lanes, Turbo task visibility for the build lane, Vitest test progress for the fast Node lane, and libtest test progress for the Rust test command. Pass `--progress=always` to use the live view when stdout is a terminal, or `--progress=never` for plain logs. The pre-commit hook redirects the check command to `/dev/tty` when Git gives the hook a non-terminal stdout. It ends with a per-lane pass/fail summary and writes per-lane logs under `logs/` unless you pass `--no-run-log`; failures also print the failed command, exit code, log path, and recent captured output.

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
pnpm run test:aggregate-derivation-kernel
pnpm run test:encrypted-aggregate-evaluator:representative
pnpm run test:encrypted-aggregate-bridge:representative
pnpm run test:encrypted-aggregate-bridge
pnpm run verify:docs
```

The default Node test command runs the fast Node project plus the heavy protocol and kernel projects. The Node coverage command covers the fast Node project only; heavy protocol, kernel, and proof-benchmark flows still run through their explicit non-coverage lanes. `pnpm run coverage:badge` runs the Node coverage lane, writes Shields-compatible coverage JSON into `docs/public`, and the Pages workflow publishes that JSON with the docs site for the README badge.

Use `pnpm run test:aggregate-derivation-kernel` for aggregate-derivation, aggregate-bridge, and aggregate-ready iteration. It has one fast mode only: representative selected contributors through verified aggregate-ready record construction, with 8 workers by default. Bridge contributor generation and verification now pass the full aggregate-derivation close/counting context, so recomputed bridge checkpoints bind `AggregateDerivationFullVerificationChecked`; cached checkpoints remain development accelerators and are labeled as cached CSPRNG artifacts when reused. The runner always tries checkpoints under `temp/test-checkpoints/` first, ignores stale or corrupt checkpoints, and recomputes only the affected stage. It writes the latest setup package, selected encrypted aggregate inputs, aggregate-ready record, and evaluator request base under the checkpoint directory so a separate manual evaluator slice can consume real bridge outputs. Supported flags are `--workers <count>`, `--checkpoint-dir <path>`, and `--force-recompute ballot-package|bridge-contributors|bgv-passive-setup`; full-matrix, encrypted evaluator, all-`K`, no-resume, and require-checkpoint modes are intentionally not available through this runner.

Use `pnpm run test:encrypted-aggregate-evaluator:representative` only after the fast aggregate runner has written a current request-base file. It prepares root-bound public evaluation-key material in process instead of serializing key-switch coefficients as JSON, runs one representative encrypted aggregate evaluator slice for `topCount = 1` by default, and writes the public encrypted evaluator result under `temp/test-checkpoints/`. It is not a full bridge matrix, all-top-count sweep, browser parity run, or benchmark lane.

Heavy checks should run selectively, only when the change touches the matching area or when closure/benchmark evidence is being refreshed:

- `pnpm run test:proof-benchmark`, `pnpm run test:proof-benchmark:node`, and `pnpm run test:proof-benchmark:browser:desktop` for proof benchmark evidence;
- `pnpm run test:encrypted-aggregate-evaluator:representative` for a selected accepted-input evaluator slice after aggregate-ready inputs exist;
- `pnpm run test:encrypted-aggregate-bridge:representative` for selected encrypted aggregate bridge rows;
- `pnpm run test:encrypted-aggregate-bridge` for the full encrypted aggregate bridge matrix;
- `pnpm run test:node:kernel`, `pnpm run test:node`, and `pnpm run test:browser` for heavy Rust/WASM and browser integration coverage.

Heavy local runners write timestamped logs under `logs/`, which is gitignored. Logged runners include `pnpm run check`, `pnpm run test:node:protocol`, `pnpm run test:node:kernel`, `pnpm run test:node`, `pnpm run test:browser`, all proof-benchmark scripts, and the encrypted aggregate bridge matrix scripts. Each run gets `logs/YYYY-MM-DD/YYYY-MM-DDTHH-mm-ss-SSSZ-script-name/` with `metadata.json`, `summary.json`, `combined.log`, and per-command logs; matrix runs also write per-row worker logs under `workers/`. The check runner stores detailed command timing data in the local summary so later local check runs can show expected durations. CI disables local log emission by passing `--no-run-log`; use the same trailing argument locally when a one-off run should skip logs, for example `pnpm run test:node:kernel -- --no-run-log`.

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
