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
- verification-oriented `verifyBridgeProof` support for encrypted aggregate bridge evidence through the packaged Rust/WASM verifier. Internal bridge evidence includes checked integer-lifted plaintext encoding, proof-friendly plaintext coefficient binding, target-threshold decryptability compatibility under the passive setup key, full aggregate-derivation verification binding when close/counting context is supplied, five-check shared-witness challenge-context binding with a 159-bit effective classical random-oracle handoff floor, explicit QROM-not-provided status for this handoff proof, coefficientwise BGV randomness/error support accounting, relation proof closure-field refusal, randomness-source evidence consistency checks, and bridge proof-record refusal when a verified statement hash or verifier output is spliced onto mutated canonical ciphertext, aggregate-selection policy, witness-privacy profile, or HE-parameter inputs. Representative selected bridge contributors now verify as decryptable setup-key-compatible bridge handoff evidence; refreshed full-matrix evidence, claim-bearing evaluator integration, and production result release remain unavailable.

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

Still unavailable:

- public ballot generation or casting APIs;
- generated certificate/workbook rows and benchmark evidence for every dynamic frozen roster size and every casual micro-roster benchmark profile that later evaluation chooses to measure;
- refreshed full-matrix encrypted aggregate bridge closure evidence from committed aggregate shares to encrypted aggregate input data, preserving bridge witness privacy;
- accepted-input sparse-target oracle success for every supported top count, a claim-bearing masked rank refresh or equivalent target-profile fix for the current projection noise gap, release-grade runtime evidence for the 20-option evaluator beyond the current public representative sweeps, the mandatory post-quantum evaluation proof, target-decryption security, and target acceptance;
- production target-bound decryption and result release.

## What is internal

Several protocol components exist only as workspace-internal implementation, test, or vector infrastructure:

- plaintext `GF(65537)` arithmetic, Shamir interpolation, top-k tallying, and sparse target fixtures;
- deterministic PVSS ballot-algebra helpers used for regression tests;
- ballot privacy profile, relation, proof-record, receiver-key proof, and scoped relation package shell infrastructure;
- sealed-lattice Rust/WASM BGV-RNS profile, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext-lifted base conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, object validation, and allowed-operation registry for the encrypted aggregate path;
- scoped passive setup HE-security evidence for the data-basis setup/bridge/evaluator path, plus setup-bound algebraic threshold LSSS share-verification roots and rank-refresh validation for a canonical setup-threshold share-selection rule, selected algebraic share-verification key binding records, trustee public-key share coefficient sidecar payloads, a canonical public input-rank ciphertext component-one payload, public masked partial-decryption share payloads, a public same-secret `PartDec` linear-relation statement tying the selected setup share-verification key binding, setup public key-share sidecar, input rank component-one payload, and partial-decryption share payload together, a `PartDec` linear-proof backend adapter and backend-input object that bind the correctly signed public source-matrix and target-vector coefficient hashes, per-data-prime parameter/encoding shape, setup-distribution and smudging-certificate-derived witness coefficient and L2 bounds, verifier-derived public randomness for the public-key-share and masked-share equations, a nested capacity-exceeded masked-share backend input that separately binds the one-row smudging relation against input component one, partial-decryption share, selected key binding, smudging certificate, statement and adapter roots, challenge-domain hash, and exact decimal witness bound, a nested capacity-fit public-key-share consistency backend input for the small setup-share relation whose full per-prime linear-proof parameter and encoding objects are bound, whose centered signed source-modulus lift is bound in the encoding metadata, whose verified branch reconstructs the public streamed one-row statement and calls the shared streamed linear-proof verifier when proof bytes are supplied, whose deterministic setup witness passes the sidecar relation check, and whose manual closure-evidence tests generate and verify first-prime and all-data-prime per-prime proof bytes, and a split same-witness binding object that publicly binds both split input roots, challenge domains, public randomness, witness columns, witness-bound statuses, and the shared trustee secret-share obligation while default fixtures remain pending until same-witness proof verification and the remaining proof-bearing refresh relations are wired, a canonical public `FinDec` Lagrange coefficient audit for the selected interpolation set, a public `FinDec` masked-opening payload whose input ciphertext component zero plus selected-share Lagrange combination is checked, a smudging-bound public bit-budget statement whose selected-share combination bound depends on the coefficient audit and whose final-noise bits must fit `B_final < Q_data/(2*p)`, canonical public mask-commitment and mask-encryption randomness evidence records plus encrypted-mask and refreshed-rank ciphertext payloads bound into the mask re-encryption proof statement with a challenge-domain hash and derived public randomness, and proof-byte hash/size/public-statement metadata whose full `PartDec`, claim-bearing `FinDec`, smudging, and mask re-encryption proof relations are still pending;
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

`pnpm run check` builds the workspace once, then runs the type-check before launching the independent docs, package-smoke, lint, package-policy, vector, knip, API summary, boundary, and fast Node lanes in parallel against that built output. The package-policy lane rejects forbidden runtime exports and direct SDK type exports for setup, evaluator, witness, raw BGV, and decryption construction surfaces. The Rust formatting, clippy, and test lane runs afterward in isolation, so memory-heavy Rust tests do not compete with docs rendering, linting, package smoke verification, and Node tests. The build and type-check run first because they emit `dist/`; the docs and package-smoke lanes reuse those artifacts instead of running their standalone rebuild scripts. The first independent lane to fail aborts the remaining work. It runs:

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

Use `pnpm run test:encrypted-aggregate-evaluator:representative` only after the fast aggregate runner has written a current request-base file. It prepares root-bound public evaluation-key material in process instead of serializing key-switch coefficients as JSON, runs the accepted-input encrypted aggregate evaluator through the shared-rank sweep command, and writes the public encrypted evaluator result under `temp/test-checkpoints/`. The representative sweep artifact and summary bind the normalized WASM hash, dependency artifact hash, evaluator source fingerprint, request-base hash, runner profile, and top-count coverage; checkpoint-bound oracle diagnostics reject artifacts that do not carry that binding. The summary includes public artifact byte sizes, shared packed-rank and sparse-target ciphertext byte lengths, setup key-size certificate extracts, operation-count extracts, and the measured Node/WASM runtime for that run. The single-run and sweep command boundaries reject malformed top-count sets plus witness/private evaluator fields before setup loading in native, Node WASM, and browser WASM coverage. It still defaults to the representative `topCount = 1` slice; pass `-- --top-counts all` only for heavyweight all-top-count release evidence after the cheaper gates are complete. Current full-profile representative slices are heavy: the 2026-06-02 accepted-input `topCount = 1` run took about 46 minutes locally, the 2026-06-03 unrefreshed `topCounts = 10,20` sweeps took about 50 to 109 minutes depending on the projection schedule, and the 2026-06-04 fresh `topCount = 10` slice took about 110 minutes. These are proposal/runtime evidence only. The latest checked-in projection schedule uses rank-lookup baby-step count 7, which lowers the rank-domain projection depth and exits the clean projection diagnostic at level 2; focused two-option and four-option tie fixtures pass. Fresh accepted-input oracle diagnostics still reject the unrefreshed `topCount = 10` sparse target, and a focused rank-lookup split search found no baby-step count from 2 through 20 that projects the accepted packed ranks correctly. A follow-up exact-rank target rewrite removed one final dense plaintext selector by carrying pre-weighted target-id and target-order rank contributions; the clean fixtures still passed, but a fresh WASM `topCount = 10` representative slice trapped after about 72.6 minutes, and a native release diagnostic completed in about 40.1 minutes with field-random sparse target identifiers. The `N = 32768` one-tail-prime candidate at `Q_data = 827` bits was also rejected: WASM still trapped on the representative `topCount = 10` slice, and native release completed but decrypted field-random sparse target identifiers. The accepted path needs a claim-bearing masked rank refresh, a different target relation, or a materially different accepted parameter profile before all-supported target projection, full bridge matrix, full browser parity, and benchmark lanes.
The kernel now exposes a masked rank-refresh profile and transcript-verification command that requires a setup package, binds setup roots, threshold verification-key roots, setup-bound algebraic LSSS share-verification roots, selected algebraic share-verification key binding records, trustee public-key share coefficient sidecar roots and payloads, a canonical public input-rank ciphertext component-one payload, public masked partial-decryption share payloads, evaluator context, rank roots, target layout, a canonical share-selection rule that must select exactly the setup decryption threshold from first-valid trustees in canonical board order, threshold-selected share records, nested `PartDec` share-equation proof statements with a public same-secret linear-relation statement, linear-proof backend adapter, and linear-proof backend input, a canonical `FinDec` Lagrange coefficient audit, a `FinDec` masked-opening statement and public masked-opening payload, a smudging-bound certificate, canonical public mask-commitment and mask-encryption randomness evidence records, encrypted-mask and refreshed-rank ciphertext payloads, a mask re-encryption proof statement that binds those payload hashes and roots, the mask commitment root, the randomness evidence hash, a verifier-derived challenge-domain hash, and public randomness derived from that challenge-domain hash, and canonical nonempty proof-byte hash/size/public-statement metadata for those proof-bearing objects, and rejects plaintext/private rank leakage. The input-rank payload is parsed from canonical BGV ciphertext bytes, checks its ciphertext root, canonical byte hash/length, parsed component-one residues, and published coefficient tables, and is bound into partial-share payloads and nested `PartDec` statements. Each selected share carries a canonical selected algebraic share-verification key binding root, and the share record, nested `PartDec` proof, `PartDec` relation statement, `FinDec` coefficient audit, and `FinDec` combiner arrays must agree on it. The `PartDec` relation statement binds the selected key binding root, setup public key-share sidecar hashes, input rank component-one table hashes, partial-decryption share table hashes, smudging-bound root, and freshness hash to the same trustee identity and roster position; its backend adapter binds the two-row public linear-proof source matrix and correctly signed target vector for public-key-share consistency plus masked partial decryption, including setup-derived common-random coefficients, `-p`, zero, input component one, one, `componentZeroB`, and `-partialDecryptionShare`. The backend input binds that adapter root, the relation-statement root, per-data-prime parameter/encoding shape, proof-byte source, verifier-derived public randomness from the challenge-domain hash, and exact witness coefficient and L2 bounds derived from the owner-routed ternary secret-share bound, eta-2 error-share bound, and smudging certificate. It also records and checks that this full-profile bound exceeds the current linear-proof backend's 128-bit witness-bound parameter capacity. A nested masked-share backend input separately binds the one-row smudging equation against input component one, partial-decryption share, selected key binding, smudging certificate, relation statement root, adapter root, challenge-domain hash, per-prime source/target hashes, and exact decimal witness bound `N*(secretShareCoefficientBound^2+smudgingNoiseCoefficientBound^2)`; it remains verifier-pending because that bound exceeds the current backend capacity. A nested public-key-share consistency backend input separately binds the one-row, two-witness relation against setup-derived common-random coefficients, `-p`, and `componentZeroB`, with witness bound `N*(1^2+2^2)`, full per-prime linear-proof parameter and encoding objects, centered signed source-modulus representation metadata, a capacity-fit status, an explicit pending proof-verification status, and a false proof-byte verification flag. If that nested public-key-share input is marked verified, the verifier requires per-prime proof bytes, checks their canonical proof-byte hash and size, reconstructs the public streamed statement from setup and sidecar material, and calls the shared streamed linear-proof verifier under the rank-refresh split profile. A split same-witness binding now ties the public-key-share and masked-share split inputs to the same trustee identity, selected algebraic key binding, statement and adapter roots, split input roots, challenge domains, public randomness fields, witness columns, witness-bound statuses, and shared `trusteeSecretShare` obligation while still requiring a future same-witness proof. The checked fixture proves that the deterministic setup witness satisfies the sidecar relation, and ignored manual closure-evidence tests generate first-prime and all-data-prime public-key-share proof bytes, verify them through that streamed verifier path, and reject recomputed-hash or single-prime proof mutations. The default fixture still stays pending because same-witness proof verification across the public-root-bound split `PartDec` inputs, proof-verified masked-share smudging relation, claim-bearing `FinDec` masked-opening proof/correctness, Appendix B smudging/noise-bound proof, and mask re-encryption proof are not wired end to end. The mask re-encryption side now requires a public mask commitment record and a non-claim-bearing mask-encryption randomness evidence record, rejects raw mask plaintext or randomness export, parses the ciphertext payloads from canonical BGV ciphertext bytes, checks ciphertext roots, canonical byte hashes/lengths, setup/public-key/layout/context roots, and role-specific transcript aliases, binds those records plus both ciphertext payloads into the proof record and proof statement, and rejects stale challenge-domain hash or public-randomness fields. The `FinDec` coefficient audit now derives and roots every per-data-prime selected-share Lagrange coefficient from the selected trustee roster positions; the smudging certificate, `FinDec` statement, and masked-opening payload must bind that audit root. The `FinDec` payload recombines the public masked partial-decryption share polynomials with the parsed input ciphertext component zero and rejects masked-opening coefficients that do not match `c0 + sum(lambda_i * PartDec_i) mod q`. The smudging-bound certificate now carries checked ceil-log2 bit-budget fields for `Q_data`, `p`, selected share count, maximum Lagrange coefficient bits, selected-share combination bits, `B_final`, and the correctness margin, and rejects public statements where `B_final` does not fit `Q_data/(2*p)`. It still fails closed after setup-bound share-selection, selected key binding, public sidecar payload, input-rank component-one payload, partial-share payload, `PartDec` adapter and backend-input validation, coefficient-audit validation, masked-opening payload, smudging bit-budget validation, mask-commitment, mask-encryption randomness evidence, mask-re-encryption ciphertext-payload validation, proof-byte metadata, and statement validation until the bound algebraic material has claim-bearing zero-knowledge `PartDec` share-equation verification, `FinDec` masked-opening proof/correctness verification, Appendix B smudging/noise-bound verification, and mask re-encryption proof support. Accepted evaluator requests may name `rankRefreshTranscript`, but native, Node WASM, and browser WASM boundaries reject it before setup loading until that share verifier is implemented.

Heavy checks should run selectively, only when the change touches the matching area or when closure/benchmark evidence is being refreshed:

- `pnpm run test:proof-benchmark`, `pnpm run test:proof-benchmark:node`, and `pnpm run test:proof-benchmark:browser:desktop` for proof benchmark evidence;
- `pnpm run test:encrypted-aggregate-evaluator:representative` for a selected accepted-input evaluator slice after aggregate-ready inputs exist, or `pnpm run test:encrypted-aggregate-evaluator:representative -- --top-counts all` for heavyweight all-top-count release evidence;
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
