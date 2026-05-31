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
- a fail-closed `verifyBridgeProof` placeholder for the encrypted aggregate bridge. Internal decryptable-convention bridge evidence now includes the full bridge matrix and negative suite, but the public SDK verifier remains unavailable until the claim-appropriate encrypted aggregate bridge verifier contract, canonical-lift/key/entropy gates, target-threshold decryptability boundary, setup/evaluator integration, and package-boundary checks are complete.

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

## Ballot privacy status

The ballot privacy implementation currently exposes verification-oriented APIs only. It can verify receiver-key proof records, ballot proof records, and proof-byte-bearing scoped relation packages through the packaged Rust/WASM proof backend. Package verification requires the public verifier inputs carried with the package shell and is not a complete voting API or supported-phone-certified result.

Current accepted ballot package dimensions are: 2 to 20 options; `shareVectorWidth = 11 * optionCount`; `n = 20` as the mandatory benchmark receiver count; dynamic frozen receiver counts from 10 to 50 only when the ballot proof statement carries bound roster-profile evidence; and explicitly acknowledged 3 to 9 receiver casual micro-roster verification only outside claim-bearing package acceptance. The casual micro-roster path has verifier and proof-record generation harness coverage for every receiver count from 3 through 9, but claim-bearing package acceptance still rejects those rosters. Current proof-size and runtime benchmark evidence has only been run for the mandatory `n = 20`, `m = 20`, threshold-7 profile; micro-roster and dynamic-roster benchmark evidence remains future full-suite work.

Implemented internally:

- frozen ballot privacy profile objects and digest namespaces;
- encoded score-share layout metadata for scalar score coordinates plus hidden one-hot score-bucket coordinates;
- relation lowering for score/Shamir rows, receiver-payload plaintext binding, share-commitment rows, receiver-encryption structure, and receiver-key binding;
- receiver-key proof records with proof-byte metadata and Rust/WASM verification for supported linear proof vectors;
- ballot proof records that bind backend statements, component proof bundles, proof bytes, proof encodings, proof parameter sets, and public randomness;
- scoped relation-bearing ballot package verification that recomputes the package digest, requires accepted receiver-key proof root evidence, checks receiver coverage, rejects witness leakage, binds the full ballot relation to the supplied component bundle, and verifies the top-level and component proof bytes;
- aggregate derivation statements and components that bind a canonical post-close counted set of proof-byte-bearing package shells, voting-closed close-record evidence, contributor action context, contributor identity, homomorphic aggregate share commitment, full encoded share layout, no-wraparound certificate, and Rust/WASM proof bytes for hidden aggregate opening knowledge. Component verification reruns the counted packages through the accepted ballot package Rust/WASM package verifier, recomputes the aggregate package references, ballot-set digest, and public aggregate commitment sum, and rejects public leakage of aggregate histograms, exact aggregate scores, aggregate score bits, plaintext comparison inputs, and raw aggregate witnesses;
- native and WASM verification of public vectors for the supported internal linear proof slices and full encoded-score package path.
- BGV-RNS backend evidence is implemented internally for the selected encrypted aggregate path: `N = 32768`, `p = 65537`, 16 selected 47-bit data primes, one 47-bit special prime, coefficient-domain canonical RNS objects, `PlaintextRoot`, `CiphertextRoot`, `BGVProfileDigest`, `BGVBatchEncoderDigest`, allowed evaluator-operation registry, and aggregate-derivation-to-BGV-RNS encrypted aggregate layout/profile bindings. This is backend and encoding evidence only, not setup, bridge closure, evaluator closure, decryption, CPAD, mobile certification, or active-malicious closure.
- Encrypted aggregate bridge internal decryptable-convention evidence exists for witness-clean bridge objects, private Rust/WASM bridge plaintext assembly, passive transcript-derived collective public-key coefficient binding, checked relation verification, checked proof-record/contribution assembly, and aggregate-ready handoff helpers. Setup, bridge, and evaluator development encryption now share the evaluator-compatible BGV convention `b = p*e - a*s`, `c0 = b*u + p*e0 + m`, `c1 = a*u + p*e1`; focused Rust tests decrypt first-limb bridge ciphertexts under the setup-derived collective secret, rebuild an evaluator key from setup-derived collective components, decrypt an evaluator ciphertext under the same convention, validate relinearization and Galois key-switch primitives from that setup-derived evaluator key, bind deterministic evaluation-key material stream commitments for the frozen direct-comparison packed-rank schedule, regenerate package-seeded relin and rotation keys from those commitments, reject the old raw-error formula, and the manual full data-prime bridge decryptability check passes. The bridge now uses an integer-lifted batch/plaintext same-witness relation over the first two BGV data primes, carries one plaintext-encoding quotient response per polynomial coefficient, rejects coherent dishonest plaintexts from different aggregate slots, and records a 165-bit effective same-witness binding floor after rejection-retry and full-matrix union-bound losses. On 2026-05-31 the full encrypted aggregate bridge matrix passed all 342 `(n, m)` rows and 8,508 negative checks, including representative 20-by-20 proof evidence, aggregate-ready evidence, private relation evidence, shared-witness zero-knowledge status, and BGV randomness-bound status. The encrypted aggregate bridge is still not closed: plaintext canonical-lift proof status remains `PlaintextCanonicalLiftProofMissing`, bridge evidence explicitly records `bgvEncryptionKeyMaterialKind: "passive-transcript-derived-collective-public-key"`, `developmentKeyOnly: false`, `thresholdDecryptable: false`, and `claimBearingBridgeEncryption: false`, where `thresholdDecryptable: false` means target-threshold decryption is not yet certified rather than a raw ciphertext-convention mismatch. Deterministic caller-supplied proof and encryption randomness seeds require explicit development acknowledgement and are not public entropy evidence, standalone bridge verification records that full aggregate derivation verification is a precondition, bridge claim closure remains open, and closure labels remain unavailable.
- A development BGV-RNS top-k evaluator is implemented internally: a leveled BGV evaluation engine (ciphertext addition, plaintext and scalar multiplication, ciphertext multiplication, relinearization, Galois rotation, and modulus switching with scaling-factor tracking), homomorphic Lagrange-weighted aggregate reconstruction, in-evaluator score-bit derivation by restricted-domain lookup polynomials, bit-sliced greater-than/equality comparison, direct encrypted score-difference comparison, ahead-indicator rank accumulation under the deterministic tie policy, and encrypted sparse `WinnerRankTopK-v1` target projection. Direct-comparison and bit-sliced runs now bind distinct comparison profiles, derivation hashes, evaluator-program hashes, and record fields, so a direct-comparison output cannot be described as the bit-sliced program. Target indicators and orders are evaluated as factored rank-prefix polynomials, removing the previous extra projection multiplication; the selected direct-comparison path now uses a depth-optimized power-table polynomial schedule and the certificate reports implemented depth 14 for the full score-domain-200 profile, while Paterson-Stockmeyer remains the lower-multiplication high-degree schedule for score-bit lookup evidence. Manual heavy packed slices now pack broadcast scores into generator-ordered slots, use real Galois rotations to compute direct-comparison ranks by evaluating each unordered option-pair distance once, verify packed target projection for two-option and four-option tie profiles, and show that the full 20-rank projection tail decrypts with one retained level; the final full `m = 20` packed target layout still needs scale/runtime evidence. The evaluator produces a `TopKEvaluationRecord` target proposal, the canonical `EvaluationContextDigest`, an evaluator/noise certificate, and the post-quantum evaluation-proof public-input statement, and a deterministic small-profile run matches the plaintext top-k oracle after decryption. Setup-bound evaluator plumbing now has two paths: the older score-ciphertext development path, and an aggregate-ready path that accepts selected encrypted aggregate bridge inputs only after rerunning the bridge proof verifier, rejecting proofless/public-binding-only inputs, and requiring fresh bridge prover plus encryption randomness evidence. It then verifies the supplied `AggregateReadyRecord` hash/setup/root/interpolation binding, reconstructs the encrypted aggregate vector with the record's Lagrange coefficients, packs the scalar score coordinates into the generator-ordered evaluator layout using setup-bound rotations, runs packed direct comparison, and emits proposal records without decoded targets or ranks. The setup rotation set now binds both aggregate-score packing rotations and packed-rank rotations, and setup-bound contexts reject missing rotation-key stream seeds instead of falling back to development seeds. Native Rust and WASM reject wrong-key bridge inputs, Rust rejects aggregate-ready selected-root drift and proofless aggregate-ready inputs, and the remaining positive aggregate-ready run must now use full bridge-proof inputs rather than bare ciphertext traces. This is still development evidence rather than closure: target-threshold decryption certification, full `m = 20` execution for every supported top-k value, packed full-profile scale evidence, accepted runtime/key-size benchmarks, and downstream evaluation-proof acceptance remain open. It produces a proposal only, never an accepted target, certified result, evaluation proof, or supported-phone evidence.

Still unavailable:

- public ballot generation or casting APIs;
- generated certificate/workbook rows and benchmark evidence for every dynamic frozen roster size and every casual micro-roster benchmark profile that later evaluation chooses to measure;
- Encrypted aggregate bridge closure for the encrypted aggregate bridge from committed aggregate shares to encrypted aggregate TargetBasisData, preserving bridge witness privacy;
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
