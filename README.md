# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Every roster participant is intended to act as both voter and trustee. Untrusted services may store and distribute transcript objects, but the verification path is participant mobile browsers, not servers or dedicated heavy verifier machines.

The published npm package is intentionally narrow while the protocol implementation is still being built and checked. Use it for development verification, package integration, transcript helpers, and foundation checks. It is not a complete voting library and must not be used for real ballots or ballot secrecy. The canonical public security posture lives in [SECURITY.md](SECURITY.md).

## Selected direction

The selected construction is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> ballot validity proofs for the fixed encrypted-ballot relation
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first target profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. Current security limitations, profile caveats, HE evidence, and target-decryption boundaries are not repeated here; see [SECURITY.md](SECURITY.md).

## Current package boundary

The public package currently exposes development verification helpers while the full voting API is being built and checked. These cover poll validation, threshold derivation, lifecycle and capability checks, foundation transcript checks, and narrow setup-development verification helpers. Reserved complete-protocol entry points fail closed until the matching implementation and verification work is complete.

Current package tests are development evidence only. They do not replace supported mobile runtime evidence, production hardening, or the complete protocol security boundary in [SECURITY.md](SECURITY.md).

## VSS compaction status

The accepted setup profile now exposes numeric development budgets for the future compact VSS path and a static baseline report for the current full public coefficient-commitment material. The current first-profile binary VSS transport is `1,604,341,697` bytes, with `1,604,321,280` bytes coming from coefficient payloads. The same report records the current Shamir scalar amplification as `1111` for one source at the largest trustee point and `11110` after aggregating ten source trustees for one recipient.

The development compact path now has a sparse seeded linear commitment prototype, canonical 384-byte compact commitment body encode/decode helpers, native/WASM compact commitment, coefficient-set, recipient-share set, aggregate-threshold set, share-linkage statement, share-linkage proof material-set, same-secret bridge statement-set and proof material-set command parity, lower-level compact share-linkage proof generation and verification command parity for the ternary-opening slice against the TypeScript implementation with command-side recomputation of each supplied compact commitment root and statement metadata, and compact share-linkage proof material records that bind each source statement root to proof-record lists whose entries bind proof bytes, proof byte hashes, and the restricted proof boundary, compact public coefficient commitment sets with verified source and set roots, fresh public recipient-share commitments, aggregate threshold commitments, private opening credentials for recipients, encrypted private-mailbox delivery of source-recipient compact opening credentials, a public linkage statement root bound to the verified compact coefficient, recipient-share, and aggregate roots, optional verifier-side compact commitment-set cross-checks for those linkage roots, accepted-package verification of compact coefficient, recipient-share, aggregate, share-linkage, and proof material only when matching restricted proof statements are supplied, source-batched linkage statement records that bind each source trustee to the Shamir-evaluation, aggregate-sum, common-key, and recipient-approval-boundary obligations, compact same-secret bridge statement sets that bind target-basis compact constant roots to data-basis same-secret statement and proof roots plus the integer-support, signed-representative, compact-encoding, and target-limb-order obligations, compact same-secret bridge proof material records that bind each bridge statement root to proof bytes, proof byte hashes, and the restricted proof boundary, optional verifier-side same-secret evidence-set cross-checks for those bridge roots, accepted-package verification of `compactSameSecretBridgeStatementSet` and `compactSameSecretBridgeProofMaterialSet` only when matching same-secret statement evidence, same-secret proof evidence, and restricted compact bridge proof statements are supplied, native/WASM reduced-ring compact same-secret bridge proof command parity that proves target-basis compact coefficient commitments open to the same signed ternary secret, local-state sealing plus restore-time validation for aggregate compact opening credentials after share parity, carry-relation checks, opening checks, and optional linkage evidence checks, a development-only target share generator path that consumes restored compact aggregate opening material whose public matrix seed hash matches setup common randomness, and native/WASM target-decryption share, restored-local-witness share, proof-statement derivation, and public statement verification command parity for the compact local-witness path. Released target shares now add deterministic plaintext-multiple Shamir zero-share masks for each target role and active RNS limb, include a hash-bound smudging input report with mask hashes and the cancellation rule, and keep the production proof boundary explicit. The target-decryption statement check verifies a supplied share against restored compact local material whose aggregate openings are recomputed against their declared compact roots, and the bound statement now names the active credential binding root, one-target-context rule, recipient-owned restored-witness boundary, canonical target-basis rule, smudging proof requirement, denominator-cleared recombination requirement, target share proof boundary, and smudging report hash. Target recombination now emits a hash-bound input report listing the selected shares, selected smudging report hashes, active-limb Lagrange numerator and denominator products, denominator inverses, coefficients, smudging cancellation rule, and decoded plaintext margin used for result acceptance. The static parameter-evidence record now references a compact parameter-certificate input binding hash for the current commitment relation, common key generation, exact message encoding, seven separated norm input classes, estimator input rows, proof coverage inputs, same-secret bridge inputs, structured-ring disclosure, and missing certificate inputs. The compact matrix expansion profile now has a hash-bound common-key rule for matrix residues and projection indices, including the seed, input-column, coordinate, limb, and rejection-sampling boundaries. Static profile accounting reports `384` bytes per compact commitment and `556,800` public compact commitment bytes for coefficient commitments, recipient-share commitments, and aggregate threshold commitments combined. That measurement is compact public commitment-body accounting only; it excludes compact transport framing, full compact linkage proof bytes beyond the restricted lower-level command path, same-secret bridge proof bytes, private mailbox bytes, encrypted persistent local-state witness bytes, target-decryption proof bytes, production smudging proof bytes, and recombination proof material. The compact public commitment bodies are about `0.83%` of the `64 MiB` public setup download budget; one source trustee's public compact commitment upload body is `52,992` bytes before linkage proofs, about `0.02%` of the `256 MiB` source upload budget. The profile also reports private opening payload accounting separately: one recipient private-mailbox credential payload is `55,050,240` bytes before envelope and encryption overhead, one aggregate opening credential payload is `1,310,720` bytes, and one recipient persistent aggregate opening payload is `9,175,040` bytes before local-state wrapper overhead. Against the current full VSS transport, the public commitment material is reduced by `1,603,784,897` bytes, about a `2,881.36x` reduction, leaving the compact public commitment bodies at about `0.035%` of the current full transport. The static work model is `6,681,600` commitment residue multiply-adds plus `33,600` aggregate public-sum residue additions, for `6,715,200` modeled residue arithmetic operations; the public-sum check adds about `0.50%` over the commitment multiply-add model.

The manual `pnpm run measure:compact-vss` CPU sanity runner replays one deterministic full-ring compact commitment through the TypeScript and Rust/WASM paths and prints the static byte accounting beside local wall-clock samples. The latest standalone local run measured `205.2 ms` for cold TypeScript seeded projection expansion plus commitment, then `62.9 ms` warm median commitment generation and `63.3 ms` warm median opening verification. Canonical body serialization overhead was small beside commitment recomputation: TypeScript warm median body encoding was `0.029 ms` and body decoding was `0.024 ms`. Linear warm extrapolation across the `1,450` first-profile commitments is about `91.2 s` for commitment generation and `91.7 s` for opening verification in the TypeScript development path. The matching Rust/WASM command measured `45.6 ms` cold, `15.1 ms` warm median commitment generation, and `14.9 ms` warm median opening verification for full-ring compact commitment recomputation on the same host. WASM warm median body encoding was `0.092 ms` and body decoding was `0.072 ms`, with a `21.8 s` linear warm generation extrapolation and `21.6 s` linear warm verification extrapolation across `1,450` commitments, so the compact primitive and canonical body format do not show a severe CPU regression at the native/WASM boundary. The same runner now also records the reduced-ring restricted compact share-linkage proof command: at ring degree `128` with three coefficient commitments it emits a `2,245,016` byte proof, with `181.3 ms` warm median generation and `291.1 ms` warm median verification. It also records the reduced-ring restricted compact same-secret bridge proof command: at ring degree `128` with one target RNS limb it emits a `1,228,192` byte proof, with `84.9 ms` warm median generation and `134.4 ms` warm median verification. The corresponding one-proof compact bridge proof material set serializes to `2,460,203` JSON bytes and verifies through the package-level native/WASM material command in `152.5 ms` warm median, including restricted proof verification. These proof measurements are restricted native/WASM command evidence only; they are not target-ready compact proof evidence and are not included in the static compact public commitment-body total.

Same-secret bridge evidence verification rejects embedded same-secret proof records whose `proofSizeBytes` or `proofBytesHash` do not match `proofBytesHex`, transported same-secret proof records whose proof-material root, full-object hash, chunk root, chunk hashes, size, or proof-byte hash do not match the supplied chunks, and compact bridge proof material records whose `proofByteLength`, `proofBytesHash`, proof-record root, or material-set root does not match the supplied proof bytes. The accepted setup verifier refuses an optional `compactSameSecretBridgeStatementSet` package object unless matching `sameSecretConsistency`, `sameSecretProofs`, `compactSameSecretBridgeProofMaterialSet`, and request-side `compactSameSecretBridgeProofStatements` are present and cross-checked. This activates package-level restricted proof verification for the compact bridge material, but it is still reduced-ring development evidence rather than target-ready compact proof evidence.

These measurements are development evidence, not a compact target-ready implementation. The lower-level native/WASM compact share-linkage proof command path is implemented only for the ternary-opening slice, and its proof material records have binding roots and per-record proof-byte hashes checked through the native/WASM material-set command. When the caller supplies the matching low-level restricted proof statements, the same command verifies one restricted proof per proof record and requires coverage for every recipient and target limb under each source statement. The compact same-secret bridge proof command and material-set command are likewise reduced-ring development paths, and accepted setup requires the matching request-side restricted proof statements before accepting the compact bridge proof material. The target-ready source-batched linkage proof backend, target-ready same-secret bridge proof backend, target-decryption proof backend and proof verifier activation for the compact statement, zero-knowledge coverage for released smudged decryption shares, parameter certificate, activation of a target-ready compact profile, and final target-profile native/WASM proof measurements remain unfinished.

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
- lifecycle transition and action capability checks;
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, first-valid ordering, and foundation transcript checks;
- setup-development verification helpers for local share checks, setup package verification input construction, setup package verification, and accepted setup handoff handling;
- foundation transcript verification through the packaged kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- production-ready setup ceremony, ballot generation, or casting APIs;
- public encrypted ballot package creation, verification, or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- production target-bound decryption, target recombination, or result release APIs;
- production security claims; see [SECURITY.md](SECURITY.md).

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Security

Read [SECURITY.md](SECURITY.md) before treating any verification result as security evidence. That file owns the public threat model, retry policy, audit status, and cryptographic caveats.

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

The native Rust heavy lane now has constrained free-runner-knob evidence. On
June 21, 2026, `pnpm run test:rust:kernel:heavy -- --no-run-log` completed with
`57 passed; 0 failed` under `CARGO_INCREMENTAL=0`, `RAYON_NUM_THREADS=4`,
`SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT=1`,
`SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE=1`,
`SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE=2`, and no checkpoint resume. The
run finished in `17978.14s` and the measured process-tree peak RSS was
`9.97 GiB`. This is native CI-runner setup/proof/key-transport evidence only; it
is not browser, WASM, or supported-phone mobile runtime evidence.

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
