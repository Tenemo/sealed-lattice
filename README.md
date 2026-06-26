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

The accepted setup profile now exposes a static baseline report for the current full public coefficient-commitment material without binding compact VSS budget or measurement records into the accepted setup artifact. The current first-profile binary VSS transport is `1,604,341,697` bytes, with `1,604,321,280` bytes coming from coefficient payloads. The same report records the current Shamir scalar amplification as `1111` for one source at the largest trustee point and `11110` after aggregating ten source trustees for one recipient.

The development compact path now has a sparse seeded linear commitment prototype, canonical 384-byte compact commitment body encode/decode helpers, native/WASM compact commitment, coefficient-set, recipient-share set, aggregate-threshold set, share-linkage statement, share-linkage proof material-set, same-secret bridge statement-set and proof material-set command parity, lower-level compact share-linkage proof generation and verification command parity for the ternary-opening slice against the TypeScript implementation with command-side recomputation of each supplied compact commitment root and statement metadata, and compact share-linkage proof material records that bind each source statement root to proof-record lists whose entries bind proof bytes, proof byte hashes, proof-record roots, packaged proof statements, and the material roots, compact public coefficient commitment sets with verified source and set roots, fresh public recipient-share commitments, aggregate threshold commitments, private opening credentials for recipients, encrypted private-mailbox delivery of source-recipient compact opening credentials without duplicating delivered share values inside the credential object and with private-envelope compact opening randomness packed as ternary hex, compact public records that no longer carry separate vector hashes for compact opening messages, opening randomness, or opening roots, a public linkage statement root bound to the verified compact coefficient, recipient-share, and aggregate roots, optional verifier-side compact commitment-set cross-checks for those linkage roots, accepted-package verification of compact coefficient, recipient-share, aggregate, share-linkage, and proof material only when the proof material carries matching packaged proof statements and the compact public material binds to setup common randomness plus the canonical target-basis hash, source-batched linkage statement records that bind each source trustee to the Shamir-evaluation, aggregate-sum, common-key, and recipient-approval-boundary obligations, compact same-secret bridge statement sets that bind target-basis compact constant roots to data-basis same-secret statement and proof roots plus the integer-support, signed-representative, compact-encoding, and target-limb-order obligations, compact same-secret bridge proof material records that bind each bridge statement root to proof bytes, proof byte hashes, packaged proof statements, proof-record roots, and the material-set root, optional verifier-side same-secret evidence-set cross-checks for those bridge roots, accepted-package verification of `compactSameSecretBridgeStatementSet` and `compactSameSecretBridgeProofMaterialSet` only when matching same-secret statement evidence, same-secret proof evidence, and compact bridge proof material with packaged proof statements are supplied, native/WASM reduced-ring compact same-secret bridge proof command parity that proves target-basis compact coefficient commitments open to the same signed ternary secret, local-state sealing plus restore-time validation for aggregate compact opening credentials after share parity, carry-relation checks, opening checks, and optional linkage evidence checks, explicit target-time preparation of the restored local witness with a target-bound smudging witness derived from local smudging seed material plus accepted target, target-decryption ciphertext, and profile bindings, and a development-only restored-local-witness target share generator path that consumes the prepared restored compact aggregate opening material whose public matrix seed hash matches setup common randomness. The seed-only target-share command is not exposed through the Rust/WASM command APIs. Native/WASM command parity covers restored-local-witness target-decryption share generation, proof-statement derivation, public statement-binding, private proof-material command dispatch for the compact local-witness path, and a private proof-gated recombination command that verifies each supplied share's proof material before interpolation. Released target shares now add deterministic plaintext-multiple Shamir zero-share masks for each target role and active RNS limb and include a hash-bound smudging input report with numeric bounds, not public hashes of the smudging vectors. The target-decryption local-witness path recomputes restored compact aggregate openings and matches them to accepted aggregate commitment records; proof-statement derivation also expands the target-bound smudging seed into signed polynomial openings, uses those openings for the released-share smudging relation, regenerates the expected target share from the restored local witness, and rejects canonically rebound share payload, share root, target-share hash, smudging-report, or smudging-opening-seed mismatches. The target-decryption statement-binding check keeps operative statement inputs only, including target and participant bindings, the target share hash, the smudging report hash, the active credential binding root, setup common randomness, the accepted share-linkage statement root, accepted aggregate commitment records, and the active accepted compact aggregate commitment bodies needed by a future proof verifier. The same proof statement also binds a target-specific compact smudging commitment set for every target role, active RNS limb, and nonconstant zero-share polynomial coefficient; statement derivation builds those commitments from the same signed polynomial openings plus seed-derived commitment randomness, and statement validation recomputes the set root and checks compact commitment shape, role, matrix seed, limb, prime, and coordinate bounds. The Rust proof backend now has an internal reduced-ring target-decryption share proof family for one target role and one RNS limb; it proves compact aggregate openings, compact smudging openings, and the released-partial equation. The Rust command dispatcher can generate and verify that proof slice from JSON while recomputing the aggregate compact commitment root and the smudging commitment-set root, and the target-decryption proof-material command composes those slices across both target roles and every active RNS limb for one real target share. The proof-material verifier checks material roots, target-share binding roots, proof byte hashes, proof-record roots, packaged proof-statement roots and coordinates, proof byte verification, and full active role/limb coverage. The private recombination command requires the interpolation quorum, verifies every supplied proof-material bundle inside the same call, rejects mismatched arrays or duplicate interpolation inputs, recombines only proof-backed shares, and returns target option values plus coefficient, slot, and result hashes. This remains development evidence and is not a public result release API. The statement-binding command returns `ok: false` with `refusalReason: "TargetDecryptionProofUnavailable"` because it does not verify target-decryption proof bytes or accept a share. No public target-recombination command is exposed through the published SDK, so there is no callable public unproven-share recombination result. The compact parameter-certificate input binding records the current commitment relation, common-key derivation domains and preimage fields, exact message encoding, numeric norm input classes, estimator row dimensions, same-secret bridge target-basis inputs, and the same-secret proof-family root. The compact matrix expansion profile now has a hash-bound common-key rule for matrix residues and projection indices, including the seed, input-column, coordinate, limb, and rejection-sampling boundaries. The manual compact VSS measurement accounting records `384` bytes per compact commitment and `556,800` public compact commitment bytes for coefficient commitments, recipient-share commitments, and aggregate threshold commitments combined. That measurement is compact public commitment-body accounting only; compact transport framing, full compact linkage proof bytes beyond the restricted lower-level command path, same-secret bridge proof bytes, private mailbox bytes, encrypted persistent local-state witness bytes, target-decryption proof-material bytes, production smudging proof bytes, and recombination proof material are reported separately or remain outside the public-body ratio. The compact public commitment bodies are about `0.83%` of the `64 MiB` public setup download budget; one source trustee's public compact commitment upload body is `52,992` bytes before linkage proofs, about `0.02%` of the `256 MiB` source upload budget. Against the current full VSS transport, the public commitment material is reduced by `1,603,784,897` bytes, about a `2,881.36x` reduction, leaving the compact public commitment bodies at about `0.035%` of the current full transport. The static work model is `6,681,600` commitment residue multiply-adds plus `33,600` aggregate public-sum residue additions, for `6,715,200` modeled residue arithmetic operations; the public-sum check adds about `0.50%` over the commitment multiply-add model.

The public SDK setup verifier streams transported setup proof chunks into the packaged kernel and passes only fresh same-call proof handles returned by the kernel stream finalizer to kernel setup verification. Caller-supplied setup proof handle objects are ignored and are not part of the exported SDK API.

The internal target-decryption proof slice accepts compact aggregate commitment openings whose message coefficients are lifted above the selected target modulus under an explicit aggregate message bound, while reducing those coefficients modulo the target prime for the released-partial equation. This keeps the compact commitment opening relation and the target decryption equation aligned for the reduced one-role, one-limb Rust proof helper, the full active-role/limb proof-material package, and the private proof-gated recombination command.

The Rust target-decryption development command can now generate that one-role, one-limb proof slice from a restored local target witness and a bound target-decryption proof statement. The proof-material command retains the already validated compact aggregate opening messages and randomness, emits proof records plus lower-level proof-slice statements without private witness vectors, and verifies every active target role and limb. The private recombination command consumes those proof-material records before interpolation; it is development-only and stripped from the public SDK.

Published `sealed-lattice` package builds strip target-decryption development bridge members, including proof-material generation, proof-material verification, and proof-gated recombination helpers, from the vendored internal WASM loader. Those private commands remain only in the unpublished workspace WASM package for tests and measurement.

Compact opening roots are now confined to private recipient opening credentials, private aggregate opening credentials, and local restored-witness material. Public compact commitment records bind accepted commitment roots, and target-decryption proof statements bind accepted commitment roots plus the active accepted commitment bodies; opening roots are recomputed from private opening material and compared inside credential verification.

The passive setup parameter certificate and target-threshold decryptability certificate now bind the canonical target basis, target level, target prime count, target modulus bit count, and target modulus product. The verifier recomputes those values from the evaluator target-basis definition rather than accepting a placeholder `qTargetBits` field.

The manual compact VSS measurement report separates implemented development artifact bytes: full-profile compact public commitment bodies remain `556,800` bytes, while reduced-ring proof samples are reported separately as `5,782,808` proof payload bytes plus `7,095,794` same-secret bridge proof-material JSON bytes and are not combined into a target-ready setup size.

The same report now measures implemented private-state development artifact JSON separately. One full-ring source-recipient private mailbox envelope reference is `14,618,535` bytes after removing duplicated delivered share values from the compact credential, removing the producer-set mailbox narration field, packing private-envelope compact opening randomness as ternary hex, and packing private-envelope share values as fixed-width 48-bit little-endian hex, with `7,294,659` bytes of private envelope JSON, `14,596,912` bytes of encrypted-envelope JSON, and `16,599` bytes of transported private-share proof-material framing around a `32` byte per-limb proof sample. The raw in-memory compact recipient-share opening credential bundle used to derive aggregate openings is `11,524,195` bytes; it is not the packed private-envelope transport shape. Extrapolated across ten recipients for one source trustee, the private mailbox envelope references are `146,185,350` bytes, leaving a `122,250,106` byte margin under the current `256 MiB` source upload budget before target-ready private-share proof bytes. Extrapolated across all `100` source-recipient pairs, the same JSON envelope-reference shape is `1,461,853,500` bytes of pairwise private transport. One one-source encrypted local-state sample has a `6,689,370` byte aggregate-threshold-share plaintext with packed aggregate share values, a `4,594,855` byte target-proof-witness plaintext with fixed-width aggregate commitment-message vectors, signed-byte aggregate-opening randomness, and no duplicate reduced-share vector, derived carry vector, or source-share opening-root provenance list, `13,382,069` bytes of sealed aggregate-share JSON, `9,193,057` bytes of sealed target-witness JSON, and a `22,585,139` byte encrypted local-state JSON object. The outer local-state ciphertext now encrypts a compact manifest of sealed-material references while the sealed material envelopes remain outside that outer ciphertext and are still validated against the local-state commitment, material roots, ciphertext references, and storage associated data. These private-state samples are development accounting; they are not target-ready proof-byte accounting or final mobile storage evidence.

The same report measures implemented target-decryption development artifact JSON separately: one prepared local target-proof witness is `4,595,776` bytes, its compact aggregate opening witness is `4,592,667` bytes, its seven compact aggregate opening credentials are `4,591,854` bytes combined, and its target-time smudging witness is `1,489` bytes. One generated development target share is `7,350,564` bytes, its target-share payload is `7,346,703` bytes, its smudging input report is `3,119` bytes, the target-decryption proof statement is `47,268` bytes after adding the target-bound smudging commitment set, and the non-accepting statement-binding verification output is `129` bytes. The compact measurement report does not yet include target-decryption proof-material bytes, production smudging proof material, or proof-gated recombination material.

The compact parameter-certificate input binding no longer carries missing-input or proof-coverage prose. Its hash covers only current binding inputs; unfinished estimator reviews, proof backends, structured-ring analysis, supported-phone measurements, and target-ready activation remain disclosed here as prose rather than bound artifact fields.

The accepted setup public-key and evaluation-key records no longer carry fixed narration fields for aggregation state, assembly state, material source, proof-byte availability, proof-binding requirement, or absent raw-key material. Their roots now bind the operative setup context, profile identifiers, material encodings, proof-family identifiers, schedules, share roots, proof roots, material roots, and recomputed transport hashes. Setup proof-generation command responses no longer return proof-randomness source, retention, binding, or nonce-hash metadata; the generation commands still bind the supplied seed and nonce into the statement-specific proof randomness before proof masking.

Setup VSS material, threshold-share commitment derivation outputs, private VSS local verification records, and the static public VSS material size report no longer carry descriptive ring-degree labels. They keep numeric ring-degree fields where those values are part of the recomputed statement, root, material, or profile shape.

Passive setup profile, evaluation-key, and setup key-correctness certificate records no longer carry recipient-witness disclosure labels, finalization labels, generated-for labels, regeneration booleans, or prose theorem/scope labels that only restated policy. Compact share-linkage profile records, evaluator schedules, evaluation-key streams, passive verification records, local deletion receipts, development fixtures, setup profiles, VSS complaint evidence, and setup commitment security certificates likewise no longer carry fixed policy narration fields, enumerated outcome lists, or non-gating assumption booleans. The remaining records bind operative relation definitions, dependency lists, roots, schedules, proof-family roots, transport fields, proof byte roots, and hashes.

The manual `pnpm run measure:compact-vss` CPU sanity runner replays one deterministic full-ring compact commitment through the TypeScript and Rust/WASM paths and prints the static byte accounting beside local wall-clock samples. It now fails if compact public commitment bodies miss the `2,800x` reduction floor, exceed the `64 MiB` public setup download budget, exceed compact public largest-object and WASM-copy budgets, exceed the measured target-decryption development artifact budget, or if WASM warm full-profile generation or verification extrapolates above `30 s` on the local measurement host. The latest standalone local run measured `142.1 ms` for cold TypeScript seeded projection expansion plus commitment, then `2.18 ms` warm median commitment generation and `2.11 ms` warm median opening verification. Canonical body serialization overhead was small beside commitment recomputation: TypeScript warm median body encoding was `0.026 ms` and body decoding was `0.022 ms`. Linear warm extrapolation across the `1,450` first-profile commitments is about `3.16 s` for commitment generation and `3.06 s` for opening verification in the TypeScript development path. The matching Rust/WASM command measured `39.7 ms` cold, `14.6 ms` warm median commitment generation, and `14.8 ms` warm median opening verification for full-ring compact commitment recomputation on the same host. WASM warm median body encoding was `0.069 ms` and body decoding was `0.059 ms`, with a `21.15 s` linear warm generation extrapolation and `21.41 s` linear warm verification extrapolation across `1,450` commitments, so the compact primitive and canonical body format remain within the local native/WASM CPU guard. The same runner also records private-state TypeScript JSON construction samples; the latest mailbox sample is `1.47 s` for one full-ring source-recipient private mailbox delivery, and the one-source encrypted local-state sample builds in `6.00 s`. The same runner now also records the reduced-ring restricted compact share-linkage proof command: at ring degree `128` with three coefficient commitments it emits a `2,243,736` byte proof, with `181.8 ms` warm median generation and `303.6 ms` warm median verification. It also records the reduced-ring restricted compact same-secret bridge proof command: at ring degree `128` with seven target RNS limbs it emits a `3,539,072` byte proof, with `329.7 ms` warm median generation and `523.7 ms` warm median verification. The corresponding one-proof compact bridge proof material set serializes to `7,095,794` JSON bytes and verifies through the package-level native/WASM material command in `582.8 ms` warm median, including restricted proof verification. These proof measurements are restricted native/WASM command evidence only; they are not target-ready compact proof evidence and are not included in the static compact public commitment-body total.

Same-secret bridge evidence verification rejects embedded same-secret proof records whose `proofSizeBytes` or `proofBytesHash` do not match `proofBytesHex`, transported same-secret proof records whose proof-material root, full-object hash, chunk root, chunk hashes, size, or proof-byte hash do not match the supplied chunks, and compact bridge proof material records whose `proofByteLength`, `proofBytesHash`, proof-record root, packaged proof statement, or material-set root does not match the supplied proof bytes. The accepted setup verifier refuses an optional `compactSameSecretBridgeStatementSet` package object unless matching `sameSecretConsistency`, `sameSecretProofs`, and `compactSameSecretBridgeProofMaterialSet` with packaged proof statements are present and cross-checked. This activates package-level restricted proof verification for the compact bridge material, but it is still reduced-ring development evidence rather than target-ready compact proof evidence.

These measurements are development evidence, not a compact target-ready implementation. The lower-level native/WASM compact share-linkage proof command path is implemented only for the ternary-opening slice, and its proof material records have binding roots and per-record proof-byte hashes checked through the native/WASM material-set command. When the proof material carries matching packaged low-level proof statements, the same command verifies one restricted proof per proof record and requires coverage for every recipient and target limb under each source statement. The compact same-secret bridge proof command and material-set command are likewise reduced-ring development paths, and accepted setup reads the compact bridge proof statements from the proof material set before accepting the compact bridge proof material. The target-ready source-batched linkage proof backend, target-ready same-secret bridge proof backend, public target result release flow, target-decryption proof-material byte measurement, zero-knowledge coverage for released smudged decryption shares in the final proof profile, compact commitment parameter security review, activation of a target-ready compact profile, and final target-profile native/WASM proof measurements remain unfinished.

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
- production target-bound decryption or result release APIs;
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
