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

The public package currently exposes development verification helpers while the final direct voting API is being built. It also exposes narrow accepted-setup helpers for signed setup intent creation, deterministic setup phase records, full-roster common-randomness commit/reveal assembly, recipient-local private VSS share verification, signed VSS acceptance and complaint records, roots-only setup contribution assembly, proof-material-only same-secret, public-key, and evaluation-key record assembly, binary-chunked same-secret and public-key setup proof material transport, stream-verified setup proof material handles for same-secret, public-key, and trustee evaluation-key proof sidecars, binary-chunked evaluation-key proof and key-switch component material transport, binary-chunked public-key share material transport, binary-chunked public evaluation-key runtime material transport, verifier-derived threshold-share commitments during setup package assembly, root-bound setup certificate generation, encrypted local trustee setup state export, restore-after-restart validation, public-only setup package verification input construction, setup package verification, and the typed accepted setup handoff shape for terminal accepted responses. Reserved complete-protocol entry points fail closed until their direct-path claim gates are actually implemented.

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
- signed setup intent creation, deterministic setup phase records, full-roster common-randomness commit/reveal assembly, recipient-local private VSS share verification, signed VSS acceptance and complaint records, roots-only accepted setup contribution assembly, proof-material-only same-secret, public-key, and evaluation-key record assembly, binary-chunked same-secret and public-key setup proof material transport, stream-verified setup proof material handles for same-secret, public-key, and trustee evaluation-key proof sidecars, binary-chunked evaluation-key proof and key-switch component material transport, binary-chunked public-key share material transport, binary-chunked public evaluation-key runtime material transport, verifier-derived threshold-share commitments during setup package assembly, root-bound setup certificate generation, encrypted local trustee setup state export, restore-after-restart validation, public-only setup package verification input construction, and setup package verification for development integration;
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

The current setup, direct proof, aggregation, evaluator, browser, and target-decryption evidence is development evidence only. The current setup completion target means claim-bearing accepted setup for `CollectiveBgvSetup-v1`; it is not gated on external validation, independent audit, or third-party proof review, but the repository must still close profile-scale integrated terminal setup-package evidence before that label can be used. Internal direct evaluator replay can consume supplied development public evaluation-key material; the accepted setup verifier can reconstruct a package-closure-pending public-only collective encryption key plus aggregate relinearization and Galois runtime keys from profile-ring material, and its terminal profile-ring gate still refuses incomplete terminal setup packages before accepted handoff. The accepted setup handoff is a typed public contract covering direct ballot encryption, public aggregation, bounded evaluator replay, future target-decryption refusal, certificate roots, and the accepted handoff root.

The internal kernel can generate and self-verify the current succinct setup proof families: one batched trustee evaluation-key argument per trustee, one keyless same-secret linkage-anchor argument per trustee, one public-key share argument per trustee, and recipient-private VSS share proofs inside dealer-to-recipient envelopes. Same-secret linkage now requires the exact commitment count for the active theorem shape, setup statement hashes length-delimit variable context fields including `setupEpoch` and the same-secret public matrix seed hash, malformed setup context tokens or protocol-hash roots are rejected before statement use, terminal setup package context validation rejects malformed `ceremonyId` and `setupEpoch` tokens before later missing-object `pending` responses, and native Rust plus WASM/TypeScript parity vectors pin the same statement hashes for the four current setup proof-family shapes. Private VSS proof records now use `sealed-lattice-private-vss-share-proof-succinct-v1`, bind statement roots, proof bytes hashes, proof material roots, and the accepted succinct private VSS accounting hash, and no longer carry LNP relation-commitment or tbox metadata on the accepted path. Public setup package assembly strips recipient-private proof transports from envelope commitments, and the accepted verifier refuses private VSS proof sidecars plus legacy private VSS LNP/tbox metadata in public envelope commitment records. Recipient-local verification keeps coefficient messages, opening randomness, carry witnesses, and source trustee secret constants out of public transcript artifacts.

Setup proof accounting now binds the private VSS, same-secret linkage-anchor, public-key share, and trustee evaluation-key succinct accounting objects plus transport, leakage, classical Fiat-Shamir transcript, and theorem accounting rows. Accepted setup profile and certificate metadata list those same four current succinct setup proof families. Public-key share accounting and setup certificates state the limb-zero linkage dependency: the public-key proof opens the selected same-secret constant commitment and relies on the same-secret anchor opening every `Q_share` constant commitment plus ternary support. The low-degree rows are accepted only under the named rate-per-query FRI conjecture, the proven fallback is recorded as insufficient at the current query count, QROM rows remain reference-only until a concrete reduction-loss calculation exists, and smudging is scoped to bounded leakage rather than 128-bit zero-knowledge. Accepted setup commitment parameter accounting, key-correctness certificates, the current HE parameter boundary, and the root-bound active-static secure-with-abort setup theorem certificate are present, but terminal profile-scale setup-package evidence is still pending.

Legacy LNP/tbox challenge-domain and setup-proof public-matrix audit metadata is explicitly scoped to private-VSS-only sampled-entry audit material, not the current accepted succinct-family proof accounting.

The internal protocol package can assemble full-roster VSS commitments, binary-chunked public VSS coefficient material, private mailbox delivery, recipient re-verification, signed acceptances, verifier-derived threshold commitments from embedded or transported VSS material, same-secret statements and keyless linkage-anchor proof records, public-key share/proof/material/succinct records, recipient-private VSS succinct proof records, the root-bound collective public key, frozen evaluator-key schedules, relinearization/Galois proof records, public evaluation-key roots, the final root-bound setup package, encrypted local trustee state, and roots-only setup contributions without exporting raw shares or caller-supplied aggregate public-key material. The public package wraps the development setup surfaces and accepted handoff response shape without exposing raw shares, aggregate public-key inputs, or proof-generation witnesses. The broad Node/WASM collective setup fixture now separates reduced-ring package-shaped private VSS envelope commitments from a focused degree-128 recipient-private proof-delivery check, but it is still development coverage rather than terminal package evidence. Accepted setup-package evidence, accepted ballot proof evidence, supported-phone evidence, production readiness, and a complete public voting API are still not closed.

Protocol setup assembly now constructs binary-chunked VSS coefficient material and binary-chunked public-key share material directly from source inputs instead of first building package-level embedded public coefficient arrays. Binary-chunked VSS delivery also avoids retaining full public commitment material records in live private opening state: assembly rebuilds one source trustee's hash-bound material for private mailbox delivery and recipient re-verification, then discards it before the next source. Source trustee opening state can now be supplied through a provider, and profile-ring setup assembly requires that provider-backed path so profile-scale callers load deterministic or persisted source openings one trustee at a time instead of constructing an all-source opening array before assembly. Reduced-size integrated tests now exercise that provider-backed route with binary VSS material, binary public-key share material, transported setup proof material, transported evaluation-key proof and component material, public evaluation-key runtime material, and the public-only verification input wrapper; provider-loaded state rebound to another trustee identity is refused. Setup certificate sizing uses the canonical binary VSS material byte-length formula instead of constructing transported material first, and private VSS delivery, acceptance creation, and local-state construction process source, recipient, and trustee payloads sequentially instead of fanning out profile-size envelopes concurrently. Verified private VSS share envelopes are loaded, decrypted, and re-verified per trustee during local-state sealing instead of retained as an all-recipient map. VSS threshold-share commitment derivation now has a chunk-fed Rust/WASM stream command path, and profile-ring binary VSS assembly feeds generated chunks into that path while returning a chunkless transported-material reference and verifier-owned `VerifiedVssCoefficientCommitmentMaterial` handle instead of a retained `chunks[]` sidecar. The accepted setup verifier can consume that handle for chunkless terminal VSS verification and refuses forged, stale, or context-mismatched handles. Public-key share coefficient material can also use binary-chunked `SetupTransportedPublicKeyShareMaterial` through protocol assembly, SDK verification requests, and WASM bridge forwarding; the binary ceremony/package path keeps the public-key share material set root-only, writes public-key share transport bytes directly into 1 MiB chunks instead of a monolithic byte array, binds public-key succinct proofs to material root references, and derives the collective public key by reading transported share material one participant at a time instead of retaining decoded `shareMaterialRecords`. Same-secret, public-key, and evaluation-key setup proof material now have binary-chunked transport creators, SDK exports, vendored package internals, setup ceremony companion propagation for root-only proof records, and chunk-fed Rust/WASM stream commands that return `VerifiedSetupProofMaterial` handles for chunkless verifier consumption of those proof sidecars. The protocol verification-input constructor preserves caller-supplied proof-material handles and removes chunk arrays only for the proof-material roots those handles cover; the public SDK verifier stream-registers chunked same-secret, public-key, and trustee evaluation-key proof sidecars before the final kernel verify command, so the final command carries compact `verifiedSetupProofMaterials` instead of those proof chunks. Evaluation-key transport also moves canonical key-switch component vectors into binary chunks and writes key-switch component material directly into proof-transport chunks instead of pre-materializing one full component byte array. Public evaluation-key runtime material now has protocol and SDK binary-chunked transport creation, supplied public evaluation-key material sidecars are checked against their public references and retained for verification input, public evaluation-key transport no longer duplicates evaluation-key component chunks when the separate component-material sidecar is supplied, and profile-ring setup ceremony assembly can generate the transported material reference from verified relinearization and Galois records instead of requiring a caller-supplied reference. The protocol and public SDK now expose a public-only setup package verification-input constructor that copies only the setup package and transported public sidecars, including chunkless VSS material references, verified VSS material handles, and handled setup proof-material references, without carrying local trustee state, raw shares, or proof-generation witnesses. Setup transport certificates now aggregate byte counts, chunk counts, chunk hashes, the full-object-set hash, and the aggregate chunk root over VSS, public-key share, setup proof, key-switch component, and public evaluation-key runtime transported objects when supplied; the verifier preserves each object's own chunk-root domain, checks sidecar metadata agreement, and refuses unrequested transported objects plus request/certificate sidecars whose roots are not referenced by setup package records. Binary-chunked VSS coefficient material now has verifier-enforced agreement between the package material transport reference and the setup transport certificate, so reduced-ring transported material cannot be paired with profile-sized certificate metadata. Terminal setup-package acceptance also refuses embedded setup material, embedded setup proof bytes, embedded key-switch component vectors, private VSS proof sidecars and legacy private VSS LNP/tbox metadata in public envelope commitment records, missing public evaluation-key runtime-material references, and non-binary terminal material encodings once all required final objects are present. Profile-ring setup ceremony assembly refuses package construction unless the first-profile 10-trustee roster and q_dec 4 threshold are selected, binary-chunked VSS coefficient material, binary-chunked public-key share material, transported same-secret, public-key, and evaluation-key setup proof/key-switch material with companion transport sets are supplied, provider-backed source opening loading is used, and generated or supplied transported public evaluation-key material is selected before package construction. This remains development setup evidence until terminal accepted setup-package evidence closes.

The remaining terminal setup proof-transport gap is integrated full-profile package evidence, not the Rust/WASM or SDK handle path for same-secret, public-key, and trustee evaluation-key sidecars. Focused recipient-local private VSS tests refuse proof-byte, proof-material-root, proof-accounting-hash, proof-statement-root, statement-hash, transported-chunk, duplicate-root, and missing requested transported-material drift. Focused public-package private VSS tests refuse recipient-local verification root drift, signed acceptance drift against private-envelope hash or local-verification roots, and non-accepted recipient verification status without returning an accepted handoff. Focused protocol-built Node/WASM setup packages now refuse drifted same-secret proof and public-key share succinct proof `statementHash` values before later terminal missing-object responses. Terminal evidence still has to reach accepted package handoff without giant JSON proof payloads and finish these checks over the integrated first-profile public object graph.

Terminal setup-package acceptance requires a chunkless VSS material reference plus a stream-verified VSS material handle; raw VSS chunk sidecars are refused at the terminal acceptance boundary.

The accepted setup verifier rejects duplicated evaluation-key component chunks in public evaluation-key material; binary evaluation-key proof records must use the separate component-material sidecar.

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
