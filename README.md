# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. The selected construction uses active-static secure-with-abort collective BGV setup, direct BGV-encrypted ballots, LaZer/LNP-derived no-wrap ballot validity proofs, public ciphertext aggregation, bounded-domain mobile evaluator replay, unanimous first-profile target finality, and one-shot target-bound threshold decryption of `C_target` only.

The public npm package is intentionally narrow while the protocol implementation is still being built and verified. It is not a complete voting library and must not be used for real ballot secrecy.

## Selected construction

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

The first claim-bearing mobile profile targets `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. Larger profiles require separate setup, proof, decryption, evaluator, and supported-phone mobile evidence before they can be treated as claim-bearing.

## Current package boundary

The published package currently supports development verification surfaces while the final direct voting API is being built. Use it for packaging, transcript, foundation, and verifier integration work, not for a complete voting ceremony.

The final direct-path package surface must be defined around:

- setup-intent registration;
- public common-randomness commit and reveal verification;
- recipient-verified VSS acceptance verification;
- local setup contribution creation;
- setup package verification;
- proof-bearing public-key share verification;
- proof-bearing evaluation-key share verification;
- threshold-share commitment derivation;
- encrypted ballot verification;
- encrypted ballot aggregation;
- bounded-domain mobile evaluator replay verification;
- target finality verification;
- target-bound decryption-share verification;
- target recombination;
- decoded result verification.

The public package must not expose raw BGV decrypt, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

Reserved complete-protocol entry points must fail closed until their direct-path claim gates are actually implemented.

Foundation helpers now include an integrated public foundation verifier. One deterministic direct-route foundation transcript fixture verifies through the public package in Node and browser, integrated foundation mutations fail with structured refusals, and the packaged Rust/WASM transcript-core path matches the fixture roots under a foundation-only profile. Browser and mobile-emulated browser coverage is useful package evidence, but it is not supported-phone evidence.

## Current implementation status

The BGV setup implementation has useful passive/development evidence:

- the selected BGV-RNS prototype profile uses `N = 32768`, `p = 65537`, 17 data primes, and one special prime;
- RNS arithmetic, NTT/INTT, batch encoding, canonical plaintext roots, canonical ciphertext roots, and profile hashes have regression coverage;
- the internal passive setup command can generate and verify a deterministic full-roster setup package;
- the package binds manifest, roster, threshold profile, collective public key root, BGV public key root, threshold verification roots, evaluation-key roots, evaluator binding roots, and certificate hashes;
- the package rejects trusted-dealer fields, raw secret material, malformed roster positions, wrong roots, rebound internal inconsistencies, evaluator-context binding drift, missing selected rotation roots, and unsupported target-decryption claims;
- the current HE security certificate accepts the largest exposed direct evaluator replay `Q_data` modulus and keeps the special prime and `Q_target` out of accepted exposure;
- public evaluation-key material can drive development relinearization and rotation checks without exporting the private setup witness;
- the pinned Lattigo oracle remains development-only parity for comparable RNS, NTT, and coefficient arithmetic behavior.

This evidence is not active-static setup evidence and is not an accepted mobile setup profile. The current setup blockers are:

- per-RNS-prime Shamir/VSS setup algebra;
- BDLOP/LNP-style commitment profile for trustee secrets and VSS coefficients;
- recipient-verified VSS private mailbox envelopes;
- recipient VSS acceptance records;
- verifier-derived `ThresholdShareCommitment_j,l` values;
- same-secret consistency across public key, VSS, relinearization, Galois, key-switch, and decryption shares;
- LNP/no-wrap public-key share proofs;
- LNP/no-wrap relinearization round-one and round-two proofs;
- LNP/no-wrap Galois-key batch proofs;
- generic key-switch proofs if generic key-switch material is used;
- target-decryption share proofs bound to verifier-derived threshold-share commitments;
- accepted evaluation-key correctness evidence;
- evaluation-key footprint reduction, binary chunking, and enforced mobile transport certification;
- public package setup contribution creation and setup package verification surfaces;
- active-static secure-with-abort setup theorem closure;
- target-decryption handoff clarity for `Q_target`, smudging, C1-C4, share proofs, and target-decryption readiness.

The direct encrypted ballot implementation has useful internal evidence:

- one 20-score direct BGV ballot can be encoded;
- private preflight checks all 17 data-prime encryption equations against one shared encoded-message, randomizer, and error witness;
- one internal binary proof checks all data-prime encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support with one shared response vector;
- the current internal proof is 18,626,400 bytes;
- binary proof transport is chunked and publicly hash-bound inside the internal command, including proof length, chunk size/count, chunk hashes, chunk Merkle root, full proof hash, statement hash, ciphertext root, voter identity, action context, profile, collective key, ballot layout, and proof profile;
- Node/WASM one-proof verification and aggregation pass through the internal command path;
- Node/WASM 20-ballot proof verification and aggregation pass with internal binary chunk transport in about 76.4 s outer wall time, 372,528,000 total proof bytes, about 396 MB WASM linear memory after the run, and about 603 MB Node resident set after the run;
- desktop Chromium proof smoke verifies one widened proof and aggregates one ballot with internal binary chunk transport in about 4.7 s and about 179 MB WASM linear memory after the run;
- the internal command uses fresh CSPRNG proof-mask and ballot-encryption randomness by default in Node/WASM and browser helpers;
- the internal command rejects reused encryption randomness, reused proof-mask randomness, and proof/encryption randomness overlap;
- duplicate voter identities, out-of-order voter identities, invalid scores, and mismatched setup witness seeds reject before encryption and proof generation;
- current evaluator evidence produces encrypted sparse target roots for requested top counts without publishing aggregate scores, ranks, comparisons, masks, evaluator intermediates, or decoded target slots;
- one native one-ballot packed batched-pair replay matches the full 20-option target oracle at working level 8 in about 240 s;
- target-accepted record and target-bound decryption-share verification refuse shares for any ciphertext other than the accepted target ciphertext;
- target-bound threshold `PartDec` and recombination math compute context-bound Shamir partial decryptions for the accepted sparse target ciphertext pair and recover target ID/order slots with Lagrange interpolation.

This evidence is not claim-bearing. The accepted ballot proof path is a LaZer/LNP-derived linear-relation proof with per-RNS-limb no-wrap lifting. Upstream LaZer native code, Sage codegen, and LaBRADOR are development reference or code-generation material only; the mobile claim path needs a Rust/WASM selective port or reimplementation of the LNP linear-relation subset.

The accepted evaluator profile is bounded-domain interpolation over certified score-difference and rank domains. Full-field `p = 65537` comparison is not the first claim path.

The current blockers are:

- accepted active-static setup contributions and setup package verification;
- per-RNS-prime VSS and commitment profile acceptance;
- collective public-key correctness evidence;
- accepted evaluation-key correctness evidence and mobile key transport;
- proof soundness accounting until encryption, encoder, score, one-hot, support, and carry/slack relations use accepted no-wrap lifting or equivalent accepted accounting;
- zero-knowledge accounting, including replacement or formal redesign of witness-dependent support commitments;
- Fiat-Shamir/QROM review;
- public package proof transport for an accepted proof profile;
- public accepted randomness API boundaries;
- supported-phone mobile proof verification;
- supported-phone mobile evaluator replay;
- browser/mobile proof-copy and memory evidence;
- bounded-domain comparator coefficients, depth, noise, and all-`K_top` replay certificate;
- target decryption share proof verification and certification;
- smudging, noise, and C1-C4 target-decryption closure;
- public target-decryption/recombination integration;
- supported-phone mobile target-decryption/recombination evidence.

The highest-risk mobile feasibility items are proof sizes for active setup, evaluation-key, ballot, and decryption-share proofs; evaluation-key size and mobile key transport; bounded-domain evaluator depth and noise certificates; and supported-phone WASM memory/copy behavior.

## What is internal

Several components exist only as workspace-internal implementation, test, or vector infrastructure:

- `GF(65537)` arithmetic and plaintext top-k oracle helpers for tests;
- sealed-lattice Rust/WASM BGV-RNS arithmetic, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext basis conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, and object validation;
- internal passive BGV setup generation, verification, certificates, and development evaluation-key material;
- an internal direct encrypted ballot command for current implementation work;
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- development-only reference-oracle tooling and generated public test vectors.

These pieces are not exported as a public voting API. The legacy passive setup profile `sealed-lattice-bgv-rns-passive-full-roster-setup-v1` is development-only and cannot close `CollectiveBgvSetup-v1`.

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

## Installation

```bash
pnpm add sealed-lattice
```

Treat the package as a development verification package until the active-static direct encrypted ballot API is explicitly published and audited.

## Development

Install dependencies:

```bash
pnpm install
```

Run the main local validation gate:

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, runs the type-check, then runs lint, docs verification, package smoke verification, public package policy verification, package-boundary verification, test vector verification, dead-code scan, Rust formatting, Rust clippy, Rust tests, and fast Node tests through the repository check runner.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Run focused verification:

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
pnpm run verify:docs
pnpm run smoke:pack:npm
```

Keep default and release gates focused on the selected direct path and shared substrate. Heavy proof, browser, and mobile evidence lanes should remain explicit and direct-path-only.

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
