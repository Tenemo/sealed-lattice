# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. The selected construction uses direct BGV-encrypted ballots, public ciphertext aggregation, mandatory mobile evaluator replay, target finality, and target-bound threshold decryption.

The public npm package is intentionally narrow while the protocol implementation is still being built and verified. It is not a complete voting library and must not be used for real ballot secrecy.

## Selected construction

The active project route is:

```text
direct BGV-encrypted ballots
-> post-quantum ballot validity proofs
-> public ciphertext aggregation
-> mandatory mobile evaluator replay
-> target finality
-> target-bound threshold decryption
```

The first claim-bearing mobile profile targets `n = 10`, `m = 20`, and every `1 <= K_top <= 20`. Larger profiles require separate mobile evidence before they can be treated as claim-bearing.

## Current package boundary

The published package currently supports development verification surfaces while the final direct voting API is being built. Use it for packaging, transcript, foundation, and verifier integration work, not for a complete voting ceremony.

The final direct-path package surface must be defined around:

- setup verification;
- encrypted ballot verification;
- encrypted ballot aggregation;
- mobile evaluator replay verification;
- target finality verification;
- target-bound decryption-share verification;
- target recombination;
- decoded result verification.

The public package must not expose raw BGV decrypt, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

Reserved complete-protocol entry points must fail closed until their direct-path claim gates are actually implemented.

Foundation helpers now include an integrated public foundation verifier. One deterministic direct-route foundation transcript fixture verifies through the public package in Node and browser, integrated foundation mutations fail with structured refusals, and the packaged Rust/WASM transcript-core path matches the fixture roots under a foundation-only profile. Browser and mobile-emulated browser coverage is useful package evidence, but it is not supported-phone evidence.

## Current implementation status

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
- the packed batched-pair evaluator produces encrypted sparse target roots for requested top counts without publishing aggregate scores, ranks, comparisons, masks, evaluator intermediates, or decoded target slots;
- one native one-ballot packed batched-pair replay matches the full 20-option target oracle at working level 8 in about 240 s;
- target-accepted record and target-bound decryption-share verification refuse shares for any ciphertext other than the accepted target ciphertext;
- target-bound threshold `PartDec` and recombination math compute context-bound Shamir partial decryptions for the accepted sparse target ciphertext pair and recover target ID/order slots with Lagrange interpolation.

This evidence is not claim-bearing. The current blockers are:

- weakest-relation proof soundness accounting, including score and one-hot checks that currently reduce over 65537;
- zero-knowledge accounting, including replacement or formal redesign of witness-dependent support commitments;
- Fiat-Shamir/QROM review;
- public package proof transport for an accepted proof profile;
- public accepted randomness API boundaries;
- supported-phone mobile proof verification;
- supported-phone mobile evaluator replay;
- browser/mobile proof-copy and memory evidence;
- target decryption share proof verification and certification;
- smudging, noise, and C1-C4 target-decryption closure;
- public target-decryption/recombination integration;
- supported-phone mobile target-decryption/recombination evidence.

## What is internal

Several components exist only as workspace-internal implementation, test, or vector infrastructure:

- `GF(65537)` arithmetic and plaintext top-k oracle helpers for tests;
- sealed-lattice Rust/WASM BGV-RNS arithmetic, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext basis conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, and object validation;
- an internal direct encrypted ballot command for current implementation work;
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- development-only reference-oracle tooling and generated public test vectors.

These pieces are not exported as a public voting API.

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

Treat the package as a development verification package until the direct encrypted ballot API is explicitly published and audited.

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
