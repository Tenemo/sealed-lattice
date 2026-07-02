# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Every roster participant is intended to act as both voter and trustee. Untrusted services may store and distribute transcript objects, but the verification path is participant mobile browsers, not servers or dedicated heavy verifier machines.

The published npm package is intentionally narrow while the protocol implementation is still being built and checked. Use it for development verification, package integration, transcript helpers, and foundation checks. The canonical public security posture lives in [SECURITY.md](SECURITY.md).

## Selected direction

The selected construction is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> ballot validity proofs for the fixed encrypted-ballot relation
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> target finality for the selected target
-> one-shot target-bound threshold decryption of C_target only
```

The first target profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. The current target-finality verifier is a 5-of-7 witness-checkpoint shell; trustee-finality and target-decryption certification remain downstream. Current security limitations, profile caveats, HE evidence, and target-decryption boundaries are not repeated here; see [SECURITY.md](SECURITY.md).

## Current package boundary

The public package currently exposes helpers for poll validation, threshold derivation, lifecycle and capability checks, foundation transcript checks, and setup-development verification.

Threshold derivation is a helper, not a security certificate. The first target profile above is the only current setup/evaluator evidence profile; other roster sizes returned by helper APIs need their own profile evidence, runtime measurements, and security review before they carry a security or mobile claim.

The first setup/evaluator boundary is implemented as development verification evidence for the first profile. Its public verifier requires externally supplied manifest and setup-roster hashes, verifies the active-static setup package, VSS acceptances, public key, evaluation keys, proof/key transport, and setup/evaluator HE boundary, and returns an accepted setup handoff for downstream development work. The missing public workflow pieces are listed below; security caveats and audit status live in [SECURITY.md](SECURITY.md).

Package tests are development evidence. Read [SECURITY.md](SECURITY.md) before treating any result as security evidence.

## Installation

```bash
npm install sealed-lattice
```

```bash
pnpm add sealed-lattice
```

## Basic usage

```typescript
import { deriveThresholdParameters, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposal should be adopted?",
    options: ["Proposal A", "Proposal B"],
    topOptionCount: 1,
});

if (!pollValidation.isValid) {
    throw new Error(
        pollValidation.errors[0]?.message ?? "Invalid poll specification.",
    );
}

const thresholdParameters = deriveThresholdParameters({
    rosterSize: 10,
});
```

`pollValidation.normalized` contains the validated poll with defaults applied. `thresholdParameters` contains the derived threshold, quorum, corruption-bound, and warning fields for the frozen roster size.

## What you can use today

- poll specification validation and canonical hash derivation;
- threshold and frozen roster parameter derivation;
- lifecycle transition and action capability checks;
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, first-valid ordering, and foundation transcript checks;
- setup-development verification helpers for local share checks, setup-roster hash derivation, setup package verification input construction, setup package verification, and accepted setup handoff consumption;
- foundation transcript verification through the packaged kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- production-ready setup ceremony, ballot generation, or casting APIs;
- public encrypted ballot package creation, verification, or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- target-bound decryption, target recombination, or result release APIs;
- security claims beyond [SECURITY.md](SECURITY.md).

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Security

Read [SECURITY.md](SECURITY.md) before treating any verification result as security evidence. That file owns the public threat model, retry policy, audit status, unsupported-evidence rules, and cryptographic caveats.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  packages/
    crypto/                     Internal canonical JSON, hashes, signatures
    protocol/                   Internal protocol logic and reference paths
    sdk/                        Published sealed-lattice package
    types/                      Shared TypeScript type declarations
    wasm/                       Internal WASM loader package
  test-vectors/                 Canonical public regression vectors
  tools/                        CI and packaging tools
```

## Development

Install dependencies:

```bash
pnpm install
```

Run the main local validation gate:

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, runs the type-check, then runs lint, package smoke verification, public package policy verification, test-lane coverage verification, package-boundary verification, dead-code scan, Rust formatting, Rust clippy, fast Rust kernel tests, fast Node tests, and the kernel-fast Node tests through the repository check runner.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Common focused verification commands:

```bash
pnpm run test:rust:kernel
pnpm run test:rust:kernel:accepted-setup
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run smoke:pack:npm
```

Use the narrower command that matches the component being changed. Accepted-setup proof lanes are maintainer evidence for setup/proof changes; they do not change the public boundary in [SECURITY.md](SECURITY.md).

Accepted-setup proof lanes default to accelerated local mode: incremental Rust compilation, proof checkpoint resume under `temp/test-checkpoints/`, and run logs under `logs/`. CI passes `--ci` to use the conservative prove-fresh mode. The final-package lane keeps cold-store libtest parallelism until one accelerated final-package run completes and writes its checkpoint completion manifest.

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
