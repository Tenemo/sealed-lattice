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

The kernel setup verifier accepts setup only through the VSS commitment path: constant-size public coefficient, recipient-share, and aggregate-threshold commitments (a fixed set of field residues per commitment, independent of the ring degree) verified through succinct share-linkage and same-secret bridge proofs, with a recomputed threshold-share commitment binding. The terminal public-key-share and evaluation-key succinct proofs open the same-secret bridge's target constant commitments, so a package without the verified bridge is refused. The trustee evaluation-key family (relinearization and Galois keys) proves through the key-switch limb-group atom schedule: one hash-based masked-FRI proof per key limb group over a single wide proof field, each transcript-bound to the statement hash and its schedule position, verified against publics the verifier recombines from the statement itself; the shared succinct engine continues to serve the other setup proof families. Acceptance stays gated purely on recomputed roots and verified proof families. This is kernel-side development evidence only, and the VSS commitment's Module-SIS binding has no recorded lattice-estimator run, so 128-bit binding is a target, not a measured value. The share-linkage and same-secret bridge proof material can be streamed through the setup-proof sidecar transport rather than embedded in the package, so the canonical setup package stays encodable at production roster sizes; this changes how the proof bytes move, not their total volume, which stays the tracked transport constraint. The trustee evaluation-key component material, the largest setup material class, streams the same way through a file-backed evaluation-key component material transport rather than embedding inline, so the transported package shrinks while the verified-download volume stays unchanged. See `SEC-012` in [SECURITY.md](SECURITY.md).

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
- development-evidence target-decryption result release from a proof-backed share quorum, which verifies each decryption share's proof inline before recombining the accepted target (development evidence only, not certified; see `SEC-002` in [SECURITY.md](SECURITY.md));
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- production-ready setup ceremony, ballot generation, or casting APIs;
- public encrypted ballot package creation, verification, or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- certified target-bound decryption, the trustee target-share generation surface (feature-gated out of the default build), or a production result-release and target-finality workflow;
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

Use the narrower command that matches the component being changed. The accepted-setup proof lane is maintainer evidence for setup/proof changes; it does not change the public boundary in [SECURITY.md](SECURITY.md).

The accepted-setup proof lane defaults to accelerated local mode: incremental Rust compilation, proof checkpoint resume under `temp/test-checkpoints/`, run logs under `logs/`, and libtest/prover concurrency sized from available memory. CI passes `--ci` to use the conservative prove-fresh mode.

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
