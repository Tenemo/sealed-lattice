# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace.

The published npm package is intentionally narrow while the protocol implementation is still being built and verified. Use it for development verification, package integration, transcript helpers, and foundation checks. It is not a complete voting library and must not be used for real ballots or ballot secrecy.

## Selected direction

The active project route is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> ballot validity proofs for the fixed encrypted-ballot relation
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first ballot proof backend candidate is the LaZer/LNP-derived no-wrap
profile. The public ballot package boundary is relation-fixed so that the proof
backend can be replaced if soundness, zero-knowledge, proof size, accepted proof
transport, or honest QROM-accounting metadata fails to close. QROM-strength
closure and mobile-compatible runtime evidence are later targets.

The first claim-bearing mobile profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. That profile is not closed yet.

## Current package boundary

The public package currently exposes development verification helpers while the full voting API is being built and verified. These cover poll specification and threshold derivation, lifecycle and transcript checks, foundation transcript verification through the bundled Rust/WASM kernel, and a set of narrow development helpers for the collective BGV setup ceremony (setup intent, common-randomness commit/reveal, recipient-local private VSS verification, signed VSS acceptances and complaints, setup contribution and certificate assembly, encrypted local trustee state export and restore, and setup package verification). Reserved complete-protocol entry points fail closed until their claim gates are actually implemented.

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
- development helpers for the collective BGV setup ceremony: setup intent, common-randomness commit/reveal, recipient-local private VSS verification, signed VSS acceptances and complaints, setup contribution and certificate assembly, encrypted local trustee state export and restore, and setup package verification;
- public SDK encrypted ballot package creation, package verification, and public ciphertext aggregation from accepted public-key material and an accepted setup handoff;
- transcript-core fixture verification through the bundled Rust/WASM kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- claim-bearing accepted setup for `CollectiveBgvSetup-v1`;
- production setup ceremony, VSS, ballot generation, or casting APIs;
- claim-bearing encrypted ballot package creation, package verification, accepted proof transport, or public aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- production target-bound decryption, target recombination, or result release APIs;
- production-readiness, audit, certification, or supported-phone claims.

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Safety boundaries

The accepted collective BGV setup for `CollectiveBgvSetup-v1` is closed for the
SL3 setup handoff under the active-static prototype boundary, and the direct
encrypted ballot package path is closed as SL3 claim-path relation evidence under
its selected proof-profile boundary. This does not make the package production,
audited, certified, supported-phone-ready, or end-to-end complete. Evaluator,
target-decryption, decoded result, finality, supported-phone runtime, QROM
strength, and conventional 128-bit quantum QROM closure remain later targets.
The package must not be used for real ballots or ballot secrecy.

The Rust/WASM transcript-core kernel can create, verify, and publicly aggregate
`EncryptedBallotPackage` artifacts from package objects, canonical ciphertext
bytes, public proof chunks, accepted public-key material, and an accepted setup
handoff root without `setupPackage`, `setupPublicMaterial`,
`setupPrivateWitness`, top-count evaluator requests, public evaluation-key
material, or plaintext oracle access in the public package commands.

In particular, the accepted collective BGV setup now has current-shape
profile-scale evidence for SL3 handoff use: the setup transport certificate binds
static measurement rows and an aggregate summary, encrypted local trustee state
export/restore carries rooted static transport evidence, the setup assembly
provenance certificate is verifier-recomputed and root-bound, and the required
manual setup-handoff evidence lane passed on 2026-06-21 after the private-VSS
family-specific accounting update. On
accepted terminal responses the setup verifier returns both
`acceptedSetupHandoff` and `acceptedPublicKeyMaterial`; the accepted ballot
package path consumes those objects directly, refuses passive setup material and
fixture-labelled randomness in accepted package creation, uses closed
`EncryptedBallotPackage` and `BallotProofChunkManifest` schemas with canonical
statement-hash vectors plus root-bound ballot layout, reserved-slot rule, witness
partition profile, arithmetic certificate hash, soundness certificate hash,
zero-knowledge certificate hash, verifier certificate hash, proof profile hash,
and batch encoder matrix identifiers, verifies voter ML-DSA protocol signature
envelopes against supplied voter signing public-key hashes and package roots,
and emits a root-bound `DirectEncryptedBallotPackageVerificationCertificate`
with the public aggregation input. Package creation emits unsigned package
material plus the exact `voterSignatureSignedRoot` for caller-side signing. The
WASM bridge and public SDK now expose accepted package creation, verification,
and public ciphertext aggregation without SDK randomness override knobs; package
creation uses Web Crypto randomness and the kernel enforces `fresh-csprng`
labels. Public aggregation re-verifies package signatures, package roots,
ciphertext transports, proof chunks, statement/profile bindings, relation
proofs, and package verification certificates before summing the verified BGV
ciphertexts and emitting a root-bound `DirectEncryptedBallotAggregateCertificate`;
private aggregation inputs, incomplete first-valid bindings, duplicate verified
package or voter replay, first-valid root mismatches, and aggregate certificate
hash tampering now have focused refusal or binding coverage. When the SDK caller
supplies first-valid ordering input, the SDK derives the verified first-valid
order hash and the kernel certificate rejects unless those ordered package roots
exactly match the verified package set.

The internal ballot proof now uses statement-derived projected scalar BGV
commitments, six projections per RNS limb component, row-specific projected
no-wrap quotient response bounds, exact signed-integer score-linkage commitments
against the full Fiat-Shamir challenge, and an appended salted masked committed
trace proof for one-hot Booleanity, ternary randomizer support,
centered-binomial error support, helper-square consistency, encoder carry
bit/slack range, projected no-wrap carry ternary-digit range, score row sums,
score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and
packed-column shape. The current deterministic command-report fixture emits a
48,175,208-byte proof, and the stable package-vector fixture emits a
48,204,584-byte proof, both using 46 one-mebibyte transport chunks. Current June
17, 2026 accepted-package runtime evidence after the direct ballot CS25/QROM
certificate update uses proof profile hash
`b3cea949d819cbcb24662ebe00ef0ee09f0a00d17d060a1b31ac4579eb1a394ba3331c660f6f4eb1cab613969a899440e74a549e2637ab355eb550461dd05c7b`
and soundness certificate hash
`ade2b1c400c5c03eeb865ce040bfd40a48e0bb850c50333e9391326fe334d2e940f0a13df3e320ec2936508a0467947b3cdd28036c703cb77e06a148facc674c`:
the native release path created, verified, and publicly aggregated a
48,149,224-byte proof in 161,507.595 ms, 59,991.540 ms, and 71,517.515 ms
respectively, and the Node/WASM bridge created, verified, and publicly
aggregated a 48,180,008-byte proof in 277,837.737 ms, 55,938.170 ms, and
63,619.524 ms respectively. The accepted package creation report now includes
`proofCostEvidence` with proof size, chunk count, kernel prove/verify timing
when the host supports timers, and a WASM measurement boundary; direct package
creation, verification, and aggregation calls through the WASM bridge attach
`wasmRuntimeEvidence` with command wall time, request and response byte lengths,
JS/WASM copy count, largest copied buffer, and linear-memory peak for the
command. The relation proof bytes now carry an explicit
format/profile/statement/dimension header, and chunk-manifest verification
checks both `statementHash` and `proofProfileHash` against proof bytes instead
of relying on a fixed statement-hash offset.

The committed trace is bound into public proof bytes, the proof profile, the
arithmetic certificate, the soundness certificate, the zero-knowledge
certificate, the verifier certificate, setup profile bindings, accepted setup
handoffs, accepted public-key material, ballot statements, and encrypted ballot
package roots. It now enforces support rows, encoder carry bit Booleanity, slack
bit Booleanity, carry bit decomposition, carry-plus-slack range, projected
no-wrap carry shifted/slack ternary digits, shifted carry decomposition, and the
projected carry range equation; the prover builds witness roots first and shares
projected BGV rows across limb proofs, native proof generation can prove limbs in
parallel, and the Node/WASM path still proves limbs serially without retaining
all limb commitments at once. Exact score-linkage soundness, projected-BGV
random-projection accounting, and committed-trace soundness accounting are
recorded in a soundness certificate with a 221-bit effective classical budget
under the named CS25 entropy-capacity low-degree row, with the proven Johnson
fallback recorded as below target at the current query count. CMS19 QROM
accounting records about 110-bit achieved quantum soundness for the accepted
statement scope and sets `qromAccepted` to false; this is recorded proof-profile
metadata, not QROM-strength closure or a conventional 128-bit quantum QROM
claim. Response-mask and committed-trace opening accounting are recorded in a
zero-knowledge certificate with 143 effective statistical bits. The arithmetic
certificate records score, encoder, committed support, response, verifier, and
BGV quotient rows; the accepted backend path is still scoped to accepted
approximate-range/no-wrap accounting rather than appending explicit carry
response polynomials. Full-profile setup-output-to-ballot integration evidence
has a current Rust kernel heavy-lane pass over the provenance-bound accepted
setup package shape. On June 21, 2026, the manual
`pnpm run test:direct-ballot:setup-handoff:evidence` lane passed with exit code
0 in 42,220,833 ms (started `2026-06-21T03:27:31.687Z`, finished
`2026-06-21T15:11:14.550Z`), running the workspace build, the 20 listed
required Rust heavy setup transport/refusal and setup-output-to-ballot tests,
the expanded 5-file public-package evidence command, and the lane-coverage
registry check.
`heavy_accepted_setup_output_drives_direct_encrypted_ballot_package_flow`
verified the accepted setup package, checked the direct-ballot setup-output
bindings and refusal matrix, created a direct encrypted ballot package, verified
it publicly, checked the package and aggregation refusal cases, and aggregated it
while consuming the `acceptedSetupHandoff` and `acceptedPublicKeyMaterial`
returned by accepted setup verification in 4,059,047 ms. That required test also
asserts that the same full-profile setup package has
static transport measurement rows for the transported VSS material, setup proof
material, public-key material, evaluation-key component material, evaluation-key
proof material, and public evaluation-key runtime material before SL3 consumes
the accepted handoff. The current required
Rust heavy-evidence registry lists 20 tests after adding final accepted-root
drift and rebound terminal trustee proof statement-hash drift checks. The
rebound terminal statement-hash drift case passes through the manual required
runner, and the full accepted-root drift matrix passed through the manual
runner on June 21, 2026 with exit code 0 in 32,406,034 ms over all 28
unique accepted roots. The rebound terminal trustee proof statement-hash drift
case passed in 1,276,431 ms. The required runner now emits one libtest thread
per selected cargo invocation by default. The normal check runner machine-checks that
required manual Rust heavy-evidence tests,
including this flow and the setup transport/refusal checks, stay named under the
manual heavy accepted-setup lane, and that the manual setup-handoff evidence
lane still includes setup public API, setup proof-material streaming, encrypted
local-state transport evidence, direct-ballot SDK handoff, and WASM bridge
command-boundary tests. It does not run the heavy proof lane, and check-runner
unit coverage asserts that the default check plan excludes the heavy package
scripts while the Rust fast lane skips the accepted setup heavy test pattern. The
manual setup-handoff evidence lane remains outside default CI. The expanded
public-package evidence command passed in the current full manual lane
with 5 test files and 32 tests after adding protocol and SDK assertions that recompute
`LocalTrusteeSetupStateTransportEvidenceRoot` from the local-state transport
evidence body. Public package API coverage checks that `verifySetupPackage` outputs are
forwarded unchanged into package creation, verification, and aggregation through
the SDK boundary; the SDK path delegates to the same Rust/WASM kernel and does
not implement a separate ballot proof verifier. The WASM bridge loader coverage
also checks the raw kernel command boundary: accepted setup verifier outputs are
forwarded into direct ballot creation, verification, and aggregation commands,
while `setupPackage` and passive `setupPublicMaterial` are excluded from those
direct ballot commands. Setup proof-material public package coverage streams the
same-secret, public-key-share, and trustee-evaluation-key transported proof
families into compact `VerifiedSetupProofMaterial` handles, or forwards
caller-supplied handles unchanged, and excludes proof chunks from the final setup
verifier command. Public setup package coverage also checks the generated
transport certificate's first-profile byte total, chunk count, storage quota,
largest-buffer bound, copy-count limit, resume policy, lazy-loading policy,
transported-object manifest, per-object static transport measurement rows, and
aggregate transport measurement summary. The heavy evidence lane remains manual
and is not added to default CI.
Supported-phone evidence remains a later runtime target, and native or Node/WASM
runs do not upgrade the package to production or supported-phone status. The
evaluator and target-decryption paths still need bounded-domain all-`K_top`
replay, target share proof certification, C1-C4 closure, and public
recombination.

Development runs on native, Node, desktop browser, or mobile-emulated browser do not count as supported-phone or production evidence. Internal package names, private workspace commands, and fixture evidence are not stable public APIs.

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
It also verifies that required manual Rust heavy-evidence tests remain covered by
the manual heavy accepted-setup lane, without running that heavy proof lane.
Check-runner unit coverage keeps the required heavy package scripts out of the
default check plan and keeps the Rust fast lane on the heavy-test skip pattern.
Use `pnpm run test:rust:kernel:heavy:required -- --list` to list the ordered
manual evidence set, and pass one or more listed test names to run selected
checkpoint-resumable evidence cases.
Use `pnpm run test:direct-ballot:setup-handoff:evidence -- --list` to inspect
the combined manual setup-handoff evidence lane before launching the full run.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Run focused verification:

```bash
pnpm run vectors
pnpm run test:rust:kernel:heavy
pnpm run test:rust:kernel:heavy:required -- --list
pnpm run test:direct-ballot:setup-handoff:evidence -- --list
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
