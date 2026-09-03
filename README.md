# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for fixed-roster, private-score, top-count polling. It researches participant-side transcript verification without a trusted tally server. Revealing no individual scores or intermediate tally values is a design requirement, not an established security claim.

Use synthetic data only. The project has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` handles cryptographic objects, protocol verification, and participant-side workflow. A separate host application handles registration and the surrounding user experience. Participants verify one another before freezing the roster; real-world identity verification and Sybil resistance are outside the library.

The participant who starts the poll is the organizer and must belong to the frozen roster. The organizer remains an ordinary eligible participant with no special protocol authority.

## Intended ceremony

1. The host supplies the poll definition and registration workflow. Participants verify one another and freeze the public roster.
2. Every roster participant contributes to tally preparation and verifies the public transcript and private deliveries in their own browser.
3. Every participant signs one declaration: submit one private ballot package or abstain. Silence leaves the poll pending.
4. Once everyone has declared and every submission has been verified as available, the protocol derives one ballot set automatically from the complete signed inventory. There is no separate ballot-set vote.
5. The verified preparation and ballot sources determine one semantic target: public all-abstention may target no result directly; any inventory containing a submission targets the exact computation without revealing whether a submitted score vector is usable. A direct roster quorum locks in that target before any selected ballot data or result-dependent evaluation material can be released.
6. After that lock-in, verified ballot inputs or equivalent online contributions may be released and the tally evaluated. The sole evaluation returns the ordered result or no result when no submitted ballot is usable. Any participant can verify that one permitted terminal. Invalid or missing contributions leave the poll unresolved; they cannot create a conflicting global abort, retry, or another target.

The public information is exactly the frozen roster, each signed submit-or-abstain declaration, whether each submitted ballot was usable, whether any usable ballot exists, and the result. The result is the ordered list of selected option identifiers, or no result when no usable ballot exists. Honest clients submit only usable ballots, so the usability bit is constant for every honest submitter and reveals nothing about honest scores; for a corrupt submitter it attributes rejection to that participant's own signed source. Individual scores, failure predicates, and every other tally or evaluation value remain private.

The protocol protects ballot contents; it does not hide who participates. Participants do not need to be online together. Missing participation leaves the poll unresolved; it never changes the roster, lowers a threshold, or activates a fallback.

## Supported scope

Schemas, formulas, validators, and deterministic tally-circuit compilers cover:

- `3 <= n <= 20` frozen roster participants;
- `2 <= optionCount <= 20` ordered options;
- scores in `1..10`; and
- `1 <= topCount <= optionCount`.

Full cryptographic integration and supported-phone qualification target only `n = 10`, `optionCount = 10`. Other admitted shapes carry no security, runtime, or support claim.

The research target is at least 80 bits of modeled post-quantum attack work under the stated assumptions and limits. The padded tally is currently an active research direction rather than a cryptographically admitted candidate; this is not an unconditional result, a production rating, an independent audit, or a certification.

Every required participant operation must retain a scalar-capable, single-worker mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. Supported-phone qualification uses release Chrome on the selected physical phone and the exact package bytes. Native, Node.js, desktop, and emulated results are development evidence only.

## Current status

The complete protocol is not exposed by the public package. The package covers poll validation, canonical foundation objects and verifiers, typed refusals, and reproducible Rust/WebAssembly packaging. Its WebAssembly artifact is built separately without the internal construction dispatcher. The deterministic tally compiler, independent evaluator, and candidate ceremony remain internal development code.

The version-one operation-fresh padded transcript with 320-bit operation keys remains a functional full-tally vertical, but its former admitted identity `dfee7cd92b199269c24f2c87db2e6d021a721345e9b0274c53edcfb45632f1b5cfd4e41be5850eb68ec9f7b9e3f3b63aa74bb5299fb5e4dfd1f436613eba1382` is withdrawn. Those bytes use a finality quorum derived from an excluded complete-profile-rollback premise, allow all-abstain no result without every participant's required postfinality action, and lack an absorbing durable local-retirement state. The current internal repair derives seven-of-ten direct finality and requires ten purpose-separated acknowledgements of the semantic target before the kernel produces a no-result-release capability; zero through nine remain pending, and acknowledgement replay is persisted before publication. Fail-closed local retirement after attributable misconduct or detected partial state loss is still being implemented. Production dispatch remains disabled while the new bytes, theorem mapping, hostile review, and runtime evidence are rebuilt.

Version one replaces the two transcript mechanisms that broke the former full ceremony. It publishes semantic decoding information only for complete verified masked product words and authorized terminal words, never for refreshed private wires. Continuation material is fresh for every gate and receiver. Each 320-bit label is sampled independently from browser platform randomness and durably checkpointed before publication, so the former mismatch between an independent-label argument and a one-seed label corpus no longer applies to those bytes. The old public-semantic-map, reused-key, and per-basis variants remain rejected and cannot be accepted as compatibility formats or fallbacks. The separate historical sixteen-row module and parser are deleted; their former command range remains a refusal tombstone.

An independently implemented tally compiler and transcript parser regenerates every version-one circuit census, chunk boundary, manifest descriptor, legal semantic-decoder position, and terminal relation directly from serialized bytes. It matched complete scalar-WebAssembly ceremonies at `topCount=1` and `topCount=10`, and the parsed terminal matched the independent direct evaluator. Evaluation now transfers one signed participant chunk per scalar command without changing protocol bytes or durable checkpoints. The clean maximum-width development-Chromium run at `logs/2026-09-03/2026-09-03T01-01-02.000Z-evidence-padded-tally-top-count-10` covers the authenticated full-inventory reseal schedule, emitted-object resources, scalar work, and request bound for commit `22d2b4a8`; its figures remain development evidence owned by that run. Its visit instrumentation begins at roster confirmation and therefore omits join. The corrected end-to-end graph has six ordinary visits for earlier joiners, five for the last joiner, and a defined recovery maximum of ten.

A separate external release-Chrome resource proxy at `logs/2026-09-03/2026-09-03T00-53-58.980Z-evidence-external-chrome-resource-screen` passed on clean commit `22d2b4a8`. It stored, reread, and digested the generated ten-submitter maximum, executed the exact generated scalar KMAC histogram under mobile emulation, measured browser-process private memory from operating-system counters, and reclaimed the same persistent profile to zero origin usage after restart. The run binds the clean commit, runner, driver, page, configuration, package inputs, production KMAC source, resource-kernel source, production WebAssembly, and instrumented WebAssembly by digest and length. It is development proxy evidence, not the complete one-participant-at-a-time hostile-relay ceremony, mobile feasibility, physical-phone qualification, or activation.

The prior identity proceeded under three explicitly named fixed-KMAC256 games for fixed public Keccak-f[1600]. Direct-row hiding used independently sampled labels only after a compiler-topological producer step hid every earlier plaintext occurrence of the challenge label. Counterfactual continuation hiding was separate and applied only to honest receivers after a gate-specific hidden stream established conditional freshness; continuation authentication was a known-key second-preimage game. Those assumptions remain unresolved fixed-function research premises rather than published reductions. The prior theorem and fresh-session reviews are useful development evidence for unchanged padded-tally relations, but they do not admit the repaired finality, no-result-release, or local-retirement protocol.

An independently calculated 192-byte operation-key projection remains rejected reopening evidence. Its ideal-permutation theorem does not establish security for fixed public Keccak-f[1600], while its maximum-width corpus would grow to 1,441,520,630 bytes, 4.74 times the current corpus. It is not a fallback, production direction, or emitted format. There is no cryptographically admitted repaired candidate, public end-to-end capability chain, active cryptographic suite, reproducible final candidate freeze, complete external release-browser qualification, or supported-phone result. See the [open security issues](SECURITY.md#open-security-issues).

A test-only randomized direct-check reference flow was removed because complementary responses under one pad would reveal a protected source and it lacked a complete security theorem. A later exact-history audit found that its removed accepted-opening verifier did not itself make the two opposite responses reachable; this correction does not restore or validate that route. The later semantic-map and reused-continuation-key experiment is also rejected and its activation commands, byte parser, worker API, durable activation records, and resource model have been removed. Its former command range and durable object kinds are reserved tombstones, and affine-bearing preparation and source records have new incompatible versions. A replacement may decode a complete masked multiplication word only after proving that word independent of private semantics, and may decode authorized terminal outputs; it must not expose a decoder for a refreshed private wire. The 320-bit padded vertical remains the active research direction under exact direct KMAC and other named assumptions; its former admission and browser evidence do not apply to the required lifecycle repair. Reproducible final freeze, complete external release-browser closure, and selected-phone qualification remain incomplete.

## Install

Node.js 24.14.1 or later is required.

```bash
npm install sealed-lattice
```

or:

```bash
pnpm add sealed-lattice
```

## Usage

This example uses the ten-option completion profile.

```typescript
import { createCanonicalManifest, validatePollSpec } from 'sealed-lattice';

const pollValidation = validatePollSpec({
    question: 'Which proposals should be adopted?',
    options: Array.from(
        { length: 10 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
});

if (!pollValidation.isValid) {
    throw new Error(
        pollValidation.errors[0]?.message ?? 'Invalid poll specification.',
    );
}

const manifest = await createCanonicalManifest(pollValidation.normalized);
console.log(manifest.manifestHash, manifest.canonicalBytes);
```

`validatePollSpec` handles pre-protocol user input only. Protocol identity starts with the canonical manifest bytes and hash produced by the Rust/WebAssembly kernel. Import public APIs from the package root; workspace packages, tests, and internal source paths are not public API.

## Development

The repository uses Node.js 24.14.1 and pnpm 11.25.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes. Rejected-architecture evidence has no source-controlled command or executable selector.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
