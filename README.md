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

The research target is at least 80 bits of modeled post-quantum attack work under the stated assumptions and limits. It has not been established end to end and is not a production rating or certification.

Every required participant operation must retain a scalar-capable, single-worker mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. Supported-phone qualification uses release Chrome on the selected physical phone and the exact package bytes. Native, Node.js, desktop, and emulated results are development evidence only.

## Current status

The complete protocol is not exposed by the public package. The package covers poll validation, canonical foundation objects and verifiers, typed refusals, and reproducible Rust/WebAssembly packaging. Its WebAssembly artifact is built separately without the internal construction dispatcher. The deterministic tally compiler, independent evaluator, and candidate ceremony remain internal development code.

No complete preparation or evaluation construction is cryptographically admitted. The leading internal candidate is the version-one operation-fresh padded transcript with 320-bit operation keys. It exercises the real ten-participant, ten-option tally for every `topCount` from one through ten through production Rust, scalar WebAssembly, a dedicated worker, and browser-local durable state. It covers submitted and abstaining participants, unusable ballots, all abstention, direct eight-of-ten finality, one postfinality activation wave, segmented cold restore, corrupt and withheld messages, malformed cryptography, forks, rollback, state loss, result uniqueness, and verified result or no result. The worker and finality verifier derive the roster, source set, circuit, output width, predecessor, and activation bindings from verified capabilities rather than trusting ambient agreement. Those results are reusable functional evidence, not cryptographic admission.

Version one replaces the two transcript mechanisms that broke the former full ceremony. It publishes semantic decoding information only for complete verified masked product words and authorized terminal words, never for refreshed private wires. Continuation material is fresh for every gate and receiver. Each 320-bit label is sampled independently from browser platform randomness and durably checkpointed before publication, so the former mismatch between an independent-label argument and a one-seed label corpus no longer applies to those bytes. The old public-semantic-map, reused-key, and per-basis variants remain rejected and cannot be accepted as compatibility formats or fallbacks.

An independently implemented tally compiler and transcript parser regenerates every version-one circuit census, chunk boundary, manifest descriptor, legal semantic-decoder position, and terminal relation directly from serialized bytes. It matched complete scalar-WebAssembly ceremonies at `topCount=1` and `topCount=10`, and the parsed terminal matched the independent direct evaluator. The maximum-width run emitted a 304,336,370-byte activation-chunk corpus, used 319,304,184 bytes of measured origin storage, and kept WebAssembly linear memory at 15,990,784 bytes. Its visit instrumentation began at roster confirmation and recorded five later loads, so it omitted the join visit. The corrected end-to-end graph has six ordinary visits for earlier joiners, five for the last joiner, and a defined recovery maximum of ten. These are development-browser correspondence and resource results for the unadmitted candidate, not cold-page external-browser or mobile qualification. The harness hosts all participant stores and the relay in one test page, and its whole process-tree memory is not the required browser-process increase over idle.

The candidate now proceeds under an explicitly named direct multi-user, multi-output KMAC256 assumption for fixed public Keccak-f[1600], at the exact emitted key, call, replacement, fan-out, and adversarial-query census. Row hiding and adversary-chosen wrong-key continuation authentication are separate games. This assumption is not a theorem or an established security claim; it is the same kind of explicit fixed-function boundary already used for the candidate's other standardized primitives. One conditional argument now maps source privacy and extraction, malicious preparation, fixed AES and shorter KDFs, local state, and straight-line static-quantum composition to exact lemmas or named direct assumptions. Independent byte-level and proof review, followed by the admission decision, remain incomplete.

An independently calculated 192-byte operation-key projection remains a dormant fallback if cryptographic review rejects the direct KMAC assumption. Its ideal-permutation theorem does not establish security for fixed public Keccak-f[1600], while its maximum-width corpus would grow to 1,441,520,630 bytes, 4.74 times the current corpus. It is not the production direction and has not been emitted. There is still no public end-to-end capability chain, active cryptographic suite, reproducible candidate freeze, external release-browser qualification, or supported-phone result. See the [open security issues](SECURITY.md#open-security-issues).

A test-only randomized direct-check reference flow was removed because complementary responses under one pad would reveal a protected source and it lacked a complete security theorem. A later exact-history audit found that its removed accepted-opening verifier did not itself make the two opposite responses reachable; this correction does not restore or validate that route. The later semantic-map and reused-continuation-key experiment is also rejected and its activation commands, byte parser, worker API, durable activation records, and resource model have been removed. Its former command range and durable object kinds are reserved tombstones, and affine-bearing preparation and source records have new incompatible versions. A replacement may decode a complete masked multiplication word only after proving that word independent of private semantics, and may decode authorized terminal outputs; it must not expose a decoder for a refreshed private wire. The 320-bit padded vertical is the leading unadmitted candidate under the direct KMAC assumption. Its exact games now have a conditional mapping, but the required independent cryptographic review and admission walk remain incomplete. Reproducible candidate freeze, external release-browser closure, and selected-phone qualification have not begun.

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
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 10 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
});

if (!pollValidation.isValid) {
    throw new Error(
        pollValidation.errors[0]?.message ?? "Invalid poll specification.",
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
