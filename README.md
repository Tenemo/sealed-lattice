# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly research prototype for fixed-roster, private-score, top-count polling. It explores how a small group can verify a poll transcript and release one agreed result without revealing individual scores or trusting a tally server.

Use synthetic data only. The project has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` owns cryptographic objects, positive protocol verification, and participant-side workflow. A separate host application owns registration, invitations, organizer workflow, interface copy, notifications, and visit cadence. Participants verify one another before freezing the roster; real-world identity verification and Sybil resistance are outside the library.

The participant who starts the poll is the organizer and must belong to the frozen roster. That person remains an ordinary participant and eligible voter. The role is not a protocol input and grants no special key, bypass, quorum weight, finality power, or release authority.

## Intended ceremony

1. The host supplies a poll definition and registration workflow, and participants confirm and freeze the public roster and action context.
2. Every roster participant contributes to malicious tally preparation and verifies the public transcript, private deliveries, and selected garbling-preprocessing terminal in their own browser.
3. Every participant signs exactly one declaration: submit one threshold-hidden ballot package or abstain. Silence leaves the action pending.
4. A roster-complete declaration and package-availability inventory deterministically defines one selected ballot set. A roster quorum authorizes exactly that set; it cannot omit a declared available submission.
5. If no selected ballot is usable, positive verification produces the terminal no-result outcome and no target. Otherwise the preparation, selected-set, and ballot-source roots determine one computation target.
6. A roster quorum positively verifies and finalizes that exact target before any active ballot input, selected input label, or opened garbling is released.
7. Only after finality may source-bound input activation and the admitted online garbling protocol run. Any participant can positively verify the exact circuit path and obtain the uniquely determined clear result or a terminal abort; withholding leaves the ceremony unresolved.
8. Positive result verification exposes only the ordered option identifiers. The same action has no second target, corrected continuation, or retry.

The only poll result is the ordered list of selected option identifiers. Signed declarations, accepted ballot authorship, and whether any selected ballot is usable are public protocol metadata. Individual scores, aggregates, margins, comparisons, ranks, garbling masks, and evaluator intermediates are not public outputs.

The protocol provides ballot secrecy, not voter anonymity. No phase requires simultaneous presence. If required participation is missing, the ceremony waits or remains unresolved; it never changes the roster, lowers a threshold, or uses a fallback construction.

## Supported scope

Schemas, formulas, validators, and deterministic tally-circuit compilers cover:

- `3 <= n <= 20` frozen roster participants;
- `2 <= optionCount <= 20` ordered options;
- scores in `1..10`; and
- `1 <= topCount <= optionCount`.

The sole cryptographic-completion, integration, performance, and supported-phone evidence target is `n = 10`, `optionCount = 10`. Other admitted shapes are structural inputs only and carry no security, runtime, or support claim.

The target is an 80-bit reduced-assurance, post-quantum-oriented mobile research prototype. That target has not been established end to end and is not a production rating or certification.

Every required participant operation must retain a scalar-capable, single-worker mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. The sole browser qualification target is release Chrome on the selected physical phone for the exact package bytes. Native Rust, Node.js, desktop Chrome, emulation, and other browsers provide development evidence only.

## Current status

The complete ceremony is not implemented, cryptographically admitted, suite-activated, or phone-qualified.

- Canonical poll validation, context binding, typed refusals, deterministic tally semantics, scalar field and sharing primitives, authenticated storage foundations, and reproducible Rust/WebAssembly packaging exist.
- An unactivated Rust verifier now closes the minimum pre-evaluation-finality chronology for one protected input, one binary AND gate, and one clear output. It derives the target, requires seven-participant finality before source-bound activation and garbling release, computes the result or authenticated abort, and covers pending, no-result, fork, replay, rollback, and retirement behavior. This fragment is not ballot custody, BMR, a public capability, or an admitted suite.
- Reusable or conditional preparation work includes scalar sharing, salted seed custody, authenticated private delivery, recipient inventories, pseudorandom zero-sharing workloads, hidden-bit checks, and direct ballot-custody models. Several components were built for rejected garbling paths and survive only if a selected replacement consumes them. They are not a malicious-preparation theorem or `VerifiedTallyPreparation`.
- The one-slot submit-or-abstain lifecycle and verifier-driven preparation-to-result chain are not connected end to end. No malicious preparation or evaluation construction is admitted. Direct compressed coded-share garbling remains rejected because one corrupt participant can recover row selectors, wire masks, and the result before finality. The leading research chronology instead finalizes one deterministic computation target before any clear-output-capable online activation, then permits one clear-output protocol execution. The first published BMR candidate was rejected because its classical simulator rewrites an extracted adversary view after online input exchange. The second published BMR family was rejected because its preprocessing proofs require readable classical randomness or classical random-oracle programming. The packed-sharing garbling candidate was also rejected at its theorem gate: its garbling and large-field LPN security are defined only against classical polynomial-time adversaries, and its main malicious theorem remains in ideal preprocessing hybrids. Only the first candidate reached executable work, which was removed. A direct honest-majority MPC route is now under theorem and interaction review and is not an admitted construction.
- Focused scalar Node/WebAssembly results exist, but no matched browser ceremony, complete resource ledger, external-Chrome lifecycle result, or selected-phone result exists.
- The public SDK exposes foundation operations only. Production dispatch accepts no cryptographic suite.

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

The validator admits `2..20` options. This example uses the sole ten-option evidence target; structural admission does not qualify a profile.

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 10 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
    topOptionCount: 5,
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

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes. Rejected-architecture evidence has no source-controlled command or executable selector.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
