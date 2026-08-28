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
5. From that verified preparation, participants perform input activation for only the input-label alternative authorized by each declaration.
6. Any participant may independently replay certified evaluation of the fixed tally circuit, reconstruct the garbling when required by the selected theorem, and positively verify every selected row. A row error produces no accepting evaluation. If no selected ballot is usable, the verifier produces no target; otherwise it derives one opaque masked result target.
7. A roster quorum whose members verified that evaluation establishes finality for the exact target.
8. A valid reconstruction threshold releases only the target-bound result masks needed to decode the ordered result.

The only poll result is the ordered list of selected option identifiers. Signed declarations, accepted ballot authorship, and whether any selected ballot is usable are public protocol metadata. Individual scores, aggregates, margins, comparisons, ranks, result masks, and evaluator intermediates are not public outputs.

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
- Conditional independent-label preparation work includes scalar sharing, salted seed custody, authenticated private delivery, recipient inventories, pseudorandom zero-sharing workloads, hidden-bit checks, and direct ballot-custody models. These components are not a malicious-preparation theorem or `VerifiedTallyPreparation`, and construction-specific field-MPC work may be removed if another garbling route is selected.
- The selected one-slot submit-or-abstain lifecycle, verifier-driven preparation-to-result chain, finality, and target-bound release are not connected end to end. The reviewed independent-label compositions fail the required malicious base-generation premise, and their distributed full-pad repair does not supply a correct adaptive base or delayed threshold decoder. The reviewed HSS/BOSS-style route also exposes output masks too early and has no matching delayed threshold-output theorem. No garbling route is selected or implemented.
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
