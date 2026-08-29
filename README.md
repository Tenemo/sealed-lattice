# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly research prototype for fixed-roster, private-score, top-count polling. It explores how a small group can verify a poll transcript and release one agreed result without revealing individual scores or trusting a tally server.

Use synthetic data only. The project has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` owns cryptographic objects, positive protocol verification, and participant-side workflow. A separate host application owns registration, invitations, organizer workflow, interface copy, notifications, and visit cadence. Participants verify one another before freezing the roster; real-world identity verification and Sybil resistance are outside the library.

The participant who starts the poll is the organizer and must belong to the frozen roster. That person remains an ordinary participant and eligible voter. The role is not a protocol input and grants no special key, bypass, quorum weight, finality power, or release authority.

## Intended ceremony

1. The host supplies a poll definition and registration workflow, and participants confirm and freeze the public roster and action context.
2. Every roster participant contributes to malicious tally preparation and verifies the public transcript, private deliveries, and selected preparation terminal in their own browser.
3. Every participant signs exactly one declaration: submit one private ballot package or abstain. Silence leaves the action pending.
4. A roster-complete declaration and package-availability inventory deterministically defines one selected ballot set. A roster quorum authorizes exactly that set; it cannot omit a declared available submission.
5. If no selected ballot is usable, positive verification produces the terminal no-result outcome and no target. Otherwise the preparation, selected-set, and ballot-source roots determine one computation target.
6. A roster quorum positively verifies and finalizes that exact target before any selected ballot input or result-dependent evaluation message is released.
7. Only after finality may verified ballot inputs be released and the admitted online evaluation run. Any participant can verify the circuit execution and obtain the uniquely determined result or a terminal abort; withholding leaves the ceremony unresolved.
8. Positive result verification exposes only the ordered option identifiers. The same action has no second target, corrected continuation, or retry.

The only poll result is the ordered list of selected option identifiers. Signed declarations, accepted ballot authorship, and whether any selected ballot is usable are public protocol metadata. Individual scores, aggregates, margins, comparisons, ranks, and internal evaluation values are not public outputs.

The protocol provides ballot secrecy, not voter anonymity. No phase requires simultaneous presence. If required participation is missing, the ceremony waits or remains unresolved; it never changes the roster, lowers a threshold, or uses a fallback construction.

## Supported scope

Schemas, formulas, validators, and deterministic tally-circuit compilers cover:

- `3 <= n <= 20` frozen roster participants;
- `2 <= optionCount <= 20` ordered options;
- scores in `1..10`; and
- `1 <= topCount <= optionCount`.

The sole target for cryptographic completion, integration, performance, and supported-phone evidence is `n = 10`, `optionCount = 10`. Other admitted shapes are structural inputs only and carry no security, runtime, or support claim.

The target is an 80-bit reduced-assurance, post-quantum-oriented mobile research prototype. That target has not been established end to end and is not a production rating or certification.

Every required participant operation must retain a scalar-capable, single-worker mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. The sole browser qualification target is release Chrome on the selected physical phone for the exact package bytes. Native Rust, Node.js, desktop Chrome, emulation, and other browsers provide development evidence only.

## Current status

The complete ceremony is not implemented, cryptographically admitted, suite-activated, or phone-qualified.

- Foundation code exists for canonical validation, deterministic tally semantics, typed refusals, scalar arithmetic, authenticated storage, and reproducible Rust/WebAssembly packaging.
- An unactivated one-gate verifier enforces target finality before verified input activation and evaluation release. It is construction-neutral development evidence, not ballot custody or an admitted evaluation protocol.
- No malicious preparation or evaluation construction is selected, and no end-to-end preparation-to-result capability exists. Retained preparation, mailbox, and state components establish only their local relations.
- No complete browser ceremony, external-Chrome result, or selected-phone qualification exists.
- The public SDK exposes foundation operations only. Production dispatch accepts no cryptographic suite. See the [open security issues](SECURITY.md#open-security-issues).

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
