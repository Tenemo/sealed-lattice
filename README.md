# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for fixed-roster, private-score, top-count polling. Participants verify the poll transcript in their browsers instead of trusting a tally server, and the protocol reveals no individual scores.

Use synthetic data only. The project has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` handles cryptographic objects, protocol verification, and participant-side workflow. A separate host application handles registration, invitations, organizer workflow, interface copy, notifications, and visit cadence. Participants verify one another before freezing the roster; real-world identity verification and Sybil resistance are outside the library.

The participant who starts the poll is the organizer and must belong to the frozen roster. The organizer remains an ordinary eligible participant with no special protocol authority.

## Intended ceremony

1. The host supplies the poll definition and registration workflow. Participants verify one another and freeze the public roster.
2. Every roster participant contributes to tally preparation and verifies the public transcript and private deliveries in their own browser.
3. Every participant signs one declaration: submit one private ballot package or abstain. Silence leaves the poll pending.
4. The complete declaration and package-availability inventory determines one ballot set. A roster quorum can authorize only that set. If it contains no usable ballot, the poll ends without a result.
5. Otherwise, the verified preparation and ballot sources determine one computation target. A roster quorum must finalize that target before any selected ballot input or result-dependent evaluation message is released.
6. After finality, verified ballot inputs may be released and the tally evaluated. Any participant can verify the evaluation and obtain the one permitted result or a terminal abort. Withholding leaves the poll unresolved; it does not create a retry or another target.

The only poll result is the ordered list of selected option identifiers. Signed declarations, accepted ballot authorship, and whether any selected ballot is usable are public protocol metadata. Individual scores, aggregates, margins, comparisons, ranks, and internal evaluation values are not public outputs.

The protocol provides ballot secrecy, not voter anonymity. Participants do not need to be online together. Missing participation leaves the poll unresolved; it never changes the roster, lowers a threshold, or activates a fallback.

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

The complete protocol is not implemented. Foundation code covers validation, deterministic tally semantics, typed refusals, scalar arithmetic, authenticated storage, and reproducible Rust/WebAssembly packaging. A construction-neutral verifier exercises finality before input and evaluation release, but it is not a complete ballot-custody or evaluation protocol.

No preparation or evaluation construction satisfies the full security model, no end-to-end capability chain exists, and production dispatch activates no cryptographic suite. No complete browser or supported-phone qualification exists. See the [open security issues](SECURITY.md#open-security-issues).

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
