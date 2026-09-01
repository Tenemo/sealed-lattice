# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for fixed-roster, private-score, top-count polling. Participants verify the poll transcript in their browsers instead of trusting a tally server, and the protocol reveals no individual scores.

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

The only poll result is the ordered list of selected option identifiers. Signed declarations, accepted ballot authorship, and whether any selected ballot is usable are also public. Individual scores and every other tally or evaluation value remain private.

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

The complete protocol is not implemented. The public package covers poll validation, canonical foundation objects and verifiers, typed refusals, and reproducible Rust/WebAssembly packaging. A standalone development-only tally compiler and evaluator remain in Rust tests.

No preparation or evaluation construction is implemented or cryptographically admitted. An internal conditional paper proof now covers one reduced one-bit/one-AND fragment, but its direct primitive assumptions and emitted Rust, WebAssembly, worker, storage, and verifier correspondence remain unproved. There is no end-to-end capability chain, active cryptographic suite, complete browser ceremony, or supported-phone qualification. See the [open security issues](SECURITY.md#open-security-issues).

A test-only randomized direct-check reference flow was removed because complementary responses under one pad would reveal a protected source and it lacked a complete security theorem. A later exact-history audit found that its removed accepted-opening verifier did not itself make the two opposite responses reachable; this correction does not restore or validate that route. The next finality-before-activation direction remains unimplemented research: no candidate protocol, visit count, resource estimate, or experimental primitive is part of the public package or evidence of security.

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

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes. Rejected-architecture evidence has no source-controlled command or executable selector.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
