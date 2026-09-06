# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for browser-first, fixed-roster, private-score polling. It targets end-to-end post-quantum security without a trusted tally service, but that security is not yet established.

Use synthetic data only. The project has no complete voting construction, independent cryptographic audit, supported-phone qualification, or production approval. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](SECURITY.md) before experimenting.

## Intended protocol

- A poll has 3 through 20 participants and 2 through 20 ordered options.
- A valid ballot gives every option an integer score from 1 through 10. Every score defaults to 1, and there is no abstention action.
- A participant may submit at most one ballot. Invalid and late submissions are ignored, and the organizer cannot choose which valid ballots count.
- The organizer may close voting without waiting for every participant to cast a ballot. Closing must create one verifiable inventory of every authoritatively published pre-close submission, including invalid submissions with their deterministic classification and the exact accepted subset. Every accepted ballot is counted exactly once.
- The result reveals only the requested ordered option identifiers. Totals, margins, comparisons, ranks, and individual scores remain private.
- If no ballot is accepted, the protocol returns a public, verifiable no-result outcome.
- After the certified inventory exists, the required disappearance and release guarantees apply without a named participant.

The [security policy](SECURITY.md#intended-security-model) summarizes the adversary, completion boundary, and derived thresholds. Those thresholds are necessary constraints, not a complete protocol.

The leading research direction combines exact threshold homomorphic encryption, public ballot proofs, reliable ballot publication, deterministic encrypted ranking, and target-bound threshold release. Malicious distributed key generation, the publication/close theorem, exact quantum-secure proofs, concrete parameters, composition, and browser feasibility remain open.

The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or a bypass around certified target-bound result release. Any future result-related interface may return only positively verified protocol capabilities and the authorized terminal result.

## Current implementation boundary

The public package exposes construction-neutral foundation operations only:

- poll validation;
- canonical poll, action, and board-policy encoding;
- canonical manifest, action, ceremony-context, and action-context verification;
- bounded Rust/WebAssembly parsing and hashing; and
- reproducible package assembly and public-export checks.

It does not expose ballot encryption, distributed setup, tally evaluation, finality signing, decryption shares, or result reconstruction. Rejected construction formats and commands have been removed rather than retained as compatibility paths.

`sealed-vote` is the host application responsible for registration, invitations, poll management, notifications, and the user interface. Anyone with the poll link may register until the organizer closes registration. Participants use the displayed public usernames to confirm the same ordered username-to-credential roster before it is frozen and supplied to `sealed-lattice`. Public usernames do not establish real-world identity, and duplicate-person prevention, coercion resistance, and endpoint security remain outside this library.

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

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const validation = validatePollSpec({
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 10 },
        (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
    ),
});

if (!validation.isValid) {
    throw new Error(
        validation.errors[0]?.message ?? "Invalid poll specification.",
    );
}

const manifest = await createCanonicalManifest(validation.normalized);
console.log(manifest.manifestHash, manifest.canonicalBytes);
```

`validatePollSpec` handles pre-protocol user input. Protocol identity starts with the canonical bytes and hash produced by the Rust/WebAssembly kernel. Import public APIs from the package root; workspace internals are not public API.

## Development

The repository uses Node.js 24.14.1 and pnpm 11.25.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
