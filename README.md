# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for browser-first, fixed-roster, private-score polling. It targets end-to-end post-quantum security without a trusted tally service, but that security is not yet established.

Use synthetic data only. The project has no complete voting construction, independent cryptographic audit, supported-phone qualification, or production approval. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](SECURITY.md) before experimenting.

## Intended protocol

- A poll has 3 through 20 participants and 2 through 20 ordered options.
- A valid ballot gives every option an integer score from 1 through 10. Every score defaults to 1, and there is no abstention action.
- A participant may submit at most one ballot. Invalid and late submissions are ignored; a submission is late when its signed ballot time is after the organizer's public close time.
- The organizer may close voting without waiting for every participant to cast a ballot. For `n` participants, let `f = floor((n - 1) / 3)`, the largest whole number below one third of `n`. Closing completes once `n-f` participants, including the organizer, respond, so up to `f` participants in total who leave, lose their state, or refuse cannot block it. Closing creates one verifiable inventory of on-time submissions, including invalid submissions with their deterministic classification and the exact accepted subset. When a result is released, every accepted ballot is counted exactly once.
- Neither the organizer nor a relay can choose which valid ballots count, apart from the close time and one bounded exception: up to `f` on-time ballots can be left out by a malicious relay, alone or with the organizer, or by ordinary delays. Only ballots that reached at most `f` honest participants, counting the voter, and not an honest organizer, before the close can be left out. Each affected voter is shown that its ballot was not included, and an on-time ballot that reached at least `f+1` honest participants or an honest organizer is always included. The [security policy](SECURITY.md#intended-security-model) describes the consequences.
- The result reveals only the requested ordered option identifiers. Totals, margins, comparisons, ranks, and individual scores remain private.
- A result is released only when at least `f+2` ballots are accepted, so it always combines at least two honest voters' ballots. Otherwise the protocol returns a public, verifiable no-result outcome.
- After the certified inventory exists, the required disappearance and release guarantees apply without a named participant.

The [security policy](SECURITY.md#intended-security-model) summarizes the adversary, completion boundary, and derived thresholds. Those thresholds are necessary constraints, not a complete protocol.

The leading research direction combines exact threshold homomorphic encryption, public ballot proofs, quorum-based ballot closing, deterministic encrypted ranking, and target-bound threshold release. Malicious distributed key generation, the closing theorem, exact quantum-secure proofs, concrete parameters, composition, and browser feasibility remain open.

The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or a bypass around certified target-bound result release. Any future result-related interface may return only positively verified protocol capabilities and the authorized terminal result.

## Current implementation boundary

The public package exposes construction-neutral foundation operations only:

- poll validation;
- canonical poll, action, and board-policy encoding;
- canonical manifest, action, ceremony-context, and action-context verification;
- bounded Rust/WebAssembly parsing and hashing;
- content-addressed public-data retention and retrieval with authenticated replica acknowledgements; and
- reproducible package assembly and public-export checks.

It does not expose ballot encryption, distributed setup, tally evaluation, finality signing, decryption shares, or result reconstruction. Rejected construction formats and commands have been removed rather than retained as compatibility paths.

The separate [protocol research workspace](crates/protocol-research/README.md) contains the executable native construction and its guarded runner. It is not part of the published SDK. Its native cryptographic workflow does not establish durable browser participation, complete security or qualification.

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

### Public archive

`createPublicArchive` accepts an expected context, trusted replica endpoints and ML-DSA verification keys, an explicit replica fault bound, and closure size limits. It encodes bounded public records, checks their exact bytes and dependencies, transfers a complete declared closure, and authenticates the replicas' retention acknowledgements. `retrieve` checks cached records again and restores missing or corrupted public bytes. Its store interface contains only public records; it does not restore participant credentials or signing authority.

`discover` yields bounded pages of untrusted root hints as replicas reply. Each replica has its own cursor over immutable content identities, so a large listing remains retrievable and one replica cannot move another's cursor. This traversal order makes no statement about publication time. A returned hint, an empty reply, a record purpose, or a storage acknowledgement never establishes ballot order, acceptance, closing, or a result. The protocol's owning verifier must check that every semantic predecessor is present. Future availability depends on the configured replica fault and retention assumptions; different URLs or keys do not establish independent physical fault domains.

The repository's `tools/archive/public-archive-replica.ts` provides a local storage host exercised by the archive tests. It binds only loopback, verifies records before writing, flushes and reads staged files before replacement, and signs a retention acknowledgement only after checking the complete closure and retaining its discovery entry. Deployment, independent fault domains, power-loss durability, and long-term retention have not been qualified.

## Development

The repository uses Node.js 24.14.1 and pnpm 11.25.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
