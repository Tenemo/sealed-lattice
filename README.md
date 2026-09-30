# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for browser-first, fixed-roster, private-score polling. It targets end-to-end post-quantum security without a trusted tally service, but that security is not yet established.

Use synthetic data only. The project implements its candidate voting construction end to end, but the construction has no independent cryptographic review, supported-phone qualification, or production approval, and its end-to-end security is not established. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](SECURITY.md) before experimenting.

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

The candidate construction combines exact threshold homomorphic encryption from a dealerless fixed-roster setup, public ballot proofs, quorum-based ballot closing, deterministic encrypted ranking, and target-bound threshold release. A conditional composed argument covers setup, proofs, closing, and release under stated lattice and signature assumptions and the further premises and registration limit that the [security policy](SECURITY.md#open-security-blockers) lists, but it has no independent review, so the composition is not established, and every run so far is development evidence rather than qualification.

The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or a bypass around certified target-bound result release. Every result-related interface returns only positively verified protocol capabilities and the authorized terminal result.

## Current implementation boundary

The public package exposes construction-neutral foundation operations:

- poll validation;
- canonical poll, action, and board-policy encoding;
- canonical manifest, action, ceremony-context, and action-context verification;
- bounded Rust/WebAssembly parsing and hashing;
- content-addressed public-data retention and retrieval with authenticated replica acknowledgements; and
- reproducible package assembly and public-export checks.

It also exposes the participant API, which runs one participant's complete lifecycle in a browser worker: registration, roster agreement, setup contribution and verification, the ballot, closing, target votes, release shares and the local result, and with a configured archive the certified target closure archived before any release share and the archived transcript of the verified outcome. The package ships the participant WebAssembly module, the worker and their source manifest, from which anyone can recompute the runtime identity. The API returns only the participant's verified progress and its authorized result; it exposes no decryption of ballots, totals or intermediate values, no participant-secret export and no path around certified release. Rejected construction formats and commands have been removed rather than retained as compatibility paths.

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

`createPublicArchive` accepts an expected context, trusted replica endpoints and ML-DSA verification keys, an explicit replica fault bound, and closure size limits. It encodes bounded public records, checks their exact bytes and dependencies, transfers a complete declared closure, and authenticates the replicas' retention acknowledgements. `retrieve` checks cached records again and restores missing or corrupted public bytes. `fetch` returns one record's checked bytes from the first replica that serves them. `store` checks one record and sends it to every replica that does not already hold it, and `retain` asks the replicas to acknowledge a root whose complete closure they already hold, so a publisher that sends records as it produces them uploads each once per replica. Its store interface contains only public records; it does not restore participant credentials or signing authority.

`discover` yields bounded pages of untrusted root hints as replicas reply. Each replica has its own cursor over immutable content identities, so a large listing remains retrievable and one replica cannot move another's cursor. This traversal order makes no statement about publication time. A returned hint, an empty reply, a record purpose, or a storage acknowledgement never establishes ballot order, acceptance, closing, or a result. The protocol's owning verifier must check that every semantic predecessor is present. Future availability depends on the configured replica fault and retention assumptions; different URLs or keys do not establish independent physical fault domains.

The repository's `tools/archive/public-archive-replica.ts` provides a local storage host exercised by the archive tests. It binds only loopback, verifies records before writing, flushes and reads staged files before replacement, and signs a retention acknowledgement only after checking the complete closure and retaining its discovery entry. It reports whether it holds a record, bounds each acknowledged closure by its retrieval limits and bounds all retained records by a separate storage capacity. Deployment, independent fault domains, power-loss durability, and long-term retention have not been qualified.

### Participant

`openParticipant({ namespace, relay, archive })` opens the participant whose local state the namespace names on the page's origin; a namespace has 1 to 64 lower-case letters, digits and inner hyphens, and one namespace holds one participant of one poll. `run({ operation, parameters })` performs one operation in a fresh worker and returns `completed` with the participant's retained progress, `refused` when the operation is not available and nothing changed, `pending` when it waits for public input, storage or a device resource such as memory, or when the participant module failed during the operation, or `stopped` when missing or inconsistent local state ended the participant for good. A later visit continues a pending participant from its last committed state. An operation on an empty namespace other than `create` is refused and leaves it empty. A participant that another build of the SDK created is refused with `reason: 'another runtime'` and, when its state names it, that build's `runtime` identity; nothing changes, so the application can continue it with that build.

The operations follow the lifecycle: `create` registers a poll's organizer from its canonical manifest or joins a poll from its signed definition, `publish` delivers the registration and the organizer's poll and roster records again, `propose-roster` and `accept-roster` agree on the roster, `contribute` generates setup key material at the first `max(f + 1, 2)` roster positions, which `status` reports once the roster is retained, `confirm` confirms the roster, committing to that contribution, `open` opens the contribution once every participant's confirmation is published, `verify-setup` verifies the setup, `ballot` casts or delivers the ballot, `close` collects the published ballots of the roster positions its `deliver` and `announce` parameters name, or of every other position when it names neither, and closes, `target` signs the target vote and reports whether the participant's own ballot is included, late, omitted or not cast, which every later operation reports again, `release` releases the share, `result` combines the published shares, and `status` reports progress. Byte parameters are lower-case hexadecimal.

The optional `archive` names the archive replicas, each by an HTTPS base URL, or HTTP on a loopback address, and its ML-DSA-65 verification key, and a fault bound `b`, with at least `2b + 1` and at most 32 distinct replicas. A participant's first `release` visit then archives the certified target closure it read, as an archived transcript that more replicas than the fault bound acknowledge, before it draws any release randomness, and reports the closure's index. A participant past its close can also `archive` its outcome: the operation verifies the outcome again from the relay and sends every public record it reads, under its record name, to each replica that does not hold it, as the parts and index of an archived transcript that more replicas than the fault bound acknowledge. `transcripts` lists the transcript indexes the replicas hold for the poll, as hints, and `release` or `result` given one of them as `transcript` reads that transcript from the replicas instead of the relay, so a participant releases its share or verifies the outcome without the relay or any other participant. A transcript that does not verify leaves the participant pending, and archive failures never stop it.

The relay is an untrusted HTTP service at the given base URL. It serves a stored record at `public/<name>` and accepts a publication at `publish/<name>?offset=<offset>` of at most one mebibyte, appending it at the record's end or accepting an identical retransmission of stored bytes, and refusing any other chunk. Record names are lower-case path segments of letters, digits, dots and hyphens. Every participant verifies what it reads, so the relay cannot create a vote, a ballot or a result, but completion needs it to keep records retrievable after their authors leave.

The worker runs from a `blob:` URL, compiles the packaged `participant.wasm` after checking its digest, and keeps its state in the IndexedDB databases `sealed-lattice-participant/<namespace>`, `sealed-lattice-setup/<namespace>` and `sealed-lattice-public-evaluation/<namespace>` under a Web Lock. It needs a secure context, Web Locks, WebCrypto and IndexedDB; a content security policy must allow `worker-src blob:`, WebAssembly compilation and fetching the module, the relay and, with an archive, the SDK's kernel and the replicas. On a cross-origin isolated page, served with `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, each operation also starts one helper worker per spare core, up to eight, from the same worker source; the helpers run the module's deterministic parallel work through shared memory and hold no participant state. Without isolation, or when a helper has not started within ten seconds, the worker does that work itself, with the same results; a helper that fails leaves the operation pending.

## Development

The repository uses Node.js 24.14.1, pnpm 11.25.0, Rust 1.90.0 for the foundation kernel, and Rust 1.95.0 with the `wasm32-unknown-unknown` target for the participant module. The participant module builds offline, so fetch its locked dependencies once before the first build.

```bash
pnpm install --frozen-lockfile
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
