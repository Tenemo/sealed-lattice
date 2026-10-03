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

The candidate construction combines exact threshold homomorphic encryption from a dealerless fixed-roster setup, public ballot proofs, quorum-based ballot closing, deterministic encrypted ranking, and target-bound threshold release. A conditional composed argument covers setup, proofs, closing, and release under the stated assumptions, cost measure and registration limit of the [security policy](SECURITY.md#intended-security-model), but it has no independent review, so the composition is not established, and every run so far is development evidence rather than qualification.

The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or a bypass around certified target-bound result release. Every result-related interface returns only positively verified protocol capabilities and the authorized terminal result.

## Current implementation boundary

The public package exposes the participant API, which runs one participant's complete lifecycle in a browser worker: registration, roster agreement, setup contribution and verification, the ballot, closing, target votes, release shares and the local result, and the outcome verifier, which checks a poll's outcome from the relay without participant state. The package ships the participant WebAssembly module, the worker and their source manifest, from which anyone can recompute the runtime identity. The API returns only the participant's verified progress and its authorized result; it exposes no decryption of ballots, totals or intermediate values, no participant-secret export and no path around certified release. Rejected construction formats and commands have been removed rather than retained as compatibility paths.

The [protocol research workspace](crates/protocol-research/README.md) holds the Rust crates from which the participant module is built, the executable native construction and its guarded runner. Its native cryptographic workflow does not establish durable browser participation, complete security or qualification.

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
import { openParticipant } from "sealed-lattice";

const participant = openParticipant({
    namespace: "board-vote",
    relay: "https://relay.example/polls/",
});
const created = await participant.run({
    operation: "create",
    parameters: {
        role: "creator",
        question: "Which proposals should be adopted?",
        options: Array.from(
            { length: 10 },
            (_unused, optionIndex) => `Proposal ${optionIndex + 1}`,
        ),
        topCount: 3,
        maximumParticipants: 10,
        username: "Organizer",
    },
});

if (created.status === "completed") {
    console.log(created.details.poll, created.details.options);
}
```

The participant module checks the question and option labels and refuses an invalid poll as `invalid request` before it generates any key. Import the public API from the package root; workspace internals are not public API.

### Participant

`openParticipant({ namespace, relay })` opens the participant whose local state the namespace names on the page's origin; a namespace has 1 to 64 lower-case letters, digits and inner hyphens, and one namespace holds one participant of one poll. `run({ operation, parameters })` performs one operation in a fresh worker and returns `completed` with the participant's retained progress; `refused` when nothing changed, with a `reason`: `unsupported browser`, `invalid request` for malformed parameters or an unknown operation, `no participant`, `participant exists`, `insufficient storage`, `another poll`, `another runtime`, or `unavailable` at the participant's stage or role; `pending` with a `cause` and a described `reason` when it waits for `public input`, `storage` or a device `resource` such as memory, or when the participant `module` or its `worker` failed during the operation; or `stopped` when missing or inconsistent local state ended the participant for good. A later visit continues a pending participant from its last committed state. Before each operation the page asks the browser to keep the origin's storage with `navigator.storage.persist()`, and a completed operation reports whether it does as `persistentStorage`; a browser may evict storage it does not keep under storage pressure, which stops the participant, so the application warns the participant before its state becomes necessary. An operation on an empty namespace other than `create` is refused as `no participant` and leaves it empty. A participant that another build of the SDK created is refused with `reason: 'another runtime'` and that build's `runtime` identity; nothing changes, so the application can continue it with that build.

The operations follow the lifecycle: `create` registers a poll's organizer from its `question`, its option labels `options` in order, its result length `topCount` and `maximumParticipants`, the largest roster the poll admits, or joins a poll from its signed definition, `publish` delivers the registration and the organizer's poll and roster records again, `propose-roster` and `accept-roster` agree on a roster no larger than the poll admits and report the usernames its verified registrations bind, in roster order, as `rosterUsernames`, which the application shows before the participant confirms, `contribute` generates setup key material at the first `max(f + 1, 2)` roster positions, which `status` reports once the roster is retained, `confirm` confirms the roster, committing to that contribution, `open` opens the contribution once every participant's confirmation is published, `verify-setup` verifies the setup, `ballot` casts or delivers the ballot, `close` collects every other roster position's published ballot and closes, `target` signs the target vote and reports whether the participant's own ballot is included, late, omitted or not cast, which every later operation reports again, `release` releases the share, `result` combines the published shares, and `status` reports progress. A participant that signed no target reads its ballot's status from the certified target in `release` and `result`, and every operation after it locks its release reports it again. Every completed operation reports the poll's `question`, its `options` in order, each with the `identifier` the result names it by and its `label`, and `topCount`, as the participant module verified them from the signed poll definition, so the application shows the poll from them. Byte parameters are lower-case hexadecimal.

`verifyOutcome({ poll, relay })` verifies a poll's outcome from the relay without participant state, so a participant whose state stopped, or any page that holds the poll's identity and the relay's URL, can check the result. A fresh worker that holds no credential or randomness reads the published records and runs every owning verifier from the signed poll definition and roster through the setup, the close records and the certified target to its release shares; its public working storage, the IndexedDB databases `sealed-lattice-setup/verification.<poll>` and `sealed-lattice-public-evaluation/verification.<poll>`, is deleted when it ends. It returns `completed` with whether the certified target carries an `encrypted` result and the result's ordered option `identifiers`, none for a certified no-result target; `refused` for an `unsupported browser` or an `invalid request`; or `pending` with a `cause` and a described `reason` when the published records do not verify yet or the device, the module or the worker failed.

The relay is an untrusted HTTP service at the given base URL. It serves a stored record at `public/<name>` and accepts a publication at `publish/<name>?offset=<offset>` of at most one mebibyte, appending it at the record's end or accepting an identical retransmission of stored bytes, and refusing any other chunk. Record names are lower-case path segments of letters, digits, dots and hyphens. Every participant verifies what it reads, so the relay cannot create a vote, a ballot or a result, but completion needs it to keep records retrievable after their authors leave.

The worker runs from a `blob:` URL, compiles the packaged `participant.wasm` after checking its digest, and keeps its state in the IndexedDB databases `sealed-lattice-participant/<namespace>`, `sealed-lattice-setup/<namespace>`, `sealed-lattice-evaluated-target/<namespace>` and `sealed-lattice-public-evaluation/<namespace>` under a Web Lock. It needs a secure context, Web Locks, WebCrypto and IndexedDB; a content security policy must allow `worker-src blob:`, WebAssembly compilation and fetching the module and the relay. On a cross-origin isolated page, served with `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, each operation also starts one helper worker per spare core, up to eight, from the same worker source; the helpers run the module's deterministic parallel work through shared memory and hold no participant state. Without isolation, or when a helper has not started within ten seconds, the worker does that work itself, with the same results; a helper that fails leaves the operation pending.

## Development

The repository uses Node.js 24.14.1, pnpm 11.25.0, and Rust 1.95.0 with the `wasm32-unknown-unknown` target, Clippy and rustfmt for the participant module. The participant module builds offline, so fetch its locked dependencies once before the first build.

```bash
pnpm install --frozen-lockfile
cargo +1.95.0 fetch --locked --manifest-path crates/protocol-research/Cargo.toml
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
