# sealed-lattice

`sealed-lattice` is a TypeScript and Rust/WebAssembly research library for browser-first, fixed-roster, private-score polling. It targets end-to-end post-quantum security without a trusted tally service, but that security is not yet established.

Use synthetic data only. The project implements its voting construction end to end, but the construction has no supported-phone qualification or production approval, and its end-to-end security is not established. Do not use it with real ballots, credentials, keys, or secret material. Read the [security policy](SECURITY.md) before experimenting.

## Intended protocol

- A poll has 3 through 20 participants and 2 through 20 ordered options.
- A valid ballot gives every option an integer score from 1 through 10. Every score defaults to 1, and there is no abstention action.
- A participant may submit at most one ballot. Invalid and late submissions are ignored; a submission is late when its signed ballot time is after the organizer's public close time.
- The organizer may close voting without waiting for every participant to cast a ballot. Closing creates one verifiable inventory of on-time submissions, including invalid submissions with their deterministic classification and the exact accepted subset. When a result is released, every accepted ballot is counted exactly once.
- For `n` participants, let `f = floor((n - 1) / 3)`. From roster fixing onward, up to `f` participants in total may leave, lose state or refuse without blocking the poll; the organizer remains required through closing, and after closure any `n-f` valid continuers must finish without a particular participant, including the organizer. Failures never shrink the roster, lower thresholds or remove accepted ballots.
- Neither the organizer nor the relay can choose which valid ballots count, apart from the close time and a bounded omission of at most `f` on-time ballots. Each affected voter is shown that its ballot was not included.
- The result reveals only the requested ordered option identifiers. Totals, margins, comparisons, ranks, and individual scores remain private.
- A result is released only when at least `f+2` ballots are accepted, so it always combines at least two honest voters' ballots. Otherwise the protocol returns a public, verifiable no-result outcome.

The [security policy](SECURITY.md#intended-security-model) defines the adversary, the closing quorums, the bounded omission and the completion boundary exactly. Those thresholds are necessary constraints, not a complete protocol.

The construction combines exact threshold homomorphic encryption from a dealerless fixed-roster setup, public ballot proofs, quorum-based ballot closing, deterministic encrypted ranking, and target-bound threshold release. The [security policy](SECURITY.md#open-security-blockers) lists what its security still requires.

## Current implementation boundary

The public package exposes the participant API, which runs one participant's complete lifecycle in a browser worker: registration, roster agreement, setup contribution and verification, the ballot, closing, target votes, release shares and the local result, and the outcome verifier, which checks a poll's outcome from the relay without participant state. The package ships the participant WebAssembly module, the worker and their source manifest, from which anyone can recompute the runtime identity. The API returns only the participant's verified progress and its authorized result; it exposes no decryption of ballots, totals or intermediate values, no participant-secret export and no path around certified release. Removed construction formats are not accepted as compatibility inputs or fallback modes.

Preparation binds contribution sources during registration and uses registration-bound public contribution offers, an organizer proposal and quorum endorsements before ballot authority. Original roster members can accept the certified setup without completing their own offer. Recorded scalar desktop cohorts exercise departures, recovery, state loss, turnout boundaries, split rosters, losing endorsements and independent retrieval, including a ten-participant workflow. The latest runtime changes still require renewal of that complete cohort evidence. An implemented step is not an established one: the runtime has run only in development environments, and its complete security bound, numerical registration limit, remaining resource limits and supported-phone qualification are still open.

The [protocol research workspace](crates/protocol-research/README.md) holds the Rust crates from which the participant module is built, the executable native construction and its guarded runner. Its native cryptographic workflow does not establish durable browser participation, complete security or qualification.

`sealed-vote` is the host application responsible for registration, invitations, poll management, notifications, and the user interface. Anyone with the poll link may register until the organizer closes registration and fixes the public username roster. Each participant confirms that ordered username-to-credential roster before acting on it. Public usernames do not establish real-world identity, and duplicate-person prevention, coercion resistance, and endpoint security remain outside this library.

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

### Participant API

`openParticipant({ namespace, relay })` opens the participant whose local state the namespace names on the page's origin. A namespace has 1 to 64 lower-case letters, digits and inner hyphens, and one namespace holds one participant of one poll. `run({ operation, parameters })` performs one operation in a fresh worker and returns one of four statuses:

| Status | Fields | Meaning |
| --- | --- | --- |
| `completed` | `details` | The operation finished; `details` reports the participant's retained progress. |
| `refused` | `reason`, and `runtime` for `another runtime` | Nothing changed. |
| `pending` | `cause`, `reason` | The operation could not finish yet; `reason` describes why. A later operation continues from the participant's last committed state. |
| `stopped` | `reason`, `stopPersistence` | Missing or inconsistent local state ended the participant for good. `stopPersistence` is `confirmed` when the browser durably recorded the stop and `unconfirmed` otherwise. |

A refusal's `reason` is one of:

- `unsupported browser`;
- `invalid request`, for malformed parameters or an unknown operation;
- `no participant`, for an operation other than `create` on an empty namespace, which stays empty;
- `participant exists`, `insufficient storage` or `another poll`;
- `unrecognized state`, for a namespace whose participant database this SDK does not recognize, which it leaves unchanged;
- `another runtime`, for a participant that another build of the SDK created, with that build's `runtime` identity, so the application can continue it with that build;
- `unavailable`, for an operation that the participant's stage or role does not allow.

A pending `cause` is `public input`, `storage` or a device `resource` such as memory when the operation waits for them, or `module` or `worker` when the participant module or its worker failed during the operation.

Enrollment interrupted after its intent is retained but before its required secrets are retained stops that participant, because the intent cannot resume private generation. Before each operation the page asks the browser to keep the origin's storage with `navigator.storage.persist()`, and a completed operation reports whether it does as `persistentStorage`. A browser may evict storage it does not keep under storage pressure, which stops the participant, so the application warns the participant before its state becomes necessary.

The preparation operations follow this order:

1. `create` registers the organizer from the poll question, ordered options, result length and participant maximum, or joins from its signed definition. `publish` delivers the registration and the organizer's poll and roster records again.
2. `propose-roster` and `accept-roster` verify the roster and return `rosterUsernames` in order. The application displays them before `confirm` records that participant's roster confirmation.
3. `contribute` generates and publishes a complete signed offer for an eligible original roster position. `isEligibleContributor` reports eligibility after roster retention. Eligible offers come from the first `max(f + 1, 2) + f` positions; the eventual selection uses exactly `max(f + 1, 2)` of them.
4. The organizer calls `select-setup` to propose and endorse a complete valid set. Other available participants call `endorse-setup` after verifying that set. An unfinished own offer does not prevent endorsement, and each participant endorses at most one selection.
5. `verify-setup` verifies the setup certificate and selected inputs, then activates ballot authority. It can accept the uniquely certified selection even when the participant's own offer or endorsement was not used.

After preparation, `ballot` casts or delivers the participant's single ballot. `close` gathers complete available ballots and signed close responses; the organizer proposes when the quorum is ready. `target` verifies and signs that target, `release` publishes the release share, and `result` combines valid published shares. `status` reports progress. A participant learns whether its ballot is included, late, omitted or not cast when it verifies the target, including during release or result if it signed no target. Later operations report that status again.

Completed operations report the verified poll's `question`, ordered `options` with their identifiers and labels, and `topCount`. Byte parameters are lower-case hexadecimal. Each operation resumes only the original saved state of its runtime; completed signatures are retransmitted unchanged.

### Outcome verification

`verifyOutcome({ poll, relay })` verifies a poll's outcome from the relay without participant state, so a participant whose state stopped, or any page that holds the poll's identity and the relay's URL, can check the result. A fresh worker that holds no credential or randomness reads the published records and runs every owning verifier from the signed poll definition and roster through the setup, the close records and the certified target to its release shares; its public working storage, the IndexedDB databases `sealed-lattice-setup/verification.<poll>` and `sealed-lattice-public-evaluation/verification.<poll>`, is deleted when it ends. It returns `completed` with whether the certified target carries an `encrypted` result and the result's ordered option `identifiers`, none for a certified no-result target; `refused` for an `unsupported browser` or an `invalid request`; or `pending` with a `cause` and a described `reason` when the published records do not verify yet or the device, the module or the worker failed.

### Relay

The relay is an untrusted HTTP service at the given base URL, which ends with a slash. It stores opaque bytes and append-only discovery lists and interprets none of them:

| Route | Request body | Response |
| --- | --- | --- |
| `POST chunks` | At most one mebibyte | The stored chunk's 16-byte locator |
| `GET chunk/<locator>` | | The chunk's bytes |
| `POST candidates/<key>` | A manifest of at most one mebibyte | The stored candidate's 16-byte locator, then its entry index in the key's list as a little-endian unsigned 64-bit integer |
| `GET candidate/<locator>` | | The candidate's manifest |
| `GET candidates/<key>?offset=<index>` | | The list's total entry count as a little-endian unsigned 64-bit integer, the page's entry count as a little-endian unsigned 32-bit integer, and at most 64 candidate locators in insertion order from the index |
| `POST offers/<position>` | One 64-byte body identity | Success; an identical announcement is idempotent |
| `GET offers/<position>?offset=<index>` | | The same page form, whose entries are at most 64 body identities |

A locator appears in a path as 32 lower-case hexadecimal digits. A key has at most 256 characters in slash-separated segments of lower-case letters and digits with inner dots and hyphens. A relay on another origin must allow the page's cross-origin requests. Any failed or malformed response leaves the operation pending. A publishing participant reads back every chunk, manifest and discovery entry it publishes and treats a different readback as a failure.

Setup discovery uses one `offers` list for each original author's roster position. Announcements from any caller can add candidates but cannot overwrite earlier ones; every candidate still requires its author signature and complete body proof. The organizer scans one finite snapshot per author fairly, and a later pending operation retries unavailable bodies and newly announced candidates. Every participant verifies what it reads, so the relay cannot create a vote, a ballot or a result, but completion needs it to keep chunks and manifests immutable, keep discovery lists append-only, and keep every record retrievable after its author leaves.

### Worker and browser requirements

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
