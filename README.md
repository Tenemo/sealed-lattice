# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly prototype for threshold homomorphic polling. It explores how participants can jointly run a poll, verify its public transcript, and release an agreed result without revealing individual ballots or trusting a tally server.

The project is development software for synthetic data. It has not been independently audited or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. See [SECURITY.md](SECURITY.md) for the current trust boundaries and known limitations.

## How it works

The protocol is designed around a public transcript and participant-side verification:

1. A poll configuration and externally anchored participant roster define the ceremony and its threshold.
2. Participants contribute verifiable secret-sharing material and collectively derive the public and evaluation keys. No single participant holds the complete decryption key.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over ciphertexts, with a replay record that clients can check.
6. A quorum of trustees produces target-bound decryption shares. Clients verify and combine them to reveal only the approved result.

Quorum certificates are reserved for shared protocol decisions such as accepted
state, finality, and authorization of the one target release. Their witnesses
are other identities from the same anchored participant roster, acting through
their own mobile-browser clients. The ceremony never requires an external
witness operator or trusted witness service. Ordinary local browser writes are
not roster-certified.

Participant action state is intentionally bound to the current phone and
browser profile. There is no backup, export, import, migration, replacement
device, or reactivation flow. Losing that state removes the participant from
the current action; the protocol continues only when the remaining participants
still satisfy the applicable setup, finality, and decryption thresholds.
If they do not, the vote may be manually restarted with a fresh action context
and fresh setup and secret material. The old action is not repaired or resumed
under newly generated local state.

Every operation required to complete a vote must run in the participant's
supported mobile browser. A desktop, native helper, server, remote prover, or
stronger device is never an accepted substitute for missing mobile capability.

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

| Area                           | Implemented now                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Remaining boundary                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public configuration           | The public package validates pre-protocol poll input and creates or verifies canonical manifests, action definitions, and board policies. The poll display identifier and top-count input do not enter manifest identity.                                                                                                                                                                                                                                                                             | The application must still provide and externally confirm the action, board policy, roster, ceremony identifier, and action identifier.                                                                                                                                                                                                                                                                                                                   |
| Canonical ceremony             | Rust and WebAssembly canonically decode and recompute manifests, rosters, action definitions, board policies, suite records, artifact references, suite identifiers, ceremony contexts, and action contexts. The fixed structural candidate binds all six artifact references, the ordered proof-family plan references, and the root-compatibility graph. Its exact evaluator setup upload accounting is 1,390,411,776 bytes, below the 2,147,483,648-byte browser profile ceiling.                  | Structural suite verification does not select a deployable suite or grant proof authority. Exact accounting finds that all twelve exact proof families exceed the 5,242,880-byte per-proof ceiling; the largest is 149,419,382 bytes. The complete action requires 9,150,628,410 proof bytes against the 1,500,000,000-byte action ceiling. Selection therefore refuses and mints no suite capability until the affected family relations are redesigned. |
| Browser-local foundation       | Internal production code composes canonical-board ingestion, roster-bound key custody, root-protected local records, action randomness and cursors, authenticated checkpoints, state reservations, and fixed-roster state-witness roles under one browser-owned authority. A desktop-browser composition test runs eight roster-bound workers through board ingestion, seven-witness reservation certification, a target proof attempt, durable witness state, byte-identical crash continuation, and permanent retirement after lost or unauthenticated state. | Local atomicity and authentication protect honest clients against corruption, interrupted writes, and concurrent same-origin use; they do not prove that an internally consistent storage snapshot is the newest one or authorize a result release. The remaining path must bind participant-verified finality to exactly one target release and pass the supported-phone profile.                                                                        |
| Bounded common-proof machinery | The Rust kernel contains the typed transcript, bounded hostile-input decoder, pollable prover and verifier state machines, canonical proof streaming, external-memory planning and replay, cancellation, authenticated continuation bindings, hard resident-memory accounting, and bounded exact-family adapter registries. The WebAssembly worker restores authenticated checkpoint state before deferred family preparation, drives generation and verification through bounded storage, and mints an opaque proof capability only after terminal Rust verification. | No selected exact proof family can currently retain an operative adapter: suite selection is unavailable at the fixed proof-resource boundary, verifier statements still require family-owned derivation from accepted board objects, and generation still requires a family-owned private-witness capability. The generic boundary therefore remains fail-closed, and decoded proof bytes or binding metadata never grant verification authority.                                                                                                                   |
| Complete vote path             | Setup, ballot, aggregation, evaluator, finality, and target-release components remain available for development and focused internal testing.                                                                                                                                                                                                                                                                                                                                                         | They do not yet form one accepted participant workflow, quorum-finalized authorization of exactly one target release, supported-phone profile, or production proof-system assurance. Ballot, evaluator, and target-release operations are not public package APIs.                                                                                                                                                                                        |

Internal storage code can atomically repair abandoned same-browser writes and
replay authenticated byte-identical outputs. Those mechanisms do not recover
deleted participant state, make it portable, or detect restoration of an older
internally consistent snapshot. A participant that acts from such a snapshot
is handled as a faulty participant at the quorum layer; adding certificates to
every local mutation would not constrain an attacker who controls that device.
See [SECURITY.md](SECURITY.md) for the authoritative limitations and evidence
boundaries.

## Installation

```bash
npm install sealed-lattice
```

or:

```bash
pnpm add sealed-lattice
```

Node.js consumers require Node.js 24.14.1 or later.

## Usage

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 20 },
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

`validatePollSpec` handles pre-protocol user input only. Protocol identity starts
with the canonical manifest bytes and hash produced by the Rust/WASM kernel.

Import public APIs from the package root. Workspace packages, test fixtures, and internal source paths are not public API.

## Development

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Useful focused verification commands are:

```bash
pnpm run tsc
pnpm run build
pnpm run test:node
pnpm run test:browser
pnpm run test:rust:kernel
pnpm run smoke:pack:npm
```

Proof-heavy tests use separate guarded runners and are intentionally excluded from routine commands. Follow the repository instructions when changing proof or setup code.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
