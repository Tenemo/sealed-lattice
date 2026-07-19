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
6. A finality quorum authorizes exactly one target result.
7. After finality, any reconstruction threshold of valid target-bound shares reveals only that approved result.

The roster and candidate-suite schemas and roster formulas cover
`3 <= n <= 20`, with
`f = floor((n - 1) / 3)` actively Byzantine participants,
`r = floor(n / 3) + 1` reconstruction shares, and
`q_final = q_state = floor((n + f) / 2) + 1`. The two quorums have distinct
roles despite the same count: `q_final` authorizes the result, while `q_state`
certifies a participant's one-shot state using other roster members. The sole
prototype completion and evidence target is `n = 10`, which gives `f = 3`,
`r = 4`, and both quorums equal to seven. Seven participants therefore do not
need to return decryption shares; any four valid shares suffice after finality.
All other roster sizes are officially unsupported and need no generated suite,
security evidence, or phone evidence for this prototype to be complete.

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
Cryptographic-suite validity is separate from supported-phone qualification.
Phone byte, memory, storage, and time values are planning targets and measured
optimization signals, not verifier inputs or cryptographic acceptance gates.
Reasonable target variance does not invalidate a verified suite or capability;
physical-phone evidence separately determines which exact device and build
combinations may be described as supported.

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

| Area                           | Implemented now                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Remaining boundary                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public configuration           | The public package validates pre-protocol poll input and creates or verifies canonical manifests, action definitions, and board policies. The poll display identifier and top-count input do not enter manifest identity.                                                                                                                                                                                                                                                                                                                                                                           | The application must still provide and externally confirm the action, board policy, roster, ceremony identifier, and action identifier.                                                                                                                                                                                                                                                                                                                        |
| Canonical ceremony             | Rust and WebAssembly canonically decode and recompute manifests, rosters, action definitions, board policies, version-two suite records, artifact references, suite identifiers, ceremony contexts, and action contexts. No exact `n = 10` selected-suite record is currently frozen, so the kernel intentionally refuses positive suite selection and does not mint the corresponding opaque suite capability. Phone accounting remains outside canonical suite bytes and future suite selection.                                                                                                  | Freeze the exact canonical parameters and artifacts, then regenerate exact per-family and complete-action accounting after evaluator topology, proof representation, release bounds, family-owned statement and witness derivation, and construction-specific security arguments settle. Previous proof-byte totals are not current evidence. Integrated browser composition and physical-phone qualification remain separate evidence boundaries.             |
| Browser-local foundation       | Internal browser runtime code composes canonical-board ingestion, roster-bound key custody, root-protected local records, action randomness and cursors, authenticated checkpoints, state reservations, and fixed-roster state-witness roles under one browser-owned authority. A fixture-backed `n = 10`-profile desktop Chromium lifecycle test runs eight roster-bound workers through board ingestion, seven-witness reservation certification, a target proof attempt, durable witness state, byte-identical crash continuation, and permanent retirement after lost or unauthenticated state. | Local atomicity and authentication protect honest clients against corruption, interrupted writes, and concurrent same-origin use; they do not prove that an internally consistent storage snapshot is the newest one or authorize a result release. The fixture-backed run is not production, exact-suite, proof-runtime, or supported-phone evidence. The remaining cryptographic path must bind participant-verified finality to exactly one target release. |
| Bounded common-proof machinery | The Rust kernel contains the typed transcript, bounded hostile-input decoder, pollable prover and verifier state machines, canonical proof streaming, external-memory planning and replay, cancellation, authenticated continuation bindings, absolute anti-exhaustion bounds, and bounded exact-family adapter registries. The WebAssembly worker restores authenticated checkpoint state before deferred family preparation, drives generation and verification through bounded storage, and mints an opaque proof capability only after terminal Rust verification.                              | Positive selected-suite activation remains unavailable. Each exact proof family must derive its verifier statement from accepted board objects and consume a family-owned private-witness capability before it can participate in an accepted path. Construction-specific extractor, zero-knowledge, QROM, and composition evidence also remains open. Decoded proof bytes or binding metadata never grant verification authority.                             |
| Complete vote path             | Setup, ballot, aggregation, evaluator, finality, and target-release components remain available for development and focused internal testing.                                                                                                                                                                                                                                                                                                                                                                                                                                                       | They do not yet form one accepted participant workflow, quorum-finalized authorization of exactly one target release, supported-phone profile, or production proof-system assurance. Ballot, evaluator, and target-release operations are not public package APIs.                                                                                                                                                                                             |

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
