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
combinations may be described as supported. Prototype completion requires the
frozen exact `n = 10` suite and build to complete the separate physical-phone
acceptance procedure on one physical Samsung Galaxy S22 Ultra in both Chrome
and Firefox. Each exact browser and build combination is reported separately.
Failure in either browser leaves runtime evidence incomplete without
invalidating the cryptographic suite.

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

| Area                           | Implemented now                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Remaining boundary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public configuration           | The public package validates pre-protocol poll input and creates or verifies canonical manifests, action definitions, and board policies. The poll display identifier and top-count input do not enter manifest identity.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | The application must still provide and externally confirm the action, board policy, roster, ceremony identifier, and action identifier.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Canonical ceremony             | Rust and WebAssembly canonically decode and recompute manifests, rosters, action definitions, board policies, version-two suite records, artifact references, suite identifiers, ceremony contexts, and action contexts. For the exact unfrozen candidate, focused Rust gates recompute `ord_65536(257) = 256`, validate 128 degree-256 plaintext extension lanes, independently validate the order-256 field-root and order-64 orbit-generator roles, exercise all 190 pair placements in the exact 93/97 split, and reject mutations of the ordered target and sharing indices `0..7`, ciphertext-modulus roots, and key-switch topology. The version-four encoder-and-ballot-layout artifact binds this fixed algebra. A fixed-algebra-only candidate record round-trips with explicit test-only placeholders for the unresolved proof-profile and evaluator-program artifacts and remains ineligible for runtime selection. No exact `n = 10` selected-suite record is currently frozen, so the kernel intentionally refuses positive suite selection and does not mint the corresponding opaque suite capability. Phone accounting remains outside canonical suite bytes and future suite selection.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Freeze the exact canonical parameters and artifacts, then regenerate exact per-family and complete-action accounting after evaluator topology, proof representation, release bounds, family-owned statement and witness derivation, and construction-specific security arguments settle. Previous proof-byte totals are not current evidence. Integrated browser composition and physical-phone qualification remain separate evidence boundaries.                                                                                                                                                                                                                                                                                                                                                                                                   |
| Browser-local foundation       | Internal browser runtime code composes canonical-board ingestion, roster-bound key custody, root-protected local records, action randomness and cursors, authenticated checkpoints, state reservations, and fixed-roster state-witness roles under one browser-owned authority. A fixture-backed `n = 10`-profile desktop Chromium lifecycle test runs eight roster-bound workers through board ingestion, seven-witness reservation certification, a target proof attempt, durable witness state, byte-identical crash continuation, and permanent retirement after lost or unauthenticated state.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Local atomicity and authentication protect honest clients against corruption, interrupted writes, and concurrent same-origin use; they do not prove that an internally consistent storage snapshot is the newest one or authorize a result release. The fixture-backed run is not production, exact-suite, proof-runtime, or supported-phone evidence. The remaining cryptographic path must bind participant-verified finality to exactly one target release.                                                                                                                                                                                                                                                                                                                                                                                       |
| Bounded common-proof machinery | The Rust kernel contains the typed transcript, bounded hostile-input decoder, pollable prover and verifier state machines, canonical proof streaming, external-memory planning and replay, cancellation, authenticated continuation bindings, absolute anti-exhaustion bounds, and bounded exact-family adapter registries. The WebAssembly worker restores authenticated checkpoint state before deferred family preparation, drives generation and verification through bounded storage, and mints an opaque proof capability only after terminal Rust verification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Positive selected-suite activation remains unavailable. A clean, non-short-circuiting static diagnostic derives all `31` selected variants across all `12` proof families, and every variant exceeds at least one unchanged absolute bound of `4,096` physical external objects and `1,073,741,824` peak stored bytes. The current same-secret row requires `31,556` objects and `71,027,507,136` peak stored bytes; the ballot-validity row requires `42,690` objects and `90,900,543,424` bytes; and the widest relinearization-round-two row requires `3,469,106` objects and `7,604,134,681,760` bytes. These figures are planning evidence, not generated-proof runtime or supported-phone evidence; representation reduction and a passing capped plan remain required. Each exact proof family must also derive its verifier statement from accepted board objects and consume a family-owned private-witness capability before it can participate in an accepted path. Construction-specific extractor, zero-knowledge, QROM, and composition evidence remains open. Decoded proof bytes or binding metadata never grant verification authority. |
| Complete vote path             | Setup, ballot, aggregation, evaluator, finality, and target-release components remain available for development and focused internal testing. Native Rust tests cover ordinal-bound randomness for both ballot ciphertexts, the exact 92-polynomial pair-character catalog, and multiplicative two-stream aggregation for every selected ballot count from 1 through 10 with both outputs normalized to modulus-chain level 19. The evaluator compiler is checked against an independent test-only full-ring semantic oracle. Its bank-preserving schedule uses 36 masks, 31 routes, and 151 automorphism hops. A guarded native encrypted covering matrix compares final decrypted ciphertexts with independently computed direct stable-sort results for ballot counts 1 through 10 and every top count from 1 through 20, including stable ties, boundary cases, and adversarial arrangements. A test-only exact-error observer reconstructs over four selected primes and verifies the result against every active limb. The guarded matrix passed its single registered test in `3,759.74` test seconds and `3,759.95` guarded seconds, with `1,032,708,096` bytes (`984.9 MiB`) peak process-tree RSS under the unchanged `32 GiB` ceiling. The routine release desktop-browser component graph passes 96 tests in 27 files across Chromium, Firefox, and WebKit against byte-identical producer and SDK kernel bytes. WebAssembly-runtime orchestration tests use test-minted positively typed accepted-setup and evaluator-key-store authorities to exercise one store-custody chain into two-input evaluator replay and a local authenticated frozen-selection checkpoint. The checkpoint binds the ordered ballot sources, remints fresh Rust authorities after resume, and rebuilds aggregation from ballot ordinal zero rather than serializing ciphertext, key, proof, or product-tree state. | This component evidence does not activate a selected suite, certify a complete accepted participant workflow, provide release-build evaluator execution or desktop-browser evaluator-performance evidence, or establish supported-phone execution. Final measured error calibration and the target-release parameter freeze remain open. The checkpoint is local continuation state and grants no protocol authority. Its supplied candidate-view root binds the resumed selection context but does not certify the view's completeness or recency, participant-verified finality, or authorization of a release. Ballot, evaluator, and target-release operations are not public package APIs.                                                                                                                                                      |

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
