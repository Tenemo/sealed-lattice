# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly prototype for threshold homomorphic polling. It explores how participants can jointly run a poll, verify its public transcript, and release an agreed result without revealing individual ballots or trusting a tally server.

The project is a research prototype for synthetic data. It has not been independently audited or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. See [SECURITY.md](SECURITY.md) for the trust boundaries and known limitations.

## How it works

The protocol is designed around a public transcript and participant-side verification:

1. A poll configuration and externally anchored participant roster define the ceremony and its threshold.
2. Participants contribute verifiable secret-sharing material and collectively derive the public and evaluation keys. No single participant holds the complete decryption key.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over ciphertexts, with a replay record that clients can check.
6. A finality quorum authorizes exactly one target result.
7. After finality, any reconstruction threshold of valid target-bound shares reveals only that approved result.

The roster and candidate-suite schemas cover `3 <= n <= 20` participants, with `f = floor((n - 1) / 3)` actively Byzantine participants, `r = floor(n / 3) + 1` reconstruction shares, and finality and state quorums of `floor((n + f) / 2) + 1` each. The sole completion and evidence target is `n = 10`, which gives `f = 3`, `r = 4`, and both quorums equal to seven. Other roster sizes pass structural validation but are unsupported and carry no security evidence.

The design requires every operation in a vote to run in the participants' own mobile browsers: quorum witnesses are other roster members acting through their own clients, transcript and mailbox services only relay bytes, and acceptance rests on canonical encodings, recomputed hashes and roots, signatures, and verified proofs over externally anchored poll and roster data. Participant state is deliberately bound to one phone and browser profile with no backup or recovery; losing it removes the participant from the current action. [SECURITY.md](SECURITY.md) describes these boundaries and their consequences.

## Prototype status

The kernel targets a fixed homomorphic-encryption parameter set selected for the `n = 10` prototype; exact parameters are provisional until the candidate suite is frozen.

Works today:

- The public package validates pre-protocol poll input and creates or verifies canonical manifests, action definitions, and board policies.
- The Rust/WebAssembly kernel canonically decodes and recomputes manifests, rosters, suite records, ceremony contexts, and action contexts, and validates the fixed algebra of the current homomorphic-encryption candidate.
- A browser-local foundation composes roster-bound key custody, authenticated local records, checkpoints, and fixed-roster state-witness roles, exercised by a fixture-backed desktop Chromium lifecycle test.
- Bounded proof machinery (typed transcripts, hostile-input decoding, pollable prover and verifier state machines, external-memory planning, cancellation) runs in Rust and through the WebAssembly worker.
- Ballot encryption, homomorphic aggregation, the encrypted evaluator, and target-release components pass focused component tests in native Rust and desktop browsers.

Not yet:

- No exact `n = 10` suite is frozen, so the kernel refuses positive suite selection and no end-to-end accepted vote path exists.
- Current proof plans exceed the kernel's fixed resource caps; a reduced proof representation is required before a candidate can activate.
- Proof-system assurance is incomplete: extractor, zero-knowledge, and quantum-model analyses remain open, and the homomorphic-encryption parameter assessment is provisional.
- No supported-phone runtime evidence exists; desktop-browser, Node.js, and native runs are development evidence only. Completion additionally requires the frozen `n = 10` build to pass the physical-phone acceptance procedure on one Samsung Galaxy S22 Ultra in Chrome and Firefox.
- Ballot, evaluator, and target-release operations are not public package APIs.

Local storage can repair interrupted same-browser writes, but it cannot recover deleted participant state or detect restoration of an older snapshot; see [SECURITY.md](SECURITY.md).

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

`validatePollSpec` handles pre-protocol user input only. Protocol identity starts with the canonical manifest bytes and hash produced by the Rust/WASM kernel.

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
