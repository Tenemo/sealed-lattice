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

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

The repository implements canonical protocol objects, browser-local
authenticated storage, development collective BGV setup and VSS proofs, and
internal ballot, aggregation, evaluation, and target-decryption components.

These components are not yet a complete participant workflow or a supported-phone
profile. The public package does not provide accepted board finality, state
authorization, or target decryption. Proof-system and end-to-end security work
also remains open. See [SECURITY.md](SECURITY.md) for the authoritative
limitations and evidence boundaries.

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
import { validatePollSpec } from "sealed-lattice";

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

console.log(pollValidation.normalized);
```

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
