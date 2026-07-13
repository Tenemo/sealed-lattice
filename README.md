# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly prototype for threshold homomorphic polling. It explores how participants can jointly run a poll, verify its public transcript, and release an agreed result without revealing individual ballots or trusting a tally server.

The project is development software for synthetic data. It has not been independently audited or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. See [SECURITY.md](SECURITY.md) for the current trust boundaries and known limitations.

## How it works

The protocol is designed around a public transcript and participant-side verification:

1. A poll configuration is validated, its participant roster is frozen, and quorum parameters are derived.
2. Participants contribute verifiable secret-sharing material and collectively derive the public and evaluation keys. No single participant holds the complete decryption key.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over ciphertexts, with a replay record that clients can check.
6. A quorum of trustees produces target-bound decryption shares. Clients verify and combine them to reveal only the approved result.

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

The repository contains development implementations of these building blocks:

- canonical poll, roster, and protocol-object encoding and validation;
- collective BGV setup, verifiable secret sharing, public-key construction, and evaluation-key material;
- internal bounded encrypted-ballot relations, homomorphic aggregation, and deterministic top-k evaluation; and
- target-bound threshold result release.

They are not yet composed into one complete participant workflow. The public package does not provide accepted canonical-board finality and state authorization, target release has no persistent non-forking one-shot authority, and the current setup and ballot proofs do not have the required end-to-end security arguments. The intended participant-facing verification path is a mobile browser, but the complete ceremony has not been demonstrated on supported physical phones. Native, Node.js, desktop-browser, fixture, and emulated-mobile results are development evidence only. The authoritative limitations are maintained in [SECURITY.md](SECURITY.md).

Target partial decryption remains development-only pending the security work tracked in [`SEC-016`](SECURITY.md#sec-016-theorem-matched-threshold-smudging).

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
import { deriveThresholdParameters, validatePollSpec } from "sealed-lattice";

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

const thresholdParameters = deriveThresholdParameters({ rosterSize: 10 });

console.log(pollValidation.normalized, thresholdParameters);
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
