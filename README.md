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

Whenever freshness or one-shot state must be witnessed, the witnesses are other identities from the same anchored participant roster, acting through their own mobile-browser clients. Witnessing is not a separate actor class or deployment: the ceremony never requires an external witness operator or trusted witness service.

Participant action state is intentionally bound to the current phone and
browser profile. There is no backup, export, import, migration, replacement
device, or reactivation flow. Losing that state removes the participant from
the current action; the protocol continues only when the remaining participants
still satisfy the applicable setup, finality, and decryption thresholds.

Every operation required to complete a vote must run in the participant's
supported mobile browser. A desktop, native helper, server, remote prover, or
stronger device is never an accepted substitute for missing mobile capability.

Transcript and mailbox services only relay bytes. Correctness and acceptance must come from canonical encodings, recomputed hashes and roots, signatures, proof verification, and externally anchored poll and roster data.

## Prototype status

The public package currently exposes poll-specification validation and hashing,
setup-roster hashing, private-VSS share verification, and development
setup-package verification. Internal Rust and WebAssembly code exercises
canonical protocol objects, browser-local authenticated storage, collective BGV
setup and VSS components, and verification substrate for state, finality, and
namespace freshness.

Internal storage code can atomically repair abandoned same-browser writes and
replay authenticated byte-identical outputs. Those mechanisms do not recover
deleted participant state or make it portable.

Ballot creation and proof, encrypted aggregation, evaluator replay, and target
decryption remain internal, test-oriented development surfaces. They are not
accepted participant capabilities or public package APIs. The repository does
not yet compose a complete participant workflow, persistent non-forking release
path across the participant quorum, supported-phone profile, or production
proof-system assurance. See
[SECURITY.md](SECURITY.md) for the authoritative limitations and evidence
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
