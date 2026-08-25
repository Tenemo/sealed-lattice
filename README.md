# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly research prototype for fixed-roster, private-score, top-count polling. It explores how a small group can verify a public poll transcript and release one agreed result without revealing individual scores or trusting a tally server.

The project is for synthetic data only. It has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the current [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` owns cryptographic objects, protocol verification, and participant-side workflow. A separate host application owns identity vetting, enrollment, invitations, organizer workflow, interface copy, notifications, and visit cadence.

The host designates one organizer from the frozen roster. That person is otherwise an ordinary participant and eligible voter. The designation is not a protocol input and grants no special key, bypass, quorum weight, finality power, or release authority.

## Intended ceremony

1. The host supplies a poll definition and an externally vetted public roster, and participants freeze one action context.
2. Every roster participant contributes to maliciously secure tally preparation and verifies the public transcript and their private deliveries in their own browser.
3. A participant may submit no ballot or one fixed candidate vector. Scores and retry validity remain protected circuit inputs.
4. A roster quorum uses one-shot state to authorize one explicit candidate view. Participants verify it, derive its exact activation, and release only the authorized input-label alternatives.
5. Each participant independently replays the public certified evaluation of the fixed tally circuit. An empty usable-ballot set produces no target; otherwise the verifier derives one opaque masked result target.
6. Available roster participants establish finality for exactly that target.
7. A valid reconstruction threshold releases only the target-bound output masks needed to decode the ordered result.

The only permitted public result is the ordered list of the selected `topCount` option identifiers, or the complete ordering when all options are selected. Individual scores, aggregate scores, margins, comparisons, ranks, retry positions, output masks, and evaluator intermediates are not public outputs.

The protocol provides ballot secrecy, not voter anonymity. The frozen roster and accepted ballot authorship are public. No phase requires simultaneous presence. If required participation is missing, the ceremony waits or remains unresolved; it never lowers a threshold or uses an unsafe fallback.

## Supported scope

Schemas, formulas, validators, and deterministic tally-circuit compilers cover:

- `3 <= n <= 20` frozen roster participants;
- `2 <= optionCount <= 20` ordered options;
- scores in `1..10`; and
- `1 <= topCount <= optionCount`.

The sole cryptographic-completion, integration, performance, and supported-phone evidence target is `n = 10`, `optionCount = 10`. Concrete preparation and sharing work is currently specific to that target. Other admitted sizes are structural inputs only and carry no security, runtime, or support claim.

The target is an 80-bit reduced-assurance, post-quantum-oriented mobile research prototype. That target has not been established end to end and is not a production rating or certification.

Every required participant operation must retain a scalar-capable, single-worker mobile-browser WebAssembly path. Transcript, mailbox, and storage services relay untrusted bytes only. The sole browser qualification target is Chrome on the selected physical phone for the exact frozen package bytes. Native Rust, Node.js, desktop Chromium, and emulated devices provide development evidence only.

## Current status

The complete ceremony is not implemented, cryptographically admitted, or phone-qualified.

- Canonical poll validation, manifest construction, foundation decoding, typed bindings, and reproducible Rust/WebAssembly packaging exist.
- The selected sealed-lattice design uses a fixed tally circuit, malicious collective preparation, multiparty garbling, authenticated one-time openings, public certified evaluation, finality, and target-bound output-mask release. Internal Rust owners exist for deterministic circuit semantics, canonical circuit bytes, completion-profile sharing and labels, authenticated-opening algebra, gate-local evaluation, and preparation research models.
- The primary preparation candidate uses fixed-roster replicated-key pseudorandom sharing and Beaver multiplication. Its canonical key-component inventory, verifier-gated recipient combination, bounded field streams, and incomplete resource models exist. No exact malicious preparation theorem, complete positive verifier, end-to-end security argument, or matched scalar WebAssembly ceremony exists.
- The former threshold-homomorphic and common-proof implementation, dependencies, bridges, fixtures, selectors, and evidence commands have been removed from the active source tree. Historical diagnostics remain development history and cannot authorize the selected design.
- The public scalar WebAssembly package exposes canonical foundation operations only. The selected design has no complete generation, verification, participant custody, checkpoint, interruption, repair, reclamation, or physical-phone path.
- Governing product requirements still contain two mechanism-specific clauses from the rejected direction. They must be aligned by the project owner before any protocol activation claim.

Cryptographic completion and supported-phone qualification remain independent results for the same exact bytes. Runtime planning targets are not verifier inputs.

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

The public validator admits `2..20` options. This example uses the sole ten-option evidence target; structural admission does not qualify a profile.

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 10 },
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

`validatePollSpec` handles pre-protocol user input only. Protocol identity starts with the canonical manifest bytes and hash produced by the Rust/WebAssembly kernel. Import public APIs from the package root; workspace packages, test fixtures, and internal source paths are not public API.

## Development

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Use `pnpm run check:desktop` for browser-facing changes and `pnpm run smoke:pack:npm` for public-package changes. Rejected-architecture evidence has no source-controlled command or executable selector.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
