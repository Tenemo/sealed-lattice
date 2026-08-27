# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly research prototype for fixed-roster, private-score, top-count polling. It explores how a small group can verify a public poll transcript and release one agreed result without revealing individual scores or trusting a tally server.

The project is for synthetic data only. It has not been independently audited, certified, or approved for production elections. Do not use it with real ballots, credentials, keys, or secret material. Read the current [security policy](https://github.com/Tenemo/sealed-lattice/blob/master/SECURITY.md) before experimenting with the library.

## Library boundary

`sealed-lattice` owns cryptographic objects, protocol verification, and participant-side workflow. A separate host application owns identity vetting, enrollment, invitations, organizer workflow, interface copy, notifications, and visit cadence.

The host designates one organizer from the frozen roster. That person is otherwise an ordinary participant and eligible voter. The designation is not a protocol input and grants no special key, bypass, quorum weight, finality power, or release authority.

## Intended ceremony

1. The host supplies a poll definition and an externally vetted public roster, and participants freeze one action context.
2. Every roster participant contributes to maliciously secure tally preparation and verifies the public transcript and their private deliveries in their own browser.
3. A participant may submit no ballot or one fixed three-attempt ballot submission. Scores, validity, and retry selection remain protected circuit inputs.
4. A roster quorum uses one-shot state to authorize one explicit selected ballot set. Participants verify it, derive its exact activation, and release only the authorized input-label alternatives.
5. Each participant independently replays the public certified evaluation of the fixed tally circuit. An empty usable-ballot set produces no target; otherwise the verifier derives one opaque masked result target.
6. Available roster participants establish finality for exactly that target.
7. A valid reconstruction threshold releases only the target-bound result masks needed to decode the ordered result.

The only permitted public result is the ordered list of the selected `topCount` option identifiers, or the complete ordering when all options are selected. Individual scores, aggregate scores, margins, comparisons, ranks, retry positions, result masks, and evaluator intermediates are not public outputs.

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

- Canonical poll validation, manifest construction, foundation decoding, typed bindings, deterministic tally semantics, the candidate scalar field, and reproducible Rust/WebAssembly packaging exist.
- The active research direction uses a fixed tally circuit, independent wire labels, malicious all-roster preparation, publicly checkable garbling, certified evaluation, finality, and target-bound result-mask release. Its leading preparation candidate uses scalar `GF(2^320)`, ordinary sharings, subset-seeded zero sharing, one same-action attempt, salted secret commitments, and a deferred collective challenge. It remains unactivated and lacks a complete emitted protocol and theorem.
- The unactivated seed-custody slice positively verifies salted subset, pair, and collective-coin leaves; all-roster root and receipt terminals; authenticated private delivery; recipient receipt and terminal endorsement; and a joined inventory containing 84 subset masters, nine pair masters, the local coin source, and its 64-byte commitment salt. Package-integrity-pinned scalar Rust/WebAssembly boundaries and one-shot state owners enforce the implemented source, delivery, burn, join, and typed-restoration transitions. They mint no preparation, coin-opening, or continuation capability.
- Completion-scale source production and a bounded per-bit zero-sharing cursor have native and scalar Node/WebAssembly development evidence with byte-identical outputs and cold restoration. Successful completion-scale sender, recipient, endorsement, and join execution under WebAssembly, the all-roster zero-codeword verifier, state-connected cursor custody, encrypted production checkpoints, and browser execution remain absent.
- The former public masked-ballot candidate is rejected under a service-censorship attack. Direct degree-three sharing of the compiler-derived masked bundle is the only retained replacement candidate; encrypting the same bundle under a degree-three-shared seed is rejected because it keeps the identical share-custody problem while adding KMAC, authenticated-encryption, ciphertext, nonce, and erasure obligations. No threshold-held ballot byte format or positive release verifier has yet established mutually exclusive included-payload and omitted-input release.
- The characteristic-two batched bit-validity route is compiler, arithmetic, and resource-model evidence only. Its emitted challenge protocol, all-roster verifier, burn transition, scalar cursor, and theorem remain open.
- The malicious seed theorem, multi-user quantum-pseudorandom-function argument, fixed-Keccak/KMAC transition, salted-commitment and garbling reductions, complete emitted-protocol simulator, and advantage ledger remain open. Standards-conformant KMAC framing and passing known-answer tests do not close those reductions.
- Authenticated storage, checkpoint-lineage, strict-durability IndexedDB, and abstract recency-coordination foundations exist. A production monotonic anchor, action-wide mutation enclosure, persistence and quota admission, bounded repair, physical reclamation, participant worker lifecycle, external Chrome evidence, and physical-phone qualification remain missing.
- The former threshold-homomorphic and common-proof implementation and executable evidence paths have been removed from the active source tree. Historical diagnostics cannot authorize the selected construction. The public SDK continues to expose foundation operations only.

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
