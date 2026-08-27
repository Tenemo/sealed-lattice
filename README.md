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

- Canonical poll validation, manifest construction, foundation decoding, typed bindings, and reproducible Rust/WebAssembly packaging exist.
- The active sealed-lattice research direction uses a fixed tally circuit, independent wire labels, malicious all-roster preparation, publicly checkable garbling, certified evaluation, finality, and target-bound result-mask release. Its leading preparation candidate uses scalar `GF(2^320)`, direct ordinary sharings, subset-seeded zero sharing, one same-action attempt, salted secret commitments, and a deferred collective challenge. This remains an unactivated research candidate, not an emitted malicious protocol or security theorem.
- Internal Rust owners now provide deterministic circuit semantics, the candidate scalar field and subset-stream arithmetic, salted subset, pair, and collective-coin source leaves, seed-catalog inclusion proofs, roster signatures, one-shot authorization verification, a complete semantic inventory of the ten authorized catalog roots, and an all-roster terminal verifier over that inventory. An unactivated sender-authenticated seed-mailbox slice uses roster-pinned ML-KEM-768 and ML-DSA-65 keys, fixed-output KMAC256 derivation, bounded AES-256-GCM-SIV chunks, and immediate root verification after decryption. A recipient verifier composes all nine authenticated streams and accepts one roster-pinned receipt signature over their ordered carrier identities and semantic inventory. Receipt production accepts only that typed complete authenticated inventory, checks the private signing key against the roster, requires fresh nonzero signing randomness, and positively verifies its own exact envelope. A further verifier requires one receipt at every roster position and all ten endorsements over one semantic receipt inventory. Before producing an endorsement, the endorser verifies the complete signed receipt inventory, requires its exact public receipt body and carrier to match its retained authenticated local receipt, checks its signing key against the roster, and positively verifies the produced endorsement. The terminal proves common view only and grants no key-combination, coin-opening, burn, or continuation authority. A subsequent Rust join positively verifies all 94 local catalog openings against the terminal-selected local root, requires the participant's exact retained receipt body and randomized carrier to match the public terminal entry, consumes the nine authenticated remote inventories, and derives exactly 84 subset masters, nine pair masters, and one unopened local coin source. Those master types have no production raw constructor, subset-field generation accepts only the joined type, and the join encodes one zeroizing local-custody payload bound to both terminal carriers and the retained local receipt. An internal state owner samples every local catalog contribution and salt, anchors the complete raw inventory before kernel invocation, retains the exact root and canonical local openings, and checkpoints all nine canonical recipient plaintexts before returning root bytes. Other state owners reserve each sender stream before generation, reserve one recipient's exact local seed custody and receipt intent before receipt production, and reserve one participant-and-action terminal-endorsement slot before endorsement production. A production scalar Rust/WebAssembly boundary now decodes the exact completed source and receipt records, re-verifies every roster root and receipt carrier plus both terminals, reconstructs each retained delivery against the selected root, checks local openings and byte-identical delivery-source correspondence, and emits the joined payload. The joined-state owner accepts only its module-branded adapter loaded against the package build's exact WebAssembly hash, atomically replaces both encrypted raw records, and revalidates retained public provenance on cold resume. A JavaScript object with matching method names is refused. The boundary remains unactivated and exposes no secret, burn, coin-opening, erasure, restoration, or preparation-continuation capability.
- The pre-root source owner accepts only an integrity-pinned, module-branded scalar Rust/WebAssembly producer. Rust derives and revalidates the complete 94-leaf catalog and all nine recipient plaintexts from the exact durably retained contributions and salts; an exact completion-scale source production and validation run passes under Node/WebAssembly. The sender-stream owner now also requires an integrity-pinned, module-branded scalar adapter and a one-shot opaque authorization from that completed source owner. Rust redecodes and positively verifies the complete retained source record together with the public root terminal, retains its nine canonical plaintexts in one opaque context, selects the recipient plaintext internally, produces and re-verifies each exact carrier, and accepts a manifest signature only after checking it against the terminal-selected roster key. Sender reservations retain only independent encapsulation and signature randomness plus public coordinates; callers cannot inject delivery plaintext. The protocol binding permits the opaque browser-local key owner to sign only the fixed 309-byte manifest body under its fixed context. Native tests cover actual recipient decryption and root matching; packaged Node/WebAssembly coverage currently establishes the exact ABI, integrity pin, and malformed-public-context refusal, not a successful completion-scale sender run. Receipt and endorsement production adapters and the action-wide sender lifecycle remain open. An exact native Rust completion fixture exercises the joined boundary from actual authenticated mailbox deliveries and retained local receipts; Node/WebAssembly joined-boundary evidence still covers the exact ABI, integrity pin, and typed malformed-input refusals rather than a successful completion join. None of this is browser or phone evidence. The collective-coin source and its commitment salt also lack their required verified degree-three sharing, authorized reconstruction, burn, checkpoint, and resource owners.
- The former ballot-submission candidate is rejected: a corrupt relay could retain a public masked ballot, censor it from every honest selected-set signer, and later combine it with the opening for an omitted participant. The ballot layer must instead keep the masked payload threshold-hidden until one selected ballot set is positively verified and must make included-payload and omitted-input release mutually exclusive. No replacement ballot byte format or production verifier is selected yet.
- A characteristic-two batched bit-validity check is a promising theorem and resource candidate, but it has no production graph, byte format, positive verifier, or scalar-browser evidence. Fresh same-action batch replacement and post-activation active-row-only verification are not part of the current direction.
- The former threshold-homomorphic and common-proof implementation, dependencies, bridges, fixtures, selectors, and evidence commands have been removed from the active source tree. Historical diagnostics remain development history and cannot authorize the selected design.
- The internal protocol runtime has authenticated copy-on-write storage, suite- and runtime-bound local record protection, checkpoint lineage and interrupted-publication repair, a strict-durability IndexedDB adapter, a fail-closed external-recency coordination interface, and the state owners described above. No production monotonic anchor or Rust/WebAssembly adapter for receipt or endorsement production is selected. Persistence admission, quota and reclamation evidence, the remaining operation-specific cursors, the participant worker path, and physical-phone qualification remain missing. The public SDK still exposes canonical foundation operations only.

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
