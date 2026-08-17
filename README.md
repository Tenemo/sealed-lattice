# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly
prototype for threshold homomorphic polling. It explores how participants can
jointly run a poll, verify its public transcript, and release an agreed result
without revealing individual ballots or trusting a tally server.

The project is for synthetic data only. It has not been independently audited
or approved for production elections. Do not use it with real ballots,
credentials, keys, or secret material. See [SECURITY.md](SECURITY.md) for the
current security issues and required trust boundaries.

`sealed-lattice` is the cryptographic and protocol library. A host application,
such as `sealed-vote`, owns identity vetting, enrollment, invite distribution,
organizer workflow, user-interface behavior, and visit cadence. An organizer
may coordinate that host workflow but has no distinct cryptographic role, key,
quorum weight, proof bypass, finality power, or decryption authority.

## How it works

The protocol target is a public transcript verified by the participants'
browsers. The intended complete flow is:

1. A poll configuration and externally anchored fixed roster define the
   ceremony and thresholds.
2. Participants contribute verifiable secret-sharing material and collectively
   derive the public and evaluation keys.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate
   the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over
   ciphertexts, with a replay record that clients can verify.
6. A finality quorum authorizes exactly one target result.
7. Any reconstruction threshold of valid target-bound shares reveals only that
   approved result.

For a completed accepted vote under a frozen suite, the public result is the
ordered list of the selected `topCount` option identifiers. Exact sums,
margins, individual scores, aggregate shares, comparison bits, ranks, and
intermediate evaluator values are not public outputs.

The protocol-family schemas cover `3 <= n <= 20` participants and
`2 <= optionCount <= 20` options. General validators and deterministic
compilers derive those ranges, but the sole cryptographic, integration, and
supported-phone target is `n = 10`, `optionCount = 10`. Other sizes are
unqualified.

Every participant-facing setup, proof, verification, aggregation, evaluation,
finality, and target-release operation must retain a single-worker mobile
browser/WebAssembly path. Transcript and mailbox services relay untrusted bytes
only. They never prove, verify, tally, finalize, or decrypt.

## Prototype status

The intended complete ceremony is not yet implemented or certified. The public
SDK currently exposes foundation validation and canonical foundation objects;
collective setup, ballot acceptance, aggregation, evaluator replay, finality,
and target release remain incomplete or internal.

### Implemented development boundary

- Canonical source compilers and structural validators derive the supported
  schema ranges while the selected source profile binds the exact ten-option
  target.
- The release Rust/WebAssembly kernel supplies canonical foundation decoding,
  bindings, typed wrappers, and package integration. The canonical participant
  build remains scalar-capable.
- The rejected row-code/WHIR proof body remains only as a fail-closed
  implementation and comparison oracle until its replacement accepts the same
  transported production relations and hostile corpus.
- The compact successor's release transport boundary strictly decodes proof and
  public-input bytes, derives the verifier transcript and response-query
  schedule, validates every salted Merkle opening, and returns typed refusals.
  It does not verify the CFW or WHIR equations and cannot mint a proof or
  workflow capability.
- Release code also owns the scalar CFW mechanics, bounded external storage,
  assignment and structured-row preparation, transcript and proof assembly,
  response-tree custody, and authenticated response checkpoints. For the
  public-key-share family, guarded selected-size native execution now reaches
  the final checkpoint after all 82 responses, including both WHIR epochs and
  every live conditional-image gate. The release-state finisher emits one
  23,815,474-byte canonical compact-proof candidate, and the independent
  transport check accepts its canonical structure, transcript chronology,
  verifier queries, and salted Merkle openings. This is transport acceptance
  only: no CFW or WHIR equation is algebraically verified, so the candidate is
  not an accepted proof and mints no capability.
- That guarded native run reconciles 4,926 CFW storage transactions,
  1,006,632,840 bytes written, 2,013,265,440 bytes read, and 587,202,560 peak
  stored bytes. The peak is 2.1875 times the 268,435,456-byte scratch planning
  target and above its 50% automatic-variance band, so it still requires an
  explicit engineering disposition. It remains below the 1,073,741,824-byte
  absolute scratch bound. None of these numbers is release-WebAssembly,
  IndexedDB, browser-process, or phone evidence.
- Release generation redecodes its canonical public input, derives the
  coefficient-to-view maps, enforces the single-proof KMAC call census, and uses
  coordinate-separated KMAC256 streams for field samples, private leaf salts,
  and Fiat-Shamir salts. The terminal whole-construction simulator, the joint
  fixed-KMAC256/fixed-SHAKE256 assumption, and the fixed-tape shared-QRO premise
  remain incomplete or external assumptions.
- The test-only semantic workbench covers the checked 82-move factor-one
  schedule and terminal simulator lifecycle. It is source-level regression
  evidence, not a production proof, emitted-byte argument, or runtime result.
- The WebAssembly producer and SDK copy have a byte-for-byte reproducibility
  gate. Reproducibility establishes build identity only.

These items are development evidence only. Test-only, fixture-backed, native,
Node.js, desktop-browser, and emulated results do not establish an accepted
ceremony or supported-phone qualification.

### Remaining completion boundary

- No exact suite is frozen or selectable.
- No production compact generation API, algebraically verified emitted compact
  proof, final proof `VerificationResult`, or complete compact generation and
  verification ABI exists. The release transport ABI checks canonical
  structure, transcript chronology, query derivation, and Merkle openings only.
- The compact successor still requires a construction-level statistical-HVZK
  argument bound to the complete emitted proof, composition of the live KMAC
  bridge with its explicit quantum-PRF and joint fixed-Keccak assumptions, and
  the applicable SHAKE256 fixed-tape and QROM theorem chain.
- Production setup, ballot-validity, and target-release call sites have not
  been cut over to the compact proof.
- Browser custody does not yet provide complete proactive authenticated
  checkpointing and exact resume for every dominant compact-proof boundary.
- The accepted setup-to-release capability flow is not connected end to end.
- No compact proof has completed the scalar release-WebAssembly desktop-browser
  evidence path after guarded native generation and independent transport
  acceptance.
- No physical-phone profile is qualified. Supported-phone evidence must use the
  same frozen bytes and remains independent from cryptographic completion.
- No connected ten-participant mobile rehearsal exists.

Phone planning targets are engineering goals, not verifier inputs or suite
validity rules. Reasonable variance is recorded without weakening cryptographic
acceptance; an unexplained orders-of-magnitude variance requires redesign.

See [SECURITY.md](SECURITY.md) for the exact security assumptions, open issues,
and trust boundaries.

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

The public validator admits `2..20` options. This example uses the sole selected
prototype profile of ten options; admission alone does not qualify any other
option count.

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

Proof-heavy evidence belongs in separate guarded runners and is intended to be
excluded from routine commands. Multi-minute construction-geometry and theorem
tests have an explicitly registered, serialized evidence lane. Follow the
repository instructions when changing proof or setup code.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
