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
  That transport boundary does not verify the CFW or WHIR equations and cannot
  mint a proof or workflow capability.
- Release code also owns the scalar CFW mechanics, bounded external storage,
  assignment and structured-row preparation, transcript and proof assembly,
  response-tree custody, and authenticated response checkpoints. For the
  public-key-share family, guarded selected-size native execution now reaches
  the final checkpoint after all 82 responses, including both WHIR epochs and
  every live conditional-image gate. The release-state finisher emits one
  23,815,474-byte canonical compact-proof candidate, and the independent
  transport check accepts its canonical structure, transcript chronology,
  verifier queries, and salted Merkle openings. A release-owned pollable
  algebraic verifier then independently derives the structured public CFW
  contribution and verifies the CFW transcript, both WHIR epochs, all six code
  switches, both terminal blinded relations, and the authenticated source and
  mask spot checks. All five CFW polynomial transforms are incremental, and the
  verifier coalesces caller poll slices to kernel-owned boundaries spaced by
  65,536 work units. The selected CFW phase contains exactly 19,038,593 work
  units: 290 cursor boundaries cover 19,005,440 units and leave one 33,153-unit
  terminal CFW segment before the still-synchronous WHIR terminal work. Each
  boundary exposes a canonical 400-byte safe cursor that binds the four
  public-input coordinates, complete proof and public-input digests, and
  cumulative completed work. It contains no opaque transform state:
  restoration revalidates the transported bytes and deterministically replays
  from genesis before live work continues. A guarded current-source run
  destroys the first verifier, restores a fresh verifier from boundary zero,
  reproduces that cursor byte for byte, observes all 290 safe-boundary
  ordinals, and accepts the exact emitted proof. This is native prototype
  evidence only.
  Raw release-kernel begin, resume, bounded-poll, cursor-copy, and cancellation
  functions own the same verifier state. An internal TypeScript closed-worker
  driver publishes and restores the cursor, suppresses publication during
  deterministic replay, preserves typed refusals, returns a positive
  `VerificationResult` only after algebraic completion, and cancels unfinished
  operations. A concrete protocol adapter binds the verifier's source list and
  safe-boundary ordinal to the authenticated checkpoint store, retains the
  previous committed cursor across interrupted replacement, restores after
  process-local store reconstruction, and fails closed on missing or corrupt
  state. It deliberately mints no authority and is not yet installed in the
  production browser-worker flow. Bounded transport and terminal WHIR work,
  the full equation-invalid hostile corpus, and the capability transition
  remain absent.
- That guarded native run reconciles 4,926 CFW storage transactions,
  1,006,632,840 bytes written, 2,013,265,440 bytes read, and 587,202,560 peak
  logically stored bytes. A separate nonqualifying desktop Chromium diagnostic
  replayed that exact compiler-derived schedule through the production browser
  custody and strict-durability IndexedDB adapter with 655,360-byte chunks. It
  observed all 4,926 transactions and all 1,713 authenticated seals over
  1,006,633,461 plaintext bytes in about 105.6 minutes. Physical accounting
  reached a 588,382,522-byte stored peak, 1,393,676,030 bytes written, and
  1,335,448,998,100 bytes read across 4,148,340 storage transactions. The
  logical peak is 2.1875 times the 268,435,456-byte scratch planning target,
  while the namespace-wide capacity rescans cause orders-of-magnitude read and
  transaction amplification. Both results require explicit redesign and
  engineering disposition, although the logical peak remains below the
  1,073,741,824-byte absolute scratch bound. The diagnostic also exercised
  scalar release-mode WebAssembly butterfly and salted-leaf kernels, but it is
  not proof execution, complete browser lifecycle evidence, or phone evidence.
- Release generation redecodes its canonical public input, derives the
  coefficient-to-view maps, enforces the single-proof KMAC call census, and uses
  coordinate-separated KMAC256 streams for field samples, private leaf salts,
  and Fiat-Shamir salts. Its release bridge carries three symbolic quantum-PRF
  hops and the named compatible fixed-KMAC256/fixed-SHAKE256 shared-Keccak
  assumption. That assumption remains unproved and has no assigned numeric
  advantage.
- The guarded security-game owner covers the checked 82-move factor-one
  schedule, all 45 abstract construction commitments, and adaptive overlapping
  queries. It derives the Real-game conditional ranks independently from the
  compiler and compares them with the witness-free Ideal simulator's consumed
  coordinates at every disclosure. The resulting pathwise statistical distance
  is exactly zero for one fresh canonical construction attempt. This is
  construction-level theorem evidence, not an emitted-byte argument,
  salted-Merkle/EPRO privacy result, production proof, or runtime result.
- Test-only noninteractive instrumentation now derives the 165 bad-transition
  events as eight executable-owner regions (`2`, `26`, `8`, `74`, `12`, `22`,
  `10`, and `11`), derives all 15 composition boundaries, and retains the
  maximum error owned by one verifier move rather than summing the chronology.
  Its decoded actual-byte owner binds the proof/public-input pair and inventories
  response tuples, verifier messages, commitments, openings, queries, salts,
  frontier nodes, transcript absorptions, consumer edges, and the shared
  fixed-SHAKE256 verifier hash graph. The conditional Appendix A.1 calculator
  requires separate semantic, masking-correspondence, emitted-byte,
  Merkle-privacy-correspondence, and SHAKE premises and derives its relaxed-RBR
  headroom from the complete `2^-80` partition. The correspondence and SHAKE
  premises have no production constructors, so this instrumentation produces
  neither an accepted proof nor a security-bit claim.
- The selected lifecycle inventory remains 103 physical proof objects and 159
  logical relation instances. A compact corpus roll-up records the public-key
  share's 23,815,474-byte object only as a transport candidate, keeps that row
  and all eleven other family sizes explicitly blocked, and therefore reports
  no accepted ceremony-wide byte total.
- A source assertion now derives 50,331,520 live retained-response-tree bytes
  at the post-lookup release boundary. This is distinct from the
  transient-inclusive 52,952,832-byte response-storage peak and is geometry
  evidence, not a browser runtime measurement.
- The WebAssembly producer and SDK copy have a byte-for-byte reproducibility
  gate. Reproducibility establishes build identity only.

These items are development evidence only. Test-only, fixture-backed, native,
Node.js, desktop-browser, and emulated results do not establish an accepted
ceremony or supported-phone qualification.

### Remaining completion boundary

- No exact suite is frozen or selectable.
- No production compact generation API, workflow-capability handoff, or complete
  compact generation and verification ABI exists. The release
  transport ABI checks canonical structure, transcript chronology, query
  derivation, and Merkle openings only. A separate raw kernel ABI and internal
  closed-worker driver can begin or restore, bounded-poll, publish source-bound
  safe cursors through a custody contract, cancel, and return the terminal
  algebraic `VerificationResult`. This covers only the bounded CFW accumulator
  after synchronous transport revalidation. The protocol package now supplies
  a concrete authenticated-store adapter for those CFW cursors, but it is not
  connected to the production browser-worker host, complete transported
  equation-invalid hostile corpus, or capability handoff.
- The compact successor still requires correspondence between the completed
  single-attempt construction-level masking theorem and every emitted proof
  byte, the actual salted-Merkle and EPRO privacy games, and composition of the
  live KMAC bridge under its unproved joint fixed-Keccak assumption with the
  applicable SHAKE256 fixed-tape and QROM theorem chain.
- Production setup, ballot-validity, and target-release call sites have not
  been cut over to the compact proof.
- Browser custody does not yet connect the compact CFW cursor adapter to the
  production worker host or provide bounded transport, bounded terminal WHIR,
  and exact resume for every dominant compact-proof boundary.
- The accepted setup-to-release capability flow is not connected end to end.
- No compact proof has completed the scalar release-WebAssembly desktop-browser
  evidence path after guarded native generation and independent transport and
  algebraic verification.
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
