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
  mask spot checks. All five CFW polynomial transforms and the seven WHIR folds
  remaining after the CFW handoff are incremental. The verifier coalesces CFW
  caller slices to kernel-owned boundaries spaced by 65,536 work units. The
  selected CFW phase contains exactly 19,038,593 work units: 290 cursor
  boundaries cover 19,005,440 units and leave one 33,153-unit terminal CFW
  segment. Contract geometry independently derives 2,129,904 remaining WHIR
  fold work units, and the current transported candidate completes them in 33
  polls of at most 65,536 units. Each CFW boundary exposes a canonical 400-byte
  safe cursor that binds the four
  public-input coordinates, complete proof and public-input digests, and
  cumulative completed work. It contains no opaque transform state:
  restoration revalidates the transported bytes and deterministically replays
  from genesis before live work continues. A guarded current-source run
  destroys the first verifier, restores a fresh verifier from boundary zero,
  reproduces that cursor byte for byte, observes all 290 safe-boundary
  ordinals, and accepts the exact emitted proof. The same guarded owner derives
  the public-key statement source independently from verified setup
  randomness, checks the canonical proof-stream descriptor and all 61 public
  ring vectors, regenerates 64 verifier-sequence columns, and rebuilds the
  four statement-owned setup-polynomial roots from the remaining 58 columns.
  All 122 transported public columns correspond to that accepted statement
  source. This is native prototype evidence for one candidate; it does not
  connect the construction masking theorem to every emitted byte or establish
  salted-Merkle or EPRO privacy.
  A source-bound accepted-setup release ABI now retains the exact statement
  authority and same-secret prerequisite, derives all four transport bindings
  internally, and carries one linear handle through prepared, running, and
  positively verified states. Its fixed 404-byte cursor extends the separate
  400-byte algebra-only cursor without serializing opaque runtime state. It
  covers the 290 CFW boundaries, one durable boundary after terminal WHIR
  returns, and 4,218 source boundaries: all 122 public columns plus 1,024
  evaluation cosets for each of four statement roots. It can begin or restore,
  bounded-poll, copy a cursor, cancel, and discard. Only after algebraic
  verification and complete source correspondence does it expose a proof
  capability; finishing that capability inserts the exact public-key-share
  terminal into the accepted setup assembly.
  The TypeScript closed-worker driver returns `isValid: true` only after that
  one-shot commit and retires its prepared, running, or positive kernel
  authority on every refusal and cancellation path. A guarded selected-size
  native run observed 33 bounded WHIR fold polls totaling 2,129,904 work units
  and exactly 4,218 source work units while reproducing all four roots and
  accepting the same 23,815,474 proof bytes. A concrete protocol adapter now
  publishes and cold-restores the
  404-byte cursor across all 4,509 accepted-verifier ordinals under a state-stream
  domain distinct from the 400-byte algebra-only cursor. It reads its byte length
  and boundary count from the loaded scalar WASM kernel and takes its operation
  kind, empty randomness cursor, and state-stream domains from canonical owners.
  Fresh and resumed custody are mutually exclusive in the worker API. A runtime
  hostile-input guard refuses both fields before kernel preparation, releases
  every distinct supplied identity once, and uses one adopted object for
  restoration, later publication, and final release. The concrete cold-restore
  test uses synthetic cursor bytes. The production custody-worker host now
  installs the accepted adapter, routes its deterministic checkpoint profile
  through a strict policy, obtains all four source digests from the prepared
  Rust verifier, publishes resume coordinates only after durable commit, and
  evicts the terminal checkpoint. Current host coverage is same-realm; it does
  not destroy and recreate a dedicated browser `Worker` or restore selected
  actual proof bytes.
  The algebraic verifier now surfaces deterministic outer polls for all seven
  WHIR folds remaining after the CFW handoff. At selected pre-challenge
  geometry, both it and verifier-derived public-covector replay fold the `2^21`
  40-byte source elements inside the original allocation and truncate it
  without allocating a clone or separate output. The public-covector replay
  still drains the shared primitive synchronously. Equivalence tests cover
  irregular poll budgets, every compact folding factor, nontrivial column
  lengths, invalid geometry, zero budgets, and terminal reuse. The six code
  switches and two base cases execute between fold polls and are not separately
  work-metered. The accepted cursor still publishes only one durable boundary
  after both WHIR epochs, so the 33 fold polls are yield and cancellation
  surfaces rather than cold-restore points. This removes the prior three-buffer
  source overlap, but it is ownership evidence rather than a browser memory
  measurement. Durable WHIR boundaries, bounded transport, selected
  actual-byte cold restoration, the full equation-invalid hostile corpus, and
  the complete durable lifecycle remain open.
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
  logical relation instances. A guarded owner emitted a 23,815,474-byte
  public-key-share candidate, and the completed production generator now feeds
  that byte length directly into the compact corpus roll-up. The proof remains
  a transport candidate rather than an accepted family size; that row and all
  eleven unknown family sizes stay blocked, so no accepted ceremony-wide byte
  total exists.
- A source assertion derives exactly 50,331,520 live retained-response-tree
  bytes at the post-lookup release boundary and separately pins the exact
  transient-inclusive 52,952,832-byte response-storage peak. Both values derive
  from all 82 production response geometries; neither is a browser runtime
  measurement.
- The WebAssembly producer and SDK copy have a byte-for-byte reproducibility
  gate. Reproducibility establishes build identity only.

These items are development evidence only. Test-only, fixture-backed, native,
Node.js, desktop-browser, and emulated results do not establish an accepted
ceremony or supported-phone qualification.

### Remaining completion boundary

- No exact suite is frozen or selectable.
- No production compact generation API, end-to-end workflow-capability handoff,
  or complete compact generation and verification ABI pair exists. The release
  transport ABI checks canonical structure, transcript chronology, query
  derivation, and Merkle openings only. The accepted-setup source-bound ABI can
  now carry one public-key-share verification through positive capability
  commit, while its internal closed-worker driver publishes source-bound safe
  cursors through a custody contract and preserves typed refusals. Its durable
  schedule covers CFW, one point after both WHIR epochs, all public-column
  reconstruction, and each statement-root coset after synchronous transport
  revalidation. The seven remaining WHIR folds are externally pollable, but
  their intermediate states are not durable cursor boundaries and their
  transition checks are not separately work-metered. The production covector
  owners reuse the input allocation rather than retaining clone and output
  buffers. The concrete
  protocol checkpoint-store adapters now separate the 400-byte, 290-boundary
  algebraic cursor from the kernel-derived 404-byte, 4,509-boundary accepted
  cursor. The worker refuses split custody before kernel preparation and retires
  every supplied identity. The custody-worker host installs the accepted
  adapter and evicts terminal state, but dedicated-worker invocation and
  destruction, selected actual-byte cold restoration, and the complete
  transported equation-invalid hostile corpus are absent.
- The compact successor still requires correspondence between the completed
  single-attempt construction-level masking theorem and every emitted proof
  byte, the actual salted-Merkle and EPRO privacy games, and composition of the
  live KMAC bridge under its unproved joint fixed-Keccak assumption with the
  applicable SHAKE256 fixed-tape and QROM theorem chain.
- Production setup, ballot-validity, and target-release call sites have not
  been cut over to the compact proof.
- Browser custody installs the single-identity accepted-cursor adapter in the
  production worker-host implementation, but has only same-realm synthetic
  resume coverage. It does not yet supply dedicated-worker destruction and
  recreation, bounded transport, durable WHIR restoration, selected actual-byte
  cold-resume evidence for every compact-proof boundary, or reconciled
  browser-origin storage reclamation.
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
