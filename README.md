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
unqualified. Browser qualification is Chrome-only: desktop Chromium supplies
development evidence, and the selected physical-phone profile uses Chrome.

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

- Canonical compilers and validators derive the admitted participant and option
  ranges. The exact evidence profile derives `f = 3`, `r = 4`,
  `q_final = q_state = 7`, 45 unordered option pairs, and ten evaluator
  streams.
- The release Rust/WebAssembly kernel provides canonical foundation decoding,
  typed bindings, package integration, reproducible kernel-to-SDK byte copying,
  and a scalar-capable participant build. Reproducibility establishes build
  identity only.
- The rejected row-code proof body remains in source only until the compact
  cutover can remove it atomically. Its terminal VSS and aggregate runs are
  frozen, non-gating development history: they must not be restarted, cannot
  select a suite, and are neither a production fallback nor an independent
  oracle for the compact construction.
- An independently implemented arithmetic interpreter checks all 4,046
  selected same-secret constraints across 48,552 program evaluations and
  detects deliberate evaluation corruption. Complete compact public-key
  structured matrices separately match that interpreter across 2,686,977
  operative rows and 5,701,631 padding rows; a changed matrix coefficient is
  detected. These are test-only relation-semantics and lowering evidence, not
  proof-soundness, zero-knowledge, browser, or phone evidence.
- A separate test-only native oracle starts from the canonical production VSS
  and aggregate same-secret objects and production witness. It binds distinct
  expected and observed statement bytes, application slots, statement hashes,
  attempts, proof profiles, relation variants, source catalogs, contexts, and
  roots. Independent arithmetic checks 2,621,440 VSS recipient-share
  coefficients, 262,144 degree-zero coefficients, and 196,608 anchor
  coefficients across 32 coefficient materials, 80 recipient-share materials,
  eight degree-zero materials, and three anchors. Deterministic corruption of
  every binding, compiler-constraint segment, semantic source category, and
  witness category is detected. The oracle cannot mint a capability and is not
  proof, WebAssembly, browser, or phone evidence.
- For the public-key-share family, the compact-only guarded native lane
  generated one 23,815,474-byte canonical compact-proof candidate. Independent
  code decoded and validated its transport, verified the CFW and both WHIR
  epochs, checked all code switches and live masking gates, reconstructed all
  122 public columns and four statement-owned roots, and minted a source-bound
  accepted-setup capability only after positive completion. This is one native
  vertical slice, not a selected proof backend or accepted ceremony.
- A separate hostile owner derives an independent same-slot proof attempt,
  changes one compiler-derived shifted witness value while retaining its
  original product value, and uses test-only dishonest-prover hooks to serialize
  the resulting invalid CFW transcript without weakening the production prover
  or verifier. The resulting 23,806,986-byte proof is canonically transport
  valid. All 23 CFW round polynomials are outside the honest masking affine
  image, and the full algebraic verifier refuses the first equation exactly as
  `Cfw(SumcheckConsistency { round_ordinal: 0 })`, exposed as
  `InvalidProof`. Substituting the positive proof's algebraic or
  accepted/source cursor into this independent attempt fails with
  `WrongContext`, and the hostile path cannot mint a capability. This is native
  test-only hostile evidence, not a production proof-generation mode.
- The algebraic verifier exposes a 408-byte cursor over 323 durable CFW and
  WHIR boundaries. The source-bound accepted verifier exposes a distinct
  412-byte cursor over 4,541 boundaries, adding all public-column and
  statement-root correspondence work. Restoration revalidates canonical source
  bytes and replays deterministically from genesis; the cursors contain no
  opaque transform state. The compact-only guarded lane persists both cursors
  in its producer Cargo process. A second Cargo process in the same
  runner-scoped execution rejects changed 408-byte cursor bindings, restores
  that cursor, replays it, and continues past its recorded algebraic boundary.
  It separately rejects malformed or context-mismatched 412-byte cursors,
  restores the exact accepted/source cursor, replays all 21,168,497 recorded
  algebraic work units, and continues through all 4,218 source-correspondence
  boundaries to the same terminal counts.
- The five CFW transforms and seven post-CFW WHIR folds use bounded outer
  polling, and both production covector consumers reuse and truncate the source
  allocation instead of retaining a clone and separate output. Verifier-derived
  pre-challenge and main WHIR public covectors now use the same budget-accounted
  fold primitive, with positive bounded work on every work and terminal poll.
  Guarded native tests match both epochs byte for byte against the prior
  allocation-based whole-operation replay and exercise the production owner.
  Synchronous transport revalidation, separately metered transition work, and
  release-WebAssembly and browser evidence remain open.
- Protocol custody adapters obtain cursor geometry and source digests from the
  kernel, separate fresh from resumed custody, publish only after durable
  commit, preserve typed refusals, and evict terminal state. Current host
  coverage is same-realm and synthetic; it does not yet destroy and recreate a
  dedicated browser worker around the exact candidate proof bytes.
- The current compact-CFW desktop Chromium storage diagnostic reproduced the
  compiler-derived logical schedule: 4,926 transactions,
  1,006,632,840 bytes written, 2,013,265,440 bytes read, and a
  587,202,560-byte logical peak. Repeated namespace-wide capacity scans inflated
  physical accounting to 4,148,340 transactions and
  1,335,448,998,100 bytes read over about 105.55 minutes. This is an
  implementation defect in storage accounting, not an estimate of required
  cryptographic work. The required replacement is an authenticated incremental
  ledger covering committed, staged, and orphanable bytes, updated atomically
  across every storage lifecycle with reserved repair headroom and bounded,
  resumable exclusive repair after any mismatch.
- Browser-reported usage rose to 1,009,837,865 bytes and remained
  1,009,702,372 bytes after logical cleanup reached 206 bytes. The discrepancy
  may be delayed backing-store compaction, but it remains unexplained and needs
  close, reopen, quota, and delayed-reclamation evidence. Strict IndexedDB
  durability remains required.
- A construction-level ideal-uniform masking game covers the complete
  82-response schedule and reports zero statistical distance for one fresh
  canonical attempt. It does not establish emitted-byte zero knowledge,
  salted-Merkle or EPRO privacy, reset or reused-randomness security,
  shared-oracle composition, or ceremony-wide security.
- The action inventory contains 103 physical proof objects and 159 logical
  relation instances. A guarded native owner invokes production-derived
  generation components and supplies the observed public-key-share proof length
  to a test-owned corpus roll-up. That observation is neither release
  generation nor an accepted family-size authority, and all eleven other family
  sizes remain unknown. No accepted ceremony-wide byte, transfer, storage,
  restart, or time total exists.
- Source assertions derive a 50,331,520-byte retained response-tree live set
  and a 52,952,832-byte transient-inclusive peak for all 82 response
  geometries. These are source-level bounds, not browser memory measurements.

All of this is development evidence. Test-only, fixture-backed, native,
Node.js, desktop-browser, and emulated results do not establish an accepted
ceremony or supported-phone qualification.

### Remaining completion boundary

- No exact suite is frozen or selectable. Suite selection correctly remains
  fail-closed rather than accepting a producer-supplied status or qualification
  field.
- The independent production source-and-witness baseline is complete for the
  selected VSS prerequisite and aggregate same-secret relations. The current
  compact public-key baseline now combines canonical proof generation and
  decoding, fresh full verification, independent source correspondence,
  baseline transported hostility, one transport-valid compiler-derived
  equation-invalid proof with a local typed refusal, independent-attempt cursor
  substitution, and authenticated persist, separate-process restore, replay,
  and continuation. Systematic algebraic, code-switch, WHIR,
  conditional-image, mask, query, cancellation, and resume hostility remains
  part of the public-key vertical-slice gap.
- The compact-only guarded lane has a terminal summary with no diagnostic
  failure. Its positive producer generated and verified the canonical
  23,815,474-byte proof, its independent-attempt hostile producer generated and
  locally refused the 23,806,986-byte equation-invalid proof, and its ordered
  restoration consumer ran in a distinct Cargo process. The positive producer
  persisted the 408-byte algebraic and 412-byte accepted/source cursors and
  checked 122 source-derived public columns and four statement-owned roots.
  The restoration consumer refused proof and public-input truncation and
  trailing bytes, wrong magics, response reordering, changed roots, transcript
  and opening salts, non-canonical field encodings, all four changed public
  bindings, changed proof and public-input cursor bindings, impossible CFW and
  WHIR counts, and excessive source progress. It restored and continued the
  408-byte cursor, then restored, replayed, and completed the 412-byte cursor
  to the same 4,541 safe boundaries and terminal verification. The diagnostic
  records the implementation worktree as dirty, so this remains exact-worktree
  native development evidence rather than clean-commit, WebAssembly, browser,
  or phone evidence.
- The rejected implementation's real checkpoint question is closed for its
  narrow development purpose. One controlled native run persisted,
  authenticated, and reread a 5,243,240-byte quotient state after 64 completed
  constraints and cancelled cleanly. A separate process restored that state
  and continued through authenticated 64-constraint boundaries up to constraint
  2,752 before the obsolete run was stopped. The continuation has no terminal
  proof summary and is not a proof pass. It establishes checkpoint persistence,
  separate-process restore, and continuation only; no terminal rejected-backend
  proof or aggregate run is required for compact replacement work.
- There is no complete production compact generation-and-verification
  release-WebAssembly ABI pair. The release transport validator checks
  canonical structure, transcript chronology, derived queries, and Merkle
  openings only; it is not algebraic proof verification.
- The exact public-key-share slice still needs the complete transported
  hostile corpus beyond the current deterministic semantic-equation case,
  exact emitted-byte masking and Merkle-privacy composition, fixed-tape
  shared-QRO mapping, symbolic shared-Keccak reduction, release-WebAssembly
  bounded transport and cold resume, and real dedicated-worker lifecycle in
  desktop Chromium. See SECURITY for the cryptographic consequences.
- Current source consistently uses key-switch block width three and three
  special primes. That topology is not frozen, and the joint lattice exposure,
  malicious threshold behavior, auxiliary inputs, and reductions to named
  cyclotomic-RLWE and BGV circular or key-dependent-message assumptions remain
  open. Diagnostic estimator results are not reductions.
- Pre-activation browser and proof-family evidence still needs one deterministic
  non-selectable candidate evidence identity derived from every bound candidate
  input and the exact scalar WebAssembly artifact. It carries no status or
  acceptance authority, cannot select a suite, and any bound-byte change must
  invalidate and repeat the affected evidence before suite selection.
- The host-facing approximately-ten-opening integration workflow is a design
  target, not implemented library behavior. Current ballot creation and
  verification still require
  `VerifiedSetup`. Any future pre-ratification ballot path must close joint
  multi-key and multi-branch privacy, correlated-setup, fresh-attempt,
  linkability, replay, losing-branch, and bounded-attempt obligations before its
  state schemas or suite can freeze.
- The remaining eleven proof families have not been ported through generation,
  verification, source correspondence, hostile inputs, browser custody, and
  application capability consumption.
- Production setup, ballot-validity, aggregation, evaluator, finality, and
  target-release paths have not been connected end to end through participant
  browser/WebAssembly generation and verification.
- No physical-phone Chrome profile is qualified and no connected
  ten-participant rehearsal exists. Phone qualification must use the same
  frozen suite and scalar bytes and remains independent from cryptographic
  validity.

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

The public validator admits `2..20` options. This example uses the sole
ten-option evidence target; admission alone does not qualify any other option
count or mean that a suite has been selected.

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

Proof-heavy evidence belongs in separate guarded runners and is excluded from
routine commands. Multi-minute construction-geometry and theorem tests have
explicitly registered, serialized evidence lanes. Inspect the executable
registry before invoking a manual proof lane: the rejected exact VSS and
aggregate tests are non-gating and must not be run. The current
`test:rust:kernel:proof-evidence` registry owns only an ordered compact
public-key positive producer, independent-attempt equation-invalid producer,
and separate-process restoration consumer. Inspect that executable registry
before invoking the lane; retired proof filters must fail preflight and remain
non-executable history.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
