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
- The rejected row-code proof body remains fail-closed until a successor
  accepts the same production corpus and hostile cases. It is not an approved
  mobile proving backend or a fallback to preserve after cutover.
- For the public-key-share family, a guarded native owner generated one
  23,815,474-byte canonical compact-proof candidate. Independent code validated
  its transport, verified the CFW and both WHIR epochs, checked all code
  switches and live masking gates, reconstructed all 122 public columns and
  four statement-owned roots, and minted a source-bound accepted-setup
  capability only after positive completion. This is one native vertical slice,
  not a selected proof backend or accepted ceremony.
- The algebraic verifier exposes a 408-byte cursor over 323 durable CFW and
  WHIR boundaries. The source-bound accepted verifier exposes a distinct
  412-byte cursor over 4,541 boundaries, adding all public-column and
  statement-root correspondence work. Restoration revalidates canonical source
  bytes and replays deterministically from genesis; the cursors contain no
  opaque transform state. Guarded native execution restores the exact proof at
  CFW and WHIR boundaries and reproduces the cursor bytes.
- The five CFW transforms and seven post-CFW WHIR folds use bounded outer
  polling, and both production covector consumers reuse and truncate the source
  allocation instead of retaining a clone and separate output. Completion of
  bounded verifier-derived public-covector replay, synchronous transport work,
  and transition metering still requires focused verification and browser
  evidence.
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
  cryptographic work.
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
  relation instances. The production generator feeds the generated
  public-key-share proof length into the corpus roll-up, but that row is not an
  accepted family size and all eleven other family sizes remain unknown. No
  accepted ceremony-wide byte, transfer, storage, restart, or time total exists.
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
- The evidence baseline is not clean while a guarded heavy Rust consumer
  depends on a generated proof fixture produced by a later test and the exact
  aggregate proof phase exceeds the current job budget. Both runner ownership
  and bounded execution evidence must be repaired before closure.
- There is no complete production compact generation-and-verification
  release-WebAssembly ABI pair. The release transport validator checks
  canonical structure, transcript chronology, derived queries, and Merkle
  openings only; it is not algebraic proof verification.
- The exact public-key-share slice still needs the complete transported
  equation-invalid hostile corpus, exact emitted-byte masking and Merkle-privacy
  composition, fixed-tape shared-QRO mapping, symbolic shared-Keccak reduction,
  bounded transport and cold resume, and real dedicated-worker lifecycle in
  desktop Chromium. See SECURITY for the cryptographic consequences.
- Key-switch topology, joint lattice exposure, malicious threshold behavior,
  auxiliary inputs, and the reductions to named cyclotomic-RLWE and BGV
  circular or key-dependent-message assumptions remain provisional. Diagnostic
  estimator results are not reductions.
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

Proof-heavy evidence belongs in separate guarded runners and is intended to be
excluded from routine commands. Multi-minute construction-geometry and theorem
tests have an explicitly registered, serialized evidence lane. Follow the
repository instructions when changing proof or setup code.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
