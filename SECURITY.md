# Security policy

`sealed-lattice` is a research prototype. The open issues below prohibit its
use for real elections or other security-sensitive activity.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is
unavailable, open a minimal public issue requesting a private contact path
without including exploit details.

Include the affected package version or commit, a minimal reproduction, the
expected property, the observed behavior, and whether secret material or
private data may have been exposed. Do not attach real election data, private
keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported versions and profile

No released version is supported for production use. The sole cryptographic,
integration, and supported-phone evidence target is the exact `n = 10`,
`optionCount = 10` suite and one reproducible build. It has fault bound `f = 3`,
share-reconstruction threshold `r = 4`, and finality and state quorums of seven.
Schemas admit rosters in `3..20` and option counts in `2..20`, but those other
profiles are structurally admitted only and carry no cryptographic or runtime
claim.

Cryptographic implementation completion and supported-phone qualification are
independent results for the same exact bytes:

- **Cryptographic implementation:** incomplete. No canonical suite currently
  has a complete participant-operated setup, ballot, aggregation, evaluator,
  finality, and target-release path with every required proof accepted from
  transported bytes.
- **Supported-phone qualification:** absent. No physical-phone and browser
  tuple has completed the required procedure. Native, Node, desktop-browser,
  and emulated-mobile results remain development evidence and cannot create a
  supported-phone claim. A phone planning-target variance does not invalidate
  otherwise valid cryptography, although an orders-of-magnitude variance is a
  mandatory redesign signal.

The sole browser qualification profile is Chrome on the selected physical
phone for the exact `n = 10`, `optionCount = 10` build. Desktop Chromium is
development evidence. No other browser engine is in scope for implementation,
testing, evidence, release, or support.

### Current proof boundary

The current executable ledger is kept in [README.md](README.md). Its security
consequences are:

- Production setup, ballot, and target-proof call sites still use the rejected
  proof body. No suite is selectable, and that implementation cannot create an
  accepted workflow capability.
- The compact successor can generate, transport-validate, algebraically
  verify, and source-check one exact public-key-share proof in guarded native
  execution. Only the completed source-correspondent verifier can mint its
  internal accepted-setup capability. The narrower transport validator checks
  canonical structure and openings but is not proof verification. The current
  compact-only lane generated and decoded the 23,815,474-byte proof, verified
  all 122 public columns and four statement-owned roots, and reached terminal
  verification in both its producer and separate restoration processes.
- This vertical slice does not close the backend. It lacks the complete
  transported equation-invalid hostile corpus, release-WebAssembly generation
  and verification pair, real dedicated-worker lifecycle, complete emitted-byte
  theorem composition, and browser resource evidence. The other eleven proof
  families remain unported.
- Small source-bound cursors now cover CFW, WHIR, and public-source
  correspondence. Both verifier-derived WHIR public-covector epochs use bounded
  in-place fold polls, and only the resulting fresh positive verification can
  mint the one-shot masking capability. Restore revalidates canonical inputs
  and deterministically replays from genesis. A producer Cargo process now
  persists the 408-byte algebraic cursor, and a second Cargo process in the
  same guarded run authenticates it, refuses changed checkpoint bytes, restores
  it, and continues through all 323 algebraic boundaries. Separate-process
  restoration of the 412-byte accepted/source cursor and the release-browser
  lifecycle remain open. Cold-resume time, lost work, restart traffic,
  synchronous transport, transition work, and storage transactions still need
  release-browser bounds; serialization of the full live verifier state is not
  required.
- Independent test code checks all 4,046 selected same-secret relation
  constraints across 48,552 program evaluations, and the compact public-key
  structured matrices match the independent interpreter across all 2,686,977
  operative rows. Deliberate evaluation and matrix-coefficient faults are
  detected. A separate test-only native source-and-witness oracle starts from
  canonical production VSS and aggregate same-secret objects and the
  production witness. It checks all 3,767 VSS and 4,046 same-secret compiler
  segments, 2,621,440 recipient-share coefficients, 262,144 degree-zero
  coefficients, and 196,608 anchor coefficients. Distinct expected and observed
  statements, slots, hashes, attempts, profiles, variants, catalogs, contexts,
  and roots are bound, and deterministic corruption of every binding, semantic
  source category, witness category, and compiler segment is detected. These
  checks establish relation semantics, lowering, and production source/witness
  correspondence only; they cannot mint a capability or establish proof
  soundness, zero knowledge, WebAssembly, browser, or phone behavior.
- The rejected proof implementation has persisted and authenticated a real
  5,243,240-byte quotient checkpoint at 64 completed constraints; a separate
  process restored it and continued through later authenticated boundaries up
  to constraint 2,752. The continuation was deliberately stopped without a
  terminal proof summary. This is checkpoint implementation evidence only. A
  terminal rejected-backend VSS or aggregate proof is neither required nor
  sufficient for compact construction closure and must not be rerun as a gate.
- Strict-durability desktop Chromium storage evidence exposed
  orders-of-magnitude read and transaction amplification from repeated
  namespace-wide capacity scans. Browser-reported origin usage also remained
  near one gigabyte after logical cleanup reached 206 bytes. Incremental
  authenticated accounting must cover committed, staged, and orphanable bytes
  and reserve repair headroom. Staging, commit, replacement, deletion, cleanup,
  and counter changes must be atomic; a mismatch must stop normal mutation and
  enter bounded, resumable exclusive repair. Close/reopen testing, quota
  handling, and delayed-reclamation evidence remain required.

### Masking and zero-knowledge boundary

Release generation independently redecodes the canonical public input, derives
coefficient-to-view maps, and enforces live conditional-image gates before each
covered disclosure. The guarded construction game covers one fresh canonical
82-response attempt and reports exact statistical distance zero between its
Real and witness-free Ideal path laws.

That result is deliberately narrow. It does not cover reset, retry,
reused-randomness, multi-proof, family, ceremony, shared-oracle, EPRO, QROM, or
canonical emitted-byte composition. The emitted proof has 82 response Merkle
roots. Its 45 construction commitments are typed ranges embedded inside those
responses, not 45 additional roots. The 79,310 private leaf salts occupy
10,151,680 proof bytes, so the salted-Merkle privacy game is both a security
obligation and a material resource owner.

Browser proof coins derive from the browser CSPRNG and domain-separated
KMAC256 streams. The current hybrid includes explicit quantum-PRF terms plus a
symbolic shared-Keccak-f[1600] joint-interface advantage for simultaneous
KMAC256 and fixed SHAKE256 use. Domain separation does not make that advantage
zero. It has no numeric instantiation.

### Emitted-byte and QROM boundary

Source correspondence for the proof descriptor, all 122 transported public
columns, and the four statement-owned roots does not by itself establish
zero knowledge or noninteractive soundness. A complete proof must assign every
emitted byte, salt, frontier, opening, transcript message, query, and verifier
consumer to the exact simulator, Merkle-privacy game, programming step, and
shared-oracle theorem.

The Appendix A.1 value `qPi = 79,310` is the IOR verifier's proof-query
complexity. It is not an adversary QRO-query bound and must not be squared or
inserted into an unrelated measure-and-reprogram loss. It enters the applicable
vector-commitment extraction accounting only where that theorem defines it.

The predecessor-linked SHAKE256 seed-and-block graph still needs a production
premise connecting it to the independent fixed verifier tapes required by the
applicable shared-QRO theorem. Framing, slot exhaustion, classical
equidistribution, or domain separation cannot supply that premise. The
project-specific `24 / |F|` initial CFW transition claim also needs its own
reviewed lemma rather than substitution into a source theorem. No soundness
certificate, adaptive-security certificate, or security-bit count is
authorized until the complete emitted-proof and assumption composition closes.

### Lattice-assumption boundary

The current source uses key-switch block width three and three special primes,
but that topology is not frozen. Every proof, noise, quotient, carry, resource,
and security input must use the same selected topology before suite activation.

The exact joint public exposure, correlated keys and errors, malicious
participant contributions, threshold behavior, auxiliary inputs, and protocol
hybrid to named ordinary cyclotomic-RLWE and BGV circular or
key-dependent-message assumptions remain open. Noise checks, parameter
estimators, and scalar-LWE diagnostics are useful engineering evidence but are
not those reductions.

### Participant workflow boundary

The accepted capability chain is incomplete. Candidate-view verification is not
yet carried through the participant bridge into aggregation, no participant
finality producer exists, and setup, ballot, aggregation, evaluator, target,
and reconstruction operations do not all provide proactive authenticated
checkpoint and exact resume.

The proposed approximately-ten-opening state and schema reductions are not
operative. Current ballot creation and verification require `VerifiedSetup`.
Any future pre-ratification ballot path must analyze the joint transcript across
every concurrently viable package and collective-key branch, maliciously
correlated setup contributions, branch and attempt bounds, linkability, fresh
randomness, replay, retries, and losing branches. A per-branch single-key
zero-knowledge argument is insufficient.

Strict IndexedDB transactions and Web Lock serialization are useful groundwork,
but supported-phone custody additionally requires persistence request and
recheck, quota admission, eviction qualification, and an external recency
anchor. Local authentication establishes snapshot integrity and origin, not
that a coherent snapshot is newest.

## Open security issues

- `SEC-001`: No independent audit, certification, or production hardening
  exists. Treat every result as prototype evidence.
- `SEC-002`: The exact ten-participant, ten-option path through setup, ballots,
  evaluation, finality, and one-shot target release is incomplete.
- `SEC-003`: Participant state has no backup, migration, replacement-device
  flow, or local proof that a coherent snapshot is newest. Lost or
  unauthenticated state retires that participant from the action.
- `SEC-004`: The production proof backend is rejected for mobile proving. The
  compact successor can generate, canonically decode, and
  source-correspondently verify one guarded native candidate. Baseline
  transported mutations and separate-process algebraic checkpoint restoration
  now fail closed, but the complete equation-invalid hostile corpus, theorem
  and privacy composition, release-WebAssembly pair, browser lifecycle, and
  remaining proof families are still required for suite selection. Independent
  relation semantics, matrix correspondence, and selected VSS and aggregate
  source/witness correspondence exist as test-only native evidence.
  Rejected-backend terminal execution provides no independent compact evidence
  and remains non-gating.
- `SEC-005`: Emitted-byte correspondence, salted-Merkle and EPRO privacy, the
  symbolic joint fixed-Keccak assumption, fixed-tape shared-QRO premise, exact
  initial-transition lemma, and complete Merkle/QROM composition remain open.
  `qPi` is proof-query complexity, not the adversary's QRO-query count. No
  security bit count is authorized.
- `SEC-006`: The participant bridge does not connect the complete
  verifier-minted capability and checkpoint chain from setup through release.
- `SEC-007`: Direct encrypted-ballot creation, proof generation, transport, and
  acceptance are incomplete. The proposed pre-ratification path has no accepted
  joint multi-key or multi-branch privacy argument or frozen schema. Real
  ballots must not be cast or collected.
- `SEC-008`: No physical Chrome profile has completed every participant
  operation. Phone qualification remains independent from cryptographic
  completion.
- `SEC-010`: BGV, VSS commitment, and proof parameters remain provisional. The
  source is internally consistent at key-switch block width three and three
  special primes, but that topology is not frozen and the complete structured
  and joint exposure surface lacks a reviewed reduction.
- `SEC-011`: Evaluation-key material relies on circular or
  key-dependent-message assumptions, and malicious collective-setup
  composition remains incomplete.
- `SEC-016`: Target-bound release lacks its complete production proof,
  correctness and privacy closure, participant finality producer, checkpoint
  lifecycle, and public workflow.
- `SEC-017`: Internal caller-key storage adapters do not safely support
  equivalent-key reimport or reuse across runtime lifecycles.
- `SEC-018`: The tracked collective-setup record establishes self-consistency,
  not independent production authority or a complete reduction. Its packet
  chronology conflicts with the normative dependency order, and it cannot mint
  a capability or select a suite.
- `SEC-019`: Reproducible scalar release WebAssembly and SDK bytes establish
  build identity only. Source-bound verification lifecycle exports and
  kernel-derived cursor adapters exist, but no compact generation ABI completes
  the release pair and current worker-host coverage is same-realm. Pre-selection
  evidence also lacks a deterministic non-selectable candidate identity that
  binds every candidate input and the exact scalar artifact; such an identity
  must carry no status or acceptance authority, and any mismatch with final
  suite inputs invalidates the evidence.
- `SEC-020`: Guarded native evidence covers the exact candidate public-key proof,
  source-bound verification, bounded CFW and WHIR polls, persistence and
  separate-process restoration of the 408-byte algebraic cursor, changed-cursor
  refusal, and continuation to terminal verification. The 412-byte
  accepted/source cursor has no separate-process restoration record.
  Dedicated-worker loss, bounded synchronous work, live browser memory, storage
  amplification, release-WebAssembly proof execution, exact candidate-byte
  browser restore, and full browser custody remain open.
- `SEC-021`: IndexedDB and Web Lock groundwork does not establish durable mobile
  custody without incremental authenticated capacity accounting for committed,
  staged, and orphanable bytes; atomic counter updates across every storage
  lifecycle; reserved repair headroom; bounded resumable repair; persistence
  admission; quota and eviction qualification; externally anchored rollback
  detection; and reconciliation of origin usage after logical cleanup.

Identifiers are stable and are not reused. `SEC-009` and `SEC-012` through
`SEC-015` were retired and remain withdrawn.

## Required security boundary

- Use synthetic data only.
- `sealed-lattice` owns cryptography and protocol verification. The host
  application owns identity vetting, enrollment, invite distribution,
  organizer orchestration, user interface, and visit cadence. Those external
  processes do not create cryptographic authority. An organizer has no special
  key, proof bypass, quorum weight, finality power, or decryption power.
- Participant state is bound to one phone and browser profile, with no backup,
  export, migration, or replacement-device flow. Missing, corrupt, or
  unauthenticated state retires that participant from the current action.
- The `n = 10` profile assumes at most three actively faulty participants. All
  ten trustees complete setup before ballots can use the collective public and
  evaluator keys; this is an intended protocol precondition.
- Transcript and mailbox services are untrusted relays that only move bytes.
  Acceptance comes from canonical encodings, recomputed hashes and roots,
  signatures, verified proofs, and an externally anchored manifest and roster.
- Aggregation must consume a complete candidate-view authority minted by the
  Rust verifier from the exact transported ballot bytes. A caller-supplied root
  or continuation label cannot substitute for that capability.
- Finality must be produced and verified by roster participants in their own
  browsers. No relay, organizer, service, or external finalizer may mint it.
- Every long participant operation must proactively commit authenticated state
  at deterministic safe boundaries before browser suspension can lose material
  work. Resume must preserve the same attempt and must not depend on a wake lock,
  visibility callback, freeze callback, or termination callback.
- One worker invocation must adopt exactly one checkpoint-custody object. Fresh
  and resumed custody inputs are mutually exclusive, and the same adopted
  object must own restoration, publication, and release so every operation
  identity is retired on success, refusal, cancellation, and failure.
- Durable state admission must request and recheck browser persistence, account
  atomically for committed, staged, and orphanable bytes, reserve repair and
  cleanup headroom, qualify quota and eviction behavior, and compare
  authenticated local state with an external recency anchor before accepting it
  as newest. Ledger mismatch stops normal mutation until bounded authenticated
  repair completes.
- Ballot creation and verification remain gated on `VerifiedSetup`. No
  provisional or pre-ratification ballot path is authorized until its joint
  multi-key and multi-branch privacy argument, state replacement theorem,
  canonical schemas, hostile cases, and suite inputs are complete.
- A pre-activation candidate evidence identity is metadata only. It never
  substitutes for canonical suite bytes, proof verification, or a
  verifier-owned capability, and changed bound inputs invalidate its evidence.
- Quorum witnesses are other roster participants acting through their own
  clients; no external witness, trusted service, or finalizer is allowed.
- Release is one-shot: a finality quorum authorizes exactly one target result,
  and every decryption share and proof binds to that result.
- Never expose shares, secret keys, encryption or proof randomness, proof
  witnesses, or local secret state, and never decrypt individual ballots,
  exact aggregates, comparison bits, ranks, evaluator intermediates, margins,
  or shares of the aggregate.
- Use only the browser-local platform CSPRNG and the protocol's domain-separated
  derivation for proof randomness. Never inject caller or public proof
  randomness. An authenticated resume may replay only the same attempt; every
  distinct attempt requires fresh randomness.
- Keep every participant operation in the participant's own mobile browser;
  never substitute a desktop, native helper, server, or remote prover.

## Outside the current model

A compromised participant device holds that participant's keys and authority:
it can disclose local secrets and send arbitrary messages, and local locks and
storage checks cannot make it honest. Protocol safety relies on verified
proofs, accepted-board rules, and the modeled bound of at most three faulty
participants. Compromise beyond that bound, data already on a compromised
device, malicious same-origin code, compromised platform key storage, denial
of service, and side channels are outside the current security boundary.
