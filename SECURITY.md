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
independent statuses for the same exact bytes:

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

- Production setup, ballot, and target-proof call sites still invoke the
  rejected row-code/WHIR implementation. The suite remains unselectable, and
  that implementation cannot create an accepted workflow capability.
- The compact release path owns canonical proof and public-input decoding,
  transcript and query derivation, salted Merkle opening validation, scalar CFW
  mechanics, bounded external storage, proof assembly, response-tree custody,
  and authenticated response checkpoints.
- For the public-key-share family, guarded selected-size native execution now
  reaches the final checkpoint after all 82 responses and enforces the live
  conditional-image gates across both WHIR epochs. Its finisher emits a
  23,815,474-byte canonical compact-proof candidate. The independent transport
  check accepts its canonical structure, transcript chronology, verifier
  queries, and salted Merkle openings. A release-owned pollable algebraic
  verifier independently derives the structured public CFW contribution and
  accepts the exact emitted proof after checking the CFW transcript, both WHIR
  epochs, all six code switches, both terminal blinded relations, and the
  authenticated source and mask spot checks. The candidate is still not an
  accepted proof: the complete equation-invalid hostile corpus, final public
  verification result, and capability transition remain open.
- The compact transport ABI returns typed refusals but does not return
  `isValid`, mint a proof capability, or supply the final `VerificationResult`.
  A separate raw release-kernel ABI begins, polls, and cancels the internal
  algebraic verifier, but it has no checkpoint codec, TypeScript worker
  integration, final typed result, or capability handoff. Complete generation
  and verification release ABIs do not exist.
- Test-only instrumentation derives the exact 165-event interactive ledger and
  15 composition boundaries from executable owners while preserving the
  maximum-per-verifier-move relaxed-RBR bound. A decoded actual-byte census is
  bound to the canonical proof/public-input pair and covers response tuples,
  commitments, openings, queries, salts, frontier nodes, transcript
  absorptions, verifier consumers, and fixed-SHAKE256 hash calls. The
  conditional Appendix A.1 calculator refuses unless semantic,
  masking-correspondence, emitted-byte, Merkle-privacy-correspondence, and SHAKE
  premises are all present and byte-bound. It derives relaxed-RBR headroom from
  the complete `2^-80` partition, but the correspondence and SHAKE premises
  still have no production constructors. No security level or proof capability
  follows from this arithmetic.
- The selected 103-physical-proof, 159-logical-instance corpus roll-up remains
  incomplete. The 23,815,474-byte public-key-share transport candidate is not
  an accepted family size, the other eleven family sizes are unknown, and no
  ceremony-wide compact byte total exists.
- Source geometry now pins 50,331,520 retained-response-tree bytes at the
  post-lookup release boundary, separately from the 52,952,832-byte
  transient-inclusive response-storage peak. Neither number is browser
  lifecycle or supported-phone evidence.
- The guarded CFW run reconciles 4,926 logical storage transactions,
  1,006,632,840 bytes written, 2,013,265,440 bytes read, and 587,202,560 peak
  stored bytes. A separate nonqualifying desktop Chromium replay used the exact
  compiler-derived schedule, 655,360-byte chunks, production authenticated
  custody, and strict-durability IndexedDB transactions. It matched the logical
  census and all 1,713 seals, but the storage layer recorded 1,335,448,998,100
  physical read bytes and 4,148,340 physical transactions. The dominant cause
  is a namespace-wide stored-value capacity scan during each lease and repair
  publication. This orders-of-magnitude amplification and the logical peak's
  2.1875-times variance over the scratch planning target require redesign and
  engineering review. The logical peak remains below the 1,073,741,824-byte
  absolute bound. This is desktop development evidence, not an accepted proof,
  complete browser lifecycle evidence, or phone evidence.

### Masking and zero-knowledge boundary

Release generation independently redecodes the canonical public input, derives
the coefficient-to-view maps, and enforces the live conditional-image gates
before each covered disclosure. The initial code switch folds 25,344
base-field encoding-randomness coordinates into 396 extension-field source
coordinates, then independently samples 6,912 next-source randomness elements
and 399 switch-mask randomness elements. Those three quantities are distinct.

The guarded construction security game covers the complete 82-move lifecycle,
all 45 abstract construction commitments, and adaptive overlapping queries. At
each disclosure it independently derives the Real-game conditional rank from
the compiler-owned map and compares that rank with the witness-free Ideal
simulator's consumed coordinates. The two path laws are identical, so the
single-fresh-attempt ideal-uniform construction has exact statistical distance
zero. The theorem binds the verified public input and refuses reset, retry,
reused-randomness, multi-proof, family, ceremony, shared-oracle, EPRO, QROM, and
canonical emitted-byte scope extensions. Salted-Merkle privacy and
correspondence with one complete emitted production proof remain open.

The release coin bridge accounts for three symbolic quantum-PRF replacements
and the exact known sampler and collision terms. It now states the compatible
joint assumption: within the declared quantum-query budget, simultaneous use of
the domain-separated keyed KMAC256 interfaces and fixed SHAKE256 is replaced by
the named per-key random functions and one ideal quantum random oracle, with the
explicit qPRF terms plus one symbolic shared-Keccak-f[1600] interface advantage.
Domain separation does not make that advantage zero. The assumption remains
unproved and has no numeric instantiation.

### Emitted-byte and QROM boundary

No complete production proof currently assigns every byte, root, salt,
frontier, transcript message, query, and verifier consumer to the theorem
correspondence. Reduced fixtures, static maxima, and the transport-only
validator cannot substitute for those bytes.

The Appendix A.1 arithmetic derives `qPi = 79,310` but still requires a
production theorem premise connecting the predecessor-linked SHAKE256 graph to
independently sampled fixed verifier tapes in the shared quantum random oracle.
Any constructor for that premise must add its positive distinguishing loss to
the complete ledger. Framing, slot exhaustion, and classical equidistribution
cannot supply it. No adaptive-soundness certificate or security bit count is
authorized until the premise and complete emitted-proof composition close.

### Participant workflow boundary

The accepted capability chain is incomplete. Candidate-view verification is not
yet carried through the participant bridge into aggregation, no participant
finality producer exists, and setup, ballot, aggregation, evaluator, target,
and reconstruction operations do not all provide proactive authenticated
checkpoint and exact resume.

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
  compact successor remains incomplete and cannot generate or verify one
  accepted production proof or select a suite.
- `SEC-005`: Emitted-byte correspondence, salted-Merkle and EPRO privacy, the
  symbolic joint fixed-Keccak assumption, fixed-tape shared-QRO premise, and
  exact Appendix A.1/Merkle/QROM composition remain open. No soundness
  certificate or security bit count is authorized.
- `SEC-006`: The participant bridge does not connect the complete verifier-
  minted capability and checkpoint chain from setup through release.
- `SEC-007`: Direct encrypted-ballot creation, proof generation, transport, and
  acceptance are incomplete. Real ballots must not be cast or collected.
- `SEC-008`: No physical Chrome profile has completed every participant
  operation. Phone qualification remains independent from cryptographic
  completion.
- `SEC-010`: BGV, VSS commitment, and proof parameters remain provisional. The
  complete structured and joint exposure surface lacks a reviewed reduction.
- `SEC-011`: Evaluation-key material relies on circular or key-dependent-message
  assumptions, and malicious collective-setup composition remains incomplete.
- `SEC-016`: Target-bound release lacks its complete production proof,
  correctness and privacy closure, participant finality producer, checkpoint
  lifecycle, and public workflow.
- `SEC-017`: Internal caller-key storage adapters do not safely support
  equivalent-key reimport or reuse across runtime lifecycles.
- `SEC-018`: The tracked collective-setup record establishes self-consistency,
  not independent production authority or a complete reduction. Its packet
  chronology conflicts with the normative dependency order, and it cannot mint
  a capability or select a suite.
- `SEC-019`: Reproducible scalar release WebAssembly and SDK bytes
  establish build identity only. The release artifact contains compact transport
  validation and public-key response generation through the complete 82-response
  schedule plus raw begin, bounded-poll, and cancellation functions for the
  internal algebraic verifier, but it has no compact generation API,
  checkpointable worker-integrated verification, final typed result, or final
  generation and verification ABIs.
- `SEC-020`: Guarded selected-size native evidence covers the public-key
  family's complete response-generation schedule and one fresh algebraic replay
  of its exact emitted proof. A separate desktop Chromium diagnostic replays its
  exact CFW storage lifecycle and exposes an orders-of-magnitude physical-storage
  amplification. The current proof boundary above owns the candidate's
  acceptance status. These results do not establish a final
  `VerificationResult`, release-WebAssembly proof execution, cold common-worker
  restoration, complete durable browser custody, or supported-phone
  feasibility.
- `SEC-021`: IndexedDB and Web Lock groundwork does not establish durable mobile
  custody without persistence admission, quota and eviction qualification, and
  externally anchored rollback detection.

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
- Durable state admission must request and recheck browser persistence, account
  for quota, qualify eviction behavior, and compare authenticated local state
  with an external recency anchor before accepting it as newest.
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
