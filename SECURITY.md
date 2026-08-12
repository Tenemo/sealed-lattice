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

The only current browser qualification profile is Chrome on the selected
physical phone for the exact `n = 10`, `optionCount = 10` build. Desktop
Chromium is development evidence. Other browser engines are not current support,
test, evidence, or release gates and may be evaluated only after Chrome completes
the full physical-phone procedure.

### Current proof boundary

The default kernel build and selected proof profile remain wired to the
row-code/WHIR backend. That backend is operationally rejected as the mobile
proving direction and cannot activate a suite. Its retained code and evidence
are comparison and transition material, not an eligible production proof path.
Its affine-image and sequential-simulation structures are accounting and proof
plans only: they neither prove the conditioned image relation from independent
matrices nor emit a witness-free simulated verifier view.
The rejected backend's mapped-soundness vector, per-family checkpoint owners,
and conservative action-composition catalog were removed after its corrected
schedule changed derived oracle counts. They are not security inputs for the
compact successor.

The latest retained complete dirty-worktree graph passed the workspace build, package,
Node, 1,218-entry ordinary Rust, and Chromium lane. The
scalar WASM and SDK bytes reproduced at
`91e5a2c5d26f9f98a7e0afa797948769c1a648f84622a78b115e7b86edc47524`, and all
35 retained theorem-registry members passed under the serialized guard. Those
results validate only that recorded dirty state. They predate the later
collective-setup record and current documentation changes and are neither
current-workspace nor clean commit-bound evidence. The desktop graph used
Node.js `22.22.2`, below the declared
`24.14.1` minimum, and therefore is not declared-toolchain closure. The theorem
registry still includes rejected row-code accounting and
proof-plan owners; it does not supply compact masking or a compact proof. No
manual browser proof-evidence result exists because there is no production
compact proof to run.

The compact CFW/WHIR semantic, prover, transport, and hostile-verifier
workbench is compiled only for tests. The `primitive-measurement-evidence`
feature contains only bounded measurement owners and the operative ring-native
arithmetic they measure. Neither scope enters the default participant build.
They currently cover a standalone public-key-share development slice; no
compact packing factor is selected, and no participant-facing API exposes a
complete compact prover or verifier.

Within that test-only workbench, the factor-one source-level semantic owner is
substantive and complete for its narrow scope. It executes the selected decoder,
construction-wide knowledge-state predicate, deterministic extractor, all 82
message transitions, adjacent extracted-witness transitions, bad-transition
implications, zero implicit tuple dimensions, and the local extraction-work
bound. The executable initial transition uses a direct bound of 24 divided by
the field order; the cited CFW coordinate gives nine divided by the field order,
so exact citation-level correspondence remains refused. This source-level
result is not an emitted proof, does not run in the default participant path,
and does not transfer to VSS, ballots, evaluation, finality, release, or other
proof packets without rederivation.

### Masking and zero-knowledge boundary

The compact masking owner is not a construction-level zero-knowledge proof. It
contains one independently derived CFW outer coefficient-to-view matrix with a
differential production check, useful topology and chronology catalogs, and
limited rank checks. Many other view identities are enum-derived catalogs;
terminal and sumcheck checks use restricted challenge fixtures; and the
recorded simulator inputs are not an executable simulator. Missing work
includes every remaining production coefficient-to-view map, joint conditional
entropy after prior disclosures, nonlinear correspondence, and an exact
ideal-uniform interactive simulator.

Deployment coins come from browser-CSPRNG-rooted KMAC256 streams. The KMAC
hybrid module explicitly provides bookkeeping rather than a security proof, and
fixed KMAC256 quantum-PRF security is an unproved computational assumption.
Consequently neither statistical HVZK for the emitted construction nor the
deployed computational masking reduction is complete.

Single-proof malicious-verifier privacy would additionally require the exact
salted-Merkle privacy error, collision-free programmed domains, and a finite
explicitly programmable-oracle map for every simulated root and frontier.
Resettable or reused-randomness privacy, shared-oracle multi-proof privacy,
proof-family simulation, complete-ceremony simulation, and QROM zero knowledge
remain separate unproved claims. Production code never reprograms SHAKE.

### Emitted-byte and QROM boundary

Canonical compact codecs, fixed verifier-message decoding, Merkle response
writing, frontier scanning, and opening verification are executable. The
byte-to-consumer owner, however, derives static or maximum regions; counted
frontier regions remain parameterized until bytes exist. Its transported-byte
test is one small response fixture. The all-factor query-schedule test uses
zero-valued public inputs and deterministic roots and salts. A separate
ring-degree-2,048 CFW-plus-two-WHIR envelope has useful hostile mutation
coverage, but the entire chain is test-only and uses reduced deterministic
authority and randomness.

There is no complete production proof whose decoded byte ranges, values,
roots, salts, frontiers, transcript messages, query schedules, and verifier
consumers instantiate that static map. There is also no production authority,
single canonical transcript, selected-size lifecycle, browser-custody resume,
or release-WASM execution for the compact chain.

The CDHZ/Merkle/QROM module performs exact conditional arithmetic from the
semantic owner and static catalogs. Its derivation is not gated by a completed
masking simulator or a complete emitted-proof certificate. Fixed
domain-separated SHAKE256 remains an explicit ideal 512-bit quantum-random-
oracle assumption; the available quantum sponge bound is not a proof about the
fixed Keccak-f permutation at the declared query budget. The reported 98-bit
per-proof, 95-bit ten-proof-union, and 92-bit complete-inventory figures are
therefore conditional calculators, not security results. Soundness closure
requires one emitted production proof plus the exact CDHZ state-restoration,
Merkle, collision, oracle-query, extractor-work, and multiplicity partition.
Privacy closure separately requires the salted-Merkle and programmable-oracle
work above and a compatible joint assumption or reduction for KMAC256 and
SHAKE256, which share fixed Keccak-f.

### Participant workflow boundary

Rust can authenticate a canonical ballot candidate view, but that verifier-
minted authority is not exported through the participant bridge. Aggregation
currently accepts a caller-supplied candidate-view root as continuation context
instead of consuming the authenticated Rust capability. Finality verification
components exist, but there is no participant finality producer boundary.

The positive capability chain is therefore incomplete. Ballot encryption,
aggregation, evaluator replay, target preparation, and reconstruction do not
all have proactive authenticated checkpoint and resume paths. Aggregation
restarts from ballot zero, evaluator replay has no checkpoint resume, target
preparation precedes its required proof checkpoints, and reconstruction is one
synchronous uncheckpointed call. These lifecycle gaps are independent of proof
theorem status and supported-phone qualification.

Strict IndexedDB transactions and Web Lock serialization provide useful local
groundwork, but durable platform qualification is incomplete. The participant
runtime does not request and recheck `persist()` or `persisted()` storage,
perform quota admission, qualify eviction behavior, or anchor recency outside
the local snapshot so coherent rollback can be detected. Local authentication
can establish snapshot integrity and origin; by itself it cannot establish that
the snapshot is the newest state.

## Open security issues

- `SEC-001`: The project has no independent audit, certification, or production
  hardening. Treat all results as prototype evidence.
- `SEC-002`: The exact ten-participant, ten-option cryptographic path through
  finality and one-shot target release is unfinished. No complete ceremony or
  released result is supported.
- `SEC-003`: Participant state has no backup, migration, replacement-device
  flow, or local newest-snapshot proof. Lost or unauthenticated state retires
  that participant from the action.
- `SEC-004`: The default selected proof backend is the operationally rejected
  row-code/WHIR path. The compact semantic, prover, transport, and hostile-
  verifier workbench is test-only; the measurement feature contains only
  bounded measurement owners and their ring-native arithmetic. The compact
  successor is unselected and lacks a production-size proof and complete
  participant runtime. No proof backend is currently mobile-feasible or suite-
  selectable.
- `SEC-005`: The compact standalone semantic owner is source-level evidence
  only. Complete production masking, ideal simulation, the KMAC quantum-PRF
  reduction, emitted-byte correspondence, salted-Merkle privacy, root and
  frontier programming, and exact CDHZ/Merkle/QROM instantiation remain open.
  The 98-, 95-, and 92-bit figures are conditional, not security results.
- `SEC-006`: Setup, ballots, aggregation, evaluation, finality, and release have
  component evidence only. The participant bridge lacks verifier-minted
  candidate-view authority and a finality producer, and the complete capability
  and checkpoint chain is not integrated.
- `SEC-007`: Direct encrypted-ballot creation, proof generation, transport, and
  acceptance are incomplete. Real ballots must not be cast or collected.
- `SEC-008`: No physical-phone and browser tuple has completed every participant
  operation. This unsupported-phone status is tracked independently from
  cryptographic implementation completion.
- `SEC-010`: BGV, VSS commitment, and proof parameters remain provisional. The
  project lacks a reviewed reduction for the complete structured and joint
  exposure surface, including ordinary cyclotomic RLWE, BGV circular or
  key-dependent-message security, range and carry constraints, and
  malicious-threshold auxiliary inputs.
- `SEC-011`: Evaluation-key material relies on circular or key-dependent-message
  assumptions, and malicious collective-setup composition is incomplete.
  Component inventories do not prove the adaptive sequential setup hybrid.
- `SEC-016`: Target-bound threshold release lacks its complete production proof,
  correctness, privacy, participant finality producer, checkpoint lifecycle,
  and public workflow.
- `SEC-017`: Internal caller-key storage adapters do not safely support
  equivalent-key reimport or reuse across runtime lifecycles.
- `SEC-018`: Schemas and deterministic compilers admit the structural option
  range and bind ten options in the selected source profile. The tracked exact-
  ten collective-setup record was produced through a guarded Rust refresh, but
  its routine Node consumer obtains the expected production authority from that
  same record. Its handwritten status catalogs are not independent theorem
  premises, its joint setup-sample transition is only a restatement of a broad
  structured-RLWE/circular-KDM assumption rather than a complete reduction, and
  its Galois/round-one schedule conflicts with the canonical packet dependency.
  The record is nonqualifying bookkeeping: its four compact construction
  imports, two setup and collective composition leaves, and exact joint
  reduction remain open, and it cannot authorize or mint a capability. Proof,
  checkpoint, runtime, and package evidence is not one reconciled exact-ten
  authority.
- `SEC-019`: The canonical scalar WASM and SDK package bytes reproduce at
  `91e5a2c5d26f9f98a7e0afa797948769c1a648f84622a78b115e7b86edc47524`, and the
  ordinary desktop-browser graph passes. The release build still omits compact
  proof generation and verification, so this is not selected-size compact-proof
  browser qualification. Compact checkpoint publication remains reduced kernel
  groundwork, not browser-custody or selected-size durable resume.
- `SEC-020`: Pollable source preparation, transpose, Merkle, codec, and reduced
  CFW/WHIR lifecycle owners provide development evidence only. Selected-size
  production authority, response values, unified transcript, authenticated
  restart, CFW-to-WHIR invocation, resource reconciliation, and browser
  execution remain unresolved.
- `SEC-021`: IndexedDB and Web Lock groundwork does not establish durable mobile
  custody. Persistence request and recheck, quota admission, eviction
  qualification, and externally anchored coherent-rollback detection are
  absent. An authenticated local snapshot does not prove recency.

Identifiers are stable and are not reused. `SEC-009` and `SEC-012` through
`SEC-015` were retired from this list and their numbers remain withdrawn.

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
