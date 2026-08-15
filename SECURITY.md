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

The latest retained complete dirty-worktree graph passed the workspace build,
package, Node, 1,218-entry ordinary Rust, and Chromium lane. Its scalar WASM and
SDK bytes reproduced, and all 35 retained theorem-registry members passed under
the serialized guard. That graph's artifact is superseded. The current scalar
release WASM and SDK byte copy are byte-identical and have normalized loader SHA-256
`712eb1fdf79b6cd7d32bf4e008ccfe3b17a46c799aa63cf50bb67eee9e220894`.
This is release-build and byte-copy development evidence only, not proof or
physical-phone qualification. The retained results validate only that recorded
dirty state. They predate the later
collective-setup record and current documentation changes and are neither
current-workspace nor clean commit-bound evidence. The desktop graph used
Node.js `22.22.2`, below the declared
`24.14.1` minimum, and therefore is not declared-toolchain closure. The theorem
registry still includes rejected row-code accounting and
proof-plan owners; it does not supply compact masking or a compact proof. No
manual browser proof-evidence result exists because there is no production
compact proof to run.

The compact typed version-three factor-one contract decoder and its statement,
relation, transcript-domain, CFW, WHIR, proof-wire, response-Merkle, fixed-
message, and checkpoint geometry and schema owners are compiled in the default
kernel. Proof and public-input encoding and decoding, fixed verifier-message
decoding and derivation, Fiat-Shamir transcript execution, salted-opening
transport verification, scalar CFW, the bounded external-memory CFW driver,
authenticated assignment loading, bounded lookup-inverse materialization, and
the owned structured-row and transpose path are ordinary release code. The row
source owns reference-counted relation and secret-assignment material rather
than borrowing worker-lifetime state. Incremental proof assembly, the prover
transcript cursor, bounded response-tree writing and scanning, retained-tree
coordination, and the authenticated response-checkpoint boundary are release
code with owned retained inputs. A release-owned compact response state now
drives those response components with verifier-selected leaf replay, exact
transaction yielding, cancellation, authenticated cursor restoration, and
byte-identical genesis replay.
A release-owned public-key generation state now joins the frozen factor-one
contract to the retained setup authority, polls the exact 202 authenticated
source columns, and derives canonical public-input bytes from verifier-minted
suite, application-statement, manifest, and relation bindings before
independently decoding them. It owns family materialization and its first
compact response together. It accepts the lookup challenge only through a
borrowed first-message authority minted by its retained compact response state
for the same proof geometry and canonical public input, then owns bounded
lookup inversion and structured-row preparation. Before that lookup challenge
exists, the production state derives the first WHIR epoch's exact
2,097,152-element source from authenticated quotient-and-multiplicity values
plus canonical zero padding. Independent action-private coin seeds drive WHIR's
rejection samplers and random-access response salts. The guarded owner retains
WHIR's exact 131,072-row by 64-element encoding, streams those values into the
salted response tree, binds a strict 56-byte attempt-and-WHIR-position cursor
into the authenticated response checkpoint, and retains the tree through 233
lookup polls, 760 structured-row polls, and one CFW poll. The selected-size path
validates the checkpoint transcript cursor in the live state, but cold
restoration through the common worker and a complete emitted WHIR epoch remain
absent.
The complete production-shaped small chain uses the compact response state, but
the later CFW and WHIR family material provider and production worker adapter
remain incomplete.
Semantic and complete CFW/WHIR execution,
Merkle privacy, masking, emitted-coordinate measurement, fixed-tape and
Appendix arithmetic remain test-only or incomplete. The
contract validates the exact target; statement-schema identifier, field count, and layout
digest; the 128-draw per-output Fiat-Shamir ceiling; both canonical wire magics;
the ordered suite, statement, manifest, and relation-plan public-input roles;
six release-consumed domains and four frozen checkpoint-binding domains;
relation schema; all response semantic
roles, value kinds, query sources, and padding; wire and Merkle geometry; the
exact CFW configuration; and both WHIR epoch configurations, folds, and unique-
decoding radii. A separate default-compiled WHIR verifier-geometry owner derives
both epoch shapes and security query budgets from the CFW cross-epoch geometry
and the vendored unique-decoding configuration at the 267-bit protocol target.
It derives schedules `[6, 4, 4, 4]` and `[7, 4, 4, 4]`, round inverse-rate
logarithms `[2, 4, 8]`, all query counts, the 399-query mask budget, and the
`2 x 1` cross-epoch mask shape. Contract decoding exact-compares every
serialized WHIR field to this owner before chronology and response derivation;
correlated alternate geometries refuse. The record does not serialize the
relation-plan variant hash,
ring-vector count, ring degree, global commitment or query-group counts, or
checkpoint-schedule digest. The decoder independently rederives those facts
from the selected relation, exact 82-step chronology, and checkpoint schedule,
including 45 total programmable construction commitments, 26 distinct query
groups, and the checkpoint digest. Of those 45, 42 are WHIR-internal
commitments and three are external mask roots for CFW inner, CFW outer, and the
shared cross-epoch mask. Its canonical 27,778-byte version-three
`compact_proof_contract.generated.bin` record has raw SHA-512
`48514bef844ef68793128c3145890efb2a0e65b7584788b7b03d1bf5ab1287c9a029b6da68720d350a13e0c6162f234a3318dd1558dd8c091f65f00e7d924298`.
Schema `0x2200` version nine `ProofProfileSet` has exactly five outer items:
proof fields, proof families, relation-plan references, root-compatibility
edges, and the typed contract's canonical-source `Hash512` under
`sealed-lattice/bgv/compact-public-key-proof-contract/source/v1`; it has no
separate contract-length item. The fifth item is the sole proof-backend binding;
there is no adjacent row-code construction-profile item. That framed, domain-
separated value is distinct from the raw file SHA-512 above. Verification
decodes the release-embedded contract and recomputes the canonical-source hash;
the binding does not make the still-refused foundation suite selectable.
It is checked in, included directly by release Rust, decoded and canonically
re-encoded, and independently regenerated byte-for-byte from the production
source adapter in its identity test. The decoder derives proof, public-input,
and transport byte lengths and the 82-response checkpoint schedule from the
bound geometry; the record carries no provisional WASM, scratch, or
2,677-boundary planning estimates. The release transport validator
owns and decodes the canonical proof/public-input pair once and derives every
fixed verifier message. It derives one selected-geometry Merkle privacy
certificate with 161 response-component embeddings and 45 construction
bindings, then gates every due query schedule and all 82 salted response
openings through it. The one shared cross-epoch root remains one construction
binding with two typed query consumers. It does not evaluate CFW or WHIR
equations, establish algebraic proof validity, return `isValid`, or mint a
capability. Its Rust/WebAssembly ABI and TypeScript worker caller consume the
certificate gate without upgrading transport acceptance into proof acceptance.
Its opaque response-boundary checkpoint supports
only in-process continuation; it is not durable, authenticated, held by browser custody, or
exact-resume evidence. The decoded salt-uniqueness registry stores 79,310
four-byte offsets into the canonical proof buffer at selected geometry:
`317,240` bytes rather than `10,151,680` bytes of copied salts. Merkle
verification absorbs already-canonical opened-value slices and parent
coordinates directly into canonical-tuple SHAKE256 hashes, avoiding per-query
field-vector re-encoding and tuple materialization while retaining byte-
identical digests. The complete semantic authority, complete CFW/WHIR verification, reduced
execution fixtures, and the retained end-to-end workbench remain test-only or
incomplete. No compact
prover, emitted compact proof, selected suite, final `VerificationResult`,
algebraic compact verification ABI, compact-proof browser run, or
physical-phone evidence exists. The `primitive-measurement-evidence` feature
contains only bounded measurement owners and the operative ring-native
arithmetic they measure. These owners cover a standalone public-key-share development slice;
foundation suite selection remains fail-closed, and no participant-facing API
exposes a complete compact prover or verifier.

The test-only factor-one source-level semantic owner is substantive and complete
for its narrow scope. It executes the selected decoder,
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

The compact masking workbench is not a construction-level zero-knowledge proof.
It contains executable coefficient-to-view maps with focused differentials
against the selected p3 sumcheck and base-case producers, the compact CFW
accumulator and terminal, Reed-Solomon encoders, limb folds, code switches,
quotient prefixes, and explicit-point claims. Its streaming entropy authority
tracks conditional ranks by private source. Its test-only adaptive simulator
transactionally processes malicious-verifier moves, but deliberately refuses
at the first role-18 base boundary because no one-shot authority yet binds the
semantic owner's carried covector to the same adaptive transcript. There is no
terminal 82-move ideal transcript or completed masking proof.

Deployment coins come from browser-CSPRNG-rooted KMAC256 streams. The test-only
KMAC census and conditional hybrid accounting derive the selected stream
coordinates, 639,270 outer leaf salts, exact known-loss terms, and two symbolic
quantum-PRF hops. They remain bookkeeping rather than a security proof. Joint
KMAC256/SHAKE256 security over the shared Keccak-f permutation is an external
unproved assumption that the accounting does not instantiate or authorize.
Consequently neither statistical HVZK for the emitted construction nor the
deployed computational masking reduction is complete.

Single-proof malicious-verifier privacy would additionally require the exact
salted-Merkle privacy error, collision-free programmed domains, and a finite
explicitly programmable-oracle map for every simulated root and frontier.
Resettable or reused-randomness privacy, shared-oracle multi-proof privacy,
proof-family simulation, complete-ceremony simulation, and QROM zero knowledge
remain separate unproved claims. Production code never reprograms SHAKE.

### Emitted-byte and QROM boundary

The typed compact contract decoder and its CFW, WHIR, checkpoint, proof-wire,
response-Merkle, transcript, and fixed-message geometry and domain owners are
default-compiled internal primitives. The Merkle privacy-certificate owner,
strict transport validator, proof and public-input decoders, transcript
execution, verifier-message derivation, and salted-opening verification are
ordinary release code. The Rust/WebAssembly ABI and TypeScript worker caller
consume that boundary. The scalar CFW prover/verifier algebra, bounded
external-memory transaction driver, authenticated assignment loader, bounded
lookup-inverse materializer, and owned structured-row and transpose path
are ordinary release code. A release-owned public-key family materialization
state connects the authenticated
loader to those phases, but no common compact proof worker calls it yet. The row
source owns reference-counted relation and secret-assignment material rather
than borrowing worker-lifetime state. Incremental proof assembly, the prover
transcript cursor, bounded response-tree writing and scanning, retained-tree
coordination, and the authenticated response-checkpoint boundary are release
code with owned retained inputs. A release-owned compact response state now
drives those response components with verifier-selected leaf replay, exact
transaction yielding, cancellation, authenticated cursor restoration, and
byte-identical genesis replay.
A release-owned public-key generation state now joins the frozen factor-one
contract to the retained setup authority, polls the exact 202 authenticated
source columns, and derives canonical public-input bytes from verifier-minted
suite, application-statement, manifest, and relation bindings before
independently decoding them. It owns family materialization and its first
compact response together. It accepts the lookup challenge only through a
borrowed first-message authority minted by its retained compact response state
for the same proof geometry and canonical public input, then owns bounded
lookup inversion and structured-row preparation. Before that lookup challenge
exists, the production state derives the first WHIR epoch's exact
2,097,152-element source from authenticated quotient-and-multiplicity values
plus canonical zero padding. Independent action-private coin seeds drive WHIR's
rejection samplers and random-access response salts. The guarded owner retains
WHIR's exact 131,072-row by 64-element encoding, streams those values into the
salted response tree, binds a strict 56-byte attempt-and-WHIR-position cursor
into the authenticated response checkpoint, and retains the tree through 233
lookup polls, 760 structured-row polls, and one CFW poll. The selected-size path
validates the checkpoint transcript cursor in the live state, but cold
restoration through the common worker and a complete emitted WHIR epoch remain
absent.
The complete production-shaped small chain uses the compact response state, but
the later CFW and WHIR family material provider and production worker adapter
remain incomplete.
The transport validator checks canonical
bytes, derives the selected-geometry
certificate with 161 response-component embeddings and 45 construction
bindings, and gates every verifier-derived schedule and all 82 response openings
through it, including the two query consumers of the one shared cross-epoch
root. It does not check CFW or WHIR equations, establish proof validity, return
`isValid`, or mint a capability. The emitted-coordinate measurement
function, its record types, the Appendix and fixed-tape arithmetic, and complete
CFW/WHIR execution remain test-only or incomplete. The test-only byte-to-consumer owner
derives static or maximum regions; counted
frontier regions remain parameterized until bytes exist. Its transported-byte
test is one small response fixture. The current factor-one schedule has 45
programmable construction commitments: 42 WHIR-internal commitments and three
external mask roots for CFW inner, CFW outer, and the shared cross-epoch mask. A
separate
ring-degree-2,048 CFW-plus-two-WHIR envelope has useful hostile mutation
coverage, but the entire chain is test-only and uses reduced deterministic
authority and randomness.

There is no complete production proof whose decoded byte ranges, values,
roots, salts, frontiers, transcript messages, query schedules, and verifier
consumers instantiate that static map. There is also no production authority,
single canonical transcript, selected-size lifecycle, browser-custody resume,
or release-WASM execution for the compact chain.

The Appendix A.1 owner restores the offline proof-query-set coordinate
`qPi = 79,310` and its fixed offline extraction term. Its terminal requires an
opaque fixed-tape-uniformity premise connecting the predecessor-linked SHAKE256
seed-and-block graph to the independently sampled uniform verifier tapes assumed
by the theorem. Canonical framing, fixed-slot exhaustion, and classical
equidistribution are insufficient to prove that shared-QRO domain extension,
and source deliberately provides no production constructor for the premise.
Only test arithmetic can assume it. There is therefore no authorized adaptive-
soundness certificate or security bit count. Soundness closure also requires one
emitted production proof plus exact state-restoration, Merkle, collision,
oracle-query, extractor-work, and multiplicity accounting.
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
  row-code/WHIR path. The compact typed contract decoder and its CFW, WHIR,
  checkpoint, proof-wire, response-Merkle, transcript, and fixed-message
  geometry and domain owners are default-compiled internal primitives. The
  proof and public-input codecs, fixed-message decoder and derivation,
  transcript execution, Merkle writer and opening verifier, checkpoint
  execution, privacy-certificate derivation, the bounded response-tree
  executor, and the pollable transport verifier are release code. The verifier
  derives the 161-component, 45-construction-binding certificate and gates
  verifier-derived schedules and 82 response openings through it, but verifies
  no CFW/WHIR equation or proof validity. The Rust/WebAssembly boundary and
  TypeScript worker consume that gate without minting a capability. Compact
  checkpoint construction remains in-process and is not durable authenticated
  browser custody. Semantic authority, complete CFW/WHIR verification, masking,
  emitted-coordinate measurement, fixed-tape and Appendix arithmetic, reduced
  execution fixtures, and the end-to-end workbench remain test-only or
  incomplete. The compact successor lacks a compact
  prover, emitted production-size proof, selected suite, final
  `VerificationResult`, release runtime ABI, complete participant runtime,
  browser run, and physical-phone evidence. No proof backend is currently
  mobile-feasible or suite-selectable.
- `SEC-005`: The compact standalone semantic owner is source-level evidence
  only. Complete production masking, ideal simulation, joint KMAC/SHAKE
  justification, emitted-byte correspondence, salted-Merkle privacy, root and
  frontier programming, the fixed-tape shared-QRO premise, and exact Appendix
  A.1/Merkle/QROM instantiation remain open. No soundness certificate or bit
  count is authorized.
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
- `SEC-019`: The current scalar release WASM and SDK byte copy are byte-identical and have normalized loader SHA-256
  `712eb1fdf79b6cd7d32bf4e008ccfe3b17a46c799aa63cf50bb67eee9e220894`.
  This is release-build and byte-copy development evidence only, and the
  retained ordinary desktop-browser graph remains historical. The release build
  contains compact relation materialization but still omits compact proof
  generation and verification, so this is not
  selected-size compact-proof browser or physical-phone qualification. Compact
  checkpoint publication remains reduced kernel
  groundwork, not browser-custody or selected-size durable resume.
- `SEC-020`: Authenticated assignment loading, bounded lookup materialization,
  owned structured-row preparation and transpose, the codec, transport gate,
  scalar CFW, incremental proof assembly, the prover transcript cursor, bounded
  response-tree custody, and authenticated response-checkpoint construction
  compile into release code. Selected-size compact source preparation has
  guarded native phase evidence for the exact initial WHIR encoding, action-
  private WHIR and response-salt seeds, real response-tree values, an attempt-
  bound construction cursor and authenticated response checkpoint, a
  transcript-minted lookup challenge, bounded structured-row materialization,
  retained-tree overlap, and one CFW poll. Cold common-worker restoration,
  complete proof execution, full resource reconciliation, and browser execution
  remain unresolved.
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
