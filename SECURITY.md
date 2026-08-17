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

Current production setup, ballot, and target-proof call sites still invoke the
rejected row-code/WHIR comparison implementation. It is not an accepted
production path, cannot activate a suite, and may remain only as a fail-closed
comparison oracle until the compact successor accepts the same transported
production relations and hostile corpus.

The default kernel compiles the compact successor's typed contract decoder and
its fixed relation, CFW, WHIR, proof-wire, response-Merkle, transcript,
fixed-message, and checkpoint geometry owners. It also exposes a release
transport validator that strictly decodes canonical proof and public-input
bytes, derives the verifier transcript and response-query schedule, and checks
every salted Merkle opening with typed refusals. The scalar CFW prover/verifier
algebra and its bounded external-memory transaction driver compile into the
release kernel. The authenticated assignment loader derives its exact source
halves from the checked relation, materializes lookup inverses with bounded
polls, and transfers the completed secret assignment into an owned structured
row source and transpose path. This state has no borrowed worker-lifetime
references. Incremental proof assembly, the prover transcript cursor, bounded
response-tree writing and scanning, retained-tree coordination, and the
authenticated response-checkpoint boundary are release code that owns copied
geometry and canonical public-input bytes. A release-owned compact response
state now drives those components with verifier-selected leaf replay, exact
transaction yielding, cancellation, authenticated cursor restoration, and
byte-identical genesis replay. A release-owned public-key family adapter joins
the frozen factor-one contract to the retained setup authority, polls the exact
202 authenticated source columns, and derives canonical public-input bytes
from verifier-minted suite, application-statement, manifest, and relation
bindings before independently decoding them. The guarded selected-size owner
now exercises a release-owned public-key generation state that owns family
materialization, its first three compact responses, and the complete CFW
response sequence together. That state accepts the
lookup challenge only through a borrowed first-message authority minted by its
retained compact response state for the same proof geometry and canonical
public input, then owns bounded lookup inversion and structured-row preparation.
Before that lookup challenge exists, the production state derives
the first WHIR epoch's exact 2,097,152-element source from authenticated
quotient-and-multiplicity values plus canonical zero padding. Distinct action-
private hiding and proof-salt coordinates supply coordinate-separated WHIR and
response-salt seeds. The guarded owner retains WHIR's exact 131,072-row by
64-element encoding, streams those values into the salted response tree, binds
a strict version-two 56-byte attempt-and-WHIR-position cursor into the
authenticated response checkpoint, refuses superseded version-one cursors, and
retains the tree through 233 lookup polls, 760
structured-row polls. The same release state samples the production CFW masks
and the inner, outer, and shared cross-epoch WHIR mask encodings, then derives
the main epoch's logical 131,072-row by 128-element extension encoding from the
production structured-row source. It never retains that 671,088,640-byte
matrix whole. Eight deterministic 16,384-row stripes keep one 83,886,080-byte
stripe and one 5,242,880-byte encoded column live while the state commits all
262,144 second-response leaves, derives the second verifier message and its
21-coordinate cross-epoch point, and publishes the next authenticated response
checkpoint. It then commits the four-leaf cross-epoch response and executes all
23 CFW rounds through the final response. Each round polynomial must pass its
compiler-derived rank-seven conditional image before response construction.
The final atomic response samples its translated full-rank terminal values
before checking the outer evaluations against the verifier-derived affine
hyperplane, while canonical bytes remain outer-first. Authenticated response
checkpoints cover the cross-epoch response, every completed round, and the
final response.
After that checkpoint, the same state takes the retained first-epoch source,
builds the exact verifier equality covector in bounded polls, and verifies the
source claim and masked cross-epoch equalities before entering the selected
initial WHIR sumcheck. It commits the canonical mask-oracle, auxiliary, and
padding response, binds the transcript-derived combination challenge, and
emits all six transcript-bound round responses. The auxiliary and every round
wire pass independently compiled conditional-image gates before commitment;
authenticated checkpoints precede every subsequent fold. Guarded selected-size
coverage completes this batch with 4,108 response leaves, 12 verifier-selected
openings, and a 32,768-element residual source and covector. This is one initial
masked-sumcheck batch. The state then folds 25,344 original encoding-randomness
coordinates into the 396-coordinate extension-field switch mask, samples the
next-source and mask encoding randomness from the live KMAC stream, and commits
the exact 8,192-row by 16-element source plus 4,096-row by one-element mask in a
16,384-leaf response. The next verifier message supplies one extension
challenge, one base-field challenge, and 396 distinct source queries. Before
any opening is released, all 25,344 query-major source coordinates pass the
compiler-derived full-rank conditional-image gate for that authenticated
message prefix. The state then opens 396 original-source leaves, binds the
challenge and query set once, and authenticates the response checkpoint. It
then constructs the exact code-switch output relation in bounded polls and
requires the accumulated source and preceding-mask claims to equal the
accumulated folded-opening target. The next masked sumcheck consumes role
nine through its exact one-extension, one-base-field, one-query-group shape,
binds that extension challenge, and gates its auxiliary and four round wires
against independently compiled conditional images before commitment.
Authenticated checkpoints cover every response. Guarded selected-size coverage
finishes this batch with 4,104 response leaves, eight compiler-required round-
wire openings, and a 2,048-element residual source and covector. The next two
code switches derive 432 and 400 source queries from their exact verifier
messages, replay only the touched canonical stripes, verify the retained query
images against independently compiled masking maps, and release the full prior
sources after binding the next relations. Only the queried rows needed by later
last-use Merkle openings remain. Both padded code-switch responses contain
8,192 leaves and emit zero openings at their own moves, as required by the
response-retention chronology. The following four-round batches each commit
4,104 leaves and supply eight round-wire openings, reducing the residual source
to 128 and then 8 elements. The release state then folds the final source and
retained mask randomness to the base case, derives the role-18 carried covector
from the canonical public input and authenticated prefix, and checks the fresh
claim. It commits the 32,768-leaf fresh response, gates the role-10 blinded
reveal before consuming its combination challenge, and commits the 16,384-leaf
blinded response. At the first-epoch final-query move, response custody supplies
19,133 authenticated openings. The masking owner consumes only the 6,681 leaves
owned by that move, excludes 830 historical source-query leaves, and evaluates
399 committed leaves of the epoch-neutral shared cross-epoch root without
opening it before its second-epoch last use. The final gate therefore checks
exactly 7,080 compiler-derived query leaves before releasing the final secret
state. Guarded native coverage executes this complete pre-challenge response
path under the repository memory ceiling. It does not close the main WHIR
epoch, a complete emitted proof, or browser evidence.
The final gate returns only an opaque in-memory continuation bound to the proof
attempt, first-epoch claim coefficients, and exact authenticated verifier-
message prefix; it is neither serialized nor caller supplied. The release
generation state uses that continuation to replay the masking chronology at the
initial main-epoch boundary. It independently derives the complete main source
covector from verifier-bound CFW challenges and production matrix-role weights,
streams all 4,194,304 authenticated witness elements into the matching relation,
checks its target, samples the initial masked-sumcheck state from the live KMAC
stream, and gates the sampled auxiliary target against the independently
compiled conditional image. Guarded selected-size native coverage reaches this
prepared state, but it has not committed a main-epoch response.
The CFW phase reconciles 4,926 external-storage transactions, 1,006,632,840
bytes written, 2,013,265,440 bytes read, and 587,202,560 peak CFW storage bytes;
measurements remain in its run diagnostics. At a later opening boundary, the
response state exposes only its verifier-derived query schedule; the production
owner filters the exact main-source rows and performs one-shot replay of each
touched canonical stripe from retained source authority and encoding
randomness. Focused parity and hostile lifecycle coverage exists, but the
selected-size owner has not reached or measured that later opening move. This
is native development evidence only.
Selected-size main-source stripe opening replay, authenticated mid-stripe
restart, cold restoration through the common worker, scalar-WASM execution,
main-epoch response execution, and a complete emitted proof remain absent.
The test-only production-shaped small-chain owner uses the response state, but
the production worker adapter, later main-WHIR response and fold execution,
semantic composition, complete masking path, emitted-coordinate accounting,
fixed-tape arithmetic, proof production, and complete algebraic proof
verification remain test-only or incomplete. Before post-lookup masking
material is drawn, release generation now independently re-decodes the canonical
public input through the selected verifier contract, derives and checks every
coefficient-to-view map, and constructs the compiler/verifier-derived public-
covector authority for those bytes. The same release gate rederives the exact
single-proof KMAC coordinate and call census from that contract. Production
uses separate KMAC256 domains for WHIR field candidates, private leaf salts,
and Fiat-Shamir round salts, bounds every Goldilocks rejection sample to 64
candidates, and refuses exhaustion or an unaccounted random-access call before
accepting a sampled batch. Before committing the third response, release
generation binds the masking attempt to its exact canonical public input and
emitted proof prefix plus the authenticated transcript cursor after the first
two responses, replays those verifier moves, and verifies the real three-
coordinate cross-epoch disclosure and CFW auxiliary scalar against the
independently compiled rank-two and rank-one conditional images. The CFW prover
cannot initialize unless that check passed. Every live CFW round, the initial
pre-challenge WHIR auxiliary, and all six initial WHIR round disclosures now
pass their conditional-image gates. The first source-query disclosure also
passes its full-rank conditional-image gate before generation releases any
opening. The later two source-query images are evaluated at their verifier-
message boundaries and retained only after the same production masking check;
all four pre-challenge auxiliaries and every round wire pass their live
conditional-image gates. The verified first-epoch base prefix also authorizes
the exact initial main-epoch replay, whose sampled auxiliary target passes its
live conditional-image gate.

The test-only factor-one semantic owner covers the checked 82-move schedule,
including prefix knowledge states, deterministic bad-transition owners,
adjacent extracted-witness continuity, zero implicit tuple dimensions, and the
local extraction-work bound. It is source-level evidence for one development
slice, not a production noninteractive proof or authority for another proof
family.

No complete production compact prover, complete emitted production proof,
selected suite, final `VerificationResult`, complete compact generation and
verification ABI, compact-proof browser run, or physical-phone evidence exists.
The release transport ABI cannot mint a proof or workflow capability. Build
reproducibility establishes byte identity only and does not close any missing
proof or security argument.

### Masking and zero-knowledge boundary

The test-only masking workbench exercises conditional images and a transactional
adaptive simulator over the same coefficient maps and public-covector replay
now compiled into release code. Its one-shot carried-covector lifecycle is bound
to verified public input and the exact semantic prefix, and guarded coverage
reaches the terminal 82-move lifecycle, including retry, restore, and nonempty-
suffix rewind.

The release path does not close masking: the main-epoch role-18 authority and
sequential conditional images, whole-construction terminal simulator binding to
the complete emitted proof, and the exact construction-level statistical-HVZK
statement remain absent. The live CFW gates bind the canonical prefix through
the final CFW response. The live pre-challenge WHIR path extends that binding
through all four masked-sumcheck batches, all three code-switch source-query
disclosures, the role-18 base claim, the role-10 blinded reveal, and the role-11
final-query image. Final-query accounting follows logical query ownership rather
than the response opening time: it excludes previously checked historical
leaves and evaluates the first 399-leaf view of the shared cross-epoch root
without releasing that root's deferred Merkle opening. These gates do not cover
the main epoch or terminal whole-construction simulator and are not a complete
emitted-byte correspondence argument.
The live bridge accounts for three symbolic quantum-PRF replacements: action-
root key expansion, proof-coin and coordinate-stream derivation, and compact-
generation expansion keyed by the two seeds. It also retains exact action-root,
context, seed, sampler, leaf-salt, and round-salt collision terms. It assigns no
numeric advantage to fixed KMAC256 and does not establish the masking claim
without the missing sequential Real/Ideal and emitted-byte work.

KMAC256 and SHAKE256 share fixed Keccak-f. Domain separation is required but
does not by itself establish an independent qPRF and ideal-QRO model. The
compatible joint assumption or reduction, salted-Merkle privacy, programmed
domains and maps, reused-randomness behavior, multi-proof and ceremony
composition, and full QROM zero knowledge remain open.

### Emitted-byte and QROM boundary

The release transport path canonically decodes proof and public-input bytes,
derives its Merkle privacy certificate and verifier messages, and gates every
scheduled response opening. Its Rust/WASM boundary consumes the four exact
suite, application-statement, manifest, and relation-plan bindings and returns
typed refusals for hostile input. It does not verify the CFW or WHIR equations,
does not return `isValid`, and cannot mint a proof or workflow capability. Its
checkpoint exercise remains in-process rather than durable browser custody.

There is no complete production proof whose byte ranges, values, roots, salts,
frontiers, transcript messages, queries, and verifier consumers instantiate the
theorem correspondence. Reduced deterministic fixtures and static maximum
regions cannot substitute for those bytes.

The Appendix A.1 arithmetic derives `qPi = 79,310` but still requires a
production theorem premise connecting the predecessor-linked SHAKE256 graph to
the independently sampled fixed verifier tapes in the shared quantum random
oracle. Framing, slot exhaustion, and classical equidistribution cannot mint
that premise. No adaptive-soundness certificate or security bit count is
authorized until it and the complete emitted-proof composition close.

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
- `SEC-005`: Construction-level masking, emitted-byte correspondence,
  salted-Merkle privacy, the deployed KMAC hybrid, fixed-tape shared-QRO premise,
  and exact Appendix A.1/Merkle/QROM composition remain open. No soundness
  certificate or security bit count is authorized.
- `SEC-006`: The participant bridge does not connect the complete verifier-
  minted capability and checkpoint chain from setup through release.
- `SEC-007`: Direct encrypted-ballot creation, proof generation, transport, and
  acceptance are incomplete. Real ballots must not be cast or collected.
- `SEC-008`: No physical-phone/browser tuple has completed every participant
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
- `SEC-019`: Reproducible scalar release WebAssembly and SDK bytes establish
  build identity only. The release artifact contains the transport validator
  and unconnected scalar CFW implementation but still omits compact proof
  generation and complete algebraic verification.
- `SEC-020`: Selected-size compact source preparation now has guarded native
  phase evidence for the exact initial WHIR encoding, action-private WHIR and
  response-salt seeds, real response-tree values, an attempt-bound construction
  cursor and authenticated response checkpoint, a transcript-minted lookup
  challenge, bounded structured-row materialization, production CFW and WHIR
  mask material, the complete striped 262,144-leaf second response, its
  transcript-minted cross-epoch point and checkpoint, retained-tree overlap,
  all 23 conditional-image-gated CFW rounds, and the verifier-bound final CFW
  response. It also owns the initial pre-challenge WHIR masked-sumcheck batch:
  bounded relation and equality-covector preparation, the canonical mask and
  auxiliary response, six transcript-bound and conditional-image-gated round
  responses, authenticated checkpoints, 4,108 response leaves, 12 openings,
  and the 32,768-element residual relation. It also owns the first code switch:
  the six-challenge fold of 25,344 base-field randomness coordinates, the
  8,192-row extension source and 4,096-row mask commitment, the live full-rank
  conditional-image gate, 396 original-source openings, one-shot verifier-move
  binding, and the authenticated response checkpoint. It then constructs the
  exact verifier-bound output relation in bounded polls and completes the
  second masked-sumcheck batch through the role-nine mixed-output challenge,
  four conditional-image-gated rounds, authenticated response checkpoints,
  4,104 response leaves, eight round-wire openings, and a 2,048-element
  residual relation. It then completes the remaining two code switches and
  masked-sumcheck batches. The 432- and 400-position query images are derived at
  their verifier-message boundaries, checked against the production masking
  maps, folded into the next relations, and retained in queried-row form for
  later last-use openings. The two 8,192-leaf code-switch commitments emit no
  premature openings; the following batches each own 4,104 response leaves and
  eight round-wire openings and reduce the residual relation to 128 and then 8
  elements. It then folds the final eight-element source and retained mask
  randomness to the base case, derives and consumes the live role-18 carried
  covector, gates the role-10 blinded reveal, and commits the fresh and blinded
  responses. At the role-11 final-query move it authenticates 19,133 response
  openings and gates exactly 7,080 logically current query leaves: 6,681
  immediate leaves plus 399 committed leaves whose shared-root Merkle opening
  remains deferred. Its CFW external-storage execution reconciles 4,926
  transactions, 1,006,632,840 bytes written, 2,013,265,440 bytes read, and
  587,202,560 peak bytes. It then derives the initial main-epoch source covector
  from the verifier-bound CFW challenges, streams the complete 4,194,304-element
  authenticated witness through the matching relation, checks its target, and
  gates the sampled initial auxiliary target using the opaque verified first-
  epoch masking prefix. The production path owns verifier-derived opening
  recomputation, but selected-size main-source stripe opening replay, mid-stripe
  restart, cold common-worker restoration, main-epoch response execution,
  complete proof execution, browser resource reconciliation, and browser
  execution remain unresolved.
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
