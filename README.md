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

The protocol is designed around a public transcript and participant-side verification:

1. A poll configuration and externally anchored participant roster define the ceremony and its threshold.
2. Participants contribute verifiable secret-sharing material and collectively derive the public and evaluation keys. No single participant holds the complete decryption key.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over ciphertexts, with a replay record that clients can check.
6. A finality quorum authorizes exactly one target result.
7. After finality, any reconstruction threshold of valid target-bound shares reveals only that approved result.

The only public result is the ordered list of the selected `topOptionCount`
option identifiers; choosing all options yields a full ranking. Exact sums,
margins, individual scores, aggregate shares, comparison bits, ranks, and
intermediate evaluator values are not public outputs.

The protocol-family boundary is `3 <= n <= 20` participants and
`2 <= optionCount <= 20` options. The sole implementation and evidence target
is `n = 10`, `optionCount = 10`, with three actively Byzantine participants,
four reconstruction shares, and finality and state quorums of seven. Other
roster sizes remain unsupported. Other option counts in `2..20` are admitted
candidate configurations but remain unqualified until separately evidenced.
The public validators and deterministic source compilers admit that complete
option-count range, and the selected source profile binds exactly ten options.
The Rust ballot-generation boundary derives its complete score-vector length
from that selected count, the selected evaluator aggregate derives exactly ten
ordered `topOptionCount` variants, and focused structural tests cover every
configurable count without generating cryptographic evidence for the other
counts.
The current version-five mapped-soundness vector contains the exact-ten
construction identities, twelve family rows, and conservative 103-physical-
proof, 159-logical-instance arithmetic. Its independently derived fixed-output
graph certificate covers coherent seed-and-block access, exact predecessor
support, database recording and extraction, and the conservative action union
under one modeled 512-bit ideal QRO. It is not yet accepted as emitted-proof
soundness authority: the evidence builder and imported collective-setup record
keep the fixed-output transform and proof composition unresolved until one
freshly transported canonical proof instantiates the certified construction
and graph identities.
Other checked construction records, resource ledgers, checkpoints, and runtime
evidence still describe the superseded twenty-option candidate and are not
eligible for suite freeze.

Every required participant operation is intended to run in the participant's
own mobile browser. Transcript and mailbox services only relay untrusted bytes;
they are not trusted to prove, verify, tally, finalize, or decrypt.

## Prototype status

The kernel's selected source profile and deterministic compilers now target
`n = 10`, `optionCount = 10`. The suite remains unavailable until its
parameters, proof construction, theorem records, vectors, resource ledgers,
and runtime evidence are regenerated and frozen together. All exact geometry,
proof-count, proof-size, transcript, soundness, and runtime figures below were
generated from the superseded twenty-option candidate unless stated otherwise;
they remain useful diagnostics but are not evidence for the selected
ten-option bytes.

Works today:

- The public package validates poll input and creates or verifies canonical
  foundation objects.
- The Rust/WebAssembly kernel recomputes their encodings, hashes, roots, roster
  formulas, and contexts.
- Browser-local custody, authenticated records, checkpoints, and fixed-roster
  state witnessing have focused desktop-browser coverage.
- Ballot encryption, aggregation, encrypted evaluation, and target release have
  focused component tests.
- All production proof-family preparation sites now use the streaming row-code
  and explicit-point WHIR construction. The old operative FRI body has been
  removed, and the successor has production-owned masked proof assembly,
  incremental canonical verification, bounded-storage primitives, and focused
  development tests.
- The live 64-way same-secret geometry and full-coordinate, inverse-rate-four
  aggregate-wide mask have production-derived static plans. The canonical
  transport sections and selected resource owner now independently reconcile a
  `5,813,652`-byte family body plus a 902-byte header, for a `5,814,554`-byte
  static proof ceiling. That is `571,674` bytes above the nominal target and
  within the automatic variance band. The current exact-ten resource owner
  derives all 21 selected variant rows; 18 exceed the automatic proof band but
  remain below the absolute parser bound and require engineering review. These
  are static ceilings, not emitted-proof or browser evidence.
- Aggregate-wide oracle commitments now use uniform 512-bit leaf transitions
  in aligned `2^20`-row stripes. The selected construction derives a
  `402,653,184`-byte DFT-plus-leaf-state core and preserves the canonical roots
  and proof-size ledger. These are contiguous commitment-row stripes in
  canonical leaf order, with 64-byte chaining values; they are not
  subgroup-coset DFT stripes.
- Phase-column commitments retain their original whole-column SHAKE leaves and
  canonical ascending Merkle coordinates, but now evaluate each row through
  `2^19`-column subgroup-coset lanes. A five-level digest-plane carry restores
  each group of 32 interleaved coordinates before the upper tree consumes it.
  Focused production-schedule tests prove exact row-value, private-salt, root,
  compact-frontier, and opening-coordinate parity with the prior natural-order
  commitment bytes.
- The selected same-secret verifier census and theorem certificate
  independently derive all 23 Merkle opening classes from the canonical
  construction and supplied-opening plans. Every class uses a
  coordinate-derived compact frontier. The nine column-streamed classes expand
  into their exact initial, ordered-column, and final SHAKE calls, deriving
  `695,547` verifier hash queries and `695,547` accepting equations across the
  complete deployed ledger. Every
  secret-bearing initial call absorbs a distinct transported 128-byte private
  salt; canonical encoding and decoding reject a reused salt across opening
  batches. The
  census derives and binds the 512-bit output width for every transcript,
  ordinary-leaf, streamed-leaf, and parent call. The construction and
  hash-profile identities also bind the 512-bit streamed state and canonical
  frame tags. Each of the `4,272` logical challenges now starts with one fixed
  512-bit seed call and expands through predecessor-linked, domain-separated
  512-bit block calls. Every bounded candidate slot is consumed even after the
  sampler accepts. The production-derived inventory contains `590,128` output
  block calls and `604,801` fixed-width calls across the complete graph. The
  theorem projection assigns `10,401` ordinary calls and `4,272` seed calls to
  the primary restriction and assigns the `590,128` output-block calls to a
  disjoint precommitted auxiliary sampler restriction of the same fixed 512-bit
  QRO.
  A construction-bound classical certificate derives all `4,260` extension,
  nine distinct-index, and three product-space sampler distributions. It binds
  the exact modulo rejection, relation-derived forbidden sets, ordered
  without-replacement query law, seed-collision term, exhaustion terms, and
  atomic no-interleaving chronology. Runtime transcript state independently
  refuses a second challenge, prover response, checkpoint, or handoff while an
  atomic sampler is active. A focused same-secret theorem additionally proves
  simultaneous auxiliary-table concentration for every product, extension,
  and production-owned distinct-query bad set, including shared query vectors
  and the 40-coordinate prefix of the 266-coordinate bound vector. It charges
  the conditioned exhaustion term inside the primary classical failure and
  the complete auxiliary-table bad event outside the CMS19 multiplier, while
  treating the fixed auxiliary table as a unitary available to the primary
  restriction reduction. The certificate maps every complete-ledger SHAKE256
  call to one canonical preimage restriction and proves the modeled oracle
  inputs form two disjoint restrictions. It embeds every finite variable-length
  adversary register into one fixed input register, factors the random function
  and query unitary, treats fragments, suffixes, repeats, and overlaps as
  computation on cached 512-bit answers, and absorbs a conditioned auxiliary
  table into the adversary between primary queries. A canonical production
  preimage parser then derives the exact CMS19 predecessor support with at most
  two pointers per database entry and connects purification, recording,
  lifting, state transition, and extraction. All 21 exact selected production
  identities derive as structural inputs. Concrete SHAKE256 is an explicit
  ideal-QRO assumption rather than a proven random oracle, and no production
  proof has been emitted.
  The exact `604,801`-call transcript census contains `6,306` original-BCS
  rounds. The executable
  whole-state evaluator and collision-free accepting-database extractor bind
  every plan-derived verifier and response address, recover every exact round
  prefix plus its next verifier message, and connect all `2,059` response
  digests to the complete verifier database and coordinate-derived commitment
  subtrees. A separate soundness-only certificate joins all 23 commitment roles
  by role rather than relying on ledger order: 12 roots are fixed by earlier
  transcript responses and 11 bound-tree roots come from the canonical
  application statement. It preserves nine shared query vectors, including the
  40-coordinate bound-input prefix of the 266-coordinate bound vector, and
  derives 5,061 semantic opened leaves, 22,756 underlying leaf calls, 67,986
  parent calls, and 90,742 complete Merkle calls. The complete deployed
  verifier ledger is `695,547` hash queries and `695,547` accepting equations.
  Its restriction projection contains `105,419` primary-restriction verifier
  hashes, `105,419` primary accepting equations, and `590,128` auxiliary-table
  calls. The correction removes 18 nonexistent public-setup sequence hashes
  and nine nonexistent distinct equations: verification consumes those values
  as already authenticated auxiliary input and makes no such SHAKE256 call.
  Conditional on an already
  fixed root and a collision-free oracle database, the accepted compact
  frontier yields one verifier-consumed partial tree. Choosing another root is
  a different statement or transcript and is not charged as a collision.
  Hostile width, domain, slot, address, response-owner, root-authority,
  shared-query, leaf-call, frontier, and message-shape mutations refuse. This
  is focused structural evidence for the separated sampler model. The
  conservative composition code assigns the complete `2^80 - 1` adversarial
  query budget to each physical proof, unions logical failures inside that
  proof, and then unions the physical-proof rows without cross-proof
  independence or shared-hybrid credit. The current version-five production
  vector expands 12 family entries into 103 physical proofs and 159 logical
  instances, charges the auxiliary-table bad event 103 times, and reports
  fixed-budget and constant-success metrics separately. The action arithmetic
  reports classical failure in `(2^-188, 2^-187]`, a conditional fixed-budget
  QROM interval of `(2^-25, 2^-24]`, and conditional 92-bit constant-success
  query boundaries under the declared fixed 512-bit ideal-QRO model. Those
  bounds now derive for the certified production rows, but the imported closure
  leaves remain unresolved until emitted transported bytes instantiate their
  construction and graph identities. Nonlinear privacy and the remaining
  setup-family and terminal composition arguments remain open.
- Secret-bearing phase-row padding now uses three KMAC-derived 512-bit seeds.
  The selected same-secret certificate inventories 62 framed SHAKE streams,
  130,023,424 accepted field outputs, seed collision, bounded rejection
  exhaustion, and classical and quantum secret-prefix replacement terms. It
  refuses the former 256-bit seed geometry at the declared quantum query
  budget. This is component evidence under the stated KMAC and ideal-oracle
  assumptions, not a complete zero-knowledge theorem.
- Attempt-private leaf salts now have one production-derived PRF certificate
  across all phase and aggregate commitments. For the selected same-secret
  construction it inventories 12 commitment roles, four private key sources,
  67,125,248 distinct framed inputs, 133,974,178 clean-path KMAC derivations,
  and 3,943 transported attempt-derived salts. The exact proof additionally
  transports 320 persistent salts from statement-owned committed-material
  openings and carries one duplicate set across all phase, bound-tree, and
  aggregate openings. The certificate retains symbolic classical and quantum
  KMAC PRF reductions and bounds the ten-proof ideal-function collision union by
  `10 * C(67,125,248, 2) / 2^1024`, between `2^-969` and `2^-970`. This is a
  hiding-component bridge, not complete common-proof soundness or
  zero-knowledge evidence.
- The aggregate-wide masking certificate now has an independent production
  correspondence for all 15 affine-view blocks. It walks the deployed
  transcript and commitment-opening catalogs, binds the six recomputable
  source encoders plus the aggregate pad and two fresh encoders, and checks the
  exact message, randomness, zero-suffix, two-adic evaluation, shared-query,
  code-switch, and lexicographic fold maps. The selected joint view has 18,025
  affine private extension coordinates, rank 18,013, and residual conditional
  entropy 12. Two additional private extension elements form the nonlinear
  aggregate leaf-salt key, for 18,027 complete private elements. This
  correspondence is one input to the construction-wide affine accounting
  below; it does not by itself establish Fiat-Shamir privacy or soundness.
- The pre-aggregate construction masking certificate independently rebuilds the
  private-view graph from the physical production layout. It covers every phase
  row, quotient extension coordinate, bound-tree opening, opening-point role,
  source authority and lifetime, resume rule, telescoping dependency, and
  aggregate delegation. For the same-secret construction it derives a
  `2,097,152`-coefficient row-pad source dimension and a required distinct-point
  rank of `3,483`. Public-only layouts keep their quotient and bound-tree
  coverage without invented private masks; the ballot layout binds all 22
  physical aggregate coordinates while assigning private aggregate views only
  to relation-owned points 0, 1, and 11. Focused mutation tests refuse omitted
  or altered coordinates, dependencies, authorities, ranks, and query
  schedules.
- The selected same-secret construction now composes every private affine
  source into one production-derived masking certificate. Its six disjoint
  classes are relation trace masks, quotient telescoping masks, the opening
  batch mask, 62 phase-row pads, 32 prior-VSS committed-material columns, and
  the 15-block aggregate-wide pad. The certificate binds each class to its
  actual current-attempt or authenticated persistent authority, uses exact
  joint ranks except for the conservative persistent-material rank ceiling,
  reconciles every residual conditional-entropy count, and links the deployed
  KMAC, framed SHAKE, rejection-sampling, leaf-salt, and aggregate-salt-key
  generator hybrids. It refuses deficient ranks, omitted coordinates, changed
  authorities or query schedules, challenge-dependent or publicly recomputable
  masks, and zero-knowledge claims outside its scope. This establishes exact
  source, view, rank-ceiling, entropy, and generator accounting under the
  uniform-source idealization. It is the production input to, rather than a
  substitute for, the conditioned image-inclusion and sequential-simulation
  certificates below. The separate fixed-root commitment certificate does not
  turn those component results into emitted-proof instantiation, complete
  Fiat-Shamir soundness, or ceremony composition.
- The selected same-secret path now also derives a query-bounded pre-opening
  commitment-root hiding theorem for all 23 deployed Merkle roles. Per proof,
  it counts `134,234,112` private leaves, `149,192,704` aggregate streaming
  state calls, and a `417,660,908`-call complete private-commitment ceiling;
  the ten-proof commitment-view hybrid is bounded between `2^-402` and
  `2^-401` under the declared domain-separated ideal-XOF and private-KMAC
  hybrids. The generic BCS16 direct-leaf comparator is explicitly refused: it
  does not match the deployed streaming chain and lies only between `2^-96`
  and `2^-95`. This root-replacement component is not by itself a
  construction-wide privacy or zero-knowledge result; opened values and
  canonical transport are handled by the separate static simulator below.
- The selected same-secret theorem now derives exact conditioned affine image
  inclusion for all six private source classes. Its production factorizations
  cover vanishing-scaled trace evaluations, the conditioned telescoping
  quotient kernel, the independent opening-batch mask, 62 phase-row
  Vandermonde maps, the joint prior-VSS producer/consumer image, and the
  15-block aggregate map. For every row, the mask-image rank equals the joined
  mask-and-witness image rank after the declared prior transcript exposure.
  One classical ideal-XOF sequential simulator then preserves the nine actual
  shared query vectors while owning all 23 commitment views, all 11 switch and
  fold views, all 22 canonical outer proof sections, and all 15 ordered
  aggregate-terminal sections. It programs 20 private coordinate-derived
  compact frontiers, verifies three public frontiers, covers 4,263 private and
  798 public opened leaves, imports rather than redraws the eight persistent
  producer roots, and retains the pre-opening bad-event bound in
  `(2^-402, 2^-401]`. The two production-empty out-of-domain vectors remain
  explicit ordered zero-byte sections. Hostile tests refuse deficient image
  rank, changed conditioning, split shared queries, redrawn persistent roots,
  omitted or reordered sections and derived views, altered canonical-empty
  vectors, and stronger security overclaims. This is static construction
  evidence under the declared classical ideal-XOF and private-generator
  hybrids. Its focused guarded owner passed with a 66.77-second test body,
  `205,246,464` bytes peak sampled process-tree RSS, and no confirmed memory
  violation. It is not emitted-proof evidence, a concrete SHAKE256 reduction,
  adaptive setup-family simulation, malicious-verifier or resettable zero
  knowledge, or quantum-random-oracle zero knowledge.
- The exact same-secret transport correspondence now walks all 22
  construction-plan proof sections through their production decoder and
  semantic-verifier owners. Its current section model derives a
  `5,813,652`-byte family body and the `2,942,104`-byte aggregate-wide terminal,
  giving `5,814,554` bytes after the 902-byte canonical header. The selected
  resource owner independently rederives the same total as a 2,872,450-byte
  pre-aggregate prefix plus that terminal. The catalog binds the statement,
  protocol, suite, ceremony, action,
  application slot, relation, construction, declared length, and final stream
  digest, and mutation tests refuse omitted or reordered sections, stale
  identities, incomplete binding or refusal catalogs, and altered byte
  ledgers. This is a static parser-to-verifier correspondence. It does not
  establish acceptance of an emitted proof or discharge nonlinear privacy and
  ceremony-level reductions.
- At the reviewed superseded checkpoint, checked construction-geometry
  certificates derived for all 31 twenty-option production identities: 27
  width-64, log-inverse-rate-two
  (inverse-rate-four) identities, including evaluator top counts 1 through 20,
  and four width-8, log-inverse-rate-five (inverse-rate-32) identities. The
  constructor now additionally requires one executable atomic predecessor-state
  evolution, one plan-addressed collision-free prefix-plus-next-message
  extractor, plan-derived polynomial and explicit-point extraction, and a
  family-specific failure ledger before it emits a checked geometry record.
  The polynomial extractor walks every relation-phase chunk, quotient and mask
  coordinate, bound-tree reduction, aggregate opening batch, WHIR epoch, and
  polynomial and selector basis identity. The failure ledger derives
  query-event presence, row-code rate, agreement ceilings, product-challenge
  degrees, statement-family multiplicity, classical loss, and a provisional
  quantum-random-oracle projection from the selected plan. All 27 width-64 and all
  four width-8 production identities passed that constructor and full-false
  terminal rejection at the reviewed checkpoint. The public-key-share schema
  `0x1212` now also has an isolated certificate owner: it recompiles the exact
  production relation, validates verifier and bound-root authorities, derives
  opening and sampler geometry, and closes its family failure rows without
  evaluating neighboring schemas. Bound query accounting follows the deployed
  reduction polynomials rather than counting each underlying tree as a
  separate logical word. In the same-secret plan, eight prior-proof roots form
  one prior-certified block with agreement ceiling `9,217`, while three direct
  roots form one direct block whose exact leaf-level quotient dimension is
  `8,192` and whose agreement ceiling is `4,198,400`. The VSS plan derives eight
  application-modulus alpha vectors with seven coordinates each, retains their
  distinct sample-space denominators, and enters their failure terms as an
  exact rational sum. The aggregate-threshold plan independently proves that
  its deterministic residual schedule has no product sampler. Hostile tests
  refuse omitted phase polynomials, changed aggregate opening columns or scalar
  counts, proof-supplied points, changed basis identities, wrong family or
  multiplicity bindings, altered VSS product or algebraic denominators, and an
  invented aggregate-threshold product row. Families with no bound tree or
  verifier-sequence source do not acquire an invented ledger row.
- Production-derived phase-liveness accounting covers source ownership, replay
  readers, DFTs, Merkle frontiers, proof material, transcript state, private
  material, browser-bridge copies, a WebAssembly runtime reserve, and allocator
  overhead. The selected VSS phase-commitment row now derives `471,779,070`
  bytes from the complete live set, including a `33,554,432`-byte runtime
  reserve and `48,691,627` bytes of allocator overhead. The complete selected
  VSS maximum is `597,023,349` bytes, leaving `6,956,427` bytes below the
  automatic ceiling and `74,065,291` bytes below the hard WebAssembly bound.
  Aggregate-source accounting now includes the resident witness and its
  simultaneously allocated padded physical row, rather than substituting the
  already-released replay chunk. The selected same-secret aggregate-source
  phase consequently derives `593,470,870` bytes, `10,508,906` below the
  automatic ceiling and `77,617,770` below the hard bound.
  This is static accounting, not a native or browser full-proof measurement;
  the narrow automatic-ceiling margin, allocator behavior, and phase lifecycle
  remain unmeasured, so memory feasibility is not closed.
  Bound-tree authentication uses
  one in-place DFT and one evaluated stripe instead of retaining complete
  evaluated columns; its complete static phase row is `289,682,322` bytes.
  These are conservative production-derived live-set bounds, not native or
  browser measurements.
- The production VSS prerequisite now has a dedicated guarded generation and
  transported-verification test. It durably seals each canonical safe boundary,
  rejects stale or malformed retained state, and resumes by deterministic
  replay through the kernel's authenticated checkpoint decoder. Its latest
  complete same-secret diagnostic ran for `6,037,835` ms and failed while
  preparing the VSS prerequisite with `Generation(Prover(InvalidColumn))`;
  peak process-tree RSS was `3,554,246,656` bytes and the guard did not report a
  memory violation. A later focused VSS diagnostic generated the browser-owned
  setup authority and reached base-tree materialization before being stopped
  after `9,195,256` ms. Peak process-tree RSS was `3,541,450,752` bytes, and the
  guard confirmed no memory-limit violation. That diagnostic used the retired
  repeated-full-transform schedule. The selected VSS base geometry still has
  1,128 rows and 32 lanes, but one pass now performs 36,096 `2^19`-point lane
  DFTs rather than 18,048 complete `2^24`-point DFTs. Production accounting
  derives `179,784,646,656` butterflies, `18,924,699,648` coset
  multiplications and value deliveries, zero coefficient folds, a
  `104,857,600`-byte SHAKE-state lane, five `33,554,432`-byte digest planes,
  and a `4,194,304`-byte row buffer. Its algorithm live set is `276,824,064`
  bytes before common phase categories. Small-geometry tests reproduce the
  exact old root and compact frontier. One authenticated pre-base checkpoint
  remains available for current decoder-and-verifier resume validation, but
  the focused guarded VSS prerequisite and any complete proof run have not been
  resumed.
  The current liveness plan materializes this geometry twice. The two passes
  therefore require `72,192` lane DFTs, `359,569,293,312` butterflies, and
  `37,849,399,296` value deliveries, or about 282 GiB of eight-byte value
  traffic before allocator and replay effects. Each salted 1,128-value phase
  leaf performs exactly 68 Keccak-f permutations, for `1,140,850,688`
  permutations per `2^24`-leaf pass and `2,281,701,376` across both passes,
  before coordinate-salt KMAC derivations and Merkle-parent hashing. A separate
  non-authoritative measurement artifact now traverses the exact 3,003-source,
  9,009-chunk production replay catalog without entering proving or
  verification. One catalog pass measured `16.5358439` seconds natively,
  `67.8726` seconds in desktop Chromium, and `360.784` seconds in desktop
  Firefox; both browsers ended at `58,720,256` bytes of WebAssembly linear
  memory and matched the native checksum. Projecting the measured owners places
  the current two-pass schedule at about 1.72 hours natively, 7.38 hours in
  Chromium, and 38.85 hours in Firefox. A modeled level-two checkpoint candidate
  uses `268,576,000` bytes of scratch and projects about 1.06, 4.58, and 23.91
  hours respectively. It is not an implemented authenticated production
  checkpoint and makes no root, transcript, proof-byte, or verifier-equivalence
  claim. The displayed owner total excludes the separately recorded checkpoint
  storage, codec, and boundary-copy time. The latest projection also combines
  base and supplemental cases measured from two different WebAssembly binaries;
  the current evidence validator refuses that stitched catalog and requires one
  complete native catalog plus complete Chromium and Firefox catalogs from one
  reproducible WebAssembly binary. No such replacement browser catalog exists
  yet. The feature-scoped selected-output DFT is measured but not consumed by
  production generation.
  A production-derived relation/replay model now reproduces the current
  factor-four, width-eight plan and derives the complete verifier rotation set
  for every power-of-two packing and row-width comparator. The raw minimum-row
  comparator remains factor 16, width 64: a `262,144`-value relation trace, 753
  prover columns, degree bound `264,192`, and 108 physical rows. It is not a
  valid construction. The compiled relation has 24 distinct opening points and
  one bound-reduction aggregate role, while that row geometry leaves only four
  aggregate columns; construction now refuses the exact `25 > 4` capacity
  mismatch. A focused static comparator now reuses the live exact synthetic
  division primitive to reduce the 24 already-fixed, distinct-point opening
  claims to one opening-claim quotient role. Together with bound reduction,
  that gives two roles in the same four-column table. Its common-denominator
  discrepancy has agreement ceiling `4,194,326` over the `16,777,216`-point
  query domain, and the production-owned 387-coordinate outer query vector
  gives the exact without-replacement term
  `C(4,194,326, 387) / C(16,777,216, 387) < 2^-774`. The 393-coordinate
  aggregate-mask query vector is separate and is not used in this term. This
  establishes the candidate's algebraic identity and finite-population bound.
  A feature-scoped construction-plan route now binds the quotient role and its
  24-claim count under a distinct canonical tag while leaving every selected
  direct-role encoding unchanged. It derives two logical columns in the
  four-column table, 387 quotient openings and 536 bound openings, 923 opening
  batches in total, 2,625 transcript operations, 2,158 logical verifier
  messages, and a maximum of 329,471 transcript hash queries. The canonical
  construction identity is 749,188 bytes. The release-native measurement
  validator independently reconciles the source, discrepancy, domain, query,
  role, variable, and batch formulas. Ordinary selected-profile construction
  still cannot call this route, and production extraction explicitly refuses
  the quotient tag. A feature-scoped materializer now streams each padded row
  into that one quotient column with one reusable carry per opening point;
  focused equality tests match the 24 materialized point columns exactly and
  hostile tests refuse duplicate points and mismatched geometry. Because the
  two live roles occupy columns zero and one, the same candidate derives the
  second physical half as canonical zero without another authenticated-source
  replay. A feature-scoped owner now composes the exact candidate artifact,
  source catalog, storage plan, proof encoder, transcript, and construction
  plan into all 13 phase-liveness rows while proving that the ordinary selected
  manifest route still refuses the candidate context. Its `661,380,505`-byte
  aggregate-source peak is `57,400,729` bytes above the automatic WebAssembly
  ceiling and only `9,708,135` below the hard bound. Authenticated scratch peaks
  at `870,692,320` bytes, reads `134,439,906,080` bytes, and writes
  `15,281,718,752` bytes. Against the exact selected VSS ledger, complete lane
  DFTs and value deliveries fall only about 6.2-fold, all `67,108,864`
  phase-leaf hashes remain, and `43,452,989,440` coefficient folds are added.
  This fails the required order-of-magnitude work reduction, so the candidate
  remains unselected. No production verifier equation, masking theorem, proof
  ledger, native measurement, or WebAssembly measurement consumes it. The
  follow-up persisted-subtree comparator removes the second full leaf pass in
  the static model, but it also fails before measurement. It charges both
  production phase trees, all 387 outer queries in separate worst-case
  checkpoint blocks, a complete streamed checkpoint-plane read and upper-tree
  rebuild, the existing scratch lifetime, and every coefficient fold, coset
  multiplication, bit-reversal visit, leaf hash, salt, and parent hash. Levels
  one through three exceed the `1,073,741,824`-byte scratch bound. Levels four
  and five fit at `1,004,910,048` and `937,801,184` bytes, respectively, but
  their complete butterfly counts are `44,245,976,400` and `45,796,723,360`
  against the selected VSS count of `365,944,635,392`. All levels still perform
  `6,207,569,920` coset multiplications and bit-reversal visits plus
  `43,452,989,440` coefficient folds. The one-pass roots alone consume
  `251,658,240` salted-leaf Keccak-f permutations; complete level-four and
  level-five replay consume `251,751,120` and `251,844,000`, so neither reaches
  a tenfold reduction from the selected complete count of `2,382,364,672`.
  The two streamed root planes are modeled as untrusted public-integrity
  scratch, are fully rehashed to the committed roots, and add no secret-record
  seals. No checkpoint level clears the static measurement-admission gate, so
  none is implemented, benchmarked, or selectable. The next feature-scoped
  comparator reconstructs the compiled base-phase batches by their exact
  opening pattern and coefficient-chunk count before changing the range-check
  arity. The deployed ternary plan has 640 material-range digit columns, 20
  quotient-range digit columns, 753 prover columns, 135 base rows, and 50
  quotient rows. Arity seven is the largest single-polynomial range check below
  the `2,097,152` opening bound: its maximum numerator degree is `1,849,337`,
  and it reduces those counts to 384 material-range digit columns, 20
  quotient-range digit columns, 497 prover columns, 99 base rows, and the
  unchanged 50 quotient rows. The complete 149-row result performs 9,536 lane
  DFTs, `47,496,298,496` butterflies, `4,999,610,368` value deliveries, and
  `436,207,616` salted-leaf Keccak-f permutations while retaining all
  `67,108,864` phase-leaf hashes. That is only about a 7.7-fold transform and
  value-delivery reduction and about a 5.5-fold salted-leaf reduction. Arity
  eight is refused because its numerator degree reaches the opening bound. No
  factor-16 range-arity candidate clears the tenfold static admission gate, so
  none changes the production relation, witness, construction identity, or
  selected profile. An exact maximum-degree grid then evaluates all 18
  degree-valid packing-width pairs. Its factor-one, width-64, arity-113 row
  initially appeared to clear all three static work gates, but that model
  omitted quotient coefficient capacity. The corrected feature-only compiler
  derives a `16,384`-value relation trace, maximum range numerator degree
  `2,082,703`, and `2,066,320` required quotient coefficients. Component count
  111 is insufficient; the exact minimum is 112, with decomposition stride
  `18,451` and capacity `2,066,512`. The checked relation and construction now
  validate with 3,683 prover columns, 59 base rows, 15 quotient rows, and 74
  rows in total. The corrected work ledger gives 4,736 lane DFTs,
  `23,588,765,696` butterflies, `2,483,027,968` delivered values, and
  `268,435,456` salted-leaf Keccak-f permutations: about 15.2-fold, 15.2-fold,
  and 8.5-fold reductions from the selected VSS construction. All `67,108,864`
  leaf hashes and `67,108,860` Merkle-parent hashes remain. The generic
  radix-three feature compiler reproduces the selected relation's canonical
  bytes and hash, while the ordinary production compiler remains unchanged.
  Because the corrected candidate misses the tenfold salted-leaf gate, it is
  unselected and has no candidate witness, production construction identity,
  proof bytes, theorem regeneration, browser result, or selected-suite status.
  The first fused-bound model used radix 42 but omitted the proof that each
  five-digit recomposition stays below the material-digit radix. Its exact
  lexicographic upper-bound constraint has degree `2,322,306`, above the
  `2,097,152` opening bound, so that candidate is rejected. The corrected
  feature-scoped grid checks every five-digit radix from 42 through 65. Radix 51
  is the sole geometry that closes the canonical bound, keeps the quotient in
  one 64-wide group, and clears every conservative count gate. It models reuse
  of the already authenticated material-bound columns, five radix-51 digits for
  each low material digit and its bounded difference, two binary borrows per
  material group, direct finite-set checks for the high material digit and
  signed quotient, and the three shift selectors. The formulas give 2,240
  range-digit columns, 224 borrow columns, 160 quotient columns, three selector
  columns, and 2,627 prover columns in total. A feature-scoped compiler now
  emits and checks that exact relation without changing the production
  radix-three compiler. Its semantic inventory contains the 2,240 range-digit
  columns, 224 bound-low recompositions, 224 finite high digits, 160 direct
  signed quotients, and 227 binary columns, of which three are shift selectors.
  The exact low-digit bound is the largest constraint at degree `1,161,153`;
  62 quotient components are necessary and sufficient at stride `18,466`,
  capacity `1,144,892`, and component degree bound `18,854`. The checked opening
  map puts all 2,624 unrotated columns into exactly 41 width-64 rows and the
  three shifted selectors into one further row. The construction therefore has
  42 base rows, 10 quotient rows, and 52 rows in total, correcting the static
  model that had unnecessarily separated material and quotient columns. Across
  its two passes it performs 3,328 lane DFTs, `16,575,889,408` butterflies,
  `12,213,813,248` coefficient folds, `1,744,830,464` coset multiplications and
  value deliveries, and `201,326,592` salted-leaf Keccak-f permutations. The
  fold count follows from 3,328 DFTs
  over a `4,194,304`-coefficient message in `524,288`-value lanes; the selected
  base phase has no folds. Even when each butterfly, fold, and coset
  multiplication is charged as one counted row-code operation, the candidate
  remains more than tenfold below the selected base-phase total. Its transform,
  delivery, and salted-leaf counts also clear their conservative tenfold
  boundaries; all `67,108,864` leaf hashes and `67,108,860` Merkle-parent hashes
  remain. Radix 50 needs 74 quotient components and radix 66 needs 112, so each
  adds another quotient-row group and misses the salted-leaf boundary. The
  radix-51 result is still only a feature-scoped implementation candidate. Its
  canonical checked compiler, distinct repeatable construction identity, and
  one-to-one 2,627-column witness layout now exist. Focused correspondence
  checks cover every selected source row and direct VSS quotient, every radix
  decomposition and borrow identity, and every compiled constraint at
  boundary-sensitive trace points through the checked interpreter. Complete
  phase liveness, theorem integration, proof bytes, and native and browser
  measurements do not yet exist, so no replay redesign is selected.
  The fastest comparator accepted by the existing one-aggregate construction
  is instead factor 1, width 32. It has 331 rows, 21,184 lane DFTs,
  `105,511,911,424` butterflies, `11,106,516,992` value deliveries, and
  `704,643,072` salted-leaf Keccak-f permutations. Its six aggregate roles fit
  eight columns, and its base commitment algorithm accounts for `289,406,976`
  live bytes before shared runtime, source, encoder, allocator, and bridge
  allocations. The 331-row result is only about a 3.4-fold reduction, so it is
  a valid comparator but not an eligible replay redesign.

    The factor-16 compiler, checked interpreter, witness layout, and restartable
    source provider remain useful lower-bound measurement owners without changing
    the selected factor-four profile. One guarded release-native measurement
    retained 64 exact compiled recipe polynomials at their `264,192`-coefficient
    bound in `1.5941774` seconds, with `135,266,304` bytes of coefficient payload
    and a `167,365,192`-byte measurement-owned peak. A second guarded measurement
    processed nine exact row chunks in `0.7330316` seconds with a
    `198,822,816`-byte measurement-owned peak. Scaling those chunks across 768
    stripes gives about 9.38 minutes of native row assembly, private padding,
    folding, and lane-DFT work for the now-refused comparator. Both guards
    completed without a memory violation; the second guard's
    `5,225,570,304`-byte process-tree peak is cold compilation, not phase memory.
    These measurements exclude complete hashing, salts, authenticated storage,
    codec, allocator, browser-boundary, proof, and lifecycle costs. No comparator
    has a same-build Chromium and Firefox result, proof-size and transcript-parity
    result, production-proof integration, or suite status. Relation, aggregate,
    and replay redesign remains required before another full-width run.

Not yet:

- The exact-ten source and schema conversion now binds the selected foundation
  profile, manifests, actions, suite records, 45 unordered pairs, and ten
  `topCount` evaluator streams while retaining deterministic structural
  compilation throughout `2..20`. The exact complete-action inventory, all 21
  selected production geometry identities, and all 12 mapped-soundness rows are
  current as version-five structural and arithmetic records. Their imported
  QROM closure statuses remain unresolved pending emitted-byte instantiation.
  Remaining construction certificates,
  resource ledgers, evidence vectors, checkpoints, and runtime results that
  inherit the exact-twenty profile must still be regenerated before any suite
  can be frozen.
- The fixed-output sampler's classical distributions, chronology, rejection and
  exhaustion accounting, deployed-call partition, auxiliary-table
  concentration, coherent-access graph, exact predecessor support, and
  extraction mapping derive. The per-proof transform and conservative
  103-proof action union are conditional theorems under the explicit ideal-QRO
  assumption. Their imported closure leaves remain fail-closed until freshly
  transported emitted proof bytes instantiate the certified identities;
  concrete SHAKE256 remains a separate assumption.
- The generic construction certificate does not establish family simulation,
  malicious-verifier zero knowledge, or quantum-random-oracle zero knowledge.
- Exact emitted-byte complete-action soundness is not established. The
  selected same-secret aggregate-leaf
  predecessor correspondence, collision arithmetic, aggregate-wide production
  affine correspondence, pre-aggregate physical masking correspondence, exact
  six-source affine accounting, conditioned affine image inclusion, the
  classical ideal-XOF sequential simulator, pre-opening commitment-root hiding,
  and all production geometry
  certificates now derive. The selected same-secret path now also derives the
  live `8,192`-coordinate, `5,055`-agreement, `393`-query
  event under one atomic plan-bounded verifier message, an executable
  predecessor-state evaluator, and an exact next-message database extractor.
  The reusable atomic predecessor and database-extraction layer is now enforced
  by the production-geometry constructor. The fixed-output inventory, classical
  sampler distributions, bounded rejection and exhaustion, atomic runtime
  chronology, and structural QRO-restriction partition derive. All 21 selected
  production identities and all 12 mapped failure rows are current inputs to the
  graph-wide conditional QROM theorem.
  The exact same-secret codec has a complete static
  section-to-decoder-to-verifier correspondence. The conservative
  103-physical-proof, 159-logical-instance union logic now consumes those
  current rows and derives both the classical union and the conditional
  fixed-budget QROM interval. Instantiation by one emitted and freshly
  transported proof, nonlinear privacy, and adaptive setup-family composition
  remain open.
- The static liveness model has not yet been confirmed by a completed native
  proof or release-WebAssembly browser measurement. Complete participant
  transport accounting is also open. The current exact-ten static owner derives
  all 21 selected variant rows and the 103-proof action arithmetic, but its
  complete proof-corpus total has not been exported and reconciled with carrier
  framing or per-participant traffic. The former `2,024,248,558`-byte
  twenty-option subtotal is superseded and is not a lower bound for the current
  profile.
- No full-width exact proof has completed on the current implementation, and no
  release WebAssembly proof has been generated and freshly verified across the
  desktop browsers. Recent guarded native attempts ended before proof emission,
  so their observed memory is diagnostic rather than completion evidence.
- The last complete routine workspace graph passed at checkpoint `52470766`.
  Its 725.5-second run covered the workspace build, type checking, package
  smoke, lint, unused-
  code analysis, Node tests, Rust formatting and Clippy, process-memory-guard
  self-tests, and all 975 ordinary Rust inventory entries. The
  construction-evidence source-authority, identity-version 11 versus production
  version 12, copied scratch-read total, and recovery-frame width 90 versus
  derived width 98 regressions also pass their focused owners. The `0x1212`
  production certificate passes its isolated owner. The fixed-output sampler's
  inventory, classical distribution, chronology, restriction partition,
  coherent-access graph, exact predecessor support, all 21 selected production
  geometries, all 12 mapped family rows, and the conservative action composer
  pass focused owners. The working tree also
  regenerates the exact-ten collective-setup evidence from a guarded Rust
  production-authority export; its canonical Node checks and independent Rust
  tracked-authority owner pass. There is no complete current-HEAD routine rerun.
  The current worktree passes warnings-denied compile-only checks for the
  ordinary, primitive-measurement, and theorem feature sets. The selected-output
  DFT is feature-scoped to tests and primitive measurements and is not a
  production generation path. A focused aggregate-threshold nonlinear-simulator
  owner eventually passed after an earlier exact failure, while the setup-family
  owner previously failed with incomplete nonlinear commitment privacy. The
  incomplete setup-family composition module has been omitted; no producer-
  populated closure booleans are retained as an adaptive simulation theorem.
  Closely overlapping retries
  additionally produced one run without a summary and one 349-symbol linker
  failure before the final focused pass; they are runner-lifecycle diagnostics,
  not cryptographic or memory evidence.
  In the 2026-08-02 PR run for current head `f8d767b2`, the
  change classifier and fast Rust job passed, but the combined static, Node,
  and browser job failed ten tests because the committed collective-setup
  evidence no longer matches the production-derived `sourceAuthority`. The
  browser matrix was consequently skipped, and the heavy Rust job had not
  completed at the reviewed cutoff. That historical fail-closed evidence-
  integrity failure is repaired in the current source tree;
  it was not a flaky or memory result. An earlier pushed measured-
  heavy job reached its 110-minute job timeout after one of six tests;
  the second active test was the aggregate-wide same-secret round trip, last
  observed while constructing VSS material. Its artifact has no terminal
  summary, peaked at 1,735,847,936 bytes of process-tree RSS under a
  10,737,418,240-byte guard, and records no memory-limit violation. It is an
  interrupted scheduling or termination diagnostic, not an out-of-memory
  result. Long theorem, heavy-kernel, full-width, and manual browser proof lanes
  remain separately guarded.
- No exact `n = 10`, `optionCount = 10` suite is frozen, no complete accepted
  vote runs end to end, and ballot, evaluator, and target-release operations are
  not public APIs.
- No physical-phone profile is qualified. Desktop-browser, Node.js, native, and
  fixture-backed runs are development evidence only.

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
