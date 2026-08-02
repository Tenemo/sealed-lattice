# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WebAssembly
prototype for threshold homomorphic polling. It explores how participants can
jointly run a poll, verify its public transcript, and release an agreed result
without revealing individual ballots or trusting a tally server.

The project is for synthetic data only. It has not been independently audited
or approved for production elections. Do not use it with real ballots,
credentials, keys, or secret material. See [SECURITY.md](SECURITY.md) for the
current security issues and required trust boundaries.

## How it works

The protocol is designed around a public transcript and participant-side verification:

1. A poll configuration and externally anchored participant roster define the ceremony and its threshold.
2. Participants contribute verifiable secret-sharing material and collectively derive the public and evaluation keys. No single participant holds the complete decryption key.
3. Voters encrypt bounded ballots and attach validity proofs.
4. Participant clients verify accepted records and homomorphically aggregate the encrypted ballots.
5. A deterministic evaluator computes the requested bounded result over ciphertexts, with a replay record that clients can check.
6. A finality quorum authorizes exactly one target result.
7. After finality, any reconstruction threshold of valid target-bound shares reveals only that approved result.

The roster and candidate-suite schemas cover `3 <= n <= 20`. The sole
implementation and evidence target is currently `n = 10`, with three actively
Byzantine participants, four reconstruction shares, and finality and state
quorums of seven. Other roster sizes remain unsupported.

Every required participant operation is intended to run in the participant's
own mobile browser. Transcript and mailbox services only relay untrusted bytes;
they are not trusted to prove, verify, tally, finalize, or decrypt.

## Prototype status

The kernel targets a fixed homomorphic-encryption candidate for the exact
`n = 10` prototype. The suite remains unavailable until its parameters, proof
construction, and evidence are frozen together.

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
  aggregate-wide mask have production-derived static plans. Static accounting
  places the same-secret proof at `5,814,554` bytes, `571,674` bytes above the
  nominal target and within its automatic variance band. The complete
  evaluator-key proof is `29,105,588` bytes: it requires engineering review
  against the nominal target but remains below the absolute proof bound.
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
  `105,437` verifier hash queries and `105,428` accepting equations. Every
  secret-bearing initial call absorbs a distinct transported 128-byte private
  salt; canonical encoding and decoding reject a reused salt across opening
  batches. The
  census derives and binds the 512-bit output width for fixed transcript
  hashes, ordinary-leaf, streamed-leaf, and parent calls. Logical challenge XOF
  length is accounted separately. The construction and
  hash-profile identities also bind the 512-bit streamed state and three
  canonical frame tags. The production transcript uses one plan-bound
  SHAKE256 XOF invocation for each of its `4,272` logical challenges and
  consumes the complete candidate-slot budget. These invocations have
  plan-fixed but variable output lengths: a 128-draw extension challenge emits
  `8,192` bytes, while a 393-index, 128-draw query vector emits `402,432`
  bytes. Treating either invocation as one fixed 512-bit random-oracle answer
  for the selected QROM transform remains an open theorem-mapping obligation.
  Its exact
  `14,673`-query census contains `6,306` original-BCS rounds. The executable
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
  parent calls, and 90,742 complete Merkle calls. Conditional on an already
  fixed root and a collision-free oracle database, the accepted compact
  frontier yields one verifier-consumed partial tree. Choosing another root is
  a different statement or transcript and is not charged as a collision.
  Hostile width, domain, slot, address, response-owner, root-authority,
  shared-query, leaf-call, frontier, and message-shape mutations refuse. This
  is focused same-secret structural soundness evidence; the variable-output
  XOF mapping, nonlinear privacy, suite-wide reduction, and ceremony-level
  reduction evidence remain open.
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
  correspondence is one input to the construction-wide affine composition
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
  masks, and zero-knowledge claims outside its scope. This establishes the
  selected construction's affine masking correspondence under its uniform-
  source idealization. The separate
  soundness-only fixed-root commitment certificate does not turn this affine
  result into nonlinear privacy, emitted-proof instantiation, complete
  Fiat-Shamir soundness, or ceremony composition.
- The exact same-secret transport correspondence now walks all 22
  construction-plan proof sections through their production decoder and
  semantic-verifier owners. It derives a `5,813,652`-byte family body and the
  `2,942,104`-byte aggregate-wide terminal from the canonical section rules;
  the complete proof remains `5,814,554` bytes after its 902-byte canonical
  header. The catalog binds the statement, protocol, suite, ceremony, action,
  application slot, relation, construction, declared length, and final stream
  digest, and mutation tests refuse omitted or reordered sections, stale
  identities, incomplete binding or refusal catalogs, and altered byte
  ledgers. This is a static parser-to-verifier correspondence. It does not
  establish acceptance of an emitted proof or discharge nonlinear privacy and
  ceremony-level reductions.
- Checked construction-geometry certificates derived for all 31
  production identities: 27 width-64, log-inverse-rate-two
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
  degrees, statement-family multiplicity, and classical and
  quantum-random-oracle loss from the selected plan. All 27 width-64 and all
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
  overhead. It now also accounts for the private-salt key, adapter state, KMAC
  and row-conversion workspaces, `545,664` transported salt bytes, the
  `750,312`-byte proof-wide uniqueness set, and the three materialized direct
  commitments. The phase-commitment row includes its live `84,934,656`-byte
  replay reader and coordinate-bearing Merkle metadata and totals
  `504,267,459` bytes. The exact static maximum remains aggregate-source
  materialization at `556,576,629` bytes: `153,923,445` bytes above the nominal
  target, `47,403,147` bytes below the automatic ceiling, and `114,512,011`
  bytes below the hard WebAssembly bound. This is not a native or browser
  measurement. Bound-tree authentication uses
  one in-place DFT and one evaluated stripe instead of retaining complete
  evaluated columns; its complete static phase row is `289,681,827` bytes.
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
  exact old root and compact frontier. One authenticated pre-base checkpoint remains
  available for current decoder-and-verifier resume validation, but the focused
  guarded VSS prerequisite and any complete proof run have not been resumed.
  The current liveness plan materializes this geometry twice. The two passes
  therefore require `72,192` lane DFTs, `359,569,293,312` butterflies, and
  `37,849,399,296` value deliveries, or about 282 GiB of eight-byte value
  traffic before allocator and replay effects. Each salted 1,128-value phase
  leaf performs exactly 68 Keccak-f permutations, for `1,140,850,688`
  permutations per `2^24`-leaf pass and `2,281,701,376` across both passes,
  before coordinate-salt KMAC derivations and Merkle-parent hashing. No elapsed-
  time projection derived only from the butterfly reduction is runtime
  evidence.

Not yet:

- The generic construction certificate does not establish family simulation,
  malicious-verifier zero knowledge, or quantum-random-oracle zero knowledge.
- Exact complete construction-wide classical and quantum-random-oracle
  soundness is not established. The selected same-secret aggregate-leaf
  predecessor correspondence, collision arithmetic, aggregate-wide production
  affine correspondence, pre-aggregate physical masking correspondence, exact
  six-source affine masking composition, and all production geometry
  certificates now derive. The selected same-secret path now also derives the
  live `8,192`-coordinate, `5,055`-agreement, `393`-query
  event under one atomic plan-bounded verifier message, an executable
  predecessor-state evaluator, and an exact next-message database extractor.
  The reusable atomic predecessor and database-extraction layer is now enforced
  by the production-geometry constructor. At the pushed checkpoint, exact
  family failure ledgers, plan-derived polynomial and point extraction, and
  full-false terminal rejection derived for every production geometry. The VSS geometry
  additionally derives its heterogeneous application-modulus
  product-challenge ledger. All 27 width-64 and four width-8 identities passed
  the complete constructor at the reviewed checkpoint, and the focused
  `0x1212` production certificate now passes independently. The exact
  same-secret codec now has a complete
  static section-to-decoder-to-verifier correspondence, while its instantiation
  by one emitted and freshly transported proof, nonlinear privacy and
  composition across commitments, and ceremony-level failure composition
  remain open. The current certificate enumerates 103 physical proofs and 159
  logical instances, but it does not yet prove that their separately domain-
  separated transcripts form one CMS-eligible concatenated IOP. A conservative
  per-proof transform and explicit union bound remains the default closure path
  unless that global reduction is supplied.
- The static liveness model has not yet been confirmed by a completed native
  proof or release-WebAssembly browser measurement. Complete participant
  transport accounting is also open. Production-derived sizes for 73 of the
  103 physical proof objects already total `2,024,248,558` bytes
  (`1.885228378698` GiB), before the ten public-key-share proofs and twenty
  ballot proofs. That is a partial corpus lower bound, not a completed traffic
  estimate; the two-GiB corpus and network values are soft planning targets.
- No full-width exact proof has completed on the current implementation, and no
  release WebAssembly proof has been generated and freshly verified across the
  desktop browsers. Recent guarded native attempts ended before proof emission,
  so their observed memory is diagnostic rather than completion evidence.
- The routine workspace graph passes after the focused repairs. Its 725.5-second
  run covered the workspace build, type checking, package smoke, lint, unused-
  code analysis, Node tests, Rust formatting and Clippy, process-memory-guard
  self-tests, and all 975 ordinary Rust inventory entries. The stale
  construction-evidence source authority, identity-version 11 versus production
  version 12, copied scratch-read total, and recovery-frame width 90 versus
  derived width 98 regressions also pass their focused owners. The `0x1212`
  production certificate passes its isolated owner. The pushed
  measured-heavy job reached its 110-minute job timeout after one of six tests;
  the second active test was the aggregate-wide same-secret round trip, last
  observed while constructing VSS material. Its artifact has no terminal
  summary, peaked at 1,735,847,936 bytes of process-tree RSS under a
  10,737,418,240-byte guard, and records no memory-limit violation. It is an
  interrupted scheduling or termination diagnostic, not an out-of-memory
  result. Long theorem, heavy-kernel, full-width, and manual browser proof lanes
  remain separately guarded.
- No exact `n = 10` suite is frozen, no complete accepted vote runs end to end,
  and ballot, evaluator, and target-release operations are not public APIs.
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

```typescript
import { createCanonicalManifest, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposals should be adopted?",
    options: Array.from(
        { length: 20 },
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
