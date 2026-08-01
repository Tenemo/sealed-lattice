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
  places the same-secret proof at `5,309,850` bytes. The complete evaluator-key
  proof is `28,749,492` bytes: it requires engineering review against the
  nominal target but remains below the absolute proof bound.
- Aggregate-wide oracle commitments now use uniform 512-bit leaf transitions
  in aligned `2^20`-row stripes. The selected construction derives a
  `402,653,184`-byte DFT-plus-leaf-state core and preserves the canonical roots
  and proof-size ledger. These are contiguous commitment-row stripes in
  canonical leaf order, with 64-byte chaining values; they are not
  subgroup-coset DFT stripes.
- The selected same-secret verifier census and theorem certificate
  independently derive all 23 Merkle opening classes from the canonical
  construction and supplied-opening plans. Every class uses a
  coordinate-derived compact frontier. The nine column-streamed classes expand
  into their exact initial, ordered-column, and final SHAKE calls, deriving
  `105,437` verifier hash queries and `102,648` accepting equations. The
  census derives and binds the 512-bit output width for transcript, fixed,
  ordinary-leaf, streamed-leaf, and parent calls. The construction and
  hash-profile identities also bind the 512-bit streamed state and three
  canonical frame tags. The production transcript uses one plan-bound,
  fixed-width SHAKE256 XOF invocation for each of its `4,272` logical
  challenges and consumes the complete candidate-slot budget. Its exact
  `14,673`-query census contains `6,306` original-BCS rounds. The executable
  whole-state evaluator and collision-free accepting-database extractor bind
  every plan-derived verifier and response address, recover every exact round
  prefix plus its next verifier message, and connect all `2,059` response
  digests to the complete verifier database and coordinate-derived commitment
  subtrees. Hostile width, domain, slot, address, response-owner, identity,
  leaf-call, frontier, and message-shape mutations refuse. This is focused
  same-secret construction evidence; suite-wide and ceremony-level reduction
  evidence remains open.
- Secret-bearing phase-row padding now uses three KMAC-derived 512-bit seeds.
  The selected same-secret certificate inventories 62 framed SHAKE streams,
  130,023,424 accepted field outputs, seed collision, bounded rejection
  exhaustion, and classical and quantum secret-prefix replacement terms. It
  refuses the former 256-bit seed geometry at the declared quantum query
  budget. This is component evidence under the stated KMAC and ideal-oracle
  assumptions, not a complete zero-knowledge theorem.
- The aggregate-wide masking certificate now has an independent production
  correspondence for all 15 affine-view blocks. It walks the deployed
  transcript and commitment-opening catalogs, binds the six recomputable
  source encoders plus the aggregate pad and two fresh encoders, and checks the
  exact message, randomness, zero-suffix, two-adic evaluation, shared-query,
  code-switch, and lexicographic fold maps. The selected joint view has 18,025
  private extension coordinates, rank 18,013, and residual conditional entropy 12. This is component correspondence; it does not establish construction-wide
  Fiat-Shamir privacy or soundness.
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
- Checked construction-geometry certificates have derived for all 31
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
  four width-8 production identities now pass this stronger constructor and
  full-false terminal rejection. Bound query accounting follows the deployed
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
- Production-derived phase-liveness accounting now covers the complete
  same-secret prover live set, including source ownership, replay readers,
  DFTs, Merkle frontiers, proof material, transcript state, private material,
  browser-bridge copies, a WebAssembly runtime reserve, and allocator overhead.
  Its maximum is `556,008,657` bytes, within the automatic planning band and
  `115,079,983` bytes below the hard WebAssembly bound. Bound-tree
  authentication uses one in-place DFT and one evaluated stripe instead of
  retaining complete evaluated columns.
- The production VSS prerequisite now has a dedicated guarded generation and
  transported-verification test. It durably seals each canonical safe boundary,
  rejects stale or malformed retained state, and resumes by deterministic
  replay through the kernel's authenticated checkpoint decoder. Its latest
  complete same-secret diagnostic ran for `6,037,835` ms and failed while
  preparing the VSS prerequisite with `Generation(Prover(InvalidColumn))`;
  peak process-tree RSS was `3,554,246,656` bytes and the guard did not report a
  memory violation. A later focused VSS diagnostic generated the browser-owned
  setup authority and reached base-tree materialization before being stopped
  after `9,195,256` ms. The selected VSS
  geometry has 1,128 base rows and 16 commitment stripes, while the current
  builder repeats a complete `2^24`-point DFT for every row in every stripe:
  18,048 full transforms before auxiliary or quotient work. Peak process-tree
  RSS was `3,541,450,752` bytes, and the guard confirmed no memory-limit
  violation. The phase commitment also keeps one 200-byte incremental SHAKE
  state for each of the `2^20` encoded columns in a stripe, or `209,715,200`
  bytes before other live data. Its Merkle frontier is already logarithmic;
  changing the tree container alone does not remove either cost. One
  authenticated pre-base checkpoint remains resumable. This runner has not
  completed a production proof.

Not yet:

- The generic construction certificate does not establish family simulation,
  malicious-verifier zero knowledge, or quantum-random-oracle zero knowledge.
- Exact construction-wide classical and quantum-random-oracle soundness is not
  established. The selected same-secret aggregate-leaf predecessor
  correspondence, collision arithmetic, aggregate-wide production affine
  correspondence, pre-aggregate physical masking correspondence, and all
  production geometry certificates now derive. The selected same-secret path
  now also derives the live `8,192`-coordinate, `5,055`-agreement, `393`-query
  event under one atomic fixed-width verifier message, an executable
  predecessor-state evaluator, and an exact next-message database extractor.
  The reusable atomic predecessor and database-extraction layer is now enforced
  by the production-geometry constructor. Exact family failure ledgers,
  plan-derived polynomial and point extraction, and full-false terminal
  rejection now derive for every production geometry. The VSS geometry
  additionally derives its heterogeneous application-modulus
  product-challenge ledger. All 27 width-64 and four width-8 identities pass
  the complete constructor. The final theorem-to-transported-bytes
  correspondence and ceremony-level failure composition remain open.
- The static liveness model has not yet been confirmed by a completed native
  proof or release-WebAssembly browser measurement. Complete participant
  transport accounting is also open. Production-derived sizes for 73 of the
  103 physical proof objects already total `1,988,841,710` bytes
  (`1.852253181860` GiB), before the ten public-key-share proofs and twenty
  ballot proofs. That is a partial corpus lower bound, not a completed traffic
  estimate; the two-GiB corpus and network values are soft planning targets.
- No full-width exact proof has completed on the current implementation, and no
  release WebAssembly proof has been generated and freshly verified across the
  desktop browsers. Recent guarded native attempts ended before proof emission,
  so their observed memory is diagnostic rather than completion evidence.
- The routine workspace graph currently passes build, type checking, lint,
  unused-code analysis, package smoke, Node tests, and all 952 ordinary Rust
  inventory entries. Long theorem, heavy-kernel, full-width, and manual browser
  proof lanes remain separately guarded and are not implied by that routine
  result.
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
