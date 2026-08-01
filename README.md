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
  `1,232,362` verifier hash queries and `1,229,573` accepting equations. The
  census derives and binds the 512-bit output width for transcript, fixed,
  ordinary-leaf, streamed-leaf, and parent calls. The construction and
  hash-profile identities also bind the 512-bit streamed state and three
  canonical frame tags. The original-BCS whole-state table binds every
  production transcript operation and every response-root equation. The exact
  `2,059` response digests comprise `1,049` complete prover messages, `1,009`
  deterministic schedule or opening-point observations, and one terminal
  canonical proof stream; hostile width, domain, slot, leaf-call, frontier, and
  message-shape mutations refuse. This remains structural evidence, not a
  complete classical or quantum-random-oracle reduction.
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
- Checked construction-geometry certificates derive for all 31 production
  identities: 27 width-64, log-inverse-rate-two (inverse-rate-four)
  identities, including evaluator top counts 1 through 20, and four width-8,
  log-inverse-rate-five (inverse-rate-32) identities.
  Each record binds its relation variant, masking status, WHIR schedule,
  plan-derived prefix and opening counts, typed state chain, deployed leaf
  ledger, and coordinate-derived compact subtree extraction. Families with no
  bound tree or verifier-sequence source do not acquire an invented ledger row.
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
  diagnostic generated the browser-owned setup authority and reached base-tree
  materialization before being stopped after `9,195,256` ms. The selected VSS
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
  production geometry certificates now derive. A complete reduction from these
  component certificates to the ceremony-level failure allocation and to
  soundness of an emitted transported proof remains open.
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
- The current pull-request checks do not pass. Static, Node, and browser work
  reaches unused-export analysis and reports six unused exports and seven
  unused exported types. The fast Rust lane records 19 failures by test 434 of
  962 and then times out; three production-geometry theorem tests alone take
  roughly 85 to 101 minutes in that routine lane. The heavy Rust lane completes
  only one of six tests before its timeout. Focused failures include a stale
  domain-profile refusal, a source-derived stride of `17,152` still compared
  with `17,266`, and reduced fixtures that no longer satisfy the selected mask
  grammar. These are integration defects, not evidence against the selected
  masking arithmetic.
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
excluded from routine commands. The current fast Rust lane still contains
three multi-minute production-geometry theorem tests; restoring that ownership
boundary is open stabilization work. Follow the repository instructions when
changing proof or setup code.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
