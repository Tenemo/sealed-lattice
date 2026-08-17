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
unqualified.

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

- Canonical source compilers and structural validators derive the supported
  schema ranges while the selected source profile binds the exact ten-option
  target.
- The release Rust/WebAssembly kernel supplies canonical foundation decoding,
  bindings, typed wrappers, and package integration. The canonical participant
  build remains scalar-capable.
- The rejected row-code/WHIR proof body remains only as a fail-closed
  implementation and comparison oracle until its replacement accepts the same
  transported production relations and hostile corpus.
- The compact successor has a default-compiled typed contract plus a release
  transport boundary that strictly decodes proof and public-input bytes,
  derives the verifier transcript and response-query schedule, and validates
  every salted Merkle opening. It returns typed refusals and cannot mint a
  proof or workflow capability because CFW and WHIR equations are not yet
  connected to that boundary. The scalar CFW prover/verifier algebra and its
  bounded external-memory transaction driver now compile into the release
  kernel. The authenticated compact assignment loader, bounded lookup-inverse
  materializer, owned structured-row preparation, and structured transpose also
  compile into the scalar release kernel without borrowed worker-lifetime
  state. The incremental proof assembler, prover transcript cursor, bounded
  response-tree writer and scanner, retained-tree coordinator, and authenticated
  response-checkpoint boundary are also release code and own the geometry and
  canonical public-input bytes they retain. A release-owned compact response
  state now drives those components with verifier-selected leaf replay, exact
  transaction yielding, cancellation, authenticated cursor restoration, and
  byte-identical genesis replay. A release-owned public-key family adapter now
  joins the frozen factor-one contract to the retained setup authority, polls
  the exact 202 authenticated source columns, and derives canonical
  public-input bytes from verifier-minted suite, application-statement,
  manifest, and relation bindings before independently decoding them. A
  release-owned public-key generation state now owns that family
  materialization, the complete CFW and pre-challenge WHIR response sequence,
  and all four main-epoch masked-sumcheck batches with their three intervening
  code switches. It accepts the
  lookup challenge only through a borrowed first-message authority minted by
  its retained compact response state for the same proof geometry and
  canonical public input, then owns bounded lookup inversion and structured-row
  preparation. Its guarded selected-size owner derives the first WHIR epoch's
  exact 2,097,152-element source from authenticated quotient-and-multiplicity
  values plus canonical zero padding, draws independent WHIR and response-salt
  seeds from action-private coins, retains WHIR's exact 131,072-row by
  64-element encoding, and streams those values into the contract-derived
  salted response tree. The same release state then samples the production CFW
  masks and the inner, outer, and shared cross-epoch WHIR mask encodings. It
  derives the main epoch's exact logical 131,072-row by 128-element extension
  encoding directly from the production structured-row source. That logical
  matrix is 671,088,640 bytes and is never retained whole: generation
  recomputes eight canonical 16,384-row stripes of 83,886,080 bytes each while
  retaining one 5,242,880-byte encoded column. It streams the complete
  262,144-leaf second response into external storage, derives the second
  verifier message and its 21-coordinate cross-epoch point, and publishes the
  next authenticated response checkpoint. It then commits the four-leaf
  cross-epoch response and executes all 23 rounds of the production
  external-memory CFW prover. Before any round response begins, generation
  checks the real polynomial against the compiler-derived rank-seven
  conditional image; each transcript challenge is bound once before the next
  fold. The final atomic response checks the translated full-rank terminal
  values first, then checks the outer evaluations against the independently
  recomputed verifier hyperplane, while retaining the canonical outer-first
  wire order. Authenticated response checkpoints cover the cross-epoch
  response, every completed CFW round, and the final CFW response. The strict
  version-two 56-byte attempt-and-WHIR-position cursor remains bound into the
  response checkpoints; superseded version-one cursors refuse.
  After the final CFW checkpoint, the same state takes custody of the retained
  first-epoch source, expands the verifier-derived equality covector in bounded
  polls, and positively checks the source claim and masked cross-epoch
  equalities. It samples the selected initial WHIR sumcheck masks from the live
  KMAC stream, commits the canonical mask-oracle, auxiliary, and padding
  response, binds the exact transcript challenge, and emits all six round
  responses. The auxiliary and every round disclosure pass their independently
  compiled conditional-image gates before response construction, and every
  response publishes an authenticated checkpoint before the next fold. The
  guarded selected-size owner completes this batch with 4,108 response leaves,
  12 verifier-selected openings, and a 32,768-element residual source and
  covector. It then folds the original source's 25,344 base-field encoding-
  randomness coordinates at those six challenges into 396 extension-field
  coordinates. The first code switch samples contract-sized next-source and
  switch-mask randomness from the live KMAC stream, streams the exact 8,192-row
  by 16-element source and 4,096-row by one-element mask into a 16,384-leaf
  response, and consumes the verifier's one extension challenge, one base-field
  challenge, and 396 distinct source queries. Before releasing any opening,
  generation routes all 25,344 query-major source coordinates through the
  independently compiled full-rank conditional-image gate. It then supplies
  the 396 original-source leaves, binds the query set and combination challenge
  once, and publishes the authenticated response checkpoint. The owner then
  constructs the exact code-switch output relation in bounded polls from the
  retained next-source values, residual covector and claims, switch-mask
  message, 396 verifier-selected positions, and folded source openings. It
  requires the accumulated source and preceding-mask claims to equal the
  accumulated opening target before starting the next batch. The role-nine
  verifier move is consumed through its exact mixed-output shape: one extension
  challenge, one base-field challenge, and one distinct-query group. The second
  masked sumcheck binds that extension challenge, enforces the independently
  compiled conditional-image gate for its auxiliary and all four round wires,
  publishes an authenticated checkpoint for every response, and finishes with
  4,104 response leaves, eight compiler-required round-wire openings, and a
  2,048-element residual source and covector. The next two code switches derive
  their 432- and 400-position source-query schedules at the exact verifier-
  message boundaries. Each makes one column-major encoding pass over the prior
  source, retains only the selected row cells, checks that query image against
  the independently compiled masking map, folds those values into the next
  relation, and releases the full prior source. Their padded commitments
  contain 8,192 leaves each and correctly emit no openings at these moves
  because no response reaches last use there.
  The following four-round masked-sumcheck batches each commit 4,104 leaves and
  supply eight required round-wire openings; their residual source lengths are
  128 and 8. The same release state then folds the final eight-element source
  and every retained mask-randomness source to the base case, independently
  derives the role-18 carried covector from the canonical public input and
  authenticated transcript prefix, and checks the resulting fresh claim. It
  commits the 32,768-leaf fresh response, consumes the transcript-derived
  combination challenge only after the role-10 blinded reveal passes its
  production conditional-image gate, and commits the 16,384-leaf blinded
  response. At the first-epoch final-query move, response-tree custody supplies
  19,133 authenticated openings. The masking owner attributes only the 6,681
  leaves selected by that move, excludes 830 historical source-query leaves
  already checked at their owning move, and evaluates 399 committed leaves of
  the epoch-neutral shared cross-epoch root without opening that root before
  its second-epoch last use. Its final gate therefore checks exactly 7,080
  compiler-derived query leaves before releasing the final secret state and
  publishing the authenticated response checkpoint. Guarded selected-size
  native execution completes this pre-challenge response path; it is not a
  complete emitted proof or browser evidence.
  The final masking gate mints only an opaque in-memory continuation bound to
  the proof attempt, first-epoch claim coefficients, and exact authenticated
  verifier-message prefix. It is not serialized or caller supplied. The same
  generation state uses that continuation to replay the masking chronology at
  the initial main-epoch boundary, independently derives the complete public
  source covector from the verifier-bound CFW point and matrix-role weights,
  and streams all 4,194,304 authenticated witness elements into the matching
  main relation. It positively checks the resulting relation target, samples
  the initial main masked-sumcheck state from the live KMAC stream, and gates
  its auxiliary target against the independently compiled conditional image.
  The shared epoch state machine then commits the initial mask-oracle,
  auxiliary, and padding response plus all seven round-wire responses. Each
  wire passes its live conditional-image gate before commitment, every response
  publishes an authenticated checkpoint, and response custody supplies the 14
  compiler-required round-wire openings. Guarded selected-size native execution
  reconciles 4,110 committed leaves and finishes with a 32,768-element residual
  source and covector. The first main-epoch code switch then commits its
  16,384-leaf next-source and switch-mask response, derives 396 source positions
  from the authenticated verifier message, and reconstructs the 131,072-row by
  128-lane main source in one column-major pass. It retains exactly those 396
  rows, verifies all 50,688 query-major values against the independently
  compiled masking image and verified first-epoch prefix, binds the folded
  openings into the next relation, and releases the full source encoding
  randomness. The response reaches no last use at that move and emits no
  opening. Its exact 13,132,944-work-unit output relation feeds the next
  four-round masked sumcheck, which commits 4,104 leaves, supplies eight round-
  wire openings, and finishes with a 2,048-element residual source and
  covector. The next two main code switches derive 432- and 400-position query
  schedules from their authenticated verifier messages, retain their selected
  rows in one column-major pass over each preceding source, and verify the
  complete query images under the same first-epoch masking prefix. Their
  8,192-leaf responses emit no premature openings. The exact 1,071,360- and
  211,200-work-unit output relations feed two more four-round batches; each
  commits 4,104 leaves and supplies eight round-wire openings, reducing the
  residual source and covector to 128 and then eight elements. Focused coverage
  matches nonconsecutive replayed rows to the eager
  canonical WHIR encoder, proves that delayed replay reads each source element
  once regardless of query dispersion, and refuses duplicate, reordered, out-
  of-range, premature, and repeated replay requests.
  Guarded native development coverage exercises this selected-size path
  through all four pre-challenge masked-sumcheck batches and all three code
  switches under the repository memory ceiling. Its CFW phase reconciles 4,926
  external-storage transactions, 1,006,632,840 bytes written, 2,013,265,440
  bytes read, and 587,202,560 peak CFW storage bytes.
  In the same guarded native run, all three main code switches and all four
  masked-sumcheck batches complete through the eight-element residual relation.
  Timings and process-memory samples remain in the owning run diagnostics and
  do not constitute scalar-WASM, browser, or phone evidence. The owner does not
  yet cover an
  authenticated interruption inside the column-major replay, cold restoration
  through the common worker, JavaScript and browser-process overlap, the
  main base case, a complete emitted proof, or algebraic verification of that
  proof. The test-
  only production-shaped small-chain owner uses the response state, but the
  main base response execution, terminal semantic composition, and the whole-
  construction masking simulator remain test-only or incomplete.
  Before the second response's masking material is drawn, release generation now re-
  decodes its canonical public input through
  the selected verifier contract, independently derives and checks every
  coefficient-to-view map, and constructs the compiler/verifier-derived public-
  covector authority for those bytes. That release gate also rederives the
  single-proof KMAC census and its three symbolic quantum-PRF replacements from
  the selected contract. Live generation draws coordinate-separated 512-bit
  WHIR and response-salt seeds from the hiding and proof-salt coordinates,
  respectively, expands them under separate KMAC256 customizations, bounds
  every Goldilocks rejection sample to 64 candidates, and refuses an exhausted
  sampler or an unaccounted random-access interface before accepting a sampled
  batch. Before the third response is committed, release generation now replays
  the first two verifier moves, binds the masking attempt to the canonical
  public input, emitted proof prefix, and authenticated transcript cursor after
  those responses, and checks the real three-coordinate cross-epoch disclosure
  against the compiler-derived rank-two image. It also
  checks the CFW auxiliary scalar against its independently derived rank-one
  image, and CFW initialization refuses unless this gate passed. Every live CFW
  round, the initial pre-challenge WHIR auxiliary, and all six initial WHIR
  round disclosures now pass their conditional-image gates. The first source-
  query disclosure also passes its verifier-prefix-derived full-rank image gate
  before any leaf is released. The later two source-query images are evaluated
  at their verifier-message boundaries and retained for last-use opening only
  after the same production masking check; all four pre-challenge auxiliaries
  and every round wire pass their live conditional-image gates. The verified
  first-epoch base prefix also authorizes the exact initial main-epoch replay;
  its sampled auxiliary target and all seven round wires pass their live
  conditional-image gates. All three main code-switch source-query images and
  every auxiliary and round wire in the following three batches pass the same
  sequential live gate under that verified prefix. The fixed KMAC256/SHAKE256
  joint assumption remains external. The live pre-challenge
  role-18 carried covector, role-10 blinded reveal, and role-11 final-query
  images are now connected to canonical generated values and the exact
  authenticated prefix. The main-epoch role-18 authority, the base-case images,
  and the terminal whole-construction simulator are not connected yet.
- The test-only semantic workbench covers the checked 82-move factor-one
  schedule. Its one-shot carried-covector lifecycle is bound to verified public
  input and the exact transcript prefix, and guarded coverage reaches the
  terminal ideal simulator lifecycle.
- The WebAssembly producer and SDK copy have a byte-for-byte reproducibility
  gate. The release path contains the compact transport validator, scalar CFW,
  and owned relation-materialization code, not compact proof generation or
  complete algebraic proof verification.

These items are development evidence only. Test-only, fixture-backed, native,
Node.js, desktop-browser, and emulated results do not establish an accepted
ceremony or supported-phone qualification.

### Remaining completion boundary

- No exact suite is frozen or selectable.
- No production compact prover, complete emitted compact proof, final proof
  `VerificationResult`, or complete compact generation and verification ABI
  exists. The release transport ABI checks canonical structure, transcript
  chronology, query derivation, and Merkle openings only.
- The compact successor still requires the main-epoch WHIR base-case
  conditional-image checks, its live role-18 masking authority, a
  construction-level statistical-HVZK argument
  bound to the complete emitted proof, composition of the live KMAC bridge with
  its explicit quantum-PRF and joint fixed-Keccak assumptions, and the
  applicable SHAKE256 fixed-tape and QROM theorem chain.
- Production setup, ballot-validity, and target-release call sites have not
  been cut over to the compact proof.
- Browser custody does not yet provide complete proactive authenticated
  checkpointing and exact resume for every dominant compact-proof boundary.
- The accepted setup-to-release capability flow is not connected end to end.
- No production compact proof has completed the guarded native and scalar
  release-WebAssembly desktop-browser evidence path.
- No physical-phone profile is qualified. Supported-phone evidence must use the
  same frozen bytes and remains independent from cryptographic completion.
- No connected ten-participant mobile rehearsal exists.

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
