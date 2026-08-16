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
  materialization, its first three compact responses, and the complete CFW
  response sequence together. It accepts the
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
  once, and publishes the authenticated response checkpoint. This is the first
  masked-sumcheck batch
  and first code-switch boundary, not a complete WHIR epoch or proof.
  When a later verifier move opens the main response, the response state exposes
  its complete verifier-derived query schedule only during that opening. The
  production owner filters the exact main-source rows and replays each touched
  canonical stripe once from retained source authority and action-private
  encoding randomness. Focused coverage matches nonconsecutive replayed rows to
  the eager canonical WHIR encoder across stripe boundaries and refuses
  duplicate, reordered, out-of-range, premature, and repeated replay requests.
  Guarded native development coverage exercises this selected-size path
  through the first pre-challenge WHIR code switch under the repository
  memory ceiling. Its CFW phase reconciles 4,926 external-storage transactions,
  1,006,632,840 bytes written, 2,013,265,440 bytes read, and 587,202,560 peak
  CFW storage bytes.
  These measurements remain in the owning run diagnostics and do not
  constitute scalar-WASM or browser evidence. The owner does not yet cover a
  selected-size main-source stripe opening replay, authenticated mid-stripe
  restart, cold restoration through the common worker, JavaScript and browser-
  process overlap, the remaining three pre-challenge masked-sumcheck batches
  and two code switches, the base opening, a complete emitted WHIR epoch, or a
  proof. The test-only production-shaped small-chain owner uses the response
  state, but the WHIR family material provider, production worker adapter, WHIR
  proof production, semantic execution, and complete masking path remain
  test-only or incomplete. Before the second response's masking material is
  drawn, release generation now re-decodes its canonical public input through
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
  before any leaf is released. The fixed KMAC256/SHAKE256 joint assumption
  remains external. The subsequent WHIR sequential images, both live role-18
  carried covectors, and the terminal whole-construction simulator are not
  connected yet.
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
- The compact successor still requires every remaining WHIR sequential
  conditional-image check after the first pre-challenge code switch, both live
  role-18 masking authorities, a construction-level statistical-HVZK argument
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
