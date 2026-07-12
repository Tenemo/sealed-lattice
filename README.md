# sealed-lattice

`sealed-lattice` is a browser-oriented TypeScript and Rust/WASM prototype for threshold homomorphic polling. It implements configuration and transcript checks, collective BGV setup records and proof checks, a bounded direct-ballot path, encrypted evaluator replay, and target-bound threshold result release.

The repository is development software. It has not been independently audited, certified, or approved for production elections, and it must not be used with real ballots or secret material. The implementation summary below records what exists now; fixtures, local runs, and component tests do not expand the security boundary in [SECURITY.md](SECURITY.md).

## Current implementation ledger

### Configuration and foundation

The TypeScript protocol layer and published package provide:

- poll validation, canonical poll hashes, threshold derivation, and frozen-roster parameter derivation;
- roster-manifest transcript checks and externally anchored roster acceptance;
- recovery-epoch and deterministic first-valid ordering checks;
- append-only board-consistency checks; and
- cast-receipt and close-record shells.

The Rust/WASM kernel also contains a bounded canonical-tuple codec, Unicode 17 stabilized-NFC ingress, the sole typed SHAKE256 hash framing, participant-identity derivation, and canonical schema codecs for the manifest, action, board, roster, suite record, artifact references, object and signed-carrier envelopes, stream descriptors, proof headers and profiles, mailbox, private randomness, runtime manifests and checkpoints, encrypted local records, and non-forking state intents and certificates. Independent exact vectors cover all 45 recognized foundation schemas in Node.js and browser WebAssembly, including schema identifiers, versions, canonical bytes, typed hashes, identity derivation, Unicode behavior, and refusal codes. Its decoders reject non-canonical framing, invalid assigned values, hostile lengths and counts before nested decoding, excess nesting, non-canonical ML-KEM public keys, and trailing bytes. Suite-record validation checks the intrinsic quorum, ring, basis, key-switch, cap, distribution, and artifact relations, but does not establish deterministic generation and binding of every suite choice. The bounded board-ingestion session ingests one canonical carrier at a time under an external canonical roster, suite and action context, immutable anchors, and explicit resource limits. It derives signature purposes and verifier routes from the decoded object family, selects ML-DSA-65 keys only from that external roster, retains replay and dependency state, and refuses equivocation. Relay metadata, caller-selected verifiers, caller keys, whole-board objects, and caller-constructed accepted candidates do not cross this boundary.

The WebAssembly command boundary rejects duplicate JSON fields at any depth, non-object requests, unsafe integer literals, cycles, accessor properties, custom serialization, non-plain objects, excess nesting, and requests above 64 MiB before command dispatch. Kernel response serialization and bridge reads are bounded at 256 MiB. The generic foundation-schema command validates and byte-identically re-encodes the public canonical object families without exposing clear storage-root recovery material or the internal record-authenticator frame. A deterministic hostile-mutation corpus exercises the schema parser without panics, and the separate `cargo-fuzz` target drives the public kernel command boundary under Address Sanitizer. The [recorded parser campaign](reference-documents/parser-fuzz-evidence.md) completed 289,458 executions without a crash, panic, abort, or sanitizer finding; this bounded campaign is evidence, not an exhaustive parser proof. The Rust canonical stream accumulator accepts bounded fragments and derives the fixed 27 stream domains incrementally. Most setup material crosses the TypeScript/WebAssembly boundary through descriptor-bound asynchronous sources and sinks with cancellation and eviction; evaluation-key aggregate-binding openings still cross as inline hexadecimal and are decoded as a complete request set. Public `verifyPrivateVssShare`, `verifySetupPackage`, and target share-proof generation calls each own a disposable WebAssembly instance, so a failed, consumed, or incompletely exported operation cannot contaminate a later call. Current Rust cleanup guards recover material roots from caller-supplied terminal request sidecars rather than from an opaque session-owned lease. A request that omits a root can leave material staged until the disposable instance is reclaimed, while a direct kernel caller can name a different staged root for eviction. Within one setup call, every referenced proof and material source is staged before one terminal verification, and the Rust consumers still retain a complete proof, decoded public-key corpus, or evaluation-key component when required. The complete accepted setup corpus does not fit the current 384 MiB WebAssembly profile. Chunked bridge transit and per-call isolation therefore do not establish an end-to-end constant-memory or mobile-capable setup verifier; that requires an opaque per-record verification session that owns and completely drains its material leases while it authenticates, verifies, and evicts each scheduled record before requesting the next one.

The foundation remains partial (`SEC-015`). The kernel now has structural proof profiles, commitments, transcript derivation, and adversarial carrier ingestion, but not the common proof prover/verifier or the twelve complete application relations. Suite records are intrinsically validated, but no deterministic generator closes evaluator, basis, proof, artifact, cap, and mobile-working-set choices into one byte-stable candidate. The reusable state verifier and durable compare-and-lock service exist, as do copy-on-write IndexedDB transactions, Web Lock ownership, authenticated checkpoint records, and owned-worker execution; the board session does not yet compose the state-authorization verifier or every relation verifier into its fixed follow-on routes. No separately anchored bootstrap currently verifies the exact application, worker, and WebAssembly assets plus the suite and its six artifacts before issuing an opaque runtime-manifest capability, and no operation-specific checkpoint parser is composed through that preflight. A canonical finality signature is therefore authenticated against the external roster and then fails closed with `missingPrerequisite`; it is not accepted as finality. The former synchronous TypeScript transcript and caller-key finality functions are no longer public package exports. `createFoundationBoardSession` is the public entry point and returns only a typed refusal or an opaque runtime-issued candidate (`SEC-013`).

### Common transparent proof

The implemented common-proof substrate fixes twelve statement families, canonical proof-field and family profiles, deterministic transcript framing, commitment leaves and frontiers, DEEP-point and rejection-sampled query derivation, and attempt and interface-counter state. It validates base-field primality, exact two-adic generator order, challenge-extension irreducibility, folding schedules, proof-tree positions, and canonical openings. These are structural prerequisites only: there is no accepted relation-plan catalog, witness extractor, common prover, or common verifier, and no security level is inferred from them.

The required backend review did not identify a conforming drop-in implementation. [Plonky3](https://github.com/Plonky3/Plonky3) is a configurable polynomial-IOP toolkit and currently warns that its verifier may panic for some invalid proofs. [Lambdaworks](https://github.com/lambdaclass/lambdaworks) provides adaptable FRI/STARK components, fuzz targets, and WebAssembly support, but not the exact common-witness relation, transcript, zero-knowledge simulator, or QROM accounting required here. [Stwo](https://github.com/starkware-libs/stwo) is a production Circle-STARK implementation over M31, CM31, and QM31 with a different domain, field tower, FRI variant, and Fiat-Shamir channel. Importing any of them without first proving the deployed relation and transcript would change the construction rather than complete it. The [reproducible backend assessment](reference-documents/common-proof-backend-assessment.md) records the reviewed source snapshots, acceptance boundary, literature result, and dependency chain.

The research boundary is likewise explicit. The [FRI Fiat-Shamir analysis](https://eprint.iacr.org/2023/1071), [QROM compiler theorem](https://eprint.iacr.org/2019/834), [IOP soundness-notion analysis](https://eprint.iacr.org/2023/1256), and [updated round-by-round FRI proof](https://eprint.iacr.org/2025/1993) provide necessary components. Newer work gives adaptively secure straight-line quantum extraction for hash-based succinct reductions in the [extended BCS transformation](https://eprint.iacr.org/2025/2166), and a [zero-knowledge IOPP for constrained interleaved codes](https://eprint.iacr.org/2026/391) with round-by-round knowledge soundness. [Jindo](https://eprint.iacr.org/2026/044) adds a promising transparent lattice polynomial commitment optimized for client-side proving, but its current [Ringo-SNARK implementation](https://github.com/sp301415/ringo-snark/tree/37c53037d2e3a3466b74733435c3473df605a745) is an under-construction Go and assembly toolkit without this repository's relation catalog, transcript, or mobile-browser WebAssembly path, and it lists a strong Fiat-Shamir transform as unfinished. None supplies the repository's twelve application relations, exact transcript instantiation, or concrete shared-oracle multi-family accounting. The June 2026 revision of the [functional-commitment Fiat-Shamir analysis](https://eprint.iacr.org/2025/902) establishes modular security in the classical random-oracle model only when the deployed oracle proof and commitment already satisfy the required state-restoration properties; it neither proves those properties for this construction nor supplies its QROM argument. [Concrete non-interactive FRI analysis](https://eprint.iacr.org/2024/1161) reports substantial gaps between conjectured and provable parameters in many deployments, while the May 2026 [threshold-halving result](https://eprint.iacr.org/2026/858) gives a new unconditional above-Johnson-bound regime with additional queries. That result covers the proximity-test and DEEP polynomial-commitment layers but explicitly leaves arithmetization and lookup composition to the concrete proof system. The [STARK zero-knowledge note](https://eprint.iacr.org/2024/1037) likewise warns that quotient decomposition and permutation arguments need construction-specific treatment. The [practical Fiat-Shamir attacks](https://eprint.iacr.org/2025/118) further show that a natural proof system can become unsound for implementation-specific circuits under a concrete transform, reinforcing that immutable reviewed relations and transcript code cannot be replaced by a generic heuristic. Consequently, the exact query schedule, QROM work factor, common-witness knowledge argument, and ceremony-wide simulator remain research work rather than implementation constants.

The primitive dependencies are exact-version pinned. The mailbox path pins NIST ACVP ML-KEM-768 key generation and encapsulation/decapsulation cases, NIST ACVP ML-DSA-65 key generation and internal-verification cases, the external ML-DSA context-bearing production path, and the composed HKDF-SHA-384/AES-256-GCM envelope. The [primitive profile review](reference-documents/primitive-profile-review.md) records exact archive checksums, upstream release snapshots, the ACVP internal/external interface distinction, vector coverage, and the update policy. NIST currently lists potential updates for both [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), while revisions of [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) and [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) are in progress. A normative correction that affects the pinned encodings or algorithms must reopen vectors and review; it does not silently change an accepted suite.

### Collective setup, VSS, and evaluation keys

The repository implements the following collective BGV setup path:

- common-randomness commit and reveal records;
- per-coefficient committed-material VSS commitments, private mailbox delivery, local share checks, acceptance records, and complaint records;
- VSS share-linkage and aggregate-threshold proofs, plus a complete-`Q_share` same-secret bridge between the accepted BDLOP constant commitments and public committed material;
- public-key share records, collective public-key construction, evaluator-key schedules, relinearization and Galois-key share records, and trustee evaluation-key proof material;
- descriptor-bound, pull-based binary transport for large public material and most proof bytes, with aggregate-binding openings still carried as inline hexadecimal;
- encrypted local trustee setup state with explicit retained-material and deletion boundaries; and
- setup phase records, transport certificates, package assembly, and Rust/WASM package verification against externally supplied manifest and roster hashes.

VSS commitment records bind collision-resistant committed-material roots. Recipient shares and aggregate threshold shares are tied to those roots by proof relations; the aggregate is not accepted from a producer-supplied sum. The same-secret bridge opens the complete accepted BDLOP constant-commitment set and the public committed-material commitments across the complete `Q_share` basis to one ternary secret. Its setup identity is `setupParametersHash`; the evaluator's final seven-prime target-basis identity remains confined to evaluator output and target decryption. Public-key share proofs bind to that bridge, while evaluation-key atom proofs open the exact canonical limb-zero source constant commitment (`SEC-012`).

The implemented setup proofs remain development evidence. They do not meet the active 80-bit QROM soundness or ceremony-wide zero-knowledge and leakage targets, much less a later 128-bit profile (`SEC-004`, `SEC-005`), and secret-dependent evaluation-key material retains the construction's KDM or circular-security assumption (`SEC-011`). The available perfect honest-verifier zero-knowledge theorem covers one narrowly instantiated neighboring-row AIR and does not establish the repository's permutation, lookup, persistent-state, multi-family, or ceremony-wide composition. Incomplete FRI, QROM, and leakage formulas are not reported as a security level; the remaining claim requires an application-witness extractor, theorem-matched FRI knowledge, exact multi-family compiler accounting, and a ceremony-wide simulator.

### Direct ballots

The Rust kernel contains a bounded direct encrypted-ballot command. The current profile accepts one to twenty ballots, exactly twenty score options, and integer scores from 1 through 10. It structurally validates a caller-supplied passive setup package and its matching private development witness, rejects reused randomness, encrypts each ballot, creates and checks a ballot-relation proof, derives and verifies chunk hashes and a chunk-tree root without retaining a second full proof copy, and aggregates the ciphertexts. It does not authenticate that setup package to the board or an opaque setup-verification capability, and it does not expose a complete public proof-transport workflow.

This path is a kernel development path driven by a private setup witness. It is not exposed as a complete public cast, collection, receipt, and accepted-ballot workflow. The TypeScript plaintext oracle is test support for checking the bounded ranking and sparse-target semantics; it is not a voting or tallying API (`SEC-007`).

### Aggregation and evaluator replay

The kernel implements homomorphic addition of accepted direct-ballot ciphertexts and a deterministic packed BGV top-k evaluator for the bounded score domain. The evaluator performs encrypted comparisons, rank accumulation, and sparse target projection, and emits a target proposal and evaluator-replay record bound to the setup, aggregate, layout, and target context.

The evaluator currently provides component and end-to-end development evidence. It does not by itself accept the target, prove the complete evaluation, or authorize result release. Fixtures and component tests do not establish complete ballot confidentiality or evaluation correctness (`SEC-006`).

### Target finality and decryption

The target-decryption kernel binds a structurally checked caller-supplied setup-package context, a structurally checked caller-supplied target record, a target ciphertext pair, a target basis, and a target share profile. The package and target record are not verifier-issued capabilities, and their internal hash consistency does not authenticate setup acceptance, finality, board inclusion, evaluator replay, or state authorization; those checks remain outside this development path. Its staged result-release path:

1. derives the release context from the setup package;
2. starts a release session for one target binding;
3. checks each distinct trustee's target-bound share proof and accumulates exactly the required quorum; and
4. interpolates only the selected target fields and consumes that target binding in process.

The browser-compatible Rust/WebAssembly kernel can derive share statements and create target-bound shares and proof material from a trustee witness restored from AEAD-encrypted local setup state. Node.js/WebAssembly integration exercises caller-supplied setup-package parsing, encrypted restore, and target-share generation with canonical full-ring setup material and a structurally valid level-zero target ciphertext. This is development evidence, not supported-phone runtime evidence. The published package exposes the staged result check, not a proofless raw-share interface.

The one-shot consumption registry is process-local and is not persistent across restarts. Target release therefore remains development-only and must not be treated as a durable authorization boundary (`SEC-002`). Retry safety for setup, key switching, and decryption under reused secret material is also open (`SEC-003`).

### Package and API surface

The published `sealed-lattice` package is an ESM package that loads the Rust kernel through the bundled WebAssembly bridge. Public consumers must import from the package root; workspace packages, fixtures, or deep source paths are not public API.

The package root currently exports these runtime functions:

- Poll and roster helpers: `validatePollSpec`, `derivePollSpecHash`, `deriveThresholdParameters`, `deriveThresholdParametersHash`, `deriveFrozenRosterParameters`, and `deriveCollectiveBgvSetupRosterHash`.
- Transcript and recovery helpers: `verifyBoardConsistency`, `verifyCastReceiptShell`, `verifyCloseRecordShell`, `deriveValidatedFirstValidOrder`, `verifyRosterExternalAcceptance`, `verifyRosterManifestTranscript`, `isActionCurrentForRecoveryEpoch`, and `verifyRecoveryEpochUpdate`.
- Setup and kernel helpers: `createFoundationBoardSession`, `foundationBoardCandidateObjectHash`, `verifyPrivateVssShare`, `createSetupPackageVerificationInput`, `verifySetupPackage`, `generateTargetDecryptionShareProofMaterial`, and `verifyTargetDecryptionResult`.

TypeScript input, result, protocol-object, setup-transport, and verification types are exported from the same package root. `packages/sdk/api-surface-summary.json` is a generated review aid for intentional public API changes; package policy and packed-package smoke tests cover runtime exports and published behavior.

### Runtime verification paths

| Runtime path             | Evidence that exists now                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Current limit                                                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Native Rust              | Kernel unit and integration tests cover setup commitments and proofs, direct ballots, evaluator operations, target-bound shares, and result release.                                                                                                                                                                                                                                                                                                                                                                                                               | Native execution is development evidence only and is not the participant-facing product runtime.                           |
| Node.js with WebAssembly | Fast and heavy kernel suites exercise the built WebAssembly bridge, setup-package verification cases, direct ballots, evaluator replay, target decryption, and the capability-bound one-carrier board session, including encrypted local-setup restore into target-share generation. Cross-runtime foundation vectors exercise canonical validation, byte-identical re-encoding, typed hashing, participant-identity derivation, and typed board refusals. TypeScript package suites cover foundation, setup construction, transport, and public package behavior. | Node.js evidence does not establish browser or supported-phone execution.                                                  |
| Desktop browser          | Chromium, Firefox, and WebKit suites load both the workspace and packaged WebAssembly kernels, execute all 45 exact canonical-schema vectors, exercise typed hashing, board-session and state-verifier operations, check package exports, and run plaintext-oracle semantics without native helpers.                                                                                                                                                                                                                                                               | The current browser suite does not run the full ceremony or its proof workloads. There is no browser proof benchmark lane. |
| Mobile-emulated browser  | Chromium and WebKit mobile-emulation projects execute the same bounded browser test selection and exact canonical-schema vectors.                                                                                                                                                                                                                                                                                                                                                                                                                                  | Emulation is development coverage only; it does not establish physical-device memory, thermal, or runtime support.         |
| Supported phone          | No physical-device runtime evidence is recorded.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Native, Node.js, desktop-browser, and emulated runs cannot substitute for supported-phone evidence (`SEC-008`).            |

Participant mobile browsers remain the required verification path: acceptance must not depend on a trusted tally server, external prover, dedicated auditor, or native-only verifier. Heavy trustee evaluation-key proving may currently require a participant-owned desktop device, but it is not an accepted native-only end state. Setup verification also remains outside the supported-phone path: its public entry point owns a fresh WebAssembly instance per call, but it stages the complete referenced corpus before terminal verification and the accepted corpus exceeds the current 384 MiB profile. Closing these runtime gaps requires proof-size and runtime work, per-record authenticated verification and eviction, and evidence from the exact supported physical-device and build combination.

## Public security and runtime boundaries

The authoritative wording and correct-use consequences are in [SECURITY.md](SECURITY.md). In summary:

- `SEC-001` and `SEC-009`: this is development software without production approval, independent audit, certification, or production hardening. Use only synthetic data.
- `SEC-002`: target decryption does not yet provide a persistent one-shot release boundary.
- `SEC-003`: repeated participation with reused setup, key-switching, or decryption secret material is not covered by an established retry-safety argument.
- `SEC-004` and `SEC-005`: the implemented setup-proof path has not established the active 80-bit QROM soundness or ceremony-wide zero-knowledge and leakage targets.
- `SEC-006`: homomorphic-encryption evidence covers components, not complete end-to-end ballot confidentiality, evaluator correctness, and target release.
- `SEC-007`: the public encrypted-ballot creation, proof, transport, aggregation, and accepted-result workflow is incomplete.
- `SEC-008`: there is no supported-phone runtime evidence.
- `SEC-010`: accepting a roster size or derived parameter set does not certify a cryptographic or runtime profile.
- `SEC-011`: evaluation-key material depends on the selected construction's KDM or circular-security assumptions.
- `SEC-012`: acceptance requires committed-material roots, the complete-`Q_share` bridge proof, its bound setup parameters, and canonical BDLOP source commitments to carry the complete VSS binding.
- `SEC-013`: finality carrier signatures are bound to the external canonical roster, but the fixed state-authorization follow-on is not yet composed, so finality remains fail-closed.
- `SEC-014`: the Rust/WASM foundation codec pins Unicode 17, but older TypeScript hash paths still depend on ambient Unicode data; callers should independently enforce one canonical representation or keep hash-critical identifiers and labels ASCII.
- `SEC-015`: canonical foundation, signed-carrier, non-forking state, and durable browser-storage acceptance are incomplete.

Do not expose VSS shares, trustee secret shares, encryption randomness, proof witnesses, decryption witnesses, or local secret state. Untrusted transcript and private-mailbox services may relay bytes, but acceptance must come from recomputed canonical encodings, hashes, roots, signatures, proof relations, and externally anchored prerequisites.

## Installation

```bash
npm install sealed-lattice
```

or:

```bash
pnpm add sealed-lattice
```

The package requires Node.js 24.14.1 or later when used in Node.js.

## Usage

```typescript
import { deriveThresholdParameters, validatePollSpec } from "sealed-lattice";

const pollValidation = validatePollSpec({
    pollId: "board-election-2026",
    question: "Which proposal should be adopted?",
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

const thresholdParameters = deriveThresholdParameters({ rosterSize: 10 });

console.log(pollValidation.normalized, thresholdParameters);
```

`pollValidation.normalized` contains the validated poll with defaults applied. Threshold derivation returns structural protocol counts for the fixed roster size; it is not a security certificate.

## Development

The repository uses Node.js 24.14.1 and pnpm 10.33.0.

```bash
pnpm install --frozen-lockfile
pnpm run check
```

Useful full verification commands are:

```bash
pnpm run tsc
pnpm run build
pnpm run test:node
pnpm run test:browser
pnpm run smoke:pack:npm
```

Kernel proof changes also use the separate fast, measured-heavy, and
accepted-setup Rust lanes:

```bash
pnpm run test:rust:kernel
pnpm run test:rust:kernel:heavy
pnpm run test:rust:kernel:accepted-setup
```

The fast Rust runner always excludes the complete
`bgv::setup::tests::accepted_setup` module, including focused filters. Use the
measured-heavy runner for ignored `heavy_rust_kernel_` tests, and the guarded
accepted-setup runner for the accepted-setup module, including its ignored
proof tests.

The measured-heavy Rust, accepted-setup Rust, and heavy Node kernel runners
verify the shared process-memory guard before starting heavy work. It applies
an aggregate Windows Job Object limit or inherited Linux address-space limit.
The ceiling is 32 GiB on large hosts, or the lower of 70 percent of total
memory and currently free memory after reserving 2 GiB on smaller hosts. The
Rust heavy runners also serialize Cargo, libtest, Rayon, trustee-proof, and
limb-proof concurrency; the heavy Node project disables file parallelism.
Every Node command whose selected lanes include `kernel-heavy`, including
`pnpm run test:node:kernel`, is guarded. The ordinary `pnpm run test:node`
aggregate runs the fast, protocol, and kernel-fast lanes only.
Proof-bearing functional and rejection fixtures use the minimum supported
three-participant roster; the ten-participant parameter and phase fixtures
remain lightweight. These tests exercise implementation behavior and do not
certify either roster profile.

After a measured-heavy failure, rerun one test by its full
`heavy_rust_kernel_`-prefixed name:

```bash
pnpm run test:rust:kernel:heavy -- heavy_rust_kernel_sparse_target_projection_decrypts_selected_ids_and_orders
```

The internal `@sealed-lattice/wasm` package's Node scripts delegate to the root
runners so the WASM build and heavy-lane containment remain in force. The
Docker-backed Lattigo arithmetic oracle is an optional development cross-check,
not part of normal verification. Run it explicitly with
`pnpm run test:lattigo-oracle`; its static non-root container has no network,
a read-only filesystem, and a 2 GiB memory-and-swap ceiling.

Generate the public SDK review summary after an intentional API change:

```bash
pnpm run api-surface:generate
```

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE).
