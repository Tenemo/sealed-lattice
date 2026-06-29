# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. Every roster participant is intended to act as both voter and trustee. Untrusted services may store and distribute transcript objects, but the verification path is participant mobile browsers, not servers or dedicated heavy verifier machines.

The published npm package is intentionally narrow while the protocol implementation is still being built and checked. Use it for development verification, package integration, transcript helpers, and foundation checks. It is not a complete voting library and must not be used for real ballots or ballot secrecy. The canonical public security posture lives in [SECURITY.md](SECURITY.md).

## Selected direction

The selected construction is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> ballot validity proofs for the fixed encrypted-ballot relation
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first target profile is planned around `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. Current security limitations, profile caveats, HE evidence, and target-decryption boundaries are not repeated here; see [SECURITY.md](SECURITY.md).

## Current package boundary

The public package currently exposes development verification helpers while the full voting API is being built and checked. These cover poll validation, threshold derivation, lifecycle and capability checks, foundation transcript checks, and narrow setup-development verification helpers. Reserved complete-protocol entry points fail closed until the matching implementation and verification work is complete.

Current package tests are development evidence only. They do not replace supported mobile runtime evidence, production hardening, or the complete protocol security boundary in [SECURITY.md](SECURITY.md).

## VSS compaction status

The accepted setup profile now exposes a static baseline report for the current full public coefficient-commitment material without binding compact VSS budget or measurement records into the accepted setup artifact. The current first-profile binary VSS transport is `1,604,341,697` bytes, with `1,604,321,280` bytes coming from coefficient payloads. The same report records the current Shamir scalar amplification as `1111` for one source at the largest trustee point and `11110` after aggregating ten source trustees for one recipient.

The development compact path now has a sparse seeded linear commitment prototype, canonical 384-byte compact commitment body encode/decode helpers, native/WASM compact commitment, coefficient-set, recipient-share set, aggregate-threshold set, share-linkage statement, share-linkage proof material-set, same-secret bridge statement-set and proof material-set command parity, lower-level compact share-linkage proof generation and verification command parity for the ternary-opening slice against the TypeScript implementation with command-side recomputation of each supplied compact commitment root and statement metadata, and compact share-linkage proof material records that bind each source statement root to proof-record lists whose entries bind proof bytes, proof byte hashes, proof-record roots, linkage coverage coordinates used for verifier-side reconstruction, and the material roots, compact public coefficient commitment sets with verified source and set roots, fresh public recipient-share commitments, aggregate threshold commitments, private opening credentials for recipients, encrypted private-mailbox delivery of source-recipient compact opening credentials without duplicating delivered share values inside the credential object and with private-envelope compact opening randomness packed as ternary hex, compact public records that no longer carry separate vector hashes for compact opening messages or opening randomness and now bind load-bearing coefficient, share, aggregate, and aggregate-source opening-root handles, a public linkage statement root bound to the verified compact coefficient, recipient-share, and aggregate roots, optional verifier-side compact commitment-set cross-checks for those linkage roots, accepted-package compact VSS public material refusal when compact coefficient, recipient-share, aggregate, share-linkage, or proof-material fields are present because the current sparse linear commitment has no certificate-grade binding argument for full-width coefficient vectors, source-batched linkage statement records that bind each source trustee to the Shamir-evaluation, aggregate-sum, common-key, and recipient-approval-boundary obligations, compact same-secret bridge statement sets that bind target-basis compact constant roots to data-basis same-secret statement and proof roots plus the canonical target-basis hash, integer-support, signed-representative, compact-encoding, and target-limb-order obligations, compact same-secret bridge proof material records that bind each bridge statement root to proof bytes, proof byte hashes, proof-record roots, and the material-set root while the verifier reconstructs the lower-level proof statement from the bound statement record and target commitment bodies, optional verifier-side same-secret evidence-set cross-checks for those bridge roots, accepted-package refusal when `compactSameSecretBridgeStatementSet` or `compactSameSecretBridgeProofMaterialSet` is present because the bridge also uses the current non-binding compact commitment, native/WASM reduced-ring compact same-secret bridge proof command parity that proves target-basis compact coefficient commitments open to the same signed ternary secret, local-state sealing plus restore-time validation for aggregate compact opening credentials after share parity, carry-relation checks, opening checks, aggregate opening-root checks against accepted aggregate commitment records, and optional linkage evidence checks, explicit target-time preparation of the restored local witness with a target-bound smudging witness derived from local smudging seed material plus accepted target, target-decryption ciphertext, and profile bindings, and a development-only restored-local-witness target share generator path that consumes the prepared restored compact aggregate opening material whose public matrix seed hash matches setup common randomness. The seed-only target-share command is not exposed through the Rust/WASM command APIs. Native/WASM command parity covers restored-local-witness target-decryption share generation, proof-statement derivation, public statement-binding, private proof-material generation and JSON verification, and private binary proof-material verification command dispatch for the compact local-witness path. Released target shares now add deterministic plaintext-multiple Shamir zero-share masks for each target role and active RNS limb and include a hash-bound smudging input report with numeric bounds, not public hashes of the smudging vectors. The target-decryption local-witness path recomputes restored compact aggregate openings and matches their commitment roots and opening roots to accepted aggregate commitment records; proof-statement derivation also expands the target-bound smudging seed into signed polynomial openings, uses those openings for the released-share smudging relation, regenerates the expected target share from the restored local witness, and rejects canonically rebound share payload, share root, target-share hash, smudging-report, smudging-opening-seed, or active aggregate opening-root mismatches. The target-decryption statement-binding check keeps operative statement inputs only, including target and participant bindings, the target share hash, the smudging report hash, the active credential binding root, setup common randomness, the accepted share-linkage statement root, accepted aggregate commitment records, active accepted aggregate opening roots, and the active accepted compact aggregate commitment bodies needed by a future proof verifier. The same proof statement also binds a target-specific compact smudging commitment set for every target role, active RNS limb, and nonconstant zero-share polynomial coefficient; statement derivation builds those commitments from the same signed polynomial openings plus seed-derived commitment randomness, and statement validation recomputes the set root and checks compact commitment shape, role, matrix seed, canonical target-basis hash, limb, prime, and coordinate bounds. The Rust proof backend now has an internal reduced-ring target-decryption share proof family that can prove all active target RNS limbs in one statement while sharing each active compact aggregate opening across both target roles and still binding each role's ciphertext component, released partial, and smudging commitments. The obsolete single-role proof-slice command is removed, and the target-decryption proof-material command emits one all-active-limb proof record for one real target share. The proof-material verifier checks material roots that bind the canonical base64 proof bytes directly, target-share binding roots, verifier-reconstructed lower-level proof statements and role/limb coordinates, proof byte verification, canonical target-role coverage, and full active-limb coverage. The target-result verifier returns `ok: false` with `refusalReason: "CompactVssPublicMaterialNotBinding"` until compact VSS public material is replaced with a certificate-grade binding construction. This remains development evidence. The published SDK keeps only the fail-closed `verifyTargetDecryptionResult` wrapper, and no raw-share, target proof-generation, or target-result release API is exposed. The private protocol package root no longer re-exports compact VSS commitment/proof development helpers, compact same-secret bridge helpers, or compact target proof witness types; focused tests and measurement tooling import those helpers by private source paths, and the package policy checks that they do not reappear as root exports. The statement-binding command returns `ok: false` with `refusalReason: "TargetDecryptionProofUnavailable"` because it does not verify target-decryption proof bytes or accept a share. The compact parameter-certificate input binding records the current commitment relation, common-key derivation domains and preimage fields, exact message encoding, numeric norm input classes, versioned parameter-review input rows, estimator row dimensions, same-secret bridge target-basis inputs, and the same-secret proof-family root. The compact matrix expansion profile now has a hash-bound common-key rule for matrix residues and projection indices, including the seed, input-column, coordinate, limb, and rejection-sampling boundaries. The manual compact VSS measurement accounting records `384` bytes per compact commitment and `556,800` public compact commitment bytes for coefficient commitments, recipient-share commitments, and aggregate threshold commitments combined. That measurement is compact public commitment-body accounting only; compact transport framing, full compact linkage proof bytes beyond the restricted lower-level command path, same-secret bridge proof bytes, private mailbox bytes, encrypted persistent local-state witness bytes, target-decryption proof-material bytes and production smudging proof bytes are reported separately or remain outside the public-body ratio. The compact public commitment bodies are about `0.83%` of the `64 MiB` public setup download budget; one source trustee's public compact commitment upload body is `52,992` bytes before linkage proofs, about `0.02%` of the `256 MiB` source upload budget. Against the current full VSS transport, the public commitment material is reduced by `1,603,784,897` bytes, about a `2,881.36x` reduction, leaving the compact public commitment bodies at about `0.035%` of the current full transport. The static work model is `8,908,800` commitment residue multiply-adds plus `33,600` aggregate public-sum residue additions, for `8,942,400` modeled residue arithmetic operations; the public-sum check adds about `0.38%` over the commitment multiply-add model.

The public target-result verifier is refusal-only while the kernel target-result verifier cannot produce an accepted result. The public wrapper takes no share, proof-material, ciphertext, or target-setup input until a real result verifier exists.

The public SDK setup verifier streams transported setup proof chunks into the packaged kernel and passes only fresh same-call proof handles returned by the kernel stream finalizer to kernel setup verification. Caller-supplied setup proof handle objects are ignored and are not part of the exported SDK API.

The internal target-decryption proof-material path accepts compact aggregate commitment openings whose message coefficients are lifted above the selected target modulus under an explicit aggregate message bound, while reducing those coefficients modulo the target prime for the released-partial equation. The target proof's masked consistency window and disclosed proof accounting now use that lifted aggregate message bound rather than the target prime alone. This keeps the compact commitment opening relation and the target decryption equation aligned for the all-active-limb proof-material package. The obsolete single-role proof-slice and private recombination commands have been removed because the current target-result path is fail-closed on compact VSS public material.

The proof-material command retains the already validated compact aggregate opening messages and randomness, emits one all-active-limb proof record per share without transporting lower-level proof-slice statements, reconstructs that public statement from the high-level target proof statement, target share, setup and ciphertext context during verification, checks the target proof accounting hash, and verifies every active limb with both canonical target roles bound inside that proof. The target proof accounting currently records a `74`-bit clear masked-claim bound for lifted aggregate messages, a `142`-digit base-3 aggregate-message mask, about `2^-151` per-aggregate-message-claim leakage, a `114`-digit base-3 smudging-message and target opening-randomness mask, `21,980` masked claims per target share, and about `2^-133` over the first-profile seven-share interpolation view. Target statements now require enough active proof fields for the widened CRT lift before proving; each aggregate-message consistency claim is carried by five proof fields using the setup commitment fields, the target's own active field when needed, and the earliest remaining active fields needed for the lift window, while smudging-message and ternary opening-randomness consistency claims use four proof fields and the shorter mask. Commitment fields still carry every compact-opening relation, and later target fields carry only the target-limb message rows needed for their released-share equation when extra lifted columns are not needed. This is still development evidence, not a target-ready zero-knowledge claim, because the proof profile, proof-material size/runtime, production smudging evidence, and supported-phone measurements remain unfinished. The kernel target-result verifier currently refuses with `CompactVssPublicMaterialNotBinding`, and the published SDK exposes only the no-argument fail-closed verifier wrapper `verifyTargetDecryptionResult`.

Published `sealed-lattice` package builds retain only the fail-closed target-result verifier behind `verifyTargetDecryptionResult`, and the public target-result verification type no longer carries an accepted-result branch while the kernel cannot produce one. They do not expose a public target-result input type or share-evidence type. They strip target-decryption development bridge members for the development fixture command, restored-local-witness share generation, proof-statement derivation, proof-material generation, standalone JSON and binary proof-material verification, and statement-binding helper from the vendored internal WASM loader, and the public SDK WASM artifact is compiled without those development command variants. Those private commands remain only in the unpublished workspace WASM package for tests and measurement.

The accepted setup handoff no longer carries a future target-decryption placeholder. Target-decryption profile identity remains in the verified profile and certificate records, while proof-backed target result release stays outside the accepted setup handoff until the final target proof profile is ready.

Public lifecycle capability checks now take direct proof transport, mobile replay evidence, evaluator replay, target finality, accepted-target, target-decryption profile-reference, certificate, proof-profile, and share-evidence hashes or roots instead of proof/evidence presence booleans. Runtime profile evidence is documented and measured separately; it is not a producer-set protocol capability flag.

Separate public hashes of compact opening messages and opening randomness remain removed. Compact coefficient records now bind `coefficientOpeningRoot`, recipient-share records bind `shareOpeningRoot`, aggregate records bind `aggregateOpeningRoot` and `sourceShareOpeningRoots`, share-linkage source statements bind ordered coefficient and recipient-share opening-root lists, compact share-linkage proof statements bind the matching opening roots for their restricted recipient and target-limb slice, and target-decryption proof statements bind the active accepted aggregate opening roots. Those roots are recomputed from private opening material during credential and local-witness verification; they are handles for cross-record consistency, not a certificate-grade binding argument for the current sparse compact commitment.

The passive setup parameter certificate and target-threshold decryptability certificate now bind the canonical target basis, target level, target prime count, target modulus bit count, and target modulus product. The verifier recomputes those values from the evaluator target-basis definition rather than accepting a placeholder `qTargetBits` field.

The manual compact VSS measurement report separates implemented development artifact bytes: full-profile compact public commitment bodies remain `556,800` bytes versus `1,604,341,697` bytes of current full coefficient transport, a `2,881.360806393678x` public-body reduction. The static compact commitment work model remains `8,908,800` commitment residue multiply-adds plus `33,600` aggregate public-sum residue additions, for `8,942,400` modeled residue arithmetic operations. The latest default runner measured the cached WASM compact commitment path at `8.15 s` warm generation and `7.60 s` warm verification extrapolated across `1,450` first-profile compact commitments, below the `30 s` development guards. The current default report verifies the compact share-linkage public statement and roots without transporting share-linkage proof bytes (`0` proof bytes in that section), and separately reports the reduced-ring same-secret bridge proof sample at `4,534,573` proof bytes and `6,049,367` proof-material JSON bytes. A full source-batch share-linkage proof-material measurement is not currently emitted by the runner; that remains unclosed evidence and must be measured again before compact VSS setup proof material can be treated as fitting the setup transport budgets. Compact share-linkage proof-material transport and binary verifier paths remain development evidence because accepted setup still refuses compact VSS public material until the compact commitment construction has certificate-grade binding evidence.

The same report now measures implemented private-state development artifact JSON separately. One source-recipient private mailbox delivery set is `12,523,228` bytes, with `9,369,186` bytes of private envelope JSON, `12,499,837` bytes of encrypted-envelope JSON, `12,521,460` bytes for the envelope reference object, and `16,599` bytes of transported private-share proof-material framing around a `32` byte per-limb proof sample. The raw in-memory compact recipient-share opening credential bundle used to derive aggregate openings is `10,201,060` bytes; it is not the packed private-envelope transport shape. Extrapolated across ten recipients for one source trustee, the private mailbox envelope references are `125,214,600` bytes, leaving a `143,220,856` byte margin under the current `256 MiB` source upload budget before target-ready private-share proof bytes. Extrapolated across all `100` source-recipient pairs, the same JSON envelope-reference shape is `1,252,146,000` bytes of pairwise private transport. One one-source encrypted local-state sample has a `6,689,370` byte aggregate-threshold-share plaintext, a `4,594,937` byte target-proof-witness plaintext, `8,922,484` bytes of sealed aggregate-share JSON, `6,129,922` bytes of sealed target-witness JSON, a `1,881` byte encrypted local-state storage manifest plaintext, and a `10,897` byte encrypted local-state JSON object. The outer local-state ciphertext encrypts only the compact manifest of sealed-material references, while the sealed material envelopes are detached from that object, transport ciphertext bytes as canonical base64, and are still validated against the local-state commitment, material roots, ciphertext references, sealed-material envelope hashes, ciphertext hashes, and storage associated data at restore time. The largest measured private-state JSON object is now the `12,523,228` byte private mailbox delivery set. These private-state samples are development accounting; they are not target-ready proof-byte accounting or final mobile storage evidence.

The same report measures implemented target-decryption development artifact JSON separately: one prepared local target-proof witness is `4,595,767` bytes, its compact aggregate opening witness is `4,592,658` bytes, its seven compact aggregate opening credentials are `4,591,854` bytes combined, and its target-time smudging witness is `1,489` bytes. One generated development target share is `7,350,564` bytes, its target-share payload is `7,346,703` bytes, its smudging input report is `3,119` bytes, the target-decryption proof statement is `48,172` bytes after adding the target-bound smudging commitment set, setup-epoch binding, and active aggregate opening-root binding, and the non-accepting statement-binding verification output is `129` bytes. The default compact measurement report skips the heavy target-decryption proof-material accounting; setting `SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL=1` runs it explicitly. The latest heavy proof-material run measured two proof-backed target shares with `4,670,157` and `4,659,573` byte proof-material JSON objects, `9,329,730` proof-material JSON bytes combined, `6,996,796` raw proof bytes combined, one all-active-limb proof record per share, `440` JSON proof-material verification response bytes combined, `1,510` binary proof-material verification response bytes combined, `114.71 s` proof-material generation, `16.20 s` JSON proof-material verification, and `16.76 s` binary proof-material verification on the local host. The same run encoded those proof materials as binary frames of `3,502,499` and `3,494,563` bytes, `6,997,062` bytes combined across eight proof chunks, saving `2,332,668` bytes versus JSON while adding only `266` bytes over the raw proof payload. Current measurement output no longer reports recombination because target-result verification fails closed until compact VSS public material has certificate-grade binding evidence. The proof-byte attribution diagnostic parses the transported proof bytes and accounts for the combined raw payload as `3,199,040` Merkle-hash bytes, `3,655,932` packed field-residue bytes, `139,776` leaf-salt bytes, and `2,048` format and length-prefix bytes; the largest sections are low-degree query paths (`2,239,296` bytes), phase-one rows (`2,067,936` bytes), low-degree final coefficients (`673,792` bytes), phase-one paths (`477,856` bytes), phase-two paths (`477,856` bytes), phase-two rows (`410,592` bytes), and low-degree query siblings (`359,268` bytes). The latest shape keeps the prior proof-material size reductions from skipping inactive target-limb gap proofs, bit-packing proof-format field residues at the derived 47-bit width, transporting packaged target proof bytes as base64, reconstructing lower-level proof statements instead of carrying them in each proof-material object, verifying decoded proof bytes through an internal byte-slice verifier rather than re-hex-encoding them, batching both target roles and all active target limbs into one proof statement, binding the main and residual low-degree commitments before sampling one shared query set, committing each queried phase row pair as one salted Merkle leaf, reusing the main phase-two row openings for the residual low-degree proof, deriving proof-material target-role and active-limb coverage during verification, binding canonical base64 proof bytes directly through the proof-material root instead of carrying duplicate proof-byte and proof-statement hash fields, keeping proof-material verification responses to the recomputed proof-material root, measuring and verifying a binary target proof-material frame with the same setup proof-material chunk hashers, lowering the fixed low-degree query count to `156` while retaining `129` conjectured classical soundness bits after the instance union under the current CS25 accounting, deriving the low-degree final coefficient layer from the statement degree bound with a `32` coefficient floor and `1024` coefficient cap through the shared cyclic inverse transform path, transmitting only the folded-layer sibling value because the verifier derives the selected slot from the previous fold before authenticating the reconstructed pair leaf, deriving the proof-accounting digest row from the implemented 32-byte internal Merkle commitment width, and encoding low-degree folded-layer siblings as adaptive raw or unique tables with bit-packed references only when that is smaller than query-order transport. It preserves the widened aggregate-message privacy margin while carrying aggregate-message consistency claims through five proof fields and smudging-message plus ternary opening-randomness consistency claims through four proof fields with shorter masks, instead of carrying every target compact-opening message and randomness column through every active target proof field. Compared with the immediately preceding JSON target proof-material transport shape, the binary frame removes `2,332,668` proof-material transport bytes without changing raw proof bytes; the private binary verifier added `0.56 s` over the JSON verifier for the two-share run and stayed under the same `30 s` verification budget. Compared with the earlier `2048` cap pair-leaf phase-tree run, the `1024` cap removes `263,452` proof-material JSON bytes and `197,590` raw proof bytes without a severe local CPU regression. Production smudging proof material remains unmeasured. The proof-material sizes and times are development evidence and are not included in the public commitment-body ratio.

The setup commitment security certificate now also carries the compact parameter-certificate input binding and its hash. Accepted setup recomputes the compact relation, sparse projection shape, norm inputs, versioned parameter-review input rows, estimator-input rows, target-basis inputs, and same-secret proof-family root for the roster before accepting that certificate. The bound review inputs include opening witness ranges for fresh and aggregate compact openings, Shamir and aggregate-sum scalar amplification rows, target-basis reduction inputs for the same-secret bridge, and Module-SIS/Module-LWE review row references. The source-derived parameter review now blocks production use of the current 16-coordinate sparse linear profile and runs as part of the standard check lane: each current commitment samples at most `1,536` of `32,768` message coefficients per message column, so at least `31,232` message coefficients are outside all message-coordinate projections regardless of seed; unrestricted full-vector messages also have a fixed-randomness counting gap of about `1,537,840` bits against the compact image, and the full-message short-SIS row exceeds the estimator precondition before lattice-reduction cost is considered. The counting-safe linear lower bound would be at least `380,120,400` public commitment-body bytes, about `4.22x` compaction and above the `64 MiB` setup download budget. Accepted setup therefore refuses optional compact VSS public material with `compactVssPublicMaterialNotBinding` when those package fields are present. This is input binding plus negative review evidence, not certificate-grade compact commitment evidence; the compact commitment construction, unfinished estimator reviews, proof backends, structured-ring analysis, supported-phone measurements, and target-ready activation remain disclosed here as prose rather than bound artifact fields.

The accepted setup public-key and evaluation-key records no longer carry fixed narration fields for aggregation state, assembly state, material source, proof-byte availability, proof-binding requirement, or absent raw-key material. Their roots now bind the operative setup context, profile identifiers, material encodings, proof-family identifiers, schedules, share roots, proof roots, material roots, and recomputed transport hashes. Setup proof-generation command inputs no longer accept proof-randomness source labels, and command responses no longer return source, retention, binding, nonce-hash, or seed-byte accounting metadata; the generation commands still bind the supplied seed and nonce into the statement-specific proof randomness before proof masking.

Setup VSS material, threshold-share commitment derivation outputs, private VSS local verification records, and the static public VSS material size report no longer carry descriptive ring-degree labels. They keep numeric ring-degree fields where those values are part of the recomputed statement, root, material, or profile shape.

Passive setup profile, evaluation-key, and setup key-correctness certificate records no longer carry recipient-witness disclosure labels, finalization labels, generated-for labels, regeneration booleans, or prose theorem/scope labels that only restated policy. Compact share-linkage profile records, evaluator schedules, evaluation-key streams, passive verification records, local deletion receipts, development fixtures, setup profiles, VSS complaint evidence, and setup commitment security certificates likewise no longer carry fixed policy narration fields, enumerated outcome lists, or non-gating assumption booleans. The remaining records bind operative relation definitions, dependency lists, roots, schedules, proof-family roots, transport fields, proof byte roots, and hashes.

The manual `pnpm run measure:compact-vss` CPU sanity runner replays one deterministic full-ring compact commitment through the TypeScript and Rust/WASM paths and prints the static byte accounting beside local wall-clock samples. It now fails if compact public commitment bodies miss the `2,800x` reduction floor, exceed the `64 MiB` public setup download budget, exceed compact public largest-object and WASM-copy budgets, exceed the measured target-decryption development artifact budget, exceed a `256 MiB` one-source private mailbox upload budget, exceed a `128 MiB` one-recipient private mailbox download budget, exceed a `16 MiB` one-recipient persistent local-state material budget, exceed a `10 s` private-state construction sample budget, exceed an `8 MiB` reduced-ring compact same-secret bridge proof payload budget, exceed a `16 MiB` compact bridge proof-material JSON budget, or if WASM warm full-profile generation or verification extrapolates above `30 s` on the local measurement host. When `SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL=1` is set, it also fails if the heavy target proof-material run exceeds `16 MiB` of proof-material JSON, `8 MiB` of binary proof-material frame bytes, `12 MiB` of raw proof bytes, `180 s` generation, or `30 s` verification. The latest isolated local run measured `275.8 ms` for cold TypeScript seeded projection expansion plus commitment, then `21.62 ms` warm median commitment generation and `18.38 ms` warm median opening verification. Linear warm extrapolation across the `1,450` first-profile commitments is about `31.35 s` for commitment generation and `26.64 s` for opening verification in the TypeScript development path. The matching Rust/WASM command measured `65.85 ms` cold, `5.62 ms` warm median commitment generation, and `5.24 ms` warm median opening verification for full-ring compact commitment recomputation on the same host, with an `8.15 s` linear warm generation extrapolation and `7.60 s` linear warm verification extrapolation across `1,450` commitments, so the compact primitive and canonical body format remain comfortably within the local `30 s` WASM CPU guard. The same runner also records private-state TypeScript JSON construction samples; the latest mailbox sample is `2.36 s` for one full-ring source-recipient private mailbox delivery, and the one-source encrypted local-state sample builds in `6.76 s`. The same runner records the reduced-ring restricted compact same-secret bridge proof command: at ring degree `128` with seven target RNS limbs it emits a `4,534,573` byte proof, with `461.97 ms` warm median generation and `790.75 ms` warm median verification. These proof measurements are restricted native/WASM command evidence only; they are not target-ready compact proof evidence and are not included in the static compact public commitment-body total.

Same-secret bridge evidence verification rejects embedded same-secret proof records whose `proofSizeBytes` or `proofBytesHash` do not match `proofBytesHex`, transported same-secret proof records whose proof-material root, full-object hash, chunk root, chunk hashes, size, or proof-byte hash do not match the supplied canonical base64 chunks, compact bridge statement sets whose `targetBasisHash` is not the kernel canonical target-basis hash, and compact bridge proof material records whose `proofBytesHash`, proof-record root, verifier-reconstructed lower-level proof statement, or material-set root does not match the supplied proof bytes and bound statement records. Compact proof-material verifiers compute proof-byte length from decoded proof bytes for reporting instead of accepting a stored record field. The accepted setup verifier now refuses optional `compactSameSecretBridgeStatementSet` and `compactSameSecretBridgeProofMaterialSet` package fields before restricted bridge proof verification, because the current compact commitment is not certificate-grade binding evidence.

These measurements are development evidence, not a compact target-ready implementation. The lower-level native/WASM compact share-linkage proof command path is implemented only for the ternary-opening slice, including batched recipient/source-limb items inside one proof statement, and its proof material records have binding roots and per-record proof-byte hashes checked through the native/WASM material-set command. When compact share-linkage proof material carries matching packaged low-level proof statements, the same command verifies one restricted proof per proof record and requires coverage for every recipient and target limb under each source statement, counting both the primary proof item and additional batched items. Accepted setup refuses compact VSS public material because those proofs sit on the current sparse linear commitment without certificate-grade binding evidence. The compact same-secret bridge proof command and material-set command are likewise reduced-ring development paths; the bridge material verifier reconstructs its lower-level proof statement from the bound bridge statement record, target commitment bodies, and proof bytes, and accepted setup now refuses compact bridge fields for the same reason. The default reduced-ring digit-range proof payload fits under the `8 MiB` development budget, but the active full source-batch proof material is over budget: reducing committed proof width or replacing the source-batch linkage proof design remains required before this path can be treated as target-ready or full-source-batch budget-compliant. The target-ready same-secret bridge proof backend, target-ready activation of the public target-result wrapper, further target-decryption proof-material size/runtime reduction, zero-knowledge coverage for released smudged decryption shares in the final proof profile, replacement compact commitment parameter security review, activation of a target-ready compact profile, and final target-profile native/WASM proof measurements remain unfinished.

## Installation

```bash
npm install sealed-lattice
```

```bash
pnpm add sealed-lattice
```

## Basic usage

```typescript
import { deriveThresholdProfile, validatePollSpec } from 'sealed-lattice';

const pollValidation = validatePollSpec({
    pollId: 'board-election-2026',
    question: 'Which proposal should be adopted?',
    options: ['Proposal A', 'Proposal B'],
    topOptionCount: 1,
});

if (!pollValidation.ok) {
    throw new Error(
        pollValidation.errors[0]?.message ?? 'Invalid poll specification.',
    );
}

const thresholdProfile = deriveThresholdProfile({
    rosterSize: 10,
});
```

`pollValidation.normalized` contains the validated poll with defaults applied. `thresholdProfile` contains the derived threshold, quorum, corruption-bound, and warning fields for the frozen roster size.

## What you can use today

- poll specification validation and canonical hash derivation;
- threshold and frozen roster profile derivation;
- lifecycle transition and action capability checks;
- board consistency, cast receipt, close record, target finality, roster manifest, recovery epoch, first-valid ordering, and foundation transcript checks;
- setup-development verification helpers for local share checks, setup package verification input construction, setup package verification, and accepted setup handoff handling;
- foundation transcript verification through the packaged kernel;
- package-boundary and public API smoke coverage for development integration.

## What is not available yet

- a complete threshold voting workflow;
- production-ready setup ceremony, ballot generation, or casting APIs;
- public encrypted ballot package creation, verification, or accepted proof transport APIs;
- public encrypted ballot aggregation APIs;
- public bounded-domain mobile evaluator replay APIs;
- production target-bound decryption or result release APIs;
- production security claims; see [SECURITY.md](SECURITY.md).

The public package must not expose raw BGV decryption, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

## Security

Read [SECURITY.md](SECURITY.md) before treating any verification result as security evidence. That file owns the public threat model, retry policy, audit status, and cryptographic caveats.

## Repository layout

```text
sealed-lattice/
  crates/
    sealed-lattice-kernel/      Rust transcript-core and proof-verifier kernel
  docs/                         Public documentation site and API documentation tools
  packages/
    crypto/                     Internal canonical JSON, hashes, signatures
    protocol/                   Internal protocol logic and reference paths
    sdk/                        Published sealed-lattice package
    types/                      Shared TypeScript type declarations
    wasm/                       Internal WASM loader package
  test-vectors/                 Canonical public regression vectors
  tools/                        CI, vector, packaging, and documentation tools
```

## Documentation

- [Documentation site](https://tenemo.github.io/sealed-lattice/)
- [Guides](https://tenemo.github.io/sealed-lattice/guides/)
- [Protocol spec](https://tenemo.github.io/sealed-lattice/spec/)
- [API reference](https://tenemo.github.io/sealed-lattice/api/)

## Development

Install dependencies:

```bash
pnpm install
```

Run the main local validation gate:

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, runs the type-check, then runs lint, docs verification, package smoke verification, public package policy verification, package-boundary verification, test vector verification, dead-code scan, Rust formatting, Rust clippy, fast Rust kernel tests, fast Node tests, and the non-heavy kernel Node tests through the repository check runner.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Run focused verification:

```bash
pnpm run vectors
pnpm run test:rust:kernel:heavy
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test:node:kernel:heavy
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run verify:docs
pnpm run smoke:pack:npm
```

The native Rust heavy lane now has constrained free-runner-knob evidence. On
June 21, 2026, `pnpm run test:rust:kernel:heavy -- --no-run-log` completed with
`57 passed; 0 failed` under `CARGO_INCREMENTAL=0`, `RAYON_NUM_THREADS=4`,
`SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT=1`,
`SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE=1`,
`SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE=2`, and no checkpoint resume. The
run finished in `17978.14s` and the measured process-tree peak RSS was
`9.97 GiB`. This is native CI-runner setup/proof/key-transport evidence only; it
is not browser, WASM, or supported-phone mobile runtime evidence.

Keep default and release gates focused on the selected direct path and shared substrate. Heavy proof, browser, and mobile evidence lanes should be added only when they measure accepted direct-path evidence.

Build and package-smoke the published SDK:

```bash
pnpm run build
pnpm run smoke:pack:npm
```

Install browser engines before the first local browser test run:

```bash
pnpm exec playwright install chromium firefox webkit
```

## License

This project is licensed under MPL-2.0. See [LICENSE](LICENSE).
