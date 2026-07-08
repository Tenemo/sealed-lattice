# Security policy

`sealed-lattice` is under active implementation. It has not been independently audited, certified, or approved for production elections. The published package is a development verification package, not a complete voting system, and must not be used for real ballots or real ballot secrecy.

This file is the canonical public security posture for the repository. Detailed mathematical derivations, implementation progress, and proof notes are maintainer evidence, not a separate public security policy.

## Report a vulnerability

Use GitHub private vulnerability reporting for this repository when available. If private reporting is not available, do not publish exploit details in a public issue. Open a minimal issue asking for a private contact path, or contact the maintainer out of band.

Include the affected package version or commit, the smallest reproduction you can share safely, the expected security property, the observed behavior, and whether any secret material, voter data, or decryption output may have been exposed. Do not attach real election data, private keys, plaintext ballots, decryption shares, or unpublished exploit material.

## Supported versions and audit status

No release is currently supported for production use. Security fixes target the active repository and the current published package line unless a later release policy states otherwise.

No part of the project has completed an independent external audit or production certification. Development tests, fixtures, native runs, Node runs, browser runs, desktop-browser evidence, and mobile-emulated evidence are not production or supported-phone evidence.

## Threat model

The intended final design is a browser-first, mobile-first, post-quantum threshold homomorphic voting system with active-static secure-with-abort setup, direct encrypted ballots, public aggregation, bounded-domain evaluator replay, first-profile trustee target finality, and one-shot target-bound threshold decryption of the finalized target ciphertext only. The current target-finality shell is witness-checkpoint based and is not yet the certified target-decryption finality gate.

The current repository is not at that final boundary. Until the open items below are resolved, callers must assume:

- no complete threshold voting workflow is published;
- no real ballot secrecy or election correctness claim is available;
- public setup workflow, ballot, aggregation, evaluator, and target-decryption paths are development evidence only;
- unsupported APIs, private package paths, fixtures, plaintext oracles, and local witness material are not stable or certified surfaces;
- acceptance must depend on recomputed hashes, roots, canonical encodings, and verified proof families, not on producer-supplied labels or summaries.

## Security notions and FHE caveats

The project uses post-quantum primitives and lattice/FHE components, but those components do not automatically make the full protocol production-secure. Relevant caveats include:

- `IND-CPA` style encryption security is not enough by itself for every application that releases decrypted or partially decrypted FHE results.
- Chosen-plaintext-with-decryption-oracle and reaction-style attacks are relevant to exact FHE and threshold FHE settings.
- Noise flooding, smudging, target binding, one-shot release rules, and application-specific decryption limits are security requirements, not optional performance details.
- Repeated multiparty participation can become a share-leakage surface unless the retry path is explicitly designed, proven, and implemented for that setting.
- Public evaluation-key material for relinearization, Galois, or key-switching is secret-dependent and relies on the selected HE construction's KDM/circular security assumption unless a later public security note cites a theorem that avoids that assumption.
- The current setup proof QROM row is a setup-proof soundness statement, not a privacy statement for all protocol data. Zero-knowledge leakage, commitment hiding, encrypted local state, transport confidentiality, and BGV/RLWE ciphertext confidentiality remain separate long-lived privacy surfaces.

These warnings follow the same class of caveats documented by production FHE libraries such as Lattigo, Microsoft SEAL, and OpenFHE, and by the CPAD and threshold-FHE literature.

## Known limitations and open security items

Severity rubric:

- `P0`: invalidates ballot secrecy or correctness, enables key recovery, accepts an invalid result, or would make real election use unsafe.
- `P1`: invalidates a stated security claim or materially lowers the disclosed security level.
- `P2`: production blocker, unsupported-evidence gap, misuse hazard, missing operational hardening, or missing audit/certification.
- `P3`: documentation, process, hardening, or clarity issue.

| Id        | Severity | Item                                                                                     | Current boundary                                                                                                                                                                                                                                         |
| --------- | -------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEC-001` | `P0`     | Real ballot use and ballot secrecy are out of scope.                                     | The package is for development verification only and has no complete threshold voting workflow.                                                                                                                                                          |
| `SEC-002` | `P0`     | Target-bound decryption is not certified.                                            | Target-bound decryption is implemented as development evidence only, not certified; the proofless raw-share commands are feature-gated out of the default surface and share release binds the accepted, verifier-gated setup package. Several boundaries remain open before any certified use; see the target-decryption boundary note below the table.                                                                                         |
| `SEC-003` | `P0/P1`  | Retry-safe multiparty participation is not implemented.                                  | Retrying setup, key-switching, decryption-share, or related threshold-FHE protocols under the same relevant material is out of scope unless a retry-safe construction is explicitly added and documented.                                                |
| `SEC-004` | `P1`     | The setup proof system does not carry a conventional 128-bit quantum soundness label.    | Setup proof soundness is below the conventional 128-bit quantum target and is scoped to proof-publication time; the kernel enforces the implemented accounting floor, but it is not a 128-bit quantum claim. Ballot proofs and target-decryption share proofs still need their own accepted accounting. See the setup-proof soundness and zero-knowledge note below the table. |
| `SEC-005` | `P1`     | Setup proof zero knowledge is bounded leakage, not full 128-bit zero knowledge.          | Setup proofs disclose a family-aware bounded per-claim statistical distance rather than a full 128-bit zero-knowledge statement. The detailed per-family derivations are maintainer evidence, not a public zero-knowledge approval. See the setup-proof soundness and zero-knowledge note below the table. |
| `SEC-006` | `P1/P2`  | Current HE evidence does not close target decryption.                                    | Current HE evidence covers the setup/evaluator boundary only. It does not close target decryption or produce a conventional 128-bit quantum claim for the full protocol.                                                                                 |
| `SEC-007` | `P1/P2`  | The public encrypted ballot proof/package path is incomplete.                            | Accepted package schemas, public proof transport, final soundness and zero-knowledge accounting, randomness boundaries, and mobile-compatible proof readiness remain unfinished.                                                                         |
| `SEC-008` | `P2`     | Supported-phone runtime evidence is missing.                                             | Native, Node, desktop-browser, and mobile-emulated runs do not count as supported-phone evidence.                                                                                                                                                        |
| `SEC-009` | `P2`     | The project has not completed independent audit, certification, or production hardening. | Any production deployment would need separate review, operational hardening, and deployment-specific risk analysis.                                                                                                                                      |
| `SEC-010` | `P2`     | Profiles outside the first target profile have no security or runtime claim.             | The setup and target-decryption code derive roster parameters for `3 <= n <= 20`, but only the first target profile has current benchmark and evidence work. The helper decryption threshold `q_dec = floor(n/3)+1` coincides with the intended bound at n=10 but diverges from `floor((n-1)/3)+1` when 3 divides n, so 3-divisible future rosters need their decryption threshold re-derived and reviewed before any claim.                                                                                              |
| `SEC-011` | `P1/P2`  | Secret-dependent evaluation-key material depends on an HE KDM/circular-security assumption. | Current setup/evaluator evidence treats this as part of the selected HE construction's assumption set. A future construction theorem can replace the assumption only if it is explicitly cited and bound into the security evidence.                      |
| `SEC-012` | `P0/P1`  | The VSS commitment does not provide message binding (a concrete collision is demonstrated). | The VSS setup path (public coefficient, recipient-share, and aggregate-threshold commitments plus the share-linkage and same-secret bridge proofs) is the only accepted public VSS material in the kernel setup verifier, and acceptance is gated purely by recomputed roots and verified proof families. The VSS commitment was intended to be computationally binding under Module-SIS on short base-`3^17` digit witnesses, but it is not message-binding: a concrete collision has been demonstrated against the deployed kernel commitment map at the production ring, where two distinct canonical openings (differing message coefficients) produce the identical 512-bit commitment root. The break is structural and residue-independent. The 384-byte commitment is only 48 output field elements; message coverage is disjoint (each ring coefficient reaches exactly one output coordinate) and the projected witness is the base-`3^17` digit, so each coordinate is a single modular constraint over roughly 1,366 unknowns whose short in-range kernel vectors are trivially found; a rank-two lattice of covolume about `2^47` always yields an in-range second opening, so no choice of the seeded matrix makes it binding. This binding is load-bearing for the verifier-derived threshold-share commitments, the same-secret bridge constant opening, and target-decryption consistency, so the VSS setup path must not be treated as an accepted, binding setup path until the commitment is redesigned; a lattice-estimator run is moot for the current instance. The share-linkage and bridge proofs share the setup proof families' soundness and bounded-leakage accounting (`SEC-004`, `SEC-005`). Setup material transport volume is tracked in the note below the table and under `SEC-008`. |
| `SEC-013` | `P1/P2`  | Target-finality witness signatures are authenticated against caller-supplied keys not bound to the roster. | The interim witness-checkpoint finality shell (`packages/protocol/src/finality`) verifies each witness signature against a caller-supplied `witnessPublicKeyHashes` map that is never cross-bound to the accepted roster: the witness policy is manifest-committed, but the keys are not, so attacker-chosen witness keys are accepted and finality can be forged. Finality is already scoped as a non-certified shell (see the threat model), which contains the exposure, but the surface must not be relied on until the certified finality replacement sources witness keys from the verified roster, as the direct encrypted ballot signing path already does. The recovery-root, board-head, and recovery-epoch expectations share the same caller-supplied-anchor weakness, and the shell's hardcoded witness quorum does not match the documented unanimous first-profile finality. |
| `SEC-014` | `P2`     | Canonical hashing applies NFC using each runtime's ambient, unpinned Unicode version, so hashes can diverge across the browser/native runtime matrix for non-ASCII input. | Canonical JSON string hashing normalizes with NFC through each runtime's ambient Unicode version (the Rust kernel's `unicode-normalization` crate and the pure-JS hasher's host engine), which are not pinned to a shared version. The versions coincide today and current identities are ASCII, so nothing diverges now, but the pure-JS hasher also runs in voter browsers, so once non-ASCII (for example human-supplied) strings are hashed the same logical object can hash differently across runtimes. This is a determinism break on a load-bearing path (roster and identity dedup feed statement hashes), not a collision; before any non-ASCII input is accepted, pin one shared NFC table (or reject non-NFC/non-ASCII at the boundary) and add cross-runtime differential vectors. |

**Target-decryption boundary.** Proof-backed release currently covers only the full-ranking `K_top = 20` target; top-k decryption for `1 <= K_top < 20` is unsupported, because the evaluator produces those targets below the canonical target-ciphertext level where CPAD-safe smudging headroom is infeasible, a scope reduction on the flagship tally-hiding output. A standalone target-acceptance and finality gate that refuses `K_top < 20` proposals is not yet implemented, so small-`K_top` refusal today rests only transitively on the accepted target record, which is fixture material; the target proposal, context, and finality hashes on that record are likewise fixture material. An end-to-end `K_top = 20` decryption runs as development evidence, not certification. The C3 smudging statistical-distance certificate is not closed. One-shot release is enforced in-process only; persistent consumed-state across process restarts is an open obligation. CPAD is mitigated by one-shot target-bound release plus mandatory smudging, never solved. WASM linear-memory pressure on this path is unmeasured, and decryption-share proof accounting and certified recombination are unfinished.

**Setup-proof soundness and zero knowledge.** The setup proof families currently record roughly 140 conditional classical bits and about 70 quantum bits of soundness after the instance union, under a recent below-capacity FRI proximity-gap conjecture rather than a proven bound. This is below the conventional 128-bit quantum target and is scoped to proof-publication time. Zero knowledge is family-aware bounded per-claim leakage of roughly 2^-40 to 2^-68 across the first roster's adversary-visible claims, not a full 128-bit zero-knowledge statement. The per-family derivations are maintainer evidence.

**Setup material transport volume.** Setup proof material and the trustee evaluation-key component material stream through the setup-proof sidecar and file-backed transports rather than embedding inline, so the canonical package stays encodable at production roster sizes. Streaming changes how the bytes move, not their volume: the share-linkage proof material is projected at roughly 1.1 GB at the production ring and the trustee evaluation-key material at tens of gigabytes per roster, so total verified-download volume remains an open transport and supported-phone runtime constraint (`SEC-008`), not a closed size.

The first setup/evaluator boundary is implemented as maintainer evidence for the first profile. It is accepted because the public setup verifier requires external manifest and setup-roster hashes, verifies active-static setup phase ordering, recipient-verified VSS acceptances, public-key and evaluation-key proof families, root-bound proof and key transport, and HE setup/evaluator evidence, and returns an accepted setup handoff only from the verified package path. Recipient-verified VSS acceptance is not public verification of private share contents: its soundness is contingent on at least `t_secret` honest recipients locally verifying their shares, a precondition the full-roster first profile satisfies and a future non-unanimous-setup profile must re-check. This statement is scoped to setup/evaluator development evidence; the open items table above owns the public list of missing security boundaries.

Public setup verification requires caller-supplied expected manifest and setup-roster hashes, and the kernel verifier compares them to the setup package. The public SDK exposes a setup-roster hash derivation helper for the `CollectiveBgvSetupRoster` object consumed by setup verification; callers must derive that hash from the externally accepted roster positions, identities, and signing-key hashes, not from an untrusted setup package. Current protocol signature checks bind signer identity, signer role, public-key hash, context, object roots, board head, and manifest hashes, and the current canonical JSON/roster paths normalize strings and reject duplicate normalized identities.

## Retry and repeated-participation policy

The project treats retries of multiparty FHE protocols as unsafe by default. Repeated participation can reveal information about secret shares when an adversary can influence the protocol inputs, outputs, or decryption/key-switching queries. A caller must not compensate for a failed setup, key-switching, decryption-share, or related threshold-FHE round by simply retrying under the same relevant secret/public material.

A retry path may be added only if it has a dedicated construction, proof boundary, transcript binding, participant binding, freshness rule, tests, and documentation. Until then, failed threshold-FHE participation must abort the affected protocol instance rather than retrying to obtain liveness.

## Correct use

Current safe use is limited to development verification, package integration, transcript helpers, and foundation/setup-development checks.

Callers must not:

- use the package for production elections, real ballots, or real ballot secrecy;
- expose internal package paths as application dependencies;
- decrypt individual ballots, aggregate scores, ranks, comparisons, evaluator intermediates, or arbitrary ciphertexts;
- expose raw VSS shares, trustee secret shares, proof witnesses, encryption randomness, proof randomness, plaintext oracles, or decryption-share witnesses;
- treat fixture-backed, local, native, Node, desktop-browser, or mobile-emulated evidence as production or supported-phone evidence;
- bypass structured verifier refusals, canonical hash/root recomputation, or proof-family checks;
- supply the local trustee-state storage key from a password or other low-entropy secret: it must be uniformly-random 256-bit device key material (for example from a platform keystore), because the at-rest key commitment is a bare hash of that key and would otherwise become an offline brute-force oracle for the sealed threshold-share material.

## Detailed evidence

Detailed implementation status, proof accounting, and supporting derivations are maintained separately from this public policy. Those notes are maintainer evidence and must not be treated as a public production-security approval.
