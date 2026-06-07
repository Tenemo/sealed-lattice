# sealed-lattice

> This project is under active implementation. It has not been audited or externally reviewed.

[![npm downloads](https://img.shields.io/npm/dm/sealed-lattice?color=5FA04E)](https://www.npmjs.com/package/sealed-lattice) [![CI](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/ci.yml?branch=master&label=tests&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/ci.yml) [![Node source coverage](https://img.shields.io/endpoint?url=https://tenemo.github.io/sealed-lattice/coverage-badge.json)](https://tenemo.github.io/sealed-lattice/coverage-summary.json) [![Documentation build](https://img.shields.io/github/actions/workflow/status/Tenemo/sealed-lattice/pages.yml?branch=master&label=docs&color=5FA04E)](https://github.com/Tenemo/sealed-lattice/actions/workflows/pages.yml) [![License](https://img.shields.io/github/license/Tenemo/sealed-lattice?color=5FA04E)](LICENSE)

`sealed-lattice` is a browser-first, mobile-first, post-quantum threshold homomorphic voting library workspace. The selected construction uses active-static secure-with-abort collective BGV setup, direct BGV-encrypted ballots, LaZer/LNP-derived no-wrap ballot validity proofs, public ciphertext aggregation, bounded-domain mobile evaluator replay, unanimous first-profile target finality, and one-shot target-bound threshold decryption of `C_target` only.

The public npm package is intentionally narrow while the protocol implementation is still being built and verified. It is not a complete voting library and must not be used for real ballot secrecy.

## Selected construction

The active project route is:

```text
active-static secure-with-abort collective BGV setup
-> direct BGV-encrypted ballots
-> LaZer/LNP-derived no-wrap ballot validity proofs
-> public ciphertext aggregation
-> bounded-domain encrypted evaluator replay on mobile
-> unanimous target finality for the first profile
-> one-shot target-bound threshold decryption of C_target only
```

The first claim-bearing mobile profile targets `n = 10`, `m = 20`, every `1 <= K_top <= 20`, `q_setup_complete = 10`, `q_ballot_release = 10`, `q_final = 10`, and `q_dec = 4`. Larger profiles require separate setup, proof, decryption, evaluator, and supported-phone mobile evidence before they can be treated as claim-bearing.

## Current package boundary

The published package currently supports development verification surfaces while the final direct voting API is being built. Use it for packaging, transcript, foundation, and verifier integration work, not for a complete voting ceremony.

The final direct-path package surface must be defined around:

- setup-intent registration;
- public common-randomness commit and reveal verification;
- recipient-verified VSS acceptance verification;
- local setup contribution creation;
- setup package verification;
- proof-bearing public-key share verification;
- proof-bearing evaluation-key share verification;
- threshold-share commitment derivation;
- encrypted ballot verification;
- encrypted ballot aggregation;
- bounded-domain mobile evaluator replay verification;
- target finality verification;
- target-bound decryption-share verification;
- target recombination;
- decoded result verification.

The public package must not expose raw BGV decrypt, arbitrary threshold decryption, individual ballot decryption, aggregate score decryption, rank or comparison opening, evaluator intermediate opening, raw VSS share export, secret-share export, ballot proof witness export, encryption randomness export, or test-only plaintext oracle access.

Reserved complete-protocol entry points must fail closed until their direct-path claim gates are actually implemented.

Foundation helpers now include an integrated public foundation verifier. One deterministic direct-route foundation transcript fixture verifies through the public package in Node and browser, integrated foundation mutations fail with structured refusals, and the packaged Rust/WASM transcript-core path matches the fixture roots under a foundation-only profile. Browser and mobile-emulated browser coverage is useful package evidence, but it is not supported-phone evidence.

## Current implementation status

The BGV setup implementation has useful passive/development evidence:

- the selected BGV-RNS prototype profile uses `N = 32768`, `p = 65537`, 17 data primes, and one special prime;
- RNS arithmetic, NTT/INTT, batch encoding, canonical plaintext roots, canonical ciphertext roots, and profile hashes have regression coverage;
- the internal passive setup command can generate and verify a deterministic full-roster setup package;
- the package binds manifest, roster, threshold profile, collective public key root, BGV public key root, threshold verification roots, evaluation-key roots, evaluator binding roots, and certificate hashes;
- the package rejects trusted-dealer fields, raw secret material, malformed roster positions, wrong roots, rebound internal inconsistencies, evaluator-context binding drift, missing selected rotation roots, and unsupported target-decryption claims;
- the current HE security certificate accepts the largest exposed direct evaluator replay `Q_data`/`Q_share` modulus and keeps the special prime and `Q_target` out of accepted exposure;
- public evaluation-key material can drive development relinearization and rotation checks without exporting the private setup witness;
- the pinned Lattigo oracle remains development-only parity for comparable RNS, NTT, and coefficient arithmetic behavior.

Initial accepted setup verifier evidence now also exists:

- the internal Rust/WASM kernel describes `CollectiveBgvSetup-v1` with compact verifier states, first-profile quorum values, phase order, default generic key-switch refusal, and a verifier-enforced binary/chunked setup transport profile;
- the internal Rust implementation defines the exact accepted `Q_share` prime list and per-RNS-prime Shamir evaluation/interpolation helpers for the first-profile roster and decryption threshold;
- the internal Rust implementation defines the carry-aware VSS share-opening relation profile, binds its hash into setup intent context, and checks the unreduced integer relation `sum(alpha_j^k * F_i,l,k) = sigma_i_to_j,l + q_l * z_i_to_j,l` with canonical share, coefficient, trustee-point, and carry-bound validation;
- the setup phase transcript now binds setup context fields, setup epoch, previous-phase roots, per-trustee phase object roots, phase object byte lengths, signing public-key hashes, phase signature context hashes, and full ML-DSA-65 signature envelopes before reaching proof verification;
- the internal Rust verifier checks phase signature envelope hashes, public-key hashes, signed-root fields, recovery/device epochs, supported ML-DSA context, and the ML-DSA signature itself; rebound tampered phase signatures refuse after phase roots are recomputed;
- accepted setup common randomness now requires full-roster commit/reveal records, verifies reveal hashes against commits, derives the ordered public matrix seed hash, root-binds the common-randomness object, and binds deterministic public derivations for BGV public `a`, public-key CRP, relinearization CRP, Galois-key CRP, commitment-matrix CRP, proof-matrix CRP, the BDLOP/LNP-style commitment profile hash, the setup-proof profile hash, setup-proof challenge-domain hash, CRT commitment modulus limbs, and coordinate-bound decoded coefficient samples for commitment and setup-proof matrices;
- the setup commitment profile now requires a root-bound review-gated `SetupCommitmentSecurityCertificate` and package-level `SetupCommitmentSecurityCertificateHash`, binding the Module-SIS binding row, Module-LWE hiding row, full-width per-RNS message bound, aggregate-opening norm growth for hidden proof witnesses, recipient-hidden aggregate-opening/carry-witness leakage boundary, estimator rows, and no-wrap bounds for the first profile without treating the parameters as claim-bearing before external parameter review and setup proof verifiers exist;
- accepted setup VSS coefficient commitment records now require a root-bound full-roster object with one dealer record per trustee and one commitment reference for every accepted `Q_share` limb and Shamir coefficient, bound to setup context, the commitment profile hash, the carry-aware VSS relation hash, and the common-randomness public matrix seed;
- accepted setup private VSS envelope commitments now require a root-bound full-roster `PrivateVssEnvelopeCommitmentSet` with one envelope reference for every dealer-recipient trustee pair, binding setup context, public matrix seed, accepted dealer commitment root, mailbox encryption profile, a hashed `EncryptedPrivateVssShareEnvelope` object, AEAD associated-data object/hash, private envelope hash, and recipient local verification root;
- accepted setup VSS share acceptances now require a root-bound full-roster `VssShareAcceptanceSet` with one recipient-signed acceptance for every dealer-recipient trustee pair, bound to setup context, the private VSS envelope commitment set, the accepted dealer commitment root, the recipient local verification root, recovery/device epochs, and ML-DSA-65 signature envelopes;
- accepted setup VSS complaints now accept a root-bound signed `VssComplaintSet`, check complaint private-envelope hashes against the same private-envelope and dealer commitment bindings as acceptances, return `aborted` for a valid first-profile complaint, and the Node/WASM setup test now inserts a protocol-built complaint set with local-verification-derived evidence to exercise that abort path;
- the internal Rust/WASM kernel now has local `GeneratePrivateVssShareProof` and `VerifyPrivateVssShareEnvelope` commands for proof-shaped private VSS envelopes: the generator consumes dealer-local coefficient messages/opening randomness plus caller-supplied proof randomness, derives hidden carry witnesses internally, emits only a root-bound `PrivateVssShareProof`, and verifies the generated proof before returning it; the verifier accepts recipient share values, coefficient commitment roots, and embedded or root-bound transported private proof bytes while rejecting leaked coefficient messages, raw Shamir coefficients, per-coefficient randomness, per-coefficient openings, plaintext aggregate openings, and plaintext carry witnesses; this remains review-gated until external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, and production non-JSON private proof streaming are complete;
- the internal crypto package now creates and decrypts private VSS mailbox envelopes using ML-KEM-768, HKDF-SHA-384, and AES-256-GCM, recomputes the AAD hash, KEM ciphertext hash, and AEAD ciphertext byte hash before key derivation or decryption, and the accepted setup verifier binds private mailbox encrypted-envelope hashes plus recipient mailbox public-key hashes and public-key bytes hashes to setup-intent roster records while validating embedded encrypted-envelope transport material when supplied; encrypted local trustee state now decodes through a positive typed sealed-payload schema with rejected unknown fields, setup epoch and device binding, aggregate threshold-share roots, and `ThresholdShareCommitmentRecipientRoot` binding while keeping forbidden-field scanning as defense in depth; local state and setup contribution records no longer store or publish aggregate-opening roots; internal protocol helpers now sample per-dealer VSS coefficient opening state from a CSPRNG/random-byte source with one centered-ternary trustee secret polynomial shared across all `Q_share` limbs for Shamir coefficient zero, uniform non-constant per-RNS Shamir coefficients, and centered-ternary BDLOP/LNP opening randomness; those helpers produce signed setup phase participant objects and phase roots, per-dealer root-bound VSS coefficient contribution records and full public material, signed VSS complaint records with evidence roots derived from local private VSS verifier refusal details, root-bound same-secret statement sets from accepted VSS constant commitments, root-bound public-key share and proof statement sets from supplied coefficient hashes, root-bound evaluator-key schedule records from the verifier-exposed frozen schedule profile, roots-only local trustee state commitments, encrypted storage envelopes bound to protocol-built roots-only local state commitments, and optional root-bound `SetupTransportedPrivateVssShareProofMaterialSet` records for recipient delivery while public setup references remain hash-only; private VSS mailbox delivery now uses the local Rust/WASM private share proof generator or an explicit proof factory and fails closed instead of deriving recipient local verification roots from plaintext aggregate openings;
- the internal Rust/WASM kernel now has a local `DeriveThresholdShareCommitments` command that checks full public `VssCoefficientCommitmentMaterial` against accepted dealer coefficient commitment records, homomorphically derives every `ThresholdShareCommitment_j,l` from trustee-point powers, and returns a root-bound `ThresholdShareCommitmentSet`;
- accepted setup threshold commitment records now require a root-bound public `VssCoefficientCommitmentMaterialSet` and a root-bound `ThresholdShareCommitmentSet`; the verifier recomputes the threshold commitments from embedded full public material or, for binary-rooted material sets, consumes out-of-band transported public VSS chunks after checking 1 MiB chunk framing, chunk hashes, full-object hash, chunk manifest root, canonical binary record order, and dealer commitment roots; the transported path derives the same threshold-share commitment set without returning embedded coefficient material and refuses missing or mismatched transported material;
- accepted setup VSS coefficient commitment material now refuses `development-reduced-ring` under `CollectiveBgvSetup-v1`; the full setup path requires `ringDegree = 32768` and `ringDegreeStatus = profile-ring`;
- accepted setup same-secret statement records now require a root-bound `SameSecretConsistencyStatementSet`, derive each `TrusteeSecretCommitmentRoot` from the accepted VSS constant coefficient commitments `C_i,l,0`, bind a canonical `SameSecretProofFamilyBindingRoot` for the secret-dependent setup proof family list plus generic key-switch and target-decryption policies, and reject drift in constant roots, trustee roots, proof-family binding roots, statement roots, or the same-secret set root;
- the setup-proof profile now distinguishes the application BGV ring degree `N = 32768` from the fixed LNP tbox proof ring degree `d = 128`, exposes the `omega = 2` challenge layout, and includes a strict LaZer-style tbox proof-byte decoder for field order, canonical uniform residues, challenge coefficients, hints, Gaussian encodings, final padding, trailing-byte rejection, and retained decoded tbox transcript fields for later algebraic verification;
- accepted setup can optionally consume a root-bound `SameSecretProofSet` whose pinned LNP same-secret proof envelope verifies that each trustee's VSS constant commitments open to one centered-ternary integer polynomial across all `Q_share` limbs, including the `-1 mod q_l = q_l - 1` wrap case, with fixed verifier-side response bounds; this binds the same-secret tbox parameter profile hash, tbox commitment prefix hash, proof bytes, proof byte hashes, statement hashes, relation commitment hashes, LNP-derived scalar challenges, proof roots, fixed setup-proof profile/challenge-domain/sampler record binding, the proof-family binding root, the proof-set root, and the public VSS material root, can extract constant commitments from verifier-checked transported binary public VSS chunks when the package uses binary-rooted material, can resolve same-secret proof bytes from root-bound binary proof-material chunks supplied with the verification request, and now has a local Rust/WASM `GenerateSameSecretLnpProof` command that uses non-test transcript domains and verifies generated proof bytes before returning them, but remains review-gated until external AB-DLOP/LNP soundness and zero-knowledge review plus full tbox quadratic/range proof closure are complete;
- accepted setup public-key share records now require root-bound `PublicKeyShareSet` and `PublicKeyShareProofSet` objects that bind setup context, accepted public common-randomness/public-`a` roots, accepted same-secret statement roots, ordered per-limb share coefficient hashes, and proof statement roots; the verifier can optionally consume root-bound `PublicKeyShareMaterialSet` and `PublicKeyShareLnpProofSet` objects whose pinned public-key LNP proof envelopes bind the accepted setup-proof profile, public-key tbox parameter profile hash, tbox commitment-prefix hash, LNP-derived scalar challenge, VSS-bound trustee secret opening, verified same-secret proof root, `SameSecretProofFamilyBindingRoot`, centered-binomial error support, coefficient-vector hashes, fixed verifier-side response bounds, and the lifted public-key share relation with explicit no-wrap carry witnesses against derived public `a`; public-key proof bytes may be embedded or resolved from root-bound transported binary proof-material chunks supplied with the verification request, and the local Rust/WASM `GeneratePublicKeyShareLnpProof` command uses non-test transcript domains and verifies generated proof bytes before returning them; the review-gated `CollectivePublicKey` aggregate binds the verified same-secret proof-set root, `SameSecretProofFamilyBindingRoot`, and public-key LNP proof-set root, but it is not accepted for claim-bearing setup use until external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, and evaluator-key proof review closure are complete;
- accepted setup evaluator-key schedule records now require a root-bound `EvaluatorKeySchedule` object that binds setup context, accepted common-randomness relinearization and Galois CRP roots, same-secret and public-key share roots, frozen relinearization levels, frozen Galois rotations and levels, `RequiredGaloisSetHash`, explicit first-profile generic key-switch refusal, and `EvaluatorKeyScheduleRoot`; the verifier now consumes proof-bearing `RelinearizationKeyShareRounds` and `GaloisKeyShareBatch` records whose embedded or transported LNP proof bytes bind the setup-proof profile, evaluator-key tbox parameter hashes, tbox commitment-prefix hashes, LNP-derived challenges, verified same-secret proof roots, `SameSecretProofFamilyBindingRoot`, the public-key LNP proof-set root, CRP roots, deterministic key-switch samples, public component-vector material, frozen relinearization/Galois schedule, round-one aggregate roots, round-two linkage, root-bound relinearization source-square binding and aggregate roots, and lifted key-switch no-wrap relations, and it now requires a root-bound `PublicEvaluationKeySet` assembled only from those verified proof roots; the assembly binds the schedule root, proof-family root, public-key LNP proof-set root, relinearization aggregate roots, relinearization source-square aggregate roots, Galois batch roots, decomposition counts, required Galois set hash, empty generic key-switch roots, no embedded raw key bytes, no verifier-generated key material, and `EvaluationKeySetHash`, while refusing missing scheduled keys, extra generic key-switch roots, source-square root drift, and root drift; this remains review-gated because quadratic relinearization source-square proof closure, external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, and production proof streaming are still incomplete;
- the accepted setup profile now exposes a static full-profile public VSS commitment material size profile: `N = 32768`, 10 trustees, 17 `Q_share` limbs, 4 Shamir coefficients, 2 commitment limbs, 3 commitment rows, and 8-byte residues imply 680 published commitments, 1,572,864 coefficient bytes per commitment, and 1,069,547,520 coefficient bytes before JSON or transport overhead;
- the accepted setup transport verifier now requires a root-bound `SetupTransportCertificate` and package-level `SetupTransportCertificateHash`, binds the accepted transport profile hash, requires 1 MiB binary chunks, 1,020 chunk hashes for the full-profile public VSS material lower bound, a canonical chunk manifest root, storage quota, largest-buffer, copy-count, resume, lazy-loading, and transported-object root fields, and refuses chunk-count, chunk-root, object-root, profile-hash, and certificate-hash drift;
- accepted setup now requires a root-bound `BgvHeSecurityCertificate` and package-level `heSecurityCertificateHash`, verifies the canonical current-exposure certificate for `N = 32768`, `p = 65537`, `Q_data`/`Q_share`, special-prime non-exposure, review-gated relinearization and Galois key-switch component exposure counts from the accepted schedule, HE-standard estimator rows, and explicit `Q_target` refusal;
- the internal Rust/WASM kernel now has a local `VerifyLocalTrusteeSetupState` command that verifies roots-only `LocalTrusteeSetupStateCommitment` records and deletion receipts, binds aggregate threshold-share roots, and rejects raw shares, openings, witnesses, seeds, and private VSS envelope payloads from the exported commitment; encrypted local trustee state now round-trips only through the positive sealed local-state schema;
- internal protocol setup orchestration now builds a roots-only `SetupContributionAssembly` from signed phase records, VSS commitment roots, private mailbox delivery references, acceptance or complaint roots, verifier-derived threshold-share roots, encrypted local-state roots, deletion receipts, and optional public-key proof-statement roots while rejecting forbidden raw material paths;
- the Rust setup module retains carry-aware VSS relation helpers for proof-statement construction and tests, but plaintext aggregate openings and carry witnesses are no longer an accepted private-envelope verification path;
- the internal verifier command accepts only `SetupPackage`/`CollectiveBgvSetup-v1` shaped material, binds the exact `Q_share`, classifies legacy passive packages as outside profile, detects phase ordering errors and forks, refuses setup seeds and trusted-dealer material, refuses evaluator schedule drift, refuses generic key-switch material unless explicitly scheduled, and refuses malformed commitment security certificates, setup transport, and HE security certificates; the WASM bridge maps thrown `verifyCollectiveBgvSetup` command failures to the neutral `InvalidProtocolObject` public error code;
- the setup package verifier intentionally remains outside claim-bearing setup acceptance until same-secret, public-key, relinearization, and Galois external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, quadratic relinearization source-square proof closure, and production proof transport are complete.

This evidence is not active-static setup closure and is not an accepted mobile setup profile. The current setup blockers are:

- full-profile public VSS commitment material is now measured at 1,020 MiB, about 1.07 GB, of coefficient bytes before overhead; the setup verifier now enforces a binary/chunked certificate and manifest for that lower bound, package-level threshold-share verification plus same-secret and public-key proof verification can consume verifier-checked transported binary public VSS material, and private VSS, same-secret, and public-key LNP proof verification can consume root-bound transported proof-byte chunks; production-grade non-JSON streaming/lazy loading and extension to relinearization, Galois, and evaluation-key material still remain before full-ring setup can be treated as mobile-viable;
- recipient-local private VSS share proof generation and verification now replace the refused plaintext aggregate-opening/carry-witness path for local Rust/WASM verification and can consume embedded or root-bound transported proof bytes; remaining blockers are external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, and production non-JSON private proof streaming;
- relinearization and Galois proof review closure; the verifier now checks pinned proof-byte records, transcript binding, same-secret family-root binding, component-vector roots, deterministic key-switch samples, lifted key-switch no-wrap algebra, relinearization source-square binding and aggregate roots, and root-bound public evaluation-key assembly, but quadratic relinearization source-square proof closure, external AB-DLOP/LNP soundness and zero-knowledge review, full tbox quadratic/range proof closure, generic key-switch proof support if ever scheduled, production proof streaming, and claim-bearing key correctness evidence remain open;
- same-secret external AB-DLOP/LNP soundness and zero-knowledge review plus full tbox quadratic/range proof closure linking the accepted trustee secret commitments to VSS, public-key, root-bound relinearization/Galois containers, generic key-switch material only if required, and future decryption shares; the current same-secret verifier has pinned tbox parameters, LNP proof envelope and challenge binding, root-bound transported proof-byte support, retained decoded tbox transcript fields, same-secret commitment relation algebra, a runtime `GenerateSameSecretLnpProof` command using non-test transcript domains, and downstream `SameSecretProofFamilyBindingRoot` consumption through current public-key and evaluation-key proof records, but it remains review-gated rather than claim-bearing;
- public-key LNP proof soundness and zero-knowledge review plus full tbox quadratic/range proof closure for the accepted public-key share relation; the current public-key verifier has pinned tbox parameters, LNP proof envelope and challenge binding, root-bound transported proof-byte support, retained decoded tbox transcript fields, VSS-bound secret linkage through the verified same-secret proof root and proof-family root, error support, no-wrap carries, a runtime `GeneratePublicKeyShareLnpProof` command using non-test transcript domains, and review-gated collective public-key aggregate binding, but it remains review-gated rather than claim-bearing;
- quadratic relinearization source-square proof closure and external review for the current root-bound round proof verifier;
- external review for the current root-bound Galois-key batch proof verifier;
- claim-bearing evaluation-key correctness evidence beyond review-gated root assembly;
- setup and evaluation-key footprint reduction, package-level lazy loading from the enforced setup transport manifest, and extension of the transported binary path beyond public VSS, same-secret proof, and public-key proof material to relinearization, Galois, and evaluation-key material;
- public package setup contribution creation, encrypted local-state import/export surfaces, and setup package verification surfaces around the internal roots-only assembly helpers;
- active-static secure-with-abort setup theorem closure;
- target-decryption handoff closure for `Q_target`, smudging, C1-C4, share proofs, and target-decryption readiness refusal.

The direct encrypted ballot implementation has useful internal evidence:

- one 20-score direct BGV ballot can be encoded;
- private preflight checks all 17 data-prime encryption equations against one shared encoded-message, randomizer, and error witness;
- one internal binary proof checks all data-prime encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support with one shared response vector;
- the current internal proof is 18,626,400 bytes;
- binary proof transport is chunked and publicly hash-bound inside the internal command, including proof length, chunk size/count, chunk hashes, chunk Merkle root, full proof hash, statement hash, ciphertext root, voter identity, action context, profile, collective key, ballot layout, and proof profile;
- Node/WASM one-proof verification and aggregation pass through the internal command path;
- Node/WASM 20-ballot proof verification and aggregation pass with internal binary chunk transport in about 76.4 s outer wall time, 372,528,000 total proof bytes, about 396 MB WASM linear memory after the run, and about 603 MB Node resident set after the run;
- desktop Chromium proof smoke verifies one widened proof and aggregates one ballot with internal binary chunk transport in about 4.7 s and about 179 MB WASM linear memory after the run;
- the internal command uses fresh CSPRNG proof-mask and ballot-encryption randomness by default in Node/WASM and browser helpers;
- the internal command rejects reused encryption randomness, reused proof-mask randomness, and proof/encryption randomness overlap;
- duplicate voter identities, out-of-order voter identities, invalid scores, and mismatched setup witness seeds reject before encryption and proof generation;
- current evaluator evidence produces encrypted sparse target roots for requested top counts without publishing aggregate scores, ranks, comparisons, masks, evaluator intermediates, or decoded target slots;
- one native one-ballot packed batched-pair replay matches the full 20-option target oracle at working level 8 in about 240 s;
- target-accepted record and target-bound decryption-share verification refuse shares for any ciphertext other than the accepted target ciphertext;
- target-bound threshold `PartDec` and recombination math compute context-bound Shamir partial decryptions for the accepted sparse target ciphertext pair and recover target ID/order slots with Lagrange interpolation.

This evidence is not claim-bearing. The accepted ballot proof path is a LaZer/LNP-derived linear-relation proof with per-RNS-limb no-wrap lifting. Upstream LaZer native code, Sage codegen, and LaBRADOR are development reference or code-generation material only; the mobile claim path needs a Rust/WASM selective port or reimplementation of the LNP linear-relation subset.

The accepted evaluator profile is bounded-domain interpolation over certified score-difference and rank domains. Full-field `p = 65537` comparison is not the first claim path.

The current blockers are:

- accepted active-static setup contributions and setup package verification;
- persisted-state setup contribution orchestration, VSS coefficient/opening sampling and restoration, encrypted local trustee state import/export integration, and proof-bearing setup records;
- accepted collective public-key correctness evidence;
- claim-bearing evaluation-key correctness evidence beyond review-gated root assembly and mobile key transport;
- proof soundness accounting until encryption, encoder, score, one-hot, support, and carry/slack relations use accepted no-wrap lifting or equivalent accepted accounting;
- zero-knowledge accounting, including replacement or formal redesign of witness-dependent support commitments;
- Fiat-Shamir/QROM review;
- public package proof transport for an accepted proof profile;
- public accepted randomness API boundaries;
- supported-phone mobile proof verification;
- supported-phone mobile evaluator replay;
- browser/mobile proof-copy and memory evidence;
- bounded-domain comparator coefficients, depth, noise, and all-`K_top` replay certificate;
- target decryption share proof verification and certification;
- smudging, noise, and C1-C4 target-decryption closure;
- public target-decryption/recombination integration;
- supported-phone mobile target-decryption/recombination evidence.

The highest-risk mobile feasibility items are proof sizes for active setup, evaluation-key, ballot, and decryption-share proofs; evaluation-key size and mobile key transport; bounded-domain evaluator depth and noise certificates; and supported-phone WASM memory/copy behavior.

## What is internal

Several components exist only as workspace-internal implementation, test, or vector infrastructure:

- `GF(65537)` arithmetic and plaintext top-k oracle helpers for tests;
- sealed-lattice Rust/WASM BGV-RNS arithmetic, selected-prime arithmetic, RNS coefficient objects, NTT/INTT, plaintext basis conversion, `BGVBatchEncode_65537`, canonical plaintext/ciphertext roots, and object validation;
- internal passive BGV setup generation, verification, certificates, and development evaluation-key material;
- an internal direct encrypted ballot command for current implementation work;
- Rust/WASM transcript-core commands used to keep TypeScript and native canonicalization behavior aligned;
- development-only reference-oracle tooling and generated public test vectors.

These pieces are not exported as a public voting API. The legacy passive setup profile `sealed-lattice-bgv-rns-passive-full-roster-setup-v1` is development-only and cannot close `CollectiveBgvSetup-v1`.

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

## Installation

```bash
pnpm add sealed-lattice
```

Treat the package as a development verification package until the active-static direct encrypted ballot API is explicitly published and audited.

## Development

Install dependencies:

```bash
pnpm install
```

Run the main local validation gate:

```bash
pnpm run check
```

`pnpm run check` builds the workspace once, runs the type-check, then runs lint, docs verification, package smoke verification, public package policy verification, package-boundary verification, test vector verification, dead-code scan, Rust formatting, Rust clippy, Rust tests, and fast Node tests through the repository check runner.

For public SDK API changes, run `pnpm run api-surface:generate` and review the compact summary diff manually in the PR. API surface review is not part of `pnpm run check`.

Run focused verification:

```bash
pnpm run vectors
pnpm run test:node:fast
pnpm run test:node:protocol
pnpm run test:node:kernel
pnpm run test:node
pnpm run test:browser
pnpm run test:lattigo-oracle
pnpm run test:proof-benchmark
pnpm run test:proof-benchmark:node
pnpm run test:proof-benchmark:browser:desktop
pnpm run verify:docs
pnpm run smoke:pack:npm
```

Keep default and release gates focused on the selected direct path and shared substrate. Heavy proof, browser, and mobile evidence lanes should remain explicit and direct-path-only.

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
