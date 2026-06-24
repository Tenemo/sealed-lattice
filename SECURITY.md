# Security policy

`sealed-lattice` is under active implementation. It has not been independently audited, certified, or approved for production elections. The published package is a development verification package, not a complete voting system, and must not be used for real ballots or real ballot secrecy.

This file is the canonical public security posture for the repository. Detailed mathematical derivations, implementation progress, and proof notes live in the implementation documentation; they are maintainer evidence, not a separate public security policy.

## Report a vulnerability

Use GitHub private vulnerability reporting for this repository when available. If private reporting is not available, do not publish exploit details in a public issue. Open a minimal issue asking for a private contact path, or contact the maintainer out of band.

Include the affected package version or commit, the smallest reproduction you can share safely, the expected security property, the observed behavior, and whether any secret material, voter data, or decryption output may have been exposed. Do not attach real election data, private keys, plaintext ballots, decryption shares, or unpublished exploit material.

## Supported versions and audit status

No release is currently supported for production use. Security fixes target the active repository and the current published package line unless a later release policy states otherwise.

No part of the project has completed an independent external audit or production certification. Development tests, fixtures, native runs, Node runs, browser runs, desktop-browser evidence, and mobile-emulated evidence are not production or supported-phone evidence.

## Threat model

The intended final design is a browser-first, mobile-first, post-quantum threshold homomorphic voting system with active-static secure-with-abort setup, direct encrypted ballots, public aggregation, bounded-domain evaluator replay, unanimous target finality for the first profile, and one-shot target-bound threshold decryption of the finalized target ciphertext only.

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
| `SEC-002` | `P0`     | Target-bound decryption is not certified.                                            | Decryption-share proofs, smudging/noise, recombination, and decoded result validation are unfinished. Current target-decryption code must be treated as development evidence only.                                                                        |
| `SEC-003` | `P0/P1`  | Retry-safe multiparty participation is not implemented.                                  | Retrying setup, key-switching, decryption-share, or related threshold-FHE protocols under the same relevant material is out of scope unless a retry-safe construction is explicitly added and documented.                                                |
| `SEC-004` | `P1`     | The setup proof system does not carry a conventional 128-bit quantum soundness label.    | Current setup proof-family accounting remains below the conventional 128-bit quantum target and is scoped to proof publication time. Ballot proofs and target-decryption share proofs need their own accepted accounting.                                  |
| `SEC-005` | `P1`     | Setup proof zero knowledge is bounded leakage, not full 128-bit zero knowledge.          | Current setup proof accounting discloses bounded leakage rather than a full 128-bit zero-knowledge statement.                                                                                                                                            |
| `SEC-006` | `P1/P2`  | Current HE evidence does not close target decryption.                                    | Current HE evidence covers the setup/evaluator boundary only. It does not close target decryption or produce a conventional 128-bit quantum claim for the full protocol.                                                                                 |
| `SEC-007` | `P1/P2`  | The public encrypted ballot proof/package path is incomplete.                            | Accepted package schemas, public proof transport, final soundness and zero-knowledge accounting, randomness boundaries, and mobile-compatible proof readiness remain unfinished.                                                                         |
| `SEC-008` | `P2`     | Supported-phone runtime evidence is missing.                                             | Native, Node, desktop-browser, and mobile-emulated runs do not count as supported-phone evidence.                                                                                                                                                        |
| `SEC-009` | `P2`     | The project has not completed independent audit, certification, or production hardening. | Any production deployment would need separate review, operational hardening, and deployment-specific risk analysis.                                                                                                                                      |
| `SEC-010` | `P2`     | Profiles outside the first target profile have no security or runtime claim.             | The setup and target-decryption code derive roster parameters for `3 <= n <= 20`, but only the first target profile has current benchmark and certificate work.                                                                                          |
| `SEC-011` | `P1/P2`  | Secret-dependent evaluation-key material depends on an HE KDM/circular-security assumption. | Current setup/evaluator evidence treats this as part of the selected HE construction's assumption set. A future construction theorem can replace the assumption only if it is explicitly cited and bound into the security evidence.                      |

Do not add signer-to-roster binding, witness-key binding, or Unicode canonicalization as open issues unless a new code review finds a specific current break. Current protocol signature checks bind signer identity, signer role, public-key hash, context, object roots, board head, and manifest hashes, and the current canonical JSON/roster paths normalize strings and reject duplicate normalized identities.

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
- bypass structured verifier refusals, canonical hash/root recomputation, or proof-family checks.

## Detailed evidence

Detailed implementation status, proof accounting, and supporting derivations are maintained separately from this public policy. Those notes are maintainer evidence and must not be treated as a public production-security approval.
