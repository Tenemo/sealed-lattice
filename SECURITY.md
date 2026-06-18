# Security policy

`sealed-lattice` is under active implementation. It has not been independently
audited, certified, or approved for production elections. The published package
is a development verification package, not a complete voting system, and must not
be used for real ballots or real ballot secrecy.

This file is the canonical public security posture for the repository. Detailed
mathematical derivations, implementation progress, and proof notes live in the
linked implementation documents; they should not restate a separate public
security ledger.

## Report a vulnerability

Use GitHub private vulnerability reporting for this repository when available.
If private reporting is not available, do not publish exploit details in a public
issue. Open a minimal issue asking for a private contact path, or contact the
maintainer out of band.

Include the affected package version or commit, the smallest reproduction you
can share safely, the expected security property, the observed behavior, and
whether any secret material, voter data, or decryption output may have been
exposed. Do not attach real election data, private keys, plaintext ballots,
decryption shares, or unpublished exploit material.

## Supported versions and audit status

No release is currently supported for production use. Security fixes target the
active repository and the current published package line unless a later release
policy states otherwise.

No part of the project has completed an independent external audit or production
certification. Development tests, fixtures, native runs, Node runs, browser runs,
desktop-browser evidence, and mobile-emulated evidence are not production or
supported-phone evidence.

## Threat model

The intended final design is a browser-first, mobile-first, post-quantum
threshold homomorphic voting system with active-static secure-with-abort setup,
direct encrypted ballots, public aggregation, bounded-domain evaluator replay,
unanimous target finality for the first profile, and one-shot target-bound
threshold decryption of the finalized target ciphertext only.

The current repository is not at that final boundary. Until the open items below
are resolved, callers must assume:

- no complete threshold voting workflow is published;
- no real ballot secrecy or election correctness claim is available;
- public setup workflow, ballot, aggregation, evaluator, and target-decryption
  paths are development evidence only, even though the setup/evaluator HE
  parameter boundary is recorded and bound in the internal evidence ledger;
- unsupported APIs, private package paths, fixtures, plaintext oracles, and local
  witness material are not stable or claim-bearing surfaces;
- acceptance must depend on recomputed hashes, roots, canonical encodings, and
  verified proof families, not on producer-supplied labels or summaries.

## Security notions and FHE caveats

The project uses post-quantum primitives and lattice/FHE components, but those
components do not automatically make the full protocol production-secure.
Relevant caveats include:

- `IND-CPA` style encryption security is not enough by itself for every
  application that releases decrypted or partially decrypted FHE results.
- Chosen-plaintext-with-decryption-oracle and reaction-style attacks are relevant
  to exact FHE and threshold FHE settings.
- Noise flooding, smudging, target binding, one-shot release rules, and
  application-specific decryption limits are security requirements, not optional
  performance details.
- Repeated multiparty participation can become a share-leakage surface unless the
  retry path is explicitly designed, proven, and implemented for that setting.

These warnings follow the same class of caveats documented by production FHE
libraries such as Lattigo, Microsoft SEAL, and OpenFHE, and by the CPAD and
threshold-FHE literature linked below.

## Known limitations and open security items

Severity rubric:

- `P0`: invalidates ballot secrecy or correctness, enables key recovery, accepts
  an invalid result, or would make real election use unsafe.
- `P1`: invalidates a stated security claim or materially lowers the disclosed
  security level.
- `P2`: production blocker, unsupported-evidence gap, misuse hazard, missing
  operational hardening, or missing audit/certification.
- `P3`: documentation, process, hardening, or clarity issue.

| Id        | Severity | Item                                                                                     | Current boundary                                                                                                                                                                                                                                         |
| --------- | -------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEC-001` | `P0`     | Real ballot use and ballot secrecy are out of scope.                                     | The package is for development verification only and has no complete threshold voting workflow.                                                                                                                                                          |
| `SEC-002` | `P0`     | Target-bound decryption is not claim-bearing.                                            | `Q_target`, decryption-share proofs, C1-C4 checks, smudging/noise, recombination, and decoded result validation are downstream. Current target-decryption code must be treated as prototype evidence only.                                               |
| `SEC-003` | `P0/P1`  | Retry-safe multiparty participation is not implemented.                                  | Retrying setup, key-switching, decryption-share, or related threshold-FHE protocols under the same relevant material is out of scope unless a retry-safe construction is explicitly added and documented.                                                |
| `SEC-004` | `P1`     | The setup proof system does not carry a conventional 128-bit quantum soundness label.    | Current QROM Fiat-Shamir accounting records about 70-bit quantum soundness after the instance union, scoped to proof-generation/publication-time soundness risk.                                                                                         |
| `SEC-005` | `P1`     | Setup proof zero knowledge is bounded leakage, not full 128-bit zero knowledge.          | The recipient-private VSS family dominates the current leakage budget at about `2^-41` total after the implemented leakage fix.                                                                                                                          |
| `SEC-006` | `P1/P2`  | Current HE evidence does not close target decryption.                                    | The setup/evaluator `Q_data` exposure records about 139.4 classical bits under the pinned estimator row and a labelled quantum-context row around 97.0 bits. That context row is not a conventional 128-bit quantum claim and does not cover `Q_target`. |
| `SEC-007` | `P1/P2`  | The public encrypted ballot proof/package path is incomplete.                            | Accepted package schemas, public proof transport, final soundness and zero-knowledge accounting, randomness boundaries, and mobile-compatible proof readiness remain unfinished.                                                                         |
| `SEC-008` | `P2`     | Supported-phone runtime evidence is missing.                                             | Native, Node, desktop-browser, and mobile-emulated runs do not count as supported-phone evidence.                                                                                                                                                        |
| `SEC-009` | `P2`     | The project has not completed independent audit, certification, or production hardening. | Any production deployment would need separate review, operational hardening, and deployment-specific risk analysis.                                                                                                                                      |
| `SEC-010` | `P2`     | Profiles outside the first target profile have no security or runtime claim.             | The setup and target-decryption code derive roster parameters for `3 <= n <= 20`, but only the first target profile has current benchmark and certificate work.                                                                                          |

Do not add signer-to-roster binding, witness-key binding, or Unicode
canonicalization as open issues unless a new code review finds a specific current
break. Current protocol signature checks bind signer identity, signer role,
public-key hash, context, object roots, board head, and manifest hashes, and the
current canonical JSON/roster paths normalize strings and reject duplicate
normalized identities.

## Retry and repeated-participation policy

The project treats retries of multiparty FHE protocols as unsafe by default.
Repeated participation can reveal information about secret shares when an
adversary can influence the protocol inputs, outputs, or decryption/key-switching
queries. A caller must not compensate for a failed setup, key-switching,
decryption-share, or related threshold-FHE round by simply retrying under the
same relevant secret/public material.

A retry path may be added only if it has a dedicated construction, proof
boundary, transcript binding, participant binding, freshness rule, tests, and
documentation. Until then, failed threshold-FHE participation must abort the
affected protocol instance rather than retrying to obtain liveness.

## Correct use

Current safe use is limited to development verification, package integration,
transcript helpers, fixtures, and foundation/setup-development checks.

Callers must not:

- use the package for production elections, real ballots, or real ballot secrecy;
- expose internal package paths as application dependencies;
- decrypt individual ballots, aggregate scores, ranks, comparisons, evaluator
  intermediates, or arbitrary ciphertexts;
- expose raw VSS shares, trustee secret shares, proof witnesses, encryption
  randomness, proof randomness, plaintext oracles, or decryption-share witnesses;
- treat fixture-backed, local, native, Node, desktop-browser, or mobile-emulated
  evidence as production or supported-phone evidence;
- bypass structured verifier refusals, canonical hash/root recomputation, or
  proof-family checks.

## Resolved security-relevant development findings

These rows record development findings that are already reflected in the current
implementation or implementation notes. They are not a statement that any release
is production-ready.

| Id          | Finding                                                                               | Current handling                                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEC-R-001` | Producer-supplied outcome labels are not accepted as authority.                       | Acceptance is based on recomputed hashes, roots, canonical encodings, and proof-family verification. Historical status-shaped certificate fields are not a separate source of authority. |
| `SEC-R-002` | Sumcheck-tail binding needed an explicit residual low-degree check.                   | The verifier checks the residual zero anchor and residual low-degree proof; tampering tests reject changed residual roots and anchors.                                                   |
| `SEC-R-003` | Private-VSS zero-knowledge accounting overstated leakage before the family-aware fix. | Redundant message consistency claims were removed, the carry-driven bound is disclosed, and the family now records about `2^-58` per claim and about `2^-41` total.                      |

## Detailed evidence

The following documents own the detailed evidence and derivations:

- [`implementation-documentation/current-status.md`](implementation-documentation/current-status.md) for implementation progress and active blockers.
- [`implementation-documentation/128-bit-pq.md`](implementation-documentation/128-bit-pq.md) for the deferred conventional 128-bit post-quantum roadmap.
- [`implementation-documentation/setup-proof-decisions/qrom-fiat-shamir-soundness.md`](implementation-documentation/setup-proof-decisions/qrom-fiat-shamir-soundness.md) for QROM Fiat-Shamir accounting.
- [`implementation-documentation/setup-proof-decisions/fri-low-degree-soundness.md`](implementation-documentation/setup-proof-decisions/fri-low-degree-soundness.md) for FRI low-degree soundness and the unconditional fallback path.
- [`implementation-documentation/setup-proof-decisions/private-vss-zero-knowledge-leakage.md`](implementation-documentation/setup-proof-decisions/private-vss-zero-knowledge-leakage.md) for the private-VSS leakage fix.
- [`implementation-documentation/setup-proof-decisions/he-noise-and-smudging-headroom.md`](implementation-documentation/setup-proof-decisions/he-noise-and-smudging-headroom.md) for setup/evaluator level headroom and the target-decryption boundary.
- [`reference-documents/CSB24_On the Practical CPAD Security of Exact and Threshold FHE Schemes and Libraries.txt`](reference-documents/CSB24_On%20the%20Practical%20CPAD%20Security%20of%20Exact%20and%20Threshold%20FHE%20Schemes%20and%20Libraries.txt), [`reference-documents/CCP24_Attacks Against the IND-CPA-D Security of Exact FHE Schemes.txt`](reference-documents/CCP24_Attacks%20Against%20the%20IND-CPA-D%20Security%20of%20Exact%20FHE%20Schemes.txt), and the threshold-FHE references under `reference-documents/` for CPAD, smudging, and threshold-decryption context.
- [`reference-projects/lattigo/SECURITY.md`](reference-projects/lattigo/SECURITY.md), [`reference-projects/SEAL/SECURITY.md`](reference-projects/SEAL/SECURITY.md), and [`reference-projects/openfhe-development/docs/static_docs/Security.md`](reference-projects/openfhe-development/docs/static_docs/Security.md) for comparable production-library disclosure patterns.
