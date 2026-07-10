# Security policy

`sealed-lattice` is development software. It has not been independently audited, certified, or approved for production elections. Do not use it for real ballots, real ballot secrecy, or production result authorization.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include the affected package version or commit, a minimal reproduction, the expected property, the observed behavior, and whether secret material or private data may have been exposed. Do not attach real election data, private keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported versions

No release is supported for production election use. Security fixes target the active repository and current published package line unless a later release policy states otherwise.

## Current security boundary

These identifiers are stable public labels; source comments refer to several of them.

| Id        | Current boundary                                                                                                                                                                                                             | Correct-use consequence                                                                                                                                   |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEC-001` | The package does not provide a production-approved voting system or ballot-secrecy claim.                                                                                                                                    | Use only synthetic data for development, testing, and integration.                                                                                        |
| `SEC-002` | Target-decryption verification is development-only and does not establish a certified, persistent one-shot release boundary. Proofless raw-share commands are excluded from the default surface.                             | Do not treat a released value as an authorized election result, expose raw decryption interfaces, or bypass proof-backed verification.                    |
| `SEC-003` | Retry safety has not been established for repeated setup, key-switching, or decryption participation under the same relevant secret material.                                                                                | Abort a failed multiparty round instead of retrying it with the same material.                                                                            |
| `SEC-004` | The implemented setup-proof accounting does not establish a conventional 128-bit quantum soundness claim for the complete protocol.                                                                                          | Treat proof acceptance as development verification, not production security evidence.                                                                     |
| `SEC-005` | The implemented setup proofs do not establish a full 128-bit zero-knowledge claim for all published proof data.                                                                                                              | Do not assume that publishing development proofs reveals no information beyond their public statements.                                                   |
| `SEC-006` | Existing homomorphic-encryption evidence covers components, not complete end-to-end ballot confidentiality, evaluation correctness, and target release.                                                                      | Do not infer full-protocol security from estimator output, fixtures, or component tests.                                                                  |
| `SEC-007` | The public encrypted-ballot creation, proof, transport, aggregation, and accepted-result workflow is incomplete.                                                                                                             | Do not use the package to cast, collect, or tally real ballots.                                                                                           |
| `SEC-008` | No supported-phone runtime evidence exists. Native, Node.js, desktop-browser, and emulated runs do not establish mobile support.                                                                                             | Do not advertise or depend on supported-phone execution without evidence from the exact physical-device and build combination.                            |
| `SEC-009` | The project has not completed independent audit, certification, or production hardening.                                                                                                                                     | Obtain independent cryptographic, implementation, deployment, and operational review before any security-sensitive deployment.                            |
| `SEC-010` | Parameter-derivation helpers can return values for several roster sizes, but those values do not certify a cryptographic or runtime profile.                                                                                 | Do not attach a security claim to a roster or parameter set merely because a helper accepted it.                                                          |
| `SEC-011` | Secret-dependent evaluation-key material relies on the selected homomorphic-encryption construction's KDM or circular-security assumptions.                                                                                  | Do not describe the evaluation-key boundary as assumption-free.                                                                                           |
| `SEC-012` | A legacy VSS projection commitment admitted a concrete binding collision and has been removed. The committed-material path replaces it, while evaluation-key atom paths without the required same-secret anchor fail closed. | Reject legacy projection artifacts and never weaken or bypass the current fail-closed anchor checks.                                                      |
| `SEC-013` | The current target-finality helper verifies witness signatures against caller-supplied witness keys that are not bound to an accepted roster.                                                                                | Treat `verifyTargetFinality` as a development shell, not an authorization or finality decision.                                                           |
| `SEC-014` | Hash-critical NFC normalization depends on each runtime's ambient Unicode data, so non-ASCII input can diverge across runtimes.                                                                                              | Keep hash-critical user-controlled identifiers and labels ASCII unless the application independently enforces one cross-runtime canonical representation. |

## Correct use

- Import only from the published `sealed-lattice` package root. Private workspace packages, fixtures, test helpers, and plaintext oracles are unsupported.
- Supply `verifySetupPackage` with manifest and roster hashes derived from an externally accepted context, never from the untrusted package being verified.
- Require positive verification of canonical encodings, hashes, roots, signatures, proof families, contexts, and prerequisites. Do not ignore structured refusals or replace them with producer-supplied labels.
- Do not decrypt individual ballots, aggregate scores, ranks, comparisons, evaluator intermediates, or arbitrary ciphertexts.
- Do not expose VSS shares, trustee secret shares, encryption randomness, proof witnesses, proof randomness, decryption witnesses, or local secret state.
- Do not retry a failed multiparty operation under the same relevant secret material.
- Do not treat fixtures or native, Node.js, desktop-browser, or emulated runs as production or supported-phone evidence.
- Protect any caller-managed secret-storage key with uniformly random platform-protected key material; do not derive it from a password or another low-entropy secret.

Endpoint compromise, malicious same-origin code, compromised platform key storage, denial of service, and side channels without explicit evidence are outside the package's current security boundary.
