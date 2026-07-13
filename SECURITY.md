# Security policy

`sealed-lattice` is development software. It has not been independently audited, certified, or approved for production elections. Do not use it for real ballots, ballot secrecy, result authorization, credentials, keys, or other secret material.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include the affected package version or commit, a minimal reproduction, the expected property, the observed behavior, and whether secret material or private data may have been exposed. Do not attach real election data, private keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported versions

No release is supported for production election use. Security fixes target the active repository and current published package line unless a later release policy states otherwise.

## Current security boundary

| Id | Current boundary | Correct-use consequence |
| --- | --- | --- |
| `SEC-001` | The project is a research prototype without independent audit, certification, production hardening, or a production ballot-secrecy claim. | Use only synthetic data for development, testing, and integration. Obtain independent cryptographic, implementation, deployment, and operational review before any security-sensitive use. |
| `SEC-002` | Target-decryption verification is development-only. It verifies target-bound share proofs, but the repository does not provide a persistent, non-forking authority that permits exactly one final result release. | Do not treat a released value as an authorized election result, expose raw decryption interfaces, or bypass proof-backed verification. |
| `SEC-003` | Retry safety has not been established for fresh randomized setup, key-switching, or decryption participation under the same relevant secret material. Authenticated continuation of the same attempt must preserve its identifier, randomness, derivation contexts, state, and bytes. | Resume only an authenticated same-attempt continuation, a permitted byte-identical deterministic rebuild, or an exact sealed replay. Otherwise abort; do not create a fresh randomized view under consumed state or reused secret material. |
| `SEC-004` | The implemented setup-proof path has no conforming 80-bit QROM work-factor result and therefore does not meet the active prototype target, much less a 128-bit claim for the complete protocol. | Treat proof acceptance as development verification, not cryptographic assurance for a real ceremony. |
| `SEC-005` | The implemented setup-proof path has not established a ceremony-wide `2^-80` zero-knowledge and construction-leakage bound, much less `2^-128`. | Do not assume that publishing development proofs reveals only their public statements. |
| `SEC-006` | Existing homomorphic-encryption evidence covers components, not complete end-to-end ballot confidentiality, evaluation correctness, and target release. | Do not infer full-protocol security from fixtures or component tests. |
| `SEC-007` | The encrypted-ballot creation, proof, transport, aggregation, and accepted-result workflow is incomplete. The current ballot-relation proof has no established claim-soundness or support-zero-knowledge argument; its weakest checked subrelation is modulo the plaintext modulus 65537 and contributes only about 16 soundness bits per transcript despite the nominal 192-bit challenge. | Do not cast, collect, or tally real ballots or treat the internal relation proof as production ballot-validity evidence. |
| `SEC-008` | No supported-phone runtime evidence exists. Native, Node.js, desktop-browser, fixture-backed, and emulated runs do not establish mobile support. | Do not advertise or depend on supported-phone execution without evidence from the exact physical-device and build combination. |
| `SEC-010` | Parameter helpers and passing commitment equations do not certify a cryptographic or runtime profile. The current structured BDLOP commitment instance has no recorded concrete Module-SIS binding or Module-LWE hiding estimate for its exact parameters and accumulated-opening bounds. | Do not attach a security claim to a roster, parameter set, or commitment instance merely because a helper accepted it. |
| `SEC-011` | Secret-dependent evaluation-key material relies on the selected homomorphic-encryption construction's KDM or circular-security assumptions, and the local setup-proof checks do not establish complete malicious collective-setup composition. | Do not describe collective setup or the evaluation-key boundary as malicious-secure or assumption-free. |
| `SEC-013` | The public package does not provide an accepted canonical-board finality session or the fixed state-authorization step needed to turn authenticated records into finality. | Authenticate and authorize finality outside the package; do not infer it from signatures, hashes, or carrier-graph structure alone. |
| `SEC-015` | The complete participant workflow is not yet composed into one bounded mobile-browser acceptance path. Canonical board ingestion, setup proofs, deterministic recomputation, state authorization, ballot acceptance, evaluator replay, finality, durable freshness, and target release remain incomplete as an end-to-end system. Current setup material and proof costs also exceed the supported-phone evidence boundary. | Treat the implemented components as development substrate, not complete protocol acceptance, bounded mobile verification, durable one-shot authority, or production proof-system assurance. |

Authenticated local records, IndexedDB transactions, Web Locks, checkpoints, and hash chains do not provide rollback-resistant freshness. A complete namespace rollback can present an older internally authentic snapshot. Durable authority requires an independently anchored monotonic or replicated freshness source under a stated fault model. If the freshest state cannot be authenticated, retire the affected witness identity and secret material; do not recreate its missing reservation, counter, vote, or release record.

### SEC-016: theorem-matched threshold smudging

Target partial decryption does not yet implement the suite-selected KLLPS target-bound threshold flooding construction. The current zero-share coefficients are deterministically derived from public target and profile bindings under a fixed coefficient bound of 16. The accepted target-share profile does not bind the required flooding bound `B_sm`, threshold-simulation bit length, fresh private domain-separated sampling, or a complete derivation showing that the exact BGV/RNS moduli, interpolation points, evaluator-noise bound, corruption threshold, and statistical failure target satisfy decryption invertibility, decryption correctness, simulation invertibility, and simulation flooding Conditions (C1)-(C4). The current partial-decryption path therefore has no established IND-CPA-D, IND-CPAD, or threshold simulation-security claim.

Closure requires the exact KLLPS source revision; a suite-bound `B_sm` and derived `thresholdSimulationBitLength`; independently uniform coefficients in `[-B_sm, B_sm]` from two private, action-bound, domain-separated target-role KMAC streams after release reservation; unbiased rejection sampling with an enforced per-coefficient draw ceiling and exhaustion accounting; exact evaluator-derived `B_eval` and interpolation norms; independent checks of Conditions (C1)-(C4) at every accepted target level and subset; and complete correctness, simulation-distance, KMAC-transition, and honest-failure accounting. `B_eval`, `thresholdSimulationBitLength`, interpolation norms, and condition margins remain suite evidence rather than runtime-artifact fields. Do not publish or use target partial-decryption shares with real secret material, and do not claim that current flooding hides the secret share or evaluation noise.

## Correct use

- Import only from the published `sealed-lattice` package root. Private workspace packages, fixtures, and test helpers are unsupported.
- Anchor setup, roster, finality, and release authority outside untrusted transcript data. Never derive an authority input from the package being verified.
- Require positive verification of canonical encodings, hashes, roots, signatures, proof families, contexts, and prerequisites. Do not ignore structured refusals or replace them with producer-supplied labels.
- Do not decrypt individual ballots, aggregate scores, ranks, comparisons, evaluator intermediates, or arbitrary ciphertexts.
- Do not expose VSS shares, trustee secret shares, encryption randomness, proof witnesses, proof randomness, decryption witnesses, or local secret state.
- Do not treat local atomicity, locks, authenticated records, or checkpoints as rollback-resistant freshness or durable one-shot authority.
- Current development APIs that accept a caller-managed secret-storage key require uniformly random, platform-protected key material; do not derive it from a password or another low-entropy secret.

Endpoint compromise, malicious same-origin code, compromised platform key storage, denial of service, and side channels without explicit evidence are outside the package's current security boundary.
