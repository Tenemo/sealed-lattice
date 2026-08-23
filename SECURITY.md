# Security policy

`sealed-lattice` is an unaudited research prototype. The open issues below prohibit its use for real elections or other security-sensitive activity. Use synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include the affected package version or commit, a minimal reproduction, the expected property, the observed behavior, and whether private material may have been exposed. Do not attach real election data, private keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported profile

No released version is supported for production use. The sole current cryptographic-completion, integration, performance, and supported-phone evidence target is one exact build with `n = 10` roster participants and `optionCount = 10` options. It derives:

- active Byzantine bound `f = 3`;
- share-reconstruction threshold `r = 4`; and
- finality and state quorums of seven.

Schemas admit rosters in `3..20` and option counts in `2..20`, but other profiles are structurally admitted only and carry no security or runtime claim.

The active profile has a minimum 80-bit post-quantum security target. Every load-bearing cryptographic component and the composed protocol must retain at least `2^80` modeled classical and quantum attack work under the stated models, reductions, assumptions, and resource bounds. This reduced-assurance research target is not a NIST security category, production rating, audit, or certification, and the open issues below mean it has not yet been established end to end.

Cryptographic completion and supported-phone qualification are independent results for the same exact bytes. Both are currently incomplete. The sole phone qualification target is Chrome on the selected physical phone. Native Rust, Node.js, desktop Chromium, emulated devices, and partial phone runs are development evidence only.

## Security model and required boundary

- The protocol protects ballot secrecy, not voter anonymity. The frozen roster and accepted ballot authorship are public.
- Identity vetting, enrollment, reusable invitations, organizer workflow, interface behavior, notifications, and visit cadence belong to the host application. The protocol provides roster binding and auditability, not Sybil resistance.
- The host designates exactly one organizer from the frozen roster. That person is an ordinary participant and eligible voter, may submit no ballot, and gains no special key, proof bypass, quorum weight, finality power, or decryption authority. The organizer designation is not a protocol input.
- All ten participants complete collective setup before any ballot can use the collective public and evaluator keys. A smaller privileged setup group is not permitted.
- The active adversary statically corrupts at most three participants. The separate passive-share-exposure game covers at most three disclosed shares; those bounds are not added into a larger active coalition.
- Transcript, private-mailbox, and storage services are untrusted. They may censor, delay, reorder, duplicate, fork, or replace bytes, but acceptance depends on canonical encoding, recomputed hashes and roots, signatures, proofs, and externally anchored manifest and roster data.
- Only roster participants acting through their own clients may witness state, establish finality, or release target-bound shares. There is no trusted tally server, organizer finalizer, external witness, remote prover, or remote verifier.
- Verification is positive: only a completed verifier result may mint a capability. Producer status fields, test oracles, transport validation, fixtures, and self-consistent records never establish acceptance.
- Finality authorizes exactly one result target. Every decryption share and proof binds to that target, and no accepted interface may decrypt ballots, individual scores, aggregate scores or shares, margins, comparison or selection bits, ranks, evaluator intermediates, or other broader results.
- Participant action state is bound to one browser profile. There is no backup, export, migration, or replacement-device continuation. Missing, corrupt, stale, or unauthenticated state retires that participant from the action.
- Long operations proactively commit authenticated checkpoints at deterministic safe boundaries. Correctness cannot depend on a wake lock, hidden-page execution, lifecycle callback, or final worker notification.
- Durable storage must account atomically for committed, staged, and orphanable bytes, reserve repair headroom, qualify persistence and eviction behavior, and reconcile local state with an external recency anchor before treating it as newest.
- Ballot and proof randomness comes only from the browser-local platform cryptographic random-number generator and domain-separated protocol derivation. A distinct attempt always requires fresh randomness.
- Every required participant operation remains in that participant's mobile browser and scalar-capable WebAssembly path. A desktop, native helper, trusted server, or stronger device cannot substitute for it.

These claims assume honest delivered application code, uncompromised participant devices, an accepted externally vetted roster, and closure of the cryptographic and implementation issues below.

## Open security issues

- `SEC-001`: No independent audit, certification, or production hardening exists. Every result remains prototype evidence.
- `SEC-002`: No exact ten-participant, ten-option setup-to-release ceremony is implemented and accepted end to end.
- `SEC-003`: No independent mechanism certifies that a locally consistent participant snapshot is the newest one. By design, lost or unverifiable state retires that participant from the action instead of permitting recovery or migration.
- `SEC-004`: No production proof system is selected. Production-derived evaluator-key quotient witnesses alone exceed the common-proof scratch ceiling, so the monolithic compact lowering is rejected. Repeating self-contained lookup proofs in smaller packets does not establish complete-action conjunction, shared-witness extraction, correlated-view zero knowledge, or shared-transcript security and already has an unfavorable storage-work floor. One shared application-level packet redesign remains to be compiled and costed before further proof-family or browser qualification work; failure of that gate requires proof-backend replacement research. The rejected previous implementation cannot be used as a fallback or as evidence.
- `SEC-005`: One reference development proof family can be decoded and checked algebraically. A guarded Node.js development run generates one canonical proof through the scalar release WebAssembly artifact and a fresh scalar instance accepts the same proof and public-input bytes; malformed framing refuses. Independent native code reconstructs its public inputs, false statements are refused, and checkpoints restore in a separate process. Independent code reconstructs the complete compiler-derived public-source and direct exact-width verifier-message transcript, and deterministic transport, binding, chronology, source, and equation faults refuse. The direct transcript removes the rejected two-stage domain extender and introduces no separate domain-extension term in the ideal-oracle arithmetic. The source-bound initial-transition owner now derives its auxiliary difference and residual data from the verifier prefix, matrices, and extracted witness, but universal knowledge and extraction, adjacent-witness compatibility, and the complete accepted-proof chronology remain open. The family still lacks proofs that the shared fixed-Keccak interface is modeled safely, emitted proof bytes reveal no witness information, and committed trees hide private data. Full Fiat--Shamir composition and probability accounting also remain incomplete. This evidence establishes no security-bit total and does not yet satisfy the profile's security target.
- `SEC-006`: The participant bridge does not yet carry verifier-minted capabilities and authenticated checkpoint custody from setup through release.
- `SEC-007`: Direct ballot creation, proof generation, transport, and acceptance are incomplete. Ballots remain gated on `VerifiedSetup`; no provisional or pre-ratification ballot path is authorized.
- `SEC-008`: No physical-phone Chrome profile has completed every participant operation.
- `SEC-010`: Homomorphic-encryption, verifiable-secret-sharing, and proof parameters remain provisional and lack a complete reviewed joint-exposure reduction.
- `SEC-011`: Evaluation-key material relies on assumptions about encrypting key-related material, and malicious collective-setup composition remains incomplete.
- `SEC-016`: Target-bound release lacks its complete production proof, correctness and privacy closure, participant finality producer, checkpoint lifecycle, and public workflow.
- `SEC-017`: Caller-key storage adapters do not safely support equivalent-key reimport or reuse across runtime lifecycles.
- `SEC-018`: The tracked collective-setup record establishes internal consistency only. Its authority and packet chronology are not independently derived, and it cannot mint a capability or select a suite.
- `SEC-019`: No immutable, content-addressed evidence record yet binds every construction input and the exact release WebAssembly bytes. Test-only fingerprints cannot select a cryptographic suite or authorize acceptance.
- `SEC-020`: The required checkpoint and interruption boundary is not yet fully implemented or evidenced in a release browser build.
- `SEC-021`: The required storage boundary is not yet fully implemented or evidenced for browser persistence, failure, rollback, and reclamation. A nonqualifying desktop Chromium replay found that namespace-wide capacity scans multiply normal-operation storage work and that internal cleanup does not yet establish physical browser reclamation. Authenticated incremental accounting and bounded exclusive repair remain required.

Identifiers are stable and are not reused. `SEC-009` and `SEC-012` through `SEC-015` are retired.

## Outside the current model

A compromised participant device holds that participant's keys and authority. It can disclose local secrets and send arbitrary messages; local locks and storage checks cannot make it honest. The following are outside the current security boundary:

- compromise beyond the active fault bound;
- data already present on a compromised device;
- malicious same-origin application code or platform key storage;
- adaptive corruption and post-action device compromise;
- everlasting secrecy, receipt freeness, coercion resistance, and endpoint security;
- denial of service and guaranteed availability; and
- timing, traffic-analysis, power, and other side channels.

Protocol safety instead relies on verified proofs, accepted-board rules, one-shot state, and the stated threshold and endpoint assumptions. See the [README](README.md) for the current implementation boundary.
