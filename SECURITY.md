# Security policy

`sealed-lattice` is an unaudited research prototype. The open issues below prohibit real elections and other security-sensitive use. Use synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include the affected package version or commit, a minimal reproduction, the expected property, the observed behavior, and whether private material may have been exposed. Do not attach real election data, private keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported profile

No released version is supported for production use. The sole cryptographic-completion, integration, performance, and supported-phone target is one exact scalar package with `n = 10` roster participants and `optionCount = 10`. It derives an active corruption bound of three, a reconstruction threshold of four, and selected-ballot-set, finality, and state quorums of seven.

Schemas and tally-circuit compilers admit rosters in `3..20` and option counts in `2..20`, but other profiles are structurally admitted only. The concrete preparation and sharing construction is completion-profile-specific and carries no security or runtime claim for another roster size.

The active target is an 80-bit reduced-assurance, post-quantum-oriented research prototype. Every load-bearing component and the composed protocol must retain at least `2^80` modeled attack work under the exact reductions, assumptions, query bounds, and resource limits. This is not a NIST category, production rating, audit, or certification, and it has not been established end to end.

Cryptographic admission and supported-phone qualification are independent results for the same exact bytes. Both are incomplete. Only release Chrome on the selected physical phone can provide supported-phone evidence.

## Security model

- The protocol protects ballot secrecy, not voter anonymity. The frozen roster and accepted ballot authorship are public.
- The host owns identity vetting, enrollment, invitations, organizer workflow, interface behavior, notifications, and visit cadence. The organizer is an ordinary roster participant and has no protocol field or special authority.
- Every roster participant contributes to tally preparation. No smaller privileged group or trusted dealer can complete it.
- The adversary statically corrupts at most three participants and may rush, equivocate, withhold, replay, or schedule their messages. The separate passive-share-exposure game covers at most three disclosed shares; the bounds are not combined.
- Transcript, mailbox, and storage services are untrusted. Canonical encoding, recomputed hashes and roots, signatures, authenticated openings, source correspondence, and positive verifiers determine acceptance.
- Ballot presence, score validity, retry selection, scores, aggregates, comparisons, ranks, and result masks remain protected. The only permitted public result is the ordered selected option identifiers.
- Only roster participants using their own clients may witness state, authorize a selected ballot set, establish finality, or release target-bound result-mask shares. There is no trusted tally server, organizer finalizer, remote prover or verifier, or external witness.
- Finality authorizes one verifier-derived opaque target. Raw shares, caller-selected targets, signatures alone, test fixtures, and producer status cannot enter reconstruction.
- Participant action state is bound to one browser profile. There is no backup, export, migration, or replacement-device continuation. Missing or unauthenticated state retires that participant from the action.
- Long operations require proactive authenticated checkpoints at deterministic safe boundaries. Correctness cannot depend on a wake lock, hidden-page execution, lifecycle callback, or final worker notification.
- Durable storage must account atomically for committed, staged, and orphanable bytes, reserve repair headroom, verify persistence and quota, reconcile local state with an external recency anchor, and measure physical reclamation.
- Cryptographic randomness comes only from browser-local platform randomness and domain-separated protocol derivation. Every new action and every independently randomized ballot-attempt secret uses fresh randomness; byte-identical resume never resamples an existing operation.
- Every required participant operation remains available through scalar-capable, single-worker mobile-browser WebAssembly without a native helper or stronger-device exception.

These properties assume honest delivered application code while secrets are handled, uncompromised honest devices, an accepted externally vetted roster, and closure of the issues below.

## Open security issues

- `SEC-001`: No independent audit, certification, production hardening, or production approval exists.
- `SEC-002`: No exact ten-participant, ten-option preparation-to-release ceremony is implemented and positively accepted end to end.
- `SEC-003`: No independent mechanism yet certifies that a locally consistent participant snapshot is newest. Lost or unverifiable state must retire that participant instead of permitting recovery or migration.
- `SEC-004`: No cryptographic suite is activated, and the public package exposes foundation operations only. Local circuit, field, sharing, storage, and checkpoint results do not constitute a complete protocol, verifier chain, composed security theorem, scalar-browser ceremony, or supported build.
- `SEC-006`: No participant bridge yet carries verifier-minted preparation, activation, evaluation, finality, release-share, and result capabilities with authenticated checkpoint custody through the complete ceremony.
- `SEC-007`: No threshold-held ballot-submission production path is selected or connected to rollback-safe quorum authorization, mutually exclusive included-payload or omitted-input release, activation, one-label opening, and complete positive evaluation through production byte interfaces.
- `SEC-008`: No physical-phone Chrome profile has completed every participant operation for the exact scalar package.
- `SEC-016`: Target-bound result-mask release lacks complete preparation provenance, target-uniqueness composition, production share verification, finality production, checkpoint lifecycle, and public workflow.
- `SEC-017`: Browser-local root-key custody does not yet demonstrate equivalent-key reimport, derivation-count continuity, or safe reuse across required cold runtime lifecycles. Current local records derive one AES-GCM key per envelope from a nonextractable HKDF root and a fresh 256-bit salt, but the production root-key lifecycle and erasure evidence remain missing.
- `SEC-019`: No immutable, content-addressed evidence bundle binds every active construction input, reduction, production counter, and exact release WebAssembly byte. Test fingerprints cannot activate a suite or authorize acceptance.
- `SEC-020`: A generic authenticated checkpoint store now provides exact lineage, predecessor, generation, source, cursor, interrupted-publication repair, and same-root-key store-reopen mechanics. Operation-specific safe boundaries, Rust cursor correspondence, cold-runtime key restoration, worker-loss coverage, bounded lost work, and release-browser evidence remain missing.
- `SEC-021`: Authenticated copy-on-write accounting and a strict-durability IndexedDB adapter exist, but persistence admission, quota and eviction behavior, external rollback reconciliation, browser storage amplification, bounded production repair, and physical reclamation remain unimplemented or unevidenced for the active direction.
- `SEC-023`: No malicious tally-preparation realization currently satisfies the security model. The leading candidate replaces the rejected dealer-supplied zero masks with subset-seeded degree-six zero sharing, uses one same-action preparation attempt, and derives its challenge from committed participant sources after the challenged roots are fixed. Local Rust verification now reaches canonical subset, pair, and collective-coin source leaves plus a semantic inventory of all ten individually authorized seed-catalog roots, but not durable state production, the state-authorized all-ten terminal, source-authorized pair-stream and collective-coin masters, authenticated private delivery, receipts, malicious key establishment, source-authorized pseudorandom streams, complete preparation verification, or a continuation capability. Its multi-user quantum-pseudorandom-function, salted-commitment, fixed-Keccak/KMAC, garbling, emitted-protocol, and selective-abort arguments remain open.
- `SEC-024`: Mobile feasibility is open for the active direction. The current one-attempt formula-level upload lower bound is `1,572,191,976` bytes, leaving `575,291,672` bytes before uncompiled signatures, state, mailbox encryption, ballot custody, checkpoints, storage overlap, repair, restart, and terminal-burn retention. The current zero source also requires `8,403,192` independently framed field outputs per participant. A batched bit-validity candidate would reduce both figures materially, but it has no production graph, verifier, counters, or scalar-browser evidence and is not an admitted resource total. No complete production-derived ledger, matched scalar ceremony, external desktop-browser lifecycle, or physical-phone result exists.
- `SEC-025`: The former public masked-ballot and omitted-input-opening lifecycle is not confidential against the stated service adversary. A corrupt relay can retain an honest masked ballot, censor it from every honest selected-set signer, obtain an authorized omission from their common censored view, and combine the later omitted-input mask with the retained value. That realization is rejected. No replacement ballot construction has yet proved malicious availability, service-censorship privacy, publicly verifiable threshold release, rollback-safe mutual exclusion of included-payload and omitted-input openings, first-honest-share leakage, exact bytes, or mobile resources.

Identifiers are stable and are not reused. `SEC-005`, `SEC-009` through `SEC-015`, and `SEC-018` are retired because they describe removed constructions or superseded status boundaries. `SEC-022` is retired because the project owner replaced the conflicting threshold-homomorphic wording in the governing product requirements with mechanism-neutral outcome and trust-boundary requirements.

## Outside the current model

A compromised participant device holds that participant's keys and authority. It can disclose local secrets and send arbitrary messages. The following remain outside the security boundary:

- compromise beyond the active fault bound;
- data already present on a compromised device;
- malicious same-origin application code or platform key storage;
- adaptive corruption and post-action device compromise;
- everlasting secrecy, receipt freeness, coercion resistance, and endpoint security;
- denial of service and guaranteed availability; and
- timing, traffic-analysis, power, cache, speculative-execution, and other side channels.

Protocol safety instead relies on the accepted roster, positive verification, one-shot state, exact target binding, and the stated cryptographic and endpoint assumptions. See the [README](README.md) for the current implementation boundary.
