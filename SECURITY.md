# Security policy

`sealed-lattice` is an unaudited research prototype. The open issues below prohibit real elections and other security-sensitive use. Use synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include:

- the affected package version or commit;
- a minimal reproduction;
- the expected and observed behavior; and
- whether private material may have been exposed.

Do not attach real election data or unpublished exploit material. Do not attach private keys, ballots, shares, or witnesses.

## Supported profile

No released version is supported for production use. The completion and qualification target is one scalar package with ten roster participants and ten options. For that profile, the protocol formulas derive an active corruption bound of three, a reconstruction threshold of four, and a direct finality quorum of eight. The finality intersection additionally tolerates one independently rolled-back or lost honest finality lock. There is no separate ballot-set or network state-witness quorum.

Schemas and tally-circuit compilers admit rosters and option counts from 3 to 20 and 2 to 20 respectively, but other profiles are structural inputs only. They carry no cryptographic, runtime, or support claim.

The design aims for at least 80 bits of modeled attack work against quantum-capable adversaries under its stated assumptions and limits. That claim has not been established end to end and is not a NIST category, production rating, audit, or certification.

Cryptographic admission and supported-phone qualification are independent results for the same exact bytes. Both are incomplete. Only release Chrome on the selected physical phone can provide supported-phone evidence.

Here, a poll is the user-facing workflow. An action is one canonical protocol execution for that poll.

## Security model

- The protocol protects ballot scores, not voter anonymity. The frozen roster, each signed submit-or-abstain declaration, accepted ballot authorship, and whether any selected ballot is usable are public.
- The host-application duties described in the [README](README.md#library-boundary) grant no protocol authority. Participants confirm and freeze the roster. Identity vetting and Sybil resistance remain outside the library, and the organizer remains an ordinary roster participant.
- Every roster participant contributes to tally preparation. No smaller group, dealer, server, or organizer can complete it.
- The adversary statically corrupts at most three participants and may rush, equivocate, withhold, replay, reorder, fork, or replace messages. A separate passive-exposure game covers at most three disclosed shares; the two bounds are not combined.
- Transcript, mailbox, and storage services are untrusted. Silence never means abstention. Missing required input leaves the action pending.
- Acceptance comes only from positive verification. The responsible verifier recomputes context and source bindings, then checks the canonical bytes and every required authentication, opening, state, and construction relation. Producer status and caller-selected targets cannot authorize acceptance; neither can signatures, raw shares, or fixtures on their own.
- The selected ballot set is derived from a roster-complete declaration and availability inventory. Every finality signer recomputes it; no separate quorum can choose another subset or authorize an omitted-input opening.
- Only roster participants using their own clients may establish direct target finality or release verified ballot inputs and evaluation messages after finality.
- Participant action state is bound to one browser profile. There is no backup, export, migration, or replacement-device continuation. Lost or unverifiable state retires that participant from the affected action.
- Long operations require authenticated checkpoints at deterministic safe boundaries. Correctness cannot depend on wake locks, hidden-page execution, lifecycle callbacks, or final worker notification.
- Cryptographic randomness comes from browser-local platform randomness and is durably retained before publication. Byte-identical resume reuses the retained value; deterministic action derivation is not a freshness or rollback proof.
- Every required participant operation remains available through scalar-capable, single-worker mobile-browser WebAssembly without native helpers or stronger-device exceptions.

These properties assume honest delivered application code while secrets are handled, uncompromised honest devices, an accepted participant-confirmed frozen roster, and closure of the issues below.

## Open security issues

These are layered blockers: construction, integration, supported-phone qualification, and activation must all pass independently.

- `SEC-001`: No independent audit, certification, production hardening, or production approval exists.
- `SEC-002`: No exact ten-participant, ten-option preparation-to-release ceremony is implemented and positively verified end to end.
- `SEC-003`: Direct finality and participant-local one-shot state are specified, but persist-before-publish locking, rollback reconciliation, byte-identical replay, and participant-retirement behavior are not implemented and evidenced for every security-sensitive output.
- `SEC-004`: No cryptographic suite is activated. The public package exposes foundation operations only, and component tests cannot authorize production dispatch.
- `SEC-006`: No participant bridge carries verified state from preparation through ballot selection, target finality, input activation, evaluation, and result decoding with authenticated checkpoints.
- `SEC-007`: No production ballot-custody construction is selected or implemented. Availability, authenticated inconsistency handling, censorship privacy, first-honest-release simulation, and positive-verifier integration remain open.
- `SEC-008`: No supported-phone qualification has completed every participant operation in release Chrome on the selected physical phone for the exact scalar package.
- `SEC-017`: Browser-local root-key custody and derivation-count continuity are not closed across the complete cold-start, resume, retirement, and cleanup lifecycle.
- `SEC-019`: No immutable evidence bundle binds the selected construction, reductions, production counters, source, dependencies, and release package bytes.
- `SEC-020`: Long operations do not yet have production-authenticated checkpoints, byte-identical cold restore, maximum lost-work bounds, or forced-termination browser evidence.
- `SEC-021`: No complete browser-storage implementation and evidence set covers quota admission, transaction overlap, amplification, eviction, action-wide mutation, repair, cleanup, and reclamation.
- `SEC-023`: A reduced one-bit/one-AND candidate has an internal conditional paper theorem. Its unexported action-key, private-preparation, complete-preparation, and one-source boundaries now have Rust, scalar-WebAssembly, worker, and durable-state development evidence, but the direct primitive assumptions and complete finality-to-result correspondence remain open. No full tally-preparation or private-evaluation construction is cryptographically admitted, and the implemented verifiers do not yet compose into an admitted protocol.
- `SEC-024`: No construction has passed the complete static resource and external-Chrome lifecycle gates. Measurements of isolated native or Node/WebAssembly components do not qualify a browser ceremony.
- `SEC-027`: The removed randomized-response flow would expose its protected source if complementary responses were obtainable under one pad. A later exact-history audit found that its accepted-opening relation did not make those opposite responses reachable, so the earlier finite cases are not evidence of an executed historical exploit. The route remains rejected and removed because it lacks a complete theorem and is not authorized as a fallback. The replacement direction now has atomic private-opening and source-fixation state, but still lacks finality through terminal correspondence, a complete scalar-WebAssembly vertical, full-tally proof, and mobile qualification.

Identifiers are stable and are not reused. `SEC-005`, `SEC-009` through `SEC-016`, `SEC-018`, `SEC-022`, `SEC-025`, and `SEC-026` are retired.

## Outside the security model

A compromised participant device holds that participant's keys and authority. It can disclose local secrets and send arbitrary messages. The following remain outside the security boundary:

- compromise beyond the active fault bound;
- data already present on a compromised device;
- malicious same-origin application code or platform key storage;
- adaptive-corruption security and post-action compromise security;
- everlasting secrecy, receipt freeness, coercion resistance, and endpoint security;
- denial-of-service resistance, guaranteed availability, or guaranteed output; and
- side-channel resistance, including timing, traffic-analysis, power, cache, and speculative-execution attacks.

Logical deletion and secret-buffer zeroization are required hygiene, but browser storage cannot attest physical erasure. Physical reclamation is measured for storage feasibility, not claimed as post-compromise secrecy.

Protocol safety instead relies on the accepted roster, positive verification, one-shot state, exact target binding, and the stated cryptographic and endpoint assumptions. See the [README](README.md) for the current implementation boundary.
