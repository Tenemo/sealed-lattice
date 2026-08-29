# Security policy

`sealed-lattice` is an unaudited research prototype. The open issues below prohibit real elections and other security-sensitive use. Use synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without including exploit details.

Include the affected package version or commit, a minimal reproduction, the expected property, the observed behavior, and whether private material may have been exposed. Do not attach real election data, private keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported profile

No released version is supported for production use. The completion and qualification target is one scalar package with ten roster participants and ten options. This profile has an active corruption bound of three, a reconstruction threshold of four, and ballot-set, finality, and state-witness quorums of seven.

Schemas and tally-circuit compilers admit rosters and option counts from 3 to 20 and 2 to 20 respectively, but other profiles are structural inputs only. They carry no cryptographic, runtime, or support claim.

The design aims for at least 80 bits of modeled attack work against quantum-capable adversaries under its stated assumptions and limits. That claim has not been established end to end and is not a NIST category, production rating, audit, or certification.

Cryptographic admission and supported-phone qualification are independent results for the same exact bytes. Both are incomplete. Only release Chrome on the selected physical phone can provide supported-phone evidence.

## Security model

- The protocol protects ballot scores, not voter anonymity. The frozen roster, each signed submit-or-abstain declaration, accepted ballot authorship, and whether any selected ballot is usable are public.
- The host handles registration, invitations, organizer workflow, interface behavior, notifications, and visit cadence; participants confirm and freeze the roster. Identity vetting and Sybil resistance remain outside the library. The organizer remains an ordinary roster participant with no special protocol authority.
- Every roster participant contributes to tally preparation. No smaller group, dealer, server, or organizer can complete it.
- The adversary statically corrupts at most three participants and may rush, equivocate, withhold, replay, reorder, fork, or replace messages. A separate passive-exposure game covers at most three disclosed shares; the two bounds are not combined.
- Transcript, mailbox, and storage services are untrusted. Silence never means abstention. Missing required input leaves the action pending.
- Positive verification of canonical bytes, source correspondence, signatures, authenticated openings, state, and construction-specific relations determines acceptance. Producer status, signatures alone, raw shares, fixtures, and caller-selected targets confer no authority.
- The selected ballot set is derived from a roster-complete declaration and availability inventory. A quorum cannot choose a different valid subset or authorize an omitted-input opening.
- Only roster participants using their own clients may witness state, authorize the selected set, establish target finality, or release verified ballot inputs and evaluation messages after finality.
- Participant action state is bound to one browser profile. There is no backup, export, migration, or replacement-device continuation. Lost or unverifiable state retires that participant from the affected action.
- Long operations require authenticated checkpoints at deterministic safe boundaries. Correctness cannot depend on wake locks, hidden-page execution, lifecycle callbacks, or final worker notification.
- Cryptographic randomness comes from browser-local platform randomness and is durably retained before publication. Byte-identical resume reuses the retained value; deterministic action derivation is not a freshness or rollback proof.
- Every required participant operation remains available through scalar-capable, single-worker mobile-browser WebAssembly without native helpers or stronger-device exceptions.

These properties assume honest delivered application code while secrets are handled, uncompromised honest devices, an accepted participant-confirmed frozen roster, and closure of the issues below.

## Open security issues

These are layered blockers: construction, integration, browser qualification, and activation must all pass independently.

- `SEC-001`: No independent audit, certification, production hardening, or production approval exists.
- `SEC-002`: No exact ten-participant, ten-option preparation-to-release ceremony is implemented and positively verified end to end.
- `SEC-003`: Roster-witnessed one-shot state is specified, but complete durable witness locking, rollback reconciliation, and participant-retirement behavior are not implemented and evidenced for every security-sensitive output.
- `SEC-004`: No cryptographic suite is activated. The public package exposes foundation operations only, and component tests cannot authorize production dispatch.
- `SEC-006`: No participant bridge carries verified state from preparation through ballot selection, target finality, input activation, evaluation, and result decoding with authenticated checkpoints.
- `SEC-007`: Direct threshold sharing is the retained ballot-custody family, but availability, authenticated inconsistency handling, censorship privacy, first-honest-release simulation, and positive-verifier integration remain incomplete.
- `SEC-008`: No physical-phone Chrome profile has completed every participant operation for the exact scalar package.
- `SEC-017`: Browser-local root-key custody and derivation-count continuity are not closed across the complete cold-start, resume, retirement, and cleanup lifecycle.
- `SEC-019`: No immutable evidence bundle binds the selected construction, reductions, production counters, source, dependencies, and release package bytes.
- `SEC-020`: Generic checkpoint and cursor components exist, but the selected long operations do not all have production-authenticated checkpoints, byte-identical cold restore, maximum lost-work bounds, or forced-termination browser evidence.
- `SEC-021`: Authenticated storage and bounded repair foundations exist, but complete quota admission, transaction overlap, browser amplification, eviction behavior, action-wide mutation enclosure, repair, cleanup, and reclamation evidence remain open.
- `SEC-023`: No tally-preparation or private-evaluation construction satisfies the stated adversary. The retained construction-neutral verifiers do not compose into an admitted protocol.
- `SEC-024`: No construction has passed the complete static resource and external-Chrome lifecycle gates. Measurements of isolated native or Node/WebAssembly components do not qualify a browser ceremony.

Identifiers are stable and are not reused. `SEC-005`, `SEC-009` through `SEC-016`, `SEC-018`, `SEC-022`, `SEC-025`, and `SEC-026` are retired.

## Outside the current model

A compromised participant device holds that participant's keys and authority. It can disclose local secrets and send arbitrary messages. The following remain outside the security boundary:

- compromise beyond the active fault bound;
- data already present on a compromised device;
- malicious same-origin application code or platform key storage;
- adaptive corruption and post-action device compromise;
- everlasting secrecy, receipt freeness, coercion resistance, and endpoint security;
- denial of service and guaranteed availability; and
- timing, traffic-analysis, power, cache, speculative-execution, and other side channels.

Logical deletion and secret-buffer zeroization are required hygiene, but browser storage cannot attest physical erasure. Physical reclamation is measured for storage feasibility, not claimed as post-compromise secrecy.

Protocol safety instead relies on the accepted roster, positive verification, one-shot state, exact target binding, and the stated cryptographic and endpoint assumptions. See the [README](README.md) for the current implementation boundary.
