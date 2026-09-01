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
- `SEC-002`: An exact ten-participant, ten-option preparation-to-release experiment passed functional development checks, but a fresh cryptographic review rejected its private-evaluation layer because public label metadata exposes intermediate circuit values and action-wide continuation secrets expose counterfactual branches. The rejected activation and evaluation implementation has been removed. No complete replacement has passed cryptographic admission, release-browser lifecycle closure, or selected-phone qualification.
- `SEC-003`: The removed experiment implemented persist-before-publish source, finality, activation, and terminal state with byte-identical replay and conflict refusal. Those historical state properties do not repair the evaluation privacy failure. Construction-neutral durable preparation, source, finality, and direct all-abstain no-result state remain as unadmitted research components. Action-wide rollback reconciliation, eviction, quota failure, retirement, cleanup, and release-browser evidence also remain incomplete.
- `SEC-004`: No cryptographic suite is activated. The public package exposes foundation operations only, its separately built WebAssembly artifact has no construction dispatcher, and component tests cannot authorize production dispatch.
- `SEC-006`: The live worker stops at source fixation and self-contained target finality, with a separate certificate-verified all-abstain no-result terminal. Finality binds the exact action, compiler, circuit, output, source, activation, and direct-finality identities, and its verifier recomputes the ordered signer roster before returning carrier-independent capability data. Both the earlier segmented evaluator and the attempted per-basis operation-fresh conjunction replacement are removed. The latter exposed degree-three affine evaluations through publicly decryptable high-basis translation rows, enabling same-gate counterfactual continuation-key recovery. Internal dispatcher commands exercise one fixed, synthetic joint-aggregate reduced fallback whose exact conditional theorem and Rust/scalar-WebAssembly bytes passed independent hostile review. That relation is not exported, durable, authorized as a tally result, or a complete admitted protocol. There is no admitted public end-to-end capability chain.
- `SEC-007`: No production ballot-custody construction is selected. The internal experiment implements full-score source fixation and positive-verifier integration, but source privacy, corrupt extraction, losing-fork simulation, direct assumptions, and production lifecycle remain original open obligations. They do not inherit a theorem from the rejected evaluation layer.
- `SEC-008`: No supported-phone qualification has completed every participant operation in release Chrome on the selected physical phone for the exact scalar package.
- `SEC-017`: Browser-local root-key custody and derivation-count continuity are not closed across the complete cold-start, resume, retirement, and cleanup lifecycle.
- `SEC-019`: No immutable evidence bundle binds the selected construction, reductions, production counters, source, dependencies, and release package bytes.
- `SEC-020`: The rejected segmented evaluator has authenticated durable checkpoints and byte-identical cold restore in native and development-browser ceremonies. This is historical state evidence only. A replacement must re-establish checkpoint noninterference, maximum lost work, forced termination behavior, and release-browser and phone evidence.
- `SEC-021`: No complete browser-storage implementation and evidence set covers quota admission, transaction overlap, amplification, eviction, action-wide mutation, repair, cleanup, and reclamation.
- `SEC-023`: The rejected emitted full tally published a zero-label semantic bit for each local label pair. Because the evaluator also received the active label, it could decode every intermediate coordinate and interpolate private conjunction values. This deterministic classical transcript attack invalidated the experiment's former conditional one-AND and full-circuit privacy arguments without breaking its PKE, hashes, AEAD, labels, or state. The exact evaluation instantiation is rejected and removed. Its former command range and durable object kinds are reserved tombstones, and old affine-bearing preparation and source records are not accepted under the replacement record versions.
- `SEC-024`: The removed experiment had a production-object static ledger and a development-Chromium ceremony, including transfer, refetch, checkpoint, protected-record, worker-copy, WebAssembly-memory, scalar-work, visit, and foreground measurements. Its activated browser result case used the shortest result width; maximum-width activation completed natively, while the maximum-width browser case was all abstention and did not evaluate the tally. The browser harness also emulated all participant stores with multiple workers in one process. Its accounted JavaScript/WebAssembly overlap was not total browser-process memory. The rejected resource model and ceremony are no longer executable; their historical values cannot be applied mechanically to a replacement. A complete maximum-width scalar-browser result, production resources, external release-Chrome behavior, and selected-phone feasibility are open.
- `SEC-027`: The removed randomized-response flow would expose its protected source if complementary responses were obtainable under one pad. A later exact-history audit found that its accepted-opening relation did not make those opposite responses reachable, so the earlier finite cases are not evidence of an executed historical exploit. The route remains rejected and removed because it lacks a complete theorem and is not authorized as a fallback. The later semantic-map direction also has a full internal scalar-WebAssembly vertical but is rejected by `SEC-023`; neither route is a fallback.
- `SEC-028`: The removed evaluator reused one affine continuation pair for every conjunction in an action. Its public gate polynomials satisfy `H_g=A+Y_gB`; any two distinct public `Y` values recover `B` by exact polynomial division and then recover `A`, even if their selector constants are equal. Observing both selector values is a simpler corollary. Including the gate ordinal in the hash input separated ciphertext domains but did not make the underlying keys gate fresh. Any retained continuation design needs operation-fresh secret material and a complete serial, fan-out, multi-output, and full-tally privacy theorem.
- `SEC-029`: The removed implementation derived all garbling labels from one 32-byte activation seed, while the working hidden-label analysis assumed independent labels. This is not a demonstrated attack on the already rejected transcript, but it is an independent theorem-to-bytes mismatch. A replacement must either sample and durably retain independent labels or prove an exact static-QPT keyed-generator and fixed-function result for the emitted correlated label corpus.
- `SEC-031`: The removed operation-fresh replacement split each affine translation into independently label-masked bit-basis rows. The evaluator could decrypt every selected row with the corresponding public active label. Four masked coordinates outside `{0,1}` exposed enough degree-three affine evaluations to recover the opposite continuation key at the same gate and decrypt both refreshed-label alternatives. This is a classical transcript attack; signatures, commitments, fresh keys, independent labels, and wrong-key tags do not repair it. Any future selected-label relation must expose only its selected aggregate and pass same-gate public-transcript extraction review before composition.
- `SEC-032`: The leading paper candidate pads each selected basis value with an independent pairwise-derived module value, derives continuation material separately for every gate and receiver, samples direct 320-bit labels, and uses KMAC256 row pads without publishing a label-corpus digest or refreshed-wire map. Its finite-field relations and first-order byte, work, and five-visit formulas passed a hostile paper screen, but this is not cryptographic admission. The exact multi-output fixed-Keccak and AES games, preparation and 400-bit source composition, ML-DSA/ML-KEM wrappers, durable allocation and rollback behavior, complete tally, hostile relay ceremony, emitted advantage ledger, external browser, and mobile evidence remain open.

Identifiers are stable and are not reused. `SEC-005`, `SEC-009` through `SEC-016`, `SEC-018`, `SEC-022`, `SEC-025`, `SEC-026`, and `SEC-030` are retired.

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
