# Security policy

`sealed-lattice` is an unaudited research prototype. The open issues below
prohibit its use for real elections or other security-sensitive activity. Use
synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable,
open a minimal public issue requesting a private contact path without including
exploit details.

Include the affected package version or commit, a minimal reproduction, the
expected property, the observed behavior, and whether private material may have
been exposed. Do not attach real election data, private keys, ballots, shares,
witnesses, or unpublished exploit material.

## Supported profile

No released version is supported for production use. The sole current
cryptographic, integration, performance, and supported-phone evidence target is
one exact build with `n = 10` roster participants and `optionCount = 10`
options. It derives:

- active Byzantine bound `f = 3`;
- share-reconstruction threshold `r = 4`; and
- finality and state quorums of seven.

Schemas admit rosters in `3..20` and option counts in `2..20`, but other
profiles are structurally admitted only and carry no security or runtime claim.

Cryptographic completion and supported-phone qualification are independent
results for the same exact bytes. Both are currently incomplete. The sole phone
qualification target is Chrome on the selected physical phone. Native Rust,
Node.js, desktop Chromium, emulated devices, and partial phone runs are
development evidence only.

## Security model and required boundary

- The protocol protects ballot secrecy, not voter anonymity. The frozen roster
  and accepted ballot authorship are public.
- Identity vetting, enrollment, reusable invitations, organizer workflow,
  interface behavior, notifications, and visit cadence belong to the host
  application. The protocol provides roster binding and auditability, not Sybil
  resistance.
- The host designates exactly one organizer from the frozen roster. That person
  is an ordinary trustee and eligible voter, may submit no ballot, and gains no
  special key, proof bypass, quorum weight, finality power, or decryption
  authority. The organizer designation is not a protocol input.
- All ten trustees complete collective setup before any ballot can use the
  collective public and evaluator keys. A smaller privileged setup group is not
  permitted.
- The active adversary statically corrupts at most three trustees. The separate
  passive-share-exposure game covers at most three disclosed trustee shares;
  those bounds are not added into a larger active coalition.
- Transcript, private-mailbox, and storage services are untrusted. They may
  censor, delay, reorder, duplicate, fork, or replace bytes, but acceptance
  depends on canonical encoding, recomputed hashes and roots, signatures,
  proofs, and externally anchored manifest and roster data.
- Only roster participants acting through their own clients may witness state,
  establish finality, or release target-bound shares. There is no trusted tally
  server, organizer finalizer, external witness, remote prover, or remote
  verifier.
- Verification is positive: only a completed verifier result may mint a
  capability. Producer status fields, test oracles, transport validation,
  fixtures, and self-consistent records never establish acceptance.
- Finality authorizes exactly one result target. Every decryption share and
  proof binds to that target, and no accepted interface may decrypt ballots,
  aggregate scores, margins, comparison bits, ranks, evaluator intermediates, or
  other broader results.
- Participant action state is bound to one browser profile. There is no backup,
  export, migration, or replacement-device continuation. Missing, corrupt,
  stale, or unauthenticated state retires that participant from the action.
- Long operations proactively commit authenticated checkpoints at deterministic
  safe boundaries. Correctness cannot depend on a wake lock, hidden-page
  execution, lifecycle callback, or final worker notification.
- Durable storage must account atomically for committed, staged, and orphanable
  bytes, reserve repair headroom, qualify persistence and eviction behavior, and
  reconcile local state with an external recency anchor before treating it as
  newest.
- Ballot and proof randomness comes only from the browser-local platform
  cryptographic random-number generator and domain-separated protocol
  derivation. A distinct attempt always requires fresh randomness.
- Every required participant operation remains in that participant's mobile
  browser and scalar-capable WebAssembly path. A desktop, native helper, trusted
  server, or stronger device cannot substitute for it.

These claims assume honest delivered application code, uncompromised participant
devices, an accepted externally vetted roster, and closure of the cryptographic
and implementation issues below.

## Open security issues

| Identifier | Open limitation                                                                                                                                                                                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SEC-001`  | No independent audit, certification, or production hardening exists. Every result remains prototype evidence.                                                                                                                                                        |
| `SEC-002`  | No exact ten-participant, ten-option setup-to-release ceremony is implemented and accepted end to end.                                                                                                                                                               |
| `SEC-003`  | Participant state has no recovery or independently certified newest-snapshot mechanism. Lost or unverifiable state permanently removes that participant from the action.                                                                                             |
| `SEC-004`  | No production proof backend is selected. The compiler derives 12 families, 103 physical applications, and 159 logical relation instances, but eleven compact family contracts, the complete hostile corpus, theorem and privacy composition, release-WebAssembly path, and browser lifecycle remain open. The rejected backend cannot satisfy any gate. |
| `SEC-005`  | The native source-verified compact public-key terminal retains the exact canonical proof size and emitted-byte census only after transport, full algebraic verification, and independent source correspondence. Its independent fixed-output tape replay covers all 82 logical rounds, 181,440 predecessor-linked output-block calls, and 11,612,160 raw tape bytes, but does not establish the quantum domain-extension reduction. Emitted-byte zero knowledge, salted-Merkle privacy, proof-to-random-oracle composition, the fixed-tape shared-quantum-random-oracle premise, the initial-transition lemma, and complete probability accounting remain open. No security-bit total is authorized. |
| `SEC-006`  | The participant bridge does not yet carry verifier-minted capabilities and authenticated checkpoint custody from setup through release.                                                                                                                              |
| `SEC-007`  | Direct ballot creation, proof generation, transport, and acceptance are incomplete. Ballots remain gated on `VerifiedSetup`; no provisional or pre-ratification ballot path is authorized.                                                                           |
| `SEC-008`  | No physical-phone Chrome profile has completed every participant operation.                                                                                                                                                                                          |
| `SEC-010`  | Homomorphic-encryption, verifiable-secret-sharing, and proof parameters remain provisional. The canonical candidate currently uses three data primes per key-switch block and three ordered special primes; it is internally consistent but lacks a complete reviewed joint-exposure reduction. |
| `SEC-011`  | Evaluation-key material relies on circular or key-dependent-message assumptions, and malicious collective-setup composition remains incomplete.                                                                                                                      |
| `SEC-016`  | Target-bound release lacks its complete production proof, correctness and privacy closure, participant finality producer, checkpoint lifecycle, and public workflow.                                                                                                 |
| `SEC-017`  | Caller-key storage adapters do not safely support equivalent-key reimport or reuse across runtime lifecycles.                                                                                                                                                        |
| `SEC-018`  | The tracked collective-setup record establishes internal consistency only; its authority and packet chronology are not independently derived and it cannot mint a capability or select a suite.                                                                      |
| `SEC-019`  | A test-only construction fingerprint and independently recomputed input inventory bind the current unactivated suite, all 12 relation families, application multiplicities, and the one available compact contract. Readiness fails closed on the eleven missing contracts and missing complete scalar release-WebAssembly proof ABI, so no candidate evidence identity is frozen. |
| `SEC-020`  | Proof execution lacks complete dedicated-worker loss, bounded synchronous work, browser-memory, release-WebAssembly, exact-byte restore, and browser-custody evidence.                                                                                               |
| `SEC-021`  | Browser storage lacks complete incremental capacity accounting, atomic lifecycle counters, repair headroom, bounded resumable repair, persistence admission, quota and eviction qualification, external rollback detection, and physical-reclamation reconciliation. |

Identifiers are stable and are not reused. `SEC-009` and `SEC-012` through
`SEC-015` are retired.

## Outside the current model

A compromised participant device holds that participant's keys and authority. It
can disclose local secrets and send arbitrary messages; local locks and storage
checks cannot make it honest. The following are outside the current security
boundary:

- compromise beyond the active fault bound;
- data already present on a compromised device;
- malicious same-origin application code or platform key storage;
- adaptive corruption and post-action device compromise;
- everlasting secrecy, receipt freeness, coercion resistance, and endpoint
  security;
- denial of service and guaranteed availability; and
- timing, traffic-analysis, power, and other side channels.

Protocol safety instead relies on verified proofs, accepted-board rules,
one-shot state, and the stated threshold and endpoint assumptions. See the
[README](README.md) for the current implementation boundary.
