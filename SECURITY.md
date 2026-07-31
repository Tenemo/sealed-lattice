# Security policy

`sealed-lattice` is a research prototype. The open issues below prohibit its
use for real elections or other security-sensitive activity.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is
unavailable, open a minimal public issue requesting a private contact path
without including exploit details.

Include the affected package version or commit, a minimal reproduction, the
expected property, the observed behavior, and whether secret material or
private data may have been exposed. Do not attach real election data, private
keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported versions and profile

No release is supported for production election use. Security fixes target
the active repository and the current published package line.

The sole implementation and evidence target is the reduced-assurance `n = 10`
research profile. It has fault bound `f = 3`, reconstruction threshold `r = 4`,
and finality and state quorums of seven. Other roster sizes are unsupported and
carry no security claim. No release currently satisfies the intended profile
end to end.

## Open security issues

| ID        | Open issue                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Current consequence                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `SEC-001` | The project has no independent audit, certification, or production hardening.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | It has no production security or ballot-secrecy claim.                                                     |
| `SEC-002` | The exact suite and complete participant-operated path through finality and release are unfinished.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | No complete ceremony or released result is currently supported.                                            |
| `SEC-003` | Participant state is bound to one browser profile, with no backup, migration, replacement-device flow, or local proof that a restored snapshot is newest.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Lost or unauthenticated state retires the participant; rollback can make that participant behave faultily. |
| `SEC-004` | The row-code common-proof implementation has static geometry, masking, and complete phase-liveness accounting. Aggregate and bound-tree commitments use bounded stripes, but no full-width production proof or release-WebAssembly browser verification has completed, so the static live-set bound has no exact runtime confirmation.                                                                                                                                                                                                                                                                                                                                                                       | Static theorem and accounting evidence do not establish an operational proof path.                         |
| `SEC-005` | Exact construction-wide classical and quantum-random-oracle soundness are not established. The selected same-secret aggregate-leaf certificate binds the deployed 512-bit frames, proves semantic predecessor closure, and derives its collision arithmetic; the phase-row generator certificate also binds its 512-bit private seeds and exact rejection ledger. Independent production correspondences now bind both the aggregate-wide affine views and the pre-aggregate physical phase, quotient, bound-opening, authority, dependency, and row-pad-rank graph. Checked structural certificates cover all 31 production identities. A complete reduction from these component certificates to the ceremony-level failure allocation and soundness of emitted transported bytes remains open. Family simulation, malicious-verifier zero knowledge, and quantum-random-oracle zero knowledge also remain unproved. | The prototype has no complete common-proof soundness, zero-knowledge, or ballot-privacy claim.             |
| `SEC-006` | Setup, ballots, aggregation, evaluation, finality, and release have only component-level evidence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Component tests do not establish end-to-end confidentiality, correctness, or release security.             |
| `SEC-007` | The direct encrypted-ballot creation, proof, transport, and acceptance path is incomplete.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Real ballots must not be cast, collected, or tallied.                                                      |
| `SEC-008` | No physical-phone and browser combination has completed every required participant operation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Native, Node.js, desktop-browser, emulated, and fixture-backed runs do not establish mobile support.       |
| `SEC-010` | The exact homomorphic-encryption and lattice-commitment parameters remain provisional and lack a reviewed assessment of their complete structured attack surface.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | No concrete security level may be claimed for the candidate suite.                                         |
| `SEC-011` | Evaluation-key material relies on circular or key-dependent-message assumptions, and malicious collective-setup composition is incomplete.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Setup must not be described as assumption-free or malicious-secure.                                        |
| `SEC-016` | Target-bound threshold release lacks its complete production proof, correctness, privacy, and public workflow.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Target decryption shares and released results are not supported.                                           |
| `SEC-017` | Internal caller-key storage adapters do not safely support equivalent-key reimport or reuse across runtime lifecycles.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | They must not replace the root-backed storage path or share key material across accounting lifecycles.     |

## Required security boundary

- Use synthetic data only.
- Participant state is bound to one phone and browser profile, with no
  backup, export, migration, or replacement-device flow. Missing, corrupt, or
  unauthenticated state retires that participant from the current action.
  Local storage does not prove that an internally consistent snapshot is the
  newest one, so restoring an older snapshot may be locally undetectable. If
  it produces a duplicate or conflicting protocol message, the fixed-roster
  quorum rules handle that participant as faulty. If the remaining
  participants no longer satisfy a required threshold, abort the current
  action. Continue only under a new externally authorized action context with
  fresh secret material.
- The `n = 10` profile assumes at most three actively faulty participants.
- Transcript and mailbox services are untrusted relays that only move bytes.
  Acceptance must come from canonical encodings, recomputed hashes and roots,
  signatures, verified proofs, and an externally anchored manifest and roster.
- Quorum witnesses are other roster participants acting through their own
  clients; no external witness, trusted service, or finalizer is allowed.
- Release is one-shot: a finality quorum authorizes exactly one target
  result, and every decryption share and proof must bind to that result.
- Never expose shares, secret keys, encryption or proof randomness, proof
  witnesses, or local secret state, and never decrypt individual ballots or
  intermediate ciphertexts.
- Use only the browser-local platform CSPRNG and the protocol's
  domain-separated derivation for proof randomness. Never inject caller or
  public proof randomness. An authenticated resume may replay only the same
  attempt; every distinct attempt requires fresh randomness.
- Keep every participant operation in the participant's own mobile browser;
  never substitute a desktop, native helper, server, or remote prover.

## Outside the current model

A compromised participant device holds that participant's keys and authority:
it can disclose local secrets and send arbitrary messages, and local locks and
storage checks cannot make it honest. Protocol safety relies on verified
proofs, accepted-board rules, and the modeled bound of at most three faulty
participants. Compromise beyond that bound, data already on a compromised
device, malicious same-origin code, compromised platform key storage, denial
of service, and side channels are outside the current security boundary.
