# Security policy

`sealed-lattice` is a research prototype. It has not been independently
audited, certified, or approved for production elections. Do not use it with
real ballots, credentials, keys, or other secret material.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is
unavailable, open a minimal public issue requesting a private contact path
without including exploit details.

Include the affected package version or commit, a minimal reproduction, the
expected property, the observed behavior, and whether secret material or
private data may have been exposed. Do not attach real election data, private
keys, ballots, shares, witnesses, or unpublished exploit material.

## Supported versions

No release is supported for production election use. Security fixes target
the active repository and the current published package line.

The sole completion and evidence target is an exact `n = 10` roster with
fault bound `f = 3`, reconstruction threshold `r = 4`, and finality and state
quorums of seven. Roster and suite schemas cover sizes `3..20`, but every
other size is unsupported and carries no security claim.

## What this prototype does not provide

- Production readiness. There is no independent audit, certification,
  hardening, or production ballot-secrecy claim.
- Complete proof-system assurance. The implemented proof paths have no
  theorem-matched application extractor, no ceremony-wide zero-knowledge and
  leakage bound, and no quantum-random-oracle work-factor result. Treat a
  passing proof as development verification, not cryptographic assurance.
- Reviewed parameter security. The homomorphic-encryption parameters and the
  lattice commitment instance are provisional candidates; no reviewed
  assessment covers the exact lattice problems and relevant attack classes.
- Assumption-free setup. Evaluation-key material relies on the selected
  construction's circular-security assumptions, and collective setup has not
  been shown secure against malicious participants end to end.
- An end-to-end vote path. Existing evidence covers separately tested
  components (setup, ballots, aggregation, encrypted evaluation, target
  release); no exact `n = 10` suite is frozen, and the public package exposes
  neither target-share generation nor result release.
- Mobile support. There is no supported-phone runtime evidence;
  desktop-browser, Node.js, native, and fixture-backed runs are development
  evidence only.

## Boundaries you must respect

- Use synthetic data only.
- Participant state is bound to one phone and browser profile, with no
  backup, export, migration, or replacement-device flow. Missing, corrupt, or
  unauthenticated state permanently removes that participant, and acting from
  a restored older snapshot marks a participant faulty. If the remaining
  participants no longer satisfy a required threshold, abort and start a new
  vote with a fresh action context and fresh secret material.
- The `n = 10` profile assumes at most three actively faulty participants.
- Transcript and mailbox services are untrusted relays that only move bytes.
  Acceptance must come from canonical encodings, recomputed hashes and roots,
  signatures, verified proofs, and an externally anchored manifest and roster.
- Quorum witnesses are other roster participants acting through their own
  clients; no external witness, trusted service, or finalizer is allowed.
- Release is one-shot: a finality quorum authorizes exactly one target
  result, and every decryption share and proof must bind to that result.

## Correct use

- Import only from the published `sealed-lattice` package root; workspace
  packages, fixtures, and test helpers are unsupported.
- Never expose shares, secret keys, encryption or proof randomness, proof
  witnesses, or local secret state, and never decrypt individual ballots or
  intermediate ciphertexts.
- Generate proof-randomness seeds with a platform CSPRNG, keep them private,
  and never reuse them across proof attempts.
- Anchor the manifest and roster outside untrusted transcript data, and
  require positive verification of encodings, hashes, roots, signatures, and
  proofs instead of producer-supplied labels.
- Treat lost or unauthenticated participant state as terminal. Do not install
  transported state or recreate empty state under the same action identity.
- Keep every participant operation in the participant's own mobile browser;
  never substitute a desktop, native helper, server, or remote prover.

A compromised participant device holds that participant's keys and authority:
it can disclose local secrets and send arbitrary messages, and local locks and
storage checks cannot make it honest. Protocol safety relies on verified
proofs, accepted-board rules, and the modeled bound of at most three faulty
participants. Compromise beyond that bound, data already on a compromised
device, malicious same-origin code, compromised platform key storage, denial
of service, and side channels are outside the current security boundary.
