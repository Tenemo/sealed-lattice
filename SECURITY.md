# Security policy

`sealed-lattice` is an unaudited post-quantum-targeting research prototype. End-to-end security is unestablished, no complete voting construction is exposed, and no released version is approved for production elections or other security-sensitive use. Use synthetic data only.

## Report a vulnerability

Use GitHub private vulnerability reporting when available. If it is unavailable, open a minimal public issue requesting a private contact path without exploit details.

Include:

- the affected package version or commit;
- a minimal reproduction;
- the expected and observed behavior; and
- whether private material may have been exposed.

Do not attach real election data, private keys, ballots, shares, witnesses, authentication material, or unpublished exploit details.

## Intended security model

- The adversary is quantum polynomial time and statically compromises fewer than one third of the frozen roster. For ten participants, at most three are compromised in total; active and passive compromise are one budget.
- The compromised participants and every relay may collude, equivocate, replay, reorder, delay, omit, replace, or withhold messages. Invalid actions are ignored. If too few valid actions remain, the poll stays unresolved.
- Completion assumes eventual delivery among cooperating honest participants. Permanent suppression of every communication path may prevent completion.
- The protocol protects scores, totals, margins, intermediate comparisons, and ranks. Public ballot information is limited to the frozen roster, submission authorship, acceptance, whether any ballot was accepted, and the requested terminal result.
- The organizer may request ballot closing but has no special cryptographic key, inventory choice, tally authority, or result authority.
- Every accepted pre-close ballot must be counted exactly once. Invalid, missing, and late ballots do not count and do not abort the poll.
- The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or any path that bypasses certified target-bound result release.
- For ten participants, seven matching signatures must certify the complete inventory and exact result target before the disappearance guarantee begins. After that boundary, any four valid target-bound release shares must suffice, even after any three participants disappear.
- Missing, stale, inconsistent, or corrupt local state stops that participant. It never enables a retry, replacement, roster change, threshold reduction, alternate target, or unverified result.
- A verified result or no-result transcript must be independently retrievable and verifiable without another participant returning.

These are requirements, not claims about the current package.

## Current implementation boundary

The package implements bounded canonical foundation encodings, context verification, and hashing in Rust/WebAssembly, together with TypeScript poll validation and package integrity checks. It does not implement or expose distributed key generation, ballot encryption, ballot proofs, reliable publication, inventory finality, homomorphic tallying, release shares, or terminal decoding. Any future construction API remains subject to the prohibition on raw decryption, secret export, and bypassing authorized release.

Removed construction formats are not accepted as compatibility inputs or fallback modes. Passing tests for the retained foundation establish only the tested encoding and verification behavior.

## Open security blockers

The current research direction cannot advance beyond research status until all of these are closed for one exact emitted protocol:

- a malicious, dealerless, fixed-roster BFV/BGV setup that creates threshold secret shares and every evaluation key without participant removal or retry;
- reliable ballot publication and an asynchronous close rule that prevents a malicious relay or organizer from selecting the accepted set;
- a publicly verifiable ballot proof for complete `1..10` score vectors with exact QPT extraction and zero knowledge;
- deterministic encrypted ranking that reveals only the requested option identifiers and has exact FHE correctness and security parameters;
- publicly verifiable, chosen-ciphertext-safe release shares for only the certified target, with any four valid shares reconstructing identically;
- one chronological composition argument covering setup, publication, proofs, encryption, finality, release, forks, replay, and unresolved behavior in a consistent QPT model;
- concrete security and failure accounting meeting the end-to-end target;
- production-derived resource, storage, restart, and visit bounds for scalar browser WebAssembly;
- independent cryptographic review; and
- release-Chrome qualification on the selected physical phone using the identical admitted package bytes.

A lattice or hash primitive does not make the composed protocol post-quantum secure by itself. Native, Node.js, desktop-browser, arithmetic, and reference-library results are development evidence only.

## Outside the security model

The security target does not cover:

- later or adaptive compromise;
- compromised participant devices or malicious delivered application code;
- data already available on a compromised device;
- coercion resistance, receipt freeness, real-world identity verification, or duplicate-person prevention;
- complete browser-profile copying or coherent rollback;
- every side channel, including traffic analysis, timing, power, cache, and speculative execution; or
- guaranteed availability when all communication paths are permanently suppressed.

Logical deletion and secret-buffer zeroization are required hygiene, but browser storage cannot attest physical erasure. Supported-phone qualification, when eventually completed, will apply only to the recorded phone, operating system, release-Chrome version, origin, package bytes, and preconditions.
