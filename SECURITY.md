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

- For a frozen roster of `n` participants, let `f = floor((n - 1) / 3)`, the largest whole number below one third of `n`. The adversary is quantum polynomial time and statically compromises at most `f` participants in total; active and passive compromise are one budget.
- The security argument may model SHAKE as an ideal random function and rely on the standard assumptions of the NIST post-quantum algorithms it uses. These are stated assumptions; every other assumption remains an open gap until it is reduced or removed.
- The compromised participants and every relay may collude, equivocate, replay, reorder, delay, omit, replace, or withhold messages. Invalid actions are ignored. If too few valid actions remain, the poll stays unresolved.
- Completion assumes eventual delivery among cooperating honest participants and that published records remain retrievable through at least one path after their authors leave. Permanent suppression of every communication path may prevent completion.
- The protocol protects scores, totals, margins, intermediate comparisons, and ranks. Public ballot information is limited to the frozen roster, submission authorship, signed ballot times, the close time, which participants reported holding each submission, acceptance, whether enough ballots were accepted for a result, and the requested terminal result.
- The organizer may request ballot closing, sets its public close time, and proposes the closed inventory from participants' close responses. It has no special cryptographic key, tally authority, or result authority, and its choice of close responses is limited to the bounded omission below.
- When a result is released, every accepted ballot must be counted exactly once. Invalid, missing, and late ballots do not count and do not abort the poll. A ballot is late when its signed ballot time is after the close time. The organizer can choose a close time earlier than the moment it closes, which excludes every ballot timed after it; the close time is public, but this cannot be prevented. An honest voter whose clock runs ahead can also be classified late.
- Closing completes once `n-f` participants, including the organizer, have sent close responses, so up to `f` participants in total who leave, lose their state, or refuse cannot block it. When `f` is zero, closing needs every participant, as the inventory certificate already does. The cost is bounded omission: up to `f` on-time ballots can be left out, by a malicious relay, alone or with the organizer, or by ordinary delays, and only ballots kept from every participant whose response is used. A ballot held by at least `f+1` honest participants, or by an honest organizer, when they respond is always included. Each affected voter is shown that its ballot was not included but cannot prove who omitted it.
- A result is released only when at least `f+2` ballots are accepted. At most `f` accepted ballots can be the adversary's, so every result combines at least two honest ballots and cannot isolate one voter's ranking. The cost is that a malicious relay working with compromised participants who do not vote can push a poll below that minimum and force the no-result outcome; when `n = 3f + 1`, this works even if every honest participant votes.
- The application and library must not expose raw ballot, total, or intermediate-value decryption, participant-secret export, or any path that bypasses certified target-bound result release.
- Before the disappearance guarantee begins, `n-f` matching signatures must certify the closed inventory and exact result target. After that boundary, any `max(f+1, 2)` valid target-bound release shares must suffice, even after any `f` participants disappear, and no single participant can decrypt anything.
- Missing, stale, inconsistent, or corrupt local state stops that participant. It never enables a retry, replacement, roster change, threshold reduction, alternate target, or unverified result.
- A verified result or no-result transcript must be independently retrievable and verifiable without another participant returning.

These are requirements, not claims about the current package.

## Current implementation boundary

The package implements bounded canonical foundation encodings, context verification, and hashing in Rust/WebAssembly, together with TypeScript poll validation and package integrity checks. It does not implement or expose distributed key generation, ballot encryption, ballot proofs, ballot closing, inventory finality, homomorphic tallying, release shares, or terminal decoding. Any future construction API remains subject to the prohibition on raw decryption, secret export, and bypassing authorized release.

Removed construction formats are not accepted as compatibility inputs or fallback modes. Passing tests for the retained foundation establish only the tested encoding and verification behavior.

## Open security blockers

The current research direction cannot advance beyond research status until all of these are closed for one exact emitted protocol:

- a malicious, dealerless, fixed-roster BFV/BGV setup that creates threshold secret shares and every evaluation key without participant removal or retry;
- an asynchronous close rule that completes from the close responses of any `n-f` participants including the organizer and limits a malicious relay or organizer to the bounded omission above;
- a publicly verifiable ballot proof for complete `1..10` score vectors with exact QPT extraction and zero knowledge;
- deterministic encrypted ranking that reveals only the requested option identifiers and has exact FHE correctness and security parameters;
- publicly verifiable, chosen-ciphertext-safe release shares for only the certified target, with any `max(f+1, 2)` valid shares reconstructing identically;
- one chronological composition argument covering setup, publication, proofs, encryption, finality, release, forks, replay, and unresolved behavior in a consistent QPT model;
- concrete security and failure accounting meeting the end-to-end target;
- production-derived resource, storage, restart, and visit bounds for scalar browser WebAssembly;
- independent cryptographic review; and
- release-Chrome qualification on the selected physical phone using the identical admitted package bytes.

A lattice or hash primitive does not make the composed protocol post-quantum secure by itself. Native, Node.js, desktop-browser, arithmetic, and reference-library results are development evidence only.

## Outside the security model

The security target does not cover:

- later or adaptive compromise;
- compromised devices beyond the compromised participants above, or malicious delivered application code;
- data already available on a compromised device;
- coercion resistance, receipt freeness, real-world identity verification, or duplicate-person prevention;
- complete browser-profile copying or coherent rollback;
- every side channel, including traffic analysis, timing, power, cache, and speculative execution; or
- guaranteed availability when all communication paths are permanently suppressed.

Logical deletion and secret-buffer zeroization are required hygiene, but browser storage cannot attest physical erasure. Supported-phone qualification, when eventually completed, will apply only to the recorded phone, operating system, release-Chrome version, origin, package bytes, and preconditions.
