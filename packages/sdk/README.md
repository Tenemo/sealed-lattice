# Sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public runtime facade exposes the safe transcript core fixture
verifier plus the threshold, lifecycle, poll specification, capability,
board-consistency, target-finality, roster-manifest, cast receipt, close
record, first-come ordering, and recovery-epoch helpers. It does not expose raw
hashing, object mutation, generic cryptography, ballots, replay-attestation
shell checks, semantic target acceptance, decryption-share shell checks,
decryption, or protocol internals.
