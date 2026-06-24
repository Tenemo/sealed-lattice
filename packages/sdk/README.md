# sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public facade exposes development verification helpers for poll validation, threshold derivation, lifecycle and capability checks, board and foundation transcript checks, target-finality checks, recovery/device epoch checks, first-valid ordering, and narrow setup-development verification.

The package is not a complete voting API. Complete setup, ballot generation, casting, encrypted aggregation, evaluator replay, target-bound decryption, and result release remain unavailable until the matching implementation and verification work is complete.

It does not expose raw cryptography, object mutation helpers, generic VSS APIs, raw BGV operations, proof witnesses, encryption randomness, raw VSS shares, plaintext oracles, bridge routes, or protocol internals. Full-protocol `verifyTranscript` remains fail-closed until the complete workflow exists.
