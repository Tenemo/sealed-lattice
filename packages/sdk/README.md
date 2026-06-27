# sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public facade exposes development helpers for poll validation, threshold derivation, lifecycle and capability checks, foundation transcript checks, target-finality checks, recovery/device epoch checks, first-valid ordering, and narrow setup-development verification.

Complete voting workflows and security boundaries are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw cryptography, object mutation helpers, generic VSS APIs, raw BGV operations, proof witnesses, encryption randomness, raw VSS shares, plaintext oracles, bridge routes, or protocol internals.
