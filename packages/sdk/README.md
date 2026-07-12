# sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public facade exposes canonical board ingestion, poll validation, structural threshold-count calculation, roster and recovery helpers, first-valid ordering, setup-development verification, and staged target-bound decryption helpers.

It is a development surface, not a complete end-to-end voting workflow or a certification of supported-phone runtime behavior. Current workflow and security boundaries are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw cryptography, bridge routes, or protocol internals.
