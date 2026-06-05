# Sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public runtime facade exposes safe-by-default helpers for transcript-core fixture verification; threshold, lifecycle, poll specification, capability, board-consistency, target-finality, roster-manifest, cast receipt, close record, first-valid ordering, and recovery-epoch checks.

It does not expose raw hashing, object mutation, generic cryptography, public ballot generation or casting, direct ballot proof construction, evaluator replay, target acceptance, decryption-share shell checks, decryption, raw BGV operations, proof witnesses, encryption randomness, or protocol internals.
