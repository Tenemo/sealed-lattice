# Sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public runtime facade exposes safe-by-default helpers for transcript-core fixture verification; threshold, lifecycle, poll specification, capability, board-consistency, target-finality, roster-manifest, foundation transcript, cast receipt, close record, first-valid ordering, and recovery-epoch checks.

These helpers verify the direct-route foundation transcript only. The integrated foundation fixture verifies through this public package in Node and browser, with structured negative fixtures and Rust/WASM canonical root parity under a foundation-only profile.

It does not expose raw hashing, object mutation, generic cryptography, public ballot generation or casting, direct ballot proof construction, evaluator replay, target acceptance, decryption-share shell checks, decryption, raw BGV operations, proof witnesses, encryption randomness, legacy bridge or evaluation-proof routes, or protocol internals. Full-protocol `verifyTranscript` remains fail-closed until the later direct-path gates exist.
