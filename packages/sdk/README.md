# Sealed-lattice public package

This package is the only published npm surface in the workspace.

The current public runtime facade exposes safe-by-default helpers for transcript-core fixture verification; threshold, lifecycle, poll specification, capability, board-consistency, target-finality, roster-manifest, cast receipt, close record, first-valid ordering, and recovery-epoch checks; and verification-oriented ballot privacy APIs for receiver-key proofs, ballot proof records, and scoped relation-bearing encoded-score ballot packages. It does not expose raw hashing, object mutation, generic cryptography, public ballot generation or casting, proof construction, local replay record checks, semantic target acceptance, decryption-share shell checks, decryption, or protocol internals.
