# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current release establishes the election foundation with private crypto package-backed canonical signed-root verification, board-root-bound inclusion checks, roster, manifest, receiver-key, and trustee-setup shells, 5-of-7 target finality, recovery-epoch checks, validated first-valid ordering, internal test-mode PVSS ballot algebra over `GF(65537)`, and the encoded-score ballot privacy verification path.

The PVSS ballot algebra is not a public ballot API. The package now carries the internal ballot privacy profile, receiver-encryption and share-commitment relation, proof-record binding, scoped relation-bearing encoded-score package verification, and the M6 aggregate derivation component relation for the supported ballot privacy dimension policy: 2 to 20 options, 20 to 50 safe participants, and 3 to 19 participants only with explicit unsafe small-roster acknowledgement. It does not implement BGV-RNS arithmetic, MHE setup, the encoded aggregate bridge or score-bit input relation, user-requested local replay generation, mandatory evaluation-proof verification, semantic target acceptance, target-bound decryption, or decryption-share proofs.
