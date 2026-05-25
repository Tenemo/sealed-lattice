# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current release includes election foundation checks backed by canonical signed-root verification, board-root-bound inclusion checks, roster and manifest shells, receiver-key and trustee-setup shells, target finality, recovery-epoch checks, validated first-valid ordering, test-mode PVSS ballot algebra over `GF(65537)`, and the encoded-score ballot privacy verification path.

The PVSS ballot algebra is not a public ballot API. The package carries the ballot privacy profile, receiver-encryption and share-commitment relation, proof-record binding, scoped relation-bearing encoded-score package verification, and aggregate derivation component relation for the supported ballot privacy dimension policy: 2 to 20 options; the mandatory 20-receiver benchmark profile; dynamic frozen receiver counts from 10 to 50 only with bound roster-profile evidence; and explicitly acknowledged 3 to 9 receiver casual micro-roster verification only outside claim-bearing package acceptance.

The 3 to 9 path has verifier and proof-record generation harness coverage for every receiver count in that range. Current proof-size and runtime benchmark evidence remains limited to the 20-option, 20-participant, threshold-7 profile.

This package does not implement public BGV-RNS arithmetic, MHE setup, the encoded aggregate bridge or score-bit input relation, user-requested local replay generation, mandatory evaluation-proof verification, semantic target acceptance, target-bound decryption, or decryption-share proofs.
