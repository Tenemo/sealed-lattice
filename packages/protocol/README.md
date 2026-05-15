# Protocol package

This package owns deterministic election state, transcript rules, canonical
selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current release establishes the election foundation with private crypto
package-backed canonical signed-root verification, board-root-bound inclusion
checks, roster, manifest, receiver-key, and trustee-setup shells, 5-of-7 target
finality, recovery-epoch checks, and validated first-valid ordering. It still
does not implement ballots, PVSS, BGV-RNS arithmetic, MHE setup, user-requested
local replay generation, mandatory evaluation-proof verification, semantic
target acceptance, Appendix-C-certified target-bound decryption, or
decryption-share proofs.
