# Protocol package

This package owns deterministic election state, transcript rules, canonical
selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current release establishes the election foundation with private crypto
package-backed canonical signed-root verification, board-root-bound inclusion
checks, roster, manifest, receiver-key, and trustee-setup shells, 5-of-7 target
finality, recovery-epoch checks, validated first-valid ordering, and internal
test-mode PVSS ballot algebra over `GF(65537)`.

The PVSS ballot algebra is not a public ballot API. The package now also carries
the internal ballot privacy profile and bound-certificate freeze for the future
receiver-encryption and ballot-proof relation, but it does not implement proof
generation, proof verification, BGV-RNS arithmetic, MHE setup, user-requested
local replay generation, mandatory evaluation-proof verification, semantic
target acceptance, target-bound decryption, or decryption-share proofs.
