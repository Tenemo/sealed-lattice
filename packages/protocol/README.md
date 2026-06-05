# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current package establishes the election foundation for the direct encrypted ballot route: canonical signed-root verification, board-root-bound inclusion checks, roster and manifest validation, trustee setup entries, target finality, recovery-epoch checks, validated first-valid ordering, lifecycle/refusal labels, and threshold-profile derivation.

The package does not expose ballot generation, proof construction, evaluator replay, target-bound decryption, raw BGV operations, or plaintext oracle helpers. Those remain internal while the direct encrypted ballot implementation is completed and claim boundaries are kept explicit.
