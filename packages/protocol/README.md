# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold profiles, lifecycle transitions, and public refusal predicates.

The current package establishes the election foundation for the selected direct encrypted ballot path: canonical signed-root verification, board inclusion checks, roster and manifest validation, target finality, recovery-epoch checks, first-valid ordering, foundation transcript verification, lifecycle transitions, refusal predicates, and threshold-profile derivation.

This is foundation coverage, not full election verification.

The package does not expose setup contribution creation, VSS APIs, ballot generation, proof construction, evaluator replay, target-bound decryption, raw BGV operations, bridge routes, or plaintext oracle helpers. Those remain internal while the public voting API is completed and trust boundaries are kept explicit.
