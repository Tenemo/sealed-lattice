# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold profiles, lifecycle labels, and public refusal predicates.

The current package establishes the election foundation for the direct encrypted ballot route: canonical signed-root verification, board-root-bound inclusion checks, roster and manifest validation, trustee setup entries, target finality, recovery-epoch checks, validated first-valid ordering, integrated foundation transcript verification, lifecycle/refusal labels, and threshold-profile derivation.

This is foundation coverage, not full election verification. The public SDK verifies one deterministic integrated direct-route foundation transcript in Node and browser, rejects integrated mutation fixtures, and matches the packaged Rust/WASM canonical roots for that fixture under a foundation-only profile.

The package does not expose ballot generation, proof construction, evaluator replay, target-bound decryption, raw BGV operations, legacy bridge or evaluation-proof routes, or plaintext oracle helpers. Those remain internal while the direct encrypted ballot implementation is completed and claim boundaries are kept explicit.
