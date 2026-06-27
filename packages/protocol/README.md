# Protocol package

This package owns deterministic election state, transcript rules, canonical selection, threshold parameters, lifecycle transitions, and public refusal predicates.

The current package establishes the election foundation for the selected direct encrypted ballot path: canonical signed-root verification, board inclusion checks, roster and manifest validation, target finality, recovery-epoch checks, first-valid ordering, foundation transcript verification, lifecycle transitions, refusal predicates, and threshold-parameter derivation.

This is foundation coverage. Full voting workflow boundaries are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw BGV operations, bridge routes, or plaintext oracle helpers.
