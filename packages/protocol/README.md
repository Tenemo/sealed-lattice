# Protocol package

This package contains deterministic protocol-development helpers for transcript rules, canonical selection, poll validation, structural threshold-count calculation, roster and manifest checks, setup artifact construction, and browser-local durable-state coordination.

These helpers validate their documented inputs and recompute local bindings, but they do not establish a complete ceremony or certify parameter security, supported-phone runtime behavior, or participant acceptance. The participant-facing verification components that exist cross the Rust/WASM kernel and the public SDK boundaries described in the root documentation.

Browser-local storage authentication and atomicity support honest-client integrity and recovery from interrupted writes. They are not quorum authority, rollback-resistant recency, or target-release authorization. Shared state, finality, and release decisions must be derived from accepted protocol objects and the applicable fixed-roster quorum.

Complete workflow boundaries and current implementation status are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw BGV operations or bridge routes.
