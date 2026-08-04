# Protocol package

This package contains deterministic protocol-development helpers for transcript rules, canonical selection, poll validation, structural threshold-count calculation, roster and manifest checks, setup artifact construction, and browser-local durable-state coordination. Roster-count helpers derive the documented formulas for `3 <= n <= 20`, and the intended manifest boundary admits `2 <= optionCount <= 20`; those structural ranges do not make a non-selected profile supported.

These helpers validate their documented inputs and recompute local bindings, but they do not establish a complete ceremony or certify parameter security, supported-phone runtime behavior, or participant acceptance. The exact `n = 10`, `optionCount = 10` suite and build is the sole prototype completion and evidence target. Other roster sizes remain unsupported. Other option counts in `2..20` are admitted and deterministically compiled but need no generated cryptographic evidence or runtime qualification for current completion. The selected source profile binds ten options. Its current mapped-soundness vector contains exact-ten structural arithmetic and keeps its QROM transform and composition imports unresolved, while other construction, resource, checkpoint, and runtime records still describe the superseded twenty-option candidate. None can freeze the suite. The participant-facing verification components that exist cross the Rust/WASM kernel and the public SDK boundaries described in the root documentation.

The implemented row-code/WHIR proof body is operationally rejected as the
mobile proving direction. A test-only direct-RNS ring candidate map preserves
the complete production family inventory and keeps every accepted BGV object
in its existing RNS representation, but no replacement prover, verifier, wire,
or complete interval theorem exists yet. Its measurement-only 440-bit field
and full degree-`32,768` NTT primitive pass release-WASM Chromium and Firefox,
but that is component evidence rather than a compiled proof or packet runtime.
The row-code mapped-soundness vector and setup imports do not transfer to that
candidate, and neither backend can freeze the suite. The candidate's earlier 255-bit field
is rejected under the active QROM query budget. Exact per-packet polynomial
counts remain uncompiled, and the earlier two-pass opening sketch is
incompatible with the reference challenge order unless openings are retained;
a discarded-opening adapter needs at least three deterministic traversals plus
rejection retries. The complete proof still requires production compilation,
theorem evidence, and release-WebAssembly generation and verification.

Enrollment, identity vetting, invite links, organizer orchestration, user interface, and visit cadence belong to the host application rather than this cryptographic library. A host-side organizer has no distinct cryptographic role or authority.

Browser-local storage authentication and atomicity support honest-client integrity and recovery from interrupted writes. They are not quorum authority, rollback-resistant recency, or target-release authorization. Shared state, finality, and release decisions must be derived from accepted protocol objects and the applicable fixed-roster quorum.

Complete workflow boundaries and current implementation status are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw BGV operations or bridge routes.
