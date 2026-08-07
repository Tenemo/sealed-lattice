# Protocol package

This package contains deterministic protocol-development helpers for transcript rules, canonical selection, poll validation, structural threshold-count calculation, roster and manifest checks, setup artifact construction, and browser-local durable-state coordination. Roster-count helpers derive the documented formulas for `3 <= n <= 20`, and the intended manifest boundary admits `2 <= optionCount <= 20`; those structural ranges do not make a non-selected profile supported.

These helpers validate their documented inputs and recompute local bindings, but they do not establish a complete ceremony or certify parameter security, supported-phone runtime behavior, or participant acceptance. The exact `n = 10`, `optionCount = 10` suite and build is the sole prototype completion and evidence target. Other roster sizes in `3..20` are structurally admitted but remain unqualified and unsupported for cryptographic or runtime use. Other option counts in `2..20` are admitted and deterministically compiled but need no generated cryptographic evidence or runtime qualification for current completion. The selected source profile binds ten options. Its current mapped-soundness vector contains exact-ten structural arithmetic and keeps its QROM transform and composition imports unresolved, while other construction, resource, checkpoint, and runtime records still describe the superseded twenty-option candidate. None can freeze the suite. The participant-facing verification components that exist cross the Rust/WASM kernel and the public SDK boundaries described in the root documentation.

The implemented row-code/WHIR proof body is operationally rejected as the
mobile proving direction. The lattice-PCS replacement is also rejected because
its available extractor and opening lifecycle do not close this protocol's
post-quantum browser path. A test-only compact Goldilocks ring-vector candidate
preserves the complete production family inventory and keeps accepted BGV
objects in their existing RNS representation. The standalone public-key slice
now has a production-derived structured relation and independent interpreter,
two commitment epochs, all CFW inner and outer masks, code-switch and WHIR
static catalogs, canonical proof and public-input codecs, one salted Merkle
commitment per logical response, and complete deterministic test-message query
schedules. The factor-one relaxed extractor, construction-level interactive
masking correspondence, emitted-byte consumer map, and conditional CDHZ/QROM
composition are independently checked. The shared two-epoch mask oracle is
owned once by the canonical response catalog; its two later verifier-message
groups open their sorted unique union through bounded canonical response counts.
These are static development owners, not an accepted proof path.

The current packing-factor proof, provisional WASM-peak, and scratch triples
are `(26,927,670, 385,505,540, 640,811,508)`,
`(26,064,742, 418,112,804, 693,240,308)`,
`(25,415,814, 484,445,268, 798,097,908)`, and
`(25,526,102, 618,845,620, 1,082,414,368)` for factors one, two, four, and
eight. Factors one, two, and four remain below every absolute byte bound.
Factor eight exceeds the scratch bound by `8,672,544` bytes under the complete
retained-tree lifecycle and is not a static default. No factor is selected.
The retained lifecycle keeps at most ten response trees and peaks at
`52,952,832`, `105,381,632`, `210,239,232`, or `419,954,432` bytes. Its
separate root-only alternative needs 18 response replays, but root-only
commitment, authenticated salt replay, and response-value replay remain
unimplemented. That alternative is deferred rather than treated as a way to
rescue factor eight.

The relaxed round-by-round theorem, construction masking correspondence,
canonical emitted-byte map, and conditional noninteractive soundness owner are
closed for this standalone geometry. The 316 schedules derived from complete
deterministic fixed verifier messages are still test-state evidence, not live
prover transcript driving. A reduced production-family chain verifies
transported CFW bytes and sequential hiding-WHIR proofs from one fixed-order
canonical envelope containing the CFW section, five external roots, and both
WHIR sections. A fresh decoder derives every WHIR shape from verifier
configuration, re-encodes the exact bytes, and rejects hostile framing, field,
root, and proof-section mutations. The chain still uses a constant provider,
deterministic development coins, and a separate WHIR challenger. Production
authority, one canonical production transcript, authenticated restart,
selected-size CFW and transpose execution, production transport integration,
and release-WASM browser evidence remain open. After those gates pass, factor
one is the first selected-size execution target; factors two and four
are measured only if verification or transport tradeoffs require them. The
row-code vectors and historical factor-eight root measurement do not transfer
to this construction and cannot freeze the suite.

The first public-key-share proof is a standalone development kill gate. It is
not a fourth outer setup packet. The canonical provisional setup schedule
remains dealer VSS, the combined post-VSS packet containing the public-key-share
relation, and relinearization round two.

Enrollment, identity vetting, invite links, organizer orchestration, user interface, and visit cadence belong to the host application rather than this cryptographic library. A host-side organizer has no distinct cryptographic role or authority.

Browser-local storage authentication and atomicity support honest-client integrity and recovery from interrupted writes. They are not quorum authority, rollback-resistant recency, or target-release authorization. Shared state, finality, and release decisions must be derived from accepted protocol objects and the applicable fixed-roster quorum.

Browser lifecycle may suspend or terminate the owning proof worker without a
usable final callback. Checkpoint-enabled operations therefore publish only at
kernel-declared safe boundaries during normal execution and resume from
authenticated custody; a wake lock or visibility callback is never a
correctness dependency.

Complete workflow boundaries and current implementation status are documented in the root `README.md` and `SECURITY.md`.

It does not expose raw BGV operations or bridge routes.
