# Test vectors

Deterministic refusal-reason, private-randomness assignment, protocol-signature
message, and conditional common-proof soundness vectors consumed by the test
suite. The consuming tests re-derive each expected value from the producing
code, so every vector is bound to the implementation that generates it. The
mapped-soundness vector records one independently derived construction row per
selected proof family and is conditional test evidence under its stated oracle
model; it is not a suite-activation record or an emitted-proof acceptance
result.

The version-four mapped-soundness vector targets the exact `n = 10`,
`optionCount = 10` profile, with one construction-identity-bound row per
selected family and conditional 103-physical-proof, 159-logical-instance action
arithmetic. All 12 rows and 21 selected production identities are current as
structural and arithmetic records against the fixed-output seed-and-block
transcript. They are not accepted QROM theorem evidence: the producer now keeps
the transform and composition unresolved because the coherent predecessor-
graph, half-preimage-support, and complete extraction arguments are not proved.
The vector remains refused as soundness and suite-selection authority until the
graph reduction is completed and independently reviewed.
It is also not a concrete-standard-model SHAKE256 proof or an emitted-proof
acceptance result. Other checked vectors that still bind the superseded twenty-
option profile remain ineligible for suite selection until regenerated.

The collective-setup security record is regenerated from the exact-ten Rust
production-authority constructor before TypeScript binds source and imported
artifact digests. Its refresh path cannot reuse or edit the authority stored in
the prior vector. The record now imports unresolved QROM transform and
composition statuses and also refuses overall closure for masking, setup-family
simulation, and terminal collective composition. It cannot serve as complete
security evidence, mint a setup capability, or select a suite.

When the producing code changes a vector's output on purpose, update the expected values in the JSON; the consuming test verifies them, and git tracks the change.
