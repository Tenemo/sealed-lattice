# Test vectors

Deterministic refusal-reason, private-randomness assignment, protocol-signature
message, and conditional common-proof soundness vectors consumed by the test
suite. The consuming tests re-derive each expected value from the producing
code, so every vector is bound to the implementation that generates it. The
mapped-soundness vector records one independently derived construction row per
selected proof family and is test evidence under its stated ideal-XOF model; it
is not a suite-activation record or an emitted-proof acceptance result.

When the producing code changes a vector's output on purpose, update the expected values in the JSON; the consuming test verifies them, and git tracks the change.
