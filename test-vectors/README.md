# Test vectors

Deterministic refusal-reason, private-randomness assignment, and protocol-signature message vectors consumed by the test suite. The consuming tests re-derive each expected value from the producing code, so every vector is bound to the implementation that generates it.

When the producing code changes a vector's output on purpose, update the expected values in the JSON; the consuming test verifies them, and git tracks the change.
