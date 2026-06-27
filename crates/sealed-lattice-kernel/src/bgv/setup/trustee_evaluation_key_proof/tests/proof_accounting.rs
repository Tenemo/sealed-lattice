#[test]
fn soundness_report_meets_the_conjectured_classical_policy_floor() {
    // The soundness gate is essential: 128-bit effective soundness depends on the
    // pre-union margin and a named, unproven FRI conjecture -- do not relax it to
    // make a proof pass. The recomputed numeric soundness bound, not self-attested
    // verdict flags, is what the policy enforces.
    let effective_soundness_bits = super::accounting::succinct_proof_effective_soundness_bits(
        crate::bgv::parameters::POLYNOMIAL_DEGREE / 2,
    )
    .expect("effective soundness bits");
    assert!(effective_soundness_bits >= 128);
    super::accounting::enforce_current_succinct_proof_soundness_policy(
        crate::bgv::parameters::POLYNOMIAL_DEGREE / 2,
    )
    .expect("conjectured classical policy floor");
}
