use super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::*;
use crate::bgv::parameters::DATA_PRIMES;

// Repo-owned accounting for the trustee-batched succinct evaluation-key
// argument. Every row states what is implemented and measured against the
// fixed parameters in this module, and every theorem row carries its closure
// argument inline. The soundness model is classical round-by-round, every
// post-commitment challenge is drawn from the degree-four challenge extension
// of the limb field, and the explicitly conjectured input (the per-query FRI
// proximity-gap bound at rate one half) is named with its insufficient proven
// fallback at the current query count.
//
// CHANGE (2026, Option B): the named conjecture was re-based onto CS25 "Our
// Conjecture 3" (mutual correlated agreement up to the q-ary list-decoding
// capacity for prime fields). The earlier accounting counted one bit per query,
// the up-to-capacity proximity-gap radius 1 - rho of BCI+23 Conjecture 8.4,
// which Crites-Stewart (CS25) and BCHKS26 DISPROVED in 2025. The repaired
// entropy-capacity radius costs about 1/log2(q) of distance over the base limb
// field, lowering per-query soundness from one bit to about 0.938 bit, so the
// fixed 168-query count now records about 140 effective bits after the union
// allowance rather than 144. The proven BCIKS20 Johnson fallback is unchanged.
//
// This conjecture is an admissible soundness foundation under the
// project's proximity-gap policy: a repaired below-capacity conjecture may carry
// post-quantum soundness, the disproved up-to-capacity one may not.
// The residual is a disclosed small-medium research risk, not a soundness gap: CS25
// Our Conjecture 3 is a recent (2025) conjecture and could be weakened by future
// work, though it is the best-pedigreed standing one (its authors disproved the
// prior conjecture). The proven BCIKS20 Johnson fallback at a larger query count
// removes that research risk entirely.
//
// The QROM row now carries the computed CMS19 reduction loss (state-restoration
// framework): the achieved quantum soundness is the Grover square-root of the
// classical round-by-round soundness, about seventy bits after the instance
// union, recorded with the present-time-threat scope and kept below the
// conventional 128-bit-quantum bar.
pub(super) fn succinct_proof_effective_soundness_bits(trace_size: usize) -> CanonicalResult<i64> {
    if trace_size == 0 || !trace_size.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "succinct proof soundness policy requires a power-of-two trace size",
        ));
    }
    let extension_size = trace_size
        .checked_mul(DOMAIN_BLOWUP)
        .ok_or_else(|| invalid_succinct_setup_proof("soundness extension size overflowed"))?;
    let commitment_bound = COMMITMENT_BOUND_FACTOR
        .checked_mul(trace_size)
        .ok_or_else(|| invalid_succinct_setup_proof("soundness commitment bound overflowed"))?;
    let smallest_limb_prime = *DATA_PRIMES
        .iter()
        .min()
        .expect("the data basis is non-empty");
    let base_field_bits = i64::from(smallest_limb_prime.ilog2());
    let challenge_field_bits = base_field_bits * CHALLENGE_EXTENSION_DEGREE as i64;
    let union_budget_bits = 16_i64;
    let fold_round_bits = challenge_field_bits - i64::from(extension_size.ilog2());
    let out_of_domain_round_bits =
        challenge_field_bits - (i64::from((3 * commitment_bound).ilog2()) + 1);
    let lincheck_round_bits =
        (challenge_field_bits - i64::from(trace_size.ilog2())) * LINCHECK_REPETITIONS as i64;
    let consistency_round_bits =
        CONSISTENCY_COEFFICIENT_BITS as i64 * CONSISTENCY_REPETITIONS as i64;
    let entropy_capacity_query_soundness_permille = 930_i64;
    let query_round_bits =
        LOW_DEGREE_QUERY_COUNT as i64 * entropy_capacity_query_soundness_permille / 1000;
    let weakest_round_bits = [
        fold_round_bits,
        out_of_domain_round_bits,
        lincheck_round_bits,
        consistency_round_bits,
        query_round_bits,
    ]
    .into_iter()
    .min()
    .expect("round list is non-empty");
    Ok(weakest_round_bits - union_budget_bits)
}

pub(super) fn enforce_current_succinct_proof_soundness_policy(
    trace_size: usize,
) -> CanonicalResult<()> {
    let effective_soundness_bits = succinct_proof_effective_soundness_bits(trace_size)?;
    if effective_soundness_bits < MINIMUM_CONJECTURED_CLASSICAL_SOUNDNESS_AFTER_UNION_BITS {
        return Err(invalid_succinct_setup_proof(format!(
            "succinct proof conjectured classical soundness after union is {effective_soundness_bits} bits, below the required {MINIMUM_CONJECTURED_CLASSICAL_SOUNDNESS_AFTER_UNION_BITS} bits"
        )));
    }

    Ok(())
}
