use num_bigint::BigUint;
use num_traits::One;

use super::field::{
    GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR, GOLDILOCKS_MODULUS,
    maximum_two_adic_generator_has_exact_order, quintic_implementation_matches_polynomial,
    quintic_polynomial_is_irreducible,
};

pub(crate) const COMMON_PROOF_PROFILE: CommonProofProfile = CommonProofProfile {
    protocol_version: 1,
    base_field_modulus: GOLDILOCKS_MODULUS,
    maximum_two_adic_subgroup_generator: GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR,
    monic_challenge_extension_polynomial_coefficients: [GOLDILOCKS_MODULUS - 3, 0, 0, 0, 0],
    evaluation_blowup_factor: 8,
    evaluation_coset_offset: 7,
    deep_point_count: 2,
    final_polynomial_degree_bound_exclusive: 256,
    unique_query_count: 168,
    nonnative_modular_identity_challenge_count: 2,
    maximum_fiat_shamir_candidate_draws_per_output: 64,
    rbr_query_distance_numerator: 3,
    rbr_query_distance_denominator: 5,
    rbr_eta_numerator: 1,
    rbr_eta_denominator: 32,
    random_oracle_query_budget_exponent: 80,
    hash_output_bit_length: 512,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofProfile {
    pub(crate) protocol_version: u16,
    pub(crate) base_field_modulus: u64,
    pub(crate) maximum_two_adic_subgroup_generator: u64,
    pub(crate) monic_challenge_extension_polynomial_coefficients: [u64; 5],
    pub(crate) evaluation_blowup_factor: u32,
    pub(crate) evaluation_coset_offset: u64,
    pub(crate) deep_point_count: u16,
    pub(crate) final_polynomial_degree_bound_exclusive: u32,
    pub(crate) unique_query_count: u32,
    pub(crate) nonnative_modular_identity_challenge_count: u16,
    pub(crate) maximum_fiat_shamir_candidate_draws_per_output: u32,
    pub(crate) rbr_query_distance_numerator: u32,
    pub(crate) rbr_query_distance_denominator: u32,
    pub(crate) rbr_eta_numerator: u32,
    pub(crate) rbr_eta_denominator: u32,
    pub(crate) random_oracle_query_budget_exponent: u16,
    pub(crate) hash_output_bit_length: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProfileValidationError {
    BaseFieldIsNotPrime,
    TwoAdicGeneratorOrderMismatch,
    ChallengePolynomialIsReducible,
    ChallengeFieldArithmeticMismatch,
    InvalidSchedule,
    InvalidRbrParameters,
    EvaluationDomainExceedsField,
    EvaluationCosetIntersectsTraceDomain,
}

impl CommonProofProfile {
    pub(crate) fn validate(
        self,
        trace_domain_size: u64,
        evaluation_domain_size: u64,
    ) -> Result<(), ProfileValidationError> {
        if !is_prime_u64(self.base_field_modulus) {
            return Err(ProfileValidationError::BaseFieldIsNotPrime);
        }
        if !maximum_two_adic_generator_has_exact_order() {
            return Err(ProfileValidationError::TwoAdicGeneratorOrderMismatch);
        }
        if !quintic_polynomial_is_irreducible() {
            return Err(ProfileValidationError::ChallengePolynomialIsReducible);
        }
        if !quintic_implementation_matches_polynomial() {
            return Err(ProfileValidationError::ChallengeFieldArithmeticMismatch);
        }
        if self.evaluation_blowup_factor != 8
            || !self.evaluation_blowup_factor.is_power_of_two()
            || self.deep_point_count == 0
            || self.final_polynomial_degree_bound_exclusive == 0
            || self.unique_query_count == 0
            || self.nonnative_modular_identity_challenge_count == 0
            || self.maximum_fiat_shamir_candidate_draws_per_output == 0
            || self.hash_output_bit_length != 512
        {
            return Err(ProfileValidationError::InvalidSchedule);
        }
        if trace_domain_size == 0
            || evaluation_domain_size == 0
            || !trace_domain_size.is_power_of_two()
            || !evaluation_domain_size.is_power_of_two()
            || !evaluation_domain_size.is_multiple_of(trace_domain_size)
            || !(self.base_field_modulus - 1).is_multiple_of(evaluation_domain_size)
        {
            return Err(ProfileValidationError::EvaluationDomainExceedsField);
        }
        let coset_offset = modular_power(
            self.evaluation_coset_offset,
            trace_domain_size,
            self.base_field_modulus,
        );
        if coset_offset == 1 {
            return Err(ProfileValidationError::EvaluationCosetIntersectsTraceDomain);
        }
        if !self.rbr_conditions_hold() {
            return Err(ProfileValidationError::InvalidRbrParameters);
        }
        Ok(())
    }

    /// Checks `eta < sqrt(rho)/(2m)` and
    /// `delta < 1 - sqrt(rho) - eta` using integer squares. Here `m=3` and
    /// `rho=1/8`; all quantities being squared are positive.
    pub(crate) fn rbr_conditions_hold(self) -> bool {
        if self.rbr_query_distance_numerator != 3
            || self.rbr_query_distance_denominator != 5
            || self.rbr_eta_numerator != 1
            || self.rbr_eta_denominator != 32
        {
            return false;
        }
        // (2*m*eta)^2 < rho: (6/32)^2 < 1/8.
        let eta_left = u128::from(6 * self.rbr_eta_numerator).pow(2) * 8;
        let eta_right = u128::from(self.rbr_eta_denominator).pow(2);
        // sqrt(rho) < 1-delta-eta. The right side is 59/160.
        let remaining_numerator = 59_u128;
        let remaining_denominator = 160_u128;
        let distance_left = remaining_denominator.pow(2);
        let distance_right = 8 * remaining_numerator.pow(2);
        eta_left < eta_right && distance_left < distance_right
    }
}

/// Exact integer/rational accounting for the selected FRI RBR and CMS19
/// database-game bounds. The theorem names and estimates are evidence only and
/// are deliberately not serialized into suite artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecurityAccounting {
    pub(crate) proof_object_multiplicity: u32,
    pub(crate) maximum_evaluation_domain_size: u64,
    pub(crate) merkle_authentication_hash_equations: u64,
    pub(crate) iop_round_count: u32,
    pub(crate) cms_programmable_points: u64,
    pub(crate) cms_total_query_count: BigUint,
    pub(crate) query_error_numerator: BigUint,
    pub(crate) query_error_denominator: BigUint,
    /// The exact field term is
    /// `field_term_rational_numerator * sqrt(2) /
    /// field_term_rational_denominator`.
    pub(crate) field_term_rational_numerator: BigUint,
    pub(crate) field_term_rational_denominator: BigUint,
    pub(crate) query_term_dominates_field_term: bool,
    pub(crate) weighted_rbr_below_two_to_minus_176: bool,
    pub(crate) cms_database_game_numerator: BigUint,
    pub(crate) cms_database_game_denominator: BigUint,
    pub(crate) cms_database_game_below_one_quarter_after_multiplicity: bool,
    pub(crate) cms_compiled_bound_below_one_quarter_after_multiplicity: bool,
}

pub(crate) fn security_accounting(
    proof_object_multiplicity: u32,
    maximum_evaluation_domain_size: u64,
    merkle_authentication_hash_equations: u64,
    iop_round_count: u32,
) -> SecurityAccounting {
    let query_count = COMMON_PROOF_PROFILE.unique_query_count;
    let query_error_numerator = BigUint::one() << query_count;
    let query_error_denominator = BigUint::from(5_u8).pow(query_count);

    // FRI RBR Theorem 4.2 with m=3 and rho=1/8 simplifies to
    // `7^7 * |L0|^2 * sqrt(2) / (24 * |F|)`, where |F|=p^5.
    let field_term_rational_numerator =
        BigUint::from(7_u8).pow(7) * BigUint::from(maximum_evaluation_domain_size).pow(2);
    let field_term_rational_denominator =
        BigUint::from(24_u8) * BigUint::from(COMMON_PROOF_PROFILE.base_field_modulus).pow(5);
    let query_term_dominates_field_term =
        BigUint::from(2_u8) * field_term_rational_numerator.pow(2) * query_error_denominator.pow(2)
            <= field_term_rational_denominator.pow(2) * query_error_numerator.pow(2);

    let multiplicity = BigUint::from(proof_object_multiplicity);
    let weighted_rbr_below_two_to_minus_176 = query_term_dominates_field_term
        && &multiplicity * &query_error_numerator * (BigUint::one() << 176_u32)
            <= query_error_denominator;

    let cms_programmable_points = merkle_authentication_hash_equations
        .checked_add(u64::from(iop_round_count).saturating_mul(2))
        .and_then(|value| value.checked_add(1))
        .expect("generated proof catalog keeps CMS programmable points in u64");
    let random_oracle_query_budget =
        (BigUint::one() << COMMON_PROOF_PROFILE.random_oracle_query_budget_exponent) - 1_u8;
    let cms_total_query_count =
        &random_oracle_query_budget + BigUint::from(cms_programmable_points);
    let hash_space = BigUint::one() << COMMON_PROOF_PROFILE.hash_output_bit_length;

    // omega_D <= 6(t^2 epsilon + 4t^3/2^lambda).
    let cms_database_game_numerator = BigUint::from(6_u8)
        * (cms_total_query_count.pow(2) * &query_error_numerator * &hash_space
            + BigUint::from(4_u8) * cms_total_query_count.pow(3) * &query_error_denominator);
    let cms_database_game_denominator = &query_error_denominator * &hash_space;
    let cms_database_game_below_one_quarter_after_multiplicity =
        BigUint::from(4_u8) * &multiplicity * &cms_database_game_numerator
            < cms_database_game_denominator;

    // CMS root lifting gives sqrt(omega_O) <= sqrt(omega_D)+sqrt(a/2^lambda).
    // Squaring with `(sqrt(x)+sqrt(y))^2 <= 2x+2y` yields a purely rational,
    // conservative compiled bound that includes the exact generated `a`.
    let compiled_numerator = BigUint::from(2_u8) * &cms_database_game_numerator * &hash_space
        + BigUint::from(2_u8)
            * BigUint::from(cms_programmable_points)
            * &cms_database_game_denominator;
    let compiled_denominator = &cms_database_game_denominator * &hash_space;
    let cms_compiled_bound_below_one_quarter_after_multiplicity =
        BigUint::from(4_u8) * multiplicity * compiled_numerator < compiled_denominator;

    SecurityAccounting {
        proof_object_multiplicity,
        maximum_evaluation_domain_size,
        merkle_authentication_hash_equations,
        iop_round_count,
        cms_programmable_points,
        cms_total_query_count,
        query_error_numerator,
        query_error_denominator,
        field_term_rational_numerator,
        field_term_rational_denominator,
        query_term_dominates_field_term,
        weighted_rbr_below_two_to_minus_176,
        cms_database_game_numerator,
        cms_database_game_denominator,
        cms_database_game_below_one_quarter_after_multiplicity,
        cms_compiled_bound_below_one_quarter_after_multiplicity,
    }
}

pub(crate) fn is_prime_u64(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    for small_prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if value == small_prime {
            return true;
        }
        if value.is_multiple_of(small_prime) {
            return false;
        }
    }
    let mut odd_component = value - 1;
    let power_of_two = odd_component.trailing_zeros();
    odd_component >>= power_of_two;
    for base in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let reduced_base = base % value;
        if reduced_base == 0 {
            continue;
        }
        let mut witness = modular_power(reduced_base, odd_component, value);
        if witness == 1 || witness == value - 1 {
            continue;
        }
        let mut reached_minus_one = false;
        for _ in 1..power_of_two {
            witness = modular_multiply(witness, witness, value);
            if witness == value - 1 {
                reached_minus_one = true;
                break;
            }
        }
        if !reached_minus_one {
            return false;
        }
    }
    true
}

pub(crate) fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = modular_multiply(result, base, modulus);
        }
        base = modular_multiply(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn modular_multiply(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}
