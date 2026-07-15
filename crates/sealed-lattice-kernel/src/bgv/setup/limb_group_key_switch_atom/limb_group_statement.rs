//! Key-switch digit atom over a limb-group modulus.
//!
//! Trustee evaluation-key material satisfies, for one key at level L, every
//! digit j and limb l (kernel keygen in `bgv::evaluator::key_switch`):
//!
//! ```text
//! b[j][l] + a[j][l] * s - t * e_j - [l == j] * source = 0   in R_{q_l}
//! ```
//!
//! with one ternary secret `s` shared by every equation, one centered
//! binomial error `e_j` per digit shared across limbs, and the diagonal
//! source a small signed polynomial (round one: s; Galois: the automorphism
//! image of s) or a public product with s (round two).
//!
//! CRT recombines the limb congruences for digit j into the limb-group modulus
//! Q = prod(q_l). With the shared small witnesses, the atom checks the integer
//! congruence
//!
//! ```text
//! B_j + A_j * s - t * e_j - G_j * source = Q * c   over the integers,
//! ```
//!
//! holds with a small carry polynomial c, where B_j, A_j are the centered
//! CRT recombinations of the per-limb public material and G_j is the CRT
//! idempotent of the diagonal limb (which is exactly the key-switch gadget
//! factor). This check is not vacuous: every input is bounded (public
//! values centered below Q/2, witnesses support-checked), so the integer
//! value of the left side is strictly below p/2 for the selected proof
//! field, and a carry whose centered lift stays within the derived bound
//! forces the integer identity, hence every per-limb congruence.

#[cfg(test)]
use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;
#[cfg(test)]
use super::wide_unsigned::to_u64;
use super::wide_unsigned::{
    add_in_place, is_less_than, multiply_word_accumulate, multiply_word_in_place, remainder_word,
    shift_right_one_in_place, subtract_in_place,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

/// A limb group with its CRT constants over a proof field. The reduced CRT
/// basis constants double as the key-switch gadget idempotents: C_l is one
/// modulo q_l and zero modulo every other group prime. Recombination uses
/// the Gauss form x = sum_l ((r_l * inv_l) mod q_l) * M_l so every
/// accumulated term stays below Q and the final reduction is a short
/// subtraction loop.
pub(crate) struct LimbGroupContext<const LIMB_COUNT: usize> {
    pub(crate) group_primes: Vec<u64>,
    group_modulus: [u64; LIMB_COUNT],
    group_modulus_half_floor: [u64; LIMB_COUNT],
    cofactors: Vec<[u64; LIMB_COUNT]>,
    cofactor_inverses: Vec<u64>,
    gadget_idempotents_centered: Vec<[u64; LIMB_COUNT]>,
    group_modulus_inverse: [u64; LIMB_COUNT],
}

impl<const LIMB_COUNT: usize> LimbGroupContext<LIMB_COUNT> {
    pub(crate) fn new(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        group_primes: &[u64],
    ) -> CanonicalResult<Self> {
        if group_primes.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "limb group must contain at least one prime",
            ));
        }
        let mut group_modulus = [0_u64; LIMB_COUNT];
        group_modulus[0] = 1;
        for prime in group_primes {
            if multiply_word_in_place(&mut group_modulus, *prime) != 0 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "limb group modulus exceeds the proof field limb width",
                ));
            }
        }
        // This constructor checks only Q < p. Each verifier call checks the
        // degree-dependent exactness bound before using the mod-p relation.
        if !is_less_than(&group_modulus, &parameters.modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "limb group modulus does not fit below the proof field modulus",
            ));
        }
        let mut group_modulus_half_floor = group_modulus;
        shift_right_one_in_place(&mut group_modulus_half_floor);

        let mut cofactors = Vec::with_capacity(group_primes.len());
        let mut cofactor_inverses = Vec::with_capacity(group_primes.len());
        let mut reduced_basis_constants = Vec::with_capacity(group_primes.len());
        for prime in group_primes {
            let mut cofactor = group_modulus;
            let remainder = super::wide_unsigned::divide_word_in_place(&mut cofactor, *prime);
            debug_assert_eq!(remainder, 0);
            let cofactor_residue = remainder_word(&cofactor, *prime);
            let cofactor_inverse = word_inverse_mod_prime(cofactor_residue, *prime);
            // The basis constant M_l * inv_l is below Q * q_l before its
            // one-time reduction, so reduce by shifted modulus multiples.
            let mut basis_constant = cofactor;
            let carry = multiply_word_in_place(&mut basis_constant, cofactor_inverse);
            debug_assert_eq!(carry, 0);
            reduce_by_shifted_modulus(&mut basis_constant, &group_modulus, 48);
            cofactors.push(cofactor);
            cofactor_inverses.push(cofactor_inverse);
            reduced_basis_constants.push(basis_constant);
        }

        let gadget_idempotents_centered = reduced_basis_constants
            .iter()
            .map(|constant| {
                centered_group_value_to_field(
                    parameters,
                    constant,
                    &group_modulus,
                    &group_modulus_half_floor,
                )
            })
            .collect::<Vec<_>>();

        let group_modulus_inverse =
            parameters.inverse(&parameters.raw_value_to_element(&group_modulus));

        Ok(Self {
            group_primes: group_primes.to_vec(),
            group_modulus,
            group_modulus_half_floor,
            cofactors,
            cofactor_inverses,
            gadget_idempotents_centered,
            group_modulus_inverse,
        })
    }

    /// CRT-recombines per-limb residue vectors into centered mod-Q
    /// representatives as proof-field elements.
    pub(crate) fn recombine_centered(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        residues_by_limb: &[Vec<u64>],
        ring_degree: usize,
    ) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        if residues_by_limb.len() != self.group_primes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "limb count does not match the limb group",
            ));
        }
        for (limb, prime) in residues_by_limb.iter().zip(self.group_primes.iter()) {
            if limb.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "limb residue vector length does not match the ring degree",
                ));
            }
            if limb.iter().any(|residue| residue >= prime) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "limb residue is not reduced modulo its group prime",
                ));
            }
        }

        let mut recombined = Vec::with_capacity(ring_degree);
        for coefficient_index in 0..ring_degree {
            let mut accumulator = [0_u64; LIMB_COUNT];
            for (limb_index, limb) in residues_by_limb.iter().enumerate() {
                let prime = self.group_primes[limb_index];
                let scaled_residue = word_multiply_mod(
                    limb[coefficient_index],
                    self.cofactor_inverses[limb_index],
                    prime,
                );
                let carry = multiply_word_accumulate(
                    &mut accumulator,
                    &self.cofactors[limb_index],
                    scaled_residue,
                );
                debug_assert_eq!(carry, 0);
            }
            // Every term is below Q, so at most group-size subtractions.
            while !is_less_than(&accumulator, &self.group_modulus) {
                subtract_in_place(&mut accumulator, &self.group_modulus);
            }
            recombined.push(centered_group_value_to_field(
                parameters,
                &accumulator,
                &self.group_modulus,
                &self.group_modulus_half_floor,
            ));
        }
        Ok(recombined)
    }

    /// The centered gadget idempotent for the group position of a digit's
    /// diagonal limb, as a proof-field element.
    pub(crate) fn gadget_idempotent(
        &self,
        group_position: usize,
    ) -> CanonicalResult<&[u64; LIMB_COUNT]> {
        self.gadget_idempotents_centered
            .get(group_position)
            .ok_or_else(invalid_diagonal_group_position)
    }

    /// The precomputed field inverse of the limb-group modulus `Q`.
    pub(crate) fn group_modulus_inverse(&self) -> &[u64; LIMB_COUNT] {
        &self.group_modulus_inverse
    }

    /// The limb-group modulus `Q` as a proof-field element.
    pub(crate) fn group_modulus_element(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) -> [u64; LIMB_COUNT] {
        parameters.raw_value_to_element(&self.group_modulus)
    }

    /// The degree-dependent exactness bound check for this group: the mod-p
    /// relation equals the integer relation only when `p > 2 (Q (2N + 1) + 4t)`.
    pub(crate) fn validate_exactness_bound(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        ring_degree: usize,
    ) -> CanonicalResult<()> {
        validate_limb_group_exactness_bound(parameters, &self.group_modulus, ring_degree)
    }
}

fn invalid_diagonal_group_position() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::ComponentMismatch,
        "diagonal group position must identify a limb in the group",
    )
}

/// The diagonal source term of the digit atom (the standalone checker's
/// input; the live path proves through the family backend).
#[cfg(test)]
pub(crate) enum DigitAtomSource<'a> {
    /// Round-one relinearization and Galois rotations: a small signed
    /// polynomial (the secret or its automorphism image).
    DiagonalSignedPolynomial(&'a [i64]),
    /// Round-two relinearization: source = signed_polynomial * aggregate,
    /// with the aggregate public as residues at the diagonal limb.
    DiagonalPublicProduct {
        aggregate_residues: &'a [u64],
        signed_polynomial: &'a [i64],
    },
    /// The atom's limb group does not contain the digit's diagonal limb.
    NoDiagonal,
}

#[cfg(test)]
pub(crate) struct LimbGroupDigitAtomInput<'a, const LIMB_COUNT: usize> {
    pub(crate) group: &'a LimbGroupContext<LIMB_COUNT>,
    pub(crate) domain: &'a NegacyclicDomain<'a, LIMB_COUNT>,
    /// Position of the digit's diagonal limb inside the group, when present.
    pub(crate) diagonal_group_position: Option<usize>,
    pub(crate) component_b_by_limb: &'a [Vec<u64>],
    pub(crate) public_sample_by_limb: &'a [Vec<u64>],
    pub(crate) secret_coefficients: &'a [i64],
    pub(crate) error_coefficients: &'a [i64],
    pub(crate) source: DigitAtomSource<'a>,
}

#[cfg(test)]
pub(crate) struct LimbGroupDigitAtomReport {
    pub(crate) maximum_carry_magnitude: u64,
    pub(crate) carry_bound: u64,
}

/// Checks the limb-group digit congruence with an exact carry bound.
///
/// Bound derivation, per coefficient over the integers, with N the ring
/// degree, Q the group modulus, and t the plaintext modulus:
/// |B| <= Q/2, |A * s| <= N * Q/2 (centered A, ternary s, negacyclic sum of
/// N terms), |t * e| <= 2t, and the diagonal term is either
/// |G * source| <= Q/2 (signed source, |source| <= 1 after centering G) or
/// |P * s| <= N * Q/2 (round two, P centered modulo Q before the product).
/// So |D| < Q * (N + 1/2) + 2t for the largest round-two shape and the exact
/// carry c = D / Q satisfies |c| <= N + 1. The proof field is checked with
/// p > Q * (2N + 1) + 4t, so the mod-p computation of D equals the integer D
/// and the check is exact.
#[cfg(test)]
pub(crate) fn verify_limb_group_digit_atom<const LIMB_COUNT: usize>(
    input: LimbGroupDigitAtomInput<'_, LIMB_COUNT>,
) -> CanonicalResult<LimbGroupDigitAtomReport> {
    let parameters = input.domain.parameters;
    let ring_degree = input.domain.size;
    validate_limb_group_exactness_bound(parameters, &input.group.group_modulus, ring_degree)?;
    validate_signed_support(input.secret_coefficients, ring_degree, 1, "secret")?;
    validate_signed_support(input.error_coefficients, ring_degree, 2, "error")?;
    let plaintext_modulus = plaintext_modulus_i64();

    let component_b =
        input
            .group
            .recombine_centered(parameters, input.component_b_by_limb, ring_degree)?;
    let public_sample =
        input
            .group
            .recombine_centered(parameters, input.public_sample_by_limb, ring_degree)?;

    let secret_field = input
        .secret_coefficients
        .iter()
        .map(|value| parameters.signed_word_to_element(*value))
        .collect::<Vec<_>>();
    let sample_secret_product = input
        .domain
        .negacyclic_product(&public_sample, &secret_field);

    let diagonal_term = diagonal_term(&input)?;

    let carry_bound = ring_degree as u64 + 1;
    let mut maximum_carry_magnitude = 0_u64;
    for coefficient_index in 0..ring_degree {
        let mut difference = parameters.add(
            &component_b[coefficient_index],
            &sample_secret_product[coefficient_index],
        );
        let scaled_error = parameters.signed_word_to_element(
            input.error_coefficients[coefficient_index] * plaintext_modulus,
        );
        difference = parameters.subtract(&difference, &scaled_error);
        if let Some(term) = &diagonal_term {
            difference = parameters.subtract(&difference, &term[coefficient_index]);
        }

        let carry = parameters.multiply(&difference, &input.group.group_modulus_inverse);
        let (_, magnitude) = parameters.centered_raw(&carry);
        let magnitude_word = to_u64(&magnitude).filter(|value| *value <= carry_bound);
        match magnitude_word {
            Some(value) => maximum_carry_magnitude = maximum_carry_magnitude.max(value),
            None => {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "limb-group key-switch digit congruence does not hold: the carry lift exceeds its integer bound",
                ));
            }
        }
    }

    Ok(LimbGroupDigitAtomReport {
        maximum_carry_magnitude,
        carry_bound,
    })
}

fn validate_limb_group_exactness_bound<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    group_modulus: &[u64; LIMB_COUNT],
    ring_degree: usize,
) -> CanonicalResult<()> {
    let relation_degree_factor = ring_degree
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(limb_group_exactness_bound_overflow)?;
    let plaintext_error_bound = crate::bgv::parameters::PLAINTEXT_MODULUS
        .checked_mul(4)
        .ok_or_else(limb_group_exactness_bound_overflow)?;

    let mut relation_bound = *group_modulus;
    if multiply_word_in_place(&mut relation_bound, relation_degree_factor) != 0 {
        return Err(limb_group_exactness_bound_overflow());
    }

    let mut error_bound = [0_u64; LIMB_COUNT];
    error_bound[0] = plaintext_error_bound;
    if add_in_place(&mut relation_bound, &error_bound) != 0 {
        return Err(limb_group_exactness_bound_overflow());
    }

    if multiply_word_in_place(&mut relation_bound, 2) != 0 {
        return Err(limb_group_exactness_bound_overflow());
    }

    if !is_less_than(&relation_bound, &parameters.modulus) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "limb-group exact relation bound does not fit below the proof field modulus",
        ));
    }

    Ok(())
}

fn limb_group_exactness_bound_overflow() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::MalformedLength,
        "limb-group exact relation bound exceeds the proof field limb width",
    )
}

#[cfg(test)]
fn plaintext_modulus_i64() -> i64 {
    i64::try_from(crate::bgv::parameters::PLAINTEXT_MODULUS).expect("plaintext modulus fits i64")
}

#[cfg(test)]
fn diagonal_term<const LIMB_COUNT: usize>(
    input: &LimbGroupDigitAtomInput<'_, LIMB_COUNT>,
) -> CanonicalResult<Option<Vec<[u64; LIMB_COUNT]>>> {
    let parameters = input.domain.parameters;
    let ring_degree = input.domain.size;
    match (&input.source, input.diagonal_group_position) {
        (DigitAtomSource::NoDiagonal, None) => Ok(None),
        (DigitAtomSource::DiagonalSignedPolynomial(source), Some(group_position)) => {
            validate_signed_support(source, ring_degree, 1, "diagonal source")?;
            let idempotent = input.group.gadget_idempotent(group_position)?;
            Ok(Some(
                source
                    .iter()
                    .map(|value| {
                        parameters.multiply(idempotent, &parameters.signed_word_to_element(*value))
                    })
                    .collect(),
            ))
        }
        (
            DigitAtomSource::DiagonalPublicProduct {
                aggregate_residues,
                signed_polynomial,
            },
            Some(group_position),
        ) => {
            input.group.gadget_idempotent(group_position).map(|_| ())?;
            validate_signed_support(signed_polynomial, ring_degree, 1, "diagonal source")?;
            // G * lift(aggregate) centered modulo Q is the CRT recombination
            // of a limb matrix that carries the aggregate at the diagonal
            // limb and zero everywhere else; centering it before the
            // convolution keeps the diagonal term inside the N * Q/2 bound.
            let padded_by_limb = (0..input.group.group_primes.len())
                .map(|limb_index| {
                    if limb_index == group_position {
                        aggregate_residues.to_vec()
                    } else {
                        vec![0_u64; ring_degree]
                    }
                })
                .collect::<Vec<_>>();
            let scaled_aggregate =
                input
                    .group
                    .recombine_centered(parameters, &padded_by_limb, ring_degree)?;
            let signed_field = signed_polynomial
                .iter()
                .map(|value| parameters.signed_word_to_element(*value))
                .collect::<Vec<_>>();
            Ok(Some(
                input
                    .domain
                    .negacyclic_product(&scaled_aggregate, &signed_field),
            ))
        }
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "digit atom source shape does not match the diagonal group position",
        )),
    }
}

pub(crate) fn validate_signed_support(
    values: &[i64],
    ring_degree: usize,
    bound: i64,
    role: &str,
) -> CanonicalResult<()> {
    if values.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{role} coefficient vector length does not match the ring degree"),
        ));
    }
    if values.iter().any(|value| value.abs() > bound) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{role} coefficient support exceeds its bound"),
        ));
    }
    Ok(())
}

fn centered_group_value_to_field<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    value: &[u64; LIMB_COUNT],
    group_modulus: &[u64; LIMB_COUNT],
    group_modulus_half_floor: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    if is_less_than(group_modulus_half_floor, value) {
        let mut magnitude = *group_modulus;
        subtract_in_place(&mut magnitude, value);
        parameters.negate(&parameters.raw_value_to_element(&magnitude))
    } else {
        parameters.raw_value_to_element(value)
    }
}

/// Reduces `value` modulo `modulus` by subtracting shifted modulus
/// multiples from the highest shift down; the caller guarantees
/// value < modulus << max_shift_bits and that the shifted modulus still
/// fits the limb width.
fn reduce_by_shifted_modulus<const LIMB_COUNT: usize>(
    value: &mut [u64; LIMB_COUNT],
    modulus: &[u64; LIMB_COUNT],
    max_shift_bits: u32,
) {
    let mut shifted = *modulus;
    for _ in 0..max_shift_bits {
        let carry = multiply_word_in_place(&mut shifted, 2);
        debug_assert_eq!(carry, 0);
    }
    for _ in 0..=max_shift_bits {
        while !is_less_than(value, &shifted) {
            subtract_in_place(value, &shifted);
        }
        shift_right_one_in_place(&mut shifted);
    }
}

fn word_multiply_mod(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

/// Fermat inverse of a word modulo a word prime.
fn word_inverse_mod_prime(value: u64, prime: u64) -> u64 {
    let mut result = 1_u128;
    let mut base = u128::from(value % prime);
    let mut exponent = prime - 2;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % u128::from(prime);
        }
        base = base * base % u128::from(prime);
        exponent >>= 1;
    }
    result as u64
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::{
        eight_limb_group_field_parameters, sixteen_limb_group_field_parameters,
    };
    use super::*;
    use crate::bgv::evaluator::key_switch::{KEY_SWITCH_ERROR_DOMAIN, KEY_SWITCH_SAMPLE_DOMAIN};
    use crate::bgv::evaluator::prg::DeterministicSampler;
    use crate::bgv::parameters::DATA_PRIMES;
    use num_bigint::BigUint;

    fn signed_residue(value: i64, modulus: u64) -> u64 {
        if value >= 0 {
            value as u64 % modulus
        } else {
            modulus - (value.unsigned_abs() % modulus)
        }
    }

    fn group_modulus_for_primes<const LIMB_COUNT: usize>(
        group_primes: &[u64],
    ) -> [u64; LIMB_COUNT] {
        let mut group_modulus = [0_u64; LIMB_COUNT];
        group_modulus[0] = 1;
        for prime in group_primes {
            assert_eq!(
                multiply_word_in_place(&mut group_modulus, *prime),
                0,
                "test group modulus must fit the selected limb width"
            );
        }

        group_modulus
    }

    fn schoolbook_negacyclic_mod(left: &[u64], right_signed: &[i64], modulus: u64) -> Vec<u64> {
        let size = left.len();
        let mut product = vec![0_u64; size];
        for (left_index, left_value) in left.iter().enumerate() {
            for (right_index, right_value) in right_signed.iter().enumerate() {
                let magnitude = u128::from(*left_value) * u128::from(right_value.unsigned_abs())
                    % u128::from(modulus);
                let magnitude = magnitude as u64;
                let wrapped_index = (left_index + right_index) % size;
                let negacyclic_negate = left_index + right_index >= size;
                let negate = negacyclic_negate != (*right_value < 0);
                if negate {
                    product[wrapped_index] =
                        (product[wrapped_index] + modulus - magnitude) % modulus;
                } else {
                    product[wrapped_index] = (product[wrapped_index] + magnitude) % modulus;
                }
            }
        }
        product
    }

    struct SyntheticAtom {
        component_b_by_limb: Vec<Vec<u64>>,
        public_sample_by_limb: Vec<Vec<u64>>,
        secret: Vec<i64>,
        error: Vec<i64>,
        source: Vec<i64>,
    }

    /// Builds digit material at a reduced ring degree straight from the
    /// pinned kernel formula b = t*e - a*s + [limb == digit] * source.
    fn synthetic_atom(
        group_primes: &[u64],
        ring_degree: usize,
        diagonal_group_position: Option<usize>,
        seed: &str,
    ) -> SyntheticAtom {
        let mut secret_sampler =
            DeterministicSampler::new("limb-group-atom-test-secret", &[seed.as_bytes()]);
        let secret = secret_sampler
            .centered_binomial_eta2(ring_degree)
            .into_iter()
            .map(|value| value.clamp(-1, 1))
            .collect::<Vec<_>>();
        let source = secret.iter().map(|value| -value).collect::<Vec<_>>();
        let error = DeterministicSampler::new("limb-group-atom-test-error", &[seed.as_bytes()])
            .centered_binomial_eta2(ring_degree);
        let plaintext_modulus = plaintext_modulus_i64();
        let mut public_sample_by_limb = Vec::new();
        let mut component_b_by_limb = Vec::new();
        for (group_position, prime) in group_primes.iter().enumerate() {
            let prime_bytes = prime.to_le_bytes();
            let sample = DeterministicSampler::new(
                "limb-group-atom-test-sample",
                &[seed.as_bytes(), &prime_bytes],
            )
            .uniform_residues(*prime, ring_degree);
            let sample_secret = schoolbook_negacyclic_mod(&sample, &secret, *prime);
            let component_b = (0..ring_degree)
                .map(|index| {
                    let scaled_error = signed_residue(error[index] * plaintext_modulus, *prime);
                    let mut value = (scaled_error + *prime - sample_secret[index]) % *prime;
                    if diagonal_group_position == Some(group_position) {
                        value = (value + signed_residue(source[index], *prime)) % *prime;
                    }
                    value
                })
                .collect::<Vec<_>>();
            public_sample_by_limb.push(sample);
            component_b_by_limb.push(component_b);
        }
        SyntheticAtom {
            component_b_by_limb,
            public_sample_by_limb,
            secret,
            error,
            source,
        }
    }

    #[test]
    fn crt_basis_constants_are_gadget_idempotents() {
        let parameters = sixteen_limb_group_field_parameters();
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..16]).expect("group builds");
        // Recompute each reduced basis constant exactly as the constructor
        // does (the context only retains the centered idempotents).
        for (constant_index, (cofactor, cofactor_inverse)) in group
            .cofactors
            .iter()
            .zip(group.cofactor_inverses.iter())
            .enumerate()
        {
            let mut constant = *cofactor;
            let carry = multiply_word_in_place(&mut constant, *cofactor_inverse);
            assert_eq!(carry, 0);
            reduce_by_shifted_modulus(&mut constant, &group.group_modulus, 48);
            assert!(
                is_less_than(&constant, &group.group_modulus),
                "basis constant {constant_index} must be reduced modulo the group modulus"
            );
            for (prime_index, prime) in group.group_primes.iter().enumerate() {
                let expected = u64::from(constant_index == prime_index);
                assert_eq!(remainder_word(&constant, *prime), expected);
            }
        }
    }

    #[test]
    fn exactness_bound_rejects_a_group_that_no_longer_fits_the_ring_degree() {
        let parameters = eight_limb_group_field_parameters();
        let group_modulus = group_modulus_for_primes::<7>(&DATA_PRIMES[..9]);

        let error = validate_limb_group_exactness_bound(
            &parameters,
            &group_modulus,
            crate::bgv::parameters::POLYNOMIAL_DEGREE,
        )
        .expect_err("nine data primes exceed the eight-limb proof field exactness bound");

        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn exactness_bound_accepts_the_full_sixteen_limb_group() {
        let parameters = sixteen_limb_group_field_parameters();
        let group = LimbGroupContext::new(&parameters, &DATA_PRIMES[..16])
            .expect("full group modulus fits below the proof field");

        validate_limb_group_exactness_bound(
            &parameters,
            &group.group_modulus,
            crate::bgv::parameters::POLYNOMIAL_DEGREE,
        )
        .expect("active full group fits the proof field exactness bound");
    }

    #[test]
    fn recombination_matches_bigint_crt() {
        let parameters = eight_limb_group_field_parameters();
        let group_primes = &DATA_PRIMES[..8];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let ring_degree = 16;
        let residues_by_limb = group_primes
            .iter()
            .enumerate()
            .map(|(limb_index, prime)| {
                (0..ring_degree)
                    .map(|coefficient_index| {
                        (0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(
                            (limb_index * ring_degree + coefficient_index + 1) as u64,
                        )) % prime
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let recombined = group
            .recombine_centered(&parameters, &residues_by_limb, ring_degree)
            .expect("recombines");

        let group_modulus = group_primes
            .iter()
            .fold(BigUint::from(1_u32), |acc, prime| {
                acc * BigUint::from(*prime)
            });
        for (coefficient_index, recombined_coefficient) in
            recombined.iter().enumerate().take(ring_degree)
        {
            let (is_negative, magnitude) = parameters.centered_raw(recombined_coefficient);
            let mut value = BigUint::from(0_u32);
            for index in (0..magnitude.len()).rev() {
                value = (value << 64) | BigUint::from(magnitude[index]);
            }
            let lifted = if is_negative {
                &group_modulus - (value % &group_modulus)
            } else {
                value % &group_modulus
            };
            for (limb_index, prime) in group_primes.iter().enumerate() {
                let expected = residues_by_limb[limb_index][coefficient_index];
                let actual = (&lifted % BigUint::from(*prime))
                    .to_u64_digits()
                    .first()
                    .copied()
                    .unwrap_or(0);
                assert_eq!(
                    actual, expected,
                    "limb {limb_index} coefficient {coefficient_index}"
                );
            }
        }
    }

    #[test]
    fn synthetic_diagonal_atom_verifies_and_reports_a_small_carry() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 256;
        let group_primes = &DATA_PRIMES[..16];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let atom = synthetic_atom(group_primes, ring_degree, Some(5), "diagonal");
        let report = verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
            group: &group,
            domain: &domain,
            diagonal_group_position: Some(5),
            component_b_by_limb: &atom.component_b_by_limb,
            public_sample_by_limb: &atom.public_sample_by_limb,
            secret_coefficients: &atom.secret,
            error_coefficients: &atom.error,
            source: DigitAtomSource::DiagonalSignedPolynomial(&atom.source),
        })
        .expect("atom verifies");
        assert!(report.maximum_carry_magnitude <= report.carry_bound);
        assert!(report.maximum_carry_magnitude > 0);
    }

    #[test]
    fn synthetic_off_diagonal_atom_verifies_without_a_source() {
        let parameters = eight_limb_group_field_parameters();
        let ring_degree = 128;
        let group_primes = &DATA_PRIMES[8..16];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let atom = synthetic_atom(group_primes, ring_degree, None, "off-diagonal");
        verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
            group: &group,
            domain: &domain,
            diagonal_group_position: None,
            component_b_by_limb: &atom.component_b_by_limb,
            public_sample_by_limb: &atom.public_sample_by_limb,
            secret_coefficients: &atom.secret,
            error_coefficients: &atom.error,
            source: DigitAtomSource::NoDiagonal,
        })
        .expect("atom verifies");
    }

    #[test]
    fn round_two_shaped_public_product_atom_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 128;
        let group_primes = &DATA_PRIMES[..16];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let diagonal_group_position = 3;
        let diagonal_prime = group_primes[diagonal_group_position];

        let mut base = synthetic_atom(group_primes, ring_degree, None, "round-two");
        let aggregate = DeterministicSampler::new("limb-group-atom-test-aggregate", &[b"agg"])
            .uniform_residues(diagonal_prime, ring_degree);
        // Add the diagonal contribution source * aggregate at the diagonal
        // limb only, matching the round-two component shape.
        let source_times_aggregate =
            schoolbook_negacyclic_mod(&aggregate, &base.source, diagonal_prime);
        for (value, contribution) in base.component_b_by_limb[diagonal_group_position]
            .iter_mut()
            .zip(source_times_aggregate.iter())
        {
            *value = (*value + *contribution) % diagonal_prime;
        }
        verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
            group: &group,
            domain: &domain,
            diagonal_group_position: Some(diagonal_group_position),
            component_b_by_limb: &base.component_b_by_limb,
            public_sample_by_limb: &base.public_sample_by_limb,
            secret_coefficients: &base.secret,
            error_coefficients: &base.error,
            source: DigitAtomSource::DiagonalPublicProduct {
                aggregate_residues: &aggregate,
                signed_polynomial: &base.source,
            },
        })
        .expect("round-two shaped atom verifies");
    }

    #[test]
    fn tampered_material_and_wrong_shapes_are_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 128;
        let group_primes = &DATA_PRIMES[..16];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let atom = synthetic_atom(group_primes, ring_degree, Some(2), "tamper");

        let verify =
            |component_b: &[Vec<u64>], secret: &[i64], error: &[i64], position: Option<usize>| {
                verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
                    group: &group,
                    domain: &domain,
                    diagonal_group_position: position,
                    component_b_by_limb: component_b,
                    public_sample_by_limb: &atom.public_sample_by_limb,
                    secret_coefficients: secret,
                    error_coefficients: error,
                    source: DigitAtomSource::DiagonalSignedPolynomial(&atom.source),
                })
            };

        assert!(
            verify(
                &atom.component_b_by_limb,
                &atom.secret,
                &atom.error,
                Some(2)
            )
            .is_ok()
        );

        let mut tampered_component = atom.component_b_by_limb.clone();
        tampered_component[7][31] = (tampered_component[7][31] + 1) % group_primes[7];
        assert!(verify(&tampered_component, &atom.secret, &atom.error, Some(2)).is_err());

        assert!(
            verify(
                &atom.component_b_by_limb,
                &atom.secret,
                &atom.error,
                Some(3)
            )
            .is_err(),
            "a wrong diagonal position must not verify"
        );

        assert!(
            verify(
                &atom.component_b_by_limb,
                &atom.secret,
                &atom.error,
                Some(group_primes.len())
            )
            .is_err(),
            "an out-of-range diagonal position must be rejected"
        );

        let off_diagonal_atom = synthetic_atom(
            group_primes,
            ring_degree,
            None,
            "out-of-range-public-product",
        );
        let aggregate = vec![1_u64; ring_degree];
        assert!(
            verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
                group: &group,
                domain: &domain,
                diagonal_group_position: Some(group_primes.len()),
                component_b_by_limb: &off_diagonal_atom.component_b_by_limb,
                public_sample_by_limb: &off_diagonal_atom.public_sample_by_limb,
                secret_coefficients: &off_diagonal_atom.secret,
                error_coefficients: &off_diagonal_atom.error,
                source: DigitAtomSource::DiagonalPublicProduct {
                    aggregate_residues: &aggregate,
                    signed_polynomial: &off_diagonal_atom.source,
                },
            })
            .is_err(),
            "an out-of-range public-product diagonal position must not be treated as no diagonal"
        );

        let mut non_ternary_secret = atom.secret.clone();
        non_ternary_secret[0] = 2;
        assert!(
            verify(
                &atom.component_b_by_limb,
                &non_ternary_secret,
                &atom.error,
                Some(2)
            )
            .is_err(),
            "secret support beyond ternary must be rejected"
        );

        let mut flipped_secret = atom.secret.clone();
        let flip_index = flipped_secret
            .iter()
            .position(|value| *value != 0)
            .expect("sampled secret has a nonzero coefficient");
        flipped_secret[flip_index] = -flipped_secret[flip_index];
        assert!(
            verify(
                &atom.component_b_by_limb,
                &flipped_secret,
                &atom.error,
                Some(2)
            )
            .is_err(),
            "a support-valid but wrong secret must fail the congruence"
        );

        let mut oversized_error = atom.error.clone();
        oversized_error[1] = 3;
        assert!(
            verify(
                &atom.component_b_by_limb,
                &atom.secret,
                &oversized_error,
                Some(2)
            )
            .is_err(),
            "error support beyond eta-2 must be rejected"
        );

        let mut unreduced = atom.component_b_by_limb.clone();
        unreduced[0][0] = group_primes[0];
        assert!(verify(&unreduced, &atom.secret, &atom.error, Some(2)).is_err());
    }

    /// The required cross-check: material generated by the production
    /// kernel key-switch keygen satisfies the limb-group digit atom with the
    /// witnesses re-derived from the same deterministic seeds.
    #[test]
    fn kernel_galois_keygen_material_satisfies_the_limb_group_atom() {
        use crate::bgv::evaluator::engine::DevelopmentBgvKey;
        use crate::bgv::evaluator::key_switch::generate_galois_key;
        use crate::bgv::parameters::{POLYNOMIAL_DEGREE, SPECIAL_PRIME};

        let parameters = sixteen_limb_group_field_parameters();
        let level = 1;
        let galois_element = 3;
        let seed_hex = "limb-group-atom-cross-check-seed";
        let key = DevelopmentBgvKey::generate("00112233445566778899aabbccddeeff")
            .expect("development key generates");
        let galois_key = generate_galois_key(&key, galois_element, level, seed_hex)
            .expect("galois key generates");

        let group_primes = &DATA_PRIMES[..=level];
        let group = LimbGroupContext::new(&parameters, group_primes).expect("group builds");
        let domain = NegacyclicDomain::new(&parameters, POLYNOMIAL_DEGREE).expect("domain builds");
        let key_switch_domain = format!("galois-{galois_element}");

        let rotated_secret = {
            let two_n = 2 * POLYNOMIAL_DEGREE;
            let mut rotated = vec![0_i64; POLYNOMIAL_DEGREE];
            for (coefficient_index, value) in key.secret().iter().enumerate() {
                let exponent = (coefficient_index * galois_element) % two_n;
                if exponent < POLYNOMIAL_DEGREE {
                    rotated[exponent] += value;
                } else {
                    rotated[exponent - POLYNOMIAL_DEGREE] -= value;
                }
            }
            rotated
        };
        let hybrid_gadget_source = rotated_secret
            .iter()
            .map(|coefficient| {
                coefficient
                    .checked_mul(i64::try_from(SPECIAL_PRIME).expect("special prime fits i64"))
                    .expect("hybrid gadget source fits i64")
            })
            .collect::<Vec<_>>();

        for (digit_index, component) in galois_key.components.iter().enumerate() {
            let component_b = component
                .component_b_coefficients()
                .expect("generated component b converts from NTT form");
            let component_b = component_b[..group_primes.len()].to_vec();
            let digit_bytes = (digit_index as u64).to_le_bytes();
            let error = DeterministicSampler::new(
                KEY_SWITCH_ERROR_DOMAIN,
                &[
                    key_switch_domain.as_bytes(),
                    seed_hex.as_bytes(),
                    &digit_bytes,
                ],
            )
            .centered_binomial_eta2(POLYNOMIAL_DEGREE);
            let public_sample_by_limb = group_primes
                .iter()
                .map(|modulus| {
                    let modulus_bytes = modulus.to_le_bytes();
                    DeterministicSampler::new(
                        KEY_SWITCH_SAMPLE_DOMAIN,
                        &[
                            key_switch_domain.as_bytes(),
                            seed_hex.as_bytes(),
                            &digit_bytes,
                            &modulus_bytes,
                        ],
                    )
                    .uniform_residues(*modulus, POLYNOMIAL_DEGREE)
                })
                .collect::<Vec<_>>();

            let report = verify_limb_group_digit_atom(LimbGroupDigitAtomInput {
                group: &group,
                domain: &domain,
                diagonal_group_position: Some(digit_index),
                component_b_by_limb: &component_b,
                public_sample_by_limb: &public_sample_by_limb,
                secret_coefficients: key.secret(),
                error_coefficients: &error,
                source: DigitAtomSource::DiagonalSignedPolynomial(&hybrid_gadget_source),
            })
            .expect("kernel-generated digit material satisfies the limb-group atom");
            assert!(report.maximum_carry_magnitude <= report.carry_bound);
        }
    }
}
