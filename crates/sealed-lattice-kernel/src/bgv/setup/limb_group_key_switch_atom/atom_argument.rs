//! Sound relation reduction for the key-switch digit atom.
//!
//! The atom relation over the proof field is, coefficient-wise,
//!
//! ```text
//! B + A * s - t * e - G * source - Q * c = 0
//! ```
//!
//! with `A` (public sample) and `s` (secret) multiplied by negacyclic
//! convolution, `G` the scalar gadget idempotent, `t` the plaintext modulus,
//! `Q` the limb-group modulus, and `c` the bounded carry. `source` is `s`
//! (relinearization round one), the automorphism image `phi_g(s)` (Galois), or
//! a public product with `s` (round two). Every term is linear in the committed
//! witness `(s, e, c)`.
//!
//! Batching the `N` coefficient identities with a Fiat-Shamir challenge vector
//! `gamma` over the large proof field collapses the whole relation to one linear
//! claim over the witness:
//!
//! ```text
//! <gamma, R> = <adjoint(A) * gamma - G * gamma, s> - t <gamma, e> - Q <gamma, c> + <gamma, B> = 0,
//! ```
//!
//! using the negacyclic adjoint identity `<a * b, c> = <b, adjoint(a) * c>`.
//! Since `R` has degree below `N` and the proof field has more than `2^768`
//! elements, `<gamma, R> = 0` for a random `gamma` implies `R = 0` except with
//! probability at most `N / |field|`, about `2^-755`. So the relation reduces,
//! with negligible soundness loss, to proving one public linear form over the
//! committed short witness equals a public target. That linear opening plus the
//! support and range arguments are the remaining backend obligations; this
//! module builds and validates the reduction itself, which is the piece the
//! soundness of the whole argument rests on.
//!
//! Test-gated: this is the family's relation core, exercised by its own
//! correctness tests, not yet wired into any acceptance path.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;

/// The public linear form `<s_coefficients, s> + <e_coefficients, e> +
/// <c_coefficients, c>` that a correct witness makes equal to `target`.
pub(crate) struct AtomLinearForm<const LIMB_COUNT: usize> {
    pub(crate) secret_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(crate) error_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(crate) carry_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(crate) target: [u64; LIMB_COUNT],
}

/// The diagonal source shape of the atom, mirroring the relation statement.
#[allow(dead_code)] // round-two (public-product) and off-diagonal (no-source) variants are part of the relation surface, constructed by those atom paths
pub(crate) enum ReductionSource<'a, const LIMB_COUNT: usize> {
    /// Round one / Galois: source is a public linear image of the secret,
    /// given as the per-coefficient permutation-with-sign of `s`. For round one
    /// this is the identity; for Galois it is `phi_g`. The map is applied to the
    /// challenge under its adjoint (a permutation-with-sign is its own kind of
    /// adjoint), so the caller passes the already-adjointed challenge image.
    LinearImageOfSecret {
        adjoint_image_of_challenge: &'a [[u64; LIMB_COUNT]],
    },
    /// Round two: source is `public_aggregate * s`, so the source contributes
    /// `G * <aggregate-adjoint * gamma, s>` to the secret coefficients.
    PublicProductWithSecret {
        aggregate_adjoint_times_challenge: &'a [[u64; LIMB_COUNT]],
    },
    /// The atom has no diagonal source in this limb group.
    NoSource,
}

/// The public atom data the reduction consumes. All are proof-field elements.
pub(crate) struct AtomPublicInputs<'a, const LIMB_COUNT: usize> {
    /// Recombined public sample `A` (the negacyclic multiplier of `s`).
    pub(crate) recombined_sample: &'a [[u64; LIMB_COUNT]],
    /// Recombined transported component `B`.
    pub(crate) recombined_component_b: &'a [[u64; LIMB_COUNT]],
    /// Scalar gadget idempotent `G` of the diagonal limb.
    pub(crate) gadget_idempotent: [u64; LIMB_COUNT],
    /// Limb-group modulus `Q` as a field element.
    pub(crate) group_modulus: [u64; LIMB_COUNT],
    /// Plaintext modulus `t` as a field element.
    pub(crate) plaintext_modulus: [u64; LIMB_COUNT],
}

/// The negacyclic adjoint `adjoint(a)` with `adjoint(a)_0 = a_0` and
/// `adjoint(a)_j = -a_{N-j}`, so `<a * b, c> = <b, adjoint(a) * c>`.
pub(crate) fn negacyclic_adjoint<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let ring_degree = coefficients.len();
    let mut adjoint = vec![parameters.zero(); ring_degree];
    adjoint[0] = coefficients[0];
    for index in 1..ring_degree {
        adjoint[index] = parameters.negate(&coefficients[ring_degree - index]);
    }
    adjoint
}

fn scale<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    vector: &[[u64; LIMB_COUNT]],
    scalar: &[u64; LIMB_COUNT],
) -> Vec<[u64; LIMB_COUNT]> {
    vector
        .iter()
        .map(|value| parameters.multiply(value, scalar))
        .collect()
}

/// Builds the public linear form for one atom and a challenge `gamma`. The
/// caller supplies the challenge and, for the diagonal source, its adjoint image
/// under the source's public linear map (identity for round one). A correct
/// witness satisfies `form(s, e, c) == form.target`.
pub(crate) fn reduce_atom_to_linear_form<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    source: &ReductionSource<'_, LIMB_COUNT>,
    challenge: &[[u64; LIMB_COUNT]],
) -> AtomLinearForm<LIMB_COUNT> {
    let ring_degree = challenge.len();

    // Secret coefficients: adjoint(A) * gamma minus the source contribution.
    let sample_adjoint = negacyclic_adjoint(parameters, public.recombined_sample);
    let mut secret_coefficients = domain.negacyclic_product(&sample_adjoint, challenge);
    match source {
        ReductionSource::LinearImageOfSecret {
            adjoint_image_of_challenge,
        } => {
            // Subtract G * (adjoint source map applied to gamma).
            for index in 0..ring_degree {
                let scaled = parameters.multiply(
                    &public.gadget_idempotent,
                    &adjoint_image_of_challenge[index],
                );
                secret_coefficients[index] =
                    parameters.subtract(&secret_coefficients[index], &scaled);
            }
        }
        ReductionSource::PublicProductWithSecret {
            aggregate_adjoint_times_challenge,
        } => {
            for index in 0..ring_degree {
                let scaled = parameters.multiply(
                    &public.gadget_idempotent,
                    &aggregate_adjoint_times_challenge[index],
                );
                secret_coefficients[index] =
                    parameters.subtract(&secret_coefficients[index], &scaled);
            }
        }
        ReductionSource::NoSource => {}
    }

    // Error coefficients: -t * gamma.
    let negated_plaintext = parameters.negate(&public.plaintext_modulus);
    let error_coefficients = scale(parameters, challenge, &negated_plaintext);

    // Carry coefficients: -Q * gamma.
    let negated_modulus = parameters.negate(&public.group_modulus);
    let carry_coefficients = scale(parameters, challenge, &negated_modulus);

    // Target: -<gamma, B>.
    let mut inner = parameters.zero();
    for index in 0..ring_degree {
        inner = parameters.add(
            &inner,
            &parameters.multiply(&challenge[index], &public.recombined_component_b[index]),
        );
    }
    let target = parameters.negate(&inner);

    AtomLinearForm {
        secret_coefficients,
        error_coefficients,
        carry_coefficients,
        target,
    }
}

/// Evaluates a linear form on a concrete witness. Used by the prover and by the
/// correctness tests; the verifier never calls this (it checks the opening, not
/// the witness).
pub(crate) fn evaluate_linear_form<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    form: &AtomLinearForm<LIMB_COUNT>,
    secret: &[[u64; LIMB_COUNT]],
    error: &[[u64; LIMB_COUNT]],
    carry: &[[u64; LIMB_COUNT]],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for (coefficient, value) in form.secret_coefficients.iter().zip(secret.iter()) {
        accumulator = parameters.add(&accumulator, &parameters.multiply(coefficient, value));
    }
    for (coefficient, value) in form.error_coefficients.iter().zip(error.iter()) {
        accumulator = parameters.add(&accumulator, &parameters.multiply(coefficient, value));
    }
    for (coefficient, value) in form.carry_coefficients.iter().zip(carry.iter()) {
        accumulator = parameters.add(&accumulator, &parameters.multiply(coefficient, value));
    }
    accumulator
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn deterministic_challenge<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        ring_degree: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..ring_degree)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    #[test]
    fn adjoint_identity_holds() {
        // <a * b, c> == <b, adjoint(a) * c> for random ring elements.
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let a = deterministic_challenge(&parameters, ring_degree, 0x11);
        let b = deterministic_challenge(&parameters, ring_degree, 0x22);
        let c = deterministic_challenge(&parameters, ring_degree, 0x33);

        let a_times_b = domain.negacyclic_product(&a, &b);
        let mut left = parameters.zero();
        for index in 0..ring_degree {
            left = parameters.add(&left, &parameters.multiply(&a_times_b[index], &c[index]));
        }

        let adjoint_a = negacyclic_adjoint(&parameters, &a);
        let adjoint_a_times_c = domain.negacyclic_product(&adjoint_a, &c);
        let mut right = parameters.zero();
        for index in 0..ring_degree {
            right = parameters.add(
                &right,
                &parameters.multiply(&b[index], &adjoint_a_times_c[index]),
            );
        }

        assert_eq!(left, right, "negacyclic adjoint identity must hold");
    }

    /// The load-bearing soundness-reduction check: a witness that satisfies the
    /// atom congruence makes the reduced linear form equal its target, for a
    /// random challenge. Built from the pinned relation `b = t*e - a*s + G*s`
    /// (round one, diagonal), matching the statement module's construction.
    #[test]
    fn round_one_witness_satisfies_the_reduced_linear_form() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 128;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");

        // Small signed witness, as field elements.
        let signed = |values: &[i64]| -> Vec<[u64; 13]> {
            values
                .iter()
                .map(|value| parameters.signed_word_to_element(*value))
                .collect()
        };
        let mut secret_values = vec![0_i64; ring_degree];
        let mut error_values = vec![0_i64; ring_degree];
        for index in 0..ring_degree {
            secret_values[index] = ((index * 7) % 3) as i64 - 1; // ternary
            error_values[index] = ((index * 5) % 5) as i64 - 2; // eta-2 range
        }
        let secret = signed(&secret_values);
        let error = signed(&error_values);

        // Public sample A, gadget idempotent G, group modulus Q, plaintext t.
        let sample = deterministic_challenge(&parameters, ring_degree, 0xa5);
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);

        // Build B and the exact carry so the relation holds:
        // R = B + A*s - t*e - G*s - Q*c = 0  =>  choose c = 0 and set
        // B = t*e + G*s - A*s, then the relation holds with carry zero. For a
        // nonzero carry we instead absorb a chosen small carry into B.
        let a_times_s = domain.negacyclic_product(&sample, &secret);
        let carry_values = (0..ring_degree)
            .map(|index| ((index % 3) as i64) - 1)
            .collect::<Vec<_>>();
        let carry = signed(&carry_values);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            // B = t*e + G*s + Q*c - A*s
            let t_e = parameters.multiply(&plaintext_modulus, &error[index]);
            let g_s = parameters.multiply(&gadget_idempotent, &secret[index]);
            let q_c = parameters.multiply(&group_modulus, &carry[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.add(&value, &q_c);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }

        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent,
            group_modulus,
            plaintext_modulus,
        };

        // Round one: source = s, so the adjoint source image of the challenge is
        // the challenge itself (identity map).
        for challenge_seed in [0x1u64, 0xbeef, 0x1234_5678] {
            let challenge = deterministic_challenge(&parameters, ring_degree, challenge_seed);
            let source = ReductionSource::LinearImageOfSecret {
                adjoint_image_of_challenge: &challenge,
            };
            let form =
                reduce_atom_to_linear_form(&parameters, &domain, &public, &source, &challenge);
            let evaluated = evaluate_linear_form(&parameters, &form, &secret, &error, &carry);
            assert_eq!(
                evaluated, form.target,
                "a correct witness must satisfy the reduced linear form (challenge {challenge_seed:#x})"
            );
        }
    }

    #[test]
    fn a_wrong_witness_breaks_the_reduced_form_whp() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 128;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let signed = |values: &[i64]| -> Vec<[u64; 13]> {
            values
                .iter()
                .map(|value| parameters.signed_word_to_element(*value))
                .collect()
        };
        let secret = signed(
            &(0..ring_degree)
                .map(|i| ((i * 7) % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let error = signed(
            &(0..ring_degree)
                .map(|i| ((i * 5) % 5) as i64 - 2)
                .collect::<Vec<_>>(),
        );
        let sample = deterministic_challenge(&parameters, ring_degree, 0xa5);
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let a_times_s = domain.negacyclic_product(&sample, &secret);
        let carry = signed(&vec![0_i64; ring_degree]);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
            let t_e = parameters.multiply(&plaintext_modulus, &error[index]);
            let g_s = parameters.multiply(&gadget_idempotent, &secret[index]);
            let mut value = parameters.add(&t_e, &g_s);
            value = parameters.subtract(&value, &a_times_s[index]);
            component_b[index] = value;
        }
        let public = AtomPublicInputs {
            recombined_sample: &sample,
            recombined_component_b: &component_b,
            gadget_idempotent,
            group_modulus,
            plaintext_modulus,
        };
        // Flip one secret coefficient: the relation no longer holds, so the
        // reduced form must miss its target for a random challenge.
        let mut wrong_secret = secret.clone();
        wrong_secret[3] = parameters.add(&secret[3], &parameters.unsigned_word_to_element(1));

        let challenge = deterministic_challenge(&parameters, ring_degree, 0xfeed);
        let source = ReductionSource::LinearImageOfSecret {
            adjoint_image_of_challenge: &challenge,
        };
        let form = reduce_atom_to_linear_form(&parameters, &domain, &public, &source, &challenge);
        let evaluated = evaluate_linear_form(&parameters, &form, &wrong_secret, &error, &carry);
        assert_ne!(
            evaluated, form.target,
            "a tampered witness must break the reduced linear form"
        );
    }
}
