//! Sound reduction of one key-switch digit atom to a single inner product.
//!
//! The atom congruence over the proof field is, coefficient-wise,
//!
//! ```text
//! B + A (*) s - t e - G source - Q c = 0,
//! ```
//!
//! with `A (*) s` a negacyclic convolution. Batching the `N` coefficient
//! identities with a random challenge `gamma` collapses the relation to one
//! linear claim `<L, w> = target` over the witness `w = (s || e || c)`, using
//! the negacyclic adjoint identity `<a (*) b, c> = <b, adjoint(a) (*) c>`. Since
//! the residual has degree below `N` and the proof field has more than `2^768`
//! elements, `<gamma, residual> = 0` for a random `gamma` implies the residual
//! is zero except with probability about `N / |field|` (about `2^-755`). This is
//! the family's relation core; it is the same reduction validated in the
//! test-gated `atom_argument` module, hosted here for the production backend.

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;

// Public atom data the reduction consumes, all as proof-field elements.
pub(super) struct AtomPublicInputs<'a, const LIMB_COUNT: usize> {
    // Recombined public sample `A` (negacyclic multiplier of the secret).
    pub(super) recombined_sample: &'a [[u64; LIMB_COUNT]],
    // Recombined transported component `B`.
    pub(super) recombined_component_b: &'a [[u64; LIMB_COUNT]],
    // Scalar gadget idempotent `G` of the diagonal limb.
    pub(super) gadget_idempotent: [u64; LIMB_COUNT],
    // Limb-group modulus `Q`.
    pub(super) group_modulus: [u64; LIMB_COUNT],
    // Plaintext modulus `t`.
    pub(super) plaintext_modulus: [u64; LIMB_COUNT],
}

// The public linear form: `<secret_coeffs, s> + <error_coeffs, e> +
// <carry_coeffs, c> = target` for a correct witness.
pub(super) struct AtomLinearForm<const LIMB_COUNT: usize> {
    pub(super) secret_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(super) error_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(super) carry_coefficients: Vec<[u64; LIMB_COUNT]>,
    // Carries `-<gamma, B_public_j>`. Retained for the documented atom-form
    // structure even though the component term no longer enters the sumcheck
    // target (it rides the material form against the committed `B_col_j`).
    #[allow(dead_code)]
    pub(super) target: [u64; LIMB_COUNT],
}

// The negacyclic adjoint: `adjoint(a)_0 = a_0`, `adjoint(a)_j = -a_{N-j}`.
fn negacyclic_adjoint<const LIMB_COUNT: usize>(
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

// The diagonal source shape of one atom. Round one and Galois contribute
// `G * source` with the scalar gadget idempotent `G`; round two's `aggregate`
// is the CENTERED diagonal aggregate term (the CRT recombination of the
// round-one aggregate placed at the diagonal limb), which already carries the
// `G` fold, so its contribution is `aggregate (*) s` with no further scaling.
// Centering before the convolution is what keeps the diagonal term inside the
// `N * Q/2` no-wrap bound the relation layer derives.
pub(super) enum AtomSource<'a, const LIMB_COUNT: usize> {
    // Relinearization round one: source = s (identity map).
    RoundOne,
    // Galois rotation: source = phi_g(s), the automorphism s(X) -> s(X^g).
    Galois { galois_element: usize },
    // Relinearization round two: the centered diagonal aggregate term.
    RoundTwo { aggregate: &'a [[u64; LIMB_COUNT]] },
}

// The transpose action of the automorphism on a public vector, mirroring the
// tested `relation/diagonal_source_algebra::galois_automorphism_transpose_apply`
// over the proof field: `(M_phi^T u)_i = u[i*g mod 2N]` with the negacyclic sign
// fold, so that `<u, phi_g(s)> = <M_phi^T u, s>`.
fn galois_transpose_apply<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    vector: &[[u64; LIMB_COUNT]],
    galois_element: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let degree = vector.len();
    let ring_order = 2 * degree;
    (0..degree)
        .map(|index| {
            let target = (index * galois_element) % ring_order;
            if target < degree {
                vector[target]
            } else {
                parameters.negate(&vector[target - degree])
            }
        })
        .collect()
}

// The adjoint image of the challenge under the source's public linear map:
// identity for round one, the automorphism transpose for Galois, and
// `adjoint(aggregate) (*) gamma` for round two (so `<gamma, aggregate (*) s> =
// <adjoint(aggregate) (*) gamma, s>`).
fn source_adjoint_image<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    source: &AtomSource<'_, LIMB_COUNT>,
    challenge: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    match source {
        AtomSource::RoundOne => challenge.to_vec(),
        AtomSource::Galois { galois_element } => {
            galois_transpose_apply(parameters, challenge, *galois_element)
        }
        AtomSource::RoundTwo { aggregate } => {
            let aggregate_adjoint = negacyclic_adjoint(parameters, aggregate);
            domain.negacyclic_product(&aggregate_adjoint, challenge)
        }
    }
}

// General atom reduction for any source: builds the public linear form for
// challenge `gamma`. The secret coefficients are `adjoint(A) (*) gamma - G *
// source_adjoint_image(gamma)` (round two's aggregate carries the `G` fold
// already, so its image is not rescaled); the error coefficients `-t gamma`;
// the carry coefficients `-Q gamma`; the target `-<gamma, B>`.
pub(super) fn reduce_atom<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    source: &AtomSource<'_, LIMB_COUNT>,
    challenge: &[[u64; LIMB_COUNT]],
) -> AtomLinearForm<LIMB_COUNT> {
    let sample_adjoint = negacyclic_adjoint(parameters, public.recombined_sample);
    let mut secret_coefficients = domain.negacyclic_product(&sample_adjoint, challenge);
    let source_image = source_adjoint_image(parameters, domain, source, challenge);
    let gadget_scales_source = !matches!(source, AtomSource::RoundTwo { .. });
    for (coefficient, image_value) in secret_coefficients.iter_mut().zip(source_image.iter()) {
        let scaled = if gadget_scales_source {
            parameters.multiply(&public.gadget_idempotent, image_value)
        } else {
            *image_value
        };
        *coefficient = parameters.subtract(coefficient, &scaled);
    }
    let negated_plaintext = parameters.negate(&public.plaintext_modulus);
    let error_coefficients = challenge
        .iter()
        .map(|value| parameters.multiply(value, &negated_plaintext))
        .collect();
    let negated_modulus = parameters.negate(&public.group_modulus);
    let carry_coefficients = challenge
        .iter()
        .map(|value| parameters.multiply(value, &negated_modulus))
        .collect();
    let mut inner = parameters.zero();
    for (challenge_value, component) in challenge.iter().zip(public.recombined_component_b.iter()) {
        inner = parameters.add(&inner, &parameters.multiply(challenge_value, component));
    }
    let target = parameters.negate(&inner);

    AtomLinearForm {
        secret_coefficients,
        error_coefficients,
        carry_coefficients,
        target,
    }
}
