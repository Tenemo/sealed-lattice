//! End-to-end witness-free atom relation proof.
//!
//! Composes the sound reduction (`atom_argument`) with the witness-free linear
//! opening (`linear_opening`): the prover commits the flat witness `w =
//! (s || e || c)`, derives the batching challenge `gamma` by Fiat-Shamir from the
//! commitment and the public statement, reduces the atom congruence to the
//! single linear claim `<L, w> = -<gamma, B>`, and proves it. The verifier
//! re-derives `gamma`, rebuilds `L` and the target from public data alone, and
//! checks the linear opening. It never sees `w`.
//!
//! What this establishes soundly: acceptance requires `<L, w> = -<gamma, B>`
//! bound to the commitment, which (over the 770-bit proof field) implies the
//! atom congruence except with probability about `N / |field|`, about `2^-755`,
//! plus the Module-SIS binding of the opening. What this module does NOT yet
//! enforce, and which is required for full soundness: the SUPPORT and RANGE of
//! the witness (ternary `s`, eta-2 `e`, bounded carry `c`). Those are the LNP22
//! quadratic-relation and approximate-range proofs; the commitment decision
//! record states the accounting, and this backend leaves an explicit hook for
//! them rather than pretending the norm is enforced. The `gamma` challenge here
//! is a single word-valued element (measurement-scale); a full instantiation
//! draws it from the large structured challenge set the soundness bound needs.
//! Test-gated.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::atom_argument::{
    AtomLinearForm, AtomPublicInputs, ReductionSource, reduce_atom_to_linear_form,
};
use super::linear_opening::{
    FlatCommitment, LinearOpeningParameters, LinearOpeningProof, commit_flat, prove_linear_opening,
    verify_linear_opening,
};
use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const GAMMA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/relation-batching-challenge-v1";

/// Flattens the reduced linear form into one vector aligned with `w = s||e||c`.
fn flatten_linear_form<const LIMB_COUNT: usize>(
    form: &AtomLinearForm<LIMB_COUNT>,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut flat = Vec::with_capacity(
        form.secret_coefficients.len()
            + form.error_coefficients.len()
            + form.carry_coefficients.len(),
    );
    flat.extend_from_slice(&form.secret_coefficients);
    flat.extend_from_slice(&form.error_coefficients);
    flat.extend_from_slice(&form.carry_coefficients);
    flat
}

/// Derives the relation batching challenge vector from the commitment and the
/// public statement material, so the prover cannot pick the witness after seeing
/// it.
fn derive_gamma<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    ring_degree: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut seed_bytes = Vec::new();
    let push = |element: &[u64; LIMB_COUNT], out: &mut Vec<u8>| {
        for limb in element {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    };
    for row in &commitment.rows {
        push(row, &mut seed_bytes);
    }
    for value in public.recombined_sample {
        push(value, &mut seed_bytes);
    }
    for value in public.recombined_component_b {
        push(value, &mut seed_bytes);
    }
    push(&public.gadget_idempotent, &mut seed_bytes);
    push(&public.group_modulus, &mut seed_bytes);
    push(&public.plaintext_modulus, &mut seed_bytes);

    (0..ring_degree)
        .map(|index| {
            let digest = hash512(GAMMA_DOMAIN, &[&seed_bytes, &(index as u64).to_le_bytes()]);
            let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
            parameters.unsigned_word_to_element(word)
        })
        .collect()
}

pub(crate) struct AtomProof<const LIMB_COUNT: usize> {
    pub(crate) linear_opening: LinearOpeningProof<LIMB_COUNT>,
}

/// Proves one round-one atom (source is the secret). Returns the commitment and
/// the proof. The witness is the flat `s || e || c`.
pub(crate) fn prove_round_one_atom<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    secret: &[[u64; LIMB_COUNT]],
    error: &[[u64; LIMB_COUNT]],
    carry: &[[u64; LIMB_COUNT]],
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, AtomProof<LIMB_COUNT>) {
    let ring_degree = secret.len();
    let mut witness = Vec::with_capacity(3 * ring_degree);
    witness.extend_from_slice(secret);
    witness.extend_from_slice(error);
    witness.extend_from_slice(carry);

    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let gamma = derive_gamma(parameters, &commitment, public, ring_degree);
    let source = ReductionSource::LinearImageOfSecret {
        adjoint_image_of_challenge: &gamma,
    };
    let form = reduce_atom_to_linear_form(parameters, domain, public, &source, &gamma);
    let linear_form = flatten_linear_form(&form);

    let (_, linear_opening) = prove_linear_opening(
        parameters,
        opening_parameters,
        &witness,
        randomness,
        &linear_form,
        &form.target,
        attempt_seed,
    );

    (commitment, AtomProof { linear_opening })
}

/// Verifies one round-one atom proof without the witness.
pub(crate) fn verify_round_one_atom<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    public: &AtomPublicInputs<'_, LIMB_COUNT>,
    ring_degree: usize,
    commitment: &FlatCommitment<LIMB_COUNT>,
    proof: &AtomProof<LIMB_COUNT>,
) -> bool {
    let gamma = derive_gamma(parameters, commitment, public, ring_degree);
    let source = ReductionSource::LinearImageOfSecret {
        adjoint_image_of_challenge: &gamma,
    };
    let form = reduce_atom_to_linear_form(parameters, domain, public, &source, &gamma);
    let linear_form = flatten_linear_form(&form);
    verify_linear_opening(
        parameters,
        opening_parameters,
        commitment,
        &linear_form,
        &form.target,
        &proof.linear_opening,
    )
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn signed<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        values: &[i64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        values
            .iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    }

    fn deterministic<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        length: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    /// Builds a synthetic round-one atom whose relation holds, and confirms the
    /// witness-free verifier accepts the honest proof and rejects a proof built
    /// on a witness that violates the congruence.
    #[test]
    fn round_one_atom_backend_accepts_honest_and_rejects_violation() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 64;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let opening_parameters = LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: 3 * ring_degree,
            randomness_length: 6,
            matrix_seed: 0xa70b1e,
            mask_bound: 1_000_003,
        };

        // Witness.
        let secret = signed(
            &parameters,
            &(0..ring_degree)
                .map(|i| ((i * 7) % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let error = signed(
            &parameters,
            &(0..ring_degree)
                .map(|i| ((i * 5) % 5) as i64 - 2)
                .collect::<Vec<_>>(),
        );
        let carry = signed(
            &parameters,
            &(0..ring_degree)
                .map(|i| (i % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);

        // Public sample, gadget, moduli.
        let sample = deterministic(&parameters, ring_degree, 0xa5);
        let gadget_idempotent = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);

        // Build B so B + A*s - t*e - G*s - Q*c = 0.
        let a_times_s = domain.negacyclic_product(&sample, &secret);
        let mut component_b = vec![parameters.zero(); ring_degree];
        for index in 0..ring_degree {
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

        // Honest proof verifies.
        let (commitment, proof) = prove_round_one_atom(
            &parameters,
            &domain,
            &opening_parameters,
            &public,
            &secret,
            &error,
            &carry,
            &randomness,
            0x5eed,
        );
        assert!(
            verify_round_one_atom(
                &parameters,
                &domain,
                &opening_parameters,
                &public,
                ring_degree,
                &commitment,
                &proof,
            ),
            "the witness-free verifier must accept an honest atom proof"
        );

        // A witness that violates the congruence (flip one secret coefficient
        // without fixing B) must be rejected.
        let mut bad_secret = secret.clone();
        bad_secret[4] = parameters.add(&bad_secret[4], &parameters.unsigned_word_to_element(1));
        let (bad_commitment, bad_proof) = prove_round_one_atom(
            &parameters,
            &domain,
            &opening_parameters,
            &public,
            &bad_secret,
            &error,
            &carry,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_round_one_atom(
                &parameters,
                &domain,
                &opening_parameters,
                &public,
                ring_degree,
                &bad_commitment,
                &bad_proof,
            ),
            "the verifier must reject a proof whose witness violates the congruence"
        );
    }
}
