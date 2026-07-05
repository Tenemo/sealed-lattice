//! Per-key aggregation of the digit atoms.
//!
//! A key has 16 digit atoms that share one secret `s`; only the per-digit error
//! `e_j` and carry `c_j` differ. Proving the 16 congruences separately would
//! commit and open `s` sixteen times. Instead this module batches them: each
//! atom's congruence reduces (via `atom_argument`) to a linear claim
//! `L_j(s, e_j, c_j) = target_j`, and a random per-atom challenge `delta_j`
//! combines them into one linear claim over the shared witness
//! `w = (s || e_0..e_15 || c_0..c_15)`:
//!
//! ```text
//! sum_j delta_j L_j(s, e_j, c_j) = sum_j delta_j target_j.
//! ```
//!
//! The secret coefficients of the combined form accumulate across atoms (all
//! `L_j` act on the same `s`), while the error and carry coefficients stay
//! per-atom. So `s` is committed and opened once per key, not once per atom -
//! the amortization the per-key byte budget relies on. One linear opening over
//! the shared commitment proves the whole key's relation layer; the secret
//! ternary support is proven once and the per-digit error and carry supports
//! per atom (composed from the support modules).
//!
//! The verifier re-derives `delta_j`, rebuilds the combined form and target from
//! public data, and checks the opening - witness-free. If any atom's congruence
//! fails, the combined claim misses its target except with probability about
//! `N / |field|` per the batching challenge, so a single tampered atom is caught.
//!
//! HONEST SCOPE. This is the sound, witness-free per-key relation aggregation and
//! its tamper set. Wiring per-trustee schedule aggregation and transport through
//! the existing chunked-sidecar path, and using the zero-knowledge opening of
//! `zk_linear_opening` in place of the plain opening, are the remaining
//! integration. Test-gated.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::atom_argument::{AtomPublicInputs, ReductionSource, reduce_atom_to_linear_form};
use super::linear_opening::{
    FlatCommitment, LinearOpeningParameters, LinearOpeningProof, commit_flat, prove_linear_opening,
    verify_linear_opening,
};
use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;
use crate::hashing::hash512;

const DELTA_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/key-aggregation-delta-v1";

/// Public inputs for one digit atom of a key (round-one / Galois source is a
/// public linear image of the shared secret; here the round-one identity image).
pub(crate) struct KeyAtomPublic<'a, const LIMB_COUNT: usize> {
    pub(crate) recombined_sample: &'a [[u64; LIMB_COUNT]],
    pub(crate) recombined_component_b: &'a [[u64; LIMB_COUNT]],
    pub(crate) gadget_idempotent: [u64; LIMB_COUNT],
    pub(crate) group_modulus: [u64; LIMB_COUNT],
    pub(crate) plaintext_modulus: [u64; LIMB_COUNT],
}

pub(crate) struct KeyAggregationProof<const LIMB_COUNT: usize> {
    pub(crate) linear_opening: LinearOpeningProof<LIMB_COUNT>,
}

/// Derives the per-atom batching challenge `delta_j` from the commitment and the
/// atom index.
fn delta_for_atom<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    atom_index: usize,
) -> [u64; LIMB_COUNT] {
    let mut seed = Vec::new();
    for row in &commitment.rows {
        for limb in row {
            seed.extend_from_slice(&limb.to_le_bytes());
        }
    }
    let digest = hash512(DELTA_DOMAIN, &[&seed, &(atom_index as u64).to_le_bytes()]);
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word)
}

/// Derives the shared batching challenge vector `gamma` used inside every atom's
/// reduction (common across atoms so the secret coefficients accumulate).
fn gamma_vector<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    ring_degree: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut seed = Vec::new();
    for row in &commitment.rows {
        for limb in row {
            seed.extend_from_slice(&limb.to_le_bytes());
        }
    }
    (0..ring_degree)
        .map(|index| {
            let digest = hash512(
                DELTA_DOMAIN,
                &[b"gamma", &seed, &(index as u64).to_le_bytes()],
            );
            let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
            parameters.unsigned_word_to_element(word)
        })
        .collect()
}

/// Builds the combined linear form over `w = (s || e_0..e_{k-1} || c_0..c_{k-1})`
/// and its target from the atom public inputs, `gamma`, and the per-atom deltas.
#[allow(clippy::type_complexity)]
fn combined_form<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    atoms: &[KeyAtomPublic<'_, LIMB_COUNT>],
    gamma: &[[u64; LIMB_COUNT]],
    commitment: &FlatCommitment<LIMB_COUNT>,
) -> (Vec<[u64; LIMB_COUNT]>, [u64; LIMB_COUNT]) {
    let ring_degree = gamma.len();
    let atom_count = atoms.len();
    let mut secret_coefficients = vec![parameters.zero(); ring_degree];
    let mut error_coefficients = vec![parameters.zero(); ring_degree * atom_count];
    let mut carry_coefficients = vec![parameters.zero(); ring_degree * atom_count];
    let mut target = parameters.zero();

    for (atom_index, atom) in atoms.iter().enumerate() {
        let delta = delta_for_atom(parameters, commitment, atom_index);
        let public = AtomPublicInputs {
            recombined_sample: atom.recombined_sample,
            recombined_component_b: atom.recombined_component_b,
            gadget_idempotent: atom.gadget_idempotent,
            group_modulus: atom.group_modulus,
            plaintext_modulus: atom.plaintext_modulus,
        };
        let source = ReductionSource::LinearImageOfSecret {
            adjoint_image_of_challenge: gamma,
        };
        let form = reduce_atom_to_linear_form(parameters, domain, &public, &source, gamma);
        // Accumulate the shared-secret coefficients (weighted by delta).
        for index in 0..ring_degree {
            secret_coefficients[index] = parameters.add(
                &secret_coefficients[index],
                &parameters.multiply(&delta, &form.secret_coefficients[index]),
            );
            error_coefficients[atom_index * ring_degree + index] =
                parameters.multiply(&delta, &form.error_coefficients[index]);
            carry_coefficients[atom_index * ring_degree + index] =
                parameters.multiply(&delta, &form.carry_coefficients[index]);
        }
        target = parameters.add(&target, &parameters.multiply(&delta, &form.target));
    }

    let mut combined = Vec::with_capacity(ring_degree + 2 * ring_degree * atom_count);
    combined.extend_from_slice(&secret_coefficients);
    combined.extend_from_slice(&error_coefficients);
    combined.extend_from_slice(&carry_coefficients);
    (combined, target)
}

/// Proves a key's `atom_count` round-one digit atoms with one opening over the
/// shared witness `w = (s || e_0..e_{k-1} || c_0..c_{k-1})`.
pub(crate) fn prove_key<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    atoms: &[KeyAtomPublic<'_, LIMB_COUNT>],
    secret: &[[u64; LIMB_COUNT]],
    errors: &[Vec<[u64; LIMB_COUNT]>],
    carries: &[Vec<[u64; LIMB_COUNT]>],
    randomness: &[[u64; LIMB_COUNT]],
    attempt_seed: u64,
) -> (FlatCommitment<LIMB_COUNT>, KeyAggregationProof<LIMB_COUNT>) {
    let ring_degree = secret.len();
    let atom_count = atoms.len();
    let mut witness = Vec::with_capacity(ring_degree + 2 * ring_degree * atom_count);
    witness.extend_from_slice(secret);
    for error in errors {
        witness.extend_from_slice(error);
    }
    for carry in carries {
        witness.extend_from_slice(carry);
    }
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let gamma = gamma_vector(parameters, &commitment, ring_degree);
    let (combined, target) = combined_form(parameters, domain, atoms, &gamma, &commitment);

    let (_, linear_opening) = prove_linear_opening(
        parameters,
        opening_parameters,
        &witness,
        randomness,
        &combined,
        &target,
        attempt_seed,
    );

    (commitment, KeyAggregationProof { linear_opening })
}

/// Verifies a key aggregation proof without the witness.
pub(crate) fn verify_key<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    atoms: &[KeyAtomPublic<'_, LIMB_COUNT>],
    ring_degree: usize,
    commitment: &FlatCommitment<LIMB_COUNT>,
    proof: &KeyAggregationProof<LIMB_COUNT>,
) -> bool {
    let gamma = gamma_vector(parameters, commitment, ring_degree);
    let (combined, target) = combined_form(parameters, domain, atoms, &gamma, commitment);
    verify_linear_opening(
        parameters,
        opening_parameters,
        commitment,
        &combined,
        &target,
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

    struct KeyMaterial {
        samples: Vec<Vec<[u64; 13]>>,
        components_b: Vec<Vec<[u64; 13]>>,
        gadget: [u64; 13],
        group_modulus: [u64; 13],
        plaintext_modulus: [u64; 13],
        errors: Vec<Vec<[u64; 13]>>,
        carries: Vec<Vec<[u64; 13]>>,
    }

    /// Builds `atom_count` synthetic round-one atoms sharing one secret, each
    /// with B set so B + A*s - t*e - G*s - Q*c = 0 holds.
    fn synthetic_key(
        parameters: &ProofFieldParameters<13>,
        domain: &NegacyclicDomain<'_, 13>,
        ring_degree: usize,
        atom_count: usize,
        secret: &[[u64; 13]],
    ) -> KeyMaterial {
        let gadget = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let mut samples = Vec::new();
        let mut components_b = Vec::new();
        let mut errors = Vec::new();
        let mut carries = Vec::new();
        for atom_index in 0..atom_count {
            let sample = deterministic(parameters, ring_degree, 0xa5 + atom_index as u64);
            let error = signed(
                parameters,
                &(0..ring_degree)
                    .map(|i| ((i + atom_index) % 5) as i64 - 2)
                    .collect::<Vec<_>>(),
            );
            let carry = signed(
                parameters,
                &(0..ring_degree)
                    .map(|i| ((i + atom_index) % 3) as i64 - 1)
                    .collect::<Vec<_>>(),
            );
            let a_times_s = domain.negacyclic_product(&sample, secret);
            let mut component_b = vec![parameters.zero(); ring_degree];
            for index in 0..ring_degree {
                let t_e = parameters.multiply(&plaintext_modulus, &error[index]);
                let g_s = parameters.multiply(&gadget, &secret[index]);
                let q_c = parameters.multiply(&group_modulus, &carry[index]);
                let mut value = parameters.add(&t_e, &g_s);
                value = parameters.add(&value, &q_c);
                value = parameters.subtract(&value, &a_times_s[index]);
                component_b[index] = value;
            }
            samples.push(sample);
            components_b.push(component_b);
            errors.push(error);
            carries.push(carry);
        }
        KeyMaterial {
            samples,
            components_b,
            gadget,
            group_modulus,
            plaintext_modulus,
            errors,
            carries,
        }
    }

    fn atoms_from<'a>(material: &'a KeyMaterial) -> Vec<KeyAtomPublic<'a, 13>> {
        (0..material.samples.len())
            .map(|index| KeyAtomPublic {
                recombined_sample: &material.samples[index],
                recombined_component_b: &material.components_b[index],
                gadget_idempotent: material.gadget,
                group_modulus: material.group_modulus,
                plaintext_modulus: material.plaintext_modulus,
            })
            .collect()
    }

    #[test]
    fn aggregated_key_accepts_honest_and_rejects_a_tampered_atom() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 32;
        let atom_count = 4;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let secret = signed(
            &parameters,
            &(0..ring_degree)
                .map(|i| ((i * 7) % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let material = synthetic_key(&parameters, &domain, ring_degree, atom_count, &secret);
        let atoms = atoms_from(&material);
        let opening_parameters = LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: ring_degree + 2 * ring_degree * atom_count,
            randomness_length: 6,
            matrix_seed: 0x9a66,
            mask_bound: 1,
        };
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);

        let (commitment, proof) = prove_key(
            &parameters,
            &domain,
            &opening_parameters,
            &atoms,
            &secret,
            &material.errors,
            &material.carries,
            &randomness,
            0x5eed,
        );
        assert!(
            verify_key(
                &parameters,
                &domain,
                &opening_parameters,
                &atoms,
                ring_degree,
                &commitment,
                &proof,
            ),
            "an honest key's 16-atom-style aggregation must verify with one opening"
        );

        // Tamper: flip one secret coefficient (violates every atom that uses it).
        let mut bad_secret = secret.clone();
        bad_secret[3] = parameters.add(&bad_secret[3], &parameters.unsigned_word_to_element(1));
        let (bad_commitment, bad_proof) = prove_key(
            &parameters,
            &domain,
            &opening_parameters,
            &atoms,
            &bad_secret,
            &material.errors,
            &material.carries,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_key(
                &parameters,
                &domain,
                &opening_parameters,
                &atoms,
                ring_degree,
                &bad_commitment,
                &bad_proof,
            ),
            "a tampered shared secret must fail the aggregated key proof"
        );
    }

    #[test]
    fn tampering_one_atom_error_is_caught_by_the_batch() {
        let parameters = sixteen_limb_group_field_parameters();
        let ring_degree = 32;
        let atom_count = 4;
        let domain = NegacyclicDomain::new(&parameters, ring_degree).expect("domain builds");
        let secret = signed(
            &parameters,
            &(0..ring_degree)
                .map(|i| ((i * 5) % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let material = synthetic_key(&parameters, &domain, ring_degree, atom_count, &secret);
        let atoms = atoms_from(&material);
        let opening_parameters = LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: ring_degree + 2 * ring_degree * atom_count,
            randomness_length: 6,
            matrix_seed: 0x9a66,
            mask_bound: 1,
        };
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);

        // Corrupt one digit's error without fixing its component B.
        let mut bad_errors = material.errors.clone();
        bad_errors[2][1] =
            parameters.add(&bad_errors[2][1], &parameters.unsigned_word_to_element(1));
        let (commitment, proof) = prove_key(
            &parameters,
            &domain,
            &opening_parameters,
            &atoms,
            &secret,
            &bad_errors,
            &material.carries,
            &randomness,
            0x5eed,
        );
        assert!(
            !verify_key(
                &parameters,
                &domain,
                &opening_parameters,
                &atoms,
                ring_degree,
                &commitment,
                &proof,
            ),
            "a single tampered atom error must be caught by the batched key proof"
        );
    }
}
