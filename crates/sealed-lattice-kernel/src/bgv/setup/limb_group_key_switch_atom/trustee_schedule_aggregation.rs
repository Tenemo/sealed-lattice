//! Per-trustee schedule aggregation, zero-knowledge opening, and chunked
//! sidecar transport for the key-switch digit atoms.
//!
//! This is the composition layer above `key_aggregation`: a trustee's whole
//! evaluation-key schedule (every key, sixteen digit atoms per key) shares one
//! ternary secret `s`, so the entire schedule reduces to ONE commitment and ONE
//! zero-knowledge linear opening over the shared witness
//!
//! ```text
//! w = (s || e_{key 0, atom 0} .. e_{key K-1, atom A-1}
//!        || c_{key 0, atom 0} .. c_{key K-1, atom A-1}).
//! ```
//!
//! Each atom's congruence reduces (via `atom_argument`) to a linear claim; a
//! per-(key, atom) challenge `delta` batches the claims so the secret
//! coefficients accumulate across the schedule while error and carry
//! coefficients stay per-atom. The challenge derivation absorbs the schedule
//! context bytes (ceremony, trustee, schedule binding), so a proof cannot be
//! replayed under a different statement.
//!
//! The opening is the zero-knowledge opening of `zk_linear_opening` (bounded
//! challenge, smudging mask, norm-bounded response) with the witness magnitude
//! bound set for this witness class: ternary secret (1), eta-2 errors (2), and
//! digit carries (`ring_degree + 1`). The honest-verifier interaction is
//! Fiat-Shamir-compilable exactly as documented there.
//!
//! Transport composes two pieces:
//!  - the trustee's public material (recombined `A`, `B` per atom) binds into
//!    one homomorphic material commitment (`material_transport`), and the
//!    published aggregate key is checked against the homomorphic sum across
//!    trustees, so raw per-trustee stores never travel; and
//!  - the proof itself travels as a chunked sidecar: fixed-size chunks, each
//!    hash-bound with its index and the total byte length into one transport
//!    root, so a flipped byte, a reordered chunk, or a truncation is rejected
//!    before any proof bytes are interpreted. This mirrors the setup-proof
//!    material chunk-stream shape at test scale.
//!
//! HONEST SCOPE. Test-gated composition of the measured atom family; not on any
//! acceptance path. Production security parameters for the commitment and the
//! smudging budget live in the key-switch-atom decision records; binding at the
//! full witness size still requires the proper-modulus ring commitment noted in
//! `zk_linear_opening`.

#![allow(
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::type_complexity
)]

use super::atom_argument::{AtomPublicInputs, ReductionSource, reduce_atom_to_linear_form};
use super::key_aggregation::KeyAtomPublic;
use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::negacyclic_transform::NegacyclicDomain;
use super::proof_field::ProofFieldParameters;
use super::zk_linear_opening::{
    ZkLinearParameters, ZkLinearProof, prove_zk_linear, verify_zk_linear,
};
use crate::hashing::hash512;

const SCHEDULE_DELTA_DOMAIN: &str =
    "sealed-lattice/setup/limb-group-atom/trustee-schedule-delta-v1";
const SIDECAR_CHUNK_DOMAIN: &str =
    "sealed-lattice/setup/limb-group-atom/trustee-schedule-sidecar-chunk-v1";
const SIDECAR_ROOT_DOMAIN: &str =
    "sealed-lattice/setup/limb-group-atom/trustee-schedule-sidecar-root-v1";

/// One trustee's schedule proof: the shared-witness commitment and one
/// zero-knowledge linear opening covering every key's every digit atom.
pub(crate) struct TrusteeScheduleProof<const LIMB_COUNT: usize> {
    pub(crate) commitment: FlatCommitment<LIMB_COUNT>,
    pub(crate) zk_opening: ZkLinearProof<LIMB_COUNT>,
}

/// Derives the per-(key, atom) batching challenge, bound to the schedule
/// context and the witness commitment.
fn schedule_delta<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    schedule_context: &[u8],
    flat_atom_index: usize,
) -> [u64; LIMB_COUNT] {
    let mut commitment_bytes = Vec::new();
    for row in &commitment.rows {
        for limb in row {
            commitment_bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    let digest = hash512(
        SCHEDULE_DELTA_DOMAIN,
        &[
            schedule_context,
            &commitment_bytes,
            &(flat_atom_index as u64).to_le_bytes(),
        ],
    );
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
    parameters.unsigned_word_to_element(word)
}

/// Derives the shared batching vector `gamma`, bound to the schedule context and
/// the witness commitment (common across atoms so the secret accumulates).
fn schedule_gamma<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment: &FlatCommitment<LIMB_COUNT>,
    schedule_context: &[u8],
    ring_degree: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut commitment_bytes = Vec::new();
    for row in &commitment.rows {
        for limb in row {
            commitment_bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    (0..ring_degree)
        .map(|coefficient_index| {
            let digest = hash512(
                SCHEDULE_DELTA_DOMAIN,
                &[
                    b"gamma",
                    schedule_context,
                    &commitment_bytes,
                    &(coefficient_index as u64).to_le_bytes(),
                ],
            );
            let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte word"));
            parameters.unsigned_word_to_element(word)
        })
        .collect()
}

/// Builds the schedule's combined linear form over the shared witness and its
/// target from public data only. `keys` is the schedule: one entry per key,
/// each holding that key's digit atoms in order.
fn schedule_combined_form<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    keys: &[Vec<KeyAtomPublic<'_, LIMB_COUNT>>],
    gamma: &[[u64; LIMB_COUNT]],
    commitment: &FlatCommitment<LIMB_COUNT>,
    schedule_context: &[u8],
) -> (Vec<[u64; LIMB_COUNT]>, [u64; LIMB_COUNT]) {
    let ring_degree = gamma.len();
    let flat_atom_count: usize = keys.iter().map(|key_atoms| key_atoms.len()).sum();
    let mut secret_coefficients = vec![parameters.zero(); ring_degree];
    let mut error_coefficients = vec![parameters.zero(); ring_degree * flat_atom_count];
    let mut carry_coefficients = vec![parameters.zero(); ring_degree * flat_atom_count];
    let mut target = parameters.zero();

    let mut flat_atom_index = 0;
    for key_atoms in keys {
        for atom in key_atoms {
            let delta = schedule_delta(parameters, commitment, schedule_context, flat_atom_index);
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
            for coefficient_index in 0..ring_degree {
                secret_coefficients[coefficient_index] = parameters.add(
                    &secret_coefficients[coefficient_index],
                    &parameters.multiply(&delta, &form.secret_coefficients[coefficient_index]),
                );
                error_coefficients[flat_atom_index * ring_degree + coefficient_index] =
                    parameters.multiply(&delta, &form.error_coefficients[coefficient_index]);
                carry_coefficients[flat_atom_index * ring_degree + coefficient_index] =
                    parameters.multiply(&delta, &form.carry_coefficients[coefficient_index]);
            }
            target = parameters.add(&target, &parameters.multiply(&delta, &form.target));
            flat_atom_index += 1;
        }
    }

    let mut combined = Vec::with_capacity(ring_degree + 2 * ring_degree * flat_atom_count);
    combined.extend_from_slice(&secret_coefficients);
    combined.extend_from_slice(&error_coefficients);
    combined.extend_from_slice(&carry_coefficients);
    (combined, target)
}

/// Proves one trustee's whole schedule with one commitment and one
/// zero-knowledge opening. `errors_by_key` and `carries_by_key` are indexed
/// `[key][atom]`, matching `keys`.
pub(crate) fn prove_trustee_schedule<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    zk_parameters: &ZkLinearParameters,
    keys: &[Vec<KeyAtomPublic<'_, LIMB_COUNT>>],
    schedule_context: &[u8],
    secret: &[[u64; LIMB_COUNT]],
    errors_by_key: &[Vec<Vec<[u64; LIMB_COUNT]>>],
    carries_by_key: &[Vec<Vec<[u64; LIMB_COUNT]>>],
    randomness: &[[u64; LIMB_COUNT]],
    challenge: u64,
    mask_seed: u64,
) -> TrusteeScheduleProof<LIMB_COUNT> {
    let ring_degree = secret.len();
    let flat_atom_count: usize = keys.iter().map(|key_atoms| key_atoms.len()).sum();
    let mut witness = Vec::with_capacity(ring_degree + 2 * ring_degree * flat_atom_count);
    witness.extend_from_slice(secret);
    for key_errors in errors_by_key {
        for atom_error in key_errors {
            witness.extend_from_slice(atom_error);
        }
    }
    for key_carries in carries_by_key {
        for atom_carry in key_carries {
            witness.extend_from_slice(atom_carry);
        }
    }
    let commitment = commit_flat(parameters, opening_parameters, &witness, randomness);
    let gamma = schedule_gamma(parameters, &commitment, schedule_context, ring_degree);
    let (combined, _target) = schedule_combined_form(
        parameters,
        domain,
        keys,
        &gamma,
        &commitment,
        schedule_context,
    );

    let zk_opening = prove_zk_linear(
        parameters,
        opening_parameters,
        zk_parameters,
        &witness,
        randomness,
        &combined,
        challenge,
        mask_seed,
    );

    TrusteeScheduleProof {
        commitment,
        zk_opening,
    }
}

/// Verifies one trustee's schedule proof from public data only: rebuilds the
/// combined form and target, then checks the zero-knowledge opening.
pub(crate) fn verify_trustee_schedule<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    domain: &NegacyclicDomain<'_, LIMB_COUNT>,
    opening_parameters: &LinearOpeningParameters,
    zk_parameters: &ZkLinearParameters,
    keys: &[Vec<KeyAtomPublic<'_, LIMB_COUNT>>],
    schedule_context: &[u8],
    ring_degree: usize,
    challenge: u64,
    proof: &TrusteeScheduleProof<LIMB_COUNT>,
) -> bool {
    let gamma = schedule_gamma(parameters, &proof.commitment, schedule_context, ring_degree);
    let (combined, target) = schedule_combined_form(
        parameters,
        domain,
        keys,
        &gamma,
        &proof.commitment,
        schedule_context,
    );
    verify_zk_linear(
        parameters,
        opening_parameters,
        zk_parameters,
        &proof.commitment,
        &combined,
        &target,
        challenge,
        &proof.zk_opening,
    )
}

/// Serializes a schedule proof into sidecar bytes (deterministic little-endian
/// limb order; commitment rows, then each opening component in order).
pub(crate) fn schedule_proof_sidecar_bytes<const LIMB_COUNT: usize>(
    proof: &TrusteeScheduleProof<LIMB_COUNT>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let push_elements = |elements: &[[u64; LIMB_COUNT]], bytes: &mut Vec<u8>| {
        for element in elements {
            for limb in element {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
    };
    push_elements(&proof.commitment.rows, &mut bytes);
    push_elements(&proof.zk_opening.mask_commitment, &mut bytes);
    push_elements(
        std::slice::from_ref(&proof.zk_opening.masked_linear_value),
        &mut bytes,
    );
    push_elements(&proof.zk_opening.response, &mut bytes);
    push_elements(&proof.zk_opening.randomness_response, &mut bytes);
    for magnitude in &proof.zk_opening.response_magnitudes {
        bytes.extend_from_slice(&magnitude.to_le_bytes());
    }
    bytes
}

/// Splits sidecar bytes into fixed-size transport chunks (the last chunk may be
/// shorter).
pub(crate) fn chunk_sidecar_bytes(sidecar_bytes: &[u8], chunk_size_bytes: usize) -> Vec<Vec<u8>> {
    sidecar_bytes
        .chunks(chunk_size_bytes.max(1))
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Binds ordered chunk digests, each chunk's index, and the total byte length
/// into one transport root.
pub(crate) fn sidecar_transport_root(chunks: &[Vec<u8>]) -> [u8; 64] {
    let total_byte_length: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
    let chunk_digests: Vec<[u8; 64]> = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            hash512(
                SIDECAR_CHUNK_DOMAIN,
                &[&(chunk_index as u64).to_le_bytes(), chunk],
            )
        })
        .collect();
    let mut root_preimage = Vec::with_capacity(16 + chunk_digests.len() * 64);
    root_preimage.extend_from_slice(&(chunks.len() as u64).to_le_bytes());
    root_preimage.extend_from_slice(&total_byte_length.to_le_bytes());
    for digest in &chunk_digests {
        root_preimage.extend_from_slice(digest);
    }
    hash512(SIDECAR_ROOT_DOMAIN, &[&root_preimage])
}

/// Verifies received chunks against the expected transport root and reassembles
/// the sidecar bytes. Any flipped byte, reordered chunk, missing chunk, or
/// appended chunk changes the recomputed root and is rejected.
pub(crate) fn verify_and_reassemble_sidecar(
    chunks: &[Vec<u8>],
    expected_transport_root: &[u8; 64],
) -> Option<Vec<u8>> {
    if sidecar_transport_root(chunks) != *expected_transport_root {
        return None;
    }
    Some(chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::super::material_transport::{
        aggregate_matches_homomorphic_sum, aggregate_material, commit_material,
    };
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    const TEST_RING_DEGREE: usize = 32;
    const TEST_KEY_COUNT: usize = 3;
    const TEST_ATOMS_PER_KEY: usize = 4;
    const TEST_TRUSTEE_COUNT: usize = 3;
    const TEST_CHALLENGE: u64 = 0xc4a11e;
    const TEST_SIDECAR_CHUNK_SIZE_BYTES: usize = 512;

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

    /// The zero-knowledge parameters for this witness class at test scale: the
    /// carry bound is `ring_degree + 1`, and the mask bound dominates
    /// `challenge_bound * witness_magnitude_bound` so smudging hides the witness.
    fn schedule_zk_parameters() -> ZkLinearParameters {
        ZkLinearParameters {
            challenge_bound: 1 << 24,
            mask_bound: 1 << 45,
            witness_magnitude_bound: (TEST_RING_DEGREE as u64) + 1,
        }
    }

    struct TrusteeScheduleMaterial {
        samples: Vec<Vec<Vec<[u64; 13]>>>,
        components_b: Vec<Vec<Vec<[u64; 13]>>>,
        gadget: [u64; 13],
        group_modulus: [u64; 13],
        plaintext_modulus: [u64; 13],
        secret: Vec<[u64; 13]>,
        errors_by_key: Vec<Vec<Vec<[u64; 13]>>>,
        carries_by_key: Vec<Vec<Vec<[u64; 13]>>>,
    }

    /// Builds one trustee's synthetic schedule: `TEST_KEY_COUNT` keys of
    /// `TEST_ATOMS_PER_KEY` atoms, all sharing one ternary secret, each atom's
    /// component B set so the congruence holds exactly.
    fn synthetic_trustee_schedule(
        parameters: &ProofFieldParameters<13>,
        domain: &NegacyclicDomain<'_, 13>,
        trustee_seed: u64,
    ) -> TrusteeScheduleMaterial {
        let gadget = parameters.unsigned_word_to_element(0x9e37);
        let group_modulus = parameters.unsigned_word_to_element(1_000_003);
        let plaintext_modulus = parameters.unsigned_word_to_element(65_537);
        let secret = signed(
            parameters,
            &(0..TEST_RING_DEGREE)
                .map(|index| ((index as u64 * 7 + trustee_seed) % 3) as i64 - 1)
                .collect::<Vec<_>>(),
        );
        let mut samples = Vec::new();
        let mut components_b = Vec::new();
        let mut errors_by_key = Vec::new();
        let mut carries_by_key = Vec::new();
        for key_index in 0..TEST_KEY_COUNT {
            let mut key_samples = Vec::new();
            let mut key_components_b = Vec::new();
            let mut key_errors = Vec::new();
            let mut key_carries = Vec::new();
            for atom_index in 0..TEST_ATOMS_PER_KEY {
                let flat_seed =
                    trustee_seed * 1_000 + (key_index * TEST_ATOMS_PER_KEY + atom_index) as u64;
                let sample = deterministic(parameters, TEST_RING_DEGREE, 0xa5 + flat_seed);
                let error = signed(
                    parameters,
                    &(0..TEST_RING_DEGREE)
                        .map(|index| ((index + key_index + atom_index) % 5) as i64 - 2)
                        .collect::<Vec<_>>(),
                );
                let carry = signed(
                    parameters,
                    &(0..TEST_RING_DEGREE)
                        .map(|index| ((index * 11 + key_index + atom_index) % 3) as i64 - 1)
                        .collect::<Vec<_>>(),
                );
                let sample_times_secret = domain.negacyclic_product(&sample, &secret);
                let mut component_b = vec![parameters.zero(); TEST_RING_DEGREE];
                for index in 0..TEST_RING_DEGREE {
                    let error_term = parameters.multiply(&plaintext_modulus, &error[index]);
                    let source_term = parameters.multiply(&gadget, &secret[index]);
                    let carry_term = parameters.multiply(&group_modulus, &carry[index]);
                    let mut value = parameters.add(&error_term, &source_term);
                    value = parameters.add(&value, &carry_term);
                    value = parameters.subtract(&value, &sample_times_secret[index]);
                    component_b[index] = value;
                }
                key_samples.push(sample);
                key_components_b.push(component_b);
                key_errors.push(error);
                key_carries.push(carry);
            }
            samples.push(key_samples);
            components_b.push(key_components_b);
            errors_by_key.push(key_errors);
            carries_by_key.push(key_carries);
        }
        TrusteeScheduleMaterial {
            samples,
            components_b,
            gadget,
            group_modulus,
            plaintext_modulus,
            secret,
            errors_by_key,
            carries_by_key,
        }
    }

    fn schedule_keys<'a>(material: &'a TrusteeScheduleMaterial) -> Vec<Vec<KeyAtomPublic<'a, 13>>> {
        (0..TEST_KEY_COUNT)
            .map(|key_index| {
                (0..TEST_ATOMS_PER_KEY)
                    .map(|atom_index| KeyAtomPublic {
                        recombined_sample: &material.samples[key_index][atom_index],
                        recombined_component_b: &material.components_b[key_index][atom_index],
                        gadget_idempotent: material.gadget,
                        group_modulus: material.group_modulus,
                        plaintext_modulus: material.plaintext_modulus,
                    })
                    .collect()
            })
            .collect()
    }

    fn schedule_opening_parameters() -> LinearOpeningParameters {
        LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: TEST_RING_DEGREE
                + 2 * TEST_RING_DEGREE * TEST_KEY_COUNT * TEST_ATOMS_PER_KEY,
            randomness_length: 6,
            matrix_seed: 0x5c4ed,
            mask_bound: 1,
        }
    }

    fn schedule_context(trustee_index: usize) -> Vec<u8> {
        let mut context = b"trustee-schedule-context-v1/".to_vec();
        context.extend_from_slice(&(trustee_index as u64).to_le_bytes());
        context
    }

    fn prove_for_trustee(
        parameters: &ProofFieldParameters<13>,
        domain: &NegacyclicDomain<'_, 13>,
        material: &TrusteeScheduleMaterial,
        trustee_index: usize,
    ) -> TrusteeScheduleProof<13> {
        let keys = schedule_keys(material);
        let randomness = signed(parameters, &[1, -1, 0, 1, -1, 0]);
        prove_trustee_schedule(
            parameters,
            domain,
            &schedule_opening_parameters(),
            &schedule_zk_parameters(),
            &keys,
            &schedule_context(trustee_index),
            &material.secret,
            &material.errors_by_key,
            &material.carries_by_key,
            &randomness,
            TEST_CHALLENGE,
            0x5eed + trustee_index as u64,
        )
    }

    #[test]
    fn full_roster_schedules_verify_and_aggregate_material_matches() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");

        let mut per_trustee_material_vectors = Vec::new();
        for trustee_index in 0..TEST_TRUSTEE_COUNT {
            let material =
                synthetic_trustee_schedule(&parameters, &domain, 0x7000 + trustee_index as u64);
            let keys = schedule_keys(&material);
            let proof = prove_for_trustee(&parameters, &domain, &material, trustee_index);
            assert!(
                verify_trustee_schedule(
                    &parameters,
                    &domain,
                    &schedule_opening_parameters(),
                    &schedule_zk_parameters(),
                    &keys,
                    &schedule_context(trustee_index),
                    TEST_RING_DEGREE,
                    TEST_CHALLENGE,
                    &proof,
                ),
                "an honest trustee schedule must verify with one commitment and one opening"
            );

            // The trustee's public material vector: every atom's recombined
            // sample and component B, flattened in schedule order.
            let mut material_vector = Vec::new();
            for key_index in 0..TEST_KEY_COUNT {
                for atom_index in 0..TEST_ATOMS_PER_KEY {
                    material_vector.extend_from_slice(&material.samples[key_index][atom_index]);
                    material_vector
                        .extend_from_slice(&material.components_b[key_index][atom_index]);
                }
            }
            per_trustee_material_vectors.push(material_vector);
        }

        // Aggregate-material check across the roster: the published aggregate
        // equals the homomorphic sum of per-trustee material commitments.
        let material_commitment_parameters = LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: per_trustee_material_vectors[0].len(),
            randomness_length: 6,
            matrix_seed: 0x3ec0,
            mask_bound: 1,
        };
        let per_trustee_commitments = per_trustee_material_vectors
            .iter()
            .map(|material_vector| {
                commit_material(
                    &parameters,
                    &material_commitment_parameters,
                    material_vector,
                )
            })
            .collect::<Vec<_>>();
        let aggregate = aggregate_material(&parameters, &per_trustee_material_vectors);
        let aggregate_commitment =
            commit_material(&parameters, &material_commitment_parameters, &aggregate);
        assert!(
            aggregate_matches_homomorphic_sum(
                &aggregate_commitment,
                &per_trustee_commitments,
                &parameters,
            ),
            "the published aggregate key material must equal the homomorphic sum of the roster's committed materials"
        );
    }

    #[test]
    fn schedule_sidecar_transport_round_trips_and_rejects_tampering() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7100);
        let proof = prove_for_trustee(&parameters, &domain, &material, 0);

        let sidecar_bytes = schedule_proof_sidecar_bytes(&proof);
        let chunks = chunk_sidecar_bytes(&sidecar_bytes, TEST_SIDECAR_CHUNK_SIZE_BYTES);
        assert!(
            chunks.len() > 3,
            "the test sidecar must span several chunks to exercise the transport"
        );
        let transport_root = sidecar_transport_root(&chunks);

        // Honest round trip.
        let reassembled =
            verify_and_reassemble_sidecar(&chunks, &transport_root).expect("honest transport");
        assert_eq!(
            reassembled, sidecar_bytes,
            "reassembled sidecar bytes must match the encoded proof"
        );

        // A flipped byte in one chunk is rejected.
        let mut flipped = chunks.clone();
        flipped[1][7] ^= 0x01;
        assert!(
            verify_and_reassemble_sidecar(&flipped, &transport_root).is_none(),
            "a flipped sidecar byte must change the transport root"
        );

        // Reordered chunks are rejected (chunk digests bind their indices).
        let mut reordered = chunks.clone();
        reordered.swap(0, 1);
        assert!(
            verify_and_reassemble_sidecar(&reordered, &transport_root).is_none(),
            "reordered sidecar chunks must change the transport root"
        );

        // Truncation is rejected (the root binds chunk count and total length).
        let truncated = chunks[..chunks.len() - 1].to_vec();
        assert!(
            verify_and_reassemble_sidecar(&truncated, &transport_root).is_none(),
            "a truncated sidecar must change the transport root"
        );

        // An appended extra chunk is rejected.
        let mut extended = chunks.clone();
        extended.push(vec![0u8; 16]);
        assert!(
            verify_and_reassemble_sidecar(&extended, &transport_root).is_none(),
            "an appended sidecar chunk must change the transport root"
        );
    }

    #[test]
    fn tampered_shared_secret_fails_the_schedule_proof() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7200);
        let keys = schedule_keys(&material);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);

        let mut tampered_secret = material.secret.clone();
        tampered_secret[5] =
            parameters.add(&tampered_secret[5], &parameters.unsigned_word_to_element(1));
        let proof = prove_trustee_schedule(
            &parameters,
            &domain,
            &schedule_opening_parameters(),
            &schedule_zk_parameters(),
            &keys,
            &schedule_context(0),
            &tampered_secret,
            &material.errors_by_key,
            &material.carries_by_key,
            &randomness,
            TEST_CHALLENGE,
            0x5eed,
        );
        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &keys,
                &schedule_context(0),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &proof,
            ),
            "a tampered shared secret must fail the schedule proof"
        );
    }

    #[test]
    fn tampered_single_atom_error_in_one_key_fails_the_schedule_proof() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7300);
        let keys = schedule_keys(&material);
        let randomness = signed(&parameters, &[1, -1, 0, 1, -1, 0]);

        let mut tampered_errors = material.errors_by_key.clone();
        tampered_errors[1][2][3] = parameters.add(
            &tampered_errors[1][2][3],
            &parameters.unsigned_word_to_element(1),
        );
        let proof = prove_trustee_schedule(
            &parameters,
            &domain,
            &schedule_opening_parameters(),
            &schedule_zk_parameters(),
            &keys,
            &schedule_context(0),
            &material.secret,
            &tampered_errors,
            &material.carries_by_key,
            &randomness,
            TEST_CHALLENGE,
            0x5eed,
        );
        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &keys,
                &schedule_context(0),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &proof,
            ),
            "one tampered atom error inside one key must be caught by the schedule batch"
        );
    }

    #[test]
    fn tampered_public_component_b_fails_verification_of_an_honest_proof() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let mut material = synthetic_trustee_schedule(&parameters, &domain, 0x7400);
        let proof = prove_for_trustee(&parameters, &domain, &material, 0);

        // The adversary alters one atom's published component B after proving.
        material.components_b[2][1][4] = parameters.add(
            &material.components_b[2][1][4],
            &parameters.unsigned_word_to_element(1),
        );
        let tampered_keys = schedule_keys(&material);
        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &tampered_keys,
                &schedule_context(0),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &proof,
            ),
            "an honest proof must not verify against altered public key material"
        );
    }

    #[test]
    fn proof_bound_to_one_schedule_context_fails_under_another() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7500);
        let keys = schedule_keys(&material);
        let proof = prove_for_trustee(&parameters, &domain, &material, 0);

        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &keys,
                &schedule_context(1),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &proof,
            ),
            "a schedule proof must not replay under a different schedule context"
        );
    }

    #[test]
    fn swapped_commitment_and_out_of_bounds_challenges_are_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7600);
        let other_material = synthetic_trustee_schedule(&parameters, &domain, 0x7700);
        let keys = schedule_keys(&material);
        let proof = prove_for_trustee(&parameters, &domain, &material, 0);
        let other_proof = prove_for_trustee(&parameters, &domain, &other_material, 0);

        // Response from one proof against another proof's commitment.
        let franken_proof = TrusteeScheduleProof {
            commitment: other_proof.commitment,
            zk_opening: proof.zk_opening,
        };
        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &keys,
                &schedule_context(0),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &franken_proof,
            ),
            "an opening must not verify against a different witness commitment"
        );

        // Challenge outside the bounded set.
        let honest_proof = prove_for_trustee(&parameters, &domain, &material, 0);
        for bad_challenge in [0u64, schedule_zk_parameters().challenge_bound + 1] {
            assert!(
                !verify_trustee_schedule(
                    &parameters,
                    &domain,
                    &schedule_opening_parameters(),
                    &schedule_zk_parameters(),
                    &keys,
                    &schedule_context(0),
                    TEST_RING_DEGREE,
                    bad_challenge,
                    &honest_proof,
                ),
                "challenges outside the bounded set must be rejected"
            );
        }
    }

    #[test]
    fn overstated_response_magnitudes_are_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, TEST_RING_DEGREE).expect("domain builds");
        let material = synthetic_trustee_schedule(&parameters, &domain, 0x7800);
        let keys = schedule_keys(&material);
        let mut proof = prove_for_trustee(&parameters, &domain, &material, 0);

        // Claiming a different magnitude than the response coordinate carries
        // must fail the norm-bound check.
        proof.zk_opening.response_magnitudes[0] =
            proof.zk_opening.response_magnitudes[0].wrapping_add(1);
        assert!(
            !verify_trustee_schedule(
                &parameters,
                &domain,
                &schedule_opening_parameters(),
                &schedule_zk_parameters(),
                &keys,
                &schedule_context(0),
                TEST_RING_DEGREE,
                TEST_CHALLENGE,
                &proof,
            ),
            "a response magnitude that does not match its coordinate must be rejected"
        );
    }
}
