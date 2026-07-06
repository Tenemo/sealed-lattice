//! Radix-2 FRI proximity argument over one atom proof field.
//!
//! Proves a committed codeword over the coset `offset * K` (|K| a power of two)
//! is close to the evaluations of a polynomial of degree below the rate bound.
//! Each round folds the codeword with a Fiat-Shamir challenge, halving the
//! domain (a coset of a 2-adic subgroup stays a coset under squaring), commits
//! the layer in a salted Merkle tree, and after enough rounds sends the small
//! final layer as coefficients. Queries open each layer's folding pair; the
//! verifier authenticates both leaves against the layer root, rechecks every
//! fold, and rechecks the final layer's low degree.
//!
//! Binding is the salted Merkle commitment; per-query soundness at rate
//! `1/blowup` follows the standard FRI analysis. The opened salts are revealed
//! per query (salts only hide unopened leaves), so the verifier recomputes the
//! exact committed leaf.

use super::super::proof_field::ProofFieldParameters;
use super::domain::{CyclicDomain, evaluate_polynomial_at};
use super::merkle::{
    BatchedMerkleOpening, MerkleDigest, MerkleTree, consistent_sorted_leaves, leaf_hash,
    sorted_unique_indices, verify_merkle_batch,
};
use super::transcript::Transcript;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// Fold until the layer domain reaches this size, then send coefficients.
pub(super) const FINAL_LAYER_MAX_SIZE: usize = 8;

pub(super) struct FriParameters {
    pub(super) blowup: usize,
}

pub(super) struct FriProof<const LIMB_COUNT: usize> {
    pub(super) layer_roots: Vec<MerkleDigest>,
    pub(super) final_coefficients: Vec<[u64; LIMB_COUNT]>,
    pub(super) query_answers: Vec<FriQueryAnswer<LIMB_COUNT>>,
}

pub(super) struct FriQueryAnswer<const LIMB_COUNT: usize> {
    pub(super) layers: Vec<FriLayerOpening<LIMB_COUNT>>,
}

// One folding-pair opening at one layer: the value at the folded position, the
// value at its sibling, both leaf salts, and the batched Merkle authentication.
pub(super) struct FriLayerOpening<const LIMB_COUNT: usize> {
    pub(super) value: [u64; LIMB_COUNT],
    pub(super) sibling_value: [u64; LIMB_COUNT],
    pub(super) value_salt: Vec<u8>,
    pub(super) sibling_salt: Vec<u8>,
    pub(super) opening: BatchedMerkleOpening,
}

struct ProverLayer<const LIMB_COUNT: usize> {
    codeword: Vec<[u64; LIMB_COUNT]>,
    salts: Vec<Vec<u8>>,
    tree: MerkleTree,
    domain: usize,
}

fn invalid_fri(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

fn leaf_words<const LIMB_COUNT: usize>(value: &[u64; LIMB_COUNT]) -> Vec<u64> {
    value.to_vec()
}

fn commit_layer<const LIMB_COUNT: usize>(
    codeword: &[[u64; LIMB_COUNT]],
    salt_seed: &mut u64,
) -> CanonicalResult<ProverLayer<LIMB_COUNT>> {
    let mut salts = Vec::with_capacity(codeword.len());
    let mut leaves = Vec::with_capacity(codeword.len());
    for (index, value) in codeword.iter().enumerate() {
        *salt_seed = salt_seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let salt = salt_seed.to_le_bytes().to_vec();
        leaves.push(leaf_hash(index, &salt, &leaf_words(value)));
        salts.push(salt);
    }
    let tree = MerkleTree::from_leaf_hashes(leaves)?;
    Ok(ProverLayer {
        domain: codeword.len(),
        codeword: codeword.to_vec(),
        salts,
        tree,
    })
}

// The fold of one pair at coset point x, shared by prover and verifier:
// g(x^2) = (f(x)+f(-x))/2 + beta*(f(x)-f(-x))/(2x).
fn fold_pair<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    value: &[u64; LIMB_COUNT],
    sibling: &[u64; LIMB_COUNT],
    x: &[u64; LIMB_COUNT],
    two_inverse: &[u64; LIMB_COUNT],
    beta: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    let even = parameters.multiply(&parameters.add(value, sibling), two_inverse);
    let odd_numerator = parameters.multiply(&parameters.subtract(value, sibling), two_inverse);
    let odd = parameters.multiply(&odd_numerator, &parameters.inverse(x));
    parameters.add(&even, &parameters.multiply(beta, &odd))
}

fn fold_codeword<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    codeword: &[[u64; LIMB_COUNT]],
    layer_domain: &CyclicDomain<'_, LIMB_COUNT>,
    layer_offset: &[u64; LIMB_COUNT],
    two_inverse: &[u64; LIMB_COUNT],
    beta: &[u64; LIMB_COUNT],
) -> Vec<[u64; LIMB_COUNT]> {
    let half = codeword.len() / 2;
    (0..half)
        .map(|index| {
            let x = parameters.multiply(layer_offset, &layer_domain.point(index));
            fold_pair(
                parameters,
                &codeword[index],
                &codeword[index + half],
                &x,
                two_inverse,
                beta,
            )
        })
        .collect()
}

// The prover's committed FRI layers, held between the commit phase (which
// absorbs the layer roots and the final coefficients into the transcript) and
// the answer phase (which opens the shared query positions the caller derives).
pub(super) struct FriCommitment<const LIMB_COUNT: usize> {
    layers: Vec<ProverLayer<LIMB_COUNT>>,
    layer_roots: Vec<MerkleDigest>,
    final_coefficients: Vec<[u64; LIMB_COUNT]>,
    top_size: usize,
}

// Commit-and-fold phase: commits every FRI layer and absorbs its root, folds
// with the transcript challenges, and absorbs the final layer's coefficients.
// The caller derives the shared query positions from the transcript afterwards
// (so trace and FRI open the same positions), then calls `fri_answer`.
pub(super) fn fri_commit<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    transcript: &mut Transcript,
    codeword: &[[u64; LIMB_COUNT]],
    initial_offset: &[u64; LIMB_COUNT],
    salt_seed: &mut u64,
) -> CanonicalResult<FriCommitment<LIMB_COUNT>> {
    if !codeword.len().is_power_of_two() || codeword.len() < 2 {
        return Err(invalid_fri(
            "FRI codeword length must be a power of two >= 2",
        ));
    }
    let two_inverse = parameters.inverse(&parameters.unsigned_word_to_element(2));
    let top_size = codeword.len();

    let mut layers: Vec<ProverLayer<LIMB_COUNT>> = Vec::new();
    let mut layer_roots: Vec<MerkleDigest> = Vec::new();
    let mut current = codeword.to_vec();
    let mut current_offset = *initial_offset;

    let final_coefficients = loop {
        if current.len() <= FINAL_LAYER_MAX_SIZE {
            let domain = CyclicDomain::new(parameters, current.len())?;
            let coefficients = domain.interpolate(&current);
            transcript.absorb_field_elements("fri-final", &coefficients);
            break coefficients;
        }
        let layer = commit_layer(&current, salt_seed)?;
        transcript.absorb_digest("fri-layer-root", &layer.tree.root());
        layer_roots.push(layer.tree.root());
        let beta = transcript.challenge_field_element(parameters, "fri-fold");
        let layer_domain = CyclicDomain::new(parameters, current.len())?;
        let folded = fold_codeword(
            parameters,
            &current,
            &layer_domain,
            &current_offset,
            &two_inverse,
            &beta,
        );
        layers.push(layer);
        current = folded;
        current_offset = parameters.multiply(&current_offset, &current_offset);
    };

    Ok(FriCommitment {
        layers,
        layer_roots,
        final_coefficients,
        top_size,
    })
}

// Answer phase: open every layer's folding pair at each caller-supplied top
// query position.
pub(super) fn fri_answer<const LIMB_COUNT: usize>(
    commitment: &FriCommitment<LIMB_COUNT>,
    query_positions: &[usize],
) -> FriProof<LIMB_COUNT> {
    let mut query_answers = Vec::with_capacity(query_positions.len());
    for &top_position in query_positions {
        let mut position = top_position % commitment.top_size;
        let mut answer_layers = Vec::with_capacity(commitment.layers.len());
        for layer in &commitment.layers {
            let half = layer.domain / 2;
            let folded_position = position % half;
            let sibling_position = folded_position + half;
            let indices = sorted_unique_indices([folded_position, sibling_position]);
            let opening = layer.tree.open_batch(&indices);
            answer_layers.push(FriLayerOpening {
                value: layer.codeword[folded_position],
                sibling_value: layer.codeword[sibling_position],
                value_salt: layer.salts[folded_position].clone(),
                sibling_salt: layer.salts[sibling_position].clone(),
                opening,
            });
            position = folded_position;
        }
        query_answers.push(FriQueryAnswer {
            layers: answer_layers,
        });
    }

    FriProof {
        layer_roots: commitment.layer_roots.clone(),
        final_coefficients: commitment.final_coefficients.clone(),
        query_answers,
    }
}

// The verifier's re-derived FRI structure between the structure phase (which
// absorbs roots and the final layer, re-derives the fold challenges, and checks
// the final low-degree bound) and the queries phase.
pub(super) struct FriVerification<'a, const LIMB_COUNT: usize> {
    betas: Vec<[u64; LIMB_COUNT]>,
    layer_sizes: Vec<usize>,
    layer_offsets: Vec<[u64; LIMB_COUNT]>,
    layer_domains: Vec<CyclicDomain<'a, LIMB_COUNT>>,
    final_size: usize,
    final_domain: CyclicDomain<'a, LIMB_COUNT>,
    two_inverse: [u64; LIMB_COUNT],
}

pub(super) fn fri_verify_structure<'a, const LIMB_COUNT: usize>(
    parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    transcript: &mut Transcript,
    proof: &FriProof<LIMB_COUNT>,
    top_size: usize,
    initial_offset: &[u64; LIMB_COUNT],
    fri_parameters: &FriParameters,
) -> CanonicalResult<Option<FriVerification<'a, LIMB_COUNT>>> {
    if !top_size.is_power_of_two() || top_size < 2 {
        return Ok(None);
    }
    let two_inverse = parameters.inverse(&parameters.unsigned_word_to_element(2));

    let mut betas = Vec::new();
    let mut layer_sizes = Vec::new();
    let mut size = top_size;
    let mut layer_index = 0;
    loop {
        if size <= FINAL_LAYER_MAX_SIZE {
            transcript.absorb_field_elements("fri-final", &proof.final_coefficients);
            break;
        }
        let Some(root) = proof.layer_roots.get(layer_index) else {
            return Ok(None);
        };
        transcript.absorb_digest("fri-layer-root", root);
        betas.push(transcript.challenge_field_element(parameters, "fri-fold"));
        layer_sizes.push(size);
        size /= 2;
        layer_index += 1;
    }
    if proof.layer_roots.len() != layer_sizes.len() {
        return Ok(None);
    }
    let final_size = size;
    if proof.final_coefficients.len() != final_size {
        return Ok(None);
    }
    let final_degree_bound = (final_size / fri_parameters.blowup).max(1);
    for coefficient in &proof.final_coefficients[final_degree_bound..] {
        if coefficient.iter().any(|limb| *limb != 0) {
            return Ok(None);
        }
    }

    let mut layer_offsets = Vec::with_capacity(layer_sizes.len());
    let mut running_offset = *initial_offset;
    for _ in &layer_sizes {
        layer_offsets.push(running_offset);
        running_offset = parameters.multiply(&running_offset, &running_offset);
    }
    let mut layer_domains = Vec::with_capacity(layer_sizes.len());
    for size in &layer_sizes {
        layer_domains.push(CyclicDomain::new(parameters, *size)?);
    }
    let final_domain = CyclicDomain::new(parameters, final_size)?;

    Ok(Some(FriVerification {
        betas,
        layer_sizes,
        layer_offsets,
        layer_domains,
        final_size,
        final_domain,
        two_inverse,
    }))
}

impl<const LIMB_COUNT: usize> FriVerification<'_, LIMB_COUNT> {
    fn authenticate_and_chain(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        proof: &FriProof<LIMB_COUNT>,
        answer: &FriQueryAnswer<LIMB_COUNT>,
        top_position: usize,
    ) -> bool {
        if answer.layers.len() != self.layer_sizes.len() {
            return false;
        }
        let mut position = top_position % self.layer_sizes[0];
        let mut chained: Option<[u64; LIMB_COUNT]> = None;
        for (index, layer_opening) in answer.layers.iter().enumerate() {
            let size = self.layer_sizes[index];
            let half = size / 2;
            let folded_position = position % half;
            let sibling_position = folded_position + half;
            let leaves = consistent_sorted_leaves([
                (
                    folded_position,
                    leaf_hash(
                        folded_position,
                        &layer_opening.value_salt,
                        &leaf_words(&layer_opening.value),
                    ),
                ),
                (
                    sibling_position,
                    leaf_hash(
                        sibling_position,
                        &layer_opening.sibling_salt,
                        &leaf_words(&layer_opening.sibling_value),
                    ),
                ),
            ]);
            let Some(leaves) = leaves else {
                return false;
            };
            let depth = size.trailing_zeros() as usize;
            if !verify_merkle_batch(
                &proof.layer_roots[index],
                depth,
                &leaves,
                &layer_opening.opening,
            ) {
                return false;
            }
            if let Some(expected) = chained {
                let entering = if position < half {
                    layer_opening.value
                } else {
                    layer_opening.sibling_value
                };
                if expected != entering {
                    return false;
                }
            }
            let x = parameters.multiply(
                &self.layer_offsets[index],
                &self.layer_domains[index].point(folded_position),
            );
            chained = Some(fold_pair(
                parameters,
                &layer_opening.value,
                &layer_opening.sibling_value,
                &x,
                &self.two_inverse,
                &self.betas[index],
            ));
            position = folded_position;
        }
        let final_point = self.final_domain.point(position);
        let expected_final =
            evaluate_polynomial_at(parameters, &proof.final_coefficients, &final_point);
        match chained {
            Some(chained) => chained == expected_final,
            None => false,
        }
    }
}

// Queries phase: check every query's Merkle authentication, fold chain, and
// final low-degree consistency at the caller-supplied positions.
pub(super) fn fri_verify_queries<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    verification: &FriVerification<'_, LIMB_COUNT>,
    proof: &FriProof<LIMB_COUNT>,
    query_positions: &[usize],
) -> bool {
    if proof.query_answers.len() != query_positions.len() {
        return false;
    }
    let _ = verification.final_size;
    proof
        .query_answers
        .iter()
        .zip(query_positions.iter())
        .all(|(answer, &position)| {
            verification.authenticate_and_chain(parameters, proof, answer, position)
        })
}

// Self-contained convenience wrapper (derives its own query positions); used by
// the FRI unit tests. The atom proof uses the two-phase API so it can share
// query positions with the trace commitment.
#[cfg(test)]
pub(super) fn prove_low_degree<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    transcript: &mut Transcript,
    codeword: &[[u64; LIMB_COUNT]],
    initial_offset: &[u64; LIMB_COUNT],
    query_count: usize,
    salt_seed: &mut u64,
) -> CanonicalResult<FriProof<LIMB_COUNT>> {
    let top_size = codeword.len();
    let commitment = fri_commit(parameters, transcript, codeword, initial_offset, salt_seed)?;
    let positions = transcript.challenge_positions("fri-query", top_size, query_count);
    Ok(fri_answer(&commitment, &positions))
}

#[cfg(test)]
pub(super) fn verify_low_degree<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    transcript: &mut Transcript,
    proof: &FriProof<LIMB_COUNT>,
    top_size: usize,
    initial_offset: &[u64; LIMB_COUNT],
    query_count: usize,
    fri_parameters: &FriParameters,
) -> CanonicalResult<bool> {
    let Some(verification) = fri_verify_structure(
        parameters,
        transcript,
        proof,
        top_size,
        initial_offset,
        fri_parameters,
    )?
    else {
        return Ok(false);
    };
    let positions = transcript.challenge_positions("fri-query", top_size, query_count);
    Ok(fri_verify_queries(
        parameters,
        &verification,
        proof,
        &positions,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::{
        ProofFieldParameters, eight_limb_group_field_parameters,
        sixteen_limb_group_field_parameters,
    };
    use super::super::domain::{CyclicDomain, coset_offset};
    use super::*;

    // A coset codeword of a polynomial with `degree_bound` coefficients over a
    // domain of `trace_size * blowup` points.
    fn low_degree_codeword<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        coefficients: &[[u64; LIMB_COUNT]],
        coset_size: usize,
        offset: &[u64; LIMB_COUNT],
    ) -> Vec<[u64; LIMB_COUNT]> {
        let domain = CyclicDomain::new(parameters, coset_size).expect("domain");
        // Shift coefficients to the coset: p(offset * y).
        let mut shifted = vec![parameters.zero(); coset_size];
        let mut offset_power = parameters.one();
        for (index, coefficient) in coefficients.iter().enumerate() {
            shifted[index] = parameters.multiply(coefficient, &offset_power);
            offset_power = parameters.multiply(&offset_power, offset);
        }
        domain.evaluate(&shifted)
    }

    fn random_coefficients<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        count: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    #[test]
    fn honest_low_degree_codeword_verifies() {
        let parameters = sixteen_limb_group_field_parameters();
        let blowup = 4;
        let trace_size = 64;
        let coset_size = trace_size * blowup;
        let offset = coset_offset(&parameters);
        let coefficients = random_coefficients(&parameters, trace_size, 0xd00d);
        let codeword = low_degree_codeword(&parameters, &coefficients, coset_size, &offset);
        let query_count = 24;
        let fri_parameters = FriParameters { blowup };

        let mut prover_transcript = Transcript::new("fri-test");
        let mut salt_seed = 0x1234;
        let proof = prove_low_degree(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            query_count,
            &mut salt_seed,
        )
        .expect("prove");

        let mut verifier_transcript = Transcript::new("fri-test");
        assert!(
            verify_low_degree(
                &parameters,
                &mut verifier_transcript,
                &proof,
                coset_size,
                &offset,
                query_count,
                &fri_parameters,
            )
            .expect("verify")
        );
    }

    #[test]
    fn high_degree_codeword_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let blowup = 4;
        let trace_size = 64;
        let coset_size = trace_size * blowup;
        let offset = coset_offset(&parameters);
        // A full-degree (coset_size coefficients) codeword is not low-degree.
        let coefficients = random_coefficients(&parameters, coset_size, 0xbadb);
        let codeword = low_degree_codeword(&parameters, &coefficients, coset_size, &offset);
        let query_count = 24;
        let fri_parameters = FriParameters { blowup };
        let mut prover_transcript = Transcript::new("fri-test");
        let mut salt_seed = 0x99;
        let proof = prove_low_degree(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            query_count,
            &mut salt_seed,
        )
        .expect("prove");
        let mut verifier_transcript = Transcript::new("fri-test");
        // A high-degree codeword either fails the final low-degree bound or the
        // fold-chain at some query; the verifier must reject.
        assert!(
            !verify_low_degree(
                &parameters,
                &mut verifier_transcript,
                &proof,
                coset_size,
                &offset,
                query_count,
                &fri_parameters,
            )
            .expect("verify")
        );
    }

    #[test]
    fn tampered_query_value_is_rejected() {
        let parameters = eight_limb_group_field_parameters();
        let blowup = 4;
        let trace_size = 32;
        let coset_size = trace_size * blowup;
        let offset = coset_offset(&parameters);
        let coefficients = random_coefficients(&parameters, trace_size, 0x7);
        let codeword = low_degree_codeword(&parameters, &coefficients, coset_size, &offset);
        let query_count = 20;
        let fri_parameters = FriParameters { blowup };
        let mut prover_transcript = Transcript::new("fri-test");
        let mut salt_seed = 0x55;
        let mut proof = prove_low_degree(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            query_count,
            &mut salt_seed,
        )
        .expect("prove");
        // Corrupt one opened value: the Merkle authentication must fail.
        proof.query_answers[0].layers[0].value =
            parameters.add(&proof.query_answers[0].layers[0].value, &parameters.one());
        let mut verifier_transcript = Transcript::new("fri-test");
        assert!(
            !verify_low_degree(
                &parameters,
                &mut verifier_transcript,
                &proof,
                coset_size,
                &offset,
                query_count,
                &fri_parameters,
            )
            .expect("verify")
        );
    }

    #[test]
    fn wrong_domain_size_is_rejected() {
        let parameters = sixteen_limb_group_field_parameters();
        let blowup = 4;
        let trace_size = 64;
        let coset_size = trace_size * blowup;
        let offset = coset_offset(&parameters);
        let coefficients = random_coefficients(&parameters, trace_size, 0x3);
        let codeword = low_degree_codeword(&parameters, &coefficients, coset_size, &offset);
        let query_count = 16;
        let fri_parameters = FriParameters { blowup };
        let mut prover_transcript = Transcript::new("fri-test");
        let mut salt_seed = 0x2;
        let proof = prove_low_degree(
            &parameters,
            &mut prover_transcript,
            &codeword,
            &offset,
            query_count,
            &mut salt_seed,
        )
        .expect("prove");
        let mut verifier_transcript = Transcript::new("fri-test");
        // Claiming a different top size desynchronizes the transcript and sizes.
        assert!(
            !verify_low_degree(
                &parameters,
                &mut verifier_transcript,
                &proof,
                coset_size * 2,
                &offset,
                query_count,
                &fri_parameters,
            )
            .expect("verify")
        );
    }
}
