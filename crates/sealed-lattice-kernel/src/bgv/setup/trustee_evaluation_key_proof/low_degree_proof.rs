use super::evaluation_domain::batch_inverse;
use super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};
use fiat_shamir_transcript::FiatShamirTranscript;
use merkle_commitment::{MerkleTree, leaf_hash, verify_merkle_opening};

// Batched FRI low-degree argument at rate 1/2. The initial layer is the
// lambda-batched DEEP quotient codeword over the extension coset; it is not
// committed here because the verifier re-derives queried values from the
// phase tree openings. Each fold halves the degree bound and the domain;
// folded layers are committed as Merkle trees over pair leaves so one opening
// serves the next fold. The recursion stops at a small final polynomial sent
// in coefficient form.
pub(super) struct LowDegreeParameters {
    pub(super) modulus: u64,
    pub(super) initial_domain_size: usize,
    pub(super) initial_offset: u64,
    pub(super) initial_root: u64,
    // Strict degree bound of the initial layer (the codeword claims degree
    // below this value); must be half the initial domain size at rate 1/2.
    pub(super) initial_degree_bound: usize,
}

pub(super) struct LowDegreeProof {
    pub(super) folded_layer_roots: Vec<[u8; 64]>,
    pub(super) final_coefficients: Vec<u64>,
    pub(super) query_openings: Vec<LowDegreeQueryOpening>,
}

pub(super) struct LowDegreeQueryOpening {
    // One (pair, Merkle path) entry per committed folded layer.
    pub(super) folded_layer_pairs: Vec<LowDegreePairOpening>,
}

pub(super) struct LowDegreePairOpening {
    pub(super) pair: [u64; 2],
    pub(super) path: Vec<[u8; 64]>,
}

fn fold_count(parameters: &LowDegreeParameters) -> usize {
    debug_assert!(parameters.initial_degree_bound.is_power_of_two());
    debug_assert!(parameters.initial_degree_bound > LOW_DEGREE_FINAL_COEFFICIENT_COUNT);
    (parameters.initial_degree_bound / LOW_DEGREE_FINAL_COEFFICIENT_COUNT).trailing_zeros() as usize
}

fn fold_layer(
    layer: &[u64],
    challenge: u64,
    offset: u64,
    root: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let half = layer.len() / 2;
    let inverse_two = inverse_mod(2, modulus)?;
    // x positions for the lower half of the layer domain, inverted in batch.
    let mut points = Vec::with_capacity(half);
    let mut point = offset;
    for _ in 0..half {
        points.push(point);
        point = mul_mod_fast(point, root, modulus);
    }
    let inverted_points = batch_inverse(&points, modulus)?;
    let mut folded = Vec::with_capacity(half);
    for position in 0..half {
        let even_part = mul_mod_fast(
            add_mod_fast(layer[position], layer[position + half], modulus),
            inverse_two,
            modulus,
        );
        let odd_part = mul_mod_fast(
            mul_mod_fast(
                sub_mod_fast(layer[position], layer[position + half], modulus),
                inverse_two,
                modulus,
            ),
            inverted_points[position],
            modulus,
        );
        folded.push(add_mod_fast(
            even_part,
            mul_mod_fast(challenge, odd_part, modulus),
            modulus,
        ));
    }

    Ok(folded)
}

// Fold-layer values are deterministic functions of the batched codeword, so
// their leaves carry no independent witness information and stay unsalted.
fn pair_leaf_hashes(layer: &[u64]) -> Vec<[u8; 64]> {
    let half = layer.len() / 2;
    (0..half)
        .map(|pair_index| {
            leaf_hash(pair_index, &[], &[layer[pair_index], layer[pair_index + half]])
        })
        .collect()
}

// Interpolate a small layer over its coset into coefficient form by direct
// Lagrange evaluation; the final layer is tiny so the quadratic cost is fine.
fn small_coset_interpolation(
    layer: &[u64],
    offset: u64,
    root: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let size = layer.len();
    let inverse_size = inverse_mod(size as u64, modulus)?;
    let offset_inverse = inverse_mod(offset, modulus)?;
    let root_inverse = inverse_mod(root, modulus)?;
    // Inverse cyclic DFT of size `size`, then unweight the coset offset.
    let mut coefficients = Vec::with_capacity(size);
    for coefficient_index in 0..size {
        let mut accumulated = 0_u64;
        let step = pow_mod(root_inverse, coefficient_index as u64, modulus)?;
        let mut point_power = 1_u64;
        for value in layer {
            accumulated = add_mod_fast(
                accumulated,
                mul_mod_fast(*value, point_power, modulus),
                modulus,
            );
            point_power = mul_mod_fast(point_power, step, modulus);
        }
        let unweighted = mul_mod_fast(
            mul_mod_fast(accumulated, inverse_size, modulus),
            pow_mod(offset_inverse, coefficient_index as u64, modulus)?,
            modulus,
        );
        coefficients.push(unweighted);
    }

    Ok(coefficients)
}

fn evaluate_coefficients(coefficients: &[u64], point: u64, modulus: u64) -> u64 {
    let mut accumulated = 0_u64;
    for coefficient in coefficients.iter().rev() {
        accumulated = add_mod_fast(
            mul_mod_fast(accumulated, point, modulus),
            *coefficient,
            modulus,
        );
    }

    accumulated
}

// Prove that the initial layer is a codeword of degree below the bound.
// Returns the proof and the queried pair indices of the initial layer so the
// caller can attach the matching phase tree openings.
pub(super) fn prove_low_degree(
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    initial_layer: &[u64],
) -> CanonicalResult<(LowDegreeProof, Vec<usize>)> {
    if initial_layer.len() != parameters.initial_domain_size
        || parameters.initial_domain_size != 2 * parameters.initial_degree_bound
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree initial layer does not match the declared parameters",
        ));
    }
    let total_folds = fold_count(parameters);
    let mut layers = vec![initial_layer.to_vec()];
    let mut trees = Vec::new();
    let mut folded_layer_roots = Vec::new();
    let mut offset = parameters.initial_offset;
    let mut root = parameters.initial_root;
    for fold_index in 0..total_folds {
        let challenge =
            transcript.challenge_nonzero_field_element("fold-challenge", parameters.modulus);
        let folded = fold_layer(
            layers.last().expect("layers are non-empty"),
            challenge,
            offset,
            root,
            parameters.modulus,
        )?;
        offset = mul_mod_fast(offset, offset, parameters.modulus);
        root = mul_mod_fast(root, root, parameters.modulus);
        if fold_index + 1 < total_folds {
            let tree = MerkleTree::from_leaf_hashes(pair_leaf_hashes(&folded))?;
            transcript.absorb("fold-layer-root", &tree.root());
            folded_layer_roots.push(tree.root());
            trees.push(tree);
            layers.push(folded);
        } else {
            let final_coefficients = small_coset_interpolation(
                &folded,
                offset,
                root,
                parameters.modulus,
            )?;
            let (low_coefficients, high_coefficients) =
                final_coefficients.split_at(LOW_DEGREE_FINAL_COEFFICIENT_COUNT);
            if high_coefficients.iter().any(|coefficient| *coefficient != 0) {
                return Err(invalid_succinct_setup_proof(
                    "low-degree final layer exceeds the final degree bound",
                ));
            }
            let final_coefficients = low_coefficients.to_vec();
            transcript.absorb_u64_slice("final-coefficients", &final_coefficients);
            let query_positions = transcript.challenge_positions(
                "query-position",
                parameters.initial_domain_size / 2,
                LOW_DEGREE_QUERY_COUNT,
            );
            let mut query_openings = Vec::with_capacity(query_positions.len());
            for query_position in &query_positions {
                let mut folded_layer_pairs = Vec::with_capacity(trees.len());
                let mut position = *query_position;
                for (layer, tree) in layers[1..].iter().zip(trees.iter()) {
                    let half = layer.len() / 2;
                    let pair_index = position % half;
                    folded_layer_pairs.push(LowDegreePairOpening {
                        pair: [layer[pair_index], layer[pair_index + half]],
                        path: tree.open(pair_index),
                    });
                    position = pair_index;
                }
                query_openings.push(LowDegreeQueryOpening { folded_layer_pairs });
            }

            return Ok((
                LowDegreeProof {
                    folded_layer_roots,
                    final_coefficients,
                    query_openings,
                },
                query_positions,
            ));
        }
    }

    Err(invalid_succinct_setup_proof(
        "low-degree folding requires at least one fold",
    ))
}

// Verify the folding argument. The callback receives (query ordinal, pair
// index in the initial layer) and must return the initial-layer values at
// (pair index, pair index + half) re-derived from the phase tree openings.
pub(super) fn verify_low_degree(
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    proof: &LowDegreeProof,
    mut initial_pair_at: impl FnMut(usize, usize) -> CanonicalResult<[u64; 2]>,
) -> CanonicalResult<()> {
    let total_folds = fold_count(parameters);
    if proof.folded_layer_roots.len() + 1 != total_folds
        || proof.final_coefficients.len() != LOW_DEGREE_FINAL_COEFFICIENT_COUNT
        || proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree proof shape does not match the declared parameters",
        ));
    }
    let modulus = parameters.modulus;
    // Replay the prover transcript order: per fold a challenge, then the root
    // of the layer that fold produced (or the final coefficients).
    let mut fold_challenges = Vec::with_capacity(total_folds);
    for fold_index in 0..total_folds {
        fold_challenges.push(transcript.challenge_nonzero_field_element("fold-challenge", modulus));
        if fold_index + 1 < total_folds {
            transcript.absorb("fold-layer-root", &proof.folded_layer_roots[fold_index]);
        } else {
            transcript.absorb_u64_slice("final-coefficients", &proof.final_coefficients);
        }
    }
    let query_positions = transcript.challenge_positions(
        "query-position",
        parameters.initial_domain_size / 2,
        LOW_DEGREE_QUERY_COUNT,
    );
    let inverse_two = inverse_mod(2, modulus)?;
    for (query_ordinal, (query_position, opening)) in query_positions
        .iter()
        .zip(proof.query_openings.iter())
        .enumerate()
    {
        if opening.folded_layer_pairs.len() + 1 != total_folds {
            return Err(invalid_succinct_setup_proof(
                "low-degree query opening does not cover every folded layer",
            ));
        }
        let mut pair = initial_pair_at(query_ordinal, *query_position)?;
        let mut pair_position = *query_position;
        let mut layer_size = parameters.initial_domain_size;
        let mut offset = parameters.initial_offset;
        let mut root = parameters.initial_root;
        for (fold_index, fold_challenge) in fold_challenges.iter().enumerate() {
            // Fold the held pair at the pair position of the current layer.
            let point = mul_mod_fast(
                offset,
                pow_mod(root, pair_position as u64, modulus)?,
                modulus,
            );
            let even_part = mul_mod_fast(
                add_mod_fast(pair[0], pair[1], modulus),
                inverse_two,
                modulus,
            );
            let odd_part = mul_mod_fast(
                mul_mod_fast(
                    sub_mod_fast(pair[0], pair[1], modulus),
                    inverse_two,
                    modulus,
                ),
                inverse_mod(point, modulus)?,
                modulus,
            );
            let folded_value = add_mod_fast(
                even_part,
                mul_mod_fast(*fold_challenge, odd_part, modulus),
                modulus,
            );
            // Move to the folded layer: its size is the current pair count and
            // the folded value sits at the held pair position.
            layer_size /= 2;
            offset = mul_mod_fast(offset, offset, modulus);
            root = mul_mod_fast(root, root, modulus);
            let value_position = pair_position;
            if fold_index + 1 < total_folds {
                let half = layer_size / 2;
                let pair_index = value_position % half;
                let slot = value_position / half;
                let pair_opening = &opening.folded_layer_pairs[fold_index];
                let leaf = leaf_hash(pair_index, &[], &pair_opening.pair);
                if !verify_merkle_opening(
                    &proof.folded_layer_roots[fold_index],
                    pair_index,
                    &leaf,
                    &pair_opening.path,
                ) {
                    return Err(invalid_succinct_setup_proof(
                        "low-degree folded layer opening failed Merkle verification",
                    ));
                }
                if pair_opening.pair[slot] != folded_value {
                    return Err(invalid_succinct_setup_proof(
                        "low-degree fold does not match the committed folded layer",
                    ));
                }
                pair = pair_opening.pair;
                pair_position = pair_index;
            } else {
                let final_point = mul_mod_fast(
                    offset,
                    pow_mod(root, value_position as u64, modulus)?,
                    modulus,
                );
                if evaluate_coefficients(&proof.final_coefficients, final_point, modulus)
                    != folded_value
                {
                    return Err(invalid_succinct_setup_proof(
                        "low-degree final polynomial does not match the folded value",
                    ));
                }
            }
        }
    }

    Ok(())
}
