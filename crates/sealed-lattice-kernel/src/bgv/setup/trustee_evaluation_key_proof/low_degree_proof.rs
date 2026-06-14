use super::evaluation_domain::batch_inverse;
use super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};
use fiat_shamir_transcript::FiatShamirTranscript;
use merkle_commitment::{
    BatchedMerkleOpening, MerkleTree, consistent_sorted_leaves, leaf_hash, sorted_unique_indices,
    verify_merkle_batch,
};

// Batched FRI low-degree argument at rate 1/2. The initial layer is the
// lambda-batched DEEP quotient codeword over the extension coset; it is not
// committed here because the verifier re-derives queried values from the
// phase tree openings. Each fold halves the degree bound and the domain;
// folded layers are committed as Merkle trees over pair leaves so one opening
// serves the next fold. The recursion stops at a small final polynomial sent
// in coefficient form.
//
// The evaluation domain stays in the base limb field, but codeword values
// and every fold challenge live in the degree-four challenge extension, so
// each fold round's soundness error is governed by the extension size
// instead of the 47-bit base field.
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
    pub(super) final_coefficients: Vec<ChallengeExtensionElement>,
    pub(super) query_openings: Vec<LowDegreeQueryOpening>,
    // One batched authentication opening per committed folded layer, covering
    // every query's pair leaf in that layer at once.
    pub(super) layer_batch_openings: Vec<BatchedMerkleOpening>,
}

pub(super) struct LowDegreeQueryOpening {
    // One pair entry per committed folded layer; the pair leaves are
    // authenticated together through `LowDegreeProof::layer_batch_openings`.
    pub(super) folded_layer_pairs: Vec<LowDegreePairOpening>,
}

pub(super) struct LowDegreePairOpening {
    pub(super) pair: [ChallengeExtensionElement; 2],
}

// fold_count is the total number of fold rounds; the codec commits
// fold_count - 1 Merkle layers because the final fold is sent as coefficients,
// not a committed layer.
fn fold_count(parameters: &LowDegreeParameters) -> usize {
    debug_assert!(parameters.initial_degree_bound.is_power_of_two());
    debug_assert!(parameters.initial_degree_bound > LOW_DEGREE_FINAL_COEFFICIENT_COUNT);
    (parameters.initial_degree_bound / LOW_DEGREE_FINAL_COEFFICIENT_COUNT).trailing_zeros() as usize
}

fn flatten_extension_pair(pair: &[ChallengeExtensionElement; 2]) -> [u64; 8] {
    [
        pair[0][0], pair[0][1], pair[0][2], pair[0][3], pair[1][0], pair[1][1], pair[1][2],
        pair[1][3],
    ]
}

fn flatten_extension_elements(elements: &[ChallengeExtensionElement]) -> Vec<u64> {
    elements.iter().flatten().copied().collect()
}

fn fold_layer(
    tower: &ChallengeExtensionTower,
    layer: &[ChallengeExtensionElement],
    challenge: &ChallengeExtensionElement,
    offset: u64,
    root: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = tower.modulus;
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
        let even_part = tower.scale_base(
            &tower.add(&layer[position], &layer[position + half]),
            inverse_two,
        );
        let odd_part = tower.scale_base(
            &tower.scale_base(
                &tower.sub(&layer[position], &layer[position + half]),
                inverse_two,
            ),
            inverted_points[position],
        );
        folded.push(tower.add(&even_part, &tower.mul(challenge, &odd_part)));
    }

    Ok(folded)
}

// Fold-layer values are deterministic functions of the batched codeword, so
// their leaves carry no independent witness information and stay unsalted.
// Fold layers need only binding so their leaves are unsalted; phase-tree leaves
// commit raw witness rows and must be salted to stay hiding -- the asymmetry is
// intentional.
fn pair_leaf_hashes(layer: &[ChallengeExtensionElement]) -> Vec<[u8; 64]> {
    let half = layer.len() / 2;
    (0..half)
        .map(|pair_index| {
            leaf_hash(
                pair_index,
                &[],
                &flatten_extension_pair(&[layer[pair_index], layer[pair_index + half]]),
            )
        })
        .collect()
}

// Interpolate a small layer over its coset into coefficient form by direct
// Lagrange evaluation; the final layer is tiny so the quadratic cost is fine.
fn small_coset_interpolation(
    tower: &ChallengeExtensionTower,
    layer: &[ChallengeExtensionElement],
    offset: u64,
    root: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = tower.modulus;
    let size = layer.len();
    let inverse_size = inverse_mod(size as u64, modulus)?;
    let offset_inverse = inverse_mod(offset, modulus)?;
    let root_inverse = inverse_mod(root, modulus)?;
    // Inverse cyclic DFT of size `size`, then unweight the coset offset.
    let mut coefficients = Vec::with_capacity(size);
    for coefficient_index in 0..size {
        let mut accumulated = ChallengeExtensionTower::zero();
        let step = pow_mod(root_inverse, coefficient_index as u64, modulus)?;
        let mut point_power = 1_u64;
        for value in layer {
            accumulated = tower.add(&accumulated, &tower.scale_base(value, point_power));
            point_power = mul_mod_fast(point_power, step, modulus);
        }
        let unweighted = tower.scale_base(
            &tower.scale_base(&accumulated, inverse_size),
            pow_mod(offset_inverse, coefficient_index as u64, modulus)?,
        );
        coefficients.push(unweighted);
    }

    Ok(coefficients)
}

fn evaluate_coefficients(
    tower: &ChallengeExtensionTower,
    coefficients: &[ChallengeExtensionElement],
    point: u64,
) -> ChallengeExtensionElement {
    let mut accumulated = ChallengeExtensionTower::zero();
    for coefficient in coefficients.iter().rev() {
        accumulated = tower.add(&tower.scale_base(&accumulated, point), coefficient);
    }

    accumulated
}

// Prove that the initial layer is a codeword of degree below the bound.
// Returns the proof and the queried pair indices of the initial layer so the
// caller can attach the matching phase tree openings.
pub(super) fn prove_low_degree(
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    initial_layer: &[ChallengeExtensionElement],
) -> CanonicalResult<(LowDegreeProof, Vec<usize>)> {
    if initial_layer.len() != parameters.initial_domain_size
        || parameters.initial_domain_size != 2 * parameters.initial_degree_bound
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree initial layer does not match the declared parameters",
        ));
    }
    let tower = ChallengeExtensionTower::for_modulus(parameters.modulus)?;
    let total_folds = fold_count(parameters);
    let mut layers = vec![initial_layer.to_vec()];
    let mut trees = Vec::new();
    let mut folded_layer_roots = Vec::new();
    let mut offset = parameters.initial_offset;
    let mut root = parameters.initial_root;
    for fold_index in 0..total_folds {
        let challenge =
            transcript.challenge_nonzero_extension_element("fold-challenge", parameters.modulus);
        let folded = fold_layer(
            &tower,
            layers.last().expect("layers are non-empty"),
            &challenge,
            offset,
            root,
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
            let final_coefficients = small_coset_interpolation(&tower, &folded, offset, root)?;
            let (low_coefficients, high_coefficients) =
                final_coefficients.split_at(LOW_DEGREE_FINAL_COEFFICIENT_COUNT);
            if high_coefficients
                .iter()
                .any(|coefficient| !ChallengeExtensionTower::is_zero(coefficient))
            {
                return Err(invalid_succinct_setup_proof(
                    "low-degree final layer exceeds the final degree bound",
                ));
            }
            let final_coefficients = low_coefficients.to_vec();
            transcript.absorb_u64_slice(
                "final-coefficients",
                &flatten_extension_elements(&final_coefficients),
            );
            let query_positions = transcript.challenge_positions(
                "query-position",
                parameters.initial_domain_size / 2,
                LOW_DEGREE_QUERY_COUNT,
            );
            let mut query_openings = Vec::with_capacity(query_positions.len());
            let mut layer_opened_indices = vec![Vec::new(); trees.len()];
            for query_position in &query_positions {
                let mut folded_layer_pairs = Vec::with_capacity(trees.len());
                let mut position = *query_position;
                for (layer_ordinal, layer) in layers[1..].iter().enumerate() {
                    let half = layer.len() / 2;
                    let pair_index = position % half;
                    folded_layer_pairs.push(LowDegreePairOpening {
                        pair: [layer[pair_index], layer[pair_index + half]],
                    });
                    layer_opened_indices[layer_ordinal].push(pair_index);
                    position = pair_index;
                }
                query_openings.push(LowDegreeQueryOpening { folded_layer_pairs });
            }
            let layer_batch_openings = trees
                .iter()
                .zip(layer_opened_indices)
                .map(|(tree, indices)| tree.open_batch(&sorted_unique_indices(indices)))
                .collect();

            return Ok((
                LowDegreeProof {
                    folded_layer_roots,
                    final_coefficients,
                    query_openings,
                    layer_batch_openings,
                },
                query_positions,
            ));
        }
    }

    Err(invalid_succinct_setup_proof(
        "low-degree folding requires at least one fold",
    ))
}

// Layer 0 is the DEEP-batched codeword and is intentionally uncommitted here;
// its queried values are re-derived and bound through the phase-tree openings
// plus the lambda batch, so its low-degreeness still implies the committed
// columns are low-degree.
// Verify the folding argument. The callback receives (query ordinal, pair
// index in the initial layer) and must return the initial-layer values at
// (pair index, pair index + half) re-derived from the phase tree openings.
pub(super) fn verify_low_degree(
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    proof: &LowDegreeProof,
    mut initial_pair_at: impl FnMut(usize, usize) -> CanonicalResult<[ChallengeExtensionElement; 2]>,
) -> CanonicalResult<()> {
    let total_folds = fold_count(parameters);
    if proof.folded_layer_roots.len() + 1 != total_folds
        || proof.final_coefficients.len() != LOW_DEGREE_FINAL_COEFFICIENT_COUNT
        || proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
        || proof.layer_batch_openings.len() + 1 != total_folds
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree proof shape does not match the declared parameters",
        ));
    }
    let modulus = parameters.modulus;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    // Replay the prover transcript order: per fold a challenge, then the root
    // of the layer that fold produced (or the final coefficients).
    let mut fold_challenges = Vec::with_capacity(total_folds);
    for fold_index in 0..total_folds {
        fold_challenges
            .push(transcript.challenge_nonzero_extension_element("fold-challenge", modulus));
        if fold_index + 1 < total_folds {
            transcript.absorb("fold-layer-root", &proof.folded_layer_roots[fold_index]);
        } else {
            transcript.absorb_u64_slice(
                "final-coefficients",
                &flatten_extension_elements(&proof.final_coefficients),
            );
        }
    }
    let query_positions = transcript.challenge_positions(
        "query-position",
        parameters.initial_domain_size / 2,
        LOW_DEGREE_QUERY_COUNT,
    );
    let inverse_two = inverse_mod(2, modulus)?;
    let mut layer_opened_leaves: Vec<Vec<(usize, [u8; 64])>> = vec![Vec::new(); total_folds - 1];
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
            let even_part = tower.scale_base(&tower.add(&pair[0], &pair[1]), inverse_two);
            let odd_part = tower.scale_base(
                &tower.scale_base(&tower.sub(&pair[0], &pair[1]), inverse_two),
                inverse_mod(point, modulus)?,
            );
            let folded_value = tower.add(&even_part, &tower.mul(fold_challenge, &odd_part));
            // Move to the folded layer: its size is the current pair count and
            // the folded value sits at the held pair position.
            layer_size /= 2;
            // Offset and root are squared each fold to descend the coset tower;
            // the fold divides the odd part by the coset point offset *
            // root^position, so this squaring must stay lockstep with the prover.
            offset = mul_mod_fast(offset, offset, modulus);
            root = mul_mod_fast(root, root, modulus);
            let value_position = pair_position;
            if fold_index + 1 < total_folds {
                let half = layer_size / 2;
                let pair_index = value_position % half;
                let slot = value_position / half;
                let pair_opening = &opening.folded_layer_pairs[fold_index];
                let leaf = leaf_hash(pair_index, &[], &flatten_extension_pair(&pair_opening.pair));
                layer_opened_leaves[fold_index].push((pair_index, leaf));
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
                if evaluate_coefficients(&tower, &proof.final_coefficients, final_point)
                    != folded_value
                {
                    return Err(invalid_succinct_setup_proof(
                        "low-degree final polynomial does not match the folded value",
                    ));
                }
            }
        }
    }

    // Authenticate every folded layer's queried pair leaves against its root in
    // one batched opening per layer, after the fold checks have re-derived them.
    for (fold_index, batch_opening) in proof.layer_batch_openings.iter().enumerate() {
        let layer_leaf_count = parameters.initial_domain_size >> (fold_index + 2);
        let layer_depth = layer_leaf_count.trailing_zeros() as usize;
        let Some(layer_leaves) =
            consistent_sorted_leaves(layer_opened_leaves[fold_index].iter().copied())
        else {
            return Err(invalid_succinct_setup_proof(
                "low-degree folded layer opens one position to two values",
            ));
        };
        if !verify_merkle_batch(
            &proof.folded_layer_roots[fold_index],
            layer_depth,
            &layer_leaves,
            batch_opening,
        ) {
            return Err(invalid_succinct_setup_proof(
                "low-degree folded layer opening failed Merkle verification",
            ));
        }
    }

    Ok(())
}
