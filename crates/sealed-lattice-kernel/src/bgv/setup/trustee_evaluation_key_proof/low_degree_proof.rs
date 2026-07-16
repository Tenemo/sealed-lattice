#[cfg(test)]
use super::evaluation_domain::{batch_inverse, coefficients_from_coset_evaluations};
#[cfg(test)]
use super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::extension_field::{ChallengeExtensionElement, ChallengeExtensionTower};
use super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};
use fiat_shamir_transcript::FiatShamirTranscript;
use merkle_commitment::{
    BatchedMerkleOpening, MerkleContext, MerkleDigest, consistent_sorted_leaves, leaf_hash,
    verify_merkle_batch,
};
#[cfg(test)]
use merkle_commitment::{MerkleTree, sorted_unique_indices};

// Batched FRI low-degree argument. The initial layer is a codeword over the
// extension coset; it is not committed here because the verifier re-derives
// queried values from the phase tree openings. Each fold halves the degree
// bound and the domain;
// folded layers are committed as Merkle trees over pair leaves so one opening
// serves the next fold. The recursion stops at a small final polynomial sent
// in coefficient form.
//
// The evaluation domain stays in the base limb field, but codeword values
// and every fold challenge live in the degree-four challenge extension.
pub(super) struct LowDegreeParameters {
    pub(super) modulus: u64,
    pub(super) initial_domain_size: usize,
    pub(super) initial_offset: u64,
    pub(super) initial_root: u64,
    // Strict degree bound of the initial layer (the codeword claims degree
    // below this value). The domain must have at least a factor-two blowup; the
    // residual sumcheck proof uses the same domain at factor-four blowup.
    pub(super) initial_degree_bound: usize,
}

pub(super) struct LowDegreeProof {
    pub(super) folded_layer_roots: Vec<MerkleDigest>,
    pub(super) final_coefficients: Vec<ChallengeExtensionElement>,
    pub(super) query_openings: Vec<LowDegreeQueryOpening>,
    // One batched authentication opening per committed folded layer, covering
    // every query's pair leaf in that layer at once.
    pub(super) layer_batch_openings: Vec<BatchedMerkleOpening>,
}

pub(super) struct LowDegreeQueryOpening {
    // One sibling entry per committed folded layer. The verifier derives the
    // selected slot from the previous fold, reconstructs the committed pair
    // leaf with this sibling, and authenticates those leaves together through
    // `LowDegreeProof::layer_batch_openings`.
    pub(super) folded_layer_siblings: Vec<LowDegreeSiblingOpening>,
}

pub(super) struct LowDegreeSiblingOpening {
    pub(super) sibling: ChallengeExtensionElement,
}

#[cfg(test)]
pub(super) struct LowDegreeProverState {
    initial_domain_size: usize,
    folded_layer_roots: Vec<MerkleDigest>,
    final_coefficients: Vec<ChallengeExtensionElement>,
    layers: Vec<Vec<ChallengeExtensionElement>>,
    trees: Vec<MerkleTree>,
}

pub(super) struct LowDegreeVerificationState {
    merkle_context: MerkleContext,
    modulus: u64,
    initial_domain_size: usize,
    initial_offset: u64,
    initial_root: u64,
    total_folds: usize,
    fold_challenges: Vec<ChallengeExtensionElement>,
}

// fold_count is the total number of fold rounds; the codec commits
// fold_count - 1 Merkle layers because the final fold is sent as coefficients,
// not a committed layer.
fn fold_count(parameters: &LowDegreeParameters) -> CanonicalResult<usize> {
    let final_coefficient_count =
        low_degree_final_coefficient_count(parameters.initial_degree_bound)?;
    Ok((parameters.initial_degree_bound / final_coefficient_count).trailing_zeros() as usize)
}

fn validate_low_degree_parameters(parameters: &LowDegreeParameters) -> CanonicalResult<()> {
    let final_coefficient_count =
        low_degree_final_coefficient_count(parameters.initial_degree_bound)?;
    if parameters.initial_domain_size == 0
        || !parameters.initial_domain_size.is_power_of_two()
        || !parameters.initial_degree_bound.is_power_of_two()
        || parameters.initial_domain_size < 2 * parameters.initial_degree_bound
        || !parameters
            .initial_degree_bound
            .is_multiple_of(final_coefficient_count)
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree parameters do not match the fixed proof shape",
        ));
    }
    let fold_ratio = parameters.initial_degree_bound / final_coefficient_count;
    if !fold_ratio.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree parameters do not have a canonical fold depth",
        ));
    }
    let total_folds = fold_count(parameters)?;
    let final_layer_size = parameters.initial_domain_size >> total_folds;
    if final_layer_size < final_coefficient_count || !final_layer_size.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree final layer does not match the fixed proof shape",
        ));
    }

    Ok(())
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

#[cfg(test)]
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
// their leaves are unsalted. Phase-tree leaves commit witness rows and remain
// salted.
#[cfg(test)]
fn pair_leaf_hashes(
    merkle_context: MerkleContext,
    layer: &[ChallengeExtensionElement],
) -> Vec<MerkleDigest> {
    let half = layer.len() / 2;
    (0..half)
        .map(|pair_index| {
            leaf_hash(
                merkle_context,
                pair_index,
                &[],
                &flatten_extension_pair(&[layer[pair_index], layer[pair_index + half]]),
            )
        })
        .collect()
}

#[cfg(test)]
fn final_layer_coefficients(
    layer: &[ChallengeExtensionElement],
    offset: u64,
    root: u64,
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let mut coefficients = vec![ChallengeExtensionTower::zero(); layer.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        let evaluations = layer
            .iter()
            .map(|element| element[coordinate])
            .collect::<Vec<_>>();
        let coordinate_coefficients =
            coefficients_from_coset_evaluations(&evaluations, offset, root, modulus)?;
        for (coefficient, coordinate_value) in coefficients.iter_mut().zip(coordinate_coefficients)
        {
            coefficient[coordinate] = coordinate_value;
        }
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

// Bind the low-degree commitment transcript before query positions are sampled.
// The caller may then use one shared query set for several related low-degree
// claims without letting the prover see those positions before all commitment
// roots and final coefficients are bound.
#[cfg(test)]
pub(super) fn commit_low_degree(
    merkle_context: MerkleContext,
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    initial_layer: &[ChallengeExtensionElement],
) -> CanonicalResult<LowDegreeProverState> {
    validate_low_degree_parameters(parameters)?;
    let final_coefficient_count =
        low_degree_final_coefficient_count(parameters.initial_degree_bound)?;
    if initial_layer.len() != parameters.initial_domain_size {
        return Err(invalid_succinct_setup_proof(
            "low-degree initial layer does not match the declared parameters",
        ));
    }
    let tower = ChallengeExtensionTower::for_modulus(parameters.modulus)?;
    let total_folds = fold_count(parameters)?;
    let mut layers = vec![initial_layer.to_vec()];
    let mut trees = Vec::new();
    let mut folded_layer_roots = Vec::new();
    let mut offset = parameters.initial_offset;
    let mut root = parameters.initial_root;
    for fold_index in 0..total_folds {
        let challenge =
            transcript.challenge_nonzero_extension_element("fold-challenge", parameters.modulus)?;
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
            let fold_context = merkle_context.with_tree_ordinal_offset(fold_index)?;
            let tree = MerkleTree::from_leaf_hashes(
                fold_context,
                pair_leaf_hashes(fold_context, &folded),
            )?;
            transcript.absorb("fold-layer-root", &tree.root());
            folded_layer_roots.push(tree.root());
            trees.push(tree);
            layers.push(folded);
        } else {
            let final_coefficients =
                final_layer_coefficients(&folded, offset, root, parameters.modulus)?;
            let (low_coefficients, high_coefficients) =
                final_coefficients.split_at(final_coefficient_count);
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

            return Ok(LowDegreeProverState {
                initial_domain_size: parameters.initial_domain_size,
                folded_layer_roots,
                final_coefficients,
                layers,
                trees,
            });
        }
    }

    Err(invalid_succinct_setup_proof(
        "low-degree folding requires at least one fold",
    ))
}

#[cfg(test)]
pub(super) fn open_low_degree_at_positions(
    state: LowDegreeProverState,
    query_positions: &[usize],
) -> CanonicalResult<LowDegreeProof> {
    if query_positions.len() != LOW_DEGREE_QUERY_COUNT
        || query_positions
            .iter()
            .any(|position| *position >= state.initial_domain_size / 2)
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree shared query positions do not match the proof shape",
        ));
    }
    let mut query_openings = Vec::with_capacity(query_positions.len());
    let mut layer_opened_indices = vec![Vec::new(); state.trees.len()];
    for query_position in query_positions {
        let mut folded_layer_siblings = Vec::with_capacity(state.trees.len());
        let mut position = *query_position;
        for (layer_ordinal, layer) in state.layers[1..].iter().enumerate() {
            let half = layer.len() / 2;
            let pair_index = position % half;
            let slot = position / half;
            let sibling_index = pair_index + (1 - slot) * half;
            folded_layer_siblings.push(LowDegreeSiblingOpening {
                sibling: layer[sibling_index],
            });
            layer_opened_indices[layer_ordinal].push(pair_index);
            position = pair_index;
        }
        query_openings.push(LowDegreeQueryOpening {
            folded_layer_siblings,
        });
    }
    let layer_batch_openings = state
        .trees
        .iter()
        .zip(layer_opened_indices)
        .map(|(tree, indices)| tree.open_batch(&sorted_unique_indices(indices)))
        .collect();

    Ok(LowDegreeProof {
        folded_layer_roots: state.folded_layer_roots,
        final_coefficients: state.final_coefficients,
        query_openings,
        layer_batch_openings,
    })
}

pub(super) fn bind_low_degree_commitment(
    merkle_context: MerkleContext,
    transcript: &mut FiatShamirTranscript,
    parameters: &LowDegreeParameters,
    proof: &LowDegreeProof,
) -> CanonicalResult<LowDegreeVerificationState> {
    validate_low_degree_parameters(parameters)?;
    let final_coefficient_count =
        low_degree_final_coefficient_count(parameters.initial_degree_bound)?;
    let total_folds = fold_count(parameters)?;
    if proof.folded_layer_roots.len() + 1 != total_folds
        || proof.final_coefficients.len() != final_coefficient_count
        || proof.layer_batch_openings.len() + 1 != total_folds
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree proof shape does not match the declared parameters",
        ));
    }
    let mut fold_challenges = Vec::with_capacity(total_folds);
    for fold_index in 0..total_folds {
        fold_challenges.push(
            transcript.challenge_nonzero_extension_element("fold-challenge", parameters.modulus)?,
        );
        if fold_index + 1 < total_folds {
            transcript.absorb("fold-layer-root", &proof.folded_layer_roots[fold_index]);
        } else {
            transcript.absorb_u64_slice(
                "final-coefficients",
                &flatten_extension_elements(&proof.final_coefficients),
            );
        }
    }

    Ok(LowDegreeVerificationState {
        merkle_context,
        modulus: parameters.modulus,
        initial_domain_size: parameters.initial_domain_size,
        initial_offset: parameters.initial_offset,
        initial_root: parameters.initial_root,
        total_folds,
        fold_challenges,
    })
}

// Layer 0 is the DEEP-batched codeword and is intentionally uncommitted here;
// its queried values are re-derived and bound through the phase-tree openings
// plus the lambda batch, so its low-degreeness still implies the committed
// columns are low-degree.
// Verify the folding argument at caller-supplied query positions. The callback
// receives (query ordinal, pair index in the initial layer) and must return the
// initial-layer values at (pair index, pair index + half) re-derived from the
// phase tree openings.
pub(super) fn verify_low_degree_openings(
    verification_state: &LowDegreeVerificationState,
    proof: &LowDegreeProof,
    query_positions: &[usize],
    mut initial_pair_at: impl FnMut(usize, usize) -> CanonicalResult<[ChallengeExtensionElement; 2]>,
) -> CanonicalResult<()> {
    if proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
        || query_positions.len() != LOW_DEGREE_QUERY_COUNT
        || query_positions
            .iter()
            .any(|position| *position >= verification_state.initial_domain_size / 2)
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree proof shape does not match the declared parameters",
        ));
    }
    let modulus = verification_state.modulus;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let inverse_two = inverse_mod(2, modulus)?;
    let mut layer_opened_leaves: Vec<Vec<(usize, MerkleDigest)>> =
        vec![Vec::new(); verification_state.total_folds - 1];
    for (query_ordinal, (query_position, opening)) in query_positions
        .iter()
        .zip(proof.query_openings.iter())
        .enumerate()
    {
        if opening.folded_layer_siblings.len() + 1 != verification_state.total_folds {
            return Err(invalid_succinct_setup_proof(
                "low-degree query opening does not cover every folded layer",
            ));
        }
        let mut pair = initial_pair_at(query_ordinal, *query_position)?;
        let mut pair_position = *query_position;
        let mut layer_size = verification_state.initial_domain_size;
        let mut offset = verification_state.initial_offset;
        let mut root = verification_state.initial_root;
        for (fold_index, fold_challenge) in verification_state.fold_challenges.iter().enumerate() {
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
            if fold_index + 1 < verification_state.total_folds {
                let half = layer_size / 2;
                let pair_index = value_position % half;
                let slot = value_position / half;
                let sibling_opening = &opening.folded_layer_siblings[fold_index];
                let mut reconstructed_pair = [ChallengeExtensionTower::zero(); 2];
                reconstructed_pair[slot] = folded_value;
                reconstructed_pair[slot ^ 1] = sibling_opening.sibling;
                let leaf = leaf_hash(
                    verification_state
                        .merkle_context
                        .with_tree_ordinal_offset(fold_index)?,
                    pair_index,
                    &[],
                    &flatten_extension_pair(&reconstructed_pair),
                );
                layer_opened_leaves[fold_index].push((pair_index, leaf));
                pair = reconstructed_pair;
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
        let layer_leaf_count = verification_state.initial_domain_size >> (fold_index + 2);
        let layer_depth = layer_leaf_count.trailing_zeros() as usize;
        let Some(layer_leaves) =
            consistent_sorted_leaves(layer_opened_leaves[fold_index].iter().copied())
        else {
            return Err(invalid_succinct_setup_proof(
                "low-degree folded layer opens one position to two values",
            ));
        };
        if !verify_merkle_batch(
            verification_state
                .merkle_context
                .with_tree_ordinal_offset(fold_index)?,
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
