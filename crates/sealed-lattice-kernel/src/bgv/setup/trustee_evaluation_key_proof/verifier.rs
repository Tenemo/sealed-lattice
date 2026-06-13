use super::evaluation_domain::EvaluationDomainPlan;
use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{LowDegreeParameters, verify_low_degree};
use super::merkle_commitment::{LEAF_SALT_BYTES, leaf_hash, verify_merkle_opening};
use super::prover::{
    LimbProof, SuccinctEvaluationKeyProof, barycentric_weights, build_limb_public_vectors,
    draw_limb_challenges, global_claim_id, sample_deep_points, trace_vanishing_at_extension,
};
use super::relation::{
    ExtensionColumnDomain, LimbColumnLayout, PHASE_TWO_COLUMN_COUNT,
    QUOTIENT_COLUMN_ROW_CHECK_HIGH, QUOTIENT_COLUMN_ROW_CHECK_LOW, QUOTIENT_COLUMN_SUMCHECK_LINEAR,
    QUOTIENT_COLUMN_SUMCHECK_VANISHING, SumcheckPublicEvaluations, TrusteeEvaluationKeyStatement,
    batched_row_check_value, batched_sumcheck_value, masked_claim_bounds,
};
use super::*;
use crate::bgv::modular_arithmetic::inverse_mod;

// Evaluate the trace-domain interpolants of both halves of a logical length-N
// extension vector at one point, sharing the barycentric weights.
fn extension_halves_at_point(
    tower: &ChallengeExtensionTower,
    weights: &[ChallengeExtensionElement],
    vector: &[ChallengeExtensionElement],
    trace_size: usize,
) -> [ChallengeExtensionElement; 2] {
    let mut halves = [ChallengeExtensionTower::zero(); 2];
    for (half, half_values) in [&vector[..trace_size], &vector[trace_size..]]
        .into_iter()
        .enumerate()
    {
        let mut accumulated = ChallengeExtensionTower::zero();
        for (weight, value) in weights.iter().zip(half_values.iter()) {
            accumulated = tower.add(&accumulated, &tower.mul(weight, value));
        }
        halves[half] = accumulated;
    }

    halves
}

// The same interpolation for a base-valued public vector.
fn base_halves_at_point(
    tower: &ChallengeExtensionTower,
    weights: &[ChallengeExtensionElement],
    vector: &[u64],
    trace_size: usize,
) -> [ChallengeExtensionElement; 2] {
    let mut halves = [ChallengeExtensionTower::zero(); 2];
    for (half, half_values) in [&vector[..trace_size], &vector[trace_size..]]
        .into_iter()
        .enumerate()
    {
        let mut accumulated = ChallengeExtensionTower::zero();
        for (weight, value) in weights.iter().zip(half_values.iter()) {
            accumulated = tower.add(&accumulated, &tower.scale_base(weight, *value));
        }
        halves[half] = accumulated;
    }

    halves
}

fn verify_limb(
    statement: &TrusteeEvaluationKeyStatement,
    limb_index: usize,
    modulus: u64,
    limb_proof: &LimbProof,
    consistency_vectors: &[Vec<u64>],
    global_transcript: &FiatShamirTranscript,
) -> CanonicalResult<()> {
    let layout = LimbColumnLayout::new(statement, limb_index)?;
    let plan = EvaluationDomainPlan::new(modulus, layout.trace_size)?;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let trace_size = plan.trace_size;
    let extension_size = plan.extension_size;
    let phase_one_columns = layout.phase_one_physical_count();
    let total_columns = phase_one_columns + PHASE_TWO_COLUMN_COUNT;
    if limb_proof.masked_consistency_claims.len() != layout.claim_count()
        || limb_proof.deep_evaluations.len() != DEEP_POINT_COUNT
        || limb_proof
            .deep_evaluations
            .iter()
            .any(|evaluations| evaluations.len() != total_columns)
        || limb_proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
    {
        return Err(invalid_succinct_setup_proof(
            "limb proof shape does not match the statement",
        ));
    }

    let mut transcript = global_transcript.fork("limb", limb_index as u64);
    let challenges = draw_limb_challenges(&mut transcript, &layout, modulus);
    let publics = build_limb_public_vectors(
        statement,
        &layout,
        limb_index,
        modulus,
        &challenges,
        &limb_proof.masked_consistency_claims,
    )?;
    let expected_constant = tower.scale_base(
        &publics.lincheck_claim,
        inverse_mod(trace_size as u64, modulus)?,
    );

    transcript.absorb("quotient-tree-root", &limb_proof.quotient_tree_root);
    transcript.absorb_u64_slice(
        "masked-consistency-claims",
        &limb_proof.masked_consistency_claims,
    );
    let deep_points = sample_deep_points(&mut transcript, &plan)?;

    // Out-of-domain identity checks: the claimed evaluations must satisfy the
    // batched row check and the sumcheck decomposition over the extension.
    let extension_domain = ExtensionColumnDomain { tower };
    let bound_power = (COMMITMENT_BOUND_FACTOR * trace_size) as u64;
    for (point_index, point) in deep_points.iter().enumerate() {
        let evaluations = &limb_proof.deep_evaluations[point_index];
        let phase_one_values = &evaluations[..phase_one_columns];
        let vanishing = trace_vanishing_at_extension(&plan, &tower, point);
        let row_check_value = batched_row_check_value(
            &extension_domain,
            phase_one_values,
            &challenges.beta,
            &layout,
        );
        let row_quotient = tower.add(
            &evaluations[phase_one_columns + QUOTIENT_COLUMN_ROW_CHECK_LOW],
            &tower.mul(
                &tower.pow(point, bound_power),
                &evaluations[phase_one_columns + QUOTIENT_COLUMN_ROW_CHECK_HIGH],
            ),
        );
        if row_check_value != tower.mul(&vanishing, &row_quotient) {
            return Err(invalid_succinct_setup_proof(
                "row check identity failed at an out-of-domain point",
            ));
        }
        let weights = barycentric_weights(&plan, &tower, point)?;
        let point_publics = SumcheckPublicEvaluations {
            secret_factor: publics
                .secret_factor
                .iter()
                .map(|vector| extension_halves_at_point(&tower, &weights, vector, trace_size))
                .collect(),
            u_power: publics
                .u_powers
                .iter()
                .map(|vector| extension_halves_at_point(&tower, &weights, vector, trace_size))
                .collect(),
            consistency: consistency_vectors
                .iter()
                .map(|vector| base_halves_at_point(&tower, &weights, vector, trace_size))
                .collect(),
            mask_selector: publics
                .mask_selectors
                .iter()
                .map(|vector| extension_halves_at_point(&tower, &weights, vector, trace_size))
                .collect(),
            linkage: publics
                .linkage_vectors
                .iter()
                .map(|vector| extension_halves_at_point(&tower, &weights, vector, trace_size))
                .collect(),
        };
        let sumcheck_value = batched_sumcheck_value(
            &extension_domain,
            phase_one_values,
            &point_publics,
            &publics.error_weights,
            &challenges.consistency_alpha,
            &layout,
        );
        let vanishing_quotient =
            &evaluations[phase_one_columns + QUOTIENT_COLUMN_SUMCHECK_VANISHING];
        let linear_quotient = &evaluations[phase_one_columns + QUOTIENT_COLUMN_SUMCHECK_LINEAR];
        let left = tower.sub(&sumcheck_value, &tower.mul(&vanishing, vanishing_quotient));
        let right = tower.add(&expected_constant, &tower.mul(point, linear_quotient));
        if left != right {
            return Err(invalid_succinct_setup_proof(
                "sumcheck identity failed at an out-of-domain point",
            ));
        }
    }

    for evaluations in &limb_proof.deep_evaluations {
        let flattened = evaluations.iter().flatten().copied().collect::<Vec<u64>>();
        transcript.absorb_u64_slice("deep-evaluations", &flattened);
    }
    let lambda = transcript.challenge_extension_elements(
        "lambda",
        modulus,
        total_columns * DEEP_POINT_COUNT,
    );

    let low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: COMMITMENT_BOUND_FACTOR * trace_size,
    };
    let half = extension_size / 2;
    let query_openings = &limb_proof.query_openings;
    let phase_two_physical_columns = PHASE_TWO_COLUMN_COUNT * CHALLENGE_EXTENSION_DEGREE;
    let reconstruct_batch_value = |phase_one_row: &[u64],
                                   phase_two_row: &[u64],
                                   position: usize|
     -> CanonicalResult<ChallengeExtensionElement> {
        let extension_point = tower.embed_base(plan.extension_point(position));
        let mut accumulated = ChallengeExtensionTower::zero();
        for (point_index, point) in deep_points.iter().enumerate() {
            let difference = tower.sub(&extension_point, point);
            let inverted_difference = tower.inverse(&difference)?;
            let mut point_sum = ChallengeExtensionTower::zero();
            for (column_index, column_value) in phase_one_row.iter().enumerate() {
                point_sum = tower.add(
                    &point_sum,
                    &tower.scale_base(
                        &lambda[column_index * DEEP_POINT_COUNT + point_index],
                        *column_value,
                    ),
                );
            }
            for logical_index in 0..PHASE_TWO_COLUMN_COUNT {
                let mut logical_value = ChallengeExtensionTower::zero();
                for (coordinate, slot) in logical_value.iter_mut().enumerate() {
                    *slot = phase_two_row[logical_index * CHALLENGE_EXTENSION_DEGREE + coordinate];
                }
                let column_index = phase_one_columns + logical_index;
                point_sum = tower.add(
                    &point_sum,
                    &tower.mul(
                        &lambda[column_index * DEEP_POINT_COUNT + point_index],
                        &logical_value,
                    ),
                );
            }
            for column_index in 0..total_columns {
                point_sum = tower.sub(
                    &point_sum,
                    &tower.mul(
                        &lambda[column_index * DEEP_POINT_COUNT + point_index],
                        &limb_proof.deep_evaluations[point_index][column_index],
                    ),
                );
            }
            accumulated = tower.add(&accumulated, &tower.mul(&point_sum, &inverted_difference));
        }

        Ok(accumulated)
    };

    verify_low_degree(
        &mut transcript,
        &low_degree_parameters,
        &limb_proof.low_degree,
        |query_ordinal, pair_index| {
            let opening = &query_openings[query_ordinal];
            if opening.phase_one_rows[0].len() != phase_one_columns
                || opening.phase_one_rows[1].len() != phase_one_columns
                || opening.phase_two_rows[0].len() != phase_two_physical_columns
                || opening.phase_two_rows[1].len() != phase_two_physical_columns
                || opening
                    .phase_one_salts
                    .iter()
                    .chain(opening.phase_two_salts.iter())
                    .any(|salt| salt.len() != LEAF_SALT_BYTES)
            {
                return Err(invalid_succinct_setup_proof(
                    "query opening shape does not match the column layout",
                ));
            }
            for (slot, position) in [pair_index, pair_index + half].into_iter().enumerate() {
                let phase_one_leaf = leaf_hash(
                    position,
                    &opening.phase_one_salts[slot],
                    &opening.phase_one_rows[slot],
                );
                let phase_two_leaf = leaf_hash(
                    position,
                    &opening.phase_two_salts[slot],
                    &opening.phase_two_rows[slot],
                );
                if !verify_merkle_opening(
                    &limb_proof.witness_tree_root,
                    position,
                    &phase_one_leaf,
                    &opening.phase_one_paths[slot],
                ) || !verify_merkle_opening(
                    &limb_proof.quotient_tree_root,
                    position,
                    &phase_two_leaf,
                    &opening.phase_two_paths[slot],
                ) {
                    return Err(invalid_succinct_setup_proof(
                        "query opening failed Merkle verification",
                    ));
                }
            }
            Ok([
                reconstruct_batch_value(
                    &opening.phase_one_rows[0],
                    &opening.phase_two_rows[0],
                    pair_index,
                )?,
                reconstruct_batch_value(
                    &opening.phase_one_rows[1],
                    &opening.phase_two_rows[1],
                    pair_index + half,
                )?,
            ])
        },
    )
}

// Cross-limb integer consistency on the masked claims: every limb publishes
// the residue of the same global claim integer (clear combination plus the
// shared smudging mask). The integer is recovered by a centered lift from the
// first two limb fields carrying the claim — the two-prime window is wider
// than twice the claim bound, so the lift is unique — and every other limb's
// residue must match that integer, which forces integer witness equality
// through the bounded random combinations.
fn verify_cross_limb_consistency(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &SuccinctEvaluationKeyProof,
) -> CanonicalResult<()> {
    let limb_moduli = statement.limb_moduli();
    let (lower_bound, upper_bound) = masked_claim_bounds(statement)?;
    let mut residues_by_global_id: std::collections::BTreeMap<u64, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for (limb_index, modulus) in limb_moduli.iter().enumerate() {
        let layout = LimbColumnLayout::new(statement, limb_index)?;
        for (local_claim, claim) in proof.limb_proofs[limb_index]
            .masked_consistency_claims
            .iter()
            .enumerate()
        {
            if *claim >= *modulus {
                return Err(invalid_succinct_setup_proof(
                    "masked consistency claim is not a reduced limb residue",
                ));
            }
            let global_id = global_claim_id(statement, &layout, local_claim);
            residues_by_global_id
                .entry(global_id)
                .or_default()
                .push((*modulus, *claim));
        }
    }
    for residues in residues_by_global_id.values() {
        let [
            (first_modulus, first_residue),
            (second_modulus, second_residue),
        ] = residues[..2]
        else {
            return Err(invalid_succinct_setup_proof(
                "masked consistency claim needs at least two limb fields for integer binding",
            ));
        };
        // Centered two-prime lift of the claim integer.
        let product = i128::from(first_modulus) * i128::from(second_modulus);
        if product <= 2 * lower_bound.abs().max(upper_bound) {
            return Err(invalid_succinct_setup_proof(
                "masked consistency claim range is too wide for two-prime lifting",
            ));
        }
        let step = i128::from(mul_mod_fast(
            (second_residue + second_modulus - (first_residue % second_modulus) % second_modulus)
                % second_modulus,
            inverse_mod(first_modulus % second_modulus, second_modulus)?,
            second_modulus,
        ));
        let mut claim_integer = i128::from(first_residue) + i128::from(first_modulus) * step;
        if claim_integer > product / 2 {
            claim_integer -= product;
        }
        if claim_integer < lower_bound || claim_integer > upper_bound {
            return Err(invalid_succinct_setup_proof(
                "masked consistency claim exceeds the accepted range",
            ));
        }
        for (modulus, residue) in &residues[2..] {
            if claim_integer.rem_euclid(i128::from(*modulus)) != i128::from(*residue) {
                return Err(invalid_succinct_setup_proof(
                    "masked consistency claim disagrees across limb fields",
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn verify_evaluation_key_share(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &SuccinctEvaluationKeyProof,
) -> CanonicalResult<()> {
    statement.validate_shape()?;
    let limb_moduli = statement.limb_moduli();
    if proof.limb_proofs.len() != limb_moduli.len() {
        return Err(invalid_succinct_setup_proof(
            "proof limb count does not match the statement",
        ));
    }
    let mut transcript = FiatShamirTranscript::new("trustee-evaluation-key-share");
    transcript.absorb("statement", &statement.statement_hash());
    for limb_proof in &proof.limb_proofs {
        transcript.absorb("witness-tree-root", &limb_proof.witness_tree_root);
    }
    let consistency_vectors = (0..CONSISTENCY_REPETITIONS)
        .map(|_| {
            transcript.challenge_bounded_integers(
                "consistency-vector",
                CONSISTENCY_COEFFICIENT_BITS,
                statement.ring_degree,
            )
        })
        .collect::<Vec<_>>();

    verify_cross_limb_consistency(statement, proof)?;
    for (limb_index, modulus) in limb_moduli.iter().enumerate() {
        verify_limb(
            statement,
            limb_index,
            *modulus,
            &proof.limb_proofs[limb_index],
            &consistency_vectors,
            &transcript,
        )?;
    }

    Ok(())
}
