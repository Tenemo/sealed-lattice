use super::evaluation_domain::EvaluationDomainPlan;
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{LowDegreeParameters, verify_low_degree};
use super::merkle_commitment::{LEAF_SALT_BYTES, leaf_hash, verify_merkle_opening};
use super::prover::{
    LimbProof, SuccinctEvaluationKeyProof, barycentric_weights, build_limb_public_vectors,
    draw_limb_challenges, global_claim_id, sample_deep_points,
};
use super::relation::{
    LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, QUOTIENT_COLUMN_ROW_CHECK_HIGH,
    QUOTIENT_COLUMN_ROW_CHECK_LOW, QUOTIENT_COLUMN_SUMCHECK_LINEAR,
    QUOTIENT_COLUMN_SUMCHECK_VANISHING, SumcheckPublicEvaluations, TrusteeEvaluationKeyStatement,
    batched_row_check_value, batched_sumcheck_value, masked_claim_bounds,
};
use super::*;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};

fn dot_product(left: &[u64], right: &[u64], modulus: u64) -> u64 {
    let mut accumulated = 0_u64;
    for (left_value, right_value) in left.iter().zip(right.iter()) {
        accumulated = add_mod_fast(
            accumulated,
            mul_mod_fast(*left_value, *right_value, modulus),
            modulus,
        );
    }

    accumulated
}

// Evaluate the trace-domain interpolants of both halves of a logical length-N
// vector at one point, sharing the barycentric weights.
fn halves_at_point(
    weights: &[u64],
    vector: &[u64],
    trace_size: usize,
    modulus: u64,
) -> [u64; 2] {
    [
        dot_product(weights, &vector[..trace_size], modulus),
        dot_product(weights, &vector[trace_size..], modulus),
    ]
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
    let expected_constant = mul_mod_fast(
        publics.lincheck_claim,
        inverse_mod(trace_size as u64, modulus)?,
        modulus,
    );

    transcript.absorb("quotient-tree-root", &limb_proof.quotient_tree_root);
    transcript.absorb_u64_slice(
        "masked-consistency-claims",
        &limb_proof.masked_consistency_claims,
    );
    let deep_points = sample_deep_points(&mut transcript, &plan)?;

    // Out-of-domain identity checks: the claimed evaluations must satisfy the
    // batched row check and the sumcheck decomposition.
    let bound_power = (COMMITMENT_BOUND_FACTOR * trace_size) as u64;
    for (point_index, point) in deep_points.iter().enumerate() {
        let evaluations = &limb_proof.deep_evaluations[point_index];
        let phase_one_values = &evaluations[..phase_one_columns];
        let vanishing = plan.trace_vanishing_at(*point);
        let row_check_value =
            batched_row_check_value(phase_one_values, &challenges.beta, &layout, modulus);
        let row_quotient = add_mod_fast(
            evaluations[phase_one_columns + QUOTIENT_COLUMN_ROW_CHECK_LOW],
            mul_mod_fast(
                pow_mod(*point, bound_power, modulus)?,
                evaluations[phase_one_columns + QUOTIENT_COLUMN_ROW_CHECK_HIGH],
                modulus,
            ),
            modulus,
        );
        if row_check_value != mul_mod_fast(vanishing, row_quotient, modulus) {
            return Err(invalid_succinct_setup_proof(
                "row check identity failed at an out-of-domain point",
            ));
        }
        let weights = barycentric_weights(&plan, *point)?;
        let point_publics = SumcheckPublicEvaluations {
            secret_factor: publics
                .secret_factor
                .iter()
                .map(|vector| halves_at_point(&weights, vector, trace_size, modulus))
                .collect(),
            u_power: publics
                .u_powers
                .iter()
                .map(|vector| halves_at_point(&weights, vector, trace_size, modulus))
                .collect(),
            consistency: consistency_vectors
                .iter()
                .map(|vector| halves_at_point(&weights, vector, trace_size, modulus))
                .collect(),
            mask_selector: publics
                .mask_selectors
                .iter()
                .map(|vector| halves_at_point(&weights, vector, trace_size, modulus))
                .collect(),
            linkage: publics
                .linkage_vectors
                .iter()
                .map(|vector| halves_at_point(&weights, vector, trace_size, modulus))
                .collect(),
        };
        let sumcheck_value = batched_sumcheck_value(
            phase_one_values,
            &point_publics,
            &publics.error_weights,
            &challenges.consistency_alpha,
            &layout,
            modulus,
        );
        let vanishing_quotient =
            evaluations[phase_one_columns + QUOTIENT_COLUMN_SUMCHECK_VANISHING];
        let linear_quotient = evaluations[phase_one_columns + QUOTIENT_COLUMN_SUMCHECK_LINEAR];
        let left = sub_mod_fast(
            sumcheck_value,
            mul_mod_fast(vanishing, vanishing_quotient, modulus),
            modulus,
        );
        let right = add_mod_fast(
            expected_constant,
            mul_mod_fast(*point, linear_quotient, modulus),
            modulus,
        );
        if left != right {
            return Err(invalid_succinct_setup_proof(
                "sumcheck identity failed at an out-of-domain point",
            ));
        }
    }

    for evaluations in &limb_proof.deep_evaluations {
        transcript.absorb_u64_slice("deep-evaluations", evaluations);
    }
    let lambda =
        transcript.challenge_field_elements("lambda", modulus, total_columns * DEEP_POINT_COUNT);

    let low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: COMMITMENT_BOUND_FACTOR * trace_size,
    };
    let half = extension_size / 2;
    let query_openings = &limb_proof.query_openings;
    let reconstruct_batch_value = |row: &[u64], position: usize| -> CanonicalResult<u64> {
        let extension_point = plan.extension_point(position);
        let mut accumulated = 0_u64;
        for column_index in 0..total_columns {
            let column_value = row[column_index];
            for (point_index, point) in deep_points.iter().enumerate() {
                let difference = sub_mod_fast(extension_point, *point, modulus);
                let quotient = mul_mod_fast(
                    sub_mod_fast(
                        column_value,
                        limb_proof.deep_evaluations[point_index][column_index],
                        modulus,
                    ),
                    inverse_mod(difference, modulus)?,
                    modulus,
                );
                accumulated = add_mod_fast(
                    accumulated,
                    mul_mod_fast(
                        lambda[column_index * DEEP_POINT_COUNT + point_index],
                        quotient,
                        modulus,
                    ),
                    modulus,
                );
            }
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
                || opening.phase_two_rows[0].len() != PHASE_TWO_COLUMN_COUNT
                || opening.phase_two_rows[1].len() != PHASE_TWO_COLUMN_COUNT
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
            let combine_row = |slot: usize| -> Vec<u64> {
                let mut row = Vec::with_capacity(total_columns);
                row.extend_from_slice(&opening.phase_one_rows[slot]);
                row.extend_from_slice(&opening.phase_two_rows[slot]);
                row
            };
            Ok([
                reconstruct_batch_value(&combine_row(0), pair_index)?,
                reconstruct_batch_value(&combine_row(1), pair_index + half)?,
            ])
        },
    )
}

// Cross-limb integer consistency on the masked claims: the same small witness
// plus the same shared smudging mask yield the same integer in every limb
// field, so centered representatives must agree and respect the range bound.
fn verify_cross_limb_consistency(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &SuccinctEvaluationKeyProof,
) -> CanonicalResult<()> {
    let limb_moduli = statement.limb_moduli();
    let (lower_bound, upper_bound) = masked_claim_bounds(statement.ring_degree);
    let mut reference_by_global_id: std::collections::BTreeMap<u64, i128> =
        std::collections::BTreeMap::new();
    for (limb_index, modulus) in limb_moduli.iter().enumerate() {
        let layout = LimbColumnLayout::new(statement, limb_index)?;
        for (local_claim, claim) in proof.limb_proofs[limb_index]
            .masked_consistency_claims
            .iter()
            .enumerate()
        {
            let centered = centered_residue_i128(*claim, *modulus);
            if centered < lower_bound || centered > upper_bound {
                return Err(invalid_succinct_setup_proof(
                    "masked consistency claim exceeds the accepted range",
                ));
            }
            let global_id = global_claim_id(statement, &layout, local_claim);
            match reference_by_global_id.get(&global_id) {
                None => {
                    reference_by_global_id.insert(global_id, centered);
                }
                Some(expected) if *expected != centered => {
                    return Err(invalid_succinct_setup_proof(
                        "masked consistency claim disagrees across limb fields",
                    ));
                }
                Some(_) => {}
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
