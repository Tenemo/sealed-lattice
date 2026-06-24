use super::accounting;
use super::evaluation_domain::EvaluationDomainPlan;
use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{LowDegreeParameters, verify_low_degree};
use super::merkle_commitment::{
    LEAF_SALT_BYTES, consistent_sorted_leaves, leaf_hash, verify_merkle_batch,
};
use super::prover::{
    LimbProof, SuccinctEvaluationKeyProof, barycentric_weights, build_limb_public_vectors,
    draw_limb_challenges, global_claim_id, sample_deep_identity_points,
    trace_vanishing_at_extension,
};
use super::relation::{
    ExtensionColumnDomain, LimbColumnLayout, PHASE_TWO_COLUMN_COUNT,
    QUOTIENT_COLUMN_ROW_CHECK_HIGH, QUOTIENT_COLUMN_ROW_CHECK_LOW,
    QUOTIENT_COLUMN_SUMCHECK_RESIDUAL, QUOTIENT_COLUMN_SUMCHECK_VANISHING,
    SumcheckPublicEvaluations, TrusteeEvaluationKeyStatement, batched_row_check_value,
    batched_sumcheck_value, masked_claim_bounds,
};
use super::*;
use crate::bgv::modular_arithmetic::inverse_mod;

// Each logical length-N vector is committed as TRACE_SPLIT half-columns over a
// half-size trace domain (2-adicity headroom), so it is interpolated as two
// independent halves sharing the barycentric weights.
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
        || limb_proof.deep_evaluations.len() != DEEP_EVALUATION_POINT_COUNT
        || limb_proof
            .deep_evaluations
            .iter()
            .any(|evaluations| evaluations.len() != total_columns)
        || limb_proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
        || limb_proof.sumcheck_residual_query_openings.len() != LOW_DEGREE_QUERY_COUNT
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
    // Univariate sumcheck: a codeword sums to the lincheck claim over the
    // size-H trace subgroup iff its constant coefficient equals claim / H, hence
    // the inverse-trace-size scaling.
    let expected_constant = tower.scale_base(
        &publics.lincheck_claim,
        inverse_mod(trace_size as u64, modulus)?,
    );

    transcript.absorb("quotient-tree-root", &limb_proof.quotient_tree_root);
    transcript.absorb_u64_slice(
        "masked-consistency-claims",
        &limb_proof.masked_consistency_claims,
    );
    let deep_points = sample_deep_identity_points(&mut transcript, &plan)?;

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
        // The cubic row-check quotient exceeds the committed degree bound, so it
        // is committed as two columns (low, high) and recombined with the
        // point^bound shift to stay under COMMITMENT_BOUND_FACTOR * trace.
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
        let sumcheck_residual = &evaluations[phase_one_columns + QUOTIENT_COLUMN_SUMCHECK_RESIDUAL];
        if ChallengeExtensionTower::is_zero(point)
            && !ChallengeExtensionTower::is_zero(sumcheck_residual)
        {
            return Err(invalid_succinct_setup_proof(
                "sumcheck residual failed the zero anchor",
            ));
        }
        let left = tower.sub(&sumcheck_value, &tower.mul(&vanishing, vanishing_quotient));
        let right = tower.add(&expected_constant, sumcheck_residual);
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
        total_columns * DEEP_EVALUATION_POINT_COUNT,
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
                        &lambda[column_index * DEEP_EVALUATION_POINT_COUNT + point_index],
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
                        &lambda[column_index * DEEP_EVALUATION_POINT_COUNT + point_index],
                        &logical_value,
                    ),
                );
            }
            for column_index in 0..total_columns {
                point_sum = tower.sub(
                    &point_sum,
                    &tower.mul(
                        &lambda[column_index * DEEP_EVALUATION_POINT_COUNT + point_index],
                        &limb_proof.deep_evaluations[point_index][column_index],
                    ),
                );
            }
            accumulated = tower.add(&accumulated, &tower.mul(&point_sum, &inverted_difference));
        }

        Ok(accumulated)
    };

    let mut witness_leaves: Vec<(usize, [u8; 64])> = Vec::new();
    let mut quotient_leaves: Vec<(usize, [u8; 64])> = Vec::new();
    transcript.absorb("low-degree-purpose", MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE);
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
            // Record both phase leaves at each queried position; the trees are
            // authenticated in one batched opening each after the fold checks.
            for (slot, position) in [pair_index, pair_index + half].into_iter().enumerate() {
                witness_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.phase_one_salts[slot],
                        &opening.phase_one_rows[slot],
                    ),
                ));
                quotient_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.phase_two_salts[slot],
                        &opening.phase_two_rows[slot],
                    ),
                ));
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
    )?;
    let sumcheck_residual_low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: trace_size,
    };
    let mut sumcheck_residual_leaves: Vec<(usize, [u8; 64])> = Vec::new();
    transcript.absorb(
        "low-degree-purpose",
        SUMCHECK_RESIDUAL_LOW_DEGREE_TRANSCRIPT_PURPOSE,
    );
    verify_low_degree(
        &mut transcript,
        &sumcheck_residual_low_degree_parameters,
        &limb_proof.sumcheck_residual_low_degree,
        |query_ordinal, pair_index| {
            let opening = &limb_proof.sumcheck_residual_query_openings[query_ordinal];
            if opening.phase_two_rows[0].len() != phase_two_physical_columns
                || opening.phase_two_rows[1].len() != phase_two_physical_columns
                || opening
                    .phase_two_salts
                    .iter()
                    .any(|salt| salt.len() != LEAF_SALT_BYTES)
            {
                return Err(invalid_succinct_setup_proof(
                    "sumcheck residual query opening shape does not match the column layout",
                ));
            }
            for (slot, position) in [pair_index, pair_index + half].into_iter().enumerate() {
                sumcheck_residual_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.phase_two_salts[slot],
                        &opening.phase_two_rows[slot],
                    ),
                ));
            }
            let mut first = ChallengeExtensionTower::zero();
            let mut second = ChallengeExtensionTower::zero();
            for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
                let column_index =
                    QUOTIENT_COLUMN_SUMCHECK_RESIDUAL * CHALLENGE_EXTENSION_DEGREE + coordinate;
                first[coordinate] = opening.phase_two_rows[0][column_index];
                second[coordinate] = opening.phase_two_rows[1][column_index];
            }

            Ok([first, second])
        },
    )?;

    // Authenticate both phase trees against their roots with one batched opening
    // each. A position opened to two different rows across queries is rejected
    // here, so binding is exactly as strong as an independent path per slot.
    let phase_tree_depth = extension_size.trailing_zeros() as usize;
    // Batched verification is only as strong as per-slot paths because
    // consistent_sorted_leaves first rejects a position opened to two different
    // leaves; without that dedup a prover could fold one value while the tree
    // binds another.
    let Some(witness_sorted_leaves) = consistent_sorted_leaves(witness_leaves) else {
        return Err(invalid_succinct_setup_proof(
            "witness tree opens one position to two values",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.witness_tree_root,
        phase_tree_depth,
        &witness_sorted_leaves,
        &limb_proof.witness_batch_opening,
    ) {
        return Err(invalid_succinct_setup_proof(
            "witness tree query openings failed batched Merkle verification",
        ));
    }
    let Some(quotient_sorted_leaves) = consistent_sorted_leaves(quotient_leaves) else {
        return Err(invalid_succinct_setup_proof(
            "quotient tree opens one position to two values",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.quotient_tree_root,
        phase_tree_depth,
        &quotient_sorted_leaves,
        &limb_proof.quotient_batch_opening,
    ) {
        return Err(invalid_succinct_setup_proof(
            "quotient tree query openings failed batched Merkle verification",
        ));
    }
    let Some(sumcheck_residual_sorted_leaves) = consistent_sorted_leaves(sumcheck_residual_leaves)
    else {
        return Err(invalid_succinct_setup_proof(
            "sumcheck residual tree opens one position to two values",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.quotient_tree_root,
        phase_tree_depth,
        &sumcheck_residual_sorted_leaves,
        &limb_proof.sumcheck_residual_batch_opening,
    ) {
        return Err(invalid_succinct_setup_proof(
            "sumcheck residual query openings failed batched Merkle verification",
        ));
    }

    Ok(())
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
        // The first two residues are the two smallest profile limbs by
        // construction, so their product exceeds twice the claim bound and the
        // centered lift is the unique integer; the range guard below enforces
        // this rather than assuming it.
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
        // Garner's step (second_residue - first_residue) * inverse(first_modulus)
        // mod second_modulus, kept non-negative by adding second_modulus before
        // the subtraction.
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
    accounting::enforce_current_succinct_proof_soundness_policy(
        statement.ring_degree / TRACE_SPLIT,
    )?;
    let limb_moduli = statement.limb_moduli();
    if proof.limb_proofs.len() != limb_moduli.len() {
        return Err(invalid_succinct_setup_proof(
            "proof limb count does not match the statement",
        ));
    }
    let mut transcript = FiatShamirTranscript::new("trustee-evaluation-key-share");
    transcript.absorb("statement", &statement.statement_hash());
    // All witness roots are absorbed before the consistency challenges so each
    // limb's quotient root (which depends on those challenges) is committed
    // afterward, preventing the prover from adapting the quotient to the
    // challenge.
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
