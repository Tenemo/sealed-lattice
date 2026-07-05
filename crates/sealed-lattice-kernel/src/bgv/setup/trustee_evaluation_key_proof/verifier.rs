use super::accounting;
use super::evaluation_domain::EvaluationDomainPlan;
use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{
    LowDegreeParameters, bind_low_degree_commitment, verify_low_degree_openings,
};
use super::merkle_commitment::{
    LEAF_SALT_BYTES, MerkleDigest, consistent_sorted_leaves, phase_pair_leaf_hash,
    verify_merkle_batch,
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
    batched_sumcheck_value, masked_claim_bounds_for_global_claim,
    masked_claim_lift_residue_count_for_moduli,
};
use super::*;
use crate::bgv::modular_arithmetic::inverse_mod;
use crate::bgv::parameters::DATA_PRIMES;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

#[cfg(test)]
fn trustee_evaluation_key_verify_progress(message: impl FnOnce() -> String) {
    if std::env::var("SEALED_LATTICE_TRUSTEE_PROOF_VERIFY_PROGRESS").as_deref() == Ok("1") {
        println!("sealed-lattice-trustee-proof-verify-progress {}", message());
    }
}

#[cfg(not(test))]
fn trustee_evaluation_key_verify_progress(_message: impl FnOnce() -> String) {}

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

    let mut witness_leaves: Vec<(usize, MerkleDigest)> = Vec::new();
    let mut quotient_leaves: Vec<(usize, MerkleDigest)> = Vec::new();
    transcript.absorb("low-degree-purpose", MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE);
    let low_degree_verification_state = bind_low_degree_commitment(
        &mut transcript,
        &low_degree_parameters,
        &limb_proof.low_degree,
    )?;
    let sumcheck_residual_low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: trace_size,
    };
    transcript.absorb(
        "low-degree-purpose",
        SUMCHECK_RESIDUAL_LOW_DEGREE_TRANSCRIPT_PURPOSE,
    );
    let sumcheck_residual_low_degree_verification_state = bind_low_degree_commitment(
        &mut transcript,
        &sumcheck_residual_low_degree_parameters,
        &limb_proof.sumcheck_residual_low_degree,
    )?;
    let query_positions = transcript.challenge_positions(
        "shared-query-position",
        extension_size / 2,
        LOW_DEGREE_QUERY_COUNT,
    );
    verify_low_degree_openings(
        &low_degree_verification_state,
        &limb_proof.low_degree,
        &query_positions,
        |query_ordinal, pair_index| {
            let opening = &query_openings[query_ordinal];
            if opening.phase_one_rows[0].len() != phase_one_columns
                || opening.phase_one_rows[1].len() != phase_one_columns
                || opening.phase_two_rows[0].len() != phase_two_physical_columns
                || opening.phase_two_rows[1].len() != phase_two_physical_columns
                || opening.phase_one_pair_salt.len() != LEAF_SALT_BYTES
                || opening.phase_two_pair_salt.len() != LEAF_SALT_BYTES
            {
                return Err(invalid_succinct_setup_proof(
                    "query opening shape does not match the column layout",
                ));
            }
            // Record one ordered pair leaf for each queried phase pair; the
            // trees are authenticated in one batched opening each after the
            // fold checks.
            witness_leaves.push((
                pair_index,
                phase_pair_leaf_hash(
                    pair_index,
                    &opening.phase_one_pair_salt,
                    &opening.phase_one_rows[0],
                    &opening.phase_one_rows[1],
                ),
            ));
            quotient_leaves.push((
                pair_index,
                phase_pair_leaf_hash(
                    pair_index,
                    &opening.phase_two_pair_salt,
                    &opening.phase_two_rows[0],
                    &opening.phase_two_rows[1],
                ),
            ));
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
    verify_low_degree_openings(
        &sumcheck_residual_low_degree_verification_state,
        &limb_proof.sumcheck_residual_low_degree,
        &query_positions,
        |query_ordinal, _pair_index| {
            let opening = &query_openings[query_ordinal];
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

    // Authenticate both phase-pair trees against their roots with one batched
    // opening each. A pair index opened to two different row pairs across
    // queries is rejected here, so binding is exactly as strong as an
    // independent path per pair leaf.
    let phase_tree_depth = half.trailing_zeros() as usize;
    // Batched verification is only as strong as per-pair paths because
    // consistent_sorted_leaves first rejects a pair index opened to two
    // different leaves; without that dedup a prover could fold one value while
    // the tree binds another.
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

    Ok(())
}

// Cross-limb integer consistency on the masked claims: every limb publishes
// the residue of the same global claim integer (clear combination plus the
// shared smudging mask). The integer is recovered by a centered lift from the
// statement-selected fields carrying the claim; the product of those fields
// must exceed twice the claim bound, so the lift is unique. Every other limb's
// residue must match that integer, which forces integer witness equality
// through the bounded random combinations.
fn verify_cross_limb_consistency(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &SuccinctEvaluationKeyProof,
) -> CanonicalResult<()> {
    let proof_limb_indices = statement.proof_limb_indices();
    let mut residues_by_global_id: std::collections::BTreeMap<u64, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for (proof_position, limb_index) in proof_limb_indices.iter().enumerate() {
        let modulus = DATA_PRIMES[*limb_index];
        let layout = LimbColumnLayout::new(statement, *limb_index)?;
        for (local_claim, claim) in proof.limb_proofs[proof_position]
            .masked_consistency_claims
            .iter()
            .enumerate()
        {
            if *claim >= modulus {
                return Err(invalid_succinct_setup_proof(
                    "masked consistency claim is not a reduced limb residue",
                ));
            }
            let global_id = global_claim_id(statement, &layout, local_claim);
            residues_by_global_id
                .entry(global_id)
                .or_default()
                .push((modulus, *claim));
        }
    }
    for (global_claim_id, residues) in &residues_by_global_id {
        // The lift window is recomputed per claim: the product of the first
        // lift_count limb moduli must exceed twice the claim's accepted range,
        // so wider compact digit claims take a three-field lift while narrow
        // base claims keep the two-field lift. The range guard below enforces
        // uniqueness rather than assuming it.
        let (lower_bound, upper_bound) =
            masked_claim_bounds_for_global_claim(statement, *global_claim_id)?;
        let lift_count = masked_claim_lift_residue_count_for_moduli(
            residues.iter().map(|(modulus, _)| *modulus),
            &lower_bound,
            &upper_bound,
        );
        if lift_count > residues.len() {
            return Err(invalid_succinct_setup_proof(
                "masked consistency claim needs enough limb fields for integer binding",
            ));
        }
        let claim_integer = centered_crt_lift(&residues[..lift_count])?;
        if claim_integer < lower_bound || claim_integer > upper_bound {
            return Err(invalid_succinct_setup_proof(
                "masked consistency claim exceeds the accepted range",
            ));
        }
        for (modulus, residue) in &residues[lift_count..] {
            if bigint_residue(&claim_integer, *modulus)? != *residue {
                return Err(invalid_succinct_setup_proof(
                    "masked consistency claim disagrees across limb fields",
                ));
            }
        }
    }

    Ok(())
}

fn centered_crt_lift(residues: &[(u64, u64)]) -> CanonicalResult<BigInt> {
    let Some((first_modulus, first_residue)) = residues.first().copied() else {
        return Err(invalid_succinct_setup_proof(
            "masked consistency claim needs at least one limb field",
        ));
    };
    let mut value = BigInt::from(first_residue);
    let mut product = BigInt::from(first_modulus);
    for (modulus, residue) in &residues[1..] {
        let current_residue = bigint_residue(&value, *modulus)?;
        let delta = (residue + modulus - current_residue) % modulus;
        let product_residue = bigint_residue(&product, *modulus)?;
        let step = mul_mod_fast(delta, inverse_mod(product_residue, *modulus)?, *modulus);
        value += &product * BigInt::from(step);
        product *= BigInt::from(*modulus);
    }

    if value > &product / BigInt::from(2_u8) {
        value -= product;
    }

    Ok(value)
}

fn bigint_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_integer = BigInt::from(modulus);
    let residue = ((value % &modulus_integer) + &modulus_integer) % &modulus_integer;
    residue
        .to_u64()
        .ok_or_else(|| invalid_succinct_setup_proof("masked consistency residue does not fit u64"))
}

pub(crate) fn verify_evaluation_key_share(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &SuccinctEvaluationKeyProof,
) -> CanonicalResult<()> {
    statement.validate_shape()?;
    let proof_trace_ring_degree = statement
        .vss_share_linkage
        .as_ref()
        .map(|share_linkage| share_linkage.packed_ring_degree(statement.ring_degree))
        .transpose()?
        .unwrap_or(statement.ring_degree);
    accounting::enforce_current_succinct_proof_soundness_policy(
        proof_trace_ring_degree / TRACE_SPLIT,
    )?;
    let proof_limb_indices = statement.proof_limb_indices();
    if proof.limb_proofs.len() != proof_limb_indices.len() {
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
    let family_shape = statement.family_shape()?;
    let consistency_vectors = (0..family_shape.consistency_repetitions())
        .map(|_| {
            transcript.challenge_bounded_integers(
                "consistency-vector",
                family_shape.consistency_coefficient_bits(),
                proof_trace_ring_degree,
            )
        })
        .collect::<Vec<_>>();

    verify_cross_limb_consistency(statement, proof)?;
    #[cfg(not(target_arch = "wasm32"))]
    let limb_verifications: Vec<CanonicalResult<()>> = proof_limb_indices
        .par_iter()
        .enumerate()
        .map(|(proof_position, limb_index)| {
            trustee_evaluation_key_verify_progress(|| {
                format!(
                    "trustee={} limb-start limb={limb_index}",
                    statement.context.trustee_roster_position
                )
            });
            let result = verify_limb(
                statement,
                *limb_index,
                DATA_PRIMES[*limb_index],
                &proof.limb_proofs[proof_position],
                &consistency_vectors,
                &transcript,
            );
            trustee_evaluation_key_verify_progress(|| {
                format!(
                    "trustee={} limb-finish limb={limb_index}",
                    statement.context.trustee_roster_position
                )
            });
            result
        })
        .collect();
    #[cfg(target_arch = "wasm32")]
    let limb_verifications: Vec<CanonicalResult<()>> = proof_limb_indices
        .iter()
        .enumerate()
        .map(|(proof_position, limb_index)| {
            trustee_evaluation_key_verify_progress(|| {
                format!(
                    "trustee={} limb-start limb={limb_index}",
                    statement.context.trustee_roster_position
                )
            });
            let result = verify_limb(
                statement,
                *limb_index,
                DATA_PRIMES[*limb_index],
                &proof.limb_proofs[proof_position],
                &consistency_vectors,
                &transcript,
            );
            trustee_evaluation_key_verify_progress(|| {
                format!(
                    "trustee={} limb-finish limb={limb_index}",
                    statement.context.trustee_roster_position
                )
            });
            result
        })
        .collect();
    limb_verifications
        .into_iter()
        .collect::<CanonicalResult<Vec<()>>>()?;

    Ok(())
}
