use super::super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionTower};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::low_degree_proof::{LowDegreeParameters, prove_low_degree};
use super::super::merkle_commitment::sorted_unique_indices;
use super::super::relation::{
    BaseColumnDomain, PHASE_TWO_COLUMN_COUNT, SumcheckPublicEvaluations,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, batched_row_check_value,
    batched_sumcheck_value,
};
use super::super::*;
use super::challenges::{build_limb_public_vectors, draw_limb_challenges};
use super::claim_masking::{global_claim_id, global_claim_integers};
use super::polynomial::{
    divide_by_trace_vanishing, extend_logical_vector, extend_logical_vector_extension,
    extension_powers, sample_deep_points, trim_trailing_zeros,
};
use super::salted_tree::commit_salted_extension_rows;
use super::witness::{
    LimbWitnessCommitment, build_limb_witness_commitment, validate_witness_support,
};
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::inverse_mod;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

fn prove_limb(
    statement: &TrusteeEvaluationKeyStatement,
    limb_index: usize,
    commitment: &LimbWitnessCommitment,
    consistency_vectors: &[Vec<u64>],
    global_claim_integers: &[i128],
    proof_randomness_seed_hex: &str,
    global_transcript: &FiatShamirTranscript,
) -> CanonicalResult<LimbProof> {
    let plan = &commitment.plan;
    let layout = &commitment.layout;
    let modulus = plan.modulus;
    let trace_size = plan.trace_size;
    let extension_size = plan.extension_size;
    let mut transcript = global_transcript.fork("limb", limb_index as u64);
    let challenges = draw_limb_challenges(&mut transcript, layout, modulus);

    // Masked consistency claims: the limb residues of the shared global
    // integer claims (clear integer sum plus the shared smudging mask), so
    // every limb publishes the same integer reduced into its field.
    let mut masked_claims = Vec::with_capacity(layout.claim_count());
    for local_claim in 0..layout.claim_count() {
        let global_id = global_claim_id(statement, layout, local_claim);
        let claim_integer = global_claim_integers[global_id as usize];
        masked_claims.push(claim_integer.rem_euclid(modulus as i128) as u64);
    }

    let publics = build_limb_public_vectors(
        statement,
        layout,
        limb_index,
        modulus,
        &challenges,
        &masked_claims,
    )?;

    // Extension evaluations of every public sumcheck vector.
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let secret_factor_extensions = publics
        .secret_factor
        .iter()
        .map(|vector| extend_logical_vector_extension(plan, vector))
        .collect::<Vec<_>>();
    let u_extensions = publics
        .u_powers
        .iter()
        .map(|vector| extend_logical_vector_extension(plan, vector))
        .collect::<Vec<_>>();
    let consistency_extensions = consistency_vectors
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();
    let mask_selector_extensions = publics
        .mask_selectors
        .iter()
        .map(|vector| extend_logical_vector_extension(plan, vector))
        .collect::<Vec<_>>();
    let linkage_extensions = publics
        .linkage_vectors
        .iter()
        .map(|vector| extend_logical_vector_extension(plan, vector))
        .collect::<Vec<_>>();

    // Batched row-check and sumcheck integrand evaluations over the coset.
    let base_domain = BaseColumnDomain { tower };
    let mut row_check_extension = Vec::with_capacity(extension_size);
    let mut sumcheck_extension = Vec::with_capacity(extension_size);
    let mut row = vec![0_u64; commitment.extension_columns.len()];
    for position in 0..extension_size {
        for (column_index, column) in commitment.extension_columns.iter().enumerate() {
            row[column_index] = column[position];
        }
        row_check_extension.push(batched_row_check_value(
            &base_domain,
            &row,
            &challenges.beta,
            layout,
        ));
        let point_publics = SumcheckPublicEvaluations {
            secret_factor: secret_factor_extensions
                .iter()
                .map(|halves| [halves[0][position], halves[1][position]])
                .collect(),
            u_power: u_extensions
                .iter()
                .map(|halves| [halves[0][position], halves[1][position]])
                .collect(),
            consistency: consistency_extensions
                .iter()
                .map(|halves| [halves[0][position], halves[1][position]])
                .collect(),
            mask_selector: mask_selector_extensions
                .iter()
                .map(|halves| [halves[0][position], halves[1][position]])
                .collect(),
            linkage: linkage_extensions
                .iter()
                .map(|halves| [halves[0][position], halves[1][position]])
                .collect(),
        };
        sumcheck_extension.push(batched_sumcheck_value(
            &base_domain,
            &row,
            &point_publics,
            &publics.error_weights,
            &challenges.consistency_alpha,
            layout,
        ));
    }

    // Quotient decompositions in coefficient form, one base decomposition per
    // challenge extension coordinate.
    let commitment_bound = COMMITMENT_BOUND_FACTOR * trace_size;
    let inverse_trace_size = inverse_mod(trace_size as u64, modulus)?;
    let mut row_quotient_low = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
    let mut row_quotient_high = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
    let mut sumcheck_quotient = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
    let mut sumcheck_linear = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
    let mut coordinate_evaluations = vec![0_u64; extension_size];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, value) in coordinate_evaluations
            .iter_mut()
            .zip(row_check_extension.iter())
        {
            *slot = value[coordinate];
        }
        let coordinate_coefficients =
            plan.coefficients_from_extension_evaluations(&coordinate_evaluations)?;
        let (quotient, remainder) =
            divide_by_trace_vanishing(&coordinate_coefficients, trace_size, modulus);
        let quotient = trim_trailing_zeros(quotient);
        if remainder.iter().any(|value| *value != 0) {
            return Err(invalid_succinct_setup_proof(
                "witness does not satisfy the batched row checks",
            ));
        }
        // The cubic row-check composition has degree up to about 3*bound, so
        // its quotient is committed as two sub-bound columns; low is
        // length-capped by truncate, only high can overflow the bound.
        let mut low = quotient.clone();
        low.truncate(commitment_bound);
        let high = if quotient.len() > commitment_bound {
            quotient[commitment_bound..].to_vec()
        } else {
            Vec::new()
        };
        if high.len() > commitment_bound {
            return Err(invalid_succinct_setup_proof(
                "row check quotient exceeds the commitment bound",
            ));
        }
        row_quotient_low[coordinate] = low;
        row_quotient_high[coordinate] = high;

        for (slot, value) in coordinate_evaluations
            .iter_mut()
            .zip(sumcheck_extension.iter())
        {
            *slot = value[coordinate];
        }
        let coordinate_coefficients =
            plan.coefficients_from_extension_evaluations(&coordinate_evaluations)?;
        let (quotient, remainder) =
            divide_by_trace_vanishing(&coordinate_coefficients, trace_size, modulus);
        let quotient = trim_trailing_zeros(quotient);
        if quotient.len() > commitment_bound {
            return Err(invalid_succinct_setup_proof(
                "sumcheck quotient exceeds the commitment bound",
            ));
        }
        // Sum of an interpolant over the subgroup H of order T equals T times
        // its constant coefficient, so only remainder[0] carries the sumcheck
        // claim; remainder[1..] is the residual low-degree term bound separately
        // by the DEEP/FRI layer.
        let expected_constant = mul_mod_fast(
            publics.lincheck_claim[coordinate],
            inverse_trace_size,
            modulus,
        );
        if remainder[0] != expected_constant {
            return Err(invalid_succinct_setup_proof(
                "witness does not satisfy the batched sumcheck claims",
            ));
        }
        sumcheck_quotient[coordinate] = quotient;
        sumcheck_linear[coordinate] = remainder[1..].to_vec();
    }
    drop(row_check_extension);
    drop(sumcheck_extension);

    // Phase-two commitment: four logical extension-valued quotient columns,
    // committed as four base coordinate columns each.
    let logical_phase_two_coefficients = [
        &row_quotient_low,
        &row_quotient_high,
        &sumcheck_quotient,
        &sumcheck_linear,
    ];
    let mut phase_two_columns =
        vec![Vec::new(); PHASE_TWO_COLUMN_COUNT * CHALLENGE_EXTENSION_DEGREE];
    for (logical_index, coordinate_sets) in logical_phase_two_coefficients.iter().enumerate() {
        for (coordinate, coefficients) in coordinate_sets.iter().enumerate() {
            phase_two_columns[logical_index * CHALLENGE_EXTENSION_DEGREE + coordinate] =
                plan.extension_evaluations_from_coefficients(coefficients);
        }
    }
    let mut phase_two_salt_sampler = DeterministicSampler::new(
        LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"phase-two",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let phase_two_salted = commit_salted_extension_rows(
        &phase_two_columns,
        extension_size,
        &mut phase_two_salt_sampler,
    )?;
    transcript.absorb("quotient-tree-root", &phase_two_salted.tree.root());
    transcript.absorb_u64_slice("masked-consistency-claims", &masked_claims);

    // Out-of-domain evaluations of every committed column at the extension
    // points, via one shared powers table per point.
    let deep_points = sample_deep_points(&mut transcript, plan)?;
    let mut deep_evaluations = Vec::with_capacity(DEEP_POINT_COUNT);
    for point in &deep_points {
        let coefficient_length = commitment
            .masked_coefficients
            .iter()
            .map(Vec::len)
            .chain(
                logical_phase_two_coefficients
                    .iter()
                    .flat_map(|sets| sets.iter().map(Vec::len)),
            )
            .max()
            .unwrap_or(0);
        let point_powers = extension_powers(&tower, point, coefficient_length);
        let evaluate_base = |coefficients: &[u64]| {
            let mut accumulated = ChallengeExtensionTower::zero();
            for (coefficient, power) in coefficients.iter().zip(point_powers.iter()) {
                accumulated = tower.add(&accumulated, &tower.scale_base(power, *coefficient));
            }
            accumulated
        };
        let mut evaluations =
            Vec::with_capacity(commitment.masked_coefficients.len() + PHASE_TWO_COLUMN_COUNT);
        for coefficients in &commitment.masked_coefficients {
            evaluations.push(evaluate_base(coefficients));
        }
        // Evaluation is F_p-linear, so an extension column equals the sum of its
        // base-coordinate columns times the basis {1, s, t, st}; evaluating each
        // coordinate over F_p then recombining through the basis is exact, not
        // an approximation.
        for coordinate_sets in &logical_phase_two_coefficients {
            // Recombine the per-coordinate base evaluations through the basis.
            let mut combined = ChallengeExtensionTower::zero();
            for (coordinate, coefficients) in coordinate_sets.iter().enumerate() {
                let coordinate_evaluation = evaluate_base(coefficients);
                let mut basis_element = ChallengeExtensionTower::zero();
                basis_element[coordinate] = 1;
                combined = tower.add(
                    &combined,
                    &tower.mul(&basis_element, &coordinate_evaluation),
                );
            }
            evaluations.push(combined);
        }
        deep_evaluations.push(evaluations);
    }
    for evaluations in &deep_evaluations {
        let flattened = evaluations.iter().flatten().copied().collect::<Vec<u64>>();
        transcript.absorb_u64_slice("deep-evaluations", &flattened);
    }

    // Lambda-batched DEEP quotient codeword over the extension coset. The
    // committed phase-one values stay in the base field; the quotients and
    // the batching weights live in the challenge extension.
    let total_column_count = commitment.extension_columns.len() + PHASE_TWO_COLUMN_COUNT;
    let lambda = transcript.challenge_extension_elements(
        "lambda",
        modulus,
        total_column_count * DEEP_POINT_COUNT,
    );
    let mut extension_points = Vec::with_capacity(extension_size);
    let mut point = plan.coset_offset;
    for _ in 0..extension_size {
        extension_points.push(point);
        point = mul_mod_fast(point, plan.extension_root, modulus);
    }
    let mut inverted_differences_by_point = Vec::with_capacity(DEEP_POINT_COUNT);
    for deep_point in &deep_points {
        let differences = extension_points
            .iter()
            .map(|extension_point| tower.sub(&tower.embed_base(*extension_point), deep_point))
            .collect::<Vec<_>>();
        inverted_differences_by_point.push(tower.batch_inverse(&differences)?);
    }
    // Per point: the lambda-weighted sum of claimed evaluations, hoisted out
    // of the position loop so the loop runs on base column values.
    let mut lambda_evaluation_sums = [ChallengeExtensionTower::zero(); DEEP_POINT_COUNT];
    let mut lambda_by_point =
        vec![vec![ChallengeExtensionTower::zero(); total_column_count]; DEEP_POINT_COUNT];
    for column_index in 0..total_column_count {
        for (point_index, evaluations) in deep_evaluations.iter().enumerate() {
            let lambda_value = &lambda[column_index * DEEP_POINT_COUNT + point_index];
            lambda_evaluation_sums[point_index] = tower.add(
                &lambda_evaluation_sums[point_index],
                &tower.mul(lambda_value, &evaluations[column_index]),
            );
            lambda_by_point[point_index][column_index] = *lambda_value;
        }
    }
    let phase_two_logical_value = |position: usize, logical_index: usize| {
        let mut value = ChallengeExtensionTower::zero();
        for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
            value[coordinate] = phase_two_columns
                [logical_index * CHALLENGE_EXTENSION_DEGREE + coordinate][position];
        }
        value
    };
    let mut batch_codeword = vec![ChallengeExtensionTower::zero(); extension_size];
    for (position, batch_value) in batch_codeword.iter_mut().enumerate() {
        let mut accumulated = ChallengeExtensionTower::zero();
        for (point_index, lambda_row) in lambda_by_point.iter().enumerate() {
            let mut point_sum = ChallengeExtensionTower::zero();
            for (column_index, column) in commitment.extension_columns.iter().enumerate() {
                point_sum = tower.add(
                    &point_sum,
                    &tower.scale_base(&lambda_row[column_index], column[position]),
                );
            }
            for logical_index in 0..PHASE_TWO_COLUMN_COUNT {
                let column_index = commitment.extension_columns.len() + logical_index;
                point_sum = tower.add(
                    &point_sum,
                    &tower.mul(
                        &lambda_row[column_index],
                        &phase_two_logical_value(position, logical_index),
                    ),
                );
            }
            point_sum = tower.sub(&point_sum, &lambda_evaluation_sums[point_index]);
            accumulated = tower.add(
                &accumulated,
                &tower.mul(
                    &point_sum,
                    &inverted_differences_by_point[point_index][position],
                ),
            );
        }
        *batch_value = accumulated;
    }

    let low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: commitment_bound,
    };
    let (low_degree, query_positions) =
        prove_low_degree(&mut transcript, &low_degree_parameters, &batch_codeword)?;

    let collect_row = |columns: &[Vec<u64>], position: usize| -> Vec<u64> {
        columns.iter().map(|column| column[position]).collect()
    };
    let half = extension_size / 2;
    let query_openings = query_positions
        .iter()
        .map(|position| PhaseQueryOpening {
            phase_one_rows: [
                collect_row(&commitment.extension_columns, *position),
                collect_row(&commitment.extension_columns, *position + half),
            ],
            phase_one_salts: [
                commitment.salted.salt(*position).to_vec(),
                commitment.salted.salt(*position + half).to_vec(),
            ],
            phase_two_rows: [
                collect_row(&phase_two_columns, *position),
                collect_row(&phase_two_columns, *position + half),
            ],
            phase_two_salts: [
                phase_two_salted.salt(*position).to_vec(),
                phase_two_salted.salt(*position + half).to_vec(),
            ],
        })
        .collect::<Vec<_>>();
    // Both phase trees are opened at the same queried positions and their coset
    // partners, so one batched opening per tree authenticates every query slot.
    let phase_opened_indices = sorted_unique_indices(
        query_positions
            .iter()
            .flat_map(|position| [*position, *position + half]),
    );
    let witness_batch_opening = commitment.salted.tree.open_batch(&phase_opened_indices);
    let quotient_batch_opening = phase_two_salted.tree.open_batch(&phase_opened_indices);

    Ok(LimbProof {
        witness_tree_root: commitment.salted.tree.root(),
        quotient_tree_root: phase_two_salted.tree.root(),
        masked_consistency_claims: masked_claims,
        deep_evaluations,
        low_degree,
        query_openings,
        witness_batch_opening,
        quotient_batch_opening,
    })
}

pub(crate) fn prove_evaluation_key_share(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
    statement.validate_shape()?;
    validate_witness_support(statement, witness)?;
    let limb_moduli = statement.limb_moduli();
    let mut transcript = FiatShamirTranscript::new("trustee-evaluation-key-share");
    transcript.absorb("statement", &statement.statement_hash());

    #[cfg(not(target_arch = "wasm32"))]
    let commitments = limb_moduli
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            build_limb_witness_commitment(
                statement,
                witness,
                limb_index,
                *modulus,
                proof_randomness_seed_hex,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let commitments = limb_moduli
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            build_limb_witness_commitment(
                statement,
                witness,
                limb_index,
                *modulus,
                proof_randomness_seed_hex,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    for commitment in &commitments {
        transcript.absorb("witness-tree-root", &commitment.salted.tree.root());
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
    let claim_integers = global_claim_integers(
        statement,
        witness,
        &consistency_vectors,
        proof_randomness_seed_hex,
    );

    #[cfg(not(target_arch = "wasm32"))]
    let limb_proofs = commitments
        .par_iter()
        .enumerate()
        .map(|(limb_index, commitment)| {
            prove_limb(
                statement,
                limb_index,
                commitment,
                &consistency_vectors,
                &claim_integers,
                proof_randomness_seed_hex,
                &transcript,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let limb_proofs = commitments
        .iter()
        .enumerate()
        .map(|(limb_index, commitment)| {
            prove_limb(
                statement,
                limb_index,
                commitment,
                &consistency_vectors,
                &claim_integers,
                proof_randomness_seed_hex,
                &transcript,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(SuccinctEvaluationKeyProof { limb_proofs })
}
