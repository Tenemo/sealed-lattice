use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::super::fiat_shamir_transcript::FiatShamirTranscript;
use super::super::low_degree_proof::{
    LowDegreeParameters, commit_low_degree, open_low_degree_at_positions,
};
use super::super::merkle_commitment::{
    MAIN_LOW_DEGREE_TREE_ORDINAL_BASE, QUOTIENT_TREE_ORDINAL_BASE,
    RESIDUAL_LOW_DEGREE_TREE_ORDINAL_BASE, limb_tree_context, low_degree_tree_context,
    sorted_unique_indices,
};
use super::super::relation::{
    BaseColumnDomain, PHASE_TWO_COLUMN_COUNT, QUOTIENT_COLUMN_SUMCHECK_RESIDUAL,
    SumcheckPublicEvaluations, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    batched_row_check_value, batched_sumcheck_value,
};
use super::super::{
    COMMITMENT_BOUND_FACTOR, DEEP_EVALUATION_POINT_COUNT, LOW_DEGREE_QUERY_COUNT,
    MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE, MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    SUMCHECK_RESIDUAL_LOW_DEGREE_TRANSCRIPT_PURPOSE, invalid_succinct_setup_proof,
};
use super::challenges::{build_limb_public_vectors, draw_limb_challenges};
use super::claim_masking::{global_claim_id, global_claim_integers};
use super::polynomial::{
    divide_by_trace_vanishing, extend_logical_vector, extend_logical_vector_extension,
    extension_powers, sample_deep_identity_points, trim_trailing_zeros,
};
use super::salted_tree::commit_salted_extension_row_pairs;
use super::witness::{
    LimbWitnessCommitment, build_limb_witness_commitment, validate_witness_support,
};
use super::{
    LEAF_SALT_DOMAIN, LimbProof, PhaseQueryOpening, SuccinctEvaluationKeyProof,
};
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::{inverse_mod, mul_mod_fast, sub_mod_fast};
use crate::bgv::parameters::DATA_PRIMES;
use crate::encoding::CanonicalResult;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
const TRUSTEE_PROOF_LIMB_BATCH_SIZE_ENVIRONMENT_VARIABLE: &str =
    "SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE";

fn normalize_limb_batch_size(requested_limb_batch_size: usize, limb_count: usize) -> usize {
    requested_limb_batch_size.max(1).min(limb_count.max(1))
}

#[cfg(test)]
fn trustee_proof_progress(message: impl AsRef<str>) {
    if matches!(
        std::env::var("SEALED_LATTICE_TRUSTEE_PROOF_PROGRESS").as_deref(),
        Ok("1")
    ) {
        println!("sealed-lattice-trustee-proof-progress {}", message.as_ref());
    }
}

#[cfg(not(test))]
fn trustee_proof_progress(_message: impl AsRef<str>) {}

#[cfg(not(target_arch = "wasm32"))]
fn configured_limb_batch_size(limb_count: usize) -> usize {
    std::env::var(TRUSTEE_PROOF_LIMB_BATCH_SIZE_ENVIRONMENT_VARIABLE)
        .ok()
        .and_then(|configured_batch_size| configured_batch_size.parse::<usize>().ok())
        .map(|configured_batch_size| normalize_limb_batch_size(configured_batch_size, limb_count))
        .unwrap_or_else(|| normalize_limb_batch_size(rayon::current_num_threads(), limb_count))
}

#[cfg(target_arch = "wasm32")]
fn configured_limb_batch_size(limb_count: usize) -> usize {
    normalize_limb_batch_size(1, limb_count)
}

#[allow(clippy::too_many_arguments)]
fn prove_limb(
    statement: &TrusteeEvaluationKeyStatement,
    limb_index: usize,
    commitment: &LimbWitnessCommitment,
    consistency_vectors: &[Vec<u64>],
    global_claim_integers: &[BigInt],
    proof_randomness_seed_hex: &str,
    global_transcript: &FiatShamirTranscript,
) -> CanonicalResult<LimbProof> {
    let plan = &commitment.plan;
    let layout = &commitment.layout;
    let modulus = plan.modulus;
    let trace_size = plan.trace_size;
    let extension_size = plan.extension_size;
    let mut transcript = global_transcript.fork("limb", limb_index as u64);
    let challenges = draw_limb_challenges(&mut transcript, layout, modulus)?;

    // Masked consistency claims: the limb residues of the shared global
    // integer claims (clear integer sum plus the shared smudging mask), so
    // every limb publishes the same integer reduced into its field.
    let mut masked_claims = Vec::with_capacity(layout.claim_count());
    for local_claim in 0..layout.claim_count() {
        let global_id = global_claim_id(statement, layout, local_claim);
        let claim_integer = &global_claim_integers[global_id as usize];
        masked_claims.push(bigint_residue(claim_integer, modulus)?);
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
    let mut sumcheck_residual = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
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
        // its constant coefficient. The committed residual is R(X) - R(0):
        // degree below T and zero at X = 0, with the zero anchor bound through
        // the DEEP batching below.
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
        let mut residual = remainder;
        residual[0] = sub_mod_fast(residual[0], expected_constant, modulus);
        sumcheck_quotient[coordinate] = quotient;
        sumcheck_residual[coordinate] = trim_trailing_zeros(residual);
    }
    drop(row_check_extension);
    drop(sumcheck_extension);

    // Phase-two commitment: four logical extension-valued quotient columns,
    // committed as four base coordinate columns each.
    let logical_phase_two_coefficients = [
        &row_quotient_low,
        &row_quotient_high,
        &sumcheck_quotient,
        &sumcheck_residual,
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
    let phase_two_salted = commit_salted_extension_row_pairs(
        limb_tree_context(
            statement.application_statement_schema_identifier(),
            QUOTIENT_TREE_ORDINAL_BASE,
            limb_index,
        )?,
        &phase_two_columns,
        extension_size,
        &mut phase_two_salt_sampler,
    )?;
    transcript.absorb("quotient-tree-root", &phase_two_salted.tree.root());
    transcript.absorb_u64_slice("masked-consistency-claims", &masked_claims);

    // Out-of-domain evaluations of every committed column at the extension
    // points, via one shared powers table per point.
    let deep_points = sample_deep_identity_points(&mut transcript, plan)?;
    let mut deep_evaluations = Vec::with_capacity(DEEP_EVALUATION_POINT_COUNT);
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
        let mut evaluations = Vec::with_capacity(
            commitment.masked_coefficients.len() + PHASE_TWO_COLUMN_COUNT,
        );
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
        total_column_count * DEEP_EVALUATION_POINT_COUNT,
    )?;
    let mut extension_points = Vec::with_capacity(extension_size);
    let mut point = plan.coset_offset;
    for _ in 0..extension_size {
        extension_points.push(point);
        point = mul_mod_fast(point, plan.extension_root, modulus);
    }
    let mut inverted_differences_by_point = Vec::with_capacity(DEEP_EVALUATION_POINT_COUNT);
    for deep_point in &deep_points {
        let differences = extension_points
            .iter()
            .map(|extension_point| tower.sub(&tower.embed_base(*extension_point), deep_point))
            .collect::<Vec<_>>();
        inverted_differences_by_point.push(tower.batch_inverse(&differences)?);
    }
    // Per point: the lambda-weighted sum of claimed evaluations, hoisted out
    // of the position loop so the loop runs on base column values.
    let mut lambda_evaluation_sums = [ChallengeExtensionTower::zero(); DEEP_EVALUATION_POINT_COUNT];
    let mut lambda_by_point = vec![
        vec![ChallengeExtensionTower::zero(); total_column_count];
        DEEP_EVALUATION_POINT_COUNT
    ];
    for column_index in 0..total_column_count {
        for (point_index, evaluations) in deep_evaluations.iter().enumerate() {
            let lambda_value = &lambda[column_index * DEEP_EVALUATION_POINT_COUNT + point_index];
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
    transcript.absorb("low-degree-purpose", MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE);
    let low_degree_state = match commit_low_degree(
        low_degree_tree_context(
            statement.application_statement_schema_identifier(),
            MAIN_LOW_DEGREE_TREE_ORDINAL_BASE,
            limb_index,
        )?,
        &mut transcript,
        &low_degree_parameters,
        &batch_codeword,
    ) {
        Ok(state) => state,
        Err(error)
            if error
                .message
                .contains("low-degree final layer exceeds the final degree bound") =>
        {
            let actual_degree = extension_codeword_degree(plan, &batch_codeword)?
                .map_or_else(|| "zero".to_string(), |degree| degree.to_string());
            return Err(invalid_succinct_setup_proof(format!(
                "limb {limb_index}: {}; DEEP-batched codeword degree {actual_degree}, claimed degree bound below {commitment_bound}",
                error.message
            )));
        }
        Err(error) => return Err(error),
    };

    let sumcheck_residual_codeword = (0..extension_size)
        .map(|position| phase_two_logical_value(position, QUOTIENT_COLUMN_SUMCHECK_RESIDUAL))
        .collect::<Vec<_>>();
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
    let sumcheck_residual_low_degree_state = commit_low_degree(
        low_degree_tree_context(
            statement.application_statement_schema_identifier(),
            RESIDUAL_LOW_DEGREE_TREE_ORDINAL_BASE,
            limb_index,
        )?,
        &mut transcript,
        &sumcheck_residual_low_degree_parameters,
        &sumcheck_residual_codeword,
    )?;
    let query_positions = transcript.challenge_positions(
        "shared-query-position",
        extension_size / 2,
        LOW_DEGREE_QUERY_COUNT,
    )?;
    let low_degree = open_low_degree_at_positions(low_degree_state, &query_positions)?;
    let sumcheck_residual_low_degree =
        open_low_degree_at_positions(sumcheck_residual_low_degree_state, &query_positions)?;

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
            phase_one_pair_salt: commitment.salted.pair_salt(*position).to_vec(),
            phase_two_rows: [
                collect_row(&phase_two_columns, *position),
                collect_row(&phase_two_columns, *position + half),
            ],
            phase_two_pair_salt: phase_two_salted.pair_salt(*position).to_vec(),
        })
        .collect::<Vec<_>>();
    // The witness and phase-two pair trees are opened at the one shared query
    // set used by both the main and residual low-degree proofs.
    let phase_opened_indices = sorted_unique_indices(query_positions.iter().copied());
    let witness_batch_opening = commitment.salted.tree.open_batch(&phase_opened_indices);
    let quotient_batch_opening = phase_two_salted.tree.open_batch(&phase_opened_indices);
    Ok(LimbProof {
        witness_tree_root: commitment.salted.tree.root(),
        quotient_tree_root: phase_two_salted.tree.root(),
        masked_consistency_claims: masked_claims,
        deep_evaluations,
        low_degree,
        sumcheck_residual_low_degree,
        query_openings,
        witness_batch_opening,
        quotient_batch_opening,
    })
}

fn extension_codeword_degree(
    plan: &EvaluationDomainPlan,
    codeword: &[ChallengeExtensionElement],
) -> CanonicalResult<Option<usize>> {
    if codeword.len() != plan.extension_size {
        return Err(invalid_succinct_setup_proof(
            "extension codeword length does not match the evaluation domain",
        ));
    }
    let mut highest_nonzero_coefficient = None;
    let mut coordinate_values = vec![0_u64; codeword.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in coordinate_values.iter_mut().zip(codeword.iter()) {
            *slot = element[coordinate];
        }
        let coefficients = plan.coefficients_from_extension_evaluations(&coordinate_values)?;
        if let Some(coefficient_index) = coefficients.iter().rposition(|value| *value != 0) {
            highest_nonzero_coefficient = Some(
                highest_nonzero_coefficient.map_or(coefficient_index, |previous: usize| {
                    previous.max(coefficient_index)
                }),
            );
        }
    }

    Ok(highest_nonzero_coefficient)
}

fn bigint_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_integer = BigInt::from(modulus);
    let residue = ((value % &modulus_integer) + &modulus_integer) % &modulus_integer;
    residue
        .to_u64()
        .ok_or_else(|| invalid_succinct_setup_proof("masked consistency residue does not fit u64"))
}

pub(crate) fn prove_evaluation_key_share(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
    prove_evaluation_key_share_with_limb_batch_size(
        statement,
        witness,
        proof_randomness_seed_hex,
        configured_limb_batch_size(statement.proof_limb_count()),
    )
}

#[cfg(test)]
pub(crate) fn prove_evaluation_key_share_with_test_limb_batch_size(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
    requested_limb_batch_size: usize,
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
    prove_evaluation_key_share_with_limb_batch_size(
        statement,
        witness,
        proof_randomness_seed_hex,
        requested_limb_batch_size,
    )
}

fn prove_evaluation_key_share_with_limb_batch_size(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
    requested_limb_batch_size: usize,
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
    statement.validate_shape()?;
    validate_witness_support(statement, witness)?;
    let proof_limb_indices = statement.proof_limb_indices();
    let limb_batch_size =
        normalize_limb_batch_size(requested_limb_batch_size, proof_limb_indices.len());
    let mut transcript = FiatShamirTranscript::new_for_schema(
        "trustee-evaluation-key-share",
        statement.application_statement_schema_identifier(),
        MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    )?;
    transcript.absorb("statement", &statement.statement_hash());

    let mut witness_tree_roots = Vec::with_capacity(proof_limb_indices.len());
    for limb_index_batch in proof_limb_indices.chunks(limb_batch_size) {
        #[cfg(not(target_arch = "wasm32"))]
        let batch_roots = limb_index_batch
            .par_iter()
            .map(|limb_index| {
                let modulus = DATA_PRIMES[*limb_index];
                trustee_proof_progress(format!("commitment-start limb={limb_index}"));
                let commitment = build_limb_witness_commitment(
                    statement,
                    witness,
                    *limb_index,
                    modulus,
                    proof_randomness_seed_hex,
                )?;
                trustee_proof_progress(format!("commitment-finish limb={limb_index}"));
                Ok(commitment.salted.tree.root())
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        #[cfg(target_arch = "wasm32")]
        let batch_roots = limb_index_batch
            .iter()
            .map(|limb_index| {
                let modulus = DATA_PRIMES[*limb_index];
                trustee_proof_progress(format!("commitment-start limb={limb_index}"));
                let commitment = build_limb_witness_commitment(
                    statement,
                    witness,
                    *limb_index,
                    modulus,
                    proof_randomness_seed_hex,
                )?;
                trustee_proof_progress(format!("commitment-finish limb={limb_index}"));
                Ok(commitment.salted.tree.root())
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        witness_tree_roots.extend(batch_roots);
    }

    for witness_tree_root in &witness_tree_roots {
        transcript.absorb("witness-tree-root", witness_tree_root);
    }
    let family_shape = statement.family_shape();
    let consistency_vector_length = statement.ring_degree;
    let consistency_vectors = (0..family_shape.consistency_repetitions())
        .map(|_| {
            transcript.challenge_bounded_integers(
                "consistency-vector",
                family_shape.consistency_coefficient_bits(),
                consistency_vector_length,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let claim_integers = global_claim_integers(
        statement,
        witness,
        &consistency_vectors,
        proof_randomness_seed_hex,
    );

    let mut limb_proofs = Vec::with_capacity(proof_limb_indices.len());
    for (batch_index, limb_index_batch) in proof_limb_indices.chunks(limb_batch_size).enumerate() {
        let batch_start = batch_index * limb_batch_size;

        #[cfg(not(target_arch = "wasm32"))]
        let proof_batch = limb_index_batch
            .par_iter()
            .enumerate()
            .map(|(batch_offset, limb_index)| {
                let proof_position = batch_start + batch_offset;
                let modulus = DATA_PRIMES[*limb_index];
                trustee_proof_progress(format!("prove-start limb={limb_index}"));
                let commitment = build_limb_witness_commitment(
                    statement,
                    witness,
                    *limb_index,
                    modulus,
                    proof_randomness_seed_hex,
                )?;
                if commitment.salted.tree.root() != witness_tree_roots[proof_position] {
                    return Err(invalid_succinct_setup_proof(
                        "regenerated witness-tree root changed before limb proving",
                    ));
                }
                prove_limb(
                    statement,
                    *limb_index,
                    &commitment,
                    &consistency_vectors,
                    &claim_integers,
                    proof_randomness_seed_hex,
                    &transcript,
                )
                .inspect(|_| {
                    trustee_proof_progress(format!("prove-finish limb={limb_index}"));
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        #[cfg(target_arch = "wasm32")]
        let proof_batch = limb_index_batch
            .iter()
            .enumerate()
            .map(|(batch_offset, limb_index)| {
                let proof_position = batch_start + batch_offset;
                let modulus = DATA_PRIMES[*limb_index];
                trustee_proof_progress(format!("prove-start limb={limb_index}"));
                let commitment = build_limb_witness_commitment(
                    statement,
                    witness,
                    *limb_index,
                    modulus,
                    proof_randomness_seed_hex,
                )?;
                if commitment.salted.tree.root() != witness_tree_roots[proof_position] {
                    return Err(invalid_succinct_setup_proof(
                        "regenerated witness-tree root changed before limb proving",
                    ));
                }
                prove_limb(
                    statement,
                    *limb_index,
                    &commitment,
                    &consistency_vectors,
                    &claim_integers,
                    proof_randomness_seed_hex,
                    &transcript,
                )
                .inspect(|_| {
                    trustee_proof_progress(format!("prove-finish limb={limb_index}"));
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        limb_proofs.extend(proof_batch);
    }

    Ok(SuccinctEvaluationKeyProof { limb_proofs })
}
