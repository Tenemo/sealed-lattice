use super::evaluation_domain::{
    EvaluationDomainPlan, batch_inverse, negacyclic_transpose_product,
};
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{LowDegreeParameters, LowDegreeProof, prove_low_degree};
use super::merkle_commitment::{LEAF_SALT_BYTES, MerkleTree, leaf_hash};
use super::relation::{
    LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, QUOTIENT_COLUMN_ROW_CHECK_HIGH,
    QUOTIENT_COLUMN_ROW_CHECK_LOW, QUOTIENT_COLUMN_SUMCHECK_LINEAR,
    QUOTIENT_COLUMN_SUMCHECK_VANISHING, SumcheckErrorWeights, SumcheckPublicEvaluations,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, batched_row_check_value,
    batched_sumcheck_value, build_linkage_public_vectors, public_key_switch_sample,
};
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
};
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const COLUMN_MASK_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/column-mask-v2";
const LEAF_SALT_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/leaf-salt-v2";
const CLAIM_MASK_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/claim-mask-v2";

pub(crate) struct SuccinctEvaluationKeyProof {
    pub(super) limb_proofs: Vec<LimbProof>,
}

pub(super) struct LimbProof {
    pub(super) witness_tree_root: [u8; 64],
    pub(super) quotient_tree_root: [u8; 64],
    // Smudging-masked consistency claims in local claim order (consistency
    // vector major, repetition minor).
    pub(super) masked_consistency_claims: Vec<u64>,
    // Per out-of-domain point: every committed column evaluation, phase-one
    // columns in layout order followed by the four phase-two columns.
    pub(super) deep_evaluations: Vec<Vec<u64>>,
    pub(super) low_degree: LowDegreeProof,
    pub(super) query_openings: Vec<PhaseQueryOpening>,
}

// Openings of both phase trees at the queried extension pair positions,
// including the leaf salts.
pub(super) struct PhaseQueryOpening {
    pub(super) phase_one_rows: [Vec<u64>; 2],
    pub(super) phase_one_salts: [Vec<u8>; 2],
    pub(super) phase_one_paths: [Vec<[u8; 64]>; 2],
    pub(super) phase_two_rows: [Vec<u64>; 2],
    pub(super) phase_two_salts: [Vec<u8>; 2],
    pub(super) phase_two_paths: [Vec<[u8; 64]>; 2],
}

struct SaltedTree {
    tree: MerkleTree,
    salts: Vec<u8>,
}

impl SaltedTree {
    fn salt(&self, position: usize) -> &[u8] {
        &self.salts[position * LEAF_SALT_BYTES..(position + 1) * LEAF_SALT_BYTES]
    }
}

fn commit_salted_extension_rows(
    extension_columns: &[Vec<u64>],
    extension_size: usize,
    salt_sampler: &mut DeterministicSampler,
) -> CanonicalResult<SaltedTree> {
    let salts = salt_sampler.bytes(extension_size * LEAF_SALT_BYTES);
    let mut leaf_hashes = Vec::with_capacity(extension_size);
    let mut row = vec![0_u64; extension_columns.len()];
    for position in 0..extension_size {
        for (column_index, column) in extension_columns.iter().enumerate() {
            row[column_index] = column[position];
        }
        leaf_hashes.push(leaf_hash(
            position,
            &salts[position * LEAF_SALT_BYTES..(position + 1) * LEAF_SALT_BYTES],
            &row,
        ));
    }

    Ok(SaltedTree {
        tree: MerkleTree::from_leaf_hashes(leaf_hashes)?,
        salts,
    })
}

fn field_powers(base: u64, count: usize, modulus: u64) -> Vec<u64> {
    let mut powers = Vec::with_capacity(count);
    let mut power = 1_u64;
    for _ in 0..count {
        powers.push(power);
        power = mul_mod_fast(power, base, modulus);
    }

    powers
}

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

fn trim_trailing_zeros(mut coefficients: Vec<u64>) -> Vec<u64> {
    while coefficients.last() == Some(&0) {
        coefficients.pop();
    }

    coefficients
}

// Synthetic division by Z_H = X^T - 1: returns (quotient, remainder) with the
// remainder of length T.
pub(super) fn divide_by_trace_vanishing(
    coefficients: &[u64],
    trace_size: usize,
    modulus: u64,
) -> (Vec<u64>, Vec<u64>) {
    if coefficients.len() <= trace_size {
        let mut remainder = coefficients.to_vec();
        remainder.resize(trace_size, 0);
        return (Vec::new(), remainder);
    }
    let quotient_length = coefficients.len() - trace_size;
    let mut quotient = vec![0_u64; quotient_length];
    for index in (0..quotient_length).rev() {
        let mut value = coefficients[index + trace_size];
        if index + trace_size < quotient_length {
            value = add_mod_fast(value, quotient[index + trace_size], modulus);
        }
        quotient[index] = value;
    }
    let mut remainder = Vec::with_capacity(trace_size);
    for index in 0..trace_size {
        let mut value = coefficients[index];
        if index < quotient_length {
            value = add_mod_fast(value, quotient[index], modulus);
        }
        remainder.push(value);
    }

    (quotient, remainder)
}

// Shared per-point trace interpolation weights at one out-of-domain point.
pub(super) fn barycentric_weights(
    plan: &EvaluationDomainPlan,
    point: u64,
) -> CanonicalResult<Vec<u64>> {
    let modulus = plan.modulus;
    let mut differences = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for _ in 0..plan.trace_size {
        differences.push(sub_mod_fast(point, subgroup_power, modulus));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }
    let inverted = batch_inverse(&differences, modulus)?;
    let scale = mul_mod_fast(
        plan.trace_vanishing_at(point),
        inverse_mod(plan.trace_size as u64, modulus)?,
        modulus,
    );
    let mut weights = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for inverted_difference in inverted {
        weights.push(mul_mod_fast(
            mul_mod_fast(scale, subgroup_power, modulus),
            inverted_difference,
            modulus,
        ));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }

    Ok(weights)
}

// Deterministic rejection sampling of out-of-domain points shared by prover
// and verifier: avoid zero, the trace subgroup, and the extension coset.
pub(super) fn sample_deep_points(
    transcript: &mut FiatShamirTranscript,
    plan: &EvaluationDomainPlan,
) -> CanonicalResult<Vec<u64>> {
    let modulus = plan.modulus;
    let coset_marker = pow_mod(plan.coset_offset, plan.extension_size as u64, modulus)?;
    let mut points = Vec::with_capacity(DEEP_POINT_COUNT);
    while points.len() < DEEP_POINT_COUNT {
        let candidate = transcript.challenge_field_elements("deep-point", modulus, 1)[0];
        if candidate == 0 {
            continue;
        }
        if pow_mod(candidate, plan.trace_size as u64, modulus)? == 1 {
            continue;
        }
        if pow_mod(candidate, plan.extension_size as u64, modulus)? == coset_marker {
            continue;
        }
        points.push(candidate);
    }

    Ok(points)
}

// Global mask bits for one claim, identical across every limb where the claim
// appears, so the masked claims stay comparable as centered integers.
pub(super) fn claim_mask_bits(
    proof_randomness_seed_hex: &str,
    global_claim_id: u64,
) -> Vec<u8> {
    let mut sampler = DeterministicSampler::new(
        CLAIM_MASK_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            &global_claim_id.to_le_bytes(),
        ],
    );
    let raw = sampler.bytes(CLAIM_MASK_DIGIT_COUNT);

    raw.into_iter().map(|byte| byte & 1).collect()
}

// Global claim identity for the cross-limb comparison and the shared mask:
// the secret claims come first, then every key's error claims in (key, digit)
// order over the whole statement, with repetitions innermost.
pub(super) fn global_claim_id(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    local_claim_index: usize,
) -> u64 {
    let repetition = local_claim_index % CONSISTENCY_REPETITIONS;
    let vector_index = local_claim_index / CONSISTENCY_REPETITIONS;
    if vector_index == 0 {
        return repetition as u64;
    }
    // Map the local error position back to (key, digit) and then to the
    // statement-global error position.
    let mut remaining = vector_index - 1;
    for (key_index, digit_count) in &layout.active_keys {
        if remaining < *digit_count {
            let global_error_position: usize = statement.keys[..*key_index]
                .iter()
                .map(|key| key.digit_count())
                .sum::<usize>()
                + remaining;
            return ((1 + global_error_position) * CONSISTENCY_REPETITIONS + repetition) as u64;
        }
        remaining -= digit_count;
    }
    // Linkage vectors: the negative indicator, then the opening-randomness
    // columns, indexed after every statement-global error vector.
    let total_error_vectors: usize = statement
        .keys
        .iter()
        .map(|key| key.digit_count())
        .sum::<usize>();
    let linkage_position = remaining;
    debug_assert!(linkage_position < 1 + layout.linkage_randomness_columns);
    ((1 + total_error_vectors + linkage_position) * CONSISTENCY_REPETITIONS + repetition) as u64
}

// Logical witness vectors in local layout order as residue vectors mod q:
// the secret, the active keys' error vectors, and in the commitment fields
// the negative indicator and the per-commitment opening-randomness columns.
fn logical_witness_residues(
    witness: &TrusteeEvaluationKeyWitness,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> Vec<Vec<u64>> {
    let mut vectors = Vec::with_capacity(layout.consistency_vector_count());
    vectors.push(
        witness
            .secret_coefficients
            .iter()
            .map(|coefficient| signed_value_residue(*coefficient, modulus))
            .collect::<Vec<_>>(),
    );
    for (key_index, digit_count) in &layout.active_keys {
        for digit_index in 0..*digit_count {
            vectors.push(
                witness.error_coefficients_by_key[*key_index][digit_index]
                    .iter()
                    .map(|coefficient| signed_value_residue(*coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
        }
    }
    if layout.linkage_active() {
        vectors.push(
            witness
                .negative_indicator_coefficients
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, modulus))
                .collect::<Vec<_>>(),
        );
        for randomness_columns in &witness.opening_randomness_by_limb {
            for column in randomness_columns {
                vectors.push(
                    column
                        .iter()
                        .map(|coefficient| signed_value_residue(*coefficient, modulus))
                        .collect::<Vec<_>>(),
                );
            }
        }
    }

    vectors
}

// The binary mask digit columns for one limb, as logical length-N vectors.
fn mask_digit_columns(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    proof_randomness_seed_hex: &str,
) -> Vec<Vec<u64>> {
    let mut columns = vec![vec![0_u64; layout.ring_degree]; layout.mask_column_count];
    for local_claim in 0..layout.claim_count() {
        let bits = claim_mask_bits(
            proof_randomness_seed_hex,
            global_claim_id(statement, layout, local_claim),
        );
        for (digit_index, bit) in bits.iter().enumerate() {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            columns[column][half * layout.trace_size + half_position] = u64::from(*bit);
        }
    }

    columns
}

struct LimbWitnessCommitment {
    plan: EvaluationDomainPlan,
    layout: LimbColumnLayout,
    // Logical witness residue vectors in local order (secret, then errors).
    logical_witness: Vec<Vec<u64>>,
    // Mask digit logical vectors.
    // Masked coefficients (length trace + mask degree) per physical column.
    masked_coefficients: Vec<Vec<u64>>,
    // Extension evaluations per physical column.
    extension_columns: Vec<Vec<u64>>,
    salted: SaltedTree,
}

// Mask one half-column: interpolate the half over the trace domain, then add
// Z_H times a fresh random polynomial so every off-trace evaluation is
// uniform while the trace values are unchanged.
fn masked_half_coefficients(
    plan: &EvaluationDomainPlan,
    half_values: &[u64],
    mask_sampler: &mut DeterministicSampler,
) -> Vec<u64> {
    let trace_size = plan.trace_size;
    let mask_degree = column_mask_degree(trace_size);
    let mut coefficients = plan.coefficients_from_trace_values(half_values);
    coefficients.resize(trace_size + mask_degree, 0);
    let mask = mask_sampler.uniform_residues(plan.modulus, mask_degree);
    for (index, mask_value) in mask.iter().enumerate() {
        // Z_H * r = (X^T - 1) * r: subtract at the low positions, add at T+.
        coefficients[index] = sub_mod_fast(coefficients[index], *mask_value, plan.modulus);
        coefficients[trace_size + index] =
            add_mod_fast(coefficients[trace_size + index], *mask_value, plan.modulus);
    }

    coefficients
}

fn build_limb_witness_commitment(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    limb_index: usize,
    modulus: u64,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<LimbWitnessCommitment> {
    let layout = LimbColumnLayout::new(statement, limb_index)?;
    let plan = EvaluationDomainPlan::new(modulus, layout.trace_size)?;
    let logical_witness = logical_witness_residues(witness, &layout, modulus);
    let mask_columns = mask_digit_columns(statement, &layout, proof_randomness_seed_hex);

    // Assemble the physical half-columns in layout order: secret halves, then
    // per error position the error halves, then the error-square halves, then
    // the mask digit halves. The grouped push order below matches the layout's
    // physical index functions exactly.
    let trace_size = layout.trace_size;
    let error_squares = (0..layout.total_error_columns)
        .map(|error_position| {
            logical_witness[1 + error_position]
                .iter()
                .map(|value| mul_mod_fast(*value, *value, modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut physical_halves: Vec<&[u64]> = Vec::with_capacity(layout.phase_one_physical_count());
    for half in 0..TRACE_SPLIT {
        physical_halves.push(&logical_witness[0][half * trace_size..(half + 1) * trace_size]);
    }
    for error_position in 0..layout.total_error_columns {
        let error = &logical_witness[1 + error_position];
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&error[half * trace_size..(half + 1) * trace_size]);
        }
    }
    for error_square in &error_squares {
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&error_square[half * trace_size..(half + 1) * trace_size]);
        }
    }
    if layout.linkage_active() {
        for linkage_vector in &logical_witness[1 + layout.total_error_columns..] {
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&linkage_vector[half * trace_size..(half + 1) * trace_size]);
            }
        }
    }
    for mask_column in &mask_columns {
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&mask_column[half * trace_size..(half + 1) * trace_size]);
        }
    }
    debug_assert_eq!(physical_halves.len(), layout.phase_one_physical_count());

    let mut masked_coefficients = Vec::with_capacity(physical_halves.len());
    let mut extension_columns = Vec::with_capacity(physical_halves.len());
    for (physical_index, half_values) in physical_halves.iter().enumerate() {
        let mut mask_sampler = DeterministicSampler::new(
            COLUMN_MASK_DOMAIN,
            &[
                proof_randomness_seed_hex.as_bytes(),
                &(limb_index as u64).to_le_bytes(),
                &(physical_index as u64).to_le_bytes(),
            ],
        );
        let coefficients = masked_half_coefficients(&plan, half_values, &mut mask_sampler);
        extension_columns.push(plan.extension_evaluations_from_coefficients(&coefficients));
        masked_coefficients.push(coefficients);
    }
    let mut salt_sampler = DeterministicSampler::new(
        LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"phase-one",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let salted =
        commit_salted_extension_rows(&extension_columns, plan.extension_size, &mut salt_sampler)?;

    Ok(LimbWitnessCommitment {
        plan,
        layout,
        logical_witness,
        masked_coefficients,
        extension_columns,
        salted,
    })
}

// Public per-limb sumcheck vectors, shared by prover and verifier: per
// repetition the combined secret factor and power vector, the consistency
// vectors, the mask selector combinations, the per-repetition error weights,
// and the combined lincheck sum.
pub(super) struct LimbPublicVectors {
    pub(super) secret_factor: Vec<Vec<u64>>,
    pub(super) u_powers: Vec<Vec<u64>>,
    pub(super) mask_selectors: Vec<Vec<u64>>,
    // Linkage pair vectors in SumcheckPublicEvaluations order, empty outside
    // the commitment fields.
    pub(super) linkage_vectors: Vec<Vec<u64>>,
    pub(super) error_weights: SumcheckErrorWeights,
    pub(super) lincheck_claim: u64,
}

pub(super) struct LimbChallenges {
    pub(super) gamma_by_key: Vec<u64>,
    pub(super) lincheck_challenges: Vec<u64>,
    pub(super) lincheck_alpha: Vec<u64>,
    pub(super) linkage_alpha: Vec<u64>,
    pub(super) consistency_alpha: Vec<u64>,
    pub(super) beta: Vec<u64>,
}

pub(super) fn draw_limb_challenges(
    transcript: &mut FiatShamirTranscript,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> LimbChallenges {
    let mut gamma_by_key = Vec::with_capacity(layout.active_keys.len());
    for _ in 0..layout.active_keys.len() {
        gamma_by_key.push(transcript.challenge_nonzero_field_element("gamma", modulus));
    }
    let mut lincheck_challenges = Vec::with_capacity(LINCHECK_REPETITIONS);
    for _ in 0..LINCHECK_REPETITIONS {
        lincheck_challenges.push(transcript.challenge_nonzero_field_element("lincheck-u", modulus));
    }
    let lincheck_alpha = transcript.challenge_field_elements(
        "lincheck-alpha",
        modulus,
        layout.active_keys.len() * LINCHECK_REPETITIONS,
    );
    let linkage_alpha = if layout.linkage_active() {
        let commitment_count =
            layout.linkage_randomness_columns / SETUP_COMMITMENT_RANDOMNESS_WIDTH;
        transcript.challenge_field_elements(
            "linkage-alpha",
            modulus,
            commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS,
        )
    } else {
        Vec::new()
    };
    let consistency_alpha =
        transcript.challenge_field_elements("consistency-alpha", modulus, layout.claim_count());
    let beta = transcript.challenge_field_elements(
        "beta",
        modulus,
        layout.row_check_constraint_count(),
    );

    LimbChallenges {
        gamma_by_key,
        lincheck_challenges,
        lincheck_alpha,
        linkage_alpha,
        consistency_alpha,
        beta,
    }
}

pub(super) fn build_limb_public_vectors(
    statement: &TrusteeEvaluationKeyStatement,
    layout: &LimbColumnLayout,
    limb_index: usize,
    modulus: u64,
    challenges: &LimbChallenges,
    masked_claims: &[u64],
) -> CanonicalResult<LimbPublicVectors> {
    let ring_degree = statement.ring_degree;
    let u_powers = challenges
        .lincheck_challenges
        .iter()
        .map(|challenge| field_powers(*challenge, ring_degree, modulus))
        .collect::<Vec<_>>();
    let mut secret_factor =
        vec![vec![0_u64; ring_degree]; LINCHECK_REPETITIONS];
    let mut error_weights =
        vec![vec![0_u64; layout.total_error_columns]; LINCHECK_REPETITIONS];
    let mut lincheck_claim = 0_u64;
    let mut error_cursor = 0_usize;
    for (key_position, (key_index, digit_count)) in layout.active_keys.iter().enumerate() {
        let key = &statement.keys[*key_index];
        let gamma = challenges.gamma_by_key[key_position];
        let gamma_powers = field_powers(gamma, *digit_count, modulus);
        // Combined public sample and component vector for this key at this limb.
        let mut combined_public_sample = vec![0_u64; ring_degree];
        let mut combined_component = vec![0_u64; ring_degree];
        for (digit_index, gamma_power) in gamma_powers.iter().copied().enumerate() {
            let public_sample = public_key_switch_sample(
                &key.key_switch_domain,
                &key.key_switch_seed_hex,
                digit_index,
                modulus,
                ring_degree,
            );
            let component = &key.component_b_by_digit[digit_index][limb_index];
            for coefficient_index in 0..ring_degree {
                combined_public_sample[coefficient_index] = add_mod_fast(
                    combined_public_sample[coefficient_index],
                    mul_mod_fast(gamma_power, public_sample[coefficient_index], modulus),
                    modulus,
                );
                combined_component[coefficient_index] = add_mod_fast(
                    combined_component[coefficient_index],
                    mul_mod_fast(gamma_power, component[coefficient_index], modulus),
                    modulus,
                );
            }
        }
        for (repetition, u_power_vector) in u_powers.iter().enumerate() {
            let alpha_value =
                challenges.lincheck_alpha[key_position * LINCHECK_REPETITIONS + repetition];
            let v_vector =
                negacyclic_transpose_product(&combined_public_sample, u_power_vector, modulus)?;
            let diagonal_vector =
                key.diagonal_source_vector(limb_index, u_power_vector, modulus)?;
            let gamma_limb_power = gamma_powers[limb_index];
            for coefficient_index in 0..ring_degree {
                let factor = sub_mod_fast(
                    v_vector[coefficient_index],
                    mul_mod_fast(gamma_limb_power, diagonal_vector[coefficient_index], modulus),
                    modulus,
                );
                secret_factor[repetition][coefficient_index] = add_mod_fast(
                    secret_factor[repetition][coefficient_index],
                    mul_mod_fast(alpha_value, factor, modulus),
                    modulus,
                );
            }
            let lincheck_sum = sub_mod_fast(
                0,
                dot_product(u_power_vector, &combined_component, modulus),
                modulus,
            );
            lincheck_claim = add_mod_fast(
                lincheck_claim,
                mul_mod_fast(alpha_value, lincheck_sum, modulus),
                modulus,
            );
            for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
                error_weights[repetition][error_cursor + digit_index] =
                    mul_mod_fast(alpha_value, *gamma_power, modulus);
            }
        }
        error_cursor += digit_count;
    }
    // Mask selector combinations: each claim contributes alpha' * 2^digit at
    // its mask slots, and alpha' * masked claim to the combined sum.
    let mut mask_selectors = vec![vec![0_u64; ring_degree]; layout.mask_column_count];
    let mut combined_claim = lincheck_claim;
    for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
        combined_claim = add_mod_fast(
            combined_claim,
            mul_mod_fast(*alpha_value, masked_claims[local_claim], modulus),
            modulus,
        );
        for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            let position = half * layout.trace_size + half_position;
            let digit_weight = mul_mod_fast(
                *alpha_value,
                (1_u64 << digit_index) % modulus,
                modulus,
            );
            mask_selectors[column][position] =
                add_mod_fast(mask_selectors[column][position], digit_weight, modulus);
        }
    }

    let mut linkage_vectors = Vec::new();
    if layout.linkage_active() {
        let linkage = statement.same_secret_linkage.as_ref().ok_or_else(|| {
            invalid_succinct_setup_proof(
                "limb layout expects a same-secret linkage on the statement",
            )
        })?;
        let (linkage_claim, vectors) = build_linkage_public_vectors(
            linkage,
            limb_index,
            modulus,
            &u_powers,
            &challenges.linkage_alpha,
        )?;
        combined_claim = add_mod_fast(combined_claim, linkage_claim, modulus);
        linkage_vectors = vectors;
    }

    Ok(LimbPublicVectors {
        secret_factor,
        u_powers,
        mask_selectors,
        linkage_vectors,
        error_weights: SumcheckErrorWeights {
            weights: error_weights,
        },
        lincheck_claim: combined_claim,
    })
}

// Split a logical length-N public vector into trace halves and extend each.
fn extend_logical_vector(plan: &EvaluationDomainPlan, vector: &[u64]) -> [Vec<u64>; 2] {
    let trace_size = plan.trace_size;
    [
        plan.extension_evaluations_from_coefficients(
            &plan.coefficients_from_trace_values(&vector[..trace_size]),
        ),
        plan.extension_evaluations_from_coefficients(
            &plan.coefficients_from_trace_values(&vector[trace_size..]),
        ),
    ]
}

fn prove_limb(
    statement: &TrusteeEvaluationKeyStatement,
    limb_index: usize,
    commitment: &LimbWitnessCommitment,
    consistency_vectors: &[Vec<u64>],
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

    // Masked consistency claims: clear integer sum plus the shared smudging
    // mask, both reduced into the limb field.
    let mut masked_claims = Vec::with_capacity(layout.claim_count());
    for local_claim in 0..layout.claim_count() {
        let repetition = local_claim % CONSISTENCY_REPETITIONS;
        let vector_index = local_claim / CONSISTENCY_REPETITIONS;
        let clear_sum = dot_product(
            &consistency_vectors[repetition],
            &commitment.logical_witness[vector_index],
            modulus,
        );
        let bits = claim_mask_bits(
            proof_randomness_seed_hex,
            global_claim_id(statement, layout, local_claim),
        );
        let mut mask_value = 0_u64;
        for (digit_index, bit) in bits.iter().enumerate() {
            if *bit == 1 {
                mask_value = add_mod_fast(
                    mask_value,
                    (1_u64 << digit_index) % modulus,
                    modulus,
                );
            }
        }
        masked_claims.push(add_mod_fast(clear_sum, mask_value, modulus));
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
    let secret_factor_extensions = publics
        .secret_factor
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();
    let u_extensions = publics
        .u_powers
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();
    let consistency_extensions = consistency_vectors
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();
    let mask_selector_extensions = publics
        .mask_selectors
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();
    let linkage_extensions = publics
        .linkage_vectors
        .iter()
        .map(|vector| extend_logical_vector(plan, vector))
        .collect::<Vec<_>>();

    // Batched row-check and sumcheck integrand evaluations over the coset.
    let mut row_check_extension = Vec::with_capacity(extension_size);
    let mut sumcheck_extension = Vec::with_capacity(extension_size);
    let mut row = vec![0_u64; commitment.extension_columns.len()];
    for position in 0..extension_size {
        for (column_index, column) in commitment.extension_columns.iter().enumerate() {
            row[column_index] = column[position];
        }
        row_check_extension.push(batched_row_check_value(
            &row,
            &challenges.beta,
            layout,
            modulus,
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
            &row,
            &point_publics,
            &publics.error_weights,
            &challenges.consistency_alpha,
            layout,
            modulus,
        ));
    }

    // Quotient decompositions in coefficient form.
    let row_check_coefficients = plan.coefficients_from_extension_evaluations(&row_check_extension)?;
    drop(row_check_extension);
    let (row_quotient, row_remainder) =
        divide_by_trace_vanishing(&row_check_coefficients, trace_size, modulus);
    let row_quotient = trim_trailing_zeros(row_quotient);
    if row_remainder.iter().any(|value| *value != 0) {
        return Err(invalid_succinct_setup_proof(
            "witness does not satisfy the batched row checks",
        ));
    }
    let commitment_bound = COMMITMENT_BOUND_FACTOR * trace_size;
    let mut row_quotient_low = row_quotient.clone();
    row_quotient_low.truncate(commitment_bound);
    let row_quotient_high = if row_quotient.len() > commitment_bound {
        row_quotient[commitment_bound..].to_vec()
    } else {
        Vec::new()
    };
    if row_quotient_high.len() > commitment_bound {
        return Err(invalid_succinct_setup_proof(
            "row check quotient exceeds the commitment bound",
        ));
    }
    let sumcheck_coefficients = plan.coefficients_from_extension_evaluations(&sumcheck_extension)?;
    drop(sumcheck_extension);
    let (sumcheck_quotient, sumcheck_remainder) =
        divide_by_trace_vanishing(&sumcheck_coefficients, trace_size, modulus);
    let sumcheck_quotient = trim_trailing_zeros(sumcheck_quotient);
    if sumcheck_quotient.len() > commitment_bound {
        return Err(invalid_succinct_setup_proof(
            "sumcheck quotient exceeds the commitment bound",
        ));
    }
    let expected_constant = mul_mod_fast(
        publics.lincheck_claim,
        inverse_mod(trace_size as u64, modulus)?,
        modulus,
    );
    if sumcheck_remainder[0] != expected_constant {
        return Err(invalid_succinct_setup_proof(
            "witness does not satisfy the batched sumcheck claims",
        ));
    }
    let sumcheck_linear = sumcheck_remainder[1..].to_vec();

    // Phase-two commitment.
    let mut phase_two_columns = vec![Vec::new(); PHASE_TWO_COLUMN_COUNT];
    phase_two_columns[QUOTIENT_COLUMN_ROW_CHECK_LOW] =
        plan.extension_evaluations_from_coefficients(&row_quotient_low);
    phase_two_columns[QUOTIENT_COLUMN_ROW_CHECK_HIGH] =
        plan.extension_evaluations_from_coefficients(&row_quotient_high);
    phase_two_columns[QUOTIENT_COLUMN_SUMCHECK_VANISHING] =
        plan.extension_evaluations_from_coefficients(&sumcheck_quotient);
    phase_two_columns[QUOTIENT_COLUMN_SUMCHECK_LINEAR] =
        plan.extension_evaluations_from_coefficients(&sumcheck_linear);
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

    // Out-of-domain evaluations of every committed column.
    let deep_points = sample_deep_points(&mut transcript, plan)?;
    let phase_two_coefficient_sets = [
        &row_quotient_low,
        &row_quotient_high,
        &sumcheck_quotient,
        &sumcheck_linear,
    ];
    let mut deep_evaluations = Vec::with_capacity(DEEP_POINT_COUNT);
    for point in &deep_points {
        let mut evaluations =
            Vec::with_capacity(commitment.masked_coefficients.len() + PHASE_TWO_COLUMN_COUNT);
        for coefficients in &commitment.masked_coefficients {
            evaluations.push(evaluate_coefficients(coefficients, *point, modulus));
        }
        for coefficients in phase_two_coefficient_sets {
            evaluations.push(evaluate_coefficients(coefficients, *point, modulus));
        }
        deep_evaluations.push(evaluations);
    }
    for evaluations in &deep_evaluations {
        transcript.absorb_u64_slice("deep-evaluations", evaluations);
    }

    // Lambda-batched DEEP quotient codeword over the extension coset.
    let total_column_count = commitment.extension_columns.len() + PHASE_TWO_COLUMN_COUNT;
    let lambda = transcript.challenge_field_elements(
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
            .map(|extension_point| sub_mod_fast(*extension_point, *deep_point, modulus))
            .collect::<Vec<_>>();
        inverted_differences_by_point.push(batch_inverse(&differences, modulus)?);
    }
    let mut batch_codeword = vec![0_u64; extension_size];
    for position in 0..extension_size {
        let mut accumulated = 0_u64;
        for (column_index, column) in commitment
            .extension_columns
            .iter()
            .chain(phase_two_columns.iter())
            .enumerate()
        {
            let column_value = column[position];
            for (point_index, evaluations) in deep_evaluations.iter().enumerate() {
                let quotient = mul_mod_fast(
                    sub_mod_fast(column_value, evaluations[column_index], modulus),
                    inverted_differences_by_point[point_index][position],
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
        batch_codeword[position] = accumulated;
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
            phase_one_paths: [
                commitment.salted.tree.open(*position),
                commitment.salted.tree.open(*position + half),
            ],
            phase_two_rows: [
                collect_row(&phase_two_columns, *position),
                collect_row(&phase_two_columns, *position + half),
            ],
            phase_two_salts: [
                phase_two_salted.salt(*position).to_vec(),
                phase_two_salted.salt(*position + half).to_vec(),
            ],
            phase_two_paths: [
                phase_two_salted.tree.open(*position),
                phase_two_salted.tree.open(*position + half),
            ],
        })
        .collect::<Vec<_>>();

    Ok(LimbProof {
        witness_tree_root: commitment.salted.tree.root(),
        quotient_tree_root: phase_two_salted.tree.root(),
        masked_consistency_claims: masked_claims,
        deep_evaluations,
        low_degree,
        query_openings,
    })
}

fn validate_witness_support(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<()> {
    if witness.secret_coefficients.len() != statement.ring_degree
        || witness.error_coefficients_by_key.len() != statement.keys.len()
    {
        return Err(invalid_succinct_setup_proof(
            "witness shape does not match the statement",
        ));
    }
    if witness
        .secret_coefficients
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_succinct_setup_proof(
            "witness secret must be ternary",
        ));
    }
    for (key, errors) in statement
        .keys
        .iter()
        .zip(witness.error_coefficients_by_key.iter())
    {
        if errors.len() != key.digit_count()
            || errors
                .iter()
                .any(|digit_errors| digit_errors.len() != statement.ring_degree)
        {
            return Err(invalid_succinct_setup_proof(
                "witness error shape does not match a key descriptor",
            ));
        }
        if errors
            .iter()
            .flatten()
            .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(invalid_succinct_setup_proof(
                "witness errors must stay in the centered binomial support",
            ));
        }
    }
    match &statement.same_secret_linkage {
        Some(linkage) => {
            if witness.negative_indicator_coefficients.len() != statement.ring_degree
                || witness
                    .negative_indicator_coefficients
                    .iter()
                    .any(|coefficient| !(0..=1).contains(coefficient))
            {
                return Err(invalid_succinct_setup_proof(
                    "witness negative indicator must be binary at the ring degree",
                ));
            }
            if witness.opening_randomness_by_limb.len() != linkage.commitments.len()
                || witness.opening_randomness_by_limb.iter().any(|columns| {
                    columns.len() != crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH
                        || columns.iter().any(|column| {
                            column.len() != statement.ring_degree
                                || column
                                    .iter()
                                    .any(|coefficient| !(-1..=1).contains(coefficient))
                        })
                })
            {
                return Err(invalid_succinct_setup_proof(
                    "witness opening randomness must be ternary per commitment and column",
                ));
            }
        }
        None => {
            if !witness.negative_indicator_coefficients.is_empty()
                || !witness.opening_randomness_by_limb.is_empty()
            {
                return Err(invalid_succinct_setup_proof(
                    "witness linkage material requires a same-secret linkage statement",
                ));
            }
        }
    }

    Ok(())
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
                proof_randomness_seed_hex,
                &transcript,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(SuccinctEvaluationKeyProof { limb_proofs })
}
