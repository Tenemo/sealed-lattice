use super::evaluation_domain::{EvaluationDomainPlan, negacyclic_transpose_product};
use super::extension_field::{
    CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
};
use super::fiat_shamir_transcript::FiatShamirTranscript;
use super::low_degree_proof::{LowDegreeParameters, LowDegreeProof, prove_low_degree};
use super::merkle_commitment::{
    BatchedMerkleOpening, LEAF_SALT_BYTES, MerkleTree, leaf_hash, sorted_unique_indices,
};
use super::relation::{
    BaseColumnDomain, LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, SumcheckErrorWeights,
    SumcheckPublicEvaluations, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    batched_row_check_value, batched_sumcheck_value, build_linkage_public_vectors,
    build_private_vss_public_vectors, private_vss_share_lifted_carry_bound,
};
use super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::modular_arithmetic::{inverse_mod, pow_mod};
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_RANDOMNESS_WIDTH, SETUP_COMMITMENT_ROW_COUNT,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const COLUMN_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/column-mask-v2";
const LEAF_SALT_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/leaf-salt-v2";
const CLAIM_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/claim-mask-v2";

pub(crate) struct SuccinctEvaluationKeyProof {
    pub(super) limb_proofs: Vec<LimbProof>,
}

pub(super) struct LimbProof {
    pub(super) witness_tree_root: [u8; 64],
    pub(super) quotient_tree_root: [u8; 64],
    // Smudging-masked consistency claims in local claim order (consistency
    // vector major, repetition minor).
    pub(super) masked_consistency_claims: Vec<u64>,
    // Per out-of-domain point: every committed column evaluation in the
    // challenge extension, phase-one columns in layout order followed by the
    // four logical phase-two columns.
    pub(super) deep_evaluations: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) low_degree: LowDegreeProof,
    pub(super) query_openings: Vec<PhaseQueryOpening>,
    // One batched authentication opening per phase tree, covering every queried
    // position and its coset partner at once instead of an independent path per
    // query slot.
    pub(super) witness_batch_opening: BatchedMerkleOpening,
    pub(super) quotient_batch_opening: BatchedMerkleOpening,
}

// Openings of both phase trees at the queried extension pair positions,
// including the leaf salts. The authentication nodes live in the per-tree
// batched openings on `LimbProof`, not here.
pub(super) struct PhaseQueryOpening {
    pub(super) phase_one_rows: [Vec<u64>; 2],
    pub(super) phase_one_salts: [Vec<u8>; 2],
    pub(super) phase_two_rows: [Vec<u64>; 2],
    pub(super) phase_two_salts: [Vec<u8>; 2],
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

// Shared per-point trace interpolation weights at one out-of-domain
// extension point.
pub(super) fn barycentric_weights(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = plan.modulus;
    // Barycentric interpolation over H = {omega^i}; valid only for a point
    // outside H (else a difference is zero and inversion fails), which
    // sample_deep_points guarantees by rejecting H.
    let mut differences = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for _ in 0..plan.trace_size {
        differences.push(tower.sub(point, &tower.embed_base(subgroup_power)));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }
    let inverted = tower.batch_inverse(&differences)?;
    let vanishing = trace_vanishing_at_extension(plan, tower, point);
    let scale = tower.scale_base(&vanishing, inverse_mod(plan.trace_size as u64, modulus)?);
    let mut weights = Vec::with_capacity(plan.trace_size);
    let mut subgroup_power = 1_u64;
    for inverted_difference in inverted {
        weights.push(tower.mul(
            &tower.scale_base(&scale, subgroup_power),
            &inverted_difference,
        ));
        subgroup_power = mul_mod_fast(subgroup_power, plan.trace_root, modulus);
    }

    Ok(weights)
}

// Z_H(z) = z^T - 1 at an extension point.
pub(super) fn trace_vanishing_at_extension(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
) -> ChallengeExtensionElement {
    tower.sub(
        &tower.pow(point, plan.trace_size as u64),
        &ChallengeExtensionTower::one(),
    )
}

// Deterministic rejection sampling of out-of-domain points shared by prover
// and verifier: extension points avoiding zero, the base trace subgroup, and
// the base extension coset.
pub(super) fn sample_deep_points(
    transcript: &mut FiatShamirTranscript,
    plan: &EvaluationDomainPlan,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let modulus = plan.modulus;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let coset_marker = tower.embed_base(pow_mod(
        plan.coset_offset,
        plan.extension_size as u64,
        modulus,
    )?);
    let mut points = Vec::with_capacity(DEEP_POINT_COUNT);
    while points.len() < DEEP_POINT_COUNT {
        let candidate = transcript.challenge_extension_elements("deep-point", modulus, 1)[0];
        if ChallengeExtensionTower::is_zero(&candidate) {
            continue;
        }
        if tower.pow(&candidate, plan.trace_size as u64) == ChallengeExtensionTower::one() {
            continue;
        }
        // Every element of the coset raises to g^extension_size, so this single
        // equality rejects the whole coset at once; likewise
        // candidate^trace_size == 1 rejects all of H.
        if tower.pow(&candidate, plan.extension_size as u64) == coset_marker {
            continue;
        }
        points.push(candidate);
    }

    Ok(points)
}

// Global mask bits for one claim, identical across every limb where the claim
// appears, so the masked claims stay comparable as centered integers.
pub(super) fn claim_mask_bits(proof_randomness_seed_hex: &str, global_claim_id: u64) -> Vec<u8> {
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
    if layout.private_vss_active() {
        debug_assert!(statement.private_vss_share.is_some());
        return (vector_index * CONSISTENCY_REPETITIONS + repetition) as u64;
    }
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

// Logical witness vectors in local layout order as residue vectors mod q. For
// private VSS: the Shamir coefficient messages, the carry, and the
// per-coefficient opening-randomness columns. For the standard family: the
// secret, the active keys' error vectors, and in the commitment fields the
// negative indicator and the per-commitment opening-randomness columns. This is
// the full trace width, which for private VSS exceeds consistency_vector_count()
// because the message columns are committed witnesses without a consistency
// claim.
fn logical_witness_residues(
    witness: &TrusteeEvaluationKeyWitness,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> Vec<Vec<u64>> {
    let logical_column_count = if layout.private_vss_active() {
        layout.private_vss_logical_columns()
    } else {
        layout.consistency_vector_count()
    };
    let mut vectors = Vec::with_capacity(logical_column_count);
    if layout.private_vss_active() {
        for coefficient_messages in &witness.private_vss_coefficient_messages_by_shamir_index {
            vectors.push(
                coefficient_messages
                    .iter()
                    .map(|coefficient| signed_value_residue(*coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
        }
        vectors.push(
            witness
                .private_vss_carry_witnesses
                .iter()
                .map(|coefficient| signed_value_residue(*coefficient, modulus))
                .collect::<Vec<_>>(),
        );
        for randomness_columns in &witness.private_vss_opening_randomness_by_shamir_index {
            for column in randomness_columns {
                vectors.push(
                    column
                        .iter()
                        .map(|coefficient| signed_value_residue(*coefficient, modulus))
                        .collect::<Vec<_>>(),
                );
            }
        }

        return vectors;
    }
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
    // coeffs - r at [0,deg) and + r at [T, T+deg) equals coeffs + (X^T - 1)*r =
    // coeffs + Z_H*r: off-trace evaluations are randomized while trace values
    // are unchanged (the ZK simulator relies on this).
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
    let mut physical_halves: Vec<&[u64]> = Vec::with_capacity(layout.phase_one_physical_count());
    let error_squares_storage: Vec<Vec<u64>>;
    if layout.private_vss_active() {
        for logical_vector in &logical_witness {
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&logical_vector[half * trace_size..(half + 1) * trace_size]);
            }
        }
    } else {
        error_squares_storage = (0..layout.total_error_columns)
            .map(|error_position| {
                logical_witness[1 + error_position]
                    .iter()
                    .map(|value| mul_mod_fast(*value, *value, modulus))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for half in 0..TRACE_SPLIT {
            physical_halves.push(&logical_witness[0][half * trace_size..(half + 1) * trace_size]);
        }
        for error_position in 0..layout.total_error_columns {
            let error = &logical_witness[1 + error_position];
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&error[half * trace_size..(half + 1) * trace_size]);
            }
        }
        for error_square in &error_squares_storage {
            for half in 0..TRACE_SPLIT {
                physical_halves.push(&error_square[half * trace_size..(half + 1) * trace_size]);
            }
        }
        if layout.linkage_active() {
            for linkage_vector in &logical_witness[1 + layout.total_error_columns..] {
                for half in 0..TRACE_SPLIT {
                    physical_halves
                        .push(&linkage_vector[half * trace_size..(half + 1) * trace_size]);
                }
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
    pub(super) secret_factor: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) u_powers: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) mask_selectors: Vec<Vec<ChallengeExtensionElement>>,
    // Linkage pair vectors in SumcheckPublicEvaluations order, empty outside
    // the commitment fields.
    pub(super) linkage_vectors: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) error_weights: SumcheckErrorWeights,
    pub(super) lincheck_claim: ChallengeExtensionElement,
}

pub(super) struct LimbChallenges {
    pub(super) gamma_by_key: Vec<ChallengeExtensionElement>,
    pub(super) lincheck_challenges: Vec<ChallengeExtensionElement>,
    pub(super) lincheck_alpha: Vec<ChallengeExtensionElement>,
    pub(super) linkage_alpha: Vec<ChallengeExtensionElement>,
    pub(super) consistency_alpha: Vec<ChallengeExtensionElement>,
    pub(super) beta: Vec<ChallengeExtensionElement>,
}

pub(super) fn draw_limb_challenges(
    transcript: &mut FiatShamirTranscript,
    layout: &LimbColumnLayout,
    modulus: u64,
) -> LimbChallenges {
    let mut gamma_by_key = Vec::with_capacity(layout.active_keys.len());
    for _ in 0..layout.active_keys.len() {
        gamma_by_key.push(transcript.challenge_nonzero_extension_element("gamma", modulus));
    }
    let mut lincheck_challenges = Vec::with_capacity(LINCHECK_REPETITIONS);
    for _ in 0..LINCHECK_REPETITIONS {
        lincheck_challenges
            .push(transcript.challenge_nonzero_extension_element("lincheck-u", modulus));
    }
    let lincheck_alpha = transcript.challenge_extension_elements(
        "lincheck-alpha",
        modulus,
        layout.active_keys.len() * LINCHECK_REPETITIONS,
    );
    let linkage_alpha = if layout.private_vss_active() {
        transcript.challenge_extension_elements(
            "private-vss-relation-alpha",
            modulus,
            layout.private_vss_relation_count() * LINCHECK_REPETITIONS,
        )
    } else if layout.linkage_active() {
        let commitment_count =
            layout.linkage_randomness_columns / SETUP_COMMITMENT_RANDOMNESS_WIDTH;
        transcript.challenge_extension_elements(
            "linkage-alpha",
            modulus,
            commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS,
        )
    } else {
        Vec::new()
    };
    let consistency_alpha =
        transcript.challenge_extension_elements("consistency-alpha", modulus, layout.claim_count());
    let beta = transcript.challenge_extension_elements(
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
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let ring_degree = statement.ring_degree;
    let u_powers = challenges
        .lincheck_challenges
        .iter()
        .map(|challenge| extension_powers(&tower, challenge, ring_degree))
        .collect::<Vec<_>>();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    if layout.private_vss_active() {
        let private_vss_share = statement.private_vss_share.as_ref().ok_or_else(|| {
            invalid_succinct_setup_proof("private VSS layout requires a private VSS statement")
        })?;
        let mut combined_claim = ChallengeExtensionTower::zero();
        let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
        for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
            combined_claim = tower.add(
                &combined_claim,
                &tower.scale_base(alpha_value, masked_claims[local_claim]),
            );
            for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
                let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
                let position = half * layout.trace_size + half_position;
                let digit_weight =
                    tower.scale_base(alpha_value, pow_mod(2, digit_index as u64, modulus)?);
                mask_selectors[column][position] =
                    tower.add(&mask_selectors[column][position], &digit_weight);
            }
        }
        let (private_vss_claim, relation_vectors) = build_private_vss_public_vectors(
            private_vss_share,
            limb_index,
            &tower,
            &u_powers,
            &challenges.linkage_alpha,
        )?;
        combined_claim = tower.add(&combined_claim, &private_vss_claim);

        return Ok(LimbPublicVectors {
            secret_factor: Vec::new(),
            u_powers,
            mask_selectors,
            linkage_vectors: relation_vectors,
            error_weights: SumcheckErrorWeights {
                weights: vec![Vec::new(); LINCHECK_REPETITIONS],
            },
            lincheck_claim: combined_claim,
        });
    }
    let mut secret_factor = vec![extension_zero_vector(); LINCHECK_REPETITIONS];
    let mut error_weights = vec![
        vec![ChallengeExtensionTower::zero(); layout.total_error_columns];
        LINCHECK_REPETITIONS
    ];
    let mut lincheck_claim = ChallengeExtensionTower::zero();
    let mut error_cursor = 0_usize;
    for (key_position, (key_index, digit_count)) in layout.active_keys.iter().enumerate() {
        let key = &statement.keys[*key_index];
        let gamma = &challenges.gamma_by_key[key_position];
        let gamma_powers = extension_powers(&tower, gamma, *digit_count);
        // Combined public sample and component vector for this key at this
        // limb, gamma-weighted into the challenge extension.
        let mut combined_public_sample = extension_zero_vector();
        let mut combined_component = extension_zero_vector();
        for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
            let public_sample = key.public_sample(digit_index, modulus, ring_degree);
            let component = &key.component_b_by_digit[digit_index][limb_index];
            for coefficient_index in 0..ring_degree {
                combined_public_sample[coefficient_index] = tower.add(
                    &combined_public_sample[coefficient_index],
                    &tower.scale_base(gamma_power, public_sample[coefficient_index]),
                );
                combined_component[coefficient_index] = tower.add(
                    &combined_component[coefficient_index],
                    &tower.scale_base(gamma_power, component[coefficient_index]),
                );
            }
        }
        for (repetition, u_power_vector) in u_powers.iter().enumerate() {
            let alpha_value =
                &challenges.lincheck_alpha[key_position * LINCHECK_REPETITIONS + repetition];
            let v_vector = negacyclic_transpose_product_extension_matrix(
                &tower,
                &combined_public_sample,
                u_power_vector,
                modulus,
            )?;
            if key.kind.has_diagonal_source() {
                let diagonal_vector =
                    key.diagonal_source_vector_extension(limb_index, u_power_vector, modulus)?;
                let gamma_limb_power = &gamma_powers[limb_index];
                for coefficient_index in 0..ring_degree {
                    let factor = tower.sub(
                        &v_vector[coefficient_index],
                        &tower.mul(gamma_limb_power, &diagonal_vector[coefficient_index]),
                    );
                    secret_factor[repetition][coefficient_index] = tower.add(
                        &secret_factor[repetition][coefficient_index],
                        &tower.mul(alpha_value, &factor),
                    );
                }
            } else {
                for (secret_factor_value, v_value) in
                    secret_factor[repetition].iter_mut().zip(v_vector.iter())
                {
                    *secret_factor_value =
                        tower.add(secret_factor_value, &tower.mul(alpha_value, v_value));
                }
            }
            let mut component_dot = ChallengeExtensionTower::zero();
            for (u_value, component_value) in u_power_vector.iter().zip(combined_component.iter()) {
                component_dot = tower.add(&component_dot, &tower.mul(u_value, component_value));
            }
            let lincheck_sum = tower.sub(&ChallengeExtensionTower::zero(), &component_dot);
            lincheck_claim = tower.add(&lincheck_claim, &tower.mul(alpha_value, &lincheck_sum));
            for (digit_index, gamma_power) in gamma_powers.iter().enumerate() {
                error_weights[repetition][error_cursor + digit_index] =
                    tower.mul(alpha_value, gamma_power);
            }
        }
        error_cursor += digit_count;
    }
    // Mask selector combinations: each claim contributes alpha' * 2^digit at
    // its mask slots, and alpha' * masked claim to the combined sum.
    let mut mask_selectors = vec![extension_zero_vector(); layout.mask_column_count];
    let mut combined_claim = lincheck_claim;
    for (local_claim, alpha_value) in challenges.consistency_alpha.iter().enumerate() {
        combined_claim = tower.add(
            &combined_claim,
            &tower.scale_base(alpha_value, masked_claims[local_claim]),
        );
        for digit_index in 0..CLAIM_MASK_DIGIT_COUNT {
            let (column, half, half_position) = layout.mask_slot(local_claim, digit_index);
            let position = half * layout.trace_size + half_position;
            let digit_weight =
                tower.scale_base(alpha_value, pow_mod(2, digit_index as u64, modulus)?);
            mask_selectors[column][position] =
                tower.add(&mask_selectors[column][position], &digit_weight);
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
            &tower,
            &u_powers,
            &challenges.linkage_alpha,
        )?;
        combined_claim = tower.add(&combined_claim, &linkage_claim);
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

fn extension_powers(
    tower: &ChallengeExtensionTower,
    base: &ChallengeExtensionElement,
    count: usize,
) -> Vec<ChallengeExtensionElement> {
    let mut powers = Vec::with_capacity(count);
    let mut power = ChallengeExtensionTower::one();
    for _ in 0..count {
        powers.push(power);
        power = tower.mul(&power, base);
    }

    powers
}

// Transpose action of the negacyclic matrix of an extension polynomial on an
// extension vector: expand both operands over the basis pairs, run the base
// transpose action per pair, and recombine through the tower basis products.
fn negacyclic_transpose_product_extension_matrix(
    tower: &ChallengeExtensionTower,
    matrix_polynomial: &[ChallengeExtensionElement],
    vector: &[ChallengeExtensionElement],
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let length = vector.len();
    let mut result = vec![ChallengeExtensionTower::zero(); length];
    let mut matrix_coordinate = vec![0_u64; matrix_polynomial.len()];
    let mut vector_coordinate = vec![0_u64; length];
    for matrix_basis in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in matrix_coordinate.iter_mut().zip(matrix_polynomial.iter()) {
            *slot = element[matrix_basis];
        }
        let mut matrix_basis_element = ChallengeExtensionTower::zero();
        matrix_basis_element[matrix_basis] = 1;
        for vector_basis in 0..CHALLENGE_EXTENSION_DEGREE {
            for (slot, element) in vector_coordinate.iter_mut().zip(vector.iter()) {
                *slot = element[vector_basis];
            }
            let transposed =
                negacyclic_transpose_product(&matrix_coordinate, &vector_coordinate, modulus)?;
            let mut vector_basis_element = ChallengeExtensionTower::zero();
            vector_basis_element[vector_basis] = 1;
            let basis_product = tower.mul(&matrix_basis_element, &vector_basis_element);
            for (target, value) in result.iter_mut().zip(transposed.iter()) {
                *target = tower.add(target, &tower.scale_base(&basis_product, *value));
            }
        }
    }

    Ok(result)
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

// The same split-and-extend for an extension-valued public vector, applied
// per challenge extension coordinate.
fn extend_logical_vector_extension(
    plan: &EvaluationDomainPlan,
    vector: &[ChallengeExtensionElement],
) -> [Vec<ChallengeExtensionElement>; 2] {
    let extension_size = plan.extension_size;
    let mut halves = [
        vec![ChallengeExtensionTower::zero(); extension_size],
        vec![ChallengeExtensionTower::zero(); extension_size],
    ];
    let mut coordinate_vector = vec![0_u64; vector.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in coordinate_vector.iter_mut().zip(vector.iter()) {
            *slot = element[coordinate];
        }
        let extended = extend_logical_vector(plan, &coordinate_vector);
        for (half, extended_half) in halves.iter_mut().zip(extended.iter()) {
            for (target, value) in half.iter_mut().zip(extended_half.iter()) {
                target[coordinate] = *value;
            }
        }
    }

    halves
}

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

fn validate_witness_support(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<()> {
    if let Some(private_vss_share) = &statement.private_vss_share {
        if !witness.secret_coefficients.is_empty()
            || !witness.error_coefficients_by_key.is_empty()
            || !witness.negative_indicator_coefficients.is_empty()
            || !witness.opening_randomness_by_limb.is_empty()
        {
            return Err(invalid_succinct_setup_proof(
                "private VSS witness must not include key or same-secret linkage material",
            ));
        }
        return validate_private_vss_witness(private_vss_share, witness, statement.ring_degree);
    }
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
                    columns.len()
                        != crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH
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

fn validate_private_vss_witness(
    statement: &super::relation::PrivateVssShareStatement,
    witness: &TrusteeEvaluationKeyWitness,
    ring_degree: usize,
) -> CanonicalResult<()> {
    let coefficient_count = statement.coefficient_commitments.len();
    if witness
        .private_vss_coefficient_messages_by_shamir_index
        .len()
        != coefficient_count
        || witness.private_vss_opening_randomness_by_shamir_index.len() != coefficient_count
        || witness.private_vss_carry_witnesses.len() != ring_degree
    {
        return Err(invalid_succinct_setup_proof(
            "private VSS witness shape does not match the statement",
        ));
    }
    let source_modulus_i64 = i64::try_from(statement.source_message_modulus)
        .map_err(|_| invalid_succinct_setup_proof("private VSS source modulus does not fit i64"))?;
    for (coefficient_index, (messages, randomness_columns)) in witness
        .private_vss_coefficient_messages_by_shamir_index
        .iter()
        .zip(
            witness
                .private_vss_opening_randomness_by_shamir_index
                .iter(),
        )
        .enumerate()
    {
        if messages.len() != ring_degree
            || messages
                .iter()
                .any(|coefficient| *coefficient < 0 || *coefficient >= source_modulus_i64)
            || randomness_columns.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || randomness_columns.iter().any(|column| {
                column.len() != ring_degree
                    || column
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
            })
        {
            return Err(invalid_succinct_setup_proof(format!(
                "private VSS witness for Shamir coefficient {coefficient_index} has the wrong shape"
            )));
        }
    }
    let carry_bound = private_vss_share_lifted_carry_bound(
        statement.recipient_roster_position,
        coefficient_count,
    )?;
    for carry in &witness.private_vss_carry_witnesses {
        let carry_i128 = i128::from(*carry);
        if carry_i128 < 0 || carry_i128 > carry_bound {
            return Err(invalid_succinct_setup_proof(
                "private VSS carry witness is outside the accepted bound",
            ));
        }
    }
    let trustee_point = i128::from(crate::bgv::setup::sharing::canonical_trustee_point(
        usize::try_from(statement.recipient_roster_position).map_err(|_| {
            invalid_succinct_setup_proof("private VSS recipient roster position does not fit usize")
        })?,
        statement.source_message_modulus,
    )?);
    let mut powers = Vec::with_capacity(coefficient_count);
    let mut power = 1_i128;
    for _ in 0..coefficient_count {
        powers.push(power);
        power = power
            .checked_mul(trustee_point)
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS point power overflowed"))?;
    }
    for coefficient_position in 0..ring_degree {
        let mut left = 0_i128;
        for (messages, trustee_point_power) in witness
            .private_vss_coefficient_messages_by_shamir_index
            .iter()
            .zip(powers.iter())
        {
            left = left
                .checked_add(
                    trustee_point_power
                        .checked_mul(i128::from(messages[coefficient_position]))
                        .ok_or_else(|| {
                            invalid_succinct_setup_proof(
                                "private VSS lifted message product overflowed",
                            )
                        })?,
                )
                .ok_or_else(|| invalid_succinct_setup_proof("private VSS lifted sum overflowed"))?;
        }
        left = left
            .checked_sub(
                i128::from(statement.source_message_modulus)
                    .checked_mul(i128::from(
                        witness.private_vss_carry_witnesses[coefficient_position],
                    ))
                    .ok_or_else(|| {
                        invalid_succinct_setup_proof("private VSS lifted carry overflowed")
                    })?,
            )
            .ok_or_else(|| {
                invalid_succinct_setup_proof("private VSS lifted relation overflowed")
            })?;
        if left != i128::from(statement.share_values[coefficient_position]) {
            return Err(invalid_succinct_setup_proof(format!(
                "private VSS lifted relation failed at coefficient {coefficient_position}"
            )));
        }
    }

    Ok(())
}

// The shared global claim integers: for every statement-global witness
// vector and consistency repetition, the clear integer combination of the
// signed witness plus the shared smudging mask. Every limb publishes the
// residues of these integers, so the cross-limb binding is integer equality
// recovered by lifting from two limb fields.
fn global_claim_integers(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    consistency_vectors: &[Vec<u64>],
    proof_randomness_seed_hex: &str,
) -> Vec<i128> {
    let mut signed_vectors: Vec<&[i64]> = Vec::new();
    if statement.private_vss_share.is_some() {
        // The message (Shamir coefficient) columns carry no consistency claim:
        // they are pinned across the commitment fields by the opening rows plus
        // the opening-randomness consistency, so masking them would only add
        // zero-knowledge leakage with no soundness gain. Only the carry and the
        // opening-randomness columns are claimed. This order must match
        // consistency_vector_count and the consistency loop in relation.rs
        // ([carry, opening-randomness...]).
        signed_vectors.push(&witness.private_vss_carry_witnesses);
        for randomness_columns in &witness.private_vss_opening_randomness_by_shamir_index {
            for column in randomness_columns {
                signed_vectors.push(column);
            }
        }
    } else {
        signed_vectors.push(&witness.secret_coefficients);
        for error_vectors in &witness.error_coefficients_by_key {
            for error_vector in error_vectors {
                signed_vectors.push(error_vector);
            }
        }
        if statement.same_secret_linkage.is_some() {
            signed_vectors.push(&witness.negative_indicator_coefficients);
            for randomness_columns in &witness.opening_randomness_by_limb {
                for column in randomness_columns {
                    signed_vectors.push(column);
                }
            }
        }
    }
    let mut integers = Vec::with_capacity(signed_vectors.len() * CONSISTENCY_REPETITIONS);
    for signed_vector in &signed_vectors {
        for consistency_vector in consistency_vectors {
            let global_id = integers.len() as u64;
            let mut clear_sum = 0_i128;
            for (coefficient, combination) in signed_vector.iter().zip(consistency_vector.iter()) {
                clear_sum += i128::from(*coefficient) * i128::from(*combination);
            }
            let bits = claim_mask_bits(proof_randomness_seed_hex, global_id);
            let mut mask_integer = 0_i128;
            for (digit_index, bit) in bits.iter().enumerate() {
                if *bit == 1 {
                    mask_integer += 1_i128 << digit_index;
                }
            }
            integers.push(clear_sum + mask_integer);
        }
    }

    integers
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
