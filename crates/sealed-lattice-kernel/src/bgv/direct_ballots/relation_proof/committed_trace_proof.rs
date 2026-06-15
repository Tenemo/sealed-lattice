use super::*;
use crate::bgv::{
    evaluator::prg::DeterministicSampler,
    modular_arithmetic::{add_mod_fast, mul_mod_fast, pow_mod, sub_mod_fast},
    polynomial_iop::{
        COMMITMENT_BOUND_FACTOR, DEEP_POINT_COUNT, LOW_DEGREE_QUERY_COUNT,
        evaluation_domain::EvaluationDomainPlan,
        extension_field::{
            CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement, ChallengeExtensionTower,
        },
        fiat_shamir_transcript::FiatShamirTranscript,
        low_degree_proof::{
            LowDegreePairOpening, LowDegreeParameters, LowDegreeProof, LowDegreeQueryOpening,
            prove_low_degree, verify_low_degree,
        },
        merkle_commitment::{
            BatchedMerkleOpening, LEAF_SALT_BYTES, MerkleTree, consistent_sorted_leaves, leaf_hash,
            sorted_unique_indices, verify_merkle_batch,
        },
    },
};

const DIRECT_BALLOT_COMMITTED_TRACE_PROOF_MAGIC: &[u8; 8] = b"SLDCTP02";
const DIRECT_BALLOT_COMMITTED_TRACE_TRANSCRIPT_LABEL: &str =
    "direct-encrypted-ballot-committed-trace";
const DIRECT_BALLOT_COMMITTED_TRACE_COLUMN_MASK_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/committed-trace-column-mask-v1";
const DIRECT_BALLOT_COMMITTED_TRACE_LEAF_SALT_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/committed-trace-leaf-salt-v1";
const DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF: usize = 108;
const DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT: usize =
    DIRECT_BALLOT_COMMITTED_TRACE_SPLIT * DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF;
const DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS: usize = 1;
const DIRECT_BALLOT_COMMITTED_SHIFTED_LINEAR_ACCUMULATOR_COLUMNS: usize = 1;
const DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS: usize = 2;
const DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS: usize =
    DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS * CHALLENGE_EXTENSION_DEGREE;

struct DirectBallotCommittedTraceProof {
    limb_proofs: Vec<DirectBallotCommittedTraceLimbProof>,
}

struct DirectBallotCommittedTraceLimbProof {
    witness_tree_root: [u8; 64],
    accumulator_tree_root: [u8; 64],
    quotient_tree_root: [u8; 64],
    deep_evaluations: Vec<Vec<ChallengeExtensionElement>>,
    low_degree: LowDegreeProof,
    query_openings: Vec<DirectBallotCommittedTraceQueryOpening>,
    witness_batch_opening: BatchedMerkleOpening,
    accumulator_batch_opening: BatchedMerkleOpening,
    quotient_batch_opening: BatchedMerkleOpening,
}

struct DirectBallotCommittedTraceQueryOpening {
    witness_rows: [Vec<u64>; 2],
    witness_salts: [Vec<u8>; 2],
    accumulator_rows: [Vec<u64>; 4],
    accumulator_salts: [Vec<u8>; 4],
    quotient_rows: [Vec<u64>; 2],
    quotient_salts: [Vec<u8>; 2],
}

struct DirectBallotCommittedTraceLimbCommitment {
    plan: EvaluationDomainPlan,
    trace_columns: Vec<Vec<u64>>,
    masked_coefficients: Vec<Vec<u64>>,
    extension_columns: Vec<Vec<u64>>,
    salted: SaltedTree,
}

struct DirectBallotCommittedTraceLinearClaim {
    coefficient_trace_columns: Vec<Vec<u64>>,
    coefficient_coefficients: Vec<Vec<u64>>,
    coefficient_extension_columns: Vec<Vec<u64>>,
    last_selector_coefficients: Vec<u64>,
    last_selector_extension: Vec<u64>,
    public_offset: u64,
}

struct DirectBallotCommittedTraceAccumulatorCommitment {
    masked_coefficients: Vec<Vec<u64>>,
    shifted_masked_coefficients: Vec<Vec<u64>>,
    extension_columns: Vec<Vec<u64>>,
    shifted_extension_columns: Vec<Vec<u64>>,
    salted: SaltedTree,
}

struct CommittedTraceBatchReconstructionInput<'a> {
    plan: &'a EvaluationDomainPlan,
    tower: &'a ChallengeExtensionTower,
    deep_points: &'a [ChallengeExtensionElement],
    deep_evaluations: &'a [Vec<ChallengeExtensionElement>],
    lambda: &'a [ChallengeExtensionElement],
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

pub(super) fn generate_direct_ballot_committed_trace_proof_bytes(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    witness_vector: &DirectBallotWitnessVector,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let mut witness_tree_roots = Vec::with_capacity(DATA_PRIMES.len());
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let commitment = build_committed_trace_limb_commitment(
            witness_vector,
            limb_index,
            modulus,
            proof_randomness_seed_hex,
        )?;
        witness_tree_roots.push(commitment.salted.tree.root());
    }

    let mut transcript = FiatShamirTranscript::new(DIRECT_BALLOT_COMMITTED_TRACE_TRANSCRIPT_LABEL);
    transcript.absorb("statement", statement_hash);
    for witness_tree_root in &witness_tree_roots {
        transcript.absorb("witness-tree-root", witness_tree_root);
    }

    let mut limb_proofs = Vec::with_capacity(DATA_PRIMES.len());
    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        let commitment = build_committed_trace_limb_commitment(
            witness_vector,
            limb_index,
            modulus,
            proof_randomness_seed_hex,
        )?;
        if commitment.salted.tree.root() != witness_tree_roots[limb_index] {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace witness root is not deterministic",
            ));
        }
        limb_proofs.push(prove_committed_trace_limb(
            statement_hash,
            public_key,
            ballot,
            limb_index,
            &commitment,
            proof_randomness_seed_hex,
            &transcript,
        )?);
    }

    encode_direct_ballot_committed_trace_proof(
        &DirectBallotCommittedTraceProof { limb_proofs },
        &DATA_PRIMES,
    )
}

pub(super) fn verify_direct_ballot_committed_trace_proof_bytes(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let proof = decode_direct_ballot_committed_trace_proof(proof_bytes, &DATA_PRIMES)?;
    if proof.limb_proofs.len() != DATA_PRIMES.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof limb count does not match the profile",
        ));
    }

    let mut transcript = FiatShamirTranscript::new(DIRECT_BALLOT_COMMITTED_TRACE_TRANSCRIPT_LABEL);
    transcript.absorb("statement", statement_hash);
    for limb_proof in &proof.limb_proofs {
        transcript.absorb("witness-tree-root", &limb_proof.witness_tree_root);
    }

    for (limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
        verify_committed_trace_limb(
            statement_hash,
            public_key,
            ballot,
            limb_index,
            modulus,
            &proof.limb_proofs[limb_index],
            &transcript,
        )
        .map_err(|error| invalid_direct_ballot_relation_proof(error.message))?;
    }

    Ok(())
}

fn build_committed_trace_limb_commitment(
    witness_vector: &DirectBallotWitnessVector,
    limb_index: usize,
    modulus: u64,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotCommittedTraceLimbCommitment> {
    let logical_columns = direct_ballot_committed_witness_columns(witness_vector, modulus)?;
    let physical_columns = direct_ballot_committed_physical_columns(&logical_columns, modulus)?;
    let trace_size = direct_ballot_committed_trace_size()?;
    let plan = EvaluationDomainPlan::new(modulus, trace_size)?;

    let mut masked_coefficients = Vec::with_capacity(physical_columns.len());
    let mut extension_columns = Vec::with_capacity(physical_columns.len());
    for (physical_column, trace_values) in physical_columns.iter().enumerate() {
        let mut mask_sampler = DeterministicSampler::new(
            DIRECT_BALLOT_COMMITTED_TRACE_COLUMN_MASK_DOMAIN,
            &[
                proof_randomness_seed_hex.as_bytes(),
                &(limb_index as u64).to_le_bytes(),
                &(physical_column as u64).to_le_bytes(),
            ],
        );
        let coefficients = masked_trace_coefficients(&plan, trace_values, &mut mask_sampler);
        extension_columns.push(plan.extension_evaluations_from_coefficients(&coefficients));
        masked_coefficients.push(coefficients);
    }

    let mut salt_sampler = DeterministicSampler::new(
        DIRECT_BALLOT_COMMITTED_TRACE_LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"witness",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let salted =
        commit_salted_extension_rows(&extension_columns, plan.extension_size, &mut salt_sampler)?;

    Ok(DirectBallotCommittedTraceLimbCommitment {
        plan,
        trace_columns: physical_columns,
        masked_coefficients,
        extension_columns,
        salted,
    })
}

fn masked_trace_coefficients(
    plan: &EvaluationDomainPlan,
    trace_values: &[u64],
    mask_sampler: &mut DeterministicSampler,
) -> Vec<u64> {
    let trace_size = plan.trace_size;
    let mask_degree = column_mask_degree(trace_size);
    let mut coefficients = plan.coefficients_from_trace_values(trace_values);
    coefficients.resize(trace_size + mask_degree, 0);
    let mask = mask_sampler.uniform_residues(plan.modulus, mask_degree);
    for (index, mask_value) in mask.iter().enumerate() {
        coefficients[index] = sub_mod_fast(coefficients[index], *mask_value, plan.modulus);
        coefficients[trace_size + index] =
            add_mod_fast(coefficients[trace_size + index], *mask_value, plan.modulus);
    }

    coefficients
}

fn column_mask_degree(trace_size: usize) -> usize {
    512.min(trace_size / 4)
}

fn commit_salted_extension_rows(
    extension_columns: &[Vec<u64>],
    extension_size: usize,
    salt_sampler: &mut DeterministicSampler,
) -> CanonicalResult<SaltedTree> {
    let salts = salt_sampler.bytes(extension_size * LEAF_SALT_BYTES);
    let mut row = vec![0_u64; extension_columns.len()];
    let mut leaf_hashes = Vec::with_capacity(extension_size);
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

fn prove_committed_trace_limb(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    limb_index: usize,
    commitment: &DirectBallotCommittedTraceLimbCommitment,
    proof_randomness_seed_hex: &str,
    global_transcript: &FiatShamirTranscript,
) -> CanonicalResult<DirectBallotCommittedTraceLimbProof> {
    let plan = &commitment.plan;
    let modulus = plan.modulus;
    let trace_size = plan.trace_size;
    let extension_size = plan.extension_size;
    let base_witness_columns = commitment.extension_columns.len();
    let mut transcript = global_transcript.fork("limb", limb_index as u64);
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let encoder_carry_bound =
        direct_ballot_encoder_arithmetic_bounds()?.encoding_carry_coefficient_maximum;
    verify_direct_ballot_committed_encoder_carry_bound(encoder_carry_bound)?;
    let projected_bgv_carry_bound =
        direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()?;
    verify_direct_ballot_committed_projected_bgv_carry_bound(projected_bgv_carry_bound, modulus)?;
    let linear_challenge_count = direct_ballot_committed_batched_linear_claim_challenge_count(
        statement_hash,
        public_key,
        ballot,
        limb_index,
    )?;
    let linear_claim_challenges =
        transcript.challenge_field_elements("linear-claim-alpha", modulus, linear_challenge_count);
    let linear_claim = build_committed_trace_linear_claim(
        plan,
        statement_hash,
        public_key,
        ballot,
        limb_index,
        modulus,
        &linear_claim_challenges,
    )?;
    let accumulator = build_committed_trace_accumulator_commitment(
        plan,
        &commitment.trace_columns,
        &linear_claim,
        limb_index,
        proof_randomness_seed_hex,
    )?;
    transcript.absorb("accumulator-tree-root", &accumulator.salted.tree.root());
    let row_check_alpha = transcript.challenge_extension_elements(
        "support-row-alpha",
        modulus,
        DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT,
    );
    let linear_row_alpha =
        transcript.challenge_extension_elements("linear-row-alpha", modulus, 1)[0];
    let phase_one_extension_columns = committed_trace_phase_one_extension_columns(
        &commitment.extension_columns,
        &accumulator.extension_columns,
        &accumulator.shifted_extension_columns,
    )?;

    let mut row_check_extension = Vec::with_capacity(extension_size);
    let mut row = vec![0_u64; base_witness_columns];
    let mut coefficient_row = vec![0_u64; base_witness_columns];
    for position in 0..extension_size {
        for (column_index, column) in commitment.extension_columns.iter().enumerate() {
            row[column_index] = column[position];
        }
        for (column_index, column) in linear_claim
            .coefficient_extension_columns
            .iter()
            .enumerate()
        {
            coefficient_row[column_index] = column[position];
        }
        let support_value = committed_support_row_check_value_base(
            &tower,
            &row,
            &row_check_alpha,
            modulus,
            encoder_carry_bound,
            projected_bgv_carry_bound,
        )?;
        let linear_value = committed_trace_linear_accumulator_row_check_value_base(
            &row,
            &coefficient_row,
            accumulator.extension_columns[0][position],
            accumulator.shifted_extension_columns[0][position],
            linear_claim.last_selector_extension[position],
            linear_claim.public_offset,
            modulus,
        )?;
        row_check_extension.push(tower.add(
            &support_value,
            &tower.scale_base(&linear_row_alpha, linear_value),
        ));
    }

    let commitment_bound = COMMITMENT_BOUND_FACTOR * trace_size;
    let mut row_quotient_low = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
    let mut row_quotient_high = vec![Vec::new(); CHALLENGE_EXTENSION_DEGREE];
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
        if let Some((remainder_index, remainder_value)) = remainder
            .iter()
            .enumerate()
            .find(|(_index, value)| **value != 0)
        {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot committed trace witness does not satisfy the committed row constraints at coordinate {coordinate} remainder {remainder_index} value {remainder_value}",
            )));
        }
        let mut low = quotient.clone();
        low.truncate(commitment_bound);
        let high = if quotient.len() > commitment_bound {
            quotient[commitment_bound..].to_vec()
        } else {
            Vec::new()
        };
        if high.len() > commitment_bound {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace row quotient exceeds the commitment bound",
            ));
        }
        row_quotient_low[coordinate] = low;
        row_quotient_high[coordinate] = high;
    }

    let mut quotient_columns =
        vec![Vec::new(); DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS];
    for (coordinate, coefficients) in row_quotient_low.iter().enumerate() {
        quotient_columns[coordinate] = plan.extension_evaluations_from_coefficients(coefficients);
    }
    for (coordinate, coefficients) in row_quotient_high.iter().enumerate() {
        quotient_columns[CHALLENGE_EXTENSION_DEGREE + coordinate] =
            plan.extension_evaluations_from_coefficients(coefficients);
    }
    let mut quotient_salt_sampler = DeterministicSampler::new(
        DIRECT_BALLOT_COMMITTED_TRACE_LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"quotient",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let quotient_salted = commit_salted_extension_rows(
        &quotient_columns,
        extension_size,
        &mut quotient_salt_sampler,
    )?;
    transcript.absorb("quotient-tree-root", &quotient_salted.tree.root());

    let deep_points = sample_deep_points(&mut transcript, plan)?;
    let mut deep_evaluations = Vec::with_capacity(DEEP_POINT_COUNT);
    let coefficient_length = commitment
        .masked_coefficients
        .iter()
        .chain(accumulator.masked_coefficients.iter())
        .chain(accumulator.shifted_masked_coefficients.iter())
        .map(Vec::len)
        .chain(row_quotient_low.iter().map(Vec::len))
        .chain(row_quotient_high.iter().map(Vec::len))
        .max()
        .unwrap_or(0);
    for point in &deep_points {
        let point_powers = extension_powers(&tower, point, coefficient_length);
        let evaluate_base = |coefficients: &[u64]| {
            let mut accumulated = ChallengeExtensionTower::zero();
            for (coefficient, power) in coefficients.iter().zip(point_powers.iter()) {
                accumulated = tower.add(&accumulated, &tower.scale_base(power, *coefficient));
            }
            accumulated
        };
        let mut evaluations = Vec::with_capacity(
            phase_one_extension_columns.len() + DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS,
        );
        for coefficients in &commitment.masked_coefficients {
            evaluations.push(evaluate_base(coefficients));
        }
        for coefficients in &accumulator.masked_coefficients {
            evaluations.push(evaluate_base(coefficients));
        }
        for coefficients in &accumulator.shifted_masked_coefficients {
            evaluations.push(evaluate_base(coefficients));
        }
        for quotient_coordinates in [&row_quotient_low, &row_quotient_high] {
            let mut quotient_value = ChallengeExtensionTower::zero();
            for (coordinate, coefficients) in quotient_coordinates.iter().enumerate() {
                let coordinate_evaluation = evaluate_base(coefficients);
                let mut basis_element = ChallengeExtensionTower::zero();
                basis_element[coordinate] = 1;
                quotient_value = tower.add(
                    &quotient_value,
                    &tower.mul(&basis_element, &coordinate_evaluation),
                );
            }
            evaluations.push(quotient_value);
        }
        deep_evaluations.push(evaluations);
    }
    for evaluations in &deep_evaluations {
        transcript.absorb_u64_slice(
            "deep-evaluations",
            &evaluations.iter().flatten().copied().collect::<Vec<_>>(),
        );
    }

    let total_column_count =
        phase_one_extension_columns.len() + DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS;
    let lambda = transcript.challenge_extension_elements(
        "lambda",
        modulus,
        total_column_count * DEEP_POINT_COUNT,
    );
    let batch_codeword = committed_trace_batch_codeword(
        plan,
        &tower,
        &deep_points,
        &deep_evaluations,
        &lambda,
        &phase_one_extension_columns,
        &quotient_columns,
    )?;

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
        .map(|position| {
            let first_shifted_position = shifted_extension_position(*position, extension_size);
            let second_position = *position + half;
            let second_shifted_position =
                shifted_extension_position(second_position, extension_size);
            DirectBallotCommittedTraceQueryOpening {
                witness_rows: [
                    collect_row(&commitment.extension_columns, *position),
                    collect_row(&commitment.extension_columns, second_position),
                ],
                witness_salts: [
                    commitment.salted.salt(*position).to_vec(),
                    commitment.salted.salt(second_position).to_vec(),
                ],
                accumulator_rows: [
                    collect_row(&accumulator.extension_columns, *position),
                    collect_row(&accumulator.extension_columns, first_shifted_position),
                    collect_row(&accumulator.extension_columns, second_position),
                    collect_row(&accumulator.extension_columns, second_shifted_position),
                ],
                accumulator_salts: [
                    accumulator.salted.salt(*position).to_vec(),
                    accumulator.salted.salt(first_shifted_position).to_vec(),
                    accumulator.salted.salt(second_position).to_vec(),
                    accumulator.salted.salt(second_shifted_position).to_vec(),
                ],
                quotient_rows: [
                    collect_row(&quotient_columns, *position),
                    collect_row(&quotient_columns, second_position),
                ],
                quotient_salts: [
                    quotient_salted.salt(*position).to_vec(),
                    quotient_salted.salt(second_position).to_vec(),
                ],
            }
        })
        .collect::<Vec<_>>();
    let witness_opened_indices = sorted_unique_indices(
        query_positions
            .iter()
            .flat_map(|position| [*position, *position + half]),
    );
    let accumulator_opened_indices =
        sorted_unique_indices(query_positions.iter().flat_map(|position| {
            let second_position = *position + half;
            [
                *position,
                shifted_extension_position(*position, extension_size),
                second_position,
                shifted_extension_position(second_position, extension_size),
            ]
        }));

    Ok(DirectBallotCommittedTraceLimbProof {
        witness_tree_root: commitment.salted.tree.root(),
        accumulator_tree_root: accumulator.salted.tree.root(),
        quotient_tree_root: quotient_salted.tree.root(),
        deep_evaluations,
        low_degree,
        query_openings,
        witness_batch_opening: commitment.salted.tree.open_batch(&witness_opened_indices),
        accumulator_batch_opening: accumulator
            .salted
            .tree
            .open_batch(&accumulator_opened_indices),
        quotient_batch_opening: quotient_salted.tree.open_batch(&witness_opened_indices),
    })
}

fn verify_committed_trace_limb(
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    limb_index: usize,
    modulus: u64,
    limb_proof: &DirectBallotCommittedTraceLimbProof,
    global_transcript: &FiatShamirTranscript,
) -> CanonicalResult<()> {
    let trace_size = direct_ballot_committed_trace_size()?;
    let plan = EvaluationDomainPlan::new(modulus, trace_size)?;
    let tower = ChallengeExtensionTower::for_modulus(modulus)?;
    let encoder_carry_bound =
        direct_ballot_encoder_arithmetic_bounds()?.encoding_carry_coefficient_maximum;
    verify_direct_ballot_committed_encoder_carry_bound(encoder_carry_bound)?;
    let projected_bgv_carry_bound =
        direct_ballot_projected_bgv_no_wrap_committed_carry_maximum_abs()?;
    verify_direct_ballot_committed_projected_bgv_carry_bound(projected_bgv_carry_bound, modulus)?;
    let base_witness_columns =
        DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT;
    let phase_one_columns = base_witness_columns
        + DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS
        + DIRECT_BALLOT_COMMITTED_SHIFTED_LINEAR_ACCUMULATOR_COLUMNS;
    let total_column_count = phase_one_columns + DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS;
    if limb_proof.deep_evaluations.len() != DEEP_POINT_COUNT
        || limb_proof
            .deep_evaluations
            .iter()
            .any(|evaluations| evaluations.len() != total_column_count)
        || limb_proof.query_openings.len() != LOW_DEGREE_QUERY_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof shape does not match the profile",
        ));
    }

    let mut transcript = global_transcript.fork("limb", limb_index as u64);
    let linear_challenge_count = direct_ballot_committed_batched_linear_claim_challenge_count(
        statement_hash,
        public_key,
        ballot,
        limb_index,
    )?;
    let linear_claim_challenges =
        transcript.challenge_field_elements("linear-claim-alpha", modulus, linear_challenge_count);
    let linear_claim = build_committed_trace_linear_claim(
        &plan,
        statement_hash,
        public_key,
        ballot,
        limb_index,
        modulus,
        &linear_claim_challenges,
    )?;
    transcript.absorb("accumulator-tree-root", &limb_proof.accumulator_tree_root);
    let row_check_alpha = transcript.challenge_extension_elements(
        "support-row-alpha",
        modulus,
        DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT,
    );
    let linear_row_alpha =
        transcript.challenge_extension_elements("linear-row-alpha", modulus, 1)[0];
    transcript.absorb("quotient-tree-root", &limb_proof.quotient_tree_root);
    let deep_points = sample_deep_points(&mut transcript, &plan)?;
    let bound_power = (COMMITMENT_BOUND_FACTOR * trace_size) as u64;
    for (point_index, point) in deep_points.iter().enumerate() {
        let evaluations = &limb_proof.deep_evaluations[point_index];
        let base_witness_values = &evaluations[..base_witness_columns];
        let accumulator_value = &evaluations[base_witness_columns];
        let shifted_accumulator_value = &evaluations[base_witness_columns + 1];
        let quotient_low = &evaluations[phase_one_columns];
        let quotient_high = &evaluations[phase_one_columns + 1];
        let shifted_quotient = tower.add(
            quotient_low,
            &tower.mul(&tower.pow(point, bound_power), quotient_high),
        );
        let coefficient_values = evaluate_public_coefficients_at_extension_point(
            &tower,
            point,
            &linear_claim.coefficient_coefficients,
        );
        let last_selector_value = evaluate_public_coefficients_at_extension_point(
            &tower,
            point,
            std::slice::from_ref(&linear_claim.last_selector_coefficients),
        )
        .remove(0);
        let support_value = committed_support_row_check_value(
            &tower,
            base_witness_values,
            &row_check_alpha,
            modulus,
            encoder_carry_bound,
            projected_bgv_carry_bound,
        )?;
        let linear_value = committed_trace_linear_accumulator_row_check_value(
            &tower,
            base_witness_values,
            &coefficient_values,
            accumulator_value,
            shifted_accumulator_value,
            &last_selector_value,
            linear_claim.public_offset,
        )?;
        let row_check_value =
            tower.add(&support_value, &tower.mul(&linear_row_alpha, &linear_value));
        if row_check_value
            != tower.mul(
                &trace_vanishing_at_extension(&plan, &tower, point),
                &shifted_quotient,
            )
        {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace row identity failed at an out-of-domain point",
            ));
        }
    }
    for evaluations in &limb_proof.deep_evaluations {
        transcript.absorb_u64_slice(
            "deep-evaluations",
            &evaluations.iter().flatten().copied().collect::<Vec<_>>(),
        );
    }
    let lambda = transcript.challenge_extension_elements(
        "lambda",
        modulus,
        total_column_count * DEEP_POINT_COUNT,
    );
    let low_degree_parameters = LowDegreeParameters {
        modulus,
        initial_domain_size: plan.extension_size,
        initial_offset: plan.coset_offset,
        initial_root: plan.extension_root,
        initial_degree_bound: COMMITMENT_BOUND_FACTOR * trace_size,
    };
    let half = plan.extension_size / 2;
    let mut witness_leaves = Vec::new();
    let mut accumulator_leaves = Vec::new();
    let mut quotient_leaves = Vec::new();
    let reconstruction_input = CommittedTraceBatchReconstructionInput {
        plan: &plan,
        tower: &tower,
        deep_points: &deep_points,
        deep_evaluations: &limb_proof.deep_evaluations,
        lambda: &lambda,
    };
    verify_low_degree(
        &mut transcript,
        &low_degree_parameters,
        &limb_proof.low_degree,
        |query_ordinal, pair_index| {
            let opening = &limb_proof.query_openings[query_ordinal];
            validate_query_opening_shape(opening, base_witness_columns)?;
            for (slot, position) in [pair_index, pair_index + half].into_iter().enumerate() {
                let shifted_position = shifted_extension_position(position, plan.extension_size);
                let accumulator_current_slot = slot * 2;
                let accumulator_shifted_slot = accumulator_current_slot + 1;
                witness_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.witness_salts[slot],
                        &opening.witness_rows[slot],
                    ),
                ));
                accumulator_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.accumulator_salts[accumulator_current_slot],
                        &opening.accumulator_rows[accumulator_current_slot],
                    ),
                ));
                accumulator_leaves.push((
                    shifted_position,
                    leaf_hash(
                        shifted_position,
                        &opening.accumulator_salts[accumulator_shifted_slot],
                        &opening.accumulator_rows[accumulator_shifted_slot],
                    ),
                ));
                quotient_leaves.push((
                    position,
                    leaf_hash(
                        position,
                        &opening.quotient_salts[slot],
                        &opening.quotient_rows[slot],
                    ),
                ));
            }
            let first_phase_row = committed_trace_phase_one_opening_row(
                &opening.witness_rows[0],
                &opening.accumulator_rows[0],
                &opening.accumulator_rows[1],
            )?;
            let second_phase_row = committed_trace_phase_one_opening_row(
                &opening.witness_rows[1],
                &opening.accumulator_rows[2],
                &opening.accumulator_rows[3],
            )?;
            Ok([
                reconstruct_committed_trace_batch_value(
                    &reconstruction_input,
                    &first_phase_row,
                    &opening.quotient_rows[0],
                    pair_index,
                )?,
                reconstruct_committed_trace_batch_value(
                    &reconstruction_input,
                    &second_phase_row,
                    &opening.quotient_rows[1],
                    pair_index + half,
                )?,
            ])
        },
    )?;

    let phase_tree_depth = plan.extension_size.trailing_zeros() as usize;
    let Some(witness_sorted_leaves) = consistent_sorted_leaves(witness_leaves) else {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace witness tree opens one position to two rows",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.witness_tree_root,
        phase_tree_depth,
        &witness_sorted_leaves,
        &limb_proof.witness_batch_opening,
    ) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace witness openings failed Merkle verification",
        ));
    }
    let Some(accumulator_sorted_leaves) = consistent_sorted_leaves(accumulator_leaves) else {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace accumulator tree opens one position to two rows",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.accumulator_tree_root,
        phase_tree_depth,
        &accumulator_sorted_leaves,
        &limb_proof.accumulator_batch_opening,
    ) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace accumulator openings failed Merkle verification",
        ));
    }
    let Some(quotient_sorted_leaves) = consistent_sorted_leaves(quotient_leaves) else {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace quotient tree opens one position to two rows",
        ));
    };
    if !verify_merkle_batch(
        &limb_proof.quotient_tree_root,
        phase_tree_depth,
        &quotient_sorted_leaves,
        &limb_proof.quotient_batch_opening,
    ) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace quotient openings failed Merkle verification",
        ));
    }

    Ok(())
}

fn validate_query_opening_shape(
    opening: &DirectBallotCommittedTraceQueryOpening,
    base_witness_columns: usize,
) -> CanonicalResult<()> {
    if opening.witness_rows[0].len() != base_witness_columns
        || opening.witness_rows[1].len() != base_witness_columns
        || opening
            .accumulator_rows
            .iter()
            .any(|row| row.len() != DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS)
        || opening.quotient_rows[0].len() != DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS
        || opening.quotient_rows[1].len() != DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS
        || opening
            .witness_salts
            .iter()
            .chain(opening.accumulator_salts.iter())
            .chain(opening.quotient_salts.iter())
            .any(|salt| salt.len() != LEAF_SALT_BYTES)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace query opening shape does not match the profile",
        ));
    }

    Ok(())
}

fn build_committed_trace_linear_claim(
    plan: &EvaluationDomainPlan,
    statement_hash: &[u8; 64],
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
    limb_index: usize,
    modulus: u64,
    batching_challenges: &[u64],
) -> CanonicalResult<DirectBallotCommittedTraceLinearClaim> {
    let batched_claim = direct_ballot_committed_batched_linear_claim(
        statement_hash,
        public_key,
        ballot,
        limb_index,
        modulus,
        batching_challenges,
    )?;
    let coefficient_trace_columns =
        direct_ballot_committed_physical_columns(&batched_claim.coefficient_columns, modulus)?;
    let mut coefficient_coefficients = Vec::with_capacity(coefficient_trace_columns.len());
    let mut coefficient_extension_columns = Vec::with_capacity(coefficient_trace_columns.len());
    for trace_column in &coefficient_trace_columns {
        let coefficients = plan.coefficients_from_trace_values(trace_column);
        coefficient_extension_columns
            .push(plan.extension_evaluations_from_coefficients(&coefficients));
        coefficient_coefficients.push(coefficients);
    }
    let mut last_selector_trace = vec![0_u64; plan.trace_size];
    let Some(last_selector) = last_selector_trace.last_mut() else {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace has an empty accumulator domain",
        ));
    };
    *last_selector = 1;
    let last_selector_coefficients = plan.coefficients_from_trace_values(&last_selector_trace);
    let last_selector_extension =
        plan.extension_evaluations_from_coefficients(&last_selector_coefficients);

    Ok(DirectBallotCommittedTraceLinearClaim {
        coefficient_trace_columns,
        coefficient_coefficients,
        coefficient_extension_columns,
        last_selector_coefficients,
        last_selector_extension,
        public_offset: batched_claim.public_offset,
    })
}

fn build_committed_trace_accumulator_commitment(
    plan: &EvaluationDomainPlan,
    witness_trace_columns: &[Vec<u64>],
    linear_claim: &DirectBallotCommittedTraceLinearClaim,
    limb_index: usize,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<DirectBallotCommittedTraceAccumulatorCommitment> {
    let contribution_trace_values = committed_trace_linear_contribution_trace_values(
        witness_trace_columns,
        &linear_claim.coefficient_trace_columns,
        plan.modulus,
    )?;
    let mut accumulator_trace_values = Vec::with_capacity(plan.trace_size);
    let mut running_sum = 0_u64;
    for contribution in contribution_trace_values {
        accumulator_trace_values.push(running_sum);
        running_sum = add_mod(running_sum, contribution, plan.modulus)?;
    }
    if add_mod(running_sum, linear_claim.public_offset, plan.modulus)? != 0 {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace accumulator does not close the batched linear claims",
        ));
    }

    let mut mask_sampler = DeterministicSampler::new(
        DIRECT_BALLOT_COMMITTED_TRACE_COLUMN_MASK_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"linear-accumulator",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let masked_coefficients =
        masked_trace_coefficients(plan, &accumulator_trace_values, &mut mask_sampler);
    let shifted_masked_coefficients = shifted_trace_coefficients(plan, &masked_coefficients)?;
    let extension_columns =
        vec![plan.extension_evaluations_from_coefficients(&masked_coefficients)];
    let shifted_extension_columns =
        vec![plan.extension_evaluations_from_coefficients(&shifted_masked_coefficients)];
    let mut salt_sampler = DeterministicSampler::new(
        DIRECT_BALLOT_COMMITTED_TRACE_LEAF_SALT_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"linear-accumulator",
            &(limb_index as u64).to_le_bytes(),
        ],
    );
    let salted =
        commit_salted_extension_rows(&extension_columns, plan.extension_size, &mut salt_sampler)?;

    Ok(DirectBallotCommittedTraceAccumulatorCommitment {
        masked_coefficients: vec![masked_coefficients],
        shifted_masked_coefficients: vec![shifted_masked_coefficients],
        extension_columns,
        shifted_extension_columns,
        salted,
    })
}

fn committed_trace_linear_contribution_trace_values(
    witness_trace_columns: &[Vec<u64>],
    coefficient_trace_columns: &[Vec<u64>],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if witness_trace_columns.len() != coefficient_trace_columns.len()
        || witness_trace_columns
            .iter()
            .chain(coefficient_trace_columns.iter())
            .any(|column| column.len() != witness_trace_columns[0].len())
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace linear contribution shape does not match the witness columns",
        ));
    }
    let trace_size = witness_trace_columns[0].len();
    let mut contributions = vec![0_u64; trace_size];
    for (witness_column, coefficient_column) in witness_trace_columns
        .iter()
        .zip(coefficient_trace_columns.iter())
    {
        for position in 0..trace_size {
            let product = mul_mod(
                witness_column[position],
                coefficient_column[position],
                modulus,
            )?;
            contributions[position] = add_mod(contributions[position], product, modulus)?;
        }
    }

    Ok(contributions)
}

fn shifted_trace_coefficients(
    plan: &EvaluationDomainPlan,
    coefficients: &[u64],
) -> CanonicalResult<Vec<u64>> {
    let trace_root = pow_mod(
        plan.extension_root,
        crate::bgv::polynomial_iop::DOMAIN_BLOWUP as u64,
        plan.modulus,
    )?;
    let mut shifted = Vec::with_capacity(coefficients.len());
    let mut multiplier = 1_u64;
    for coefficient in coefficients {
        shifted.push(mul_mod(*coefficient, multiplier, plan.modulus)?);
        multiplier = mul_mod(multiplier, trace_root, plan.modulus)?;
    }

    Ok(shifted)
}

fn committed_trace_phase_one_extension_columns(
    witness_columns: &[Vec<u64>],
    accumulator_columns: &[Vec<u64>],
    shifted_accumulator_columns: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if accumulator_columns.len() != DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS
        || shifted_accumulator_columns.len()
            != DIRECT_BALLOT_COMMITTED_SHIFTED_LINEAR_ACCUMULATOR_COLUMNS
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace accumulator column count does not match the profile",
        ));
    }
    let mut columns = Vec::with_capacity(
        witness_columns.len() + accumulator_columns.len() + shifted_accumulator_columns.len(),
    );
    columns.extend(witness_columns.iter().cloned());
    columns.extend(accumulator_columns.iter().cloned());
    columns.extend(shifted_accumulator_columns.iter().cloned());

    Ok(columns)
}

fn committed_trace_phase_one_opening_row(
    witness_row: &[u64],
    accumulator_row: &[u64],
    shifted_accumulator_row: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if accumulator_row.len() != DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS
        || shifted_accumulator_row.len()
            != DIRECT_BALLOT_COMMITTED_SHIFTED_LINEAR_ACCUMULATOR_COLUMNS
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace accumulator opening row does not match the profile",
        ));
    }
    let mut row = Vec::with_capacity(
        witness_row.len() + accumulator_row.len() + shifted_accumulator_row.len(),
    );
    row.extend_from_slice(witness_row);
    row.extend_from_slice(accumulator_row);
    row.extend_from_slice(shifted_accumulator_row);

    Ok(row)
}

fn shifted_extension_position(position: usize, extension_size: usize) -> usize {
    (position + crate::bgv::polynomial_iop::DOMAIN_BLOWUP) % extension_size
}

fn committed_trace_linear_accumulator_row_check_value_base(
    witness_row: &[u64],
    coefficient_row: &[u64],
    accumulator_value: u64,
    shifted_accumulator_value: u64,
    last_selector_value: u64,
    public_offset: u64,
    modulus: u64,
) -> CanonicalResult<u64> {
    let contribution =
        committed_trace_linear_contribution_value_base(witness_row, coefficient_row, modulus)?;
    let transition_difference = sub_mod(shifted_accumulator_value, accumulator_value, modulus)?;
    let expected_difference = add_mod(
        contribution,
        mul_mod(last_selector_value, public_offset, modulus)?,
        modulus,
    )?;
    sub_mod(transition_difference, expected_difference, modulus)
}

fn committed_trace_linear_contribution_value_base(
    witness_row: &[u64],
    coefficient_row: &[u64],
    modulus: u64,
) -> CanonicalResult<u64> {
    if witness_row.len() != coefficient_row.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace linear contribution row shape does not match the coefficients",
        ));
    }
    let mut contribution = 0_u64;
    for (witness_value, coefficient_value) in witness_row.iter().zip(coefficient_row.iter()) {
        contribution = add_mod(
            contribution,
            mul_mod(*witness_value, *coefficient_value, modulus)?,
            modulus,
        )?;
    }

    Ok(contribution)
}

fn committed_trace_linear_accumulator_row_check_value(
    tower: &ChallengeExtensionTower,
    witness_row: &[ChallengeExtensionElement],
    coefficient_row: &[ChallengeExtensionElement],
    accumulator_value: &ChallengeExtensionElement,
    shifted_accumulator_value: &ChallengeExtensionElement,
    last_selector_value: &ChallengeExtensionElement,
    public_offset: u64,
) -> CanonicalResult<ChallengeExtensionElement> {
    if witness_row.len() != coefficient_row.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace linear contribution row shape does not match the coefficients",
        ));
    }
    let mut contribution = ChallengeExtensionTower::zero();
    for (witness_value, coefficient_value) in witness_row.iter().zip(coefficient_row.iter()) {
        contribution = tower.add(&contribution, &tower.mul(witness_value, coefficient_value));
    }
    let transition_difference = tower.sub(shifted_accumulator_value, accumulator_value);
    let expected_difference = tower.add(
        &contribution,
        &tower.scale_base(last_selector_value, public_offset),
    );

    Ok(tower.sub(&transition_difference, &expected_difference))
}

fn evaluate_public_coefficients_at_extension_point(
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
    coefficient_columns: &[Vec<u64>],
) -> Vec<ChallengeExtensionElement> {
    let coefficient_length = coefficient_columns.iter().map(Vec::len).max().unwrap_or(0);
    let point_powers = extension_powers(tower, point, coefficient_length);
    coefficient_columns
        .iter()
        .map(|coefficients| {
            let mut value = ChallengeExtensionTower::zero();
            for (coefficient, power) in coefficients.iter().zip(point_powers.iter()) {
                value = tower.add(&value, &tower.scale_base(power, *coefficient));
            }
            value
        })
        .collect()
}

fn committed_support_row_check_value(
    tower: &ChallengeExtensionTower,
    row: &[ChallengeExtensionElement],
    alpha: &[ChallengeExtensionElement],
    modulus: u64,
    encoder_carry_bound: u64,
    projected_bgv_carry_bound: u64,
) -> CanonicalResult<ChallengeExtensionElement> {
    if row.len() != DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT
        || alpha.len() != DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed support row check shape does not match the profile",
        ));
    }
    let mut accumulated = ChallengeExtensionTower::zero();
    for half in 0..DIRECT_BALLOT_COMMITTED_TRACE_SPLIT {
        let alpha_offset = half * DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF;
        let randomizer = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN,
            half,
        )?];
        let first_error = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN,
            half,
        )?];
        let first_error_square = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_SQUARE_COLUMN,
            half,
        )?];
        let second_error = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN,
            half,
        )?];
        let second_error_square = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN,
            half,
        )?];
        let encoding_carry = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN,
            half,
        )?];
        let projected_bgv_carry = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN,
            half,
        )?];
        let one_hot = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN,
            half,
        )?];
        let mut constraints =
            Vec::with_capacity(DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF);
        constraints.push(extension_ternary_support_value(tower, &randomizer));
        constraints.push(tower.sub(&first_error_square, &tower.mul(&first_error, &first_error)));
        constraints.push(extension_centered_binomial_eta_two_support_value(
            tower,
            &first_error,
            &first_error_square,
            modulus,
        ));
        constraints.push(tower.sub(
            &second_error_square,
            &tower.mul(&second_error, &second_error),
        ));
        constraints.push(extension_centered_binomial_eta_two_support_value(
            tower,
            &second_error,
            &second_error_square,
            modulus,
        ));
        let encoding_carry_bit_sum = committed_trace_extension_unsigned_bit_sum(
            tower,
            row,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN,
            half,
            &mut constraints,
        )?;
        let encoding_carry_slack_bit_sum = committed_trace_extension_unsigned_bit_sum(
            tower,
            row,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN,
            half,
            &mut constraints,
        )?;
        constraints.push(tower.sub(&encoding_carry, &encoding_carry_bit_sum));
        constraints.push(tower.sub(
            &tower.add(&encoding_carry, &encoding_carry_slack_bit_sum),
            &tower.embed_base(encoder_carry_bound % modulus),
        ));
        let projected_bgv_carry_shifted_sum = committed_trace_extension_ternary_digit_sum(
            tower,
            row,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        let projected_bgv_carry_slack_sum = committed_trace_extension_ternary_digit_sum(
            tower,
            row,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        constraints.push(tower.sub(
            &tower.add(
                &projected_bgv_carry,
                &tower.embed_base(projected_bgv_carry_bound % modulus),
            ),
            &projected_bgv_carry_shifted_sum,
        ));
        constraints.push(tower.sub(
            &tower.add(
                &projected_bgv_carry_shifted_sum,
                &projected_bgv_carry_slack_sum,
            ),
            &tower.embed_base(
                direct_ballot_committed_projected_bgv_carry_twice_bound_modulus(
                    projected_bgv_carry_bound,
                    modulus,
                )?,
            ),
        ));
        constraints.push(extension_boolean_support_value(tower, &one_hot));
        if constraints.len() != DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed support row constraint count does not match the profile",
            ));
        }
        for (constraint_index, constraint) in constraints.iter().enumerate() {
            accumulated = tower.add(
                &accumulated,
                &tower.mul(&alpha[alpha_offset + constraint_index], constraint),
            );
        }
    }

    Ok(accumulated)
}

fn committed_support_row_check_value_base(
    tower: &ChallengeExtensionTower,
    row: &[u64],
    alpha: &[ChallengeExtensionElement],
    modulus: u64,
    encoder_carry_bound: u64,
    projected_bgv_carry_bound: u64,
) -> CanonicalResult<ChallengeExtensionElement> {
    if row.len() != DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT
        || alpha.len() != DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINT_COUNT
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed support row check shape does not match the profile",
        ));
    }
    let mut accumulated = ChallengeExtensionTower::zero();
    for half in 0..DIRECT_BALLOT_COMMITTED_TRACE_SPLIT {
        let alpha_offset = half * DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF;
        let randomizer = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_RANDOMIZER_COLUMN,
            half,
        )?];
        let first_error = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_COLUMN,
            half,
        )?];
        let first_error_square = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_FIRST_ERROR_SQUARE_COLUMN,
            half,
        )?];
        let second_error = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_SECOND_ERROR_COLUMN,
            half,
        )?];
        let second_error_square = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_SECOND_ERROR_SQUARE_COLUMN,
            half,
        )?];
        let encoding_carry = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_COLUMN,
            half,
        )?];
        let projected_bgv_carry = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_COLUMN,
            half,
        )?];
        let one_hot = row[direct_ballot_committed_physical_column(
            DIRECT_BALLOT_COMMITTED_ONE_HOT_COLUMN,
            half,
        )?];
        let mut constraints =
            Vec::with_capacity(DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF);
        constraints.push(ternary_support_value(randomizer, modulus)?);
        constraints.push(sub_mod_fast(
            first_error_square,
            mul_mod_fast(first_error, first_error, modulus),
            modulus,
        ));
        constraints.push(centered_binomial_eta_two_support_value(
            first_error,
            first_error_square,
            modulus,
        )?);
        constraints.push(sub_mod_fast(
            second_error_square,
            mul_mod_fast(second_error, second_error, modulus),
            modulus,
        ));
        constraints.push(centered_binomial_eta_two_support_value(
            second_error,
            second_error_square,
            modulus,
        )?);
        let encoding_carry_bit_sum = committed_trace_unsigned_bit_sum(
            row,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        let encoding_carry_slack_bit_sum = committed_trace_unsigned_bit_sum(
            row,
            DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_SLACK_BIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        constraints.push(sub_mod_fast(
            encoding_carry,
            encoding_carry_bit_sum,
            modulus,
        ));
        constraints.push(sub_mod_fast(
            add_mod_fast(encoding_carry, encoding_carry_slack_bit_sum, modulus),
            encoder_carry_bound % modulus,
            modulus,
        ));
        let projected_bgv_carry_shifted_sum = committed_trace_ternary_digit_sum(
            row,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SHIFTED_DIGIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        let projected_bgv_carry_slack_sum = committed_trace_ternary_digit_sum(
            row,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_SLACK_DIGIT_START_COLUMN,
            half,
            modulus,
            &mut constraints,
        )?;
        constraints.push(sub_mod_fast(
            add_mod_fast(
                projected_bgv_carry,
                projected_bgv_carry_bound % modulus,
                modulus,
            ),
            projected_bgv_carry_shifted_sum,
            modulus,
        ));
        constraints.push(sub_mod_fast(
            add_mod_fast(
                projected_bgv_carry_shifted_sum,
                projected_bgv_carry_slack_sum,
                modulus,
            ),
            direct_ballot_committed_projected_bgv_carry_twice_bound_modulus(
                projected_bgv_carry_bound,
                modulus,
            )?,
            modulus,
        ));
        constraints.push(boolean_support_value(one_hot, modulus)?);
        if constraints.len() != DIRECT_BALLOT_COMMITTED_SUPPORT_CONSTRAINTS_PER_HALF {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed support row constraint count does not match the profile",
            ));
        }
        for (constraint_index, constraint) in constraints.iter().enumerate() {
            accumulated = tower.add(
                &accumulated,
                &tower.scale_base(&alpha[alpha_offset + constraint_index], *constraint),
            );
        }
    }

    Ok(accumulated)
}

fn extension_boolean_support_value(
    tower: &ChallengeExtensionTower,
    value: &ChallengeExtensionElement,
) -> ChallengeExtensionElement {
    tower.sub(&tower.mul(value, value), value)
}

fn extension_ternary_support_value(
    tower: &ChallengeExtensionTower,
    value: &ChallengeExtensionElement,
) -> ChallengeExtensionElement {
    tower.sub(&tower.mul(&tower.mul(value, value), value), value)
}

fn extension_ternary_digit_support_value(
    tower: &ChallengeExtensionTower,
    value: &ChallengeExtensionElement,
    modulus: u64,
) -> ChallengeExtensionElement {
    tower.mul(
        value,
        &tower.mul(
            &tower.sub(value, &tower.embed_base(1)),
            &tower.sub(value, &tower.embed_base(2 % modulus)),
        ),
    )
}

fn extension_centered_binomial_eta_two_support_value(
    tower: &ChallengeExtensionTower,
    value: &ChallengeExtensionElement,
    value_square: &ChallengeExtensionElement,
    modulus: u64,
) -> ChallengeExtensionElement {
    let minus_one = tower.sub(value_square, &tower.embed_base(1));
    let minus_four = tower.sub(value_square, &tower.embed_base(4 % modulus));
    tower.mul(value, &tower.mul(&minus_one, &minus_four))
}

fn committed_trace_extension_unsigned_bit_sum(
    tower: &ChallengeExtensionTower,
    row: &[ChallengeExtensionElement],
    start_column: usize,
    half: usize,
    constraints: &mut Vec<ChallengeExtensionElement>,
) -> CanonicalResult<ChallengeExtensionElement> {
    let mut sum = ChallengeExtensionTower::zero();
    for bit_index in 0..DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT {
        let bit = row[direct_ballot_committed_physical_column(start_column + bit_index, half)?];
        constraints.push(extension_boolean_support_value(tower, &bit));
        sum = tower.add(&sum, &tower.scale_base(&bit, 1_u64 << bit_index));
    }

    Ok(sum)
}

fn committed_trace_extension_ternary_digit_sum(
    tower: &ChallengeExtensionTower,
    row: &[ChallengeExtensionElement],
    start_column: usize,
    half: usize,
    modulus: u64,
    constraints: &mut Vec<ChallengeExtensionElement>,
) -> CanonicalResult<ChallengeExtensionElement> {
    let mut sum = ChallengeExtensionTower::zero();
    let mut weight = 1_u64;
    for digit_index in 0..DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT {
        let digit = row[direct_ballot_committed_physical_column(start_column + digit_index, half)?];
        constraints.push(extension_ternary_digit_support_value(
            tower, &digit, modulus,
        ));
        sum = tower.add(&sum, &tower.scale_base(&digit, weight));
        weight = mul_mod_fast(
            weight,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX % modulus,
            modulus,
        );
    }

    Ok(sum)
}

fn committed_trace_unsigned_bit_sum(
    row: &[u64],
    start_column: usize,
    half: usize,
    modulus: u64,
    constraints: &mut Vec<u64>,
) -> CanonicalResult<u64> {
    let mut sum = 0_u64;
    for bit_index in 0..DIRECT_BALLOT_COMMITTED_ENCODING_CARRY_BIT_COUNT {
        let bit = row[direct_ballot_committed_physical_column(start_column + bit_index, half)?];
        constraints.push(boolean_support_value(bit, modulus)?);
        sum = add_mod_fast(
            sum,
            mul_mod_fast(bit, (1_u64 << bit_index) % modulus, modulus),
            modulus,
        );
    }

    Ok(sum)
}

fn committed_trace_ternary_digit_sum(
    row: &[u64],
    start_column: usize,
    half: usize,
    modulus: u64,
    constraints: &mut Vec<u64>,
) -> CanonicalResult<u64> {
    let mut sum = 0_u64;
    let mut weight = 1_u64;
    for digit_index in 0..DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_TERNARY_DIGIT_COUNT {
        let digit = row[direct_ballot_committed_physical_column(start_column + digit_index, half)?];
        constraints.push(ternary_digit_support_value(digit, modulus)?);
        sum = add_mod_fast(sum, mul_mod_fast(digit, weight, modulus), modulus);
        weight = mul_mod_fast(
            weight,
            DIRECT_BALLOT_COMMITTED_PROJECTED_BGV_CARRY_DIGIT_RADIX % modulus,
            modulus,
        );
    }

    Ok(sum)
}

fn committed_trace_batch_codeword(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    deep_points: &[ChallengeExtensionElement],
    deep_evaluations: &[Vec<ChallengeExtensionElement>],
    lambda: &[ChallengeExtensionElement],
    witness_columns: &[Vec<u64>],
    quotient_columns: &[Vec<u64>],
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let reconstruction_input = CommittedTraceBatchReconstructionInput {
        plan,
        tower,
        deep_points,
        deep_evaluations,
        lambda,
    };
    let mut codeword = vec![ChallengeExtensionTower::zero(); plan.extension_size];
    for (position, value) in codeword.iter_mut().enumerate() {
        let witness_row = witness_columns
            .iter()
            .map(|column| column[position])
            .collect::<Vec<_>>();
        let quotient_row = quotient_columns
            .iter()
            .map(|column| column[position])
            .collect::<Vec<_>>();
        *value = reconstruct_committed_trace_batch_value(
            &reconstruction_input,
            &witness_row,
            &quotient_row,
            position,
        )?;
    }

    Ok(codeword)
}

fn reconstruct_committed_trace_batch_value(
    input: &CommittedTraceBatchReconstructionInput<'_>,
    witness_row: &[u64],
    quotient_row: &[u64],
    position: usize,
) -> CanonicalResult<ChallengeExtensionElement> {
    let total_column_count = witness_row.len() + DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS;
    if quotient_row.len() != DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS
        || input.lambda.len() != total_column_count * DEEP_POINT_COUNT
        || input.deep_evaluations.len() != DEEP_POINT_COUNT
        || input
            .deep_evaluations
            .iter()
            .any(|evaluations| evaluations.len() != total_column_count)
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace low-degree reconstruction shape is invalid",
        ));
    }
    let extension_point = input.tower.embed_base(input.plan.extension_point(position));
    let mut accumulated = ChallengeExtensionTower::zero();
    for (point_index, point) in input.deep_points.iter().enumerate() {
        let inverted_difference = input
            .tower
            .inverse(&input.tower.sub(&extension_point, point))?;
        let mut point_sum = ChallengeExtensionTower::zero();
        for (column_index, column_value) in witness_row.iter().enumerate() {
            point_sum = input.tower.add(
                &point_sum,
                &input.tower.scale_base(
                    &input.lambda[column_index * DEEP_POINT_COUNT + point_index],
                    *column_value,
                ),
            );
        }
        for logical_index in 0..DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS {
            let mut quotient_value = ChallengeExtensionTower::zero();
            let row_offset = logical_index * CHALLENGE_EXTENSION_DEGREE;
            for (coordinate, slot) in quotient_value.iter_mut().enumerate() {
                *slot = quotient_row[row_offset + coordinate];
            }
            let quotient_column_index = witness_row.len() + logical_index;
            point_sum = input.tower.add(
                &point_sum,
                &input.tower.mul(
                    &input.lambda[quotient_column_index * DEEP_POINT_COUNT + point_index],
                    &quotient_value,
                ),
            );
        }
        for column_index in 0..total_column_count {
            point_sum = input.tower.sub(
                &point_sum,
                &input.tower.mul(
                    &input.lambda[column_index * DEEP_POINT_COUNT + point_index],
                    &input.deep_evaluations[point_index][column_index],
                ),
            );
        }
        accumulated = input.tower.add(
            &accumulated,
            &input.tower.mul(&point_sum, &inverted_difference),
        );
    }

    Ok(accumulated)
}

fn sample_deep_points(
    transcript: &mut FiatShamirTranscript,
    plan: &EvaluationDomainPlan,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let tower = ChallengeExtensionTower::for_modulus(plan.modulus)?;
    let coset_marker = tower.embed_base(pow_mod(
        plan.coset_offset,
        plan.extension_size as u64,
        plan.modulus,
    )?);
    let mut points = Vec::with_capacity(DEEP_POINT_COUNT);
    while points.len() < DEEP_POINT_COUNT {
        let candidate = transcript.challenge_extension_elements("deep-point", plan.modulus, 1)[0];
        if ChallengeExtensionTower::is_zero(&candidate) {
            continue;
        }
        if tower.pow(&candidate, plan.trace_size as u64) == ChallengeExtensionTower::one() {
            continue;
        }
        if tower.pow(&candidate, plan.extension_size as u64) == coset_marker {
            continue;
        }
        points.push(candidate);
    }

    Ok(points)
}

fn trace_vanishing_at_extension(
    plan: &EvaluationDomainPlan,
    tower: &ChallengeExtensionTower,
    point: &ChallengeExtensionElement,
) -> ChallengeExtensionElement {
    tower.sub(
        &tower.pow(point, plan.trace_size as u64),
        &ChallengeExtensionTower::one(),
    )
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

fn divide_by_trace_vanishing(
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

fn trim_trailing_zeros(mut coefficients: Vec<u64>) -> Vec<u64> {
    while coefficients.last() == Some(&0) {
        coefficients.pop();
    }

    coefficients
}

fn encode_direct_ballot_committed_trace_proof(
    proof: &DirectBallotCommittedTraceProof,
    limb_moduli: &[u64],
) -> CanonicalResult<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DIRECT_BALLOT_COMMITTED_TRACE_PROOF_MAGIC);
    append_u64_checked(&mut bytes, proof.limb_proofs.len())?;
    if proof.limb_proofs.len() != limb_moduli.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof limb count does not match the profile",
        ));
    }
    for (limb_proof, modulus) in proof.limb_proofs.iter().zip(limb_moduli.iter().copied()) {
        bytes.extend_from_slice(&limb_proof.witness_tree_root);
        bytes.extend_from_slice(&limb_proof.accumulator_tree_root);
        bytes.extend_from_slice(&limb_proof.quotient_tree_root);
        for evaluations in &limb_proof.deep_evaluations {
            write_extension_slice(&mut bytes, evaluations, modulus)?;
        }
        encode_low_degree_proof(&mut bytes, &limb_proof.low_degree, modulus)?;
        for opening in &limb_proof.query_openings {
            for slot in 0..2 {
                let accumulator_current_slot = slot * 2;
                let accumulator_shifted_slot = accumulator_current_slot + 1;
                write_base_field_slice(&mut bytes, &opening.witness_rows[slot], modulus)?;
                write_bytes_with_length(&mut bytes, &opening.witness_salts[slot])?;
                write_base_field_slice(
                    &mut bytes,
                    &opening.accumulator_rows[accumulator_current_slot],
                    modulus,
                )?;
                write_bytes_with_length(
                    &mut bytes,
                    &opening.accumulator_salts[accumulator_current_slot],
                )?;
                write_base_field_slice(
                    &mut bytes,
                    &opening.accumulator_rows[accumulator_shifted_slot],
                    modulus,
                )?;
                write_bytes_with_length(
                    &mut bytes,
                    &opening.accumulator_salts[accumulator_shifted_slot],
                )?;
                write_base_field_slice(&mut bytes, &opening.quotient_rows[slot], modulus)?;
                write_bytes_with_length(&mut bytes, &opening.quotient_salts[slot])?;
            }
        }
        write_batched_opening(&mut bytes, &limb_proof.witness_batch_opening)?;
        write_batched_opening(&mut bytes, &limb_proof.accumulator_batch_opening)?;
        write_batched_opening(&mut bytes, &limb_proof.quotient_batch_opening)?;
    }

    Ok(bytes)
}

fn decode_direct_ballot_committed_trace_proof(
    bytes: &[u8],
    limb_moduli: &[u64],
) -> CanonicalResult<DirectBallotCommittedTraceProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed_bytes::<8>(bytes, &mut cursor)?;
    if &magic != DIRECT_BALLOT_COMMITTED_TRACE_PROOF_MAGIC {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof has the wrong format marker",
        ));
    }
    let limb_count = usize::try_from(read_u64(bytes, &mut cursor)?).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof limb count does not fit usize",
        )
    })?;
    if limb_count != limb_moduli.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof limb count does not match the profile",
        ));
    }
    let phase_one_columns = DIRECT_BALLOT_COMMITTED_COLUMN_COUNT
        * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT
        + DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS
        + DIRECT_BALLOT_COMMITTED_SHIFTED_LINEAR_ACCUMULATOR_COLUMNS;
    let base_witness_columns =
        DIRECT_BALLOT_COMMITTED_COLUMN_COUNT * DIRECT_BALLOT_COMMITTED_TRACE_SPLIT;
    let total_column_count = phase_one_columns + DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_COLUMNS;
    let mut limb_proofs = Vec::with_capacity(limb_count);
    for modulus in limb_moduli.iter().copied() {
        let witness_tree_root = read_hash(bytes, &mut cursor)?;
        let accumulator_tree_root = read_hash(bytes, &mut cursor)?;
        let quotient_tree_root = read_hash(bytes, &mut cursor)?;
        let mut deep_evaluations = Vec::with_capacity(DEEP_POINT_COUNT);
        for _ in 0..DEEP_POINT_COUNT {
            deep_evaluations.push(read_extension_vec(
                bytes,
                &mut cursor,
                total_column_count,
                modulus,
            )?);
        }
        let low_degree = decode_low_degree_proof(bytes, &mut cursor, modulus)?;
        let mut query_openings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
        for _ in 0..LOW_DEGREE_QUERY_COUNT {
            let mut witness_rows = [Vec::new(), Vec::new()];
            let mut witness_salts = [Vec::new(), Vec::new()];
            let mut accumulator_rows = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
            let mut accumulator_salts = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
            let mut quotient_rows = [Vec::new(), Vec::new()];
            let mut quotient_salts = [Vec::new(), Vec::new()];
            for slot in 0..2 {
                witness_rows[slot] =
                    read_base_field_vec(bytes, &mut cursor, base_witness_columns, modulus)?;
                witness_salts[slot] = read_exact_length_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
                let accumulator_current_slot = slot * 2;
                let accumulator_shifted_slot = accumulator_current_slot + 1;
                accumulator_rows[accumulator_current_slot] = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS,
                    modulus,
                )?;
                accumulator_salts[accumulator_current_slot] =
                    read_exact_length_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
                accumulator_rows[accumulator_shifted_slot] = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    DIRECT_BALLOT_COMMITTED_LINEAR_ACCUMULATOR_COLUMNS,
                    modulus,
                )?;
                accumulator_salts[accumulator_shifted_slot] =
                    read_exact_length_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
                quotient_rows[slot] = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    DIRECT_BALLOT_COMMITTED_TRACE_QUOTIENT_PHYSICAL_COLUMNS,
                    modulus,
                )?;
                quotient_salts[slot] =
                    read_exact_length_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
            }
            query_openings.push(DirectBallotCommittedTraceQueryOpening {
                witness_rows,
                witness_salts,
                accumulator_rows,
                accumulator_salts,
                quotient_rows,
                quotient_salts,
            });
        }
        let tree_depth = (direct_ballot_committed_trace_size()?
            * crate::bgv::polynomial_iop::DOMAIN_BLOWUP)
            .trailing_zeros() as usize;
        let batch_node_bound = 2 * LOW_DEGREE_QUERY_COUNT * tree_depth;
        let accumulator_batch_node_bound = 4 * LOW_DEGREE_QUERY_COUNT * tree_depth;
        let witness_batch_opening = read_batched_opening(bytes, &mut cursor, batch_node_bound)?;
        let accumulator_batch_opening =
            read_batched_opening(bytes, &mut cursor, accumulator_batch_node_bound)?;
        let quotient_batch_opening = read_batched_opening(bytes, &mut cursor, batch_node_bound)?;
        limb_proofs.push(DirectBallotCommittedTraceLimbProof {
            witness_tree_root,
            accumulator_tree_root,
            quotient_tree_root,
            deep_evaluations,
            low_degree,
            query_openings,
            witness_batch_opening,
            accumulator_batch_opening,
            quotient_batch_opening,
        });
    }
    if cursor != bytes.len() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace proof has trailing bytes",
        ));
    }

    Ok(DirectBallotCommittedTraceProof { limb_proofs })
}

fn encode_low_degree_proof(
    bytes: &mut Vec<u8>,
    low_degree: &LowDegreeProof,
    modulus: u64,
) -> CanonicalResult<()> {
    append_u64_checked(bytes, low_degree.folded_layer_roots.len())?;
    for root in &low_degree.folded_layer_roots {
        bytes.extend_from_slice(root);
    }
    write_extension_slice(bytes, &low_degree.final_coefficients, modulus)?;
    for query_opening in &low_degree.query_openings {
        for pair_opening in &query_opening.folded_layer_pairs {
            write_extension_slice(bytes, &pair_opening.pair, modulus)?;
        }
    }
    for layer_opening in &low_degree.layer_batch_openings {
        write_batched_opening(bytes, layer_opening)?;
    }

    Ok(())
}

fn decode_low_degree_proof(
    bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<LowDegreeProof> {
    let committed_fold_count = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed trace fold count does not fit usize",
        )
    })?;
    let expected_committed_fold_count = expected_committed_low_degree_fold_count()?;
    if committed_fold_count != expected_committed_fold_count {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace fold count does not match the profile",
        ));
    }
    let mut folded_layer_roots = Vec::with_capacity(committed_fold_count);
    for _ in 0..committed_fold_count {
        folded_layer_roots.push(read_hash(bytes, cursor)?);
    }
    let final_coefficients = read_extension_vec(
        bytes,
        cursor,
        crate::bgv::polynomial_iop::LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
        modulus,
    )?;
    let mut query_openings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
    for _ in 0..LOW_DEGREE_QUERY_COUNT {
        let mut folded_layer_pairs = Vec::with_capacity(committed_fold_count);
        for _ in 0..committed_fold_count {
            let first = read_extension_element(bytes, cursor, modulus)?;
            let second = read_extension_element(bytes, cursor, modulus)?;
            folded_layer_pairs.push(LowDegreePairOpening {
                pair: [first, second],
            });
        }
        query_openings.push(LowDegreeQueryOpening { folded_layer_pairs });
    }
    let mut layer_batch_openings = Vec::with_capacity(committed_fold_count);
    let initial_domain_size =
        direct_ballot_committed_trace_size()? * crate::bgv::polynomial_iop::DOMAIN_BLOWUP;
    for fold_index in 0..committed_fold_count {
        let layer_leaf_count = initial_domain_size >> (fold_index + 2);
        let maximum_nodes = LOW_DEGREE_QUERY_COUNT * layer_leaf_count.trailing_zeros() as usize;
        layer_batch_openings.push(read_batched_opening(bytes, cursor, maximum_nodes)?);
    }

    Ok(LowDegreeProof {
        folded_layer_roots,
        final_coefficients,
        query_openings,
        layer_batch_openings,
    })
}

fn expected_committed_low_degree_fold_count() -> CanonicalResult<usize> {
    let trace_size = direct_ballot_committed_trace_size()?;
    let initial_degree_bound = COMMITMENT_BOUND_FACTOR * trace_size;
    let final_count = crate::bgv::polynomial_iop::LOW_DEGREE_FINAL_COEFFICIENT_COUNT;
    if !initial_degree_bound.is_multiple_of(final_count) {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace degree bound does not match the final FRI layer",
        ));
    }
    let fold_ratio = initial_degree_bound / final_count;
    if !fold_ratio.is_power_of_two() {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace degree bound does not have a canonical fold depth",
        ));
    }

    Ok(fold_ratio.trailing_zeros() as usize - 1)
}

fn write_extension_slice(
    bytes: &mut Vec<u8>,
    values: &[ChallengeExtensionElement],
    modulus: u64,
) -> CanonicalResult<()> {
    for value in values {
        for coordinate in value {
            if *coordinate >= modulus {
                return Err(invalid_direct_ballot_relation_proof(
                    "direct ballot committed trace extension element is not canonical",
                ));
            }
            append_u64(bytes, *coordinate);
        }
    }

    Ok(())
}

fn write_base_field_slice(
    bytes: &mut Vec<u8>,
    values: &[u64],
    modulus: u64,
) -> CanonicalResult<()> {
    for value in values {
        if *value >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace field element is not canonical",
            ));
        }
        append_u64(bytes, *value);
    }

    Ok(())
}

fn read_extension_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    (0..count)
        .map(|_| read_extension_element(bytes, cursor, modulus))
        .collect()
}

fn read_extension_element(
    bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<ChallengeExtensionElement> {
    let mut element = ChallengeExtensionTower::zero();
    for slot in &mut element {
        *slot = read_u64(bytes, cursor)?;
        if *slot >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace extension element is not canonical",
            ));
        }
    }

    Ok(element)
}

fn read_base_field_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = read_u64(bytes, cursor)?;
        if value >= modulus {
            return Err(invalid_direct_ballot_relation_proof(
                "direct ballot committed trace field element is not canonical",
            ));
        }
        values.push(value);
    }

    Ok(values)
}

fn write_batched_opening(
    bytes: &mut Vec<u8>,
    opening: &BatchedMerkleOpening,
) -> CanonicalResult<()> {
    append_u64_checked(bytes, opening.authentication_nodes.len())?;
    for node in &opening.authentication_nodes {
        bytes.extend_from_slice(node);
    }

    Ok(())
}

fn read_batched_opening(
    bytes: &[u8],
    cursor: &mut usize,
    maximum_nodes: usize,
) -> CanonicalResult<BatchedMerkleOpening> {
    let node_count = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed trace Merkle opening length does not fit usize",
        )
    })?;
    if node_count > maximum_nodes {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace Merkle opening length exceeds the profile bound",
        ));
    }
    let mut authentication_nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        authentication_nodes.push(read_hash(bytes, cursor)?);
    }

    Ok(BatchedMerkleOpening {
        authentication_nodes,
    })
}

fn write_bytes_with_length(bytes: &mut Vec<u8>, value: &[u8]) -> CanonicalResult<()> {
    append_u64_checked(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn read_exact_length_bytes(
    bytes: &[u8],
    cursor: &mut usize,
    expected_length: usize,
) -> CanonicalResult<Vec<u8>> {
    let length = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
        invalid_direct_ballot_relation_proof(
            "direct ballot committed trace byte vector length does not fit usize",
        )
    })?;
    if length != expected_length {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot committed trace byte vector length does not match the profile",
        ));
    }
    let end = cursor.checked_add(length).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot committed trace cursor overflowed")
    })?;
    let slice = bytes.get(*cursor..end).ok_or_else(|| {
        invalid_direct_ballot_relation_proof("direct ballot committed trace proof ended early")
    })?;
    *cursor = end;
    Ok(slice.to_vec())
}

fn append_u64_checked(bytes: &mut Vec<u8>, value: usize) -> CanonicalResult<()> {
    append_u64(
        bytes,
        u64::try_from(value).map_err(|_| {
            invalid_direct_ballot_relation_proof(
                "direct ballot committed trace length does not fit u64",
            )
        })?,
    );
    Ok(())
}
