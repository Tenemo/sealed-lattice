//! Allocation-bounded plain-WHIR prover.
//!
//! The upstream prover retains every Merkle layer beside each encoded
//! codeword. The initial target commitment is large enough that this exceeds
//! the participant WebAssembly memory ceiling. This adapter preserves the
//! upstream transcript and proof types while deriving roots and authentication
//! paths in separate deterministic passes. Encoded matrices are released
//! after each pass; only their smaller source polynomial and a logarithmic
//! Merkle frontier remain live between transcript stages.

use core::mem::size_of;
use std::collections::BTreeMap;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use p3_challenger::{
    CanObserve, CanSample, CanSampleUniformBits, FieldChallenger, GrindingChallenger,
};
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch, SumcheckData,
    constraints::{
        Constraint, Statements,
        statement::{EqStatement, SelectStatement},
    },
    layout::{Layout, Witness},
    strategy::VariableOrder,
};
use p3_symmetric::{MerkleCap, PseudoCompressionFunction};
use p3_whir::{PcsProof, QueryOpening, WhirProof, WhirRoundProof};
use tiny_keccak::keccakf;

use super::{
    ChallengeField, DomainSeparatedShake256, ExtensionFieldChallenger, MERKLE_DIGEST_WORD_LENGTH,
    NodeCompressor, ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN, ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
    plain_whir::{
        AggregateLayout, PlainAggregateCommitment, PlainAggregatePcs, PlainAggregateProof,
    },
};

type MerkleDigest = [u64; MERKLE_DIGEST_WORD_LENGTH];

const SHAKE256_STATE_WORD_LENGTH: usize = 25;
const SHAKE256_RATE_BYTE_LENGTH: usize = 136;
const SHAKE256_DELIMITER: u8 = 0x1f;
const SHAKE256_FINAL_BIT: u8 = 0x80;
const MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT: usize = 1 << 15;

#[cfg(test)]
fn trace_streaming_phase(label: &str) {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after the Unix epoch");
    eprintln!(
        "[streaming-whir] unixMilliseconds={} phase={label}",
        elapsed.as_millis()
    );
}

pub(super) struct StreamingPlainAggregateProverData {
    layout: AggregateLayout,
}

#[cfg(test)]
struct EncodedMatrix {
    values: Vec<ChallengeField>,
    width: usize,
    height: usize,
}

struct MatrixOpenings {
    root: PlainAggregateCommitment,
    rows: Vec<Vec<ChallengeField>>,
    paths: Vec<Vec<MerkleDigest>>,
}

#[derive(Clone, Copy)]
enum QueryValueKind {
    Base,
    Extension,
}

struct RetainedRoundSource {
    polynomial: Poly<ChallengeField>,
    root: PlainAggregateCommitment,
    query_value_kind: QueryValueKind,
    folding_factor: usize,
    inverse_rate: usize,
}

pub(super) fn commit_streaming_plain_aggregate(
    pcs: &PlainAggregatePcs,
    witness: Witness<ChallengeField>,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(PlainAggregateCommitment, StreamingPlainAggregateProverData), String> {
    #[cfg(test)]
    trace_streaming_phase("initial-commitment-start");
    if witness.num_variables() != pcs.num_variables {
        return Err(format!(
            "plain WHIR witness has {} variables, expected {}",
            witness.num_variables(),
            pcs.num_variables
        ));
    }
    let commitment = stream_prefix_polynomial(
        witness.poly(),
        pcs.round_folding_factor(0),
        1_usize
            .checked_shl(
                u32::try_from(pcs.params.starting_log_inv_rate)
                    .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
        None,
    )?
    .root;
    #[cfg(test)]
    trace_streaming_phase("initial-commitment-complete");
    challenger.observe(commitment.clone());
    Ok((
        commitment,
        streaming_plain_aggregate_prover_data(pcs, witness)?,
    ))
}

pub(super) fn streaming_plain_aggregate_prover_data(
    pcs: &PlainAggregatePcs,
    witness: Witness<ChallengeField>,
) -> Result<StreamingPlainAggregateProverData, String> {
    if witness.num_variables() != pcs.num_variables {
        return Err(format!(
            "plain WHIR witness has {} variables, expected {}",
            witness.num_variables(),
            pcs.num_variables
        ));
    }
    Ok(StreamingPlainAggregateProverData {
        layout: AggregateLayout::from_witness(witness),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn open_streaming_plain_aggregate_batches_at_points<RecomputeInitialPolynomial>(
    pcs: &PlainAggregatePcs,
    initial_commitment: &PlainAggregateCommitment,
    mut prover_data: StreamingPlainAggregateProverData,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
    mut recompute_initial_polynomial: RecomputeInitialPolynomial,
) -> Result<PlainAggregateProof, String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    #[cfg(test)]
    trace_streaming_phase("opening-start");
    if points.len() != requested_columns_by_point.len() {
        return Err("plain WHIR points and opening requests have different lengths".to_owned());
    }
    let mut whir = empty_plain_whir_proof(pcs);
    whir.initial_ood_answers = (0..pcs.commitment_ood_samples)
        .map(|_| prover_data.layout.add_virtual_eval(challenger))
        .collect();
    let evaluations = points
        .iter()
        .cloned()
        .zip(requested_columns_by_point)
        .map(|(point, requested_columns)| {
            let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
            prover_data
                .layout
                .eval_at_point(0, &request, point, challenger)
        })
        .collect();
    prove_streaming_whir(
        pcs,
        &mut whir,
        challenger,
        prover_data.layout,
        initial_commitment,
        &mut recompute_initial_polynomial,
    )?;
    challenger.ensure_sampling_succeeded()?;
    #[cfg(test)]
    trace_streaming_phase("opening-complete");
    Ok(PcsProof {
        whir,
        evals: evaluations,
    })
}

fn prove_streaming_whir<RecomputeInitialPolynomial>(
    pcs: &PlainAggregatePcs,
    proof: &mut WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    challenger: &mut ExtensionFieldChallenger,
    layout: AggregateLayout,
    initial_commitment: &PlainAggregateCommitment,
    recompute_initial_polynomial: &mut RecomputeInitialPolynomial,
) -> Result<(), String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    if pcs.round_folding_factor(0) != layout.folding() {
        return Err("plain WHIR layout has the wrong initial folding factor".to_owned());
    }
    let variable_order = AggregateLayout::variable_order();
    if variable_order != VariableOrder::Prefix {
        return Err("bounded plain WHIR prover requires prefix variable order".to_owned());
    }
    let (mut sumcheck_prover, mut folding_randomness) = layout.into_sumcheck(
        &mut proof.initial_sumcheck,
        pcs.starting_folding_pow_bits,
        challenger,
    );
    #[cfg(test)]
    trace_streaming_phase("initial-sumcheck-complete");
    let mut retained_round_source: Option<RetainedRoundSource> = None;

    for round_index in 0..=pcs.n_rounds() {
        let expected_variable_count = pcs.num_variables - pcs.total_folded_through(round_index);
        if sumcheck_prover.num_variables() != expected_variable_count {
            return Err(format!(
                "plain WHIR round {round_index} has {} variables, expected {expected_variable_count}",
                sumcheck_prover.num_variables()
            ));
        }
        if round_index == pcs.n_rounds() {
            #[cfg(test)]
            trace_streaming_phase("final-round-start");
            prove_final_round(
                pcs,
                proof,
                challenger,
                &mut sumcheck_prover,
                retained_round_source.take(),
                initial_commitment,
                recompute_initial_polynomial,
            )?;
            #[cfg(test)]
            trace_streaming_phase("final-round-complete");
            break;
        }

        let round_parameters = &pcs.round_parameters[round_index];
        let next_folding_factor = pcs.round_folding_factor(round_index + 1);
        #[cfg(test)]
        trace_streaming_phase(&format!("round-{round_index}-commitment-start"));
        let current_polynomial = sumcheck_prover.evals();
        let current_root = stream_prefix_polynomial(
            &current_polynomial,
            next_folding_factor,
            pcs.inv_rate(round_index),
            None,
        )?
        .root;
        #[cfg(test)]
        trace_streaming_phase(&format!("round-{round_index}-commitment-complete"));
        challenger.observe(current_root.clone());
        proof.rounds[round_index].commitment = Some(current_root.clone());

        let mut out_of_domain_statement = EqStatement::initialize(sumcheck_prover.num_variables());
        let mut out_of_domain_answers = Vec::with_capacity(round_parameters.ood_samples);
        for _ in 0..round_parameters.ood_samples {
            let point = Point::expand_from_univariate(
                challenger.sample_algebra_element(),
                sumcheck_prover.num_variables(),
            );
            let evaluation = sumcheck_prover.eval(&point);
            challenger.observe_algebra_element(evaluation);
            out_of_domain_answers.push(evaluation);
            out_of_domain_statement.add_evaluated_constraint(point, evaluation);
        }
        proof.rounds[round_index].ood_answers = out_of_domain_answers;

        if round_parameters.pow_bits > 0 {
            proof.rounds[round_index].pow_witness = challenger.grind(round_parameters.pow_bits);
        }
        let _: ChallengeField = challenger.sample();
        let query_indices = sample_distinct_query_indices(
            round_parameters.domain_size,
            pcs.round_folding_factor(round_index),
            round_parameters.num_queries,
            challenger,
        )?;
        let previous_openings = if let Some(previous) = retained_round_source.take() {
            #[cfg(test)]
            trace_streaming_phase(&format!("round-{round_index}-prior-openings-start"));
            let openings = stream_prefix_polynomial(
                &previous.polynomial,
                previous.folding_factor,
                previous.inverse_rate,
                Some(&query_indices),
            )?;
            if openings.root != previous.root {
                return Err(format!(
                    "plain WHIR round {round_index} recomputed the wrong prior commitment"
                ));
            }
            #[cfg(test)]
            trace_streaming_phase(&format!("round-{round_index}-prior-openings-complete"));
            (openings, previous.query_value_kind)
        } else {
            #[cfg(test)]
            trace_streaming_phase("round-0-initial-recomputation-start");
            let initial_polynomial = recompute_initial_polynomial()?;
            #[cfg(test)]
            trace_streaming_phase("round-0-initial-recomputation-complete");
            if initial_polynomial.num_variables() != pcs.num_variables {
                return Err(format!(
                    "recomputed initial polynomial has {} variables, expected {}",
                    initial_polynomial.num_variables(),
                    pcs.num_variables
                ));
            }
            let openings = stream_prefix_polynomial(
                &initial_polynomial,
                pcs.round_folding_factor(0),
                1_usize
                    .checked_shl(
                        u32::try_from(pcs.params.starting_log_inv_rate)
                            .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
                    )
                    .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
                Some(&query_indices),
            )?;
            #[cfg(test)]
            trace_streaming_phase("round-0-initial-openings-complete");
            drop(initial_polynomial);
            if openings.root != *initial_commitment {
                return Err("recomputed initial polynomial has the wrong commitment".to_owned());
            }
            (openings, QueryValueKind::Base)
        };

        let query_randomness = folding_randomness.clone();
        let mut selection_statement = SelectStatement::initialize(sumcheck_prover.num_variables());
        let mut queries = Vec::with_capacity(query_indices.len());
        for ((query_index, values), path) in query_indices
            .iter()
            .copied()
            .zip(previous_openings.0.rows)
            .zip(previous_openings.0.paths)
        {
            let query_polynomial = Poly::new(values);
            let evaluation = match previous_openings.1 {
                QueryValueKind::Base => query_polynomial.eval_base(&query_randomness),
                QueryValueKind::Extension => {
                    query_polynomial.eval_ext::<ChallengeField>(&query_randomness)
                }
            };
            let domain_point = round_parameters
                .folded_domain_gen
                .exp_u64(query_index as u64);
            selection_statement.add_constraint(domain_point, evaluation);
            let values = query_polynomial.into_evals();
            queries.push(match previous_openings.1 {
                QueryValueKind::Base => QueryOpening::Base {
                    values,
                    proof: path,
                },
                QueryValueKind::Extension => QueryOpening::Extension {
                    values,
                    proof: path,
                },
            });
        }
        proof.rounds[round_index].queries = queries;

        let constraint = Constraint::new(
            challenger.sample_algebra_element(),
            sumcheck_prover.num_variables(),
            vec![
                Statements::Eq(out_of_domain_statement),
                Statements::Select(selection_statement),
            ],
        );
        let mut sumcheck_data = SumcheckData::default();
        folding_randomness = sumcheck_prover.compute_sumcheck_polynomials(
            &mut sumcheck_data,
            challenger,
            next_folding_factor,
            round_parameters.folding_pow_bits,
            Some(constraint),
        );
        #[cfg(test)]
        trace_streaming_phase(&format!("round-{round_index}-sumcheck-complete"));
        proof.rounds[round_index].sumcheck = sumcheck_data;
        retained_round_source = Some(RetainedRoundSource {
            polynomial: current_polynomial,
            root: current_root,
            query_value_kind: QueryValueKind::Extension,
            folding_factor: next_folding_factor,
            inverse_rate: pcs.inv_rate(round_index),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_final_round<RecomputeInitialPolynomial>(
    pcs: &PlainAggregatePcs,
    proof: &mut WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    challenger: &mut ExtensionFieldChallenger,
    sumcheck_prover: &mut p3_sumcheck::strategy::SumcheckProver<ChallengeField, ChallengeField>,
    retained_round_source: Option<RetainedRoundSource>,
    initial_commitment: &PlainAggregateCommitment,
    recompute_initial_polynomial: &mut RecomputeInitialPolynomial,
) -> Result<(), String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    #[cfg(test)]
    trace_streaming_phase("final-polynomial-start");
    let final_polynomial = sumcheck_prover.evals();
    challenger.observe_algebra_slice(final_polynomial.as_slice());
    proof.final_poly = Some(final_polynomial);
    if pcs.final_pow_bits > 0 {
        proof.final_pow_witness = challenger.grind(pcs.final_pow_bits);
    }
    let final_query_indices = sample_distinct_query_indices(
        pcs.final_round_config().domain_size,
        pcs.round_folding_factor(pcs.n_rounds()),
        pcs.final_queries,
        challenger,
    )?;
    #[cfg(test)]
    trace_streaming_phase("final-polynomial-complete");
    let (openings, query_value_kind) = if let Some(previous) = retained_round_source {
        #[cfg(test)]
        trace_streaming_phase("final-openings-start");
        let openings = stream_prefix_polynomial(
            &previous.polynomial,
            previous.folding_factor,
            previous.inverse_rate,
            Some(&final_query_indices),
        )?;
        if openings.root != previous.root {
            return Err("plain WHIR final round recomputed the wrong prior commitment".to_owned());
        }
        #[cfg(test)]
        trace_streaming_phase("final-openings-complete");
        (openings, previous.query_value_kind)
    } else {
        let initial_polynomial = recompute_initial_polynomial()?;
        let openings = stream_prefix_polynomial(
            &initial_polynomial,
            pcs.round_folding_factor(0),
            1_usize
                .checked_shl(
                    u32::try_from(pcs.params.starting_log_inv_rate)
                        .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
                )
                .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
            Some(&final_query_indices),
        )?;
        if openings.root != *initial_commitment {
            return Err("recomputed initial polynomial has the wrong commitment".to_owned());
        }
        (openings, QueryValueKind::Base)
    };
    proof.final_queries = openings
        .rows
        .into_iter()
        .zip(openings.paths)
        .map(|(values, path)| match query_value_kind {
            QueryValueKind::Base => QueryOpening::Base {
                values,
                proof: path,
            },
            QueryValueKind::Extension => QueryOpening::Extension {
                values,
                proof: path,
            },
        })
        .collect();

    if pcs.final_sumcheck_rounds > 0 {
        let mut sumcheck_data = SumcheckData::default();
        sumcheck_prover.compute_sumcheck_polynomials(
            &mut sumcheck_data,
            challenger,
            pcs.final_sumcheck_rounds,
            pcs.final_folding_pow_bits,
            None,
        );
        proof.final_sumcheck = Some(sumcheck_data);
    }
    Ok(())
}

fn sample_distinct_query_indices(
    domain_size: usize,
    folding_factor: usize,
    query_count: usize,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<usize>, String> {
    let folded_domain_size = domain_size
        .checked_shr(
            u32::try_from(folding_factor)
                .map_err(|_| "plain WHIR folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR folded query domain overflowed".to_owned())?;
    if folded_domain_size == 0 || !folded_domain_size.is_power_of_two() {
        return Err("plain WHIR folded query domain is not a nonzero power of two".to_owned());
    }
    let bit_length = folded_domain_size.ilog2() as usize;
    let target_count = query_count.min(folded_domain_size);
    let mut indices = Vec::with_capacity(target_count);
    while indices.len() < target_count {
        let candidate = challenger
            .sample_uniform_bits::<true>(bit_length)
            .map_err(|_| {
                "plain WHIR query sampling unexpectedly requested resampling".to_owned()
            })?;
        if !indices.contains(&candidate) {
            indices.push(candidate);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

struct StreamingMatrixLeafHasher {
    states: Vec<[u64; SHAKE256_STATE_WORD_LENGTH]>,
    next_rate_byte: usize,
}

impl StreamingMatrixLeafHasher {
    fn new(row_count: usize) -> Result<Self, String> {
        if row_count == 0 || row_count > MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT {
            return Err("plain WHIR leaf-hasher stripe has an unsupported row count".to_owned());
        }
        let mut base_state = [0_u64; SHAKE256_STATE_WORD_LENGTH];
        let mut next_rate_byte = 0_usize;
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
        );
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            &(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len() as u64).to_le_bytes(),
        );
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
        );
        Ok(Self {
            states: vec![base_state; row_count],
            next_rate_byte,
        })
    }

    fn absorb_column(&mut self, column: &[ChallengeField]) -> Result<(), String> {
        if column.len() != self.states.len() {
            return Err("plain WHIR encoded column has the wrong row count".to_owned());
        }
        let starting_rate_byte = self.next_rate_byte;
        let mut expected_next_rate_byte = None;
        for (state, value) in self.states.iter_mut().zip(column) {
            let mut next_rate_byte = starting_rate_byte;
            for coefficient in
                <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(value)
            {
                absorb_shake_word(state, &mut next_rate_byte, coefficient.as_canonical_u64());
            }
            if let Some(expected) = expected_next_rate_byte {
                debug_assert_eq!(next_rate_byte, expected);
            } else {
                expected_next_rate_byte = Some(next_rate_byte);
            }
        }
        self.next_rate_byte = expected_next_rate_byte.unwrap_or(starting_rate_byte);
        Ok(())
    }

    fn finish_digests(self) -> impl Iterator<Item = MerkleDigest> {
        let next_rate_byte = self.next_rate_byte;
        self.states.into_iter().map(move |mut state| {
            xor_shake_byte(&mut state, next_rate_byte, SHAKE256_DELIMITER);
            xor_shake_byte(
                &mut state,
                SHAKE256_RATE_BYTE_LENGTH - 1,
                SHAKE256_FINAL_BIT,
            );
            keccakf(&mut state);
            core::array::from_fn(|word_index| state[word_index])
        })
    }
}

fn absorb_shake_bytes(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_byte: &mut usize,
    bytes: &[u8],
) {
    for byte in bytes {
        xor_shake_byte(state, *next_rate_byte, *byte);
        *next_rate_byte += 1;
        if *next_rate_byte == SHAKE256_RATE_BYTE_LENGTH {
            keccakf(state);
            *next_rate_byte = 0;
        }
    }
}

fn absorb_shake_word(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_byte: &mut usize,
    word: u64,
) {
    let available_rate_bytes = SHAKE256_RATE_BYTE_LENGTH - *next_rate_byte;
    if available_rate_bytes >= size_of::<u64>() {
        let state_word_index = *next_rate_byte / size_of::<u64>();
        let bit_offset = (*next_rate_byte % size_of::<u64>()) * u8::BITS as usize;
        state[state_word_index] ^= word << bit_offset;
        if bit_offset != 0 {
            state[state_word_index + 1] ^= word >> (u64::BITS as usize - bit_offset);
        }
        *next_rate_byte += size_of::<u64>();
        if *next_rate_byte == SHAKE256_RATE_BYTE_LENGTH {
            keccakf(state);
            *next_rate_byte = 0;
        }
        return;
    }

    let bytes = word.to_le_bytes();
    absorb_shake_bytes(state, next_rate_byte, &bytes[..available_rate_bytes]);
    absorb_shake_bytes(state, next_rate_byte, &bytes[available_rate_bytes..]);
}

fn xor_shake_byte(state: &mut [u64; SHAKE256_STATE_WORD_LENGTH], rate_byte_index: usize, byte: u8) {
    debug_assert!(rate_byte_index < SHAKE256_RATE_BYTE_LENGTH);
    let word_index = rate_byte_index / size_of::<u64>();
    let bit_offset = (rate_byte_index % size_of::<u64>()) * u8::BITS as usize;
    state[word_index] ^= u64::from(byte) << bit_offset;
}

fn stream_prefix_polynomial(
    polynomial: &Poly<ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
    query_indices: Option<&[usize]>,
) -> Result<MatrixOpenings, String> {
    stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
        polynomial,
        folding_factor,
        inverse_rate,
        query_indices,
        MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT,
    )
}

fn stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
    polynomial: &Poly<ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
    query_indices: Option<&[usize]>,
    maximum_leaf_hasher_row_count: usize,
) -> Result<MatrixOpenings, String> {
    let (width, source_height, height) =
        prefix_encoding_geometry(polynomial, folding_factor, inverse_rate)?;
    if maximum_leaf_hasher_row_count == 0
        || !maximum_leaf_hasher_row_count.is_power_of_two()
        || maximum_leaf_hasher_row_count > MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
    {
        return Err("plain WHIR leaf-hasher stripe bound is invalid".to_owned());
    }
    if query_indices.is_some_and(|indices| {
        indices.windows(2).any(|window| window[0] >= window[1])
            || indices.last().is_some_and(|last| *last >= height)
    }) {
        return Err("plain WHIR query indices are not canonical for the matrix".to_owned());
    }

    let mut opened_rows = query_indices.map_or_else(Vec::new, |indices| {
        vec![vec![ChallengeField::ZERO; width]; indices.len()]
    });
    let capture_targets = query_indices.map(|indices| merkle_capture_targets(height, indices));
    let mut merkle_builder = StreamingMerkleBuilder::new(height, capture_targets.as_ref())?;
    let transform = Radix2Dit::<ChallengeField>::default();
    for stripe_start in (0..height).step_by(maximum_leaf_hasher_row_count) {
        let stripe_end = stripe_start
            .checked_add(maximum_leaf_hasher_row_count)
            .map_or(height, |end| end.min(height));
        let mut leaf_hasher = StreamingMatrixLeafHasher::new(stripe_end - stripe_start)?;
        for source_column in 0..width {
            let source_start = source_column * source_height;
            let mut encoded_column = ChallengeField::zero_vec(height);
            encoded_column[..source_height].copy_from_slice(
                &polynomial.as_slice()[source_start..source_start + source_height],
            );
            let encoded_column = transform.dft(encoded_column);
            if let Some(indices) = query_indices {
                for (query_ordinal, query_index) in indices.iter().copied().enumerate() {
                    if (stripe_start..stripe_end).contains(&query_index) {
                        opened_rows[query_ordinal][source_column] = encoded_column[query_index];
                    }
                }
            }
            leaf_hasher.absorb_column(&encoded_column[stripe_start..stripe_end])?;
        }
        for digest in leaf_hasher.finish_digests() {
            merkle_builder.push(digest)?;
        }
    }

    let (root, paths) = merkle_builder.finish()?;
    Ok(MatrixOpenings {
        root: MerkleCap::new(vec![root]),
        rows: opened_rows,
        paths: paths.unwrap_or_default(),
    })
}

fn prefix_encoding_geometry(
    polynomial: &Poly<ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
) -> Result<(usize, usize, usize), String> {
    if folding_factor > polynomial.num_variables() {
        return Err("plain WHIR folding factor exceeds the polynomial arity".to_owned());
    }
    if inverse_rate == 0 || !inverse_rate.is_power_of_two() {
        return Err("plain WHIR inverse rate is not a nonzero power of two".to_owned());
    }
    let width = 1_usize
        .checked_shl(
            u32::try_from(folding_factor)
                .map_err(|_| "plain WHIR folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR encoded width overflowed".to_owned())?;
    let source_height = 1_usize
        .checked_shl(
            u32::try_from(polynomial.num_variables() - folding_factor)
                .map_err(|_| "plain WHIR source height exponent exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR source height overflowed".to_owned())?;
    let height = source_height
        .checked_mul(inverse_rate)
        .ok_or_else(|| "plain WHIR encoded height overflowed".to_owned())?;
    let expected_source_value_count = source_height
        .checked_mul(width)
        .ok_or_else(|| "plain WHIR source value count overflowed".to_owned())?;
    if polynomial.as_slice().len() != expected_source_value_count {
        return Err("plain WHIR polynomial length does not match its arity".to_owned());
    }
    Ok((width, source_height, height))
}

#[cfg(test)]
fn encode_prefix_polynomial(
    polynomial: &Poly<ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
) -> Result<EncodedMatrix, String> {
    let (width, source_height, height) =
        prefix_encoding_geometry(polynomial, folding_factor, inverse_rate)?;
    let value_count = height
        .checked_mul(width)
        .ok_or_else(|| "plain WHIR encoded value count overflowed".to_owned())?;
    let mut values = ChallengeField::zero_vec(value_count);
    for source_row in 0..source_height {
        for source_column in 0..width {
            values[source_row * width + source_column] =
                polynomial.as_slice()[source_column * source_height + source_row];
        }
    }
    bounded_dft_rows(&mut values, width, height)?;
    Ok(EncodedMatrix {
        values,
        width,
        height,
    })
}

#[cfg(test)]
fn bounded_dft_rows(
    values: &mut Vec<ChallengeField>,
    width: usize,
    height: usize,
) -> Result<(), String> {
    let expected_value_count = width
        .checked_mul(height)
        .ok_or_else(|| "plain WHIR DFT matrix value count overflowed".to_owned())?;
    if height == 0 || !height.is_power_of_two() || values.len() != expected_value_count {
        return Err("plain WHIR DFT matrix has invalid geometry".to_owned());
    }
    if height == 1 {
        return Ok(());
    }
    let matrix = RowMajorMatrix::new(core::mem::take(values), width);
    *values = Radix2Dit::<ChallengeField>::default()
        .dft_batch(matrix)
        .values;
    Ok(())
}

fn node_compressor() -> NodeCompressor {
    NodeCompressor::new(DomainSeparatedShake256 {
        domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    })
}

type CaptureTargets = Vec<BTreeMap<usize, Vec<(usize, usize)>>>;
type MerkleBuilderOutput = (MerkleDigest, Option<Vec<Vec<MerkleDigest>>>);

fn merkle_capture_targets(height: usize, query_indices: &[usize]) -> CaptureTargets {
    let tree_depth = height.ilog2() as usize;
    let mut capture_targets = vec![BTreeMap::<usize, Vec<(usize, usize)>>::new(); tree_depth];
    for (query_ordinal, query_index) in query_indices.iter().copied().enumerate() {
        for (level, level_targets) in capture_targets.iter_mut().enumerate() {
            let sibling_index = (query_index >> level) ^ 1;
            level_targets
                .entry(sibling_index)
                .or_default()
                .push((query_ordinal, level));
        }
    }
    capture_targets
}

struct StreamingMerkleBuilder<'capture> {
    leaf_count: usize,
    next_leaf_index: usize,
    capture_targets: Option<&'capture CaptureTargets>,
    paths: Option<Vec<Vec<MerkleDigest>>>,
    captured: Option<Vec<Vec<bool>>>,
    frontier: Vec<Option<MerkleDigest>>,
    compressor: NodeCompressor,
}

impl<'capture> StreamingMerkleBuilder<'capture> {
    fn new(
        leaf_count: usize,
        capture_targets: Option<&'capture CaptureTargets>,
    ) -> Result<Self, String> {
        if leaf_count == 0 || !leaf_count.is_power_of_two() {
            return Err("plain WHIR Merkle leaf count is not a power of two".to_owned());
        }
        let tree_depth = leaf_count.ilog2() as usize;
        if capture_targets.is_some_and(|targets| targets.len() != tree_depth) {
            return Err("plain WHIR Merkle capture depth is invalid".to_owned());
        }
        let query_count = capture_targets
            .map(|targets| {
                targets
                    .iter()
                    .flat_map(BTreeMap::values)
                    .flat_map(|placements| placements.iter().map(|(ordinal, _)| *ordinal))
                    .max()
                    .map_or(0, |maximum| maximum + 1)
            })
            .unwrap_or(0);
        Ok(Self {
            leaf_count,
            next_leaf_index: 0,
            capture_targets,
            paths: capture_targets
                .map(|_| vec![vec![[0_u64; MERKLE_DIGEST_WORD_LENGTH]; tree_depth]; query_count]),
            captured: capture_targets.map(|_| vec![vec![false; tree_depth]; query_count]),
            frontier: vec![None::<MerkleDigest>; tree_depth + 1],
            compressor: node_compressor(),
        })
    }

    fn push(&mut self, mut digest: MerkleDigest) -> Result<(), String> {
        if self.next_leaf_index >= self.leaf_count {
            return Err("plain WHIR Merkle builder received an extra leaf".to_owned());
        }
        let leaf_index = self.next_leaf_index;
        let mut level = 0_usize;
        let mut node_index = leaf_index;
        capture_digest(
            self.capture_targets,
            self.paths.as_mut(),
            self.captured.as_mut(),
            level,
            node_index,
            digest,
        )?;
        loop {
            let Some(left_digest) = self.frontier[level].take() else {
                self.frontier[level] = Some(digest);
                break;
            };
            digest = self.compressor.compress([left_digest, digest]);
            level += 1;
            node_index >>= 1;
            capture_digest(
                self.capture_targets,
                self.paths.as_mut(),
                self.captured.as_mut(),
                level,
                node_index,
                digest,
            )?;
        }
        self.next_leaf_index += 1;
        Ok(())
    }

    fn finish(self) -> Result<MerkleBuilderOutput, String> {
        if self.next_leaf_index != self.leaf_count {
            return Err("plain WHIR Merkle builder ended before its final leaf".to_owned());
        }
        let tree_depth = self.leaf_count.ilog2() as usize;
        let root = self
            .frontier
            .last()
            .and_then(|root| *root)
            .ok_or_else(|| "plain WHIR Merkle walk did not produce a root".to_owned())?;
        if self.frontier[..tree_depth].iter().any(Option::is_some) {
            return Err("plain WHIR Merkle walk left an incomplete frontier".to_owned());
        }
        if self
            .captured
            .as_ref()
            .is_some_and(|captured| captured.iter().flatten().any(|was_captured| !was_captured))
        {
            return Err(
                "plain WHIR Merkle walk did not capture every authentication node".to_owned(),
            );
        }
        Ok((root, self.paths))
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_digest(
    capture_targets: Option<&CaptureTargets>,
    paths: Option<&mut Vec<Vec<MerkleDigest>>>,
    captured: Option<&mut Vec<Vec<bool>>>,
    level: usize,
    node_index: usize,
    digest: MerkleDigest,
) -> Result<(), String> {
    let (Some(targets), Some(paths), Some(captured)) = (capture_targets, paths, captured) else {
        return Ok(());
    };
    let Some(level_targets) = targets.get(level) else {
        return Ok(());
    };
    let Some(placements) = level_targets.get(&node_index) else {
        return Ok(());
    };
    for (query_ordinal, path_position) in placements {
        let was_captured = captured
            .get_mut(*query_ordinal)
            .and_then(|query| query.get_mut(*path_position))
            .ok_or_else(|| "plain WHIR Merkle capture target is out of range".to_owned())?;
        if *was_captured {
            return Err("plain WHIR Merkle authentication node was captured twice".to_owned());
        }
        paths[*query_ordinal][*path_position] = digest;
        *was_captured = true;
    }
    Ok(())
}

fn empty_plain_whir_proof(
    pcs: &PlainAggregatePcs,
) -> WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme> {
    WhirProof {
        initial_ood_answers: Vec::with_capacity(pcs.commitment_ood_samples),
        initial_sumcheck: Default::default(),
        rounds: (0..pcs.n_rounds())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: ChallengeField::ZERO,
        final_queries: Vec::with_capacity(pcs.final_queries),
        final_sumcheck: None,
    }
}

#[cfg(test)]
mod tests {
    use p3_commit::Mmcs;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_sumcheck::layout::Table;

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::{
        plain_whir::{
            commit_plain_aggregate_batch, open_plain_aggregate_batches_at_points,
            plain_aggregate_challenger, plain_aggregate_pcs_with_parameters,
            verify_plain_aggregate_batches_at_points,
        },
        plain_whir_wire::encode_plain_whir_batch_proof,
    };

    fn deterministic_messages(variable_count: usize, width: usize) -> Vec<Poly<ChallengeField>> {
        (0..width)
            .map(|column_index| {
                Poly::new(
                    (0..1_usize << variable_count)
                        .map(|row_index| {
                            ChallengeField::from_u64(
                                column_index as u64 * 65_537 + row_index as u64 * 257 + 11,
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn bounded_dft_matches_the_upstream_transform() {
        let width = 8;
        let height = 64;
        let original = (0..width * height)
            .map(|index| ChallengeField::from_u64(index as u64 * 17 + 5))
            .collect::<Vec<_>>();
        let expected = super::super::DiscreteFourierTransform::default()
            .dft_batch(RowMajorMatrix::new(original.clone(), width))
            .values;
        let mut actual = original;
        bounded_dft_rows(&mut actual, width, height).expect("bounded DFT");
        assert_eq!(actual, expected);
    }

    #[test]
    fn column_streamed_merkle_paths_match_the_upstream_commitment() {
        let polynomial = Poly::new(
            (0..1_usize << 9)
                .map(|index| ChallengeField::from_u64(index as u64 * 31 + 7))
                .collect(),
        );
        let matrix = encode_prefix_polynomial(&polynomial, 3, 4).expect("encoded matrix");
        let pcs = plain_aggregate_pcs_with_parameters(9, 2, 3).expect("plain WHIR");
        let upstream_matrix = RowMajorMatrix::new(matrix.values.clone(), matrix.width);
        let (upstream_root, upstream_data) = pcs.mmcs.commit_matrix(upstream_matrix);
        let query_indices = [0, 1, 7, 19, matrix.height - 1];
        let streamed = stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
            &polynomial,
            3,
            4,
            Some(&query_indices),
            16,
        )
        .expect("stripe-streamed openings");
        assert_eq!(streamed.root, upstream_root);
        for (query_ordinal, query_index) in query_indices.iter().copied().enumerate() {
            let upstream = pcs.mmcs.open_batch(query_index, &upstream_data);
            assert_eq!(streamed.rows[query_ordinal], upstream.opened_values[0]);
            assert_eq!(streamed.paths[query_ordinal], upstream.opening_proof);
        }
    }

    #[test]
    fn bounded_prover_matches_upstream_canonical_bytes() {
        let table_variable_count = 10;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let points = vec![
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 3 + 2))
                    .collect(),
            ),
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 11 + 5))
                    .collect(),
            ),
        ];
        let requested_columns = vec![vec![0, 2], vec![1, 3]];
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let statement = b"bounded plain WHIR parity";

        let mut upstream_challenger = plain_aggregate_challenger(&pcs, statement);
        let (upstream_commitment, upstream_data) =
            commit_plain_aggregate_batch(&pcs, messages.clone(), &mut upstream_challenger);
        let upstream_proof = open_plain_aggregate_batches_at_points(
            &pcs,
            upstream_data,
            &points,
            &requested_columns,
            &mut upstream_challenger,
        );

        let witness =
            AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
        let initial_polynomial = witness.poly().clone();
        let mut bounded_challenger = plain_aggregate_challenger(&pcs, statement);
        let (bounded_commitment, bounded_data) =
            commit_streaming_plain_aggregate(&pcs, witness, &mut bounded_challenger)
                .expect("bounded commitment");
        let bounded_proof = open_streaming_plain_aggregate_batches_at_points(
            &pcs,
            &bounded_commitment,
            bounded_data,
            &points,
            &requested_columns,
            &mut bounded_challenger,
            || Ok(initial_polynomial.clone()),
        )
        .expect("bounded proof");

        assert_eq!(bounded_commitment, upstream_commitment);
        let upstream_wire =
            encode_plain_whir_batch_proof(&pcs, &upstream_proof, &[2, 2], table_width)
                .expect("encode upstream proof");
        let bounded_wire =
            encode_plain_whir_batch_proof(&pcs, &bounded_proof, &[2, 2], table_width)
                .expect("encode bounded proof");
        assert_eq!(bounded_wire, upstream_wire);

        let mut verifier_challenger = plain_aggregate_challenger(&pcs, statement);
        verify_plain_aggregate_batches_at_points(
            &pcs,
            &bounded_commitment,
            &bounded_proof,
            &points,
            table_variable_count,
            table_width,
            &requested_columns,
            &mut verifier_challenger,
        )
        .expect("verify bounded proof");
    }

    #[test]
    fn recomputed_initial_polynomial_is_bound_to_the_commitment() {
        let table_variable_count = 6;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let witness =
            AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
        let mut challenger = plain_aggregate_challenger(&pcs, b"changed initial source");
        let (commitment, prover_data) =
            commit_streaming_plain_aggregate(&pcs, witness, &mut challenger)
                .expect("bounded commitment");
        let point = Point::new(vec![ChallengeField::TWO; table_variable_count]);
        let changed = Poly::new(vec![ChallengeField::ONE; 1_usize << variable_count]);
        let result = open_streaming_plain_aggregate_batches_at_points(
            &pcs,
            &commitment,
            prover_data,
            &[point],
            &[vec![0]],
            &mut challenger,
            || Ok(changed.clone()),
        );
        let error = match result {
            Ok(_) => panic!("changed recomputed source must fail"),
            Err(error) => error,
        };
        assert!(error.contains("wrong commitment"));
    }

    #[test]
    fn stripe_streaming_bounds_live_leaf_hash_states() {
        let exact_initial_height = 1_usize << 20;
        let full_leaf_state_byte_length =
            exact_initial_height * SHAKE256_STATE_WORD_LENGTH * core::mem::size_of::<u64>();
        let striped_leaf_state_byte_length = MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
            * SHAKE256_STATE_WORD_LENGTH
            * core::mem::size_of::<u64>();
        let encoded_column_byte_length =
            exact_initial_height * core::mem::size_of::<ChallengeField>();
        assert_eq!(
            exact_initial_height / MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT,
            32
        );
        assert_eq!(striped_leaf_state_byte_length, 6_553_600);
        assert!(striped_leaf_state_byte_length < full_leaf_state_byte_length / 16);
        assert!(striped_leaf_state_byte_length + encoded_column_byte_length < 64 * 1_048_576);
    }
}
