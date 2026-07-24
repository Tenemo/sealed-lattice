//! Explicit-point plain WHIR adapter for the masked aggregate polynomial.
//!
//! The upstream plain adapter samples univariate opening points internally.
//! This construction instead receives points already derived by the enclosing
//! relation and column-reduction transcript. The pinned local sumcheck copy
//! exposes an explicit-point claim method that absorbs each point before its
//! evaluation, preserving commitment-before-challenge ordering.

use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch,
    layout::{Layout, PrefixProver, Table, Verifier, Witness},
    table::{OpeningProtocol, TableShape, TableSpec},
};
use p3_whir::{
    DomainSeparator, FoldingFactor, PcsProof, ProtocolParameters, SecurityAssumption, WhirConfig,
    WhirProof, WhirProver, WhirProverData, WhirRoundProof, WhirVerifier,
};

use super::{
    ChallengeField, CommitmentScheme, DiscreteFourierTransform, ExtensionFieldChallenger,
    LeafHasher, NodeCompressor,
};

const STARTING_LOG_INV_RATE: usize = 2;
const FOLDING_FACTOR: usize = 4;
const SECURITY_LEVEL: usize = super::PROTOCOL_SECURITY_LEVEL;

type AggregateLayout = PrefixProver<ChallengeField, ChallengeField>;
pub(super) type PlainAggregatePcs = WhirProver<
    ChallengeField,
    ChallengeField,
    DiscreteFourierTransform,
    CommitmentScheme,
    ExtensionFieldChallenger,
    AggregateLayout,
>;
pub(super) type PlainAggregateCommitment =
    <PlainAggregatePcs as MultilinearPcs<ChallengeField, ExtensionFieldChallenger>>::Commitment;
pub(super) type PlainAggregateProof = PcsProof<ChallengeField, ChallengeField, CommitmentScheme>;

pub(super) fn plain_aggregate_pcs(variable_count: usize) -> Result<PlainAggregatePcs, String> {
    plain_aggregate_pcs_with_parameters(variable_count, STARTING_LOG_INV_RATE, FOLDING_FACTOR)
}

fn plain_aggregate_pcs_with_parameters(
    variable_count: usize,
    starting_log_inverse_rate: usize,
    folding_factor: usize,
) -> Result<PlainAggregatePcs, String> {
    let configuration =
        WhirConfig::<ChallengeField, ChallengeField, ExtensionFieldChallenger>::new(
            variable_count,
            ProtocolParameters {
                starting_log_inv_rate: starting_log_inverse_rate,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::Constant(folding_factor),
                soundness_type: SecurityAssumption::UniqueDecoding,
                security_level: SECURITY_LEVEL,
                pow_bits: 0,
            },
        )
        .map_err(|error| format!("construct plain WHIR configuration: {error}"))?;
    let commitment_scheme = CommitmentScheme::new(
        LeafHasher::new(super::DomainSeparatedShake256 {
            domain: b"aggregate-plain-pcs/merkle-leaf/v1",
        }),
        NodeCompressor::new(super::DomainSeparatedShake256 {
            domain: b"aggregate-plain-pcs/merkle-node/v1",
        }),
        0,
    );
    Ok(WhirProver::new(
        configuration,
        DiscreteFourierTransform::default(),
        commitment_scheme,
    ))
}

pub(super) fn plain_aggregate_challenger(
    pcs: &PlainAggregatePcs,
    statement: &[u8],
) -> ExtensionFieldChallenger {
    let mut initial_state =
        b"sealed-lattice/streaming-polynomial-commitment/plain-aggregate/v1".to_vec();
    initial_state.extend_from_slice(&(statement.len() as u64).to_le_bytes());
    initial_state.extend_from_slice(statement);
    let mut challenger =
        ExtensionFieldChallenger::new(initial_state, b"aggregate-plain-pcs/challenges/v1");
    let mut separator = DomainSeparator::<ChallengeField, ChallengeField>::new(Vec::new());
    pcs.add_domain_separator::<{ super::MERKLE_DIGEST_WORD_LENGTH }>(&mut separator);
    separator.observe_domain_separator(&mut challenger);
    challenger
}

pub(super) fn plain_aggregate_opening_protocol_for_requests(
    variable_count: usize,
    table_width: usize,
    requested_columns_by_point: &[Vec<usize>],
) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(variable_count, table_width),
        requested_columns_by_point
            .iter()
            .cloned()
            .map(|requested_columns| OpeningBatch::new(requested_columns, Vec::new()))
            .collect(),
    )])
}

pub(super) fn commit_plain_aggregate(
    pcs: &PlainAggregatePcs,
    message: Poly<ChallengeField>,
    challenger: &mut ExtensionFieldChallenger,
) -> (
    PlainAggregateCommitment,
    WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
) {
    commit_plain_aggregate_batch(pcs, vec![message], challenger)
}

pub(super) fn commit_plain_aggregate_batch(
    pcs: &PlainAggregatePcs,
    messages: Vec<Poly<ChallengeField>>,
    challenger: &mut ExtensionFieldChallenger,
) -> (
    PlainAggregateCommitment,
    WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
) {
    let witness: Witness<ChallengeField> =
        AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
    pcs.commit(witness, challenger)
}

pub(super) fn open_plain_aggregate_at_points(
    pcs: &PlainAggregatePcs,
    prover_data: WhirProverData<ChallengeField, ChallengeField, CommitmentScheme, AggregateLayout>,
    points: &[Point<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> PlainAggregateProof {
    let requested_columns_by_point = vec![vec![0]; points.len()];
    open_plain_aggregate_batches_at_points(
        pcs,
        prover_data,
        points,
        &requested_columns_by_point,
        challenger,
    )
}

pub(super) fn open_plain_aggregate_batches_at_points(
    pcs: &PlainAggregatePcs,
    mut prover_data: WhirProverData<
        ChallengeField,
        ChallengeField,
        CommitmentScheme,
        AggregateLayout,
    >,
    points: &[Point<ChallengeField>],
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
) -> PlainAggregateProof {
    assert_eq!(points.len(), requested_columns_by_point.len());
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
    pcs.prove(
        &mut whir,
        challenger,
        prover_data.layout,
        prover_data.merkle_data,
    );
    PcsProof {
        whir,
        evals: evaluations,
    }
}

pub(super) fn verify_plain_aggregate_at_points(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    let requested_columns_by_point = vec![vec![0]; points.len()];
    verify_plain_aggregate_batches_at_points(
        pcs,
        commitment,
        proof,
        points,
        pcs.num_variables,
        1,
        &requested_columns_by_point,
        challenger,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_plain_aggregate_batches_at_points(
    pcs: &PlainAggregatePcs,
    commitment: &PlainAggregateCommitment,
    proof: &PlainAggregateProof,
    points: &[Point<ChallengeField>],
    table_variable_count: usize,
    table_width: usize,
    requested_columns_by_point: &[Vec<usize>],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(), String> {
    if proof.evals.len() != points.len() {
        return Err(format!(
            "plain WHIR proof has {} opening batches for {} explicit points",
            proof.evals.len(),
            points.len()
        ));
    }
    if requested_columns_by_point.len() != points.len()
        || requested_columns_by_point.iter().any(|columns| {
            columns.is_empty() || columns.iter().any(|column| *column >= table_width)
        })
    {
        return Err("plain WHIR opening requests do not match the committed table".to_owned());
    }
    challenger.observe(commitment.clone());
    let protocol = plain_aggregate_opening_protocol_for_requests(
        table_variable_count,
        table_width,
        requested_columns_by_point,
    );
    let mut layout_verifier = Verifier::<ChallengeField, ChallengeField>::new(
        &protocol.table_shapes(),
        AggregateLayout::strategy(),
    );
    if proof.whir.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(format!(
            "plain WHIR proof has {} initial OOD answers, expected {}",
            proof.whir.initial_ood_answers.len(),
            pcs.commitment_ood_samples
        ));
    }
    for evaluation in &proof.whir.initial_ood_answers {
        layout_verifier.add_virtual_eval(*evaluation, challenger);
    }
    for ((point, evaluations), requested_columns) in points
        .iter()
        .cloned()
        .zip(&proof.evals)
        .zip(requested_columns_by_point)
    {
        let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
        layout_verifier
            .add_claim_at_point(0, &request, evaluations, point, challenger)
            .map_err(|error| format!("register explicit plain WHIR claim: {error}"))?;
    }
    let batching_challenge = challenger.sample_algebra_element();
    let constraint = layout_verifier.constraint(batching_challenge);
    let mut claimed_evaluation = ChallengeField::ZERO;
    constraint.combine_evals(&mut claimed_evaluation);
    WhirVerifier::new(&pcs.config, &pcs.mmcs, AggregateLayout::variable_order())
        .verify(
            &proof.whir,
            challenger,
            commitment,
            constraint,
            claimed_evaluation,
        )
        .map(|_| ())
        .map_err(|error| format!("verify explicit-point plain WHIR proof: {error}"))
}

fn empty_plain_whir_proof(
    pcs: &PlainAggregatePcs,
) -> WhirProof<ChallengeField, ChallengeField, CommitmentScheme> {
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
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::bgv::proof_suite::backend_spike::streaming_polynomial_commitment::ChallengeField;

    #[test]
    fn target_plain_aggregate_configuration_is_pinned() {
        let pcs = plain_aggregate_pcs(20).expect("plain WHIR configuration");
        assert_eq!(pcs.num_variables, 20);
        assert_eq!(pcs.params.starting_log_inv_rate, STARTING_LOG_INV_RATE);
        assert_eq!(pcs.params.security_level, SECURITY_LEVEL);
        assert_eq!(
            pcs.params.soundness_type,
            SecurityAssumption::UniqueDecoding
        );
        assert_eq!(pcs.params.pow_bits, 0);
        assert_eq!(pcs.folding_schedule, [4, 4, 4, 4]);
        assert_eq!(
            pcs.round_parameters
                .iter()
                .map(|round| (
                    round.num_variables,
                    round.log_inv_rate,
                    round.num_queries,
                    round.pow_bits,
                    round.folding_pow_bits,
                    round.ood_samples,
                ))
                .collect::<Vec<_>>(),
            [
                (16, 5, 384, 0, 0, 0),
                (12, 8, 273, 0, 0, 0),
                (8, 11, 262, 0, 0, 0)
            ]
        );
        assert_eq!(pcs.starting_folding_pow_bits, 0);
        assert_eq!(pcs.final_queries, 261);
        assert_eq!(pcs.final_pow_bits, 0);
        assert_eq!(pcs.final_folding_pow_bits, 0);
        assert_eq!(pcs.final_round_config().num_variables, 4);
        assert_eq!(pcs.final_round_config().log_inv_rate, 11);
        assert!(pcs.check_pow_bits());
    }

    #[test]
    fn explicit_points_are_bound_and_verified() {
        let variable_count = 8;
        let pcs = plain_aggregate_pcs(variable_count).expect("plain WHIR configuration");
        let mut prover_challenger = plain_aggregate_challenger(&pcs, b"plain explicit-point test");
        let message = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 19 + 7))
                .collect(),
        );
        let points = vec![
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 + 2))
                    .collect(),
            ),
            Point::new(
                (0..variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 3 + 11))
                    .collect(),
            ),
        ];
        let (commitment, prover_data) =
            commit_plain_aggregate(&pcs, message, &mut prover_challenger);
        let proof =
            open_plain_aggregate_at_points(&pcs, prover_data, &points, &mut prover_challenger);

        let verifier_pcs = plain_aggregate_pcs(variable_count).expect("verifier configuration");
        let mut verifier_challenger =
            plain_aggregate_challenger(&verifier_pcs, b"plain explicit-point test");
        verify_plain_aggregate_at_points(
            &verifier_pcs,
            &commitment,
            &proof,
            &points,
            &mut verifier_challenger,
        )
        .expect("verify explicit points");

        let mut changed_coordinates = points[0].as_slice().to_vec();
        changed_coordinates[0] += ChallengeField::ONE;
        let mut changed_points = points;
        changed_points[0] = Point::new(changed_coordinates);
        let mut changed_verifier_challenger =
            plain_aggregate_challenger(&verifier_pcs, b"plain explicit-point test");
        assert!(
            verify_plain_aggregate_at_points(
                &verifier_pcs,
                &commitment,
                &proof,
                &changed_points,
                &mut changed_verifier_challenger,
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "manual target-size evidence"]
    fn heavy_rust_kernel_target_plain_whir_aggregate_proof_size() {
        use std::collections::BTreeSet;

        let variable_count = 20;
        let opening_count = 480;
        let pcs = plain_aggregate_pcs(variable_count).expect("plain WHIR configuration");
        let statement = b"plain aggregate target-size evidence";
        let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
        let message = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 1_000_003 + 41))
                .collect(),
        );
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let (commitment, prover_data) =
            commit_plain_aggregate(&pcs, message, &mut prover_challenger);
        let proof =
            open_plain_aggregate_at_points(&pcs, prover_data, &points, &mut prover_challenger);
        let encoded = postcard::to_allocvec(&proof).expect("encode target plain WHIR proof");
        println!("plain aggregate proof bytes: {}", encoded.len());
        let canonical =
            super::super::plain_whir_wire::encode_plain_whir_proof(&pcs, &proof, opening_count)
                .expect("encode bounded canonical plain WHIR proof");
        let breakdown =
            super::super::plain_whir_wire::plain_whir_wire_breakdown(&pcs, &proof, opening_count)
                .expect("measure canonical plain WHIR proof");
        println!(
            "canonical plain aggregate proof bytes: {}, query values: {}, dictionary: {}, references: {}",
            canonical.len(),
            breakdown.query_value_byte_length,
            breakdown.merkle_dictionary_byte_length,
            breakdown.merkle_reference_byte_length,
        );
        println!(
            "plain WHIR rounds: {}, initial fold: {}, final queries: {}, final variables: {}",
            pcs.n_rounds(),
            pcs.round_folding_factor(0),
            pcs.final_queries,
            pcs.final_round_config().num_variables,
        );
        for (round_index, round) in proof.whir.rounds.iter().enumerate() {
            let first_query = round.queries.first().expect("round query");
            let (value_count, path_count) = match first_query {
                p3_whir::QueryOpening::Base { values, proof }
                | p3_whir::QueryOpening::Extension { values, proof } => (values.len(), proof.len()),
            };
            println!(
                "round {round_index}: queries {}, values {}, path {}, OOD {}, sumcheck {}",
                round.queries.len(),
                value_count,
                path_count,
                round.ood_answers.len(),
                round.sumcheck.num_rounds(),
            );
        }
        let first_final_query = proof.whir.final_queries.first().expect("final query");
        let (final_value_count, final_path_count) = match first_final_query {
            p3_whir::QueryOpening::Base { values, proof }
            | p3_whir::QueryOpening::Extension { values, proof } => (values.len(), proof.len()),
        };
        println!(
            "final: queries {}, values {}, path {}, sumcheck {}",
            proof.whir.final_queries.len(),
            final_value_count,
            final_path_count,
            proof
                .whir
                .final_sumcheck
                .as_ref()
                .map_or(0, p3_sumcheck::SumcheckData::num_rounds),
        );
        let mut unique_merkle_nodes = BTreeSet::new();
        let mut merkle_references = 0_usize;
        for query in proof
            .whir
            .rounds
            .iter()
            .flat_map(|round| round.queries.iter())
            .chain(proof.whir.final_queries.iter())
        {
            let path = match query {
                p3_whir::QueryOpening::Base { proof, .. }
                | p3_whir::QueryOpening::Extension { proof, .. } => proof,
            };
            merkle_references += path.len();
            unique_merkle_nodes.extend(path.iter().copied());
        }
        println!(
            "Merkle dictionary: {} unique nodes, {} references, {} fixed bytes",
            unique_merkle_nodes.len(),
            merkle_references,
            unique_merkle_nodes.len() * super::super::MERKLE_DIGEST_WORD_LENGTH * 8
                + merkle_references * 4,
        );

        let verifier_pcs = plain_aggregate_pcs(variable_count).expect("verifier configuration");
        let decoded = super::super::plain_whir_wire::decode_plain_whir_proof(
            &verifier_pcs,
            &canonical,
            opening_count,
        )
        .expect("decode bounded canonical plain WHIR proof");
        let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
        verify_plain_aggregate_at_points(
            &verifier_pcs,
            &commitment,
            &decoded,
            &points,
            &mut verifier_challenger,
        )
        .expect("verify target plain WHIR proof");
    }

    #[test]
    #[ignore = "manual parameter-size evidence"]
    fn heavy_rust_kernel_plain_whir_parameter_size_sweep() {
        let variable_count = 20;
        let opening_count = 480;
        let statement = b"plain aggregate parameter-size sweep";
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        for starting_log_inverse_rate in 2..=4 {
            for folding_factor in 4..=8 {
                let Ok(pcs) = plain_aggregate_pcs_with_parameters(
                    variable_count,
                    starting_log_inverse_rate,
                    folding_factor,
                ) else {
                    println!(
                        "configuration start={starting_log_inverse_rate} fold={folding_factor}: invalid"
                    );
                    continue;
                };
                let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
                let message = Poly::new(
                    (0..1_usize << variable_count)
                        .map(|index| ChallengeField::from_u64(index as u64 * 1_000_003 + 41))
                        .collect(),
                );
                let (commitment, prover_data) =
                    commit_plain_aggregate(&pcs, message, &mut prover_challenger);
                let proof = open_plain_aggregate_at_points(
                    &pcs,
                    prover_data,
                    &points,
                    &mut prover_challenger,
                );
                let Ok(canonical) = super::super::plain_whir_wire::encode_plain_whir_proof(
                    &pcs,
                    &proof,
                    opening_count,
                ) else {
                    println!(
                        "configuration start={starting_log_inverse_rate} fold={folding_factor}: exceeds canonical wire cap"
                    );
                    continue;
                };
                let breakdown = super::super::plain_whir_wire::plain_whir_wire_breakdown(
                    &pcs,
                    &proof,
                    opening_count,
                )
                .expect("measure parameter-sweep proof");
                let verifier_pcs = plain_aggregate_pcs_with_parameters(
                    variable_count,
                    starting_log_inverse_rate,
                    folding_factor,
                )
                .expect("reconstruct verifier configuration");
                let decoded = super::super::plain_whir_wire::decode_plain_whir_proof(
                    &verifier_pcs,
                    &canonical,
                    opening_count,
                )
                .expect("decode parameter-sweep proof");
                let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
                verify_plain_aggregate_at_points(
                    &verifier_pcs,
                    &commitment,
                    &decoded,
                    &points,
                    &mut verifier_challenger,
                )
                .expect("verify parameter-sweep proof");
                println!(
                    "configuration start={starting_log_inverse_rate} fold={folding_factor}: bytes={}, values={}, dictionary={}, references={}, rounds={}, final_queries={}, final_variables={}",
                    canonical.len(),
                    breakdown.query_value_byte_length,
                    breakdown.merkle_dictionary_byte_length,
                    breakdown.merkle_reference_byte_length,
                    pcs.n_rounds(),
                    pcs.final_queries,
                    pcs.final_round_config().num_variables,
                );
            }
        }
    }

    #[test]
    #[ignore = "manual exact-layout size evidence"]
    fn heavy_rust_kernel_exact_layout_plain_whir_size() {
        let table_variable_count = 18;
        let opening_count = super::super::protocol::COLUMN_QUERY_COUNT + 3;
        let table_width = 3_usize;
        let selector_variable_count = table_width.next_power_of_two().ilog2() as usize;
        let pcs_variable_count = table_variable_count + selector_variable_count;
        let pcs = plain_aggregate_pcs(pcs_variable_count).expect("exact-layout configuration");
        let statement = b"plain aggregate exact production-layout size";
        let mut prover_challenger = plain_aggregate_challenger(&pcs, statement);
        let messages = (0..table_width)
            .map(|table_column| {
                Poly::new(
                    (0..1_usize << table_variable_count)
                        .map(|index| {
                            ChallengeField::from_u64(
                                index as u64 * 1_000_003 + table_column as u64 * 65_537 + 41,
                            )
                        })
                        .collect(),
                )
            })
            .collect();
        let points = (0..opening_count)
            .map(|opening_index| {
                Point::new(
                    (0..table_variable_count)
                        .map(|variable_index| {
                            ChallengeField::from_u64(
                                opening_index as u64 * 65_537 + variable_index as u64 * 257 + 17,
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let mut requested_columns_by_point = vec![vec![0], vec![1], vec![2]];
        requested_columns_by_point
            .extend((0..super::super::protocol::COLUMN_QUERY_COUNT).map(|_| vec![0, 1, 2]));
        let expected_opening_widths = requested_columns_by_point
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>();
        let (commitment, prover_data) =
            commit_plain_aggregate_batch(&pcs, messages, &mut prover_challenger);
        let proof = open_plain_aggregate_batches_at_points(
            &pcs,
            prover_data,
            &points,
            &requested_columns_by_point,
            &mut prover_challenger,
        );
        let canonical = super::super::plain_whir_wire::encode_plain_whir_batch_proof(
            &pcs,
            &proof,
            &expected_opening_widths,
            table_width,
        )
        .expect("encode exact-layout proof");
        let breakdown = super::super::plain_whir_wire::plain_whir_batch_wire_breakdown(
            &pcs,
            &proof,
            &expected_opening_widths,
            table_width,
        )
        .expect("measure exact-layout proof");
        let verifier_pcs = plain_aggregate_pcs(pcs_variable_count).expect("verifier configuration");
        let decoded = super::super::plain_whir_wire::decode_plain_whir_batch_proof(
            &verifier_pcs,
            &canonical,
            &expected_opening_widths,
            table_width,
        )
        .expect("decode exact-layout proof");
        let mut verifier_challenger = plain_aggregate_challenger(&verifier_pcs, statement);
        verify_plain_aggregate_batches_at_points(
            &verifier_pcs,
            &commitment,
            &decoded,
            &points,
            table_variable_count,
            table_width,
            &requested_columns_by_point,
            &mut verifier_challenger,
        )
        .expect("verify exact-layout proof");
        println!(
            "exact layout: bytes={}, values={}, dictionary={}, references={}, rounds={}, final_queries={}, final_variables={}",
            canonical.len(),
            breakdown.query_value_byte_length,
            breakdown.merkle_dictionary_byte_length,
            breakdown.merkle_reference_byte_length,
            pcs.n_rounds(),
            pcs.final_queries,
            pcs.final_round_config().num_variables,
        );
    }
}
