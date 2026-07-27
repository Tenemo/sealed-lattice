//! Allocation-bounded canonical wire for the explicit-point plain WHIR proof.
//!
//! Every structural length except the Merkle dictionary size is derived from
//! the verifier-owned WHIR configuration and expected opening schedule. Field
//! elements use fixed-width canonical Goldilocks limbs. Merkle paths refer to a
//! first-use-ordered dictionary so repeated authentication nodes are sent once.

use std::collections::BTreeMap;
use std::collections::HashSet;

use p3_field::BasedVectorSpace;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch, SumcheckData,
    constraints::{Constraint, Statements},
};
use p3_symmetric::MerkleCap;
#[cfg(test)]
use p3_whir::PcsProof;
use p3_whir::{QueryOpening, WhirProof, WhirRoundProof};

#[cfg(test)]
use super::super::prover::BoundedCommonProofByteSink;
use super::super::{CommonProofByteSink, MAXIMUM_COMMON_PROOF_BYTE_LENGTH, ProofByteSource};
use super::{
    ChallengeField, ExtensionFieldChallenger, MERKLE_DIGEST_WORD_LENGTH,
    plain_whir::{
        PlainAggregateIncrementalVerification, PlainAggregateIncrementalVerificationPreparation,
        PlainAggregatePcs, PlainAggregateProof,
    },
};

const WIRE_MAGIC: &[u8; 8] = b"SLPWHR03";
const CHALLENGE_FIELD_LIMB_COUNT: usize = 5;

type MerkleNode = [u64; MERKLE_DIGEST_WORD_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PlainWhirWireEncodingProgress {
    Pending,
    Complete { canonical_byte_length: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PlainWhirWireSinkEncodingError<SinkError> {
    InvalidProof(String),
    Sink(SinkError),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PlainWhirWireBreakdown {
    pub(super) complete_byte_length: usize,
    pub(super) query_value_byte_length: usize,
    pub(super) merkle_dictionary_byte_length: usize,
    pub(super) merkle_reference_byte_length: usize,
    pub(super) merkle_unique_node_count: usize,
    pub(super) merkle_reference_count: usize,
    pub(super) query_count: usize,
}

#[cfg(test)]
pub(super) fn encode_plain_whir_proof(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_count: usize,
) -> Result<Vec<u8>, String> {
    encode_plain_whir_batch_proof(pcs, proof, &vec![1; expected_opening_count], 1)
}

#[cfg(test)]
pub(super) fn encode_plain_whir_batch_proof(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<Vec<u8>, String> {
    let mut encoder =
        PlainWhirWireSinkEncoder::new(pcs, proof, expected_opening_widths, table_width)?;
    let mut sink = BoundedCommonProofByteSink::new(encoder.canonical_byte_length())
        .map_err(|error| format!("construct plain WHIR test sink: {error:?}"))?;
    match encoder.write_available(proof, &mut sink) {
        Ok(PlainWhirWireEncodingProgress::Complete {
            canonical_byte_length,
        }) if canonical_byte_length == encoder.canonical_byte_length() => Ok(sink.finish()),
        Ok(PlainWhirWireEncodingProgress::Complete {
            canonical_byte_length,
        }) => Err(format!(
            "plain WHIR encoder completed at {canonical_byte_length} bytes, expected {}",
            encoder.canonical_byte_length()
        )),
        Ok(PlainWhirWireEncodingProgress::Pending) => {
            Err("plain WHIR in-memory encoder stopped before completion".to_owned())
        }
        Err(PlainWhirWireSinkEncodingError::InvalidProof(error)) => Err(error),
        Err(PlainWhirWireSinkEncodingError::Sink(error)) => {
            Err(format!("write plain WHIR test bytes: {error:?}"))
        }
    }
}

#[cfg(test)]
pub(super) fn decode_plain_whir_proof(
    pcs: &PlainAggregatePcs,
    canonical: &[u8],
    expected_opening_count: usize,
) -> Result<PlainAggregateProof, String> {
    decode_plain_whir_batch_proof(pcs, canonical, &vec![1; expected_opening_count], 1)
}

#[derive(Clone, Copy)]
struct PlainWhirWireRoundShape {
    ood_answer_count: usize,
    query_count: usize,
    query_value_count: usize,
    query_path_length: usize,
    dictionary_count_ceiling: usize,
    sumcheck_round_count: usize,
    uses_base_field_query_variant: bool,
}

struct PlainWhirWireConfiguration {
    variable_count: usize,
    opening_widths: Vec<usize>,
    table_width: usize,
    initial_ood_answer_count: usize,
    initial_sumcheck_round_count: usize,
    rounds: Vec<PlainWhirWireRoundShape>,
    final_polynomial_evaluation_count: usize,
    final_query_count: usize,
    final_query_value_count: usize,
    final_query_path_length: usize,
    final_dictionary_count_ceiling: usize,
    final_sumcheck_round_count: usize,
    final_queries_use_base_field_variant: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PlainWhirIncrementalDecoderResidentMemoryAccounting {
    maximum_resident_byte_length: u64,
    #[cfg(test)]
    maximum_section_state_byte_length: u64,
}

impl PlainWhirIncrementalDecoderResidentMemoryAccounting {
    pub(super) const fn maximum_resident_byte_length(self) -> u64 {
        self.maximum_resident_byte_length
    }

    #[cfg(test)]
    #[cfg(test)]
    pub(super) const fn maximum_section_state_byte_length(self) -> u64 {
        self.maximum_section_state_byte_length
    }
}

fn checked_plain_whir_resident_memory_add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "plain WHIR resident-memory accounting overflowed".to_owned())
}

fn checked_plain_whir_resident_memory_multiply(left: usize, right: usize) -> Result<u64, String> {
    u64::try_from(left)
        .ok()
        .and_then(|left| {
            u64::try_from(right)
                .ok()
                .and_then(|right| left.checked_mul(right))
        })
        .ok_or_else(|| "plain WHIR resident-memory accounting overflowed".to_owned())
}

fn plain_whir_resident_vector_payload_byte_length<Value>(
    element_count: usize,
) -> Result<u64, String> {
    checked_plain_whir_resident_memory_multiply(element_count, core::mem::size_of::<Value>())
}

fn plain_whir_resident_count_sum(
    values: impl IntoIterator<Item = usize>,
    label: &str,
) -> Result<usize, String> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| format!("plain WHIR {label} count overflowed"))
    })
}

fn plain_whir_dictionary_uniqueness_payload_byte_length(
    dictionary_count: usize,
) -> Result<u64, String> {
    // HashSet reserves below full load and stores one control byte per raw
    // bucket. Two buckets per admitted node conservatively cover rounding,
    // the load factor, and the terminal control group.
    let raw_bucket_count = if dictionary_count == 0 {
        0
    } else {
        dictionary_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(16))
            .ok_or_else(|| "plain WHIR dictionary uniqueness count overflowed".to_owned())?
    };
    checked_plain_whir_resident_memory_multiply(
        raw_bucket_count,
        core::mem::size_of::<MerkleNode>() + core::mem::size_of::<u8>(),
    )
}

fn plain_whir_constraint_payload_byte_length(
    constraint_count: usize,
    statement_count: usize,
    evaluated_point_count: usize,
    variable_count: usize,
) -> Result<u64, String> {
    let point_coordinate_and_evaluation_count = evaluated_point_count
        .checked_mul(
            variable_count
                .checked_add(1)
                .ok_or_else(|| "plain WHIR constraint variable count overflowed".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR constraint scalar count overflowed".to_owned())?;
    [
        plain_whir_resident_vector_payload_byte_length::<
            Constraint<ChallengeField, ChallengeField>,
        >(constraint_count)?,
        plain_whir_resident_vector_payload_byte_length::<
            Statements<ChallengeField, ChallengeField>,
        >(statement_count)?,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
            point_coordinate_and_evaluation_count,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)
}

/// Derives the peak live owned payload of the production semantic decoder
/// before any proof-controlled allocation. Proof length is authenticated only
/// against the absolute common-proof bound. The memory ceiling follows the
/// forward-only lifecycle: preparation state, compact verifier state, one
/// epoch dictionary, one expanded query, one current sumcheck, and the final
/// polynomial. No term scales with the complete canonical proof length.
pub(super) fn plain_whir_incremental_decoder_resident_memory_accounting(
    pcs: &PlainAggregatePcs,
    expected_opening_widths: &[usize],
    table_width: usize,
    declared_plain_whir_byte_length: usize,
) -> Result<PlainWhirIncrementalDecoderResidentMemoryAccounting, String> {
    if declared_plain_whir_byte_length == 0
        || declared_plain_whir_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
    {
        return Err("plain WHIR proof has an invalid authenticated byte length".to_owned());
    }
    let configuration =
        PlainWhirWireConfiguration::from_pcs(pcs, expected_opening_widths, table_width)?;
    let opening_evaluation_count = plain_whir_resident_count_sum(
        configuration.opening_widths.iter().copied(),
        "opening evaluation",
    )?;
    let configuration_payload_byte_length = [
        plain_whir_resident_vector_payload_byte_length::<usize>(
            configuration.opening_widths.len(),
        )?,
        plain_whir_resident_vector_payload_byte_length::<PlainWhirWireRoundShape>(
            configuration.rounds.len(),
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;

    let semantic_configuration_payload_byte_length = [
        u64::try_from(core::mem::size_of_val(pcs.round_parameters.as_slice()))
            .map_err(|_| "plain WHIR round-configuration byte length exceeds u64".to_owned())?,
        u64::try_from(core::mem::size_of_val(pcs.folding_schedule.as_slice()))
            .map_err(|_| "plain WHIR folding-schedule byte length exceeds u64".to_owned())?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;
    let opening_point_count = configuration.opening_widths.len();
    let opening_point_coordinate_count = opening_point_count
        .checked_mul(configuration.variable_count)
        .ok_or_else(|| "plain WHIR opening-point coordinate count overflowed".to_owned())?;
    let nested_opening_vector_metadata_byte_length =
        plain_whir_resident_vector_payload_byte_length::<Vec<ChallengeField>>(opening_point_count)?;
    let preparation_payload_byte_length = [
        semantic_configuration_payload_byte_length,
        plain_whir_resident_vector_payload_byte_length::<Point<ChallengeField>>(
            opening_point_count,
        )?,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
            opening_point_coordinate_count,
        )?,
        plain_whir_resident_vector_payload_byte_length::<Vec<usize>>(opening_point_count)?,
        plain_whir_resident_vector_payload_byte_length::<usize>(opening_evaluation_count)?,
        nested_opening_vector_metadata_byte_length,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(opening_evaluation_count)?,
        plain_whir_resident_vector_payload_byte_length::<OpeningBatch<ChallengeField>>(
            opening_point_count,
        )?,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(opening_evaluation_count)?,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
            configuration.initial_ood_answer_count,
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;

    let initial_statement_count = opening_point_count
        .checked_add(usize::from(configuration.initial_ood_answer_count != 0))
        .ok_or_else(|| "plain WHIR initial statement count overflowed".to_owned())?;
    let initial_evaluated_point_count = opening_evaluation_count
        .checked_add(configuration.initial_ood_answer_count)
        .ok_or_else(|| "plain WHIR initial constraint count overflowed".to_owned())?;
    let mut constraint_payload_byte_length = plain_whir_constraint_payload_byte_length(
        1,
        initial_statement_count,
        initial_evaluated_point_count,
        configuration.variable_count,
    )?;
    for (round, round_parameters) in configuration.rounds.iter().zip(&pcs.round_parameters) {
        let evaluated_point_count = round
            .ood_answer_count
            .checked_add(round.query_count)
            .ok_or_else(|| "plain WHIR round constraint count overflowed".to_owned())?;
        constraint_payload_byte_length = checked_plain_whir_resident_memory_add(
            constraint_payload_byte_length,
            plain_whir_constraint_payload_byte_length(
                1,
                2,
                evaluated_point_count,
                round_parameters.num_variables,
            )?,
        )?;
    }
    let folding_point_count = configuration
        .rounds
        .len()
        .checked_add(2)
        .ok_or_else(|| "plain WHIR folding-point count overflowed".to_owned())?;
    let folding_coordinate_count = folding_point_count
        .checked_mul(configuration.variable_count)
        .ok_or_else(|| "plain WHIR folding-coordinate count overflowed".to_owned())?;
    let folding_payload_byte_length = [
        plain_whir_resident_vector_payload_byte_length::<Point<ChallengeField>>(
            folding_point_count,
        )?,
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(folding_coordinate_count)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;
    let semantic_persistent_payload_byte_length = [
        semantic_configuration_payload_byte_length,
        constraint_payload_byte_length,
        folding_payload_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;

    let maximum_intermediate_dictionary_count = configuration
        .rounds
        .iter()
        .map(|round| round.dictionary_count_ceiling)
        .max()
        .unwrap_or(0);
    let maximum_intermediate_query_count = configuration
        .rounds
        .iter()
        .map(|round| round.query_count)
        .max()
        .unwrap_or(0);
    let maximum_intermediate_query_value_count = configuration
        .rounds
        .iter()
        .map(|round| round.query_value_count)
        .max()
        .unwrap_or(0);
    let maximum_intermediate_query_path_length = configuration
        .rounds
        .iter()
        .map(|round| round.query_path_length)
        .max()
        .unwrap_or(0);
    let maximum_intermediate_ood_answer_count = configuration
        .rounds
        .iter()
        .map(|round| round.ood_answer_count)
        .max()
        .unwrap_or(0);
    let maximum_intermediate_sumcheck_round_count = configuration
        .rounds
        .iter()
        .map(|round| round.sumcheck_round_count)
        .max()
        .unwrap_or(0)
        .max(configuration.initial_sumcheck_round_count);
    let section_peak = |dictionary_count: usize,
                        query_count: usize,
                        query_value_count: usize,
                        query_path_length: usize,
                        sumcheck_round_count: usize|
     -> Result<u64, String> {
        let dictionary_payload_byte_length =
            plain_whir_resident_vector_payload_byte_length::<MerkleNode>(dictionary_count)?;
        let dictionary_loading_payload_byte_length = checked_plain_whir_resident_memory_add(
            dictionary_payload_byte_length,
            plain_whir_dictionary_uniqueness_payload_byte_length(dictionary_count)?,
        )?;
        let dictionary_query_payload_byte_length = [
            dictionary_payload_byte_length,
            plain_whir_resident_vector_payload_byte_length::<bool>(dictionary_count)?,
            plain_whir_resident_vector_payload_byte_length::<ChallengeField>(query_value_count)?,
            plain_whir_resident_vector_payload_byte_length::<MerkleNode>(query_path_length)?,
            u64::try_from(core::mem::size_of::<
                QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>,
            >())
            .map_err(|_| "plain WHIR query-opening byte length exceeds u64".to_owned())?,
            plain_whir_resident_vector_payload_byte_length::<usize>(query_count)?,
            plain_whir_resident_vector_payload_byte_length::<ChallengeField>(query_count)?,
            plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
                configuration.variable_count,
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;
        let sumcheck_payload_byte_length =
            plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
                sumcheck_round_count
                    .checked_mul(2)
                    .ok_or_else(|| "plain WHIR sumcheck field count overflowed".to_owned())?,
            )?;
        Ok(dictionary_loading_payload_byte_length
            .max(dictionary_query_payload_byte_length)
            .max(sumcheck_payload_byte_length))
    };
    let intermediate_section_peak_byte_length = checked_plain_whir_resident_memory_add(
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
            maximum_intermediate_ood_answer_count,
        )?,
        section_peak(
            maximum_intermediate_dictionary_count,
            maximum_intermediate_query_count,
            maximum_intermediate_query_value_count,
            maximum_intermediate_query_path_length,
            maximum_intermediate_sumcheck_round_count,
        )?,
    )?;
    let final_section_peak_byte_length = checked_plain_whir_resident_memory_add(
        plain_whir_resident_vector_payload_byte_length::<ChallengeField>(
            configuration.final_polynomial_evaluation_count,
        )?,
        section_peak(
            configuration.final_dictionary_count_ceiling,
            configuration.final_query_count,
            configuration.final_query_value_count,
            configuration.final_query_path_length,
            configuration.final_sumcheck_round_count,
        )?,
    )?;
    let maximum_section_state_byte_length =
        intermediate_section_peak_byte_length.max(final_section_peak_byte_length);
    let semantic_peak_payload_byte_length = checked_plain_whir_resident_memory_add(
        semantic_persistent_payload_byte_length,
        maximum_section_state_byte_length,
    )?;
    let fixed_resident_byte_length =
        u64::try_from(core::mem::size_of::<PlainWhirIncrementalDecoder>())
            .map_err(|_| "plain WHIR fixed resident byte length exceeds u64".to_owned())?;
    let maximum_resident_byte_length = [
        fixed_resident_byte_length,
        configuration_payload_byte_length,
        preparation_payload_byte_length.max(semantic_peak_payload_byte_length),
    ]
    .into_iter()
    .try_fold(0_u64, checked_plain_whir_resident_memory_add)?;
    Ok(PlainWhirIncrementalDecoderResidentMemoryAccounting {
        maximum_resident_byte_length,
        #[cfg(test)]
        maximum_section_state_byte_length,
    })
}

impl PlainWhirWireConfiguration {
    fn from_pcs(
        pcs: &PlainAggregatePcs,
        expected_opening_widths: &[usize],
        table_width: usize,
    ) -> Result<Self, String> {
        validate_codec_configuration(pcs)?;
        if table_width == 0
            || expected_opening_widths
                .iter()
                .any(|width| *width == 0 || *width > table_width)
        {
            return Err("plain WHIR opening widths do not match the committed table".to_owned());
        }
        let mut opening_widths = Vec::new();
        opening_widths
            .try_reserve_exact(expected_opening_widths.len())
            .map_err(|_| "plain WHIR opening-width allocation failed".to_owned())?;
        opening_widths.extend_from_slice(expected_opening_widths);
        let mut rounds = Vec::new();
        rounds
            .try_reserve_exact(pcs.n_rounds())
            .map_err(|_| "plain WHIR round-shape allocation failed".to_owned())?;
        for (round_index, parameters) in pcs.round_parameters.iter().enumerate() {
            rounds.push(PlainWhirWireRoundShape {
                ood_answer_count: parameters.ood_samples,
                query_count: parameters.num_queries,
                query_value_count: initial_query_value_count(pcs, round_index)?,
                query_path_length: query_path_length(
                    parameters.domain_size,
                    pcs.round_folding_factor(round_index),
                )?,
                dictionary_count_ceiling: parameters
                    .num_queries
                    .checked_mul(query_path_length(
                        parameters.domain_size,
                        pcs.round_folding_factor(round_index),
                    )?)
                    .ok_or_else(|| "plain WHIR round dictionary bound overflowed".to_owned())?,
                sumcheck_round_count: pcs.round_folding_factor(round_index + 1),
                uses_base_field_query_variant: round_index == 0,
            });
        }
        let final_configuration = pcs.final_round_config();
        let final_polynomial_evaluation_count = 1_usize
            .checked_shl(
                u32::try_from(final_configuration.num_variables)
                    .map_err(|_| "plain WHIR final variable count exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "plain WHIR final polynomial length overflowed".to_owned())?;
        Ok(Self {
            variable_count: pcs.num_variables,
            opening_widths,
            table_width,
            initial_ood_answer_count: pcs.commitment_ood_samples,
            initial_sumcheck_round_count: pcs.round_folding_factor(0),
            rounds,
            final_polynomial_evaluation_count,
            final_query_count: pcs.final_queries,
            final_query_value_count: initial_query_value_count(pcs, pcs.n_rounds())?,
            final_query_path_length: query_path_length(
                final_configuration.domain_size,
                pcs.round_folding_factor(pcs.n_rounds()),
            )?,
            final_dictionary_count_ceiling: pcs
                .final_queries
                .checked_mul(query_path_length(
                    final_configuration.domain_size,
                    pcs.round_folding_factor(pcs.n_rounds()),
                )?)
                .ok_or_else(|| "plain WHIR final dictionary bound overflowed".to_owned())?,
            final_sumcheck_round_count: pcs.final_sumcheck_rounds,
            final_queries_use_base_field_variant: pcs.n_rounds() == 0,
        })
    }

    fn checked_remaining_wire_byte_length(
        &self,
        dictionary_counts: &[usize],
    ) -> Result<usize, String> {
        if dictionary_counts.len() != self.rounds.len() + 1 {
            return Err("plain WHIR dictionary-count schedule has the wrong shape".to_owned());
        }
        let field_byte_length = CHALLENGE_FIELD_LIMB_COUNT
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "plain WHIR field byte length overflowed".to_owned())?;
        let merkle_node_byte_length = MERKLE_DIGEST_WORD_LENGTH
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| "plain WHIR Merkle-node byte length overflowed".to_owned())?;
        let mut byte_length = 0_usize;
        let opening_evaluation_count =
            self.opening_widths
                .iter()
                .try_fold(0_usize, |count, width| {
                    count
                        .checked_add(*width)
                        .ok_or_else(|| "plain WHIR opening-evaluation count overflowed".to_owned())
                })?;
        checked_add_wire_elements(
            &mut byte_length,
            opening_evaluation_count,
            field_byte_length,
            "opening evaluations",
        )?;
        checked_add_wire_elements(
            &mut byte_length,
            self.initial_ood_answer_count,
            field_byte_length,
            "initial OOD answers",
        )?;
        checked_add_sumcheck_wire_bytes(
            &mut byte_length,
            self.initial_sumcheck_round_count,
            field_byte_length,
            "initial sumcheck",
        )?;
        for (round_index, round) in self.rounds.iter().enumerate() {
            checked_add_wire_elements(
                &mut byte_length,
                1,
                merkle_node_byte_length,
                &format!("round {round_index} commitment"),
            )?;
            checked_add_wire_elements(
                &mut byte_length,
                round.ood_answer_count,
                field_byte_length,
                &format!("round {round_index} OOD answers"),
            )?;
            checked_add_wire_elements(
                &mut byte_length,
                1,
                core::mem::size_of::<u32>(),
                &format!("round {round_index} Merkle dictionary count"),
            )?;
            checked_add_wire_elements(
                &mut byte_length,
                dictionary_counts[round_index],
                merkle_node_byte_length,
                &format!("round {round_index} Merkle dictionary"),
            )?;
            checked_add_query_wire_bytes(
                &mut byte_length,
                round.query_count,
                round.query_value_count,
                round.query_path_length,
                field_byte_length,
                &format!("round {round_index} queries"),
            )?;
            checked_add_sumcheck_wire_bytes(
                &mut byte_length,
                round.sumcheck_round_count,
                field_byte_length,
                &format!("round {round_index} sumcheck"),
            )?;
        }
        checked_add_wire_elements(
            &mut byte_length,
            self.final_polynomial_evaluation_count,
            field_byte_length,
            "final polynomial",
        )?;
        checked_add_wire_elements(
            &mut byte_length,
            1,
            core::mem::size_of::<u32>(),
            "final Merkle dictionary count",
        )?;
        checked_add_wire_elements(
            &mut byte_length,
            dictionary_counts[self.rounds.len()],
            merkle_node_byte_length,
            "final Merkle dictionary",
        )?;
        checked_add_query_wire_bytes(
            &mut byte_length,
            self.final_query_count,
            self.final_query_value_count,
            self.final_query_path_length,
            field_byte_length,
            "final queries",
        )?;
        checked_add_sumcheck_wire_bytes(
            &mut byte_length,
            self.final_sumcheck_round_count,
            field_byte_length,
            "final sumcheck",
        )?;
        Ok(byte_length)
    }
}

fn checked_add_wire_elements(
    byte_length: &mut usize,
    element_count: usize,
    element_byte_length: usize,
    label: &str,
) -> Result<(), String> {
    let section_byte_length = element_count
        .checked_mul(element_byte_length)
        .ok_or_else(|| format!("plain WHIR {label} byte length overflowed"))?;
    *byte_length = byte_length
        .checked_add(section_byte_length)
        .ok_or_else(|| format!("plain WHIR cumulative length overflowed after {label}"))?;
    Ok(())
}

fn checked_add_sumcheck_wire_bytes(
    byte_length: &mut usize,
    round_count: usize,
    field_byte_length: usize,
    label: &str,
) -> Result<(), String> {
    let field_count = round_count
        .checked_mul(2)
        .ok_or_else(|| format!("plain WHIR {label} field count overflowed"))?;
    checked_add_wire_elements(byte_length, field_count, field_byte_length, label)
}

fn checked_add_query_wire_bytes(
    byte_length: &mut usize,
    query_count: usize,
    query_value_count: usize,
    query_path_length: usize,
    field_byte_length: usize,
    label: &str,
) -> Result<(), String> {
    let value_byte_length = query_value_count
        .checked_mul(field_byte_length)
        .ok_or_else(|| format!("plain WHIR {label} value byte length overflowed"))?;
    let path_byte_length = query_path_length
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or_else(|| format!("plain WHIR {label} path byte length overflowed"))?;
    let query_byte_length = value_byte_length
        .checked_add(path_byte_length)
        .ok_or_else(|| format!("plain WHIR {label} byte length overflowed"))?;
    checked_add_wire_elements(byte_length, query_count, query_byte_length, label)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlainWhirQueryDestination {
    Round(usize),
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlainWhirSumcheckDestination {
    Initial,
    Round(usize),
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlainWhirIncrementalDecodePhase {
    Magic,
    VariableCount,
    OpeningCount,
    TableWidth,
    DictionaryCount {
        destination: PlainWhirQueryDestination,
    },
    DictionaryNodes {
        destination: PlainWhirQueryDestination,
        next_node_index: usize,
    },
    OpeningEvaluations {
        opening_index: usize,
        next_value_index: usize,
    },
    InitialOodAnswers {
        next_answer_index: usize,
    },
    Sumcheck {
        destination: PlainWhirSumcheckDestination,
        next_field_index: usize,
    },
    RoundCommitment {
        round_index: usize,
    },
    RoundOodAnswers {
        round_index: usize,
        next_answer_index: usize,
    },
    QueryValues {
        destination: PlainWhirQueryDestination,
        query_index: usize,
        next_value_index: usize,
    },
    QueryDictionaryReferences {
        destination: PlainWhirQueryDestination,
        query_index: usize,
        next_reference_index: usize,
    },
    FinalPolynomial {
        next_value_index: usize,
    },
    Complete,
}

/// Forward-only canonical decoder used by the production exact verifier.
/// In semantic mode it authenticates and folds one query at a time, then
/// releases the decoded values, expanded Merkle path, and section dictionary.
pub(super) struct PlainWhirIncrementalDecoder {
    configuration: PlainWhirWireConfiguration,
    declared_complete_proof_byte_length: usize,
    offset: usize,
    phase: PlainWhirIncrementalDecodePhase,
    expected_dictionary_count: Option<usize>,
    dictionary: Vec<MerkleNode>,
    distinct_dictionary_nodes: Option<HashSet<MerkleNode>>,
    dictionary_usage: Option<DictionaryUsage>,
    evaluations: Vec<OpeningBatch<ChallengeField>>,
    whir: WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    pending_values: Vec<ChallengeField>,
    pending_query_path: Vec<MerkleNode>,
    pending_sumcheck_first_evaluation: Option<ChallengeField>,
    semantic_mode: bool,
    semantic_preparation: Option<PlainAggregateIncrementalVerificationPreparation>,
    semantic_verification: Option<PlainAggregateIncrementalVerification>,
    completed_semantic_challenger: Option<ExtensionFieldChallenger>,
}

impl PlainWhirIncrementalDecoder {
    #[cfg(test)]
    pub(super) fn new(
        pcs: &PlainAggregatePcs,
        expected_opening_widths: &[usize],
        table_width: usize,
        section_start_offset: usize,
        declared_complete_proof_byte_length: usize,
    ) -> Result<Self, String> {
        Self::new_with_semantic_preparation(
            pcs,
            expected_opening_widths,
            table_width,
            section_start_offset,
            declared_complete_proof_byte_length,
            None,
        )
    }

    pub(super) fn new_semantic(
        pcs: &PlainAggregatePcs,
        expected_opening_widths: &[usize],
        table_width: usize,
        section_start_offset: usize,
        declared_complete_proof_byte_length: usize,
        semantic_preparation: PlainAggregateIncrementalVerificationPreparation,
    ) -> Result<Self, String> {
        Self::new_with_semantic_preparation(
            pcs,
            expected_opening_widths,
            table_width,
            section_start_offset,
            declared_complete_proof_byte_length,
            Some(semantic_preparation),
        )
    }

    fn new_with_semantic_preparation(
        pcs: &PlainAggregatePcs,
        expected_opening_widths: &[usize],
        table_width: usize,
        section_start_offset: usize,
        declared_complete_proof_byte_length: usize,
        semantic_preparation: Option<PlainAggregateIncrementalVerificationPreparation>,
    ) -> Result<Self, String> {
        if declared_complete_proof_byte_length == 0
            || declared_complete_proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH
            || section_start_offset >= declared_complete_proof_byte_length
        {
            return Err("plain WHIR proof has an invalid authenticated byte length".to_owned());
        }
        let configuration =
            PlainWhirWireConfiguration::from_pcs(pcs, expected_opening_widths, table_width)?;
        let mut rounds = Vec::new();
        rounds
            .try_reserve_exact(configuration.rounds.len())
            .map_err(|_| "plain WHIR proof-round allocation failed".to_owned())?;
        rounds.resize_with(configuration.rounds.len(), WhirRoundProof::default);
        let has_final_sumcheck = configuration.final_sumcheck_round_count != 0;
        let semantic_mode = semantic_preparation.is_some();
        Ok(Self {
            configuration,
            declared_complete_proof_byte_length,
            offset: section_start_offset,
            phase: PlainWhirIncrementalDecodePhase::Magic,
            expected_dictionary_count: None,
            dictionary: Vec::new(),
            distinct_dictionary_nodes: None,
            dictionary_usage: None,
            evaluations: Vec::new(),
            whir: WhirProof {
                initial_ood_answers: Vec::new(),
                initial_sumcheck: SumcheckData::default(),
                rounds,
                final_poly: None,
                final_pow_witness: ChallengeField::ZERO,
                final_queries: Vec::new(),
                final_sumcheck: has_final_sumcheck.then(SumcheckData::default),
            },
            pending_values: Vec::new(),
            pending_query_path: Vec::new(),
            pending_sumcheck_first_evaluation: None,
            semantic_mode,
            semantic_preparation,
            semantic_verification: None,
            completed_semantic_challenger: None,
        })
    }

    pub(super) const fn offset(&self) -> usize {
        self.offset
    }

    pub(super) const fn is_complete(&self) -> bool {
        matches!(self.phase, PlainWhirIncrementalDecodePhase::Complete)
    }

    /// Conservative live owned payload retained at the current decode point.
    pub(super) fn resident_decoded_payload_byte_length(&self) -> usize {
        let mut resident_byte_length = self
            .dictionary
            .capacity()
            .saturating_mul(core::mem::size_of::<MerkleNode>())
            .saturating_add(self.distinct_dictionary_nodes.as_ref().map_or(0, |nodes| {
                nodes.capacity().saturating_mul(
                    core::mem::size_of::<MerkleNode>().saturating_add(core::mem::size_of::<u8>()),
                )
            }))
            .saturating_add(
                self.dictionary_usage
                    .as_ref()
                    .map_or(0, DictionaryUsage::resident_payload_byte_length),
            )
            .saturating_add(
                self.pending_values
                    .capacity()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            )
            .saturating_add(
                self.pending_query_path
                    .capacity()
                    .saturating_mul(core::mem::size_of::<MerkleNode>()),
            )
            .saturating_add(
                self.evaluations
                    .capacity()
                    .saturating_mul(core::mem::size_of::<OpeningBatch<ChallengeField>>()),
            );
        resident_byte_length = resident_byte_length.saturating_add(
            self.evaluations
                .iter()
                .map(|batch| {
                    batch
                        .current()
                        .len()
                        .saturating_add(batch.next().len())
                        .saturating_mul(core::mem::size_of::<ChallengeField>())
                })
                .fold(0_usize, usize::saturating_add),
        );
        resident_byte_length =
            resident_byte_length.saturating_add(self.whir.rounds.capacity().saturating_mul(
                core::mem::size_of::<
                    WhirRoundProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
                >(),
            ));
        resident_byte_length = resident_byte_length.saturating_add(
            self.whir
                .initial_ood_answers
                .capacity()
                .saturating_mul(core::mem::size_of::<ChallengeField>()),
        );
        for round in &self.whir.rounds {
            resident_byte_length = resident_byte_length
                .saturating_add(
                    round
                        .ood_answers
                        .capacity()
                        .saturating_mul(core::mem::size_of::<ChallengeField>()),
                )
                .saturating_add(sumcheck_resident_payload_byte_length(&round.sumcheck))
                .saturating_add(query_resident_payload_byte_length(&round.queries));
        }
        resident_byte_length = resident_byte_length
            .saturating_add(sumcheck_resident_payload_byte_length(
                &self.whir.initial_sumcheck,
            ))
            .saturating_add(query_resident_payload_byte_length(&self.whir.final_queries));
        if let Some(final_polynomial) = &self.whir.final_poly {
            resident_byte_length = resident_byte_length.saturating_add(
                final_polynomial
                    .as_slice()
                    .len()
                    .saturating_mul(core::mem::size_of::<ChallengeField>()),
            );
        }
        if let Some(final_sumcheck) = &self.whir.final_sumcheck {
            resident_byte_length = resident_byte_length
                .saturating_add(sumcheck_resident_payload_byte_length(final_sumcheck));
        }
        if let Some(verification) = &self.semantic_verification {
            resident_byte_length =
                resident_byte_length.saturating_add(verification.resident_payload_byte_length());
        }
        resident_byte_length
    }

    pub(super) fn consume_available<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
        available_end_offset: usize,
    ) -> Result<(), String> {
        if source.byte_length() != self.declared_complete_proof_byte_length
            || available_end_offset > self.declared_complete_proof_byte_length
            || available_end_offset < self.offset
        {
            return Err(
                "plain WHIR decoder received the wrong authenticated byte range".to_owned(),
            );
        }
        loop {
            if self.is_complete() {
                if self.offset != self.declared_complete_proof_byte_length {
                    return Err(format!(
                        "plain WHIR proof has {} trailing bytes",
                        self.declared_complete_proof_byte_length - self.offset
                    ));
                }
                return Ok(());
            }
            let next_byte_length = self.next_primitive_byte_length();
            let available_byte_length = available_end_offset - self.offset;
            if available_byte_length < next_byte_length {
                if available_end_offset == self.declared_complete_proof_byte_length {
                    return Err(format!(
                        "plain WHIR proof is truncated at byte {}, while reading {next_byte_length} bytes",
                        self.offset
                    ));
                }
                return Ok(());
            }
            self.consume_next_primitive(source)?;
        }
    }

    #[cfg(test)]
    pub(super) fn finish(self, pcs: &PlainAggregatePcs) -> Result<PlainAggregateProof, String> {
        if !self.is_complete() || self.offset != self.declared_complete_proof_byte_length {
            return Err("plain WHIR proof ended before its canonical terminal shape".to_owned());
        }
        if self.semantic_mode {
            return Err("plain WHIR semantic decoder cannot materialize a proof".to_owned());
        }
        if self.dictionary_usage.is_some()
            || !self.dictionary.is_empty()
            || self.distinct_dictionary_nodes.is_some()
        {
            return Err("plain WHIR decoder retained completed dictionary state".to_owned());
        }
        let proof = PcsProof {
            whir: self.whir,
            evals: self.evaluations,
        };
        validate_proof_shape(
            pcs,
            &proof,
            &self.configuration.opening_widths,
            self.configuration.table_width,
        )?;
        Ok(proof)
    }

    pub(super) fn finish_semantic(self) -> Result<ExtensionFieldChallenger, String> {
        if !self.semantic_mode
            || !self.is_complete()
            || self.offset != self.declared_complete_proof_byte_length
        {
            return Err(
                "plain WHIR semantic proof ended before its canonical terminal shape".to_owned(),
            );
        }
        if self.semantic_preparation.is_some()
            || self.semantic_verification.is_some()
            || self.dictionary_usage.is_some()
            || !self.dictionary.is_empty()
            || self.distinct_dictionary_nodes.is_some()
        {
            return Err(
                "plain WHIR semantic decoder retained incomplete verifier state".to_owned(),
            );
        }
        self.completed_semantic_challenger
            .ok_or_else(|| "plain WHIR semantic decoder omitted its final challenger".to_owned())
    }

    const fn next_primitive_byte_length(&self) -> usize {
        match self.phase {
            PlainWhirIncrementalDecodePhase::Magic => WIRE_MAGIC.len(),
            PlainWhirIncrementalDecodePhase::VariableCount
            | PlainWhirIncrementalDecodePhase::OpeningCount
            | PlainWhirIncrementalDecodePhase::TableWidth
            | PlainWhirIncrementalDecodePhase::DictionaryCount { .. }
            | PlainWhirIncrementalDecodePhase::QueryDictionaryReferences { .. } => {
                core::mem::size_of::<u32>()
            }
            PlainWhirIncrementalDecodePhase::DictionaryNodes { .. }
            | PlainWhirIncrementalDecodePhase::RoundCommitment { .. } => {
                MERKLE_DIGEST_WORD_LENGTH * core::mem::size_of::<u64>()
            }
            PlainWhirIncrementalDecodePhase::OpeningEvaluations { .. }
            | PlainWhirIncrementalDecodePhase::InitialOodAnswers { .. }
            | PlainWhirIncrementalDecodePhase::Sumcheck { .. }
            | PlainWhirIncrementalDecodePhase::RoundOodAnswers { .. }
            | PlainWhirIncrementalDecodePhase::QueryValues { .. }
            | PlainWhirIncrementalDecodePhase::FinalPolynomial { .. } => {
                CHALLENGE_FIELD_LIMB_COUNT * core::mem::size_of::<u64>()
            }
            PlainWhirIncrementalDecodePhase::Complete => 0,
        }
    }

    fn consume_next_primitive<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<(), String> {
        let phase = self.phase;
        match phase {
            PlainWhirIncrementalDecodePhase::Magic => {
                if self.read_array::<_, 8>(source)? != *WIRE_MAGIC {
                    return Err("plain WHIR proof has the wrong wire magic".to_owned());
                }
                self.phase = PlainWhirIncrementalDecodePhase::VariableCount;
            }
            PlainWhirIncrementalDecodePhase::VariableCount => {
                let encoded = self.read_u32(source)? as usize;
                if encoded != self.configuration.variable_count {
                    return Err(format!(
                        "plain WHIR proof targets {encoded} variables, expected {}",
                        self.configuration.variable_count
                    ));
                }
                self.phase = PlainWhirIncrementalDecodePhase::OpeningCount;
            }
            PlainWhirIncrementalDecodePhase::OpeningCount => {
                let encoded = self.read_u32(source)? as usize;
                if encoded != self.configuration.opening_widths.len() {
                    return Err(format!(
                        "plain WHIR proof carries {encoded} openings, expected {}",
                        self.configuration.opening_widths.len()
                    ));
                }
                self.phase = PlainWhirIncrementalDecodePhase::TableWidth;
            }
            PlainWhirIncrementalDecodePhase::TableWidth => {
                let encoded = self.read_u32(source)? as usize;
                if encoded != self.configuration.table_width {
                    return Err(format!(
                        "plain WHIR proof targets table width {encoded}, expected {}",
                        self.configuration.table_width
                    ));
                }
                self.phase = self.phase_before_opening_evaluations()?;
            }
            PlainWhirIncrementalDecodePhase::DictionaryCount { destination } => {
                let dictionary_count = self.read_u32(source)? as usize;
                let dictionary_count_ceiling = self.dictionary_count_ceiling(destination)?;
                if dictionary_count > dictionary_count_ceiling {
                    return Err(format!(
                        "plain WHIR Merkle dictionary has {dictionary_count} nodes, exceeding the configuration-derived maximum {}",
                        dictionary_count_ceiling
                    ));
                }
                self.ensure_declared_remaining_elements(
                    dictionary_count,
                    MERKLE_DIGEST_WORD_LENGTH * core::mem::size_of::<u64>(),
                    "Merkle dictionary nodes",
                )?;
                self.dictionary
                    .try_reserve_exact(dictionary_count)
                    .map_err(|_| "plain WHIR dictionary allocation failed".to_owned())?;
                let mut distinct_dictionary_nodes = HashSet::new();
                distinct_dictionary_nodes
                    .try_reserve(dictionary_count)
                    .map_err(|_| "plain WHIR dictionary-set allocation failed".to_owned())?;
                self.distinct_dictionary_nodes = Some(distinct_dictionary_nodes);
                self.expected_dictionary_count = Some(dictionary_count);
                self.dictionary_usage = Some(DictionaryUsage::try_new(dictionary_count)?);
                self.phase = if dictionary_count == 0 {
                    self.phase_after_dictionary(destination)?
                } else {
                    PlainWhirIncrementalDecodePhase::DictionaryNodes {
                        destination,
                        next_node_index: 0,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::DictionaryNodes {
                destination,
                next_node_index,
            } => {
                let node = self.read_merkle_node(source)?;
                if !self
                    .distinct_dictionary_nodes
                    .as_mut()
                    .ok_or_else(|| {
                        "plain WHIR dictionary uniqueness state is unavailable".to_owned()
                    })?
                    .insert(node)
                {
                    return Err(format!(
                        "plain WHIR Merkle dictionary node {next_node_index} is duplicated"
                    ));
                }
                self.dictionary.push(node);
                let following_node_index = next_node_index + 1;
                self.phase = if Some(following_node_index) == self.expected_dictionary_count {
                    self.phase_after_dictionary(destination)?
                } else {
                    PlainWhirIncrementalDecodePhase::DictionaryNodes {
                        destination,
                        next_node_index: following_node_index,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::OpeningEvaluations {
                opening_index,
                next_value_index,
            } => {
                let field = self.read_field(source)?;
                self.pending_values.push(field);
                let following_value_index = next_value_index + 1;
                let opening_width = self.configuration.opening_widths[opening_index];
                if following_value_index == opening_width {
                    let values = core::mem::take(&mut self.pending_values);
                    self.evaluations.push(OpeningBatch::new(values, Vec::new()));
                    let following_opening_index = opening_index + 1;
                    self.phase =
                        if following_opening_index == self.configuration.opening_widths.len() {
                            self.phase_before_initial_sumcheck()?
                        } else {
                            self.prepare_pending_values(
                                self.configuration.opening_widths[following_opening_index],
                                "opening evaluations",
                            )?;
                            PlainWhirIncrementalDecodePhase::OpeningEvaluations {
                                opening_index: following_opening_index,
                                next_value_index: 0,
                            }
                        };
                } else {
                    self.phase = PlainWhirIncrementalDecodePhase::OpeningEvaluations {
                        opening_index,
                        next_value_index: following_value_index,
                    };
                }
            }
            PlainWhirIncrementalDecodePhase::InitialOodAnswers { next_answer_index } => {
                let field = self.read_field(source)?;
                self.whir.initial_ood_answers.push(field);
                let following_answer_index = next_answer_index + 1;
                self.phase =
                    if following_answer_index == self.configuration.initial_ood_answer_count {
                        self.begin_sumcheck(
                            PlainWhirSumcheckDestination::Initial,
                            self.configuration.initial_sumcheck_round_count,
                        )?
                    } else {
                        PlainWhirIncrementalDecodePhase::InitialOodAnswers {
                            next_answer_index: following_answer_index,
                        }
                    };
            }
            PlainWhirIncrementalDecodePhase::Sumcheck {
                destination,
                next_field_index,
            } => {
                let field = self.read_field(source)?;
                if next_field_index % 2 == 0 {
                    if self
                        .pending_sumcheck_first_evaluation
                        .replace(field)
                        .is_some()
                    {
                        return Err(
                            "plain WHIR sumcheck parser retained an unexpected field".to_owned()
                        );
                    }
                } else {
                    let first = self
                        .pending_sumcheck_first_evaluation
                        .take()
                        .ok_or_else(|| {
                            "plain WHIR sumcheck parser omitted its first field".to_owned()
                        })?;
                    self.sumcheck_mut(destination)?
                        .polynomial_evaluations
                        .push([first, field]);
                }
                let following_field_index = next_field_index + 1;
                let total_field_count = self
                    .sumcheck_round_count(destination)?
                    .checked_mul(2)
                    .ok_or_else(|| "plain WHIR sumcheck field count overflowed".to_owned())?;
                self.phase = if following_field_index == total_field_count {
                    self.phase_after_sumcheck(destination)?
                } else {
                    PlainWhirIncrementalDecodePhase::Sumcheck {
                        destination,
                        next_field_index: following_field_index,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::RoundCommitment { round_index } => {
                let root = self.read_merkle_node(source)?;
                self.whir.rounds[round_index].commitment = Some(MerkleCap::new(vec![root]));
                let answer_count = self.configuration.rounds[round_index].ood_answer_count;
                self.whir.rounds[round_index]
                    .ood_answers
                    .try_reserve_exact(answer_count)
                    .map_err(|_| "plain WHIR round OOD allocation failed".to_owned())?;
                self.phase = if answer_count == 0 {
                    self.begin_dictionary(PlainWhirQueryDestination::Round(round_index))?
                } else {
                    PlainWhirIncrementalDecodePhase::RoundOodAnswers {
                        round_index,
                        next_answer_index: 0,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::RoundOodAnswers {
                round_index,
                next_answer_index,
            } => {
                let field = self.read_field(source)?;
                self.whir.rounds[round_index].ood_answers.push(field);
                let following_answer_index = next_answer_index + 1;
                self.phase = if following_answer_index
                    == self.configuration.rounds[round_index].ood_answer_count
                {
                    self.begin_dictionary(PlainWhirQueryDestination::Round(round_index))?
                } else {
                    PlainWhirIncrementalDecodePhase::RoundOodAnswers {
                        round_index,
                        next_answer_index: following_answer_index,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::QueryValues {
                destination,
                query_index,
                next_value_index,
            } => {
                let field = self.read_field(source)?;
                self.pending_values.push(field);
                let following_value_index = next_value_index + 1;
                let (_, value_count, path_length) = self.query_shape(destination)?;
                self.phase = if following_value_index == value_count {
                    if path_length == 0 {
                        self.finish_query(destination, query_index)?;
                        self.phase_after_completed_query(destination, query_index)?
                    } else {
                        PlainWhirIncrementalDecodePhase::QueryDictionaryReferences {
                            destination,
                            query_index,
                            next_reference_index: 0,
                        }
                    }
                } else {
                    PlainWhirIncrementalDecodePhase::QueryValues {
                        destination,
                        query_index,
                        next_value_index: following_value_index,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::QueryDictionaryReferences {
                destination,
                query_index,
                next_reference_index,
            } => {
                let reference = self.read_u32(source)? as usize;
                let node = *self.dictionary.get(reference).ok_or_else(|| {
                    format!(
                        "plain WHIR Merkle dictionary reference {reference} is outside {} nodes",
                        self.dictionary.len()
                    )
                })?;
                self.dictionary_usage
                    .as_mut()
                    .ok_or_else(|| "plain WHIR proof omitted dictionary usage state".to_owned())?
                    .observe(reference)?;
                self.pending_query_path.push(node);
                let following_reference_index = next_reference_index + 1;
                let path_length = self.query_shape(destination)?.2;
                if following_reference_index == path_length {
                    self.finish_query(destination, query_index)?;
                    self.phase = self.phase_after_completed_query(destination, query_index)?;
                } else {
                    self.phase = PlainWhirIncrementalDecodePhase::QueryDictionaryReferences {
                        destination,
                        query_index,
                        next_reference_index: following_reference_index,
                    };
                }
            }
            PlainWhirIncrementalDecodePhase::FinalPolynomial { next_value_index } => {
                let field = self.read_field(source)?;
                self.pending_values.push(field);
                let following_value_index = next_value_index + 1;
                self.phase = if following_value_index
                    == self.configuration.final_polynomial_evaluation_count
                {
                    let final_polynomial = Poly::new(core::mem::take(&mut self.pending_values));
                    if self.semantic_mode {
                        self.semantic_verification
                            .as_mut()
                            .ok_or_else(|| {
                                "plain WHIR semantic verifier is absent before the final polynomial"
                                    .to_owned()
                            })?
                            .begin_final_polynomial(final_polynomial)?;
                    } else {
                        self.whir.final_poly = Some(final_polynomial);
                    }
                    self.begin_dictionary(PlainWhirQueryDestination::Final)?
                } else {
                    PlainWhirIncrementalDecodePhase::FinalPolynomial {
                        next_value_index: following_value_index,
                    }
                };
            }
            PlainWhirIncrementalDecodePhase::Complete => {
                return Err("plain WHIR decoder was polled after completion".to_owned());
            }
        }
        Ok(())
    }

    fn phase_before_opening_evaluations(
        &mut self,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        if self.expected_dictionary_count.is_some()
            || !self.dictionary.is_empty()
            || self.distinct_dictionary_nodes.is_some()
            || self.dictionary_usage.is_some()
        {
            return Err("plain WHIR decoder entered openings with dictionary state".to_owned());
        }
        self.evaluations
            .try_reserve_exact(self.configuration.opening_widths.len())
            .map_err(|_| "plain WHIR opening-batch allocation failed".to_owned())?;
        if let Some(first_width) = self.configuration.opening_widths.first().copied() {
            self.prepare_pending_values(first_width, "opening evaluations")?;
            Ok(PlainWhirIncrementalDecodePhase::OpeningEvaluations {
                opening_index: 0,
                next_value_index: 0,
            })
        } else {
            self.phase_before_initial_sumcheck()
        }
    }

    fn phase_after_dictionary(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        self.distinct_dictionary_nodes.take().ok_or_else(|| {
            "plain WHIR dictionary uniqueness state was already released".to_owned()
        })?;
        self.expected_dictionary_count = None;
        self.begin_queries(destination)
    }

    fn phase_before_initial_sumcheck(&mut self) -> Result<PlainWhirIncrementalDecodePhase, String> {
        self.whir
            .initial_ood_answers
            .try_reserve_exact(self.configuration.initial_ood_answer_count)
            .map_err(|_| "plain WHIR initial OOD allocation failed".to_owned())?;
        if self.configuration.initial_ood_answer_count == 0 {
            self.begin_sumcheck(
                PlainWhirSumcheckDestination::Initial,
                self.configuration.initial_sumcheck_round_count,
            )
        } else {
            Ok(PlainWhirIncrementalDecodePhase::InitialOodAnswers {
                next_answer_index: 0,
            })
        }
    }

    fn begin_sumcheck(
        &mut self,
        destination: PlainWhirSumcheckDestination,
        round_count: usize,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        if destination == PlainWhirSumcheckDestination::Initial {
            self.start_semantic_verification()?;
        }
        if round_count == 0 {
            self.phase_after_sumcheck(destination)
        } else {
            self.sumcheck_mut(destination)?
                .polynomial_evaluations
                .try_reserve_exact(round_count)
                .map_err(|_| "plain WHIR sumcheck allocation failed".to_owned())?;
            Ok(PlainWhirIncrementalDecodePhase::Sumcheck {
                destination,
                next_field_index: 0,
            })
        }
    }

    fn phase_after_sumcheck(
        &mut self,
        destination: PlainWhirSumcheckDestination,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        self.verify_completed_sumcheck(destination)?;
        match destination {
            PlainWhirSumcheckDestination::Initial => {
                if self.configuration.rounds.is_empty() {
                    self.begin_final_polynomial()
                } else {
                    Ok(PlainWhirIncrementalDecodePhase::RoundCommitment { round_index: 0 })
                }
            }
            PlainWhirSumcheckDestination::Round(round_index) => {
                let following_round_index = round_index + 1;
                if following_round_index == self.configuration.rounds.len() {
                    self.begin_final_polynomial()
                } else {
                    Ok(PlainWhirIncrementalDecodePhase::RoundCommitment {
                        round_index: following_round_index,
                    })
                }
            }
            PlainWhirSumcheckDestination::Final => Ok(PlainWhirIncrementalDecodePhase::Complete),
        }
    }

    fn begin_final_polynomial(&mut self) -> Result<PlainWhirIncrementalDecodePhase, String> {
        self.prepare_pending_values(
            self.configuration.final_polynomial_evaluation_count,
            "final polynomial",
        )?;
        Ok(PlainWhirIncrementalDecodePhase::FinalPolynomial {
            next_value_index: 0,
        })
    }

    fn begin_dictionary(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        if self.expected_dictionary_count.is_some()
            || !self.dictionary.is_empty()
            || self.distinct_dictionary_nodes.is_some()
            || self.dictionary_usage.is_some()
        {
            return Err("plain WHIR decoder retained the preceding dictionary".to_owned());
        }
        if self.semantic_mode {
            if let PlainWhirQueryDestination::Round(round_index) = destination {
                let round =
                    self.whir.rounds.get_mut(round_index).ok_or_else(|| {
                        "plain WHIR semantic round is outside the proof".to_owned()
                    })?;
                let commitment = round
                    .commitment
                    .take()
                    .ok_or_else(|| "plain WHIR semantic round omitted its commitment".to_owned())?;
                let ood_answers = core::mem::take(&mut round.ood_answers);
                self.semantic_verification
                    .as_mut()
                    .ok_or_else(|| {
                        "plain WHIR semantic verifier is absent before round queries".to_owned()
                    })?
                    .begin_round(round_index, commitment, &ood_answers)?;
            }
        }
        Ok(PlainWhirIncrementalDecodePhase::DictionaryCount { destination })
    }

    fn dictionary_count_ceiling(
        &self,
        destination: PlainWhirQueryDestination,
    ) -> Result<usize, String> {
        match destination {
            PlainWhirQueryDestination::Round(round_index) => self
                .configuration
                .rounds
                .get(round_index)
                .map(|round| round.dictionary_count_ceiling)
                .ok_or_else(|| {
                    "plain WHIR dictionary round is outside the configuration".to_owned()
                }),
            PlainWhirQueryDestination::Final => {
                Ok(self.configuration.final_dictionary_count_ceiling)
            }
        }
    }

    fn start_semantic_verification(&mut self) -> Result<(), String> {
        if !self.semantic_mode {
            return Ok(());
        }
        if self.semantic_verification.is_some() || self.completed_semantic_challenger.is_some() {
            return Err("plain WHIR semantic verifier was initialized twice".to_owned());
        }
        let preparation = self.semantic_preparation.take().ok_or_else(|| {
            "plain WHIR semantic preparation is absent before the initial sumcheck".to_owned()
        })?;
        let initial_ood_answers = core::mem::take(&mut self.whir.initial_ood_answers);
        let opening_evaluations = core::mem::take(&mut self.evaluations);
        self.semantic_verification =
            Some(preparation.start(initial_ood_answers, opening_evaluations)?);
        Ok(())
    }

    fn verify_completed_sumcheck(
        &mut self,
        destination: PlainWhirSumcheckDestination,
    ) -> Result<(), String> {
        if !self.semantic_mode {
            return Ok(());
        }
        match destination {
            PlainWhirSumcheckDestination::Initial => {
                let sumcheck = core::mem::take(&mut self.whir.initial_sumcheck);
                self.semantic_verification
                    .as_mut()
                    .ok_or_else(|| {
                        "plain WHIR semantic verifier is absent at the initial sumcheck".to_owned()
                    })?
                    .verify_initial_sumcheck(&sumcheck)
            }
            PlainWhirSumcheckDestination::Round(round_index) => {
                let sumcheck = self
                    .whir
                    .rounds
                    .get_mut(round_index)
                    .map(|round| core::mem::take(&mut round.sumcheck))
                    .ok_or_else(|| {
                        "plain WHIR semantic sumcheck round is outside the proof".to_owned()
                    })?;
                self.semantic_verification
                    .as_mut()
                    .ok_or_else(|| {
                        "plain WHIR semantic verifier is absent at a round sumcheck".to_owned()
                    })?
                    .verify_round_sumcheck(round_index, &sumcheck)
            }
            PlainWhirSumcheckDestination::Final => {
                let final_sumcheck = self.whir.final_sumcheck.take();
                let mut verification = self.semantic_verification.take().ok_or_else(|| {
                    "plain WHIR semantic verifier is absent at the final sumcheck".to_owned()
                })?;
                verification.verify_final_sumcheck(final_sumcheck.as_ref())?;
                self.completed_semantic_challenger = Some(verification.finish()?);
                Ok(())
            }
        }
    }

    fn begin_queries(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        let (query_count, _, _) = self.query_shape(destination)?;
        if !self.semantic_mode {
            self.query_output_mut(destination)
                .try_reserve_exact(query_count)
                .map_err(|_| "plain WHIR query allocation failed".to_owned())?;
        }
        if query_count == 0 {
            self.phase_after_queries(destination)
        } else {
            self.prepare_query_buffers(destination)?;
            Ok(PlainWhirIncrementalDecodePhase::QueryValues {
                destination,
                query_index: 0,
                next_value_index: 0,
            })
        }
    }

    fn phase_after_queries(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        self.finish_dictionary()?;
        if self.semantic_mode {
            let verification = self
                .semantic_verification
                .as_mut()
                .ok_or_else(|| "plain WHIR semantic verifier is absent after queries".to_owned())?;
            match destination {
                PlainWhirQueryDestination::Round(round_index) => {
                    verification.finish_round_queries(round_index)?;
                }
                PlainWhirQueryDestination::Final => {
                    verification.finish_final_queries()?;
                }
            }
        }
        match destination {
            PlainWhirQueryDestination::Round(round_index) => self.begin_sumcheck(
                PlainWhirSumcheckDestination::Round(round_index),
                self.configuration.rounds[round_index].sumcheck_round_count,
            ),
            PlainWhirQueryDestination::Final => {
                if self.configuration.final_sumcheck_round_count == 0 {
                    self.begin_sumcheck(PlainWhirSumcheckDestination::Final, 0)
                } else {
                    self.begin_sumcheck(
                        PlainWhirSumcheckDestination::Final,
                        self.configuration.final_sumcheck_round_count,
                    )
                }
            }
        }
    }

    fn finish_dictionary(&mut self) -> Result<(), String> {
        self.dictionary_usage
            .take()
            .ok_or_else(|| "plain WHIR proof omitted its dictionary header".to_owned())?
            .finish()?;
        self.dictionary = Vec::new();
        self.distinct_dictionary_nodes = None;
        self.expected_dictionary_count = None;
        Ok(())
    }

    fn phase_after_completed_query(
        &mut self,
        destination: PlainWhirQueryDestination,
        query_index: usize,
    ) -> Result<PlainWhirIncrementalDecodePhase, String> {
        let following_query_index = query_index
            .checked_add(1)
            .ok_or_else(|| "plain WHIR query index overflowed".to_owned())?;
        let query_count = self.query_shape(destination)?.0;
        if following_query_index == query_count {
            self.phase_after_queries(destination)
        } else {
            self.prepare_query_buffers(destination)?;
            Ok(PlainWhirIncrementalDecodePhase::QueryValues {
                destination,
                query_index: following_query_index,
                next_value_index: 0,
            })
        }
    }

    fn query_shape(
        &self,
        destination: PlainWhirQueryDestination,
    ) -> Result<(usize, usize, usize), String> {
        match destination {
            PlainWhirQueryDestination::Round(round_index) => self
                .configuration
                .rounds
                .get(round_index)
                .map(|shape| {
                    (
                        shape.query_count,
                        shape.query_value_count,
                        shape.query_path_length,
                    )
                })
                .ok_or_else(|| "plain WHIR query round is outside the configuration".to_owned()),
            PlainWhirQueryDestination::Final => Ok((
                self.configuration.final_query_count,
                self.configuration.final_query_value_count,
                self.configuration.final_query_path_length,
            )),
        }
    }

    fn prepare_query_buffers(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> Result<(), String> {
        let (_, value_count, path_length) = self.query_shape(destination)?;
        self.prepare_pending_values(value_count, "query values")?;
        self.pending_query_path.clear();
        self.pending_query_path
            .try_reserve_exact(path_length)
            .map_err(|_| "plain WHIR query-path allocation failed".to_owned())
    }

    fn finish_query(
        &mut self,
        destination: PlainWhirQueryDestination,
        query_index: usize,
    ) -> Result<(), String> {
        let values = core::mem::take(&mut self.pending_values);
        let proof = core::mem::take(&mut self.pending_query_path);
        let uses_base_variant = match destination {
            PlainWhirQueryDestination::Round(round_index) => {
                self.configuration
                    .rounds
                    .get(round_index)
                    .ok_or_else(|| {
                        "plain WHIR query round is outside the configuration".to_owned()
                    })?
                    .uses_base_field_query_variant
            }
            PlainWhirQueryDestination::Final => {
                self.configuration.final_queries_use_base_field_variant
            }
        };
        let query = if uses_base_variant {
            QueryOpening::Base { values, proof }
        } else {
            QueryOpening::Extension { values, proof }
        };
        if self.semantic_mode {
            let verification = self.semantic_verification.as_mut().ok_or_else(|| {
                "plain WHIR semantic verifier is absent while decoding a query".to_owned()
            })?;
            match destination {
                PlainWhirQueryDestination::Round(round_index) => {
                    verification.verify_query(round_index, query_index, &query)?;
                }
                PlainWhirQueryDestination::Final => {
                    verification.verify_final_query(query_index, &query)?;
                }
            }
        } else {
            self.query_output_mut(destination).push(query);
        }
        Ok(())
    }

    fn query_output_mut(
        &mut self,
        destination: PlainWhirQueryDestination,
    ) -> &mut Vec<QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>> {
        match destination {
            PlainWhirQueryDestination::Round(round_index) => {
                &mut self.whir.rounds[round_index].queries
            }
            PlainWhirQueryDestination::Final => &mut self.whir.final_queries,
        }
    }

    fn sumcheck_round_count(
        &self,
        destination: PlainWhirSumcheckDestination,
    ) -> Result<usize, String> {
        match destination {
            PlainWhirSumcheckDestination::Initial => {
                Ok(self.configuration.initial_sumcheck_round_count)
            }
            PlainWhirSumcheckDestination::Round(round_index) => self
                .configuration
                .rounds
                .get(round_index)
                .map(|shape| shape.sumcheck_round_count)
                .ok_or_else(|| "plain WHIR sumcheck round is outside the configuration".to_owned()),
            PlainWhirSumcheckDestination::Final => {
                Ok(self.configuration.final_sumcheck_round_count)
            }
        }
    }

    fn sumcheck_mut(
        &mut self,
        destination: PlainWhirSumcheckDestination,
    ) -> Result<&mut SumcheckData<ChallengeField, ChallengeField>, String> {
        match destination {
            PlainWhirSumcheckDestination::Initial => Ok(&mut self.whir.initial_sumcheck),
            PlainWhirSumcheckDestination::Round(round_index) => self
                .whir
                .rounds
                .get_mut(round_index)
                .map(|round| &mut round.sumcheck)
                .ok_or_else(|| "plain WHIR sumcheck round is outside the proof".to_owned()),
            PlainWhirSumcheckDestination::Final => self
                .whir
                .final_sumcheck
                .as_mut()
                .ok_or_else(|| "plain WHIR final sumcheck storage is absent".to_owned()),
        }
    }

    fn prepare_pending_values(&mut self, count: usize, label: &str) -> Result<(), String> {
        self.pending_values.clear();
        self.pending_values
            .try_reserve_exact(count)
            .map_err(|_| format!("plain WHIR {label} allocation failed"))
    }

    fn ensure_declared_remaining_elements(
        &self,
        element_count: usize,
        element_byte_length: usize,
        label: &str,
    ) -> Result<(), String> {
        let required_byte_length = element_count
            .checked_mul(element_byte_length)
            .ok_or_else(|| format!("plain WHIR {label} byte count overflowed"))?;
        let remaining_byte_length = self
            .declared_complete_proof_byte_length
            .checked_sub(self.offset)
            .ok_or_else(|| "plain WHIR wire cursor exceeds its declared length".to_owned())?;
        if required_byte_length > remaining_byte_length {
            return Err(format!(
                "plain WHIR proof is truncated before {label} requiring {required_byte_length} bytes"
            ));
        }
        Ok(())
    }

    fn read_array<Source: ProofByteSource + ?Sized, const BYTE_COUNT: usize>(
        &mut self,
        source: &Source,
    ) -> Result<[u8; BYTE_COUNT], String> {
        let mut bytes = [0_u8; BYTE_COUNT];
        if !source.copy_bytes(self.offset, &mut bytes) {
            return Err(format!(
                "plain WHIR proof is truncated at byte {}, while reading {BYTE_COUNT} bytes",
                self.offset
            ));
        }
        self.offset = self
            .offset
            .checked_add(BYTE_COUNT)
            .ok_or_else(|| "plain WHIR wire cursor overflowed".to_owned())?;
        Ok(bytes)
    }

    fn read_u32<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_array(source)?))
    }

    fn read_u64<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array(source)?))
    }

    fn read_field<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<ChallengeField, String> {
        let mut coefficients = [Goldilocks::ZERO; CHALLENGE_FIELD_LIMB_COUNT];
        for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
            let canonical = self.read_u64(source)?;
            if canonical >= Goldilocks::ORDER_U64 {
                return Err(format!(
                    "plain WHIR field limb {coefficient_index} is not canonical"
                ));
            }
            *coefficient = Goldilocks::new(canonical);
        }
        Ok(ChallengeField::new(coefficients))
    }

    fn read_merkle_node<Source: ProofByteSource + ?Sized>(
        &mut self,
        source: &Source,
    ) -> Result<MerkleNode, String> {
        let mut node = [0_u64; MERKLE_DIGEST_WORD_LENGTH];
        for word in &mut node {
            *word = self.read_u64(source)?;
        }
        Ok(node)
    }
}

fn sumcheck_resident_payload_byte_length(
    sumcheck: &SumcheckData<ChallengeField, ChallengeField>,
) -> usize {
    sumcheck
        .polynomial_evaluations
        .capacity()
        .saturating_mul(core::mem::size_of::<[ChallengeField; 2]>())
        .saturating_add(
            sumcheck
                .pow_witnesses
                .capacity()
                .saturating_mul(core::mem::size_of::<ChallengeField>()),
        )
}

fn query_resident_payload_byte_length(
    queries: &Vec<QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>>,
) -> usize {
    queries
        .capacity()
        .saturating_mul(core::mem::size_of::<
            QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>,
        >())
        .saturating_add(
            queries
                .iter()
                .map(|query| {
                    let (values, proof) = query_parts(query);
                    values
                        .capacity()
                        .saturating_mul(core::mem::size_of::<ChallengeField>())
                        .saturating_add(
                            proof
                                .capacity()
                                .saturating_mul(core::mem::size_of::<MerkleNode>()),
                        )
                })
                .fold(0_usize, usize::saturating_add),
        )
}

#[cfg(test)]
pub(super) fn decode_plain_whir_batch_proof(
    pcs: &PlainAggregatePcs,
    canonical: &[u8],
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<PlainAggregateProof, String> {
    let mut decoder = PlainWhirIncrementalDecoder::new(
        pcs,
        expected_opening_widths,
        table_width,
        0,
        canonical.len(),
    )?;
    decoder.consume_available(canonical, canonical.len())?;
    decoder.finish(pcs)
}

#[cfg(test)]
pub(super) fn plain_whir_wire_breakdown(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_count: usize,
) -> Result<PlainWhirWireBreakdown, String> {
    plain_whir_batch_wire_breakdown(pcs, proof, &vec![1; expected_opening_count], 1)
}

#[cfg(test)]
pub(super) fn plain_whir_batch_wire_breakdown(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<PlainWhirWireBreakdown, String> {
    let canonical =
        encode_plain_whir_batch_proof(pcs, proof, expected_opening_widths, table_width)?;
    let merkle_dictionary_node_count = proof
        .whir
        .rounds
        .iter()
        .map(|round| MerkleNodeDictionary::from_queries(&round.queries))
        .chain(core::iter::once(MerkleNodeDictionary::from_queries(
            &proof.whir.final_queries,
        )))
        .try_fold(0_usize, |node_count, dictionary| {
            node_count
                .checked_add(dictionary?.nodes.len())
                .ok_or_else(|| "plain WHIR dictionary-node count overflowed".to_owned())
        })?;
    let (query_count, query_value_count, merkle_reference_count) = proof
        .whir
        .rounds
        .iter()
        .flat_map(|round| round.queries.iter())
        .chain(proof.whir.final_queries.iter())
        .try_fold((0_usize, 0_usize, 0_usize), |totals, query| {
            let (values, path) = query_parts(query);
            Ok::<_, String>((
                totals
                    .0
                    .checked_add(1)
                    .ok_or_else(|| "plain WHIR query count overflowed".to_owned())?,
                totals
                    .1
                    .checked_add(values.len())
                    .ok_or_else(|| "plain WHIR query-value count overflowed".to_owned())?,
                totals
                    .2
                    .checked_add(path.len())
                    .ok_or_else(|| "plain WHIR Merkle-reference count overflowed".to_owned())?,
            ))
        })?;
    Ok(PlainWhirWireBreakdown {
        complete_byte_length: canonical.len(),
        query_value_byte_length: query_value_count * CHALLENGE_FIELD_LIMB_COUNT * 8,
        merkle_dictionary_byte_length: merkle_dictionary_node_count * MERKLE_DIGEST_WORD_LENGTH * 8,
        merkle_reference_byte_length: merkle_reference_count * 4,
        merkle_unique_node_count: merkle_dictionary_node_count,
        merkle_reference_count,
        query_count,
    })
}

fn validate_codec_configuration(pcs: &PlainAggregatePcs) -> Result<(), String> {
    if pcs.starting_folding_pow_bits != 0
        || pcs.final_pow_bits != 0
        || pcs.final_folding_pow_bits != 0
        || pcs
            .round_parameters
            .iter()
            .any(|round| round.pow_bits != 0 || round.folding_pow_bits != 0)
    {
        return Err(
            "plain WHIR canonical wire only supports the zero-PoW configuration".to_owned(),
        );
    }
    Ok(())
}

fn validate_proof_shape(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<(), String> {
    if table_width == 0
        || expected_opening_widths
            .iter()
            .any(|width| *width == 0 || *width > table_width)
    {
        return Err("plain WHIR opening widths do not match the committed table".to_owned());
    }
    if proof.evals.len() != expected_opening_widths.len() {
        return Err(format!(
            "plain WHIR proof has {} opening batches, expected {}",
            proof.evals.len(),
            expected_opening_widths.len()
        ));
    }
    for (opening_index, (batch, expected_width)) in
        proof.evals.iter().zip(expected_opening_widths).enumerate()
    {
        if batch.current().len() != *expected_width || !batch.next().is_empty() {
            return Err(format!(
                "plain WHIR opening batch {opening_index} must contain {expected_width} current evaluations and no successor evaluation"
            ));
        }
    }
    if proof.whir.initial_ood_answers.len() != pcs.commitment_ood_samples {
        return Err(
            "plain WHIR initial OOD answer count does not match the configuration".to_owned(),
        );
    }
    validate_sumcheck(
        &proof.whir.initial_sumcheck,
        pcs.round_folding_factor(0),
        "initial",
    )?;
    if proof.whir.rounds.len() != pcs.n_rounds() {
        return Err(format!(
            "plain WHIR proof has {} rounds, expected {}",
            proof.whir.rounds.len(),
            pcs.n_rounds()
        ));
    }
    for (round_index, round) in proof.whir.rounds.iter().enumerate() {
        let parameters = &pcs.round_parameters[round_index];
        let commitment = round
            .commitment
            .as_ref()
            .ok_or_else(|| format!("plain WHIR round {round_index} has no commitment"))?;
        if commitment.num_roots() != 1 {
            return Err(format!(
                "plain WHIR round {round_index} commitment has {} roots, expected 1",
                commitment.num_roots()
            ));
        }
        if round.ood_answers.len() != parameters.ood_samples {
            return Err(format!(
                "plain WHIR round {round_index} has {} OOD answers, expected {}",
                round.ood_answers.len(),
                parameters.ood_samples
            ));
        }
        if round.pow_witness != ChallengeField::ZERO {
            return Err(format!(
                "plain WHIR round {round_index} carries a PoW witness in a zero-PoW configuration"
            ));
        }
        validate_queries(
            &round.queries,
            parameters.num_queries,
            initial_query_value_count(pcs, round_index)?,
            query_path_length(
                parameters.domain_size,
                pcs.round_folding_factor(round_index),
            )?,
            round_index == 0,
            &format!("round {round_index}"),
        )?;
        validate_sumcheck(
            &round.sumcheck,
            pcs.round_folding_factor(round_index + 1),
            &format!("round {round_index}"),
        )?;
    }
    let final_configuration = pcs.final_round_config();
    let final_poly = proof
        .whir
        .final_poly
        .as_ref()
        .ok_or_else(|| "plain WHIR proof has no final polynomial".to_owned())?;
    let expected_final_polynomial_length = 1_usize << final_configuration.num_variables;
    if final_poly.num_evals() != expected_final_polynomial_length {
        return Err(format!(
            "plain WHIR final polynomial has {} evaluations, expected {expected_final_polynomial_length}",
            final_poly.num_evals()
        ));
    }
    if proof.whir.final_pow_witness != ChallengeField::ZERO {
        return Err(
            "plain WHIR proof carries a final PoW witness in a zero-PoW configuration".to_owned(),
        );
    }
    validate_queries(
        &proof.whir.final_queries,
        pcs.final_queries,
        initial_query_value_count(pcs, pcs.n_rounds())?,
        query_path_length(
            final_configuration.domain_size,
            pcs.round_folding_factor(pcs.n_rounds()),
        )?,
        pcs.n_rounds() == 0,
        "final",
    )?;
    match (pcs.final_sumcheck_rounds, &proof.whir.final_sumcheck) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err("plain WHIR proof has an unexpected final sumcheck".to_owned());
        }
        (expected, Some(sumcheck)) => validate_sumcheck(sumcheck, expected, "final")?,
        (expected, None) => {
            return Err(format!(
                "plain WHIR proof is missing its {expected}-round final sumcheck"
            ));
        }
    }
    Ok(())
}

fn validate_sumcheck(
    sumcheck: &SumcheckData<ChallengeField, ChallengeField>,
    expected_round_count: usize,
    label: &str,
) -> Result<(), String> {
    if sumcheck.polynomial_evaluations.len() != expected_round_count {
        return Err(format!(
            "plain WHIR {label} sumcheck has {} rounds, expected {expected_round_count}",
            sumcheck.polynomial_evaluations.len()
        ));
    }
    if !sumcheck.pow_witnesses.is_empty() {
        return Err(format!(
            "plain WHIR {label} sumcheck carries PoW witnesses in a zero-PoW configuration"
        ));
    }
    Ok(())
}

fn validate_queries(
    queries: &[QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>],
    expected_query_count: usize,
    expected_value_count: usize,
    expected_path_length: usize,
    expect_base_variant: bool,
    label: &str,
) -> Result<(), String> {
    if queries.len() != expected_query_count {
        return Err(format!(
            "plain WHIR {label} has {} queries, expected {expected_query_count}",
            queries.len()
        ));
    }
    for (query_index, query) in queries.iter().enumerate() {
        let is_base = matches!(query, QueryOpening::Base { .. });
        if is_base != expect_base_variant {
            return Err(format!(
                "plain WHIR {label} query {query_index} has the wrong field variant"
            ));
        }
        let (values, path) = query_parts(query);
        if values.len() != expected_value_count {
            return Err(format!(
                "plain WHIR {label} query {query_index} has {} values, expected {expected_value_count}",
                values.len()
            ));
        }
        if path.len() != expected_path_length {
            return Err(format!(
                "plain WHIR {label} query {query_index} has a {}-node path, expected {expected_path_length}",
                path.len()
            ));
        }
    }
    Ok(())
}

fn query_path_length(domain_size: usize, folding_factor: usize) -> Result<usize, String> {
    if !domain_size.is_power_of_two() {
        return Err(format!(
            "plain WHIR query domain size {domain_size} is not a power of two"
        ));
    }
    (domain_size.ilog2() as usize)
        .checked_sub(folding_factor)
        .ok_or_else(|| {
            format!(
                "plain WHIR folding factor {folding_factor} exceeds log domain size {}",
                domain_size.ilog2()
            )
        })
}

fn initial_query_value_count(pcs: &PlainAggregatePcs, round_index: usize) -> Result<usize, String> {
    1_usize
        .checked_shl(pcs.round_folding_factor(round_index) as u32)
        .ok_or_else(|| "plain WHIR folded query-value count overflowed".to_owned())
}

fn query_parts(
    query: &QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>,
) -> (&Vec<ChallengeField>, &Vec<MerkleNode>) {
    match query {
        QueryOpening::Base { values, proof } | QueryOpening::Extension { values, proof } => {
            (values, proof)
        }
    }
}

struct MerkleNodeDictionary {
    nodes: Vec<MerkleNode>,
    indices: BTreeMap<MerkleNode, u32>,
}

impl MerkleNodeDictionary {
    fn from_queries(
        queries: &[QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>],
    ) -> Result<Self, String> {
        let mut nodes = Vec::new();
        let mut indices = BTreeMap::new();
        for query in queries {
            let (_, path) = query_parts(query);
            for node in path {
                if !indices.contains_key(node) {
                    let index = checked_u32(nodes.len(), "plain WHIR Merkle dictionary index")?;
                    indices.insert(*node, index);
                    nodes.push(*node);
                }
            }
        }
        Ok(Self { nodes, indices })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlainWhirWireSinkEncodingPhase {
    Magic,
    VariableCount,
    OpeningCount,
    TableWidth,
    RoundDictionaryCount {
        round_index: usize,
    },
    RoundDictionaryNode {
        round_index: usize,
        node_index: usize,
    },
    OpeningEvaluation {
        batch_index: usize,
        evaluation_index: usize,
    },
    InitialOutOfDomainAnswer {
        answer_index: usize,
    },
    InitialSumcheck {
        round_index: usize,
        evaluation_index: usize,
    },
    RoundCommitment {
        round_index: usize,
    },
    RoundOutOfDomainAnswer {
        round_index: usize,
        answer_index: usize,
    },
    RoundQueryValue {
        round_index: usize,
        query_index: usize,
        value_index: usize,
    },
    RoundQueryReference {
        round_index: usize,
        query_index: usize,
        reference_index: usize,
    },
    RoundSumcheck {
        round_index: usize,
        sumcheck_round_index: usize,
        evaluation_index: usize,
    },
    FinalPolynomial {
        evaluation_index: usize,
    },
    FinalDictionaryCount,
    FinalDictionaryNode {
        node_index: usize,
    },
    FinalQueryValue {
        query_index: usize,
        value_index: usize,
    },
    FinalQueryReference {
        query_index: usize,
        reference_index: usize,
    },
    FinalSumcheck {
        round_index: usize,
        evaluation_index: usize,
    },
    Complete,
}

pub(super) struct PlainWhirWireSinkEncoder {
    configuration: PlainWhirWireConfiguration,
    dictionary: Option<MerkleNodeDictionary>,
    phase: PlainWhirWireSinkEncodingPhase,
    written_byte_length: usize,
    canonical_byte_length: usize,
}

impl PlainWhirWireSinkEncoder {
    pub(super) fn new(
        pcs: &PlainAggregatePcs,
        proof: &PlainAggregateProof,
        expected_opening_widths: &[usize],
        table_width: usize,
    ) -> Result<Self, String> {
        validate_proof_shape(pcs, proof, expected_opening_widths, table_width)?;
        let configuration =
            PlainWhirWireConfiguration::from_pcs(pcs, expected_opening_widths, table_width)?;
        let mut dictionary_counts = Vec::new();
        dictionary_counts
            .try_reserve_exact(configuration.rounds.len() + 1)
            .map_err(|_| "plain WHIR dictionary-count allocation failed".to_owned())?;
        for (round_index, (round, shape)) in proof
            .whir
            .rounds
            .iter()
            .zip(&configuration.rounds)
            .enumerate()
        {
            let dictionary_count = MerkleNodeDictionary::from_queries(&round.queries)?
                .nodes
                .len();
            if dictionary_count > shape.dictionary_count_ceiling {
                return Err(format!(
                    "plain WHIR round {round_index} Merkle dictionary has {dictionary_count} nodes, exceeding its {}-node ceiling",
                    shape.dictionary_count_ceiling
                ));
            }
            dictionary_counts.push(dictionary_count);
        }
        let final_dictionary_count = MerkleNodeDictionary::from_queries(&proof.whir.final_queries)?
            .nodes
            .len();
        if final_dictionary_count > configuration.final_dictionary_count_ceiling {
            return Err(format!(
                "plain WHIR final Merkle dictionary has {final_dictionary_count} nodes, exceeding its {}-node ceiling",
                configuration.final_dictionary_count_ceiling
            ));
        }
        dictionary_counts.push(final_dictionary_count);
        let header_byte_length = WIRE_MAGIC
            .len()
            .checked_add(3 * core::mem::size_of::<u32>())
            .ok_or_else(|| "plain WHIR canonical header length overflowed".to_owned())?;
        let remaining_byte_length =
            configuration.checked_remaining_wire_byte_length(&dictionary_counts)?;
        let canonical_byte_length = header_byte_length
            .checked_add(remaining_byte_length)
            .ok_or_else(|| "plain WHIR canonical byte length overflowed".to_owned())?;
        Ok(Self {
            configuration,
            dictionary: None,
            phase: PlainWhirWireSinkEncodingPhase::Magic,
            written_byte_length: 0,
            canonical_byte_length,
        })
    }

    pub(super) const fn canonical_byte_length(&self) -> usize {
        self.canonical_byte_length
    }

    #[cfg(test)]
    pub(super) fn write_available<Sink>(
        &mut self,
        proof: &PlainAggregateProof,
        sink: &mut Sink,
    ) -> Result<PlainWhirWireEncodingProgress, PlainWhirWireSinkEncodingError<Sink::Error>>
    where
        Sink: CommonProofByteSink,
    {
        loop {
            match self.write_next(proof, sink)? {
                PlainWhirWireEncodingProgress::Pending => {}
                complete @ PlainWhirWireEncodingProgress::Complete { .. } => return Ok(complete),
            }
        }
    }

    pub(super) fn write_next<Sink>(
        &mut self,
        proof: &PlainAggregateProof,
        sink: &mut Sink,
    ) -> Result<PlainWhirWireEncodingProgress, PlainWhirWireSinkEncodingError<Sink::Error>>
    where
        Sink: CommonProofByteSink,
    {
        loop {
            match self.phase {
                PlainWhirWireSinkEncodingPhase::Magic => {
                    self.write_bytes(sink, WIRE_MAGIC)?;
                    self.phase = PlainWhirWireSinkEncodingPhase::VariableCount;
                }
                PlainWhirWireSinkEncodingPhase::VariableCount => {
                    let value = checked_u32(
                        self.configuration.variable_count,
                        "plain WHIR variable count",
                    )
                    .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?;
                    self.write_bytes(sink, &value.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::OpeningCount;
                }
                PlainWhirWireSinkEncodingPhase::OpeningCount => {
                    let value = checked_u32(
                        self.configuration.opening_widths.len(),
                        "plain WHIR opening count",
                    )
                    .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?;
                    self.write_bytes(sink, &value.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::TableWidth;
                }
                PlainWhirWireSinkEncodingPhase::TableWidth => {
                    let value =
                        checked_u32(self.configuration.table_width, "plain WHIR table width")
                            .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?;
                    self.write_bytes(sink, &value.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::OpeningEvaluation {
                        batch_index: 0,
                        evaluation_index: 0,
                    };
                }
                PlainWhirWireSinkEncodingPhase::OpeningEvaluation {
                    batch_index,
                    evaluation_index,
                } => {
                    let Some(batch) = proof.evals.get(batch_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::InitialOutOfDomainAnswer {
                            answer_index: 0,
                        };
                        continue;
                    };
                    let Some(evaluation) = batch.current().get(evaluation_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::OpeningEvaluation {
                            batch_index: batch_index + 1,
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*evaluation))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::OpeningEvaluation {
                        batch_index,
                        evaluation_index: evaluation_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::InitialOutOfDomainAnswer { answer_index } => {
                    let Some(answer) = proof.whir.initial_ood_answers.get(answer_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::InitialSumcheck {
                            round_index: 0,
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*answer))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::InitialOutOfDomainAnswer {
                        answer_index: answer_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::InitialSumcheck {
                    round_index,
                    evaluation_index,
                } => {
                    let Some(evaluations) = proof
                        .whir
                        .initial_sumcheck
                        .polynomial_evaluations
                        .get(round_index)
                    else {
                        self.phase =
                            PlainWhirWireSinkEncodingPhase::RoundCommitment { round_index: 0 };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(evaluations[evaluation_index]))?;
                    self.phase = if evaluation_index == 0 {
                        PlainWhirWireSinkEncodingPhase::InitialSumcheck {
                            round_index,
                            evaluation_index: 1,
                        }
                    } else {
                        PlainWhirWireSinkEncodingPhase::InitialSumcheck {
                            round_index: round_index + 1,
                            evaluation_index: 0,
                        }
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundCommitment { round_index } => {
                    let Some(round) = proof.whir.rounds.get(round_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalPolynomial {
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    let root = round
                        .commitment
                        .as_ref()
                        .and_then(|commitment| commitment.roots().first())
                        .ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(format!(
                                "plain WHIR round {round_index} has no canonical commitment root"
                            ))
                        })?;
                    self.write_bytes(sink, &merkle_node_bytes(root))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundOutOfDomainAnswer {
                        round_index,
                        answer_index: 0,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundOutOfDomainAnswer {
                    round_index,
                    answer_index,
                } => {
                    let round = proof.whir.rounds.get(round_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR round disappeared during encoding".to_owned(),
                        )
                    })?;
                    let Some(answer) = round.ood_answers.get(answer_index) else {
                        self.phase =
                            PlainWhirWireSinkEncodingPhase::RoundDictionaryCount { round_index };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*answer))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundOutOfDomainAnswer {
                        round_index,
                        answer_index: answer_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundDictionaryCount { round_index } => {
                    if self.dictionary.is_none() {
                        let round = proof.whir.rounds.get(round_index).ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR round disappeared during dictionary encoding"
                                    .to_owned(),
                            )
                        })?;
                        self.dictionary = Some(
                            MerkleNodeDictionary::from_queries(&round.queries)
                                .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?,
                        );
                    }
                    let dictionary_count = self
                        .dictionary
                        .as_ref()
                        .ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR round dictionary is absent".to_owned(),
                            )
                        })?
                        .nodes
                        .len();
                    let value =
                        checked_u32(dictionary_count, "plain WHIR round Merkle dictionary size")
                            .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?;
                    self.write_bytes(sink, &value.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundDictionaryNode {
                        round_index,
                        node_index: 0,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundDictionaryNode {
                    round_index,
                    node_index,
                } => {
                    let Some(node) = self
                        .dictionary
                        .as_ref()
                        .and_then(|dictionary| dictionary.nodes.get(node_index))
                    else {
                        self.phase = PlainWhirWireSinkEncodingPhase::RoundQueryValue {
                            round_index,
                            query_index: 0,
                            value_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &merkle_node_bytes(node))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundDictionaryNode {
                        round_index,
                        node_index: node_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundQueryValue {
                    round_index,
                    query_index,
                    value_index,
                } => {
                    let round = proof.whir.rounds.get(round_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR round disappeared during query encoding".to_owned(),
                        )
                    })?;
                    let Some(query) = round.queries.get(query_index) else {
                        self.dictionary.take().ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR round dictionary disappeared before its queries ended"
                                    .to_owned(),
                            )
                        })?;
                        self.phase = PlainWhirWireSinkEncodingPhase::RoundSumcheck {
                            round_index,
                            sumcheck_round_index: 0,
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    let (values, _) = query_parts(query);
                    let Some(value) = values.get(value_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::RoundQueryReference {
                            round_index,
                            query_index,
                            reference_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*value))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundQueryValue {
                        round_index,
                        query_index,
                        value_index: value_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundQueryReference {
                    round_index,
                    query_index,
                    reference_index,
                } => {
                    let round = proof.whir.rounds.get(round_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR round disappeared during path encoding".to_owned(),
                        )
                    })?;
                    let query = round.queries.get(query_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR query disappeared during path encoding".to_owned(),
                        )
                    })?;
                    let (_, path) = query_parts(query);
                    let Some(node) = path.get(reference_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::RoundQueryValue {
                            round_index,
                            query_index: query_index + 1,
                            value_index: 0,
                        };
                        continue;
                    };
                    let reference = self
                        .dictionary
                        .as_ref()
                        .and_then(|dictionary| dictionary.indices.get(node))
                        .ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR query path contains a node absent from its dictionary"
                                    .to_owned(),
                            )
                        })?;
                    self.write_bytes(sink, &reference.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::RoundQueryReference {
                        round_index,
                        query_index,
                        reference_index: reference_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::RoundSumcheck {
                    round_index,
                    sumcheck_round_index,
                    evaluation_index,
                } => {
                    let round = proof.whir.rounds.get(round_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR round disappeared during sumcheck encoding".to_owned(),
                        )
                    })?;
                    let Some(evaluations) = round
                        .sumcheck
                        .polynomial_evaluations
                        .get(sumcheck_round_index)
                    else {
                        self.phase = PlainWhirWireSinkEncodingPhase::RoundCommitment {
                            round_index: round_index + 1,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(evaluations[evaluation_index]))?;
                    self.phase = if evaluation_index == 0 {
                        PlainWhirWireSinkEncodingPhase::RoundSumcheck {
                            round_index,
                            sumcheck_round_index,
                            evaluation_index: 1,
                        }
                    } else {
                        PlainWhirWireSinkEncodingPhase::RoundSumcheck {
                            round_index,
                            sumcheck_round_index: sumcheck_round_index + 1,
                            evaluation_index: 0,
                        }
                    };
                }
                PlainWhirWireSinkEncodingPhase::FinalPolynomial { evaluation_index } => {
                    let final_polynomial = proof.whir.final_poly.as_ref().ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR final polynomial disappeared during encoding".to_owned(),
                        )
                    })?;
                    let Some(evaluation) = final_polynomial.as_slice().get(evaluation_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalDictionaryCount;
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*evaluation))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::FinalPolynomial {
                        evaluation_index: evaluation_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::FinalDictionaryCount => {
                    if self.dictionary.is_none() {
                        self.dictionary = Some(
                            MerkleNodeDictionary::from_queries(&proof.whir.final_queries)
                                .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?,
                        );
                    }
                    let dictionary_count = self
                        .dictionary
                        .as_ref()
                        .ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR final dictionary is absent".to_owned(),
                            )
                        })?
                        .nodes
                        .len();
                    let value =
                        checked_u32(dictionary_count, "plain WHIR final Merkle dictionary size")
                            .map_err(PlainWhirWireSinkEncodingError::InvalidProof)?;
                    self.write_bytes(sink, &value.to_le_bytes())?;
                    self.phase =
                        PlainWhirWireSinkEncodingPhase::FinalDictionaryNode { node_index: 0 };
                }
                PlainWhirWireSinkEncodingPhase::FinalDictionaryNode { node_index } => {
                    let Some(node) = self
                        .dictionary
                        .as_ref()
                        .and_then(|dictionary| dictionary.nodes.get(node_index))
                    else {
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalQueryValue {
                            query_index: 0,
                            value_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &merkle_node_bytes(node))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::FinalDictionaryNode {
                        node_index: node_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::FinalQueryValue {
                    query_index,
                    value_index,
                } => {
                    let Some(query) = proof.whir.final_queries.get(query_index) else {
                        self.dictionary.take().ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR final dictionary disappeared before its queries ended"
                                    .to_owned(),
                            )
                        })?;
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalSumcheck {
                            round_index: 0,
                            evaluation_index: 0,
                        };
                        continue;
                    };
                    let (values, _) = query_parts(query);
                    let Some(value) = values.get(value_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalQueryReference {
                            query_index,
                            reference_index: 0,
                        };
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(*value))?;
                    self.phase = PlainWhirWireSinkEncodingPhase::FinalQueryValue {
                        query_index,
                        value_index: value_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::FinalQueryReference {
                    query_index,
                    reference_index,
                } => {
                    let query = proof.whir.final_queries.get(query_index).ok_or_else(|| {
                        PlainWhirWireSinkEncodingError::InvalidProof(
                            "plain WHIR final query disappeared during path encoding".to_owned(),
                        )
                    })?;
                    let (_, path) = query_parts(query);
                    let Some(node) = path.get(reference_index) else {
                        self.phase = PlainWhirWireSinkEncodingPhase::FinalQueryValue {
                            query_index: query_index + 1,
                            value_index: 0,
                        };
                        continue;
                    };
                    let reference = self
                        .dictionary
                        .as_ref()
                        .and_then(|dictionary| dictionary.indices.get(node))
                        .ok_or_else(|| {
                            PlainWhirWireSinkEncodingError::InvalidProof(
                                "plain WHIR final query path contains a node absent from its dictionary"
                                    .to_owned(),
                            )
                        })?;
                    self.write_bytes(sink, &reference.to_le_bytes())?;
                    self.phase = PlainWhirWireSinkEncodingPhase::FinalQueryReference {
                        query_index,
                        reference_index: reference_index + 1,
                    };
                }
                PlainWhirWireSinkEncodingPhase::FinalSumcheck {
                    round_index,
                    evaluation_index,
                } => {
                    let Some(final_sumcheck) = proof.whir.final_sumcheck.as_ref() else {
                        self.phase = PlainWhirWireSinkEncodingPhase::Complete;
                        continue;
                    };
                    let Some(evaluations) = final_sumcheck.polynomial_evaluations.get(round_index)
                    else {
                        self.phase = PlainWhirWireSinkEncodingPhase::Complete;
                        continue;
                    };
                    self.write_bytes(sink, &challenge_field_bytes(evaluations[evaluation_index]))?;
                    self.phase = if evaluation_index == 0 {
                        PlainWhirWireSinkEncodingPhase::FinalSumcheck {
                            round_index,
                            evaluation_index: 1,
                        }
                    } else {
                        PlainWhirWireSinkEncodingPhase::FinalSumcheck {
                            round_index: round_index + 1,
                            evaluation_index: 0,
                        }
                    };
                }
                PlainWhirWireSinkEncodingPhase::Complete => {
                    if self.written_byte_length != self.canonical_byte_length {
                        return Err(PlainWhirWireSinkEncodingError::InvalidProof(format!(
                            "plain WHIR encoder wrote {} bytes, expected {}",
                            self.written_byte_length, self.canonical_byte_length
                        )));
                    }
                    return Ok(PlainWhirWireEncodingProgress::Complete {
                        canonical_byte_length: self.canonical_byte_length,
                    });
                }
            }
            return Ok(PlainWhirWireEncodingProgress::Pending);
        }
    }

    fn write_bytes<Sink>(
        &mut self,
        sink: &mut Sink,
        bytes: &[u8],
    ) -> Result<(), PlainWhirWireSinkEncodingError<Sink::Error>>
    where
        Sink: CommonProofByteSink,
    {
        let following_byte_length = self
            .written_byte_length
            .checked_add(bytes.len())
            .filter(|byte_length| *byte_length <= self.canonical_byte_length)
            .ok_or_else(|| {
                PlainWhirWireSinkEncodingError::InvalidProof(
                    "plain WHIR encoder exceeded its checked canonical length".to_owned(),
                )
            })?;
        sink.write_bytes(bytes)
            .map_err(PlainWhirWireSinkEncodingError::Sink)?;
        self.written_byte_length = following_byte_length;
        Ok(())
    }
}

fn challenge_field_bytes(value: ChallengeField) -> [u8; CHALLENGE_FIELD_LIMB_COUNT * 8] {
    let coefficients =
        <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
    debug_assert_eq!(coefficients.len(), CHALLENGE_FIELD_LIMB_COUNT);
    let mut bytes = [0_u8; CHALLENGE_FIELD_LIMB_COUNT * 8];
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        let start = coefficient_index * 8;
        bytes[start..start + 8].copy_from_slice(&coefficient.as_canonical_u64().to_le_bytes());
    }
    bytes
}

fn merkle_node_bytes(node: &MerkleNode) -> [u8; MERKLE_DIGEST_WORD_LENGTH * 8] {
    let mut bytes = [0_u8; MERKLE_DIGEST_WORD_LENGTH * 8];
    for (word_index, word) in node.iter().enumerate() {
        let start = word_index * 8;
        bytes[start..start + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

struct DictionaryUsage {
    observed: Vec<bool>,
    next_first_reference: usize,
}

impl DictionaryUsage {
    fn try_new(dictionary_count: usize) -> Result<Self, String> {
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(dictionary_count)
            .map_err(|_| "plain WHIR dictionary-usage allocation failed".to_owned())?;
        observed.resize(dictionary_count, false);
        Ok(Self {
            observed,
            next_first_reference: 0,
        })
    }

    fn resident_payload_byte_length(&self) -> usize {
        self.observed
            .capacity()
            .saturating_mul(core::mem::size_of::<bool>())
    }

    fn observe(&mut self, reference: usize) -> Result<(), String> {
        if !self.observed[reference] {
            if reference != self.next_first_reference {
                return Err(format!(
                    "plain WHIR Merkle dictionary first uses node {reference}, expected node {}",
                    self.next_first_reference
                ));
            }
            self.observed[reference] = true;
            self.next_first_reference += 1;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), String> {
        if self.next_first_reference != self.observed.len() {
            return Err(format!(
                "plain WHIR Merkle dictionary has {} unused trailing nodes",
                self.observed.len() - self.next_first_reference
            ));
        }
        Ok(())
    }
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} {value} exceeds canonical u32"))
}

#[cfg(test)]
mod tests {
    use p3_challenger::CanObserve;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_multilinear_util::{point::Point, poly::Poly};

    use super::super::plain_whir::{
        PlainAggregateCommitment, PlainAggregateIncrementalVerificationPreparation,
        PlainAggregateProof, commit_plain_aggregate, open_plain_aggregate_at_points,
        plain_aggregate_challenger, plain_aggregate_pcs, plain_aggregate_pcs_with_parameters,
    };
    use super::*;

    const TEST_VARIABLE_COUNT: usize = 12;
    const U32_BYTE_LENGTH: usize = core::mem::size_of::<u32>();
    const FIELD_BYTE_LENGTH: usize = CHALLENGE_FIELD_LIMB_COUNT * core::mem::size_of::<u64>();
    const MERKLE_NODE_BYTE_LENGTH: usize = MERKLE_DIGEST_WORD_LENGTH * core::mem::size_of::<u64>();

    fn upstream_complete_whir_proof_payload_resident_lower_bound(
        configuration: &PlainWhirWireConfiguration,
    ) -> Result<u64, String> {
        let field_byte_length = u64::try_from(core::mem::size_of::<ChallengeField>())
            .map_err(|_| "plain WHIR field resident byte length exceeds u64".to_owned())?;
        let merkle_node_byte_length = u64::try_from(core::mem::size_of::<MerkleNode>())
            .map_err(|_| "plain WHIR Merkle-node resident byte length exceeds u64".to_owned())?;
        let query_payload_byte_length = |query_count: usize,
                                         query_value_count: usize,
                                         query_path_length: usize|
         -> Result<u64, String> {
            let value_byte_length = u64::try_from(query_value_count)
                .ok()
                .and_then(|count| count.checked_mul(field_byte_length))
                .ok_or_else(|| "plain WHIR query-value residency overflowed".to_owned())?;
            let path_byte_length = u64::try_from(query_path_length)
                .ok()
                .and_then(|count| count.checked_mul(merkle_node_byte_length))
                .ok_or_else(|| "plain WHIR query-path residency overflowed".to_owned())?;
            u64::try_from(query_count)
                .ok()
                .and_then(|count| {
                    count.checked_mul(value_byte_length.checked_add(path_byte_length)?)
                })
                .ok_or_else(|| "plain WHIR complete query residency overflowed".to_owned())
        };

        let mut byte_length = u64::try_from(configuration.final_polynomial_evaluation_count)
            .ok()
            .and_then(|count| count.checked_mul(field_byte_length))
            .ok_or_else(|| "plain WHIR final-polynomial residency overflowed".to_owned())?;
        for round in &configuration.rounds {
            byte_length = byte_length
                .checked_add(query_payload_byte_length(
                    round.query_count,
                    round.query_value_count,
                    round.query_path_length,
                )?)
                .ok_or_else(|| "plain WHIR complete-proof residency overflowed".to_owned())?;
        }
        byte_length
            .checked_add(query_payload_byte_length(
                configuration.final_query_count,
                configuration.final_query_value_count,
                configuration.final_query_path_length,
            )?)
            .ok_or_else(|| "plain WHIR complete-proof residency overflowed".to_owned())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ForcedPartialWrite {
        Yield,
    }

    struct RetryingTestProofByteSink {
        canonical: Vec<u8>,
        pending_write: Option<(Vec<u8>, usize)>,
        forced_yield_count: usize,
    }

    impl RetryingTestProofByteSink {
        const fn new() -> Self {
            Self {
                canonical: Vec::new(),
                pending_write: None,
                forced_yield_count: 0,
            }
        }
    }

    impl CommonProofByteSink for RetryingTestProofByteSink {
        type Error = ForcedPartialWrite;

        fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            assert!(!bytes.is_empty(), "canonical writer emitted an empty atom");
            if let Some((expected_bytes, consumed_byte_length)) = self.pending_write.take() {
                assert_eq!(
                    bytes, expected_bytes,
                    "encoder retry changed the partially consumed canonical atom"
                );
                self.canonical
                    .extend_from_slice(&bytes[consumed_byte_length..]);
                return Ok(());
            }

            let consumed_byte_length = bytes.len().div_ceil(2);
            self.canonical
                .extend_from_slice(&bytes[..consumed_byte_length]);
            self.pending_write = Some((bytes.to_vec(), consumed_byte_length));
            self.forced_yield_count += 1;
            Err(ForcedPartialWrite::Yield)
        }
    }

    struct DeterministicWireFixture {
        pcs: PlainAggregatePcs,
        canonical: Vec<u8>,
        commitment: PlainAggregateCommitment,
        opening_point: Point<ChallengeField>,
        expected_opening_evaluations: Vec<Vec<ChallengeField>>,
    }

    fn deterministic_wire_fixture() -> DeterministicWireFixture {
        let pcs = plain_aggregate_pcs_with_parameters(TEST_VARIABLE_COUNT, 2, 3)
            .expect("small plain WHIR configuration");
        let message = Poly::new(
            (0..1_usize << TEST_VARIABLE_COUNT)
                .map(|coefficient_index| {
                    ChallengeField::from_u64(coefficient_index as u64 * 19 + 7)
                })
                .collect(),
        );
        let opening_point = Point::new(
            (0..TEST_VARIABLE_COUNT)
                .map(|coordinate_index| ChallengeField::from_u64(coordinate_index as u64 * 5 + 3))
                .collect(),
        );
        let mut challenger = plain_aggregate_challenger(&pcs, b"plain WHIR hostile wire test");
        let (commitment, prover_data) = commit_plain_aggregate(&pcs, message, &mut challenger);
        let proof = open_plain_aggregate_at_points(
            &pcs,
            prover_data,
            core::slice::from_ref(&opening_point),
            &mut challenger,
        );
        let expected_opening_evaluations = proof
            .evals
            .iter()
            .map(|batch| batch.current().to_vec())
            .collect();
        let canonical =
            encode_plain_whir_proof(&pcs, &proof, 1).expect("encode small canonical proof");
        decode_plain_whir_proof(&pcs, &canonical, 1)
            .expect("decode the unmodified small canonical proof");
        DeterministicWireFixture {
            pcs,
            canonical,
            commitment,
            opening_point,
            expected_opening_evaluations,
        }
    }

    fn deterministic_semantic_preparation(
        fixture: &DeterministicWireFixture,
    ) -> PlainAggregateIncrementalVerificationPreparation {
        let mut challenger =
            plain_aggregate_challenger(&fixture.pcs, b"plain WHIR hostile wire test");
        challenger.observe(fixture.commitment.clone());
        PlainAggregateIncrementalVerificationPreparation::new_for_requests(
            &fixture.pcs,
            fixture.commitment.clone(),
            vec![fixture.opening_point.clone()],
            TEST_VARIABLE_COUNT,
            1,
            vec![vec![0]],
            fixture.expected_opening_evaluations.clone(),
            challenger,
        )
        .expect("construct deterministic semantic verifier preparation")
    }

    fn read_wire_u32(canonical: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            canonical[offset..offset + U32_BYTE_LENGTH]
                .try_into()
                .expect("a fixed-width wire u32 slice converts to an array"),
        )
    }

    fn read_wire_u64(canonical: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            canonical[offset..offset + core::mem::size_of::<u64>()]
                .try_into()
                .expect("a fixed-width wire u64 slice converts to an array"),
        )
    }

    fn write_wire_u32(canonical: &mut [u8], offset: usize, value: u32) {
        canonical[offset..offset + U32_BYTE_LENGTH].copy_from_slice(&value.to_le_bytes());
    }

    fn first_round_dictionary_count_offset(pcs: &PlainAggregatePcs) -> usize {
        let configuration = PlainWhirWireConfiguration::from_pcs(pcs, &[1], 1)
            .expect("derive the deterministic wire geometry");
        let first_round = configuration
            .rounds
            .first()
            .expect("the small fixture has a committed WHIR round");
        let prefix_field_count = 1_usize
            .checked_add(configuration.initial_ood_answer_count)
            .and_then(|count| {
                count.checked_add(
                    configuration
                        .initial_sumcheck_round_count
                        .checked_mul(2)
                        .expect("the initial sumcheck field count fits usize"),
                )
            })
            .and_then(|count| count.checked_add(first_round.ood_answer_count))
            .expect("the first-round prefix field count fits usize");
        WIRE_MAGIC
            .len()
            .checked_add(3 * U32_BYTE_LENGTH)
            .and_then(|offset| {
                offset.checked_add(
                    prefix_field_count
                        .checked_mul(FIELD_BYTE_LENGTH)
                        .expect("the first-round prefix byte length fits usize"),
                )
            })
            .and_then(|offset| offset.checked_add(MERKLE_NODE_BYTE_LENGTH))
            .expect("the first-round dictionary count offset fits usize")
    }

    fn dictionary_end_offset(dictionary_start: usize, dictionary_count: usize) -> usize {
        dictionary_start
            .checked_add(
                dictionary_count
                    .checked_mul(MERKLE_NODE_BYTE_LENGTH)
                    .expect("the small fixture dictionary byte length fits usize"),
            )
            .expect("the small fixture dictionary end fits usize")
    }

    fn first_dictionary_reference_offset(pcs: &PlainAggregatePcs, dictionary_end: usize) -> usize {
        let first_round_parameters = pcs
            .round_parameters
            .first()
            .expect("the small fixture has a committed WHIR round");
        assert!(first_round_parameters.num_queries > 0);
        assert!(
            query_path_length(
                first_round_parameters.domain_size,
                pcs.round_folding_factor(0),
            )
            .expect("derive the first query path length")
                > 0
        );
        dictionary_end
            .checked_add(
                initial_query_value_count(pcs, 0)
                    .expect("derive the first query value count")
                    .checked_mul(FIELD_BYTE_LENGTH)
                    .expect("the first query value byte length fits usize"),
            )
            .expect("the first dictionary reference offset fits usize")
    }

    fn checked_test_section_end(
        offset: usize,
        element_count: usize,
        element_byte_length: usize,
    ) -> usize {
        offset
            .checked_add(
                element_count
                    .checked_mul(element_byte_length)
                    .expect("the deterministic section byte length fits usize"),
            )
            .expect("the deterministic section end fits usize")
    }

    fn canonical_section_end_offsets(pcs: &PlainAggregatePcs, canonical: &[u8]) -> Vec<usize> {
        let configuration = PlainWhirWireConfiguration::from_pcs(pcs, &[1], 1)
            .expect("derive deterministic wire sections");
        let mut section_end_offsets = vec![
            WIRE_MAGIC.len(),
            WIRE_MAGIC.len() + U32_BYTE_LENGTH,
            WIRE_MAGIC.len() + 2 * U32_BYTE_LENGTH,
            WIRE_MAGIC.len() + 3 * U32_BYTE_LENGTH,
        ];
        let mut offset = WIRE_MAGIC.len() + 3 * U32_BYTE_LENGTH;
        let opening_evaluation_count = configuration
            .opening_widths
            .iter()
            .try_fold(0_usize, |count, width| count.checked_add(*width))
            .expect("the deterministic opening count fits usize");
        offset = checked_test_section_end(offset, opening_evaluation_count, FIELD_BYTE_LENGTH);
        section_end_offsets.push(offset);
        offset = checked_test_section_end(
            offset,
            configuration.initial_ood_answer_count,
            FIELD_BYTE_LENGTH,
        );
        section_end_offsets.push(offset);
        offset = checked_test_section_end(
            offset,
            configuration
                .initial_sumcheck_round_count
                .checked_mul(2)
                .expect("the deterministic initial sumcheck count fits usize"),
            FIELD_BYTE_LENGTH,
        );
        section_end_offsets.push(offset);
        for round in &configuration.rounds {
            offset = checked_test_section_end(offset, 1, MERKLE_NODE_BYTE_LENGTH);
            section_end_offsets.push(offset);
            offset = checked_test_section_end(offset, round.ood_answer_count, FIELD_BYTE_LENGTH);
            section_end_offsets.push(offset);
            let dictionary_count = read_wire_u32(canonical, offset) as usize;
            offset = checked_test_section_end(offset, 1, U32_BYTE_LENGTH);
            section_end_offsets.push(offset);
            offset = checked_test_section_end(offset, dictionary_count, MERKLE_NODE_BYTE_LENGTH);
            section_end_offsets.push(offset);
            let query_byte_length = round
                .query_value_count
                .checked_mul(FIELD_BYTE_LENGTH)
                .and_then(|value_byte_length| {
                    round
                        .query_path_length
                        .checked_mul(U32_BYTE_LENGTH)
                        .and_then(|path_byte_length| {
                            value_byte_length.checked_add(path_byte_length)
                        })
                })
                .expect("the deterministic round query length fits usize");
            offset = checked_test_section_end(offset, round.query_count, query_byte_length);
            section_end_offsets.push(offset);
            offset = checked_test_section_end(
                offset,
                round
                    .sumcheck_round_count
                    .checked_mul(2)
                    .expect("the deterministic round sumcheck count fits usize"),
                FIELD_BYTE_LENGTH,
            );
            section_end_offsets.push(offset);
        }
        offset = checked_test_section_end(
            offset,
            configuration.final_polynomial_evaluation_count,
            FIELD_BYTE_LENGTH,
        );
        section_end_offsets.push(offset);
        let final_dictionary_count = read_wire_u32(canonical, offset) as usize;
        offset = checked_test_section_end(offset, 1, U32_BYTE_LENGTH);
        section_end_offsets.push(offset);
        offset = checked_test_section_end(offset, final_dictionary_count, MERKLE_NODE_BYTE_LENGTH);
        section_end_offsets.push(offset);
        let final_query_byte_length = configuration
            .final_query_value_count
            .checked_mul(FIELD_BYTE_LENGTH)
            .and_then(|value_byte_length| {
                configuration
                    .final_query_path_length
                    .checked_mul(U32_BYTE_LENGTH)
                    .and_then(|path_byte_length| value_byte_length.checked_add(path_byte_length))
            })
            .expect("the deterministic final query length fits usize");
        offset = checked_test_section_end(
            offset,
            configuration.final_query_count,
            final_query_byte_length,
        );
        section_end_offsets.push(offset);
        offset = checked_test_section_end(
            offset,
            configuration
                .final_sumcheck_round_count
                .checked_mul(2)
                .expect("the deterministic final sumcheck count fits usize"),
            FIELD_BYTE_LENGTH,
        );
        section_end_offsets.push(offset);
        assert_eq!(offset, canonical.len());
        section_end_offsets.sort_unstable();
        section_end_offsets.dedup();
        section_end_offsets
    }

    fn distinct_unused_dictionary_node(
        canonical: &[u8],
        dictionary_start: usize,
        dictionary_count: usize,
    ) -> [u8; MERKLE_NODE_BYTE_LENGTH] {
        let dictionary_end = dictionary_end_offset(dictionary_start, dictionary_count);
        let dictionary_bytes = &canonical[dictionary_start..dictionary_end];
        for candidate_ordinal in 0..=dictionary_count {
            let mut candidate = [0_u8; MERKLE_NODE_BYTE_LENGTH];
            candidate[..core::mem::size_of::<u64>()].copy_from_slice(
                &u64::try_from(candidate_ordinal)
                    .expect("the small fixture candidate ordinal fits u64")
                    .to_le_bytes(),
            );
            if dictionary_bytes
                .chunks_exact(MERKLE_NODE_BYTE_LENGTH)
                .all(|node| node != candidate.as_slice())
            {
                return candidate;
            }
        }
        unreachable!("one more candidate than dictionary nodes must leave an unused value")
    }

    fn assert_wire_refused(
        pcs: &PlainAggregatePcs,
        canonical: &[u8],
        expected_error_fragment: &str,
        mutation_label: &str,
    ) {
        let error = match decode_plain_whir_proof(pcs, canonical, 1) {
            Ok(_) => panic!("plain WHIR decoder accepted {mutation_label}"),
            Err(error) => error,
        };
        assert!(
            error.contains(expected_error_fragment),
            "plain WHIR {mutation_label} returned an unexpected error: {error}"
        );
    }

    fn decode_with_available_end_offsets(
        pcs: &PlainAggregatePcs,
        canonical: &[u8],
        available_end_offsets: impl IntoIterator<Item = usize>,
    ) -> PlainAggregateProof {
        let mut decoder = PlainWhirIncrementalDecoder::new(pcs, &[1], 1, 0, canonical.len())
            .expect("construct the bounded incremental decoder");
        let mut previous_available_end_offset = 0_usize;
        for available_end_offset in available_end_offsets {
            assert!(
                available_end_offset >= previous_available_end_offset
                    && available_end_offset <= canonical.len(),
                "incremental availability ends must be canonical and monotonic"
            );
            decoder
                .consume_available(canonical, available_end_offset)
                .unwrap_or_else(|error| {
                    panic!(
                        "incremental decode failed with bytes available through {available_end_offset}: {error}"
                    )
                });
            assert!(decoder.offset() <= available_end_offset);
            previous_available_end_offset = available_end_offset;
        }
        assert_eq!(previous_available_end_offset, canonical.len());
        decoder.finish(pcs).expect("finish incremental decoding")
    }

    fn decode_semantically_with_available_end_offsets(
        fixture: &DeterministicWireFixture,
        available_end_offsets: impl IntoIterator<Item = usize>,
    ) -> Result<ExtensionFieldChallenger, String> {
        let mut decoder = PlainWhirIncrementalDecoder::new_semantic(
            &fixture.pcs,
            &[1],
            1,
            0,
            fixture.canonical.len(),
            deterministic_semantic_preparation(fixture),
        )?;
        let mut previous_available_end_offset = 0_usize;
        for available_end_offset in available_end_offsets {
            assert!(
                available_end_offset >= previous_available_end_offset
                    && available_end_offset <= fixture.canonical.len(),
                "incremental availability ends must be canonical and monotonic"
            );
            decoder.consume_available(&fixture.canonical, available_end_offset)?;
            assert!(decoder.offset() <= available_end_offset);
            previous_available_end_offset = available_end_offset;
        }
        assert_eq!(previous_available_end_offset, fixture.canonical.len());
        decoder.finish_semantic()
    }

    #[test]
    fn incremental_decoder_accepts_one_byte_section_and_adversarial_fragment_boundaries() {
        let fixture = deterministic_wire_fixture();
        let pcs = &fixture.pcs;
        let canonical = &fixture.canonical;
        let one_byte_fragment_decoded =
            decode_with_available_end_offsets(pcs, canonical, 0..=canonical.len());
        let reencoded = encode_plain_whir_proof(pcs, &one_byte_fragment_decoded, 1)
            .expect("re-encode the incrementally decoded proof");
        assert_eq!(reencoded.as_slice(), canonical.as_slice());

        for (label, available_end_offsets) in [
            (
                "one-byte final fragment",
                vec![0, canonical.len() - 1, canonical.len()],
            ),
            ("long final fragment", vec![0, 1, canonical.len()]),
            ("adversarial fragments", {
                let fragment_byte_lengths = [7_usize, 1, 63, 4_097, 3, 65_537, 2];
                let mut offsets = vec![0_usize];
                let mut offset = 0_usize;
                let mut fragment_ordinal = 0_usize;
                while offset < canonical.len() {
                    offset = offset
                        .checked_add(
                            fragment_byte_lengths[fragment_ordinal % fragment_byte_lengths.len()],
                        )
                        .expect("the hostile fragment schedule fits usize")
                        .min(canonical.len());
                    offsets.push(offset);
                    fragment_ordinal += 1;
                }
                offsets
            }),
        ] {
            let decoded = decode_with_available_end_offsets(pcs, canonical, available_end_offsets);
            let reencoded = encode_plain_whir_proof(pcs, &decoded, 1)
                .unwrap_or_else(|error| panic!("re-encode {label}: {error}"));
            assert_eq!(
                reencoded.as_slice(),
                canonical.as_slice(),
                "{label} changed canonical bytes"
            );
        }
    }

    #[test]
    fn semantic_decoder_authenticates_one_byte_and_adversarial_fragments() {
        let fixture = deterministic_wire_fixture();
        decode_semantically_with_available_end_offsets(&fixture, 0..=fixture.canonical.len())
            .expect("semantically verify one-byte fragments");
        decode_semantically_with_available_end_offsets(
            &fixture,
            [0, 1, fixture.canonical.len() - 1, fixture.canonical.len()],
        )
        .expect("semantically verify hostile final fragments");

        let dictionary_count_offset = first_round_dictionary_count_offset(&fixture.pcs);
        let dictionary_count = read_wire_u32(&fixture.canonical, dictionary_count_offset) as usize;
        let dictionary_start = dictionary_count_offset + U32_BYTE_LENGTH;
        let dictionary_end = dictionary_end_offset(dictionary_start, dictionary_count);
        let mut changed_query_value = fixture.canonical.clone();
        let changed_limb = read_wire_u64(&changed_query_value, dictionary_end).wrapping_add(1)
            % Goldilocks::ORDER_U64;
        changed_query_value[dictionary_end..dictionary_end + core::mem::size_of::<u64>()]
            .copy_from_slice(&changed_limb.to_le_bytes());
        let changed_fixture = DeterministicWireFixture {
            pcs: fixture.pcs,
            canonical: changed_query_value,
            commitment: fixture.commitment,
            opening_point: fixture.opening_point,
            expected_opening_evaluations: fixture.expected_opening_evaluations,
        };
        let error = decode_semantically_with_available_end_offsets(
            &changed_fixture,
            [0, changed_fixture.canonical.len()],
        )
        .expect_err("semantic verification must reject a changed authenticated query value");
        assert!(
            error.contains("verify plain WHIR") || error.contains("Merkle"),
            "changed query value returned an unexpected error: {error}"
        );
    }

    #[test]
    fn sink_encoder_replays_identical_atoms_after_partial_writes() {
        let fixture = deterministic_wire_fixture();
        let pcs = &fixture.pcs;
        let canonical = &fixture.canonical;
        let proof = decode_plain_whir_proof(pcs, canonical, 1)
            .expect("decode the deterministic proof for retrying sink coverage");
        let mut encoder = PlainWhirWireSinkEncoder::new(pcs, &proof, &[1], 1)
            .expect("construct the deterministic retrying sink encoder");
        assert_eq!(encoder.canonical_byte_length(), canonical.len());
        let mut sink = RetryingTestProofByteSink::new();

        loop {
            match encoder.write_next(&proof, &mut sink) {
                Ok(PlainWhirWireEncodingProgress::Pending) => {}
                Ok(PlainWhirWireEncodingProgress::Complete {
                    canonical_byte_length,
                }) => {
                    assert_eq!(canonical_byte_length, canonical.len());
                    break;
                }
                Err(PlainWhirWireSinkEncodingError::Sink(ForcedPartialWrite::Yield)) => {}
                Err(PlainWhirWireSinkEncodingError::InvalidProof(error)) => {
                    panic!("retrying sink encoder rejected the deterministic proof: {error}")
                }
            }
        }

        assert!(
            sink.forced_yield_count > 1,
            "the retry test must cross multiple canonical write atoms"
        );
        assert!(sink.pending_write.is_none());
        assert_eq!(sink.canonical.as_slice(), canonical.as_slice());
    }

    #[test]
    fn decoder_admission_uses_only_the_absolute_common_proof_bound() {
        let pcs = plain_aggregate_pcs_with_parameters(TEST_VARIABLE_COUNT, 2, 3)
            .expect("small plain WHIR configuration");
        PlainWhirIncrementalDecoder::new(&pcs, &[1], 1, 0, MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .expect("the absolute common-proof bound is admissible");
        let error = PlainWhirIncrementalDecoder::new(
            &pcs,
            &[1],
            1,
            0,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1,
        )
        .err()
        .expect("one byte beyond the absolute common-proof bound must be refused");
        assert!(error.contains("invalid authenticated byte length"));
    }

    #[test]
    fn semantic_decoder_resident_accounting_tracks_peak_state_not_stream_length() {
        let pcs = plain_aggregate_pcs_with_parameters(TEST_VARIABLE_COUNT, 2, 3)
            .expect("small plain WHIR configuration");
        let short_stream_accounting =
            plain_whir_incremental_decoder_resident_memory_accounting(&pcs, &[1], 1, 1)
                .expect("account the minimum authenticated stream length");
        let maximum_stream_accounting = plain_whir_incremental_decoder_resident_memory_accounting(
            &pcs,
            &[1],
            1,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        )
        .expect("account the absolute maximum authenticated stream length");

        assert_eq!(short_stream_accounting, maximum_stream_accounting);
        assert!(
            short_stream_accounting.maximum_resident_byte_length()
                > u64::try_from(core::mem::size_of::<PlainWhirIncrementalDecoder>())
                    .expect("the decoder size fits u64"),
            "the accounting must include dynamic semantic and section state"
        );
    }

    #[test]
    fn selected_whir_resumable_api_reduces_required_proof_payload_residency() {
        let pcs = plain_aggregate_pcs(21).expect("selected plain WHIR configuration");
        let configuration = PlainWhirWireConfiguration::from_pcs(&pcs, &[1], 1)
            .expect("derive selected plain WHIR wire geometry");
        let upstream_complete_proof_resident_lower_bound =
            upstream_complete_whir_proof_payload_resident_lower_bound(&configuration)
                .expect("derive upstream complete-proof residency lower bound");
        let resumable_accounting = plain_whir_incremental_decoder_resident_memory_accounting(
            &pcs,
            &[1],
            1,
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        )
        .expect("derive selected resumable section-state peak");
        let resumable_section_state_peak = resumable_accounting.maximum_section_state_byte_length();
        let resident_byte_delta = upstream_complete_proof_resident_lower_bound
            .checked_sub(resumable_section_state_peak)
            .expect("the selected resumable section state is smaller than a complete proof");
        let ratio_basis_points = upstream_complete_proof_resident_lower_bound
            .checked_mul(10_000)
            .and_then(|scaled| scaled.checked_div(resumable_section_state_peak))
            .expect("derive selected residency ratio");

        assert_eq!(
            pcs.round_parameters
                .iter()
                .map(|round| round.num_queries)
                .chain(core::iter::once(pcs.final_queries))
                .collect::<Vec<_>>(),
            [387, 288, 268, 264, 263]
        );
        assert_eq!(
            configuration
                .rounds
                .iter()
                .map(|round| round.query_path_length)
                .chain(core::iter::once(configuration.final_query_path_length))
                .collect::<Vec<_>>(),
            [20, 19, 18, 17, 16]
        );
        assert_eq!(upstream_complete_proof_resident_lower_bound, 2_183_808);
        assert_eq!(resumable_section_state_peak, 1_502_600);
        assert_eq!(resident_byte_delta, 681_208);
        assert_eq!(ratio_basis_points, 14_533);
    }

    #[test]
    fn canonical_wire_rejects_hostile_raw_mutations() {
        let fixture = deterministic_wire_fixture();
        let pcs = fixture.pcs;
        let canonical = fixture.canonical;
        let dictionary_count_offset = first_round_dictionary_count_offset(&pcs);
        let dictionary_start = dictionary_count_offset + U32_BYTE_LENGTH;
        let dictionary_count = read_wire_u32(&canonical, dictionary_count_offset) as usize;
        let maximum_dictionary_count = PlainWhirWireConfiguration::from_pcs(&pcs, &[1], 1)
            .expect("derive the deterministic wire geometry")
            .rounds[0]
            .dictionary_count_ceiling;
        assert!(dictionary_count >= 2);
        assert!(dictionary_count < maximum_dictionary_count);
        let dictionary_end = dictionary_end_offset(dictionary_start, dictionary_count);
        let first_reference_offset = first_dictionary_reference_offset(&pcs, dictionary_end);
        assert_eq!(read_wire_u32(&canonical, first_reference_offset), 0);

        let mut oversized_dictionary_count = canonical.clone();
        write_wire_u32(
            &mut oversized_dictionary_count,
            dictionary_count_offset,
            u32::MAX,
        );
        assert_wire_refused(
            &pcs,
            &oversized_dictionary_count,
            "exceeding the configuration-derived maximum",
            "an oversized dictionary count",
        );

        let missing_dictionary_payload = canonical[..dictionary_start].to_vec();
        assert_wire_refused(
            &pcs,
            &missing_dictionary_payload,
            "truncated",
            "a dictionary count without its node payload",
        );

        let mut duplicate_dictionary_node = canonical.clone();
        let first_node = duplicate_dictionary_node
            [dictionary_start..dictionary_start + MERKLE_NODE_BYTE_LENGTH]
            .to_vec();
        duplicate_dictionary_node[dictionary_start + MERKLE_NODE_BYTE_LENGTH
            ..dictionary_start + 2 * MERKLE_NODE_BYTE_LENGTH]
            .copy_from_slice(&first_node);
        assert_wire_refused(
            &pcs,
            &duplicate_dictionary_node,
            "node 1 is duplicated",
            "a duplicate dictionary node",
        );

        let mut unused_dictionary_node = canonical.clone();
        let distinct_node =
            distinct_unused_dictionary_node(&canonical, dictionary_start, dictionary_count);
        unused_dictionary_node.splice(dictionary_end..dictionary_end, distinct_node);
        write_wire_u32(
            &mut unused_dictionary_node,
            dictionary_count_offset,
            u32::try_from(dictionary_count + 1)
                .expect("the small fixture dictionary count fits u32"),
        );
        assert_wire_refused(
            &pcs,
            &unused_dictionary_node,
            "unused trailing nodes",
            "an unused trailing dictionary node",
        );

        let mut first_use_violation = canonical.clone();
        write_wire_u32(&mut first_use_violation, first_reference_offset, 1);
        assert_wire_refused(
            &pcs,
            &first_use_violation,
            "first uses node 1, expected node 0",
            "an out-of-order first dictionary use",
        );

        let mut out_of_range_reference = canonical.clone();
        write_wire_u32(
            &mut out_of_range_reference,
            first_reference_offset,
            u32::try_from(dictionary_count).expect("the small dictionary count fits u32"),
        );
        assert_wire_refused(
            &pcs,
            &out_of_range_reference,
            "is outside",
            "an out-of-range dictionary reference",
        );

        let mut noncanonical_field_limb = canonical.clone();
        noncanonical_field_limb[dictionary_end..dictionary_end + core::mem::size_of::<u64>()]
            .copy_from_slice(&Goldilocks::ORDER_U64.to_le_bytes());
        assert_wire_refused(
            &pcs,
            &noncanonical_field_limb,
            "field limb 0 is not canonical",
            "a noncanonical field limb",
        );

        for section_end_offset in canonical_section_end_offsets(&pcs, &canonical)
            .into_iter()
            .filter(|section_end_offset| *section_end_offset < canonical.len())
        {
            assert_wire_refused(
                &pcs,
                &canonical[..section_end_offset],
                "truncated",
                &format!("a proof truncated at section boundary {section_end_offset}"),
            );
        }

        let mut truncated = canonical.clone();
        truncated.pop();
        assert_wire_refused(&pcs, &truncated, "truncated", "a truncated proof");

        let mut trailing_data = canonical;
        trailing_data.push(0);
        assert_wire_refused(
            &pcs,
            &trailing_data,
            "1 trailing bytes",
            "a proof with trailing data",
        );
    }
}
