//! Canonical allocation-bounded wire for the aggregate-wide hiding opening.
//!
//! Query coordinates come only from Fiat-Shamir. Every authenticated batch
//! carries its opened rows followed by one coordinate-derived minimal Merkle
//! frontier; individual paths and coordinates are never serialized.

#[cfg(test)]
use core::ops::Range;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_sumcheck::{OpeningBatch, zk::ZkSumcheckData};
use p3_symmetric::MerkleCap;
use p3_whir::{BaseCaseZkProof, BlindedMask, MaskOpeningPair, QueryOpening};

use super::aggregate_wide_hiding::{AggregateWideOpeningProof, AggregateWidePadLayout};
use super::aggregate_wide_pcs::AggregateWideCommitment;
use super::coordinate_derived_hiding_mmcs::{
    CoordinateDerivedLeafSaltProof, TransportedPrivateLeafSalt,
};
use super::hiding_whir::SelectedHidingWhirConfig;
use super::private_leaf_salt::AcceptedPrivateLeafSaltSet;
#[cfg(test)]
use super::private_leaf_salt::PRIVATE_LEAF_SALT_BYTE_LENGTH;
use super::{
    ChallengeField, MERKLE_DIGEST_WORD_LENGTH,
    compact_merkle_frontier::{
        compact_frontier_from_query_paths, compact_frontier_node_count,
        reconstruct_query_paths_from_compact_frontier,
    },
};
use crate::bgv::proof_suite::{CommonProofByteSink, MAXIMUM_COMMON_PROOF_BYTE_LENGTH};

const WIRE_MAGIC: &[u8; 8] = b"SLAWIR01";
const CHALLENGE_FIELD_LIMB_COUNT: usize = 5;
const ENCODER_CHUNK_BYTE_LENGTH: usize = 4_096;

type MerkleNode = [u64; MERKLE_DIGEST_WORD_LENGTH];
type AggregateQueryOpening =
    QueryOpening<ChallengeField, ChallengeField, CoordinateDerivedLeafSaltProof>;
type AggregateBaseCase = BaseCaseZkProof<ChallengeField, ChallengeField, super::CommitmentScheme>;

pub(super) struct CompactAggregateWideQueryBatch {
    rows: Vec<Vec<ChallengeField>>,
    private_leaf_salts: Vec<TransportedPrivateLeafSalt>,
    frontier: Vec<MerkleNode>,
    leaf_count: usize,
    row_width: usize,
    variant: QueryVariant,
}

impl CompactAggregateWideQueryBatch {
    pub(super) fn materialize(
        &self,
        query_indices: &[usize],
        expected_commitment: &AggregateWideCommitment,
    ) -> Result<Vec<AggregateQueryOpening>, String> {
        if self.rows.len() != query_indices.len()
            || self.private_leaf_salts.len() != query_indices.len()
            || self.rows.iter().any(|row| row.len() != self.row_width)
        {
            return Err("aggregate-wide compact query batch has the wrong shape".to_owned());
        }
        let expected_frontier_count = compact_frontier_node_count(self.leaf_count, query_indices)?;
        if self.frontier.len() != expected_frontier_count {
            return Err(format!(
                "aggregate-wide frontier has {} nodes, expected {expected_frontier_count}",
                self.frontier.len()
            ));
        }
        let row_slices = self.rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let paths = reconstruct_query_paths_from_compact_frontier(
            self.leaf_count,
            query_indices,
            &row_slices,
            Some(&self.private_leaf_salts),
            &self.frontier,
            Some(commitment_root(expected_commitment)?),
        )?;
        Ok(self
            .rows
            .iter()
            .cloned()
            .zip(self.private_leaf_salts.iter().cloned())
            .zip(paths)
            .map(
                |((values, private_leaf_salt), siblings)| match self.variant {
                    QueryVariant::Base => QueryOpening::Base {
                        values,
                        proof: CoordinateDerivedLeafSaltProof {
                            private_leaf_salts: vec![private_leaf_salt],
                            siblings,
                        },
                    },
                    QueryVariant::Extension => QueryOpening::Extension {
                        values,
                        proof: CoordinateDerivedLeafSaltProof {
                            private_leaf_salts: vec![private_leaf_salt],
                            siblings,
                        },
                    },
                },
            )
            .collect())
    }

    pub(super) fn resident_byte_length(&self) -> usize {
        self.rows
            .iter()
            .map(|row| row.capacity() * core::mem::size_of::<ChallengeField>())
            .sum::<usize>()
            .saturating_add(self.rows.capacity() * core::mem::size_of::<Vec<ChallengeField>>())
            .saturating_add(
                self.private_leaf_salts.capacity()
                    * core::mem::size_of::<TransportedPrivateLeafSalt>(),
            )
            .saturating_add(self.frontier.capacity() * core::mem::size_of::<MerkleNode>())
    }
}

pub(super) struct CompactAggregateWideRoundProof {
    pub(super) commitment: AggregateWideCommitment,
    pub(super) switch_mask_delta: Vec<ChallengeField>,
    pub(super) proof_of_work_witness: ChallengeField,
    pub(super) queries: CompactAggregateWideQueryBatch,
}

pub(super) struct CompactAggregateWideBaseCase {
    pub(super) fresh_main_commitment: AggregateWideCommitment,
    pub(super) fresh_pad_commitment: AggregateWideCommitment,
    pub(super) masked_claim: ChallengeField,
    pub(super) blinded_message: Vec<ChallengeField>,
    pub(super) blinded_randomness: Vec<ChallengeField>,
    pub(super) blinded_pad_message: Vec<ChallengeField>,
    pub(super) blinded_pad_randomness: Vec<ChallengeField>,
    pub(super) proof_of_work_witness: ChallengeField,
    source_queries: CompactAggregateWideQueryBatch,
    fresh_main_queries: CompactAggregateWideQueryBatch,
    carried_pad_queries: CompactAggregateWideQueryBatch,
    fresh_pad_queries: CompactAggregateWideQueryBatch,
}

impl CompactAggregateWideBaseCase {
    pub(super) fn materialize(
        &self,
        active_source_commitment: &AggregateWideCommitment,
        pad_commitment: &AggregateWideCommitment,
        source_query_indices: &[usize],
        pad_query_indices: &[usize],
    ) -> Result<AggregateBaseCase, String> {
        let source_queries = self
            .source_queries
            .materialize(source_query_indices, active_source_commitment)?;
        let fresh_main_queries = self
            .fresh_main_queries
            .materialize(source_query_indices, &self.fresh_main_commitment)?;
        let carried_queries = self
            .carried_pad_queries
            .materialize(pad_query_indices, pad_commitment)?;
        let fresh_queries = self
            .fresh_pad_queries
            .materialize(pad_query_indices, &self.fresh_pad_commitment)?;
        let mask_pairs = carried_queries
            .into_iter()
            .zip(fresh_queries)
            .map(|(carried, fresh)| MaskOpeningPair { carried, fresh })
            .collect();
        Ok(BaseCaseZkProof {
            fresh_main_commitment: self.fresh_main_commitment.clone(),
            fresh_mask_commitments: vec![self.fresh_pad_commitment.clone()],
            masked_claim: self.masked_claim,
            blinded_message: self.blinded_message.clone(),
            blinded_randomness: self.blinded_randomness.clone(),
            blinded_masks: vec![BlindedMask {
                message: self.blinded_pad_message.clone(),
                randomness: self.blinded_pad_randomness.clone(),
            }],
            pow_witness: self.proof_of_work_witness,
            source_queries,
            fresh_main_queries,
            mask_queries: vec![mask_pairs],
        })
    }

    fn resident_byte_length(&self) -> usize {
        [
            self.blinded_message.capacity(),
            self.blinded_randomness.capacity(),
            self.blinded_pad_message.capacity(),
            self.blinded_pad_randomness.capacity(),
        ]
        .into_iter()
        .sum::<usize>()
        .saturating_mul(core::mem::size_of::<ChallengeField>())
        .saturating_add(self.source_queries.resident_byte_length())
        .saturating_add(self.fresh_main_queries.resident_byte_length())
        .saturating_add(self.carried_pad_queries.resident_byte_length())
        .saturating_add(self.fresh_pad_queries.resident_byte_length())
    }
}

pub(super) struct CompactAggregateWideOpeningProof {
    pub(super) evaluations: Vec<OpeningBatch<ChallengeField>>,
    pub(super) sumchecks: Vec<ZkSumcheckData<ChallengeField, ChallengeField>>,
    pub(super) rounds: Vec<CompactAggregateWideRoundProof>,
    pub(super) base_case: CompactAggregateWideBaseCase,
}

impl CompactAggregateWideOpeningProof {
    pub(super) fn resident_byte_length(&self) -> usize {
        let evaluation_bytes = self
            .evaluations
            .iter()
            .map(|batch| {
                (batch.current().len() + batch.next().len())
                    * core::mem::size_of::<ChallengeField>()
            })
            .sum::<usize>();
        let round_bytes = self
            .rounds
            .iter()
            .map(|round| {
                round.switch_mask_delta.capacity() * core::mem::size_of::<ChallengeField>()
                    + round.queries.resident_byte_length()
            })
            .sum::<usize>();
        evaluation_bytes
            .saturating_add(round_bytes)
            .saturating_add(self.base_case.resident_byte_length())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AggregateWideWireEncodingProgress {
    Pending,
    Complete { canonical_byte_length: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AggregateWideWireSinkEncodingError<SinkError> {
    Sink(SinkError),
}

/// Retry-safe bounded sink encoder. A failed sink write leaves the byte cursor
/// unchanged, so browser storage can resume the same canonical chunk.
pub(super) struct AggregateWideWireSinkEncoder {
    canonical: Vec<u8>,
    next_byte_offset: usize,
}

impl AggregateWideWireSinkEncoder {
    pub(super) fn new(
        configuration: &SelectedHidingWhirConfig,
        proof: &AggregateWideOpeningProof,
        expected_opening_widths: &[usize],
        table_width: usize,
        prior_private_leaf_salts: AcceptedPrivateLeafSaltSet,
    ) -> Result<Self, String> {
        Ok(Self {
            canonical: encode_aggregate_wide_opening(
                configuration,
                proof,
                expected_opening_widths,
                table_width,
                prior_private_leaf_salts,
            )?,
            next_byte_offset: 0,
        })
    }

    pub(super) fn canonical_byte_length(&self) -> usize {
        self.canonical.len()
    }

    pub(super) fn write_next<Sink: CommonProofByteSink>(
        &mut self,
        sink: &mut Sink,
    ) -> Result<AggregateWideWireEncodingProgress, AggregateWideWireSinkEncodingError<Sink::Error>>
    {
        if self.next_byte_offset == self.canonical.len() {
            return Ok(AggregateWideWireEncodingProgress::Complete {
                canonical_byte_length: self.canonical.len(),
            });
        }
        let following_offset = self
            .next_byte_offset
            .saturating_add(ENCODER_CHUNK_BYTE_LENGTH)
            .min(self.canonical.len());
        sink.write_bytes(&self.canonical[self.next_byte_offset..following_offset])
            .map_err(AggregateWideWireSinkEncodingError::Sink)?;
        self.next_byte_offset = following_offset;
        if self.next_byte_offset == self.canonical.len() {
            Ok(AggregateWideWireEncodingProgress::Complete {
                canonical_byte_length: self.canonical.len(),
            })
        } else {
            Ok(AggregateWideWireEncodingProgress::Pending)
        }
    }
}

pub(super) fn encode_aggregate_wide_opening(
    configuration: &SelectedHidingWhirConfig,
    proof: &AggregateWideOpeningProof,
    expected_opening_widths: &[usize],
    table_width: usize,
    prior_private_leaf_salts: AcceptedPrivateLeafSaltSet,
) -> Result<Vec<u8>, String> {
    validate_top_level_shape(configuration, proof, expected_opening_widths, table_width)?;
    let pad_layout = AggregateWidePadLayout::derive(configuration)?;
    let query_schedule = proof.query_index_schedule();
    let mut writer = CanonicalWriter::with_prior_private_leaf_salts(prior_private_leaf_salts);
    writer.write_bytes(WIRE_MAGIC)?;
    writer.write_u32(checked_u32(configuration.num_variables, "variable count")?)?;
    writer.write_u32(checked_u32(expected_opening_widths.len(), "opening count")?)?;
    writer.write_u32(checked_u32(table_width, "table width")?)?;

    for (evaluations, expected_width) in proof.evaluations.iter().zip(expected_opening_widths) {
        if evaluations.current().len() != *expected_width || !evaluations.next().is_empty() {
            return Err("aggregate-wide evaluation batch has the wrong shape".to_owned());
        }
        writer.write_fields(evaluations.current())?;
    }
    encode_sumcheck(
        &mut writer,
        &proof.sumchecks[0],
        configuration.zk.ell_zk,
        configuration.round_folding_factor(0),
        configuration.starting_folding_pow_bits,
    )?;

    for (round_ordinal, round) in proof.rounds.iter().enumerate() {
        let round_configuration = &configuration.round_parameters[round_ordinal];
        writer.write_commitment(&round.commitment)?;
        let switch_mask_range = pad_layout.switch_mask_range(round_ordinal)?;
        if round.switch_mask_delta.len() != switch_mask_range.len() {
            return Err("aggregate-wide switch-mask delta has the wrong length".to_owned());
        }
        writer.write_fields(&round.switch_mask_delta)?;
        encode_optional_witness(
            &mut writer,
            round_configuration.pow_bits,
            round.proof_of_work_witness,
            "round proof of work",
        )?;
        let folding_factor = configuration.round_folding_factor(round_ordinal);
        encode_query_batch(
            &mut writer,
            &round.queries,
            &query_schedule[round_ordinal],
            round_configuration.domain_size >> folding_factor,
            1 << folding_factor,
            if round_ordinal == 0 {
                QueryVariant::Base
            } else {
                QueryVariant::Extension
            },
        )?;
        encode_sumcheck(
            &mut writer,
            &proof.sumchecks[round_ordinal + 1],
            configuration.zk.ell_zk,
            configuration.round_folding_factor(round_ordinal + 1),
            round_configuration.folding_pow_bits,
        )?;
    }

    encode_base_case(
        &mut writer,
        configuration,
        &pad_layout,
        &proof.base_case,
        &query_schedule[configuration.n_rounds()],
        &query_schedule[configuration.n_rounds() + 1],
    )?;
    writer.finish()
}

/// Decodes the coordinate-free wire without accepting query coordinates from
/// the producer. The semantic verifier materializes each batch only after the
/// live Fiat-Shamir challenger derives that epoch's coordinates.
pub(super) fn decode_compact_aggregate_wide_opening(
    configuration: &SelectedHidingWhirConfig,
    canonical: &[u8],
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<CompactAggregateWideOpeningProof, String> {
    decode_compact_aggregate_wide_opening_with_prior_private_leaf_salts(
        configuration,
        canonical,
        expected_opening_widths,
        table_width,
        AcceptedPrivateLeafSaltSet::default(),
    )
}

pub(super) fn decode_compact_aggregate_wide_opening_with_prior_private_leaf_salts(
    configuration: &SelectedHidingWhirConfig,
    canonical: &[u8],
    expected_opening_widths: &[usize],
    table_width: usize,
    prior_private_leaf_salts: AcceptedPrivateLeafSaltSet,
) -> Result<CompactAggregateWideOpeningProof, String> {
    if canonical.is_empty() || canonical.len() > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err("aggregate-wide canonical byte length is outside the proof bound".to_owned());
    }
    if table_width == 0
        || expected_opening_widths.is_empty()
        || expected_opening_widths
            .iter()
            .any(|width| *width == 0 || *width > table_width)
    {
        return Err("aggregate-wide verifier opening geometry is invalid".to_owned());
    }
    let pad_layout = AggregateWidePadLayout::derive(configuration)?;
    let mut reader =
        CanonicalReader::with_prior_private_leaf_salts(canonical, prior_private_leaf_salts);
    if reader.read_array::<8>()? != *WIRE_MAGIC {
        return Err("aggregate-wide wire magic is not canonical".to_owned());
    }
    if reader.read_u32_as_usize()? != configuration.num_variables
        || reader.read_u32_as_usize()? != expected_opening_widths.len()
        || reader.read_u32_as_usize()? != table_width
    {
        return Err("aggregate-wide wire header disagrees with verifier geometry".to_owned());
    }

    let evaluations = expected_opening_widths
        .iter()
        .map(|width| Ok(OpeningBatch::new(reader.read_fields(*width)?, Vec::new())))
        .collect::<Result<Vec<_>, String>>()?;
    let mut sumchecks = Vec::with_capacity(configuration.n_rounds() + 1);
    sumchecks.push(decode_sumcheck(
        &mut reader,
        configuration.zk.ell_zk,
        configuration.round_folding_factor(0),
        configuration.starting_folding_pow_bits,
    )?);

    let mut rounds = Vec::with_capacity(configuration.n_rounds());
    for round_ordinal in 0..configuration.n_rounds() {
        let round_configuration = &configuration.round_parameters[round_ordinal];
        let commitment = reader.read_commitment()?;
        let switch_mask_range = pad_layout.switch_mask_range(round_ordinal)?;
        let switch_mask_delta = reader.read_fields(switch_mask_range.len())?;
        let proof_of_work_witness =
            decode_optional_witness(&mut reader, round_configuration.pow_bits)?;
        let folding_factor = configuration.round_folding_factor(round_ordinal);
        let queries = decode_compact_query_batch(
            &mut reader,
            round_configuration.num_queries,
            round_configuration.domain_size >> folding_factor,
            1 << folding_factor,
            if round_ordinal == 0 {
                QueryVariant::Base
            } else {
                QueryVariant::Extension
            },
        )?;
        sumchecks.push(decode_sumcheck(
            &mut reader,
            configuration.zk.ell_zk,
            configuration.round_folding_factor(round_ordinal + 1),
            round_configuration.folding_pow_bits,
        )?);
        rounds.push(CompactAggregateWideRoundProof {
            commitment,
            switch_mask_delta,
            proof_of_work_witness,
            queries,
        });
    }

    let base_case = decode_compact_base_case(&mut reader, configuration, &pad_layout)?;
    reader.finish()?;
    Ok(CompactAggregateWideOpeningProof {
        evaluations,
        sumchecks,
        rounds,
        base_case,
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AggregateWideHostileMutationTargetKind {
    Count,
    Field,
    Frontier,
    Root,
    Salt,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateWideHostileMutationTarget {
    pub(super) label: String,
    pub(super) byte_range: Range<usize>,
    pub(super) kind: AggregateWideHostileMutationTargetKind,
}

#[cfg(test)]
struct AggregateWideMutationScanner<'a> {
    canonical: &'a [u8],
    offset: usize,
    targets: Vec<AggregateWideHostileMutationTarget>,
}

#[cfg(test)]
impl<'a> AggregateWideMutationScanner<'a> {
    const fn new(canonical: &'a [u8]) -> Self {
        Self {
            canonical,
            offset: 0,
            targets: Vec::new(),
        }
    }

    fn take_bytes(&mut self, byte_length: usize, label: &str) -> Result<Range<usize>, String> {
        let following_offset = self
            .offset
            .checked_add(byte_length)
            .filter(|following_offset| *following_offset <= self.canonical.len())
            .ok_or_else(|| format!("aggregate-wide mutation scan truncated at {label}"))?;
        let byte_range = self.offset..following_offset;
        self.offset = following_offset;
        Ok(byte_range)
    }

    fn record_bytes(
        &mut self,
        byte_length: usize,
        label: impl Into<String>,
        kind: AggregateWideHostileMutationTargetKind,
    ) -> Result<Range<usize>, String> {
        let label = label.into();
        let byte_range = self.take_bytes(byte_length, &label)?;
        if byte_range.is_empty() {
            return Err(format!("aggregate-wide mutation target {label} is empty"));
        }
        self.targets.push(AggregateWideHostileMutationTarget {
            label,
            byte_range: byte_range.clone(),
            kind,
        });
        Ok(byte_range)
    }

    fn take_field_vector(
        &mut self,
        field_count: usize,
        label: &str,
        record: bool,
    ) -> Result<Range<usize>, String> {
        let byte_length = field_count
            .checked_mul(CHALLENGE_FIELD_LIMB_COUNT)
            .and_then(|limb_count| limb_count.checked_mul(core::mem::size_of::<u64>()))
            .ok_or_else(|| format!("aggregate-wide mutation field length overflowed at {label}"))?;
        if record {
            self.record_bytes(
                byte_length,
                label,
                AggregateWideHostileMutationTargetKind::Field,
            )
        } else {
            self.take_bytes(byte_length, label)
        }
    }

    fn read_count(&mut self, label: impl Into<String>) -> Result<usize, String> {
        let label = label.into();
        let byte_range = self.record_bytes(
            core::mem::size_of::<u32>(),
            label,
            AggregateWideHostileMutationTargetKind::Count,
        )?;
        Ok(u32::from_le_bytes(
            self.canonical[byte_range]
                .try_into()
                .map_err(|_| "aggregate-wide mutation count has the wrong width".to_owned())?,
        ) as usize)
    }

    fn scan_sumcheck(
        &mut self,
        label: impl Into<String>,
        ell_zk: usize,
        round_count: usize,
        proof_of_work_bits: usize,
    ) -> Result<(), String> {
        let wire_length = ell_zk
            .checked_sub(1)
            .ok_or_else(|| "aggregate-wide mutation sumcheck mask length is zero".to_owned())?;
        let per_round_field_count = wire_length
            .checked_add(usize::from(proof_of_work_bits > 0))
            .ok_or_else(|| "aggregate-wide mutation sumcheck width overflowed".to_owned())?;
        let field_count = round_count
            .checked_mul(per_round_field_count)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| "aggregate-wide mutation sumcheck length overflowed".to_owned())?;
        self.take_field_vector(field_count, &label.into(), true)?;
        Ok(())
    }

    fn scan_query_batch(
        &mut self,
        label: &str,
        query_count: usize,
        leaf_count: usize,
        row_width: usize,
    ) -> Result<(), String> {
        if query_count == 0
            || leaf_count == 0
            || !leaf_count.is_power_of_two()
            || query_count > leaf_count
            || row_width == 0
        {
            return Err(format!(
                "aggregate-wide mutation query geometry is invalid at {label}"
            ));
        }
        for query_ordinal in 0..query_count {
            let salt_label = format!("{label} opening {query_ordinal} private leaf salt");
            if query_ordinal == 0 || query_ordinal + 1 == query_count {
                self.record_bytes(
                    super::private_leaf_salt::PRIVATE_LEAF_SALT_BYTE_LENGTH,
                    salt_label,
                    AggregateWideHostileMutationTargetKind::Salt,
                )?;
            } else {
                self.take_bytes(
                    super::private_leaf_salt::PRIVATE_LEAF_SALT_BYTE_LENGTH,
                    &salt_label,
                )?;
            }
            self.take_field_vector(
                row_width,
                &format!("{label} opening {query_ordinal} values"),
                query_ordinal == 0 || query_ordinal + 1 == query_count,
            )?;
        }
        let frontier_count = self.read_count(format!("{label} frontier count"))?;
        let maximum_frontier_count = query_count
            .checked_mul(leaf_count.ilog2() as usize)
            .ok_or_else(|| {
                format!("aggregate-wide mutation frontier bound overflowed at {label}")
            })?;
        if frontier_count > maximum_frontier_count {
            return Err(format!(
                "aggregate-wide mutation frontier at {label} exceeds its checked maximum"
            ));
        }
        if frontier_count == 0 {
            return Err(format!(
                "aggregate-wide mutation frontier at {label} is unexpectedly empty"
            ));
        }
        self.record_bytes(
            frontier_count
                .checked_mul(core::mem::size_of::<MerkleNode>())
                .ok_or_else(|| {
                    format!("aggregate-wide mutation frontier length overflowed at {label}")
                })?,
            format!("{label} compact frontier"),
            AggregateWideHostileMutationTargetKind::Frontier,
        )?;
        Ok(())
    }

    fn finish(self) -> Result<Vec<AggregateWideHostileMutationTarget>, String> {
        if self.offset != self.canonical.len() {
            return Err(format!(
                "aggregate-wide mutation scan left {} trailing bytes",
                self.canonical.len() - self.offset
            ));
        }
        Ok(self.targets)
    }
}

/// Locates hostile-test mutations by replaying the selected production wire
/// geometry. The proof never supplies query coordinates or section widths.
#[cfg(test)]
pub(super) fn aggregate_wide_hostile_mutation_targets(
    configuration: &SelectedHidingWhirConfig,
    canonical: &[u8],
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<Vec<AggregateWideHostileMutationTarget>, String> {
    if canonical.is_empty()
        || table_width == 0
        || expected_opening_widths.is_empty()
        || expected_opening_widths
            .iter()
            .any(|width| *width == 0 || *width > table_width)
    {
        return Err("aggregate-wide mutation scan has invalid verifier geometry".to_owned());
    }
    let pad_layout = AggregateWidePadLayout::derive(configuration)?;
    let mut scanner = AggregateWideMutationScanner::new(canonical);
    let wire_magic = scanner.take_bytes(WIRE_MAGIC.len(), "wire magic")?;
    if canonical[wire_magic] != *WIRE_MAGIC {
        return Err("aggregate-wide mutation scan found the wrong wire magic".to_owned());
    }
    let variable_count = scanner.read_count("aggregate-wide variable count")?;
    let opening_count = scanner.read_count("aggregate-wide opening count")?;
    let encoded_table_width = scanner.read_count("aggregate-wide table width")?;
    if variable_count != configuration.num_variables
        || opening_count != expected_opening_widths.len()
        || encoded_table_width != table_width
    {
        return Err("aggregate-wide mutation scan found the wrong header geometry".to_owned());
    }

    for (opening_ordinal, opening_width) in expected_opening_widths.iter().enumerate() {
        let record = opening_ordinal == 0 || opening_ordinal + 1 == expected_opening_widths.len();
        scanner.take_field_vector(
            *opening_width,
            &if opening_ordinal + 1 == expected_opening_widths.len() {
                "terminal non-Boolean opening evaluation".to_owned()
            } else {
                format!("aggregate opening evaluation {opening_ordinal}")
            },
            record,
        )?;
    }
    scanner.scan_sumcheck(
        "initial WHIR sumcheck",
        configuration.zk.ell_zk,
        configuration.round_folding_factor(0),
        configuration.starting_folding_pow_bits,
    )?;

    for (round_ordinal, round_configuration) in configuration.round_parameters.iter().enumerate() {
        scanner.record_bytes(
            core::mem::size_of::<MerkleNode>(),
            format!("WHIR round {round_ordinal} root"),
            AggregateWideHostileMutationTargetKind::Root,
        )?;
        scanner.take_field_vector(
            pad_layout.switch_mask_range(round_ordinal)?.len(),
            &format!("WHIR round {round_ordinal} switch-mask delta"),
            true,
        )?;
        if round_configuration.pow_bits > 0 {
            scanner.take_field_vector(
                1,
                &format!("WHIR round {round_ordinal} proof-of-work witness"),
                true,
            )?;
        }
        let folding_factor = configuration.round_folding_factor(round_ordinal);
        scanner.scan_query_batch(
            &format!("WHIR round {round_ordinal}"),
            round_configuration.num_queries,
            round_configuration.domain_size >> folding_factor,
            1 << folding_factor,
        )?;
        scanner.scan_sumcheck(
            format!("WHIR round {round_ordinal} follow-up sumcheck"),
            configuration.zk.ell_zk,
            configuration.round_folding_factor(round_ordinal + 1),
            round_configuration.folding_pow_bits,
        )?;
    }

    scanner.record_bytes(
        core::mem::size_of::<MerkleNode>(),
        "WHIR fresh-main root",
        AggregateWideHostileMutationTargetKind::Root,
    )?;
    scanner.record_bytes(
        core::mem::size_of::<MerkleNode>(),
        "WHIR fresh-pad root",
        AggregateWideHostileMutationTargetKind::Root,
    )?;
    scanner.take_field_vector(1, "WHIR terminal masked claim", true)?;
    let final_configuration = configuration.final_round_config();
    scanner.take_field_vector(
        1 << final_configuration.num_variables,
        "WHIR blinded terminal message",
        true,
    )?;
    scanner.take_field_vector(
        configuration.oracle_randomness[configuration.n_rounds()],
        "WHIR blinded terminal randomness",
        true,
    )?;
    scanner.take_field_vector(
        pad_layout.message_length(),
        "WHIR blinded pad message",
        true,
    )?;
    scanner.take_field_vector(
        configuration.mask_queries,
        "WHIR blinded pad randomness",
        true,
    )?;
    if configuration.final_pow_bits > 0 {
        scanner.take_field_vector(1, "WHIR terminal proof-of-work witness", true)?;
    }

    let source_leaf_count = final_configuration.domain_size >> final_configuration.folding_factor;
    scanner.scan_query_batch(
        "WHIR terminal source",
        configuration.final_queries,
        source_leaf_count,
        1 << final_configuration.folding_factor,
    )?;
    scanner.scan_query_batch(
        "WHIR terminal fresh-main",
        configuration.final_queries,
        source_leaf_count,
        1,
    )?;
    let pad_leaf_count = pad_codeword_domain_size(configuration, &pad_layout);
    scanner.scan_query_batch(
        "WHIR terminal carried-pad",
        configuration.mask_queries,
        pad_leaf_count,
        1,
    )?;
    scanner.scan_query_batch(
        "WHIR terminal fresh-pad",
        configuration.mask_queries,
        pad_leaf_count,
        1,
    )?;
    scanner.finish()
}

fn validate_top_level_shape(
    configuration: &SelectedHidingWhirConfig,
    proof: &AggregateWideOpeningProof,
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<(), String> {
    if table_width == 0
        || expected_opening_widths.is_empty()
        || expected_opening_widths
            .iter()
            .any(|width| *width == 0 || *width > table_width)
        || proof.evaluations.len() != expected_opening_widths.len()
        || proof.rounds.len() != configuration.n_rounds()
        || proof.sumchecks.len() != configuration.n_rounds() + 1
        || proof.query_index_schedule().len() != configuration.n_rounds() + 2
    {
        return Err("aggregate-wide proof has the wrong top-level shape".to_owned());
    }
    for (round_ordinal, indices) in proof
        .query_index_schedule()
        .iter()
        .take(configuration.n_rounds())
        .enumerate()
    {
        let round = &configuration.round_parameters[round_ordinal];
        if indices.len() != round.num_queries {
            return Err(format!(
                "aggregate-wide round {round_ordinal} has {} query indices, expected {}",
                indices.len(),
                round.num_queries
            ));
        }
    }
    if proof.query_index_schedule()[configuration.n_rounds()].len() != configuration.final_queries
        || proof.query_index_schedule()[configuration.n_rounds() + 1].len()
            != configuration.mask_queries
    {
        return Err("aggregate-wide base query schedule has the wrong shape".to_owned());
    }
    Ok(())
}

fn encode_sumcheck(
    writer: &mut CanonicalWriter,
    sumcheck: &ZkSumcheckData<ChallengeField, ChallengeField>,
    ell_zk: usize,
    round_count: usize,
    proof_of_work_bits: usize,
) -> Result<(), String> {
    let expected_wire_length = ell_zk
        .checked_sub(1)
        .ok_or_else(|| "aggregate-wide sumcheck mask length is zero".to_owned())?;
    let expected_witness_count = if proof_of_work_bits == 0 {
        0
    } else {
        round_count
    };
    if sumcheck.ell_zk != ell_zk
        || sumcheck.round_coefficients.len() != round_count
        || sumcheck
            .round_coefficients
            .iter()
            .any(|wire| wire.len() != expected_wire_length)
        || sumcheck.pow_witnesses.len() != expected_witness_count
    {
        return Err("aggregate-wide sumcheck has a noncanonical shape".to_owned());
    }
    writer.write_field(sumcheck.mu_tilde)?;
    for (round_ordinal, wire) in sumcheck.round_coefficients.iter().enumerate() {
        writer.write_fields(wire)?;
        if proof_of_work_bits > 0 {
            writer.write_field(sumcheck.pow_witnesses[round_ordinal])?;
        }
    }
    Ok(())
}

fn decode_sumcheck(
    reader: &mut CanonicalReader<'_>,
    ell_zk: usize,
    round_count: usize,
    proof_of_work_bits: usize,
) -> Result<ZkSumcheckData<ChallengeField, ChallengeField>, String> {
    let wire_length = ell_zk
        .checked_sub(1)
        .ok_or_else(|| "aggregate-wide sumcheck mask length is zero".to_owned())?;
    let mu_tilde = reader.read_field()?;
    let mut round_coefficients = Vec::with_capacity(round_count);
    let mut pow_witnesses = Vec::with_capacity(if proof_of_work_bits == 0 {
        0
    } else {
        round_count
    });
    for _ in 0..round_count {
        round_coefficients.push(reader.read_fields(wire_length)?);
        if proof_of_work_bits > 0 {
            pow_witnesses.push(reader.read_field()?);
        }
    }
    Ok(ZkSumcheckData {
        mu_tilde,
        ell_zk,
        round_coefficients,
        pow_witnesses,
    })
}

#[derive(Clone, Copy)]
enum QueryVariant {
    Base,
    Extension,
}

fn query_parts(
    opening: &AggregateQueryOpening,
    expected_variant: QueryVariant,
) -> Result<
    (
        &[ChallengeField],
        &TransportedPrivateLeafSalt,
        &[MerkleNode],
    ),
    String,
> {
    match (expected_variant, opening) {
        (QueryVariant::Base, QueryOpening::Base { values, proof })
        | (QueryVariant::Extension, QueryOpening::Extension { values, proof }) => {
            let private_leaf_salt = proof
                .private_leaf_salts
                .as_slice()
                .first()
                .filter(|_| proof.private_leaf_salts.len() == 1)
                .ok_or_else(|| {
                    "aggregate-wide query opening has the wrong private leaf-salt count".to_owned()
                })?;
            Ok((values, private_leaf_salt, &proof.siblings))
        }
        _ => Err("aggregate-wide query opening has the wrong field variant".to_owned()),
    }
}

fn encode_query_batch(
    writer: &mut CanonicalWriter,
    queries: &[AggregateQueryOpening],
    query_indices: &[usize],
    leaf_count: usize,
    row_width: usize,
    expected_variant: QueryVariant,
) -> Result<(), String> {
    if queries.len() != query_indices.len() {
        return Err("aggregate-wide query batch has the wrong opening count".to_owned());
    }
    let mut paths = Vec::with_capacity(queries.len());
    for query in queries {
        let (values, private_leaf_salt, path) = query_parts(query, expected_variant)?;
        if values.len() != row_width {
            return Err("aggregate-wide query row has the wrong width".to_owned());
        }
        writer.write_private_leaf_salt(private_leaf_salt)?;
        writer.write_fields(values)?;
        paths.push(path);
    }
    let frontier = compact_frontier_from_query_paths(leaf_count, query_indices, &paths)?;
    writer.write_u32(checked_u32(frontier.len(), "frontier node count")?)?;
    for node in &frontier {
        writer.write_merkle_node(node)?;
    }
    Ok(())
}

fn decode_compact_query_batch(
    reader: &mut CanonicalReader<'_>,
    query_count: usize,
    leaf_count: usize,
    row_width: usize,
    variant: QueryVariant,
) -> Result<CompactAggregateWideQueryBatch, String> {
    if query_count == 0
        || leaf_count == 0
        || !leaf_count.is_power_of_two()
        || query_count > leaf_count
        || row_width == 0
    {
        return Err("aggregate-wide compact query geometry is invalid".to_owned());
    }
    let mut rows = Vec::with_capacity(query_count);
    let mut private_leaf_salts = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        private_leaf_salts.push(reader.read_private_leaf_salt()?);
        rows.push(reader.read_fields(row_width)?);
    }
    let frontier_count = reader.read_u32_as_usize()?;
    let maximum_frontier_count = query_count
        .checked_mul(leaf_count.ilog2() as usize)
        .ok_or_else(|| "aggregate-wide compact frontier bound overflowed".to_owned())?;
    if frontier_count > maximum_frontier_count {
        return Err(format!(
            "aggregate-wide compact frontier has {frontier_count} nodes, exceeding {maximum_frontier_count}"
        ));
    }
    let frontier = (0..frontier_count)
        .map(|_| reader.read_merkle_node())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompactAggregateWideQueryBatch {
        rows,
        private_leaf_salts,
        frontier,
        leaf_count,
        row_width,
        variant,
    })
}

fn encode_base_case(
    writer: &mut CanonicalWriter,
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
    base_case: &AggregateBaseCase,
    source_query_indices: &[usize],
    pad_query_indices: &[usize],
) -> Result<(), String> {
    if base_case.fresh_mask_commitments.len() != 1
        || base_case.blinded_masks.len() != 1
        || base_case.mask_queries.len() != 1
    {
        return Err("aggregate-wide base case must carry exactly one pad group".to_owned());
    }
    writer.write_commitment(&base_case.fresh_main_commitment)?;
    writer.write_commitment(&base_case.fresh_mask_commitments[0])?;
    writer.write_field(base_case.masked_claim)?;
    let final_configuration = configuration.final_round_config();
    let expected_source_message_length = 1 << final_configuration.num_variables;
    let expected_source_randomness_length =
        configuration.oracle_randomness[configuration.n_rounds()];
    if base_case.blinded_message.len() != expected_source_message_length
        || base_case.blinded_randomness.len() != expected_source_randomness_length
        || base_case.blinded_masks[0].message.len() != pad_layout.message_length()
        || base_case.blinded_masks[0].randomness.len() != configuration.mask_queries
    {
        return Err("aggregate-wide base reveals have the wrong shape".to_owned());
    }
    writer.write_fields(&base_case.blinded_message)?;
    writer.write_fields(&base_case.blinded_randomness)?;
    writer.write_fields(&base_case.blinded_masks[0].message)?;
    writer.write_fields(&base_case.blinded_masks[0].randomness)?;
    encode_optional_witness(
        writer,
        configuration.final_pow_bits,
        base_case.pow_witness,
        "base proof of work",
    )?;

    let source_leaf_count = final_configuration.domain_size >> final_configuration.folding_factor;
    let source_row_width = 1 << final_configuration.folding_factor;
    encode_query_batch(
        writer,
        &base_case.source_queries,
        source_query_indices,
        source_leaf_count,
        source_row_width,
        QueryVariant::Extension,
    )?;
    encode_query_batch(
        writer,
        &base_case.fresh_main_queries,
        source_query_indices,
        source_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    let pairs = &base_case.mask_queries[0];
    if pairs.len() != pad_query_indices.len() {
        return Err("aggregate-wide pad opening count is not canonical".to_owned());
    }
    let carried = pairs
        .iter()
        .map(|pair| pair.carried.clone())
        .collect::<Vec<_>>();
    let fresh = pairs
        .iter()
        .map(|pair| pair.fresh.clone())
        .collect::<Vec<_>>();
    let pad_leaf_count = pad_codeword_domain_size(configuration, pad_layout);
    encode_query_batch(
        writer,
        &carried,
        pad_query_indices,
        pad_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    encode_query_batch(
        writer,
        &fresh,
        pad_query_indices,
        pad_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    Ok(())
}

fn decode_compact_base_case(
    reader: &mut CanonicalReader<'_>,
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
) -> Result<CompactAggregateWideBaseCase, String> {
    let fresh_main_commitment = reader.read_commitment()?;
    let fresh_pad_commitment = reader.read_commitment()?;
    let masked_claim = reader.read_field()?;
    let final_configuration = configuration.final_round_config();
    let blinded_message = reader.read_fields(1 << final_configuration.num_variables)?;
    let blinded_randomness =
        reader.read_fields(configuration.oracle_randomness[configuration.n_rounds()])?;
    let blinded_pad_message = reader.read_fields(pad_layout.message_length())?;
    let blinded_pad_randomness = reader.read_fields(configuration.mask_queries)?;
    let proof_of_work_witness = decode_optional_witness(reader, configuration.final_pow_bits)?;

    let source_leaf_count = final_configuration.domain_size >> final_configuration.folding_factor;
    let source_row_width = 1 << final_configuration.folding_factor;
    let source_queries = decode_compact_query_batch(
        reader,
        configuration.final_queries,
        source_leaf_count,
        source_row_width,
        QueryVariant::Extension,
    )?;
    let fresh_main_queries = decode_compact_query_batch(
        reader,
        configuration.final_queries,
        source_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    let pad_leaf_count = pad_codeword_domain_size(configuration, pad_layout);
    let carried_pad_queries = decode_compact_query_batch(
        reader,
        configuration.mask_queries,
        pad_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    let fresh_pad_queries = decode_compact_query_batch(
        reader,
        configuration.mask_queries,
        pad_leaf_count,
        1,
        QueryVariant::Extension,
    )?;
    Ok(CompactAggregateWideBaseCase {
        fresh_main_commitment,
        fresh_pad_commitment,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_pad_message,
        blinded_pad_randomness,
        proof_of_work_witness,
        source_queries,
        fresh_main_queries,
        carried_pad_queries,
        fresh_pad_queries,
    })
}

fn pad_codeword_domain_size(
    configuration: &SelectedHidingWhirConfig,
    pad_layout: &AggregateWidePadLayout,
) -> usize {
    (pad_layout.message_length() + configuration.mask_queries).next_power_of_two()
        << super::aggregate_wide_hiding::AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE
}

fn encode_optional_witness(
    writer: &mut CanonicalWriter,
    proof_of_work_bits: usize,
    witness: ChallengeField,
    label: &str,
) -> Result<(), String> {
    if proof_of_work_bits == 0 {
        if witness != ChallengeField::ZERO {
            return Err(format!("aggregate-wide {label} is nonzero when disabled"));
        }
        Ok(())
    } else {
        writer.write_field(witness)
    }
}

fn decode_optional_witness(
    reader: &mut CanonicalReader<'_>,
    proof_of_work_bits: usize,
) -> Result<ChallengeField, String> {
    if proof_of_work_bits == 0 {
        Ok(ChallengeField::ZERO)
    } else {
        reader.read_field()
    }
}

fn commitment_root(commitment: &AggregateWideCommitment) -> Result<MerkleNode, String> {
    let roots = commitment.roots();
    if roots.len() != 1 {
        return Err(format!(
            "aggregate-wide commitment has {} roots, expected one",
            roots.len()
        ));
    }
    Ok(roots[0])
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("aggregate-wide {label} exceeds canonical u32"))
}

struct CanonicalWriter {
    bytes: Vec<u8>,
    private_leaf_salts: AcceptedPrivateLeafSaltSet,
}

impl CanonicalWriter {
    fn with_prior_private_leaf_salts(private_leaf_salts: AcceptedPrivateLeafSaltSet) -> Self {
        Self {
            bytes: Vec::new(),
            private_leaf_salts,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        let following_length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .ok_or_else(|| "aggregate-wide wire exceeds the common-proof bound".to_owned())?;
        self.bytes
            .try_reserve_exact(following_length - self.bytes.len())
            .map_err(|_| "aggregate-wide wire allocation failed".to_owned())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), String> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_field(&mut self, value: ChallengeField) -> Result<(), String> {
        let coefficients =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
        if coefficients.len() != CHALLENGE_FIELD_LIMB_COUNT {
            return Err("aggregate-wide challenge field has the wrong basis length".to_owned());
        }
        for coefficient in coefficients {
            self.write_bytes(&coefficient.as_canonical_u64().to_le_bytes())?;
        }
        Ok(())
    }

    fn write_fields(&mut self, values: &[ChallengeField]) -> Result<(), String> {
        for value in values {
            self.write_field(*value)?;
        }
        Ok(())
    }

    fn write_private_leaf_salt(&mut self, salt: &TransportedPrivateLeafSalt) -> Result<(), String> {
        self.private_leaf_salts.insert(salt.bytes())?;
        self.write_bytes(&salt.bytes())
    }

    fn write_merkle_node(&mut self, node: &MerkleNode) -> Result<(), String> {
        for word in node {
            self.write_bytes(&word.to_le_bytes())?;
        }
        Ok(())
    }

    fn write_commitment(&mut self, commitment: &AggregateWideCommitment) -> Result<(), String> {
        self.write_merkle_node(&commitment_root(commitment)?)
    }

    fn finish(self) -> Result<Vec<u8>, String> {
        if self.bytes.is_empty() {
            Err("aggregate-wide encoder produced an empty wire".to_owned())
        } else {
            Ok(self.bytes)
        }
    }
}

struct CanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    private_leaf_salts: AcceptedPrivateLeafSaltSet,
}

impl<'a> CanonicalReader<'a> {
    fn with_prior_private_leaf_salts(
        bytes: &'a [u8],
        private_leaf_salts: AcceptedPrivateLeafSaltSet,
    ) -> Self {
        Self {
            bytes,
            offset: 0,
            private_leaf_salts,
        }
    }

    fn read_array<const BYTE_COUNT: usize>(&mut self) -> Result<[u8; BYTE_COUNT], String> {
        let following_offset = self
            .offset
            .checked_add(BYTE_COUNT)
            .ok_or_else(|| "aggregate-wide wire cursor overflowed".to_owned())?;
        let source = self
            .bytes
            .get(self.offset..following_offset)
            .ok_or_else(|| {
                format!(
                    "aggregate-wide proof is truncated at byte {} while reading {BYTE_COUNT} bytes",
                    self.offset
                )
            })?;
        let mut output = [0_u8; BYTE_COUNT];
        output.copy_from_slice(source);
        self.offset = following_offset;
        Ok(output)
    }

    fn read_u32_as_usize(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.read_array()?) as usize)
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_field(&mut self) -> Result<ChallengeField, String> {
        let mut coefficients = [Goldilocks::ZERO; CHALLENGE_FIELD_LIMB_COUNT];
        for (limb_ordinal, coefficient) in coefficients.iter_mut().enumerate() {
            let canonical = self.read_u64()?;
            if canonical >= Goldilocks::ORDER_U64 {
                return Err(format!(
                    "aggregate-wide field limb {limb_ordinal} is not canonical"
                ));
            }
            *coefficient = Goldilocks::new(canonical);
        }
        Ok(ChallengeField::new(coefficients))
    }

    fn read_fields(&mut self, count: usize) -> Result<Vec<ChallengeField>, String> {
        let required_bytes = count
            .checked_mul(CHALLENGE_FIELD_LIMB_COUNT * core::mem::size_of::<u64>())
            .ok_or_else(|| "aggregate-wide field byte count overflowed".to_owned())?;
        if self.offset.saturating_add(required_bytes) > self.bytes.len() {
            return Err("aggregate-wide proof is truncated before a field vector".to_owned());
        }
        (0..count).map(|_| self.read_field()).collect()
    }

    fn read_private_leaf_salt(&mut self) -> Result<TransportedPrivateLeafSalt, String> {
        let salt = TransportedPrivateLeafSalt::from_bytes(self.read_array()?);
        self.private_leaf_salts.insert(salt.bytes())?;
        Ok(salt)
    }

    fn read_merkle_node(&mut self) -> Result<MerkleNode, String> {
        let mut node = [0_u64; MERKLE_DIGEST_WORD_LENGTH];
        for word in &mut node {
            *word = self.read_u64()?;
        }
        Ok(node)
    }

    fn read_commitment(&mut self) -> Result<AggregateWideCommitment, String> {
        Ok(MerkleCap::new(vec![self.read_merkle_node()?]))
    }

    fn finish(self) -> Result<(), String> {
        if self.offset != self.bytes.len() {
            Err(format!(
                "aggregate-wide proof has {} trailing bytes",
                self.bytes.len() - self.offset
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_wide_wire_magic_has_fixed_width() {
        assert_eq!(WIRE_MAGIC.len(), 8);
    }

    #[test]
    fn disabled_proof_of_work_has_no_wire_field() {
        let mut writer =
            CanonicalWriter::with_prior_private_leaf_salts(AcceptedPrivateLeafSaltSet::default());
        encode_optional_witness(&mut writer, 0, ChallengeField::ZERO, "test witness")
            .expect("encode disabled witness");
        assert!(writer.finish().is_err(), "disabled witness writes no bytes");
        let error = encode_optional_witness(
            &mut CanonicalWriter::with_prior_private_leaf_salts(
                AcceptedPrivateLeafSaltSet::default(),
            ),
            0,
            ChallengeField::ONE,
            "test witness",
        )
        .expect_err("nonzero disabled witness must be rejected");
        assert!(error.contains("nonzero"));
    }

    #[test]
    fn canonical_wire_refuses_reused_private_leaf_salts_across_batches() {
        let first = TransportedPrivateLeafSalt::from_bytes([0x31; PRIVATE_LEAF_SALT_BYTE_LENGTH]);
        let second = TransportedPrivateLeafSalt::from_bytes([0x92; PRIVATE_LEAF_SALT_BYTE_LENGTH]);
        let mut writer =
            CanonicalWriter::with_prior_private_leaf_salts(AcceptedPrivateLeafSaltSet::default());
        writer
            .write_private_leaf_salt(&first)
            .expect("the first salt is accepted");
        writer
            .write_private_leaf_salt(&second)
            .expect("a distinct salt is accepted");
        assert!(writer.write_private_leaf_salt(&first).is_err());

        let mut canonical = Vec::new();
        canonical.extend_from_slice(&first.bytes());
        canonical.extend_from_slice(&second.bytes());
        canonical.extend_from_slice(&first.bytes());
        let mut reader = CanonicalReader::with_prior_private_leaf_salts(
            &canonical,
            AcceptedPrivateLeafSaltSet::default(),
        );
        assert_eq!(reader.read_private_leaf_salt(), Ok(first.clone()));
        assert_eq!(reader.read_private_leaf_salt(), Ok(second));
        assert!(reader.read_private_leaf_salt().is_err());
    }

    #[test]
    fn canonical_wire_refuses_a_salt_already_accepted_by_an_earlier_proof_section() {
        let prior = TransportedPrivateLeafSalt::from_bytes([0x47; PRIVATE_LEAF_SALT_BYTE_LENGTH]);
        let fresh = TransportedPrivateLeafSalt::from_bytes([0xa6; PRIVATE_LEAF_SALT_BYTE_LENGTH]);
        let mut prior_salts = AcceptedPrivateLeafSaltSet::default();
        prior_salts
            .insert(prior.bytes())
            .expect("the earlier section accepts its first salt");

        let mut writer = CanonicalWriter::with_prior_private_leaf_salts(prior_salts.clone());
        assert!(writer.write_private_leaf_salt(&prior).is_err());
        writer
            .write_private_leaf_salt(&fresh)
            .expect("a salt distinct from every earlier section is accepted");

        let prior_bytes = prior.bytes();
        let mut reader =
            CanonicalReader::with_prior_private_leaf_salts(&prior_bytes, prior_salts.clone());
        assert!(reader.read_private_leaf_salt().is_err());

        let fresh_bytes = fresh.bytes();
        let mut reader = CanonicalReader::with_prior_private_leaf_salts(&fresh_bytes, prior_salts);
        assert_eq!(reader.read_private_leaf_salt(), Ok(fresh));
        reader.finish().expect("the fresh salt consumes the wire");
    }
}
