//! Allocation-bounded canonical wire for the explicit-point plain WHIR proof.
//!
//! Every structural length except the Merkle dictionary size is derived from
//! the verifier-owned WHIR configuration and expected opening schedule. Field
//! elements use fixed-width canonical Goldilocks limbs. Merkle paths refer to a
//! first-use-ordered dictionary so repeated authentication nodes are sent once.

use std::collections::{BTreeMap, BTreeSet};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::{OpeningBatch, SumcheckData};
use p3_symmetric::MerkleCap;
use p3_whir::{PcsProof, QueryOpening, WhirProof, WhirRoundProof};

use super::{
    ChallengeField, MERKLE_DIGEST_WORD_LENGTH,
    plain_whir::{PlainAggregatePcs, PlainAggregateProof},
};

const WIRE_MAGIC: &[u8; 8] = b"SLPWHR02";
const CHALLENGE_FIELD_LIMB_COUNT: usize = 5;
pub(super) const MAXIMUM_PLAIN_WHIR_WIRE_BYTE_LENGTH: usize = 5_242_880;

type MerkleNode = [u64; MERKLE_DIGEST_WORD_LENGTH];

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

pub(super) fn encode_plain_whir_batch_proof(
    pcs: &PlainAggregatePcs,
    proof: &PlainAggregateProof,
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<Vec<u8>, String> {
    validate_codec_configuration(pcs)?;
    validate_proof_shape(pcs, proof, expected_opening_widths, table_width)?;
    let dictionary = MerkleNodeDictionary::from_proof(proof)?;
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(WIRE_MAGIC);
    writer.write_u32(checked_u32(pcs.num_variables, "plain WHIR variable count")?);
    writer.write_u32(checked_u32(
        expected_opening_widths.len(),
        "plain WHIR opening count",
    )?);
    writer.write_u32(checked_u32(table_width, "plain WHIR table width")?);
    writer.write_u32(checked_u32(
        dictionary.nodes.len(),
        "plain WHIR Merkle dictionary size",
    )?);
    for node in &dictionary.nodes {
        writer.write_merkle_node(node);
    }

    for evaluations in &proof.evals {
        write_fields(&mut writer, evaluations.current());
    }
    write_fields(&mut writer, &proof.whir.initial_ood_answers);
    write_sumcheck(&mut writer, &proof.whir.initial_sumcheck);

    for round in &proof.whir.rounds {
        writer.write_merkle_node(
            round
                .commitment
                .as_ref()
                .expect("shape validation requires a round commitment")
                .roots()
                .first()
                .expect("shape validation requires one commitment root"),
        );
        write_fields(&mut writer, &round.ood_answers);
        write_queries(&mut writer, &round.queries, &dictionary)?;
        write_sumcheck(&mut writer, &round.sumcheck);
    }

    write_fields(
        &mut writer,
        proof
            .whir
            .final_poly
            .as_ref()
            .expect("shape validation requires the final polynomial")
            .as_slice(),
    );
    write_queries(&mut writer, &proof.whir.final_queries, &dictionary)?;
    if let Some(final_sumcheck) = &proof.whir.final_sumcheck {
        write_sumcheck(&mut writer, final_sumcheck);
    }

    let canonical = writer.finish();
    if canonical.len() > MAXIMUM_PLAIN_WHIR_WIRE_BYTE_LENGTH {
        return Err(format!(
            "plain WHIR proof has {} canonical bytes, exceeding the {}-byte hard limit",
            canonical.len(),
            MAXIMUM_PLAIN_WHIR_WIRE_BYTE_LENGTH
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
pub(super) fn decode_plain_whir_proof(
    pcs: &PlainAggregatePcs,
    canonical: &[u8],
    expected_opening_count: usize,
) -> Result<PlainAggregateProof, String> {
    decode_plain_whir_batch_proof(pcs, canonical, &vec![1; expected_opening_count], 1)
}

pub(super) fn decode_plain_whir_batch_proof(
    pcs: &PlainAggregatePcs,
    canonical: &[u8],
    expected_opening_widths: &[usize],
    table_width: usize,
) -> Result<PlainAggregateProof, String> {
    validate_codec_configuration(pcs)?;
    if canonical.len() > MAXIMUM_PLAIN_WHIR_WIRE_BYTE_LENGTH {
        return Err(format!(
            "plain WHIR proof has {} canonical bytes, exceeding the {}-byte hard limit",
            canonical.len(),
            MAXIMUM_PLAIN_WHIR_WIRE_BYTE_LENGTH
        ));
    }
    let maximum_merkle_references = maximum_merkle_reference_count(pcs)?;
    let mut reader = CanonicalReader::new(canonical);
    if reader.read_exact::<8>()? != *WIRE_MAGIC {
        return Err("plain WHIR proof has the wrong wire magic".to_owned());
    }
    let encoded_variable_count = reader.read_u32()? as usize;
    if encoded_variable_count != pcs.num_variables {
        return Err(format!(
            "plain WHIR proof targets {encoded_variable_count} variables, expected {}",
            pcs.num_variables
        ));
    }
    let encoded_opening_count = reader.read_u32()? as usize;
    if encoded_opening_count != expected_opening_widths.len() {
        return Err(format!(
            "plain WHIR proof carries {encoded_opening_count} openings, expected {}",
            expected_opening_widths.len()
        ));
    }
    let encoded_table_width = reader.read_u32()? as usize;
    if encoded_table_width != table_width {
        return Err(format!(
            "plain WHIR proof targets table width {encoded_table_width}, expected {table_width}"
        ));
    }
    let dictionary_count = reader.read_u32()? as usize;
    if dictionary_count > maximum_merkle_references {
        return Err(format!(
            "plain WHIR Merkle dictionary has {dictionary_count} nodes, exceeding the configuration-derived maximum {maximum_merkle_references}"
        ));
    }
    let mut dictionary = Vec::with_capacity(dictionary_count);
    let mut distinct_nodes = BTreeSet::new();
    for dictionary_index in 0..dictionary_count {
        let node = reader.read_merkle_node()?;
        if !distinct_nodes.insert(node) {
            return Err(format!(
                "plain WHIR Merkle dictionary node {dictionary_index} is duplicated"
            ));
        }
        dictionary.push(node);
    }
    let mut dictionary_usage = DictionaryUsage::new(dictionary_count);

    let mut evaluations = Vec::with_capacity(expected_opening_widths.len());
    for opening_width in expected_opening_widths {
        evaluations.push(OpeningBatch::new(
            reader.read_fields(*opening_width, "opening evaluations")?,
            Vec::new(),
        ));
    }
    let initial_ood_answers =
        reader.read_fields(pcs.commitment_ood_samples, "initial OOD answers")?;
    let initial_sumcheck = reader.read_sumcheck(pcs.round_folding_factor(0))?;

    let mut rounds = Vec::with_capacity(pcs.n_rounds());
    for round_index in 0..pcs.n_rounds() {
        let parameters = &pcs.round_parameters[round_index];
        let commitment = Some(MerkleCap::new(vec![reader.read_merkle_node()?]));
        let ood_answers = reader.read_fields(parameters.ood_samples, "round OOD answers")?;
        let queries = read_queries(
            &mut reader,
            &dictionary,
            &mut dictionary_usage,
            parameters.num_queries,
            initial_query_value_count(pcs, round_index)?,
            query_path_length(
                parameters.domain_size,
                pcs.round_folding_factor(round_index),
            )?,
            round_index == 0,
        )?;
        let sumcheck = reader.read_sumcheck(pcs.round_folding_factor(round_index + 1))?;
        rounds.push(WhirRoundProof {
            commitment,
            ood_answers,
            pow_witness: ChallengeField::ZERO,
            queries,
            sumcheck,
        });
    }

    let final_configuration = pcs.final_round_config();
    let final_poly = Some(Poly::new(reader.read_fields(
        1_usize << final_configuration.num_variables,
        "final polynomial",
    )?));
    let final_queries = read_queries(
        &mut reader,
        &dictionary,
        &mut dictionary_usage,
        pcs.final_queries,
        initial_query_value_count(pcs, pcs.n_rounds())?,
        query_path_length(
            final_configuration.domain_size,
            pcs.round_folding_factor(pcs.n_rounds()),
        )?,
        pcs.n_rounds() == 0,
    )?;
    let final_sumcheck = if pcs.final_sumcheck_rounds == 0 {
        None
    } else {
        Some(reader.read_sumcheck(pcs.final_sumcheck_rounds)?)
    };
    reader.finish()?;
    dictionary_usage.finish()?;

    let proof = PcsProof {
        whir: WhirProof {
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness: ChallengeField::ZERO,
            final_queries,
            final_sumcheck,
        },
        evals: evaluations,
    };
    validate_proof_shape(pcs, &proof, expected_opening_widths, table_width)?;
    Ok(proof)
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
    let dictionary = MerkleNodeDictionary::from_proof(proof)?;
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
        merkle_dictionary_byte_length: dictionary.nodes.len() * MERKLE_DIGEST_WORD_LENGTH * 8,
        merkle_reference_byte_length: merkle_reference_count * 4,
        merkle_unique_node_count: dictionary.nodes.len(),
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

fn maximum_merkle_reference_count(pcs: &PlainAggregatePcs) -> Result<usize, String> {
    let mut maximum = 0_usize;
    for (round_index, parameters) in pcs.round_parameters.iter().enumerate() {
        let path_length = query_path_length(
            parameters.domain_size,
            pcs.round_folding_factor(round_index),
        )?;
        maximum = maximum
            .checked_add(
                parameters
                    .num_queries
                    .checked_mul(path_length)
                    .ok_or_else(|| {
                        "plain WHIR round Merkle-reference bound overflowed".to_owned()
                    })?,
            )
            .ok_or_else(|| "plain WHIR Merkle-reference bound overflowed".to_owned())?;
    }
    let final_configuration = pcs.final_round_config();
    let final_path_length = query_path_length(
        final_configuration.domain_size,
        pcs.round_folding_factor(pcs.n_rounds()),
    )?;
    maximum
        .checked_add(
            pcs.final_queries
                .checked_mul(final_path_length)
                .ok_or_else(|| "plain WHIR final Merkle-reference bound overflowed".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR Merkle-reference bound overflowed".to_owned())
}

fn write_sumcheck(
    writer: &mut CanonicalWriter,
    sumcheck: &SumcheckData<ChallengeField, ChallengeField>,
) {
    for evaluations in &sumcheck.polynomial_evaluations {
        writer.write_field(evaluations[0]);
        writer.write_field(evaluations[1]);
    }
}

fn write_fields(writer: &mut CanonicalWriter, values: &[ChallengeField]) {
    for value in values {
        writer.write_field(*value);
    }
}

fn write_queries(
    writer: &mut CanonicalWriter,
    queries: &[QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>],
    dictionary: &MerkleNodeDictionary,
) -> Result<(), String> {
    for query in queries {
        let (values, path) = query_parts(query);
        write_fields(writer, values);
        for node in path {
            let reference = dictionary.indices.get(node).ok_or_else(|| {
                "plain WHIR query path contains a node absent from its dictionary".to_owned()
            })?;
            writer.write_u32(*reference);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_queries(
    reader: &mut CanonicalReader<'_>,
    dictionary: &[MerkleNode],
    dictionary_usage: &mut DictionaryUsage,
    query_count: usize,
    value_count: usize,
    path_length: usize,
    base_variant: bool,
) -> Result<Vec<QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>>, String> {
    let mut queries = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        let values = reader.read_fields(value_count, "query values")?;
        let mut path = Vec::with_capacity(path_length);
        for _ in 0..path_length {
            let reference = reader.read_u32()? as usize;
            let node = dictionary.get(reference).ok_or_else(|| {
                format!(
                    "plain WHIR Merkle dictionary reference {reference} is outside {} nodes",
                    dictionary.len()
                )
            })?;
            dictionary_usage.observe(reference)?;
            path.push(*node);
        }
        queries.push(if base_variant {
            QueryOpening::Base {
                values,
                proof: path,
            }
        } else {
            QueryOpening::Extension {
                values,
                proof: path,
            }
        });
    }
    Ok(queries)
}

fn query_parts(
    query: &QueryOpening<ChallengeField, ChallengeField, Vec<MerkleNode>>,
) -> (&[ChallengeField], &[MerkleNode]) {
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
    fn from_proof(proof: &PlainAggregateProof) -> Result<Self, String> {
        let mut nodes = Vec::new();
        let mut indices = BTreeMap::new();
        for query in proof
            .whir
            .rounds
            .iter()
            .flat_map(|round| round.queries.iter())
            .chain(proof.whir.final_queries.iter())
        {
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

struct DictionaryUsage {
    observed: Vec<bool>,
    next_first_reference: usize,
}

impl DictionaryUsage {
    fn new(dictionary_count: usize) -> Self {
        Self {
            observed: vec![false; dictionary_count],
            next_first_reference: 0,
        }
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

struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_field(&mut self, value: ChallengeField) {
        let coefficients =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
        debug_assert_eq!(coefficients.len(), CHALLENGE_FIELD_LIMB_COUNT);
        for coefficient in coefficients {
            self.write_u64(coefficient.as_canonical_u64());
        }
    }

    fn write_merkle_node(&mut self, node: &MerkleNode) {
        for word in node {
            self.write_u64(*word);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct CanonicalReader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> CanonicalReader<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], String> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or_else(|| "plain WHIR wire cursor overflowed".to_owned())?;
        let source = self.bytes.get(self.offset..end).ok_or_else(|| {
            format!(
                "plain WHIR proof is truncated at byte {}, while reading {LENGTH} bytes",
                self.offset
            )
        })?;
        self.offset = end;
        Ok(source
            .try_into()
            .expect("an exactly sized slice converts to an array"))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.read_exact()?))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_exact()?))
    }

    fn read_field(&mut self) -> Result<ChallengeField, String> {
        let mut coefficients = [Goldilocks::ZERO; CHALLENGE_FIELD_LIMB_COUNT];
        for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
            let canonical = self.read_u64()?;
            if canonical >= Goldilocks::ORDER_U64 {
                return Err(format!(
                    "plain WHIR field limb {coefficient_index} is not canonical"
                ));
            }
            *coefficient = Goldilocks::new(canonical);
        }
        Ok(ChallengeField::new(coefficients))
    }

    fn read_merkle_node(&mut self) -> Result<MerkleNode, String> {
        let mut node = [0_u64; MERKLE_DIGEST_WORD_LENGTH];
        for word in &mut node {
            *word = self.read_u64()?;
        }
        Ok(node)
    }

    fn read_fields(&mut self, count: usize, label: &str) -> Result<Vec<ChallengeField>, String> {
        let required_bytes = count
            .checked_mul(CHALLENGE_FIELD_LIMB_COUNT * 8)
            .ok_or_else(|| format!("plain WHIR {label} byte count overflowed"))?;
        if self.bytes.len().saturating_sub(self.offset) < required_bytes {
            return Err(format!(
                "plain WHIR proof is truncated before {count} {label}"
            ));
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            fields.push(self.read_field()?);
        }
        Ok(fields)
    }

    fn read_sumcheck(
        &mut self,
        round_count: usize,
    ) -> Result<SumcheckData<ChallengeField, ChallengeField>, String> {
        let fields = self.read_fields(round_count * 2, "sumcheck fields")?;
        let polynomial_evaluations = fields
            .chunks_exact(2)
            .map(|pair| [pair[0], pair[1]])
            .collect();
        Ok(SumcheckData {
            polynomial_evaluations,
            pow_witnesses: Vec::new(),
        })
    }

    fn finish(self) -> Result<(), String> {
        if self.offset != self.bytes.len() {
            return Err(format!(
                "plain WHIR proof has {} trailing bytes",
                self.bytes.len() - self.offset
            ));
        }
        Ok(())
    }
}

fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} {value} exceeds canonical u32"))
}
