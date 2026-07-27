//! Complete bounded-memory streaming polynomial-commitment protocol.

use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, RawDataSerializable,
};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::super::MAXIMUM_COMMON_PROOF_BYTE_LENGTH;
use super::algebra::{aggregate_opening_reduction, coset_point};
use super::column_commitment::{ColumnDigest, StreamingColumnHasher, verify_column_frontier};
use super::plain_whir::{
    PlainAggregateCommitment, PlainAggregateProof, commit_plain_aggregate,
    open_plain_aggregate_at_points, plain_aggregate_challenger, plain_aggregate_pcs,
    verify_plain_aggregate_at_points,
};
use super::plain_whir_wire::{decode_plain_whir_proof, encode_plain_whir_proof};
#[cfg(test)]
use super::row_encoding::ROW_CODE_LOG_INV_RATE;
use super::row_encoding::{RowEncodingGeometry, encode_row, padded_row_coefficients};
use super::{
    AuthenticatedColumn, BoundedSamplingError, ChallengeField, GOLDILOCKS_MODULUS,
    sample_bounded_goldilocks_candidate, sample_bounded_residue_index,
};

// A rate-one-quarter Reed-Solomon code has relative distance three quarters
// and unique-decoding radius three eighths. A word outside that radius evades
// one query with probability at most 5/8. The two-bit margin leaves the outer
// query term below 2^-262 while the HidingWhir component targets 2^-260; their
// sum remains below the project's strict 2^-258 round-by-round floor.
#[cfg(test)]
const COLUMN_QUERY_SOUNDNESS_BITS: usize = super::PROTOCOL_SECURITY_LEVEL + 2;
pub(super) const COLUMN_QUERY_COUNT: usize = 387;
const CHALLENGE_FIELD_LIMB_COUNT: usize = 5;
const MAXIMUM_OPENING_CLAIM_COUNT: usize = 64;
const PROTOCOL_BINDING_DOMAIN: &[u8] = b"sealed-lattice/streaming-polynomial-commitment/v2";
const STREAMING_WIRE_MAGIC: &[u8; 8] = b"SLSTRM04";

pub(super) trait RecomputableRowSource {
    fn read_row(&self, row_index: usize) -> Result<Vec<Goldilocks>, String>;
}

impl<RowReader> RecomputableRowSource for RowReader
where
    RowReader: Fn(usize) -> Result<Vec<Goldilocks>, String>,
{
    fn read_row(&self, row_index: usize) -> Result<Vec<Goldilocks>, String> {
        self(row_index)
    }
}

#[derive(Clone, Debug)]
pub(super) struct StreamingOpeningStatement {
    pub(super) context: Vec<u8>,
    pub(super) row_points: Vec<Point<ChallengeField>>,
    pub(super) within_row_point: Point<ChallengeField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamingCommitment {
    pub(super) column_root: ColumnDigest,
}

#[derive(Clone)]
pub(super) struct StreamingOpeningProof {
    pub(super) aggregate_commitment: PlainAggregateCommitment,
    pub(super) aggregate_opening_proof: PlainAggregateProof,
    pub(super) authenticated_columns: Vec<AuthenticatedColumn>,
    pub(super) column_frontier: Vec<ColumnDigest>,
}

pub(super) struct StreamingProverOutput {
    pub(super) commitment: StreamingCommitment,
    pub(super) claimed_evaluations: Vec<ChallengeField>,
    pub(super) proof: StreamingOpeningProof,
}

pub(super) fn encode_streaming_prover_output(
    geometry: RowEncodingGeometry,
    output: &StreamingProverOutput,
) -> Result<Vec<u8>, String> {
    validate_streaming_wire_shape(geometry, output)?;
    let aggregate_opening_proof = encode_plain_whir_proof(
        &plain_aggregate_pcs(geometry.coefficient_variable_count() + 1)?,
        &output.proof.aggregate_opening_proof,
        COLUMN_QUERY_COUNT + 1,
    )?;
    let mut writer = StreamingWireWriter::new();
    writer.write_bytes(STREAMING_WIRE_MAGIC);
    writer.write_digest(&output.commitment.column_root);
    writer.write_u32(
        u32::try_from(output.claimed_evaluations.len())
            .map_err(|_| "streaming proof terminal-claim count exceeds canonical u32".to_owned())?,
    );
    for evaluation in &output.claimed_evaluations {
        writer.write_field(*evaluation);
    }
    writer.write_digest(
        output
            .proof
            .aggregate_commitment
            .roots()
            .first()
            .expect("wire-shape validation requires one aggregate root"),
    );
    for column in &output.proof.authenticated_columns {
        for value in &column.values {
            writer.write_u64(value.as_canonical_u64());
        }
    }
    writer.write_u32(
        u32::try_from(output.proof.column_frontier.len())
            .map_err(|_| "streaming proof frontier count exceeds canonical u32".to_owned())?,
    );
    for node in &output.proof.column_frontier {
        writer.write_digest(node);
    }
    writer.write_bytes(&aggregate_opening_proof);
    let canonical = writer.finish();
    if canonical.len() > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(format!(
            "streaming proof wire has {} bytes, exceeding the {}-byte decoder cap",
            canonical.len(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        ));
    }
    Ok(canonical)
}

pub(super) fn decode_streaming_prover_output(
    geometry: RowEncodingGeometry,
    canonical: &[u8],
) -> Result<StreamingProverOutput, String> {
    if canonical.len() > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(format!(
            "streaming proof wire has {} bytes, exceeding the {}-byte decoder cap",
            canonical.len(),
            MAXIMUM_COMMON_PROOF_BYTE_LENGTH
        ));
    }
    let mut reader = StreamingWireReader::new(canonical);
    if reader.read_exact::<8>()? != *STREAMING_WIRE_MAGIC {
        return Err("streaming proof has the wrong wire magic".to_owned());
    }
    let column_root = reader.read_digest()?;
    let claimed_evaluation_count = reader.read_u32()? as usize;
    if claimed_evaluation_count == 0 || claimed_evaluation_count > MAXIMUM_OPENING_CLAIM_COUNT {
        return Err(format!(
            "streaming proof has {claimed_evaluation_count} terminal claims, expected between 1 and {MAXIMUM_OPENING_CLAIM_COUNT}"
        ));
    }
    let claimed_evaluations = reader.read_fields(claimed_evaluation_count, "terminal claims")?;
    let aggregate_commitment = p3_merkle_tree::MerkleCap::new(vec![reader.read_digest()?]);
    let mut authenticated_columns = Vec::with_capacity(COLUMN_QUERY_COUNT);
    for _ in 0..COLUMN_QUERY_COUNT {
        let values = reader.read_goldilocks_values(geometry.row_count)?;
        authenticated_columns.push(AuthenticatedColumn { values });
    }
    let frontier_count = reader.read_u32()? as usize;
    let maximum_frontier_count = COLUMN_QUERY_COUNT
        .checked_mul(geometry.encoded_column_count.ilog2() as usize)
        .ok_or_else(|| "streaming proof frontier bound overflowed".to_owned())?;
    if frontier_count > maximum_frontier_count {
        return Err(format!(
            "streaming proof has {frontier_count} frontier nodes, exceeding the geometry-derived maximum {maximum_frontier_count}"
        ));
    }
    let frontier_byte_length = frontier_count
        .checked_mul(super::MERKLE_DIGEST_WORD_LENGTH * core::mem::size_of::<u64>())
        .ok_or_else(|| "streaming proof frontier byte count overflowed".to_owned())?;
    if reader.remaining().len() < frontier_byte_length {
        return Err(format!(
            "streaming proof is truncated before {frontier_count} column frontier nodes"
        ));
    }
    let mut column_frontier = Vec::with_capacity(frontier_count);
    for _ in 0..frontier_count {
        column_frontier.push(reader.read_digest()?);
    }
    let aggregate_opening_proof = decode_plain_whir_proof(
        &plain_aggregate_pcs(geometry.coefficient_variable_count() + 1)?,
        reader.remaining(),
        COLUMN_QUERY_COUNT + 1,
    )?;
    let output = StreamingProverOutput {
        commitment: StreamingCommitment { column_root },
        claimed_evaluations,
        proof: StreamingOpeningProof {
            aggregate_commitment,
            aggregate_opening_proof,
            authenticated_columns,
            column_frontier,
        },
    };
    validate_streaming_wire_shape(geometry, &output)?;
    Ok(output)
}

fn validate_streaming_wire_shape(
    geometry: RowEncodingGeometry,
    output: &StreamingProverOutput,
) -> Result<(), String> {
    if output.claimed_evaluations.is_empty()
        || output.claimed_evaluations.len() > MAXIMUM_OPENING_CLAIM_COUNT
    {
        return Err(format!(
            "streaming proof has {} terminal claims, expected between 1 and {MAXIMUM_OPENING_CLAIM_COUNT}",
            output.claimed_evaluations.len()
        ));
    }
    if output.proof.aggregate_commitment.num_roots() != 1 {
        return Err(format!(
            "streaming aggregate commitment has {} roots, expected 1",
            output.proof.aggregate_commitment.num_roots()
        ));
    }
    if output.proof.authenticated_columns.len() != COLUMN_QUERY_COUNT {
        return Err(format!(
            "streaming proof has {} authenticated columns, expected {COLUMN_QUERY_COUNT}",
            output.proof.authenticated_columns.len()
        ));
    }
    for (column_ordinal, column) in output.proof.authenticated_columns.iter().enumerate() {
        if column.values.len() != geometry.row_count {
            return Err(format!(
                "streaming authenticated column {column_ordinal} has {} values, expected {}",
                column.values.len(),
                geometry.row_count
            ));
        }
    }
    let maximum_frontier_count = COLUMN_QUERY_COUNT
        .checked_mul(geometry.encoded_column_count.ilog2() as usize)
        .ok_or_else(|| "streaming proof frontier bound overflowed".to_owned())?;
    if output.proof.column_frontier.len() > maximum_frontier_count {
        return Err(format!(
            "streaming proof has {} frontier nodes, exceeding the geometry-derived maximum {maximum_frontier_count}",
            output.proof.column_frontier.len()
        ));
    }
    Ok(())
}

struct StreamingWireWriter {
    bytes: Vec<u8>,
}

impl StreamingWireWriter {
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

    fn write_digest(&mut self, digest: &ColumnDigest) {
        for word in digest {
            self.write_u64(*word);
        }
    }

    fn write_field(&mut self, value: ChallengeField) {
        let coefficients =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
        debug_assert_eq!(coefficients.len(), CHALLENGE_FIELD_LIMB_COUNT);
        for coefficient in coefficients {
            self.write_u64(coefficient.as_canonical_u64());
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct StreamingWireReader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> StreamingWireReader<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], String> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or_else(|| "streaming proof wire cursor overflowed".to_owned())?;
        let source = self.bytes.get(self.offset..end).ok_or_else(|| {
            format!(
                "streaming proof is truncated at byte {}, while reading {LENGTH} bytes",
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

    fn read_digest(&mut self) -> Result<ColumnDigest, String> {
        let mut digest = [0_u64; super::MERKLE_DIGEST_WORD_LENGTH];
        for word in &mut digest {
            *word = self.read_u64()?;
        }
        Ok(digest)
    }

    fn read_field(&mut self) -> Result<ChallengeField, String> {
        let mut coefficients = [Goldilocks::ZERO; CHALLENGE_FIELD_LIMB_COUNT];
        for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
            let canonical = self.read_u64()?;
            if canonical >= Goldilocks::ORDER_U64 {
                return Err(format!(
                    "streaming proof field limb {coefficient_index} is not canonical"
                ));
            }
            *coefficient = Goldilocks::new(canonical);
        }
        Ok(ChallengeField::new(coefficients))
    }

    fn read_fields(&mut self, count: usize, label: &str) -> Result<Vec<ChallengeField>, String> {
        let required_bytes = count
            .checked_mul(CHALLENGE_FIELD_LIMB_COUNT * 8)
            .ok_or_else(|| format!("streaming proof {label} byte count overflowed"))?;
        if self.remaining().len() < required_bytes {
            return Err(format!(
                "streaming proof is truncated before {count} {label}"
            ));
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            fields.push(self.read_field()?);
        }
        Ok(fields)
    }

    fn read_goldilocks_values(&mut self, count: usize) -> Result<Vec<Goldilocks>, String> {
        let required_bytes = count
            .checked_mul(8)
            .ok_or_else(|| "streaming column byte count overflowed".to_owned())?;
        if self.remaining().len() < required_bytes {
            return Err(format!(
                "streaming proof is truncated before an authenticated column of {count} values"
            ));
        }
        let mut values = Vec::with_capacity(count);
        for value_index in 0..count {
            let canonical = self.read_u64()?;
            if canonical >= Goldilocks::ORDER_U64 {
                return Err(format!(
                    "streaming authenticated-column value {value_index} is not canonical"
                ));
            }
            values.push(Goldilocks::new(canonical));
        }
        Ok(values)
    }

    fn remaining(&self) -> &'bytes [u8] {
        &self.bytes[self.offset..]
    }
}

/// Commits the witness before a sumcheck or another outer protocol derives
/// the multilinear opening point.
pub(super) fn commit_streaming_witness<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    secret_row_pad_seed: &[u8; 32],
) -> Result<StreamingCommitment, String> {
    commit_columns(source, geometry, secret_row_pad_seed)
}

/// Evaluates the committed witness after an outer protocol has derived its
/// opening points. This is a separate bounded pass because those points do not
/// exist when the first-pass commitment is constructed.
pub(super) fn evaluate_streaming_witness<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
) -> Result<Vec<ChallengeField>, String> {
    validate_statement(geometry, statement)?;
    let row_equality_tables = row_equality_tables(statement);
    let mut claimed_evaluations = vec![ChallengeField::ZERO; statement.row_points.len()];
    for row_index in 0..geometry.row_count {
        let mut witness_values = Poly::new(read_witness_row(source, geometry, row_index)?);
        accumulate_row_claims(
            row_index,
            &witness_values,
            statement,
            &row_equality_tables,
            &mut claimed_evaluations,
        );
        witness_values.as_mut_slice().fill(Goldilocks::ZERO);
    }
    Ok(claimed_evaluations)
}

/// Opens a previously committed witness after an outer protocol has fixed the
/// points and claims. The aggregate opening authenticates those claims, while
/// the recomputed column root rejects a changed source or pad seed.
pub(super) fn prove_streaming_opening_after_commitment<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
    commitment: StreamingCommitment,
    claimed_evaluations: Vec<ChallengeField>,
    secret_row_pad_seed: &[u8; 32],
) -> Result<StreamingProverOutput, String> {
    validate_statement(geometry, statement)?;
    validate_claimed_evaluations(statement, &claimed_evaluations)?;
    if geometry.encoded_column_count < COLUMN_QUERY_COUNT {
        return Err(format!(
            "encoded column count {} is below query count {COLUMN_QUERY_COUNT}",
            geometry.encoded_column_count
        ));
    }

    let binding = protocol_binding(geometry, statement, &commitment, &claimed_evaluations)?;
    let integrity_row_weights = derive_integrity_row_weights(&binding, geometry.row_count)?;
    let claim_batching_weights =
        derive_claim_batching_weights(&binding, claimed_evaluations.len())?;
    let evaluation_row_weights =
        combined_claim_row_weights(geometry, statement, &claim_batching_weights)?;
    let aggregate_message = aggregate_message(
        source,
        geometry,
        secret_row_pad_seed,
        &integrity_row_weights,
        &evaluation_row_weights,
    )?;

    let aggregate_variable_count = geometry.coefficient_variable_count() + 1;
    let pcs = plain_aggregate_pcs(aggregate_variable_count)?;
    let mut aggregate_prover_challenger = plain_aggregate_challenger(&pcs, &binding);
    let (aggregate_commitment, aggregate_prover_data) =
        commit_plain_aggregate(&pcs, aggregate_message, &mut aggregate_prover_challenger);
    let post_commitment_binding =
        post_aggregate_commitment_binding(&binding, &aggregate_commitment)?;
    let (aggregate_batching_challenge, column_indices) =
        derive_post_commitment_challenges(&post_commitment_binding, geometry.encoded_column_count)?;
    let opening_points = aggregate_opening_points(
        geometry,
        statement,
        aggregate_batching_challenge,
        &column_indices,
    )?;

    let (authenticated_columns, column_frontier) = recompute_authenticated_columns(
        source,
        geometry,
        secret_row_pad_seed,
        &commitment,
        &column_indices,
    )?;
    let aggregate_opening_proof = open_plain_aggregate_at_points(
        &pcs,
        aggregate_prover_data,
        &opening_points,
        &mut aggregate_prover_challenger,
    );
    let authenticated_batched_claim = aggregate_opening_proof
        .evals
        .first()
        .ok_or_else(|| "aggregate opening proof contains no evaluation claim".to_owned())?;
    let authenticated_batched_claim = *authenticated_batched_claim
        .current()
        .first()
        .ok_or_else(|| "aggregate opening proof contains an empty evaluation batch".to_owned())?;
    let expected_batched_claim =
        batched_claimed_evaluation(&claimed_evaluations, &claim_batching_weights)?;
    if authenticated_batched_claim != expected_batched_claim {
        return Err(
            "aggregate opening does not authenticate the derived batch of terminal claims"
                .to_owned(),
        );
    }

    Ok(StreamingProverOutput {
        commitment,
        claimed_evaluations,
        proof: StreamingOpeningProof {
            aggregate_commitment,
            aggregate_opening_proof,
            authenticated_columns,
            column_frontier,
        },
    })
}

pub(super) fn verify_streaming_opening(
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
    commitment: &StreamingCommitment,
    claimed_evaluations: &[ChallengeField],
    proof: &StreamingOpeningProof,
) -> Result<(), String> {
    validate_statement(geometry, statement)?;
    validate_claimed_evaluations(statement, claimed_evaluations)?;
    let binding = protocol_binding(geometry, statement, commitment, claimed_evaluations)?;
    let integrity_row_weights = derive_integrity_row_weights(&binding, geometry.row_count)?;
    let claim_batching_weights =
        derive_claim_batching_weights(&binding, claimed_evaluations.len())?;
    let evaluation_row_weights =
        combined_claim_row_weights(geometry, statement, &claim_batching_weights)?;
    let post_commitment_binding =
        post_aggregate_commitment_binding(&binding, &proof.aggregate_commitment)?;
    let (aggregate_batching_challenge, expected_column_indices) =
        derive_post_commitment_challenges(&post_commitment_binding, geometry.encoded_column_count)?;
    if proof.authenticated_columns.len() != COLUMN_QUERY_COUNT {
        return Err(format!(
            "proof has {} authenticated columns, expected {COLUMN_QUERY_COUNT}",
            proof.authenticated_columns.len()
        ));
    }

    for (column_ordinal, opening) in proof.authenticated_columns.iter().enumerate() {
        if opening.values.len() != geometry.row_count {
            return Err(format!(
                "authenticated column {column_ordinal} has {} row values, expected {}",
                opening.values.len(),
                geometry.row_count
            ));
        }
    }
    let opened_columns = expected_column_indices
        .iter()
        .copied()
        .zip(
            proof
                .authenticated_columns
                .iter()
                .map(|opening| opening.values.as_slice()),
        )
        .collect::<Vec<_>>();
    verify_column_frontier(
        &commitment.column_root,
        geometry.encoded_column_count,
        &opened_columns,
        &proof.column_frontier,
    )?;

    let expected_evaluations = expected_aggregate_evaluations(
        claimed_evaluations,
        &claim_batching_weights,
        aggregate_batching_challenge,
        geometry.coefficient_variable_count(),
        &expected_column_indices,
        &integrity_row_weights,
        &evaluation_row_weights,
        &proof.authenticated_columns,
    );
    let aggregate_evaluations = proof
        .aggregate_opening_proof
        .evals
        .iter()
        .map(|batch| {
            if batch.current().len() != 1 || !batch.next().is_empty() {
                return Err(
                    "aggregate opening batch must contain one current evaluation and no successor evaluation"
                        .to_owned(),
                );
            }
            Ok(batch.current()[0])
        })
        .collect::<Result<Vec<_>, String>>()?;
    if aggregate_evaluations != expected_evaluations {
        return Err(
            "aggregate opening evaluations do not match the public claim and authenticated columns"
                .to_owned(),
        );
    }

    let opening_points = aggregate_opening_points(
        geometry,
        statement,
        aggregate_batching_challenge,
        &expected_column_indices,
    )?;
    let verifier_pcs = plain_aggregate_pcs(geometry.coefficient_variable_count() + 1)?;
    let mut aggregate_verifier_challenger = plain_aggregate_challenger(&verifier_pcs, &binding);
    verify_plain_aggregate_at_points(
        &verifier_pcs,
        &proof.aggregate_commitment,
        &proof.aggregate_opening_proof,
        &opening_points,
        &mut aggregate_verifier_challenger,
    )
}

fn validate_statement(
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
) -> Result<(), String> {
    let expected_row_variables = geometry.row_count.ilog2() as usize;
    if statement.row_points.is_empty() || statement.row_points.len() > MAXIMUM_OPENING_CLAIM_COUNT {
        return Err(format!(
            "statement has {} row points, expected between 1 and {MAXIMUM_OPENING_CLAIM_COUNT}",
            statement.row_points.len()
        ));
    }
    for (point_index, row_point) in statement.row_points.iter().enumerate() {
        if row_point.num_variables() != expected_row_variables {
            return Err(format!(
                "row point {point_index} has {} variables, expected {expected_row_variables}",
                row_point.num_variables()
            ));
        }
    }
    let expected_within_row_variables = geometry.witness_values_per_row.ilog2() as usize;
    if statement.within_row_point.num_variables() != expected_within_row_variables {
        return Err(format!(
            "within-row point has {} variables, expected {expected_within_row_variables}",
            statement.within_row_point.num_variables()
        ));
    }
    Ok(())
}

fn validate_claimed_evaluations(
    statement: &StreamingOpeningStatement,
    claimed_evaluations: &[ChallengeField],
) -> Result<(), String> {
    if claimed_evaluations.len() != statement.row_points.len() {
        return Err(format!(
            "proof has {} terminal claims for {} row points",
            claimed_evaluations.len(),
            statement.row_points.len()
        ));
    }
    Ok(())
}

fn commit_columns<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    secret_row_pad_seed: &[u8; 32],
) -> Result<StreamingCommitment, String> {
    let mut column_hasher =
        StreamingColumnHasher::new(geometry.row_count, geometry.encoded_column_count)?;
    for row_index in 0..geometry.row_count {
        let mut witness_values = read_witness_row(source, geometry, row_index)?;
        let mut encoded_row =
            encode_row(geometry, row_index, &witness_values, secret_row_pad_seed)?;
        column_hasher.absorb_row(&encoded_row)?;
        witness_values.fill(Goldilocks::ZERO);
        encoded_row.fill(Goldilocks::ZERO);
    }
    Ok(StreamingCommitment {
        column_root: column_hasher.finalize_root()?,
    })
}

fn read_witness_row<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    row_index: usize,
) -> Result<Vec<Goldilocks>, String> {
    let witness_values = source.read_row(row_index)?;
    if witness_values.len() != geometry.witness_values_per_row {
        return Err(format!(
            "row {row_index} has {} witness values, expected {}",
            witness_values.len(),
            geometry.witness_values_per_row
        ));
    }
    Ok(witness_values)
}

fn row_equality_tables(statement: &StreamingOpeningStatement) -> Vec<Poly<ChallengeField>> {
    statement
        .row_points
        .iter()
        .map(|row_point| Poly::new_from_point(row_point.as_slice(), ChallengeField::ONE))
        .collect()
}

fn accumulate_row_claims(
    row_index: usize,
    witness_values: &Poly<Goldilocks>,
    statement: &StreamingOpeningStatement,
    row_equality_tables: &[Poly<ChallengeField>],
    claimed_evaluations: &mut [ChallengeField],
) {
    let within_row_evaluation = witness_values.eval_base(&statement.within_row_point);
    for ((claimed_evaluation, row_equality_table), row_point) in claimed_evaluations
        .iter_mut()
        .zip(row_equality_tables)
        .zip(&statement.row_points)
    {
        debug_assert_eq!(
            row_equality_table.num_variables(),
            row_point.num_variables()
        );
        *claimed_evaluation += row_equality_table.as_slice()[row_index] * within_row_evaluation;
    }
}

fn aggregate_message<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    secret_row_pad_seed: &[u8; 32],
    integrity_row_weights: &[ChallengeField],
    evaluation_row_weights: &[ChallengeField],
) -> Result<Poly<ChallengeField>, String> {
    if integrity_row_weights.len() != geometry.row_count
        || evaluation_row_weights.len() != geometry.row_count
    {
        return Err("aggregate row-weight count does not match geometry".to_owned());
    }
    let coefficient_count = geometry.padded_coefficient_count;
    let mut integrity_coefficient_limbs =
        vec![vec![Goldilocks::ZERO; coefficient_count]; CHALLENGE_FIELD_LIMB_COUNT];
    let mut evaluation_coefficient_limbs =
        vec![vec![Goldilocks::ZERO; coefficient_count]; CHALLENGE_FIELD_LIMB_COUNT];

    for row_index in 0..geometry.row_count {
        let mut witness_values = source.read_row(row_index)?;
        let mut padded_coefficients =
            padded_row_coefficients(geometry, row_index, &witness_values, secret_row_pad_seed)?;
        let integrity_weight_limbs: &[Goldilocks] =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &integrity_row_weights[row_index],
            );
        let evaluation_weight_limbs: &[Goldilocks] =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &evaluation_row_weights[row_index],
            );
        for (coefficient_index, coefficient) in padded_coefficients.iter().enumerate() {
            for (limb, weight_limb) in integrity_coefficient_limbs
                .iter_mut()
                .zip(integrity_weight_limbs)
            {
                limb[coefficient_index] += *weight_limb * *coefficient;
            }
            for (limb, weight_limb) in evaluation_coefficient_limbs
                .iter_mut()
                .zip(evaluation_weight_limbs)
            {
                limb[coefficient_index] += *weight_limb * *coefficient;
            }
        }
        witness_values.fill(Goldilocks::ZERO);
        padded_coefficients.fill(Goldilocks::ZERO);
    }

    let mut aggregate = Vec::with_capacity(2 * coefficient_count);
    for coefficient_index in 0..coefficient_count {
        aggregate.push(ChallengeField::new(core::array::from_fn(|limb_index| {
            integrity_coefficient_limbs
                .get(limb_index)
                .map_or(Goldilocks::ZERO, |limb| limb[coefficient_index])
        })));
    }
    for coefficient_index in 0..coefficient_count {
        aggregate.push(ChallengeField::new(core::array::from_fn(|limb_index| {
            evaluation_coefficient_limbs[limb_index][coefficient_index]
        })));
    }
    Ok(Poly::new(aggregate))
}

/// Forms one extension-field linear combination of the padded coefficient rows.
/// The caller owns the row-weight derivation and may combine independently
/// committed phases as long as each phase is recomputed with its own pad seed.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) fn aggregate_weighted_message<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    secret_row_pad_seed: &[u8; 32],
    row_weights: &[ChallengeField],
) -> Result<Poly<ChallengeField>, String> {
    if row_weights.len() != geometry.row_count {
        return Err(format!(
            "aggregate has {} row weights for {} rows",
            row_weights.len(),
            geometry.row_count
        ));
    }
    let coefficient_count = geometry.padded_coefficient_count;
    let mut coefficient_limbs =
        vec![vec![Goldilocks::ZERO; coefficient_count]; CHALLENGE_FIELD_LIMB_COUNT];
    for (row_index, row_weight) in row_weights.iter().copied().enumerate() {
        if row_weight == ChallengeField::ZERO {
            continue;
        }
        let mut witness_values = read_witness_row(source, geometry, row_index)?;
        let mut padded_coefficients =
            padded_row_coefficients(geometry, row_index, &witness_values, secret_row_pad_seed)?;
        let weight_limbs: &[Goldilocks] =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &row_weight,
            );
        for (coefficient_index, coefficient) in padded_coefficients.iter().copied().enumerate() {
            for (limb, weight_limb) in coefficient_limbs.iter_mut().zip(weight_limbs) {
                limb[coefficient_index] += *weight_limb * coefficient;
            }
        }
        witness_values.fill(Goldilocks::ZERO);
        padded_coefficients.fill(Goldilocks::ZERO);
    }
    Ok(Poly::new(
        (0..coefficient_count)
            .map(|coefficient_index| {
                ChallengeField::new(core::array::from_fn(|limb_index| {
                    coefficient_limbs[limb_index][coefficient_index]
                }))
            })
            .collect(),
    ))
}

pub(super) fn recompute_authenticated_columns<Source: RecomputableRowSource>(
    source: &Source,
    geometry: RowEncodingGeometry,
    secret_row_pad_seed: &[u8; 32],
    commitment: &StreamingCommitment,
    column_indices: &[usize],
) -> Result<(Vec<AuthenticatedColumn>, Vec<ColumnDigest>), String> {
    let mut column_values = column_indices
        .iter()
        .map(|_| Vec::with_capacity(geometry.row_count))
        .collect::<Vec<_>>();
    let mut column_hasher =
        StreamingColumnHasher::new(geometry.row_count, geometry.encoded_column_count)?;
    for row_index in 0..geometry.row_count {
        let mut witness_values = source.read_row(row_index)?;
        let mut encoded_row =
            encode_row(geometry, row_index, &witness_values, secret_row_pad_seed)?;
        for (opened_values, column_index) in column_values.iter_mut().zip(column_indices) {
            opened_values.push(encoded_row[*column_index]);
        }
        column_hasher.absorb_row(&encoded_row)?;
        witness_values.fill(Goldilocks::ZERO);
        encoded_row.fill(Goldilocks::ZERO);
    }
    let recomputed = column_hasher.finalize_commitment(column_indices)?;
    if recomputed.root != commitment.column_root {
        return Err(
            "recomputed column commitment differs from the first-pass commitment".to_owned(),
        );
    }
    let columns = column_values
        .into_iter()
        .map(|values| AuthenticatedColumn { values })
        .collect();
    Ok((columns, recomputed.frontier))
}

fn combined_claim_row_weights(
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
    claim_batching_weights: &[ChallengeField],
) -> Result<Vec<ChallengeField>, String> {
    if statement.row_points.len() != claim_batching_weights.len() {
        return Err("claim batching-weight count does not match row-point count".to_owned());
    }
    let mut combined_weights = vec![ChallengeField::ZERO; geometry.row_count];
    for (row_point, claim_batching_weight) in
        statement.row_points.iter().zip(claim_batching_weights)
    {
        let row_weights = Poly::new_from_point(row_point.as_slice(), *claim_batching_weight);
        if row_weights.num_evals() != geometry.row_count {
            return Err("row-point equality table does not match geometry".to_owned());
        }
        for (combined_weight, row_weight) in combined_weights.iter_mut().zip(row_weights.as_slice())
        {
            *combined_weight += *row_weight;
        }
    }
    Ok(combined_weights)
}

fn aggregate_opening_points(
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
    batching_challenge: ChallengeField,
    column_indices: &[usize],
) -> Result<Vec<Point<ChallengeField>>, String> {
    let mut relation_coordinates =
        Vec::with_capacity(statement.within_row_point.num_variables() + 2);
    relation_coordinates.push(ChallengeField::ONE);
    relation_coordinates.push(ChallengeField::ZERO);
    relation_coordinates.extend_from_slice(statement.within_row_point.as_slice());
    let mut points = Vec::with_capacity(column_indices.len() + 1);
    points.push(Point::new(relation_coordinates));
    for column_index in column_indices {
        let evaluation_point = coset_point(
            geometry.encoded_column_count.ilog2() as usize,
            *column_index,
        )?;
        points.push(
            aggregate_opening_reduction(
                evaluation_point,
                geometry.coefficient_variable_count(),
                batching_challenge,
            )?
            .multilinear_point,
        );
    }
    Ok(points)
}

fn expected_aggregate_evaluations(
    claimed_evaluations: &[ChallengeField],
    claim_batching_weights: &[ChallengeField],
    batching_challenge: ChallengeField,
    coefficient_variable_count: usize,
    authenticated_column_indices: &[usize],
    integrity_row_weights: &[ChallengeField],
    evaluation_row_weights: &[ChallengeField],
    authenticated_columns: &[AuthenticatedColumn],
) -> Vec<ChallengeField> {
    debug_assert_eq!(
        authenticated_column_indices.len(),
        authenticated_columns.len()
    );
    let mut evaluations = Vec::with_capacity(authenticated_columns.len() + 1);
    evaluations.push(
        batched_claimed_evaluation(claimed_evaluations, claim_batching_weights)
            .expect("validated claim and batching-weight counts agree"),
    );
    for (column_index, opening) in authenticated_column_indices
        .iter()
        .zip(authenticated_columns)
    {
        let integrity_value = opening
            .values
            .iter()
            .zip(integrity_row_weights)
            .fold(ChallengeField::ZERO, |sum, (value, weight)| {
                sum + *weight * ChallengeField::from(*value)
            });
        let evaluation_value = opening
            .values
            .iter()
            .zip(evaluation_row_weights)
            .fold(ChallengeField::ZERO, |sum, (value, weight)| {
                sum + *weight * ChallengeField::from(*value)
            });
        let batched_polynomial_value = (ChallengeField::ONE - batching_challenge) * integrity_value
            + batching_challenge * evaluation_value;
        let evaluation_point = coset_point(
            coefficient_variable_count + super::row_encoding::ROW_CODE_LOG_INV_RATE,
            *column_index,
        )
        .expect("verified column geometry gives a valid coset point");
        let reduction = aggregate_opening_reduction(
            evaluation_point,
            coefficient_variable_count,
            batching_challenge,
        )
        .expect("generator coset has no reduction pole");
        evaluations
            .push(batched_polynomial_value * reduction.multilinear_to_polynomial_scale.inverse());
    }
    evaluations
}

fn batched_claimed_evaluation(
    claimed_evaluations: &[ChallengeField],
    claim_batching_weights: &[ChallengeField],
) -> Result<ChallengeField, String> {
    if claimed_evaluations.len() != claim_batching_weights.len() {
        return Err("claim batching-weight count does not match terminal-claim count".to_owned());
    }
    Ok(claimed_evaluations
        .iter()
        .zip(claim_batching_weights)
        .fold(ChallengeField::ZERO, |sum, (claim, weight)| {
            sum + *claim * *weight
        }))
}

fn protocol_binding(
    geometry: RowEncodingGeometry,
    statement: &StreamingOpeningStatement,
    commitment: &StreamingCommitment,
    claimed_evaluations: &[ChallengeField],
) -> Result<Vec<u8>, String> {
    validate_claimed_evaluations(statement, claimed_evaluations)?;
    let mut binding = Vec::new();
    append_length_prefixed(&mut binding, PROTOCOL_BINDING_DOMAIN)?;
    append_length_prefixed(&mut binding, &statement.context)?;
    append_u64(&mut binding, geometry.row_count)?;
    append_u64(&mut binding, geometry.witness_values_per_row)?;
    append_u64(&mut binding, geometry.padded_coefficient_count)?;
    append_u64(&mut binding, geometry.encoded_column_count)?;
    append_u64(&mut binding, statement.row_points.len())?;
    for row_point in &statement.row_points {
        append_point(&mut binding, row_point)?;
    }
    append_point(&mut binding, &statement.within_row_point)?;
    for word in commitment.column_root {
        binding.extend_from_slice(&word.to_le_bytes());
    }
    append_u64(&mut binding, claimed_evaluations.len())?;
    for claimed_evaluation in claimed_evaluations {
        binding.extend(
            <ChallengeField as RawDataSerializable>::into_bytes(*claimed_evaluation).into_iter(),
        );
    }
    Ok(binding)
}

fn post_aggregate_commitment_binding(
    binding: &[u8],
    aggregate_commitment: &PlainAggregateCommitment,
) -> Result<Vec<u8>, String> {
    if aggregate_commitment.num_roots() != 1 {
        return Err(format!(
            "aggregate commitment has {} roots, expected 1",
            aggregate_commitment.num_roots()
        ));
    }
    let canonical_commitment = aggregate_commitment.roots()[0]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let mut result = binding.to_vec();
    append_length_prefixed(&mut result, &canonical_commitment)?;
    Ok(result)
}

fn append_point(output: &mut Vec<u8>, point: &Point<ChallengeField>) -> Result<(), String> {
    append_u64(output, point.num_variables())?;
    for coordinate in point.as_slice() {
        output.extend(<ChallengeField as RawDataSerializable>::into_bytes(*coordinate).into_iter());
    }
    Ok(())
}

fn append_length_prefixed(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    append_u64(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_u64(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    let value = u64::try_from(value)
        .map_err(|_| format!("value {value} does not fit the canonical u64 encoding"))?;
    output.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn derive_integrity_row_weights(
    binding: &[u8],
    count: usize,
) -> Result<Vec<ChallengeField>, String> {
    derive_challenge_vector(b"sealed-lattice/integrity-row-weights/v2", binding, count)
}

fn derive_claim_batching_weights(
    binding: &[u8],
    count: usize,
) -> Result<Vec<ChallengeField>, String> {
    derive_challenge_vector(b"sealed-lattice/terminal-claim-batching/v1", binding, count)
}

fn derive_challenge_vector(
    domain: &[u8],
    binding: &[u8],
    count: usize,
) -> Result<Vec<ChallengeField>, String> {
    let mut state = Shake256::default();
    state.update(&(domain.len() as u64).to_le_bytes());
    state.update(domain);
    state.update(&(binding.len() as u64).to_le_bytes());
    state.update(binding);
    let mut reader = state.finalize_xof();
    let mut challenges = Vec::with_capacity(count);
    for _ in 0..count {
        challenges.push(sample_challenge(&mut reader)?);
    }
    Ok(challenges)
}

fn derive_post_commitment_challenges(
    binding: &[u8],
    encoded_column_count: usize,
) -> Result<(ChallengeField, Vec<usize>), String> {
    let mut state = Shake256::default();
    state.update(b"sealed-lattice/streaming-post-aggregate/v2");
    state.update(&(binding.len() as u64).to_le_bytes());
    state.update(binding);
    let mut reader = state.finalize_xof();
    let batching_challenge = sample_challenge(&mut reader)?;
    let mut column_indices = Vec::with_capacity(COLUMN_QUERY_COUNT);
    while column_indices.len() < COLUMN_QUERY_COUNT {
        let candidate = sample_bounded_residue_index(
            encoded_column_count,
            |candidate| !column_indices.contains(&candidate),
            || {
                let mut bytes = [0_u8; 8];
                reader.read(&mut bytes);
                u64::from_le_bytes(bytes)
            },
        )
        .map_err(|error| match error {
            BoundedSamplingError::InvalidUpperBound => {
                "encoded column count cannot be sampled canonically".to_owned()
            }
            BoundedSamplingError::CandidateDrawsExhausted => {
                "distinct column sampling exhausted its candidate ceiling".to_owned()
            }
        })?;
        column_indices.push(candidate);
    }
    Ok((batching_challenge, column_indices))
}

fn sample_challenge(reader: &mut impl XofReader) -> Result<ChallengeField, String> {
    let mut coordinates = [Goldilocks::ZERO; CHALLENGE_FIELD_LIMB_COUNT];
    for coordinate in &mut coordinates {
        *coordinate = sample_bounded_goldilocks_candidate(|| {
            let mut bytes = [0_u8; 8];
            reader.read(&mut bytes);
            u64::from_le_bytes(bytes)
        })
        .map_err(|_| {
            "streaming protocol Goldilocks sampling exhausted its candidate ceiling".to_owned()
        })?;
    }
    Ok(ChallengeField::new(coordinates))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use num_bigint::BigUint;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    fn deterministic_rows(geometry: RowEncodingGeometry) -> Vec<Vec<Goldilocks>> {
        (0..geometry.row_count)
            .map(|row_index| {
                (0..geometry.witness_values_per_row)
                    .map(|value_index| {
                        Goldilocks::from_u64(
                            row_index as u64 * 1_000_003 + value_index as u64 * 97 + 41,
                        )
                    })
                    .collect()
            })
            .collect()
    }

    fn sample_statement(geometry: RowEncodingGeometry) -> StreamingOpeningStatement {
        let row_variable_count = geometry.row_count.ilog2() as usize;
        let shared_coordinates = (0..row_variable_count)
            .map(|index| ChallengeField::from_u64(index as u64 * 7 + 3))
            .collect::<Vec<_>>();
        StreamingOpeningStatement {
            context: b"streaming PCS integration test statement".to_vec(),
            row_points: (0..4)
                .map(|component_index| {
                    let mut coordinates = shared_coordinates.clone();
                    coordinates[0] = ChallengeField::from_u64(((component_index >> 1) & 1) as u64);
                    coordinates[1] = ChallengeField::from_u64((component_index & 1) as u64);
                    Point::new(coordinates)
                })
                .collect(),
            within_row_point: Point::new(
                (0..geometry.witness_values_per_row.ilog2() as usize)
                    .map(|index| ChallengeField::from_u64(index as u64 * 11 + 5))
                    .collect(),
            ),
        }
    }

    fn direct_evaluation(
        rows: &[Vec<Goldilocks>],
        statement: &StreamingOpeningStatement,
    ) -> Vec<ChallengeField> {
        let table = rows.iter().flatten().copied().collect::<Vec<_>>();
        let polynomial = Poly::new(table);
        statement
            .row_points
            .iter()
            .map(|row_point| {
                let mut coordinates = row_point.as_slice().to_vec();
                coordinates.extend_from_slice(statement.within_row_point.as_slice());
                polynomial.eval_base(&Point::new(coordinates))
            })
            .collect()
    }

    fn prove_test_opening<Source: RecomputableRowSource>(
        source: &Source,
        geometry: RowEncodingGeometry,
        statement: &StreamingOpeningStatement,
        row_pad_seed: &[u8; 32],
    ) -> Result<StreamingProverOutput, String> {
        let commitment = commit_streaming_witness(source, geometry, row_pad_seed)?;
        let claimed_evaluations = evaluate_streaming_witness(source, geometry, statement)?;
        prove_streaming_opening_after_commitment(
            source,
            geometry,
            statement,
            commitment,
            claimed_evaluations,
            row_pad_seed,
        )
    }

    #[test]
    fn complete_streaming_protocol_verifies_with_a_fresh_verifier() {
        let geometry = RowEncodingGeometry::new(8, 14).expect("valid integration geometry");
        let rows = deterministic_rows(geometry);
        let statement = sample_statement(geometry);
        let expected_evaluation = direct_evaluation(&rows, &statement);
        let source = |row_index: usize| Ok(rows[row_index].clone());
        let output = prove_test_opening(&source, geometry, &statement, &[17; 32])
            .expect("generate complete streaming proof");
        assert_eq!(output.claimed_evaluations, expected_evaluation);
        let canonical = encode_streaming_prover_output(geometry, &output)
            .expect("encode canonical streaming proof");
        assert!(canonical.len() < MAXIMUM_COMMON_PROOF_BYTE_LENGTH);
        let decoded = decode_streaming_prover_output(geometry, &canonical)
            .expect("decode canonical streaming proof into verifier-owned types");
        verify_streaming_opening(
            geometry,
            &statement,
            &decoded.commitment,
            &decoded.claimed_evaluations,
            &decoded.proof,
        )
        .expect("fresh verifier accepts complete streaming proof");
    }

    #[test]
    fn verifier_rejects_each_outer_binding_mutation() {
        let geometry = RowEncodingGeometry::new(8, 14).expect("valid integration geometry");
        let rows = deterministic_rows(geometry);
        let statement = sample_statement(geometry);
        let source = |row_index: usize| Ok(rows[row_index].clone());
        let output = prove_test_opening(&source, geometry, &statement, &[31; 32])
            .expect("generate complete streaming proof");

        let mut wrong_statement = statement.clone();
        wrong_statement.context.push(0);
        assert!(
            verify_streaming_opening(
                geometry,
                &wrong_statement,
                &output.commitment,
                &output.claimed_evaluations,
                &output.proof,
            )
            .is_err()
        );
        let mut wrong_claims = output.claimed_evaluations.clone();
        wrong_claims[2] += ChallengeField::ONE;
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &wrong_claims,
                &output.proof,
            )
            .is_err()
        );

        let mut missing_claim = output.claimed_evaluations.clone();
        missing_claim.pop();
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &missing_claim,
                &output.proof,
            )
            .is_err()
        );

        let mut reordered_claims = output.claimed_evaluations.clone();
        reordered_claims.swap(0, 3);
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &reordered_claims,
                &output.proof,
            )
            .is_err()
        );

        let mut wrong_row_point_statement = statement.clone();
        let mut wrong_row_coordinates = wrong_row_point_statement.row_points[1].as_slice().to_vec();
        wrong_row_coordinates[2] += ChallengeField::ONE;
        wrong_row_point_statement.row_points[1] = Point::new(wrong_row_coordinates);
        assert!(
            verify_streaming_opening(
                geometry,
                &wrong_row_point_statement,
                &output.commitment,
                &output.claimed_evaluations,
                &output.proof,
            )
            .is_err()
        );

        let mut wrong_within_row_statement = statement.clone();
        let mut wrong_within_row_coordinates = wrong_within_row_statement
            .within_row_point
            .as_slice()
            .to_vec();
        wrong_within_row_coordinates[5] += ChallengeField::ONE;
        wrong_within_row_statement.within_row_point = Point::new(wrong_within_row_coordinates);
        assert!(
            verify_streaming_opening(
                geometry,
                &wrong_within_row_statement,
                &output.commitment,
                &output.claimed_evaluations,
                &output.proof,
            )
            .is_err()
        );

        let mut wrong_commitment = output.commitment;
        wrong_commitment.column_root[0] ^= 1;
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &wrong_commitment,
                &output.claimed_evaluations,
                &output.proof,
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_column_and_aggregate_forgery_attempts() {
        let geometry = RowEncodingGeometry::new(8, 14).expect("valid integration geometry");
        let rows = deterministic_rows(geometry);
        let statement = sample_statement(geometry);
        let source = |row_index: usize| Ok(rows[row_index].clone());
        let output = prove_test_opening(&source, geometry, &statement, &[43; 32])
            .expect("generate complete streaming proof");

        let mut changed_value = output.proof.clone();
        changed_value.authenticated_columns[0].values[0] += Goldilocks::ONE;
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &output.claimed_evaluations,
                &changed_value,
            )
            .is_err()
        );

        let mut changed_frontier = output.proof.clone();
        changed_frontier.column_frontier[0][0] ^= 1;
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &output.claimed_evaluations,
                &changed_frontier,
            )
            .is_err()
        );

        let mut truncated_frontier = output.proof.clone();
        truncated_frontier.column_frontier.pop();
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &output.claimed_evaluations,
                &truncated_frontier,
            )
            .is_err()
        );

        let mut changed_order = output.proof.clone();
        changed_order.authenticated_columns.swap(0, 1);
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &output.claimed_evaluations,
                &changed_order,
            )
            .is_err()
        );

        let mut changed_aggregate_evaluation = output.proof.clone();
        let changed_evaluation = changed_aggregate_evaluation.aggregate_opening_proof.evals[1]
            .current()[0]
            + ChallengeField::ONE;
        changed_aggregate_evaluation.aggregate_opening_proof.evals[1] =
            p3_sumcheck::OpeningBatch::new(vec![changed_evaluation], Vec::new());
        assert!(
            verify_streaming_opening(
                geometry,
                &statement,
                &output.commitment,
                &output.claimed_evaluations,
                &changed_aggregate_evaluation,
            )
            .is_err()
        );
    }

    #[test]
    fn prover_rejects_a_source_that_changes_between_passes() {
        let geometry = RowEncodingGeometry::new(8, 14).expect("valid integration geometry");
        let rows = deterministic_rows(geometry);
        let statement = sample_statement(geometry);
        let read_count = Cell::new(0_usize);
        let source = |row_index: usize| {
            let current_read = read_count.get();
            read_count.set(current_read + 1);
            let mut row = rows[row_index].clone();
            if current_read >= 3 * geometry.row_count && row_index == 0 {
                row[0] += Goldilocks::ONE;
            }
            Ok(row)
        };
        let error = prove_test_opening(&source, geometry, &statement, &[53; 32])
            .err()
            .expect("changed source must be rejected");
        assert!(error.contains("differs from the first-pass commitment"));
    }

    #[test]
    fn query_indices_are_distinct_deterministic_and_in_range() {
        let binding = b"query derivation test";
        let first =
            derive_post_commitment_challenges(binding, 1 << 20).expect("valid query geometry");
        let second =
            derive_post_commitment_challenges(binding, 1 << 20).expect("valid query geometry");
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
        assert_eq!(first.1.len(), COLUMN_QUERY_COUNT);
        for (position, index) in first.1.iter().enumerate() {
            assert!(*index < 1 << 20);
            assert!(!first.1[..position].contains(index));
        }
    }

    #[test]
    fn query_count_is_minimal_for_the_strict_outer_soundness_margin() {
        assert_eq!(ROW_CODE_LOG_INV_RATE, 2);
        let numerator =
            BigUint::from(5_u8).pow(COLUMN_QUERY_COUNT as u32) << COLUMN_QUERY_SOUNDNESS_BITS;
        let denominator = BigUint::from(8_u8).pow(COLUMN_QUERY_COUNT as u32);
        assert!(numerator < denominator);

        let previous_numerator =
            BigUint::from(5_u8).pow((COLUMN_QUERY_COUNT - 1) as u32) << COLUMN_QUERY_SOUNDNESS_BITS;
        let previous_denominator = BigUint::from(8_u8).pow((COLUMN_QUERY_COUNT - 1) as u32);
        assert!(previous_numerator >= previous_denominator);
    }

    #[test]
    fn target_queries_leave_a_full_rank_secret_pad_submatrix() {
        let geometry = RowEncodingGeometry::new(1 << 10, 16).expect("target row geometry");
        let (_, query_indices) = derive_post_commitment_challenges(
            b"target secret-pad rank certificate",
            geometry.encoded_column_count,
        )
        .expect("derive target query indices");
        assert_eq!(query_indices.len(), COLUMN_QUERY_COUNT);
        assert!(query_indices.len() <= geometry.pad_value_count());

        // Restrict the opened-pad evaluation matrix to its first q columns.
        // Its determinant is diag(x_i^N) times a Vandermonde determinant, so
        // nonzero distinct coset points prove rank q without materializing a
        // 387-by-65,536 matrix in the test process.
        let points = query_indices
            .iter()
            .map(|column_index| {
                coset_point(
                    geometry.encoded_column_count.ilog2() as usize,
                    *column_index,
                )
                .expect("query index gives a valid coset point")
            })
            .collect::<Vec<_>>();
        let mut determinant = Goldilocks::ONE;
        for (point_index, point) in points.iter().enumerate() {
            determinant *= point.exp_u64(geometry.witness_values_per_row as u64);
            for previous_point in &points[..point_index] {
                determinant *= *point - *previous_point;
            }
        }
        assert_ne!(determinant, Goldilocks::ZERO);
    }

    #[test]
    fn target_interleaved_code_batching_error_has_wide_field_margin() {
        let geometry = RowEncodingGeometry::new(1 << 10, 16).expect("target row geometry");
        let challenge_field_order = BigUint::from(GOLDILOCKS_MODULUS).pow(5);

        // BCIKS20, Theorem 3.1 and Remark 1.2 give M / |F_ext| for the
        // random extension-field combination of an M-symbol interleaved word.
        assert!(
            (BigUint::from(geometry.encoded_column_count) << 298_usize) < challenge_field_order
        );
        assert!((BigUint::from(1_u8) << 319_usize) < challenge_field_order);
    }

    #[test]
    fn streaming_wire_rejects_truncation_trailing_bytes_and_wrong_schema() {
        let geometry = RowEncodingGeometry::new(8, 14).expect("valid integration geometry");
        let rows = deterministic_rows(geometry);
        let statement = sample_statement(geometry);
        let source = |row_index: usize| Ok(rows[row_index].clone());
        let output = prove_test_opening(&source, geometry, &statement, &[61; 32])
            .expect("generate complete streaming proof");
        let canonical = encode_streaming_prover_output(geometry, &output)
            .expect("encode canonical streaming proof");

        let frontier_count_offset = STREAMING_WIRE_MAGIC.len()
            + core::mem::size_of::<ColumnDigest>()
            + core::mem::size_of::<u32>()
            + output.claimed_evaluations.len()
                * CHALLENGE_FIELD_LIMB_COUNT
                * core::mem::size_of::<u64>()
            + core::mem::size_of::<ColumnDigest>()
            + COLUMN_QUERY_COUNT * geometry.row_count * core::mem::size_of::<u64>();
        assert_eq!(
            u32::from_le_bytes(
                canonical[frontier_count_offset..frontier_count_offset + 4]
                    .try_into()
                    .expect("the frontier-count slice has canonical u32 width")
            ) as usize,
            output.proof.column_frontier.len(),
        );
        let mut missing_frontier_payload = canonical[..frontier_count_offset + 4].to_vec();
        missing_frontier_payload[frontier_count_offset..frontier_count_offset + 4]
            .copy_from_slice(&1_u32.to_le_bytes());
        let missing_frontier_error =
            decode_streaming_prover_output(geometry, &missing_frontier_payload)
                .err()
                .expect("a declared frontier without node bytes must be rejected");
        assert!(
            missing_frontier_error.contains("truncated before 1 column frontier nodes"),
            "unexpected missing-frontier error: {missing_frontier_error}"
        );

        let mut truncated = canonical.clone();
        truncated.pop();
        assert!(decode_streaming_prover_output(geometry, &truncated).is_err());

        let mut with_trailing_byte = canonical.clone();
        with_trailing_byte.push(0);
        assert!(decode_streaming_prover_output(geometry, &with_trailing_byte).is_err());

        let mut wrong_schema = canonical;
        wrong_schema[0] ^= 1;
        assert!(decode_streaming_prover_output(geometry, &wrong_schema).is_err());
    }
}
