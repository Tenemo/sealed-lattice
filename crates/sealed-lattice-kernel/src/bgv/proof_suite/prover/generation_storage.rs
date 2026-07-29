//! Browser-compatible storage primitives used by construction-driven proof generation.

use zeroize::{Zeroize, Zeroizing};

use super::{
    CommonProofProverError, CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    ProofEvaluationDomain,
};
use crate::bgv::proof_suite::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryPlan,
    ProofExternalMemorySecretSealCustodyRequirement,
};
use crate::bgv::proof_suite::field::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement,
    ProofChallengeExtensionElement,
};
use crate::bgv::proof_suite::profile::ProofProfileError;
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationColumnValueType,
    RelationCompactTraceEncoding, RelationPlanCheckContext, RelationPlanError, RelationPlanVariant,
    RelationTreeDescriptor,
};
use crate::bgv::proof_suite::transcript::TranscriptError;
use crate::bgv::proof_suite::{
    CompiledRelationPlan, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    ProofLeafVisibility, ProofTreeRole, RelationProofTreeInput, StatementOwnedProofTreeInput,
};

const HASH_BYTE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofReplayPolynomialEncoding {
    CanonicalCoefficients,
    CompactBaseTrace {
        trace_value_count: usize,
        interval: RelationCompactTraceEncoding,
    },
}

impl CommonProofReplayPolynomialEncoding {
    pub(crate) fn exact_byte_length(
        self,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
    ) -> Result<u64, CommonProofProverError> {
        match self {
            Self::CanonicalCoefficients => u64::try_from(coefficient_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .checked_mul(resident_value_byte_length(value_type))
                .ok_or(CommonProofProverError::CountOverflow),
            Self::CompactBaseTrace {
                trace_value_count,
                interval,
            } => {
                if value_type != RelationColumnValueType::BaseField
                    || trace_value_count == 0
                    || !trace_value_count.is_power_of_two()
                    || trace_value_count > coefficient_count
                    || !(1..core::mem::size_of::<u64>() as u8)
                        .contains(&interval.encoded_value_byte_length())
                {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                let trace_byte_length = u64::try_from(trace_value_count)
                    .ok()
                    .and_then(|count| {
                        count.checked_mul(u64::from(interval.encoded_value_byte_length()))
                    })
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let tail_byte_length = u64::try_from(coefficient_count - trace_value_count)
                    .ok()
                    .and_then(|count| count.checked_mul(core::mem::size_of::<u64>() as u64))
                    .ok_or(CommonProofProverError::CountOverflow)?;
                trace_byte_length
                    .checked_add(tail_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)
            }
        }
    }
}

/// Complete application-owned inputs for one production proof attempt.
pub(crate) struct CommonProofGenerationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) source_polynomial_provider: Box<dyn CommonProofSourcePolynomialProvider>,
    pub(crate) maximum_external_memory_chunk_byte_length: u32,
    pub(crate) maximum_proof_transport_chunk_byte_length: usize,
    pub(crate) maximum_prefetched_query_byte_length: u64,
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationError<StorageError, CoinError, SinkError> {
    Prover(CommonProofProverError),
    Relation(RelationPlanError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
    Sink(SinkError),
}

impl<StorageError, CoinError, SinkError> core::fmt::Display
    for CommonProofGenerationError<StorageError, CoinError, SinkError>
where
    StorageError: core::fmt::Debug,
    CoinError: core::fmt::Debug,
    SinkError: core::fmt::Debug,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prover(error) => write!(formatter, "common proof prover failed: {error:?}"),
            Self::Relation(error) => write!(formatter, "common proof relation failed: {error:?}"),
            Self::Transcript(error) => {
                write!(formatter, "common proof transcript failed: {error:?}")
            }
            Self::StoragePlan(error) => {
                write!(formatter, "common proof storage plan failed: {error:?}")
            }
            Self::Storage(error) => write!(formatter, "common proof storage failed: {error:?}"),
            Self::CoinSource(error) => {
                write!(
                    formatter,
                    "common proof private coin source failed: {error:?}"
                )
            }
            Self::Sink(error) => write!(formatter, "common proof output sink failed: {error:?}"),
        }
    }
}

impl<StorageError, CoinError, SinkError> std::error::Error
    for CommonProofGenerationError<StorageError, CoinError, SinkError>
where
    StorageError: core::fmt::Debug,
    CoinError: core::fmt::Debug,
    SinkError: core::fmt::Debug,
{
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofExternalMemoryRequirement {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    secret_seal_custody_requirement: ProofExternalMemorySecretSealCustodyRequirement,
}

impl CommonProofExternalMemoryRequirement {
    pub(crate) fn from_external_memory_plan(
        plan: &ProofExternalMemoryPlan,
    ) -> Result<Self, ProofExternalMemoryError> {
        Ok(Self {
            step_count: plan.step_count(),
            maximum_chunk_byte_length: plan.maximum_chunk_byte_length(),
            maximum_transaction_payload_byte_length: plan.maximum_transaction_payload_byte_length(),
            distinct_physical_object_count: plan.physical_object_count()?,
            object_lifecycle_count: plan.object_lifecycle_count()?,
            peak_stored_byte_length: plan.maximum_stored_byte_length(),
            total_written_byte_length: plan.maximum_total_written_byte_length(),
            total_read_byte_length: plan.maximum_total_read_byte_length(),
            transaction_count: plan.maximum_transaction_count(),
            secret_seal_custody_requirement: plan.secret_seal_custody_requirement()?,
        })
    }

    pub(crate) const fn step_count(self) -> u32 {
        self.step_count
    }

    pub(crate) const fn maximum_chunk_byte_length(self) -> u32 {
        self.maximum_chunk_byte_length
    }

    pub(crate) const fn maximum_transaction_payload_byte_length(self) -> u64 {
        self.maximum_transaction_payload_byte_length
    }

    pub(crate) const fn distinct_physical_object_count(self) -> u32 {
        self.distinct_physical_object_count
    }

    pub(crate) const fn object_lifecycle_count(self) -> u32 {
        self.object_lifecycle_count
    }

    pub(crate) const fn peak_stored_byte_length(self) -> u64 {
        self.peak_stored_byte_length
    }

    pub(crate) const fn total_written_byte_length(self) -> u64 {
        self.total_written_byte_length
    }

    pub(crate) const fn total_read_byte_length(self) -> u64 {
        self.total_read_byte_length
    }

    pub(crate) const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    pub(crate) const fn local_record_seal_invocation_count(self) -> u64 {
        self.secret_seal_custody_requirement
            .local_record_seal_invocation_count()
    }

    pub(crate) const fn local_record_sealed_plaintext_byte_length(self) -> u64 {
        self.secret_seal_custody_requirement
            .local_record_sealed_plaintext_byte_length()
    }

    #[cfg(test)]
    pub(crate) const fn exceeds_active_root_seal_custody_budget(self) -> bool {
        self.secret_seal_custody_requirement
            .exceeds_active_root_budget()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofReplayPolynomialPlan {
    object: ProofExternalMemoryObject,
    object_byte_offset: u64,
    seals_object: bool,
    value_type: RelationColumnValueType,
    coefficient_count: usize,
    encoding: CommonProofReplayPolynomialEncoding,
    exact_byte_length: u64,
}

impl CommonProofReplayPolynomialPlan {
    pub(crate) fn new(
        object: ProofExternalMemoryObject,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
    ) -> Result<Self, CommonProofProverError> {
        Self::for_object_segment(object, 0, true, value_type, coefficient_count)
    }

    pub(crate) fn for_object_segment(
        object: ProofExternalMemoryObject,
        object_byte_offset: u64,
        seals_object: bool,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
    ) -> Result<Self, CommonProofProverError> {
        Self::for_object_segment_with_encoding(
            object,
            object_byte_offset,
            seals_object,
            value_type,
            coefficient_count,
            CommonProofReplayPolynomialEncoding::CanonicalCoefficients,
        )
    }

    pub(crate) fn for_object_segment_with_encoding(
        object: ProofExternalMemoryObject,
        object_byte_offset: u64,
        seals_object: bool,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
        encoding: CommonProofReplayPolynomialEncoding,
    ) -> Result<Self, CommonProofProverError> {
        if coefficient_count == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let exact_byte_length = encoding.exact_byte_length(value_type, coefficient_count)?;
        object_byte_offset
            .checked_add(exact_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if !object_byte_offset.is_multiple_of(core::mem::size_of::<u64>() as u64) {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            object,
            object_byte_offset,
            seals_object,
            value_type,
            coefficient_count,
            encoding,
            exact_byte_length,
        })
    }

    pub(crate) const fn exact_byte_length(self) -> u64 {
        self.exact_byte_length
    }

    pub(crate) const fn object(self) -> ProofExternalMemoryObject {
        self.object
    }

    pub(crate) const fn object_byte_offset(self) -> u64 {
        self.object_byte_offset
    }

    pub(crate) const fn seals_object(self) -> bool {
        self.seals_object
    }

    pub(crate) const fn value_type(self) -> RelationColumnValueType {
        self.value_type
    }

    pub(crate) const fn coefficient_count(self) -> usize {
        self.coefficient_count
    }
}

pub(crate) enum CommonProofReplayPolynomialRef<'polynomial> {
    Source(&'polynomial CommonProofSourcePolynomial),
}

impl CommonProofReplayPolynomialRef<'_> {
    fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Source(polynomial) => polynomial.value_type(),
        }
    }

    fn coefficient_count(&self) -> usize {
        match self {
            Self::Source(polynomial) => polynomial.coefficient_count(),
        }
    }

    fn append_coefficient_bytes(&self, coefficient_index: usize, destination: &mut Vec<u8>) {
        match self {
            Self::Source(CommonProofSourcePolynomial::Base(coefficients)) => {
                destination.extend_from_slice(
                    &coefficients
                        .get(coefficient_index)
                        .copied()
                        .unwrap_or(ProofBaseFieldElement::ZERO)
                        .canonical()
                        .to_le_bytes(),
                );
            }
            Self::Source(CommonProofSourcePolynomial::Extension(coefficients)) => {
                append_extension_coefficient_bytes(
                    coefficients
                        .get(coefficient_index)
                        .copied()
                        .unwrap_or(ProofChallengeExtensionElement::ZERO),
                    destination,
                );
            }
        }
    }
}

fn append_extension_coefficient_bytes(
    coefficient: ProofChallengeExtensionElement,
    destination: &mut Vec<u8>,
) {
    for coordinate in coefficient.canonical_coordinates() {
        destination.extend_from_slice(&coordinate.to_le_bytes());
    }
}

fn compact_trace_signed_value(
    value: ProofBaseFieldElement,
    interval: RelationCompactTraceEncoding,
) -> Result<i128, CommonProofProverError> {
    let positive = i128::from(value.canonical());
    let negative = positive - i128::from(PROOF_BASE_FIELD_MODULUS);
    let positive_is_in_interval = (interval.minimum()..=interval.maximum()).contains(&positive);
    let negative_is_in_interval = (interval.minimum()..=interval.maximum()).contains(&negative);
    match (positive_is_in_interval, negative_is_in_interval) {
        (true, false) => Ok(positive),
        (false, true) => Ok(negative),
        _ => Err(CommonProofProverError::InvalidColumn),
    }
}

fn encode_compact_base_trace_polynomial(
    polynomial: CommonProofReplayPolynomialRef<'_>,
    coefficient_count: usize,
    trace_value_count: usize,
    interval: RelationCompactTraceEncoding,
) -> Result<Zeroizing<Vec<u8>>, CommonProofProverError> {
    let CommonProofReplayPolynomialRef::Source(CommonProofSourcePolynomial::Base(coefficients)) =
        polynomial
    else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    if coefficients.is_empty()
        || coefficients.len() > coefficient_count
        || trace_value_count > coefficient_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }

    let encoding = CommonProofReplayPolynomialEncoding::CompactBaseTrace {
        trace_value_count,
        interval,
    };
    let exact_byte_length = usize::try_from(
        encoding.exact_byte_length(RelationColumnValueType::BaseField, coefficient_count)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut trace_values = Vec::new();
    trace_values
        .try_reserve_exact(trace_value_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    trace_values.resize(trace_value_count, ProofBaseFieldElement::ZERO);
    for coefficient_index in 0..coefficient_count {
        let coefficient = coefficients
            .get(coefficient_index)
            .copied()
            .unwrap_or(ProofBaseFieldElement::ZERO);
        let reduced_index = coefficient_index % trace_value_count;
        trace_values[reduced_index] = trace_values[reduced_index].add(coefficient);
    }
    ProofEvaluationDomain::new_subgroup(trace_value_count)?
        .evaluate_base_polynomial_in_place(&mut trace_values)?;

    let encoded_value_byte_length = usize::from(interval.encoded_value_byte_length());
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(exact_byte_length)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for value in trace_values {
        let signed_value = compact_trace_signed_value(value, interval)?;
        let offset = u64::try_from(signed_value - interval.minimum())
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let encoded_offset = offset.to_le_bytes();
        if encoded_offset[encoded_value_byte_length..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        encoded.extend_from_slice(&encoded_offset[..encoded_value_byte_length]);
    }
    for coefficient_index in trace_value_count..coefficient_count {
        encoded.extend_from_slice(
            &coefficients
                .get(coefficient_index)
                .copied()
                .unwrap_or(ProofBaseFieldElement::ZERO)
                .canonical()
                .to_le_bytes(),
        );
    }
    if encoded.len() != exact_byte_length {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(encoded)
}

fn decode_compact_base_trace_polynomial(
    encoded: &[u8],
    coefficient_count: usize,
    trace_value_count: usize,
    interval: RelationCompactTraceEncoding,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, ProofExternalMemoryError> {
    let exact_byte_length = usize::try_from(
        CommonProofReplayPolynomialEncoding::CompactBaseTrace {
            trace_value_count,
            interval,
        }
        .exact_byte_length(RelationColumnValueType::BaseField, coefficient_count)
        .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
    )
    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
    if encoded.len() != exact_byte_length {
        return Err(ProofExternalMemoryError::WrongOffsetOrLength);
    }

    let encoded_value_byte_length = usize::from(interval.encoded_value_byte_length());
    let trace_byte_length = trace_value_count
        .checked_mul(encoded_value_byte_length)
        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
    let inclusive_interval_width = u128::try_from(interval.maximum() - interval.minimum())
        .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
    let mut coefficients = Zeroizing::new(Vec::new());
    coefficients
        .try_reserve_exact(coefficient_count)
        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
    for encoded_value in encoded[..trace_byte_length].chunks_exact(encoded_value_byte_length) {
        let mut offset_bytes = [0_u8; core::mem::size_of::<u64>()];
        offset_bytes[..encoded_value_byte_length].copy_from_slice(encoded_value);
        let offset = u64::from_le_bytes(offset_bytes);
        if u128::from(offset) > inclusive_interval_width {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        }
        let signed_value = interval
            .minimum()
            .checked_add(i128::from(offset))
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let canonical = if signed_value >= 0 {
            u64::try_from(signed_value).map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?
        } else {
            PROOF_BASE_FIELD_MODULUS
                .checked_sub(
                    u64::try_from(-signed_value)
                        .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                )
                .ok_or(ProofExternalMemoryError::InvalidLifecycle)?
        };
        coefficients.push(
            ProofBaseFieldElement::from_canonical(canonical)
                .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
        );
    }
    ProofEvaluationDomain::new_subgroup(trace_value_count)
        .and_then(|domain| domain.interpolate_base_polynomial_in_place(&mut coefficients))
        .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
    coefficients.resize(coefficient_count, ProofBaseFieldElement::ZERO);

    for (tail_ordinal, encoded_coefficient) in encoded[trace_byte_length..]
        .chunks_exact(core::mem::size_of::<u64>())
        .enumerate()
    {
        let coefficient_index = trace_value_count
            .checked_add(tail_ordinal)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let canonical = u64::from_le_bytes(
            encoded_coefficient
                .try_into()
                .map_err(|_| ProofExternalMemoryError::WrongOffsetOrLength)?,
        );
        let tail_coefficient = ProofBaseFieldElement::from_canonical(canonical)
            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
        let reduced_index = coefficient_index % trace_value_count;
        coefficients[reduced_index] = coefficients[reduced_index].subtract(tail_coefficient);
        coefficients[coefficient_index] = tail_coefficient;
    }
    Ok(coefficients)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayPolynomialWriterPhase {
    Begin,
    Append,
    Seal,
    Complete,
}

pub(crate) struct CommonProofReplayPolynomialWriter {
    plan: CommonProofReplayPolynomialPlan,
    phase: CommonProofReplayPolynomialWriterPhase,
    committed_byte_offset: usize,
    coefficient_bytes: Zeroizing<Vec<u8>>,
    compact_encoded_bytes: Zeroizing<Vec<u8>>,
    write_chunk: Zeroizing<Vec<u8>>,
}

impl CommonProofReplayPolynomialWriter {
    pub(crate) fn new(
        plan: CommonProofReplayPolynomialPlan,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = plan
            .encoding
            .exact_byte_length(plan.value_type, plan.coefficient_count)?;
        if polynomial.value_type() != plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > plan.coefficient_count
            || expected_byte_length != plan.exact_byte_length
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if let CommonProofReplayPolynomialEncoding::CompactBaseTrace {
            trace_value_count, ..
        } = plan.encoding
        {
            let source_byte_length = u64::try_from(plan.coefficient_count)
                .ok()
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>() as u64))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let trace_byte_length = u64::try_from(trace_value_count)
                .ok()
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>() as u64))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let encoding_peak = source_byte_length
                .checked_add(trace_byte_length)
                .and_then(|length| length.checked_add(plan.exact_byte_length))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let writing_peak = source_byte_length
                .checked_add(plan.exact_byte_length)
                .and_then(|length| {
                    length.checked_add(u64::from(
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    ))
                })
                .ok_or(CommonProofProverError::CountOverflow)?;
            if encoding_peak.max(writing_peak) > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
                return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
            }
        }
        let compact_encoded_bytes = match plan.encoding {
            CommonProofReplayPolynomialEncoding::CanonicalCoefficients => {
                Zeroizing::new(Vec::new())
            }
            CommonProofReplayPolynomialEncoding::CompactBaseTrace {
                trace_value_count,
                interval,
            } => encode_compact_base_trace_polynomial(
                polynomial,
                plan.coefficient_count,
                trace_value_count,
                interval,
            )?,
        };
        Ok(Self {
            plan,
            phase: if plan.object_byte_offset == 0 {
                CommonProofReplayPolynomialWriterPhase::Begin
            } else {
                CommonProofReplayPolynomialWriterPhase::Append
            },
            committed_byte_offset: 0,
            coefficient_bytes: Zeroizing::new(Vec::new()),
            compact_encoded_bytes,
            write_chunk: Zeroizing::new(Vec::new()),
        })
    }

    fn prepare_next_write_chunk(
        &mut self,
        polynomial: CommonProofReplayPolynomialRef<'_>,
        maximum_chunk_byte_length: usize,
    ) -> Result<usize, ProofExternalMemoryError> {
        let exact_byte_length = usize::try_from(self.plan.exact_byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        if maximum_chunk_byte_length == 0 || self.committed_byte_offset >= exact_byte_length {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        }
        let prepared_byte_offset = self
            .committed_byte_offset
            .checked_add(maximum_chunk_byte_length)
            .map_or(exact_byte_length, |offset| offset.min(exact_byte_length));
        let prepared_byte_length = prepared_byte_offset
            .checked_sub(self.committed_byte_offset)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;

        self.write_chunk.zeroize();
        self.write_chunk
            .try_reserve_exact(prepared_byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        match self.plan.encoding {
            CommonProofReplayPolynomialEncoding::CanonicalCoefficients => {
                let value_byte_length =
                    usize::try_from(resident_value_byte_length(self.plan.value_type))
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                if value_byte_length == 0 {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
                let mut source_byte_offset = self.committed_byte_offset;
                while source_byte_offset < prepared_byte_offset {
                    let coefficient_index = source_byte_offset / value_byte_length;
                    let coefficient_byte_offset = source_byte_offset % value_byte_length;
                    self.coefficient_bytes.zeroize();
                    self.coefficient_bytes
                        .try_reserve_exact(value_byte_length)
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    polynomial
                        .append_coefficient_bytes(coefficient_index, &mut self.coefficient_bytes);
                    if self.coefficient_bytes.len() != value_byte_length {
                        return Err(ProofExternalMemoryError::InvalidLifecycle);
                    }
                    let copied_byte_length = (value_byte_length - coefficient_byte_offset)
                        .min(prepared_byte_offset - source_byte_offset);
                    let coefficient_end = coefficient_byte_offset
                        .checked_add(copied_byte_length)
                        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    self.write_chunk.extend_from_slice(
                        &self.coefficient_bytes[coefficient_byte_offset..coefficient_end],
                    );
                    source_byte_offset = source_byte_offset
                        .checked_add(copied_byte_length)
                        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                }
            }
            CommonProofReplayPolynomialEncoding::CompactBaseTrace { .. } => {
                if self.compact_encoded_bytes.len() != exact_byte_length {
                    return Err(ProofExternalMemoryError::InvalidLifecycle);
                }
                self.write_chunk.extend_from_slice(
                    &self.compact_encoded_bytes[self.committed_byte_offset..prepared_byte_offset],
                );
            }
        }
        if self.write_chunk.len() != prepared_byte_length {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        }
        Ok(prepared_byte_offset)
    }

    pub(crate) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if polynomial.value_type() != self.plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > self.plan.coefficient_count
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        match self.phase {
            CommonProofReplayPolynomialWriterPhase::Begin => {
                executor.begin_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Append;
                Ok(false)
            }
            CommonProofReplayPolynomialWriterPhase::Append => {
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                let prepared_byte_offset =
                    self.prepare_next_write_chunk(polynomial, maximum_chunk_byte_length)?;
                executor.append_owned_object_bytes(
                    storage,
                    self.plan.object,
                    &mut self.write_chunk,
                )?;
                self.write_chunk.zeroize();
                self.committed_byte_offset = prepared_byte_offset;
                if u64::try_from(self.committed_byte_offset)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
                    == self.plan.exact_byte_length
                {
                    self.compact_encoded_bytes.zeroize();
                    self.compact_encoded_bytes.clear();
                    if self.plan.seals_object {
                        self.phase = CommonProofReplayPolynomialWriterPhase::Seal;
                    } else {
                        self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            CommonProofReplayPolynomialWriterPhase::Seal => {
                executor.seal_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                Ok(true)
            }
            CommonProofReplayPolynomialWriterPhase::Complete => Ok(true),
        }
    }
}

enum CommonProofReplayPolynomialCoefficients {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

pub(crate) enum CommonProofReplayPolynomialRangeDestination<'destination> {
    Base(&'destination mut [ProofBaseFieldElement]),
    Extension(&'destination mut [ProofChallengeExtensionElement]),
}

impl CommonProofReplayPolynomialRangeDestination<'_> {
    const fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Base(_) => RelationColumnValueType::BaseField,
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    const fn coefficient_count(&self) -> usize {
        match self {
            Self::Base(coefficients) => coefficients.len(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    fn decode_canonical_chunk(
        &mut self,
        destination_coefficient_offset: usize,
        coefficient_count: usize,
        encoded: &[u8],
    ) -> Result<(), ProofExternalMemoryError> {
        let destination_coefficient_end = destination_coefficient_offset
            .checked_add(coefficient_count)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        match self {
            Self::Base(coefficients) => {
                let destination = coefficients
                    .get_mut(destination_coefficient_offset..destination_coefficient_end)
                    .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
                let expected_byte_length = coefficient_count
                    .checked_mul(core::mem::size_of::<u64>())
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                if encoded.len() != expected_byte_length {
                    return Err(ProofExternalMemoryError::WrongOffsetOrLength);
                }
                for (destination, canonical) in destination.iter_mut().zip(encoded.chunks_exact(8))
                {
                    let canonical: [u8; 8] = canonical
                        .try_into()
                        .map_err(|_| ProofExternalMemoryError::WrongOffsetOrLength)?;
                    *destination =
                        ProofBaseFieldElement::from_canonical(u64::from_le_bytes(canonical))
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
                }
            }
            Self::Extension(coefficients) => {
                let destination = coefficients
                    .get_mut(destination_coefficient_offset..destination_coefficient_end)
                    .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
                let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
                    .checked_mul(core::mem::size_of::<u64>())
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                let expected_byte_length = coefficient_count
                    .checked_mul(value_byte_length)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                if encoded.len() != expected_byte_length {
                    return Err(ProofExternalMemoryError::WrongOffsetOrLength);
                }
                for (destination, encoded_coefficient) in destination
                    .iter_mut()
                    .zip(encoded.chunks_exact(value_byte_length))
                {
                    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                    for (coordinate, canonical) in coordinates
                        .iter_mut()
                        .zip(encoded_coefficient.chunks_exact(8))
                    {
                        let canonical: [u8; 8] = canonical
                            .try_into()
                            .map_err(|_| ProofExternalMemoryError::WrongOffsetOrLength)?;
                        *coordinate = u64::from_le_bytes(canonical);
                    }
                    *destination =
                        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
                }
            }
        }
        Ok(())
    }
}

/// Pollable reader for one checked coefficient range of a replay polynomial.
pub(crate) struct CommonProofReplayPolynomialRangeReader {
    plan: CommonProofReplayPolynomialPlan,
    coefficient_range: core::ops::Range<usize>,
    next_coefficient_index: usize,
    compact_encoded_bytes: Zeroizing<Vec<u8>>,
    next_compact_encoded_byte_offset: usize,
}

impl CommonProofReplayPolynomialRangeReader {
    pub(crate) fn new(
        plan: CommonProofReplayPolynomialPlan,
        coefficient_range: core::ops::Range<usize>,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = plan
            .encoding
            .exact_byte_length(plan.value_type, plan.coefficient_count)?;
        if plan.coefficient_count == 0
            || expected_byte_length != plan.exact_byte_length
            || coefficient_range.start > coefficient_range.end
            || coefficient_range.end > plan.coefficient_count
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if matches!(
            plan.encoding,
            CommonProofReplayPolynomialEncoding::CompactBaseTrace { .. }
        ) {
            let decoded_polynomial_byte_length = u64::try_from(plan.coefficient_count)
                .ok()
                .and_then(|count| count.checked_mul(core::mem::size_of::<u64>() as u64))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let destination_byte_length =
                u64::try_from(coefficient_range.end - coefficient_range.start)
                    .ok()
                    .and_then(|count| count.checked_mul(core::mem::size_of::<u64>() as u64))
                    .ok_or(CommonProofProverError::CountOverflow)?;
            let decoding_peak = plan
                .exact_byte_length
                .checked_add(decoded_polynomial_byte_length)
                .and_then(|length| length.checked_add(destination_byte_length))
                .ok_or(CommonProofProverError::CountOverflow)?;
            if decoding_peak > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
                return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
            }
        }
        let next_coefficient_index = coefficient_range.start;
        Ok(Self {
            plan,
            coefficient_range,
            next_coefficient_index,
            compact_encoded_bytes: Zeroizing::new(Vec::new()),
            next_compact_encoded_byte_offset: 0,
        })
    }

    pub(crate) const fn requested_coefficient_count(&self) -> usize {
        self.coefficient_range.end - self.coefficient_range.start
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.next_coefficient_index == self.coefficient_range.end
    }

    pub(crate) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        mut destination: CommonProofReplayPolynomialRangeDestination<'_>,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if destination.value_type() != self.plan.value_type {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        if destination.coefficient_count() != self.requested_coefficient_count() {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        if self.is_complete() {
            return Ok(true);
        }

        if let CommonProofReplayPolynomialEncoding::CompactBaseTrace {
            trace_value_count,
            interval,
        } = self.plan.encoding
        {
            let CommonProofReplayPolynomialRangeDestination::Base(destination) = &mut destination
            else {
                return Err(ProofExternalMemoryError::InvalidLifecycle.into());
            };
            let exact_byte_length = usize::try_from(self.plan.exact_byte_length)
                .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
            if self.compact_encoded_bytes.is_empty() {
                self.compact_encoded_bytes
                    .try_reserve_exact(exact_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                self.compact_encoded_bytes.resize(exact_byte_length, 0);
            }
            if self.compact_encoded_bytes.len() != exact_byte_length
                || self.next_compact_encoded_byte_offset >= exact_byte_length
            {
                return Err(ProofExternalMemoryError::InvalidLifecycle.into());
            }
            let read_byte_length = usize::try_from(executor.maximum_chunk_byte_length())
                .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
                .min(exact_byte_length - self.next_compact_encoded_byte_offset);
            let next_encoded_byte_offset = self
                .next_compact_encoded_byte_offset
                .checked_add(read_byte_length)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            let object_byte_offset = self
                .plan
                .object_byte_offset
                .checked_add(
                    u64::try_from(self.next_compact_encoded_byte_offset)
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?,
                )
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            executor.read_object_bytes(
                storage,
                self.plan.object,
                object_byte_offset,
                &mut self.compact_encoded_bytes
                    [self.next_compact_encoded_byte_offset..next_encoded_byte_offset],
            )?;
            self.next_compact_encoded_byte_offset = next_encoded_byte_offset;
            if next_encoded_byte_offset != exact_byte_length {
                return Ok(false);
            }

            let coefficients = decode_compact_base_trace_polynomial(
                &self.compact_encoded_bytes,
                self.plan.coefficient_count,
                trace_value_count,
                interval,
            )?;
            destination.copy_from_slice(
                coefficients
                    .get(self.coefficient_range.clone())
                    .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?,
            );
            self.compact_encoded_bytes.zeroize();
            self.compact_encoded_bytes.clear();
            self.next_coefficient_index = self.coefficient_range.end;
            return Ok(true);
        }

        let value_byte_length = usize::try_from(resident_value_byte_length(self.plan.value_type))
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let maximum_coefficient_count = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let coefficient_count =
            maximum_coefficient_count.min(self.coefficient_range.end - self.next_coefficient_index);
        let byte_length = coefficient_count
            .checked_mul(value_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        encoded.resize(byte_length, 0);
        let polynomial_byte_offset = self
            .next_coefficient_index
            .checked_mul(value_byte_length)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let polynomial_byte_end = polynomial_byte_offset
            .checked_add(
                u64::try_from(byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?,
            )
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if polynomial_byte_end > self.plan.exact_byte_length {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let object_byte_offset = self
            .plan
            .object_byte_offset
            .checked_add(polynomial_byte_offset)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        executor.read_object_bytes(storage, self.plan.object, object_byte_offset, &mut encoded)?;

        let destination_coefficient_offset = self
            .next_coefficient_index
            .checked_sub(self.coefficient_range.start)
            .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
        destination.decode_canonical_chunk(
            destination_coefficient_offset,
            coefficient_count,
            &encoded,
        )?;
        self.next_coefficient_index = self
            .next_coefficient_index
            .checked_add(coefficient_count)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        Ok(self.is_complete())
    }
}

pub(crate) struct CommonProofReplayPolynomialReader {
    range_reader: CommonProofReplayPolynomialRangeReader,
    coefficients: CommonProofReplayPolynomialCoefficients,
}

impl CommonProofReplayPolynomialReader {
    pub(crate) fn new(
        plan: CommonProofReplayPolynomialPlan,
    ) -> Result<Self, CommonProofProverError> {
        let range_reader =
            CommonProofReplayPolynomialRangeReader::new(plan, 0..plan.coefficient_count)?;
        let coefficients = match plan.value_type {
            RelationColumnValueType::BaseField => {
                CommonProofReplayPolynomialCoefficients::Base(Zeroizing::new(Vec::new()))
            }
            RelationColumnValueType::ChallengeExtension => {
                CommonProofReplayPolynomialCoefficients::Extension(Zeroizing::new(Vec::new()))
            }
        };
        Ok(Self {
            range_reader,
            coefficients,
        })
    }

    pub(crate) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        match &mut self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(coefficients) => {
                if coefficients.is_empty() {
                    coefficients
                        .try_reserve_exact(self.range_reader.requested_coefficient_count())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    coefficients.resize(
                        self.range_reader.requested_coefficient_count(),
                        ProofBaseFieldElement::ZERO,
                    );
                }
                self.range_reader.advance(
                    executor,
                    storage,
                    CommonProofReplayPolynomialRangeDestination::Base(coefficients),
                )
            }
            CommonProofReplayPolynomialCoefficients::Extension(coefficients) => {
                if coefficients.is_empty() {
                    coefficients
                        .try_reserve_exact(self.range_reader.requested_coefficient_count())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    coefficients.resize(
                        self.range_reader.requested_coefficient_count(),
                        ProofChallengeExtensionElement::ZERO,
                    );
                }
                self.range_reader.advance(
                    executor,
                    storage,
                    CommonProofReplayPolynomialRangeDestination::Extension(coefficients),
                )
            }
        }
    }

    pub(crate) fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if !self.range_reader.is_complete() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(match self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(mut coefficients) => {
                trim_base_polynomial(&mut coefficients);
                CommonProofSourcePolynomial::Base(coefficients)
            }
            CommonProofReplayPolynomialCoefficients::Extension(mut coefficients) => {
                trim_extension_polynomial(&mut coefficients);
                CommonProofSourcePolynomial::Extension(coefficients)
            }
        })
    }
}

pub(crate) fn validate_generation_relation_trees(
    variant: &RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<(), CommonProofProverError> {
    if relation_trees.len() != variant.ordered_trees().len() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for (descriptor, input) in variant.ordered_trees().iter().zip(relation_trees) {
        match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let expected_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let expected_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|index| variant.ordered_columns().get(index))
                        .is_some_and(|column| column.origin() == &RelationColumnOrigin::Prover)
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                if *tree_role != expected_role
                    || *row_width != expected_width
                    || *leaf_visibility != expected_visibility
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                validate_generation_tree_columns(variant, ordered_column_ordinals, None)?;
            }
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                validate_generation_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let construction_matches = match (construction_kind, statement_tree) {
                    (
                        BoundTreeConstructionKind::CommittedMaterial,
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                    ) => ordered_column_ordinals.len() == 4,
                    (
                        BoundTreeConstructionKind::SetupPolynomial,
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                    ) => usize::try_from(*row_width)
                        .is_ok_and(|width| width == ordered_column_ordinals.len()),
                    _ => false,
                };
                if !construction_matches {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        }
    }
    Ok(())
}

fn validate_generation_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for column_ordinal in ordered_column_ordinals {
        let column = variant
            .ordered_columns()
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofProverError::InvalidTree);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofProverError::InvalidTree);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationInitializationError {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    StoragePlan(ProofExternalMemoryError),
}

/// Absolute WebAssembly-memory safety bound, distinct from phone qualification targets.
pub(crate) const MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH: u64 = 671_088_640;

const fn resident_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => core::mem::size_of::<u64>() as u64,
        RelationColumnValueType::ChallengeExtension => {
            (PROOF_CHALLENGE_EXTENSION_DEGREE * core::mem::size_of::<u64>()) as u64
        }
    }
}

fn trim_base_polynomial(coefficients: &mut Vec<ProofBaseFieldElement>) {
    while coefficients.len() > 1 && coefficients.last() == Some(&ProofBaseFieldElement::ZERO) {
        coefficients.pop();
    }
}

fn trim_extension_polynomial(coefficients: &mut Vec<ProofChallengeExtensionElement>) {
    while coefficients.len() > 1
        && coefficients.last() == Some(&ProofChallengeExtensionElement::ZERO)
    {
        coefficients.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_field_element_from_signed(value: i64) -> ProofBaseFieldElement {
        let canonical = if value >= 0 {
            value as u64
        } else {
            PROOF_BASE_FIELD_MODULUS - value.unsigned_abs()
        };
        ProofBaseFieldElement::from_canonical(canonical).expect("test value is canonical")
    }

    fn masked_polynomial_with_bounded_trace() -> (
        Vec<ProofBaseFieldElement>,
        RelationCompactTraceEncoding,
        usize,
    ) {
        let trace_values = [-8_i64, -1, 0, 1, 4, 15, 7, -4]
            .into_iter()
            .map(base_field_element_from_signed)
            .collect::<Vec<_>>();
        let trace_value_count = trace_values.len();
        let coefficient_count = 19;
        let mut coefficients = ProofEvaluationDomain::new_subgroup(trace_value_count)
            .expect("test subgroup exists")
            .interpolate_base_polynomial(&trace_values)
            .expect("bounded trace interpolates");
        coefficients.resize(coefficient_count, ProofBaseFieldElement::ZERO);
        for coefficient_index in trace_value_count..coefficient_count {
            let tail_coefficient = ProofBaseFieldElement::from_canonical(
                10_003 + u64::try_from(coefficient_index).expect("test index fits u64") * 97,
            )
            .expect("test mask coefficient is canonical");
            let reduced_index = coefficient_index % trace_value_count;
            coefficients[reduced_index] = coefficients[reduced_index].subtract(tail_coefficient);
            coefficients[coefficient_index] = tail_coefficient;
        }
        (
            coefficients,
            RelationCompactTraceEncoding::new_for_test(-8, 15, 1),
            trace_value_count,
        )
    }

    #[test]
    fn compact_trace_and_mask_tail_round_trip_exact_coefficients() {
        let (coefficients, interval, trace_value_count) = masked_polynomial_with_bounded_trace();
        let polynomial = CommonProofSourcePolynomial::Base(coefficients.clone().into());
        let encoded = encode_compact_base_trace_polynomial(
            CommonProofReplayPolynomialRef::Source(&polynomial),
            coefficients.len(),
            trace_value_count,
            interval,
        )
        .expect("bounded trace and complete mask tail encode");
        assert_eq!(
            encoded.len(),
            trace_value_count + (coefficients.len() - trace_value_count) * 8
        );
        assert!(encoded.len() < coefficients.len() * 8);

        let decoded = decode_compact_base_trace_polynomial(
            &encoded,
            coefficients.len(),
            trace_value_count,
            interval,
        )
        .expect("compact replay decodes");
        assert_eq!(&*decoded, coefficients.as_slice());
        assert_eq!(
            &decoded[3..17],
            &coefficients[3..17],
            "a non-aligned replay range retains low coefficients and the mask tail",
        );
    }

    #[test]
    fn compact_trace_codec_rejects_out_of_interval_and_noncanonical_values() {
        let (coefficients, interval, trace_value_count) = masked_polynomial_with_bounded_trace();
        let polynomial = CommonProofSourcePolynomial::Base(coefficients.clone().into());
        let encoded = encode_compact_base_trace_polynomial(
            CommonProofReplayPolynomialRef::Source(&polynomial),
            coefficients.len(),
            trace_value_count,
            interval,
        )
        .expect("valid compact replay encodes");

        let mut out_of_interval_trace = encoded.to_vec();
        out_of_interval_trace[0] = 24;
        assert_eq!(
            decode_compact_base_trace_polynomial(
                &out_of_interval_trace,
                coefficients.len(),
                trace_value_count,
                interval,
            ),
            Err(ProofExternalMemoryError::InvalidLifecycle),
        );

        let mut noncanonical_tail = encoded.to_vec();
        noncanonical_tail[trace_value_count..trace_value_count + 8]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_eq!(
            decode_compact_base_trace_polynomial(
                &noncanonical_tail,
                coefficients.len(),
                trace_value_count,
                interval,
            ),
            Err(ProofExternalMemoryError::InvalidLifecycle),
        );

        let outside_polynomial = CommonProofSourcePolynomial::Base(
            vec![ProofBaseFieldElement::from_canonical(16).expect("test value is canonical")]
                .into(),
        );
        assert_eq!(
            encode_compact_base_trace_polynomial(
                CommonProofReplayPolynomialRef::Source(&outside_polynomial),
                trace_value_count,
                trace_value_count,
                interval,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
    }

    #[test]
    fn compact_trace_plan_rejects_non_base_and_non_compact_widths() {
        let object = ProofExternalMemoryObject::new(0);
        for encoded_value_byte_length in [0, 8, u8::MAX] {
            let encoding = CommonProofReplayPolynomialEncoding::CompactBaseTrace {
                trace_value_count: 8,
                interval: RelationCompactTraceEncoding::new_for_test(
                    -1,
                    1,
                    encoded_value_byte_length,
                ),
            };
            assert_eq!(
                CommonProofReplayPolynomialPlan::for_object_segment_with_encoding(
                    object,
                    0,
                    true,
                    RelationColumnValueType::BaseField,
                    8,
                    encoding,
                ),
                Err(CommonProofProverError::InvalidColumn),
            );
        }
        assert_eq!(
            CommonProofReplayPolynomialPlan::for_object_segment_with_encoding(
                object,
                0,
                true,
                RelationColumnValueType::ChallengeExtension,
                8,
                CommonProofReplayPolynomialEncoding::CompactBaseTrace {
                    trace_value_count: 8,
                    interval: RelationCompactTraceEncoding::new_for_test(-1, 1, 1),
                },
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
    }

    #[test]
    fn packed_writer_preserves_compact_and_canonical_segment_boundaries() {
        let (coefficients, interval, trace_value_count) = masked_polynomial_with_bounded_trace();
        let compact_polynomial = CommonProofSourcePolynomial::Base(coefficients.clone().into());
        let object = ProofExternalMemoryObject::new(0);
        let compact_plan = CommonProofReplayPolynomialPlan::for_object_segment_with_encoding(
            object,
            0,
            false,
            RelationColumnValueType::BaseField,
            coefficients.len(),
            CommonProofReplayPolynomialEncoding::CompactBaseTrace {
                trace_value_count,
                interval,
            },
        )
        .expect("compact segment plan derives");
        let expected_compact_bytes = encode_compact_base_trace_polynomial(
            CommonProofReplayPolynomialRef::Source(&compact_polynomial),
            coefficients.len(),
            trace_value_count,
            interval,
        )
        .expect("compact segment encodes");
        assert_eq!(compact_plan.exact_byte_length(), 96);

        let canonical_coefficients = [17_u64, 29, 43]
            .into_iter()
            .map(|value| {
                ProofBaseFieldElement::from_canonical(value).expect("test value is canonical")
            })
            .collect::<Vec<_>>();
        let canonical_polynomial =
            CommonProofSourcePolynomial::Base(canonical_coefficients.clone().into());
        let canonical_plan = CommonProofReplayPolynomialPlan::for_object_segment(
            object,
            compact_plan.exact_byte_length(),
            true,
            RelationColumnValueType::BaseField,
            canonical_coefficients.len(),
        )
        .expect("canonical segment plan derives");

        let mut observed_bytes = Vec::new();
        let mut observed_chunk_lengths = Vec::new();
        let mut compact_writer = CommonProofReplayPolynomialWriter::new(
            compact_plan,
            CommonProofReplayPolynomialRef::Source(&compact_polynomial),
        )
        .expect("compact writer initializes");
        while compact_writer.committed_byte_offset
            < usize::try_from(compact_plan.exact_byte_length()).expect("compact length fits usize")
        {
            let prepared_byte_offset = compact_writer
                .prepare_next_write_chunk(
                    CommonProofReplayPolynomialRef::Source(&compact_polynomial),
                    64,
                )
                .expect("compact chunk prepares");
            observed_chunk_lengths.push(compact_writer.write_chunk.len());
            observed_bytes.extend_from_slice(&compact_writer.write_chunk);
            compact_writer.committed_byte_offset = prepared_byte_offset;
        }

        let mut canonical_writer = CommonProofReplayPolynomialWriter::new(
            canonical_plan,
            CommonProofReplayPolynomialRef::Source(&canonical_polynomial),
        )
        .expect("canonical writer initializes");
        let prepared_byte_offset = canonical_writer
            .prepare_next_write_chunk(
                CommonProofReplayPolynomialRef::Source(&canonical_polynomial),
                64,
            )
            .expect("canonical chunk prepares");
        observed_chunk_lengths.push(canonical_writer.write_chunk.len());
        observed_bytes.extend_from_slice(&canonical_writer.write_chunk);
        canonical_writer.committed_byte_offset = prepared_byte_offset;

        let mut expected_bytes = expected_compact_bytes.to_vec();
        for coefficient in canonical_coefficients {
            expected_bytes.extend_from_slice(&coefficient.canonical().to_le_bytes());
        }
        assert_eq!(observed_chunk_lengths, [64, 32, 24]);
        assert_eq!(observed_bytes, expected_bytes);
        assert_eq!(canonical_writer.committed_byte_offset, 24);
    }
}
