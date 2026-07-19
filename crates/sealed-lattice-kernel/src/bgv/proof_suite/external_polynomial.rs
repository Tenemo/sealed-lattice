//! Sequential external-memory polynomial transforms for the browser prover.
//!
//! Each Stockham pass writes one immutable, append-only object. A pass becomes
//! a checkpoint boundary only after the output is sealed and the executor has
//! completed the pass step, which transactionally deletes any input whose
//! caller-declared last use is that pass.
//! The implementation retains at most two input scan blocks, one encoded
//! output block, and one canonical external-memory write record; no resident
//! field grows with the transform domain.

use zeroize::{Zeroize, Zeroizing};

use super::external_memory::{
    EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH,
    ProofExternalMemoryTransactionOperation,
};
use super::relation_plan::RelationColumnValueType;
use super::{
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ProofExternalMemory, ProofExternalMemoryError,
    ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
    ProofExternalMemoryObjectPlan, ProofExternalMemoryProtection, ProofFieldError,
};

const BASE_FIELD_ELEMENT_BYTE_LENGTH: usize = 8;
const EXTENSION_FIELD_ELEMENT_BYTE_LENGTH: usize = PROOF_CHALLENGE_EXTENSION_DEGREE * 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalPolynomialError {
    InvalidDomain,
    InvalidVector,
    InvalidPlan,
    WrongTransformStep,
    CountOverflow,
    AllocationLimitExceeded,
    Field(ProofFieldError),
}

impl From<ProofFieldError> for ExternalPolynomialError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalPolynomialVector {
    object: ProofExternalMemoryObject,
    value_type: RelationColumnValueType,
    element_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalPolynomialValue {
    Base(ProofBaseFieldElement),
    Extension(ProofChallengeExtensionElement),
}

impl ExternalPolynomialVector {
    pub(crate) fn new(
        object: ProofExternalMemoryObject,
        value_type: RelationColumnValueType,
        element_count: usize,
    ) -> Result<Self, ExternalPolynomialError> {
        if element_count == 0 {
            return Err(ExternalPolynomialError::InvalidVector);
        }
        Ok(Self {
            object,
            value_type,
            element_count,
        })
    }

    pub(crate) const fn object(self) -> ProofExternalMemoryObject {
        self.object
    }

    pub(crate) const fn value_type(self) -> RelationColumnValueType {
        self.value_type
    }

    pub(crate) const fn element_count(self) -> usize {
        self.element_count
    }

    pub(crate) fn exact_byte_length(self) -> Result<u64, ExternalPolynomialError> {
        u64::try_from(self.element_count)
            .ok()
            .and_then(|count| count.checked_mul(external_value_byte_length(self.value_type)))
            .ok_or(ExternalPolynomialError::CountOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalStockhamTransformDirection {
    Forward,
    Inverse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalStockhamPassPlan {
    input: ExternalPolynomialVector,
    output: ExternalPolynomialVector,
    stage_ordinal: u32,
    executor_step: u32,
}

impl ExternalStockhamPassPlan {
    pub(crate) const fn input(self) -> ExternalPolynomialVector {
        self.input
    }

    pub(crate) const fn output(self) -> ExternalPolynomialVector {
        self.output
    }

    pub(crate) const fn stage_ordinal(self) -> u32 {
        self.stage_ordinal
    }

    pub(crate) const fn executor_step(self) -> u32 {
        self.executor_step
    }
}

/// Planner output for one complete radix-two transform. The source object plan
/// is owned by the caller because its issuance and earlier uses precede this
/// transform. Its declared last use may be this transform's first pass or a
/// later use by another transform or proof phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalStockhamTransformPlan {
    domain: ProofEvaluationDomain,
    direction: ExternalStockhamTransformDirection,
    passes: Vec<ExternalStockhamPassPlan>,
    object_plans: Vec<ProofExternalMemoryObjectPlan>,
    final_output: ExternalPolynomialVector,
    next_object_ordinal: u32,
    next_executor_step: u32,
    maximum_scan_element_count: usize,
    maximum_resident_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count_excluding_deletions: u64,
}

impl ExternalStockhamTransformPlan {
    pub(crate) fn resident_owned_payload_byte_length(
        &self,
    ) -> Result<u64, ExternalPolynomialError> {
        let pass_catalog_byte_length = u64::try_from(self.passes.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ExternalStockhamPassPlan>()).ok()?,
                )
            })
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let object_plan_catalog_byte_length = u64::try_from(self.object_plans.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(std::mem::size_of::<ProofExternalMemoryObjectPlan>()).ok()?,
                )
            })
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        pass_catalog_byte_length
            .checked_add(object_plan_catalog_byte_length)
            .ok_or(ExternalPolynomialError::CountOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalStockhamResidentMemoryRequirement {
    component_working_set_byte_length: u64,
    transaction_overlap_peak_byte_length: u64,
    peak_byte_length: u64,
}

impl ExternalStockhamResidentMemoryRequirement {
    pub(crate) const fn component_working_set_byte_length(self) -> u64 {
        self.component_working_set_byte_length
    }

    pub(crate) const fn transaction_overlap_peak_byte_length(self) -> u64 {
        self.transaction_overlap_peak_byte_length
    }

    pub(crate) const fn peak_byte_length(self) -> u64 {
        self.peak_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalPolynomialExtensionReadResidentMemoryRequirement {
    component_working_set_byte_length: u64,
    transaction_overlap_peak_byte_length: u64,
    peak_byte_length: u64,
}

impl ExternalPolynomialExtensionReadResidentMemoryRequirement {
    pub(crate) const fn component_working_set_byte_length(self) -> u64 {
        self.component_working_set_byte_length
    }

    pub(crate) const fn transaction_overlap_peak_byte_length(self) -> u64 {
        self.transaction_overlap_peak_byte_length
    }

    pub(crate) const fn peak_byte_length(self) -> u64 {
        self.peak_byte_length
    }
}

pub(crate) fn external_polynomial_extension_read_resident_memory_requirement(
    value_type: RelationColumnValueType,
    element_count: u64,
) -> Result<ExternalPolynomialExtensionReadResidentMemoryRequirement, ExternalPolynomialError> {
    if element_count == 0 {
        return Err(ExternalPolynomialError::InvalidVector);
    }
    let encoded_byte_length = element_count
        .checked_mul(external_value_byte_length(value_type))
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let typed_value_byte_length = element_count
        .checked_mul(
            u64::try_from(match value_type {
                RelationColumnValueType::BaseField => core::mem::size_of::<ProofBaseFieldElement>(),
                RelationColumnValueType::ChallengeExtension => {
                    core::mem::size_of::<ProofChallengeExtensionElement>()
                }
            })
            .map_err(|_| ExternalPolynomialError::CountOverflow)?,
        )
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let extension_output_byte_length = element_count
        .checked_mul(
            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
        )
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let conversion_overlap_byte_length = match value_type {
        RelationColumnValueType::BaseField => typed_value_byte_length
            .checked_add(extension_output_byte_length)
            .ok_or(ExternalPolynomialError::CountOverflow)?,
        RelationColumnValueType::ChallengeExtension => typed_value_byte_length,
    };
    let component_working_set_byte_length = typed_value_byte_length
        .checked_add(encoded_byte_length)
        .ok_or(ExternalPolynomialError::CountOverflow)?
        .max(conversion_overlap_byte_length);
    let operation_allocation_byte_length =
        u64::try_from(core::mem::size_of::<ProofExternalMemoryTransactionOperation>())
            .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let read_result_allocation_byte_length =
        u64::try_from(core::mem::size_of::<Zeroizing<Vec<u8>>>())
            .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let transaction_overlap_peak_byte_length = typed_value_byte_length
        .checked_add(
            encoded_byte_length
                .checked_mul(2)
                .ok_or(ExternalPolynomialError::CountOverflow)?,
        )
        .and_then(|length| length.checked_add(operation_allocation_byte_length))
        .and_then(|length| length.checked_add(read_result_allocation_byte_length))
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    Ok(ExternalPolynomialExtensionReadResidentMemoryRequirement {
        component_working_set_byte_length,
        transaction_overlap_peak_byte_length,
        peak_byte_length: component_working_set_byte_length
            .max(transaction_overlap_peak_byte_length),
    })
}

pub(crate) fn external_stockham_resident_memory_requirement(
    scan_byte_length: u64,
    transaction_chunk_byte_length: u64,
) -> Result<ExternalStockhamResidentMemoryRequirement, ExternalPolynomialError> {
    if scan_byte_length == 0 || transaction_chunk_byte_length == 0 {
        return Err(ExternalPolynomialError::InvalidPlan);
    }
    // The transform owns two typed scan vectors, one encoded-output vector,
    // and one output-transaction chunk. A read additionally retains its local
    // encoded vector while replay owns the response bytes. An append request
    // retains the recorder's payload copy while operation encoding and final
    // worker-request encoding coexist. The operation and outer read-result
    // vector allocations are explicit so the plan does not rely on the
    // executor reserve to hide payload-sized transaction copies.
    let persistent_transform_byte_length = scan_byte_length
        .checked_mul(3)
        .and_then(|length| length.checked_add(transaction_chunk_byte_length))
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let component_working_set_byte_length = persistent_transform_byte_length
        .checked_add(scan_byte_length)
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let operation_allocation_byte_length =
        u64::try_from(core::mem::size_of::<ProofExternalMemoryTransactionOperation>())
            .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let read_result_allocation_byte_length =
        u64::try_from(core::mem::size_of::<Zeroizing<Vec<u8>>>())
            .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let replay_response_overlap_byte_length = persistent_transform_byte_length
        .checked_add(
            scan_byte_length
                .checked_mul(2)
                .ok_or(ExternalPolynomialError::CountOverflow)?,
        )
        .and_then(|length| length.checked_add(operation_allocation_byte_length))
        .and_then(|length| length.checked_add(read_result_allocation_byte_length))
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let request_framing_byte_length = u64::try_from(
        EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH
            .checked_mul(2)
            .and_then(|length| length.checked_add(EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH))
            .ok_or(ExternalPolynomialError::CountOverflow)?,
    )
    .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let append_request_overlap_byte_length = persistent_transform_byte_length
        .checked_add(
            transaction_chunk_byte_length
                .checked_mul(3)
                .ok_or(ExternalPolynomialError::CountOverflow)?,
        )
        .and_then(|length| length.checked_add(request_framing_byte_length))
        .and_then(|length| length.checked_add(operation_allocation_byte_length))
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let transaction_overlap_peak_byte_length =
        replay_response_overlap_byte_length.max(append_request_overlap_byte_length);
    Ok(ExternalStockhamResidentMemoryRequirement {
        component_working_set_byte_length,
        transaction_overlap_peak_byte_length,
        peak_byte_length: component_working_set_byte_length
            .max(transaction_overlap_peak_byte_length),
    })
}

impl ExternalStockhamTransformPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        domain: ProofEvaluationDomain,
        direction: ExternalStockhamTransformDirection,
        source: ExternalPolynomialVector,
        first_object_ordinal: u32,
        first_executor_step: u32,
        final_output_last_use_step: u32,
        maximum_chunk_byte_length: u32,
        protection: ProofExternalMemoryProtection,
    ) -> Result<Self, ExternalPolynomialError> {
        Self::new_with_optional_output_objects(
            domain,
            direction,
            source,
            first_object_ordinal,
            None,
            first_executor_step,
            final_output_last_use_step,
            maximum_chunk_byte_length,
            protection,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_output_objects(
        domain: ProofEvaluationDomain,
        direction: ExternalStockhamTransformDirection,
        source: ExternalPolynomialVector,
        output_objects: &[ProofExternalMemoryObject],
        first_executor_step: u32,
        final_output_last_use_step: u32,
        maximum_chunk_byte_length: u32,
        protection: ProofExternalMemoryProtection,
    ) -> Result<Self, ExternalPolynomialError> {
        Self::new_with_optional_output_objects(
            domain,
            direction,
            source,
            0,
            Some(output_objects),
            first_executor_step,
            final_output_last_use_step,
            maximum_chunk_byte_length,
            protection,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_optional_output_objects(
        domain: ProofEvaluationDomain,
        direction: ExternalStockhamTransformDirection,
        source: ExternalPolynomialVector,
        first_object_ordinal: u32,
        output_objects: Option<&[ProofExternalMemoryObject]>,
        first_executor_step: u32,
        final_output_last_use_step: u32,
        maximum_chunk_byte_length: u32,
        protection: ProofExternalMemoryProtection,
    ) -> Result<Self, ExternalPolynomialError> {
        let domain_size = domain.size();
        if domain_size < 2 || !domain_size.is_power_of_two() || source.element_count > domain_size {
            return Err(ExternalPolynomialError::InvalidDomain);
        }
        let value_byte_length = external_value_byte_length(source.value_type);
        let maximum_scan_element_count = u64::from(maximum_chunk_byte_length)
            .checked_div(value_byte_length)
            .and_then(|count| usize::try_from(count).ok())
            .filter(|count| *count != 0)
            .ok_or(ExternalPolynomialError::InvalidPlan)?;
        let pass_count = domain_size.trailing_zeros();
        let pass_count_usize =
            usize::try_from(pass_count).map_err(|_| ExternalPolynomialError::CountOverflow)?;
        if output_objects.is_some_and(|objects| {
            objects.len() != pass_count_usize
                || objects.iter().any(|object| *object == source.object())
                || objects.windows(2).any(|pair| pair[0] == pair[1])
        }) {
            return Err(ExternalPolynomialError::InvalidPlan);
        }
        let next_executor_step = first_executor_step
            .checked_add(pass_count)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        if final_output_last_use_step < next_executor_step {
            return Err(ExternalPolynomialError::InvalidPlan);
        }

        let output_exact_byte_length = u64::try_from(domain_size)
            .ok()
            .and_then(|count| count.checked_mul(value_byte_length))
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let mut passes = Vec::new();
        let mut object_plans = Vec::new();
        passes
            .try_reserve_exact(
                usize::try_from(pass_count).map_err(|_| ExternalPolynomialError::CountOverflow)?,
            )
            .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
        object_plans
            .try_reserve_exact(
                usize::try_from(pass_count).map_err(|_| ExternalPolynomialError::CountOverflow)?,
            )
            .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;

        let mut next_object_ordinal = first_object_ordinal;
        let mut input = source;
        let mut transaction_count_excluding_deletions = 0_u64;
        let mut total_read_byte_length = 0_u64;
        for stage_ordinal in 0..pass_count {
            let executor_step = first_executor_step
                .checked_add(stage_ordinal)
                .ok_or(ExternalPolynomialError::CountOverflow)?;
            let object = if let Some(objects) = output_objects {
                *objects
                    .get(
                        usize::try_from(stage_ordinal)
                            .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                    )
                    .ok_or(ExternalPolynomialError::InvalidPlan)?
            } else {
                let object = ProofExternalMemoryObject::new(next_object_ordinal);
                next_object_ordinal = next_object_ordinal
                    .checked_add(1)
                    .ok_or(ExternalPolynomialError::CountOverflow)?;
                object
            };
            let output = ExternalPolynomialVector::new(object, source.value_type, domain_size)?;
            let last_use_step = if stage_ordinal + 1 == pass_count {
                final_output_last_use_step
            } else {
                executor_step
                    .checked_add(1)
                    .ok_or(ExternalPolynomialError::CountOverflow)?
            };
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                protection,
                output_exact_byte_length,
                executor_step,
                executor_step,
                last_use_step,
            ));
            passes.push(ExternalStockhamPassPlan {
                input,
                output,
                stage_ordinal,
                executor_step,
            });

            let half_block_size = 1_usize
                .checked_shl(stage_ordinal)
                .ok_or(ExternalPolynomialError::CountOverflow)?;
            let output_chunk_count =
                output_exact_byte_length.div_ceil(u64::from(maximum_chunk_byte_length));
            let first_half_input_count = input.element_count.min(domain_size / 2);
            let second_half_input_count = input.element_count.saturating_sub(domain_size / 2);
            let read_transaction_count = chunked_prefix_read_count(
                first_half_input_count,
                half_block_size,
                maximum_scan_element_count,
            )?
            .checked_add(chunked_prefix_read_count(
                second_half_input_count,
                half_block_size,
                maximum_scan_element_count,
            )?)
            .and_then(|count| count.checked_mul(2))
            .ok_or(ExternalPolynomialError::CountOverflow)?;
            // Create, every nonempty input read, every canonical output-record
            // append, and seal. Deletions are planned globally because the
            // executor batches every object with the same exact last-use step
            // into one transaction.
            transaction_count_excluding_deletions = transaction_count_excluding_deletions
                .checked_add(
                    output_chunk_count
                        .checked_add(read_transaction_count)
                        .and_then(|count| count.checked_add(2))
                        .ok_or(ExternalPolynomialError::CountOverflow)?,
                )
                .ok_or(ExternalPolynomialError::CountOverflow)?;
            total_read_byte_length = total_read_byte_length
                .checked_add(
                    input
                        .exact_byte_length()?
                        .checked_mul(2)
                        .ok_or(ExternalPolynomialError::CountOverflow)?,
                )
                .ok_or(ExternalPolynomialError::CountOverflow)?;
            input = output;
        }
        let final_output = input;
        if let Some(objects) = output_objects {
            next_object_ordinal = objects
                .iter()
                .map(|object| object.ordinal())
                .max()
                .and_then(|ordinal| ordinal.checked_add(1))
                .ok_or(ExternalPolynomialError::InvalidPlan)?;
        }
        let pass_count_u64 = u64::from(pass_count);
        let total_written_byte_length = output_exact_byte_length
            .checked_mul(pass_count_u64)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let scan_byte_length = u64::try_from(maximum_scan_element_count)
            .ok()
            .and_then(|count| count.checked_mul(value_byte_length))
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let maximum_resident_byte_length = external_stockham_resident_memory_requirement(
            scan_byte_length,
            u64::from(maximum_chunk_byte_length),
        )?
        .peak_byte_length();

        Ok(Self {
            domain,
            direction,
            passes,
            object_plans,
            final_output,
            next_object_ordinal,
            next_executor_step,
            maximum_scan_element_count,
            maximum_resident_byte_length,
            total_written_byte_length,
            total_read_byte_length,
            transaction_count_excluding_deletions,
        })
    }

    pub(crate) fn passes(&self) -> &[ExternalStockhamPassPlan] {
        &self.passes
    }

    pub(crate) fn object_plans(&self) -> &[ProofExternalMemoryObjectPlan] {
        &self.object_plans
    }

    pub(crate) const fn final_output(&self) -> ExternalPolynomialVector {
        self.final_output
    }

    pub(crate) const fn next_object_ordinal(&self) -> u32 {
        self.next_object_ordinal
    }

    pub(crate) const fn next_executor_step(&self) -> u32 {
        self.next_executor_step
    }

    pub(crate) const fn maximum_scan_element_count(&self) -> usize {
        self.maximum_scan_element_count
    }

    pub(crate) const fn maximum_resident_byte_length(&self) -> u64 {
        self.maximum_resident_byte_length
    }

    pub(crate) const fn total_written_byte_length(&self) -> u64 {
        self.total_written_byte_length
    }

    pub(crate) const fn total_read_byte_length(&self) -> u64 {
        self.total_read_byte_length
    }

    pub(crate) const fn transaction_count_excluding_deletions(&self) -> u64 {
        self.transaction_count_excluding_deletions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalStockhamCheckpointBoundary {
    next_pass_ordinal: u32,
    next_executor_step: u32,
    sealed_input: ExternalPolynomialVector,
}

impl ExternalStockhamCheckpointBoundary {
    pub(crate) const fn next_pass_ordinal(self) -> u32 {
        self.next_pass_ordinal
    }

    pub(crate) const fn next_executor_step(self) -> u32 {
        self.next_executor_step
    }

    pub(crate) const fn sealed_input(self) -> ExternalPolynomialVector {
        self.sealed_input
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalStockhamTransformProgress {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    PassCommitted(ExternalStockhamCheckpointBoundary),
    Complete(ExternalPolynomialVector),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalStockhamTransformPhase {
    BeginOutput,
    ReadLeft,
    ReadRight,
    AppendOutput,
    FlushOutput,
    SealOutput,
    CompleteExecutorStep,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalStockhamOutputHalf {
    Sum,
    Difference,
}

enum ExternalPolynomialValues {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

impl ExternalPolynomialValues {
    fn with_capacity(
        value_type: RelationColumnValueType,
        capacity: usize,
    ) -> Result<Self, ExternalPolynomialError> {
        match value_type {
            RelationColumnValueType::BaseField => {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(capacity)
                    .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
                Ok(Self::Base(Zeroizing::new(values)))
            }
            RelationColumnValueType::ChallengeExtension => {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(capacity)
                    .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
                Ok(Self::Extension(Zeroizing::new(values)))
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Base(values) => values.len(),
            Self::Extension(values) => values.len(),
        }
    }

    fn clear(&mut self) {
        match self {
            Self::Base(values) => values.zeroize(),
            Self::Extension(values) => values.zeroize(),
        }
    }

    fn pad_with_zeros(
        &mut self,
        value_type: RelationColumnValueType,
        element_count: usize,
    ) -> Result<(), ExternalPolynomialError> {
        match (self, value_type) {
            (Self::Base(values), RelationColumnValueType::BaseField) => {
                if values.len() > element_count {
                    return Err(ExternalPolynomialError::InvalidVector);
                }
                values.resize(element_count, ProofBaseFieldElement::ZERO);
            }
            (Self::Extension(values), RelationColumnValueType::ChallengeExtension) => {
                if values.len() > element_count {
                    return Err(ExternalPolynomialError::InvalidVector);
                }
                values.resize(element_count, ProofChallengeExtensionElement::ZERO);
            }
            _ => return Err(ExternalPolynomialError::InvalidVector),
        }
        Ok(())
    }

    fn decode(
        &mut self,
        value_type: RelationColumnValueType,
        encoded: &[u8],
    ) -> Result<(), ExternalPolynomialError> {
        self.clear();
        let value_byte_length = usize::try_from(external_value_byte_length(value_type))
            .map_err(|_| ExternalPolynomialError::CountOverflow)?;
        if encoded.is_empty() || !encoded.len().is_multiple_of(value_byte_length) {
            return Err(ExternalPolynomialError::InvalidVector);
        }
        match (self, value_type) {
            (Self::Base(values), RelationColumnValueType::BaseField) => {
                for bytes in encoded.chunks_exact(BASE_FIELD_ELEMENT_BYTE_LENGTH) {
                    let mut canonical = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
                    canonical.copy_from_slice(bytes);
                    values.push(ProofBaseFieldElement::from_canonical(u64::from_le_bytes(
                        canonical,
                    ))?);
                }
            }
            (Self::Extension(values), RelationColumnValueType::ChallengeExtension) => {
                for bytes in encoded.chunks_exact(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH) {
                    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                    for (coordinate, coordinate_bytes) in
                        coordinates.iter_mut().zip(bytes.chunks_exact(8))
                    {
                        let mut canonical = [0_u8; 8];
                        canonical.copy_from_slice(coordinate_bytes);
                        *coordinate = u64::from_le_bytes(canonical);
                    }
                    values.push(ProofChallengeExtensionElement::from_canonical_coordinates(
                        coordinates,
                    )?);
                }
            }
            _ => return Err(ExternalPolynomialError::InvalidVector),
        }
        Ok(())
    }

    fn into_extension_values(
        self,
    ) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, ExternalPolynomialError> {
        match self {
            Self::Base(values) => {
                let mut extension_values = Vec::new();
                extension_values
                    .try_reserve_exact(values.len())
                    .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
                extension_values.extend(
                    values
                        .iter()
                        .copied()
                        .map(ProofChallengeExtensionElement::from_base),
                );
                Ok(Zeroizing::new(extension_values))
            }
            Self::Extension(values) => Ok(values),
        }
    }

    fn into_base_values(
        self,
    ) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, ExternalPolynomialError> {
        match self {
            Self::Base(values) => Ok(values),
            Self::Extension(_) => Err(ExternalPolynomialError::InvalidVector),
        }
    }
}

/// Pollable sequential Stockham transform. `PassCommitted` reports a safe pause
/// boundary where the cursor names the sole sealed prerequisite for the next
/// pass and no partial output object remains live. This cursor does not
/// serialize or restore the surrounding prover state.
pub(crate) struct ExternalStockhamTransform {
    plan: ExternalStockhamTransformPlan,
    next_pass_index: usize,
    phase: ExternalStockhamTransformPhase,
    output_half: ExternalStockhamOutputHalf,
    group_start: usize,
    offset_within_group: usize,
    current_block_element_count: usize,
    left_values: ExternalPolynomialValues,
    right_values: ExternalPolynomialValues,
    encoded_output: Zeroizing<Vec<u8>>,
    encoded_output_offset: usize,
    output_write_chunk: Zeroizing<Vec<u8>>,
}

impl ExternalStockhamTransform {
    pub(crate) fn new(
        plan: ExternalStockhamTransformPlan,
    ) -> Result<Self, ExternalPolynomialError> {
        let value_type = plan
            .passes
            .first()
            .map(|pass| pass.input.value_type)
            .ok_or(ExternalPolynomialError::InvalidPlan)?;
        let left_values =
            ExternalPolynomialValues::with_capacity(value_type, plan.maximum_scan_element_count)?;
        let right_values =
            ExternalPolynomialValues::with_capacity(value_type, plan.maximum_scan_element_count)?;
        let mut encoded_output = Zeroizing::new(Vec::new());
        encoded_output
            .try_reserve_exact(
                plan.maximum_scan_element_count
                    .checked_mul(
                        usize::try_from(external_value_byte_length(value_type))
                            .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                    )
                    .ok_or(ExternalPolynomialError::CountOverflow)?,
            )
            .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
        Ok(Self {
            plan,
            next_pass_index: 0,
            phase: ExternalStockhamTransformPhase::BeginOutput,
            output_half: ExternalStockhamOutputHalf::Sum,
            group_start: 0,
            offset_within_group: 0,
            current_block_element_count: 0,
            left_values,
            right_values,
            encoded_output,
            encoded_output_offset: 0,
            output_write_chunk: Zeroizing::new(Vec::new()),
        })
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<ExternalStockhamCheckpointBoundary> {
        if self.phase != ExternalStockhamTransformPhase::BeginOutput {
            return None;
        }
        let next_pass_ordinal = u32::try_from(self.next_pass_index).ok()?;
        let pass = self.plan.passes.get(self.next_pass_index)?;
        Some(ExternalStockhamCheckpointBoundary {
            next_pass_ordinal,
            next_executor_step: pass.executor_step,
            sealed_input: pass.input,
        })
    }

    pub(crate) const fn maximum_resident_byte_length(&self) -> u64 {
        self.plan.maximum_resident_byte_length
    }

    pub(crate) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<ExternalStockhamTransformProgress, ExternalStockhamTransformError<Storage::Error>>
    {
        if self.phase == ExternalStockhamTransformPhase::Complete {
            return Ok(ExternalStockhamTransformProgress::Complete(
                self.plan.final_output,
            ));
        }
        let pass = *self
            .plan
            .passes
            .get(self.next_pass_index)
            .ok_or(ExternalPolynomialError::InvalidPlan)?;
        if executor.current_step() != pass.executor_step {
            return Err(ExternalPolynomialError::WrongTransformStep.into());
        }
        match self.phase {
            ExternalStockhamTransformPhase::BeginOutput => {
                if !self.encoded_output.is_empty()
                    || self.encoded_output_offset != 0
                    || !self.output_write_chunk.is_empty()
                {
                    return Err(ExternalPolynomialError::InvalidPlan.into());
                }
                executor.begin_object(storage, pass.output.object)?;
                self.output_half = ExternalStockhamOutputHalf::Sum;
                self.group_start = 0;
                self.offset_within_group = 0;
                self.phase = ExternalStockhamTransformPhase::ReadLeft;
                Ok(ExternalStockhamTransformProgress::StorageTransactionCompleted)
            }
            ExternalStockhamTransformPhase::ReadLeft => {
                let (offset, element_count) = self.next_input_block(pass)?;
                self.current_block_element_count = element_count;
                let did_read = read_external_values(
                    executor,
                    storage,
                    pass.input,
                    offset,
                    element_count,
                    &mut self.left_values,
                )?;
                self.phase = ExternalStockhamTransformPhase::ReadRight;
                Ok(if did_read {
                    ExternalStockhamTransformProgress::StorageTransactionCompleted
                } else {
                    ExternalStockhamTransformProgress::ArithmeticStepCompleted
                })
            }
            ExternalStockhamTransformPhase::ReadRight => {
                let (left_offset, element_count) = self.next_input_block(pass)?;
                if element_count != self.current_block_element_count {
                    return Err(ExternalPolynomialError::InvalidPlan.into());
                }
                let right_offset = left_offset
                    .checked_add(self.plan.domain.size() / 2)
                    .ok_or(ExternalPolynomialError::CountOverflow)?;
                let did_read = read_external_values(
                    executor,
                    storage,
                    pass.input,
                    right_offset,
                    element_count,
                    &mut self.right_values,
                )?;
                self.phase = ExternalStockhamTransformPhase::AppendOutput;
                Ok(if did_read {
                    ExternalStockhamTransformProgress::StorageTransactionCompleted
                } else {
                    ExternalStockhamTransformProgress::ArithmeticStepCompleted
                })
            }
            ExternalStockhamTransformPhase::AppendOutput => {
                if self.encoded_output.is_empty() {
                    self.encode_current_output_block(pass)?;
                    self.encoded_output_offset = 0;
                }
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ExternalPolynomialError::CountOverflow)?;
                if maximum_chunk_byte_length == 0
                    || self.output_write_chunk.len() > maximum_chunk_byte_length
                    || self.encoded_output_offset > self.encoded_output.len()
                {
                    return Err(ExternalPolynomialError::InvalidPlan.into());
                }
                let remaining_chunk_capacity =
                    maximum_chunk_byte_length - self.output_write_chunk.len();
                self.output_write_chunk
                    .try_reserve_exact(remaining_chunk_capacity)
                    .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
                let copied_byte_length = remaining_chunk_capacity
                    .min(self.encoded_output.len() - self.encoded_output_offset);
                let encoded_output_end = self
                    .encoded_output_offset
                    .checked_add(copied_byte_length)
                    .ok_or(ExternalPolynomialError::CountOverflow)?;
                self.output_write_chunk.extend_from_slice(
                    &self.encoded_output[self.encoded_output_offset..encoded_output_end],
                );
                self.encoded_output_offset = encoded_output_end;
                let encoded_block_is_buffered =
                    self.encoded_output_offset == self.encoded_output.len();
                if self.output_write_chunk.len() == maximum_chunk_byte_length {
                    executor.append_object_bytes(
                        storage,
                        pass.output.object,
                        &self.output_write_chunk,
                    )?;
                    self.output_write_chunk.zeroize();
                    if encoded_block_is_buffered {
                        self.encoded_output.zeroize();
                        self.encoded_output_offset = 0;
                        self.advance_scan_cursor(pass)?;
                    }
                    return Ok(ExternalStockhamTransformProgress::StorageTransactionCompleted);
                }
                if !encoded_block_is_buffered {
                    return Err(ExternalPolynomialError::InvalidVector.into());
                }
                self.encoded_output.zeroize();
                self.encoded_output_offset = 0;
                self.advance_scan_cursor(pass)?;
                Ok(ExternalStockhamTransformProgress::ArithmeticStepCompleted)
            }
            ExternalStockhamTransformPhase::FlushOutput => {
                if self.output_write_chunk.is_empty() {
                    self.phase = ExternalStockhamTransformPhase::SealOutput;
                    return Ok(ExternalStockhamTransformProgress::ArithmeticStepCompleted);
                }
                executor.append_object_bytes(
                    storage,
                    pass.output.object,
                    &self.output_write_chunk,
                )?;
                self.output_write_chunk.zeroize();
                self.phase = ExternalStockhamTransformPhase::SealOutput;
                Ok(ExternalStockhamTransformProgress::StorageTransactionCompleted)
            }
            ExternalStockhamTransformPhase::SealOutput => {
                executor.seal_object(storage, pass.output.object)?;
                self.phase = ExternalStockhamTransformPhase::CompleteExecutorStep;
                Ok(ExternalStockhamTransformProgress::StorageTransactionCompleted)
            }
            ExternalStockhamTransformPhase::CompleteExecutorStep => {
                executor.complete_step(storage)?;
                self.next_pass_index = self
                    .next_pass_index
                    .checked_add(1)
                    .ok_or(ExternalPolynomialError::CountOverflow)?;
                if self.next_pass_index == self.plan.passes.len() {
                    self.phase = ExternalStockhamTransformPhase::Complete;
                    Ok(ExternalStockhamTransformProgress::Complete(
                        self.plan.final_output,
                    ))
                } else {
                    self.phase = ExternalStockhamTransformPhase::BeginOutput;
                    let next_pass = self.plan.passes[self.next_pass_index];
                    Ok(ExternalStockhamTransformProgress::PassCommitted(
                        ExternalStockhamCheckpointBoundary {
                            next_pass_ordinal: u32::try_from(self.next_pass_index)
                                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                            next_executor_step: next_pass.executor_step,
                            sealed_input: next_pass.input,
                        },
                    ))
                }
            }
            ExternalStockhamTransformPhase::Complete => Ok(
                ExternalStockhamTransformProgress::Complete(self.plan.final_output),
            ),
        }
    }

    fn next_input_block(
        &self,
        pass: ExternalStockhamPassPlan,
    ) -> Result<(usize, usize), ExternalPolynomialError> {
        let half_block_size = 1_usize
            .checked_shl(pass.stage_ordinal)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        if self.group_start >= self.plan.domain.size() / 2
            || self.offset_within_group >= half_block_size
        {
            return Err(ExternalPolynomialError::InvalidPlan);
        }
        let element_count = self
            .plan
            .maximum_scan_element_count
            .min(half_block_size - self.offset_within_group);
        let offset = self
            .group_start
            .checked_add(self.offset_within_group)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        Ok((offset, element_count))
    }

    fn encode_current_output_block(
        &mut self,
        pass: ExternalStockhamPassPlan,
    ) -> Result<(), ExternalPolynomialError> {
        if self.left_values.len() != self.current_block_element_count
            || self.right_values.len() != self.current_block_element_count
        {
            return Err(ExternalPolynomialError::InvalidVector);
        }
        self.encoded_output.clear();
        let domain_size = self.plan.domain.size();
        let half_block_size = 1_usize
            .checked_shl(pass.stage_ordinal)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let transform_root = match self.plan.direction {
            ExternalStockhamTransformDirection::Forward => self.plan.domain.generator(),
            ExternalStockhamTransformDirection::Inverse => {
                self.plan.domain.generator().inverse()?
            }
        };
        let twiddle_exponent_step = domain_size
            .checked_div(
                half_block_size
                    .checked_mul(2)
                    .ok_or(ExternalPolynomialError::CountOverflow)?,
            )
            .ok_or(ExternalPolynomialError::InvalidDomain)?;
        let first_twiddle_exponent = self
            .offset_within_group
            .checked_mul(twiddle_exponent_step)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let mut twiddle = transform_root.power(
            u64::try_from(first_twiddle_exponent)
                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
        );
        let twiddle_step = transform_root.power(
            u64::try_from(twiddle_exponent_step)
                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
        );
        let output_start = self
            .group_start
            .checked_mul(2)
            .and_then(|start| {
                start.checked_add(match self.output_half {
                    ExternalStockhamOutputHalf::Sum => 0,
                    ExternalStockhamOutputHalf::Difference => half_block_size,
                })
            })
            .and_then(|start| start.checked_add(self.offset_within_group))
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        let is_final_inverse_pass = self.plan.direction
            == ExternalStockhamTransformDirection::Inverse
            && self.next_pass_index + 1 == self.plan.passes.len();
        let inverse_domain_size = if is_final_inverse_pass {
            Some(
                ProofBaseFieldElement::from_canonical(
                    u64::try_from(domain_size)
                        .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                )?
                .inverse()?,
            )
        } else {
            None
        };
        let inverse_coset_offset = if is_final_inverse_pass {
            Some(self.plan.domain.coset_offset().inverse()?)
        } else {
            None
        };

        match (&self.left_values, &self.right_values) {
            (ExternalPolynomialValues::Base(left), ExternalPolynomialValues::Base(right)) => {
                for (block_offset, (left, right)) in
                    left.iter().copied().zip(right.iter().copied()).enumerate()
                {
                    let input_index = self
                        .group_start
                        .checked_add(self.offset_within_group)
                        .and_then(|index| index.checked_add(block_offset))
                        .ok_or(ExternalPolynomialError::CountOverflow)?;
                    let (left, right) = if self.plan.direction
                        == ExternalStockhamTransformDirection::Forward
                        && self.next_pass_index == 0
                    {
                        let left_scale = self.plan.domain.coset_offset().power(
                            u64::try_from(input_index)
                                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                        );
                        let right_scale = self.plan.domain.coset_offset().power(
                            u64::try_from(
                                input_index
                                    .checked_add(domain_size / 2)
                                    .ok_or(ExternalPolynomialError::CountOverflow)?,
                            )
                            .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                        );
                        (left.multiply(left_scale), right.multiply(right_scale))
                    } else {
                        (left, right)
                    };
                    let product = right.multiply(twiddle);
                    let mut output = match self.output_half {
                        ExternalStockhamOutputHalf::Sum => left.add(product),
                        ExternalStockhamOutputHalf::Difference => left.subtract(product),
                    };
                    if let (Some(inverse_size), Some(inverse_offset)) =
                        (inverse_domain_size, inverse_coset_offset)
                    {
                        let output_index = output_start
                            .checked_add(block_offset)
                            .ok_or(ExternalPolynomialError::CountOverflow)?;
                        output = output.multiply(inverse_size).multiply(
                            inverse_offset.power(
                                u64::try_from(output_index)
                                    .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                            ),
                        );
                    }
                    self.encoded_output
                        .extend_from_slice(&output.canonical().to_le_bytes());
                    twiddle = twiddle.multiply(twiddle_step);
                }
            }
            (
                ExternalPolynomialValues::Extension(left),
                ExternalPolynomialValues::Extension(right),
            ) => {
                for (block_offset, (left, right)) in
                    left.iter().copied().zip(right.iter().copied()).enumerate()
                {
                    let input_index = self
                        .group_start
                        .checked_add(self.offset_within_group)
                        .and_then(|index| index.checked_add(block_offset))
                        .ok_or(ExternalPolynomialError::CountOverflow)?;
                    let (left, right) = if self.plan.direction
                        == ExternalStockhamTransformDirection::Forward
                        && self.next_pass_index == 0
                    {
                        let left_scale = self.plan.domain.coset_offset().power(
                            u64::try_from(input_index)
                                .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                        );
                        let right_scale = self.plan.domain.coset_offset().power(
                            u64::try_from(
                                input_index
                                    .checked_add(domain_size / 2)
                                    .ok_or(ExternalPolynomialError::CountOverflow)?,
                            )
                            .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                        );
                        (
                            left.multiply_base(left_scale),
                            right.multiply_base(right_scale),
                        )
                    } else {
                        (left, right)
                    };
                    let product = right.multiply_base(twiddle);
                    let mut output = match self.output_half {
                        ExternalStockhamOutputHalf::Sum => left.add(product),
                        ExternalStockhamOutputHalf::Difference => left.subtract(product),
                    };
                    if let (Some(inverse_size), Some(inverse_offset)) =
                        (inverse_domain_size, inverse_coset_offset)
                    {
                        let output_index = output_start
                            .checked_add(block_offset)
                            .ok_or(ExternalPolynomialError::CountOverflow)?;
                        output = output.multiply_base(inverse_size).multiply_base(
                            inverse_offset.power(
                                u64::try_from(output_index)
                                    .map_err(|_| ExternalPolynomialError::CountOverflow)?,
                            ),
                        );
                    }
                    for coordinate in output.canonical_coordinates() {
                        self.encoded_output
                            .extend_from_slice(&coordinate.to_le_bytes());
                    }
                    twiddle = twiddle.multiply(twiddle_step);
                }
            }
            _ => return Err(ExternalPolynomialError::InvalidVector),
        }
        if self.encoded_output.is_empty()
            || self.encoded_output.len()
                > usize::try_from(external_value_byte_length(pass.output.value_type))
                    .map_err(|_| ExternalPolynomialError::CountOverflow)?
                    .checked_mul(self.plan.maximum_scan_element_count)
                    .ok_or(ExternalPolynomialError::CountOverflow)?
        {
            return Err(ExternalPolynomialError::InvalidVector);
        }
        Ok(())
    }

    fn advance_scan_cursor(
        &mut self,
        pass: ExternalStockhamPassPlan,
    ) -> Result<(), ExternalPolynomialError> {
        let half_block_size = 1_usize
            .checked_shl(pass.stage_ordinal)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        self.offset_within_group = self
            .offset_within_group
            .checked_add(self.current_block_element_count)
            .ok_or(ExternalPolynomialError::CountOverflow)?;
        if self.offset_within_group == half_block_size {
            match self.output_half {
                ExternalStockhamOutputHalf::Sum => {
                    self.output_half = ExternalStockhamOutputHalf::Difference;
                    self.offset_within_group = 0;
                }
                ExternalStockhamOutputHalf::Difference => {
                    self.output_half = ExternalStockhamOutputHalf::Sum;
                    self.offset_within_group = 0;
                    self.group_start = self
                        .group_start
                        .checked_add(half_block_size)
                        .ok_or(ExternalPolynomialError::CountOverflow)?;
                }
            }
        }
        self.left_values.clear();
        self.right_values.clear();
        self.current_block_element_count = 0;
        self.phase = if self.group_start == self.plan.domain.size() / 2 {
            ExternalStockhamTransformPhase::FlushOutput
        } else {
            ExternalStockhamTransformPhase::ReadLeft
        };
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExternalStockhamTransformError<StorageError> {
    Polynomial(ExternalPolynomialError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

impl<StorageError> From<ExternalPolynomialError> for ExternalStockhamTransformError<StorageError> {
    fn from(error: ExternalPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for ExternalStockhamTransformError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

fn read_external_values<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
    destination: &mut ExternalPolynomialValues,
) -> Result<bool, ExternalStockhamTransformError<Storage::Error>> {
    if element_count == 0 || element_offset.checked_add(element_count).is_none() {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    let available_element_count = vector
        .element_count
        .saturating_sub(element_offset)
        .min(element_count);
    destination.clear();
    if available_element_count == 0 {
        destination.pad_with_zeros(vector.value_type, element_count)?;
        return Ok(false);
    }
    let value_byte_length = usize::try_from(external_value_byte_length(vector.value_type))
        .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let byte_length = available_element_count
        .checked_mul(value_byte_length)
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let byte_offset = element_offset
        .checked_mul(value_byte_length)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(byte_length)
        .map_err(|_| ExternalPolynomialError::AllocationLimitExceeded)?;
    encoded.resize(byte_length, 0);
    executor.read_object_bytes(storage, vector.object, byte_offset, &mut encoded)?;
    destination.decode(vector.value_type, &encoded)?;
    destination.pad_with_zeros(vector.value_type, element_count)?;
    Ok(true)
}

pub(crate) fn read_external_polynomial_value<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_index: usize,
) -> Result<ExternalPolynomialValue, ExternalStockhamTransformError<Storage::Error>> {
    if element_index >= vector.element_count {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    let value_byte_length = usize::try_from(external_value_byte_length(vector.value_type))
        .map_err(|_| ExternalPolynomialError::CountOverflow)?;
    let byte_offset = element_index
        .checked_mul(value_byte_length)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(ExternalPolynomialError::CountOverflow)?;
    let mut encoded = [0_u8; EXTENSION_FIELD_ELEMENT_BYTE_LENGTH];
    executor.read_object_bytes(
        storage,
        vector.object,
        byte_offset,
        &mut encoded[..value_byte_length],
    )?;
    match vector.value_type {
        RelationColumnValueType::BaseField => {
            let mut canonical = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
            canonical.copy_from_slice(&encoded[..BASE_FIELD_ELEMENT_BYTE_LENGTH]);
            Ok(ExternalPolynomialValue::Base(
                ProofBaseFieldElement::from_canonical(u64::from_le_bytes(canonical))
                    .map_err(ExternalPolynomialError::from)?,
            ))
        }
        RelationColumnValueType::ChallengeExtension => {
            let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
            for (coordinate, coordinate_bytes) in coordinates
                .iter_mut()
                .zip(encoded.chunks_exact(BASE_FIELD_ELEMENT_BYTE_LENGTH))
            {
                let mut canonical = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
                canonical.copy_from_slice(coordinate_bytes);
                *coordinate = u64::from_le_bytes(canonical);
            }
            Ok(ExternalPolynomialValue::Extension(
                ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                    .map_err(ExternalPolynomialError::from)?,
            ))
        }
    }
}

pub(crate) fn read_external_polynomial_extension_values<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
) -> Result<
    Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ExternalStockhamTransformError<Storage::Error>,
> {
    if element_count == 0
        || element_offset
            .checked_add(element_count)
            .filter(|end| *end <= vector.element_count())
            .is_none()
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    let mut values = ExternalPolynomialValues::with_capacity(vector.value_type(), element_count)?;
    if !read_external_values(
        executor,
        storage,
        vector,
        element_offset,
        element_count,
        &mut values,
    )? || values.len() != element_count
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    values.into_extension_values().map_err(Into::into)
}

pub(crate) fn read_external_polynomial_base_values<Storage: ProofExternalMemory>(
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut Storage,
    vector: ExternalPolynomialVector,
    element_offset: usize,
    element_count: usize,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, ExternalStockhamTransformError<Storage::Error>> {
    if vector.value_type() != RelationColumnValueType::BaseField
        || element_count == 0
        || element_offset
            .checked_add(element_count)
            .filter(|end| *end <= vector.element_count())
            .is_none()
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    let mut values = ExternalPolynomialValues::with_capacity(vector.value_type(), element_count)?;
    if !read_external_values(
        executor,
        storage,
        vector,
        element_offset,
        element_count,
        &mut values,
    )? || values.len() != element_count
    {
        return Err(ExternalPolynomialError::InvalidVector.into());
    }
    values.into_base_values().map_err(Into::into)
}

pub(crate) const fn external_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => BASE_FIELD_ELEMENT_BYTE_LENGTH as u64,
        RelationColumnValueType::ChallengeExtension => EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64,
    }
}

fn ceiling_division_usize(
    numerator: usize,
    denominator: usize,
) -> Result<usize, ExternalPolynomialError> {
    if numerator == 0 || denominator == 0 {
        return Err(ExternalPolynomialError::InvalidPlan);
    }
    numerator
        .checked_add(denominator - 1)
        .map(|adjusted| adjusted / denominator)
        .ok_or(ExternalPolynomialError::CountOverflow)
}

fn chunked_prefix_read_count(
    prefix_element_count: usize,
    half_block_size: usize,
    maximum_scan_element_count: usize,
) -> Result<u64, ExternalPolynomialError> {
    if half_block_size == 0 || maximum_scan_element_count == 0 {
        return Err(ExternalPolynomialError::InvalidPlan);
    }
    let complete_group_count = prefix_element_count / half_block_size;
    let remainder_element_count = prefix_element_count % half_block_size;
    let chunks_per_complete_group =
        ceiling_division_usize(half_block_size, maximum_scan_element_count)?;
    let remainder_chunk_count = if remainder_element_count == 0 {
        0
    } else {
        ceiling_division_usize(remainder_element_count, maximum_scan_element_count)?
    };
    complete_group_count
        .checked_mul(chunks_per_complete_group)
        .and_then(|count| count.checked_add(remainder_chunk_count))
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(ExternalPolynomialError::CountOverflow)
}

pub(crate) fn map_external_polynomial_plan_error(
    error: ExternalPolynomialError,
) -> ProofExternalMemoryError {
    match error {
        ExternalPolynomialError::CountOverflow
        | ExternalPolynomialError::AllocationLimitExceeded => {
            ProofExternalMemoryError::ResourceLimitExceeded
        }
        ExternalPolynomialError::WrongTransformStep => ProofExternalMemoryError::WrongStep,
        ExternalPolynomialError::InvalidDomain
        | ExternalPolynomialError::InvalidVector
        | ExternalPolynomialError::InvalidPlan
        | ExternalPolynomialError::Field(_) => ProofExternalMemoryError::InvalidPlan,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::bgv::proof_suite::{PROOF_EVALUATION_COSET_OFFSET, ProofExternalMemoryPlan};

    #[derive(Clone)]
    struct TestObject {
        bytes: Vec<u8>,
        exact_byte_length: usize,
        sealed: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStorageError {
        TransactionAlreadyActive,
        TransactionMissing,
        ObjectAlreadyExists,
        ObjectMissing,
        WrongLifecycle,
        WrongRange,
        OperationLimitExceeded,
        PayloadLimitExceeded,
    }

    struct TestTransaction {
        objects: BTreeMap<ProofExternalMemoryObject, TestObject>,
        remaining_operation_count: u32,
        remaining_payload_byte_length: usize,
    }

    #[derive(Default)]
    struct TestStorage {
        committed: BTreeMap<ProofExternalMemoryObject, TestObject>,
        transaction: Option<TestTransaction>,
    }

    impl TestStorage {
        fn transaction(
            &mut self,
            payload_byte_length: usize,
        ) -> Result<&mut TestTransaction, TestStorageError> {
            let transaction = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::TransactionMissing)?;
            transaction.remaining_operation_count = transaction
                .remaining_operation_count
                .checked_sub(1)
                .ok_or(TestStorageError::OperationLimitExceeded)?;
            transaction.remaining_payload_byte_length = transaction
                .remaining_payload_byte_length
                .checked_sub(payload_byte_length)
                .ok_or(TestStorageError::PayloadLimitExceeded)?;
            Ok(transaction)
        }
    }

    impl ProofExternalMemory for TestStorage {
        type Error = TestStorageError;

        fn begin_transaction(
            &mut self,
            maximum_payload_byte_length: u64,
            maximum_operation_count: u32,
        ) -> Result<(), Self::Error> {
            if self.transaction.is_some() {
                return Err(TestStorageError::TransactionAlreadyActive);
            }
            self.transaction = Some(TestTransaction {
                objects: self.committed.clone(),
                remaining_operation_count: maximum_operation_count,
                remaining_payload_byte_length: usize::try_from(maximum_payload_byte_length)
                    .map_err(|_| TestStorageError::PayloadLimitExceeded)?,
            });
            Ok(())
        }

        fn create_object(
            &mut self,
            object: ProofExternalMemoryObject,
            _protection: ProofExternalMemoryProtection,
            exact_byte_length: u64,
        ) -> Result<(), Self::Error> {
            let exact_byte_length =
                usize::try_from(exact_byte_length).map_err(|_| TestStorageError::WrongRange)?;
            let transaction = self.transaction(0)?;
            if transaction.objects.contains_key(&object) {
                return Err(TestStorageError::ObjectAlreadyExists);
            }
            transaction.objects.insert(
                object,
                TestObject {
                    bytes: Vec::new(),
                    exact_byte_length,
                    sealed: false,
                },
            );
            Ok(())
        }

        fn append_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let expected_offset =
                usize::try_from(expected_offset).map_err(|_| TestStorageError::WrongRange)?;
            let stored = self
                .transaction(bytes.len())?
                .objects
                .get_mut(&object)
                .ok_or(TestStorageError::ObjectMissing)?;
            if stored.sealed
                || stored.bytes.len() != expected_offset
                || stored
                    .bytes
                    .len()
                    .checked_add(bytes.len())
                    .filter(|length| *length <= stored.exact_byte_length)
                    .is_none()
            {
                return Err(TestStorageError::WrongLifecycle);
            }
            stored.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            let stored = self
                .transaction(0)?
                .objects
                .get_mut(&object)
                .ok_or(TestStorageError::ObjectMissing)?;
            if stored.sealed || stored.bytes.len() != stored.exact_byte_length {
                return Err(TestStorageError::WrongLifecycle);
            }
            stored.sealed = true;
            Ok(())
        }

        fn read_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let offset = usize::try_from(offset).map_err(|_| TestStorageError::WrongRange)?;
            let stored = self
                .transaction(destination.len())?
                .objects
                .get(&object)
                .ok_or(TestStorageError::ObjectMissing)?;
            let end = offset
                .checked_add(destination.len())
                .ok_or(TestStorageError::WrongRange)?;
            if !stored.sealed {
                return Err(TestStorageError::WrongLifecycle);
            }
            destination.copy_from_slice(
                stored
                    .bytes
                    .get(offset..end)
                    .ok_or(TestStorageError::WrongRange)?,
            );
            Ok(())
        }

        fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.transaction(0)?
                .objects
                .remove(&object)
                .ok_or(TestStorageError::ObjectMissing)?;
            Ok(())
        }

        fn commit_transaction(&mut self) -> Result<(), Self::Error> {
            self.committed = self
                .transaction
                .take()
                .ok_or(TestStorageError::TransactionMissing)?
                .objects;
            Ok(())
        }

        fn abort_transaction(&mut self) -> Result<(), Self::Error> {
            self.transaction
                .take()
                .ok_or(TestStorageError::TransactionMissing)?;
            Ok(())
        }
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("the test value is canonical")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            value,
            value.wrapping_mul(3),
            value.wrapping_mul(5),
            value.wrapping_mul(7),
            value.wrapping_mul(11),
        ])
        .expect("the test coordinates are canonical")
    }

    fn encode_base(values: &[ProofBaseFieldElement]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.canonical().to_le_bytes())
            .collect()
    }

    fn encode_extension(values: &[ProofChallengeExtensionElement]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| {
                value
                    .canonical_coordinates()
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
            })
            .collect()
    }

    fn decode_base(encoded: &[u8]) -> Vec<ProofBaseFieldElement> {
        encoded
            .chunks_exact(BASE_FIELD_ELEMENT_BYTE_LENGTH)
            .map(|bytes| {
                let mut canonical = [0_u8; BASE_FIELD_ELEMENT_BYTE_LENGTH];
                canonical.copy_from_slice(bytes);
                ProofBaseFieldElement::from_canonical(u64::from_le_bytes(canonical))
                    .expect("the external result is canonical")
            })
            .collect()
    }

    fn decode_extension(encoded: &[u8]) -> Vec<ProofChallengeExtensionElement> {
        encoded
            .chunks_exact(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
            .map(|bytes| {
                let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                for (coordinate, coordinate_bytes) in
                    coordinates.iter_mut().zip(bytes.chunks_exact(8))
                {
                    let mut canonical = [0_u8; 8];
                    canonical.copy_from_slice(coordinate_bytes);
                    *coordinate = u64::from_le_bytes(canonical);
                }
                ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                    .expect("the external result is canonical")
            })
            .collect()
    }

    struct CompletedTransform {
        encoded_output: Vec<u8>,
        checkpoint_boundaries: Vec<ExternalStockhamCheckpointBoundary>,
        usage: super::super::ProofExternalMemoryUsage,
        plan: ExternalStockhamTransformPlan,
    }

    fn execute_transform(
        domain: ProofEvaluationDomain,
        value_type: RelationColumnValueType,
        direction: ExternalStockhamTransformDirection,
        encoded_source: &[u8],
        maximum_chunk_byte_length: u32,
    ) -> CompletedTransform {
        execute_transform_with_output_objects(
            domain,
            value_type,
            direction,
            encoded_source,
            maximum_chunk_byte_length,
            None,
        )
    }

    fn execute_transform_with_output_objects(
        domain: ProofEvaluationDomain,
        value_type: RelationColumnValueType,
        direction: ExternalStockhamTransformDirection,
        encoded_source: &[u8],
        maximum_chunk_byte_length: u32,
        output_objects: Option<&[ProofExternalMemoryObject]>,
    ) -> CompletedTransform {
        let domain_size = domain.size();
        let value_byte_length = usize::try_from(external_value_byte_length(value_type))
            .expect("the value byte length fits usize");
        assert!(!encoded_source.is_empty());
        assert_eq!(encoded_source.len() % value_byte_length, 0);
        let source_element_count = encoded_source.len() / value_byte_length;
        let source = ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(0),
            value_type,
            source_element_count,
        )
        .expect("the source vector is valid");
        assert_eq!(
            encoded_source.len(),
            usize::try_from(
                source
                    .exact_byte_length()
                    .expect("source byte length is valid"),
            )
            .expect("source length fits usize")
        );
        let first_transform_step = 1;
        let transform_plan = if let Some(output_objects) = output_objects {
            ExternalStockhamTransformPlan::new_with_output_objects(
                domain,
                direction,
                source,
                output_objects,
                first_transform_step,
                first_transform_step + domain_size.trailing_zeros(),
                maximum_chunk_byte_length,
                ProofExternalMemoryProtection::PublicIntegrity,
            )
        } else {
            ExternalStockhamTransformPlan::new(
                domain,
                direction,
                source,
                1,
                first_transform_step,
                first_transform_step + domain_size.trailing_zeros(),
                maximum_chunk_byte_length,
                ProofExternalMemoryProtection::PublicIntegrity,
            )
        }
        .expect("the external transform plan is valid");
        let final_step = transform_plan.next_executor_step();
        let mut object_plans = vec![ProofExternalMemoryObjectPlan::new(
            source.object(),
            ProofExternalMemoryProtection::PublicIntegrity,
            source.exact_byte_length().expect("source length is valid"),
            0,
            0,
            first_transform_step,
        )];
        object_plans.extend_from_slice(transform_plan.object_plans());
        let aligned_chunk_byte_length = usize::try_from(maximum_chunk_byte_length)
            .expect("chunk size fits usize")
            / value_byte_length
            * value_byte_length;
        assert_ne!(aligned_chunk_byte_length, 0);
        let source_chunk_count = encoded_source.len().div_ceil(aligned_chunk_byte_length);
        let output_exact_byte_length = transform_plan
            .final_output()
            .exact_byte_length()
            .expect("output length is valid");
        let output_chunk_count = usize::try_from(output_exact_byte_length)
            .expect("the output length fits usize")
            .div_ceil(aligned_chunk_byte_length);
        let deletion_transaction_count = u64::try_from(
            object_plans
                .iter()
                .map(|object_plan| object_plan.last_use_step())
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .expect("the deletion transaction count fits u64");
        let maximum_transaction_count = transform_plan
            .transaction_count_excluding_deletions()
            .checked_add(
                u64::try_from(source_chunk_count + output_chunk_count + 2)
                    .expect("the test transaction count fits u64"),
            )
            .and_then(|count| count.checked_add(deletion_transaction_count))
            .expect("the transaction count does not overflow");
        let source_exact_byte_length = source.exact_byte_length().expect("source length is valid");
        let maximum_stored_byte_length = source_exact_byte_length
            .checked_add(output_exact_byte_length)
            .expect("the first-pass overlap does not overflow")
            .max(if transform_plan.passes().len() > 1 {
                output_exact_byte_length
                    .checked_mul(2)
                    .expect("the later-pass overlap does not overflow")
            } else {
                0
            });
        let external_plan = ProofExternalMemoryPlan::new(
            final_step + 1,
            maximum_chunk_byte_length,
            u64::from(maximum_chunk_byte_length),
            u32::try_from(object_plans.len()).expect("the object count fits u32"),
            maximum_stored_byte_length,
            source_exact_byte_length + transform_plan.total_written_byte_length(),
            transform_plan.total_read_byte_length() + output_exact_byte_length,
            maximum_transaction_count,
            object_plans,
        )
        .expect("the complete external plan is valid");
        let mut executor = ProofExternalMemoryExecutor::new(external_plan);
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, source.object())
            .expect("the source object begins");
        for chunk in encoded_source.chunks(aligned_chunk_byte_length) {
            executor
                .append_object_bytes(&mut storage, source.object(), chunk)
                .expect("one bounded source chunk appends");
        }
        executor
            .seal_object(&mut storage, source.object())
            .expect("the source object seals");
        executor
            .complete_step(&mut storage)
            .expect("the source issuance step completes");

        let mut transform = ExternalStockhamTransform::new(transform_plan.clone())
            .expect("the transform initializes");
        let initial_boundary = transform
            .checkpoint_boundary()
            .expect("the sealed source is an initial safe boundary");
        assert_eq!(initial_boundary.next_pass_ordinal(), 0);
        assert_eq!(initial_boundary.next_executor_step(), first_transform_step);
        assert_eq!(initial_boundary.sealed_input(), source);
        let mut checkpoint_boundaries = vec![initial_boundary];
        let final_output = loop {
            match transform
                .advance(&mut executor, &mut storage)
                .expect("the external transform advances")
            {
                ExternalStockhamTransformProgress::ArithmeticStepCompleted => {}
                ExternalStockhamTransformProgress::StorageTransactionCompleted => {}
                ExternalStockhamTransformProgress::PassCommitted(boundary) => {
                    assert_eq!(
                        storage.committed.len(),
                        1,
                        "a pass boundary retains only its sealed output",
                    );
                    assert!(
                        storage
                            .committed
                            .get(&boundary.sealed_input().object())
                            .is_some_and(|object| object.sealed),
                    );
                    checkpoint_boundaries.push(boundary);
                }
                ExternalStockhamTransformProgress::Complete(output) => break output,
            }
        };
        assert_eq!(final_output, transform_plan.final_output());
        assert_eq!(executor.current_step(), final_step);
        let mut encoded_output = vec![
            0_u8;
            usize::try_from(output_exact_byte_length)
                .expect("the output length fits usize")
        ];
        for (chunk_index, destination) in encoded_output
            .chunks_mut(aligned_chunk_byte_length)
            .enumerate()
        {
            executor
                .read_object_bytes(
                    &mut storage,
                    final_output.object(),
                    u64::try_from(chunk_index * aligned_chunk_byte_length)
                        .expect("the result offset fits u64"),
                    destination,
                )
                .expect("one bounded result chunk reads");
        }
        executor
            .complete_step(&mut storage)
            .expect("the final output last-use step completes");
        let usage = executor.finish().expect("the exact plan is exhausted");
        assert!(storage.committed.is_empty());
        assert_eq!(usage.peak_stored_byte_length, maximum_stored_byte_length);
        assert_eq!(
            usage.total_written_byte_length,
            source_exact_byte_length + transform_plan.total_written_byte_length(),
        );
        assert_eq!(
            usage.total_read_byte_length,
            transform_plan.total_read_byte_length() + output_exact_byte_length,
        );
        assert_eq!(usage.transaction_count, maximum_transaction_count);
        CompletedTransform {
            encoded_output,
            checkpoint_boundaries,
            usage,
            plan: transform_plan,
        }
    }

    #[test]
    fn external_stockham_matches_base_and_extension_coset_transforms() {
        for domain_size in [2_usize, 4, 8, 32, 64] {
            let domain = ProofEvaluationDomain::new(domain_size, PROOF_EVALUATION_COSET_OFFSET)
                .expect("the test domain is valid");
            let mut base_coefficients = (0..domain_size / 2 + 1)
                .map(|index| base((index as u64 + 1).pow(3)))
                .collect::<Vec<_>>();
            base_coefficients.resize(domain_size, ProofBaseFieldElement::ZERO);
            let expected_base_evaluations = domain
                .evaluate_base_polynomial(&base_coefficients)
                .expect("the in-memory base evaluation succeeds");
            let base_forward = execute_transform(
                domain,
                RelationColumnValueType::BaseField,
                ExternalStockhamTransformDirection::Forward,
                &encode_base(&base_coefficients),
                24,
            );
            assert_eq!(
                decode_base(&base_forward.encoded_output),
                expected_base_evaluations,
            );
            let base_inverse = execute_transform(
                domain,
                RelationColumnValueType::BaseField,
                ExternalStockhamTransformDirection::Inverse,
                &base_forward.encoded_output,
                24,
            );
            assert_eq!(decode_base(&base_inverse.encoded_output), base_coefficients);

            let mut extension_coefficients = (0..domain_size / 2 + 1)
                .map(|index| extension(index as u64 + 1))
                .collect::<Vec<_>>();
            extension_coefficients.resize(domain_size, ProofChallengeExtensionElement::ZERO);
            let expected_extension_evaluations = domain
                .evaluate_extension_polynomial(&extension_coefficients)
                .expect("the in-memory extension evaluation succeeds");
            let extension_forward = execute_transform(
                domain,
                RelationColumnValueType::ChallengeExtension,
                ExternalStockhamTransformDirection::Forward,
                &encode_extension(&extension_coefficients),
                80,
            );
            assert_eq!(
                decode_extension(&extension_forward.encoded_output),
                expected_extension_evaluations,
            );
            let extension_inverse = execute_transform(
                domain,
                RelationColumnValueType::ChallengeExtension,
                ExternalStockhamTransformDirection::Inverse,
                &extension_forward.encoded_output,
                80,
            );
            assert_eq!(
                decode_extension(&extension_inverse.encoded_output),
                extension_coefficients,
            );
        }
    }

    #[test]
    fn stockham_backend_reuses_two_intermediate_objects_without_changing_output() {
        let domain = ProofEvaluationDomain::new(32, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the test domain is valid");
        let coefficients = (0..17)
            .map(|index| extension(index as u64 + 9))
            .collect::<Vec<_>>();
        let encoded_coefficients = encode_extension(&coefficients);
        let output_objects = [
            ProofExternalMemoryObject::new(1),
            ProofExternalMemoryObject::new(2),
            ProofExternalMemoryObject::new(1),
            ProofExternalMemoryObject::new(2),
            ProofExternalMemoryObject::new(3),
        ];
        let reused = execute_transform_with_output_objects(
            domain,
            RelationColumnValueType::ChallengeExtension,
            ExternalStockhamTransformDirection::Forward,
            &encoded_coefficients,
            80,
            Some(&output_objects),
        );
        let ordinary = execute_transform(
            domain,
            RelationColumnValueType::ChallengeExtension,
            ExternalStockhamTransformDirection::Forward,
            &encoded_coefficients,
            80,
        );
        assert_eq!(reused.encoded_output, ordinary.encoded_output);
        assert_eq!(
            reused
                .plan
                .object_plans()
                .iter()
                .map(|plan| plan.object())
                .collect::<BTreeSet<_>>()
                .len(),
            3,
        );
        assert_eq!(reused.plan.object_plans().len(), 5);
        assert_eq!(reused.usage.deleted_object_count(), 6);
    }

    #[test]
    fn forward_transform_zero_pads_degree_sized_sources() {
        let domain = ProofEvaluationDomain::new(64, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the test domain is valid");

        let base_coefficients = (0..11)
            .map(|index| base((index as u64 + 3).pow(3)))
            .collect::<Vec<_>>();
        let mut padded_base_coefficients = base_coefficients.clone();
        padded_base_coefficients.resize(domain.size(), ProofBaseFieldElement::ZERO);
        let expected_base_evaluations = domain
            .evaluate_base_polynomial(&padded_base_coefficients)
            .expect("the in-memory base evaluation succeeds");
        let base_forward = execute_transform(
            domain,
            RelationColumnValueType::BaseField,
            ExternalStockhamTransformDirection::Forward,
            &encode_base(&base_coefficients),
            24,
        );
        assert_eq!(
            decode_base(&base_forward.encoded_output),
            expected_base_evaluations,
        );
        assert_eq!(base_forward.plan.passes()[0].input.element_count(), 11);

        let extension_coefficients = (0..37)
            .map(|index| extension(index as u64 + 5))
            .collect::<Vec<_>>();
        let mut padded_extension_coefficients = extension_coefficients.clone();
        padded_extension_coefficients.resize(domain.size(), ProofChallengeExtensionElement::ZERO);
        let expected_extension_evaluations = domain
            .evaluate_extension_polynomial(&padded_extension_coefficients)
            .expect("the in-memory extension evaluation succeeds");
        let extension_forward = execute_transform(
            domain,
            RelationColumnValueType::ChallengeExtension,
            ExternalStockhamTransformDirection::Forward,
            &encode_extension(&extension_coefficients),
            80,
        );
        assert_eq!(
            decode_extension(&extension_forward.encoded_output),
            expected_extension_evaluations,
        );
        assert_eq!(extension_forward.plan.passes()[0].input.element_count(), 37,);
    }

    #[test]
    fn transform_resident_buffers_remain_fixed_as_the_domain_grows() {
        let small_domain = ProofEvaluationDomain::new(8, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the small domain is valid");
        let large_domain = ProofEvaluationDomain::new(1 << 18, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the large domain is valid");
        let small_source = ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(0),
            RelationColumnValueType::ChallengeExtension,
            small_domain.size(),
        )
        .expect("the small source is valid");
        let large_source = ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(0),
            RelationColumnValueType::ChallengeExtension,
            large_domain.size(),
        )
        .expect("the large source is valid");
        let small_plan = ExternalStockhamTransformPlan::new(
            small_domain,
            ExternalStockhamTransformDirection::Forward,
            small_source,
            1,
            1,
            1 + small_domain.size().trailing_zeros(),
            1_048_576,
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
        )
        .expect("the small plan is valid");
        let large_plan = ExternalStockhamTransformPlan::new(
            large_domain,
            ExternalStockhamTransformDirection::Forward,
            large_source,
            1,
            1,
            1 + large_domain.size().trailing_zeros(),
            1_048_576,
            ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
        )
        .expect("the large plan is valid");
        assert_eq!(
            small_plan.maximum_resident_byte_length(),
            large_plan.maximum_resident_byte_length(),
        );
        assert_eq!(
            small_plan.maximum_scan_element_count(),
            large_plan.maximum_scan_element_count(),
        );
        assert_eq!(small_plan.passes().len(), 3);
        assert_eq!(large_plan.passes().len(), 18);
        let resident_requirement =
            external_stockham_resident_memory_requirement(1_048_560, 1_048_576)
                .expect("the aligned Stockham buffers have one resident requirement");
        assert_eq!(
            large_plan.maximum_resident_byte_length(),
            resident_requirement.peak_byte_length(),
            "the transform plan includes its full transaction-overlap peak",
        );
        assert_eq!(
            resident_requirement.component_working_set_byte_length(),
            4 * 1_048_560 + 1_048_576,
            "a replayable read retains the three transform vectors and one encoded read vector",
        );
        assert!(
            resident_requirement.transaction_overlap_peak_byte_length()
                > resident_requirement.component_working_set_byte_length(),
            "request encoding includes the recorder, operation, and final request copies",
        );
    }

    #[test]
    fn transform_plan_refuses_invalid_domains_chunks_and_liveness() {
        let domain = ProofEvaluationDomain::new(8, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the test domain is valid");
        let oversized_source = ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(0),
            RelationColumnValueType::BaseField,
            9,
        )
        .expect("the oversized vector is representable");
        assert_eq!(
            ExternalStockhamTransformPlan::new(
                domain,
                ExternalStockhamTransformDirection::Forward,
                oversized_source,
                1,
                1,
                4,
                8,
                ProofExternalMemoryProtection::PublicIntegrity,
            ),
            Err(ExternalPolynomialError::InvalidDomain),
        );
        let source = ExternalPolynomialVector::new(
            ProofExternalMemoryObject::new(0),
            RelationColumnValueType::ChallengeExtension,
            domain.size(),
        )
        .expect("the source is valid");
        assert_eq!(
            ExternalStockhamTransformPlan::new(
                domain,
                ExternalStockhamTransformDirection::Forward,
                source,
                1,
                1,
                4,
                39,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            ),
            Err(ExternalPolynomialError::InvalidPlan),
        );
        assert_eq!(
            ExternalStockhamTransformPlan::new(
                domain,
                ExternalStockhamTransformDirection::Forward,
                source,
                1,
                1,
                3,
                80,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
            ),
            Err(ExternalPolynomialError::InvalidPlan),
        );
    }

    #[test]
    fn every_nonterminal_pass_exposes_one_sealed_safe_boundary_input() {
        let domain = ProofEvaluationDomain::new(64, PROOF_EVALUATION_COSET_OFFSET)
            .expect("the test domain is valid");
        let coefficients = (0..domain.size())
            .map(|index| extension(index as u64 + 1))
            .collect::<Vec<_>>();
        let completed = execute_transform(
            domain,
            RelationColumnValueType::ChallengeExtension,
            ExternalStockhamTransformDirection::Forward,
            &encode_extension(&coefficients),
            80,
        );
        assert_eq!(completed.checkpoint_boundaries.len(), 6);
        for (pass_ordinal, boundary) in completed.checkpoint_boundaries.iter().enumerate() {
            assert_eq!(
                boundary.next_pass_ordinal(),
                u32::try_from(pass_ordinal).expect("the pass ordinal fits u32"),
            );
            assert_eq!(
                boundary.next_executor_step(),
                u32::try_from(pass_ordinal + 1).expect("the executor step fits u32"),
            );
            assert_eq!(
                boundary.sealed_input(),
                completed.plan.passes()[pass_ordinal].input(),
            );
        }
        assert_eq!(
            completed.usage.deleted_object_count,
            u32::try_from(completed.plan.passes().len() + 1).expect("the object count fits u32"),
        );
    }
}
