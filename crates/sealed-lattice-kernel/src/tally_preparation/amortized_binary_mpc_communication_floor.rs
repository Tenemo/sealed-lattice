use crate::tally_circuit::CompiledTallyCircuit;

use super::{
    TallyPreparationError,
    binary_ring_packed_mpc_evaluation_floor::BinaryRingPackedMpcEvaluationFloor,
};

const RANDOM_SUBSPACE_VECTOR_LIMB_COUNT: u64 = 2;

/// Explicit reverse-embedding geometry for the addition-local binary-MPC
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryCircuitAmortizationParameters {
    pub(crate) packed_value_count: u64,
    pub(crate) extension_degree: u64,
    pub(crate) extension_field_cardinality: u64,
}

/// Accepted-path communication known before the underlying secure
/// multiplication protocol is instantiated.
///
/// The count gives every conjunction the largest packing permitted by the
/// chosen explicit reverse embedding. It then includes the exact public
/// reconstruction and random-subspace generation messages required to
/// re-encode each packed multiplication. It excludes the base multiplication
/// protocol, external inputs, random gates, player-elimination paths, wrappers,
/// signatures, checkpoints, and storage traffic, so it is a strict optimistic
/// lower bound for this realization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AmortizedBinaryMpcCircuitCommunicationFloor {
    pub(crate) binary_conjunction_count: u64,
    pub(crate) packed_multiplication_count: u64,
    pub(crate) public_reconstruction_batch_count: u64,
    pub(crate) random_subspace_generation_batch_count: u64,
    pub(crate) public_reconstruction_remote_field_element_count: u64,
    pub(crate) random_subspace_generation_remote_field_element_count: u64,
    pub(crate) known_remote_field_element_count: u64,
    pub(crate) known_remote_bit_length: u64,
    pub(crate) known_remote_byte_length: u64,
    pub(crate) minimum_maximum_participant_upload_byte_length: u64,
}

/// Exact re-encoding floor for the evaluated addition-local binary-MPC route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AmortizedBinaryMpcCommunicationFloor {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) robust_reconstruction_batch_size: u64,
    pub(crate) amortization: BinaryCircuitAmortizationParameters,
    pub(crate) public_reconstruction_remote_field_elements_per_batch: u64,
    pub(crate) random_subspace_outputs_per_batch: u64,
    pub(crate) random_subspace_remote_field_elements_per_batch: u64,
    pub(crate) shared_offset: AmortizedBinaryMpcCircuitCommunicationFloor,
    pub(crate) independent_label: AmortizedBinaryMpcCircuitCommunicationFloor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReencodingBatchGeometry {
    participant_count: u64,
    robust_reconstruction_batch_size: u64,
    amortization: BinaryCircuitAmortizationParameters,
    public_reconstruction_remote_field_elements_per_batch: u64,
    random_subspace_outputs_per_batch: u64,
    random_subspace_remote_field_elements_per_batch: u64,
}

impl AmortizedBinaryMpcCommunicationFloor {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let binary_ring_floor = BinaryRingPackedMpcEvaluationFloor::derive(circuit)?;
        let participant_count = binary_ring_floor.participant_count;
        let active_fault_bound = binary_ring_floor.active_fault_bound;
        let robust_reconstruction_batch_size = participant_count
            .checked_sub(checked_multiply(active_fault_bound, 2)?)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if robust_reconstruction_batch_size == 0 {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let amortization = explicit_amortization_parameters(participant_count)?;
        if amortization.extension_field_cardinality <= checked_multiply(participant_count, 2)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let remote_recipient_count = participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let public_reconstruction_remote_field_elements_per_batch = checked_multiply(
            checked_multiply(participant_count, remote_recipient_count)?,
            2,
        )?;
        let random_subspace_outputs_per_batch = checked_multiply(
            amortization.extension_degree,
            robust_reconstruction_batch_size,
        )?;
        let random_subspace_remote_field_elements_per_batch = checked_multiply(
            checked_multiply(
                checked_subtract(
                    checked_multiply(participant_count, 2)?,
                    robust_reconstruction_batch_size,
                )?,
                remote_recipient_count,
            )?,
            checked_multiply(
                amortization.extension_degree,
                RANDOM_SUBSPACE_VECTOR_LIMB_COUNT,
            )?,
        )?;
        let batch_geometry = ReencodingBatchGeometry {
            participant_count,
            robust_reconstruction_batch_size,
            amortization,
            public_reconstruction_remote_field_elements_per_batch,
            random_subspace_outputs_per_batch,
            random_subspace_remote_field_elements_per_batch,
        };

        Ok(Self {
            participant_count,
            active_fault_bound,
            robust_reconstruction_batch_size,
            amortization,
            public_reconstruction_remote_field_elements_per_batch,
            random_subspace_outputs_per_batch,
            random_subspace_remote_field_elements_per_batch,
            shared_offset: derive_circuit_floor(
                binary_ring_floor
                    .shared_offset
                    .tower_binary_conjunction_count,
                batch_geometry,
            )?,
            independent_label: derive_circuit_floor(
                binary_ring_floor
                    .independent_label
                    .tower_binary_conjunction_count,
                batch_geometry,
            )?,
        })
    }
}

fn explicit_amortization_parameters(
    participant_count: u64,
) -> Result<BinaryCircuitAmortizationParameters, TallyPreparationError> {
    let (packed_value_count, extension_degree) = if participant_count <= 15 {
        // The interpolation construction gives a `(3, 5)` binary embedding.
        (3, 5)
    } else {
        // Concatenating `(2, 3)` embeddings over `GF(2)` and `GF(2^3)` gives
        // `(4, 9)` and supplies enough field points for every larger admitted
        // roster.
        (4, 9)
    };
    let extension_field_cardinality = 1_u64
        .checked_shl(
            u32::try_from(extension_degree)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        )
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    Ok(BinaryCircuitAmortizationParameters {
        packed_value_count,
        extension_degree,
        extension_field_cardinality,
    })
}

fn derive_circuit_floor(
    binary_conjunction_count: u64,
    geometry: ReencodingBatchGeometry,
) -> Result<AmortizedBinaryMpcCircuitCommunicationFloor, TallyPreparationError> {
    let packed_multiplication_count = checked_ceiling_divide(
        binary_conjunction_count,
        geometry.amortization.packed_value_count,
    )?;
    let public_reconstruction_batch_count = checked_ceiling_divide(
        packed_multiplication_count,
        geometry.robust_reconstruction_batch_size,
    )?;
    let random_subspace_generation_batch_count = checked_ceiling_divide(
        packed_multiplication_count,
        geometry.random_subspace_outputs_per_batch,
    )?;
    let public_reconstruction_remote_field_element_count = checked_multiply(
        public_reconstruction_batch_count,
        geometry.public_reconstruction_remote_field_elements_per_batch,
    )?;
    let random_subspace_generation_remote_field_element_count = checked_multiply(
        random_subspace_generation_batch_count,
        geometry.random_subspace_remote_field_elements_per_batch,
    )?;
    let known_remote_field_element_count = checked_add(
        public_reconstruction_remote_field_element_count,
        random_subspace_generation_remote_field_element_count,
    )?;
    let known_remote_bit_length = checked_multiply(
        known_remote_field_element_count,
        geometry.amortization.extension_degree,
    )?;
    let known_remote_byte_length =
        checked_ceiling_divide(known_remote_bit_length, u8::BITS.into())?;

    Ok(AmortizedBinaryMpcCircuitCommunicationFloor {
        binary_conjunction_count,
        packed_multiplication_count,
        public_reconstruction_batch_count,
        random_subspace_generation_batch_count,
        public_reconstruction_remote_field_element_count,
        random_subspace_generation_remote_field_element_count,
        known_remote_field_element_count,
        known_remote_bit_length,
        known_remote_byte_length,
        minimum_maximum_participant_upload_byte_length: checked_ceiling_divide(
            known_remote_byte_length,
            geometry.participant_count,
        )?,
    })
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    checked_add(
        dividend / divisor,
        u64::from(!dividend.is_multiple_of(divisor)),
    )
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_subtract(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_sub(right)
        .ok_or(TallyPreparationError::GeometryMismatch)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
