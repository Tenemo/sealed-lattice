use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    binary_field_multiplication_circuit::karatsuba_conjunction_count,
    garbling_alternative_resource_model::IndependentLabelGarblingResourceLowerBound,
    preparation_arithmetic_graph::PreparationArithmeticGraph,
    tower_field_multiplication_circuit::{
        tower_field_multiplication_conjunction_count, tower_field_multiplication_exclusive_or_count,
    },
};

const FIELD_BIT_LENGTH: u64 = BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64 * 8;
const MASKED_OPERAND_COUNT_PER_GATE: u64 = 2;
const REMOTE_MESSAGE_COUNT_PER_MASKED_OPERAND: u64 = 2;
const LABEL_BODY_FIELD_LIMB_COUNT: u64 = 3;

/// Explicit reverse multiplication-friendly embedding parameters used only to
/// make the packed binary-ring comparison concrete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryRingPackingParameters {
    pub(crate) packed_value_count: u64,
    pub(crate) extension_degree: u64,
    pub(crate) residue_field_cardinality: u64,
}

/// Evaluation traffic for one preparation circuit under the evaluated packed
/// binary-ring route.
///
/// The current-scalar, Karatsuba, and bilinear comparisons exclude addition
/// gates. The tower circuit includes every XOR inside its explicit field
/// multiplier, but excludes the surrounding preparation graph's additions.
/// Every comparison excludes random-zero sharing, triples, verification,
/// routing, input and output delivery, consensus, fault paths, and every
/// transport wrapper. They therefore remain incomplete accepted-path counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryRingPackedMpcCircuitEvaluationFloor {
    pub(crate) full_field_multiplication_count: u64,
    pub(crate) bit_by_field_multiplication_count: u64,
    pub(crate) bit_multiplication_count: u64,
    pub(crate) current_scalar_field_multiplication_conjunction_count: u64,
    pub(crate) current_scalar_binary_conjunction_count: u64,
    pub(crate) current_scalar_evaluation_bit_length: u64,
    pub(crate) current_scalar_evaluation_byte_length: u64,
    pub(crate) minimum_maximum_participant_current_scalar_upload_byte_length: u64,
    pub(crate) karatsuba_field_multiplication_conjunction_count: u64,
    pub(crate) karatsuba_binary_conjunction_count: u64,
    pub(crate) karatsuba_evaluation_bit_length: u64,
    pub(crate) karatsuba_evaluation_byte_length: u64,
    pub(crate) minimum_maximum_participant_karatsuba_upload_byte_length: u64,
    pub(crate) tower_field_multiplication_conjunction_count: u64,
    pub(crate) tower_field_multiplication_exclusive_or_count: u64,
    pub(crate) tower_binary_conjunction_count: u64,
    pub(crate) tower_binary_exclusive_or_count: u64,
    pub(crate) tower_binary_gate_count: u64,
    pub(crate) tower_evaluation_bit_length: u64,
    pub(crate) tower_evaluation_byte_length: u64,
    pub(crate) minimum_maximum_participant_tower_upload_byte_length: u64,
    pub(crate) bilinear_field_multiplication_conjunction_floor: u64,
    pub(crate) bilinear_binary_conjunction_floor: u64,
    pub(crate) bilinear_evaluation_bit_length_floor: u64,
    pub(crate) bilinear_evaluation_byte_length_floor: u64,
    pub(crate) minimum_maximum_participant_bilinear_upload_byte_length_floor: u64,
}

/// Known evaluation-only communication floors for a packed binary-ring
/// realization of the two garbling alternatives.
///
/// The current scalar count translates the kernel's fixed 256-step
/// shift-and-add field multiplication into one binary conjunction per product
/// bit. The executable Karatsuba circuit provides a smaller conservative
/// realization. The executable tower circuit uses 63 evaluations over
/// `GF(2^8)`, 27 Karatsuba conjunctions per evaluation, and a direct canonical
/// linear circuit. The bilinear count uses the `2m - 1` rank floor for a
/// degree-`m` field multiplication and is only a comparison floor for bilinear
/// algorithms. It is not an executable multiplier and does not prove that the
/// floor is attainable over `GF(2)` at degree 256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryRingPackedMpcEvaluationFloor {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) source_theorem_exact_roster_shape: bool,
    pub(crate) packing: BinaryRingPackingParameters,
    pub(crate) remote_evaluation_bit_count_per_binary_gate: u64,
    pub(crate) shared_offset: BinaryRingPackedMpcCircuitEvaluationFloor,
    pub(crate) independent_label: BinaryRingPackedMpcCircuitEvaluationFloor,
}

impl BinaryRingPackedMpcEvaluationFloor {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let arithmetic_graph = PreparationArithmeticGraph::derive(circuit)?;
        let independent_resources = IndependentLabelGarblingResourceLowerBound::derive(circuit)?;
        let participant_count = arithmetic_graph.participant_count;
        let roster_parameters = derive_foundation_roster_parameters(
            circuit.profile().participant_count(),
        )
        .ok_or(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count: circuit.profile().participant_count(),
        })?;
        let active_fault_bound = u64::from(roster_parameters.active_fault_bound);
        if participant_count <= checked_multiply(active_fault_bound, 3)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let packing = explicit_packing_parameters(participant_count)?;
        let minimum_residue_field_cardinality =
            checked_add(checked_multiply(participant_count, 2)?, 1)?;
        if packing.residue_field_cardinality < minimum_residue_field_cardinality {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let remote_recipient_count = participant_count
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let remote_evaluation_bit_count_per_binary_gate = checked_multiply(
            checked_multiply(
                MASKED_OPERAND_COUNT_PER_GATE,
                REMOTE_MESSAGE_COUNT_PER_MASKED_OPERAND,
            )?,
            remote_recipient_count,
        )?;

        let independent_label_bit_by_field_multiplication_count = checked_multiply(
            checked_multiply(independent_resources.paid_gate_row_count, participant_count)?,
            LABEL_BODY_FIELD_LIMB_COUNT,
        )?;

        Ok(Self {
            participant_count,
            active_fault_bound,
            source_theorem_exact_roster_shape: participant_count
                == checked_add(checked_multiply(active_fault_bound, 3)?, 1)?,
            packing,
            remote_evaluation_bit_count_per_binary_gate,
            shared_offset: derive_circuit_floor(
                arithmetic_graph.authenticated_tag_multiplication_count,
                arithmetic_graph.row_offset_limb_multiplication_count,
                arithmetic_graph.mask_product_multiplication_count,
                remote_evaluation_bit_count_per_binary_gate,
                participant_count,
            )?,
            independent_label: derive_circuit_floor(
                independent_resources.dkac_tag_generation_field_multiplication_count,
                independent_label_bit_by_field_multiplication_count,
                independent_resources.conjunction_gate_count,
                remote_evaluation_bit_count_per_binary_gate,
                participant_count,
            )?,
        })
    }
}

fn explicit_packing_parameters(
    participant_count: u64,
) -> Result<BinaryRingPackingParameters, TallyPreparationError> {
    let (packed_value_count, extension_degree) = if participant_count <= 3 {
        // The bounded rational-function-field construction gives `(2, 3)`.
        (2, 3)
    } else if participant_count <= 15 {
        // The same construction gives `(3, 5)`, including the selected roster.
        (3, 5)
    } else {
        // Composing two `(2, 3)` embeddings gives `(4, 9)`.
        (4, 9)
    };
    let residue_field_cardinality = 1_u64
        .checked_shl(
            u32::try_from(extension_degree)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        )
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;

    Ok(BinaryRingPackingParameters {
        packed_value_count,
        extension_degree,
        residue_field_cardinality,
    })
}

fn derive_circuit_floor(
    full_field_multiplication_count: u64,
    bit_by_field_multiplication_count: u64,
    bit_multiplication_count: u64,
    remote_evaluation_bit_count_per_binary_gate: u64,
    participant_count: u64,
) -> Result<BinaryRingPackedMpcCircuitEvaluationFloor, TallyPreparationError> {
    let current_scalar_field_multiplication_conjunction_count =
        checked_multiply(FIELD_BIT_LENGTH, FIELD_BIT_LENGTH)?;
    let karatsuba_field_multiplication_conjunction_count = karatsuba_conjunction_count()?;
    let tower_field_multiplication_conjunction_count =
        tower_field_multiplication_conjunction_count();
    let tower_field_multiplication_exclusive_or_count =
        tower_field_multiplication_exclusive_or_count();
    let bilinear_field_multiplication_conjunction_floor = checked_multiply(FIELD_BIT_LENGTH, 2)?
        .checked_sub(1)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let current_scalar_binary_conjunction_count = derive_binary_conjunction_count(
        full_field_multiplication_count,
        bit_by_field_multiplication_count,
        bit_multiplication_count,
        current_scalar_field_multiplication_conjunction_count,
    )?;
    let bilinear_binary_conjunction_floor = derive_binary_conjunction_count(
        full_field_multiplication_count,
        bit_by_field_multiplication_count,
        bit_multiplication_count,
        bilinear_field_multiplication_conjunction_floor,
    )?;
    let karatsuba_binary_conjunction_count = derive_binary_conjunction_count(
        full_field_multiplication_count,
        bit_by_field_multiplication_count,
        bit_multiplication_count,
        karatsuba_field_multiplication_conjunction_count,
    )?;
    let tower_binary_conjunction_count = derive_binary_conjunction_count(
        full_field_multiplication_count,
        bit_by_field_multiplication_count,
        bit_multiplication_count,
        tower_field_multiplication_conjunction_count,
    )?;
    let tower_binary_exclusive_or_count = checked_multiply(
        full_field_multiplication_count,
        tower_field_multiplication_exclusive_or_count,
    )?;
    let tower_binary_gate_count = checked_add(
        tower_binary_conjunction_count,
        tower_binary_exclusive_or_count,
    )?;
    let current_scalar_evaluation_bit_length = checked_multiply(
        current_scalar_binary_conjunction_count,
        remote_evaluation_bit_count_per_binary_gate,
    )?;
    let bilinear_evaluation_bit_length_floor = checked_multiply(
        bilinear_binary_conjunction_floor,
        remote_evaluation_bit_count_per_binary_gate,
    )?;
    let karatsuba_evaluation_bit_length = checked_multiply(
        karatsuba_binary_conjunction_count,
        remote_evaluation_bit_count_per_binary_gate,
    )?;
    let tower_evaluation_bit_length = checked_multiply(
        tower_binary_gate_count,
        remote_evaluation_bit_count_per_binary_gate,
    )?;
    let current_scalar_evaluation_byte_length =
        checked_ceiling_divide(current_scalar_evaluation_bit_length, u8::BITS.into())?;
    let karatsuba_evaluation_byte_length =
        checked_ceiling_divide(karatsuba_evaluation_bit_length, u8::BITS.into())?;
    let bilinear_evaluation_byte_length_floor =
        checked_ceiling_divide(bilinear_evaluation_bit_length_floor, u8::BITS.into())?;
    let tower_evaluation_byte_length =
        checked_ceiling_divide(tower_evaluation_bit_length, u8::BITS.into())?;

    Ok(BinaryRingPackedMpcCircuitEvaluationFloor {
        full_field_multiplication_count,
        bit_by_field_multiplication_count,
        bit_multiplication_count,
        current_scalar_field_multiplication_conjunction_count,
        current_scalar_binary_conjunction_count,
        current_scalar_evaluation_bit_length,
        current_scalar_evaluation_byte_length,
        minimum_maximum_participant_current_scalar_upload_byte_length: checked_ceiling_divide(
            current_scalar_evaluation_byte_length,
            participant_count,
        )?,
        karatsuba_field_multiplication_conjunction_count,
        karatsuba_binary_conjunction_count,
        karatsuba_evaluation_bit_length,
        karatsuba_evaluation_byte_length,
        minimum_maximum_participant_karatsuba_upload_byte_length: checked_ceiling_divide(
            karatsuba_evaluation_byte_length,
            participant_count,
        )?,
        tower_field_multiplication_conjunction_count,
        tower_field_multiplication_exclusive_or_count,
        tower_binary_conjunction_count,
        tower_binary_exclusive_or_count,
        tower_binary_gate_count,
        tower_evaluation_bit_length,
        tower_evaluation_byte_length,
        minimum_maximum_participant_tower_upload_byte_length: checked_ceiling_divide(
            tower_evaluation_byte_length,
            participant_count,
        )?,
        bilinear_field_multiplication_conjunction_floor,
        bilinear_binary_conjunction_floor,
        bilinear_evaluation_bit_length_floor,
        bilinear_evaluation_byte_length_floor,
        minimum_maximum_participant_bilinear_upload_byte_length_floor: checked_ceiling_divide(
            bilinear_evaluation_byte_length_floor,
            participant_count,
        )?,
    })
}

fn derive_binary_conjunction_count(
    full_field_multiplication_count: u64,
    bit_by_field_multiplication_count: u64,
    bit_multiplication_count: u64,
    field_multiplication_conjunction_count: u64,
) -> Result<u64, TallyPreparationError> {
    checked_sum(&[
        checked_multiply(
            full_field_multiplication_count,
            field_multiplication_conjunction_count,
        )?,
        checked_multiply(bit_by_field_multiplication_count, FIELD_BIT_LENGTH)?,
        bit_multiplication_count,
    ])
}

fn checked_ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, TallyPreparationError> {
    if divisor == 0 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    checked_add(quotient, u64::from(remainder != 0))
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}
