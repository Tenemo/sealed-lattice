use crate::{
    foundation::{DECLARED_ADVERSARIAL_QUERY_BUDGET, derive_foundation_roster_parameters},
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    TallyPreparationError, authenticated_opening::AUTHENTICATED_SHARE_SALT_BYTE_LENGTH,
    garbled_resource_model::GarbledTallyResourceLowerBound, label_encoding::LABEL_BODY_BYTE_LENGTH,
    output_sharing::DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
};

const HASH_OUTPUT_BIT_LENGTH: u64 = 512;
const BITS_PER_BYTE: u64 = 8;
const ADAPTIVE_REPROGRAMMING_STAGE_COUNT: u64 = 1;
const ADAPTIVE_REPROGRAMMING_COEFFICIENT: u128 = 4;

/// Exact census for the current candidate core's adaptive-oracle repair.
///
/// The hidden-point counts are diagnostics. They are not a multiplicative
/// guessing factor: canonical domain and coordinate framing makes each basis
/// query select at most one hidden coordinate. The advantage fields record
/// only the arithmetic consequence of a separately proved measured-query
/// probability of at most `2^-minimum_hidden_point_entropy_bit_count`.
/// `roster_fault_bound_within_implemented_share_privacy` and
/// `implemented_share_threshold_matches_roster` expose whether the current
/// degree-three sharing primitive can support that premise for the selected
/// roster. The completion profile satisfies both; the general circuit census
/// does not silently generalize the fixed sharing degree.
///
/// This census excludes the unimplemented malicious preparation transcript,
/// wrappers, signatures, mailboxes, repeated capsules, and the fixed-Keccak
/// transition. It cannot authorize admission, mint a capability, or establish
/// a numeric composed security result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdaptiveOracleRepairCensus {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) honest_holder_count: u64,
    pub(crate) implemented_share_reconstruction_threshold: u64,
    pub(crate) implemented_share_privacy_fault_bound: u64,
    pub(crate) roster_fault_bound_within_implemented_share_privacy: bool,
    pub(crate) implemented_share_threshold_matches_roster: bool,
    pub(crate) input_bit_count: u64,
    pub(crate) input_bit_count_per_participant: u64,
    pub(crate) fresh_label_wire_count: u64,
    pub(crate) conjunction_gate_count: u64,
    pub(crate) output_mask_count: u64,
    pub(crate) modeled_label_commitment_call_count: u64,
    pub(crate) modeled_authenticated_share_commitment_call_count: u64,
    pub(crate) modeled_garbling_generation_call_count: u64,
    pub(crate) modeled_garbling_evaluation_call_count: u64,
    pub(crate) modeled_core_shared_oracle_call_count: u64,
    pub(crate) modeled_core_shared_oracle_output_bit_count: u64,
    pub(crate) initial_hidden_label_commitment_point_count: u64,
    pub(crate) initial_hidden_garbling_point_count: u64,
    pub(crate) initial_hidden_label_share_commitment_point_count: u64,
    pub(crate) initial_hidden_scalar_share_commitment_point_count: u64,
    pub(crate) initial_hidden_point_count: u64,
    pub(crate) activation_patched_label_commitment_point_count: u64,
    pub(crate) activation_patched_garbling_point_count: u64,
    pub(crate) activation_patched_label_share_commitment_point_count: u64,
    pub(crate) activation_patched_active_row_commitment_point_count: u64,
    pub(crate) activation_patched_output_mask_commitment_point_count: u64,
    pub(crate) maximum_activation_patched_input_mask_commitment_point_count: u64,
    pub(crate) minimum_remaining_hidden_point_count: u64,
    pub(crate) maximum_remaining_hidden_point_count: u64,
    pub(crate) minimum_hidden_point_entropy_bit_count: u64,
    pub(crate) authenticated_share_salt_entropy_bit_count: u64,
    pub(crate) adaptive_reprogramming_stage_count: u64,
    pub(crate) declared_adversarial_query_budget: u128,
    pub(crate) conditional_advantage_numerator: u128,
    pub(crate) conditional_advantage_denominator_power: u64,
    pub(crate) conditional_strict_power_of_two_bound_exponent: u64,
}

impl AdaptiveOracleRepairCensus {
    pub(crate) fn derive(circuit: &CompiledTallyCircuit) -> Result<Self, TallyPreparationError> {
        let resource_lower_bound = GarbledTallyResourceLowerBound::derive(circuit)?;
        let participant_count = resource_lower_bound.participant_count;
        let roster_parameters = derive_foundation_roster_parameters(
            circuit.profile().participant_count(),
        )
        .ok_or(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count: circuit.profile().participant_count(),
        })?;
        let active_fault_bound = u64::from(roster_parameters.active_fault_bound);
        let honest_holder_count = participant_count
            .checked_sub(active_fault_bound)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let implemented_share_reconstruction_threshold =
            u64::try_from(DEGREE_THREE_RECONSTRUCTION_THRESHOLD)
                .map_err(|_| TallyPreparationError::IntegerConversion)?;
        let implemented_share_privacy_fault_bound = implemented_share_reconstruction_threshold
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let roster_fault_bound_within_implemented_share_privacy = participant_count
            >= implemented_share_reconstruction_threshold
            && active_fault_bound <= implemented_share_privacy_fault_bound;
        let implemented_share_threshold_matches_roster = participant_count
            >= implemented_share_reconstruction_threshold
            && u64::from(roster_parameters.reconstruction_threshold)
                == implemented_share_reconstruction_threshold;
        let input_bit_count = resource_lower_bound.input_bit_count;
        if !input_bit_count.is_multiple_of(participant_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let input_bit_count_per_participant = input_bit_count / participant_count;
        let output_mask_count = checked_add(
            resource_lower_bound.public_output_bit_count,
            resource_lower_bound.private_result_bit_count,
        )?;

        let modeled_label_commitment_call_count = resource_lower_bound.label_commitment_count;
        let modeled_authenticated_share_commitment_call_count =
            resource_lower_bound.total_share_record_count;
        let modeled_garbling_generation_call_count = resource_lower_bound.garbling_hash_call_count;
        let modeled_garbling_evaluation_call_count =
            resource_lower_bound.evaluation_hash_call_count;
        let modeled_core_shared_oracle_call_count = checked_sum(&[
            modeled_label_commitment_call_count,
            modeled_authenticated_share_commitment_call_count,
            modeled_garbling_generation_call_count,
            modeled_garbling_evaluation_call_count,
        ])?;
        let modeled_core_shared_oracle_output_bit_count = checked_sum(&[
            checked_multiply(modeled_label_commitment_call_count, HASH_OUTPUT_BIT_LENGTH)?,
            checked_multiply(
                modeled_authenticated_share_commitment_call_count,
                HASH_OUTPUT_BIT_LENGTH,
            )?,
            checked_multiply(
                modeled_garbling_generation_call_count,
                resource_lower_bound.garbling_output_bit_length_per_call,
            )?,
            checked_multiply(
                modeled_garbling_evaluation_call_count,
                resource_lower_bound.garbling_output_bit_length_per_call,
            )?,
        ])?;

        // Privacy needs one statically designated honest label component. The
        // remaining honest holders protect authenticated Shamir openings.
        let initial_hidden_label_commitment_point_count =
            checked_multiply(resource_lower_bound.fresh_label_wire_count, 2)?;
        let initial_hidden_garbling_point_count = resource_lower_bound.and_row_count;
        let initial_hidden_label_share_commitment_point_count =
            checked_multiply(checked_multiply(input_bit_count, 2)?, honest_holder_count)?;
        let scalar_record_count_per_holder = resource_lower_bound
            .scalar_share_record_count
            .checked_div(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if checked_multiply(scalar_record_count_per_holder, participant_count)?
            != resource_lower_bound.scalar_share_record_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let initial_hidden_scalar_share_commitment_point_count =
            checked_multiply(scalar_record_count_per_holder, honest_holder_count)?;
        let initial_hidden_point_count = checked_sum(&[
            initial_hidden_label_commitment_point_count,
            initial_hidden_garbling_point_count,
            initial_hidden_label_share_commitment_point_count,
            initial_hidden_scalar_share_commitment_point_count,
        ])?;

        let activation_patched_label_commitment_point_count =
            resource_lower_bound.fresh_label_wire_count;
        let activation_patched_garbling_point_count = resource_lower_bound.conjunction_gate_count;
        let activation_patched_label_share_commitment_point_count =
            checked_multiply(input_bit_count, honest_holder_count)?;
        let activation_patched_active_row_commitment_point_count = checked_multiply(
            resource_lower_bound.conjunction_gate_count,
            honest_holder_count,
        )?;
        let activation_patched_output_mask_commitment_point_count =
            checked_multiply(output_mask_count, honest_holder_count)?;
        let maximum_activation_patched_input_mask_commitment_point_count =
            checked_multiply(input_bit_count, honest_holder_count)?;

        let common_activation_patched_point_count = checked_sum(&[
            activation_patched_label_commitment_point_count,
            activation_patched_garbling_point_count,
            activation_patched_label_share_commitment_point_count,
            activation_patched_active_row_commitment_point_count,
            activation_patched_output_mask_commitment_point_count,
        ])?;
        let maximum_remaining_hidden_point_count = initial_hidden_point_count
            .checked_sub(common_activation_patched_point_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let minimum_remaining_hidden_point_count = maximum_remaining_hidden_point_count
            .checked_sub(maximum_activation_patched_input_mask_commitment_point_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;

        let minimum_hidden_point_entropy_bit_count = checked_multiply(
            u64::try_from(LABEL_BODY_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
            BITS_PER_BYTE,
        )?;
        let authenticated_share_salt_entropy_bit_count = checked_multiply(
            u64::try_from(AUTHENTICATED_SHARE_SALT_BYTE_LENGTH)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
            BITS_PER_BYTE,
        )?;
        if !minimum_hidden_point_entropy_bit_count.is_multiple_of(2) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let conditional_advantage_denominator_power = minimum_hidden_point_entropy_bit_count / 2;
        let conditional_advantage_numerator = DECLARED_ADVERSARIAL_QUERY_BUDGET
            .checked_mul(ADAPTIVE_REPROGRAMMING_COEFFICIENT)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let numerator_power_of_two_upper_bound = u64::from(
            u128::BITS
                .checked_sub(conditional_advantage_numerator.leading_zeros())
                .ok_or(TallyPreparationError::GeometryMismatch)?,
        );
        let conditional_strict_power_of_two_bound_exponent =
            conditional_advantage_denominator_power
                .checked_sub(numerator_power_of_two_upper_bound)
                .ok_or(TallyPreparationError::GeometryMismatch)?;

        Ok(Self {
            participant_count,
            active_fault_bound,
            honest_holder_count,
            implemented_share_reconstruction_threshold,
            implemented_share_privacy_fault_bound,
            roster_fault_bound_within_implemented_share_privacy,
            implemented_share_threshold_matches_roster,
            input_bit_count,
            input_bit_count_per_participant,
            fresh_label_wire_count: resource_lower_bound.fresh_label_wire_count,
            conjunction_gate_count: resource_lower_bound.conjunction_gate_count,
            output_mask_count,
            modeled_label_commitment_call_count,
            modeled_authenticated_share_commitment_call_count,
            modeled_garbling_generation_call_count,
            modeled_garbling_evaluation_call_count,
            modeled_core_shared_oracle_call_count,
            modeled_core_shared_oracle_output_bit_count,
            initial_hidden_label_commitment_point_count,
            initial_hidden_garbling_point_count,
            initial_hidden_label_share_commitment_point_count,
            initial_hidden_scalar_share_commitment_point_count,
            initial_hidden_point_count,
            activation_patched_label_commitment_point_count,
            activation_patched_garbling_point_count,
            activation_patched_label_share_commitment_point_count,
            activation_patched_active_row_commitment_point_count,
            activation_patched_output_mask_commitment_point_count,
            maximum_activation_patched_input_mask_commitment_point_count,
            minimum_remaining_hidden_point_count,
            maximum_remaining_hidden_point_count,
            minimum_hidden_point_entropy_bit_count,
            authenticated_share_salt_entropy_bit_count,
            adaptive_reprogramming_stage_count: ADAPTIVE_REPROGRAMMING_STAGE_COUNT,
            declared_adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            conditional_advantage_numerator,
            conditional_advantage_denominator_power,
            conditional_strict_power_of_two_bound_exponent,
        })
    }

    pub(crate) fn remaining_hidden_point_count(
        self,
        submitted_participant_count: u16,
    ) -> Result<u64, TallyPreparationError> {
        let submitted_participant_count = u64::from(submitted_participant_count);
        if submitted_participant_count > self.participant_count {
            return Err(TallyPreparationError::SubmittedParticipantCountOutOfRange {
                submitted_participant_count,
                participant_count: self.participant_count,
            });
        }
        let omitted_participant_count = self
            .participant_count
            .checked_sub(submitted_participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let patched_input_mask_commitment_point_count = checked_multiply(
            checked_multiply(
                omitted_participant_count,
                self.input_bit_count_per_participant,
            )?,
            self.honest_holder_count,
        )?;
        self.maximum_remaining_hidden_point_count
            .checked_sub(patched_input_mask_commitment_point_count)
            .ok_or(TallyPreparationError::GeometryMismatch)
    }
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
