use core::num::NonZeroU16;

use crate::tally_circuit::TALLY_BALLOT_ATTEMPT_COUNT;

use super::TallyPreparationError;

/// Separates retry geometry inside one ballot from fresh preparation retries.
///
/// This unactivated parameter object does not select a maximum preparation
/// attempt count. A future suite must encode that positive value explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationAttemptLimits {
    ballot_attempt_count: NonZeroU16,
    maximum_preparation_attempt_count: NonZeroU16,
}

impl PreparationAttemptLimits {
    pub(crate) fn new(
        ballot_attempt_count: u16,
        maximum_preparation_attempt_count: u16,
    ) -> Result<Self, TallyPreparationError> {
        let ballot_attempt_count = NonZeroU16::new(ballot_attempt_count)
            .ok_or(TallyPreparationError::BallotAttemptCountZero)?;
        let maximum_preparation_attempt_count = NonZeroU16::new(maximum_preparation_attempt_count)
            .ok_or(TallyPreparationError::MaximumPreparationAttemptCountZero)?;

        Ok(Self {
            ballot_attempt_count,
            maximum_preparation_attempt_count,
        })
    }

    pub(crate) fn for_current_tally_circuit(
        maximum_preparation_attempt_count: u16,
    ) -> Result<Self, TallyPreparationError> {
        Self::new(
            u16::try_from(TALLY_BALLOT_ATTEMPT_COUNT)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
            maximum_preparation_attempt_count,
        )
    }

    pub(crate) const fn ballot_attempt_count(self) -> u16 {
        self.ballot_attempt_count.get()
    }

    pub(crate) const fn maximum_preparation_attempt_count(self) -> u16 {
        self.maximum_preparation_attempt_count.get()
    }
}

/// Per-attempt lower-bound inputs derived from an exact preparation schema.
///
/// A zero retained-public value is a valid lower bound when the corresponding
/// emitted burn or success record has not yet been compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationAttemptResourceFloorInput {
    pub(crate) private_delivery_byte_length_per_fully_delivered_attempt: u64,
    pub(crate) retained_public_byte_length_per_burned_attempt: u64,
    pub(crate) retained_public_byte_length_per_successful_attempt: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationAttemptResourceFloor {
    pub(crate) one_success_upload_byte_length: u64,
    pub(crate) maximum_fully_delivered_private_byte_length: u64,
    pub(crate) maximum_late_burn_then_success_upload_byte_length: u64,
    pub(crate) maximum_all_burn_upload_byte_length: u64,
    pub(crate) maximum_reachable_upload_byte_length: u64,
}

impl PreparationAttemptResourceFloor {
    pub(crate) fn derive(
        limits: PreparationAttemptLimits,
        input: PreparationAttemptResourceFloorInput,
    ) -> Result<Self, TallyPreparationError> {
        let maximum_preparation_attempt_count =
            u64::from(limits.maximum_preparation_attempt_count());
        let maximum_burned_attempt_count = maximum_preparation_attempt_count - 1;

        let one_success_upload_byte_length = checked_add(
            input.private_delivery_byte_length_per_fully_delivered_attempt,
            input.retained_public_byte_length_per_successful_attempt,
        )?;
        let maximum_fully_delivered_private_byte_length = checked_product(
            input.private_delivery_byte_length_per_fully_delivered_attempt,
            maximum_preparation_attempt_count,
        )?;
        let retained_late_burn_byte_length = checked_product(
            input.retained_public_byte_length_per_burned_attempt,
            maximum_burned_attempt_count,
        )?;
        let maximum_late_burn_then_success_upload_byte_length = checked_sum(&[
            maximum_fully_delivered_private_byte_length,
            retained_late_burn_byte_length,
            input.retained_public_byte_length_per_successful_attempt,
        ])?;
        let maximum_all_burn_upload_byte_length = checked_product(
            checked_add(
                input.private_delivery_byte_length_per_fully_delivered_attempt,
                input.retained_public_byte_length_per_burned_attempt,
            )?,
            maximum_preparation_attempt_count,
        )?;
        let maximum_reachable_upload_byte_length =
            maximum_late_burn_then_success_upload_byte_length
                .max(maximum_all_burn_upload_byte_length);

        Ok(Self {
            one_success_upload_byte_length,
            maximum_fully_delivered_private_byte_length,
            maximum_late_burn_then_success_upload_byte_length,
            maximum_all_burn_upload_byte_length,
            maximum_reachable_upload_byte_length,
        })
    }

    pub(crate) const fn excess_over_upload_target(self, upload_target: u64) -> u64 {
        self.maximum_reachable_upload_byte_length
            .saturating_sub(upload_target)
    }

    pub(crate) fn exceeds_architecture_review_boundary(
        self,
        upload_target: u64,
    ) -> Result<bool, TallyPreparationError> {
        let architecture_review_boundary = checked_add(upload_target, upload_target / 2)?;
        Ok(self.maximum_reachable_upload_byte_length > architecture_review_boundary)
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_product(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, TallyPreparationError> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}
