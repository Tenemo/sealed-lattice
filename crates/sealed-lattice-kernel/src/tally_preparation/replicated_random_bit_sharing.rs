use crate::foundation::derive_foundation_roster_parameters;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

/// Visits the authorized subsets in ascending excluded-position-mask order.
///
/// The random-bit owner needs only the random-sharing coordinate from each
/// subset. Keeping that enumeration here prevents its production path from
/// depending on the complete random-and-zero key-ceremony inventory.
pub(super) fn for_each_canonical_random_bit_subset(
    participant_count: u16,
    mut visit: impl FnMut(ReplicatedRandomSharingSubset) -> Result<(), TallyPreparationError>,
) -> Result<(), TallyPreparationError> {
    let roster_parameters = derive_foundation_roster_parameters(participant_count)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let excluded_position_mask_limit = 1_u32
        .checked_shl(u32::from(participant_count))
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    let expected_subset_count =
        ReplicatedRandomSharingGeometry::derive(participant_count)?.authorized_subset_count;
    let mut visited_subset_count = 0_u64;

    for excluded_position_mask in 0..excluded_position_mask_limit {
        if excluded_position_mask.count_ones() != u32::from(roster_parameters.active_fault_bound) {
            continue;
        }
        let excluded_positions = (0..participant_count)
            .filter(|roster_position| {
                let position_bit = 1_u32 << u32::from(*roster_position);
                excluded_position_mask & position_bit != 0
            })
            .collect::<Vec<_>>();
        visit(ReplicatedRandomSharingSubset::from_excluded_positions(
            participant_count,
            &excluded_positions,
        )?)?;
        visited_subset_count = visited_subset_count
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    }

    if visited_subset_count != expected_subset_count {
        return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
    }
    Ok(())
}

/// Precomputed local weights for the replicated-key random-bit construction.
///
/// Component bits are supplied in canonical authorized-subset order, omitting
/// exactly the subsets that do not contain this participant. The omitted
/// subset polynomials evaluate to zero at this participant's point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomBitShareDeriver {
    participant_count: u16,
    roster_position: u16,
    member_subset_weights: Box<[BinaryFieldElement256]>,
}

impl ReplicatedRandomBitShareDeriver {
    pub(crate) fn new(
        participant_count: u16,
        roster_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if roster_position >= participant_count {
            return Err(TallyPreparationError::RosterPositionOutOfRange {
                roster_position,
                participant_count,
            });
        }
        let evaluation_point = canonical_evaluation_point(participant_count, roster_position)?;
        let mut member_subset_weights = Vec::new();
        for_each_canonical_random_bit_subset(participant_count, |subset| {
            if subset.contains(roster_position)? {
                member_subset_weights.push(
                    subset
                        .random_sharing_polynomial(BinaryFieldElement256::ONE)?
                        .evaluate(evaluation_point),
                );
            }
            Ok(())
        })?;
        let expected_component_count = usize::try_from(
            super::replicated_random_sharing::ReplicatedRandomSharingGeometry::derive(
                participant_count,
            )?
            .authorized_subset_count_per_participant,
        )
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if member_subset_weights.len() != expected_component_count
            || member_subset_weights.iter().any(|weight| weight.is_zero())
            || usize::from(roster_parameters.active_fault_bound) + 1
                > usize::from(participant_count)
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok(Self {
            participant_count,
            roster_position,
            member_subset_weights: member_subset_weights.into_boxed_slice(),
        })
    }

    pub(crate) fn component_count(&self) -> usize {
        self.member_subset_weights.len()
    }

    pub(crate) fn derive_share(
        &self,
        component_bits: &[u8],
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        if component_bits.len() != self.member_subset_weights.len() {
            return Err(
                TallyPreparationError::ReplicatedRandomBitComponentCountMismatch {
                    expected: self.member_subset_weights.len(),
                    actual: component_bits.len(),
                },
            );
        }
        component_bits.iter().copied().enumerate().try_fold(
            BinaryFieldElement256::ZERO,
            |share, (component_position, component_bit)| match component_bit {
                0 => Ok(share),
                1 => Ok(share.add(self.member_subset_weights[component_position])),
                value => Err(
                    TallyPreparationError::ReplicatedRandomBitComponentNonCanonical {
                        component_position,
                        value,
                    },
                ),
            },
        )
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }
}
