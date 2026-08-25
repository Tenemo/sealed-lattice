use subtle::ConstantTimeEq;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::{
        DEGREE_THREE_RECONSTRUCTION_THRESHOLD, DegreeThreeMaskShare, reconstruct_degree_three_mask,
    },
};

/// Reconstructs one public authenticated-opening key field and checks it
/// against one participant's private preparation share.
///
/// The public interpolation basis is fixed to roster positions zero through
/// three. A participant in that basis compares the published value directly
/// with its private share. Every other participant supplies a fifth point,
/// which must lie on the uniquely interpolated degree-three polynomial.
///
/// This is only the field-level algebra used before an all-ten release
/// acknowledgement. It verifies no encoding, signature, predecessor root,
/// record coordinate, stream completeness, state, or malicious-MPC source and
/// cannot mint any protocol capability.
pub(crate) fn reconstruct_locally_checked_authenticated_key_field(
    expected_participant_count: u16,
    published_basis_shares: &[DegreeThreeMaskShare],
    local_share: DegreeThreeMaskShare,
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    if published_basis_shares.len() != DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
        return Err(
            TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                expected: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
                actual: published_basis_shares.len(),
            },
        );
    }
    if local_share.participant_count() != expected_participant_count {
        return Err(TallyPreparationError::ParticipantCountMismatch);
    }
    for (basis_position, share) in published_basis_shares.iter().copied().enumerate() {
        let expected_roster_position =
            u16::try_from(basis_position).map_err(|_| TallyPreparationError::IntegerConversion)?;
        if share.roster_position() != expected_roster_position {
            return Err(
                TallyPreparationError::AuthenticatedKeyReleaseBasisPositionMismatch {
                    basis_position,
                    expected_roster_position,
                    actual_roster_position: share.roster_position(),
                },
            );
        }
    }

    if usize::from(local_share.roster_position()) < DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
        let published_local_share = published_basis_shares
            .get(usize::from(local_share.roster_position()))
            .copied()
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if published_local_share
            .value()
            .ct_eq(&local_share.value())
            .unwrap_u8()
            != 1
        {
            return Err(TallyPreparationError::InconsistentShare {
                roster_position: local_share.roster_position(),
            });
        }
        reconstruct_degree_three_mask(expected_participant_count, published_basis_shares)
    } else {
        let mut shares = Vec::with_capacity(DEGREE_THREE_RECONSTRUCTION_THRESHOLD + 1);
        shares.extend_from_slice(published_basis_shares);
        shares.push(local_share);
        reconstruct_degree_three_mask(expected_participant_count, &shares)
    }
}
