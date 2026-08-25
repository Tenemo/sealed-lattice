use crate::foundation::FOUNDATION_PROFILE;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    authenticated_key_release::reconstruct_locally_checked_authenticated_key_field,
    output_sharing::{DegreeThreeMaskPolynomial, DegreeThreeMaskShare},
};

#[test]
fn every_participant_reconstructs_the_same_honest_key_field() {
    let polynomial = polynomial(0x71, [0x12, 0x34, 0x56]);
    let shares = polynomial
        .shares(FOUNDATION_PROFILE.participant_count)
        .unwrap();
    let basis = &shares[..4];

    for local_share in shares.iter().copied() {
        assert_eq!(
            reconstruct_locally_checked_authenticated_key_field(
                FOUNDATION_PROFILE.participant_count,
                basis,
                local_share,
            )
            .unwrap(),
            field(0x71)
        );
    }
}

#[test]
fn every_nonbasis_participant_refuses_each_changed_basis_share() {
    let polynomial = polynomial(0x82, [0x23, 0x45, 0x67]);
    let shares = polynomial
        .shares(FOUNDATION_PROFILE.participant_count)
        .unwrap();

    for changed_basis_position in 0..4 {
        let mut changed_basis = shares[..4].to_vec();
        let changed_share = changed_basis[changed_basis_position];
        changed_basis[changed_basis_position] = DegreeThreeMaskShare::new(
            changed_share.participant_count(),
            changed_share.roster_position(),
            changed_share.evaluation_point(),
            changed_share.value().add(BinaryFieldElement256::ONE),
        )
        .unwrap();

        for honest_nonbasis_share in shares[4..].iter().copied() {
            assert_eq!(
                reconstruct_locally_checked_authenticated_key_field(
                    FOUNDATION_PROFILE.participant_count,
                    &changed_basis,
                    honest_nonbasis_share,
                ),
                Err(TallyPreparationError::InconsistentShare {
                    roster_position: honest_nonbasis_share.roster_position(),
                })
            );
        }
    }
}

#[test]
fn basis_participant_refuses_a_published_value_different_from_its_private_share() {
    let polynomial = polynomial(0x93, [0x34, 0x56, 0x78]);
    let shares = polynomial
        .shares(FOUNDATION_PROFILE.participant_count)
        .unwrap();
    let mut changed_basis = shares[..4].to_vec();
    let changed_share = changed_basis[2];
    changed_basis[2] = DegreeThreeMaskShare::new(
        changed_share.participant_count(),
        changed_share.roster_position(),
        changed_share.evaluation_point(),
        changed_share.value().add(BinaryFieldElement256::ONE),
    )
    .unwrap();

    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(
            FOUNDATION_PROFILE.participant_count,
            &changed_basis,
            shares[2],
        ),
        Err(TallyPreparationError::InconsistentShare { roster_position: 2 })
    );
}

#[test]
fn checker_refuses_wrong_basis_size_order_and_participant_count() {
    let polynomial = polynomial(0xa4, [0x45, 0x67, 0x89]);
    let shares = polynomial
        .shares(FOUNDATION_PROFILE.participant_count)
        .unwrap();
    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(
            FOUNDATION_PROFILE.participant_count,
            &shares[..3],
            shares[4],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                expected: 4,
                actual: 3,
            }
        )
    );
    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(
            FOUNDATION_PROFILE.participant_count,
            &shares[..5],
            shares[5],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                expected: 4,
                actual: 5,
            }
        )
    );

    let reordered_basis = [shares[0], shares[2], shares[1], shares[3]];
    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(
            FOUNDATION_PROFILE.participant_count,
            &reordered_basis,
            shares[4],
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyReleaseBasisPositionMismatch {
                basis_position: 1,
                expected_roster_position: 1,
                actual_roster_position: 2,
            }
        )
    );
    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(9, &shares[..4], shares[4]),
        Err(TallyPreparationError::ParticipantCountMismatch)
    );
}

#[test]
fn checker_refuses_a_wrong_nonbasis_private_point() {
    let polynomial = polynomial(0xb5, [0x56, 0x78, 0x9a]);
    let shares = polynomial
        .shares(FOUNDATION_PROFILE.participant_count)
        .unwrap();
    let local_share = shares[8];
    let changed_local_share = DegreeThreeMaskShare::new(
        local_share.participant_count(),
        local_share.roster_position(),
        local_share.evaluation_point(),
        local_share.value().add(BinaryFieldElement256::ONE),
    )
    .unwrap();

    assert_eq!(
        reconstruct_locally_checked_authenticated_key_field(
            FOUNDATION_PROFILE.participant_count,
            &shares[..4],
            changed_local_share,
        ),
        Err(TallyPreparationError::InconsistentShare { roster_position: 8 })
    );
}

fn polynomial(secret: u16, coefficients: [u16; 3]) -> DegreeThreeMaskPolynomial {
    DegreeThreeMaskPolynomial::new(field(secret), coefficients.map(field))
}

fn field(value: u16) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_low_polynomial_u16(value)
}
