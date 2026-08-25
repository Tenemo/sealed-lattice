use crate::foundation::{
    FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
};

use super::{
    BinaryFieldElement256,
    output_sharing::canonical_evaluation_point,
    replicated_random_sharing::{BinaryFieldPolynomial, ReplicatedRandomSharingSubset},
    replicated_sharing_simulator_basis::{
        ReplicatedSharingHiddenComponents, ReplicatedSharingSimulatorBasis,
        ReplicatedSharingSimulatorBasisError,
    },
};

#[test]
fn every_completion_corruption_set_has_an_exact_hidden_opening_basis() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let subsets = ReplicatedRandomSharingSubset::all(participant_count).unwrap();
    assert_eq!(subsets.len(), 120);

    for (subset_ordinal, subset) in subsets.into_iter().enumerate() {
        let corrupt_positions = subset.excluded_positions();
        let basis =
            ReplicatedSharingSimulatorBasis::new(participant_count, &corrupt_positions).unwrap();
        assert_eq!(basis.maximum_opening_degree(), 6);
        assert_eq!(basis.random_sharing_basis().degree(), 3);
        assert_eq!(basis.zero_sharing_bases().len(), 3);
        assert_eq!(
            basis
                .zero_sharing_bases()
                .iter()
                .map(BinaryFieldPolynomial::degree)
                .collect::<Vec<_>>(),
            vec![4, 5, 6]
        );

        let hidden_components = hostile_hidden_components(subset_ordinal, 3);
        let difference = basis.reassemble(&hidden_components).unwrap();
        let decomposed = basis.decompose(&difference).unwrap();
        assert_eq!(decomposed, hidden_components);
        assert_eq!(basis.reassemble(&decomposed).unwrap(), difference);

        let direct_test_points = (0..participant_count)
            .map(|roster_position| {
                canonical_evaluation_point(participant_count, roster_position).unwrap()
            })
            .chain([
                BinaryFieldElement256::ZERO,
                hostile_field_element(subset_ordinal, 0x91),
            ]);
        for test_point in direct_test_points {
            assert_eq!(
                difference.evaluate(test_point),
                direct_hidden_difference_evaluation(
                    participant_count,
                    &corrupt_positions,
                    &hidden_components,
                    test_point,
                )
            );
        }
    }
}

#[test]
fn every_configurable_fault_geometry_round_trips_its_derived_basis() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let active_fault_bound = usize::from(
            derive_foundation_roster_parameters(participant_count)
                .unwrap()
                .active_fault_bound,
        );
        let corrupt_positions = (0..u16::try_from(active_fault_bound).unwrap()).collect::<Vec<_>>();
        let basis =
            ReplicatedSharingSimulatorBasis::new(participant_count, &corrupt_positions).unwrap();
        assert_eq!(basis.maximum_opening_degree(), 2 * active_fault_bound);

        let hidden_components =
            hostile_hidden_components(usize::from(participant_count), active_fault_bound);
        let difference = basis.reassemble(&hidden_components).unwrap();
        assert_eq!(basis.decompose(&difference).unwrap(), hidden_components);
    }
}

#[test]
fn differences_outside_the_exact_kernel_are_refused() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let corrupt_positions = [0, 4, 9];
    let basis =
        ReplicatedSharingSimulatorBasis::new(participant_count, &corrupt_positions).unwrap();

    let excessive_degree = BinaryFieldPolynomial::monomial(
        basis.maximum_opening_degree() + 1,
        BinaryFieldElement256::ONE,
    );
    assert_eq!(
        basis.decompose(&excessive_degree),
        Err(
            ReplicatedSharingSimulatorBasisError::DifferenceDegreeOutOfRange {
                maximum_degree: 6,
                actual_degree: 7,
            }
        )
    );

    let visible_difference = BinaryFieldPolynomial::constant(BinaryFieldElement256::ONE);
    assert_eq!(
        basis.decompose(&visible_difference),
        Err(
            ReplicatedSharingSimulatorBasisError::DifferenceVisibleAtCorruptPosition {
                roster_position: 0,
            }
        )
    );
}

#[test]
fn corrupt_position_inventory_must_be_complete_and_canonical() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    assert_eq!(
        ReplicatedSharingSimulatorBasis::new(participant_count, &[0, 4]),
        Err(
            ReplicatedSharingSimulatorBasisError::CorruptPositionCountMismatch {
                expected: 3,
                actual: 2,
            }
        )
    );
    assert_eq!(
        ReplicatedSharingSimulatorBasis::new(participant_count, &[0, 4, 4]),
        Err(ReplicatedSharingSimulatorBasisError::CorruptPositionsNotCanonical)
    );
    assert_eq!(
        ReplicatedSharingSimulatorBasis::new(participant_count, &[9, 4, 0]),
        Err(ReplicatedSharingSimulatorBasisError::CorruptPositionsNotCanonical)
    );
}

fn hostile_hidden_components(
    test_ordinal: usize,
    zero_component_count: usize,
) -> ReplicatedSharingHiddenComponents {
    ReplicatedSharingHiddenComponents::new(
        hostile_field_element(test_ordinal, 0x31),
        (0..zero_component_count)
            .map(|component_position| {
                hostile_field_element(test_ordinal + component_position + 1, 0x5b)
            })
            .collect(),
    )
}

fn direct_hidden_difference_evaluation(
    participant_count: u16,
    corrupt_positions: &[u16],
    hidden_components: &ReplicatedSharingHiddenComponents,
    evaluation_point: BinaryFieldElement256,
) -> BinaryFieldElement256 {
    let (root_at_evaluation_point, root_at_zero) = corrupt_positions.iter().fold(
        (BinaryFieldElement256::ONE, BinaryFieldElement256::ONE),
        |(evaluated_root, constant_root), roster_position| {
            let corrupt_evaluation_point =
                canonical_evaluation_point(participant_count, *roster_position).unwrap();
            (
                evaluated_root.multiply(evaluation_point.add(corrupt_evaluation_point)),
                constant_root.multiply(corrupt_evaluation_point),
            )
        },
    );
    let normalized_random_basis =
        root_at_evaluation_point.multiply(root_at_zero.multiplicative_inverse().unwrap());
    let random_contribution = hidden_components
        .random_sharing_component()
        .multiply(normalized_random_basis);
    let mut evaluation_power = evaluation_point;
    hidden_components.zero_sharing_components().iter().fold(
        random_contribution,
        |evaluated_difference, zero_component| {
            let contribution = zero_component
                .multiply(root_at_evaluation_point)
                .multiply(evaluation_power);
            evaluation_power = evaluation_power.multiply(evaluation_point);
            evaluated_difference.add(contribution)
        },
    )
}

fn hostile_field_element(test_ordinal: usize, domain_byte: u8) -> BinaryFieldElement256 {
    let mut bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = domain_byte
            .wrapping_add(u8::try_from(test_ordinal % 251).unwrap())
            .wrapping_mul(u8::try_from(byte_position + 1).unwrap())
            ^ u8::try_from((test_ordinal + 3 * byte_position) % 256).unwrap();
    }
    BinaryFieldElement256::from_canonical_bytes(&bytes).unwrap()
}
