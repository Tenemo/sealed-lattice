use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext,
    output_sharing::canonical_evaluation_point,
    replicated_beaver_opening::TripleReductionOpeningCoordinate,
    replicated_beaver_simulator::{
        ReplicatedBeaverSimulationSequence, ReplicatedBeaverSimulatorError,
        ReplicatedBeaverSimulatorPolynomialRole, ReplicatedBeaverTripleOpeningSimulator,
        ReplicatedBeaverTripleOpeningWitness,
    },
    replicated_random_sharing::{BinaryFieldPolynomial, ReplicatedRandomSharingSubset},
    replicated_sharing_simulator_basis::{
        ReplicatedSharingHiddenComponents, ReplicatedSharingSimulatorBasis,
        ReplicatedSharingSimulatorBasisError,
    },
};

const COMPLETION_PARTICIPANT_COUNT: u16 = 10;
const COMPLETION_SHARING_DEGREE: usize = 3;

#[test]
fn every_completion_corruption_set_retargets_the_exact_affine_fiber() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT);
    let context = preparation_context(0x41, &circuit);
    let coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x52), 0).unwrap();
    let subsets = ReplicatedRandomSharingSubset::all(COMPLETION_PARTICIPANT_COUNT).unwrap();
    assert_eq!(subsets.len(), 120);

    for (subset_ordinal, subset) in subsets.into_iter().enumerate() {
        let corrupt_positions = subset.excluded_positions();
        let simulator = ReplicatedBeaverTripleOpeningSimulator::new(
            COMPLETION_PARTICIPANT_COUNT,
            &corrupt_positions,
        )
        .unwrap();
        assert_eq!(
            simulator.maximum_sharing_degree(),
            COMPLETION_SHARING_DEGREE
        );
        let (
            witness,
            left_operand_sharing,
            right_operand_sharing,
            reduction_mask_sharing,
            zero_sharing,
        ) = witness(subset_ordinal);
        let original_public_opening = witness.public_opening_polynomial();
        let expected_hidden_component_adjustments = hidden_component_adjustments(subset_ordinal);
        let basis =
            ReplicatedSharingSimulatorBasis::new(COMPLETION_PARTICIPANT_COUNT, &corrupt_positions)
                .unwrap();
        let sampled_public_opening = original_public_opening.add(
            &basis
                .reassemble(&expected_hidden_component_adjustments)
                .unwrap(),
        );

        let result = simulator
            .retarget(coordinate, &witness, sampled_public_opening.clone())
            .unwrap();
        assert_eq!(result.coordinate_identity(), coordinate.identity());
        assert_eq!(
            result.hidden_component_adjustments(),
            &expected_hidden_component_adjustments
        );
        assert_eq!(result.sampled_public_opening(), &sampled_public_opening);
        assert_eq!(
            left_operand_sharing
                .multiply(&right_operand_sharing)
                .add(result.programmed_reduction_mask_sharing())
                .add(result.programmed_zero_sharing()),
            sampled_public_opening
        );
        assert_eq!(
            result
                .output_sharing()
                .evaluate(BinaryFieldElement256::ZERO),
            left_operand_sharing
                .evaluate(BinaryFieldElement256::ZERO)
                .multiply(right_operand_sharing.evaluate(BinaryFieldElement256::ZERO))
        );
        assert!(
            result
                .programmed_zero_sharing()
                .evaluate(BinaryFieldElement256::ZERO)
                .is_zero()
        );

        let opened_constant = result
            .sampled_public_opening()
            .evaluate(BinaryFieldElement256::ZERO);
        for corrupt_position in corrupt_positions {
            let evaluation_point =
                canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, corrupt_position).unwrap();
            assert_eq!(
                result
                    .programmed_reduction_mask_sharing()
                    .evaluate(evaluation_point),
                reduction_mask_sharing.evaluate(evaluation_point)
            );
            assert_eq!(
                result.programmed_zero_sharing().evaluate(evaluation_point),
                zero_sharing.evaluate(evaluation_point)
            );
            assert_eq!(
                result.output_sharing().evaluate(evaluation_point),
                reduction_mask_sharing
                    .evaluate(evaluation_point)
                    .add(opened_constant)
            );
        }
    }
}

#[test]
fn sequence_uses_distinct_canonical_coordinates_in_graph_order() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT);
    let context = preparation_context(0x42, &circuit);
    let corrupt_positions = [1, 5, 8];
    let basis =
        ReplicatedSharingSimulatorBasis::new(COMPLETION_PARTICIPANT_COUNT, &corrupt_positions)
            .unwrap();
    let (witness, ..) = witness(0x71);
    let original_public_opening = witness.public_opening_polynomial();
    let mut sequence =
        ReplicatedBeaverSimulationSequence::new(context, &circuit, hash(0x53), &corrupt_positions)
            .unwrap();
    let mut coordinate_identities = Vec::new();

    for simulation_ordinal in 0..4 {
        let adjustments = hidden_component_adjustments(0x80 + simulation_ordinal);
        let sampled_public_opening =
            original_public_opening.add(&basis.reassemble(&adjustments).unwrap());
        let result = sequence
            .retarget_next(&witness, sampled_public_opening.clone())
            .unwrap();
        assert_eq!(result.sampled_public_opening(), &sampled_public_opening);
        coordinate_identities.push(result.coordinate_identity());
        assert_eq!(
            sequence.next_multiplication_ordinal(),
            u64::try_from(simulation_ordinal + 1).unwrap()
        );
    }

    coordinate_identities.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    coordinate_identities.dedup();
    assert_eq!(coordinate_identities.len(), 4);
}

#[test]
fn rejected_retargeting_does_not_consume_a_simulation_coordinate() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT);
    let context = preparation_context(0x43, &circuit);
    let corrupt_positions = [0, 4, 9];
    let basis =
        ReplicatedSharingSimulatorBasis::new(COMPLETION_PARTICIPANT_COUNT, &corrupt_positions)
            .unwrap();
    let (witness, ..) = witness(0x91);
    let original_public_opening = witness.public_opening_polynomial();
    let mut sequence =
        ReplicatedBeaverSimulationSequence::new(context, &circuit, hash(0x54), &corrupt_positions)
            .unwrap();

    let visible_difference = BinaryFieldPolynomial::constant(BinaryFieldElement256::ONE);
    assert_eq!(
        sequence.retarget_next(&witness, original_public_opening.add(&visible_difference)),
        Err(ReplicatedBeaverSimulatorError::SimulatorBasis(
            ReplicatedSharingSimulatorBasisError::DifferenceVisibleAtCorruptPosition {
                roster_position: 0,
            }
        ))
    );
    assert_eq!(sequence.next_multiplication_ordinal(), 0);

    let admissible_adjustments = hidden_component_adjustments(0x92);
    let sampled_public_opening =
        original_public_opening.add(&basis.reassemble(&admissible_adjustments).unwrap());
    let result = sequence
        .retarget_next(&witness, sampled_public_opening.clone())
        .unwrap();
    let expected_coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x54), 0).unwrap();
    assert_eq!(result.coordinate_identity(), expected_coordinate.identity());
    assert_eq!(result.sampled_public_opening(), &sampled_public_opening);
    assert_eq!(sequence.next_multiplication_ordinal(), 1);
}

#[test]
fn polynomial_and_coordinate_mismatches_are_refused() {
    let excessive_degree_polynomial =
        BinaryFieldPolynomial::monomial(COMPLETION_SHARING_DEGREE + 1, BinaryFieldElement256::ONE);
    let degree_three_polynomial = polynomial(COMPLETION_SHARING_DEGREE, 0xa1);
    let zero_sharing = zero_polynomial(2 * COMPLETION_SHARING_DEGREE, 0xa2);
    assert_eq!(
        ReplicatedBeaverTripleOpeningWitness::new(
            COMPLETION_SHARING_DEGREE,
            excessive_degree_polynomial,
            degree_three_polynomial.clone(),
            degree_three_polynomial.clone(),
            zero_sharing.clone(),
        ),
        Err(ReplicatedBeaverSimulatorError::PolynomialDegreeOutOfRange {
            role: ReplicatedBeaverSimulatorPolynomialRole::LeftOperandSharing,
            maximum_degree: 3,
            actual_degree: 4,
        })
    );
    assert_eq!(
        ReplicatedBeaverTripleOpeningWitness::new(
            COMPLETION_SHARING_DEGREE,
            degree_three_polynomial.clone(),
            degree_three_polynomial.clone(),
            degree_three_polynomial,
            BinaryFieldPolynomial::constant(BinaryFieldElement256::ONE),
        ),
        Err(ReplicatedBeaverSimulatorError::ZeroSharingConstantNotZero)
    );

    let completion_circuit = circuit(COMPLETION_PARTICIPANT_COUNT);
    let completion_context = preparation_context(0x44, &completion_circuit);
    let completion_coordinate = TripleReductionOpeningCoordinate::derive(
        completion_context,
        &completion_circuit,
        hash(0x55),
        0,
    )
    .unwrap();
    let simulator =
        ReplicatedBeaverTripleOpeningSimulator::new(COMPLETION_PARTICIPANT_COUNT, &[0, 4, 9])
            .unwrap();
    let (witness, ..) = witness(0xb1);
    assert_eq!(
        simulator.retarget(
            completion_coordinate,
            &witness,
            BinaryFieldPolynomial::monomial(7, BinaryFieldElement256::ONE),
        ),
        Err(ReplicatedBeaverSimulatorError::PolynomialDegreeOutOfRange {
            role: ReplicatedBeaverSimulatorPolynomialRole::SampledPublicOpening,
            maximum_degree: 6,
            actual_degree: 7,
        })
    );

    let other_participant_count = 9;
    let other_circuit = circuit(other_participant_count);
    let other_context = preparation_context(0x45, &other_circuit);
    let other_coordinate =
        TripleReductionOpeningCoordinate::derive(other_context, &other_circuit, hash(0x55), 0)
            .unwrap();
    assert_eq!(
        simulator.retarget(
            other_coordinate,
            &witness,
            witness.public_opening_polynomial(),
        ),
        Err(
            ReplicatedBeaverSimulatorError::CoordinateParticipantCountMismatch {
                expected: COMPLETION_PARTICIPANT_COUNT,
                actual: other_participant_count,
            }
        )
    );
}

fn witness(
    test_ordinal: usize,
) -> (
    ReplicatedBeaverTripleOpeningWitness,
    BinaryFieldPolynomial,
    BinaryFieldPolynomial,
    BinaryFieldPolynomial,
    BinaryFieldPolynomial,
) {
    let left_operand_sharing = polynomial(COMPLETION_SHARING_DEGREE, test_ordinal + 0x11);
    let right_operand_sharing = polynomial(COMPLETION_SHARING_DEGREE, test_ordinal + 0x23);
    let reduction_mask_sharing = polynomial(COMPLETION_SHARING_DEGREE, test_ordinal + 0x35);
    let zero_sharing = zero_polynomial(2 * COMPLETION_SHARING_DEGREE, test_ordinal + 0x47);
    let witness = ReplicatedBeaverTripleOpeningWitness::new(
        COMPLETION_SHARING_DEGREE,
        left_operand_sharing.clone(),
        right_operand_sharing.clone(),
        reduction_mask_sharing.clone(),
        zero_sharing.clone(),
    )
    .unwrap();
    (
        witness,
        left_operand_sharing,
        right_operand_sharing,
        reduction_mask_sharing,
        zero_sharing,
    )
}

fn hidden_component_adjustments(test_ordinal: usize) -> ReplicatedSharingHiddenComponents {
    ReplicatedSharingHiddenComponents::new(
        hostile_field_element(test_ordinal, 0x59),
        (0..usize::from(FOUNDATION_PROFILE.active_fault_bound))
            .map(|component_position| {
                hostile_field_element(test_ordinal + component_position + 1, 0x6b)
            })
            .collect(),
    )
}

fn polynomial(maximum_degree: usize, test_ordinal: usize) -> BinaryFieldPolynomial {
    BinaryFieldPolynomial::new(
        (0..=maximum_degree)
            .map(|coefficient_position| {
                hostile_field_element(test_ordinal + coefficient_position, 0x7d)
            })
            .collect(),
    )
}

fn zero_polynomial(maximum_degree: usize, test_ordinal: usize) -> BinaryFieldPolynomial {
    BinaryFieldPolynomial::new(
        core::iter::once(BinaryFieldElement256::ZERO)
            .chain((1..=maximum_degree).map(|coefficient_position| {
                hostile_field_element(test_ordinal + coefficient_position, 0x8f)
            }))
            .collect(),
    )
}

fn hostile_field_element(test_ordinal: usize, domain_byte: u8) -> BinaryFieldElement256 {
    let mut bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = domain_byte
            .wrapping_add(u8::try_from(test_ordinal % 251).unwrap())
            .wrapping_mul(u8::try_from(byte_position + 1).unwrap())
            ^ u8::try_from((test_ordinal + 5 * byte_position) % 256).unwrap();
    }
    BinaryFieldElement256::from_canonical_bytes(&bytes).unwrap()
}

fn preparation_context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        hash(marker),
        hash(marker.wrapping_add(1)),
        [marker.wrapping_add(2); 32],
        circuit,
    )
    .unwrap()
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}

fn circuit(participant_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(TallyCircuitProfile::new(participant_count, 2, 1).unwrap())
        .unwrap()
}
