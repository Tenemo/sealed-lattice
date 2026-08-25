use crate::{
    foundation::{
        Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    output_sharing::{DEGREE_THREE_RECONSTRUCTION_THRESHOLD, canonical_evaluation_point},
    preparation_multiplication_catalog::PreparationMultiplicationCatalog,
    replicated_beaver_opening::{
        TripleReductionOpeningBurnReason, TripleReductionOpeningCollector,
        TripleReductionOpeningCoordinate, TripleReductionOpeningError,
        TripleReductionOpeningProgress, TripleReductionOpeningSubmission,
    },
    replicated_random_sharing::{BinaryFieldPolynomial, CanonicalPolynomialConsistencyVerifier},
};

const COMPLETION_PARTICIPANT_COUNT: u16 = 10;
const COMPLETION_MAXIMUM_TRIPLE_OPENING_DEGREE: usize = 6;

#[test]
fn three_error_degree_six_correction_has_two_exact_candidates() {
    let zero_polynomial = BinaryFieldPolynomial::zero();
    let alternate_polynomial = polynomial_with_roots(COMPLETION_PARTICIPANT_COUNT, &[0, 1, 2, 3]);
    assert!(alternate_polynomial.degree() <= COMPLETION_MAXIMUM_TRIPLE_OPENING_DEGREE);

    let received_values = (0..COMPLETION_PARTICIPANT_COUNT)
        .map(|roster_position| {
            let evaluation_point =
                canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, roster_position).unwrap();
            if roster_position < 7 {
                zero_polynomial.evaluate(evaluation_point)
            } else {
                alternate_polynomial.evaluate(evaluation_point)
            }
        })
        .collect::<Vec<_>>();
    let zero_agreement_positions = agreement_positions(
        COMPLETION_PARTICIPANT_COUNT,
        &received_values,
        &zero_polynomial,
    );
    let alternate_agreement_positions = agreement_positions(
        COMPLETION_PARTICIPANT_COUNT,
        &received_values,
        &alternate_polynomial,
    );
    assert_eq!(zero_agreement_positions, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(alternate_agreement_positions, vec![0, 1, 2, 3, 7, 8, 9]);
    assert_ne!(zero_polynomial, alternate_polynomial);

    let exact_verifier = CanonicalPolynomialConsistencyVerifier::new(
        COMPLETION_PARTICIPANT_COUNT,
        COMPLETION_MAXIMUM_TRIPLE_OPENING_DEGREE,
    )
    .unwrap();
    assert_eq!(
        exact_verifier
            .interpolate_and_verify(&received_values)
            .unwrap(),
        None
    );
}

#[test]
fn clean_rushing_and_reordered_all_roster_opening_is_algebraically_consistent() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let context = preparation_context(0x21, &circuit);
    let coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x32), 0).unwrap();
    assert_eq!(coordinate.participant_count(), COMPLETION_PARTICIPANT_COUNT);
    assert_eq!(
        coordinate.maximum_degree(),
        COMPLETION_MAXIMUM_TRIPLE_OPENING_DEGREE
    );
    let opening_polynomial = honest_triple_reduction_polynomial();
    assert_eq!(
        opening_polynomial.degree(),
        COMPLETION_MAXIMUM_TRIPLE_OPENING_DEGREE
    );
    let corrupt_positions = [1_u16, 5, 8];
    let honest_positions = (0..COMPLETION_PARTICIPANT_COUNT)
        .filter(|roster_position| !corrupt_positions.contains(roster_position))
        .collect::<Vec<_>>();
    let delivery_order = honest_positions
        .into_iter()
        .rev()
        .chain(corrupt_positions.into_iter().rev())
        .collect::<Vec<_>>();
    let mut collector = TripleReductionOpeningCollector::new(coordinate).unwrap();

    let first_submission = submission(coordinate, delivery_order[0], &opening_polynomial);
    assert_eq!(
        collector.absorb(first_submission).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );
    assert_eq!(
        collector.absorb(first_submission).unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 1,
            required_sender_count: 10,
        }
    );

    let mut final_progress = None;
    for roster_position in delivery_order.into_iter().skip(1) {
        final_progress = Some(
            collector
                .absorb(submission(coordinate, roster_position, &opening_polynomial))
                .unwrap(),
        );
    }
    let TripleReductionOpeningProgress::AlgebraicallyConsistent(result) = final_progress.unwrap()
    else {
        panic!("the complete exact codeword must be algebraically consistent");
    };
    assert_eq!(result.coordinate_identity(), coordinate.identity());
    assert_eq!(result.polynomial(), &opening_polynomial);
    assert_eq!(
        result.opened_constant(),
        opening_polynomial.evaluate(BinaryFieldElement256::ZERO)
    );
    assert_eq!(
        collector.absorb(first_submission),
        Err(TripleReductionOpeningError::AlreadyTerminal)
    );
}

#[test]
fn one_through_three_changed_positions_burn_without_a_polynomial() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let context = preparation_context(0x22, &circuit);
    let coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x33), 0).unwrap();
    let opening_polynomial = honest_triple_reduction_polynomial();

    for changed_position_count in 1..=3_u16 {
        let mut collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
        let mut final_progress = None;
        for roster_position in 0..COMPLETION_PARTICIPANT_COUNT {
            let mut value = opening_polynomial.evaluate(
                canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, roster_position).unwrap(),
            );
            if roster_position >= COMPLETION_PARTICIPANT_COUNT - changed_position_count {
                value = value.add(BinaryFieldElement256::from_low_polynomial_u16(
                    0x700_u16.checked_add(roster_position).unwrap(),
                ));
            }
            final_progress = Some(
                collector
                    .absorb(
                        TripleReductionOpeningSubmission::new(coordinate, roster_position, value)
                            .unwrap(),
                    )
                    .unwrap(),
            );
        }
        assert_eq!(
            final_progress.unwrap(),
            TripleReductionOpeningProgress::BurnRequired(
                TripleReductionOpeningBurnReason::NonCodeword
            )
        );
    }
}

#[test]
fn distance_four_boundary_distinguishes_noncodeword_from_alternate_codeword() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let context = preparation_context(0x23, &circuit);
    let coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x34), 0).unwrap();

    let degree_six_alternate =
        polynomial_with_roots(COMPLETION_PARTICIPANT_COUNT, &[0, 1, 2, 3, 4, 5]);
    assert_eq!(degree_six_alternate.degree(), 6);
    let degree_six_values = evaluations(COMPLETION_PARTICIPANT_COUNT, &degree_six_alternate);
    assert!(degree_six_values[..6].iter().all(|value| value.is_zero()));
    assert!(degree_six_values[6..].iter().all(|value| !value.is_zero()));
    let accepted_result = complete_opening(coordinate, &degree_six_values);
    let TripleReductionOpeningProgress::AlgebraicallyConsistent(accepted_result) = accepted_result
    else {
        panic!("a distance-four alternate codeword must pass the algebra-only check");
    };
    assert_eq!(accepted_result.polynomial(), &degree_six_alternate);

    let degree_seven_noncodeword = degree_six_alternate.multiply(&BinaryFieldPolynomial::monomial(
        1,
        BinaryFieldElement256::ONE,
    ));
    assert_eq!(degree_seven_noncodeword.degree(), 7);
    let degree_seven_values = evaluations(COMPLETION_PARTICIPANT_COUNT, &degree_seven_noncodeword);
    assert!(degree_seven_values[..6].iter().all(|value| value.is_zero()));
    assert!(
        degree_seven_values[6..]
            .iter()
            .all(|value| !value.is_zero())
    );
    assert_eq!(
        complete_opening(coordinate, &degree_seven_values),
        TripleReductionOpeningProgress::BurnRequired(TripleReductionOpeningBurnReason::NonCodeword)
    );
}

#[test]
fn every_supported_fault_geometry_accepts_exact_words_and_burns_changed_fault_positions() {
    let minimum_supported_participant_count = u16::try_from(DEGREE_THREE_RECONSTRUCTION_THRESHOLD)
        .unwrap()
        .max(MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT);
    for participant_count in
        minimum_supported_participant_count..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let active_fault_bound = usize::from(
            derive_foundation_roster_parameters(participant_count)
                .unwrap()
                .active_fault_bound,
        );
        let maximum_degree = 2 * active_fault_bound;
        let polynomial = BinaryFieldPolynomial::new(
            (0..=maximum_degree)
                .map(|coefficient_position| {
                    BinaryFieldElement256::from_low_polynomial_u16(
                        u16::try_from(0x510 + coefficient_position).unwrap(),
                    )
                })
                .collect(),
        );
        let verifier =
            CanonicalPolynomialConsistencyVerifier::new(participant_count, maximum_degree).unwrap();
        let honest_values = evaluations(participant_count, &polynomial);
        assert_eq!(
            verifier.interpolate_and_verify(&honest_values).unwrap(),
            Some(polynomial)
        );

        if active_fault_bound == 0 {
            continue;
        }
        let mut changed_values = honest_values;
        for changed_position in 0..active_fault_bound {
            let roster_position = usize::from(participant_count) - 1 - changed_position;
            changed_values[roster_position] = changed_values[roster_position].add(
                BinaryFieldElement256::from_low_polynomial_u16(
                    u16::try_from(0x620 + changed_position).unwrap(),
                ),
            );
        }
        assert_eq!(
            verifier.interpolate_and_verify(&changed_values).unwrap(),
            None
        );
        assert!(usize::from(participant_count) - active_fault_bound > maximum_degree);
    }
}

#[test]
fn roster_below_the_degree_three_sharing_threshold_is_refused() {
    let unsupported_participant_count =
        u16::try_from(DEGREE_THREE_RECONSTRUCTION_THRESHOLD - 1).unwrap();
    let active_fault_bound = usize::from(
        derive_foundation_roster_parameters(unsupported_participant_count)
            .unwrap()
            .active_fault_bound,
    );
    assert!(matches!(
        CanonicalPolynomialConsistencyVerifier::new(
            unsupported_participant_count,
            2 * active_fault_bound,
        ),
        Err(TallyPreparationError::ParticipantCountOutOfRange {
            participant_count,
        })
            if participant_count == unsupported_participant_count
    ));
}

#[test]
fn missing_equivocated_mixed_context_and_replayed_slots_fail_closed() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let context = preparation_context(0x24, &circuit);
    let coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x35), 0).unwrap();
    let opening_polynomial = honest_triple_reduction_polynomial();

    let mut missing_collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let mut final_pending = None;
    for roster_position in 0..(COMPLETION_PARTICIPANT_COUNT - 1) {
        final_pending = Some(
            missing_collector
                .absorb(submission(coordinate, roster_position, &opening_polynomial))
                .unwrap(),
        );
    }
    assert_eq!(
        final_pending.unwrap(),
        TripleReductionOpeningProgress::Pending {
            received_sender_count: 9,
            required_sender_count: 10,
        }
    );

    let mut equivocation_collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let baseline_submission = submission(coordinate, 0, &opening_polynomial);
    equivocation_collector.absorb(baseline_submission).unwrap();
    let conflicting_submission = TripleReductionOpeningSubmission::new(
        coordinate,
        0,
        baseline_submission_value(&opening_polynomial, 0).add(BinaryFieldElement256::ONE),
    )
    .unwrap();
    assert_eq!(
        equivocation_collector
            .absorb(conflicting_submission)
            .unwrap(),
        TripleReductionOpeningProgress::BurnRequired(
            TripleReductionOpeningBurnReason::Equivocation
        )
    );

    let changed_context = preparation_context(0x25, &circuit);
    let changed_context_coordinate =
        TripleReductionOpeningCoordinate::derive(changed_context, &circuit, hash(0x35), 0).unwrap();
    let changed_predecessor_coordinate =
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x36), 0).unwrap();
    for replayed_coordinate in [changed_context_coordinate, changed_predecessor_coordinate] {
        let mut collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
        assert_eq!(
            collector
                .absorb(submission(replayed_coordinate, 0, &opening_polynomial))
                .unwrap(),
            TripleReductionOpeningProgress::BurnRequired(
                TripleReductionOpeningBurnReason::CoordinateMismatch
            )
        );
    }

    let expected_value = baseline_submission_value(&opening_polynomial, 0);
    let mut wrong_point_collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let wrong_point_submission = TripleReductionOpeningSubmission::from_untrusted_fields(
        coordinate.identity(),
        coordinate.participant_count(),
        0,
        canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, 1).unwrap(),
        expected_value,
    );
    assert_eq!(
        wrong_point_collector
            .absorb(wrong_point_submission)
            .unwrap(),
        TripleReductionOpeningProgress::BurnRequired(
            TripleReductionOpeningBurnReason::EvaluationPointMismatch
        )
    );

    let mut wrong_count_collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let wrong_count_submission = TripleReductionOpeningSubmission::from_untrusted_fields(
        coordinate.identity(),
        coordinate.participant_count() - 1,
        0,
        canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, 0).unwrap(),
        expected_value,
    );
    assert_eq!(
        wrong_count_collector
            .absorb(wrong_count_submission)
            .unwrap(),
        TripleReductionOpeningProgress::BurnRequired(
            TripleReductionOpeningBurnReason::ParticipantCountMismatch
        )
    );

    let mut out_of_range_collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let out_of_range_submission = TripleReductionOpeningSubmission::from_untrusted_fields(
        coordinate.identity(),
        coordinate.participant_count(),
        coordinate.participant_count(),
        BinaryFieldElement256::ONE,
        expected_value,
    );
    assert_eq!(
        out_of_range_collector
            .absorb(out_of_range_submission)
            .unwrap(),
        TripleReductionOpeningProgress::BurnRequired(
            TripleReductionOpeningBurnReason::SenderPositionOutOfRange
        )
    );
}

#[test]
fn opening_coordinate_rejects_an_out_of_range_multiplication_ordinal() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let context = preparation_context(0x26, &circuit);
    assert!(matches!(
        TripleReductionOpeningCoordinate::derive(context, &circuit, hash(0x37), u64::MAX),
        Err(TripleReductionOpeningError::Preparation(
            TallyPreparationError::PreparationMultiplicationIndexOutOfRange { .. }
        ))
    ));
}

#[test]
fn cached_multiplication_catalog_must_match_the_preparation_context() {
    let circuit = circuit(COMPLETION_PARTICIPANT_COUNT, 2, 1);
    let catalog_context = preparation_context(0x27, &circuit);
    let mismatched_context = preparation_context(0x28, &circuit);
    let catalog = PreparationMultiplicationCatalog::derive(catalog_context, &circuit).unwrap();
    assert_eq!(
        TripleReductionOpeningCoordinate::derive_from_catalog(
            mismatched_context,
            &catalog,
            hash(0x38),
            0,
        ),
        Err(TripleReductionOpeningError::Preparation(
            TallyPreparationError::GeometryMismatch,
        ))
    );
}

fn complete_opening(
    coordinate: TripleReductionOpeningCoordinate,
    values: &[BinaryFieldElement256],
) -> TripleReductionOpeningProgress {
    let mut collector = TripleReductionOpeningCollector::new(coordinate).unwrap();
    let mut final_progress = None;
    for (roster_position, value) in values.iter().copied().enumerate() {
        final_progress = Some(
            collector
                .absorb(
                    TripleReductionOpeningSubmission::new(
                        coordinate,
                        u16::try_from(roster_position).unwrap(),
                        value,
                    )
                    .unwrap(),
                )
                .unwrap(),
        );
    }
    final_progress.unwrap()
}

fn submission(
    coordinate: TripleReductionOpeningCoordinate,
    roster_position: u16,
    polynomial: &BinaryFieldPolynomial,
) -> TripleReductionOpeningSubmission {
    TripleReductionOpeningSubmission::new(
        coordinate,
        roster_position,
        baseline_submission_value(polynomial, roster_position),
    )
    .unwrap()
}

fn baseline_submission_value(
    polynomial: &BinaryFieldPolynomial,
    roster_position: u16,
) -> BinaryFieldElement256 {
    polynomial.evaluate(
        canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, roster_position).unwrap(),
    )
}

fn agreement_positions(
    participant_count: u16,
    received_values: &[BinaryFieldElement256],
    polynomial: &BinaryFieldPolynomial,
) -> Vec<u16> {
    (0..participant_count)
        .filter(|roster_position| {
            let evaluation_point =
                canonical_evaluation_point(participant_count, *roster_position).unwrap();
            polynomial.evaluate(evaluation_point) == received_values[usize::from(*roster_position)]
        })
        .collect()
}

fn evaluations(
    participant_count: u16,
    polynomial: &BinaryFieldPolynomial,
) -> Vec<BinaryFieldElement256> {
    (0..participant_count)
        .map(|roster_position| {
            polynomial
                .evaluate(canonical_evaluation_point(participant_count, roster_position).unwrap())
        })
        .collect()
}

fn polynomial_with_roots(participant_count: u16, root_positions: &[u16]) -> BinaryFieldPolynomial {
    root_positions.iter().fold(
        BinaryFieldPolynomial::one(),
        |polynomial, roster_position| {
            polynomial.multiply(&BinaryFieldPolynomial::new(vec![
                canonical_evaluation_point(participant_count, *roster_position).unwrap(),
                BinaryFieldElement256::ONE,
            ]))
        },
    )
}

fn honest_triple_reduction_polynomial() -> BinaryFieldPolynomial {
    let left = BinaryFieldPolynomial::new(
        (0..=3)
            .map(|coefficient_position| {
                BinaryFieldElement256::from_low_polynomial_u16(0x101 + coefficient_position)
            })
            .collect(),
    );
    let right = BinaryFieldPolynomial::new(
        (0..=3)
            .map(|coefficient_position| {
                BinaryFieldElement256::from_low_polynomial_u16(0x211 + coefficient_position)
            })
            .collect(),
    );
    let reduction_mask = BinaryFieldPolynomial::new(
        (0..=3)
            .map(|coefficient_position| {
                BinaryFieldElement256::from_low_polynomial_u16(0x321 + coefficient_position)
            })
            .collect(),
    );
    let degree_six_zero_sharing = BinaryFieldPolynomial::new(
        core::iter::once(BinaryFieldElement256::ZERO)
            .chain((1..=6).map(|coefficient_position| {
                BinaryFieldElement256::from_low_polynomial_u16(0x431 + coefficient_position)
            }))
            .collect(),
    );
    left.multiply(&right)
        .add(&reduction_mask)
        .add(&degree_six_zero_sharing)
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

fn circuit(participant_count: u16, option_count: u16, top_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
    )
    .unwrap()
}
