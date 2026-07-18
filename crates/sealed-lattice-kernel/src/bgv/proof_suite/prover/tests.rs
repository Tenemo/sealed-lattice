use std::rc::Rc;

use super::*;
use crate::foundation::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    ParticipantIdentity, PersistentProofCoinInput, ProofApplicationSlot,
};

fn base(value: u64) -> ProofBaseFieldElement {
    ProofBaseFieldElement::from_canonical(value).expect("test value is canonical")
}

fn extension(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(base(value))
}

fn signed_base(value: i64) -> ProofBaseFieldElement {
    if value >= 0 {
        base(value as u64)
    } else {
        base(super::super::PROOF_BASE_FIELD_MODULUS - value.unsigned_abs())
    }
}

fn naive_negacyclic_product(
    left: &[ProofBaseFieldElement],
    right: &[ProofBaseFieldElement],
) -> Vec<ProofBaseFieldElement> {
    assert_eq!(left.len(), right.len());
    let mut output = vec![ProofBaseFieldElement::ZERO; left.len()];
    for (left_ordinal, left_value) in left.iter().copied().enumerate() {
        for (right_ordinal, right_value) in right.iter().copied().enumerate() {
            let product = left_value.multiply(right_value);
            let sum_ordinal = left_ordinal + right_ordinal;
            if sum_ordinal < left.len() {
                output[sum_ordinal] = output[sum_ordinal].add(product);
            } else {
                output[sum_ordinal - left.len()] =
                    output[sum_ordinal - left.len()].subtract(product);
            }
        }
    }
    output
}

fn naive_ordinary_product(
    left: &[ProofBaseFieldElement],
    right: &[ProofBaseFieldElement],
) -> Vec<ProofBaseFieldElement> {
    assert_eq!(left.len(), right.len());
    let mut output = vec![ProofBaseFieldElement::ZERO; left.len() * 2];
    for (left_ordinal, left_value) in left.iter().copied().enumerate() {
        for (right_ordinal, right_value) in right.iter().copied().enumerate() {
            let sum_ordinal = left_ordinal + right_ordinal;
            output[sum_ordinal] = output[sum_ordinal].add(left_value.multiply(right_value));
        }
    }
    output
}

fn theta_fingerprint(
    coefficients: &[ProofBaseFieldElement],
    theta: ProofBaseFieldElement,
) -> ProofBaseFieldElement {
    coefficients
        .iter()
        .rev()
        .fold(ProofBaseFieldElement::ZERO, |accumulated, coefficient| {
            accumulated.multiply(theta).add(*coefficient)
        })
}

#[test]
fn trace_mask_changes_coefficients_but_preserves_every_trace_domain_value() {
    let witness =
        CommonProofSourcePolynomial::from_base_coefficients(vec![base(7), base(11), base(13)]);
    let mask =
        CommonProofSourcePolynomial::from_base_coefficients(vec![base(17), base(19), base(23)]);
    let masked = apply_trace_mask(witness.clone(), 8, mask).expect("valid trace mask is applied");
    assert_ne!(masked, witness);

    let trace_domain = ProofEvaluationDomain::new(8, 7)
        .expect("evaluation domain exposes the trace subgroup generator");
    for position in 0..trace_domain.size() {
        let point = ProofChallengeExtensionElement::from_base(
            trace_domain
                .generator()
                .power(u64::try_from(position).expect("test position fits the field exponent")),
        );
        assert_eq!(masked.evaluate_at(point), witness.evaluate_at(point));
    }
}

#[test]
fn trace_mask_rejects_cross_field_application() {
    let result = apply_trace_mask(
        CommonProofSourcePolynomial::from_base_coefficients(vec![base(1)]),
        4,
        CommonProofSourcePolynomial::from_extension_coefficients(vec![extension(2)]),
    );
    assert_eq!(result, Err(CommonProofProverError::InvalidMask));
}

#[test]
fn reversal_fingerprints_cover_zero_one_and_largest_non_native_challenges() {
    let source = [3, -2, 7, 1, -4, 5, 2, -1].map(signed_base).to_vec();
    let mut reversed = source.iter().copied().rev().collect::<Vec<_>>();
    for theta in [base(0), base(1), base(96)] {
        let prefix = prefix_evaluation_rows(&source, theta);
        let suffix = suffix_evaluation_rows(&reversed, theta);
        assert_eq!(prefix[0], source[0]);
        for row_ordinal in 1..source.len() {
            assert_eq!(
                prefix[row_ordinal],
                source[row_ordinal].add(theta.multiply(prefix[row_ordinal - 1])),
            );
        }
        assert_eq!(suffix[source.len() - 1], reversed[source.len() - 1]);
        for row_ordinal in 0..source.len() - 1 {
            assert_eq!(
                suffix[row_ordinal],
                reversed[row_ordinal].add(theta.multiply(suffix[row_ordinal + 1])),
            );
        }
        assert_eq!(prefix[source.len() - 1], suffix[0]);

        reversed[0] = reversed[0].add(ProofBaseFieldElement::ONE);
        assert_ne!(
            prefix[source.len() - 1],
            suffix_evaluation_rows(&reversed, theta)[0],
        );
        reversed[0] = reversed[0].subtract(ProofBaseFieldElement::ONE);
    }
}

#[test]
fn convolution_transposes_match_all_checked_convolution_kinds() {
    for row_count in [4_usize, 8] {
        let multiplicand = (0..row_count)
            .map(|ordinal| signed_base((ordinal as i64 % 5) - 2))
            .collect::<Vec<_>>();
        let multiplier = (0..row_count)
            .map(|ordinal| signed_base(((ordinal * 3 + 1) as i64 % 7) - 3))
            .collect::<Vec<_>>();
        let reversed_multiplier = multiplier.iter().copied().rev().collect::<Vec<_>>();
        let ordinary = naive_ordinary_product(&multiplicand, &multiplier);
        let negacyclic = naive_negacyclic_product(&multiplicand, &multiplier);
        for theta in [base(0), base(1), base(96)] {
            let suffix = suffix_evaluation_rows(&multiplicand, theta);
            for (kind, expected_coefficients) in [
                (
                    RelationIntegerLiftConvolutionKind::Negacyclic,
                    negacyclic.as_slice(),
                ),
                (
                    RelationIntegerLiftConvolutionKind::OrdinaryLowHalf,
                    &ordinary[..row_count],
                ),
                (
                    RelationIntegerLiftConvolutionKind::OrdinaryHighHalf,
                    &ordinary[row_count..],
                ),
            ] {
                let transpose = convolution_transpose_rows(kind, &multiplicand, &suffix, theta)
                    .expect("checked transpose rows");
                let dot_product = transpose
                    .iter()
                    .copied()
                    .zip(reversed_multiplier.iter().copied())
                    .fold(ProofBaseFieldElement::ZERO, |sum, (left, right)| {
                        sum.add(left.multiply(right))
                    });
                assert_eq!(
                    dot_product,
                    theta_fingerprint(expected_coefficients, theta),
                    "kind={kind:?} row_count={row_count} theta={}",
                    theta.canonical(),
                );
            }
        }
    }
}

#[test]
fn full_ring_transposes_match_both_negacyclic_product_halves() {
    for half_ring_degree in [4_usize, 8] {
        let multiplicand_low = (0..half_ring_degree)
            .map(|ordinal| signed_base((ordinal as i64 % 5) - 1))
            .collect::<Vec<_>>();
        let multiplicand_high = (0..half_ring_degree)
            .map(|ordinal| signed_base(((ordinal * 2 + 3) as i64 % 7) - 2))
            .collect::<Vec<_>>();
        let multiplier_low = (0..half_ring_degree)
            .map(|ordinal| signed_base(((ordinal * 3 + 2) as i64 % 7) - 3))
            .collect::<Vec<_>>();
        let multiplier_high = (0..half_ring_degree)
            .map(|ordinal| signed_base(((ordinal * 5 + 1) as i64 % 11) - 5))
            .collect::<Vec<_>>();
        let mut multiplicand = multiplicand_low.clone();
        multiplicand.extend_from_slice(&multiplicand_high);
        let mut multiplier = multiplier_low.clone();
        multiplier.extend_from_slice(&multiplier_high);
        let product = naive_negacyclic_product(&multiplicand, &multiplier);
        let reversed_multiplier_low = multiplier_low.iter().copied().rev().collect::<Vec<_>>();
        let reversed_multiplier_high = multiplier_high.iter().copied().rev().collect::<Vec<_>>();

        for theta in [base(0), base(1), base(96)] {
            let low_suffix = suffix_evaluation_rows(&multiplicand_low, theta);
            let high_suffix = suffix_evaluation_rows(&multiplicand_high, theta);
            for selected_half in [
                RelationIntegerLiftFullRingHalf::Low,
                RelationIntegerLiftFullRingHalf::High,
            ] {
                let low_transpose = full_ring_transpose_rows(
                    selected_half,
                    true,
                    &multiplicand_low,
                    &multiplicand_high,
                    &low_suffix,
                    &high_suffix,
                    theta,
                )
                .expect("low multiplier transpose");
                let high_transpose = full_ring_transpose_rows(
                    selected_half,
                    false,
                    &multiplicand_low,
                    &multiplicand_high,
                    &low_suffix,
                    &high_suffix,
                    theta,
                )
                .expect("high multiplier transpose");
                let dot_product =
                    (0..half_ring_degree).fold(ProofBaseFieldElement::ZERO, |sum, row_ordinal| {
                        sum.add(
                            low_transpose[row_ordinal]
                                .multiply(reversed_multiplier_low[row_ordinal]),
                        )
                        .add(
                            high_transpose[row_ordinal]
                                .multiply(reversed_multiplier_high[row_ordinal]),
                        )
                    });
                let selected_coefficients = match selected_half {
                    RelationIntegerLiftFullRingHalf::Low => &product[..half_ring_degree],
                    RelationIntegerLiftFullRingHalf::High => &product[half_ring_degree..],
                };
                assert_eq!(
                    dot_product,
                    theta_fingerprint(selected_coefficients, theta),
                    "half={selected_half:?} degree={half_ring_degree} theta={}",
                    theta.canonical(),
                );

                let mut mutated = low_transpose;
                mutated[0] = mutated[0].add(ProofBaseFieldElement::ONE);
                let mutated_dot_product =
                    (0..half_ring_degree).fold(ProofBaseFieldElement::ZERO, |sum, row_ordinal| {
                        sum.add(mutated[row_ordinal].multiply(reversed_multiplier_low[row_ordinal]))
                            .add(
                                high_transpose[row_ordinal]
                                    .multiply(reversed_multiplier_high[row_ordinal]),
                            )
                    });
                assert_ne!(
                    mutated_dot_product,
                    theta_fingerprint(selected_coefficients, theta),
                );
            }
        }
    }
}

#[test]
fn product_accumulator_enforces_every_row_and_the_terminal_identity() {
    let product_rows = [4, -3, 7, 2, -5, 1, 6, -2].map(signed_base).to_vec();
    let accumulator = product_accumulator_rows(&product_rows);
    for row_ordinal in 0..product_rows.len() - 1 {
        assert_eq!(
            accumulator[row_ordinal + 1],
            accumulator[row_ordinal].add(product_rows[row_ordinal]),
        );
    }
    let total = product_rows
        .iter()
        .copied()
        .fold(ProofBaseFieldElement::ZERO, ProofBaseFieldElement::add);
    let linear_at_zero = total.negate();
    assert_eq!(
        accumulator[0]
            .subtract(accumulator[accumulator.len() - 1])
            .subtract(product_rows[product_rows.len() - 1])
            .subtract(linear_at_zero),
        ProofBaseFieldElement::ZERO,
    );
    assert_ne!(
        accumulator[0]
            .subtract(accumulator[accumulator.len() - 1])
            .subtract(product_rows[product_rows.len() - 1].add(ProofBaseFieldElement::ONE))
            .subtract(linear_at_zero),
        ProofBaseFieldElement::ZERO,
    );
}

#[test]
fn quotient_decomposition_is_constant_first_and_exactly_reconstructible() {
    let quotient = (1..=11).map(extension).collect::<Vec<_>>();
    let components = decompose_composed_quotient(&quotient, 3, 4)
        .expect("quotient fits the declared decomposition");
    assert_eq!(
        components
            .iter()
            .map(|component| component.len())
            .collect::<Vec<_>>(),
        vec![4, 4, 3]
    );
    let reconstructed_quotient = Zeroizing::new(
        components
            .iter()
            .flat_map(|component| component.iter().copied())
            .collect::<Vec<_>>(),
    );
    assert_eq!(reconstructed_quotient.as_slice(), quotient.as_slice());
    assert_eq!(
        decompose_composed_quotient(&[extension(1); 9], 2, 4),
        Err(CommonProofProverError::InvalidQuotient)
    );
}

#[test]
fn quotient_rotation_positions_cover_both_directions_wraparound_and_reduction() {
    let rotate = |position, is_negative, magnitude| {
        rotated_relation_evaluation_position(position, 32, 8, 4, is_negative, magnitude)
            .expect("the exact trace/evaluation geometry is valid")
    };
    assert_eq!(rotate(17, false, 0), 17);
    assert_eq!(rotate(17, true, 0), 17);
    assert_eq!(rotate(29, false, 1), 1);
    assert_eq!(rotate(2, true, 1), 30);
    assert_eq!(rotate(29, false, 9), 1);
    assert_eq!(rotate(2, true, u64::MAX), 6);

    for (evaluation_size, trace_domain_size, trace_rotation_stride, position) in [
        (0, 8, 4, 0),
        (32, 0, 4, 0),
        (32, 8, 0, 0),
        (32, 8, 2, 0),
        (32, 8, 4, 32),
    ] {
        assert_eq!(
            rotated_relation_evaluation_position(
                position,
                evaluation_size,
                trace_domain_size,
                trace_rotation_stride,
                false,
                1,
            ),
            Err(CommonProofProverError::InvalidOpening),
        );
    }
}

#[test]
fn materialization_write_budget_counts_every_bounded_record_append() {
    assert_eq!(
        common_tree_materialization_write_transaction_count(4, 100, 1_024)
            .expect("the leaf object and each digest level fit the transaction count"),
        4,
    );
    assert_eq!(
        common_tree_materialization_write_transaction_count(4, 100, 48)
            .expect("object-wide canonical chunking fits the transaction count"),
        20,
    );
    assert_eq!(
        common_tree_materialization_write_transaction_count(1_u64 << 63, 100, 48),
        Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        )),
    );
}

#[test]
fn proof_header_delegates_to_the_foundation_schema() {
    let statement = CanonicalTuple::new(0x1216, 1, vec![CanonicalItem::unsigned16(7)])
        .encode()
        .expect("test statement encodes");
    let expected = ProofObjectHeader::from_canonical_application_statement(
        statement.clone(),
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.encode())
    .expect("foundation proof header encodes");
    assert_eq!(
        canonical_proof_object_header_bytes(&statement).expect("prover proof header encodes"),
        expected
    );
    assert_eq!(
        canonical_proof_object_header_bytes(&[]),
        Err(CommonProofProverError::InvalidInput)
    );
}

#[test]
fn private_randomness_coin_source_resumes_exactly_and_keeps_purposes_independent() {
    let suite_identifier = Hash512::from_bytes([0x11; 64]);
    let ceremony_context_hash = Hash512::from_bytes([0x22; 64]);
    let action_context_hash = Hash512::from_bytes([0x33; 64]);
    let participant_identity =
        ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]);
    let action_private_randomness = Rc::new(
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x55; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        ))
        .expect("action private randomness derives"),
    );
    let application_slot = ProofApplicationSlot::new(
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        0x1211,
        Some(2),
        None,
        None,
    )
    .expect("reset-safe proof slot is assigned");
    let attempt_input =
        PersistentProofCoinInput::new(application_slot, Hash512::from_bytes([0x66; 64]))
            .expect("persistent proof attempt input is valid");
    let mut witness_binding = action_private_randomness
        .begin_persistent_proof_witness_coin_binding(&attempt_input)
        .expect("persistent proof witness binding starts");
    witness_binding
        .absorb_canonical_bytes(b"sealed-lattice/test/common-proof-coin-witness/v1")
        .expect("test witness domain is absorbed");
    witness_binding
        .absorb_canonical_u64_values(&[3, 5, 8, 13, 21])
        .expect("test witness is absorbed");
    let attempt_identifier = witness_binding
        .finish()
        .expect("persistent proof attempt derives");
    let derivation_context_hash = Hash512::from_bytes([0x77; 64]);
    let first_coordinate =
        CommonProofPrivateCoinCoordinate::mask(1, 0).expect("trace private-coin class is assigned");
    let second_coordinate =
        CommonProofPrivateCoinCoordinate::mask(1, 1).expect("trace private-coin class is assigned");

    let mut uninterrupted = PrivateRandomnessCommonProofCoinSource::new(
        Rc::clone(&action_private_randomness),
        0x1211,
        derivation_context_hash,
        attempt_identifier,
        CommonProofPrivateCoinCoordinateCapacity::for_test(2, 0, 0, true),
    )
    .expect("coin source starts");
    let _first = uninterrupted
        .sample_modulo(first_coordinate, super::super::PROOF_BASE_FIELD_MODULUS, 64)
        .expect("first purpose-one sample succeeds");
    let authenticated_cursors = uninterrupted.cursors().collect::<Vec<_>>();
    let expected_next = uninterrupted
        .sample_modulo(first_coordinate, super::super::PROOF_BASE_FIELD_MODULUS, 64)
        .expect("uninterrupted suffix sample succeeds");
    let expected_purpose_two = uninterrupted
        .sample_modulo(
            second_coordinate,
            super::super::PROOF_BASE_FIELD_MODULUS,
            64,
        )
        .expect("independent purpose-two sample succeeds");

    let mut resumed = PrivateRandomnessCommonProofCoinSource::resume(
        Rc::clone(&action_private_randomness),
        0x1211,
        derivation_context_hash,
        attempt_identifier,
        CommonProofPrivateCoinCoordinateCapacity::for_test(2, 0, 0, true),
        authenticated_cursors,
    )
    .expect("authenticated cursor resumes");
    assert_eq!(
        resumed
            .sample_modulo(first_coordinate, super::super::PROOF_BASE_FIELD_MODULUS, 64)
            .expect("resumed suffix sample succeeds"),
        expected_next,
    );
    assert_eq!(
        resumed
            .sample_modulo(
                second_coordinate,
                super::super::PROOF_BASE_FIELD_MODULUS,
                64
            )
            .expect("resumed independent purpose starts at counter zero"),
        expected_purpose_two,
    );
    let duplicate_cursor = resumed
        .cursors()
        .next()
        .expect("at least one cursor was retained");
    assert!(matches!(
        PrivateRandomnessCommonProofCoinSource::resume(
            Rc::clone(&action_private_randomness),
            0x1211,
            derivation_context_hash,
            attempt_identifier,
            CommonProofPrivateCoinCoordinateCapacity::for_test(2, 0, 0, true),
            [duplicate_cursor, duplicate_cursor],
        ),
        Err(PrivateRandomnessCommonProofCoinError::DuplicateCursorCoordinate),
    ));
}
