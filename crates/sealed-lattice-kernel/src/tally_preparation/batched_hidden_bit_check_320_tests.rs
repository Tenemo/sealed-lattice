use std::collections::BTreeSet;

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    hashing::hash_framed_parts_512,
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    batched_hidden_bit_check_320::{
        BATCHED_HIDDEN_BIT_CHECK_CATALOG_IDENTITY_DOMAIN,
        BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE, BatchedHiddenBitAffineFiberBasis320,
        BatchedHiddenBitBatch320, BatchedHiddenBitCheckCatalog320, BatchedHiddenBitCheckError320,
        BatchedHiddenBitCheckResourceModel320, BatchedHiddenBitPolynomial320,
        BatchedHiddenBitSource320, BatchedHiddenBitSourceCoordinate320,
        BatchedHiddenBitZeroSharing320, BatchedHiddenBitZeroSharingCoordinate320,
        evaluate_batched_hidden_bit_check_share_320,
    },
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::{
        CanonicalZeroSharingCodewordVerifier320, canonical_evaluation_point_320,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

#[test]
fn completion_catalog_compiles_every_nonconstant_wire_and_exact_zero_source() {
    let circuit = completion_circuit();
    let catalog = BatchedHiddenBitCheckCatalog320::derive(
        hash(0x11),
        preparation_context(0x21, &circuit),
        &circuit,
    )
    .unwrap();

    assert_eq!(catalog.profile(), circuit.profile());
    assert_eq!(catalog.hidden_bit_count(), 7_982);
    assert_eq!(catalog.batch_count(), 2);
    assert_eq!(
        catalog
            .batches()
            .map(|batch| (
                batch.batch_ordinal,
                batch.first_hidden_bit_ordinal,
                batch.hidden_bit_count,
                batch.zero_sharing_ordinal,
            ))
            .collect::<Vec<_>>(),
        vec![(0, 0, 4_096, 0), (1, 4_096, 3_886, 1),]
    );
    assert_eq!(catalog.conjunction_product_count(), 2_962);
    assert_eq!(catalog.zero_sharing_count(), 2_964);
    assert_eq!(catalog.soundness_union_numerator(), 7_980);
    assert_eq!(catalog.soundness_field_bit_length(), 320);

    let hidden_bits = catalog.hidden_bits().collect::<Vec<_>>();
    assert_eq!(catalog.hidden_bit(0).unwrap(), hidden_bits[0]);
    assert_eq!(hidden_bits.first().unwrap().hidden_bit_ordinal, 0);
    assert_eq!(hidden_bits.last().unwrap().hidden_bit_ordinal, 7_981);
    assert_eq!(
        hidden_bits
            .iter()
            .map(|entry| entry.hidden_bit_ordinal)
            .collect::<BTreeSet<_>>()
            .len(),
        hidden_bits.len()
    );
    assert_eq!(
        hidden_bits
            .iter()
            .filter(|entry| matches!(
                entry.coordinate,
                BatchedHiddenBitSourceCoordinate320::AcceptedAuthorshipOutput { .. }
            ))
            .count(),
        10
    );
    assert_eq!(
        hidden_bits
            .iter()
            .filter(|entry| matches!(
                entry.coordinate,
                BatchedHiddenBitSourceCoordinate320::PublicNonemptyOutput { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        hidden_bits
            .iter()
            .filter(|entry| matches!(
                entry.coordinate,
                BatchedHiddenBitSourceCoordinate320::PrivateResultOutput { .. }
            ))
            .count(),
        40
    );

    let zero_sharings = catalog.zero_sharings().collect::<Vec<_>>();
    assert_eq!(zero_sharings.len(), 2_964);
    assert!(zero_sharings[..2].iter().all(|entry| matches!(
        entry.coordinate,
        BatchedHiddenBitZeroSharingCoordinate320::BatchMask { .. }
    )));
    assert!(zero_sharings[2..].iter().all(|entry| matches!(
        entry.coordinate,
        BatchedHiddenBitZeroSharingCoordinate320::ConjunctionProductMask { .. }
    )));
    assert_eq!(
        zero_sharings
            .iter()
            .map(|entry| entry.zero_sharing_ordinal)
            .collect::<BTreeSet<_>>()
            .len(),
        zero_sharings.len()
    );
    assert_eq!(
        catalog.hidden_bit(catalog.hidden_bit_count()),
        Err(BatchedHiddenBitCheckError320::HiddenBitOrdinalOutOfRange {
            hidden_bit_ordinal: 7_982,
            hidden_bit_count: 7_982,
        })
    );
    assert_eq!(
        catalog.batch(catalog.batch_count()),
        Err(BatchedHiddenBitCheckError320::BatchOrdinalOutOfRange {
            batch_ordinal: 2,
            batch_count: 2,
        })
    );
    assert_eq!(
        catalog.zero_sharing(catalog.zero_sharing_count()),
        Err(
            BatchedHiddenBitCheckError320::ZeroSharingOrdinalOutOfRange {
                zero_sharing_ordinal: 2_964,
                zero_sharing_count: 2_964,
            }
        )
    );

    let canonical_bytes = catalog.canonical_bytes();
    assert_eq!(catalog.artifact_byte_length(), canonical_bytes.len() as u64);
    assert_eq!(
        catalog.identity().as_bytes(),
        &hash_framed_parts_512(
            BATCHED_HIDDEN_BIT_CHECK_CATALOG_IDENTITY_DOMAIN,
            &[&canonical_bytes]
        )
    );
    assert!(
        hidden_bits
            .iter()
            .all(|entry| entry.canonical_bytes() == independently_encode_hidden_bit(*entry))
    );
    assert!(
        catalog
            .batches()
            .all(|batch| batch.canonical_bytes() == independently_encode_batch(batch))
    );
    assert!(
        zero_sharings
            .iter()
            .all(|entry| entry.canonical_bytes() == independently_encode_zero_sharing(*entry))
    );
    assert_eq!(hidden_bits[0].canonical_bytes(), [1, 0, 0]);
    assert_eq!(
        catalog.batch(0).unwrap().canonical_bytes(),
        [0, 0, 0x80, 0x20, 0]
    );
}

#[test]
fn resource_compiler_compares_bounded_single_batch_and_per_bit_routes() {
    let circuit = completion_circuit();
    let catalog = BatchedHiddenBitCheckCatalog320::derive(
        hash(0x12),
        preparation_context(0x22, &circuit),
        &circuit,
    )
    .unwrap();
    let resources = BatchedHiddenBitCheckResourceModel320::derive(&catalog, &circuit, 7).unwrap();

    assert_eq!(resources.hidden_bit_count, 7_982);
    assert_eq!(resources.batch_count, 2);
    assert_eq!(resources.maximum_batch_size, 4_096);
    assert_eq!(resources.final_batch_size, 3_886);
    assert_eq!(resources.conjunction_product_count, 2_962);
    assert_eq!(resources.zero_sharing_count, 2_964);
    assert_eq!(resources.hidden_bit_square_count_per_participant, 7_982);
    assert_eq!(
        resources.challenge_multiplication_count_per_participant,
        7_980
    );
    assert_eq!(
        resources.batch_evaluation_multiplication_count_per_participant,
        15_962
    );
    assert_eq!(
        resources.batch_evaluation_addition_count_per_participant,
        15_964
    );
    assert_eq!(resources.soundness_union_numerator, 7_980);
    assert_eq!(resources.soundness_field_bit_length, 320);
    assert_eq!(resources.single_batch_zero_sharing_count, 2_963);
    assert_eq!(
        resources.single_batch_field_output_count_per_participant,
        746_676
    );
    assert_eq!(
        resources.bounded_batch_additional_field_output_count_per_participant,
        252
    );
    assert_eq!(resources.per_bit_zero_sharing_count, 18_926);
    assert_eq!(resources.zero_sharing_count_reduction, 15_962);
    assert_eq!(
        resources.per_bit_field_output_count_per_participant,
        4_769_352
    );
    assert_eq!(
        resources.field_output_count_reduction_per_participant,
        4_022_424
    );
    assert_eq!(
        resources.field_output_byte_length_reduction_per_participant,
        160_896_960
    );
    assert_eq!(resources.selected_cursor.field_output_count, 746_928);
    assert_eq!(resources.selected_cursor.output_chunk_count, 1);
    assert_eq!(resources.selected_cursor.work_checkpoint_count, 252);
}

#[test]
fn every_admitted_profile_derives_contiguous_batches_and_semantic_coordinates() {
    for participant_count in 4..=FOUNDATION_PROFILE.participant_count {
        for option_count in 2..=FOUNDATION_PROFILE.option_count {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let catalog = BatchedHiddenBitCheckCatalog320::derive(
                    hash(0x13),
                    preparation_context(0x23, &circuit),
                    &circuit,
                )
                .unwrap();
                assert!(catalog.hidden_bit_count() > 0);
                assert!(catalog.batches().all(|batch| batch.hidden_bit_count > 0
                    && batch.hidden_bit_count <= BATCHED_HIDDEN_BIT_CHECK_MAXIMUM_BATCH_SIZE));
                let mut next_hidden_bit_ordinal = 0_u64;
                for batch in catalog.batches() {
                    assert_eq!(batch.first_hidden_bit_ordinal, next_hidden_bit_ordinal);
                    next_hidden_bit_ordinal += batch.hidden_bit_count;
                }
                assert_eq!(next_hidden_bit_ordinal, catalog.hidden_bit_count());
                assert_eq!(
                    catalog.zero_sharing_count(),
                    catalog.batch_count() + catalog.conjunction_product_count()
                );
            }
        }
    }
}

#[test]
fn horner_evaluation_matches_independent_challenge_powers_and_zero_codeword_check() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let batch = super::batched_hidden_bit_check_320::BatchedHiddenBitBatch320 {
        batch_ordinal: 0,
        first_hidden_bit_ordinal: 0,
        hidden_bit_count: 7,
        zero_sharing_ordinal: 0,
    };
    let challenge = field(0x91);
    let hidden_polynomials = (0..7)
        .map(|hidden_bit_position| {
            degree_three_polynomial(
                BinaryFieldElement320::from_low_polynomial_u16(hidden_bit_position % 2),
                0x110 + hidden_bit_position,
            )
        })
        .collect::<Vec<_>>();
    let zero_mask = zero_constant_degree_six_polynomial(0x210);
    let opened_values = (0..participant_count)
        .map(|roster_position| {
            let point = canonical_evaluation_point_320(participant_count, roster_position).unwrap();
            let hidden_values = hidden_polynomials
                .iter()
                .map(|polynomial| polynomial.evaluate(point))
                .collect::<Vec<_>>();
            let actual = evaluate_batched_hidden_bit_check_share_320(
                batch,
                challenge,
                &hidden_values,
                zero_mask.evaluate(point),
            )
            .unwrap();
            let expected =
                independent_batch_evaluation(challenge, &hidden_values, zero_mask.evaluate(point));
            assert_eq!(actual, expected);
            actual
        })
        .collect::<Vec<_>>();
    assert!(
        CanonicalZeroSharingCodewordVerifier320::new(participant_count)
            .unwrap()
            .verify(&opened_values)
            .unwrap()
    );

    assert_eq!(
        evaluate_batched_hidden_bit_check_share_320(
            batch,
            challenge,
            &opened_values[..6],
            BinaryFieldElement320::ZERO,
        ),
        Err(
            BatchedHiddenBitCheckError320::HiddenBitEvaluationCountMismatch {
                expected: 7,
                actual: 6,
            }
        )
    );
}

#[test]
fn nonbit_secret_creates_the_exact_nonzero_challenge_polynomial() {
    let secrets = [
        BinaryFieldElement320::ZERO,
        BinaryFieldElement320::ONE,
        field(0x71),
        BinaryFieldElement320::ONE,
        field(0x83),
    ];
    let residual_coefficients = secrets
        .iter()
        .copied()
        .map(|secret| secret.square().add(secret))
        .collect::<Vec<_>>();
    assert!(residual_coefficients[0].is_zero());
    assert!(residual_coefficients[1].is_zero());
    assert!(!residual_coefficients[2].is_zero());
    assert!(residual_coefficients[3].is_zero());
    assert!(!residual_coefficients[4].is_zero());
    let polynomial = BatchedHiddenBitPolynomial320::from_coefficients(residual_coefficients);
    assert!(polynomial.degree() < secrets.len());
    assert!((0_u16..64).any(|challenge| {
        !polynomial
            .evaluate(BinaryFieldElement320::from_low_polynomial_u16(challenge))
            .is_zero()
    }));
}

#[test]
fn every_completion_corruption_set_has_an_exact_three_dimensional_affine_fiber() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    for (subset_ordinal, subset) in ReplicatedRandomSharingSubset::all(participant_count)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let basis = BatchedHiddenBitAffineFiberBasis320::derive(
            participant_count,
            &subset.excluded_positions(),
        )
        .unwrap();
        assert_eq!(basis.maximum_degree(), 6);
        assert_eq!(basis.dimension(), 3);
        assert_eq!(
            basis
                .bases()
                .iter()
                .map(BatchedHiddenBitPolynomial320::degree)
                .collect::<Vec<_>>(),
            vec![4, 5, 6]
        );
        let components = [
            field(u16::try_from(0x301 + subset_ordinal).unwrap()),
            field(u16::try_from(0x401 + subset_ordinal).unwrap()),
            field(u16::try_from(0x501 + subset_ordinal).unwrap()),
        ];
        let difference = basis.reassemble(&components).unwrap();
        assert_eq!(basis.decompose(&difference).unwrap(), components);
        assert!(difference.evaluate(BinaryFieldElement320::ZERO).is_zero());
        for corrupt_position in subset.excluded_positions() {
            assert!(
                difference
                    .evaluate(
                        canonical_evaluation_point_320(participant_count, corrupt_position)
                            .unwrap()
                    )
                    .is_zero()
            );
        }
    }
}

#[test]
fn affine_fiber_refuses_wrong_corrupt_sets_visible_values_and_excess_degree() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    assert_eq!(
        BatchedHiddenBitAffineFiberBasis320::derive(participant_count, &[0, 1]),
        Err(
            BatchedHiddenBitCheckError320::CorruptPositionCountMismatch {
                expected: 3,
                actual: 2,
            }
        )
    );
    assert_eq!(
        BatchedHiddenBitAffineFiberBasis320::derive(participant_count, &[0, 1, 1]),
        Err(BatchedHiddenBitCheckError320::CorruptPositionsNotCanonical)
    );
    let basis = BatchedHiddenBitAffineFiberBasis320::derive(participant_count, &[0, 4, 9]).unwrap();
    let nonzero_constant =
        BatchedHiddenBitPolynomial320::from_coefficients(vec![BinaryFieldElement320::ONE]);
    assert_eq!(
        basis.decompose(&nonzero_constant),
        Err(
            BatchedHiddenBitCheckError320::PolynomialVisibleAtFixedPoint {
                roster_position: None,
            }
        )
    );
    let excessive_degree = BatchedHiddenBitPolynomial320::from_coefficients(
        (0..=7)
            .map(|degree| {
                if degree == 7 {
                    BinaryFieldElement320::ONE
                } else {
                    BinaryFieldElement320::ZERO
                }
            })
            .collect(),
    );
    assert_eq!(
        basis.decompose(&excessive_degree),
        Err(BatchedHiddenBitCheckError320::PolynomialDegreeOutOfRange {
            maximum_degree: 6,
            actual_degree: 7,
        })
    );
}

fn completion_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
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

fn degree_three_polynomial(
    constant: BinaryFieldElement320,
    marker: u16,
) -> BatchedHiddenBitPolynomial320 {
    BatchedHiddenBitPolynomial320::from_coefficients(vec![
        constant,
        field(marker),
        field(marker.wrapping_add(1)),
        field(marker.wrapping_add(2)),
    ])
}

fn zero_constant_degree_six_polynomial(marker: u16) -> BatchedHiddenBitPolynomial320 {
    BatchedHiddenBitPolynomial320::from_coefficients(
        core::iter::once(BinaryFieldElement320::ZERO)
            .chain((0..6).map(|offset| field(marker.wrapping_add(offset))))
            .collect(),
    )
}

fn independent_batch_evaluation(
    challenge: BinaryFieldElement320,
    hidden_bit_evaluations: &[BinaryFieldElement320],
    zero_mask_evaluation: BinaryFieldElement320,
) -> BinaryFieldElement320 {
    let mut challenge_power = BinaryFieldElement320::ONE;
    let mut result = zero_mask_evaluation;
    for hidden_bit_evaluation in hidden_bit_evaluations.iter().copied() {
        result = result.add(
            hidden_bit_evaluation
                .square()
                .add(hidden_bit_evaluation)
                .multiply(challenge_power),
        );
        challenge_power = challenge_power.multiply(challenge);
    }
    result
}

fn independently_encode_hidden_bit(entry: BatchedHiddenBitSource320) -> Vec<u8> {
    let mut bytes = Vec::new();
    match entry.coordinate {
        BatchedHiddenBitSourceCoordinate320::CoreWire { wire_index } => {
            append_independent_varuint(&mut bytes, 1);
            append_independent_varuint(&mut bytes, entry.hidden_bit_ordinal);
            append_independent_varuint(&mut bytes, u64::from(wire_index));
        }
        BatchedHiddenBitSourceCoordinate320::AcceptedAuthorshipOutput {
            participant_position,
            source_wire,
            output_wire,
        } => {
            append_independent_varuint(&mut bytes, 2);
            append_independent_varuint(&mut bytes, entry.hidden_bit_ordinal);
            append_independent_varuint(&mut bytes, u64::from(participant_position));
            append_independent_varuint(&mut bytes, u64::from(source_wire));
            append_independent_varuint(&mut bytes, u64::from(output_wire));
        }
        BatchedHiddenBitSourceCoordinate320::PublicNonemptyOutput {
            source_wire,
            output_wire,
        } => {
            append_independent_varuint(&mut bytes, 3);
            append_independent_varuint(&mut bytes, entry.hidden_bit_ordinal);
            append_independent_varuint(&mut bytes, u64::from(source_wire));
            append_independent_varuint(&mut bytes, u64::from(output_wire));
        }
        BatchedHiddenBitSourceCoordinate320::PrivateResultOutput {
            result_bit_position,
            source_wire,
            output_wire,
        } => {
            append_independent_varuint(&mut bytes, 4);
            append_independent_varuint(&mut bytes, entry.hidden_bit_ordinal);
            append_independent_varuint(&mut bytes, result_bit_position);
            append_independent_varuint(&mut bytes, u64::from(source_wire));
            append_independent_varuint(&mut bytes, u64::from(output_wire));
        }
    }
    bytes
}

fn independently_encode_batch(batch: BatchedHiddenBitBatch320) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_independent_varuint(&mut bytes, batch.batch_ordinal);
    append_independent_varuint(&mut bytes, batch.first_hidden_bit_ordinal);
    append_independent_varuint(&mut bytes, batch.hidden_bit_count);
    append_independent_varuint(&mut bytes, batch.zero_sharing_ordinal);
    bytes
}

fn independently_encode_zero_sharing(entry: BatchedHiddenBitZeroSharing320) -> Vec<u8> {
    let mut bytes = Vec::new();
    match entry.coordinate {
        BatchedHiddenBitZeroSharingCoordinate320::BatchMask {
            batch_ordinal,
            first_hidden_bit_ordinal,
            hidden_bit_count,
        } => {
            append_independent_varuint(&mut bytes, 1);
            append_independent_varuint(&mut bytes, entry.zero_sharing_ordinal);
            append_independent_varuint(&mut bytes, batch_ordinal);
            append_independent_varuint(&mut bytes, first_hidden_bit_ordinal);
            append_independent_varuint(&mut bytes, hidden_bit_count);
        }
        BatchedHiddenBitZeroSharingCoordinate320::ConjunctionProductMask {
            conjunction_ordinal,
            circuit_operation_position,
            output_wire,
            left_wire,
            right_wire,
        } => {
            append_independent_varuint(&mut bytes, 2);
            append_independent_varuint(&mut bytes, entry.zero_sharing_ordinal);
            append_independent_varuint(&mut bytes, conjunction_ordinal);
            append_independent_varuint(&mut bytes, circuit_operation_position);
            append_independent_varuint(&mut bytes, u64::from(output_wire));
            append_independent_varuint(&mut bytes, u64::from(left_wire));
            append_independent_varuint(&mut bytes, u64::from(right_wire));
        }
    }
    bytes
}

fn append_independent_varuint(bytes: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut encoded = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value != 0 {
            encoded |= 0x80;
        }
        bytes.push(encoded);
        if value == 0 {
            break;
        }
    }
}

fn field(value: u16) -> BinaryFieldElement320 {
    BinaryFieldElement320::from_low_polynomial_u16(value)
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}
