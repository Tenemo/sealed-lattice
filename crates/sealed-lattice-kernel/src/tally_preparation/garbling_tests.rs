use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{CanonicalItem, Hash512, canonical_foundation_tuple_hash_preimage},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    garbling::{
        AffineLabelCommitments, GARBLING_XOF_DOMAIN, GarblingGateRow, GarblingInputComponentLabels,
        combine_individual_garbling_shares, create_individual_garbling_share,
        derive_affine_wire_label, derive_exclusive_or_wire_label, derive_negated_wire_label,
        evaluate_active_and_row, garbling_xof_components, verify_active_and_output,
    },
    label_encoding::{
        LABEL_BODY_BYTE_LENGTH, LabelBody, WIRE_LABEL_BIT_LENGTH, WireLabel,
        encode_garbling_output_components, garbling_output_byte_length,
    },
};

const OUTPUT_WIRE_INDEX: u32 = 311;

#[test]
fn honest_and_rows_preserve_semantics_for_every_mask_and_external_bit_pattern() {
    let context = preparation_context(7);
    let mut case_ordinal = 0_u32;
    for left_mask in [false, true] {
        for right_mask in [false, true] {
            for output_mask in [false, true] {
                for left_external_bit in [false, true] {
                    for right_external_bit in [false, true] {
                        let case = honest_and_case(
                            context,
                            case_ordinal,
                            left_mask,
                            right_mask,
                            output_mask,
                            left_external_bit,
                            right_external_bit,
                        );
                        let evaluated_output_bit = verify_active_and_output(
                            case.context,
                            OUTPUT_WIRE_INDEX,
                            &case.evaluated_components,
                            &case.output_commitments,
                            field(u16::from(case.row_bit)),
                        )
                        .unwrap();
                        assert_eq!(evaluated_output_bit, case.row_bit);
                        assert_eq!(
                            evaluated_output_bit ^ output_mask,
                            (left_external_bit ^ left_mask) & (right_external_bit ^ right_mask)
                        );
                        assert_eq!(case.evaluated_components, case.expected_output_components);
                        case_ordinal += 1;
                    }
                }
            }
        }
    }
}

#[test]
fn repaired_free_gate_labels_preserve_external_and_semantic_bits() {
    for left_mask in [false, true] {
        for right_mask in [false, true] {
            let exclusive_or_mask = left_mask ^ right_mask;
            for left_external_bit in [false, true] {
                for right_external_bit in [false, true] {
                    let offset = label_body(91);
                    let left_label =
                        derive_affine_wire_label(label_body(17), offset, left_external_bit);
                    let right_label =
                        derive_affine_wire_label(label_body(43), offset, right_external_bit);
                    let output_label = derive_exclusive_or_wire_label(left_label, right_label);
                    assert_eq!(
                        output_label.point_bit(),
                        left_external_bit ^ right_external_bit
                    );
                    assert_eq!(
                        output_label.point_bit() ^ exclusive_or_mask,
                        (left_external_bit ^ left_mask) ^ (right_external_bit ^ right_mask)
                    );
                }
            }

            let input_mask = left_mask;
            let output_mask = !input_mask;
            for external_bit in [false, true] {
                let input_label =
                    derive_affine_wire_label(label_body(17), label_body(91), external_bit);
                let output_label = derive_negated_wire_label(input_label);
                assert_eq!(output_label, input_label);
                assert_eq!(
                    output_label.point_bit() ^ output_mask,
                    !(external_bit ^ input_mask)
                );
            }
        }
    }
}

#[test]
fn garbling_xof_matches_the_foundation_tuple_and_masks_non_byte_aligned_output() {
    let context = preparation_context(19);
    let left_label = derive_affine_wire_label(label_body(3), label_body(101), true);
    let right_label = derive_affine_wire_label(label_body(37), label_body(151), false);
    let components = garbling_xof_components(
        context,
        GarblingGateRow::new(23, true, false),
        GarblingInputComponentLabels::new(left_label, right_label),
    )
    .unwrap();
    let actual_bytes =
        encode_garbling_output_components(context.participant_count(), &components).unwrap();

    let output_bit_length = usize::from(context.participant_count()) * WIRE_LABEL_BIT_LENGTH;
    let output_byte_length = garbling_output_byte_length(context.participant_count()).unwrap();
    let items = [
        CanonicalItem::variable_bytes(context.canonical_bytes()).unwrap(),
        CanonicalItem::unsigned32(23),
        CanonicalItem::boolean(true),
        CanonicalItem::boolean(false),
        CanonicalItem::fixed_bytes(left_label.canonical_bytes()).unwrap(),
        CanonicalItem::fixed_bytes(right_label.canonical_bytes()).unwrap(),
        CanonicalItem::unsigned16(context.participant_count()),
        CanonicalItem::unsigned64(output_bit_length as u64),
    ];
    let preimage = canonical_foundation_tuple_hash_preimage(GARBLING_XOF_DOMAIN, &items).unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut expected_bytes = vec![0_u8; output_byte_length];
    hasher.finalize_xof().read(&mut expected_bytes);
    let used_final_byte_bit_count = output_bit_length % 8;
    let used_final_byte_mask = (1_u8 << used_final_byte_bit_count) - 1;
    *expected_bytes.last_mut().unwrap() &= used_final_byte_mask;

    assert_eq!(actual_bytes, expected_bytes);
    assert_eq!(output_bit_length, 1_923);
    assert_eq!(output_byte_length, 241);
    assert_eq!(actual_bytes.last().unwrap() & !used_final_byte_mask, 0);
}

#[test]
fn audit_refuses_wrong_inputs_rows_contexts_and_malicious_garbling_shares() {
    let case = honest_and_case(preparation_context(29), 41, true, false, true, false, true);

    let mut wrong_left_labels = case.active_left_components.clone();
    let mut wrong_left_label_bytes = wrong_left_labels[0].canonical_bytes();
    wrong_left_label_bytes[9] ^= 0x20;
    wrong_left_labels[0] = WireLabel::from_canonical_bytes(&wrong_left_label_bytes).unwrap();
    let wrong_input_evaluation = evaluate_active_and_row(
        case.context,
        GarblingGateRow::new(
            case.gate_index,
            case.left_external_bit,
            case.right_external_bit,
        ),
        &wrong_left_labels,
        &case.active_right_components,
        &case.combined_row_bytes,
    )
    .unwrap();
    assert!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &wrong_input_evaluation,
            &case.output_commitments,
            field(u16::from(case.row_bit)),
        )
        .is_err()
    );

    assert!(matches!(
        evaluate_active_and_row(
            case.context,
            GarblingGateRow::new(
                case.gate_index,
                !case.left_external_bit,
                case.right_external_bit,
            ),
            &case.active_left_components,
            &case.active_right_components,
            &case.combined_row_bytes,
        ),
        Err(TallyPreparationError::GarblingInputPointBitMismatch { .. })
    ));

    let mut malicious_row_bytes = case.combined_row_bytes.clone();
    malicious_row_bytes[73] ^= 0x04;
    let malicious_evaluation = evaluate_active_and_row(
        case.context,
        GarblingGateRow::new(
            case.gate_index,
            case.left_external_bit,
            case.right_external_bit,
        ),
        &case.active_left_components,
        &case.active_right_components,
        &malicious_row_bytes,
    )
    .unwrap();
    assert!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &malicious_evaluation,
            &case.output_commitments,
            field(u16::from(case.row_bit)),
        )
        .is_err()
    );

    let different_context = preparation_context(30);
    let mixed_capsule_evaluation = evaluate_active_and_row(
        different_context,
        GarblingGateRow::new(
            case.gate_index,
            case.left_external_bit,
            case.right_external_bit,
        ),
        &case.active_left_components,
        &case.active_right_components,
        &case.combined_row_bytes,
    )
    .unwrap();
    assert!(
        verify_active_and_output(
            different_context,
            OUTPUT_WIRE_INDEX,
            &mixed_capsule_evaluation,
            &case.output_commitments,
            field(u16::from(case.row_bit)),
        )
        .is_err()
    );
}

#[test]
fn audit_refuses_wrong_output_membership_inconsistent_bits_equal_commitments_and_non_bits() {
    let case = honest_and_case(preparation_context(31), 47, false, true, false, true, true);

    let mut wrong_output_components = case.evaluated_components.clone();
    let mut wrong_output_bytes = wrong_output_components[0].canonical_bytes();
    wrong_output_bytes[27] ^= 0x01;
    wrong_output_components[0] = WireLabel::from_canonical_bytes(&wrong_output_bytes).unwrap();
    assert!(matches!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &wrong_output_components,
            &case.output_commitments,
            field(u16::from(case.row_bit)),
        ),
        Err(TallyPreparationError::GarblingLabelCommitmentMembershipMismatch { .. })
    ));

    let mut inconsistent_components = case.expected_output_components.clone();
    inconsistent_components[1] = case.output_one_labels[1];
    inconsistent_components[0] = case.output_zero_labels[0];
    assert!(matches!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &inconsistent_components,
            &case.output_commitments,
            BinaryFieldElement256::ZERO,
        ),
        Err(TallyPreparationError::GarblingComponentPointBitMismatch { .. })
    ));

    let mut equal_commitments = case.output_commitments.clone();
    equal_commitments[0] = AffineLabelCommitments::from_commitments_for_test(
        equal_commitments[0].zero(),
        equal_commitments[0].zero(),
    );
    assert!(matches!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &case.evaluated_components,
            &equal_commitments,
            field(u16::from(case.row_bit)),
        ),
        Err(TallyPreparationError::AffineLabelCommitmentsEqual {
            component_position: 0
        })
    ));

    assert_eq!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &case.evaluated_components,
            &case.output_commitments,
            field(2),
        ),
        Err(TallyPreparationError::GarblingAuthenticatedRowValueNotBit)
    );
    assert_eq!(
        verify_active_and_output(
            case.context,
            OUTPUT_WIRE_INDEX,
            &case.evaluated_components,
            &case.output_commitments,
            field(u16::from(!case.row_bit)),
        ),
        Err(TallyPreparationError::GarblingAuthenticatedRowBitMismatch)
    );
}

struct HonestAndCase {
    context: TallyPreparationContext,
    gate_index: u32,
    left_external_bit: bool,
    right_external_bit: bool,
    row_bit: bool,
    active_left_components: Vec<WireLabel>,
    active_right_components: Vec<WireLabel>,
    combined_row_bytes: Vec<u8>,
    evaluated_components: Vec<WireLabel>,
    expected_output_components: Vec<WireLabel>,
    output_zero_labels: Vec<WireLabel>,
    output_one_labels: Vec<WireLabel>,
    output_commitments: Vec<AffineLabelCommitments>,
}

fn honest_and_case(
    context: TallyPreparationContext,
    gate_index: u32,
    left_mask: bool,
    right_mask: bool,
    output_mask: bool,
    left_external_bit: bool,
    right_external_bit: bool,
) -> HonestAndCase {
    let participant_count = usize::from(context.participant_count());
    let offsets = (0..participant_count)
        .map(|component_position| label_body(101 + component_position as u8 * 7))
        .collect::<Vec<_>>();
    let left_zero_labels = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                label_body(7 + component_position as u8 * 11),
                offsets[component_position],
                false,
            )
        })
        .collect::<Vec<_>>();
    let right_zero_labels = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                label_body(37 + component_position as u8 * 13),
                offsets[component_position],
                false,
            )
        })
        .collect::<Vec<_>>();
    let output_zero_labels = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                label_body(67 + component_position as u8 * 17),
                offsets[component_position],
                false,
            )
        })
        .collect::<Vec<_>>();
    let output_one_labels = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                output_zero_labels[component_position].body(),
                offsets[component_position],
                true,
            )
        })
        .collect::<Vec<_>>();
    let active_left_components = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                left_zero_labels[component_position].body(),
                offsets[component_position],
                left_external_bit,
            )
        })
        .collect::<Vec<_>>();
    let active_right_components = (0..participant_count)
        .map(|component_position| {
            derive_affine_wire_label(
                right_zero_labels[component_position].body(),
                offsets[component_position],
                right_external_bit,
            )
        })
        .collect::<Vec<_>>();
    let row_bit =
        ((left_mask ^ left_external_bit) & (right_mask ^ right_external_bit)) ^ output_mask;

    let zero_label = WireLabel::new(
        LabelBody::from_canonical_bytes(&[0_u8; LABEL_BODY_BYTE_LENGTH]).unwrap(),
        false,
    );
    let mut correlation_shares = vec![vec![zero_label; participant_count]; participant_count];
    if row_bit {
        for (component_position, offset) in offsets.iter().copied().enumerate() {
            correlation_shares[participant_count - 1][component_position] =
                WireLabel::new(offset, true);
        }
    }
    let individual_share_bytes = (0..participant_count)
        .map(|contributor_position| {
            create_individual_garbling_share(
                context,
                GarblingGateRow::new(gate_index, left_external_bit, right_external_bit),
                contributor_position as u16,
                GarblingInputComponentLabels::new(
                    active_left_components[contributor_position],
                    active_right_components[contributor_position],
                ),
                &correlation_shares[contributor_position],
                output_zero_labels[contributor_position],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let combined_row_bytes =
        combine_individual_garbling_shares(context.participant_count(), &individual_share_bytes)
            .unwrap();
    let evaluated_components = evaluate_active_and_row(
        context,
        GarblingGateRow::new(gate_index, left_external_bit, right_external_bit),
        &active_left_components,
        &active_right_components,
        &combined_row_bytes,
    )
    .unwrap();
    let expected_output_components = if row_bit {
        output_one_labels.clone()
    } else {
        output_zero_labels.clone()
    };
    let output_commitments = (0..participant_count)
        .map(|component_position| {
            AffineLabelCommitments::derive(
                context,
                OUTPUT_WIRE_INDEX,
                component_position as u16,
                output_zero_labels[component_position],
                output_one_labels[component_position],
            )
            .unwrap()
        })
        .collect();

    HonestAndCase {
        context,
        gate_index,
        left_external_bit,
        right_external_bit,
        row_bit,
        active_left_components,
        active_right_components,
        combined_row_bytes,
        evaluated_components,
        expected_output_components,
        output_zero_labels,
        output_one_labels,
        output_commitments,
    }
}

fn preparation_context(attempt_byte: u8) -> TallyPreparationContext {
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(3, 2, 1).unwrap()).unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([17_u8; 64]),
        Hash512::from_bytes([29_u8; 64]),
        [attempt_byte; 32],
        &circuit,
    )
    .unwrap()
}

fn label_body(seed: u8) -> LabelBody {
    let bytes = core::array::from_fn::<_, LABEL_BODY_BYTE_LENGTH, _>(|byte_position| {
        seed.wrapping_add((byte_position as u8).wrapping_mul(37))
    });
    LabelBody::from_canonical_bytes(&bytes).unwrap()
}

fn field(value: u16) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_low_polynomial_u16(value)
}
