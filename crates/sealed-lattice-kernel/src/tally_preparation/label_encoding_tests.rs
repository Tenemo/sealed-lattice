use super::{
    BinaryFieldElement256, TallyPreparationError,
    label_encoding::{
        DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC, DegreeThreeLabelPolynomial, DegreeThreeLabelShare,
        LABEL_BODY_BYTE_LENGTH, LABEL_BODY_FIELD_LIMB_COUNT, LABEL_SHARE_VALUE_BYTE_LENGTH,
        LabelBody, WIRE_LABEL_CANONICAL_BYTE_LENGTH, WireLabel,
        decode_canonical_degree_three_label_share, decode_garbling_output_components,
        encode_garbling_output_components, garbling_output_byte_length,
        reconstruct_degree_three_label_body,
    },
    output_sharing::{DegreeThreeMaskPolynomial, canonical_evaluation_point},
};
use crate::foundation::{
    MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

const COMPLETION_PARTICIPANT_COUNT: u16 = 10;

#[test]
fn label_body_uses_three_field_limbs_but_every_share_value_uses_all_ninety_six_bytes() {
    let label_body = patterned_label_body(0x31);
    let polynomial = sample_label_polynomial(label_body);
    let shares = polynomial.shares(COMPLETION_PARTICIPANT_COUNT).unwrap();

    assert_eq!(LABEL_BODY_BYTE_LENGTH, 80);
    assert_eq!(LABEL_BODY_FIELD_LIMB_COUNT, 3);
    assert_eq!(LABEL_SHARE_VALUE_BYTE_LENGTH, 96);
    assert!(
        shares
            .iter()
            .all(|share| { share.canonical_value_bytes().len() == LABEL_SHARE_VALUE_BYTE_LENGTH })
    );
    assert!(shares.iter().any(|share| {
        share.canonical_value_bytes()[LABEL_BODY_BYTE_LENGTH..]
            .iter()
            .any(|byte| *byte != 0)
    }));

    let first_share_third_limb = shares[0].values()[2].canonical_bytes();
    assert!(
        first_share_third_limb[16..].iter().any(|byte| *byte != 0),
        "a Shamir share's third limb must not inherit the secret's zero padding"
    );
}

#[test]
fn every_four_label_share_subset_reconstructs_and_extra_shares_are_checked() {
    let label_body = patterned_label_body(0xa7);
    let shares = sample_label_polynomial(label_body)
        .shares(COMPLETION_PARTICIPANT_COUNT)
        .unwrap();
    let mut subset_count = 0_usize;

    for first_position in 0..7 {
        for second_position in (first_position + 1)..8 {
            for third_position in (second_position + 1)..9 {
                for fourth_position in (third_position + 1)..10 {
                    let subset = [
                        shares[first_position],
                        shares[second_position],
                        shares[third_position],
                        shares[fourth_position],
                    ];
                    assert_eq!(
                        reconstruct_degree_three_label_body(COMPLETION_PARTICIPANT_COUNT, &subset,)
                            .unwrap(),
                        label_body
                    );
                    subset_count += 1;
                }
            }
        }
    }
    assert_eq!(subset_count, 210);

    let mut inconsistent_shares = shares;
    let changed_values = {
        let mut values = inconsistent_shares[7].values();
        values[1] = values[1].add(BinaryFieldElement256::ONE);
        values
    };
    inconsistent_shares[7] = DegreeThreeLabelShare::new(
        COMPLETION_PARTICIPANT_COUNT,
        inconsistent_shares[7].roster_position(),
        inconsistent_shares[7].evaluation_point(),
        changed_values,
    )
    .unwrap();
    assert!(matches!(
        reconstruct_degree_three_label_body(COMPLETION_PARTICIPANT_COUNT, &inconsistent_shares,),
        Err(TallyPreparationError::InconsistentShare { roster_position: 7 })
    ));
}

#[test]
fn reconstruction_rejects_nonzero_secret_padding_without_restricting_individual_shares() {
    let zero_polynomial = DegreeThreeMaskPolynomial::new(
        BinaryFieldElement256::ZERO,
        [BinaryFieldElement256::ZERO; 3],
    );
    let mut padded_secret_bytes = [0_u8; 32];
    padded_secret_bytes[31] = 0x80;
    let padded_secret = BinaryFieldElement256::from_canonical_bytes(&padded_secret_bytes).unwrap();
    let padded_polynomial = DegreeThreeMaskPolynomial::new(
        padded_secret,
        [
            repeated_field_element(0x45),
            repeated_field_element(0x9a),
            repeated_field_element(0xf1),
        ],
    );
    let shares = (0..COMPLETION_PARTICIPANT_COUNT)
        .map(|roster_position| {
            let evaluation_point =
                canonical_evaluation_point(COMPLETION_PARTICIPANT_COUNT, roster_position).unwrap();
            DegreeThreeLabelShare::new(
                COMPLETION_PARTICIPANT_COUNT,
                roster_position,
                evaluation_point,
                [
                    zero_polynomial.evaluate(evaluation_point),
                    zero_polynomial.evaluate(evaluation_point),
                    padded_polynomial.evaluate(evaluation_point),
                ],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(shares.iter().any(|share| {
        share.values()[2].canonical_bytes()[16..]
            .iter()
            .any(|byte| *byte != 0)
    }));
    assert_eq!(
        reconstruct_degree_three_label_body(COMPLETION_PARTICIPANT_COUNT, &shares[..4]),
        Err(TallyPreparationError::LabelBodyPaddingNonzero)
    );
}

#[test]
fn label_share_artifact_roundtrips_and_refuses_wrong_framing_points_and_lengths() {
    let share = sample_label_polynomial(patterned_label_body(0x72))
        .share(COMPLETION_PARTICIPANT_COUNT, 6)
        .unwrap();
    assert_eq!(share.participant_count(), COMPLETION_PARTICIPANT_COUNT);
    let canonical_bytes = share.canonical_bytes();
    assert_eq!(
        decode_canonical_degree_three_label_share(&canonical_bytes).unwrap(),
        share
    );

    let version_offset = 1 + DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC.len();
    let participant_count_offset = version_offset + 1;
    let roster_position_offset = participant_count_offset + 1;
    let evaluation_point_length_offset = roster_position_offset + 1;
    let evaluation_point_offset = evaluation_point_length_offset + 1;

    let mut wrong_magic = canonical_bytes.clone();
    wrong_magic[1] ^= 1;
    assert_eq!(
        decode_canonical_degree_three_label_share(&wrong_magic),
        Err(TallyPreparationError::LabelShareArtifactMagicMismatch)
    );

    let mut wrong_version = canonical_bytes.clone();
    wrong_version[version_offset] = 2;
    assert_eq!(
        decode_canonical_degree_three_label_share(&wrong_version),
        Err(TallyPreparationError::UnsupportedLabelShareArtifactVersion { version: 2 })
    );

    let mut wrong_roster_position = canonical_bytes.clone();
    wrong_roster_position[roster_position_offset] = 10;
    assert!(matches!(
        decode_canonical_degree_three_label_share(&wrong_roster_position),
        Err(TallyPreparationError::RosterPositionOutOfRange { .. })
    ));

    let mut wrong_point = canonical_bytes.clone();
    wrong_point[evaluation_point_offset] ^= 1;
    assert!(matches!(
        decode_canonical_degree_three_label_share(&wrong_point),
        Err(TallyPreparationError::EvaluationPointMismatch { .. })
    ));

    let mut short_point = canonical_bytes.clone();
    short_point[evaluation_point_length_offset] = 31;
    assert!(matches!(
        decode_canonical_degree_three_label_share(&short_point),
        Err(TallyPreparationError::FieldElementByteLength {
            expected: 32,
            actual: 31
        })
    ));

    let mut trailing = canonical_bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode_canonical_degree_three_label_share(&trailing),
        Err(TallyPreparationError::TrailingLabelShareArtifactBytes)
    );
}

#[test]
fn compact_garbling_output_is_exactly_six_thousand_four_hundred_ten_bits() {
    let mut components = (0..usize::from(COMPLETION_PARTICIPANT_COUNT))
        .map(|component_position| {
            WireLabel::new(
                patterned_label_body(u8::try_from(component_position * 19).unwrap()),
                component_position % 2 == 0,
            )
        })
        .collect::<Vec<_>>();
    let mut second_body_bytes = *components[1].body().canonical_bytes();
    second_body_bytes[0] |= 1;
    components[1] = WireLabel::new(
        LabelBody::from_canonical_bytes(&second_body_bytes).unwrap(),
        false,
    );

    let bytes =
        encode_garbling_output_components(COMPLETION_PARTICIPANT_COUNT, &components).unwrap();
    assert_eq!(bytes.len(), 802);
    assert_eq!(
        garbling_output_byte_length(COMPLETION_PARTICIPANT_COUNT),
        Ok(802)
    );
    assert_eq!(bytes[80] & 0b11, 0b11);
    assert_eq!(bytes[801] & 0b1111_1100, 0);
    assert_eq!(
        decode_garbling_output_components(COMPLETION_PARTICIPANT_COUNT, &bytes).unwrap(),
        components
    );

    for high_padding_bit in 2..8 {
        let mut noncanonical = bytes.clone();
        noncanonical[801] |= 1_u8 << high_padding_bit;
        assert_eq!(
            decode_garbling_output_components(COMPLETION_PARTICIPANT_COUNT, &noncanonical),
            Err(TallyPreparationError::GarblingOutputPaddingNonzero)
        );
    }
    assert!(matches!(
        decode_garbling_output_components(COMPLETION_PARTICIPANT_COUNT, &bytes[..801]),
        Err(TallyPreparationError::GarblingOutputByteLength {
            expected: 802,
            actual: 801
        })
    ));
    assert!(matches!(
        encode_garbling_output_components(9, &components),
        Err(
            TallyPreparationError::GarblingOutputComponentCountMismatch {
                expected: 9,
                actual: 10
            }
        )
    ));
}

#[test]
fn garbling_output_lengths_and_padding_are_canonical_for_every_admitted_roster_size() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let components = (0..participant_count)
            .map(|roster_position| {
                WireLabel::new(
                    patterned_label_body(u8::try_from(roster_position).unwrap()),
                    roster_position % 3 == 0,
                )
            })
            .collect::<Vec<_>>();
        let encoded = encode_garbling_output_components(participant_count, &components).unwrap();
        assert_eq!(
            encoded.len(),
            (usize::from(participant_count) * 641).div_ceil(8)
        );
        assert_eq!(
            decode_garbling_output_components(participant_count, &encoded).unwrap(),
            components
        );
    }
}

#[test]
fn standalone_wire_label_encoding_requires_an_explicit_canonical_point_bit() {
    let wire_label = WireLabel::new(patterned_label_body(0xc4), true);
    let canonical_bytes = wire_label.canonical_bytes();
    assert_eq!(canonical_bytes.len(), WIRE_LABEL_CANONICAL_BYTE_LENGTH);
    assert_eq!(canonical_bytes[LABEL_BODY_BYTE_LENGTH], 1);
    assert_eq!(
        WireLabel::from_canonical_bytes(&canonical_bytes).unwrap(),
        wire_label
    );

    let mut noncanonical_point_bit = canonical_bytes;
    noncanonical_point_bit[LABEL_BODY_BYTE_LENGTH] = 2;
    assert_eq!(
        WireLabel::from_canonical_bytes(&noncanonical_point_bit),
        Err(TallyPreparationError::NonCanonicalPointBit { value: 2 })
    );
    assert!(matches!(
        WireLabel::from_canonical_bytes(&canonical_bytes[..LABEL_BODY_BYTE_LENGTH]),
        Err(TallyPreparationError::WireLabelByteLength { .. })
    ));
    assert!(matches!(
        LabelBody::from_canonical_bytes(&canonical_bytes[..LABEL_BODY_BYTE_LENGTH - 1]),
        Err(TallyPreparationError::LabelBodyByteLength { .. })
    ));
}

fn sample_label_polynomial(label_body: LabelBody) -> DegreeThreeLabelPolynomial {
    DegreeThreeLabelPolynomial::new(
        label_body,
        [
            [
                repeated_field_element(0x11),
                repeated_field_element(0x27),
                repeated_field_element(0x3d),
            ],
            [
                repeated_field_element(0x54),
                repeated_field_element(0x6a),
                repeated_field_element(0x80),
            ],
            [
                repeated_field_element(0x97),
                repeated_field_element(0xad),
                repeated_field_element(0xc3),
            ],
        ],
    )
}

fn patterned_label_body(seed: u8) -> LabelBody {
    let mut bytes = [0_u8; LABEL_BODY_BYTE_LENGTH];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(u8::try_from(byte_position).unwrap().wrapping_mul(0x35))
            .rotate_left(u32::try_from(byte_position % 8).unwrap());
    }
    LabelBody::from_canonical_bytes(&bytes).unwrap()
}

fn repeated_field_element(byte: u8) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_canonical_bytes(&[byte; 32]).unwrap()
}
