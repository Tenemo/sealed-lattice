use crate::{
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
    },
    tally_circuit::{
        CompiledTallyCircuit, TALLY_BALLOT_ATTEMPT_COUNT, TallyBallotAttemptInput,
        TallyCircuitError, TallyCircuitProfile,
    },
};

use super::{
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bundle_320::{
        MaskedBallotBundle320, MaskedBallotBundleError320, masked_ballot_bundle_input_bit_count,
    },
};

#[test]
fn completion_bundle_uses_the_exact_compiler_order_and_minimal_bytes() {
    let circuit = completion_circuit();
    let ballot_attempts = vec![
        TallyBallotAttemptInput::new(true, (1_u8..=10).collect()),
        TallyBallotAttemptInput::new(false, (1_u8..=10).rev().collect()),
        TallyBallotAttemptInput::new(
            true,
            (0..FOUNDATION_PROFILE.option_count)
                .map(|option_position| {
                    u8::try_from((option_position * 7 + 3) % 16)
                        .expect("completion option positions fit in u8")
                })
                .collect(),
        ),
    ];
    let independently_encoded_input_bits = independent_input_bits(&circuit, &ballot_attempts);
    assert_eq!(independently_encoded_input_bits.len(), 123);
    let input_mask_bits = (0..independently_encoded_input_bits.len())
        .map(|bit_position| bit_position % 5 == 1 || bit_position % 7 == 3)
        .collect::<Vec<_>>();
    let expected_masked_bits = independently_encoded_input_bits
        .iter()
        .copied()
        .zip(input_mask_bits.iter().copied())
        .map(|(input_bit, input_mask_bit)| input_bit ^ input_mask_bit)
        .collect::<Vec<_>>();

    let bundle = MaskedBallotBundle320::derive(
        &circuit,
        FOUNDATION_PROFILE.participant_count - 1,
        &ballot_attempts,
        &input_mask_bits,
    )
    .unwrap();
    assert_eq!(bundle.input_bit_count(), 123);
    assert_eq!(bundle.masked_input_bits(), expected_masked_bits);

    let canonical_bytes = bundle.canonical_bytes();
    assert_eq!(canonical_bytes.len(), 16);
    assert_eq!(canonical_bytes[15] & 0b1111_1000, 0);
    let independently_packed_bytes = independent_pack(&expected_masked_bits);
    assert_eq!(canonical_bytes, independently_packed_bytes);

    let field_bytes = bundle.field_element().canonical_bytes();
    assert_eq!(&field_bytes[..16], canonical_bytes);
    assert!(field_bytes[16..].iter().all(|byte| *byte == 0));
    assert_eq!(
        MaskedBallotBundle320::from_canonical_bytes(&circuit, &canonical_bytes).unwrap(),
        bundle
    );
    assert!(format!("{bundle:?}").contains("[redacted]"));
}

#[test]
fn every_configurable_option_count_and_every_bundle_bit_round_trip() {
    for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(FOUNDATION_PROFILE.participant_count, option_count, 1)
                .unwrap(),
        )
        .unwrap();
        let ballot_attempts = zero_ballot_attempts(option_count);
        let input_bit_count = masked_ballot_bundle_input_bit_count(&circuit).unwrap();
        assert_eq!(
            input_bit_count,
            TALLY_BALLOT_ATTEMPT_COUNT * (1 + usize::from(option_count) * 4)
        );
        assert!(input_bit_count <= BinaryFieldElement320::CANONICAL_BYTE_LENGTH * 8);

        for selected_bit_position in 0..input_bit_count {
            let mut input_mask_bits = vec![false; input_bit_count];
            input_mask_bits[selected_bit_position] = true;
            let bundle =
                MaskedBallotBundle320::derive(&circuit, 0, &ballot_attempts, &input_mask_bits)
                    .unwrap();
            let canonical_bytes = bundle.canonical_bytes();
            assert_eq!(
                canonical_bytes.len(),
                input_bit_count.div_ceil(8),
                "option count {option_count}, bit {selected_bit_position}"
            );
            assert_eq!(
                canonical_bytes
                    .iter()
                    .map(|byte| byte.count_ones())
                    .sum::<u32>(),
                1,
                "option count {option_count}, bit {selected_bit_position}"
            );
            let decoded =
                MaskedBallotBundle320::from_canonical_bytes(&circuit, &canonical_bytes).unwrap();
            assert_eq!(decoded.masked_input_bits(), input_mask_bits);
        }
    }
}

#[test]
fn decoder_rejects_every_nonzero_padding_bit_and_wrong_byte_length() {
    for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(FOUNDATION_PROFILE.participant_count, option_count, 1)
                .unwrap(),
        )
        .unwrap();
        let input_bit_count = masked_ballot_bundle_input_bit_count(&circuit).unwrap();
        let canonical_byte_length = input_bit_count.div_ceil(8);
        let canonical_zero = vec![0_u8; canonical_byte_length];
        assert!(MaskedBallotBundle320::from_canonical_bytes(&circuit, &canonical_zero).is_ok());

        for padding_bit_position in input_bit_count % 8..8 {
            if input_bit_count.is_multiple_of(8) {
                break;
            }
            let mut noncanonical = canonical_zero.clone();
            noncanonical[canonical_byte_length - 1] |= 1_u8 << padding_bit_position;
            assert_eq!(
                MaskedBallotBundle320::from_canonical_bytes(&circuit, &noncanonical),
                Err(MaskedBallotBundleError320::NonzeroCanonicalPadding),
                "option count {option_count}, padding bit {padding_bit_position}"
            );
        }

        let short = &canonical_zero[..canonical_zero.len() - 1];
        assert_eq!(
            MaskedBallotBundle320::from_canonical_bytes(&circuit, short),
            Err(MaskedBallotBundleError320::CanonicalByteLengthMismatch {
                expected: canonical_byte_length,
                actual: canonical_byte_length - 1,
            })
        );
        let mut long = canonical_zero.clone();
        long.push(0);
        assert_eq!(
            MaskedBallotBundle320::from_canonical_bytes(&circuit, &long),
            Err(MaskedBallotBundleError320::CanonicalByteLengthMismatch {
                expected: canonical_byte_length,
                actual: canonical_byte_length + 1,
            })
        );
    }
}

#[test]
fn constructor_rejects_wrong_mask_and_every_malformed_ballot_shape() {
    let circuit = completion_circuit();
    let valid_attempts = zero_ballot_attempts(FOUNDATION_PROFILE.option_count);
    let input_bit_count = masked_ballot_bundle_input_bit_count(&circuit).unwrap();
    assert_eq!(
        MaskedBallotBundle320::derive(
            &circuit,
            0,
            &valid_attempts,
            &vec![false; input_bit_count - 1],
        ),
        Err(MaskedBallotBundleError320::InputMaskBitCountMismatch {
            expected: input_bit_count,
            actual: input_bit_count - 1,
        })
    );

    let too_few_attempts = &valid_attempts[..TALLY_BALLOT_ATTEMPT_COUNT - 1];
    assert!(matches!(
        MaskedBallotBundle320::derive(&circuit, 0, too_few_attempts, &vec![false; input_bit_count],),
        Err(MaskedBallotBundleError320::TallyCircuit(
            TallyCircuitError::InputBallotAttemptCountMismatch { .. }
        ))
    ));

    let mut wrong_option_count = zero_ballot_attempts(FOUNDATION_PROFILE.option_count);
    wrong_option_count[1] = TallyBallotAttemptInput::new(false, vec![0; 9]);
    assert!(matches!(
        MaskedBallotBundle320::derive(
            &circuit,
            0,
            &wrong_option_count,
            &vec![false; input_bit_count],
        ),
        Err(MaskedBallotBundleError320::TallyCircuit(
            TallyCircuitError::InputOptionCountMismatch { .. }
        ))
    ));

    let mut out_of_range_score = zero_ballot_attempts(FOUNDATION_PROFILE.option_count);
    out_of_range_score[2] = TallyBallotAttemptInput::new(true, [vec![16], vec![0; 9]].concat());
    assert!(matches!(
        MaskedBallotBundle320::derive(
            &circuit,
            0,
            &out_of_range_score,
            &vec![false; input_bit_count],
        ),
        Err(MaskedBallotBundleError320::TallyCircuit(
            TallyCircuitError::ScoreEncodingOutOfRange { .. }
        ))
    ));

    assert!(matches!(
        MaskedBallotBundle320::derive(
            &circuit,
            FOUNDATION_PROFILE.participant_count,
            &valid_attempts,
            &vec![false; input_bit_count],
        ),
        Err(MaskedBallotBundleError320::TallyCircuit(
            TallyCircuitError::InputParticipantPositionOutOfRange { .. }
        ))
    ));
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

fn zero_ballot_attempts(option_count: u16) -> Vec<TallyBallotAttemptInput> {
    (0..TALLY_BALLOT_ATTEMPT_COUNT)
        .map(|_| TallyBallotAttemptInput::new(false, vec![0; usize::from(option_count)]))
        .collect()
}

fn independent_input_bits(
    circuit: &CompiledTallyCircuit,
    ballot_attempts: &[TallyBallotAttemptInput],
) -> Vec<bool> {
    let mut bits = Vec::new();
    for ballot_attempt in ballot_attempts {
        bits.push(ballot_attempt.is_present());
        for score_encoding in ballot_attempt.score_encodings() {
            for bit_position in 0..circuit.geometry().score_bit_width {
                bits.push(((*score_encoding >> bit_position) & 1) == 1);
            }
        }
    }
    bits
}

fn independent_pack(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0_u8; bits.len().div_ceil(8)];
    for (bit_position, bit) in bits.iter().copied().enumerate() {
        if bit {
            bytes[bit_position / 8] |= 1_u8 << (bit_position % 8);
        }
    }
    bytes
}
