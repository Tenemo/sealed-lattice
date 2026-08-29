use tiny_keccak::{Hasher, Kmac};

use crate::foundation::Hash512;

use super::lpsy15_bmr_prf::{
    LPSY15_BMR_PRF_CUSTOMIZATION, LPSY15_BMR_PRF_KEY_BYTE_LENGTH, LPSY15_BMR_PRF_MESSAGE_DOMAIN,
    LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH, Lpsy15BmrPrfInput, evaluate_lpsy15_bmr_prf,
};

#[test]
fn canonical_message_has_the_compiler_width_and_binds_every_coordinate() {
    let baseline = sample_input();
    let baseline_bytes = baseline.canonical_message_bytes().unwrap();
    assert_eq!(baseline_bytes.len(), 452);
    assert!(
        baseline_bytes
            .windows(LPSY15_BMR_PRF_MESSAGE_DOMAIN.len())
            .any(|window| { window == LPSY15_BMR_PRF_MESSAGE_DOMAIN.as_bytes() })
    );

    let variants = [
        Lpsy15BmrPrfInput {
            candidate_identity: Hash512::from_bytes([0xa1; 64]),
            ..baseline
        },
        Lpsy15BmrPrfInput {
            roster_root: Hash512::from_bytes([0xa2; 64]),
            ..baseline
        },
        Lpsy15BmrPrfInput {
            circuit_identity: Hash512::from_bytes([0xa3; 64]),
            ..baseline
        },
        Lpsy15BmrPrfInput {
            preparation_attempt_root: Hash512::from_bytes([0xa4; 64]),
            ..baseline
        },
        Lpsy15BmrPrfInput {
            complete_predecessor_root: Hash512::from_bytes([0xa5; 64]),
            ..baseline
        },
        Lpsy15BmrPrfInput {
            gate_index: baseline.gate_index + 1,
            ..baseline
        },
        Lpsy15BmrPrfInput {
            input_side: baseline.input_side + 1,
            ..baseline
        },
        Lpsy15BmrPrfInput {
            output_component: baseline.output_component + 1,
            ..baseline
        },
        Lpsy15BmrPrfInput {
            branch: baseline.branch + 1,
            ..baseline
        },
    ];
    for variant in variants {
        assert_ne!(variant.canonical_message_bytes().unwrap(), baseline_bytes);
    }
}

#[test]
fn fixed_output_matches_independent_tiny_keccak_kmac256() {
    let key = core::array::from_fn::<_, LPSY15_BMR_PRF_KEY_BYTE_LENGTH, _>(|position| {
        0x31_u8.wrapping_add((position as u8).wrapping_mul(7))
    });
    let input = sample_input();
    let message = input.canonical_message_bytes().unwrap();
    let actual = evaluate_lpsy15_bmr_prf(&key, input).unwrap();

    let mut independent = Kmac::v256(&key, LPSY15_BMR_PRF_CUSTOMIZATION);
    independent.update(&message);
    let mut expected = [0_u8; LPSY15_BMR_PRF_OUTPUT_BYTE_LENGTH];
    independent.finalize(&mut expected);
    assert_eq!(actual.as_ref(), &expected);
}

#[test]
fn key_and_each_public_coordinate_change_the_prf_output() {
    let first_key = [0x17_u8; LPSY15_BMR_PRF_KEY_BYTE_LENGTH];
    let mut second_key = first_key;
    second_key[19] ^= 0x80;
    let baseline = sample_input();
    let baseline_output = evaluate_lpsy15_bmr_prf(&first_key, baseline).unwrap();
    let distinct_key_output = evaluate_lpsy15_bmr_prf(&second_key, baseline).unwrap();
    let distinct_branch_output = evaluate_lpsy15_bmr_prf(
        &first_key,
        Lpsy15BmrPrfInput {
            branch: baseline.branch + 1,
            ..baseline
        },
    )
    .unwrap();
    assert_ne!(baseline_output.as_ref(), distinct_key_output.as_ref());
    assert_ne!(baseline_output.as_ref(), distinct_branch_output.as_ref());
}

fn sample_input() -> Lpsy15BmrPrfInput {
    Lpsy15BmrPrfInput {
        candidate_identity: Hash512::from_bytes([0x11; 64]),
        roster_root: Hash512::from_bytes([0x22; 64]),
        circuit_identity: Hash512::from_bytes([0x33; 64]),
        preparation_attempt_root: Hash512::from_bytes([0x44; 64]),
        complete_predecessor_root: Hash512::from_bytes([0x55; 64]),
        gate_index: 2_962,
        input_side: 1,
        output_component: 9,
        branch: 1,
    }
}
