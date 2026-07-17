use super::*;
use crate::foundation::FOUNDATION_PROFILE;

#[test]
fn q_share_trustee_points_are_distinct_for_foundation_roster() {
    for modulus in DATA_PRIMES {
        let trustee_points = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .map(|roster_position| {
                canonical_trustee_point(roster_position, modulus).expect("trustee point")
            })
            .collect::<Vec<_>>();

        for (left_index, left_point) in trustee_points.iter().enumerate() {
            assert_ne!(*left_point, 0);
            assert!(*left_point < modulus);
            for right_point in trustee_points.iter().skip(left_index + 1) {
                assert_ne!(
                    left_point, right_point,
                    "duplicate trustee point modulo {modulus}"
                );
            }
        }
    }
}

#[test]
fn every_four_share_subset_recovers_the_constant_for_each_q_share_prime() {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let reconstruction_threshold = usize::from(FOUNDATION_PROFILE.reconstruction_threshold);
    assert_eq!(reconstruction_threshold, 4);
    for modulus in DATA_PRIMES {
        let secret = modulus - 17;
        let coefficients = [
            secret,
            12_345 % modulus,
            (modulus / 3) + 7,
            (modulus / 5) + 11,
        ];
        let shares = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .map(|roster_position| {
                let trustee_point =
                    canonical_trustee_point(roster_position, modulus).expect("trustee point");
                let value = evaluate_shamir_polynomial(&coefficients, trustee_point, modulus)
                    .expect("share evaluation");

                RnsShamirShare {
                    roster_position,
                    value,
                }
            })
            .collect::<Vec<_>>();

        for first_index in 0..(participant_count - 3) {
            for second_index in (first_index + 1)..(participant_count - 2) {
                for third_index in (second_index + 1)..(participant_count - 1) {
                    for fourth_index in (third_index + 1)..participant_count {
                        let selected_shares = [
                            shares[first_index],
                            shares[second_index],
                            shares[third_index],
                            shares[fourth_index],
                        ];
                        let recovered_secret = interpolate_shamir_constant_with_threshold(
                            &selected_shares,
                            reconstruction_threshold,
                            modulus,
                        )
                        .expect("interpolate");

                        assert_eq!(
                            recovered_secret, secret,
                            "wrong secret for modulus {modulus} and share indexes {first_index},{second_index},{third_index},{fourth_index}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn q_share_shamir_arithmetic_rejects_malformed_inputs() {
    let modulus = DATA_PRIMES[0];
    let valid_coefficients = [7, 11, 13, 17];
    let trustee_point = canonical_trustee_point(0, modulus).expect("trustee point");

    assert!(evaluate_shamir_polynomial(&[], trustee_point, modulus).is_err());
    assert!(evaluate_shamir_polynomial(&[modulus], trustee_point, modulus).is_err());
    assert!(evaluate_shamir_polynomial(&valid_coefficients, 0, modulus).is_err());
    assert!(evaluate_shamir_polynomial(&valid_coefficients, modulus, modulus).is_err());

    let shares = (0..4)
        .map(|roster_position| {
            let trustee_point =
                canonical_trustee_point(roster_position, modulus).expect("trustee point");
            let value = evaluate_shamir_polynomial(&valid_coefficients, trustee_point, modulus)
                .expect("share evaluation");

            RnsShamirShare {
                roster_position,
                value,
            }
        })
        .collect::<Vec<_>>();

    assert!(interpolate_shamir_constant_with_threshold(&shares[..3], 4, modulus).is_err());
    assert!(
        interpolate_shamir_constant_with_threshold(
            &[shares[0], shares[0], shares[2], shares[3]],
            4,
            modulus
        )
        .is_err()
    );

    let mut out_of_range_share = shares;
    out_of_range_share[0].value = modulus;
    assert!(interpolate_shamir_constant_with_threshold(&out_of_range_share, 4, modulus).is_err());
}
