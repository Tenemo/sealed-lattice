use super::*;

#[test]
fn q_share_trustee_points_are_distinct_for_first_roster() {
    for modulus in DATA_PRIMES {
        let trustee_points = (0..10)
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
    for modulus in DATA_PRIMES {
        let secret = modulus - 17;
        let coefficients = [
            secret,
            12_345 % modulus,
            (modulus / 3) + 7,
            (modulus / 5) + 11,
        ];
        let shares = (0..10)
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

        for first_index in 0..7 {
            for second_index in (first_index + 1)..8 {
                for third_index in (second_index + 1)..9 {
                    for fourth_index in (third_index + 1)..10 {
                        let selected_shares = [
                            shares[first_index],
                            shares[second_index],
                            shares[third_index],
                            shares[fourth_index],
                        ];
                        let recovered_secret = interpolate_shamir_constant_with_threshold(
                            &selected_shares,
                            4,
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
