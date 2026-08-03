use super::*;

#[test]
fn interpolation_reproduces_sampled_values() {
    let values = [5_u64, 9, 2, 7, PLAINTEXT_MODULUS - 1];
    let coefficients = interpolate_coefficients(&values).expect("interpolate");
    for (point, value) in values.iter().enumerate() {
        assert_eq!(evaluate_plaintext(&coefficients, point as u64), *value);
    }
}

#[test]
fn rank_lookup_polynomials_reproduce_both_targets_for_every_configurable_option_count() {
    for option_count in usize::from(crate::foundation::MINIMUM_CONFIGURABLE_OPTION_COUNT)
        ..=usize::from(crate::foundation::MAXIMUM_CONFIGURABLE_OPTION_COUNT)
    {
        for top_count in 1..=option_count {
            let identifier_values = (0..option_count)
                .map(|rank| u64::from(rank < top_count))
                .collect::<Vec<_>>();
            let order_values = (0..option_count)
                .map(|rank| {
                    if rank < top_count {
                        u64::try_from(rank + 1).expect("rank fits u64")
                    } else {
                        0
                    }
                })
                .collect::<Vec<_>>();
            let identifier_coefficients =
                interpolate_coefficients(&identifier_values).expect("identifier interpolation");
            let order_coefficients =
                interpolate_coefficients(&order_values).expect("order interpolation");

            for rank in 0..option_count {
                let rank_field_value = u64::try_from(rank).expect("rank fits u64");
                assert_eq!(
                    evaluate_plaintext(&identifier_coefficients, rank_field_value),
                    u64::from(rank < top_count),
                    "identifier lookup drifted for option count {option_count}, top count {top_count}, and rank {rank}",
                );
                assert_eq!(
                    evaluate_plaintext(&order_coefficients, rank_field_value),
                    if rank < top_count {
                        rank_field_value + 1
                    } else {
                        0
                    },
                    "order lookup drifted for option count {option_count}, top count {top_count}, and rank {rank}",
                );
            }
        }
    }
}
