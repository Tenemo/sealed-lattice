use super::*;

// Every boundary shape and the completion profile.
fn profiles() -> Vec<Profile> {
    [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)]
        .into_iter()
        .map(|(participants, options)| Profile::new(participants, options).unwrap())
        .collect()
}
// Direct evaluation-basis interpolation, independent of the decoder's NTT.
// A nonzero evaluation at z contributes z^(-j)/2048 to the embedded
// coefficient j. The primitive 4096-th root is 11^3 modulo 12289.
fn encode_evaluations(entries: &[(usize, u32)]) -> Vec<u32> {
    let modulus = BigInt::from(12_289u32);
    let inverse_length = 12_283u64;
    let mut coefficients = vec![0u32; 65_536];
    for (index, value) in entries {
        let root = BigInt::from(1_331u32).modpow(&BigInt::from(2 * index + 1), &modulus);
        let inverse = root
            .modpow(&BigInt::from(12_287u32), &modulus)
            .to_u64_digits()
            .1[0];
        let mut term = u64::from(*value) * inverse_length % 12_289;
        for coefficient in coefficients.iter_mut().step_by(32) {
            *coefficient = ((u64::from(*coefficient) + term) % 12_289) as u32;
            term = term * inverse % 12_289;
        }
    }
    coefficients
}
fn evaluation_index(slot: usize) -> usize {
    let exponent = BigInt::from(5u32)
        .modpow(&BigInt::from(slot), &BigInt::from(4_096u32))
        .to_u64_digits()
        .1[0] as usize;
    (exponent - 1) / 2
}
fn slot(profile: Profile, option: usize, rank: usize) -> usize {
    (option * profile.rank_window() + 1_024 - rank) % 1_024
}
fn entries(profile: Profile, order: &[usize]) -> Vec<(usize, u32)> {
    order
        .iter()
        .enumerate()
        .map(|(rank, option)| (evaluation_index(slot(profile, *option, rank)), 1))
        .collect()
}
// The identity, its reverse and a fixed shuffle of the options.
fn orders(options: usize) -> Vec<Vec<usize>> {
    let identity: Vec<usize> = (0..options).collect();
    let reverse = identity.iter().rev().copied().collect();
    let shuffled = (0..options)
        .map(|index| (index * 7 + 3) % options)
        .collect::<Vec<_>>();
    let mut orders = vec![identity, reverse];
    let mut sorted = shuffled.clone();
    sorted.sort_unstable();
    if sorted == orders[0] {
        orders.push(shuffled);
    }
    orders
}
#[test]
fn direct_interpolation_decodes_varied_exact_rankings() {
    for profile in profiles() {
        let options = profile.options();
        for order in orders(options) {
            for top_count in [1, options / 2, options - 1, options] {
                let top_count = top_count.max(1);
                assert_eq!(
                    selected_positions(
                        profile,
                        &encode_evaluations(&entries(profile, &order[..top_count])),
                        top_count,
                    )
                    .unwrap(),
                    order[..top_count]
                );
            }
        }
    }
}
#[test]
fn decoder_rejects_extra_values_missing_ranks_and_noncanonical_polynomials() {
    for profile in profiles() {
        let options = profile.options();
        let window = profile.rank_window();
        let identity: Vec<usize> = (0..options).collect();
        let original = entries(profile, &identity);
        let mut variants = Vec::new();
        let mut missing = original.clone();
        missing.pop();
        variants.push(missing);
        for extra in [
            (evaluation_index(1), 1),
            (evaluation_index(options * window), 1),
            // Root exponent 3 belongs to the complementary packing orbit.
            (1, 1),
            (original[0].0, 1),
            (evaluation_index(slot(profile, 1, 0)), 1),
        ] {
            let mut changed = original.clone();
            changed.push(extra);
            variants.push(changed);
        }
        let mut repeated = identity.clone();
        repeated[1] = 0;
        variants.push(entries(profile, &repeated));
        for changed in variants {
            assert!(selected_positions(profile, &encode_evaluations(&changed), options).is_err());
        }
        let valid = encode_evaluations(&original);
        for (index, value) in [(1, 1), (2, 1), (16, 1), (31, 1), (0, 12_289)] {
            let mut changed = valid.clone();
            changed[index] = value;
            assert!(selected_positions(profile, &changed, options).is_err());
        }
        assert!(selected_positions(profile, &valid[..valid.len() - 1], options).is_err());
        let mut changed = valid;
        changed.push(0);
        assert!(selected_positions(profile, &changed, options).is_err());
    }
}

// Direct evaluation at one packing slot, independent of every transform.
fn slot_value(coefficients: &[u32], slot: usize) -> u32 {
    let exponent = BigInt::from(5u32)
        .modpow(&BigInt::from(slot % 1_024), &BigInt::from(4_096u32))
        .to_u64_digits()
        .1[0] as u32;
    let exponent = if slot < 1_024 {
        exponent
    } else {
        4_096 - exponent
    };
    let point = u64::from(power(1_331, exponent));
    coefficients
        .iter()
        .step_by(32)
        .rev()
        .fold(0u64, |sum, value| {
            (sum * point + u64::from(*value)) % u64::from(PLAINTEXT_MODULUS)
        }) as u32
}
#[test]
fn packed_ballots_decode_through_every_requested_result_length() {
    for profile in profiles() {
        let options = profile.options();
        let window = profile.rank_window();
        // Scores of every value, with repeated totals so that the
        // canonical tie rule decides positions.
        let ballots: Vec<Vec<u8>> = (0..profile.participants().min(5))
            .map(|ballot| {
                (0..options)
                    .map(|option| ((option * (ballot + 3) + ballot) % 10 + 1) as u8)
                    .collect()
            })
            .collect();
        let mut sum = vec![0u32; 65_536];
        for scores in &ballots {
            let packed = ballot_encryption::packing::encode(scores).unwrap();
            for (total, value) in sum.iter_mut().zip(packed) {
                *total = (*total + value.rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
                    % PLAINTEXT_MODULUS;
            }
        }
        let totals: Vec<i64> = (0..options)
            .map(|option| ballots.iter().map(|scores| i64::from(scores[option])).sum())
            .collect();
        let centered = |value: u32| {
            if value > PLAINTEXT_MODULUS / 2 {
                i64::from(value) - i64::from(PLAINTEXT_MODULUS)
            } else {
                i64::from(value)
            }
        };
        // Each option has one comparison window. The other orbit holds
        // the literal scores used by the linked ballot relation.
        let mut ranks = vec![0; options];
        for option in 0..options {
            let mut ahead = 0;
            for lane in 0..window {
                let difference = centered(slot_value(&sum, option * window + lane));
                let expected = if lane < options {
                    2 * (totals[lane] - totals[option])
                } else {
                    0
                };
                assert_eq!(difference, expected, "option={option}, lane={lane}");
                let bias = if lane < option { 1 } else { -1 };
                ahead += usize::from(difference + bias > 0);
            }
            ranks[option] = ahead;
            assert_eq!(i64::from(slot_value(&sum, 1_024 + option)), totals[option]);
        }
        for padding in [options * window, 1_023, 1_024 + options, 2_047] {
            assert_eq!(slot_value(&sum, padding), 0);
        }
        let mut order: Vec<usize> = (0..options).collect();
        order.sort_by_key(|option| (std::cmp::Reverse(totals[*option]), *option));
        for top_count in 1..=options {
            let output: Vec<_> = (0..options)
                .filter(|option| ranks[*option] < top_count)
                .map(|option| (evaluation_index(slot(profile, option, ranks[option])), 1))
                .collect();
            assert_eq!(
                selected_positions(profile, &encode_evaluations(&output), top_count).unwrap(),
                order[..top_count]
            );
        }
    }
}

#[test]
fn shorter_outputs_reject_omitted_ranks_in_the_plaintext() {
    for profile in profiles() {
        let options = profile.options();
        let order: Vec<usize> = (0..options).rev().collect();
        let complete = encode_evaluations(&entries(profile, &order));
        for top_count in [1, options - 1] {
            if top_count == options {
                continue;
            }
            assert!(selected_positions(profile, &complete, top_count).is_err());
            let mut extra = entries(profile, &order[..top_count]);
            extra.push((
                evaluation_index(slot(profile, order[top_count], top_count)),
                1,
            ));
            assert!(selected_positions(profile, &encode_evaluations(&extra), top_count).is_err());
            let mut missing = entries(profile, &order[..top_count]);
            missing.pop();
            assert!(selected_positions(profile, &encode_evaluations(&missing), top_count).is_err());
        }
        for top_count in [0, options + 1, usize::MAX] {
            assert!(selected_positions(profile, &complete, top_count).is_err());
        }
    }
}
