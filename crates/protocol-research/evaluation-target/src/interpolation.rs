use supported_profile::Profile;

/// The signed monomial X^exponent of Z[X]/(X^R + 1).
fn monomial(exponent: usize, degree: usize) -> Vec<i64> {
    let mut value = vec![0; degree];
    value[exponent % degree] = if (exponent / degree).is_multiple_of(2) {
        1
    } else {
        -1
    };
    value
}
fn product(left: &[i64], right: &[i64]) -> Vec<i64> {
    let degree = left.len();
    let mut result = vec![0i64; degree];
    for (first, left) in left.iter().enumerate() {
        for (second, right) in right.iter().enumerate() {
            let term = left.checked_mul(*right).unwrap();
            if first + second < degree {
                result[first + second] += term;
            } else {
                result[first + second - degree] -= term;
            }
        }
    }
    result
}
/// Twice the inverse of 1 - X^k for k not a multiple of 2R. With
/// k = 2^v * odd, X^k has order 2R / 2^v, so with L = R / 2^v,
/// (1 - X^k) * sum_{i < L} X^(k i) = 1 - X^(k L) = 2.
fn doubled_inverse(exponent: usize, degree: usize) -> Vec<i64> {
    let exponent = exponent % (2 * degree);
    assert_ne!(exponent, 0);
    let mut result = vec![0; degree];
    for index in 0..degree >> exponent.trailing_zeros() {
        for (sum, value) in result.iter_mut().zip(monomial(exponent * index, degree)) {
            *sum += value;
        }
    }
    result
}

/// The clearing factor times each selected position's Lagrange coefficient
/// at zero in Z[X]/(X^R + 1), where roster position a is X^a. The
/// coefficient of position i is the product over the other positions j of
/// 1 / (1 - X^(a_i - a_j)). The caller lifts X to X^(N/R) in the ciphertext
/// ring.
pub(crate) fn cleared_weights(profile: Profile, positions: &[usize]) -> Result<Vec<Vec<i64>>, ()> {
    if positions.len() != profile.release_threshold()
        || positions
            .iter()
            .any(|position| *position >= profile.participants())
        || positions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(());
    }
    let degree = profile.interpolation_degree();
    let period = 2 * degree;
    let clearing = profile.clearing_factor() as i64;
    // Each factor is half a doubled inverse.
    let divisor = 1i64 << (positions.len() - 1);
    Ok(positions
        .iter()
        .map(|member| {
            let mut numerator = monomial(0, degree);
            for other in positions.iter().filter(|other| *other != member) {
                numerator = product(
                    &numerator,
                    &doubled_inverse((member + period - other) % period, degree),
                );
            }
            numerator
                .into_iter()
                .map(|value| {
                    let scaled = value * clearing;
                    assert_eq!(
                        scaled % divisor,
                        0,
                        "The clearing factor clears every reconstruction denominator"
                    );
                    scaled / divisor
                })
                .collect()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reconstruction at zero of each sharing basis term X^(a * power) below
    // the release threshold: the cleared weights sum to the clearing factor
    // for the constant term and to zero for every other term.
    fn check(profile: Profile, positions: &[usize]) {
        let degree = profile.interpolation_degree();
        let weights = cleared_weights(profile, positions).unwrap();
        for power in 0..profile.release_threshold() {
            let mut sum = vec![0i64; degree];
            for (position, weight) in positions.iter().zip(&weights) {
                for (total, value) in sum
                    .iter_mut()
                    .zip(product(weight, &monomial(position * power, degree)))
                {
                    *total += value;
                }
            }
            let mut expected = vec![0i64; degree];
            if power == 0 {
                expected[0] = profile.clearing_factor() as i64;
            }
            assert_eq!(
                sum, expected,
                "profile={profile:?}, positions={positions:?}"
            );
        }
    }
    fn subsets(count: usize, size: usize, visit: &mut impl FnMut(&[usize])) {
        fn extend(
            next: usize,
            count: usize,
            size: usize,
            chosen: &mut Vec<usize>,
            visit: &mut impl FnMut(&[usize]),
        ) {
            if chosen.len() == size {
                visit(chosen);
                return;
            }
            for position in next..count {
                chosen.push(position);
                extend(position + 1, count, size, chosen, visit);
                chosen.pop();
            }
        }
        extend(0, count, size, &mut Vec::new(), visit);
    }

    #[test]
    fn every_release_subset_of_small_rosters_reconstructs_all_sharing_basis_terms() {
        for (participants, expected) in [(3, 3), (4, 6), (7, 35), (10, 210), (12, 495)] {
            let profile = Profile::new(participants, 2).unwrap();
            let mut count = 0;
            subsets(
                participants,
                profile.release_threshold(),
                &mut |positions| {
                    check(profile, positions);
                    count += 1;
                },
            );
            assert_eq!(count, expected);
        }
    }

    #[test]
    fn spread_release_subsets_of_large_rosters_reconstruct_all_sharing_basis_terms() {
        for participants in [13, 16, 19, 20] {
            let profile = Profile::new(participants, 2).unwrap();
            let size = profile.release_threshold();
            let mut state = 0x2545_f491_4f6c_dd1d_u64 ^ participants as u64;
            let mut candidates = vec![
                (0..size).collect::<Vec<_>>(),
                (participants - size..participants).collect(),
                (0..size)
                    .map(|index| index * (participants - 1) / (size - 1))
                    .collect(),
            ];
            for _ in 0..64 {
                let mut positions: Vec<usize> = (0..participants).collect();
                for index in (1..participants).rev() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    positions.swap(index, (state % (index as u64 + 1)) as usize);
                }
                let mut chosen = positions[..size].to_vec();
                chosen.sort_unstable();
                candidates.push(chosen);
            }
            for positions in candidates {
                check(profile, &positions);
            }
        }
    }

    #[test]
    fn malformed_position_sets_refuse() {
        let profile = Profile::new(10, 10).unwrap();
        assert!(cleared_weights(profile, &[0, 0, 1, 2]).is_err());
        assert!(cleared_weights(profile, &[0, 1, 2, 10]).is_err());
        assert!(cleared_weights(profile, &[2, 1, 3, 4]).is_err());
        assert!(cleared_weights(profile, &[0, 1, 2]).is_err());
        assert!(cleared_weights(profile, &[0, 1, 2, 3, 4]).is_err());
    }
}
