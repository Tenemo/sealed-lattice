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
#[path = "interpolation-tests.rs"]
mod tests;
