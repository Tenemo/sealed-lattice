use super::{Element, Error, MODULUS, ZERO, arithmetic, minus, multiply, plus};

pub const SYSTEMATIC_SIZE: usize = 65_536;
pub const QUERY_LIMIT: usize = 2 * 704;

fn scale(value: Element, scalar: u128) -> Element {
    value.map(|entry| multiply(entry, scalar))
}

// A transform of one length. Each stage's twiddles lie together: the stage
// of width w keeps the w/2 powers of a primitive w-th root at offset w/2 - 1.
struct Transform {
    twiddles: Vec<u128>,
}
impl Transform {
    fn new(length: usize, inverse: bool) -> Self {
        let mut root = arithmetic::power(7, (MODULUS - 1) / length as u128);
        if inverse {
            root = arithmetic::power(root, MODULUS - 2);
        }
        let mut powers = vec![1; length / 2];
        for index in 1..powers.len() {
            powers[index] = multiply(powers[index - 1], root);
        }
        let mut twiddles = Vec::with_capacity(length - 1);
        let mut width = 2;
        while width <= length {
            let stride = length / width;
            twiddles.extend((0..width / 2).map(|index| powers[index * stride]));
            width *= 2;
        }
        Self { twiddles }
    }
    // The unnormalized transform of natural-order values in place: each
    // stage's first butterfly has twiddle one.
    fn apply(&self, values: &mut [Element]) {
        let logarithm = values.len().ilog2();
        for index in 0..values.len() {
            let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let mut width = 2;
        while width <= values.len() {
            let stage = &self.twiddles[width / 2 - 1..width - 1];
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                let original = left[0];
                left[0] = plus(original, right[0]);
                right[0] = minus(original, right[0]);
                for ((lower, upper), twiddle) in left[1..]
                    .iter_mut()
                    .zip(right[1..].iter_mut())
                    .zip(&stage[1..])
                {
                    let product = scale(*upper, *twiddle);
                    let original = *lower;
                    *lower = plus(original, product);
                    *upper = minus(original, product);
                }
            }
            width *= 2;
        }
    }
    // The transform's outputs at the selected natural-order positions, each
    // written to its destination. The values are split into the even and odd
    // outputs' half-length inputs, and a half without selected outputs is
    // never computed.
    fn selected(
        &self,
        values: &mut [Element],
        selected: &[(usize, usize)],
        output: &mut [Element],
    ) {
        if selected.is_empty() {
            return;
        }
        if values.len() == 1 {
            for (_, destination) in selected {
                output[*destination] = values[0];
            }
            return;
        }
        let (mut even, mut odd) = (Vec::new(), Vec::new());
        for &(position, destination) in selected {
            if position & 1 == 0 {
                even.push((position / 2, destination));
            } else {
                odd.push((position / 2, destination));
            }
        }
        let stage = &self.twiddles[values.len() / 2 - 1..values.len() - 1];
        let (left, right) = values.split_at_mut(values.len() / 2);
        for ((lower, upper), twiddle) in left.iter_mut().zip(right.iter_mut()).zip(stage) {
            let original = *lower;
            if !even.is_empty() {
                *lower = plus(original, *upper);
            }
            if !odd.is_empty() {
                *upper = scale(minus(original, *upper), *twiddle);
            }
        }
        self.selected(left, &even, output);
        self.selected(right, &odd, output);
    }
}

pub(crate) fn validate_indices_in(indices: &[u32], domain_size: usize) -> Result<(), Error> {
    if indices.is_empty()
        || indices.len() > QUERY_LIMIT
        || indices.iter().any(|index| *index as usize >= domain_size)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::Parameters);
    }
    Ok(())
}

pub fn evaluate(values: Vec<Element>, indices: &[u32]) -> Result<Vec<Element>, Error> {
    evaluate_in(values, indices, SYSTEMATIC_SIZE)
}

pub(crate) fn evaluate_in(
    mut values: Vec<Element>,
    indices: &[u32],
    systematic_size: usize,
) -> Result<Vec<Element>, Error> {
    if !systematic_size.is_power_of_two() || !(2..=SYSTEMATIC_SIZE).contains(&systematic_size) {
        return Err(Error::Parameters);
    }
    let domain_size = 4 * systematic_size;
    validate_indices_in(indices, domain_size)?;
    let degree = values.len();
    if !degree.is_power_of_two() || degree < 2 || degree > systematic_size {
        return Err(Error::Parameters);
    }
    // The coefficients times the degree; each coset's twist powers carry the
    // inverse degree instead.
    Transform::new(degree, true).apply(&mut values);
    let transform = Transform::new(degree, false);
    let cosets = domain_size / degree;
    let mut groups = vec![Vec::new(); cosets];
    for (output, index) in indices.iter().enumerate() {
        groups[*index as usize % cosets].push((*index as usize / cosets, output));
    }
    let root = arithmetic::power(7, (MODULUS - 1) / domain_size as u128);
    let stride = systematic_size / degree;
    let inverse_stride = arithmetic::power(stride as u128, MODULUS - 2);
    let inverse_degree = arithmetic::power(degree as u128, MODULUS - 2);
    let mut scratch = vec![ZERO; degree];
    let mut output = vec![ZERO; indices.len()];
    for (coset, positions) in groups.iter().enumerate() {
        if positions.is_empty() {
            continue;
        }
        let twist = multiply(7, arithmetic::power(root, coset as u128));
        let mut current = inverse_degree;
        for (destination, coefficient) in scratch.iter_mut().zip(&values) {
            *destination = scale(*coefficient, current);
            current = multiply(current, twist);
        }
        // The auxiliary values occupy every stride-th systematic position.
        // The indicator interpolant is (1/stride) sum_j X^(degree*j).
        let high = arithmetic::power(twist, degree as u128);
        let mut term = 1;
        let mut indicator = 0;
        for _ in 0..stride {
            indicator = arithmetic::add(indicator, term);
            term = multiply(term, high);
        }
        indicator = multiply(indicator, inverse_stride);
        let mut computed = vec![ZERO; positions.len()];
        let local: Vec<_> = positions
            .iter()
            .enumerate()
            .map(|(order, (position, _))| (*position, order))
            .collect();
        transform.selected(&mut scratch, &local, &mut computed);
        for ((_, destination), value) in positions.iter().zip(computed) {
            output[*destination] = scale(value, indicator);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DOMAIN_SIZE: usize = 4 * SYSTEMATIC_SIZE;

    #[test]
    fn transforms_match_every_direct_fourier_coefficient() {
        for length in [2, 4, 8, 16, 32] {
            let original: Vec<Element> = (0..length)
                .map(|index| {
                    [
                        index as u128,
                        MODULUS - 1 - index as u128,
                        (index * index + 7) as u128,
                    ]
                })
                .collect();
            // The inverse transform is unnormalized.
            for inverse in [false, true] {
                let mut root = arithmetic::power(7, (MODULUS - 1) / length as u128);
                if inverse {
                    root = arithmetic::power(root, MODULUS - 2);
                }
                let expected: Vec<Element> = (0..length)
                    .map(|output| {
                        original
                            .iter()
                            .enumerate()
                            .fold(ZERO, |sum, (input, value)| {
                                plus(
                                    sum,
                                    scale(
                                        *value,
                                        arithmetic::power(root, (input * output) as u128),
                                    ),
                                )
                            })
                    })
                    .collect();
                let mut actual = original.clone();
                Transform::new(length, inverse).apply(&mut actual);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn query_values_match_direct_evaluation_of_the_masked_interpolant() {
        let systematic_size = 16;
        let domain_size = 4 * systematic_size;
        let domain_root = arithmetic::power(7, (MODULUS - 1) / domain_size as u128);
        for degree in [2, 4, 8, 16] {
            let values: Vec<Element> = (0..degree)
                .map(|index| {
                    [
                        (index * index + 3) as u128,
                        MODULUS - 1 - (index * 5) as u128,
                        1 << (index + 90),
                    ]
                })
                .collect();
            // The interpolant's coefficients by the inverse Fourier sum.
            let root = arithmetic::power(7, (MODULUS - 1) / degree as u128);
            let inverse_root = arithmetic::power(root, MODULUS - 2);
            let inverse_degree = arithmetic::power(degree as u128, MODULUS - 2);
            let coefficients: Vec<Element> = (0..degree)
                .map(|power| {
                    scale(
                        values.iter().enumerate().fold(ZERO, |sum, (index, value)| {
                            plus(
                                sum,
                                scale(
                                    *value,
                                    arithmetic::power(inverse_root, (index * power) as u128),
                                ),
                            )
                        }),
                        inverse_degree,
                    )
                })
                .collect();
            let stride = systematic_size / degree;
            let indices: Vec<u32> = (0..domain_size as u32).step_by(3).collect();
            let actual = evaluate_in(values.clone(), &indices, systematic_size).unwrap();
            for (index, value) in indices.iter().zip(actual) {
                let point = multiply(7, arithmetic::power(domain_root, u128::from(*index)));
                let interpolant = coefficients.iter().rev().fold(ZERO, |sum, coefficient| {
                    plus(scale(sum, point), *coefficient)
                });
                let indicator = (0..stride).fold(0, |sum, power| {
                    arithmetic::add(sum, arithmetic::power(point, (degree * power) as u128))
                });
                let indicator = multiply(indicator, arithmetic::power(stride as u128, MODULUS - 2));
                assert_eq!(value, scale(interpolant, indicator));
            }
        }
    }

    #[test]
    fn refuses_invalid_query_sets_before_transform_work() {
        for indices in [
            vec![],
            vec![0, 0],
            vec![1, 0],
            vec![DOMAIN_SIZE as u32],
            (0..=QUERY_LIMIT as u32).collect(),
        ] {
            assert_eq!(
                validate_indices_in(&indices, DOMAIN_SIZE),
                Err(Error::Parameters)
            );
        }
        assert_eq!(
            validate_indices_in(&[0, (DOMAIN_SIZE - 1) as u32], DOMAIN_SIZE),
            Ok(())
        );
    }
}
