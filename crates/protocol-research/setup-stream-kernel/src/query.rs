use super::{Element, Error, MODULUS, ZERO, arithmetic, minus, multiply, plus};

pub const SYSTEMATIC_SIZE: usize = 65_536;
pub const DOMAIN_SIZE: usize = 4 * SYSTEMATIC_SIZE;
pub const QUERY_LIMIT: usize = 2 * 704;

fn scale(value: Element, scalar: u128) -> Element {
    value.map(|entry| multiply(entry, scalar))
}

struct Transform {
    twiddles: Vec<u128>,
    inverse: bool,
}
impl Transform {
    fn new(length: usize, inverse: bool) -> Self {
        let mut root = arithmetic::power(7, (MODULUS - 1) / length as u128);
        if inverse {
            root = arithmetic::power(root, MODULUS - 2);
        }
        let mut twiddles = vec![1; length / 2];
        for index in 1..twiddles.len() {
            twiddles[index] = multiply(twiddles[index - 1], root);
        }
        Self { twiddles, inverse }
    }
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
            let stride = values.len() / width;
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
                    let product = scale(*upper, self.twiddles[index * stride]);
                    let original = *lower;
                    *lower = plus(original, product);
                    *upper = minus(original, product);
                }
            }
            width *= 2;
        }
        if self.inverse {
            let factor = arithmetic::power(values.len() as u128, MODULUS - 2);
            for value in values {
                *value = scale(*value, factor);
            }
        }
    }
}

pub fn validate_indices(indices: &[u32]) -> Result<(), Error> {
    validate_indices_in(indices, DOMAIN_SIZE)
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
    Transform::new(degree, true).apply(&mut values);
    let transform = Transform::new(degree, false);
    let cosets = domain_size / degree;
    let mut groups = vec![Vec::new(); cosets];
    for (output, index) in indices.iter().enumerate() {
        groups[*index as usize % cosets].push((output, *index as usize / cosets));
    }
    let root = arithmetic::power(7, (MODULUS - 1) / domain_size as u128);
    let stride = systematic_size / degree;
    let inverse_stride = arithmetic::power(stride as u128, MODULUS - 2);
    let mut scratch = vec![ZERO; degree];
    let mut output = vec![ZERO; indices.len()];
    for (coset, positions) in groups.iter().enumerate() {
        if positions.is_empty() {
            continue;
        }
        let twist = multiply(7, arithmetic::power(root, coset as u128));
        let mut current = 1;
        for (destination, coefficient) in scratch.iter_mut().zip(&values) {
            *destination = scale(*coefficient, current);
            current = multiply(current, twist);
        }
        // The auxiliary values occupy every stride-th systematic position.
        // The indicator interpolant is (1/stride) sum_j X^(degree*j).
        let mut term = 1;
        let mut indicator = 0;
        for _ in 0..stride {
            indicator = arithmetic::add(indicator, term);
            term = multiply(term, current);
        }
        indicator = multiply(indicator, inverse_stride);
        transform.apply(&mut scratch);
        for (output_index, position) in positions {
            output[*output_index] = scale(scratch[*position], indicator);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            for inverse in [false, true] {
                let mut root = arithmetic::power(7, (MODULUS - 1) / length as u128);
                let normalization = if inverse {
                    root = arithmetic::power(root, MODULUS - 2);
                    arithmetic::power(length as u128, MODULUS - 2)
                } else {
                    1
                };
                let expected: Vec<Element> = (0..length)
                    .map(|output| {
                        scale(
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
                                }),
                            normalization,
                        )
                    })
                    .collect();
                let mut actual = original.clone();
                Transform::new(length, inverse).apply(&mut actual);
                assert_eq!(actual, expected);
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
            assert_eq!(validate_indices(&indices), Err(Error::Parameters));
        }
        assert_eq!(validate_indices(&[0, (DOMAIN_SIZE - 1) as u32]), Ok(()));
    }
}
