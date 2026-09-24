#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
pub mod base;
pub(crate) use base::MODULUS;
pub type Element = [u128; 3];
pub const ZERO: Element = [0, 0, 0];
pub const ONE: Element = [1, 0, 0];
pub fn add(left: Element, right: Element) -> Element {
    std::array::from_fn(|i| base::add(left[i], right[i]))
}
pub fn subtract(left: Element, right: Element) -> Element {
    std::array::from_fn(|i| base::subtract(left[i], right[i]))
}
pub fn scale(value: Element, scalar: u128) -> Element {
    value.map(|value| base::multiply(value, scalar))
}
pub fn multiply(left: Element, right: Element) -> Element {
    let mut result = ZERO;
    for (first, a) in left.iter().enumerate() {
        for (second, b) in right.iter().enumerate() {
            let mut value = base::multiply(*a, *b);
            if first + second >= 3 {
                value = base::add(value, value);
            }
            let index = (first + second) % 3;
            result[index] = base::add(result[index], value);
        }
    }
    result
}
pub fn inverse(value: Element) -> Element {
    assert_ne!(value, ZERO);
    let [a, b, c] = value;
    let numerator = [
        base::subtract(
            base::multiply(a, a),
            base::multiply(2, base::multiply(b, c)),
        ),
        base::subtract(
            base::multiply(2, base::multiply(c, c)),
            base::multiply(a, b),
        ),
        base::subtract(base::multiply(b, b), base::multiply(a, c)),
    ];
    let denominator = multiply(value, numerator);
    assert_eq!(denominator[1..], [0, 0]);
    assert_ne!(denominator[0], 0);
    scale(numerator, base::power(denominator[0], MODULUS - 2))
}
pub fn batch_inverse(values: &[Element]) -> Vec<Element> {
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = ONE;
    for value in values {
        assert_ne!(*value, ZERO);
        prefixes.push(product);
        product = multiply(product, *value);
    }
    let mut suffix = inverse(product);
    let mut result = vec![ZERO; values.len()];
    for index in (0..values.len()).rev() {
        result[index] = multiply(prefixes[index], suffix);
        suffix = multiply(suffix, values[index]);
    }
    result
}
pub fn root(length: usize) -> u128 {
    assert!(length.is_power_of_two() && (2..=1 << 20).contains(&length));
    base::power(7, (MODULUS - 1) / length as u128)
}
pub fn encode(value: Element) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (i, value) in value.iter().enumerate() {
        bytes[16 * i..16 * (i + 1)].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

pub struct Transform {
    pub length: usize,
    forward: Vec<u128>,
    backward: Vec<u128>,
    inverse_length: u128,
}

fn selected_forward<T: Copy>(
    values: &mut [T],
    selected: &[(usize, usize)],
    powers: &[u128],
    length: usize,
    output: &mut [T],
    operations: &(
        impl Fn(T, T) -> T,
        impl Fn(T, T) -> T,
        impl Fn(T, u128) -> T,
    ),
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
    let mut even = Vec::with_capacity(selected.len());
    let mut odd = Vec::with_capacity(selected.len());
    for &(index, destination) in selected {
        if index & 1 == 0 {
            even.push((index / 2, destination));
        } else {
            odd.push((index / 2, destination));
        }
    }
    let stride = length / values.len();
    let (left, right) = values.split_at_mut(values.len() / 2);
    for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
        let original = *lower;
        if !even.is_empty() {
            *lower = operations.0(original, *upper);
        }
        if !odd.is_empty() {
            *upper = operations.2(operations.1(original, *upper), powers[index * stride]);
        }
    }
    selected_forward(left, &even, powers, length, output, operations);
    selected_forward(right, &odd, powers, length, output, operations);
}

impl Transform {
    pub fn new(length: usize) -> Self {
        let root = root(length);
        let inverse = base::power(root, MODULUS - 2);
        let powers = |value| {
            let mut result = vec![1; length / 2];
            for index in 1..result.len() {
                result[index] = base::multiply(result[index - 1], value);
            }
            result
        };
        Self {
            length,
            forward: powers(root),
            backward: powers(inverse),
            inverse_length: base::power(length as u128, MODULUS - 2),
        }
    }
    pub fn base(&self, values: &mut [u128], inverse: bool) {
        assert_eq!(values.len(), self.length);
        let log = self.length.ilog2();
        for index in 0..self.length {
            let reversed = index.reverse_bits() >> (usize::BITS - log);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let twiddles = if inverse {
            &self.backward
        } else {
            &self.forward
        };
        let mut width = 2;
        while width <= self.length {
            let stride = self.length / width;
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
                    let value = base::multiply(*upper, twiddles[index * stride]);
                    let old = *lower;
                    *lower = base::add(old, value);
                    *upper = base::subtract(old, value);
                }
            }
            width *= 2;
        }
        if inverse {
            for value in values {
                *value = base::multiply(*value, self.inverse_length);
            }
        }
    }
    pub fn selected_base(&self, values: &mut [u128], indices: &[usize]) -> Vec<u128> {
        assert_eq!(values.len(), self.length);
        assert!(indices.iter().all(|index| *index < self.length));
        let selected = indices
            .iter()
            .copied()
            .enumerate()
            .map(|(position, index)| (index, position))
            .collect::<Vec<_>>();
        let mut output = vec![0; indices.len()];
        selected_forward(
            values,
            &selected,
            &self.forward,
            self.length,
            &mut output,
            &(base::add, base::subtract, base::multiply),
        );
        output
    }
    pub fn selected_extension(&self, values: &mut [Element], indices: &[usize]) -> Vec<Element> {
        assert_eq!(values.len(), self.length);
        assert!(indices.iter().all(|index| *index < self.length));
        let selected = indices
            .iter()
            .copied()
            .enumerate()
            .map(|(position, index)| (index, position))
            .collect::<Vec<_>>();
        let mut output = vec![ZERO; indices.len()];
        selected_forward(
            values,
            &selected,
            &self.forward,
            self.length,
            &mut output,
            &(add, subtract, scale),
        );
        output
    }
    pub fn extension(&self, values: &mut [Element], inverse: bool) {
        assert_eq!(values.len(), self.length);
        let log = self.length.ilog2();
        for index in 0..self.length {
            let reversed = index.reverse_bits() >> (usize::BITS - log);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
        let twiddles = if inverse {
            &self.backward
        } else {
            &self.forward
        };
        let mut width = 2;
        while width <= self.length {
            let stride = self.length / width;
            for block in values.chunks_exact_mut(width) {
                let (left, right) = block.split_at_mut(width / 2);
                for (index, (lower, upper)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
                    let value = scale(*upper, twiddles[index * stride]);
                    let old = *lower;
                    *lower = add(old, value);
                    *upper = subtract(old, value);
                }
            }
            width *= 2;
        }
        if inverse {
            for value in values {
                *value = scale(*value, self.inverse_length);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_outputs_match_direct_evaluation_for_every_small_subset() {
        for length in [2, 4, 8] {
            let transform = Transform::new(length);
            let source: Vec<_> = (0..length)
                .map(|index| {
                    [
                        index as u128,
                        MODULUS - 1 - index as u128,
                        (index * index + 17) as u128,
                    ]
                })
                .collect();
            for mask in 0..1usize << length {
                let indices: Vec<_> = (0..length)
                    .filter(|index| mask & (1 << index) != 0)
                    .collect();
                let expected: Vec<_> = indices
                    .iter()
                    .map(|point| {
                        source.iter().enumerate().fold(ZERO, |sum, (index, value)| {
                            add(
                                sum,
                                scale(*value, base::power(root(length), (index * point) as u128)),
                            )
                        })
                    })
                    .collect();
                assert_eq!(
                    transform.selected_extension(&mut source.clone(), &indices),
                    expected
                );
                let mut base_values: Vec<_> = source.iter().map(|value| value[0]).collect();
                assert_eq!(
                    transform.selected_base(&mut base_values, &indices),
                    expected.iter().map(|value| value[0]).collect::<Vec<_>>()
                );
            }
            let indices = [length - 1, 0, length - 1];
            let mut complete = source.clone();
            transform.extension(&mut complete, false);
            assert_eq!(
                transform.selected_extension(&mut source.clone(), &indices),
                indices
                    .iter()
                    .map(|index| complete[*index])
                    .collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn invalid_selection_leaves_input_untouched() {
        let transform = Transform::new(8);
        let mut data = vec![ONE; 8];
        let original = data.clone();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || transform.selected_extension(&mut data, &[8])
            ))
            .is_err()
        );
        assert_eq!(data, original);
    }
    #[test]
    fn inverse_and_batch_products_are_exact() {
        let values = [
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [17, 37, 91],
            [MODULUS - 1, MODULUS - 2, MODULUS - 3],
        ];
        for (value, inverted) in values.iter().zip(batch_inverse(&values)) {
            assert_eq!(multiply(*value, inverted), ONE);
            assert_eq!(inverted, inverse(*value));
        }
    }
    #[test]
    fn transforms_match_direct_fourier_values() {
        for n in [2, 4, 8, 16] {
            let data: Vec<Element> = (0..n)
                .map(|i| [i as u128, MODULUS - 1 - i as u128, (i * i + 7) as u128])
                .collect();
            let expected: Vec<Element> = (0..n)
                .map(|j| {
                    data.iter().enumerate().fold(ZERO, |sum, (i, value)| {
                        add(sum, scale(*value, base::power(root(n), (i * j) as u128)))
                    })
                })
                .collect();
            let transform = Transform::new(n);
            let mut actual = data.clone();
            transform.extension(&mut actual, false);
            assert_eq!(actual, expected);
            transform.extension(&mut actual, true);
            assert_eq!(actual, data);
            let mut first: Vec<u128> = data.iter().map(|x| x[0]).collect();
            transform.base(&mut first, false);
            assert_eq!(first, expected.iter().map(|x| x[0]).collect::<Vec<_>>());
        }
    }
}
