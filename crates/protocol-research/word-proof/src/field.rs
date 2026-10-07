pub use base::MODULUS;
pub use setup_stream_kernel::arithmetic as base;
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
    base::multiply_extension(left, right)
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
/// The element of 48 encoded bytes, which the encoder produced.
pub fn decode(bytes: &[u8]) -> Element {
    std::array::from_fn(|i| u128::from_le_bytes(bytes[16 * i..16 * (i + 1)].try_into().unwrap()))
}

pub struct Transform {
    pub length: usize,
    // Each stage's twiddles lie together: the stage of width w keeps the w/2
    // powers of a primitive w-th root at offset w/2 - 1. The inverse
    // transform reads them too, since the inverse root's power j is the
    // root's power w/2 - j negated.
    twiddles: Vec<u128>,
    inverse_length: u128,
}

// The stage twiddles of a transform of the given length and root. The
// widest stage's are the root's powers, of which each narrower stage's are
// every stride-th.
fn stage_twiddles(root: u128, length: usize) -> Vec<u128> {
    let mut twiddles = vec![1; length - 1];
    let widest = length / 2 - 1;
    for index in 1..length / 2 {
        twiddles[widest + index] = base::multiply(twiddles[widest + index - 1], root);
    }
    let mut width = 2;
    while width < length {
        let stride = length / width;
        for index in 0..width / 2 {
            twiddles[width / 2 - 1 + index] = twiddles[widest + index * stride];
        }
        width *= 2;
    }
    twiddles
}

// An in-place iterative transform of bit-reversed values: each stage's
// first butterfly has twiddle one, and the width-two stage has no other.
// The inverse takes a stage's forward twiddles in reverse order, each the
// negated inverse twiddle, so its butterflies exchange sum and difference.
// A stage beyond the tables multiplies each twiddle by the stage's root, or
// that root's inverse, to reach the next, which gives the powers its table
// would hold.
fn butterflies<T: Copy>(
    values: &mut [T],
    twiddles: &[u128],
    inverse: bool,
    add: impl Fn(T, T) -> T,
    subtract: impl Fn(T, T) -> T,
    scale: impl Fn(T, u128) -> T,
) {
    let log = values.len().ilog2();
    for index in 0..values.len() {
        let reversed = index.reverse_bits() >> (usize::BITS - log);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let butterfly = |lower: &mut T, upper: &mut T, twiddle: u128| {
        let value = scale(*upper, twiddle);
        let old = *lower;
        *lower = add(old, value);
        *upper = subtract(old, value);
    };
    let mut width = 2;
    while width <= values.len() {
        let stage = twiddles.get(width / 2 - 1..width - 1);
        let root = if stage.is_none() {
            Transform::stage_root(width, inverse)
        } else {
            1
        };
        for block in values.chunks_exact_mut(width) {
            let (left, right) = block.split_at_mut(width / 2);
            let (lower, upper) = (left[0], right[0]);
            left[0] = add(lower, upper);
            right[0] = subtract(lower, upper);
            let pairs = left[1..].iter_mut().zip(right[1..].iter_mut());
            match stage {
                Some(stage) if inverse => {
                    for ((lower, upper), twiddle) in pairs.zip(stage[1..].iter().rev()) {
                        let value = scale(*upper, *twiddle);
                        let old = *lower;
                        *lower = subtract(old, value);
                        *upper = add(old, value);
                    }
                }
                Some(stage) => {
                    for ((lower, upper), twiddle) in pairs.zip(&stage[1..]) {
                        butterfly(lower, upper, *twiddle);
                    }
                }
                None => {
                    let mut twiddle = 1;
                    for (lower, upper) in pairs {
                        twiddle = base::multiply(twiddle, root);
                        butterfly(lower, upper, twiddle);
                    }
                }
            }
        }
        width *= 2;
    }
}

fn selected_forward<T: Copy>(
    values: &mut [T],
    selected: &[(usize, usize)],
    twiddles: &[u128],
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
    let stage = &twiddles[values.len() / 2 - 1..values.len() - 1];
    let (left, right) = values.split_at_mut(values.len() / 2);
    for ((lower, upper), twiddle) in left.iter_mut().zip(right.iter_mut()).zip(stage) {
        let original = *lower;
        if !even.is_empty() {
            *lower = operations.0(original, *upper);
        }
        if !odd.is_empty() {
            *upper = operations.2(operations.1(original, *upper), *twiddle);
        }
    }
    selected_forward(left, &even, twiddles, output, operations);
    selected_forward(right, &odd, twiddles, output, operations);
}

impl Transform {
    /// The transform of a length, built once and kept.
    pub fn cached(length: usize) -> &'static Self {
        static TRANSFORMS: [std::sync::OnceLock<Transform>; 21] =
            [const { std::sync::OnceLock::new() }; 21];
        assert!(length.is_power_of_two());
        TRANSFORMS[length.ilog2() as usize].get_or_init(|| Self::new(length))
    }
    pub fn new(length: usize) -> Self {
        Self {
            length,
            twiddles: stage_twiddles(root(length), length),
            inverse_length: base::power(length as u128, MODULUS - 2),
        }
    }
    // The stage twiddles of a transform of the length that the tables hold:
    // those of every stage up to the tables' length, which begin those of
    // every longer transform, since each stage's twiddles are powers of its
    // own width's root.
    fn stages(&self, length: usize) -> &[u128] {
        assert!(length.is_power_of_two() && length >= 2);
        &self.twiddles[..length.min(self.length) - 1]
    }
    // A stage's primitive root of its width, or that root's inverse.
    fn stage_root(width: usize, inverse: bool) -> u128 {
        let root = root(width);
        if inverse {
            base::power(root, MODULUS - 2)
        } else {
            root
        }
    }
    fn inverse_length(&self, length: usize) -> u128 {
        if length == self.length {
            self.inverse_length
        } else {
            base::power(length as u128, MODULUS - 2)
        }
    }
    /// Transforms base values of any power-of-two length from the
    /// transform's tables.
    pub fn base(&self, values: &mut [u128], inverse: bool) {
        let twiddles = self.stages(values.len());
        butterflies(
            values,
            twiddles,
            inverse,
            base::add,
            base::subtract,
            base::multiply,
        );
        if inverse {
            let inverse_length = self.inverse_length(values.len());
            for value in values {
                *value = base::multiply(*value, inverse_length);
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
            &self.twiddles,
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
            &self.twiddles,
            &mut output,
            &(add, subtract, scale),
        );
        output
    }
    /// Transforms extension values of any power-of-two length from the
    /// transform's tables.
    pub fn extension(&self, values: &mut [Element], inverse: bool) {
        let twiddles = self.stages(values.len());
        butterflies(values, twiddles, inverse, add, subtract, scale);
        if inverse {
            let inverse_length = self.inverse_length(values.len());
            for value in values {
                *value = scale(*value, inverse_length);
            }
        }
    }
}

#[cfg(test)]
#[path = "field-tests.rs"]
mod tests;
