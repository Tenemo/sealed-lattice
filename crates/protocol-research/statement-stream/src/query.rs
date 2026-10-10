use super::{Element, Error, MODULUS, ZERO, arithmetic, minus, multiply, plus};

pub const SYSTEMATIC_SIZE: usize = 65_536;
pub const QUERY_LIMIT: usize = 2 * 704;

fn scale(value: Element, scalar: u128) -> Element {
    value.map(|entry| multiply(entry, scalar))
}

struct SelectedQuery {
    coset: usize,
    position: usize,
    destination: usize,
}

// A transform of one length. Each stage's twiddles lie together: the stage
// of width w keeps the w/2 powers of a primitive w-th root at offset w/2 - 1.
struct Transform {
    twiddles: Vec<u128>,
}
impl Transform {
    fn new(length: usize) -> Self {
        let root = arithmetic::power(7, (MODULUS - 1) / length as u128);
        let mut twiddles = vec![1; length - 1];
        let widest = length / 2 - 1;
        for index in 1..length / 2 {
            twiddles[widest + index] = multiply(twiddles[widest + index - 1], root);
        }
        let mut width = 2;
        while width < length {
            let stride = length / width;
            for index in 0..width / 2 {
                twiddles[width / 2 - 1 + index] = twiddles[widest + index * stride];
            }
            width *= 2;
        }
        Self { twiddles }
    }
    // The unnormalized transform of natural-order values in place: each
    // stage's first butterfly has twiddle one.
    fn apply(&self, values: &mut [Element], inverse: bool) {
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
                let pairs = left[1..].iter_mut().zip(right[1..].iter_mut());
                if inverse {
                    // The inverse twiddle at i is the forward twiddle at
                    // width/2 - i negated, so its butterfly swaps signs.
                    for ((lower, upper), twiddle) in pairs.zip(stage[1..].iter().rev()) {
                        let product = scale(*upper, *twiddle);
                        let original = *lower;
                        *lower = minus(original, product);
                        *upper = plus(original, product);
                    }
                } else {
                    for ((lower, upper), twiddle) in pairs.zip(&stage[1..]) {
                        let product = scale(*upper, *twiddle);
                        let original = *lower;
                        *lower = plus(original, product);
                        *upper = minus(original, product);
                    }
                }
            }
            width *= 2;
        }
    }
    // The transform's outputs at the selected natural-order positions, each
    // written to its destination. Bit-reversed query order puts each even
    // and odd branch in one contiguous slice, so recursion needs no copied
    // query lists. A half without selected outputs is never computed.
    fn selected(
        &self,
        values: &mut [Element],
        selected: &[SelectedQuery],
        output: &mut [Element],
        bit: usize,
    ) {
        if selected.is_empty() {
            return;
        }
        if values.len() == 1 {
            for query in selected {
                output[query.destination] = values[0];
            }
            return;
        }
        let split = selected.partition_point(|query| query.position & (1 << bit) == 0);
        let (even, odd) = selected.split_at(split);
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
        self.selected(left, even, output, bit + 1);
        self.selected(right, odd, output, bit + 1);
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

/// The refusals of an evaluation of that many values at the indices.
pub(crate) fn check_in(
    degree: usize,
    indices: &[u32],
    systematic_size: usize,
) -> Result<(), Error> {
    if !systematic_size.is_power_of_two() || !(2..=SYSTEMATIC_SIZE).contains(&systematic_size) {
        return Err(Error::Parameters);
    }
    validate_indices_in(indices, 4 * systematic_size)?;
    if !degree.is_power_of_two() || degree < 2 || degree > systematic_size {
        return Err(Error::Parameters);
    }
    Ok(())
}

pub(crate) fn evaluate_in(
    mut values: Vec<Element>,
    indices: &[u32],
    systematic_size: usize,
) -> Result<Vec<Element>, Error> {
    check_in(values.len(), indices, systematic_size)?;
    let domain_size = 4 * systematic_size;
    let degree = values.len();
    let transform = Transform::new(degree);
    // The coefficients times the degree; each coset's twist powers carry the
    // inverse degree instead.
    transform.apply(&mut values, true);
    let cosets = domain_size / degree;
    let mut selected: Vec<_> = indices
        .iter()
        .enumerate()
        .map(|(destination, index)| SelectedQuery {
            coset: *index as usize % cosets,
            position: *index as usize / cosets,
            destination,
        })
        .collect();
    selected.sort_unstable_by_key(|query| (query.coset, query.position.reverse_bits()));
    let root = arithmetic::power(7, (MODULUS - 1) / domain_size as u128);
    let stride = systematic_size / degree;
    let inverse_stride = arithmetic::power(stride as u128, MODULUS - 2);
    let inverse_degree = arithmetic::power(degree as u128, MODULUS - 2);
    let mut scratch = vec![ZERO; degree];
    let mut output = vec![ZERO; indices.len()];
    for group in selected.chunk_by(|left, right| left.coset == right.coset) {
        let twist = multiply(7, arithmetic::power(root, group[0].coset as u128));
        let mut current = inverse_degree;
        for (destination, coefficient) in scratch.iter_mut().zip(&values) {
            *destination = scale(*coefficient, current);
            current = multiply(current, twist);
        }
        // The auxiliary values occupy every stride-th systematic position.
        // The indicator interpolant is (1/stride) sum_j X^(degree*j).
        let high = arithmetic::power(twist, degree as u128);
        // For a power-of-two stride, the geometric sum is the product
        // (1 + high) (1 + high^2) ... (1 + high^(stride/2)). This identity
        // also covers high equal to zero or one without an inversion.
        let mut term = high;
        let mut indicator = 1;
        let mut remaining = stride;
        while remaining > 1 {
            indicator = multiply(indicator, arithmetic::add(1, term));
            term = multiply(term, term);
            remaining /= 2;
        }
        indicator = multiply(indicator, inverse_stride);
        transform.selected(&mut scratch, group, &mut output, 0);
        for query in group {
            output[query.destination] = scale(output[query.destination], indicator);
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "query-tests.rs"]
mod tests;
