pub use supported_profile::DEGREE;
use supported_profile::{MAXIMUM_SCORE, MINIMUM_SCORE, PLAINTEXT_MODULUS as MODULUS, Profile};

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Options,
    Scores,
    Capacity,
}

pub struct PackingMatrix {
    options: usize,
    baseline: Vec<i32>,
}
impl PackingMatrix {
    pub fn new(options: usize) -> Result<Self, Refusal> {
        if !Profile::option_range().contains(&options) {
            return Err(Refusal::Options);
        }
        let baseline = encode(&vec![1; options])?;
        Ok(Self { options, baseline })
    }
    pub fn column(&self, selected: usize) -> Result<Vec<i32>, Refusal> {
        if selected >= self.options {
            return Err(Refusal::Options);
        }
        let mut scores = vec![1; self.options];
        scores[selected] = 2;
        let shifted = encode(&scores)?;
        Ok(shifted
            .into_iter()
            .zip(&self.baseline)
            .map(|(value, baseline)| {
                let value = (value - baseline).rem_euclid(MODULUS as i32);
                if value > (MODULUS / 2) as i32 {
                    value - MODULUS as i32
                } else {
                    value
                }
            })
            .collect())
    }
}

pub struct PackingWitness {
    scores: zeroize::Zeroizing<Vec<u8>>,
    message: zeroize::Zeroizing<Vec<i32>>,
    quotients: zeroize::Zeroizing<Vec<i16>>,
}
impl PackingWitness {
    pub fn new(scores: &[u8]) -> Result<Self, Refusal> {
        let message = zeroize::Zeroizing::new(encode(scores)?);
        let matrix = PackingMatrix::new(scores.len())?;
        let mut integer_message = zeroize::Zeroizing::new(vec![0i32; DEGREE]);
        for (option, score) in scores.iter().enumerate() {
            for (sum, coefficient) in integer_message.iter_mut().zip(matrix.column(option)?) {
                *sum += coefficient * i32::from(*score);
            }
        }
        let quotients = message
            .iter()
            .zip(integer_message.iter())
            .map(|(canonical, integer)| {
                let difference = canonical - integer;
                assert_eq!(difference.rem_euclid(MODULUS as i32), 0);
                i16::try_from(difference / MODULUS as i32).expect(
                    "The supported score and option bounds fit the signed packing quotient.",
                )
            })
            .collect();
        Ok(Self {
            scores: zeroize::Zeroizing::new(scores.to_vec()),
            message,
            quotients: zeroize::Zeroizing::new(quotients),
        })
    }
    pub fn message(&self) -> &[i32] {
        &self.message
    }
    pub fn scores(&self) -> &[u8] {
        &self.scores
    }
    pub fn quotients(&self) -> &[i16] {
        &self.quotients
    }
}

fn multiply(left: u32, right: u32) -> u32 {
    ((u64::from(left) * u64::from(right)) % u64::from(MODULUS)) as u32
}
fn power(mut value: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}
fn inverse_transform(values: &mut [u32], root: u32) {
    let length = values.len();
    let logarithm = length.ilog2();
    for index in 0..length {
        let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let inverse_root = power(root, MODULUS - 2);
    let mut width = 2;
    while width <= length {
        let step = power(inverse_root, (length / width) as u32);
        for block in values.chunks_exact_mut(width) {
            let (left, right) = block.split_at_mut(width / 2);
            let mut twiddle = 1;
            for (left, right) in left.iter_mut().zip(right) {
                let first = *left;
                let second = multiply(*right, twiddle);
                *left = (first + second) % MODULUS;
                *right = (first + MODULUS - second) % MODULUS;
                twiddle = multiply(twiddle, step);
            }
        }
        width *= 2;
    }
    let inverse_length = power(length as u32, MODULUS - 2);
    for value in values {
        *value = multiply(*value, inverse_length);
    }
}

/// The two comparison-orbit halves are distinct. Only the selected orbit is
/// populated; the other half and every odd coefficient remain zero.
///
/// Every option has one comparison window for every rank, whatever result
/// length the poll requests. The evaluator selects the requested ranks, so the
/// ballot layout never depends on the result length.
pub fn encode(scores: &[u8]) -> Result<Vec<i32>, Refusal> {
    encode_with_degree(scores, DEGREE)
}
/// Refuses option counts and scores outside the supported packing domain.
pub fn check_scores(scores: &[u8]) -> Result<(), Refusal> {
    if !Profile::option_range().contains(&scores.len()) {
        return Err(Refusal::Options);
    }
    if scores
        .iter()
        .any(|score| !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(&usize::from(*score)))
    {
        return Err(Refusal::Scores);
    }
    Ok(())
}
fn encode_with_degree(scores: &[u8], degree: usize) -> Result<Vec<i32>, Refusal> {
    check_scores(scores)?;
    if !degree.is_power_of_two() || !(16..=DEGREE).contains(&degree) {
        return Err(Refusal::Capacity);
    }
    let ranks = scores.len();
    let window = scores.len().next_power_of_two();
    let active = scores.len() * ranks * window;
    if active + scores.len() >= degree / 4 {
        return Err(Refusal::Capacity);
    }
    let mut slots = vec![0u32; degree / 4];
    for (option, score) in scores.iter().enumerate() {
        for rank in 0..ranks {
            for (opponent, other) in scores.iter().enumerate() {
                slots[(option * ranks + rank) * window + opponent] =
                    (2 * (i32::from(*other) - i32::from(*score))).rem_euclid(MODULUS as i32) as u32;
            }
        }
    }
    for (position, score) in scores.iter().enumerate() {
        slots[active + position] = u32::from(*score);
    }
    let root = power(3, (MODULUS - 1) / degree as u32);
    let mut natural = vec![0; degree / 2];
    let mut exponent = 1;
    for value in slots {
        natural[(exponent - 1) / 2] = value;
        exponent = 5 * exponent % degree;
    }
    inverse_transform(&mut natural, multiply(root, root));
    let inverse_root = power(root, MODULUS - 2);
    let mut twist = 1;
    let mut coefficients = vec![0; degree];
    for (position, value) in natural.into_iter().enumerate() {
        let value = multiply(value, twist);
        coefficients[2 * position] = if value > MODULUS / 2 {
            value as i32 - MODULUS as i32
        } else {
            value as i32
        };
        twist = multiply(twist, inverse_root);
    }
    Ok(coefficients)
}

#[cfg(test)]
#[path = "packing-tests.rs"]
mod tests;
