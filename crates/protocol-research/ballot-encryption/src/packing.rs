pub use supported_profile::DEGREE;
use supported_profile::{MAXIMUM_SCORE, MINIMUM_SCORE, PLAINTEXT_MODULUS, Profile, plaintext};

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
                let value = (value - baseline).rem_euclid(PLAINTEXT_MODULUS as i32);
                if value > (PLAINTEXT_MODULUS / 2) as i32 {
                    value - PLAINTEXT_MODULUS as i32
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
                assert_eq!(difference.rem_euclid(PLAINTEXT_MODULUS as i32), 0);
                i16::try_from(difference / PLAINTEXT_MODULUS as i32).expect(
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
                    (2 * (i32::from(*other) - i32::from(*score)))
                        .rem_euclid(PLAINTEXT_MODULUS as i32) as u32;
            }
        }
    }
    for (position, score) in scores.iter().enumerate() {
        slots[active + position] = u32::from(*score);
    }
    Ok(plaintext::encode_slots(&slots, degree))
}

#[cfg(test)]
#[path = "packing-tests.rs"]
mod tests;
