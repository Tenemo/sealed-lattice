use super::DEGREE;
use supported_profile::{
    PLAINTEXT_MODULUS, Profile,
    plaintext::{ACTIVE_SLOTS, centered, encode_slots, multiply, power},
};

fn interpolate(points: &[u32], values: &[u32]) -> Vec<u32> {
    let mut differences = values.to_vec();
    for order in 1..points.len() {
        for index in (order..points.len()).rev() {
            let numerator = (differences[index] + PLAINTEXT_MODULUS - differences[index - 1])
                % PLAINTEXT_MODULUS;
            let denominator =
                (points[index] + PLAINTEXT_MODULUS - points[index - order]) % PLAINTEXT_MODULUS;
            assert_ne!(denominator, 0);
            differences[index] = multiply(numerator, power(denominator, PLAINTEXT_MODULUS - 2));
        }
    }
    let mut polynomial = vec![*differences.last().unwrap()];
    for index in (0..points.len() - 1).rev() {
        let mut next = vec![0; polynomial.len() + 1];
        for (degree, coefficient) in polynomial.into_iter().enumerate() {
            next[degree] = (next[degree] + PLAINTEXT_MODULUS
                - multiply(coefficient, points[index]))
                % PLAINTEXT_MODULUS;
            next[degree + 1] = (next[degree + 1] + coefficient) % PLAINTEXT_MODULUS;
        }
        next[0] = (next[0] + differences[index]) % PLAINTEXT_MODULUS;
        polynomial = next;
    }
    polynomial
}

pub(super) fn encode(slots: &[u32]) -> Vec<i32> {
    encode_slots(slots, DEGREE)
}

/// The comparison polynomial's coefficients, each rank-equality power's
/// weights at the requested ranks' slots and the comparison input offset.
///
/// The comparison polynomial is one on every odd point of the profile's
/// comparison degree above zero and zero below it. Slot
/// `option * window + opponent` compares the option with the opponent,
/// and the offset breaks ties toward the lower position.
pub fn parameters(profile: Profile, top_count: usize) -> (Vec<i32>, Vec<Vec<i32>>, Vec<i32>) {
    let options = profile.options();
    let window = profile.rank_window();
    assert!((1..=options).contains(&top_count));
    let maximum = profile.comparison_degree() as i32;
    let points: Vec<_> = (0..=maximum)
        .map(|index| (2 * index - maximum).rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
        .collect();
    let values: Vec<_> = (0..=maximum)
        .map(|index| u32::from(2 * index > maximum))
        .collect();
    let comparison = interpolate(&points, &values);
    assert_eq!(comparison[0], power(2, PLAINTEXT_MODULUS - 2));
    assert!(
        comparison
            .iter()
            .enumerate()
            .all(|(index, value)| index == 0 || index % 2 == 1 || *value == 0)
    );
    let ranks: Vec<_> = (0..options as u32).collect();
    let equality: Vec<_> = (0..options as u32)
        .map(|requested| {
            interpolate(
                &ranks,
                &ranks
                    .iter()
                    .map(|rank| u32::from(*rank == requested))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let ranking = (0..options)
        .map(|exponent| {
            let mut slots = vec![0; ACTIVE_SLOTS];
            for (position, value) in slots.iter_mut().enumerate() {
                let rank = (window - position % window) % window;
                if rank < top_count {
                    *value = equality[rank][exponent];
                }
            }
            encode(&slots)
        })
        .collect();
    let mut offset = vec![PLAINTEXT_MODULUS - 1; ACTIVE_SLOTS];
    for option in 0..options {
        for opponent in 0..option {
            offset[option * window + opponent] = 1;
        }
    }
    (
        comparison.into_iter().map(centered).collect(),
        ranking,
        encode(&offset),
    )
}

/// Keeps exactly the base of each comparison window and removes the entire
/// literal-score orbit before broadcasting the ranks.
pub fn rank_mask(profile: Profile) -> Vec<i32> {
    encode(
        &(0..ACTIVE_SLOTS)
            .map(|position| u32::from(position.is_multiple_of(profile.rank_window())))
            .collect::<Vec<_>>(),
    )
}

/// Removes the rank-zero constant contributed by the unused option windows.
pub fn padding_correction(profile: Profile) -> Vec<i32> {
    encode(
        &(0..ACTIVE_SLOTS)
            .map(|position| {
                if position.is_multiple_of(profile.rank_window())
                    && position / profile.rank_window() >= profile.options()
                {
                    PLAINTEXT_MODULUS - 1
                } else {
                    0
                }
            })
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
#[path = "ranking-plaintext-tests.rs"]
mod tests;
