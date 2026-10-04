use crate::{DEGREE, RECIPIENTS, SEED_BITS, SUPPORT, profile};
use supported_profile::relation::{Relation, SYSTEMATIC};

pub const STRIDE: usize = SYSTEMATIC / DEGREE;

/// Signed variables: the one nonconstant sharing coefficient's low/high
/// parts, then each recipient's two quotient/carry/error triples.
pub fn widths() -> Vec<usize> {
    let profile = profile();
    let mut result = vec![
        profile.share_limb_bits(),
        profile.sharing_coefficient_bits() - profile.share_limb_bits(),
    ];
    for _ in 0..RECIPIENTS {
        result.extend([16, profile.share_carry_bits(), 7, 16, 16, 7]);
    }
    result
}
pub fn variable(recipient: usize, component: usize, offset: usize) -> usize {
    2 + 6 * recipient + 3 * component + offset
}

pub struct Layout {
    pub relation: Relation,
    pub signed: Vec<Vec<(usize, u128)>>,
    pub widths: Vec<usize>,
    pub seed: usize,
}
impl Layout {
    pub fn new(statement_bytes: usize) -> Self {
        let widths = widths();
        let words: usize = widths.iter().map(|bits| (bits / 16).max(1)).sum();
        let seed = words + 2 * RECIPIENTS;
        let mut boolean = seed + 1;
        let mut word = 0;
        let mut signed = Vec::new();
        let mut narrow = Vec::new();
        for &bits in &widths {
            let whole = (bits / 16).max(1);
            let mut digits = Vec::new();
            for index in 0..whole {
                digits.push((word, 1u128 << (16 * index)));
                word += 1;
            }
            if bits < 16 {
                narrow.push((word - 1, 1 << (16 - bits)));
            } else {
                for bit in 0..bits % 16 {
                    digits.push((boolean, 1u128 << (16 * whole + bit)));
                    boolean += 1;
                }
            }
            signed.push(digits);
        }
        let mut relation = Relation {
            tag: b"bounded-outer-seed-sharing/1",
            proof_magic: b"OSP1",
            words,
            booleans: boolean - words,
            narrow,
            zero_product_pairs: (0..RECIPIENTS)
                .map(|recipient| (words + 2 * recipient, words + 2 * recipient + 1))
                .collect(),
            supports: vec![(STRIDE, (SUPPORT / 2) as u64); RECIPIENTS],
            message_bytes: 0,
            statement_bytes,
            parameters: vec![DEGREE, RECIPIENTS, SEED_BITS, SUPPORT],
        };
        relation.parameters.extend(&widths);
        relation.message_bytes = relation.minimum_message_bytes();
        Self {
            relation,
            signed,
            widths,
            seed,
        }
    }
}
