use crate::{DEGREE, KEY_ERROR_BITS, RECOVERY_ERROR_BITS, SELECTED, SUPPORT, WORD_BITS};
use supported_profile::relation::{Relation, SYSTEMATIC};

pub const STRIDE: usize = SYSTEMATIC / DEGREE;
pub fn widths() -> Vec<usize> {
    let mut widths = vec![WORD_BITS, WORD_BITS, KEY_ERROR_BITS];
    for _ in 0..SELECTED {
        widths.extend([WORD_BITS, WORD_BITS, RECOVERY_ERROR_BITS]);
    }
    widths
}
pub struct Layout {
    pub relation: Relation,
    pub signed: Vec<Vec<(usize, u128)>>,
    pub widths: Vec<usize>,
}
impl Layout {
    pub fn new(statement_bytes: usize) -> Self {
        let widths = widths();
        let words = widths.iter().map(|bits| (bits / WORD_BITS).max(1)).sum();
        let mut boolean = words + 2;
        let mut word = 0;
        let mut signed = Vec::new();
        let mut narrow = Vec::new();
        for &bits in &widths {
            let whole = (bits / WORD_BITS).max(1);
            let mut digits = Vec::new();
            for index in 0..whole {
                digits.push((word, 1u128 << (WORD_BITS * index)));
                word += 1;
            }
            if bits < WORD_BITS {
                narrow.push((word - 1, 1 << (WORD_BITS - bits)));
            } else {
                for bit in 0..bits % WORD_BITS {
                    digits.push((boolean, 1u128 << (WORD_BITS * whole + bit)));
                    boolean += 1;
                }
            }
            signed.push(digits);
        }
        let mut relation = Relation {
            tag: b"bounded-opening-share/1",
            proof_magic: b"OPP1",
            words,
            booleans: boolean - words,
            narrow,
            zero_product_pairs: vec![(words, words + 1)],
            supports: vec![(STRIDE, (SUPPORT / 2) as u64)],
            message_bytes: 0,
            statement_bytes,
            parameters: vec![DEGREE, SELECTED, SUPPORT],
        };
        relation.parameters.extend(&widths);
        relation.message_bytes = relation.minimum_message_bytes();
        Self {
            relation,
            signed,
            widths,
        }
    }
}
