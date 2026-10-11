use crate::{
    field::{self, Element, Transform, base},
    transcript::{Transcript, challenge},
    tree::Tree,
};
use supported_profile::relation::*;
use zeroize::{Zeroize, Zeroizing};

pub struct Layer {
    pub tree: Tree,
    pub values: Vec<Element>,
}
impl Drop for Layer {
    fn drop(&mut self) {
        self.values.zeroize();
    }
}
impl Layer {
    /// The layer's encoded values at the leaves.
    pub fn rows(&self, leaves: &[usize]) -> Vec<[u8; 48]> {
        leaves
            .iter()
            .map(|index| field::encode(self.values[*index]))
            .collect()
    }
}
pub struct Fri {
    pub layers: Vec<Layer>,
    pub terminal: Element,
    pub queries: Vec<usize>,
}
pub fn requested(queries: &[usize], length: usize) -> Vec<usize> {
    let mut output: Vec<usize> = queries
        .iter()
        .flat_map(|query| {
            let index = query % (length / 2);
            [index, index + length / 2]
        })
        .collect();
    output.sort_unstable();
    output.dedup();
    output
}
impl Fri {
    /// The first fold challenge follows the relation's combination
    /// challenges, two for each of its oracles.
    pub fn create(
        role: &[u8],
        oracles: usize,
        coefficients: Vec<Element>,
        transcript: &mut Transcript,
    ) -> Self {
        let mut coefficients = Zeroizing::new(coefficients);
        assert_eq!(coefficients.len(), MAXIMUM_DEGREE + 1);
        let mut length = EVALUATION_DOMAIN_SIZE;
        let mut coset = 7;
        let mut layers = Vec::new();
        let rounds = (EVALUATION_DOMAIN_SIZE / 2).ilog2() as usize;
        for round in 0..rounds {
            if round > 0 {
                transcript.next();
            }
            let scalar = challenge(
                &transcript.message,
                if round == 0 { 2 * oracles } else { 0 },
                false,
            );
            for index in 0..coefficients.len() / 2 {
                coefficients[index] = field::add(
                    coefficients[2 * index],
                    field::multiply(scalar, coefficients[2 * index + 1]),
                );
            }
            let folded = coefficients.len() / 2;
            coefficients.truncate(folded);
            length /= 2;
            coset = base::multiply(coset, coset);
            if length == 2 {
                assert_eq!(coefficients.len(), 1);
                transcript.respond(&[&field::encode(coefficients[0])]);
            } else {
                let mut values = Zeroizing::new(vec![field::ZERO; length]);
                let mut power = 1;
                for (destination, coefficient) in values.iter_mut().zip(coefficients.iter()) {
                    *destination = field::scale(*coefficient, power);
                    power = base::multiply(power, coset);
                }
                Transform::cached(SYSTEMATIC).extension(&mut values, false);
                let mut tree = Tree::new(role, 3 + round, length, 48);
                // Openings read the layer's values again.
                tree.forget_leaves();
                tree.hash_rows(|index, rows| rows.extend(field::encode(values[index])));
                transcript.respond(&[&tree.root()]);
                layers.push(Layer {
                    tree,
                    values: std::mem::take(&mut *values),
                });
            }
        }
        transcript.next();
        let queries = (0..QUERY_COUNT)
            .map(|index| {
                u32::from_le_bytes(
                    transcript.message[4 * index..4 * (index + 1)]
                        .try_into()
                        .unwrap(),
                ) as usize
                    % (EVALUATION_DOMAIN_SIZE / 2)
            })
            .collect();
        Self {
            layers,
            terminal: coefficients[0],
            queries,
        }
    }
}
