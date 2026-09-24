use crate::{
    field::{self, Element, Transform, base},
    parameters::*,
    transcript::{Transcript, challenge},
    tree::Tree,
};
use stateful_sha3::Digest;
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
    pub fn create(role: &[u8], coefficients: Vec<Element>, transcript: &mut Transcript) -> Self {
        let mut coefficients = Zeroizing::new(coefficients);
        assert_eq!(coefficients.len(), MAX_DEGREE + 1);
        let mut length = DOMAIN;
        let mut coset = 7;
        let mut layers = Vec::new();
        let rounds = (DOMAIN / 2).ilog2() as usize;
        for round in 0..rounds {
            if round > 0 {
                transcript.next();
            }
            let scalar = challenge(
                &transcript.message,
                if round == 0 { 2 * ORACLES } else { 0 },
                false,
            );
            coefficients = Zeroizing::new(
                coefficients
                    .chunks_exact(2)
                    .map(|pair| field::add(pair[0], field::multiply(scalar, pair[1])))
                    .collect(),
            );
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
                Transform::new(length).extension(&mut values, false);
                let mut tree = Tree::new(role, 3 + round, length, 48);
                let prefix = tree.leaf_hash_prefix();
                for (index, value) in values.iter().enumerate() {
                    let mut hasher = tree.leaf_hasher(index, &prefix);
                    hasher.update(field::encode(*value));
                    tree.leaf(index, hasher);
                }
                tree.finish();
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
                    % (DOMAIN / 2)
            })
            .collect();
        Self {
            layers,
            terminal: coefficients[0],
            queries,
        }
    }
}
