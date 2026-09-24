use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    oracles::extension_values,
    parameters::*,
    tree::Tree,
};
use stateful_sha3::Digest;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};
pub struct LinearOracle {
    pub target: Element,
    pub claimed_sum: Element,
    pub quotient: Vec<Element>,
    pub remainder: Vec<Element>,
    pub tree: Tree,
    pub lookup_weight: Element,
}
impl Drop for LinearOracle {
    fn drop(&mut self) {
        self.quotient.zeroize();
        self.remainder.zeroize();
    }
}

impl LinearOracle {
    pub fn from_evaluations(
        role: &[u8],
        evaluations: Vec<Element>,
        target: Element,
        lookup_weight: Element,
        mask_challenge: Element,
        mask_sum: Element,
        adversarial_affine: bool,
    ) -> Self {
        let mut evaluations = Zeroizing::new(evaluations);
        assert_eq!(evaluations.len(), DOMAIN);
        let transform = Transform::new(SYSTEMATIC);
        Transform::new(DOMAIN).extension(&mut evaluations, true);
        let inverse_coset = base::power(7, MODULUS - 2);
        let mut weight = 1;
        for value in evaluations.iter_mut() {
            *value = field::scale(*value, weight);
            weight = base::multiply(weight, inverse_coset);
        }
        assert!(
            evaluations[SUM_DEGREE + 1..]
                .iter()
                .all(|value| *value == ZERO),
            "masked affine sum degree"
        );
        let claimed_sum = field::add(field::multiply(mask_challenge, target), mask_sum);
        let actual_sum = field::scale(
            evaluations
                .iter()
                .step_by(SYSTEMATIC)
                .copied()
                .fold(ZERO, field::add),
            SYSTEMATIC as u128,
        );
        if adversarial_affine {
            assert_ne!(actual_sum, claimed_sum);
        } else {
            assert_eq!(
                actual_sum, claimed_sum,
                "full witness and public target disagree"
            );
        }
        evaluations.truncate(SUM_DEGREE + 1);
        let mut quotient = Zeroizing::new(vec![ZERO; SUM_DEGREE - SYSTEMATIC + 1]);
        for index in (SYSTEMATIC..evaluations.len()).rev() {
            quotient[index - SYSTEMATIC] = evaluations[index];
            evaluations[index - SYSTEMATIC] =
                field::add(evaluations[index - SYSTEMATIC], evaluations[index]);
        }
        if !adversarial_affine {
            assert_eq!(
                evaluations[0],
                field::scale(claimed_sum, base::power(SYSTEMATIC as u128, MODULUS - 2))
            );
        }
        let mut remainder = Zeroizing::new(evaluations[1..SYSTEMATIC].to_vec());
        drop(evaluations);
        let mut tree = Tree::new(role, 2, DOMAIN, 48);
        let prefix = tree.leaf_hash_prefix();
        for coset in 0..4 {
            let twist = base::multiply(7, base::power(field::root(DOMAIN), coset as u128));
            let values = Zeroizing::new(extension_values(&quotient, twist, &transform));
            for (index, value) in values.iter().copied().enumerate() {
                let position = coset + 4 * index;
                let mut hasher = tree.leaf_hasher(position, &prefix);
                hasher.update(field::encode(value));
                tree.leaf(position, hasher);
            }
        }
        tree.finish();
        Self {
            target,
            claimed_sum,
            quotient: std::mem::take(&mut *quotient),
            remainder: std::mem::take(&mut *remainder),
            tree,
            lookup_weight,
        }
    }
    pub fn save(&self, directory: &Path) {
        self.tree.save(directory, "third-tree.bin");
        let mut file = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("linear-polynomials.bin"))
                .unwrap(),
        );
        for value in self.quotient.iter().chain(&self.remainder) {
            file.write_all(&field::encode(*value)).unwrap();
        }
        file.flush().unwrap();
    }
    pub fn openings(&self, indices: &[usize]) -> Vec<Vec<u8>> {
        let transform = Transform::new(SYSTEMATIC);
        let mut data = vec![ZERO; indices.len()];
        for coset in 0..4 {
            let selected: Vec<_> = indices
                .iter()
                .enumerate()
                .filter(|(_, index)| **index % 4 == coset)
                .collect();
            if selected.is_empty() {
                continue;
            }
            let twist = base::multiply(7, base::power(field::root(DOMAIN), coset as u128));
            let positions: Vec<_> = selected.iter().map(|(_, index)| **index / 4).collect();
            let values = crate::oracles::extension_values_selected(
                &self.quotient,
                twist,
                &transform,
                &positions,
            );
            for ((output, _), value) in selected.into_iter().zip(values) {
                data[output] = value;
            }
        }
        indices
            .iter()
            .zip(data)
            .map(|(index, value)| self.tree.opening(*index, &field::encode(value)))
            .collect()
    }
}
