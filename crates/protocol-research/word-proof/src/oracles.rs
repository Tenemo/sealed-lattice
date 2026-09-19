use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    parameters::*,
    tree::Tree,
};
use stateful_sha3::{Digest, Sha3_512};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub fn random_base(count: usize) -> Vec<u128> {
    let mut output = Vec::with_capacity(count);
    let mut bytes = Zeroizing::new(vec![0; 65536]);
    while output.len() < count {
        crate::random::fill(&mut bytes);
        for word in bytes.chunks_exact(16) {
            let value = u128::from_le_bytes(word.try_into().unwrap());
            if value < MODULUS {
                output.push(value);
                if output.len() == count {
                    break;
                }
            }
        }
    }
    output
}
pub fn random_extension(count: usize) -> Vec<Element> {
    Zeroizing::new(random_base(3 * count))
        .chunks_exact(3)
        .map(|values| [values[0], values[1], values[2]])
        .collect()
}
pub struct Witness {
    pub statement: [u8; 64],
    pub columns: Vec<Vec<u16>>,
    pub counts: Vec<u128>,
}
impl Witness {
    pub fn read(path: &Path) -> Self {
        let mut file = File::open(path).unwrap();
        let mut header = [0; 80];
        file.read_exact(&mut header).unwrap();
        assert_eq!(&header[..4], WITNESS_MAGIC);
        for (index, expected) in [SYSTEMATIC, WORDS, BOOLEANS].iter().enumerate() {
            assert_eq!(
                u32::from_le_bytes(header[4 + 4 * index..8 + 4 * index].try_into().unwrap())
                    as usize,
                *expected
            );
        }
        let mut columns = Vec::new();
        let mut bytes = Zeroizing::new(vec![0; 2 * SYSTEMATIC]);
        for column in 0..COLUMNS {
            file.read_exact(&mut bytes).unwrap();
            let values: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                .collect();
            if column >= WORDS {
                assert!(values.iter().all(|value| *value <= 1));
            }
            columns.push(values);
        }
        assert_eq!(file.read(&mut [0]).unwrap(), 0);
        Self::from_columns(header[16..].try_into().unwrap(), columns).unwrap()
    }
    pub fn from_columns(statement: [u8; 64], columns: Vec<Vec<u16>>) -> Result<Self, &'static str> {
        let mut columns = Zeroizing::new(columns);
        if columns.len() != COLUMNS || columns.iter().any(|column| column.len() != SYSTEMATIC) {
            return Err("Witness shape");
        }
        if columns[WORDS..].iter().flatten().any(|value| *value > 1) {
            return Err("Boolean range");
        }
        let mut counts = vec![0; SYSTEMATIC];
        for pair in 0..ZERO_PRODUCTS {
            let (left, right) = zero_product_columns(pair);
            if columns[left]
                .iter()
                .zip(&columns[right])
                .any(|(left, right)| *left != 0 && *right != 0)
            {
                return Err("Nonzero product");
            }
        }
        for pair in 0..SUPPORT_PAIRS {
            let positive = &columns[WORDS + 2 * pair];
            let negative = &columns[WORDS + 2 * pair + 1];
            let (stride, required) = support(pair);
            let mut counts = [0u64; 2];
            for position in 0..SYSTEMATIC {
                if position % stride == 0 {
                    counts[0] += u64::from(positive[position]);
                    counts[1] += u64::from(negative[position]);
                }
            }
            if counts != [required, required] {
                return Err("Support count");
            }
        }
        for index in 0..LOOKUPS {
            let (column, scale) = lookup(index);
            for value in &columns[column] {
                let value = usize::from(*value) * scale as usize;
                if value >= SYSTEMATIC {
                    return Err("Narrow range");
                }
                counts[value] += 1;
            }
        }
        Ok(Self {
            statement,
            columns: std::mem::take(&mut *columns),
            counts,
        })
    }
}
pub struct FirstOracle {
    pub masks: Vec<Vec<u128>>,
    pub degree_mask: Vec<Element>,
    pub tree: Tree,
    pub(crate) hashers: Vec<Sha3_512>,
}

pub struct SecondOracle {
    pub masks: Vec<Vec<Element>>,
    pub sum_mask: Vec<Element>,
    pub mask_sum: Element,
    pub lookup_coefficients: Vec<Element>,
    pub tree: Tree,
    hashers: Vec<Sha3_512>,
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.columns.zeroize();
        self.counts.zeroize();
    }
}
impl Drop for FirstOracle {
    fn drop(&mut self) {
        self.masks.zeroize();
        self.degree_mask.zeroize();
    }
}
impl Drop for SecondOracle {
    fn drop(&mut self) {
        self.masks.zeroize();
        self.sum_mask.zeroize();
        self.lookup_coefficients.zeroize();
    }
}

pub(crate) fn masked_extension_coefficients(
    values: Vec<Element>,
    mask: &[Element],
    transform: &Transform,
) -> Vec<Element> {
    let mut values = Zeroizing::new(values);
    transform.extension(&mut values, true);
    for (index, value) in mask.iter().enumerate() {
        values[index] = field::subtract(values[index], *value);
    }
    values.extend_from_slice(mask);
    std::mem::take(&mut *values)
}

impl SecondOracle {
    pub fn create(role: &[u8], witness: &Witness, inverses: &[Element]) -> Self {
        assert_eq!(inverses.len(), SYSTEMATIC);
        let mut result = Self::initialize(role);
        for column in 0..LOOKUPS + 2 {
            result.commit_column(witness, inverses, column);
        }
        result.finish_commitment();
        result
    }
    pub fn initialize(role: &[u8]) -> Self {
        let masks = (0..LOOKUPS + 1).map(|_| random_extension(MASKS)).collect();
        let sum_mask = random_extension(WITNESS_DEGREE + 1);
        let mask_sum = field::scale(
            field::add(sum_mask[0], sum_mask[SYSTEMATIC]),
            SYSTEMATIC as u128,
        );
        let tree = Tree::new(role, 1, DOMAIN, SECOND_WIDTH);
        let prefix = tree.leaf_hash_prefix();
        let hashers = (0..DOMAIN)
            .map(|row| tree.leaf_hasher(row, &prefix))
            .collect();
        Self {
            masks,
            sum_mask,
            mask_sum,
            lookup_coefficients: vec![ZERO; WITNESS_DEGREE + 1],
            tree,
            hashers,
        }
    }
    pub fn commit_column(&mut self, witness: &Witness, inverses: &[Element], column: usize) {
        assert!(column < LOOKUPS + 2 && inverses.len() == SYSTEMATIC);
        let transform = Transform::new(SYSTEMATIC);
        let coefficients = Zeroizing::new(if column == LOOKUPS + 1 {
            self.sum_mask.clone()
        } else {
            let values = if column == LOOKUPS {
                witness
                    .counts
                    .iter()
                    .zip(inverses)
                    .map(|(count, inverse)| field::scale(*inverse, *count))
                    .collect()
            } else {
                let (index, factor) = lookup(column);
                witness.columns[index]
                    .iter()
                    .map(|value| inverses[usize::from(*value) * factor as usize])
                    .collect()
            };
            let coefficients =
                masked_extension_coefficients(values, &self.masks[column], &transform);
            for (sum, value) in self.lookup_coefficients.iter_mut().zip(&coefficients) {
                *sum = if column == LOOKUPS {
                    field::subtract(*sum, *value)
                } else {
                    field::add(*sum, *value)
                };
            }
            coefficients
        });
        for coset_index in 0..4 {
            let values = Zeroizing::new(extension_values(
                &coefficients,
                coset(coset_index),
                &transform,
            ));
            for (row, value) in values.iter().copied().enumerate() {
                self.hashers[coset_index + 4 * row].update(field::encode(value));
            }
        }
    }
    pub fn finish_commitment(&mut self) {
        for (row, hasher) in std::mem::take(&mut self.hashers).into_iter().enumerate() {
            self.tree.leaf(row, hasher);
        }
        self.tree.finish();
    }
    pub fn save(&self, directory: &Path) {
        self.tree.save(directory, "second-tree.bin");
        let mut masks = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("inverse-masks.bin"))
                .unwrap(),
        );
        for column in &self.masks {
            for value in column {
                masks.write_all(&field::encode(*value)).unwrap();
            }
        }
        masks.flush().unwrap();
        let mut sums = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("sum-polynomials.bin"))
                .unwrap(),
        );
        for value in self.sum_mask.iter().chain(&self.lookup_coefficients) {
            sums.write_all(&field::encode(*value)).unwrap();
        }
        sums.flush().unwrap();
    }
    pub fn openings(
        &self,
        witness: &Witness,
        inverses: &[Element],
        indices: &[usize],
    ) -> Vec<Vec<u8>> {
        let transform = Transform::new(SYSTEMATIC);
        let mut data = vec![Vec::with_capacity(SECOND_WIDTH); indices.len()];
        let groups = query_groups(indices);
        for column in 0..LOOKUPS + 1 {
            let raw = if column == LOOKUPS {
                witness
                    .counts
                    .iter()
                    .zip(inverses)
                    .map(|(count, inverse)| field::scale(*inverse, *count))
                    .collect()
            } else {
                let (index, factor) = lookup(column);
                witness.columns[index]
                    .iter()
                    .map(|value| inverses[usize::from(*value) * factor as usize])
                    .collect()
            };
            let coefficients = Zeroizing::new(masked_extension_coefficients(
                raw,
                &self.masks[column],
                &transform,
            ));
            for (coset_index, selected) in groups.iter().enumerate() {
                if selected.is_empty() {
                    continue;
                }
                let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
                let values = extension_values_selected(
                    &coefficients,
                    coset(coset_index),
                    &transform,
                    &positions,
                );
                for ((output, _), value) in selected.iter().zip(values) {
                    data[*output].extend(field::encode(value));
                }
            }
        }
        for (coset_index, selected) in groups.iter().enumerate() {
            if selected.is_empty() {
                continue;
            }
            let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
            let values = extension_values_selected(
                &self.sum_mask,
                coset(coset_index),
                &transform,
                &positions,
            );
            for ((output, _), value) in selected.iter().zip(values) {
                data[*output].extend(field::encode(value));
            }
        }
        indices
            .iter()
            .zip(data)
            .map(|(index, data)| self.tree.opening(*index, &data))
            .collect()
    }
}
pub(crate) fn coset(index: usize) -> u128 {
    base::multiply(7, base::power(field::root(DOMAIN), index as u128))
}
fn query_groups(indices: &[usize]) -> [Vec<(usize, usize)>; 4] {
    let mut groups: [Vec<(usize, usize)>; 4] = std::array::from_fn(|_| Vec::new());
    for (output, index) in indices.iter().enumerate() {
        groups[index % 4].push((output, index / 4));
    }
    groups
}
pub fn masked_base(
    values: &[u128],
    mask: &[u128],
    coset: u128,
    transform: &Transform,
) -> Vec<u128> {
    let mut coefficients = values.to_vec();
    transform.base(&mut coefficients, true);
    masked_base_coefficients(coefficients, mask, coset, transform, None)
}
pub(crate) fn masked_base_coefficients(
    coefficients: Vec<u128>,
    mask: &[u128],
    coset: u128,
    transform: &Transform,
    indices: Option<&[usize]>,
) -> Vec<u128> {
    let mut coefficients = Zeroizing::new(coefficients);
    let vanishing = base::subtract(base::power(coset, SYSTEMATIC as u128), 1);
    for (index, mask) in mask.iter().enumerate() {
        coefficients[index] = base::add(coefficients[index], base::multiply(vanishing, *mask));
    }
    let mut power = 1;
    for value in coefficients.iter_mut() {
        *value = base::multiply(*value, power);
        power = base::multiply(power, coset);
    }
    if let Some(indices) = indices {
        transform.selected_base(&mut coefficients, indices)
    } else {
        transform.base(&mut coefficients, false);
        std::mem::take(&mut *coefficients)
    }
}
pub fn extension_values(
    coefficients: &[Element],
    coset: u128,
    transform: &Transform,
) -> Vec<Element> {
    extension_values_inner(coefficients, coset, transform, None)
}
pub fn extension_values_selected(
    coefficients: &[Element],
    coset: u128,
    transform: &Transform,
    indices: &[usize],
) -> Vec<Element> {
    extension_values_inner(coefficients, coset, transform, Some(indices))
}
fn extension_values_inner(
    coefficients: &[Element],
    coset: u128,
    transform: &Transform,
    indices: Option<&[usize]>,
) -> Vec<Element> {
    assert!(coefficients.len() <= 2 * SYSTEMATIC + 1);
    let high = base::power(coset, SYSTEMATIC as u128);
    let mut power = 1;
    let mut values = Zeroizing::new(vec![ZERO; SYSTEMATIC]);
    for (index, value) in values.iter_mut().enumerate() {
        *value = field::scale(
            field::add(
                coefficients.get(index).copied().unwrap_or(ZERO),
                field::scale(
                    coefficients
                        .get(SYSTEMATIC + index)
                        .copied()
                        .unwrap_or(ZERO),
                    high,
                ),
            ),
            power,
        );
        power = base::multiply(power, coset);
    }
    if coefficients.len() == 2 * SYSTEMATIC + 1 {
        values[0] = field::add(
            values[0],
            field::scale(coefficients[2 * SYSTEMATIC], base::multiply(high, high)),
        );
    }
    if let Some(indices) = indices {
        transform.selected_extension(&mut values, indices)
    } else {
        transform.extension(&mut values, false);
        std::mem::take(&mut *values)
    }
}
impl FirstOracle {
    pub fn create(role: &[u8], witness: &Witness, excess_degree: bool) -> Self {
        let mut result = Self::initialize(role, excess_degree);
        for column in 0..COLUMNS + 2 {
            result.commit_column(witness, column);
        }
        result.finish_commitment();
        result
    }
    pub fn initialize(role: &[u8], excess_degree: bool) -> Self {
        let masks = (0..COLUMNS + 1).map(|_| random_base(MASKS)).collect();
        let mut degree_mask = random_extension(MAX_DEGREE + 1);
        if excess_degree {
            degree_mask.push(field::ONE);
        }
        let tree = Tree::new(role, 0, DOMAIN, FIRST_WIDTH);
        let prefix = tree.leaf_hash_prefix();
        let hashers = (0..DOMAIN)
            .map(|row| tree.leaf_hasher(row, &prefix))
            .collect();
        Self {
            masks,
            degree_mask,
            tree,
            hashers,
        }
    }
    pub fn commit_column(&mut self, witness: &Witness, column: usize) {
        assert!(column < COLUMNS + 2);
        let transform = Transform::new(SYSTEMATIC);
        if column <= COLUMNS {
            let mut coefficients = Zeroizing::new(if column == COLUMNS {
                witness.counts.clone()
            } else {
                witness.columns[column]
                    .iter()
                    .map(|value| u128::from(*value))
                    .collect::<Vec<u128>>()
            });
            transform.base(&mut coefficients, true);
            for coset_index in 0..4 {
                let values = Zeroizing::new(masked_base_coefficients(
                    coefficients.to_vec(),
                    &self.masks[column],
                    coset(coset_index),
                    &transform,
                    None,
                ));
                for (row, value) in values.iter().copied().enumerate() {
                    self.hashers[coset_index + 4 * row].update(value.to_le_bytes());
                }
            }
        } else {
            for coset_index in 0..4 {
                let values = Zeroizing::new(extension_values(
                    &self.degree_mask,
                    coset(coset_index),
                    &transform,
                ));
                for (row, value) in values.iter().copied().enumerate() {
                    self.hashers[coset_index + 4 * row].update(field::encode(value));
                }
            }
        }
    }
    pub fn finish_commitment(&mut self) {
        for (row, hasher) in std::mem::take(&mut self.hashers).into_iter().enumerate() {
            self.tree.leaf(row, hasher);
        }
        self.tree.finish();
    }
    pub fn save(&self, directory: &Path) {
        self.tree.save(directory, "first-tree.bin");
        let mut masks = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("first-masks.bin"))
                .unwrap(),
        );
        for column in &self.masks {
            for value in column {
                masks.write_all(&value.to_le_bytes()).unwrap();
            }
        }
        masks.flush().unwrap();
        let mut mask = BufWriter::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join("degree-mask.bin"))
                .unwrap(),
        );
        for value in &self.degree_mask {
            mask.write_all(&field::encode(*value)).unwrap();
        }
        mask.flush().unwrap();
    }
    pub fn openings(&self, witness: &Witness, indices: &[usize]) -> Vec<Vec<u8>> {
        let mut data = vec![Vec::with_capacity(FIRST_WIDTH); indices.len()];
        let transform = Transform::new(SYSTEMATIC);
        let groups = query_groups(indices);
        for column in 0..COLUMNS + 1 {
            let mut coefficients = Zeroizing::new(if column == COLUMNS {
                witness.counts.clone()
            } else {
                witness.columns[column]
                    .iter()
                    .map(|value| u128::from(*value))
                    .collect::<Vec<u128>>()
            });
            transform.base(&mut coefficients, true);
            for (coset_index, selected) in groups.iter().enumerate() {
                if selected.is_empty() {
                    continue;
                }
                let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
                let values = masked_base_coefficients(
                    coefficients.to_vec(),
                    &self.masks[column],
                    coset(coset_index),
                    &transform,
                    Some(&positions),
                );
                for ((output, _), value) in selected.iter().zip(values) {
                    data[*output].extend(value.to_le_bytes());
                }
            }
        }
        for (coset_index, selected) in groups.iter().enumerate() {
            if selected.is_empty() {
                continue;
            }
            let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
            let values = extension_values_selected(
                &self.degree_mask,
                coset(coset_index),
                &transform,
                &positions,
            );
            for ((output, _), value) in selected.iter().zip(values) {
                data[*output].extend(field::encode(value));
            }
        }
        indices
            .iter()
            .zip(data)
            .map(|(index, data)| self.tree.opening(*index, &data))
            .collect()
    }
}
