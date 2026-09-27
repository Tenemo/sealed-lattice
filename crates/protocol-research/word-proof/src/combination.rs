//! The combined oracle's values on two cosets, as sums of term groups that
//! independent jobs add: each group of committed columns that zero
//! products join, with its lookups, the lookup multiplicities and table,
//! and each remaining extension oracle.
use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    linear::LinearOracle,
    oracles::{self, FirstOracle, SecondOracle, Witness},
    parameters::*,
    sums::{self, Sums},
    transcript::challenge,
};
use parallel_work::{Job, Part, share, submit};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Adds the terms of committed columns that only their own zero products
/// join, with their lookups', on both cosets.
pub static COLUMNS: Job = Job {
    kind: 0x0130,
    run: add_columns,
};
/// Adds the multiplicity, table reciprocal and table residual terms.
pub static COUNTS: Job = Job {
    kind: 0x0131,
    run: add_counts,
};
/// Adds an extension oracle's weighted values, or the degree mask's values.
pub static EXTENSION: Job = Job {
    kind: 0x0132,
    run: add_extension_oracle,
};

// Every honest combined oracle has degree below twice the systematic size.
// Interpolate on that many points; the verifier still checks the full domain.
const COSETS: [usize; 2] = [0, 2];
// The degree mask's values join the sums without a weight.
const UNWEIGHTED: usize = u32::MAX as usize;
const WORD_BYTES: usize = 16;
const ELEMENT_BYTES: usize = 48;

struct Weights {
    coefficients: Vec<Element>,
    powers: Vec<Vec<u128>>,
    classes: Vec<usize>,
}
impl Weights {
    /// The weights on a coset, from every oracle's challenge pair and degree
    /// shift, with the powers of the listed oracles' shifts.
    fn new(coefficients: &[Element], shifts: &[usize], coset: u128, oracles: &[usize]) -> Self {
        let mut unique = shifts.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let classes: Vec<usize> = shifts
            .iter()
            .map(|shift| unique.binary_search(shift).unwrap())
            .collect();
        let needed: BTreeSet<usize> = oracles.iter().map(|oracle| classes[*oracle]).collect();
        let powers = unique
            .iter()
            .enumerate()
            .map(|(class, shift)| {
                if !needed.contains(&class) {
                    return Vec::new();
                }
                let mut value = base::power(coset, *shift as u128);
                let step = base::power(field::root(SYSTEMATIC), *shift as u128);
                (0..SYSTEMATIC)
                    .map(|_| {
                        let previous = value;
                        value = base::multiply(value, step);
                        previous
                    })
                    .collect()
            })
            .collect();
        Self {
            coefficients: coefficients.to_vec(),
            powers,
            classes,
        }
    }
    fn value(&self, oracle: usize, position: usize) -> Element {
        field::add(
            self.coefficients[2 * oracle],
            field::scale(
                self.coefficients[2 * oracle + 1],
                self.powers[self.classes[oracle]][position],
            ),
        )
    }
    fn add_base(&self, output: &mut [Element], oracle: usize, values: &[u128]) {
        for (position, (sum, value)) in output.iter_mut().zip(values).enumerate() {
            *sum = field::add(*sum, field::scale(self.value(oracle, position), *value));
        }
    }
    fn add_extension(&self, output: &mut [Element], oracle: usize, values: &[Element]) {
        for (position, (sum, value)) in output.iter_mut().zip(values).enumerate() {
            *sum = field::add(*sum, field::multiply(self.value(oracle, position), *value));
        }
    }
    fn add_lookup(
        &self,
        output: &mut [Element],
        lookup: LookupOracles,
        beta: Element,
        inverse_vanishing: u128,
        words: &[u128],
        reciprocals: &[Element],
    ) {
        let LookupOracles {
            inverse: inverse_oracle,
            residual: residual_oracle,
            factor,
        } = lookup;
        let residual_constant =
            field::scale(self.coefficients[2 * residual_oracle], inverse_vanishing);
        let residual_shifted = field::scale(
            self.coefficients[2 * residual_oracle + 1],
            inverse_vanishing,
        );
        let constant = field::add(
            self.coefficients[2 * inverse_oracle],
            field::multiply(beta, residual_constant),
        );
        let challenge_shifted = field::multiply(beta, residual_shifted);
        let word_constant = field::scale(residual_constant, factor);
        let word_shifted = field::scale(residual_shifted, factor);
        // Collect both occurrences of the reciprocal before multiplying it.
        // The verifier still evaluates the original inverse and quotient rows.
        for (position, ((sum, word), reciprocal)) in
            output.iter_mut().zip(words).zip(reciprocals).enumerate()
        {
            let inverse_power = self.powers[self.classes[inverse_oracle]][position];
            let residual_power = self.powers[self.classes[residual_oracle]][position];
            let coefficient = field::subtract(
                field::add(
                    constant,
                    field::add(
                        field::scale(self.coefficients[2 * inverse_oracle + 1], inverse_power),
                        field::scale(challenge_shifted, residual_power),
                    ),
                ),
                field::scale(
                    field::add(word_constant, field::scale(word_shifted, residual_power)),
                    *word,
                ),
            );
            *sum = field::add(
                *sum,
                field::subtract(
                    field::multiply(coefficient, *reciprocal),
                    field::add(
                        residual_constant,
                        field::scale(residual_shifted, residual_power),
                    ),
                ),
            );
        }
    }
}
// A lookup's reciprocal and residual oracles and its word scale.
#[derive(Clone, Copy)]
struct LookupOracles {
    inverse: usize,
    residual: usize,
    factor: u128,
}
fn lookup_oracles(relation: &Relation, lookup_index: usize) -> LookupOracles {
    LookupOracles {
        inverse: relation.columns() + 1 + lookup_index,
        residual: relation.original_oracles()
            + relation.booleans()
            + relation.zero_products()
            + lookup_index,
        factor: relation.lookup(lookup_index).1,
    }
}

// The combination challenges, every oracle's degree shift and the lookup
// challenge, which every job reads.
struct Common {
    coefficients: Vec<Element>,
    shifts: Vec<usize>,
    beta: Element,
}
fn encode_common(relation: &Relation, message: &[u8], beta: Element) -> Vec<u8> {
    let oracles = relation.oracles();
    let mut bytes = Vec::from((oracles as u32).to_le_bytes());
    for index in 0..2 * oracles {
        bytes.extend(field::encode(challenge(message, index, false)));
    }
    for degree in relation.degrees() {
        bytes.extend(((MAX_DEGREE - degree) as u32).to_le_bytes());
    }
    bytes.extend(field::encode(beta));
    bytes
}

// A job input read in order.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        taken
    }
    fn number(&mut self) -> usize {
        u32::from_le_bytes(self.take(4).try_into().unwrap()) as usize
    }
    fn word(&mut self) -> u128 {
        u128::from_le_bytes(self.take(WORD_BYTES).try_into().unwrap())
    }
    fn element(&mut self) -> Element {
        field::decode(self.take(ELEMENT_BYTES))
    }
    fn words(&mut self, count: usize) -> Zeroizing<Vec<u128>> {
        Zeroizing::new((0..count).map(|_| self.word()).collect())
    }
    fn elements(&mut self, count: usize) -> Zeroizing<Vec<Element>> {
        Zeroizing::new((0..count).map(|_| self.element()).collect())
    }
    fn common(&mut self) -> Common {
        let oracles = self.number();
        Common {
            coefficients: (0..2 * oracles).map(|_| self.element()).collect(),
            shifts: (0..oracles).map(|_| self.number()).collect(),
            beta: self.element(),
        }
    }
    fn finish(self) {
        assert!(self.0.is_empty());
    }
}
fn push_number(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend((value as u32).to_le_bytes());
}

// The weights and reciprocal vanishing values of both cosets.
struct Cosets {
    points: [u128; 2],
    weights: [Weights; 2],
    inverse_vanishing: [u128; 2],
}
impl Cosets {
    fn new(common: &Common, oracles: &[usize]) -> Self {
        let points = COSETS.map(oracles::coset);
        Self {
            points,
            weights: points
                .map(|coset| Weights::new(&common.coefficients, &common.shifts, coset, oracles)),
            inverse_vanishing: points.map(|coset| {
                base::power(
                    base::subtract(base::power(coset, SYSTEMATIC as u128), 1),
                    MODULUS - 2,
                )
            }),
        }
    }
}
// Adds a job's terms to both cosets' halves of the sums.
fn with_cosets(input: &[u8], action: impl FnOnce(Reader, [&mut [Element]; 2])) {
    let (session, length, rest) = sums::header(input);
    assert_eq!(length, 2 * SYSTEMATIC);
    sums::with(session, length, |sums| {
        let (first, second) = sums.split_at_mut(SYSTEMATIC);
        action(Reader(rest), [first, second]);
    });
}

// The groups of committed columns that zero products join, each in
// column order.
fn components(relation: &Relation) -> Vec<Vec<usize>> {
    let columns = relation.columns();
    let mut root: Vec<usize> = (0..columns).collect();
    fn find(root: &mut [usize], mut column: usize) -> usize {
        while root[column] != column {
            root[column] = root[root[column]];
            column = root[column];
        }
        column
    }
    for pair in 0..relation.zero_products() {
        let (left, right) = relation.zero_product_columns(pair);
        let (left, right) = (find(&mut root, left), find(&mut root, right));
        root[left.max(right)] = left.min(right);
    }
    let mut groups = vec![Vec::new(); columns];
    for column in 0..columns {
        groups[find(&mut root, column)].push(column);
    }
    groups.retain(|group| !group.is_empty());
    groups
}

// A group of committed columns: each column's oracle, Boolean residual
// oracle, mask, words and lookups, then the zero products inside it. Only
// a group with lookups needs the reciprocal table.
fn encode_columns(
    witness: &Witness,
    first: &FirstOracle,
    second: &SecondOracle,
    group: &[usize],
) -> (Zeroizing<Vec<u8>>, bool) {
    let relation = &witness.relation;
    let words = relation.words();
    let original = relation.original_oracles();
    let mut bytes = Zeroizing::new(Vec::new());
    let mut lookups = false;
    push_number(&mut bytes, group.len());
    for &column in group {
        push_number(&mut bytes, column);
        push_number(
            &mut bytes,
            if column < words {
                UNWEIGHTED
            } else {
                original + column - words
            },
        );
        for mask in &first.masks[column] {
            bytes.extend(mask.to_le_bytes());
        }
        for value in &witness.columns[column] {
            bytes.extend(value.to_le_bytes());
        }
        let indices: Vec<usize> = (0..relation.lookups())
            .filter(|index| column < words && relation.lookup(*index).0 == column)
            .collect();
        push_number(&mut bytes, indices.len());
        for index in indices {
            lookups = true;
            let oracles = lookup_oracles(relation, index);
            push_number(&mut bytes, oracles.inverse);
            push_number(&mut bytes, oracles.residual);
            bytes.extend(oracles.factor.to_le_bytes());
            for mask in &second.masks[index] {
                bytes.extend(field::encode(*mask));
            }
        }
    }
    let pairs: Vec<_> = (0..relation.zero_products())
        .filter(|pair| group.contains(&relation.zero_product_columns(*pair).0))
        .collect();
    push_number(&mut bytes, pairs.len());
    for pair in pairs {
        let (left, right) = relation.zero_product_columns(pair);
        assert!(left < right);
        for column in [left, right] {
            push_number(&mut bytes, group.binary_search(&column).unwrap());
        }
        push_number(&mut bytes, original + relation.booleans() + pair);
    }
    bytes.push(u8::from(lookups));
    (bytes, lookups)
}
// A column's lookup: its oracles and word scale, and its reciprocal mask.
struct Lookup<'a> {
    oracles: LookupOracles,
    mask: &'a [u8],
}
struct Column<'a> {
    oracle: usize,
    boolean: Option<usize>,
    mask: Zeroizing<Vec<u128>>,
    words: &'a [u8],
    lookups: Vec<Lookup<'a>>,
}
fn add_columns(input: &[u8]) -> Vec<u8> {
    with_cosets(input, |mut reader, outputs| {
        let common = reader.common();
        let columns: Vec<Column> = (0..reader.number())
            .map(|_| {
                let oracle = reader.number();
                let boolean = Some(reader.number()).filter(|oracle| *oracle != UNWEIGHTED);
                let mask = reader.words(MASKS);
                let words = reader.take(2 * SYSTEMATIC);
                let lookups = (0..reader.number())
                    .map(|_| Lookup {
                        oracles: LookupOracles {
                            inverse: reader.number(),
                            residual: reader.number(),
                            factor: reader.word(),
                        },
                        mask: reader.take(MASKS * ELEMENT_BYTES),
                    })
                    .collect();
                Column {
                    oracle,
                    boolean,
                    mask,
                    words,
                    lookups,
                }
            })
            .collect();
        let pairs: Vec<[usize; 3]> = (0..reader.number())
            .map(|_| std::array::from_fn(|_| reader.number()))
            .collect();
        let inverses = (reader.take(1)[0] == 1).then(|| reader.take(SYSTEMATIC * ELEMENT_BYTES));
        reader.finish();
        let mut used = Vec::new();
        for column in &columns {
            used.push(column.oracle);
            used.extend(column.boolean);
            for lookup in &column.lookups {
                used.extend([lookup.oracles.inverse, lookup.oracles.residual]);
            }
        }
        used.extend(pairs.iter().map(|pair| pair[2]));
        let cosets = Cosets::new(&common, &used);
        let transform = Transform::cached(SYSTEMATIC);
        let mut values = Vec::with_capacity(columns.len());
        for column in &columns {
            let words: Zeroizing<Vec<u16>> = Zeroizing::new(
                column
                    .words
                    .chunks_exact(2)
                    .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                    .collect(),
            );
            let mut coefficients: Zeroizing<Vec<u128>> =
                Zeroizing::new(words.iter().map(|value| u128::from(*value)).collect());
            transform.base(&mut coefficients, true);
            let column_values = cosets.points.map(|coset| {
                Zeroizing::new(oracles::masked_base_coefficients(
                    coefficients.to_vec(),
                    &column.mask,
                    coset,
                    transform,
                    None,
                ))
            });
            for coset in 0..2 {
                cosets.weights[coset].add_base(
                    outputs[coset],
                    column.oracle,
                    &column_values[coset],
                );
            }
            for lookup in &column.lookups {
                let inverses = inverses.unwrap();
                let raw = words.iter().map(|value| {
                    let index = usize::from(*value) * lookup.oracles.factor as usize;
                    field::decode(&inverses[ELEMENT_BYTES * index..])
                });
                let mask = Reader(lookup.mask).elements(MASKS);
                let coefficients = Zeroizing::new(oracles::masked_extension_coefficients(
                    raw, &mask, transform,
                ));
                for coset in 0..2 {
                    let reciprocal = Zeroizing::new(oracles::extension_values(
                        &coefficients,
                        cosets.points[coset],
                        transform,
                    ));
                    cosets.weights[coset].add_lookup(
                        outputs[coset],
                        lookup.oracles,
                        common.beta,
                        cosets.inverse_vanishing[coset],
                        &column_values[coset],
                        &reciprocal,
                    );
                }
            }
            if let Some(oracle) = column.boolean {
                for coset in 0..2 {
                    let residuals = Zeroizing::new(
                        column_values[coset]
                            .iter()
                            .map(|value| {
                                base::multiply(
                                    base::multiply(*value, base::subtract(*value, 1)),
                                    cosets.inverse_vanishing[coset],
                                )
                            })
                            .collect::<Vec<u128>>(),
                    );
                    cosets.weights[coset].add_base(outputs[coset], oracle, &residuals);
                }
            }
            values.push(column_values);
        }
        for [left, right, oracle] in pairs {
            for coset in 0..2 {
                let residuals = Zeroizing::new(
                    values[left][coset]
                        .iter()
                        .zip(values[right][coset].iter())
                        .map(|(left, right)| {
                            base::multiply(
                                base::multiply(*left, *right),
                                cosets.inverse_vanishing[coset],
                            )
                        })
                        .collect::<Vec<u128>>(),
                );
                cosets.weights[coset].add_base(outputs[coset], oracle, &residuals);
            }
        }
    });
    Vec::new()
}

// The multiplicities with their mask, the table reciprocals' mask, and the
// oracles of the multiplicity, table reciprocal and table residual.
fn encode_counts(
    witness: &Witness,
    first: &FirstOracle,
    second: &SecondOracle,
) -> Zeroizing<Vec<u8>> {
    let relation = &witness.relation;
    let (columns, lookups) = (relation.columns(), relation.lookups());
    let mut bytes = Zeroizing::new(Vec::new());
    for oracle in [columns, columns + 1 + lookups, relation.oracles() - 2] {
        push_number(&mut bytes, oracle);
    }
    for mask in &first.masks[columns] {
        bytes.extend(mask.to_le_bytes());
    }
    for mask in &second.masks[lookups] {
        bytes.extend(field::encode(*mask));
    }
    for count in &witness.counts {
        bytes.extend(count.to_le_bytes());
    }
    bytes
}
fn add_counts(input: &[u8]) -> Vec<u8> {
    with_cosets(input, |mut reader, outputs| {
        let common = reader.common();
        let [multiplicity_oracle, table_oracle, residual_oracle] =
            std::array::from_fn(|_| reader.number());
        let first_mask = reader.words(MASKS);
        let second_mask = reader.elements(MASKS);
        let counts = reader.words(SYSTEMATIC);
        let inverses = reader.elements(SYSTEMATIC);
        reader.finish();
        let cosets = Cosets::new(
            &common,
            &[multiplicity_oracle, table_oracle, residual_oracle],
        );
        let transform = Transform::cached(SYSTEMATIC);
        let mut count_coefficients = Zeroizing::new(counts.to_vec());
        transform.base(&mut count_coefficients, true);
        let raw = counts
            .iter()
            .zip(inverses.iter())
            .map(|(count, inverse)| field::scale(*inverse, *count));
        let coefficients = Zeroizing::new(oracles::masked_extension_coefficients(
            raw,
            &second_mask,
            transform,
        ));
        for (coset_index, output) in outputs.into_iter().enumerate() {
            let coset = cosets.points[coset_index];
            let weights = &cosets.weights[coset_index];
            let inverse_vanishing = cosets.inverse_vanishing[coset_index];
            let multiplicity = Zeroizing::new(oracles::masked_base_coefficients(
                count_coefficients.to_vec(),
                &first_mask,
                coset,
                transform,
                None,
            ));
            weights.add_base(output, multiplicity_oracle, &multiplicity);
            let table_inverse =
                Zeroizing::new(oracles::extension_values(&coefficients, coset, transform));
            weights.add_extension(output, table_oracle, &table_inverse);
            let table = oracles::masked_base(
                &(0..SYSTEMATIC)
                    .map(|value| value as u128)
                    .collect::<Vec<_>>(),
                &[],
                coset,
                transform,
            );
            let residuals = Zeroizing::new(
                table_inverse
                    .iter()
                    .zip(&table)
                    .zip(multiplicity.iter())
                    .map(|((inverse, table), multiplicity)| {
                        field::scale(
                            field::subtract(
                                field::multiply(
                                    field::subtract(common.beta, [*table, 0, 0]),
                                    *inverse,
                                ),
                                [*multiplicity, 0, 0],
                            ),
                            inverse_vanishing,
                        )
                    })
                    .collect::<Vec<Element>>(),
            );
            weights.add_extension(output, residual_oracle, &residuals);
        }
    });
    Vec::new()
}

// An extension oracle's coefficients, or the degree mask's without a
// weight.
fn encode_extension(oracle: usize, coefficients: &[Element]) -> Zeroizing<Vec<u8>> {
    assert!(coefficients.len() <= 2 * SYSTEMATIC + 1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(8 + ELEMENT_BYTES * coefficients.len()));
    push_number(&mut bytes, oracle);
    push_number(&mut bytes, coefficients.len());
    for coefficient in coefficients {
        bytes.extend(field::encode(*coefficient));
    }
    bytes
}
fn add_extension_oracle(input: &[u8]) -> Vec<u8> {
    with_cosets(input, |mut reader, outputs| {
        let common = reader.common();
        let oracle = reader.number();
        let count = reader.number();
        assert!(count <= 2 * SYSTEMATIC + 1);
        let coefficients = reader.elements(count);
        reader.finish();
        let used = if oracle == UNWEIGHTED {
            Vec::new()
        } else {
            vec![oracle]
        };
        let cosets = Cosets::new(&common, &used);
        let transform = Transform::cached(SYSTEMATIC);
        for (coset, output) in outputs.into_iter().enumerate() {
            let values = Zeroizing::new(oracles::extension_values(
                &coefficients,
                cosets.points[coset],
                transform,
            ));
            if oracle == UNWEIGHTED {
                for (sum, value) in output.iter_mut().zip(values.iter()) {
                    *sum = field::add(*sum, *value);
                }
            } else {
                cosets.weights[coset].add_extension(output, oracle, &values);
            }
        }
    });
    Vec::new()
}

pub fn polynomial(
    witness: &Witness,
    first: &FirstOracle,
    second: &SecondOracle,
    linear: &LinearOracle,
    beta: Element,
    inverses: &[Element],
    message: &[u8],
) -> Vec<Element> {
    let relation = &witness.relation;
    let (columns, lookups, oracles) = (relation.columns(), relation.lookups(), relation.oracles());
    let common = share(Zeroizing::new(encode_common(relation, message, beta)));
    let mut table = Zeroizing::new(Vec::with_capacity(ELEMENT_BYTES * inverses.len()));
    for inverse in inverses {
        table.extend(field::encode(*inverse));
    }
    let table = share(table);
    let mut sums = Sums::new(2 * SYSTEMATIC);
    let header = sums.header();
    for group in components(relation) {
        let (unit, lookups) = encode_columns(witness, first, second, &group);
        let mut parts = vec![
            Part::Bytes(&header),
            Part::Shared(&common),
            Part::Bytes(&unit),
        ];
        if lookups {
            parts.push(Part::Shared(&table));
        }
        sums.add(submit(&COLUMNS, None, &parts, 0));
    }
    let counts = encode_counts(witness, first, second);
    sums.add(submit(
        &COUNTS,
        None,
        &[
            Part::Bytes(&header),
            Part::Shared(&common),
            Part::Bytes(&counts),
            Part::Shared(&table),
        ],
        0,
    ));
    for (oracle, coefficients) in [
        (UNWEIGHTED, &first.degree_mask),
        (columns + lookups + 2, &second.sum_mask),
        (columns + lookups + 3, &linear.quotient),
        (oracles - 1, &linear.remainder),
    ] {
        let unit = encode_extension(oracle, coefficients);
        sums.add(submit(
            &EXTENSION,
            None,
            &[
                Part::Bytes(&header),
                Part::Shared(&common),
                Part::Bytes(&unit),
            ],
            0,
        ));
    }
    let total = sums.finish();
    let mut evaluations = Zeroizing::new(vec![ZERO; 2 * SYSTEMATIC]);
    for (coset, output) in total.chunks_exact(SYSTEMATIC).enumerate() {
        for (position, value) in output.iter().copied().enumerate() {
            evaluations[coset + 2 * position] = value;
        }
    }
    Transform::new(2 * SYSTEMATIC).extension(&mut evaluations, true);
    let inverse_coset = base::power(7, MODULUS - 2);
    let mut power = 1;
    for value in evaluations.iter_mut() {
        *value = field::scale(*value, power);
        power = base::multiply(power, inverse_coset);
    }
    std::mem::take(&mut *evaluations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ONE;
    #[test]
    fn collected_reciprocal_terms_equal_the_direct_constraint_for_every_lookup_scale() {
        let mut state = 0x935ac307125aec91u128;
        let mut sample = || {
            state ^= state << 23;
            state ^= state >> 31;
            state ^= state << 17;
            state % MODULUS
        };
        // Whole words and narrow words scaled by powers of two or by a
        // score range's quotient.
        for narrow in [vec![(2, 512)], vec![(6, 8), (9, 512)], vec![(22, 7281)]] {
            let relation = Relation {
                tag: b"combination-test",
                proof_magic: b"TEST",
                words: 27,
                booleans: 5,
                narrow,
                zero_product_pairs: vec![(27, 28), (29, 30), (20, 31)],
                supports: vec![(1, 512), (16, 128)],
                message_bytes: 1 << 18,
                statement_bytes: 1,
                parameters: Vec::new(),
            };
            let (words_count, lookups) = (relation.words(), relation.lookups());
            let weights = Weights {
                coefficients: (0..2 * relation.oracles())
                    .map(|_| [sample(), sample(), sample()])
                    .collect(),
                powers: vec![vec![0, 1, MODULUS - 1, 37], vec![11, 0, 2, MODULUS - 1]],
                classes: (0..relation.oracles()).map(|index| index % 2).collect(),
            };
            let words = [0, 1, MODULUS - 1, sample()];
            let reciprocals = [
                [0, 0, 0],
                [1, 0, 0],
                [MODULUS - 1; 3],
                [sample(), sample(), sample()],
            ];
            for lookup_index in [0, 1, words_count - 1, words_count, lookups - 1] {
                for beta in [ZERO, ONE, [0, 0, 1], [sample(), sample(), sample()]] {
                    for inverse_vanishing in [0, 1, MODULUS - 1, sample()] {
                        let mut actual = vec![ONE; words.len()];
                        weights.add_lookup(
                            &mut actual,
                            lookup_oracles(&relation, lookup_index),
                            beta,
                            inverse_vanishing,
                            &words,
                            &reciprocals,
                        );
                        for position in 0..words.len() {
                            let inverse_oracle = relation.columns() + 1 + lookup_index;
                            let residual_oracle = relation.columns()
                                + lookups
                                + 4
                                + relation.booleans()
                                + relation.zero_products()
                                + lookup_index;
                            let residue = field::scale(
                                field::subtract(
                                    field::multiply(
                                        reciprocals[position],
                                        field::subtract(
                                            beta,
                                            [
                                                base::multiply(
                                                    words[position],
                                                    relation.lookup(lookup_index).1,
                                                ),
                                                0,
                                                0,
                                            ],
                                        ),
                                    ),
                                    ONE,
                                ),
                                inverse_vanishing,
                            );
                            let expected = field::add(
                                ONE,
                                field::add(
                                    field::multiply(
                                        weights.value(inverse_oracle, position),
                                        reciprocals[position],
                                    ),
                                    field::multiply(
                                        weights.value(residual_oracle, position),
                                        residue,
                                    ),
                                ),
                            );
                            assert_eq!(actual[position], expected);
                        }
                    }
                }
            }
        }
    }
}
