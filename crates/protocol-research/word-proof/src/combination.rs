//! The combined oracle's values on two cosets, as sums of term groups that
//! independent jobs add: each group of committed columns that zero
//! products join, with its lookups, the lookup multiplicities and table,
//! and each remaining extension oracle.
use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    linear::LinearOracle,
    oracles::{self, FirstOracle, SecondOracle, Witness},
    rows,
    sums::{self, Sums},
    transcript::challenge,
};
use parallel_work::{Job, Part, Shared, StreamedRecords, gather, share, submit};
use supported_profile::relation::*;
use zeroize::Zeroizing;

/// Adds the terms of committed columns that only their own zero products
/// join, with their lookups', on both cosets; a group with lookups streams
/// the reciprocal table.
pub static COLUMNS: Job = Job {
    kind: 0x0130,
    run: add_columns,
};
/// Adds the multiplicity, table reciprocal and table residual terms on one
/// coset from the reciprocal table it streams.
pub static COUNTS: Job = Job {
    kind: 0x0131,
    run: add_counts,
};
/// Adds an extension oracle's weighted values, or the degree mask's values,
/// from the coefficients it streams.
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
    // Each class's shift power at the coset's first position and its step
    // from one position to the next.
    powers: Vec<(u128, u128)>,
    classes: Vec<usize>,
}
impl Weights {
    /// The weights on a coset, from every oracle's challenge pair and degree
    /// shift.
    fn new(coefficients: &[Element], shifts: &[usize], coset: u128) -> Self {
        let mut unique = shifts.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let classes = shifts
            .iter()
            .map(|shift| unique.binary_search(shift).unwrap())
            .collect();
        let root = field::root(SYSTEMATIC);
        let powers = unique
            .iter()
            .map(|shift| {
                (
                    base::power(coset, *shift as u128),
                    base::power(root, *shift as u128),
                )
            })
            .collect();
        Self {
            coefficients: coefficients.to_vec(),
            powers,
            classes,
        }
    }
    // The oracle's shift powers at the positions in order.
    fn powers(&self, oracle: usize) -> impl Iterator<Item = u128> + use<> {
        let (first, step) = self.powers[self.classes[oracle]];
        std::iter::successors(Some(first), move |power| Some(base::multiply(*power, step)))
    }
    // The oracle's weights at the positions in order.
    fn values(&self, oracle: usize) -> impl Iterator<Item = Element> + use<> {
        let (constant, shifted) = (
            self.coefficients[2 * oracle],
            self.coefficients[2 * oracle + 1],
        );
        self.powers(oracle)
            .map(move |power| field::add(constant, field::scale(shifted, power)))
    }
    fn add_base(
        &self,
        output: &mut [Element],
        oracle: usize,
        values: impl IntoIterator<Item = u128>,
    ) {
        for ((sum, weight), value) in output.iter_mut().zip(self.values(oracle)).zip(values) {
            *sum = field::add(*sum, field::scale(weight, value));
        }
    }
    fn add_extension(
        &self,
        output: &mut [Element],
        oracle: usize,
        values: impl IntoIterator<Item = Element>,
    ) {
        for ((sum, weight), value) in output.iter_mut().zip(self.values(oracle)).zip(values) {
            *sum = field::add(*sum, field::multiply(weight, value));
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
        // Collect both occurrences of the reciprocal before multiplying it.
        // The verifier still evaluates the original inverse and quotient rows.
        // The scaled word's term is the residual weight times the word and
        // its scale.
        for ((((sum, word), reciprocal), inverse_power), residual_power) in output
            .iter_mut()
            .zip(words)
            .zip(reciprocals)
            .zip(self.powers(inverse_oracle))
            .zip(self.powers(residual_oracle))
        {
            let residual = field::add(
                residual_constant,
                field::scale(residual_shifted, residual_power),
            );
            let coefficient = field::subtract(
                field::add(
                    constant,
                    field::add(
                        field::scale(self.coefficients[2 * inverse_oracle + 1], inverse_power),
                        field::scale(challenge_shifted, residual_power),
                    ),
                ),
                field::scale(residual, base::multiply(*word, factor)),
            );
            *sum = field::add(
                *sum,
                field::subtract(field::multiply(coefficient, *reciprocal), residual),
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
        bytes.extend(((MAXIMUM_DEGREE - degree) as u32).to_le_bytes());
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
    fn new(common: &Common) -> Self {
        let points = COSETS.map(oracles::coset);
        Self {
            points,
            weights: points.map(|coset| Weights::new(&common.coefficients, &common.shifts, coset)),
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
    let (session, shard, length, rest) = sums::header(input);
    assert_eq!(length, 2 * SYSTEMATIC);
    sums::with(session, shard, length, |sums| {
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
// a group with lookups streams the reciprocal table. The bytes are written
// once to count them and once into a buffer of that exact length, which no
// growth copies without zeroizing.
fn encode_columns(
    witness: &Witness,
    first_masks: &[Vec<u128>],
    second_masks: &[Vec<Element>],
    group: &[usize],
) -> (Zeroizing<Vec<u8>>, bool) {
    let mut length = 0;
    write_columns(witness, first_masks, second_masks, group, &mut |part| {
        length += part.len();
    });
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    let lookups = write_columns(witness, first_masks, second_masks, group, &mut |part| {
        bytes.extend_from_slice(part);
    });
    (bytes, lookups)
}
// Writes a group's column input through the function, part by part, and
// returns whether the group has lookups.
fn write_columns(
    witness: &Witness,
    first_masks: &[Vec<u128>],
    second_masks: &[Vec<Element>],
    group: &[usize],
    put: &mut dyn FnMut(&[u8]),
) -> bool {
    fn number(put: &mut dyn FnMut(&[u8]), value: usize) {
        put(&(value as u32).to_le_bytes());
    }
    let relation = &witness.relation;
    let words = relation.words();
    let original = relation.original_oracles();
    let mut lookups = false;
    number(put, group.len());
    for &column in group {
        number(put, column);
        number(
            put,
            if column < words {
                UNWEIGHTED
            } else {
                original + column - words
            },
        );
        for mask in &first_masks[column] {
            put(&mask.to_le_bytes());
        }
        for value in &witness.columns[column] {
            put(&value.to_le_bytes());
        }
        let indices: Vec<usize> = (0..relation.lookups())
            .filter(|index| column < words && relation.lookup(*index).0 == column)
            .collect();
        number(put, indices.len());
        for index in indices {
            lookups = true;
            let oracles = lookup_oracles(relation, index);
            number(put, oracles.inverse);
            number(put, oracles.residual);
            put(&oracles.factor.to_le_bytes());
            for mask in &second_masks[index] {
                put(&field::encode(*mask));
            }
        }
    }
    let pairs: Vec<_> = (0..relation.zero_products())
        .filter(|pair| group.contains(&relation.zero_product_columns(*pair).0))
        .collect();
    number(put, pairs.len());
    for pair in pairs {
        let (left, right) = relation.zero_product_columns(pair);
        assert!(left < right);
        for column in [left, right] {
            number(put, group.binary_search(&column).unwrap());
        }
        number(put, original + relation.booleans() + pair);
    }
    put(&[u8::from(lookups)]);
    lookups
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
        let lookups = reader.take(1)[0] == 1;
        reader.finish();
        assert!(!lookups || parallel_work::streamed_length() == SYSTEMATIC * ELEMENT_BYTES);
        let cosets = Cosets::new(&common);
        let transform = Transform::cached(SYSTEMATIC);
        // The last column whose zero products need each column's values.
        let needed: Vec<usize> = (0..columns.len())
            .map(|index| {
                pairs
                    .iter()
                    .filter(|pair| pair[..2].contains(&index))
                    .map(|pair| pair[1])
                    .fold(index, usize::max)
            })
            .collect();
        let mut values: Vec<Option<[Zeroizing<Vec<u128>>; 2]>> =
            (0..columns.len()).map(|_| None).collect();
        for (index, column) in columns.iter().enumerate() {
            let words = || {
                column
                    .words
                    .chunks_exact(2)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            };
            let mut coefficients: Zeroizing<Vec<u128>> =
                Zeroizing::new(words().map(u128::from).collect());
            transform.base(&mut coefficients, true);
            let column_values = [coefficients.to_vec(), std::mem::take(&mut *coefficients)]
                .into_iter()
                .zip(cosets.points)
                .map(|(coefficients, coset)| {
                    Zeroizing::new(oracles::masked_base_coefficients(
                        coefficients,
                        &column.mask,
                        coset,
                        transform,
                        None,
                    ))
                });
            let column_values: [Zeroizing<Vec<u128>>; 2] =
                column_values.collect::<Vec<_>>().try_into().unwrap();
            for coset in 0..2 {
                cosets.weights[coset].add_base(
                    outputs[coset],
                    column.oracle,
                    column_values[coset].iter().copied(),
                );
            }
            for lookup in &column.lookups {
                assert!(lookups);
                // Each word's reciprocal at its scaled index, gathered from
                // the streamed table.
                let mut raw = Zeroizing::new(Vec::with_capacity(SYSTEMATIC + MASKS));
                raw.resize(SYSTEMATIC, ZERO);
                gather(
                    ELEMENT_BYTES,
                    SYSTEMATIC,
                    |position| {
                        usize::from(u16::from_le_bytes([
                            column.words[2 * position],
                            column.words[2 * position + 1],
                        ])) * lookup.oracles.factor as usize
                    },
                    |position, record| raw[position] = field::decode(record),
                );
                let mask = Reader(lookup.mask).elements(MASKS);
                let coefficients = Zeroizing::new(oracles::masked_extension_coefficients_of(
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
                    let inverse_vanishing = cosets.inverse_vanishing[coset];
                    cosets.weights[coset].add_base(
                        outputs[coset],
                        oracle,
                        column_values[coset].iter().map(|value| {
                            base::multiply(
                                base::multiply(*value, base::subtract(*value, 1)),
                                inverse_vanishing,
                            )
                        }),
                    );
                }
            }
            values[index] = Some(column_values);
            for [left, right, oracle] in pairs.iter().filter(|pair| pair[1] == index) {
                let (left, right) = (
                    values[*left].as_ref().unwrap(),
                    values[*right].as_ref().unwrap(),
                );
                for coset in 0..2 {
                    let inverse_vanishing = cosets.inverse_vanishing[coset];
                    cosets.weights[coset].add_base(
                        outputs[coset],
                        *oracle,
                        left[coset]
                            .iter()
                            .zip(right[coset].iter())
                            .map(|(left, right)| {
                                base::multiply(base::multiply(*left, *right), inverse_vanishing)
                            }),
                    );
                }
            }
            for (column, last) in needed.iter().enumerate() {
                if *last <= index {
                    values[column] = None;
                }
            }
        }
    });
    Vec::new()
}

// The coset, the oracles of the multiplicity, table reciprocal and table
// residual, and the multiplicities with their mask and the table
// reciprocals' mask.
fn encode_counts(
    coset: usize,
    witness: &Witness,
    first_masks: &[Vec<u128>],
    second_masks: &[Vec<Element>],
) -> Zeroizing<Vec<u8>> {
    let relation = &witness.relation;
    let (columns, lookups) = (relation.columns(), relation.lookups());
    // The exact length, which no growth copies without zeroizing.
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        4 * 4
            + first_masks[columns].len() * WORD_BYTES
            + second_masks[lookups].len() * ELEMENT_BYTES
            + witness.counts.len() * WORD_BYTES,
    ));
    for oracle in [
        coset,
        columns,
        columns + 1 + lookups,
        relation.oracles() - 2,
    ] {
        push_number(&mut bytes, oracle);
    }
    for mask in &first_masks[columns] {
        bytes.extend(mask.to_le_bytes());
    }
    for mask in &second_masks[lookups] {
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
        let coset_index = reader.number();
        let [multiplicity_oracle, table_oracle, residual_oracle] =
            std::array::from_fn(|_| reader.number());
        let first_mask = reader.words(MASKS);
        let second_mask = reader.elements(MASKS);
        let counts = reader.take(SYSTEMATIC * WORD_BYTES);
        reader.finish();
        let mut table = StreamedRecords::new(ELEMENT_BYTES, SYSTEMATIC);
        assert_eq!(table.count(), SYSTEMATIC);
        let cosets = Cosets::new(&common);
        let transform = Transform::cached(SYSTEMATIC);
        let count = |index: usize| {
            u128::from_le_bytes(
                counts[WORD_BYTES * index..WORD_BYTES * (index + 1)]
                    .try_into()
                    .unwrap(),
            )
        };
        let output = outputs.into_iter().nth(coset_index).unwrap();
        let coset = cosets.points[coset_index];
        let weights = &cosets.weights[coset_index];
        let inverse_vanishing = cosets.inverse_vanishing[coset_index];
        let mut count_coefficients: Zeroizing<Vec<u128>> =
            Zeroizing::new((0..SYSTEMATIC).map(count).collect());
        transform.base(&mut count_coefficients, true);
        let multiplicity = Zeroizing::new(oracles::masked_base_coefficients(
            std::mem::take(&mut *count_coefficients),
            &first_mask,
            coset,
            transform,
            None,
        ));
        weights.add_base(output, multiplicity_oracle, multiplicity.iter().copied());
        let raw = (0..SYSTEMATIC)
            .map(|index| field::scale(field::decode(table.record(index)), count(index)));
        let table_inverse = Zeroizing::new(oracles::extension_values_owned(
            oracles::masked_extension_coefficients(raw, &second_mask, transform),
            coset,
            transform,
        ));
        weights.add_extension(output, table_oracle, table_inverse.iter().copied());
        // The table's coefficients, from its values on the systematic
        // domain.
        let mut table_coefficients: Vec<u128> = (0..SYSTEMATIC as u128).collect();
        transform.base(&mut table_coefficients, true);
        let table =
            oracles::masked_base_coefficients(table_coefficients, &[], coset, transform, None);
        weights.add_extension(
            output,
            residual_oracle,
            table_inverse
                .iter()
                .zip(&table)
                .zip(multiplicity.iter())
                .map(|((inverse, table), multiplicity)| {
                    field::scale(
                        field::subtract(
                            field::multiply(field::subtract(common.beta, [*table, 0, 0]), *inverse),
                            [*multiplicity, 0, 0],
                        ),
                        inverse_vanishing,
                    )
                }),
        );
    });
    Vec::new()
}

// An extension oracle, or the degree mask's without a weight, and its
// coefficients, which the job streams.
fn encode_extension(oracle: usize, coefficients: &[Element]) -> (Vec<u8>, Shared) {
    assert!(coefficients.len() <= 2 * SYSTEMATIC + 1);
    let mut unit = Vec::new();
    push_number(&mut unit, oracle);
    let mut bytes = Zeroizing::new(Vec::with_capacity(ELEMENT_BYTES * coefficients.len()));
    for coefficient in coefficients {
        bytes.extend(field::encode(*coefficient));
    }
    (unit, share(bytes))
}
fn add_extension_oracle(input: &[u8]) -> Vec<u8> {
    with_cosets(input, |mut reader, outputs| {
        let common = reader.common();
        let oracle = reader.number();
        reader.finish();
        let cosets = Cosets::new(&common);
        for (index, output) in outputs.into_iter().enumerate() {
            // Each coset's values from the coefficients the job streams.
            let values = rows::streamed_extension_values(COSETS[index] as u32, 1);
            if oracle == UNWEIGHTED {
                for (sum, value) in output.iter_mut().zip(values.iter()) {
                    *sum = field::add(*sum, *value);
                }
            } else {
                cosets.weights[index].add_extension(output, oracle, values.iter().copied());
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
        let (unit, lookups) = encode_columns(witness, &first.masks, &second.masks, &group);
        let mut parts = vec![
            Part::Bytes(&header),
            Part::Shared(&common),
            Part::Bytes(&unit),
        ];
        if lookups {
            parts.push(Part::Streamed(&table));
        }
        sums.add(submit(&COLUMNS, None, &parts, 0));
    }
    for coset in 0..COSETS.len() {
        let counts = encode_counts(coset, witness, &first.masks, &second.masks);
        sums.add(submit(
            &COUNTS,
            None,
            &[
                Part::Bytes(&header),
                Part::Shared(&common),
                Part::Bytes(&counts),
                Part::Streamed(&table),
            ],
            0,
        ));
    }
    for (oracle, coefficients) in [
        (UNWEIGHTED, &first.degree_mask),
        (columns + lookups + 2, &second.sum_mask),
        (columns + lookups + 3, &linear.quotient),
        (oracles - 1, &linear.remainder),
    ] {
        let (unit, coefficients) = encode_extension(oracle, coefficients);
        sums.add(submit(
            &EXTENSION,
            None,
            &[
                Part::Bytes(&header),
                Part::Shared(&common),
                Part::Bytes(&unit),
                Part::Streamed(&coefficients),
            ],
            0,
        ));
    }
    // Each coset's sums interleave with the other's in interpolation order.
    let mut evaluations = Zeroizing::new(vec![ZERO; 2 * SYSTEMATIC]);
    sums.finish(|index, value| {
        let position = index / SYSTEMATIC + 2 * (index % SYSTEMATIC);
        evaluations[position] = field::add(evaluations[position], value);
    });
    Transform::cached(SYSTEMATIC).extension(&mut evaluations, true);
    let inverse_coset = base::power(7, MODULUS - 2);
    let mut power = 1;
    for value in evaluations.iter_mut() {
        *value = field::scale(*value, power);
        power = base::multiply(power, inverse_coset);
    }
    std::mem::take(&mut *evaluations)
}

#[cfg(test)]
#[path = "combination-tests.rs"]
mod tests;
